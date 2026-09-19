//go:build linux

package operations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

const securityRollbackWindow = 6 * time.Minute

type securityLeaseState string

const (
	securityLeaseArmed       securityLeaseState = "armed"
	securityLeaseConfirmed   securityLeaseState = "confirmed"
	securityLeaseRollingBack securityLeaseState = "rolling_back"
	securityLeaseRolledBack  securityLeaseState = "rolled_back"
	securityLeaseAmbiguous   securityLeaseState = "ambiguous"
)

type securityActiveGeneration struct {
	Version         uint16       `json:"version"`
	Kind            ResourceKind `json:"kind"`
	ResourceID      ResourceID   `json:"resource_id"`
	Generation      uint64       `json:"generation"`
	PolicyDigest    string       `json:"policy_digest"`
	NativeDigest    string       `json:"native_digest"`
	NativePath      string       `json:"native_path"`
	ActivationProof string       `json:"activation_proof"`
}

type securityRollbackLease struct {
	Version                uint16                    `json:"version"`
	LeaseID                string                    `json:"lease_id"`
	ConfirmationNonce      string                    `json:"confirmation_nonce"`
	EffectID               string                    `json:"effect_id"`
	RequestDigest          string                    `json:"request_digest"`
	Kind                   ResourceKind              `json:"kind"`
	Candidate              securityActiveGeneration  `json:"candidate"`
	Previous               *securityActiveGeneration `json:"previous,omitempty"`
	Snapshots              []operationsFileSnapshot  `json:"snapshots"`
	PreviousRuntimePresent bool                      `json:"previous_runtime_present"`
	PreviousSSHPorts       []uint16                  `json:"previous_ssh_ports,omitempty"`
	State                  securityLeaseState        `json:"state"`
	ArmedAt                time.Time                 `json:"armed_at"`
	Deadline               time.Time                 `json:"deadline"`
	Activation             *ActivationEvidence       `json:"activation,omitempty"`
	RollbackProofDigest    string                    `json:"rollback_proof_digest,omitempty"`
	FailureCode            string                    `json:"failure_code,omitempty"`
}

type securityRecoveryReceipt struct {
	EffectID    string `json:"effect_id"`
	LeaseID     string `json:"lease_id"`
	ProofDigest string `json:"proof_digest"`
}

func securityDirectoryName(kind ResourceKind) (string, error) {
	switch kind {
	case KindFirewallPolicy:
		return "firewall", nil
	case KindSSHPolicy:
		return "ssh", nil
	default:
		return "", ErrInvalidEffect
	}
}

func (executor *LinuxOperationsExecutor) securityRoot(kind ResourceKind) (string, error) {
	name, err := securityDirectoryName(kind)
	if err != nil {
		return "", err
	}
	return filepath.Join(executor.stateRoot, "security", name), nil
}

func (executor *LinuxOperationsExecutor) securityActivePath(kind ResourceKind) (string, error) {
	root, err := executor.securityRoot(kind)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "active.json"), nil
}

func (executor *LinuxOperationsExecutor) securityLeasePath(effectID string) (string, error) {
	if _, err := executor.journalPath(effectID); err != nil {
		return "", err
	}
	return filepath.Join(executor.stateRoot, "security", "leases", effectID+".json"), nil
}

func (executor *LinuxOperationsExecutor) stageSecurityGeneration(kind ResourceKind, id ResourceID, generation uint64, policy any, native []byte, extension string) (securityActiveGeneration, error) {
	if id.IsZero() || generation == 0 || len(native) == 0 || (extension != "nft" && extension != "conf") {
		return securityActiveGeneration{}, ErrInvalidEffect
	}
	policyDigest, err := activationDigest(policy)
	if err != nil {
		return securityActiveGeneration{}, err
	}
	root, err := executor.securityRoot(kind)
	if err != nil {
		return securityActiveGeneration{}, err
	}
	path := filepath.Join(root, "generations", fmt.Sprintf("%020d-%s.%s", generation, policyDigest, extension))
	if err = writeImmutableSecurityFile(path, native); err != nil {
		return securityActiveGeneration{}, err
	}
	return securityActiveGeneration{
		Version: 1, Kind: kind, ResourceID: id, Generation: generation,
		PolicyDigest: policyDigest, NativeDigest: digestBytes(native), NativePath: path,
	}, nil
}

func writeImmutableSecurityFile(path string, content []byte) error {
	if existing, err := os.ReadFile(path); err == nil {
		if digestBytes(existing) != digestBytes(content) {
			return ErrConflict
		}
		return validateImmutableSecurityFile(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".generation-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o400); err == nil {
		_, err = temporary.Write(content)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Chown(temporaryPath, 0, 0); err != nil {
		return err
	}
	if err = os.Link(temporaryPath, path); errors.Is(err, os.ErrExist) {
		existing, readErr := os.ReadFile(path)
		if readErr != nil || digestBytes(existing) != digestBytes(content) {
			return ErrConflict
		}
	} else if err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return err
	}
	return validateImmutableSecurityFile(path)
}

func validateImmutableSecurityFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o277 != 0 {
		return ErrInvalidEffect
	}
	return nil
}

func (executor *LinuxOperationsExecutor) securityGenerationCAS(candidate securityActiveGeneration) (*securityActiveGeneration, bool, error) {
	current, found, err := executor.loadSecurityActive(candidate.Kind)
	if err != nil {
		return nil, false, err
	}
	if !found {
		if candidate.Generation != 1 {
			return nil, false, ErrConflict
		}
		return nil, false, nil
	}
	if current.ResourceID != candidate.ResourceID {
		return nil, false, ErrConflict
	}
	if current.Generation == candidate.Generation && current.PolicyDigest == candidate.PolicyDigest && current.NativeDigest == candidate.NativeDigest {
		return &current, true, nil
	}
	if candidate.Generation != current.Generation+1 {
		return nil, false, ErrConflict
	}
	return &current, false, nil
}

func (executor *LinuxOperationsExecutor) loadSecurityActive(kind ResourceKind) (securityActiveGeneration, bool, error) {
	path, err := executor.securityActivePath(kind)
	if err != nil {
		return securityActiveGeneration{}, false, err
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return securityActiveGeneration{}, false, nil
	}
	if err != nil {
		return securityActiveGeneration{}, false, err
	}
	var active securityActiveGeneration
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&active); err != nil || decoder.Decode(&struct{}{}) != io.EOF || validateSecurityActive(executor, active) != nil {
		return securityActiveGeneration{}, false, ErrInvalidReceipt
	}
	return active, true, nil
}

func validateSecurityActive(executor *LinuxOperationsExecutor, active securityActiveGeneration) error {
	if active.Version != 1 || active.ResourceID.IsZero() || active.Generation == 0 || !validSHA256(active.PolicyDigest) || !validSHA256(active.NativeDigest) {
		return ErrInvalidReceipt
	}
	root, err := executor.securityRoot(active.Kind)
	if err != nil || !strings.HasPrefix(filepath.Clean(active.NativePath), filepath.Join(root, "generations")+string(os.PathSeparator)) {
		return ErrInvalidReceipt
	}
	content, err := os.ReadFile(active.NativePath)
	if err != nil || digestBytes(content) != active.NativeDigest || validateImmutableSecurityFile(active.NativePath) != nil {
		return ErrInvalidReceipt
	}
	if active.ActivationProof != "" && !validSHA256(active.ActivationProof) {
		return ErrInvalidReceipt
	}
	return nil
}

func (executor *LinuxOperationsExecutor) storeSecurityActive(active securityActiveGeneration) error {
	path, err := executor.securityActivePath(active.Kind)
	if err != nil || validateSecurityActive(executor, active) != nil {
		return ErrInvalidEffect
	}
	content, err := json.Marshal(active)
	if err != nil {
		return err
	}
	return atomicOperationsFile(path, content, 0o600)
}

func (executor *LinuxOperationsExecutor) armSecurityLease(request EffectRequest, candidate securityActiveGeneration, previous *securityActiveGeneration, snapshots []operationsFileSnapshot, previousRuntime bool, previousPorts []uint16) (securityRollbackLease, error) {
	if existing, found, err := executor.loadSecurityLease(request.EffectID); err != nil {
		return securityRollbackLease{}, err
	} else if found {
		if existing.RequestDigest != request.RequestDigest || existing.Candidate.PolicyDigest != candidate.PolicyDigest {
			return securityRollbackLease{}, ErrIdempotency
		}
		return existing, nil
	}
	leaseID, err := randomSecurityToken("seclease-")
	if err != nil {
		return securityRollbackLease{}, err
	}
	nonce, err := randomSecurityToken("secconfirm-")
	if err != nil {
		return securityRollbackLease{}, err
	}
	now := executor.clock.Now().UTC()
	lease := securityRollbackLease{
		Version: 1, LeaseID: leaseID, ConfirmationNonce: nonce,
		EffectID: request.EffectID, RequestDigest: request.RequestDigest, Kind: candidate.Kind,
		Candidate: candidate, Previous: previous, Snapshots: snapshots,
		PreviousRuntimePresent: previousRuntime, PreviousSSHPorts: append([]uint16(nil), previousPorts...),
		State: securityLeaseArmed, ArmedAt: now, Deadline: now.Add(securityRollbackWindow),
	}
	if err = executor.storeSecurityLease(lease); err != nil {
		return securityRollbackLease{}, err
	}
	executor.scheduleSecurityRollback(lease.EffectID, lease.Deadline)
	return lease, nil
}

func randomSecurityToken(prefix string) (string, error) {
	var entropy [32]byte
	if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(entropy[:]), nil
}

func (executor *LinuxOperationsExecutor) loadSecurityLease(effectID string) (securityRollbackLease, bool, error) {
	path, err := executor.securityLeasePath(effectID)
	if err != nil {
		return securityRollbackLease{}, false, err
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return securityRollbackLease{}, false, nil
	}
	if err != nil {
		return securityRollbackLease{}, false, err
	}
	var lease securityRollbackLease
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&lease); err != nil || decoder.Decode(&struct{}{}) != io.EOF || executor.validateSecurityLease(lease) != nil {
		return securityRollbackLease{}, false, ErrInvalidReceipt
	}
	return lease, true, nil
}

func (executor *LinuxOperationsExecutor) validateSecurityLease(lease securityRollbackLease) error {
	if lease.Version != 1 || lease.EffectID == "" || !validSHA256(lease.RequestDigest) || lease.LeaseID == "" || lease.ConfirmationNonce == "" || lease.Kind != lease.Candidate.Kind || lease.ArmedAt.IsZero() || !lease.Deadline.After(lease.ArmedAt) {
		return ErrInvalidReceipt
	}
	if validateSecurityActive(executor, lease.Candidate) != nil {
		return ErrInvalidReceipt
	}
	if lease.Previous != nil && validateSecurityActive(executor, *lease.Previous) != nil {
		return ErrInvalidReceipt
	}
	for _, snapshot := range lease.Snapshots {
		if lease.Kind == KindFirewallPolicy && snapshot.Path != "/etc/cyberpanel/firewall.nft" || lease.Kind == KindSSHPolicy && snapshot.Path != "/etc/ssh/sshd_config.d/50-cyberpanel.conf" {
			return ErrInvalidReceipt
		}
	}
	switch lease.State {
	case securityLeaseArmed, securityLeaseRollingBack, securityLeaseRolledBack, securityLeaseConfirmed, securityLeaseAmbiguous:
	default:
		return ErrInvalidReceipt
	}
	return nil
}

func (executor *LinuxOperationsExecutor) storeSecurityLease(lease securityRollbackLease) error {
	if executor.validateSecurityLease(lease) != nil {
		return ErrInvalidReceipt
	}
	path, err := executor.securityLeasePath(lease.EffectID)
	if err != nil {
		return err
	}
	content, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	return atomicOperationsFile(path, content, 0o600)
}

func (executor *LinuxOperationsExecutor) confirmSecurityLease(effectID, nonce string, activation *ActivationEvidence) error {
	lease, found, err := executor.loadSecurityLease(effectID)
	if err != nil || !found || lease.State != securityLeaseArmed || lease.ConfirmationNonce != nonce || activation == nil || activation.CandidateDigest != lease.Candidate.PolicyDigest {
		return ErrCompensationFailed
	}
	lease.State = securityLeaseConfirmed
	lease.Activation = activation
	lease.Candidate.ActivationProof = activation.CommitReceiptDigest
	if err = executor.storeSecurityActive(lease.Candidate); err != nil {
		return err
	}
	return executor.storeSecurityLease(lease)
}

func (executor *LinuxOperationsExecutor) replaySecurityEffect(ctx context.Context, request EffectRequest) (linuxEffectResult, bool, error) {
	lease, found, err := executor.loadSecurityLease(request.EffectID)
	if err != nil || !found {
		return linuxEffectResult{}, false, err
	}
	if lease.RequestDigest != request.RequestDigest {
		return linuxEffectResult{}, true, ErrIdempotency
	}
	switch lease.State {
	case securityLeaseConfirmed:
		if lease.Activation == nil {
			return linuxEffectResult{MutationObserved: true}, true, ErrCompensationFailed
		}
		return linuxEffectResult{MutationObserved: true, Activation: lease.Activation}, true, nil
	case securityLeaseArmed:
		if !executor.clock.Now().UTC().Before(lease.Deadline) {
			err = executor.rollbackSecurityLease(ctx, request.EffectID)
			return linuxEffectResult{MutationObserved: true}, true, errors.Join(ErrCompensationFailed, err)
		}
		return linuxEffectResult{MutationObserved: true}, true, ErrCompensationFailed
	case securityLeaseRollingBack, securityLeaseAmbiguous:
		err = executor.rollbackSecurityLease(ctx, request.EffectID)
		return linuxEffectResult{MutationObserved: true}, true, errors.Join(ErrCompensationFailed, err)
	case securityLeaseRolledBack:
		return linuxEffectResult{}, true, ErrInvalidEffect
	default:
		return linuxEffectResult{MutationObserved: true}, true, ErrCompensationFailed
	}
}

func (executor *LinuxOperationsExecutor) scheduleSecurityRollback(effectID string, deadline time.Time) {
	go func() {
		delay := time.Until(deadline)
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			<-timer.C
		}
		for {
			executor.mu.Lock()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			err := executor.rollbackSecurityLease(ctx, effectID)
			cancel()
			executor.mu.Unlock()
			if err == nil || !errors.Is(err, rebootcontrol.ErrConflict) {
				return
			}
			// Admission denial changes no lease state. Retry the same durable
			// identity after closure; ambiguous admitted effects never replay.
			timer := time.NewTimer(30 * time.Second)
			<-timer.C
		}
	}()
}

// ResumeSecurityWatchdogs rolls back every unconfirmed pre-restart lease before
// the privileged broker accepts new work. A restart is conservatively treated
// as loss of the validating path; wall clock can never extend the lease.
func (executor *LinuxOperationsExecutor) ResumeSecurityWatchdogs(ctx context.Context) error {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(executor.stateRoot, "security", "leases"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		effectID := strings.TrimSuffix(entry.Name(), ".json")
		lease, found, loadErr := executor.loadSecurityLease(effectID)
		if loadErr != nil {
			return loadErr
		}
		if found && (lease.State == securityLeaseArmed || lease.State == securityLeaseRollingBack || lease.State == securityLeaseAmbiguous || lease.State == securityLeaseRolledBack) {
			if err = executor.rollbackSecurityLease(ctx, effectID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (executor *LinuxOperationsExecutor) rollbackSecurityLease(ctx context.Context, effectID string) error {
	lease, found, err := executor.loadSecurityLease(effectID)
	if err != nil || !found {
		return errors.Join(ErrCompensationFailed, err)
	}
	if lease.State == securityLeaseConfirmed {
		return nil
	}
	if lease.State != securityLeaseArmed && lease.State != securityLeaseRollingBack && lease.State != securityLeaseAmbiguous && lease.State != securityLeaseRolledBack {
		return ErrCompensationFailed
	}
	if executor.admission == nil {
		return rebootcontrol.ErrConflict
	}
	canonical := lease
	canonical.State = ""
	canonical.FailureCode = ""
	canonical.RollbackProofDigest = ""
	digest := rebootcontrol.ExecutionDigest(canonical)
	admitted, err := executor.admission.AdmitExecution(ctx, rebootcontrol.ExecutionBinding{Boundary: "operations-recovery", Method: "security_rollback", EffectID: lease.LeaseID, RequestDigest: digest, Caller: "panel-execd-recovery", Resource: rebootcontrol.ExecutionResource(struct {
		Kind       ResourceKind
		Resource   ResourceID
		Generation uint64
		Request    string
	}{lease.Kind, lease.Candidate.ResourceID, lease.Candidate.Generation, lease.RequestDigest})})
	if err != nil {
		return err
	}
	if len(admitted.Cached) != 0 {
		var receipt securityRecoveryReceipt
		if json.Unmarshal(admitted.Cached, &receipt) != nil || !validSecurityRecoveryReceipt(lease, effectID, receipt) {
			return rebootcontrol.ErrIntegrity
		}
		return nil
	}
	defer func() { _ = rebootcontrol.SettleExecution(executor.admission, admitted, false, nil) }()
	if lease.State == securityLeaseRolledBack {
		receipt := securityRecoveryReceipt{EffectID: effectID, LeaseID: lease.LeaseID, ProofDigest: lease.RollbackProofDigest}
		if !validSecurityRecoveryReceipt(lease, effectID, receipt) {
			return ErrCompensationFailed
		}
		return rebootcontrol.SettleExecution(executor.admission, admitted, true, receipt)
	}
	lease.State = securityLeaseRollingBack
	if err = executor.storeSecurityLease(lease); err != nil {
		return err
	}
	var proof []byte
	if err = executor.restoreSnapshots(lease.Snapshots); err == nil {
		switch lease.Kind {
		case KindFirewallPolicy:
			proof, err = executor.restoreFirewallRuntime(ctx, lease)
		case KindSSHPolicy:
			proof, err = executor.restoreSSHRuntime(ctx, lease)
		default:
			err = ErrInvalidEffect
		}
	}
	if err == nil {
		err = executor.restoreSecurityActive(lease)
	}
	if err != nil {
		lease.State = securityLeaseAmbiguous
		lease.FailureCode = "rollback_unproven"
		_ = executor.storeSecurityLease(lease)
		return errors.Join(ErrCompensationFailed, err)
	}
	lease.State = securityLeaseRolledBack
	lease.FailureCode = ""
	lease.RollbackProofDigest = digestBytes(append([]byte(snapshotProof(lease.Snapshots)+"\x00"), proof...))
	if err = executor.storeSecurityLease(lease); err != nil {
		return err
	}
	stored, storedFound, loadErr := executor.loadSecurityLease(effectID)
	if loadErr != nil || !storedFound {
		return errors.Join(ErrCompensationFailed, loadErr)
	}
	receipt := securityRecoveryReceipt{EffectID: effectID, LeaseID: stored.LeaseID, ProofDigest: stored.RollbackProofDigest}
	if !validSecurityRecoveryReceipt(stored, effectID, receipt) {
		return ErrCompensationFailed
	}
	return rebootcontrol.SettleExecution(executor.admission, admitted, true, receipt)
}

func validSecurityRecoveryReceipt(lease securityRollbackLease, effectID string, receipt securityRecoveryReceipt) bool {
	return lease.State == securityLeaseRolledBack && lease.EffectID == effectID && receipt.EffectID == effectID && receipt.LeaseID == lease.LeaseID && validSHA256(receipt.ProofDigest) && receipt.ProofDigest == lease.RollbackProofDigest
}

func (executor *LinuxOperationsExecutor) restoreFirewallRuntime(ctx context.Context, lease securityRollbackLease) ([]byte, error) {
	if lease.Previous == nil || !lease.PreviousRuntimePresent {
		output, deleteErr := executor.runner.Run(ctx, "/usr/sbin/nft", "delete", "table", "inet", "cyberpanel")
		if deleteErr != nil {
			if _, listErr := executor.runner.Run(ctx, "/usr/sbin/nft", "list", "table", "inet", "cyberpanel"); listErr == nil {
				return output, deleteErr
			}
		}
		return output, nil
	}
	output, err := executor.runner.Run(ctx, "/usr/sbin/nft", "--file", lease.Previous.NativePath)
	if err != nil {
		return output, err
	}
	observed, err := executor.verifyNFTGeneration(ctx, *lease.Previous, nil)
	return []byte(observed), err
}

func (executor *LinuxOperationsExecutor) restoreSSHRuntime(ctx context.Context, lease securityRollbackLease) ([]byte, error) {
	validated, err := executor.runner.Run(ctx, "/usr/sbin/sshd", "-t", "-f", "/etc/ssh/sshd_config")
	if err != nil {
		return validated, err
	}
	reloaded, err := executor.reloadSSHD(ctx)
	if err != nil {
		return append(validated, reloaded...), err
	}
	var proof []byte
	ports := append([]uint16(nil), lease.PreviousSSHPorts...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	for _, port := range ports {
		observed, probeErr := executor.probeSSHListener(ctx, port, 1)
		if probeErr != nil {
			return append(append(validated, reloaded...), proof...), probeErr
		}
		proof = append(proof, observed...)
	}
	return append(append(validated, reloaded...), proof...), nil
}

func (executor *LinuxOperationsExecutor) restoreSecurityActive(lease securityRollbackLease) error {
	path, err := executor.securityActivePath(lease.Kind)
	if err != nil {
		return err
	}
	if lease.Previous == nil {
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		generationPath := executor.generationPath(lease.Kind, lease.Candidate.ResourceID)
		if err = os.Remove(generationPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err = executor.storeSecurityActive(*lease.Previous); err != nil {
		return err
	}
	return executor.storeGeneration(lease.Previous.Kind, lease.Previous.ResourceID, lease.Previous.Generation, lease.Previous.PolicyDigest)
}

func (executor *LinuxOperationsExecutor) reloadSSHD(ctx context.Context) ([]byte, error) {
	output, err := executor.runner.Run(ctx, "/usr/bin/systemctl", "reload", "sshd.service")
	if err == nil {
		return output, nil
	}
	fallback, fallbackErr := executor.runner.Run(ctx, "/usr/bin/systemctl", "reload", "ssh.service")
	return append(output, fallback...), fallbackErr
}

func parseSSHDPorts(output []byte) []uint16 {
	seen := map[uint16]struct{}{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "port" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 16)
		if err == nil && value != 0 {
			seen[uint16(value)] = struct{}{}
		}
	}
	ports := make([]uint16, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}
