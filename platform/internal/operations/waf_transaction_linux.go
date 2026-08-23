//go:build linux

package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const wafRollbackWindow = 6 * time.Minute

type wafTransactionState string

const (
	wafTransactionArmed       wafTransactionState = "armed"
	wafTransactionConfirmed   wafTransactionState = "confirmed"
	wafTransactionRollingBack wafTransactionState = "rolling_back"
	wafTransactionRolledBack  wafTransactionState = "rolled_back"
	wafTransactionAmbiguous   wafTransactionState = "ambiguous"
)

type wafPolicyPointer struct {
	ScopeKey    string     `json:"scope_key"`
	ResourceID  ResourceID `json:"resource_id"`
	Generation  uint64     `json:"generation"`
	Digest      string     `json:"digest"`
	Path        string     `json:"path"`
}

type wafActiveIndex struct {
	Version  uint16             `json:"version"`
	Policies []wafPolicyPointer `json:"policies"`
}

type wafSourceEvidence struct {
	Provider ResourceID `json:"provider"`
	Name     ResourceID `json:"name"`
	Version  string     `json:"version"`
	Digest   string     `json:"digest"`
	Path     string     `json:"path"`
}

type wafExclusionEvidence struct {
	ScopeKey        string     `json:"scope_key"`
	PolicyID        ResourceID `json:"policy_id"`
	PolicyGeneration uint64    `json:"policy_generation"`
	Ordinal         uint32     `json:"ordinal"`
	ReasonCode      ResourceID `json:"reason_code"`
	ExpiresAt       time.Time  `json:"expires_at"`
	Digest          string     `json:"digest"`
}

type wafNativeGeneration struct {
	Version      uint16                 `json:"version"`
	Digest       string                 `json:"digest"`
	ConfigPath   string                 `json:"config_path"`
	EvidencePath string                 `json:"evidence_path"`
	Policies     []wafPolicyPointer     `json:"policies"`
	Sources      []wafSourceEvidence    `json:"sources,omitempty"`
	Exclusions   []wafExclusionEvidence `json:"exclusions,omitempty"`
}

type wafRollbackLease struct {
	Version           uint16                 `json:"version"`
	LeaseID           string                 `json:"lease_id"`
	ConfirmationNonce string                 `json:"confirmation_nonce"`
	EffectID          string                 `json:"effect_id"`
	RequestDigest     string                 `json:"request_digest"`
	PolicyDigest      string                 `json:"policy_digest"`
	PolicyScopeKey    string                 `json:"policy_scope_key"`
	PreviousIndex     wafActiveIndex         `json:"previous_index"`
	CandidateIndex    wafActiveIndex         `json:"candidate_index"`
	PreviousGeneration *wafNativeGeneration `json:"previous_generation,omitempty"`
	CandidateGeneration wafNativeGeneration `json:"candidate_generation"`
	Snapshot          operationsFileSnapshot `json:"snapshot"`
	State             wafTransactionState    `json:"state"`
	ArmedAt           time.Time              `json:"armed_at"`
	Deadline          time.Time              `json:"deadline"`
	Activation        *ActivationEvidence    `json:"activation,omitempty"`
	RollbackProofDigest string               `json:"rollback_proof_digest,omitempty"`
	FailureCode       string                 `json:"failure_code,omitempty"`
}

func wafPolicyScope(policy WAFPolicy) (string, error) {
	if policy.NodeID.IsZero() {
		return "", ErrInvalidEffect
	}
	if policy.TenantID.String() == "" && policy.SiteID.String() == "" {
		return "node:" + policy.NodeID.String(), nil
	}
	if policy.TenantID.String() == "" || policy.SiteID.String() == "" {
		return "", ErrInvalidEffect
	}
	return "site:" + policy.NodeID.String() + ":" + policy.TenantID.String() + ":" + policy.SiteID.String(), nil
}

func (executor *LinuxOperationsExecutor) stageWAFPolicy(policy WAFPolicy) (wafPolicyPointer, error) {
	scope, err := wafPolicyScope(policy)
	if err != nil || policy.Validate() != nil {
		return wafPolicyPointer{}, ErrInvalidEffect
	}
	digest, err := activationDigest(policy)
	if err != nil {
		return wafPolicyPointer{}, err
	}
	scopeDigest := digestBytes([]byte("cyberpanel:waf-scope:v1\x00" + scope))
	directory := filepath.Join(executor.stateRoot, "waf", "policies", scopeDigest)
	if err = ensurePrivateWAFDirectory(directory); err != nil {
		return wafPolicyPointer{}, err
	}
	path := filepath.Join(directory, fmt.Sprintf("%020d-%s.json", policy.Generation, digest))
	content, err := json.Marshal(policy)
	if err != nil {
		return wafPolicyPointer{}, err
	}
	if err = writeImmutableWAFFile(path, content); err != nil {
		return wafPolicyPointer{}, err
	}
	return wafPolicyPointer{ScopeKey: scope, ResourceID: policy.ID, Generation: policy.Generation, Digest: digest, Path: path}, nil
}

func ensurePrivateWAFDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return ErrInvalidEffect
	}
	return os.Chown(directory, 0, 0)
}

func writeImmutableWAFFile(path string, content []byte) error {
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, content) {
			return ErrConflict
		}
		return validateImmutableWAFFile(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".waf-generation-")
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
		if readErr != nil || !bytes.Equal(existing, content) {
			return ErrConflict
		}
	} else if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err = directory.Sync(); err != nil {
		return err
	}
	return validateImmutableWAFFile(path)
}

func validateImmutableWAFFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o400 || info.Size() <= 0 || info.Size() > 64<<20 {
		return ErrInvalidEffect
	}
	return nil
}

func (executor *LinuxOperationsExecutor) loadWAFPolicy(pointer wafPolicyPointer) (WAFPolicy, error) {
	if pointer.ScopeKey == "" || pointer.ResourceID.IsZero() || pointer.Generation == 0 || !validSHA256(pointer.Digest) || validateImmutableWAFFile(pointer.Path) != nil || !strings.HasPrefix(filepath.Clean(pointer.Path), filepath.Join(executor.stateRoot, "waf", "policies")+string(os.PathSeparator)) {
		return WAFPolicy{}, ErrInvalidReceipt
	}
	content, err := os.ReadFile(pointer.Path)
	if err != nil {
		return WAFPolicy{}, err
	}
	var policy WAFPolicy
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&policy); err != nil || decoder.Decode(&struct{}{}) != io.EOF || policy.Validate() != nil {
		return WAFPolicy{}, ErrInvalidReceipt
	}
	canonical, err := json.Marshal(policy)
	if err != nil || !bytes.Equal(canonical, content) {
		return WAFPolicy{}, ErrInvalidReceipt
	}
	digest, _ := activationDigest(policy)
	scope, _ := wafPolicyScope(policy)
	if digest != pointer.Digest || scope != pointer.ScopeKey || policy.ID != pointer.ResourceID || policy.Generation != pointer.Generation {
		return WAFPolicy{}, ErrInvalidReceipt
	}
	return policy, nil
}

func (executor *LinuxOperationsExecutor) loadWAFActiveIndex() (wafActiveIndex, error) {
	path := filepath.Join(executor.stateRoot, "waf", "active.json")
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return wafActiveIndex{Version: 1, Policies: []wafPolicyPointer{}}, nil
	}
	if err != nil {
		return wafActiveIndex{}, err
	}
	var index wafActiveIndex
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&index); err != nil || decoder.Decode(&struct{}{}) != io.EOF || executor.validateWAFActiveIndex(index) != nil {
		return wafActiveIndex{}, ErrInvalidReceipt
	}
	return index, nil
}

func (executor *LinuxOperationsExecutor) validateWAFActiveIndex(index wafActiveIndex) error {
	if index.Version != 1 || len(index.Policies) > 4097 {
		return ErrInvalidReceipt
	}
	previous := ""
	nodePolicies := 0
	for _, pointer := range index.Policies {
		if pointer.ScopeKey <= previous {
			return ErrInvalidReceipt
		}
		policy, err := executor.loadWAFPolicy(pointer)
		if err != nil {
			return err
		}
		if policy.TenantID.String() == "" {
			nodePolicies++
		}
		previous = pointer.ScopeKey
	}
	if nodePolicies > 1 {
		return ErrInvalidReceipt
	}
	return nil
}

func (executor *LinuxOperationsExecutor) wafIndexCAS(current wafActiveIndex, candidate wafPolicyPointer) (wafActiveIndex, bool, error) {
	next := wafActiveIndex{Version: 1, Policies: append([]wafPolicyPointer(nil), current.Policies...)}
	position := sort.Search(len(next.Policies), func(index int) bool { return next.Policies[index].ScopeKey >= candidate.ScopeKey })
	if position == len(next.Policies) || next.Policies[position].ScopeKey != candidate.ScopeKey {
		if candidate.Generation != 1 {
			return wafActiveIndex{}, false, ErrConflict
		}
		next.Policies = append(next.Policies, wafPolicyPointer{})
		copy(next.Policies[position+1:], next.Policies[position:])
		next.Policies[position] = candidate
		return next, false, executor.validateWAFActiveIndex(next)
	}
	active := next.Policies[position]
	if active.ResourceID != candidate.ResourceID {
		return wafActiveIndex{}, false, ErrConflict
	}
	if active.Generation == candidate.Generation && active.Digest == candidate.Digest {
		return next, true, nil
	}
	if candidate.Generation != active.Generation+1 {
		return wafActiveIndex{}, false, ErrConflict
	}
	next.Policies[position] = candidate
	return next, false, executor.validateWAFActiveIndex(next)
}

func (executor *LinuxOperationsExecutor) storeWAFActiveIndex(index wafActiveIndex) error {
	if executor.validateWAFActiveIndex(index) != nil {
		return ErrInvalidReceipt
	}
	content, err := json.Marshal(index)
	if err != nil {
		return err
	}
	return atomicOperationsFile(filepath.Join(executor.stateRoot, "waf", "active.json"), content, 0o600)
}

func (executor *LinuxOperationsExecutor) loadWAFPolicies(index wafActiveIndex) ([]WAFPolicy, error) {
	policies := make([]WAFPolicy, 0, len(index.Policies))
	nodePolicies := 0
	for _, pointer := range index.Policies {
		policy, err := executor.loadWAFPolicy(pointer)
		if err != nil {
			return nil, err
		}
		if policy.TenantID.String() == "" {
			nodePolicies++
		}
		policies = append(policies, policy)
	}
	if nodePolicies != 1 {
		return nil, ErrConflict
	}
	return policies, nil
}

func (executor *LinuxOperationsExecutor) stageWAFGeneration(index wafActiveIndex, content []byte, sources []wafSourceEvidence, exclusions []wafExclusionEvidence) (wafNativeGeneration, error) {
	digest := digestBytes(content)
	root := filepath.Join(executor.stateRoot, "waf", "generations")
	configPath := filepath.Join(root, digest+".conf")
	evidencePath := filepath.Join(root, digest+".json")
	generation := wafNativeGeneration{Version: 1, Digest: digest, ConfigPath: configPath, EvidencePath: evidencePath, Policies: append([]wafPolicyPointer(nil), index.Policies...), Sources: sources, Exclusions: exclusions}
	evidence, err := json.Marshal(generation)
	if err != nil {
		return wafNativeGeneration{}, err
	}
	if err = writeImmutableWAFFile(configPath, content); err != nil {
		return wafNativeGeneration{}, err
	}
	if err = writeImmutableWAFFile(evidencePath, evidence); err != nil {
		return wafNativeGeneration{}, err
	}
	return generation, nil
}

func (executor *LinuxOperationsExecutor) validateWAFGeneration(generation wafNativeGeneration) error {
	if generation.Version != 1 || !validSHA256(generation.Digest) || validateImmutableWAFFile(generation.ConfigPath) != nil || validateImmutableWAFFile(generation.EvidencePath) != nil || !strings.HasPrefix(filepath.Clean(generation.ConfigPath), filepath.Join(executor.stateRoot, "waf", "generations")+string(os.PathSeparator)) {
		return ErrInvalidReceipt
	}
	content, err := os.ReadFile(generation.ConfigPath)
	if err != nil || digestBytes(content) != generation.Digest {
		return ErrInvalidReceipt
	}
	evidence, err := os.ReadFile(generation.EvidencePath)
	if err != nil {
		return err
	}
	var decoded wafNativeGeneration
	decoder := json.NewDecoder(bytes.NewReader(evidence))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&decoded); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !wafGenerationsEqual(decoded, generation) {
		return ErrInvalidReceipt
	}
	return nil
}

func wafGenerationsEqual(left, right wafNativeGeneration) bool {
	leftEncoded, leftErr := json.Marshal(left)
	rightEncoded, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftEncoded, rightEncoded)
}

func (executor *LinuxOperationsExecutor) loadCurrentWAFGeneration() (*wafNativeGeneration, error) {
	content, err := os.ReadFile(filepath.Join(executor.stateRoot, "waf", "current.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var generation wafNativeGeneration
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&generation); err != nil || decoder.Decode(&struct{}{}) != io.EOF || executor.validateWAFGeneration(generation) != nil {
		return nil, ErrInvalidReceipt
	}
	return &generation, nil
}

func (executor *LinuxOperationsExecutor) storeCurrentWAFGeneration(generation wafNativeGeneration) error {
	if executor.validateWAFGeneration(generation) != nil {
		return ErrInvalidReceipt
	}
	content, err := json.Marshal(generation)
	if err != nil {
		return err
	}
	return atomicOperationsFile(filepath.Join(executor.stateRoot, "waf", "current.json"), content, 0o600)
}

func (executor *LinuxOperationsExecutor) wafLeasePath(effectID string) (string, error) {
	if _, err := executor.journalPath(effectID); err != nil {
		return "", err
	}
	return filepath.Join(executor.stateRoot, "waf", "leases", effectID+".json"), nil
}

func (executor *LinuxOperationsExecutor) armWAFLease(request EffectRequest, policyDigest, scope string, previousIndex, candidateIndex wafActiveIndex, previousGeneration *wafNativeGeneration, candidateGeneration wafNativeGeneration, snapshot operationsFileSnapshot) (wafRollbackLease, error) {
	if existing, found, err := executor.loadWAFLease(request.EffectID); err != nil {
		return wafRollbackLease{}, err
	} else if found {
		if existing.RequestDigest != request.RequestDigest || existing.PolicyDigest != policyDigest || existing.CandidateGeneration.Digest != candidateGeneration.Digest {
			return wafRollbackLease{}, ErrIdempotency
		}
		return existing, nil
	}
	leaseID, err := randomSecurityToken("waflease-")
	if err != nil {
		return wafRollbackLease{}, err
	}
	nonce, err := randomSecurityToken("wafconfirm-")
	if err != nil {
		return wafRollbackLease{}, err
	}
	now := executor.clock.Now().UTC()
	lease := wafRollbackLease{
		Version: 1, LeaseID: leaseID, ConfirmationNonce: nonce, EffectID: request.EffectID,
		RequestDigest: request.RequestDigest, PolicyDigest: policyDigest, PolicyScopeKey: scope,
		PreviousIndex: previousIndex, CandidateIndex: candidateIndex, PreviousGeneration: previousGeneration,
		CandidateGeneration: candidateGeneration, Snapshot: snapshot,
		State: wafTransactionArmed, ArmedAt: now, Deadline: now.Add(wafRollbackWindow),
	}
	if err = executor.storeWAFLease(lease); err != nil {
		return wafRollbackLease{}, err
	}
	executor.scheduleWAFRollback(lease.EffectID, lease.Deadline)
	return lease, nil
}

func (executor *LinuxOperationsExecutor) loadWAFLease(effectID string) (wafRollbackLease, bool, error) {
	path, err := executor.wafLeasePath(effectID)
	if err != nil {
		return wafRollbackLease{}, false, err
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return wafRollbackLease{}, false, nil
	}
	if err != nil {
		return wafRollbackLease{}, false, err
	}
	var lease wafRollbackLease
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&lease); err != nil || decoder.Decode(&struct{}{}) != io.EOF || executor.validateWAFLease(lease) != nil {
		return wafRollbackLease{}, false, ErrInvalidReceipt
	}
	return lease, true, nil
}

func (executor *LinuxOperationsExecutor) validateWAFLease(lease wafRollbackLease) error {
	if lease.Version != 1 || lease.LeaseID == "" || lease.ConfirmationNonce == "" || lease.EffectID == "" || !validSHA256(lease.RequestDigest) || !validSHA256(lease.PolicyDigest) || lease.PolicyScopeKey == "" || lease.Snapshot.Path != "/usr/local/lsws/conf/modsec/cyberpanel.conf" || lease.ArmedAt.IsZero() || !lease.Deadline.After(lease.ArmedAt) || executor.validateWAFActiveIndex(lease.PreviousIndex) != nil || executor.validateWAFActiveIndex(lease.CandidateIndex) != nil || executor.validateWAFGeneration(lease.CandidateGeneration) != nil {
		return ErrInvalidReceipt
	}
	if !wafPolicyPointersEqual(lease.CandidateGeneration.Policies, lease.CandidateIndex.Policies) {
		return ErrInvalidReceipt
	}
	if lease.PreviousGeneration != nil && executor.validateWAFGeneration(*lease.PreviousGeneration) != nil {
		return ErrInvalidReceipt
	}
	if lease.PreviousGeneration != nil && !wafPolicyPointersEqual(lease.PreviousGeneration.Policies, lease.PreviousIndex.Policies) {
		return ErrInvalidReceipt
	}
	if lease.Activation != nil && (lease.Activation.Strategy != ActivationCompileProbeSwap || lease.Activation.CandidateDigest != lease.PolicyDigest || !validSHA256(lease.Activation.StageReceiptDigest) || !validSHA256(lease.Activation.ProbeReceiptDigest) || !validSHA256(lease.Activation.CommitReceiptDigest)) {
		return ErrInvalidReceipt
	}
	switch lease.State {
	case wafTransactionArmed, wafTransactionConfirmed, wafTransactionRollingBack, wafTransactionRolledBack, wafTransactionAmbiguous:
	default:
		return ErrInvalidReceipt
	}
	return nil
}

func (executor *LinuxOperationsExecutor) storeWAFLease(lease wafRollbackLease) error {
	if executor.validateWAFLease(lease) != nil {
		return ErrInvalidReceipt
	}
	path, err := executor.wafLeasePath(lease.EffectID)
	if err != nil {
		return err
	}
	content, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	return atomicOperationsFile(path, content, 0o600)
}

func (executor *LinuxOperationsExecutor) confirmWAFLease(effectID, nonce string, activation *ActivationEvidence) error {
	lease, found, err := executor.loadWAFLease(effectID)
	if err != nil || !found || lease.State != wafTransactionArmed || lease.ConfirmationNonce != nonce || activation == nil || activation.CandidateDigest != lease.PolicyDigest {
		return ErrCompensationFailed
	}
	if err = executor.storeWAFActiveIndex(lease.CandidateIndex); err != nil {
		return err
	}
	if err = executor.storeCurrentWAFGeneration(lease.CandidateGeneration); err != nil {
		return err
	}
	lease.State = wafTransactionConfirmed
	lease.Activation = activation
	return executor.storeWAFLease(lease)
}

func (executor *LinuxOperationsExecutor) replayWAFEffect(ctx context.Context, request EffectRequest) (linuxEffectResult, bool, error) {
	lease, found, err := executor.loadWAFLease(request.EffectID)
	if err != nil || !found {
		return linuxEffectResult{}, false, err
	}
	if lease.RequestDigest != request.RequestDigest {
		return linuxEffectResult{}, true, ErrIdempotency
	}
	switch lease.State {
	case wafTransactionConfirmed:
		if lease.Activation == nil {
			return linuxEffectResult{MutationObserved: true}, true, ErrCompensationFailed
		}
		return linuxEffectResult{MutationObserved: true, Activation: lease.Activation}, true, nil
	case wafTransactionArmed:
		if !executor.clock.Now().UTC().Before(lease.Deadline) {
			err = executor.rollbackWAFLease(ctx, request.EffectID)
			return linuxEffectResult{MutationObserved: true}, true, errors.Join(ErrCompensationFailed, err)
		}
		return linuxEffectResult{MutationObserved: true}, true, ErrCompensationFailed
	case wafTransactionRollingBack, wafTransactionAmbiguous:
		err = executor.rollbackWAFLease(ctx, request.EffectID)
		return linuxEffectResult{MutationObserved: true}, true, errors.Join(ErrCompensationFailed, err)
	case wafTransactionRolledBack:
		return linuxEffectResult{}, true, ErrInvalidEffect
	default:
		return linuxEffectResult{MutationObserved: true}, true, ErrCompensationFailed
	}
}

func (executor *LinuxOperationsExecutor) scheduleWAFRollback(effectID string, deadline time.Time) {
	go func() {
		if delay := time.Until(deadline); delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			<-timer.C
		}
		executor.mu.Lock()
		defer executor.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = executor.rollbackWAFLease(ctx, effectID)
	}()
}

func (executor *LinuxOperationsExecutor) ResumeWAFTransactions(ctx context.Context) error {
	entries, err := os.ReadDir(filepath.Join(executor.stateRoot, "waf", "leases"))
	if err != nil {
		return err
	}
	var joined error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		effectID := strings.TrimSuffix(entry.Name(), ".json")
		lease, found, loadErr := executor.loadWAFLease(effectID)
		if loadErr != nil {
			joined = errors.Join(joined, loadErr)
			continue
		}
		if found && (lease.State == wafTransactionArmed || lease.State == wafTransactionRollingBack || lease.State == wafTransactionAmbiguous) {
			joined = errors.Join(joined, executor.rollbackWAFLease(ctx, effectID))
		}
	}
	return joined
}

func (executor *LinuxOperationsExecutor) rollbackWAFLease(ctx context.Context, effectID string) error {
	lease, found, err := executor.loadWAFLease(effectID)
	if err != nil || !found {
		return errors.Join(ErrCompensationFailed, err)
	}
	if lease.State == wafTransactionConfirmed || lease.State == wafTransactionRolledBack {
		return nil
	}
	lease.State = wafTransactionRollingBack
	if err = executor.storeWAFLease(lease); err != nil {
		return err
	}
	if err = executor.restoreSnapshots([]operationsFileSnapshot{lease.Snapshot}); err == nil {
		_, err = executor.validateWebConfiguration(ctx)
	}
	var reloadProof []byte
	if err == nil {
		reloadProof, err = executor.runner.Run(ctx, "/usr/local/lsws/bin/lswsctrl", "reload")
	}
	var runtimeProof []byte
	if err == nil {
		runtimeProof, err = executor.proveWAFRuntime(ctx)
	}
	if err == nil {
		err = executor.storeWAFActiveIndex(lease.PreviousIndex)
	}
	if err == nil {
		if lease.PreviousGeneration == nil {
			removeErr := os.Remove(filepath.Join(executor.stateRoot, "waf", "current.json"))
			if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = removeErr
			}
		} else {
			err = executor.storeCurrentWAFGeneration(*lease.PreviousGeneration)
		}
	}
	if err == nil {
		previous, previousFound := wafPointerForScope(lease.PreviousIndex, lease.PolicyScopeKey)
		candidate, candidateFound := wafPointerForScope(lease.CandidateIndex, lease.PolicyScopeKey)
		if !candidateFound {
			err = ErrInvalidReceipt
		} else if previousFound {
			err = executor.storeGeneration(KindWAFPolicy, previous.ResourceID, previous.Generation, previous.Digest)
		} else {
			removeErr := os.Remove(executor.generationPath(KindWAFPolicy, candidate.ResourceID))
			if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = removeErr
			}
		}
	}
	if err != nil {
		lease.State = wafTransactionAmbiguous
		lease.FailureCode = "waf_rollback_unproven"
		_ = executor.storeWAFLease(lease)
		return errors.Join(ErrCompensationFailed, err)
	}
	lease.State = wafTransactionRolledBack
	lease.FailureCode = ""
	lease.RollbackProofDigest = digestBytes(append(append([]byte(snapshotProof([]operationsFileSnapshot{lease.Snapshot})+"\x00"), reloadProof...), runtimeProof...))
	return executor.storeWAFLease(lease)
}

func wafPointerForScope(index wafActiveIndex, scope string) (wafPolicyPointer, bool) {
	position := sort.Search(len(index.Policies), func(candidate int) bool { return index.Policies[candidate].ScopeKey >= scope })
	if position == len(index.Policies) || index.Policies[position].ScopeKey != scope {
		return wafPolicyPointer{}, false
	}
	return index.Policies[position], true
}
