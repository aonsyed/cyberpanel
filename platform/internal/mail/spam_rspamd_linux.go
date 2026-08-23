//go:build linux

package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
)

const (
	SpamConfigurationRoot = "/var/lib/cyberpanel/rspamd-policy"
	spamRspamadmPath       = "/usr/bin/rspamadm"
	spamSystemctlPath      = "/usr/bin/systemctl"
	spamRspamdUnit         = "rspamd.service"
	spamCommandOutputLimit = 256 << 10
)

type LinuxRspamdPolicyRuntime struct {
	Store     *daemoncfg.Store
	RspamdGID uint32
	Now       func() time.Time
	mu        sync.Mutex
}

func NewLinuxRspamdPolicyRuntime(root string, rspamdGID uint32, now func() time.Time) (*LinuxRspamdPolicyRuntime, error) {
	if root != SpamConfigurationRoot || rspamdGID == 0 {
		return nil, ErrInvalidCommand
	}
	store, err := daemoncfg.OpenStore(root, SpamConfigurationRoot)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &LinuxRspamdPolicyRuntime{Store: store, RspamdGID: rspamdGID, Now: now}, nil
}

func (runtime *LinuxRspamdPolicyRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.Store == nil {
		return nil
	}
	err := runtime.Store.Close()
	runtime.Store = nil
	return err
}

func (runtime *LinuxRspamdPolicyRuntime) ApplySpamGeneration(ctx context.Context, generation SpamConfigGeneration) (SpamActivationReceipt, error) {
	receipt := SpamActivationReceipt{GenerationID: generation.ID, PolicyGeneration: generation.PolicyGeneration, SnapshotDigest: generation.SnapshotDigest, ArtifactDigest: generation.ArtifactDigest}
	if runtime == nil || runtime.RspamdGID == 0 || runtime.Now == nil || ctx == nil {
		return receipt, ErrInvalidCommand
	}
	artifacts, storeDigest, err := runtimeArtifacts(generation, runtime.RspamdGID)
	if err != nil {
		return receipt, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.Store == nil {
		return receipt, ErrInvalidCommand
	}
	receipt.ObservedAt = runtime.now()
	if _, err = runtime.Store.Stage(ctx, generation.ID, storeDigest, artifacts); err != nil {
		return receipt, err
	}
	generationConfig := filepath.Join(SpamConfigurationRoot, "generations", generation.ID, "rspamd.conf")
	validation, err := runSpamFixed(ctx, 15*time.Second, spamRspamadmPath, "configtest", "-c", generationConfig)
	receipt.ValidationDigest = spamCommandDigest(spamRspamadmPath, []string{"configtest", "-c", generationConfig}, validation)
	if err != nil {
		return receipt, err
	}
	previous, err := runtime.Store.Activate(ctx, generation.ID)
	if err != nil {
		return receipt, err
	}
	receipt.PreviousID = previous
	reload, err := runSpamFixed(ctx, 20*time.Second, spamSystemctlPath, "reload", spamRspamdUnit)
	receipt.ReloadDigest = spamCommandDigest(spamSystemctlPath, []string{"reload", spamRspamdUnit}, reload)
	if err == nil {
		var probe spamCommandResult
		probe, err = runtime.probe(ctx, generation.ID, storeDigest, generationConfig)
		receipt.ProbeDigest = spamRequestDigest(struct {
			GenerationID string
			StoreDigest  string
			LiveProbe    string
		}{generation.ID, storeDigest, spamCommandDigest(spamSystemctlPath, []string{"is-active", "--quiet", spamRspamdUnit}, probe)})
	}
	if err == nil {
		return receipt, nil
	}
	receipt.RolledBack = true
	rollbackErr := runtime.Store.Rollback(context.WithoutCancel(ctx), previous)
	rollbackCommand, reloadErr := runSpamFixed(context.WithoutCancel(ctx), 20*time.Second, spamSystemctlPath, "reload", spamRspamdUnit)
	receipt.RollbackDigest = spamCommandDigest(spamSystemctlPath, []string{"reload", spamRspamdUnit}, rollbackCommand)
	return receipt, errors.Join(err, rollbackErr, reloadErr)
}

func (runtime *LinuxRspamdPolicyRuntime) SpamStatus(ctx context.Context, desired SpamConfigGeneration) (SpamHealthStatus, error) {
	status := SpamHealthStatus{State: SpamHealthUnavailable, DesiredGeneration: desired.ID, DesiredDigest: desired.ArtifactDigest, Code: "runtime_unavailable"}
	if runtime == nil || runtime.RspamdGID == 0 || runtime.Now == nil || ctx == nil {
		return status, ErrInvalidCommand
	}
	_, storeDigest, err := runtimeArtifacts(desired, runtime.RspamdGID)
	if err != nil {
		return status, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.Store == nil {
		return status, ErrInvalidCommand
	}
	status.CheckedAt = runtime.now()
	current, err := runtime.Store.Current()
	if err != nil {
		status.Code = "generation_store_unavailable"
		return status, err
	}
	status.ActiveGeneration = current
	if current != desired.ID {
		status.State = SpamHealthDrifted
		status.Code = "active_generation_mismatch"
		return status, nil
	}
	status.ActiveDigest = desired.ArtifactDigest
	config := filepath.Join(SpamConfigurationRoot, "generations", desired.ID, "rspamd.conf")
	if _, err = runtime.Store.Verify(desired.ID, storeDigest); err != nil {
		status.State = SpamHealthDrifted
		status.Code = "active_generation_integrity"
		return status, err
	}
	if _, err = runtime.probe(ctx, desired.ID, storeDigest, config); err != nil {
		status.Code = "rspamd_unavailable"
		return status, err
	}
	status.State = SpamHealthHealthy
	status.Code = "ok"
	return status, nil
}

func (runtime *LinuxRspamdPolicyRuntime) probe(ctx context.Context, generationID, storeDigest, config string) (spamCommandResult, error) {
	current, err := runtime.Store.Current()
	if err != nil || current != generationID {
		return spamCommandResult{}, errors.Join(ErrConflict, err)
	}
	if _, err = runtime.Store.Verify(generationID, storeDigest); err != nil {
		return spamCommandResult{}, err
	}
	if _, err = runSpamFixed(ctx, 15*time.Second, spamRspamadmPath, "configtest", "-c", config); err != nil {
		return spamCommandResult{}, err
	}
	return runSpamFixed(ctx, 10*time.Second, spamSystemctlPath, "is-active", "--quiet", spamRspamdUnit)
}

func runtimeArtifacts(generation SpamConfigGeneration, gid uint32) ([]daemoncfg.Artifact, string, error) {
	if gid == 0 || !validSpamID(generation.ID, "spamg_") || !validOpaque(generation.TenantID) || generation.PolicyGeneration == 0 || !validSpamDigest(generation.SnapshotDigest) || !validSpamDigest(generation.ArtifactDigest) || !canonicalSpamTime(generation.CreatedAt) || len(generation.Artifacts) == 0 || len(generation.Artifacts) > 32 {
		return nil, "", ErrInvalidCommand
	}
	artifacts := make([]daemoncfg.Artifact, 0, len(generation.Artifacts))
	seen := make(map[string]struct{}, len(generation.Artifacts))
	artifactHasher := sha256.New()
	for _, artifact := range generation.Artifacts {
		if artifact.Path == "" || filepath.Base(artifact.Path) != artifact.Path || artifact.Mode != 0440 || !validSpamDigest(artifact.SHA256) || len(artifact.Content) > 4<<20 {
			return nil, "", ErrInvalidCommand
		}
		if _, exists := seen[artifact.Path]; exists {
			return nil, "", ErrInvalidCommand
		}
		seen[artifact.Path] = struct{}{}
		sum := sha256.Sum256(artifact.Content)
		if hex.EncodeToString(sum[:]) != artifact.SHA256 {
			return nil, "", ErrInvalidReceipt
		}
		fmt.Fprintf(artifactHasher, "%s\x00%o\x00%s\x00", artifact.Path, artifact.Mode, artifact.SHA256)
		artifacts = append(artifacts, daemoncfg.Artifact{Path: artifact.Path, Mode: artifact.Mode, GID: gid, Content: append([]byte(nil), artifact.Content...), SHA256: artifact.SHA256})
	}
	if hex.EncodeToString(artifactHasher.Sum(nil)) != generation.ArtifactDigest {
		return nil, "", ErrInvalidReceipt
	}
	digest, err := daemoncfg.ComputeDigest(artifacts)
	if err != nil {
		return nil, "", err
	}
	return artifacts, digest, nil
}

type spamCommandResult struct {
	Output   []byte
	Overflow bool
	ExitCode int
}

func runSpamFixed(ctx context.Context, timeout time.Duration, executable string, arguments ...string) (spamCommandResult, error) {
	result := spamCommandResult{ExitCode: -1}
	if ctx == nil || timeout <= 0 || timeout > 30*time.Second || !validSpamFixedCommand(executable, arguments) {
		return result, ErrInvalidCommand
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, executable, arguments...)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdin = nil
	output := &spamBoundedOutput{limit: spamCommandOutputLimit}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	result.Output = append([]byte(nil), output.buffer.Bytes()...)
	result.Overflow = output.overflow
	if command.ProcessState != nil {
		result.ExitCode = command.ProcessState.ExitCode()
	}
	if output.overflow {
		return result, ErrInvalidReceipt
	}
	if commandContext.Err() != nil {
		return result, commandContext.Err()
	}
	if err != nil || result.ExitCode != 0 {
		return result, errors.Join(ErrInvalidReceipt, err)
	}
	return result, nil
}

func validSpamFixedCommand(executable string, arguments []string) bool {
	if executable == spamSystemctlPath {
		return len(arguments) == 2 && arguments[0] == "reload" && arguments[1] == spamRspamdUnit || len(arguments) == 3 && arguments[0] == "is-active" && arguments[1] == "--quiet" && arguments[2] == spamRspamdUnit
	}
	if executable != spamRspamadmPath || len(arguments) != 3 || arguments[0] != "configtest" || arguments[1] != "-c" {
		return false
	}
	prefix := filepath.Join(SpamConfigurationRoot, "generations") + string(filepath.Separator)
	clean := filepath.Clean(arguments[2])
	return clean == arguments[2] && filepath.IsAbs(clean) && filepath.Dir(filepath.Dir(clean)) == filepath.Join(SpamConfigurationRoot, "generations") && filepath.Base(clean) == "rspamd.conf" && len(clean) > len(prefix)
}

type spamBoundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (output *spamBoundedOutput) Write(raw []byte) (int, error) {
	written := len(raw)
	remaining := output.limit - output.buffer.Len()
	if remaining > 0 {
		if remaining > len(raw) {
			remaining = len(raw)
		}
		_, _ = output.buffer.Write(raw[:remaining])
	}
	if remaining < len(raw) {
		output.overflow = true
	}
	return written, nil
}

func spamCommandDigest(executable string, arguments []string, result spamCommandResult) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(executable))
	for _, argument := range arguments {
		_, _ = hasher.Write([]byte{'\x00'})
		_, _ = hasher.Write([]byte(argument))
	}
	_, _ = hasher.Write([]byte(fmt.Sprintf("\x00%d\x00%t\x00", result.ExitCode, result.Overflow)))
	_, _ = hasher.Write(result.Output)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (runtime *LinuxRspamdPolicyRuntime) now() time.Time { return runtime.Now().UTC().Truncate(time.Second) }
