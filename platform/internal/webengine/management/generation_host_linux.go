//go:build linux

package management

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation/fsstore"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

type lifecycleGenerationRecord struct {
	Input      lifecycleGenerationInput `json:"input"`
	Stage      EffectReceipt            `json:"stage"`
	Validation ValidationReceipt        `json:"validation"`
	Probe      ProbeReceipt             `json:"probe"`
}

type lifecycleSwitchRecord struct {
	Request  SwitchRequest      `json:"request"`
	Receipt  SwitchReceipt      `json:"receipt"`
	Previous lifecycleHostState `json:"previous"`
	State    string             `json:"state"`
	Probe    ProbeReceipt       `json:"probe"`
}

type generationRecoveryReceipt struct {
	LeaseID       string        `json:"lease_id"`
	RequestDigest string        `json:"request_digest"`
	Switch        SwitchReceipt `json:"switch"`
	Probe         ProbeReceipt  `json:"probe"`
	CompletedAt   time.Time     `json:"completed_at"`
}

func (host *LinuxLifecycleHost) coordinateConfiguration(ctx context.Context) error {
	if host.configurationRelease != nil {
		return nil
	}
	release, err := activation.LockConfiguration(ctx)
	if err != nil {
		return err
	}
	host.configurationRelease = release
	return nil
}

func (host *LinuxLifecycleHost) releaseConfiguration() {
	if host.configurationRelease != nil && !host.switchPending() {
		host.configurationRelease()
		host.configurationRelease = nil
	}
}

func openLifecycleStore(edition webengine.Edition) (*fsstore.Store, error) {
	info, err := os.Lstat(lifecycleConfigurationRoot)
	if err != nil || !rootOwnedFile(info) {
		return nil, ErrInvalid
	}
	return fsstore.New(lifecycleConfigurationRoot, edition)
}

func generationOperation(operation LinuxManagementOperation) bool {
	switch operation {
	case LinuxManagementStage, LinuxManagementValidate, LinuxManagementShadow, LinuxManagementActiveProbe, LinuxManagementSwitch, LinuxManagementConfirm, LinuxManagementRestore:
		return true
	default:
		return false
	}
}

func renderLifecycleGeneration(ctx context.Context, input lifecycleGenerationInput) (native.ConfigGeneration, error) {
	if input.Request.ExpectedGeneration == 0 || validateLifecycleEffect(input.Request, input.ConfigDigest) != nil {
		return native.ConfigGeneration{}, ErrInvalid
	}
	var renderer native.Renderer
	switch input.Render.Desired.Engine.Edition {
	case webengine.EditionOpenLiteSpeed:
		renderer = ols.New()
	case webengine.EditionLiteSpeedEnterprise:
		renderer = enterprise.New()
	default:
		return native.ConfigGeneration{}, ErrInvalid
	}
	generation, err := renderer.Render(ctx, input.Render)
	if err != nil || generation.ContentDigest != input.ConfigDigest {
		return native.ConfigGeneration{}, errors.Join(ErrConflict, err)
	}
	if len(input.PrivateTLS) != 0 {
		if err = validatePrivateTLSMaterials(input.Render, input.PrivateTLS, time.Now().UTC()); err != nil {
			return native.ConfigGeneration{}, err
		}
	}
	return generation, nil
}

func (host *LinuxLifecycleHost) handleGeneration(ctx context.Context, request LinuxManagementRequest) (any, error) {
	switch request.Operation {
	case LinuxManagementSwitch:
		var input SwitchRequest
		if decodeLifecyclePayload(request.Payload, &input) != nil {
			return nil, ErrInvalid
		}
		return host.switchGeneration(ctx, input)
	case LinuxManagementConfirm, LinuxManagementRestore:
		var input SwitchReceipt
		if decodeLifecyclePayload(request.Payload, &input) != nil {
			return nil, ErrInvalid
		}
		if request.Operation == LinuxManagementRestore {
			return host.restoreGeneration(ctx, input)
		}
		return host.confirmGeneration(ctx, input)
	default:
		if host.switchPending() {
			return nil, ErrConflict
		}
		var input lifecycleGenerationInput
		if decodeLifecyclePayload(request.Payload, &input) != nil {
			return nil, ErrInvalid
		}
		if request.Operation != LinuxManagementShadow && len(input.PrivateTLS) != 0 {
			return nil, ErrInvalid
		}
		if request.Operation == LinuxManagementActiveProbe {
			return host.probeActiveGeneration(ctx, input)
		}
		record, err := host.stageGeneration(ctx, input)
		if err != nil {
			return nil, err
		}
		if request.Operation == LinuxManagementStage {
			return record.Stage, nil
		}
		// Re-run observational checks: cached success is never fresh runtime proof.
		mode := "validate"
		if request.Operation == LinuxManagementShadow {
			mode = "probe"
		}
		observed, err := runLifecycleCandidate(ctx, input, mode)
		if err != nil {
			if mode == "validate" {
				return observed.Validation, err
			}
			return observed.Probe, err
		}
		if mode == "validate" {
			record.Validation = observed.Validation
			host.journal.Generations[input.ConfigDigest] = record
			return observed.Validation, host.persist()
		}
		record.Validation, record.Probe = observed.Validation, observed.Probe
		host.journal.Generations[input.ConfigDigest] = record
		return observed.Probe, host.persist()
	}
}

func (host *LinuxLifecycleHost) probeActiveGeneration(ctx context.Context, input lifecycleGenerationInput) (ProbeReceipt, error) {
	if _, err := renderLifecycleGeneration(ctx, input); err != nil {
		return ProbeReceipt{}, err
	}
	if err := host.adoptGeneration(ctx, input.Request.ExpectedGeneration); err != nil {
		return ProbeReceipt{}, err
	}
	edition, err := readLifecycleEdition()
	if err != nil || edition != input.Render.Desired.Engine.Edition {
		return ProbeReceipt{}, ErrConflict
	}
	store, err := openLifecycleStore(edition)
	if err != nil {
		return ProbeReceipt{}, err
	}
	defer store.Close()
	current, err := store.Current(ctx)
	if err != nil {
		return ProbeReceipt{}, err
	}
	if err = verifyLifecycleService(ctx, host.journal.Host.Plan); err != nil {
		return ProbeReceipt{}, err
	}
	probe, err := probeLifecycleHTTP(ctx, input)
	if err != nil {
		return probe, err
	}
	after, err := store.Current(ctx)
	if err != nil || after.Digest != current.Digest {
		return ProbeReceipt{}, ErrConflict
	}
	probe.EvidenceDigest = digestJSON(struct{ ActiveConfig, SiteProbe string }{current.Digest, probe.EvidenceDigest})
	return probe, nil
}

func (host *LinuxLifecycleHost) stageGeneration(ctx context.Context, input lifecycleGenerationInput) (lifecycleGenerationRecord, error) {
	generation, err := renderLifecycleGeneration(ctx, input)
	if err != nil {
		return lifecycleGenerationRecord{}, err
	}
	if err = host.adoptGeneration(ctx, input.Request.ExpectedGeneration); err != nil {
		return lifecycleGenerationRecord{}, err
	}
	if !host.journal.Host.Active || host.journal.Host.Plan.Edition != generation.Edition {
		return lifecycleGenerationRecord{}, ErrUnsupported
	}
	if err = installedLifecyclePlan(ctx, host.journal.Host.Plan); err != nil {
		return lifecycleGenerationRecord{}, err
	}
	if input.Request.Fence <= host.journal.Host.Fence {
		return lifecycleGenerationRecord{}, ErrConflict
	}
	if host.journal.Generations == nil {
		host.journal.Generations = map[string]lifecycleGenerationRecord{}
	}
	record, exists := host.journal.Generations[input.ConfigDigest]
	if exists && digestJSON(record.Input) != digestJSON(input) {
		return record, ErrConflict
	}
	if !exists && len(host.journal.Generations) >= 32 {
		oldest := ""
		for digest, candidate := range host.journal.Generations {
			if digest == host.journal.Host.ConfigDigest || host.journal.Switch != nil && (digest == host.journal.Switch.Receipt.PreviousConfigDigest || digest == host.journal.Switch.Receipt.TargetConfigDigest) {
				continue
			}
			if oldest == "" || candidate.Stage.ObservedAt.Before(host.journal.Generations[oldest].Stage.ObservedAt) {
				oldest = digest
			}
		}
		if oldest == "" {
			return record, ErrConflict
		}
		delete(host.journal.Generations, oldest)
	}
	store, err := openLifecycleStore(generation.Edition)
	if err != nil {
		return record, err
	}
	defer store.Close()
	staged, err := store.Stage(ctx, generation)
	if err != nil {
		return record, err
	}
	if _, err = store.GenerationPath(ctx, staged); err != nil {
		return record, err
	}
	if !exists {
		record.Input = input
		record.Stage = EffectReceipt{EffectID: input.Request.EffectID, PlanDigest: input.Request.PlanDigest, EvidenceDigest: staged.Digest, Generation: input.Request.ExpectedGeneration + 1, Fence: input.Request.Fence, Outcome: "staged", ObservedAt: host.now().UTC()}
		host.journal.Generations[input.ConfigDigest] = record
		if err = host.persist(); err != nil {
			delete(host.journal.Generations, input.ConfigDigest)
			return record, err
		}
	}
	return record, nil
}

func (host *LinuxLifecycleHost) switchPending() bool {
	return host.conversionPending() || host.journal.Switch != nil && host.journal.Switch.State != "confirmed" && host.journal.Switch.State != "restored"
}

func (host *LinuxLifecycleHost) switchGeneration(ctx context.Context, input SwitchRequest) (SwitchReceipt, error) {
	if host.journal.Switch != nil && host.journal.Switch.Request.EffectRequest.EffectID == input.EffectRequest.EffectID {
		if digestJSON(host.journal.Switch.Request) != digestJSON(input) {
			return SwitchReceipt{}, ErrConflict
		}
		if host.journal.Switch.State != "switched" && host.journal.Switch.State != "confirmed" && host.journal.Switch.State != "restored" {
			return host.journal.Switch.Receipt, ErrAmbiguous
		}
		return host.journal.Switch.Receipt, nil
	}
	if host.switchPending() || validateLifecycleEffect(input.EffectRequest, input.TargetConfigDigest) != nil || !validSHA256(input.PreviousConfigDigest) || !input.RollbackDeadline.After(host.now().Add(time.Minute)) || input.RollbackDeadline.After(host.now().Add(24*time.Hour)) {
		return SwitchReceipt{}, ErrInvalid
	}
	// Package replacement cannot be hidden inside a configuration switch. A
	// matching edition must already have passed signed-package admission.
	edition, err := readLifecycleEdition()
	if err != nil || edition != input.Target || input.Previous != input.Target {
		return SwitchReceipt{}, ErrUnsupported
	}
	if err = host.adoptGeneration(ctx, input.EffectRequest.ExpectedGeneration); err != nil {
		return SwitchReceipt{}, err
	}
	if !host.journal.Host.Active || host.journal.Host.Plan.Edition != input.Previous || host.journal.Host.Fence >= input.EffectRequest.Fence {
		return SwitchReceipt{}, ErrConflict
	}
	target, found := host.journal.Generations[input.TargetConfigDigest]
	previous, previousFound := host.journal.Generations[input.PreviousConfigDigest]
	if !found || !previousFound || digestJSON(target.Input.Request) != digestJSON(input.EffectRequest) || target.Input.Render.Desired.Engine.Edition != input.Target || !target.Validation.Valid || !target.Probe.PHP || !validSHA256(target.Probe.EvidenceDigest) || target.Probe.ObservedAt.Before(host.now().Add(-5*time.Minute)) || previous.Input.Render.Desired.Engine.Edition != input.Previous {
		return SwitchReceipt{}, ErrConflict
	}
	store, err := openLifecycleStore(edition)
	if err != nil {
		return SwitchReceipt{}, err
	}
	defer store.Close()
	current, err := store.Current(ctx)
	if err != nil || current.Digest != input.PreviousConfigDigest {
		return SwitchReceipt{}, ErrConflict
	}
	if err = verifyLifecycleService(ctx, host.journal.Host.Plan); err != nil {
		return SwitchReceipt{}, err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return SwitchReceipt{}, err
	}
	now := host.now().UTC()
	receipt := SwitchReceipt{EffectID: input.EffectRequest.EffectID, Previous: input.Previous, Target: input.Target, PreviousConfigDigest: input.PreviousConfigDigest, TargetConfigDigest: input.TargetConfigDigest, LeaseID: "generation-" + input.EffectRequest.EffectID, ConfirmNonce: hex.EncodeToString(nonce[:]), Fence: input.EffectRequest.Fence, SwitchedAt: now, RollbackDeadline: input.RollbackDeadline}
	state := host.journal.Host
	state.ConfigDigest = current.Digest
	previousSwitch := host.journal.Switch
	host.journal.Switch = &lifecycleSwitchRecord{Request: input, Receipt: receipt, Previous: state, State: "switching"}
	if err = host.persist(); err != nil {
		host.journal.Switch = previousSwitch
		return receipt, err
	}
	go host.generationWatchdog(receipt)
	if err = store.SwapMaster(ctx, activation.Receipt{Edition: edition, Digest: input.TargetConfigDigest}); err == nil {
		err = runLifecycle(ctx, lifecycleBinaryPath, "-t")
	}
	if err == nil {
		err = runLifecycle(ctx, "/usr/bin/systemctl", "restart", lifecycleService)
	}
	if err == nil {
		err = verifyLifecycleService(ctx, host.journal.Host.Plan)
	}
	if err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		_, rollbackErr := host.restoreGeneration(rollbackCtx, receipt)
		cancel()
		return host.journal.Switch.Receipt, errors.Join(ErrAmbiguous, err, rollbackErr)
	}
	host.journal.Switch.State = "switched"
	host.journal.Host.Generation, host.journal.Host.Fence = input.EffectRequest.ExpectedGeneration+1, input.EffectRequest.Fence
	host.journal.Host.ConfigDigest, host.journal.Host.UpdatedAt = input.TargetConfigDigest, now
	if err = host.persist(); err != nil {
		return receipt, errors.Join(ErrAmbiguous, err)
	}
	return receipt, nil
}

func (host *LinuxLifecycleHost) checkSwitch(input SwitchReceipt) error {
	if host.journal.Switch == nil {
		return ErrNotFound
	}
	expected := host.journal.Switch.Receipt
	// Mutable outcome fields are observations, not authorization credentials.
	input.Confirmed, input.Restored, input.EvidenceDigest = false, false, ""
	expected.Confirmed, expected.Restored, expected.EvidenceDigest = false, false, ""
	if digestJSON(input) != digestJSON(expected) {
		return ErrConflict
	}
	return nil
}

func (host *LinuxLifecycleHost) confirmGeneration(ctx context.Context, input SwitchReceipt) (ProbeReceipt, error) {
	if err := host.checkSwitch(input); err != nil {
		return ProbeReceipt{}, err
	}
	record := host.journal.Switch
	if record.State == "confirmed" {
		return record.Probe, nil
	}
	if record.State != "switched" || !host.now().Before(input.RollbackDeadline) {
		return ProbeReceipt{}, ErrConflict
	}
	if host.journal.Host.Fence != input.Fence || host.journal.Host.ConfigDigest != input.TargetConfigDigest {
		return ProbeReceipt{}, ErrConflict
	}
	candidate := host.journal.Generations[input.TargetConfigDigest]
	probe, err := probeLifecycleHTTP(ctx, candidate.Input)
	if err != nil {
		return probe, err
	}
	store, err := openLifecycleStore(input.Target)
	if err != nil {
		return probe, err
	}
	defer store.Close()
	if err = verifyLifecycleService(ctx, host.journal.Host.Plan); err != nil {
		return probe, err
	}
	if err = store.Confirm(ctx, activation.Receipt{Edition: input.Target, Digest: input.TargetConfigDigest}); err != nil {
		return probe, err
	}
	record.State, record.Probe = "confirmed", probe
	record.Receipt.Confirmed, record.Receipt.EvidenceDigest = true, probe.EvidenceDigest
	if err = host.persist(); err != nil {
		record.State = "switched"
		record.Receipt.Confirmed = false
		return probe, errors.Join(ErrAmbiguous, err)
	}
	return probe, nil
}

func (host *LinuxLifecycleHost) restoreGeneration(ctx context.Context, input SwitchReceipt) (ProbeReceipt, error) {
	if err := host.checkSwitch(input); err != nil {
		return ProbeReceipt{}, err
	}
	record := host.journal.Switch
	if record.State == "restored" {
		return record.Probe, nil
	}
	if record.State == "confirmed" {
		return ProbeReceipt{}, ErrConflict
	}
	if host.journal.Host.Fence > input.Fence {
		return ProbeReceipt{}, ErrConflict
	}
	record.State = "restoring"
	if err := host.persist(); err != nil {
		return ProbeReceipt{}, err
	}
	store, err := openLifecycleStore(input.Previous)
	if err != nil {
		return ProbeReceipt{}, err
	}
	defer store.Close()
	previous := activation.Receipt{Edition: input.Previous, Digest: input.PreviousConfigDigest}
	if err = store.RestoreMaster(ctx, previous); err == nil {
		err = runLifecycle(ctx, lifecycleBinaryPath, "-t")
	}
	if err == nil {
		err = runLifecycle(ctx, "/usr/bin/systemctl", "restart", lifecycleService)
	}
	if err == nil {
		err = verifyLifecycleService(ctx, record.Previous.Plan)
	}
	if err != nil {
		return ProbeReceipt{}, errors.Join(ErrAmbiguous, err)
	}
	baseline, found := host.journal.Generations[input.PreviousConfigDigest]
	if !found {
		return ProbeReceipt{}, ErrAmbiguous
	}
	probe, err := probeLifecycleHTTP(ctx, baseline.Input)
	if err != nil {
		return probe, errors.Join(ErrAmbiguous, err)
	}
	if err = store.Confirm(ctx, previous); err != nil {
		return probe, err
	}
	host.journal.Host = record.Previous
	// Rollback consumes the fence; a stale command must never become valid again.
	host.journal.Host.Generation, host.journal.Host.Fence = record.Request.EffectRequest.ExpectedGeneration+1, input.Fence
	host.journal.Host.UpdatedAt = host.now().UTC()
	record.State, record.Probe = "restored", probe
	record.Receipt.Restored, record.Receipt.EvidenceDigest = true, probe.EvidenceDigest
	if err = host.persist(); err != nil {
		record.State = "restoring"
		record.Receipt.Restored = false
		return probe, errors.Join(ErrAmbiguous, err)
	}
	return probe, nil
}

func (host *LinuxLifecycleHost) recoverGenerationSwitch(ctx context.Context) error {
	if host.journal.Switch == nil || host.journal.Switch.State == "confirmed" {
		return nil
	}
	record := host.journal.Switch
	if record.State != "switching" && record.State != "switched" && record.State != "restoring" && record.State != "restored" {
		return ErrAmbiguous
	}
	baseReceipt := record.Receipt
	baseReceipt.Confirmed, baseReceipt.Restored, baseReceipt.EvidenceDigest = false, false, ""
	requestDigest := rebootcontrol.ExecutionDigest(struct {
		Request  SwitchRequest      `json:"request"`
		Receipt  SwitchReceipt      `json:"receipt"`
		Previous lifecycleHostState `json:"previous"`
	}{Request: record.Request, Receipt: baseReceipt, Previous: record.Previous})
	lease, err := host.admission.AdmitExecution(ctx, rebootcontrol.ExecutionBinding{
		Boundary:      "webengine-management-recovery",
		Method:        "generation_switch_rollback",
		EffectID:      record.Receipt.LeaseID,
		RequestDigest: requestDigest,
		Caller:        "panel-execd-recovery",
		Resource: rebootcontrol.ExecutionResource(struct {
			Effect   string `json:"effect"`
			Previous string `json:"previous"`
			Target   string `json:"target"`
			Fence    uint64 `json:"fence"`
		}{Effect: record.Request.EffectRequest.EffectID, Previous: record.Request.PreviousConfigDigest, Target: record.Request.TargetConfigDigest, Fence: record.Request.EffectRequest.Fence}),
	})
	if err != nil {
		return err
	}
	if len(lease.Cached) != 0 {
		var receipt generationRecoveryReceipt
		if json.Unmarshal(lease.Cached, &receipt) != nil || !host.validGenerationRecoveryReceipt(receipt, requestDigest) {
			return rebootcontrol.ErrIntegrity
		}
		host.releaseConfiguration()
		return nil
	}
	defer func() { _ = rebootcontrol.SettleExecution(host.admission, lease, false, nil) }()
	if record.State != "restored" {
		if err = host.coordinateConfiguration(ctx); err != nil {
			return err
		}
		if _, err = host.restoreGeneration(ctx, record.Receipt); err != nil {
			return err
		}
	}
	host.releaseConfiguration()
	receipt := generationRecoveryReceipt{
		LeaseID:       record.Receipt.LeaseID,
		RequestDigest: requestDigest,
		Switch:        record.Receipt,
		Probe:         record.Probe,
		CompletedAt:   host.now().UTC(),
	}
	if !host.validGenerationRecoveryReceipt(receipt, requestDigest) {
		return ErrAmbiguous
	}
	return rebootcontrol.SettleExecution(host.admission, lease, true, receipt)
}

func (host *LinuxLifecycleHost) validGenerationRecoveryReceipt(receipt generationRecoveryReceipt, requestDigest string) bool {
	record := host.journal.Switch
	if record == nil || record.State != "restored" || !record.Receipt.Restored || record.Receipt.Confirmed || receipt.LeaseID != record.Receipt.LeaseID || receipt.RequestDigest != requestDigest ||
		digestJSON(receipt.Switch) != digestJSON(record.Receipt) || digestJSON(receipt.Probe) != digestJSON(record.Probe) || receipt.CompletedAt.IsZero() || receipt.CompletedAt.After(host.now().UTC().Add(time.Minute)) {
		return false
	}
	if record.Probe.EffectID != record.Receipt.EffectID || record.Probe.ConfigDigest != record.Receipt.PreviousConfigDigest || !record.Probe.PHP || !validSHA256(record.Probe.EvidenceDigest) || record.Probe.ObservedAt.IsZero() || record.Receipt.EvidenceDigest != record.Probe.EvidenceDigest {
		return false
	}
	return host.journal.Host.ConfigDigest == record.Receipt.PreviousConfigDigest && host.journal.Host.Fence == record.Receipt.Fence && host.journal.Host.Generation == record.Request.EffectRequest.ExpectedGeneration+1
}

func (host *LinuxLifecycleHost) generationWatchdog(receipt SwitchReceipt) {
	timer := time.NewTimer(time.Until(receipt.RollbackDeadline))
	defer timer.Stop()
	<-timer.C
	for {
		host.mu.Lock()
		if host.checkSwitch(receipt) != nil || host.journal.Switch.State == "confirmed" {
			host.mu.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := host.recoverGenerationSwitch(ctx)
		cancel()
		host.mu.Unlock()
		if err == nil || !errors.Is(err, rebootcontrol.ErrConflict) {
			return
		}
		retry := time.NewTimer(30 * time.Second)
		<-retry.C
	}
}
