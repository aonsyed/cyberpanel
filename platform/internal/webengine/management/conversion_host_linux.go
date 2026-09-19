//go:build linux

package management

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

const (
	conversionPhaseBackupLicense         = "backup_license"
	conversionPhasePreflight             = "preflight"
	conversionPhaseMaskStop              = "mask_stop"
	conversionPhaseRemovePrevious        = "remove_previous"
	conversionPhaseInstallTarget         = "install_target"
	conversionPhaseConfigureTarget       = "configure_target"
	conversionPhaseLicenseTarget         = "license_target"
	conversionPhaseStartTarget           = "start_target"
	conversionPhaseProbeTarget           = "probe_target"
	conversionPhaseConfirmTarget         = "confirm_target"
	conversionPhaseConfirmed             = "confirmed"
	conversionPhaseRollbackVerify        = "rollback_verify"
	conversionPhaseRollbackStop          = "rollback_stop"
	conversionPhaseRollbackRemoveTarget  = "rollback_remove_target"
	conversionPhaseRollbackInstallPrior  = "rollback_install_previous"
	conversionPhaseRollbackConfiguration = "rollback_configuration"
	conversionPhaseRollbackLicense       = "rollback_license"
	conversionPhaseRollbackService       = "rollback_service"
	conversionPhaseRollbackProbe         = "rollback_probe"
	conversionPhaseRollbackConfirm       = "rollback_confirm"
	conversionPhaseRestored              = "restored"
)

type conversionPackage struct {
	Artifact PackageArtifact `json:"artifact"`
	Path     string          `json:"path"`
}

type conversionLicenseFile struct {
	Name    string `json:"name"`
	Digest  string `json:"digest,omitempty"`
	Present bool   `json:"present"`
}

type conversionServiceState struct {
	Enablement string `json:"enablement"`
	Active     bool   `json:"active"`
}

type lifecycleConversionRecord struct {
	Input            lifecycleConvertInput   `json:"input"`
	Previous         lifecycleHostState      `json:"previous"`
	PreviousService  conversionServiceState  `json:"previous_service"`
	PreviousLicense  LicenseStatus           `json:"previous_license"`
	TargetLicense    LicenseStatus           `json:"target_license,omitempty"`
	PreviousFiles    []conversionLicenseFile `json:"previous_license_files,omitempty"`
	PreviousPackages []conversionPackage     `json:"previous_packages"`
	TargetPackages   []conversionPackage     `json:"target_packages"`
	CatalogDigest    string                  `json:"catalog_digest"`
	CatalogSequence  uint64                  `json:"catalog_sequence"`
	HostDigest       string                  `json:"host_digest"`
	ImageDigest      string                  `json:"image_digest,omitempty"`
	Phase            string                  `json:"phase"`
	Probe            ProbeReceipt            `json:"probe,omitempty"`
	RollbackProbe    ProbeReceipt            `json:"rollback_probe,omitempty"`
	Receipt          SwitchReceipt           `json:"receipt"`
	UpdatedAt        time.Time               `json:"updated_at"`
}

func (host *LinuxLifecycleHost) conversionPending() bool {
	return host.journal.Conversion != nil && host.journal.Conversion.Phase != conversionPhaseConfirmed && host.journal.Conversion.Phase != conversionPhaseRestored
}

func conversionGeneration(ctx context.Context, request EffectRequest, render native.RenderRequest) (lifecycleGenerationInput, native.ConfigGeneration, error) {
	if ctx == nil {
		return lifecycleGenerationInput{}, native.ConfigGeneration{}, ErrInvalid
	}
	var renderer native.Renderer
	switch render.Desired.Engine.Edition {
	case webengine.EditionOpenLiteSpeed:
		renderer = ols.New()
	case webengine.EditionLiteSpeedEnterprise:
		renderer = enterprise.New()
	default:
		return lifecycleGenerationInput{}, native.ConfigGeneration{}, ErrInvalid
	}
	generation, err := renderer.Render(ctx, render)
	if err != nil {
		return lifecycleGenerationInput{}, generation, err
	}
	request.PlanDigest = generation.ContentDigest
	input := lifecycleGenerationInput{Request: request, Render: render, ConfigDigest: generation.ContentDigest}
	_, err = renderLifecycleGeneration(ctx, input)
	return input, generation, err
}

func (host *LinuxLifecycleHost) convertEdition(ctx context.Context, input lifecycleConvertInput) (SwitchReceipt, error) {
	if record := host.journal.Conversion; record != nil && record.Input.Request.EffectID == input.Request.EffectID {
		if digestJSON(record.Input) != digestJSON(input) {
			return SwitchReceipt{}, ErrConflict
		}
		if record.Phase == conversionPhaseConfirmed {
			return record.Receipt, nil
		}
		if record.Phase == conversionPhaseRestored {
			return record.Receipt, ErrInvalid
		}
		return host.reconcileEdition(ctx)
	}
	selection := conversionSelection(input.Request, input.Plan.Edition)
	localOS, localVersion, localArchitecture, tupleErr := localPlatformTuple()
	if tupleErr != nil || selection.OS != localOS || selection.OSVersion != localVersion || selection.Architecture != localArchitecture ||
		selection.Version != input.Plan.Version || !validChannel(selection.Channel) ||
		host.switchPending() || input.Request.ExpectedGeneration == 0 ||
		!validConversionLicense(input.Plan.Edition, input.License) || input.License != conversionLicense(input.Request) ||
		input.RollbackWindow < time.Minute || input.RollbackWindow > 24*time.Hour || validateArtifactPlan(input.Plan) != nil ||
		validateLifecycleEffect(input.Request, ConversionPlanDigest(selection, input.Plan, input.Generation.ContentDigest, input.License, input.RollbackWindow)) != nil {
		return SwitchReceipt{}, ErrInvalid
	}
	targetInput, target, err := conversionGeneration(ctx, input.Request, input.Target)
	if err != nil || target.ContentDigest != input.Generation.ContentDigest || target.Edition != input.Plan.Edition {
		return SwitchReceipt{}, errors.Join(ErrInvalid, err)
	}
	supplied, err := nativeGeneration(input.Generation)
	if err != nil || supplied.ContentDigest != target.ContentDigest || supplied.Edition != target.Edition || supplied.SnapshotGeneration != target.SnapshotGeneration {
		return SwitchReceipt{}, errors.Join(ErrInvalid, err)
	}
	previousInput, previous, err := conversionGeneration(ctx, input.Request, input.Previous)
	if err != nil || previous.ContentDigest != input.PreviousConfigDigest || previous.Edition == target.Edition {
		return SwitchReceipt{}, errors.Join(ErrInvalid, err)
	}
	if err = host.adoptGeneration(ctx, input.Request.ExpectedGeneration); err != nil {
		return SwitchReceipt{}, err
	}
	if !host.journal.Host.Active || host.journal.Host.Plan.Edition != previous.Edition || host.journal.Host.Fence >= input.Request.Fence {
		return SwitchReceipt{}, ErrConflict
	}
	if err = verifyLifecycleService(ctx, host.journal.Host.Plan); err != nil {
		return SwitchReceipt{}, err
	}
	store, err := openLifecycleStore(previous.Edition)
	if err != nil {
		return SwitchReceipt{}, err
	}
	current, currentErr := store.Current(ctx)
	closeErr := store.Close()
	if currentErr != nil || closeErr != nil || current.Digest != previous.ContentDigest {
		return SwitchReceipt{}, errors.Join(ErrConflict, currentErr, closeErr)
	}
	catalogValue, err := readLocalArtifactCatalog(true)
	if err != nil {
		return SwitchReceipt{}, err
	}
	if err = host.validateEngineCatalog(catalogValue); err != nil {
		return SwitchReceipt{}, err
	}
	previousPackages, previousChannel, err := pinConversionPlan(ctx, catalogValue, host.journal.Host.Plan, host.journal.Host.Channel)
	if err != nil {
		return SwitchReceipt{}, err
	}
	targetPackages, targetChannel, err := pinConversionPlan(ctx, catalogValue, input.Plan, selection.Channel)
	if err != nil {
		return SwitchReceipt{}, err
	}
	service, err := captureConversionService(ctx)
	if err != nil {
		return SwitchReceipt{}, err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return SwitchReceipt{}, err
	}
	now := host.now().UTC()
	receipt := SwitchReceipt{
		EffectID: input.Request.EffectID, Previous: previous.Edition, Target: target.Edition,
		PreviousConfigDigest: previous.ContentDigest, TargetConfigDigest: target.ContentDigest,
		Fence: input.Request.Fence, LeaseID: "edition-" + input.Request.EffectID,
		ConfirmNonce: hex.EncodeToString(nonce[:]), SwitchedAt: now, RollbackDeadline: now.Add(input.RollbackWindow),
		ConversionDigest: input.Request.PlanDigest, PreviousPlan: host.journal.Host.Plan, TargetPlan: input.Plan,
		PreviousPlanDigest: digestJSON(host.journal.Host.Plan), TargetPlanDigest: digestJSON(input.Plan),
		PreviousChannel: previousChannel, TargetChannel: targetChannel,
		CatalogDigest: catalogValue.Digest, CatalogSequence: catalogValue.Sequence,
	}
	state := host.journal.Host
	state.ConfigDigest = previous.ContentDigest
	state.Channel = previousChannel
	record := &lifecycleConversionRecord{
		Input: input, Previous: state, PreviousService: service, PreviousLicense: host.journal.License,
		PreviousPackages: previousPackages, TargetPackages: targetPackages,
		CatalogDigest: catalogValue.Digest, CatalogSequence: catalogValue.Sequence,
		Phase: conversionPhaseBackupLicense, Receipt: receipt, UpdatedAt: now,
	}
	record.HostDigest = conversionHostDigest(record)
	record.Receipt.HostDigest = record.HostDigest
	host.journal.Conversion = record
	host.journal.EngineCatalogSequence, host.journal.EngineCatalogDigest = catalogValue.Sequence, catalogValue.Digest
	if err = host.persist(); err != nil {
		// Retain the admitted record in memory. persist uses an atomic rename,
		// so a directory-sync failure is ambiguous and discarding the record
		// could allow a duplicate admission in this process.
		return receipt, err
	}
	go host.conversionWatchdog(receipt.EffectID, receipt.RollbackDeadline)
	deadlineCtx, cancel := context.WithDeadline(ctx, receipt.RollbackDeadline)
	defer cancel()
	receipt, err = host.continueEdition(deadlineCtx, targetInput, target, previousInput)
	if err == nil {
		return receipt, nil
	}
	rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
	defer rollbackCancel()
	restored, rollbackErr := host.rollbackEdition(rollbackCtx)
	return restored, errors.Join(err, rollbackErr)
}

func (host *LinuxLifecycleHost) reconcileEdition(ctx context.Context) (SwitchReceipt, error) {
	record := host.journal.Conversion
	if record == nil {
		return SwitchReceipt{}, ErrNotFound
	}
	if record.Phase == conversionPhaseConfirmed {
		return record.Receipt, nil
	}
	if record.Phase == conversionPhaseRestored {
		return record.Receipt, ErrInvalid
	}
	if !validConversionRecord(record) {
		return record.Receipt, ErrConflict
	}
	if strings.HasPrefix(record.Phase, "rollback_") || !host.now().Before(record.Receipt.RollbackDeadline) {
		return host.rollbackEdition(ctx)
	}
	targetInput, target, err := conversionGeneration(ctx, record.Input.Request, record.Input.Target)
	if err != nil || target.ContentDigest != record.Input.Generation.ContentDigest {
		return record.Receipt, errors.Join(ErrConflict, err)
	}
	previousInput, previous, err := conversionGeneration(ctx, record.Input.Request, record.Input.Previous)
	if err != nil || previous.ContentDigest != record.Input.PreviousConfigDigest {
		return record.Receipt, errors.Join(ErrConflict, err)
	}
	deadlineCtx, cancel := context.WithDeadline(ctx, record.Receipt.RollbackDeadline)
	defer cancel()
	receipt, err := host.continueEdition(deadlineCtx, targetInput, target, previousInput)
	if err == nil {
		return receipt, nil
	}
	rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
	defer rollbackCancel()
	restored, rollbackErr := host.rollbackEdition(rollbackCtx)
	return restored, errors.Join(err, rollbackErr)
}

func (host *LinuxLifecycleHost) continueEdition(ctx context.Context, targetInput lifecycleGenerationInput, target native.ConfigGeneration, previousInput lifecycleGenerationInput) (SwitchReceipt, error) {
	for {
		record := host.journal.Conversion
		if record == nil {
			return SwitchReceipt{}, ErrNotFound
		}
		if err := ctx.Err(); err != nil {
			return record.Receipt, err
		}
		switch record.Phase {
		case conversionPhaseBackupLicense:
			files, err := backupConversionLicense(record)
			if err != nil {
				return record.Receipt, err
			}
			record.PreviousFiles = files
			if record.Previous.Plan.Edition == webengine.EditionLiteSpeedEnterprise {
				if record.PreviousLicense.ReceiptDigest != licenseReceiptDigest(record.PreviousLicense, record.Input.Request) || !conversionLicenseUsable(record.PreviousLicense, previousInput) {
					record.PreviousLicense, err = observeConversionLicense(ctx, record.PreviousLicense, previousInput, record.Input.Request)
					if err != nil {
						return record.Receipt, err
					}
				}
			}
			if _, err = probeLifecycleHTTP(ctx, previousInput); err != nil {
				return record.Receipt, err
			}
			if err = host.persist(); err != nil {
				return record.Receipt, err
			}
			if err = host.conversionPhase(conversionPhasePreflight); err != nil {
				return record.Receipt, err
			}
		case conversionPhasePreflight:
			digest, err := stageConversionImage(ctx, record, target)
			if err != nil {
				return record.Receipt, err
			}
			record.ImageDigest = digest
			if err = host.persist(); err != nil {
				return record.Receipt, err
			}
			if _, err = runConversionCandidate(ctx, targetInput, record); err != nil {
				return record.Receipt, err
			}
			if err = host.conversionPhase(conversionPhaseMaskStop); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseMaskStop:
			if err := stopConversionService(ctx); err != nil {
				return record.Receipt, err
			}
			if err := host.conversionPhase(conversionPhaseRemovePrevious); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseRemovePrevious:
			if err := runConversionPackages(ctx, record, "remove_previous"); err != nil {
				return record.Receipt, err
			}
			if err := host.conversionPhase(conversionPhaseInstallTarget); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseInstallTarget:
			if err := runConversionPackages(ctx, record, "install_target"); err != nil {
				return record.Receipt, err
			}
			if err := host.conversionPhase(conversionPhaseConfigureTarget); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseConfigureTarget:
			if err := ensureConversionGeneration(ctx, targetInput); err != nil {
				return record.Receipt, err
			}
			if err := host.conversionPhase(conversionPhaseLicenseTarget); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseLicenseTarget:
			license := record.TargetLicense
			if !storedConversionLicenseUsable(license, record.Input.License, targetInput, record.Input.Request) {
				var err error
				license, err = reconcileTargetLicense(ctx, record.Input.License, targetInput, record.Input.Request)
				if err != nil {
					return record.Receipt, err
				}
			}
			record.TargetLicense, host.journal.License = license, license
			if err := host.persist(); err != nil {
				return record.Receipt, err
			}
			if err := host.conversionPhase(conversionPhaseStartTarget); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseStartTarget:
			if _, err := runLifecycleOutput(ctx, lifecycleBinaryPath, "-t"); err != nil {
				return record.Receipt, err
			}
			if err := restoreConversionService(ctx, record.PreviousService); err != nil {
				return record.Receipt, err
			}
			if err := verifyConversionTarget(ctx, record, targetInput); err != nil {
				return record.Receipt, err
			}
			if err := host.conversionPhase(conversionPhaseProbeTarget); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseProbeTarget:
			probe, err := probeLifecycleHTTP(ctx, targetInput)
			if err != nil {
				return record.Receipt, err
			}
			record.Probe = probe
			if err = host.persist(); err != nil {
				return record.Receipt, err
			}
			if err = host.conversionPhase(conversionPhaseConfirmTarget); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseConfirmTarget:
			if record.Probe.ObservedAt.Before(host.now().Add(-5 * time.Minute)) {
				probe, err := probeLifecycleHTTP(ctx, targetInput)
				if err != nil {
					return record.Receipt, err
				}
				record.Probe = probe
				if err = host.persist(); err != nil {
					return record.Receipt, err
				}
			}
			if !host.now().Before(record.Receipt.RollbackDeadline) {
				return record.Receipt, ErrConflict
			}
			if err := confirmConversionGeneration(ctx, targetInput); err != nil {
				return record.Receipt, err
			}
			if currentLifecycleConfig(ctx, record.Input.Plan.Edition) != targetInput.ConfigDigest {
				return record.Receipt, ErrConflict
			}
			if err := verifyConversionTarget(ctx, record, targetInput); err != nil {
				return record.Receipt, err
			}
			host.journal.Host = lifecycleHostState{Active: true, Generation: record.Input.Request.ExpectedGeneration + 1, Fence: record.Input.Request.Fence, Channel: record.Receipt.TargetChannel, Plan: record.Input.Plan, ConfigDigest: target.ContentDigest, UpdatedAt: host.now().UTC()}
			record.Receipt.Confirmed = true
			record.Receipt.ProbeDigest = record.Probe.EvidenceDigest
			record.Receipt.License = record.TargetLicense
			record.Receipt.LicenseDigest = digestJSON(record.TargetLicense)
			record.Receipt.EvidenceDigest = conversionEvidence(record)
			record.Phase, record.UpdatedAt = conversionPhaseConfirmed, host.now().UTC()
			if err := host.persist(); err != nil {
				return record.Receipt, errors.Join(ErrAmbiguous, err)
			}
			return record.Receipt, nil
		case conversionPhaseConfirmed:
			return record.Receipt, nil
		default:
			return record.Receipt, ErrConflict
		}
	}
}

func (host *LinuxLifecycleHost) conversionPhase(phase string) error {
	if host.journal.Conversion == nil {
		return ErrNotFound
	}
	host.journal.Conversion.Phase = phase
	host.journal.Conversion.UpdatedAt = host.now().UTC()
	return host.persist()
}

func (host *LinuxLifecycleHost) rollbackEdition(ctx context.Context) (SwitchReceipt, error) {
	record := host.journal.Conversion
	if record == nil {
		return SwitchReceipt{}, ErrNotFound
	}
	if record.Phase == conversionPhaseRestored {
		return record.Receipt, nil
	}
	if record.Phase == conversionPhaseConfirmed || host.journal.Host.Fence > record.Input.Request.Fence {
		return record.Receipt, ErrConflict
	}
	previousInput, _, err := conversionGeneration(ctx, record.Input.Request, record.Input.Previous)
	if err != nil {
		return record.Receipt, err
	}
	if !strings.HasPrefix(record.Phase, "rollback_") {
		phase := conversionPhaseRollbackStop
		if record.Phase == conversionPhaseBackupLicense || record.Phase == conversionPhasePreflight {
			phase = conversionPhaseRollbackVerify
		}
		if err = host.conversionPhase(phase); err != nil {
			return record.Receipt, err
		}
	}
	for {
		record = host.journal.Conversion
		if err = ctx.Err(); err != nil {
			return record.Receipt, err
		}
		switch record.Phase {
		case conversionPhaseRollbackVerify:
			if err = verifyPreviousConversionState(ctx, record, previousInput); err != nil {
				return record.Receipt, errors.Join(ErrAmbiguous, err)
			}
			probe, probeErr := probeLifecycleHTTP(ctx, previousInput)
			if probeErr != nil {
				return record.Receipt, errors.Join(ErrAmbiguous, probeErr)
			}
			record.RollbackProbe = probe
			if err = host.persist(); err != nil {
				return record.Receipt, err
			}
			if err = host.conversionPhase(conversionPhaseRollbackConfirm); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseRollbackStop:
			if err = stopConversionService(ctx); err != nil {
				return record.Receipt, err
			}
			if err = host.conversionPhase(conversionPhaseRollbackRemoveTarget); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseRollbackRemoveTarget:
			if err = runConversionPackages(ctx, record, "remove_target"); err != nil {
				return record.Receipt, errors.Join(ErrAmbiguous, err)
			}
			if err = host.conversionPhase(conversionPhaseRollbackInstallPrior); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseRollbackInstallPrior:
			if err = runConversionPackages(ctx, record, "install_previous"); err != nil {
				return record.Receipt, errors.Join(ErrAmbiguous, err)
			}
			if err = host.conversionPhase(conversionPhaseRollbackConfiguration); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseRollbackConfiguration:
			if err = ensureConversionGeneration(ctx, previousInput); err != nil {
				return record.Receipt, err
			}
			if err = host.conversionPhase(conversionPhaseRollbackLicense); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseRollbackLicense:
			if err = restoreConversionLicense(record); err != nil {
				return record.Receipt, err
			}
			if err = host.conversionPhase(conversionPhaseRollbackService); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseRollbackService:
			if _, err = runLifecycleOutput(ctx, lifecycleBinaryPath, "-t"); err != nil {
				return record.Receipt, err
			}
			if err = restoreConversionService(ctx, record.PreviousService); err != nil {
				return record.Receipt, err
			}
			if err = confirmConversionGeneration(ctx, previousInput); err != nil {
				return record.Receipt, err
			}
			if err = verifyPreviousConversionState(ctx, record, previousInput); err != nil {
				return record.Receipt, err
			}
			if err = host.conversionPhase(conversionPhaseRollbackProbe); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseRollbackProbe:
			if err = confirmConversionGeneration(ctx, previousInput); err != nil {
				return record.Receipt, err
			}
			probe, probeErr := probeLifecycleHTTP(ctx, previousInput)
			if probeErr != nil {
				return record.Receipt, errors.Join(ErrAmbiguous, probeErr)
			}
			record.RollbackProbe = probe
			if err = host.persist(); err != nil {
				return record.Receipt, err
			}
			if err = host.conversionPhase(conversionPhaseRollbackConfirm); err != nil {
				return record.Receipt, err
			}
		case conversionPhaseRollbackConfirm:
			if record.RollbackProbe.ObservedAt.Before(host.now().Add(-5 * time.Minute)) {
				probe, probeErr := probeLifecycleHTTP(ctx, previousInput)
				if probeErr != nil {
					return record.Receipt, errors.Join(ErrAmbiguous, probeErr)
				}
				record.RollbackProbe = probe
				if err = host.persist(); err != nil {
					return record.Receipt, err
				}
			}
			if err = confirmConversionGeneration(ctx, previousInput); err != nil {
				return record.Receipt, err
			}
			license := record.PreviousLicense
			if record.Previous.Plan.Edition == webengine.EditionLiteSpeedEnterprise {
				if license.ReceiptDigest != licenseReceiptDigest(license, record.Input.Request) || !conversionLicenseUsable(license, previousInput) {
					license, err = observeConversionLicense(ctx, license, previousInput, record.Input.Request)
					if err != nil {
						return record.Receipt, errors.Join(ErrLicense, err)
					}
				}
				record.PreviousLicense = license
			}
			host.journal.Host = record.Previous
			host.journal.Host.Generation, host.journal.Host.Fence = record.Input.Request.ExpectedGeneration+1, record.Input.Request.Fence
			host.journal.Host.UpdatedAt = host.now().UTC()
			host.journal.License = license
			record.Receipt.Confirmed, record.Receipt.Restored = false, true
			record.Receipt.ProbeDigest = record.RollbackProbe.EvidenceDigest
			record.Receipt.License = license
			record.Receipt.LicenseDigest = digestJSON(license)
			record.Receipt.EvidenceDigest = conversionEvidence(record)
			record.Phase, record.UpdatedAt = conversionPhaseRestored, host.now().UTC()
			if err = host.persist(); err != nil {
				return record.Receipt, errors.Join(ErrAmbiguous, err)
			}
			return record.Receipt, nil
		case conversionPhaseRestored:
			return record.Receipt, nil
		default:
			return record.Receipt, ErrConflict
		}
	}
}

func conversionHostDigest(record *lifecycleConversionRecord) string {
	if record == nil {
		return ""
	}
	return digestJSON(struct {
		Domain           string
		Request          EffectRequest
		CatalogDigest    string
		CatalogSequence  uint64
		Previous         lifecycleHostState
		PreviousService  conversionServiceState
		PreviousPackages []conversionPackage
		TargetPackages   []conversionPackage
		PreviousConfig   string
		TargetConfig     string
		License          LicenseRequest
		RollbackDeadline time.Time
	}{
		"cyberpanel:edition-conversion-host:v1", record.Input.Request,
		record.CatalogDigest, record.CatalogSequence, record.Previous, record.PreviousService,
		record.PreviousPackages, record.TargetPackages, record.Input.PreviousConfigDigest,
		record.Input.Generation.ContentDigest, record.Input.License, record.Receipt.RollbackDeadline,
	})
}

func validConversionRecord(record *lifecycleConversionRecord) bool {
	if record == nil || !validConversionReceiptBase(record.Receipt) || !validConversionReceipt(record.Receipt) && (record.Phase == conversionPhaseConfirmed || record.Phase == conversionPhaseRestored) {
		return false
	}
	selection := conversionSelection(record.Input.Request, record.Input.Plan.Edition)
	receipt := record.Receipt
	valid := validLifecycleTuple(selection.OS, selection.OSVersion, selection.Architecture) && validChannel(selection.Channel) &&
		selection.Version == record.Input.Plan.Version && validConversionLicense(record.Input.Plan.Edition, record.Input.License) &&
		record.Input.RollbackWindow >= time.Minute && record.Input.RollbackWindow <= 24*time.Hour &&
		record.PreviousService.Active && validConversionEnablement(record.PreviousService.Enablement) &&
		record.HostDigest == conversionHostDigest(record) && receipt.HostDigest == record.HostDigest &&
		receipt.EffectID == record.Input.Request.EffectID && receipt.Fence == record.Input.Request.Fence &&
		receipt.ConversionDigest == record.Input.Request.PlanDigest &&
		record.Input.Request.PlanDigest == ConversionPlanDigest(selection, record.Input.Plan, record.Input.Generation.ContentDigest, record.Input.License, record.Input.RollbackWindow) &&
		receipt.Previous == record.Previous.Plan.Edition && receipt.Target == record.Input.Plan.Edition &&
		receipt.PreviousConfigDigest == record.Input.PreviousConfigDigest && receipt.TargetConfigDigest == record.Input.Generation.ContentDigest &&
		record.Input.License == conversionLicense(record.Input.Request) && receipt.RollbackDeadline.Sub(receipt.SwitchedAt) == record.Input.RollbackWindow &&
		receipt.PreviousPlanDigest == digestJSON(record.Previous.Plan) && receipt.TargetPlanDigest == digestJSON(record.Input.Plan) &&
		digestJSON(receipt.PreviousPlan) == digestJSON(record.Previous.Plan) && digestJSON(receipt.TargetPlan) == digestJSON(record.Input.Plan) &&
		receipt.PreviousChannel == record.Previous.Channel && receipt.TargetChannel == selection.Channel && receipt.CatalogDigest == record.CatalogDigest &&
		receipt.CatalogSequence == record.CatalogSequence && record.CatalogSequence > 0 && validSHA256(record.CatalogDigest)
	if !valid {
		return false
	}
	if receipt.Confirmed {
		return validConversionProbe(record.Probe, receipt.EffectID, receipt.TargetConfigDigest, record.UpdatedAt) &&
			receipt.ProbeDigest == record.Probe.EvidenceDigest && receipt.LicenseDigest == digestJSON(record.TargetLicense) &&
			digestJSON(receipt.License) == digestJSON(record.TargetLicense)
	}
	if receipt.Restored {
		return validConversionProbe(record.RollbackProbe, receipt.EffectID, receipt.PreviousConfigDigest, record.UpdatedAt) &&
			receipt.ProbeDigest == record.RollbackProbe.EvidenceDigest && receipt.LicenseDigest == digestJSON(record.PreviousLicense) &&
			digestJSON(receipt.License) == digestJSON(record.PreviousLicense)
	}
	return true
}

func validConversionProbe(probe ProbeReceipt, effect, config string, completed time.Time) bool {
	return probe.EffectID == effect && probe.ConfigDigest == config && probe.PHP && (probe.HTTP || probe.HTTPS) &&
		validSHA256(probe.EvidenceDigest) && !probe.ObservedAt.IsZero() && !completed.IsZero() &&
		!probe.ObservedAt.After(completed.Add(time.Minute)) && !probe.ObservedAt.Before(completed.Add(-5*time.Minute))
}

func conversionEvidence(record *lifecycleConversionRecord) string {
	receipt := record.Receipt
	receipt.EvidenceDigest = ""
	return digestJSON(struct {
		Receipt       SwitchReceipt
		CatalogDigest string
		CatalogSeq    uint64
		HostDigest    string
		ImageDigest   string
	}{receipt, record.CatalogDigest, record.CatalogSequence, record.HostDigest, record.ImageDigest})
}

func (host *LinuxLifecycleHost) conversionWatchdog(effect string, deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	<-timer.C
	host.mu.Lock()
	defer host.mu.Unlock()
	if !host.conversionPending() || host.journal.Conversion.Input.Request.EffectID != effect {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	_ = host.recoverEditionConversion(ctx)
}

func installConversionGeneration(ctx context.Context, input lifecycleGenerationInput) error {
	generation, err := renderLifecycleGeneration(ctx, input)
	if err != nil {
		return err
	}
	if err = prepareConversionConfigRoot(); err != nil {
		return err
	}
	store, err := openLifecycleStore(generation.Edition)
	if err != nil {
		return err
	}
	defer store.Close()
	staged, err := store.Stage(ctx, generation)
	if err != nil {
		return err
	}
	return store.SwapMaster(ctx, staged)
}

func ensureConversionGeneration(ctx context.Context, input lifecycleGenerationInput) error {
	if err := recoverConversionConfigResidue(input.Render.Desired.Engine.Edition); err != nil {
		return err
	}
	if currentLifecycleConfig(ctx, input.Render.Desired.Engine.Edition) == input.ConfigDigest {
		edition, err := readLifecycleEdition()
		if err == nil && edition == input.Render.Desired.Engine.Edition {
			return nil
		}
	}
	if err := installConversionGeneration(ctx, input); err != nil {
		return err
	}
	return writeLifecycleEdition(input.Render.Desired.Engine.Edition)
}

func confirmConversionGeneration(ctx context.Context, input lifecycleGenerationInput) error {
	if err := recoverConversionConfigResidue(input.Render.Desired.Engine.Edition); err != nil {
		return err
	}
	store, err := openLifecycleStore(input.Render.Desired.Engine.Edition)
	if err != nil {
		return err
	}
	defer store.Close()
	if current, currentErr := store.Current(ctx); currentErr == nil && current.Digest == input.ConfigDigest {
		return nil
	}
	return store.Confirm(ctx, activation.Receipt{Edition: input.Render.Desired.Engine.Edition, Digest: input.ConfigDigest})
}

func verifyConversionTarget(ctx context.Context, record *lifecycleConversionRecord, input lifecycleGenerationInput) error {
	if err := verifyLifecycleService(ctx, record.Input.Plan); err != nil {
		return err
	}
	edition, err := readLifecycleEdition()
	if err != nil || edition != record.Input.Plan.Edition || input.ConfigDigest != record.Input.Generation.ContentDigest {
		return ErrConflict
	}
	return nil
}

func verifyPreviousConversionState(ctx context.Context, record *lifecycleConversionRecord, input lifecycleGenerationInput) error {
	if err := verifyLifecycleService(ctx, record.Previous.Plan); err != nil {
		return err
	}
	edition, err := readLifecycleEdition()
	if err != nil || edition != record.Previous.Plan.Edition || currentLifecycleConfig(ctx, edition) != input.ConfigDigest {
		return ErrConflict
	}
	return verifyConversionService(ctx, record.PreviousService)
}

func configureConversionLicense(ctx context.Context, license LicenseRequest, input lifecycleGenerationInput, binding EffectRequest) (LicenseStatus, error) {
	var material []byte
	var err error
	if !license.Trial {
		material, err = readLicenseMaterial(ctx, license.SecretRef)
		if err != nil {
			return LicenseStatus{}, err
		}
		defer wipeLicenseMaterial(material)
	}
	observation, err := runLicenseAdapter(ctx, "configure", license.Mode, material)
	status := LicenseStatus{Mode: license.Mode, SecretRef: license.SecretRef, State: observation.State, Limits: observation.Limits, CheckedAt: time.Now().UTC(), ExpiresAt: observation.ExpiresAt}
	if len(material) > 0 {
		status.SerialFingerprint = linuxManagementDigest(material)
	}
	status.ReceiptDigest = licenseReceiptDigest(status, binding)
	if err != nil || !conversionLicenseUsable(status, input) {
		return status, errors.Join(ErrLicense, err)
	}
	return status, nil
}

func observeConversionLicense(ctx context.Context, status LicenseStatus, input lifecycleGenerationInput, binding EffectRequest) (LicenseStatus, error) {
	if status.Mode == "" {
		return status, ErrLicense
	}
	observation, err := runLicenseAdapter(ctx, "refresh", status.Mode, nil)
	status.State, status.Limits, status.ExpiresAt, status.CheckedAt = observation.State, observation.Limits, observation.ExpiresAt, time.Now().UTC()
	status.ReceiptDigest = licenseReceiptDigest(status, binding)
	if err != nil || !conversionLicenseUsable(status, input) {
		return status, errors.Join(ErrLicense, err)
	}
	return status, nil
}

func reconcileTargetLicense(ctx context.Context, license LicenseRequest, input lifecycleGenerationInput, binding EffectRequest) (LicenseStatus, error) {
	if input.Render.Desired.Engine.Edition == webengine.EditionOpenLiteSpeed {
		if err := disableConversionLicense(); err != nil {
			return LicenseStatus{}, err
		}
		status := LicenseStatus{State: LicenseUnknown, CheckedAt: time.Now().UTC()}
		status.ReceiptDigest = licenseReceiptDigest(status, binding)
		return status, nil
	}
	observed := LicenseStatus{Mode: license.Mode, SecretRef: license.SecretRef}
	if !license.Trial {
		material, err := readLicenseMaterial(ctx, license.SecretRef)
		if err != nil {
			return LicenseStatus{}, err
		}
		observed.SerialFingerprint = linuxManagementDigest(material)
		wipeLicenseMaterial(material)
	}
	if status, err := observeConversionLicense(ctx, observed, input, binding); err == nil {
		return status, nil
	}
	return configureConversionLicense(ctx, license, input, binding)
}

func storedConversionLicenseUsable(status LicenseStatus, license LicenseRequest, input lifecycleGenerationInput, binding EffectRequest) bool {
	if status.CheckedAt.IsZero() || status.ReceiptDigest != licenseReceiptDigest(status, binding) {
		return false
	}
	if input.Render.Desired.Engine.Edition == webengine.EditionOpenLiteSpeed {
		return license == (LicenseRequest{}) && status.Mode == "" && status.SecretRef == "" && status.State == LicenseUnknown
	}
	return status.Mode == license.Mode && status.SecretRef == license.SecretRef && conversionLicenseUsable(status, input)
}

func conversionLicenseUsable(status LicenseStatus, input lifecycleGenerationInput) bool {
	if status.State != webengine.LicenseActive && status.State != webengine.LicenseTrial ||
		!status.ExpiresAt.IsZero() && !status.ExpiresAt.After(time.Now()) ||
		status.State == webengine.LicenseTrial && status.Mode != LicenseModeTrial {
		return false
	}
	if status.Limits.Workers > 0 && status.Limits.Workers < input.Render.Desired.Engine.Tuning.WorkerProcesses {
		return false
	}
	var domains uint32
	for _, binding := range input.Render.Desired.Bindings {
		if binding.RoutingState == webengine.RoutingServe && binding.Relationship == webengine.BindingPrimary {
			domains += uint32(len(binding.Hostnames))
		}
	}
	return status.Limits.Domains == 0 || status.Limits.Domains >= domains
}
