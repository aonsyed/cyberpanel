//go:build linux

package backup

import (
	"context"
	"errors"
	"path/filepath"
)

// ReconcileRestore never replays archive extraction or SQL. Missing completion
// evidence (including all pre-versioned journals) is deliberately unsupported.
func (host *LinuxBackupHost) ReconcileRestore(ctx context.Context, plan RestorePlanSpec, receipt RestoreReceipt) (RestoreRecoveryProof, error) {
	var proof RestoreRecoveryProof
	if host == nil || receipt.PlanID != plan.ID || receipt.TenantID != plan.TenantID || receipt.PlanDigest != nativeRestorePlanDigest(plan) || receipt.ScratchID == "" || receipt.PreviousGeneration == "" || receipt.SafetySnapshotID == "" || receipt.RollbackFrontier == 0 {
		return proof, ErrInvalidBackup
	}
	if plan.SourceScope != plan.TargetScope {
		return proof, ErrInvalidBackup
	}
	for component := range plan.ComponentMapping {
		if component != ComponentFiles && component != ComponentDatabase {
			return proof, ErrBackupAmbiguous
		}
	}
	binding, err := host.resolve(ctx, plan.TenantID, plan.TargetScope)
	if err != nil {
		return proof, err
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	root := host.restoreRoot(plan)
	var state linuxRestoreState
	if err = readLinuxBackupJSON(filepath.Join(root, "state.json"), &state); err != nil {
		return proof, err
	}
	if state.RecoveryVersion != 1 || state.PlanDigest != receipt.PlanDigest || state.SourceGeneration != binding.Generation || state.PlanID != plan.ID || state.TenantID != plan.TenantID || state.TargetScope != plan.TargetScope || state.ScratchID != receipt.ScratchID || state.PreviousGeneration != receipt.PreviousGeneration || state.SafetyID != receipt.SafetySnapshotID || state.Watermark < receipt.RollbackFrontier || state.Fingerprint == "" || state.Promoted == state.RolledBack {
		return proof, ErrBackupAmbiguous
	}
	var manifest RecoveryPointManifest
	if err = readLinuxBackupJSON(filepath.Join(root, "manifest.json"), &manifest); err != nil {
		return proof, err
	}
	if ValidateRecoveryPointManifest(manifest) != nil || manifest.ManifestDigest != receipt.ManifestDigest || manifest.RecoveryPointID != plan.RecoveryPointID || manifest.TenantID != plan.TenantID || manifest.Scope != plan.SourceScope {
		return proof, ErrBackupAmbiguous
	}
	if state.Promoted {
		if !state.Frozen && !isSHA256(state.HealthDigest) {
			return proof, ErrBackupAmbiguous
		}
		if state.TargetGeneration == "" || receipt.TargetGeneration != "" && receipt.TargetGeneration != state.TargetGeneration {
			return proof, ErrBackupConflict
		}
		proof.Phase = RestoreActive
		proof.TargetGeneration = state.TargetGeneration
	} else {
		if receipt.TargetGeneration == "" || receipt.TargetGeneration != state.RolledBackFrom {
			return proof, ErrBackupConflict
		}
		proof.Phase = RestoreRolledBack
		proof.TargetGeneration = state.RolledBackFrom
	}
	if _, ok := plan.ComponentMapping[ComponentFiles]; ok {
		identity, identityErr := linuxBackupReleaseIdentity(filepath.Join(host.generationRoot(binding), "releases", "current"), true)
		if identityErr != nil || state.CompletedReleaseIdentity == "" || identity != state.CompletedReleaseIdentity {
			return proof, errors.Join(ErrBackupAmbiguous, identityErr)
		}
	}
	fingerprint, err := host.targetFingerprint(ctx, plan, binding)
	if err != nil {
		return proof, err
	}
	if fingerprint != state.Fingerprint {
		if state.Watermark == ^uint64(0) {
			return proof, ErrBackupConflict
		}
		if state.FirstWriteAt == nil {
			now := host.now()
			state.FirstWriteAt = &now
		}
		state.Watermark++
		state.Fingerprint = fingerprint
		if err = writeLinuxBackupJSON(host.watermarkPath(plan.TargetScope), state.Watermark); err != nil {
			return proof, err
		}
		if err = writeLinuxBackupJSON(filepath.Join(root, "state.json"), state); err != nil {
			return proof, err
		}
	}
	proof.Watermark = state.Watermark
	proof.FirstWriteAt = state.FirstWriteAt
	proof.Frozen = state.Frozen
	proof.HealthDigest = state.HealthDigest
	proof.Digest = linuxBackupDigest("recovery", state.PlanDigest, string(proof.Phase), state.Fingerprint, state.CompletedReleaseIdentity)
	return proof, nil
}
