package backup

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Recovery is opt-in evidence from the native target, not permission to replay
// an incomplete destructive import. Only durably completed boundaries qualify.
type RestoreRecoveryProof struct {
	Phase            RestorePhase `json:"phase"`
	TargetGeneration string       `json:"target_generation"`
	Watermark        uint64       `json:"watermark"`
	FirstWriteAt     *time.Time   `json:"first_write_at,omitempty"`
	Frozen           bool         `json:"frozen"`
	Digest           string       `json:"digest"`
}
type RestoreRecoveryTarget interface {
	ReconcileRestore(context.Context, RestorePlanSpec, RestoreReceipt) (RestoreRecoveryProof, error)
}

func nativeRestorePlanDigest(plan RestorePlanSpec) string {
	raw, _ := json.Marshal(plan)
	return restorePlanDigest(raw)
}

func (c RestoreCoordinator) observeRollback(ctx context.Context, plan RestorePlanSpec, receipt RestoreReceipt) (uint64, *time.Time, error) {
	if target, ok := c.Target.(RestoreRecoveryTarget); ok {
		proof, err := target.ReconcileRestore(ctx, plan, receipt)
		if err != nil {
			return 0, nil, err
		}
		if proof.Phase != RestoreActive {
			return 0, nil, ErrBackupAmbiguous
		}
		return proof.Watermark, proof.FirstWriteAt, nil
	}
	return c.Target.ObserveWrites(ctx, plan, receipt.TargetGeneration, string(plan.ID)+":observe-rollback")
}

func (c RestoreCoordinator) recoverCompleted(ctx context.Context, plan RestorePlanSpec, receipt RestoreReceipt) (RestoreReceipt, error) {
	target, ok := c.Target.(RestoreRecoveryTarget)
	if !ok {
		return receipt, ErrBackupAmbiguous
	}
	proof, err := target.ReconcileRestore(ctx, plan, receipt)
	if err != nil {
		return receipt, errors.Join(ErrBackupAmbiguous, err)
	}
	if proof.Watermark < receipt.RollbackFrontier || !isSHA256(proof.Digest) || (proof.Phase != RestoreActive && proof.Phase != RestoreRolledBack) {
		return receipt, ErrBackupAmbiguous
	}
	receipt.TargetWriteWatermark = proof.Watermark
	receipt.FirstWriteAt = proof.FirstWriteAt
	if proof.FirstWriteAt != nil || proof.Watermark > receipt.RollbackFrontier {
		receipt.Phase = RestoreFailForward
		receipt.Error = ErrRestoreWriteFrontier.Error()
		_ = c.Target.Quarantine(ctx, plan, receipt.ScratchID, string(plan.ID)+":recovery")
		if err = c.Store.Save(ctx, &receipt); err != nil {
			return receipt, err
		}
		return receipt, ErrRestoreWriteFrontier
	}
	if proof.Phase == RestoreActive {
		if proof.TargetGeneration == "" || receipt.TargetGeneration != "" && receipt.TargetGeneration != proof.TargetGeneration {
			return receipt, ErrBackupAmbiguous
		}
		receipt.TargetGeneration = proof.TargetGeneration
		// A rollback interrupted before any target effect can resume only from the
		// still-complete promoted state, reobserved by Rollback before mutation.
		if receipt.Phase == RestoreRollingBack {
			return c.Rollback(ctx, plan, receipt)
		}
	}
	if proof.Frozen {
		generation := proof.TargetGeneration
		if proof.Phase == RestoreRolledBack {
			generation = receipt.PreviousGeneration
		}
		if err = c.Safety.UnfreezeTargetWrites(ctx, plan, generation, string(plan.ID)+":recovery-unfreeze"); err != nil {
			return receipt, err
		}
		// Do not reuse the pre-unfreeze observation or a broker-cached fingerprint.
		proof, err = target.ReconcileRestore(ctx, plan, receipt)
		if err != nil {
			return receipt, err
		}
		if proof.FirstWriteAt != nil || proof.Watermark > receipt.RollbackFrontier {
			return c.recoverCompleted(ctx, plan, receipt)
		}
		if proof.Frozen {
			return receipt, ErrBackupAmbiguous
		}
	}
	receipt.Phase = proof.Phase
	receipt.ProbeDigest = proof.Digest
	receipt.Error = ""
	if err = c.Store.Save(ctx, &receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}
