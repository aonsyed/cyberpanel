package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

func cancelQueuedTransfer(ctx context.Context, transaction *sql.Tx, state TransferJobState, now time.Time) error {
	if state.Attempt != 0 || state.Progress.Phase != TransferPhaseQueued {
		return ErrTransferStale
	}
	// Finalizing a never-started job consumes its first lifecycle attempt, but
	// creates no process receipt and explicitly records that no mutation occurred.
	receipt := SealTransferReceipt(TransferReceipt{JobID: state.Job.ID, JobDigest: state.Job.Digest, Attempt: 1, Generation: state.Generation + 1, Status: TransferCancelled, ResumeClass: TransferResumeNotSafe, FailureCode: "cancelled_before_execution", SourcePreserved: true, OccurredAt: now})
	if receipt.Validate(state.Job) != nil {
		return ErrTransferInvalid
	}
	progress := SealTransferProgress(TransferProgress{JobID: state.Job.ID, Generation: receipt.Generation, Phase: TransferPhaseTerminal, SafePoint: true, UpdatedAt: now})
	if progress.Validate(state.Job) != nil {
		return ErrTransferInvalid
	}
	document, err := json.Marshal(progress)
	if err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, `UPDATE database_transfer_state_v1 SET generation=?,status=?,attempt=?,cancel_requested=1,latest_progress_digest=?,updated_at=? WHERE job_id=? AND generation=? AND status='queued' AND lease_token=''`, receipt.Generation, receipt.Status, receipt.Attempt, progress.Digest, formatTransferTime(now), state.Job.ID.String(), state.Generation)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrTransferStale
	}
	if _, err = transaction.ExecContext(ctx, `INSERT INTO database_transfer_progress_v1(job_id,generation,phase,progress_digest,updated_at,document) VALUES(?,?,?,?,?,?)`, progress.JobID.String(), progress.Generation, progress.Phase, progress.Digest, formatTransferTime(now), document); err != nil {
		return err
	}
	return insertTransferReceipt(ctx, transaction, receipt)
}
