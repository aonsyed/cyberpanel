package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

func checkTransferRecovery(ctx context.Context, tx *sql.Tx, id ResourceID, generation uint64, now time.Time) (TransferJobState, error) {
	state, err := loadTransferState(ctx, tx, id)
	if err != nil {
		return state, err
	}
	if generation == 0 || now.IsZero() || now.Before(state.Progress.UpdatedAt) || state.Generation != generation || state.Job.Direction != TransferImport || state.Attempt == 0 || (state.Status != TransferAmbiguous && state.Status != TransferPromoting) {
		return state, ErrTransferStale
	}
	var token, until string
	if err = tx.QueryRowContext(ctx, `SELECT lease_token,lease_until FROM database_transfer_state_v1 WHERE job_id=?`, id.String()).Scan(&token, &until); err != nil {
		return state, err
	}
	if token != "" {
		expires, err := parseTransferTime(until)
		if err != nil || now.Before(expires) {
			return state, ErrTransferStale
		}
	}
	return state, nil
}

func (repository *SQLiteTransferRepository) CheckTransferRecovery(ctx context.Context, id ResourceID, generation uint64, now time.Time) error {
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = checkTransferRecovery(ctx, tx, id, generation, now)
	return err
}

// The caller must obtain proof through the authenticated executor, after job
// authorization. State/lease checks repeat in the transaction to fence races.
func (repository *SQLiteTransferRepository) ReconcileTransferPromotion(ctx context.Context, id ResourceID, generation uint64, result TransferImportResult, now time.Time) (TransferReceipt, error) {
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return TransferReceipt{}, err
	}
	defer tx.Rollback()
	state, err := checkTransferRecovery(ctx, tx, id, generation, now)
	if err != nil {
		return TransferReceipt{}, err
	}
	request := TransferImportRequest{Action: "recover", Job: state.Job}
	if state.Job.ExportSource != nil {
		request.SourceExport = *state.Job.ExportSource
	}
	if request.validate() != nil || !result.matches(request) {
		return TransferReceipt{}, ErrInvalidReceipt
	}
	receipt := SealTransferReceipt(TransferReceipt{JobID: id, JobDigest: state.Job.Digest, Attempt: state.Attempt, Generation: generation + 1, Status: TransferCompleted, ResumeClass: TransferResumeNotSafe, Process: result.Process, VerificationDigest: result.Verification.Digest, PromotionDigest: result.Promotion.ProofDigest, SourcePreserved: true, MutationPossible: true, OccurredAt: now})
	if receipt.Validate(state.Job) != nil {
		return TransferReceipt{}, ErrInvalidReceipt
	}
	progress := SealTransferProgress(TransferProgress{JobID: id, Generation: receipt.Generation, Phase: TransferPhaseTerminal, BytesProcessed: result.Process.BytesProcessed, RowsProcessed: result.Verification.RowCount, TablesProcessed: state.Progress.TablesProcessed, SafePoint: true, UpdatedAt: now})
	if progress.Validate(state.Job) != nil {
		return TransferReceipt{}, ErrInvalidReceipt
	}
	document, err := json.Marshal(progress)
	if err != nil {
		return TransferReceipt{}, err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE database_transfer_state_v1 SET generation=?,status=?,lease_worker='',lease_token='',lease_digest='',lease_acquired_at='',lease_until='',latest_progress_digest=?,updated_at=? WHERE job_id=? AND generation=?`, receipt.Generation, receipt.Status, progress.Digest, formatTransferTime(now), id.String(), generation)
	if err != nil {
		return TransferReceipt{}, err
	}
	count, err := updated.RowsAffected()
	if err != nil || count != 1 {
		return TransferReceipt{}, ErrTransferStale
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO database_transfer_progress_v1(job_id,generation,phase,progress_digest,updated_at,document) VALUES(?,?,?,?,?,?)`, id.String(), progress.Generation, progress.Phase, progress.Digest, formatTransferTime(now), document); err != nil {
		return TransferReceipt{}, err
	}
	if err = insertTransferReceipt(ctx, tx, receipt); err != nil {
		return TransferReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return TransferReceipt{}, err
	}
	return receipt, nil
}
