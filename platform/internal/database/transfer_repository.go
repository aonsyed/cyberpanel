package database

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const transferDatabaseTimeFormat = "2006-01-02T15:04:05.000000000Z"

type TransferJobState struct {
	Job               TransferJob      `json:"job"`
	Generation        uint64           `json:"generation"`
	Status            TransferStatus   `json:"status"`
	Attempt           uint32           `json:"attempt"`
	CancellationRequested bool         `json:"cancellation_requested"`
	Progress          TransferProgress `json:"progress"`
}

type SQLiteTransferRepository struct{ db *sql.DB }

func OpenSQLiteTransferRepository(path string) (*SQLiteTransferRepository, error) {
	if path == "" || !filepath.IsAbs(path) { return nil, ErrTransferInvalid }
	database, err := sql.Open("sqlite", path)
	if err != nil { return nil, err }
	database.SetMaxOpenConns(1)
	return &SQLiteTransferRepository{db: database}, nil
}

func NewSQLiteTransferRepository(database *sql.DB) (*SQLiteTransferRepository, error) {
	if database == nil { return nil, ErrTransferInvalid }
	return &SQLiteTransferRepository{db: database}, nil
}

func (repository *SQLiteTransferRepository) Close() error {
	if repository == nil || repository.db == nil { return nil }
	return repository.db.Close()
}

func (repository *SQLiteTransferRepository) BootstrapTransfers(ctx context.Context) error {
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS database_transfer_jobs_v1 (
			job_id TEXT PRIMARY KEY,
			idempotency_key TEXT NOT NULL UNIQUE,
			tenant_id TEXT NOT NULL,
			site_id TEXT NOT NULL,
			database_id TEXT NOT NULL,
			database_generation INTEGER NOT NULL CHECK(database_generation > 0),
			direction TEXT NOT NULL CHECK(direction IN ('export','import')),
			job_digest TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL,
			document BLOB NOT NULL
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS database_transfer_jobs_scope_v1 ON database_transfer_jobs_v1(tenant_id,site_id,database_id,created_at DESC)`,
		`CREATE TRIGGER IF NOT EXISTS database_transfer_jobs_no_update_v1 BEFORE UPDATE ON database_transfer_jobs_v1 BEGIN SELECT RAISE(ABORT, 'transfer jobs are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS database_transfer_jobs_no_delete_v1 BEFORE DELETE ON database_transfer_jobs_v1 BEGIN SELECT RAISE(ABORT, 'transfer jobs are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS database_transfer_state_v1 (
			job_id TEXT PRIMARY KEY,
			generation INTEGER NOT NULL CHECK(generation > 0),
			status TEXT NOT NULL,
			attempt INTEGER NOT NULL CHECK(attempt >= 0),
			cancel_requested INTEGER NOT NULL CHECK(cancel_requested IN (0,1)),
			lease_worker TEXT NOT NULL,
			lease_token TEXT NOT NULL,
			lease_digest TEXT NOT NULL,
			lease_acquired_at TEXT NOT NULL,
			lease_until TEXT NOT NULL,
			latest_progress_digest TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(job_id) REFERENCES database_transfer_jobs_v1(job_id)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS database_transfer_progress_v1 (
			job_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			phase TEXT NOT NULL,
			progress_digest TEXT NOT NULL UNIQUE,
			updated_at TEXT NOT NULL,
			document BLOB NOT NULL,
			PRIMARY KEY(job_id,generation),
			FOREIGN KEY(job_id) REFERENCES database_transfer_jobs_v1(job_id)
		) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS database_transfer_progress_no_update_v1 BEFORE UPDATE ON database_transfer_progress_v1 BEGIN SELECT RAISE(ABORT, 'transfer progress is immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS database_transfer_progress_no_delete_v1 BEFORE DELETE ON database_transfer_progress_v1 BEGIN SELECT RAISE(ABORT, 'transfer progress is immutable'); END`,
		`CREATE TABLE IF NOT EXISTS database_transfer_receipts_v1 (
			job_id TEXT NOT NULL,
			attempt INTEGER NOT NULL CHECK(attempt > 0),
			generation INTEGER NOT NULL CHECK(generation > 0),
			status TEXT NOT NULL,
			receipt_digest TEXT NOT NULL UNIQUE,
			occurred_at TEXT NOT NULL,
			document BLOB NOT NULL,
			PRIMARY KEY(job_id,attempt,generation),
			FOREIGN KEY(job_id) REFERENCES database_transfer_jobs_v1(job_id)
		) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS database_transfer_receipts_no_update_v1 BEFORE UPDATE ON database_transfer_receipts_v1 BEGIN SELECT RAISE(ABORT, 'transfer receipts are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS database_transfer_receipts_no_delete_v1 BEFORE DELETE ON database_transfer_receipts_v1 BEGIN SELECT RAISE(ABORT, 'transfer receipts are immutable'); END`,
	}
	for _, statement := range statements { if _, err := repository.db.ExecContext(ctx, statement); err != nil { return err } }
	return nil
}

func (repository *SQLiteTransferRepository) CreateTransfer(ctx context.Context, job TransferJob) (TransferJobState, error) {
	if job.Validate() != nil { return TransferJobState{}, ErrTransferInvalid }
	jobDocument, err := json.Marshal(job)
	if err != nil || len(jobDocument) > MaximumTransferReceiptBytes { return TransferJobState{}, ErrTransferInvalid }
	progress := SealTransferProgress(TransferProgress{JobID: job.ID, Generation: 1, Phase: TransferPhaseQueued, SafePoint: true, UpdatedAt: job.CreatedAt})
	progressDocument, _ := json.Marshal(progress)
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return TransferJobState{}, err }
	defer transaction.Rollback()
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_transfer_jobs_v1(job_id,idempotency_key,tenant_id,site_id,database_id,database_generation,direction,job_digest,created_at,document) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		job.ID.String(), job.IdempotencyKey, job.TenantID.String(), job.SiteID.String(), job.DatabaseID.String(), job.DatabaseGeneration, job.Direction, job.Digest, formatTransferTime(job.CreatedAt), jobDocument)
	if err != nil {
		var storedDigest string
		if scanErr := transaction.QueryRowContext(ctx, `SELECT job_digest FROM database_transfer_jobs_v1 WHERE idempotency_key=?`, job.IdempotencyKey).Scan(&storedDigest); scanErr == nil && storedDigest == job.Digest {
			state, loadErr := loadTransferState(ctx, transaction, job.ID)
			if loadErr != nil { return TransferJobState{}, loadErr }
			return state, transaction.Commit()
		}
		return TransferJobState{}, ErrTransferStale
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_transfer_state_v1(job_id,generation,status,attempt,cancel_requested,lease_worker,lease_token,lease_digest,lease_acquired_at,lease_until,latest_progress_digest,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		job.ID.String(), 1, TransferQueued, 0, false, "", "", "", "", "", progress.Digest, formatTransferTime(job.CreatedAt))
	if err != nil { return TransferJobState{}, err }
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_transfer_progress_v1(job_id,generation,phase,progress_digest,updated_at,document) VALUES(?,?,?,?,?,?)`,
		job.ID.String(), progress.Generation, progress.Phase, progress.Digest, formatTransferTime(progress.UpdatedAt), progressDocument)
	if err != nil { return TransferJobState{}, err }
	if err = transaction.Commit(); err != nil { return TransferJobState{}, err }
	return TransferJobState{Job: job, Generation: 1, Status: TransferQueued, Progress: progress}, nil
}

func (repository *SQLiteTransferRepository) LoadTransfer(ctx context.Context, jobID ResourceID) (TransferJobState, error) {
	if jobID.IsZero() { return TransferJobState{}, ErrTransferInvalid }
	return loadTransferState(ctx, repository.db, jobID)
}

func (repository *SQLiteTransferRepository) LatestTransferReceipt(ctx context.Context, jobID ResourceID) (TransferReceipt, error) {
	if jobID.IsZero() { return TransferReceipt{}, ErrTransferInvalid }
	state, err := repository.LoadTransfer(ctx, jobID)
	if err != nil { return TransferReceipt{}, err }
	var document []byte
	err = repository.db.QueryRowContext(ctx, `SELECT document FROM database_transfer_receipts_v1 WHERE job_id=? ORDER BY attempt DESC,generation DESC LIMIT 1`, jobID.String()).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return TransferReceipt{}, ErrNotFound }
	if err != nil { return TransferReceipt{}, err }
	var receipt TransferReceipt
	if decodeTransferDocument(document, &receipt) != nil || receipt.Validate(state.Job) != nil { return TransferReceipt{}, ErrTransferInvalid }
	return receipt, nil
}

type transferQueryRow interface { QueryRowContext(context.Context, string, ...any) *sql.Row }

func loadTransferState(ctx context.Context, query transferQueryRow, jobID ResourceID) (TransferJobState, error) {
	var jobDocument, progressDocument []byte
	var state TransferJobState
	err := query.QueryRowContext(ctx, `SELECT j.document,s.generation,s.status,s.attempt,s.cancel_requested,p.document FROM database_transfer_jobs_v1 j JOIN database_transfer_state_v1 s ON s.job_id=j.job_id JOIN database_transfer_progress_v1 p ON p.job_id=s.job_id AND p.progress_digest=s.latest_progress_digest WHERE j.job_id=?`,
		jobID.String()).Scan(&jobDocument, &state.Generation, &state.Status, &state.Attempt, &state.CancellationRequested, &progressDocument)
	if errors.Is(err, sql.ErrNoRows) { return TransferJobState{}, ErrNotFound }
	if err != nil { return TransferJobState{}, err }
	if decodeTransferDocument(jobDocument, &state.Job) != nil || state.Job.Validate() != nil || state.Job.ID != jobID || decodeTransferDocument(progressDocument, &state.Progress) != nil ||
		state.Progress.Validate(state.Job) != nil || state.Progress.Generation > state.Generation || !validTransferStatus(state.Status) { return TransferJobState{}, ErrTransferInvalid }
	return state, nil
}

func (repository *SQLiteTransferRepository) ClaimTransfer(ctx context.Context, jobID ResourceID, workerID string, expectedGeneration uint64, now time.Time, duration time.Duration) (TransferLease, error) {
	if jobID.IsZero() || !validTransferIdentifier(workerID) || expectedGeneration == 0 || now.IsZero() || duration < time.Second || duration > 5*time.Minute { return TransferLease{}, ErrTransferInvalid }
	now = now.UTC()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return TransferLease{}, err }
	defer transaction.Rollback()
	state, err := loadTransferState(ctx, transaction, jobID)
	if err != nil { return TransferLease{}, err }
	if state.Generation != expectedGeneration || state.CancellationRequested || IsTransferTerminal(state.Status) { return TransferLease{}, ErrTransferStale }
	var leaseUntilText, leaseToken string
	err = transaction.QueryRowContext(ctx, `SELECT lease_until,lease_token FROM database_transfer_state_v1 WHERE job_id=?`, jobID.String()).Scan(&leaseUntilText, &leaseToken)
	if err != nil { return TransferLease{}, err }
	if leaseToken != "" {
		leaseUntil, parseErr := parseTransferTime(leaseUntilText)
		if parseErr != nil { return TransferLease{}, ErrTransferInvalid }
		if now.Before(leaseUntil) { return TransferLease{}, ErrTransferStale }
	}
	if state.Status != TransferQueued && state.Status != TransferRunning && state.Status != TransferVerifying && state.Status != TransferPromoting { return TransferLease{}, ErrTransferStale }
	if state.Attempt > 0 && state.Status != TransferQueued {
		resume := transferResumeFor(state.Job, state.Status, state.Progress.Phase)
		expired := SealTransferReceipt(TransferReceipt{JobID: state.Job.ID, JobDigest: state.Job.Digest, Attempt: state.Attempt, Generation: state.Generation,
			Status: TransferFailed, ResumeClass: resume, FailureCode: "lease_expired", SourcePreserved: true, MutationPossible: true, OccurredAt: now})
		if resume == TransferResumeNotSafe { expired.Status = TransferAmbiguous; expired = SealTransferReceipt(expired) }
		if expired.Validate(state.Job) != nil { return TransferLease{}, ErrTransferInvalid }
		if err = insertTransferReceipt(ctx, transaction, expired); err != nil { return TransferLease{}, err }
		if resume == TransferResumeNotSafe {
			_, err = transaction.ExecContext(ctx, `UPDATE database_transfer_state_v1 SET status=?,lease_worker='',lease_token='',lease_digest='',lease_acquired_at='',lease_until='',updated_at=? WHERE job_id=? AND generation=?`,
				TransferAmbiguous, formatTransferTime(now), jobID.String(), state.Generation)
			if err != nil { return TransferLease{}, err }
			if err = transaction.Commit(); err != nil { return TransferLease{}, err }
			return TransferLease{}, ErrAmbiguous
		}
	}
	token, err := randomTransferToken()
	if err != nil { return TransferLease{}, err }
	lease := TransferLease{JobID: jobID, WorkerID: workerID, Generation: state.Generation + 1, Attempt: state.Attempt + 1, FenceToken: token,
		FenceDigest: transferDigest([]byte(token)), AcquiredAt: now, ExpiresAt: now.Add(duration), Duration: duration}
	result, err := transaction.ExecContext(ctx, `UPDATE database_transfer_state_v1 SET generation=?,status=?,attempt=?,lease_worker=?,lease_token=?,lease_digest=?,lease_acquired_at=?,lease_until=?,updated_at=? WHERE job_id=? AND generation=?`,
		lease.Generation, TransferRunning, lease.Attempt, lease.WorkerID, lease.FenceToken, lease.FenceDigest, formatTransferTime(lease.AcquiredAt), formatTransferTime(lease.ExpiresAt), formatTransferTime(now), jobID.String(), state.Generation)
	if err != nil { return TransferLease{}, err }
	affected, _ := result.RowsAffected()
	if affected != 1 { return TransferLease{}, ErrTransferStale }
	if err = transaction.Commit(); err != nil { return TransferLease{}, err }
	return lease, nil
}

func (repository *SQLiteTransferRepository) CheckpointTransfer(ctx context.Context, lease TransferLease, progress TransferProgress) (TransferLease, error) {
	if lease.Validate() != nil || progress.JobID != lease.JobID || progress.Generation != lease.Generation+1 || progress.UpdatedAt.Before(lease.AcquiredAt) { return TransferLease{}, ErrTransferInvalid }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return TransferLease{}, err }
	defer transaction.Rollback()
	state, err := loadTransferState(ctx, transaction, lease.JobID)
	if err != nil { return TransferLease{}, err }
	if state.Generation != lease.Generation || progress.Validate(state.Job) != nil || progress.BytesProcessed < state.Progress.BytesProcessed || progress.RowsProcessed < state.Progress.RowsProcessed ||
		progress.TablesProcessed < state.Progress.TablesProcessed { return TransferLease{}, ErrTransferStale }
	var cancelRequested bool
	var leaseUntilText string
	err = transaction.QueryRowContext(ctx, `SELECT cancel_requested,lease_until FROM database_transfer_state_v1 WHERE job_id=? AND lease_worker=? AND lease_token=?`,
		lease.JobID.String(), lease.WorkerID, lease.FenceToken).Scan(&cancelRequested, &leaseUntilText)
	if errors.Is(err, sql.ErrNoRows) { return TransferLease{}, ErrTransferStale }
	if err != nil { return TransferLease{}, err }
	leaseUntil, err := parseTransferTime(leaseUntilText)
	if err != nil || progress.UpdatedAt.After(leaseUntil) { return TransferLease{}, ErrTransferStale }
	if cancelRequested && progress.SafePoint { return TransferLease{}, ErrTransferCancelled }
	status := transferStatusForPhase(progress.Phase)
	document, _ := json.Marshal(progress)
	newExpiry := progress.UpdatedAt.Add(lease.Duration)
	result, err := transaction.ExecContext(ctx, `UPDATE database_transfer_state_v1 SET generation=?,status=?,lease_until=?,latest_progress_digest=?,updated_at=? WHERE job_id=? AND generation=? AND lease_worker=? AND lease_token=?`,
		progress.Generation, status, formatTransferTime(newExpiry), progress.Digest, formatTransferTime(progress.UpdatedAt), lease.JobID.String(), lease.Generation, lease.WorkerID, lease.FenceToken)
	if err != nil { return TransferLease{}, err }
	affected, _ := result.RowsAffected()
	if affected != 1 { return TransferLease{}, ErrTransferStale }
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_transfer_progress_v1(job_id,generation,phase,progress_digest,updated_at,document) VALUES(?,?,?,?,?,?)`,
		progress.JobID.String(), progress.Generation, progress.Phase, progress.Digest, formatTransferTime(progress.UpdatedAt), document)
	if err != nil { return TransferLease{}, err }
	lease.Generation = progress.Generation
	lease.AcquiredAt = progress.UpdatedAt
	lease.ExpiresAt = newExpiry
	if err = transaction.Commit(); err != nil { return TransferLease{}, err }
	return lease, nil
}

func (repository *SQLiteTransferRepository) RequestTransferCancellation(ctx context.Context, jobID ResourceID, expectedGeneration uint64, now time.Time) error {
	if jobID.IsZero() || expectedGeneration == 0 || now.IsZero() { return ErrTransferInvalid }
	result, err := repository.db.ExecContext(ctx, `UPDATE database_transfer_state_v1 SET cancel_requested=1,updated_at=? WHERE job_id=? AND generation=? AND status NOT IN ('completed','failed','cancelled','ambiguous')`,
		formatTransferTime(now), jobID.String(), expectedGeneration)
	if err != nil { return err }
	affected, _ := result.RowsAffected()
	if affected != 1 { return ErrTransferStale }
	return nil
}

func (repository *SQLiteTransferRepository) CompleteTransfer(ctx context.Context, lease TransferLease, receipt TransferReceipt) error {
	if lease.Validate() != nil || receipt.JobID != lease.JobID || receipt.Attempt != lease.Attempt || receipt.Generation != lease.Generation+1 || !IsTransferTerminal(receipt.Status) { return ErrTransferInvalid }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	state, err := loadTransferState(ctx, transaction, lease.JobID)
	if err != nil { return err }
	if state.Generation != lease.Generation || receipt.Validate(state.Job) != nil { return ErrTransferStale }
	result, err := transaction.ExecContext(ctx, `UPDATE database_transfer_state_v1 SET generation=?,status=?,lease_worker='',lease_token='',lease_digest='',lease_acquired_at='',lease_until='',updated_at=? WHERE job_id=? AND generation=? AND lease_worker=? AND lease_token=?`,
		receipt.Generation, receipt.Status, formatTransferTime(receipt.OccurredAt), lease.JobID.String(), lease.Generation, lease.WorkerID, lease.FenceToken)
	if err != nil { return err }
	affected, _ := result.RowsAffected()
	if affected != 1 { return ErrTransferStale }
	if err = insertTransferReceipt(ctx, transaction, receipt); err != nil { return err }
	return transaction.Commit()
}

func insertTransferReceipt(ctx context.Context, transaction *sql.Tx, receipt TransferReceipt) error {
	document, err := json.Marshal(receipt)
	if err != nil || len(document) > MaximumTransferReceiptBytes { return ErrTransferInvalid }
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_transfer_receipts_v1(job_id,attempt,generation,status,receipt_digest,occurred_at,document) VALUES(?,?,?,?,?,?,?)`,
		receipt.JobID.String(), receipt.Attempt, receipt.Generation, receipt.Status, receipt.Digest, formatTransferTime(receipt.OccurredAt), document)
	return err
}

func transferResumeFor(job TransferJob, status TransferStatus, phase TransferPhase) TransferResumeClass {
	if status == TransferPromoting || phase == TransferPhasePromoting || phase == TransferPhaseCleanup { return TransferResumeNotSafe }
	if job.Direction == TransferImport { return TransferResumeRestartIsolated }
	return TransferResumeRestartArtifact
}

func transferStatusForPhase(phase TransferPhase) TransferStatus {
	switch phase {
	case TransferPhaseVerifying:
		return TransferVerifying
	case TransferPhasePromoting, TransferPhaseCleanup:
		return TransferPromoting
	default:
		return TransferRunning
	}
}

func IsTransferTerminal(status TransferStatus) bool {
	return status == TransferCompleted || status == TransferFailed || status == TransferCancelled || status == TransferAmbiguous
}

func randomTransferToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil { return "", err }
	return hex.EncodeToString(buffer), nil
}

func formatTransferTime(value time.Time) string { return value.UTC().Format(transferDatabaseTimeFormat) }

func parseTransferTime(value string) (time.Time, error) { return time.Parse(transferDatabaseTimeFormat, value) }

func decodeTransferDocument(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return err }
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return ErrTransferInvalid }
	return nil
}
