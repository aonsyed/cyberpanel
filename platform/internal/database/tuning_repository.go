package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const tuningDatabaseTimeFormat = "2006-01-02T15:04:05.000000000Z"

type SQLiteTuningRepository struct{ db *sql.DB }

func OpenSQLiteTuningRepository(path string) (*SQLiteTuningRepository, error) {
	if path == "" || !filepath.IsAbs(path) { return nil, ErrTuningInvalid }
	database, err := sql.Open("sqlite", path)
	if err != nil { return nil, err }
	database.SetMaxOpenConns(1)
	return &SQLiteTuningRepository{db: database}, nil
}

func NewSQLiteTuningRepository(database *sql.DB) (*SQLiteTuningRepository, error) {
	if database == nil { return nil, ErrTuningInvalid }
	return &SQLiteTuningRepository{db: database}, nil
}

func (repository *SQLiteTuningRepository) Close() error {
	if repository == nil || repository.db == nil { return nil }
	return repository.db.Close()
}

func (repository *SQLiteTuningRepository) BootstrapTuning(ctx context.Context) error {
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS database_tuning_observations_v1 (
			observation_id TEXT PRIMARY KEY,
			instance_id TEXT NOT NULL,
			server_major INTEGER NOT NULL,
			server_minor INTEGER NOT NULL,
			server_patch INTEGER NOT NULL,
			config_generation INTEGER NOT NULL CHECK(config_generation > 0),
			captured_at TEXT NOT NULL,
			digest TEXT NOT NULL UNIQUE,
			document BLOB NOT NULL
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS database_tuning_observations_instance_v1 ON database_tuning_observations_v1(instance_id,captured_at DESC)`,
		`CREATE TRIGGER IF NOT EXISTS database_tuning_observations_no_update_v1 BEFORE UPDATE ON database_tuning_observations_v1 BEGIN SELECT RAISE(ABORT, 'tuning observations are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS database_tuning_observations_no_delete_v1 BEFORE DELETE ON database_tuning_observations_v1 BEGIN SELECT RAISE(ABORT, 'tuning observations are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS database_tuning_plans_v1 (
			plan_id TEXT PRIMARY KEY,
			instance_id TEXT NOT NULL,
			observation_id TEXT NOT NULL,
			plan_generation INTEGER NOT NULL CHECK(plan_generation = 1),
			config_generation INTEGER NOT NULL CHECK(config_generation > 0),
			plan_digest TEXT NOT NULL UNIQUE,
			candidate_digest TEXT NOT NULL,
			created_at TEXT NOT NULL,
			document BLOB NOT NULL,
			FOREIGN KEY(observation_id) REFERENCES database_tuning_observations_v1(observation_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS database_tuning_plans_instance_v1 ON database_tuning_plans_v1(instance_id,created_at DESC)`,
		`CREATE TRIGGER IF NOT EXISTS database_tuning_plans_no_update_v1 BEFORE UPDATE ON database_tuning_plans_v1 BEGIN SELECT RAISE(ABORT, 'tuning plans are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS database_tuning_plans_no_delete_v1 BEFORE DELETE ON database_tuning_plans_v1 BEGIN SELECT RAISE(ABORT, 'tuning plans are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS database_tuning_executions_v1 (
			plan_id TEXT PRIMARY KEY,
			generation INTEGER NOT NULL CHECK(generation > 0),
			status TEXT NOT NULL,
			latest_receipt_digest TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(plan_id) REFERENCES database_tuning_plans_v1(plan_id)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS database_tuning_receipts_v1 (
			plan_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK(generation > 0),
			status TEXT NOT NULL,
			receipt_digest TEXT NOT NULL UNIQUE,
			occurred_at TEXT NOT NULL,
			document BLOB NOT NULL,
			PRIMARY KEY(plan_id,generation),
			FOREIGN KEY(plan_id) REFERENCES database_tuning_plans_v1(plan_id)
		) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS database_tuning_receipts_no_update_v1 BEFORE UPDATE ON database_tuning_receipts_v1 BEGIN SELECT RAISE(ABORT, 'tuning receipts are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS database_tuning_receipts_no_delete_v1 BEFORE DELETE ON database_tuning_receipts_v1 BEGIN SELECT RAISE(ABORT, 'tuning receipts are immutable'); END`,
	}
	for _, statement := range statements {
		if _, err := repository.db.ExecContext(ctx, statement); err != nil { return err }
	}
	return nil
}

func (repository *SQLiteTuningRepository) SaveObservation(ctx context.Context, observation TuningObservation) error {
	if observation.Validate() != nil { return ErrTuningInvalid }
	document, err := json.Marshal(observation)
	if err != nil || len(document) > MaximumTuningSnapshotBytes { return ErrTuningInvalid }
	_, err = repository.db.ExecContext(ctx, `INSERT INTO database_tuning_observations_v1(observation_id,instance_id,server_major,server_minor,server_patch,config_generation,captured_at,digest,document) VALUES(?,?,?,?,?,?,?,?,?)`,
		observation.ID.String(), observation.InstanceID.String(), observation.ServerVersion.Major, observation.ServerVersion.Minor, observation.ServerVersion.Patch,
		observation.ConfigGeneration, formatTuningDatabaseTime(observation.CapturedAt), observation.Digest, document)
	if err == nil { return nil }
	var storedDigest string
	if scanErr := repository.db.QueryRowContext(ctx, `SELECT digest FROM database_tuning_observations_v1 WHERE observation_id=?`, observation.ID.String()).Scan(&storedDigest); scanErr == nil && storedDigest == observation.Digest {
		return nil
	}
	return ErrTuningConflict
}

func (repository *SQLiteTuningRepository) LoadObservation(ctx context.Context, observationID ResourceID) (TuningObservation, error) {
	if observationID.IsZero() { return TuningObservation{}, ErrTuningInvalid }
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM database_tuning_observations_v1 WHERE observation_id=?`, observationID.String()).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return TuningObservation{}, ErrNotFound }
	if err != nil { return TuningObservation{}, err }
	var observation TuningObservation
	if decodeTuningDocument(document, &observation) != nil || observation.Validate() != nil || observation.ID != observationID { return TuningObservation{}, ErrTuningInvalid }
	return observation, nil
}

func (repository *SQLiteTuningRepository) AdmitPlan(ctx context.Context, plan TuningPlan, acceptedAt time.Time) (TuningReceipt, error) {
	if plan.Validate() != nil || acceptedAt.IsZero() || acceptedAt.Before(plan.CreatedAt) { return TuningReceipt{}, ErrTuningInvalid }
	planDocument, err := json.Marshal(plan)
	if err != nil || len(planDocument) > MaximumTuningSnapshotBytes { return TuningReceipt{}, ErrTuningInvalid }
	receipt := sealTuningReceipt(TuningReceipt{PlanID: plan.ID, PlanDigest: plan.Digest, Generation: 1, Status: TuningAccepted,
		CandidateConfigDigest: plan.CandidateConfigDigest, OccurredAt: acceptedAt.UTC()})
	if receipt.Validate() != nil { return TuningReceipt{}, ErrTuningInvalid }
	receiptDocument, err := json.Marshal(receipt)
	if err != nil { return TuningReceipt{}, err }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return TuningReceipt{}, err }
	defer transaction.Rollback()
	var observationDigest string
	err = transaction.QueryRowContext(ctx, `SELECT digest FROM database_tuning_observations_v1 WHERE observation_id=? AND instance_id=?`,
		plan.Preconditions.ObservationID.String(), plan.InstanceID.String()).Scan(&observationDigest)
	if errors.Is(err, sql.ErrNoRows) || observationDigest != plan.Preconditions.ObservationDigest { return TuningReceipt{}, ErrTuningStale }
	if err != nil { return TuningReceipt{}, err }
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_tuning_plans_v1(plan_id,instance_id,observation_id,plan_generation,config_generation,plan_digest,candidate_digest,created_at,document) VALUES(?,?,?,?,?,?,?,?,?)`,
		plan.ID.String(), plan.InstanceID.String(), plan.Preconditions.ObservationID.String(), plan.Generation, plan.Preconditions.ConfigGeneration, plan.Digest,
		plan.CandidateConfigDigest, formatTuningDatabaseTime(plan.CreatedAt), planDocument)
	if err != nil {
		var existingDigest string
		if scanErr := transaction.QueryRowContext(ctx, `SELECT plan_digest FROM database_tuning_plans_v1 WHERE plan_id=?`, plan.ID.String()).Scan(&existingDigest); scanErr == nil && existingDigest == plan.Digest {
			existing, loadErr := loadLatestTuningReceipt(ctx, transaction, plan.ID)
			if loadErr != nil { return TuningReceipt{}, loadErr }
			return existing, transaction.Commit()
		}
		return TuningReceipt{}, ErrTuningConflict
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_tuning_executions_v1(plan_id,generation,status,latest_receipt_digest,updated_at) VALUES(?,?,?,?,?)`,
		plan.ID.String(), receipt.Generation, receipt.Status, receipt.Digest, formatTuningDatabaseTime(receipt.OccurredAt))
	if err != nil { return TuningReceipt{}, err }
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_tuning_receipts_v1(plan_id,generation,status,receipt_digest,occurred_at,document) VALUES(?,?,?,?,?,?)`,
		plan.ID.String(), receipt.Generation, receipt.Status, receipt.Digest, formatTuningDatabaseTime(receipt.OccurredAt), receiptDocument)
	if err != nil { return TuningReceipt{}, err }
	if err = transaction.Commit(); err != nil { return TuningReceipt{}, err }
	return receipt, nil
}

func (repository *SQLiteTuningRepository) LoadPlan(ctx context.Context, planID ResourceID) (TuningPlan, error) {
	if planID.IsZero() { return TuningPlan{}, ErrTuningInvalid }
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM database_tuning_plans_v1 WHERE plan_id=?`, planID.String()).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return TuningPlan{}, ErrNotFound }
	if err != nil { return TuningPlan{}, err }
	var plan TuningPlan
	if decodeTuningDocument(document, &plan) != nil || plan.Validate() != nil || plan.ID != planID { return TuningPlan{}, ErrTuningInvalid }
	return plan, nil
}

func (repository *SQLiteTuningRepository) LatestReceipt(ctx context.Context, planID ResourceID) (TuningReceipt, error) {
	if planID.IsZero() { return TuningReceipt{}, ErrTuningInvalid }
	return loadLatestTuningReceipt(ctx, repository.db, planID)
}

type tuningQueryRow interface { QueryRowContext(context.Context, string, ...any) *sql.Row }

func loadLatestTuningReceipt(ctx context.Context, query tuningQueryRow, planID ResourceID) (TuningReceipt, error) {
	var document []byte
	err := query.QueryRowContext(ctx, `SELECT r.document FROM database_tuning_receipts_v1 r JOIN database_tuning_executions_v1 e ON e.plan_id=r.plan_id AND e.generation=r.generation WHERE r.plan_id=?`, planID.String()).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return TuningReceipt{}, ErrNotFound }
	if err != nil { return TuningReceipt{}, err }
	var receipt TuningReceipt
	if decodeTuningDocument(document, &receipt) != nil || receipt.Validate() != nil || receipt.PlanID != planID { return TuningReceipt{}, ErrTuningInvalid }
	return receipt, nil
}

func (repository *SQLiteTuningRepository) AppendReceipt(ctx context.Context, receipt TuningReceipt, expectedGeneration uint64) error {
	if receipt.Validate() != nil || expectedGeneration == 0 || receipt.Generation != expectedGeneration+1 { return ErrTuningInvalid }
	document, err := json.Marshal(receipt)
	if err != nil || len(document) > 64<<10 { return ErrTuningInvalid }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	var currentStatus TuningExecutionStatus
	var planDigest, candidateDigest string
	err = transaction.QueryRowContext(ctx, `SELECT e.status,p.plan_digest,p.candidate_digest FROM database_tuning_executions_v1 e JOIN database_tuning_plans_v1 p ON p.plan_id=e.plan_id WHERE e.plan_id=? AND e.generation=?`,
		receipt.PlanID.String(), expectedGeneration).Scan(&currentStatus, &planDigest, &candidateDigest)
	if errors.Is(err, sql.ErrNoRows) { return ErrTuningConflict }
	if err != nil { return err }
	if receipt.PlanDigest != planDigest || receipt.CandidateConfigDigest != candidateDigest || !validTuningTransition(currentStatus, receipt.Status) { return ErrTuningInvalid }
	result, err := transaction.ExecContext(ctx, `UPDATE database_tuning_executions_v1 SET generation=?,status=?,latest_receipt_digest=?,updated_at=? WHERE plan_id=? AND generation=?`,
		receipt.Generation, receipt.Status, receipt.Digest, formatTuningDatabaseTime(receipt.OccurredAt), receipt.PlanID.String(), expectedGeneration)
	if err != nil { return err }
	affected, _ := result.RowsAffected()
	if affected != 1 { return ErrTuningConflict }
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_tuning_receipts_v1(plan_id,generation,status,receipt_digest,occurred_at,document) VALUES(?,?,?,?,?,?)`,
		receipt.PlanID.String(), receipt.Generation, receipt.Status, receipt.Digest, formatTuningDatabaseTime(receipt.OccurredAt), document)
	if err != nil { return ErrTuningConflict }
	return transaction.Commit()
}

func validTuningTransition(current, next TuningExecutionStatus) bool {
	switch current {
	case TuningAccepted:
		return next == TuningValidated || next == TuningFailed || next == TuningAmbiguous
	case TuningValidated:
		return next == TuningStaged || next == TuningFailed || next == TuningAmbiguous
	case TuningStaged:
		return next == TuningApplying || next == TuningCompensated || next == TuningAmbiguous
	case TuningApplying:
		return next == TuningVerifying || next == TuningCompensated || next == TuningAmbiguous
	case TuningVerifying:
		return next == TuningCommitted || next == TuningCompensated || next == TuningAmbiguous
	default:
		return false
	}
}

func sealTuningReceipt(receipt TuningReceipt) TuningReceipt {
	receipt.Digest = tuningReceiptDigest(receipt)
	return receipt
}

func formatTuningDatabaseTime(value time.Time) string { return value.UTC().Format(tuningDatabaseTimeFormat) }

func decodeTuningDocument(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return err }
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return ErrTuningInvalid }
	return nil
}
