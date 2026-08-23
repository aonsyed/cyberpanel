package migration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const repositorySchema = `
CREATE TABLE IF NOT EXISTS panel_migrations (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  phase TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  manifest_root TEXT NOT NULL,
  plan_digest TEXT NOT NULL,
  source_generation INTEGER NOT NULL,
  target_generation INTEGER NOT NULL,
  fence INTEGER NOT NULL,
  last_checkpoint TEXT NOT NULL,
  target_write_watermark TEXT NOT NULL,
  rollback_deadline TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  error_code TEXT NOT NULL,
  error_message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS panel_migration_manifests (
  merkle_root TEXT PRIMARY KEY,
  migration_id TEXT NOT NULL,
  source_generation INTEGER NOT NULL,
  manifest_json BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS panel_migration_manifest_generation
  ON panel_migration_manifests(migration_id, source_generation);
CREATE TABLE IF NOT EXISTS panel_migration_plans (
  dry_run_digest TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL UNIQUE,
  migration_id TEXT NOT NULL,
  plan_json BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS panel_migration_progress (
  migration_id TEXT NOT NULL,
  resource_kind TEXT NOT NULL,
  source_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  progress_json BLOB NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(migration_id, resource_kind, source_id)
);
CREATE TABLE IF NOT EXISTS panel_migration_receipts (
  migration_id TEXT NOT NULL,
  receipt_kind TEXT NOT NULL,
  receipt_json BLOB NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(migration_id, receipt_kind)
);
CREATE TABLE IF NOT EXISTS panel_migration_chunk_progress (
  migration_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  transferred_bytes INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  state TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(migration_id, digest)
);`

// SQLRepository is the sole writer for migration orchestration state. It owns
// no source credentials and stores only signed canonical manifests, plans,
// checkpoints, and bounded effect receipts.
type SQLRepository struct {
	db    *sql.DB
	clock func() time.Time
	mu    sync.Mutex
}

func NewSQLRepository(db *sql.DB) (*SQLRepository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &SQLRepository{db: db, clock: time.Now}, nil
}

func (r *SQLRepository) Bootstrap(ctx context.Context) error {
	if r == nil || r.db == nil {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := r.db.ExecContext(ctx, repositorySchema)
	return err
}

func (r *SQLRepository) Create(ctx context.Context, value Migration) error {
	if r == nil || r.db == nil || validateMigration(value) != nil || value.Phase != PhaseCreated {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := r.db.ExecContext(ctx, `INSERT INTO panel_migrations
(id,source,phase,attempt_id,manifest_root,plan_digest,source_generation,target_generation,fence,last_checkpoint,target_write_watermark,rollback_deadline,created_at,updated_at,error_code,error_message)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.ID.String(), string(value.Source), string(value.Phase), value.AttemptID,
		value.ManifestRoot, value.PlanDigest, value.SourceGeneration, value.TargetGeneration, value.Fence,
		value.LastCheckpoint, value.TargetWriteWatermark, encodeTime(value.RollbackDeadline), encodeTime(value.CreatedAt),
		encodeTime(value.UpdatedAt), value.ErrorCode, value.ErrorMessage)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (r *SQLRepository) Migration(ctx context.Context, id ID) (Migration, error) {
	if r == nil || r.db == nil || !id.Valid() {
		return Migration{}, ErrInvalid
	}
	row := r.db.QueryRowContext(ctx, `SELECT source,phase,attempt_id,manifest_root,plan_digest,source_generation,target_generation,fence,last_checkpoint,target_write_watermark,rollback_deadline,created_at,updated_at,error_code,error_message
FROM panel_migrations WHERE id=?`, id.String())
	value, err := scanMigration(id, row)
	if errors.Is(err, sql.ErrNoRows) {
		return Migration{}, ErrNotFound
	}
	return value, err
}

func (r *SQLRepository) Transition(ctx context.Context, id ID, from, to Phase, checkpoint string, generation uint64) (Migration, error) {
	if r == nil || r.db == nil || !id.Valid() || !validPhase(from) || !validPhase(to) || !transitionAllowed(from, to) || len(checkpoint) > 4096 {
		return Migration{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Migration{}, err
	}
	defer tx.Rollback()
	value, err := scanMigration(id, tx.QueryRowContext(ctx, `SELECT source,phase,attempt_id,manifest_root,plan_digest,source_generation,target_generation,fence,last_checkpoint,target_write_watermark,rollback_deadline,created_at,updated_at,error_code,error_message FROM panel_migrations WHERE id=?`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return Migration{}, ErrNotFound
	}
	if err != nil {
		return Migration{}, err
	}
	if value.Phase != from {
		return Migration{}, ErrConflict
	}
	value.Phase = to
	value.LastCheckpoint = checkpoint
	value.UpdatedAt = r.clock().UTC()
	if generation != 0 {
		value.SourceGeneration = generation
	}
	switch to {
	case PhaseInventoried:
		value.ManifestRoot = checkpoint
	case PhasePlanned, PhaseReady:
		value.PlanDigest = checkpoint
	case PhaseVerifying:
		value.TargetGeneration++
	case PhasePausedRetryable, PhaseBlockedPolicy, PhaseFailedTerminal:
		value.ErrorCode = checkpoint
	case PhaseCanceled:
		value.ErrorCode, value.ErrorMessage = "", ""
	default:
		value.ErrorCode, value.ErrorMessage = "", ""
	}
	result, err := tx.ExecContext(ctx, `UPDATE panel_migrations SET phase=?,manifest_root=?,plan_digest=?,source_generation=?,target_generation=?,fence=?,last_checkpoint=?,target_write_watermark=?,rollback_deadline=?,updated_at=?,error_code=?,error_message=? WHERE id=? AND phase=? AND fence=?`,
		string(value.Phase), value.ManifestRoot, value.PlanDigest, value.SourceGeneration, value.TargetGeneration, value.Fence,
		value.LastCheckpoint, value.TargetWriteWatermark, encodeTime(value.RollbackDeadline), encodeTime(value.UpdatedAt),
		value.ErrorCode, value.ErrorMessage, id.String(), string(from), value.Fence)
	if err != nil {
		return Migration{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return Migration{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Migration{}, err
	}
	return value, nil
}

func (r *SQLRepository) PutManifest(ctx context.Context, value Manifest) error {
	if r == nil || r.db == nil || value.Validate() != nil {
		return ErrInvalid
	}
	raw, err := canonicalJSON(value, 32<<20)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err = r.db.ExecContext(ctx, `INSERT INTO panel_migration_manifests(merkle_root,migration_id,source_generation,manifest_json,created_at) VALUES(?,?,?,?,?)`, value.MerkleRoot, value.MigrationID.String(), value.SourceGeneration, raw, encodeTime(value.CreatedAt))
	if isUniqueViolation(err) {
		var existing []byte
		loadErr := r.db.QueryRowContext(ctx, `SELECT manifest_json FROM panel_migration_manifests WHERE merkle_root=?`, value.MerkleRoot).Scan(&existing)
		if loadErr == nil && bytes.Equal(existing, raw) {
			return nil
		}
		return ErrConflict
	}
	return err
}

func (r *SQLRepository) Manifest(ctx context.Context, root string) (Manifest, error) {
	if r == nil || r.db == nil || !isDigest(root) {
		return Manifest{}, ErrInvalid
	}
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT manifest_json FROM panel_migration_manifests WHERE merkle_root=?`, root).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Manifest{}, ErrNotFound
	}
	if err != nil {
		return Manifest{}, err
	}
	var value Manifest
	if err := strictDecode(raw, &value, 32<<20); err != nil || value.Validate() != nil || value.MerkleRoot != root {
		return Manifest{}, ErrInvalid
	}
	return value, nil
}

func (r *SQLRepository) PutPlan(ctx context.Context, value Plan) error {
	if r == nil || r.db == nil || validatePlan(value) != nil {
		return ErrInvalid
	}
	raw, err := canonicalJSON(value, 8<<20)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err = r.db.ExecContext(ctx, `INSERT INTO panel_migration_plans(dry_run_digest,plan_id,migration_id,plan_json,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(dry_run_digest) DO UPDATE SET plan_json=excluded.plan_json,updated_at=excluded.updated_at WHERE panel_migration_plans.plan_id=excluded.plan_id AND panel_migration_plans.migration_id=excluded.migration_id`, value.DryRunDigest, value.ID.String(), value.MigrationID.String(), raw, encodeTime(r.clock().UTC()))
	return err
}

func (r *SQLRepository) Plan(ctx context.Context, digest string) (Plan, error) {
	if r == nil || r.db == nil || !isDigest(digest) {
		return Plan{}, ErrInvalid
	}
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT plan_json FROM panel_migration_plans WHERE dry_run_digest=?`, digest).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	if err != nil {
		return Plan{}, err
	}
	var value Plan
	if err := strictDecode(raw, &value, 8<<20); err != nil || validatePlan(value) != nil || value.DryRunDigest != digest {
		return Plan{}, ErrInvalid
	}
	return value, nil
}

func (r *SQLRepository) PutProgress(ctx context.Context, value ResourceProgress) error {
	if r == nil || r.db == nil || validateProgress(value) != nil {
		return ErrInvalid
	}
	raw, err := canonicalJSON(value, 1<<20)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err = r.db.ExecContext(ctx, `INSERT INTO panel_migration_progress(migration_id,resource_kind,source_id,target_id,phase,progress_json,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(migration_id,resource_kind,source_id) DO UPDATE SET target_id=excluded.target_id,phase=excluded.phase,progress_json=excluded.progress_json,updated_at=excluded.updated_at WHERE panel_migration_progress.updated_at<=excluded.updated_at`, value.MigrationID.String(), value.Kind, value.SourceID.String(), value.TargetID.String(), string(value.Phase), raw, encodeTime(value.UpdatedAt))
	return err
}

func (r *SQLRepository) Progress(ctx context.Context, id ID) ([]ResourceProgress, error) {
	if r == nil || r.db == nil || !id.Valid() {
		return nil, ErrInvalid
	}
	rows, err := r.db.QueryContext(ctx, `SELECT progress_json FROM panel_migration_progress WHERE migration_id=? ORDER BY resource_kind,source_id`, id.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []ResourceProgress
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var value ResourceProgress
		if err := strictDecode(raw, &value, 1<<20); err != nil || validateProgress(value) != nil {
			return nil, ErrInvalid
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *SQLRepository) PutReceipt(ctx context.Context, migrationID ID, kind string, value any) error {
	if r == nil || r.db == nil || !migrationID.Valid() || !validReceiptKind(kind) {
		return ErrInvalid
	}
	raw, err := canonicalJSON(value, 4<<20)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err = r.db.ExecContext(ctx, `INSERT INTO panel_migration_receipts(migration_id,receipt_kind,receipt_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(migration_id,receipt_kind) DO UPDATE SET receipt_json=excluded.receipt_json,updated_at=excluded.updated_at`, migrationID.String(), kind, raw, encodeTime(r.clock().UTC()))
	return err
}

func (r *SQLRepository) Receipt(ctx context.Context, migrationID ID, kind string, destination any) error {
	if r == nil || r.db == nil || !migrationID.Valid() || !validReceiptKind(kind) || destination == nil {
		return ErrInvalid
	}
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT receipt_json FROM panel_migration_receipts WHERE migration_id=? AND receipt_kind=?`, migrationID.String(), kind).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return strictDecode(raw, destination, 4<<20)
}

func (r *SQLRepository) RecordChunkProgress(ctx context.Context, migrationID ID, digest string, transferred, total uint64, state string) error {
	if r == nil || r.db == nil || !migrationID.Valid() || !isDigest(digest) || transferred > total || (state != "transferring" && state != "verified" && state != "failed") {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := r.db.ExecContext(ctx, `INSERT INTO panel_migration_chunk_progress(migration_id,digest,transferred_bytes,total_bytes,state,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(migration_id,digest) DO UPDATE SET transferred_bytes=excluded.transferred_bytes,total_bytes=excluded.total_bytes,state=excluded.state,updated_at=excluded.updated_at WHERE panel_migration_chunk_progress.total_bytes=excluded.total_bytes AND panel_migration_chunk_progress.transferred_bytes<=excluded.transferred_bytes`, migrationID.String(), digest, transferred, total, state, encodeTime(r.clock().UTC()))
	return err
}

type scanner interface{ Scan(...any) error }

func scanMigration(id ID, row scanner) (Migration, error) {
	var value Migration
	var source, phase, rollback, created, updated string
	value.ID = id
	if err := row.Scan(&source, &phase, &value.AttemptID, &value.ManifestRoot, &value.PlanDigest, &value.SourceGeneration, &value.TargetGeneration, &value.Fence, &value.LastCheckpoint, &value.TargetWriteWatermark, &rollback, &created, &updated, &value.ErrorCode, &value.ErrorMessage); err != nil {
		return Migration{}, err
	}
	value.Source, value.Phase = SourceKind(source), Phase(phase)
	var err error
	if value.RollbackDeadline, err = decodeTime(rollback); err != nil {
		return Migration{}, err
	}
	if value.CreatedAt, err = decodeTime(created); err != nil {
		return Migration{}, err
	}
	if value.UpdatedAt, err = decodeTime(updated); err != nil {
		return Migration{}, err
	}
	if err := validateMigration(value); err != nil {
		return Migration{}, err
	}
	return value, nil
}

func validateMigration(value Migration) error {
	if !value.ID.Valid() || (value.Source != SourceCyberPanel && value.Source != SourceCyberPanelBackup && value.Source != SourceCPanel && value.Source != SourceCanonical) || !validPhase(value.Phase) || value.AttemptID == "" || value.Fence == 0 || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return ErrInvalid
	}
	return nil
}

func validPhase(value Phase) bool {
	switch value {
	case PhaseCreated, PhaseDiscovering, PhaseInventoried, PhasePlanned, PhaseReady, PhaseBaseSync, PhaseQuiescing, PhaseFinalSync, PhaseCutoverReady, PhaseCutoverCommitting, PhaseVerifying, PhaseCommitted, PhaseCleanup, PhasePausedRetryable, PhaseBlockedPolicy, PhaseFailedTerminal, PhaseRollingBack, PhaseRolledBack, PhaseCanceled:
		return true
	default:
		return false
	}
}

func transitionAllowed(from, to Phase) bool {
	if to == PhaseFailedTerminal {
		return from != PhaseRolledBack && from != PhaseCanceled
	}
	if to == PhasePausedRetryable || to == PhaseBlockedPolicy {
		return from != PhaseCommitted && from != PhaseCleanup && from != PhaseRolledBack && from != PhaseFailedTerminal && from != PhaseCanceled
	}
	if to == PhaseRollingBack {
		switch from {
		case PhaseCreated, PhaseDiscovering, PhaseInventoried, PhasePlanned, PhaseReady, PhaseBaseSync, PhaseQuiescing, PhasePausedRetryable, PhaseBlockedPolicy, PhaseVerifying:
			return true
		default:
			return false
		}
	}
	if to == PhaseCanceled {
		switch from {
		case PhaseCreated, PhaseDiscovering, PhaseInventoried, PhasePlanned, PhaseReady, PhaseBaseSync, PhaseQuiescing, PhasePausedRetryable, PhaseBlockedPolicy, PhaseRollingBack:
			return true
		default:
			return false
		}
	}
	allowed := map[Phase][]Phase{
		PhaseCreated: {PhaseDiscovering}, PhaseDiscovering: {PhaseInventoried}, PhaseInventoried: {PhasePlanned},
		PhasePlanned: {PhaseReady}, PhaseReady: {PhaseBaseSync}, PhaseBaseSync: {PhaseQuiescing},
		PhaseQuiescing: {PhaseFinalSync}, PhaseFinalSync: {PhaseCutoverReady}, PhaseCutoverReady: {PhaseCutoverCommitting},
		PhaseCutoverCommitting: {PhaseVerifying}, PhaseVerifying: {PhaseCommitted, PhaseRollingBack},
		PhaseRollingBack: {PhaseRolledBack}, PhaseCommitted: {PhaseCleanup},
		PhasePausedRetryable: {PhaseDiscovering, PhaseBaseSync, PhaseQuiescing, PhaseFinalSync, PhaseCutoverReady, PhaseCutoverCommitting, PhaseVerifying},
	}
	for _, candidate := range allowed[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

func validatePlan(value Plan) error {
	if !value.ID.Valid() || !value.MigrationID.Valid() || !isDigest(value.ManifestRoot) || !isDigest(value.DryRunDigest) || value.RollbackWindow <= 0 || value.QuiesceMode == "" || value.CutoverMethod == "" {
		return ErrInvalid
	}
	for _, mapping := range value.Mappings {
		if mapping.SourceKind == "" || !mapping.SourceID.Valid() || !validDisposition(mapping.Disposition) {
			return ErrInvalid
		}
	}
	return nil
}

func validDisposition(value ResourceDisposition) bool {
	switch value {
	case DispositionCreate, DispositionMerge, DispositionReplace, DispositionSkip, DispositionBlock:
		return true
	default:
		return false
	}
}

func validateProgress(value ResourceProgress) error {
	if !value.MigrationID.Valid() || value.Kind == "" || !value.SourceID.Valid() || !value.TargetID.Valid() || !validPhase(value.Phase) || value.UpdatedAt.IsZero() || len(value.EffectID) > 256 || len(value.Checkpoint) > 4096 {
		return ErrInvalid
	}
	return nil
}

func validReceiptKind(kind string) bool {
	if len(kind) < 1 || len(kind) > 64 {
		return false
	}
	for _, character := range kind {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func canonicalJSON(value any, limit int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, ErrCapacity
	}
	return raw, nil
}

func strictDecode(raw []byte, destination any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrInvalid
	}
	return nil
}

func encodeTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func decodeTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, ErrInvalid
	}
	return parsed.UTC(), nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique") || strings.Contains(message, "constraint") || strings.Contains(message, "duplicate")
}

func (r *SQLRepository) String() string {
	return fmt.Sprintf("migration.SQLRepository(%p)", r)
}
