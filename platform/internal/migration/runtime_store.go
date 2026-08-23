package migration

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	DefaultChunkQuarantineDelay = 24 * time.Hour
	maximumChunkQuarantineDelay = 365 * 24 * time.Hour
)

const runtimeScopeSchema = `
CREATE TABLE IF NOT EXISTS panel_migration_scopes (
  migration_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source_endpoint TEXT NOT NULL,
  generation INTEGER NOT NULL,
  last_command_id TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS panel_migration_scopes_tenant
  ON panel_migration_scopes(tenant_id,migration_id);
CREATE TABLE IF NOT EXISTS panel_migration_chunk_objects (
  digest TEXT PRIMARY KEY,
  size_bytes INTEGER NOT NULL,
  object_epoch INTEGER NOT NULL,
  materialized INTEGER NOT NULL,
  state TEXT NOT NULL,
  quarantine_after TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK(size_bytes >= 0),
  CHECK(object_epoch > 0),
  CHECK(materialized IN (0,1)),
  CHECK(state IN ('active','quarantined','deleting','ambiguous','deleted'))
);
CREATE TABLE IF NOT EXISTS panel_migration_chunk_refs (
  tenant_id TEXT NOT NULL,
  migration_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  object_epoch INTEGER NOT NULL,
  state TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  released_at TEXT NOT NULL,
  PRIMARY KEY(migration_id,digest),
  FOREIGN KEY(migration_id) REFERENCES panel_migration_scopes(migration_id) ON DELETE RESTRICT,
  FOREIGN KEY(digest) REFERENCES panel_migration_chunk_objects(digest) ON DELETE RESTRICT,
  CHECK(object_epoch > 0),
  CHECK(state IN ('active','released'))
);
CREATE INDEX IF NOT EXISTS panel_migration_chunk_refs_owner
  ON panel_migration_chunk_refs(tenant_id,migration_id,state,digest);
CREATE INDEX IF NOT EXISTS panel_migration_chunk_refs_object
  ON panel_migration_chunk_refs(digest,object_epoch,state);
CREATE TABLE IF NOT EXISTS panel_migration_chunk_release_receipts (
  migration_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  receipt_json BLOB NOT NULL,
  released_at TEXT NOT NULL,
  FOREIGN KEY(migration_id) REFERENCES panel_migration_scopes(migration_id) ON DELETE RESTRICT,
  CHECK(reason IN ('canceled','completed','expired'))
);
CREATE TABLE IF NOT EXISTS panel_migration_chunk_gc_receipts (
  digest TEXT NOT NULL,
  object_epoch INTEGER NOT NULL,
  state TEXT NOT NULL,
  receipt_json BLOB NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(digest,object_epoch),
  FOREIGN KEY(digest) REFERENCES panel_migration_chunk_objects(digest) ON DELETE RESTRICT,
  CHECK(object_epoch > 0),
  CHECK(state IN ('prepared','completed','ambiguous'))
);`

// RuntimeScope binds orchestration state to the tenant and remote extractor
// endpoint authorized at creation time. Source credentials are deliberately
// absent; the extractor connection is authenticated by TLS and signed manifest
// trust configured outside the control database.
type RuntimeScope struct {
	MigrationID   ID
	TenantID      string
	SourceEndpoint string
	Generation    uint64
	LastCommandID string
	UpdatedAt     time.Time
}

type ScopedMigration struct {
	Scope     RuntimeScope
	Migration Migration
}

type ChunkReference struct {
	TenantID     string
	MigrationID  ID
	Digest       string
	Size         uint64
	ObjectEpoch  uint64
	Materialized bool
}

type ChunkReleaseReason string

const (
	ChunkReleaseCanceled  ChunkReleaseReason = "canceled"
	ChunkReleaseCompleted ChunkReleaseReason = "completed"
	ChunkReleaseExpired   ChunkReleaseReason = "expired"
)

type ChunkReleaseEntry struct {
	Digest          string
	Size            uint64
	ObjectEpoch     uint64
	Quarantined     bool
	QuarantineAfter time.Time
}

type ChunkReleaseReceipt struct {
	MigrationID    ID
	TenantID       string
	Reason         ChunkReleaseReason
	Chunks         []ChunkReleaseEntry
	ReleasedAt     time.Time
	EvidenceDigest string
}

type ChunkGCReceipt struct {
	Digest          string
	Size            uint64
	ObjectEpoch     uint64
	QuarantineAfter time.Time
	State           string
	StartedAt       time.Time
	CompletedAt     time.Time
	EvidenceDigest  string
}

type ChunkReferenceStore interface {
	AcquireChunkReference(context.Context, ID, Chunk) (ChunkReference, error)
	ConfirmChunkReference(context.Context, ID, Chunk) error
	ReleaseChunkReferences(context.Context, ID, ChunkReleaseReason, time.Duration) (ChunkReleaseReceipt, error)
}

type RuntimeScopeStore struct {
	db    *sql.DB
	clock func() time.Time
	mu    sync.Mutex
}

func NewRuntimeScopeStore(db *sql.DB) (*RuntimeScopeStore, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &RuntimeScopeStore{db: db, clock: time.Now}, nil
}

func (store *RuntimeScopeStore) Bootstrap(ctx context.Context) error {
	if store == nil || store.db == nil || ctx == nil {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	_, err := store.db.ExecContext(ctx, runtimeScopeSchema+chunkMaintenanceSchema)
	return err
}

func (store *RuntimeScopeStore) Create(ctx context.Context, scope RuntimeScope) (bool, error) {
	if store == nil || store.db == nil || ctx == nil || validateRuntimeScope(scope) != nil || scope.Generation != 1 {
		return false, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	_, err := store.db.ExecContext(ctx, `INSERT INTO panel_migration_scopes(migration_id,tenant_id,source_endpoint,generation,last_command_id,updated_at) VALUES(?,?,?,?,?,?)`, scope.MigrationID.String(), scope.TenantID, scope.SourceEndpoint, scope.Generation, scope.LastCommandID, encodeTime(scope.UpdatedAt))
	if err == nil {
		return true, nil
	}
	if !isUniqueViolation(err) {
		return false, err
	}
	existing, loadErr := store.Load(ctx, scope.TenantID, scope.MigrationID)
	if loadErr == nil && existing.SourceEndpoint == scope.SourceEndpoint && existing.LastCommandID == scope.LastCommandID {
		return false, nil
	}
	return false, errors.Join(ErrConflict, loadErr)
}

func (store *RuntimeScopeStore) RemoveUnstarted(ctx context.Context, tenantID string, migrationID ID, commandID string) error {
	if store == nil || store.db == nil || ctx == nil || !runtimeScopeText(tenantID, 128) || !migrationID.Valid() || !runtimeScopeText(commandID, 256) {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	_, err := store.db.ExecContext(ctx, `DELETE FROM panel_migration_scopes WHERE migration_id=? AND tenant_id=? AND generation=1 AND last_command_id=?`, migrationID.String(), tenantID, commandID)
	return err
}

func (store *RuntimeScopeStore) Load(ctx context.Context, tenantID string, migrationID ID) (RuntimeScope, error) {
	if store == nil || store.db == nil || ctx == nil || !runtimeScopeText(tenantID, 128) || !migrationID.Valid() {
		return RuntimeScope{}, ErrInvalid
	}
	return store.scan(store.db.QueryRowContext(ctx, `SELECT source_endpoint,generation,last_command_id,updated_at FROM panel_migration_scopes WHERE migration_id=? AND tenant_id=?`, migrationID.String(), tenantID), tenantID, migrationID)
}

func (store *RuntimeScopeStore) LoadByMigration(ctx context.Context, migrationID ID) (RuntimeScope, error) {
	if store == nil || store.db == nil || ctx == nil || !migrationID.Valid() {
		return RuntimeScope{}, ErrInvalid
	}
	var tenantID string
	err := store.db.QueryRowContext(ctx, `SELECT tenant_id FROM panel_migration_scopes WHERE migration_id=?`, migrationID.String()).Scan(&tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeScope{}, ErrNotFound
	}
	if err != nil {
		return RuntimeScope{}, err
	}
	return store.Load(ctx, tenantID, migrationID)
}

func (store *RuntimeScopeStore) Claim(ctx context.Context, tenantID string, migrationID ID, expected uint64, commandID string) (RuntimeScope, error) {
	if store == nil || store.db == nil || ctx == nil || !runtimeScopeText(tenantID, 128) || !migrationID.Valid() || expected == 0 || !runtimeScopeText(commandID, 256) {
		return RuntimeScope{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.clock().UTC()
	result, err := store.db.ExecContext(ctx, `UPDATE panel_migration_scopes SET generation=generation+1,last_command_id=?,updated_at=? WHERE migration_id=? AND tenant_id=? AND generation=?`, commandID, encodeTime(now), migrationID.String(), tenantID, expected)
	if err != nil {
		return RuntimeScope{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return RuntimeScope{}, ErrConflict
	}
	return store.Load(ctx, tenantID, migrationID)
}

func (store *RuntimeScopeStore) List(ctx context.Context, tenantID string, limit uint16, cursor string) ([]ScopedMigration, string, uint64, error) {
	if store == nil || store.db == nil || ctx == nil || !runtimeScopeText(tenantID, 128) || limit == 0 || limit > 200 || cursor != "" && !ID(cursor).Valid() {
		return nil, "", 0, ErrInvalid
	}
	var total uint64
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_scopes WHERE tenant_id=?`, tenantID).Scan(&total); err != nil {
		return nil, "", 0, err
	}
	rows, err := store.db.QueryContext(ctx, `SELECT s.migration_id,s.source_endpoint,s.generation,s.last_command_id,s.updated_at,m.source,m.phase,m.attempt_id,m.manifest_root,m.plan_digest,m.source_generation,m.target_generation,m.fence,m.last_checkpoint,m.target_write_watermark,m.rollback_deadline,m.created_at,m.updated_at,m.error_code,m.error_message FROM panel_migration_scopes s JOIN panel_migrations m ON m.id=s.migration_id WHERE s.tenant_id=? AND s.migration_id>? ORDER BY s.migration_id LIMIT ?`, tenantID, cursor, int(limit)+1)
	if err != nil {
		return nil, "", 0, err
	}
	defer rows.Close()
	values := make([]ScopedMigration, 0, limit)
	for rows.Next() {
		var value ScopedMigration
		var migrationID, source, phase, scopeUpdated, rollbackDeadline, createdAt, updatedAt string
		if err := rows.Scan(&migrationID, &value.Scope.SourceEndpoint, &value.Scope.Generation, &value.Scope.LastCommandID, &scopeUpdated, &source, &phase, &value.Migration.AttemptID, &value.Migration.ManifestRoot, &value.Migration.PlanDigest, &value.Migration.SourceGeneration, &value.Migration.TargetGeneration, &value.Migration.Fence, &value.Migration.LastCheckpoint, &value.Migration.TargetWriteWatermark, &rollbackDeadline, &createdAt, &updatedAt, &value.Migration.ErrorCode, &value.Migration.ErrorMessage); err != nil {
			return nil, "", 0, err
		}
		id, parseErr := NewID(migrationID)
		if parseErr != nil {
			return nil, "", 0, ErrInvalid
		}
		value.Scope.MigrationID, value.Scope.TenantID = id, tenantID
		value.Migration.ID, value.Migration.Source, value.Migration.Phase = id, SourceKind(source), Phase(phase)
		if value.Scope.UpdatedAt, parseErr = decodeTime(scopeUpdated); parseErr != nil {
			return nil, "", 0, parseErr
		}
		if value.Migration.RollbackDeadline, parseErr = decodeTime(rollbackDeadline); parseErr != nil {
			return nil, "", 0, parseErr
		}
		if value.Migration.CreatedAt, parseErr = decodeTime(createdAt); parseErr != nil {
			return nil, "", 0, parseErr
		}
		if value.Migration.UpdatedAt, parseErr = decodeTime(updatedAt); parseErr != nil || validateRuntimeScope(value.Scope) != nil || validateMigration(value.Migration) != nil {
			return nil, "", 0, ErrInvalid
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, "", 0, err
	}
	next := ""
	if len(values) > int(limit) {
		next = values[limit-1].Migration.ID.String()
		values = values[:limit]
	}
	return values, next, total, nil
}

func (store *RuntimeScopeStore) AcquireChunkReference(ctx context.Context, migrationID ID, descriptor Chunk) (ChunkReference, error) {
	if store == nil || store.db == nil || ctx == nil || !migrationID.Valid() || !validChunk(descriptor, uint64(math.MaxInt64)) {
		return ChunkReference{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ChunkReference{}, err
	}
	defer tx.Rollback()
	var tenantID string
	if err = tx.QueryRowContext(ctx, `SELECT tenant_id FROM panel_migration_scopes WHERE migration_id=?`, migrationID.String()).Scan(&tenantID); errors.Is(err, sql.ErrNoRows) {
		return ChunkReference{}, ErrNotFound
	} else if err != nil {
		return ChunkReference{}, err
	}
	if !runtimeScopeText(tenantID, 128) {
		return ChunkReference{}, ErrAmbiguous
	}
	var released int
	if err = tx.QueryRowContext(ctx, `SELECT 1 FROM panel_migration_chunk_release_receipts WHERE migration_id=?`, migrationID.String()).Scan(&released); err == nil {
		return ChunkReference{}, ErrConflict
	} else if !errors.Is(err, sql.ErrNoRows) {
		return ChunkReference{}, err
	}
	var storedSize, storedEpoch int64
	var materialized int
	var state string
	err = tx.QueryRowContext(ctx, `SELECT size_bytes,object_epoch,materialized,state FROM panel_migration_chunk_objects WHERE digest=?`, descriptor.Digest).Scan(&storedSize, &storedEpoch, &materialized, &state)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		storedSize, storedEpoch, materialized, state = int64(descriptor.Size), 1, 0, "active"
		if _, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_chunk_objects(digest,size_bytes,object_epoch,materialized,state,quarantine_after,updated_at) VALUES(?,?,1,0,'active','',?)`, descriptor.Digest, storedSize, encodeTime(store.clock().UTC())); err != nil {
			return ChunkReference{}, err
		}
	case err != nil:
		return ChunkReference{}, err
	case !validStoredChunkObject(descriptor.Digest, storedSize, storedEpoch, materialized, state) || uint64(storedSize) != descriptor.Size:
		return ChunkReference{}, ErrAmbiguous
	case state == "deleting" || state == "ambiguous":
		return ChunkReference{}, ErrAmbiguous
	case state == "quarantined" || state == "deleted":
		var active uint64
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_chunk_refs WHERE digest=? AND object_epoch=? AND state='active'`, descriptor.Digest, storedEpoch).Scan(&active); err != nil {
			return ChunkReference{}, err
		}
		if active != 0 {
			return ChunkReference{}, ErrAmbiguous
		}
		expectedEpoch := storedEpoch
		if state == "deleted" {
			if storedEpoch == math.MaxInt64 {
				return ChunkReference{}, ErrAmbiguous
			}
			storedEpoch++
			materialized = 0
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE panel_migration_chunk_objects SET object_epoch=?,materialized=?,state='active',quarantine_after='',updated_at=? WHERE digest=? AND object_epoch=? AND state=?`, storedEpoch, materialized, encodeTime(store.clock().UTC()), descriptor.Digest, expectedEpoch, state)
		if updateErr != nil {
			return ChunkReference{}, updateErr
		}
		if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
			return ChunkReference{}, ErrConflict
		}
	case state != "active":
		return ChunkReference{}, ErrAmbiguous
	}
	var referenceTenant, referenceState string
	var referenceEpoch int64
	err = tx.QueryRowContext(ctx, `SELECT tenant_id,object_epoch,state FROM panel_migration_chunk_refs WHERE migration_id=? AND digest=?`, migrationID.String(), descriptor.Digest).Scan(&referenceTenant, &referenceEpoch, &referenceState)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_chunk_refs(tenant_id,migration_id,digest,object_epoch,state,acquired_at,released_at) VALUES(?,?,?,?, 'active',?,'')`, tenantID, migrationID.String(), descriptor.Digest, storedEpoch, encodeTime(store.clock().UTC())); err != nil {
			return ChunkReference{}, err
		}
	case err != nil:
		return ChunkReference{}, err
	case referenceTenant != tenantID || referenceEpoch != storedEpoch || referenceState != "active":
		return ChunkReference{}, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return ChunkReference{}, err
	}
	return ChunkReference{TenantID: tenantID, MigrationID: migrationID, Digest: descriptor.Digest, Size: descriptor.Size, ObjectEpoch: uint64(storedEpoch), Materialized: materialized == 1}, nil
}

func (store *RuntimeScopeStore) ConfirmChunkReference(ctx context.Context, migrationID ID, descriptor Chunk) error {
	if store == nil || store.db == nil || ctx == nil || !migrationID.Valid() || !validChunk(descriptor, uint64(math.MaxInt64)) {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var storedSize, objectEpoch, referenceEpoch int64
	var materialized int
	var objectState, referenceState string
	err = tx.QueryRowContext(ctx, `SELECT o.size_bytes,o.object_epoch,o.materialized,o.state,r.object_epoch,r.state FROM panel_migration_chunk_objects o JOIN panel_migration_chunk_refs r ON r.digest=o.digest WHERE r.migration_id=? AND o.digest=?`, migrationID.String(), descriptor.Digest).Scan(&storedSize, &objectEpoch, &materialized, &objectState, &referenceEpoch, &referenceState)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !validStoredChunkObject(descriptor.Digest, storedSize, objectEpoch, materialized, objectState) || uint64(storedSize) != descriptor.Size || objectState != "active" || referenceState != "active" || referenceEpoch != objectEpoch {
		return ErrAmbiguous
	}
	if materialized == 1 {
		return nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_chunk_objects SET materialized=1,updated_at=? WHERE digest=? AND object_epoch=? AND state='active' AND materialized=0`, encodeTime(store.clock().UTC()), descriptor.Digest, objectEpoch)
	if err != nil {
		return err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (store *RuntimeScopeStore) ReleaseChunkReferences(ctx context.Context, migrationID ID, reason ChunkReleaseReason, quarantineDelay time.Duration) (ChunkReleaseReceipt, error) {
	if store == nil || store.db == nil || ctx == nil || !migrationID.Valid() || !validChunkReleaseReason(reason) || quarantineDelay <= 0 || quarantineDelay > maximumChunkQuarantineDelay {
		return ChunkReleaseReceipt{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.releaseChunkReferencesLocked(ctx, migrationID, reason, quarantineDelay)
}

func (store *RuntimeScopeStore) releaseChunkReferencesLocked(ctx context.Context, migrationID ID, reason ChunkReleaseReason, quarantineDelay time.Duration) (ChunkReleaseReceipt, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ChunkReleaseReceipt{}, err
	}
	defer tx.Rollback()
	var tenantID string
	if err = tx.QueryRowContext(ctx, `SELECT tenant_id FROM panel_migration_scopes WHERE migration_id=?`, migrationID.String()).Scan(&tenantID); errors.Is(err, sql.ErrNoRows) {
		return ChunkReleaseReceipt{}, ErrNotFound
	} else if err != nil {
		return ChunkReleaseReceipt{}, err
	}
	if !runtimeScopeText(tenantID, 128) {
		return ChunkReleaseReceipt{}, ErrAmbiguous
	}
	var existingRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT receipt_json FROM panel_migration_chunk_release_receipts WHERE migration_id=?`, migrationID.String()).Scan(&existingRaw); err == nil {
		var existing ChunkReleaseReceipt
		if decodeErr := strictDecode(existingRaw, &existing, 8<<20); decodeErr != nil || !validChunkReleaseReceipt(existing) || existing.MigrationID != migrationID || existing.TenantID != tenantID || existing.Reason != reason {
			return ChunkReleaseReceipt{}, ErrAmbiguous
		}
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return ChunkReleaseReceipt{}, err
	}
	var previouslyReleased uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_chunk_refs WHERE migration_id=? AND state='released'`, migrationID.String()).Scan(&previouslyReleased); err != nil {
		return ChunkReleaseReceipt{}, err
	}
	if previouslyReleased != 0 {
		return ChunkReleaseReceipt{}, ErrAmbiguous
	}
	var activeReferences uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_chunk_refs WHERE migration_id=? AND state='active'`, migrationID.String()).Scan(&activeReferences); err != nil {
		return ChunkReleaseReceipt{}, err
	}
	type releaseCandidate struct {
		digest       string
		size         int64
		epoch        int64
		materialized int
		state        string
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.digest,o.size_bytes,o.object_epoch,o.materialized,o.state FROM panel_migration_chunk_refs r JOIN panel_migration_chunk_objects o ON o.digest=r.digest AND o.object_epoch=r.object_epoch WHERE r.migration_id=? AND r.tenant_id=? AND r.state='active' ORDER BY r.digest`, migrationID.String(), tenantID)
	if err != nil {
		return ChunkReleaseReceipt{}, err
	}
	var candidates []releaseCandidate
	for rows.Next() {
		var candidate releaseCandidate
		if err = rows.Scan(&candidate.digest, &candidate.size, &candidate.epoch, &candidate.materialized, &candidate.state); err != nil {
			rows.Close()
			return ChunkReleaseReceipt{}, err
		}
		if !validStoredChunkObject(candidate.digest, candidate.size, candidate.epoch, candidate.materialized, candidate.state) || candidate.state != "active" {
			rows.Close()
			return ChunkReleaseReceipt{}, ErrAmbiguous
		}
		candidates = append(candidates, candidate)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return ChunkReleaseReceipt{}, err
	}
	if err = rows.Close(); err != nil {
		return ChunkReleaseReceipt{}, err
	}
	if activeReferences != uint64(len(candidates)) {
		return ChunkReleaseReceipt{}, ErrAmbiguous
	}
	now := store.clock().UTC()
	receipt := ChunkReleaseReceipt{MigrationID: migrationID, TenantID: tenantID, Reason: reason, Chunks: make([]ChunkReleaseEntry, 0, len(candidates)), ReleasedAt: now}
	for _, candidate := range candidates {
		result, updateErr := tx.ExecContext(ctx, `UPDATE panel_migration_chunk_refs SET state='released',released_at=? WHERE migration_id=? AND tenant_id=? AND digest=? AND object_epoch=? AND state='active'`, encodeTime(now), migrationID.String(), tenantID, candidate.digest, candidate.epoch)
		if updateErr != nil {
			return ChunkReleaseReceipt{}, updateErr
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
			return ChunkReleaseReceipt{}, ErrConflict
		}
		var active uint64
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_chunk_refs WHERE digest=? AND object_epoch=? AND state='active'`, candidate.digest, candidate.epoch).Scan(&active); err != nil {
			return ChunkReleaseReceipt{}, err
		}
		entry := ChunkReleaseEntry{Digest: candidate.digest, Size: uint64(candidate.size), ObjectEpoch: uint64(candidate.epoch)}
		if active == 0 {
			entry.Quarantined = true
			entry.QuarantineAfter = now.Add(quarantineDelay)
			result, updateErr = tx.ExecContext(ctx, `UPDATE panel_migration_chunk_objects SET state='quarantined',quarantine_after=?,updated_at=? WHERE digest=? AND object_epoch=? AND state='active'`, encodeTime(entry.QuarantineAfter), encodeTime(now), candidate.digest, candidate.epoch)
			if updateErr != nil {
				return ChunkReleaseReceipt{}, updateErr
			}
			if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
				return ChunkReleaseReceipt{}, ErrConflict
			}
		}
		receipt.Chunks = append(receipt.Chunks, entry)
	}
	receipt.EvidenceDigest = chunkReleaseEvidence(receipt)
	raw, err := canonicalJSON(receipt, 8<<20)
	if err != nil {
		return ChunkReleaseReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_chunk_release_receipts(migration_id,tenant_id,reason,receipt_json,released_at) VALUES(?,?,?,?,?)`, migrationID.String(), tenantID, string(reason), raw, encodeTime(now)); err != nil {
		return ChunkReleaseReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return ChunkReleaseReceipt{}, err
	}
	return receipt, nil
}

func (store *RuntimeScopeStore) ReleaseExpiredChunkReferences(ctx context.Context, expiredBefore time.Time, quarantineDelay time.Duration, limit uint16) ([]ChunkReleaseReceipt, error) {
	receipts, _, err := store.releaseExpiredChunkReferencesAfter(ctx, expiredBefore, quarantineDelay, "", limit)
	return receipts, err
}

func (store *RuntimeScopeStore) releaseExpiredChunkReferencesAfter(ctx context.Context, expiredBefore time.Time, quarantineDelay time.Duration, cursor string, limit uint16) ([]ChunkReleaseReceipt, string, error) {
	if store == nil || store.db == nil || ctx == nil || expiredBefore.IsZero() || expiredBefore.After(store.clock().UTC()) || quarantineDelay <= 0 || quarantineDelay > maximumChunkQuarantineDelay || limit == 0 || limit > 200 {
		return nil, cursor, ErrInvalid
	}
	if cursor != "" {
		if _, err := NewID(cursor); err != nil {
			return nil, cursor, ErrInvalid
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	rows, err := store.db.QueryContext(ctx, `SELECT DISTINCT s.migration_id FROM panel_migration_scopes s JOIN panel_migration_chunk_refs r ON r.migration_id=s.migration_id AND r.state='active' LEFT JOIN panel_migration_chunk_release_receipts x ON x.migration_id=s.migration_id WHERE s.updated_at<=? AND x.migration_id IS NULL AND s.migration_id>? ORDER BY s.migration_id LIMIT ?`, encodeTime(expiredBefore.UTC()), cursor, int(limit))
	if err != nil {
		return nil, cursor, err
	}
	var migrationIDs []ID
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, cursor, err
		}
		id, parseErr := NewID(raw)
		if parseErr != nil {
			rows.Close()
			return nil, cursor, ErrAmbiguous
		}
		migrationIDs = append(migrationIDs, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, cursor, err
	}
	if err = rows.Close(); err != nil {
		return nil, cursor, err
	}
	if len(migrationIDs) == 0 {
		return []ChunkReleaseReceipt{}, "", nil
	}
	receipts := make([]ChunkReleaseReceipt, 0, len(migrationIDs))
	next := cursor
	for _, migrationID := range migrationIDs {
		receipt, releaseErr := store.releaseChunkReferencesLocked(ctx, migrationID, ChunkReleaseExpired, quarantineDelay)
		if releaseErr != nil {
			return receipts, next, releaseErr
		}
		receipts = append(receipts, receipt)
		next = migrationID.String()
	}
	return receipts, next, nil
}

type chunkGCCandidate struct {
	digest          string
	size            int64
	epoch           int64
	materialized    int
	state           string
	quarantineAfter time.Time
}

func (store *RuntimeScopeStore) CollectChunkGarbage(ctx context.Context, chunks *ChunkStore, limit uint16) ([]ChunkGCReceipt, error) {
	receipts, _, err := store.collectChunkGarbageAfter(ctx, chunks, "", limit)
	return receipts, err
}

func (store *RuntimeScopeStore) collectChunkGarbageAfter(ctx context.Context, chunks *ChunkStore, cursor string, limit uint16) ([]ChunkGCReceipt, string, error) {
	if store == nil || store.db == nil || ctx == nil || chunks == nil || cursor != "" && !isDigest(cursor) || limit == 0 || limit > 200 {
		return nil, cursor, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.clock().UTC()
	rows, err := store.db.QueryContext(ctx, `SELECT digest,size_bytes,object_epoch,materialized,state,quarantine_after FROM panel_migration_chunk_objects WHERE ((state='quarantined' AND quarantine_after<>'' AND quarantine_after<=?) OR state='deleting') AND digest>? ORDER BY digest LIMIT ?`, encodeTime(now), cursor, int(limit))
	if err != nil {
		return nil, cursor, err
	}
	var candidates []chunkGCCandidate
	for rows.Next() {
		var candidate chunkGCCandidate
		var quarantineAfter string
		if err = rows.Scan(&candidate.digest, &candidate.size, &candidate.epoch, &candidate.materialized, &candidate.state, &quarantineAfter); err != nil {
			rows.Close()
			return nil, cursor, err
		}
		candidate.quarantineAfter, err = decodeTime(quarantineAfter)
		if err != nil || !validStoredChunkObject(candidate.digest, candidate.size, candidate.epoch, candidate.materialized, candidate.state) || candidate.quarantineAfter.IsZero() || candidate.quarantineAfter.After(now) && candidate.state == "quarantined" {
			rows.Close()
			return nil, cursor, ErrAmbiguous
		}
		candidates = append(candidates, candidate)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, cursor, err
	}
	if err = rows.Close(); err != nil {
		return nil, cursor, err
	}
	if len(candidates) == 0 {
		return []ChunkGCReceipt{}, "", nil
	}
	receipts := make([]ChunkGCReceipt, 0, len(candidates))
	next := cursor
	for _, candidate := range candidates {
		var receipt ChunkGCReceipt
		if candidate.state == "quarantined" {
			if inspectErr := chunks.inspectForGarbageCollection(ctx, candidate.digest, uint64(candidate.size), candidate.materialized == 0); inspectErr != nil {
				if ctx.Err() != nil {
					return receipts, next, ctx.Err()
				}
				ambiguous, markErr := store.markChunkGCAmbiguousLocked(ctx, candidate)
				if markErr == nil {
					receipts = append(receipts, ambiguous)
					next = candidate.digest
				}
				return receipts, next, errors.Join(ErrAmbiguous, inspectErr, markErr)
			}
			receipt, err = store.prepareChunkGCLocked(ctx, candidate, now)
		} else {
			receipt, err = store.loadPreparedChunkGCLocked(ctx, candidate)
		}
		if err != nil {
			if ctx.Err() != nil {
				return receipts, next, ctx.Err()
			}
			if errors.Is(err, ErrAmbiguous) {
				ambiguous, markErr := store.markChunkGCAmbiguousLocked(ctx, candidate)
				if markErr == nil {
					receipts = append(receipts, ambiguous)
					next = candidate.digest
				}
				return receipts, next, errors.Join(ErrAmbiguous, err, markErr)
			}
			return receipts, next, err
		}
		allowMissing := candidate.state == "deleting" || candidate.materialized == 0
		if err = chunks.deleteQuarantined(ctx, candidate.digest, uint64(candidate.size), allowMissing); err != nil {
			if ctx.Err() != nil {
				return receipts, next, ctx.Err()
			}
			ambiguous, markErr := store.markChunkGCAmbiguousLocked(ctx, candidate)
			if markErr == nil {
				receipts = append(receipts, ambiguous)
				next = candidate.digest
			}
			return receipts, next, errors.Join(ErrAmbiguous, err, markErr)
		}
		receipt, err = store.completeChunkGCLocked(ctx, candidate, receipt)
		if err != nil {
			if ctx.Err() != nil {
				return receipts, next, ctx.Err()
			}
			ambiguous, markErr := store.markChunkGCAmbiguousLocked(ctx, candidate)
			if markErr == nil {
				receipts = append(receipts, ambiguous)
				next = candidate.digest
			}
			return receipts, next, errors.Join(ErrAmbiguous, err, markErr)
		}
		receipts = append(receipts, receipt)
		next = candidate.digest
	}
	return receipts, next, nil
}

func (store *RuntimeScopeStore) prepareChunkGCLocked(ctx context.Context, candidate chunkGCCandidate, now time.Time) (ChunkGCReceipt, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	defer tx.Rollback()
	var size, epoch int64
	var materialized int
	var state, quarantineAfter string
	if err = tx.QueryRowContext(ctx, `SELECT size_bytes,object_epoch,materialized,state,quarantine_after FROM panel_migration_chunk_objects WHERE digest=?`, candidate.digest).Scan(&size, &epoch, &materialized, &state, &quarantineAfter); err != nil {
		return ChunkGCReceipt{}, err
	}
	parsedAfter, parseErr := decodeTime(quarantineAfter)
	if parseErr != nil || size != candidate.size || epoch != candidate.epoch || materialized != candidate.materialized || state != "quarantined" || !parsedAfter.Equal(candidate.quarantineAfter) || parsedAfter.After(now) {
		return ChunkGCReceipt{}, ErrConflict
	}
	var active uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_chunk_refs WHERE digest=? AND object_epoch=? AND state='active'`, candidate.digest, candidate.epoch).Scan(&active); err != nil {
		return ChunkGCReceipt{}, err
	}
	if active != 0 {
		return ChunkGCReceipt{}, ErrConflict
	}
	receipt := ChunkGCReceipt{Digest: candidate.digest, Size: uint64(candidate.size), ObjectEpoch: uint64(candidate.epoch), QuarantineAfter: candidate.quarantineAfter, State: "prepared", StartedAt: now}
	receipt.EvidenceDigest = chunkGCEvidence(receipt)
	raw, err := canonicalJSON(receipt, 1<<20)
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_chunk_objects SET state='deleting',updated_at=? WHERE digest=? AND object_epoch=? AND state='quarantined' AND quarantine_after=?`, encodeTime(now), candidate.digest, candidate.epoch, encodeTime(candidate.quarantineAfter))
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return ChunkGCReceipt{}, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_chunk_gc_receipts(digest,object_epoch,state,receipt_json,updated_at) VALUES(?,?,'prepared',?,?)`, candidate.digest, candidate.epoch, raw, encodeTime(now)); err != nil {
		return ChunkGCReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return ChunkGCReceipt{}, err
	}
	return receipt, nil
}

func (store *RuntimeScopeStore) loadPreparedChunkGCLocked(ctx context.Context, candidate chunkGCCandidate) (ChunkGCReceipt, error) {
	var state string
	var raw []byte
	if err := store.db.QueryRowContext(ctx, `SELECT state,receipt_json FROM panel_migration_chunk_gc_receipts WHERE digest=? AND object_epoch=?`, candidate.digest, candidate.epoch).Scan(&state, &raw); errors.Is(err, sql.ErrNoRows) {
		return ChunkGCReceipt{}, ErrAmbiguous
	} else if err != nil {
		return ChunkGCReceipt{}, err
	}
	var receipt ChunkGCReceipt
	if state != "prepared" || strictDecode(raw, &receipt, 1<<20) != nil || !validChunkGCReceipt(receipt) || receipt.State != "prepared" || receipt.Digest != candidate.digest || receipt.Size != uint64(candidate.size) || receipt.ObjectEpoch != uint64(candidate.epoch) || !receipt.QuarantineAfter.Equal(candidate.quarantineAfter) {
		return ChunkGCReceipt{}, ErrAmbiguous
	}
	return receipt, nil
}

func (store *RuntimeScopeStore) completeChunkGCLocked(ctx context.Context, candidate chunkGCCandidate, prepared ChunkGCReceipt) (ChunkGCReceipt, error) {
	if !validChunkGCReceipt(prepared) || prepared.State != "prepared" || prepared.Digest != candidate.digest || prepared.Size != uint64(candidate.size) || prepared.ObjectEpoch != uint64(candidate.epoch) || !prepared.QuarantineAfter.Equal(candidate.quarantineAfter) {
		return ChunkGCReceipt{}, ErrInvalid
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	defer tx.Rollback()
	var active uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_migration_chunk_refs WHERE digest=? AND object_epoch=? AND state='active'`, candidate.digest, candidate.epoch).Scan(&active); err != nil {
		return ChunkGCReceipt{}, err
	}
	if active != 0 {
		return ChunkGCReceipt{}, ErrAmbiguous
	}
	completed := prepared
	completed.State = "completed"
	completed.CompletedAt = store.clock().UTC()
	if completed.CompletedAt.Before(completed.StartedAt) {
		completed.CompletedAt = completed.StartedAt
	}
	completed.EvidenceDigest = chunkGCEvidence(completed)
	raw, err := canonicalJSON(completed, 1<<20)
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_chunk_objects SET materialized=0,state='deleted',quarantine_after='',updated_at=? WHERE digest=? AND object_epoch=? AND state='deleting'`, encodeTime(completed.CompletedAt), candidate.digest, candidate.epoch)
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return ChunkGCReceipt{}, ErrAmbiguous
	}
	result, err = tx.ExecContext(ctx, `UPDATE panel_migration_chunk_gc_receipts SET state='completed',receipt_json=?,updated_at=? WHERE digest=? AND object_epoch=? AND state='prepared'`, raw, encodeTime(completed.CompletedAt), candidate.digest, candidate.epoch)
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return ChunkGCReceipt{}, ErrAmbiguous
	}
	if err = tx.Commit(); err != nil {
		return ChunkGCReceipt{}, err
	}
	return completed, nil
}

func (store *RuntimeScopeStore) markChunkGCAmbiguousLocked(ctx context.Context, candidate chunkGCCandidate) (ChunkGCReceipt, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	defer tx.Rollback()
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT state FROM panel_migration_chunk_objects WHERE digest=? AND object_epoch=?`, candidate.digest, candidate.epoch).Scan(&state); err != nil {
		return ChunkGCReceipt{}, err
	}
	var receipt ChunkGCReceipt
	var existingRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT receipt_json FROM panel_migration_chunk_gc_receipts WHERE digest=? AND object_epoch=?`, candidate.digest, candidate.epoch).Scan(&existingRaw); err == nil {
		if decodeErr := strictDecode(existingRaw, &receipt, 1<<20); decodeErr != nil || !validChunkGCReceipt(receipt) || receipt.Digest != candidate.digest || receipt.ObjectEpoch != uint64(candidate.epoch) || receipt.State != "prepared" && receipt.State != "ambiguous" {
			return ChunkGCReceipt{}, ErrAmbiguous
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return ChunkGCReceipt{}, err
	} else {
		startedAt := store.clock().UTC()
		if startedAt.Before(candidate.quarantineAfter) {
			startedAt = candidate.quarantineAfter
		}
		receipt = ChunkGCReceipt{Digest: candidate.digest, Size: uint64(candidate.size), ObjectEpoch: uint64(candidate.epoch), QuarantineAfter: candidate.quarantineAfter, State: "prepared", StartedAt: startedAt}
	}
	if state == "ambiguous" && receipt.State == "ambiguous" {
		return receipt, nil
	}
	if state != "quarantined" && state != "deleting" {
		return ChunkGCReceipt{}, ErrConflict
	}
	receipt.State = "ambiguous"
	receipt.CompletedAt = time.Time{}
	receipt.EvidenceDigest = chunkGCEvidence(receipt)
	raw, err := canonicalJSON(receipt, 1<<20)
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	now := store.clock().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE panel_migration_chunk_objects SET state='ambiguous',updated_at=? WHERE digest=? AND object_epoch=? AND state=?`, encodeTime(now), candidate.digest, candidate.epoch, state)
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return ChunkGCReceipt{}, ErrConflict
	}
	if len(existingRaw) == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO panel_migration_chunk_gc_receipts(digest,object_epoch,state,receipt_json,updated_at) VALUES(?,?,'ambiguous',?,?)`, candidate.digest, candidate.epoch, raw, encodeTime(now))
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE panel_migration_chunk_gc_receipts SET state='ambiguous',receipt_json=?,updated_at=? WHERE digest=? AND object_epoch=?`, raw, encodeTime(now), candidate.digest, candidate.epoch)
	}
	if err != nil {
		return ChunkGCReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return ChunkGCReceipt{}, err
	}
	return receipt, nil
}

func validStoredChunkObject(digest string, size, epoch int64, materialized int, state string) bool {
	if !isDigest(digest) || size < 0 || epoch <= 0 || materialized != 0 && materialized != 1 {
		return false
	}
	switch state {
	case "active", "quarantined", "deleting", "ambiguous", "deleted":
		return true
	default:
		return false
	}
}

func validChunkReleaseReason(reason ChunkReleaseReason) bool {
	return reason == ChunkReleaseCanceled || reason == ChunkReleaseCompleted || reason == ChunkReleaseExpired
}

func validChunkReleaseReceipt(receipt ChunkReleaseReceipt) bool {
	if !receipt.MigrationID.Valid() || !runtimeScopeText(receipt.TenantID, 128) || !validChunkReleaseReason(receipt.Reason) || receipt.ReleasedAt.IsZero() || !isDigest(receipt.EvidenceDigest) || receipt.EvidenceDigest != chunkReleaseEvidence(receipt) {
		return false
	}
	previous := ""
	for _, entry := range receipt.Chunks {
		if !isDigest(entry.Digest) || entry.Digest <= previous || entry.Size > uint64(math.MaxInt64) || entry.ObjectEpoch == 0 || entry.ObjectEpoch > uint64(math.MaxInt64) {
			return false
		}
		if entry.Quarantined {
			if entry.QuarantineAfter.IsZero() || !entry.QuarantineAfter.After(receipt.ReleasedAt) {
				return false
			}
		} else if !entry.QuarantineAfter.IsZero() {
			return false
		}
		previous = entry.Digest
	}
	return true
}

func chunkReleaseEvidence(receipt ChunkReleaseReceipt) string {
	receipt.EvidenceDigest = ""
	return digestJSON(struct {
		Domain  string
		Receipt ChunkReleaseReceipt
	}{"migration-chunk-release-v1", receipt})
}

func validChunkGCReceipt(receipt ChunkGCReceipt) bool {
	if !isDigest(receipt.Digest) || receipt.Size > uint64(math.MaxInt64) || receipt.ObjectEpoch == 0 || receipt.ObjectEpoch > uint64(math.MaxInt64) || receipt.QuarantineAfter.IsZero() || receipt.StartedAt.IsZero() || receipt.StartedAt.Before(receipt.QuarantineAfter) || !isDigest(receipt.EvidenceDigest) || receipt.EvidenceDigest != chunkGCEvidence(receipt) {
		return false
	}
	switch receipt.State {
	case "prepared", "ambiguous":
		return receipt.CompletedAt.IsZero()
	case "completed":
		return !receipt.CompletedAt.IsZero() && !receipt.CompletedAt.Before(receipt.StartedAt)
	default:
		return false
	}
}

func chunkGCEvidence(receipt ChunkGCReceipt) string {
	receipt.EvidenceDigest = ""
	return digestJSON(struct {
		Domain  string
		Receipt ChunkGCReceipt
	}{"migration-chunk-gc-v1", receipt})
}

func (store *RuntimeScopeStore) scan(row *sql.Row, tenantID string, migrationID ID) (RuntimeScope, error) {
	value := RuntimeScope{MigrationID: migrationID, TenantID: tenantID}
	var updatedAt string
	if err := row.Scan(&value.SourceEndpoint, &value.Generation, &value.LastCommandID, &updatedAt); errors.Is(err, sql.ErrNoRows) {
		return RuntimeScope{}, ErrNotFound
	} else if err != nil {
		return RuntimeScope{}, err
	}
	var err error
	value.UpdatedAt, err = decodeTime(updatedAt)
	if err != nil || validateRuntimeScope(value) != nil {
		return RuntimeScope{}, ErrInvalid
	}
	return value, nil
}

func validateRuntimeScope(value RuntimeScope) error {
	if !value.MigrationID.Valid() || !runtimeScopeText(value.TenantID, 128) || !runtimeScopeText(value.SourceEndpoint, 2048) || value.Generation == 0 || !runtimeScopeText(value.LastCommandID, 256) || value.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

func runtimeScopeText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}
