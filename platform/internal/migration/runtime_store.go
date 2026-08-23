package migration

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
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
  ON panel_migration_scopes(tenant_id,migration_id);`

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

type RuntimeScopeStore struct {
	db    *sql.DB
	clock func() time.Time
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
	_, err := store.db.ExecContext(ctx, runtimeScopeSchema)
	return err
}

func (store *RuntimeScopeStore) Create(ctx context.Context, scope RuntimeScope) (bool, error) {
	if store == nil || store.db == nil || ctx == nil || validateRuntimeScope(scope) != nil || scope.Generation != 1 {
		return false, ErrInvalid
	}
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
