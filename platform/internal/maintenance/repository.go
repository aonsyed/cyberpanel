package maintenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const MaxPageSize = 500

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &Repository{db: db}, nil
}

func (repository *Repository) Bootstrap(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS maintenance_windows (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			scope_kind TEXT NOT NULL,
			node_id TEXT NOT NULL,
			resource_kind TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
			generation INTEGER NOT NULL CHECK (generation > 0),
			window_digest TEXT NOT NULL,
			window_json BLOB NOT NULL,
			updated_unix_nano INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS maintenance_windows_tenant_idx
			ON maintenance_windows (tenant_id, deleted, id)`,
		`CREATE INDEX IF NOT EXISTS maintenance_windows_scope_idx
			ON maintenance_windows (tenant_id, enabled, deleted, scope_kind, node_id, resource_kind, resource_id, id)`,
		`CREATE TABLE IF NOT EXISTS maintenance_occurrences (
			id TEXT PRIMARY KEY,
			window_id TEXT NOT NULL,
			window_generation INTEGER NOT NULL CHECK (window_generation > 0),
			starts_unix_nano INTEGER NOT NULL,
			ends_unix_nano INTEGER NOT NULL,
			occurrence_digest TEXT NOT NULL,
			occurrence_json BLOB NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS maintenance_occurrences_window_idx
			ON maintenance_occurrences (window_id, id)`,
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (repository *Repository) CreateWindow(ctx context.Context, window Window) error {
	return repository.putWindow(ctx, window, 0)
}

func (repository *Repository) UpdateWindow(ctx context.Context, window Window, expectedGeneration uint64) error {
	if expectedGeneration == 0 {
		return ErrInvalid
	}
	return repository.putWindow(ctx, window, expectedGeneration)
}

func (repository *Repository) putWindow(ctx context.Context, window Window, expectedGeneration uint64) error {
	canonical, err := CanonicalWindow(window)
	if err != nil || expectedGeneration >= maxGeneration || canonical.Generation != expectedGeneration+1 {
		return ErrInvalid
	}
	raw, digest, err := encodeWindow(canonical)
	if err != nil {
		return err
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if expectedGeneration == 0 {
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO maintenance_windows
			(id, tenant_id, scope_kind, node_id, resource_kind, resource_id, enabled, deleted,
			generation, window_digest, window_json, updated_unix_nano)
			VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`, canonical.ID, canonical.Scope.TenantID,
			canonical.Scope.Kind, canonical.Scope.NodeID, canonical.Scope.ResourceKind,
			canonical.Scope.ResourceID, boolInteger(canonical.Enabled), canonical.Generation,
			digest, raw, canonical.UpdatedAt.UnixNano())
		if err != nil {
			return err
		}
		if !oneRow(result) {
			return ErrConflict
		}
		return tx.Commit()
	}
	previous, err := loadWindowQuery(ctx, tx, canonical.ID)
	if err != nil {
		return err
	}
	if previous.Generation != expectedGeneration {
		return ErrConflict
	}
	if previous.Scope != canonical.Scope || !previous.CreatedAt.Equal(canonical.CreatedAt) || canonical.UpdatedAt.Before(previous.UpdatedAt) {
		return ErrInvalid
	}
	result, err := tx.ExecContext(ctx, `UPDATE maintenance_windows SET tenant_id = ?, scope_kind = ?,
		node_id = ?, resource_kind = ?, resource_id = ?, enabled = ?, generation = ?, window_digest = ?,
		window_json = ?, updated_unix_nano = ? WHERE id = ? AND generation = ? AND deleted = 0`,
		canonical.Scope.TenantID, canonical.Scope.Kind, canonical.Scope.NodeID, canonical.Scope.ResourceKind,
		canonical.Scope.ResourceID, boolInteger(canonical.Enabled), canonical.Generation, digest, raw,
		canonical.UpdatedAt.UnixNano(), canonical.ID, expectedGeneration)
	if err != nil {
		return err
	}
	if !oneRow(result) {
		return ErrConflict
	}
	return tx.Commit()
}

func (repository *Repository) DisableWindow(ctx context.Context, id string, expectedGeneration uint64, at time.Time) (Window, error) {
	if !identifierPattern.MatchString(id) || expectedGeneration == 0 || expectedGeneration >= maxGeneration || !validTimestamp(at) {
		return Window{}, ErrInvalid
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Window{}, err
	}
	defer tx.Rollback()
	window, err := loadWindowQuery(ctx, tx, id)
	if err != nil {
		return Window{}, err
	}
	if window.Generation != expectedGeneration {
		return Window{}, ErrConflict
	}
	if !window.Enabled || at.Before(window.UpdatedAt) {
		return Window{}, ErrInvalid
	}
	window.Enabled = false
	window.Generation++
	window.UpdatedAt = at
	if err := window.Validate(); err != nil {
		return Window{}, err
	}
	raw, digest, err := encodeWindow(window)
	if err != nil {
		return Window{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE maintenance_windows SET enabled = 0, generation = ?,
		window_digest = ?, window_json = ?, updated_unix_nano = ? WHERE id = ? AND generation = ? AND deleted = 0`,
		window.Generation, digest, raw, at.UnixNano(), id, expectedGeneration)
	if err != nil {
		return Window{}, err
	}
	if !oneRow(result) {
		return Window{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Window{}, err
	}
	return window, nil
}

// DeleteWindow leaves a generation tombstone so IDs cannot be reused while
// immutable historical occurrences remain addressable.
func (repository *Repository) DeleteWindow(ctx context.Context, id string, expectedGeneration uint64, at time.Time) error {
	if !identifierPattern.MatchString(id) || expectedGeneration == 0 || expectedGeneration >= maxGeneration || !validTimestamp(at) {
		return ErrInvalid
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	window, err := loadWindowQuery(ctx, tx, id)
	if err != nil {
		return err
	}
	if window.Generation != expectedGeneration {
		return ErrConflict
	}
	if at.Before(window.UpdatedAt) {
		return ErrInvalid
	}
	window.Enabled = false
	window.Generation++
	window.UpdatedAt = at
	if err := window.Validate(); err != nil {
		return err
	}
	raw, digest, err := encodeWindow(window)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE maintenance_windows SET enabled = 0, deleted = 1,
		generation = ?, window_digest = ?, window_json = ?, updated_unix_nano = ?
		WHERE id = ? AND generation = ? AND deleted = 0`, window.Generation, digest, raw,
		at.UnixNano(), id, expectedGeneration)
	if err != nil {
		return err
	}
	if !oneRow(result) {
		return ErrConflict
	}
	return tx.Commit()
}

func (repository *Repository) LoadWindow(ctx context.Context, id string) (Window, error) {
	if !identifierPattern.MatchString(id) {
		return Window{}, ErrInvalid
	}
	return loadWindowQuery(ctx, repository.db, id)
}

type WindowPage struct {
	Windows    []Window
	NextCursor string
}

func (repository *Repository) ListWindows(ctx context.Context, tenantID string, limit int, cursor string) (WindowPage, error) {
	if !identifierPattern.MatchString(tenantID) || !validPage(limit, cursor) {
		return WindowPage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT id, generation, window_digest, window_json
		FROM maintenance_windows WHERE tenant_id = ? AND deleted = 0 AND id > ? ORDER BY id LIMIT ?`,
		tenantID, cursor, limit+1)
	if err != nil {
		return WindowPage{}, err
	}
	defer rows.Close()
	page := WindowPage{Windows: make([]Window, 0, limit)}
	for rows.Next() {
		var id, digest string
		var generation uint64
		var raw []byte
		if err := rows.Scan(&id, &generation, &digest, &raw); err != nil {
			return WindowPage{}, err
		}
		window, err := decodeWindow(raw, digest)
		if err != nil || window.ID != id || window.Generation != generation || window.Scope.TenantID != tenantID {
			return WindowPage{}, ErrIntegrity
		}
		if len(page.Windows) == limit {
			page.NextCursor = page.Windows[len(page.Windows)-1].ID
			break
		}
		page.Windows = append(page.Windows, window)
	}
	if err := rows.Err(); err != nil {
		return WindowPage{}, err
	}
	return page, nil
}

func (repository *Repository) listEnabled(ctx context.Context, tenantID string, limit int) ([]Window, error) {
	if !identifierPattern.MatchString(tenantID) || limit < 1 || limit > MaxPageSize {
		return nil, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT id, generation, window_digest, window_json
		FROM maintenance_windows WHERE tenant_id = ? AND enabled = 1 AND deleted = 0 ORDER BY id LIMIT ?`,
		tenantID, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	windows := make([]Window, 0, limit)
	for rows.Next() {
		if len(windows) == limit {
			return nil, ErrCapacity
		}
		var id, digest string
		var generation uint64
		var raw []byte
		if err := rows.Scan(&id, &generation, &digest, &raw); err != nil {
			return nil, err
		}
		window, err := decodeWindow(raw, digest)
		if err != nil || window.ID != id || window.Generation != generation || window.Scope.TenantID != tenantID || !window.Enabled {
			return nil, ErrIntegrity
		}
		windows = append(windows, window)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return windows, nil
}

func (repository *Repository) ensureOccurrence(ctx context.Context, occurrence Occurrence) error {
	if err := verifyOccurrence(occurrence); err != nil {
		return err
	}
	raw, err := json.Marshal(occurrence)
	if err != nil {
		return err
	}
	storageDigest := digestBytes(raw)
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO maintenance_occurrences
		(id, window_id, window_generation, starts_unix_nano, ends_unix_nano, occurrence_digest, occurrence_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, occurrence.ID, occurrence.WindowID, occurrence.WindowGeneration,
		occurrence.StartsAt.UnixNano(), occurrence.EndsAt.UnixNano(), storageDigest, raw)
	if err != nil {
		return err
	}
	if !oneRow(result) {
		stored, err := loadOccurrenceQuery(ctx, tx, occurrence.ID)
		if err != nil {
			return err
		}
		if stored.Digest != occurrence.Digest {
			return ErrIntegrity
		}
	}
	return tx.Commit()
}

func (repository *Repository) occurrenceExists(ctx context.Context, id string) (bool, error) {
	if !identifierPattern.MatchString(id) {
		return false, ErrInvalid
	}
	_, err := repository.LoadOccurrence(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (repository *Repository) LoadOccurrence(ctx context.Context, id string) (Occurrence, error) {
	if !identifierPattern.MatchString(id) {
		return Occurrence{}, ErrInvalid
	}
	return loadOccurrenceQuery(ctx, repository.db, id)
}

type OccurrencePage struct {
	Occurrences []Occurrence
	NextCursor  string
}

func (repository *Repository) ListOccurrences(ctx context.Context, windowID string, limit int, cursor string) (OccurrencePage, error) {
	if !identifierPattern.MatchString(windowID) || !validPage(limit, cursor) {
		return OccurrencePage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT id, window_generation, starts_unix_nano,
		ends_unix_nano, occurrence_digest, occurrence_json
		FROM maintenance_occurrences WHERE window_id = ? AND id > ? ORDER BY id LIMIT ?`, windowID, cursor, limit+1)
	if err != nil {
		return OccurrencePage{}, err
	}
	defer rows.Close()
	page := OccurrencePage{Occurrences: make([]Occurrence, 0, limit)}
	for rows.Next() {
		var id, digest string
		var generation uint64
		var starts, ends int64
		var raw []byte
		if err := rows.Scan(&id, &generation, &starts, &ends, &digest, &raw); err != nil {
			return OccurrencePage{}, err
		}
		occurrence, err := decodeOccurrence(raw, digest)
		if err != nil || occurrence.ID != id || occurrence.WindowID != windowID || occurrence.WindowGeneration != generation || occurrence.StartsAt.UnixNano() != starts || occurrence.EndsAt.UnixNano() != ends {
			return OccurrencePage{}, ErrIntegrity
		}
		if len(page.Occurrences) == limit {
			page.NextCursor = page.Occurrences[len(page.Occurrences)-1].ID
			break
		}
		page.Occurrences = append(page.Occurrences, occurrence)
	}
	if err := rows.Err(); err != nil {
		return OccurrencePage{}, err
	}
	return page, nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadWindowQuery(ctx context.Context, query queryer, id string) (Window, error) {
	var digest string
	var generation uint64
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT generation, window_digest, window_json
		FROM maintenance_windows WHERE id = ? AND deleted = 0`, id).Scan(&generation, &digest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Window{}, ErrNotFound
	}
	if err != nil {
		return Window{}, err
	}
	window, err := decodeWindow(raw, digest)
	if err != nil || window.ID != id || window.Generation != generation {
		return Window{}, ErrIntegrity
	}
	return window, nil
}

func loadOccurrenceQuery(ctx context.Context, query queryer, id string) (Occurrence, error) {
	var windowID, digest string
	var generation uint64
	var starts, ends int64
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT window_id, window_generation, starts_unix_nano,
		ends_unix_nano, occurrence_digest, occurrence_json FROM maintenance_occurrences WHERE id = ?`, id).
		Scan(&windowID, &generation, &starts, &ends, &digest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Occurrence{}, ErrNotFound
	}
	if err != nil {
		return Occurrence{}, err
	}
	occurrence, err := decodeOccurrence(raw, digest)
	if err != nil || occurrence.ID != id || occurrence.WindowID != windowID || occurrence.WindowGeneration != generation || occurrence.StartsAt.UnixNano() != starts || occurrence.EndsAt.UnixNano() != ends {
		return Occurrence{}, ErrIntegrity
	}
	return occurrence, nil
}

func encodeWindow(window Window) ([]byte, string, error) {
	raw, err := json.Marshal(window)
	if err != nil {
		return nil, "", err
	}
	return raw, digestBytes(raw), nil
}

func decodeWindow(raw []byte, digest string) (Window, error) {
	if !validDigest(digest) || digestBytes(raw) != digest {
		return Window{}, ErrIntegrity
	}
	var window Window
	if err := json.Unmarshal(raw, &window); err != nil || window.Validate() != nil {
		return Window{}, ErrIntegrity
	}
	return window, nil
}

func decodeOccurrence(raw []byte, digest string) (Occurrence, error) {
	if !validDigest(digest) || digestBytes(raw) != digest {
		return Occurrence{}, ErrIntegrity
	}
	var occurrence Occurrence
	if err := json.Unmarshal(raw, &occurrence); err != nil || verifyOccurrence(occurrence) != nil {
		return Occurrence{}, ErrIntegrity
	}
	return occurrence, nil
}

func validPage(limit int, cursor string) bool {
	return limit > 0 && limit <= MaxPageSize && (cursor == "" || identifierPattern.MatchString(cursor))
}

func boolInteger(value bool) int {
	if value {
		return 1
	}
	return 0
}

func oneRow(result sql.Result) bool {
	count, err := result.RowsAffected()
	return err == nil && count == 1
}
