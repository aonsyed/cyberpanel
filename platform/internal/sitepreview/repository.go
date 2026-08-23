package sitepreview

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

const Schema = `
CREATE TABLE IF NOT EXISTS site_preview_sessions_v1 (
 tenant_id TEXT NOT NULL,
 session_id TEXT NOT NULL,
 site_id TEXT NOT NULL,
 site_generation INTEGER NOT NULL CHECK(site_generation > 0),
 preview_hostname TEXT NOT NULL UNIQUE,
 audience_key TEXT NOT NULL,
 authz_epoch INTEGER NOT NULL CHECK(authz_epoch > 0),
 state TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation > 0),
 expires_at TEXT NOT NULL,
 last_used_at TEXT NOT NULL,
 idle_expires_at TEXT NOT NULL,
 session_json BLOB NOT NULL,
 PRIMARY KEY(tenant_id, session_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS site_preview_sessions_expiry_v1 ON site_preview_sessions_v1(state, expires_at, tenant_id, session_id);
CREATE INDEX IF NOT EXISTS site_preview_sessions_site_v1 ON site_preview_sessions_v1(tenant_id, site_id, site_generation, state);
CREATE TABLE IF NOT EXISTS site_preview_token_grants_v1 (
 token_digest TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 session_id TEXT NOT NULL,
 audience_key TEXT NOT NULL,
 grant_mode TEXT NOT NULL,
 authz_epoch INTEGER NOT NULL CHECK(authz_epoch > 0),
 expires_at TEXT NOT NULL,
 consumed_at TEXT,
 revoked_at TEXT,
 FOREIGN KEY(tenant_id,session_id) REFERENCES site_preview_sessions_v1(tenant_id,session_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS site_preview_token_session_v1 ON site_preview_token_grants_v1(tenant_id,session_id);
CREATE TABLE IF NOT EXISTS site_preview_route_leases_v1 (
 tenant_id TEXT NOT NULL,
 lease_id TEXT NOT NULL,
 session_id TEXT NOT NULL,
 state TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation > 0),
 expires_at TEXT NOT NULL,
 lease_json BLOB NOT NULL,
 PRIMARY KEY(tenant_id,lease_id),
 UNIQUE(tenant_id,session_id),
 FOREIGN KEY(tenant_id,session_id) REFERENCES site_preview_sessions_v1(tenant_id,session_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS site_preview_route_expiry_v1 ON site_preview_route_leases_v1(state,expires_at,tenant_id,lease_id);
CREATE TABLE IF NOT EXISTS site_preview_screenshot_jobs_v1 (
 tenant_id TEXT NOT NULL,
 job_id TEXT NOT NULL,
 site_id TEXT NOT NULL,
 site_generation INTEGER NOT NULL CHECK(site_generation > 0),
 state TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation > 0),
 worker_id TEXT NOT NULL,
 lease_until TEXT,
 job_json BLOB NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,job_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS site_preview_screenshot_claim_v1 ON site_preview_screenshot_jobs_v1(state,lease_until,created_at,tenant_id,job_id);
CREATE TABLE IF NOT EXISTS site_preview_screenshot_artifacts_v1 (
 tenant_id TEXT NOT NULL,
 artifact_id TEXT NOT NULL,
 job_id TEXT NOT NULL,
 site_id TEXT NOT NULL,
 site_generation INTEGER NOT NULL CHECK(site_generation > 0),
 digest TEXT NOT NULL,
 artifact_json BLOB NOT NULL,
 created_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,artifact_id),
 UNIQUE(tenant_id,job_id),
 UNIQUE(tenant_id,digest),
 FOREIGN KEY(tenant_id,job_id) REFERENCES site_preview_screenshot_jobs_v1(tenant_id,job_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS site_preview_receipts_v1 (
 tenant_id TEXT NOT NULL,
 receipt_id TEXT NOT NULL,
 resource_kind TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 operation TEXT NOT NULL,
 receipt_json BLOB NOT NULL,
 occurred_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,receipt_id),
 UNIQUE(tenant_id,resource_kind,resource_id,operation)
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS site_preview_receipts_no_update_v1 BEFORE UPDATE ON site_preview_receipts_v1 BEGIN SELECT RAISE(ABORT,'site preview receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS site_preview_receipts_no_delete_v1 BEFORE DELETE ON site_preview_receipts_v1 BEGIN SELECT RAISE(ABORT,'site preview receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS site_preview_artifacts_no_update_v1 BEFORE UPDATE ON site_preview_screenshot_artifacts_v1 BEGIN SELECT RAISE(ABORT,'site preview artifacts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS site_preview_artifacts_no_delete_v1 BEFORE DELETE ON site_preview_screenshot_artifacts_v1 BEGIN SELECT RAISE(ABORT,'site preview artifacts are immutable'); END;
`

const maximumStoredJSON = 128 << 10

type Repository struct {
	db            *sql.DB
	previewDomain string
	writer        sync.Mutex
}

func NewRepository(db *sql.DB, previewDomain string) (*Repository, error) {
	previewDomain = strings.ToLower(strings.TrimSuffix(previewDomain, "."))
	if db == nil || !validHostname(previewDomain) {
		return nil, ErrInvalid
	}
	return &Repository{db: db, previewDomain: previewDomain}, nil
}

func (repository *Repository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil || ctx == nil {
		return ErrInvalid
	}
	_, err := repository.db.ExecContext(ctx, Schema)
	return err
}

func encodeStored(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumStoredJSON {
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalid
	}
	return encoded, nil
}

func decodeStored(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maximumStoredJSON {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrIntegrity
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrIntegrity
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrIntegrity
	}
	return nil
}

type TokenGrant struct {
	Digest     string
	Audience   Audience
	Mode       GrantMode
	AuthzEpoch uint64
	ExpiresAt  time.Time
}

func (grant TokenGrant) validate(session PreviewSession) error {
	if !validDigest(grant.Digest) || grant.Audience.Validate() != nil || grant.Audience != session.Audience || grant.Mode != session.GrantMode || grant.AuthzEpoch != session.AuthzEpoch ||
		grant.ExpiresAt.IsZero() || !grant.ExpiresAt.Equal(session.ExpiresAt) {
		return ErrInvalid
	}
	return nil
}

func (repository *Repository) CreateSession(ctx context.Context, session PreviewSession, grant TokenGrant) error {
	if repository == nil || session.Validate(repository.previewDomain) != nil || session.State != SessionPreparing || session.Generation != 1 || grant.validate(session) != nil {
		return ErrInvalid
	}
	encoded, err := encodeStored(session)
	if err != nil {
		return err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO site_preview_sessions_v1(tenant_id,session_id,site_id,site_generation,preview_hostname,audience_key,authz_epoch,state,generation,expires_at,last_used_at,idle_expires_at,session_json)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, session.TenantID, session.ID, session.SiteID, session.SiteGeneration, session.PreviewHostname, session.Audience.Key(), session.AuthzEpoch, session.State, session.Generation, timestamp(session.ExpiresAt), timestamp(session.LastUsedAt), timestamp(session.LastUsedAt.Add(session.Limits.IdleTTL)), encoded)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		if err == nil {
			err = ErrConflict
		}
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO site_preview_token_grants_v1(token_digest,tenant_id,session_id,audience_key,grant_mode,authz_epoch,expires_at,consumed_at,revoked_at) VALUES(?,?,?,?,?,?,?,NULL,NULL)`,
		grant.Digest, session.TenantID, session.ID, session.Audience.Key(), session.GrantMode, session.AuthzEpoch, timestamp(session.ExpiresAt))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *Repository) LoadSession(ctx context.Context, tenantID TenantID, sessionID SessionID) (PreviewSession, error) {
	if repository == nil || !validID(string(tenantID)) || !validID(string(sessionID)) {
		return PreviewSession{}, ErrInvalid
	}
	var encoded []byte
	err := repository.db.QueryRowContext(ctx, `SELECT session_json FROM site_preview_sessions_v1 WHERE tenant_id=? AND session_id=?`, tenantID, sessionID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return PreviewSession{}, ErrNotFound
	}
	if err != nil {
		return PreviewSession{}, err
	}
	return repository.decodeSession(encoded, tenantID, sessionID)
}

func (repository *Repository) ListSessions(ctx context.Context, tenantID TenantID, siteID SiteID, after SessionID, limit uint32) ([]PreviewSession, SessionID, error) {
	if repository == nil || !validID(string(tenantID)) || !validID(string(siteID)) || after != "" && !validID(string(after)) || limit == 0 || limit > 500 {
		return nil, "", ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT session_id,session_json FROM site_preview_sessions_v1 WHERE tenant_id=? AND site_id=? AND session_id>? ORDER BY session_id LIMIT ?`, tenantID, siteID, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	values := make([]PreviewSession, 0, limit)
	for rows.Next() {
		var sessionID SessionID
		var encoded []byte
		if err = rows.Scan(&sessionID, &encoded); err != nil {
			return nil, "", err
		}
		session, decodeErr := repository.decodeSession(encoded, tenantID, sessionID)
		if decodeErr != nil || session.SiteID != siteID {
			return nil, "", ErrIntegrity
		}
		values = append(values, session)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	var next SessionID
	if len(values) > int(limit) {
		values = values[:limit]
		next = values[len(values)-1].ID
	}
	return values, next, nil
}

func (repository *Repository) decodeSession(encoded []byte, tenantID TenantID, sessionID SessionID) (PreviewSession, error) {
	var session PreviewSession
	if decodeStored(encoded, &session) != nil || session.Validate(repository.previewDomain) != nil || session.TenantID != tenantID || session.ID != sessionID {
		return PreviewSession{}, ErrIntegrity
	}
	return session, nil
}

func (repository *Repository) ActivateSession(ctx context.Context, session PreviewSession, expected uint64, lease RouteLease, receipt Receipt) error {
	if repository == nil || session.Validate(repository.previewDomain) != nil || session.State != SessionActive || session.Generation != expected+1 || lease.Validate() != nil ||
		lease.SessionID != session.ID || lease.SpecDigest != digestJSON("cyberpanel:sitepreview:route:v1", routeSpec(session)) || receipt.Validate() != nil || receipt.TenantID != session.TenantID || receipt.ResourceID != string(session.ID) {
		return ErrInvalid
	}
	encodedSession, err := encodeStored(session)
	if err != nil {
		return err
	}
	encodedLease, err := encodeStored(lease)
	if err != nil {
		return err
	}
	encodedReceipt, err := encodeStored(receipt)
	if err != nil {
		return err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE site_preview_sessions_v1 SET state=?,generation=?,last_used_at=?,idle_expires_at=?,session_json=? WHERE tenant_id=? AND session_id=? AND state=? AND generation=?`,
		session.State, session.Generation, timestamp(session.LastUsedAt), timestamp(session.LastUsedAt.Add(session.Limits.IdleTTL)), encodedSession, session.TenantID, session.ID, SessionPreparing, expected)
	if err != nil {
		return err
	}
	if err = requireOne(result); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO site_preview_route_leases_v1(tenant_id,lease_id,session_id,state,generation,expires_at,lease_json) VALUES(?,?,?,?,?,?,?)`,
		session.TenantID, lease.ID, lease.SessionID, lease.State, lease.Generation, timestamp(lease.ExpiresAt), encodedLease)
	if err != nil {
		return err
	}
	if err = insertReceipt(ctx, tx, receipt, encodedReceipt); err != nil {
		return err
	}
	return tx.Commit()
}

type ConsumeGrantRequest struct {
	TokenDigest       string
	Audience          Audience
	CurrentAuthzEpoch uint64
	PreviewHostname   string
	RequestBytes      uint64
	Now               time.Time
}

func (repository *Repository) ConsumeGrant(ctx context.Context, request ConsumeGrantRequest) (PreviewSession, error) {
	if repository == nil || !validDigest(request.TokenDigest) || request.Audience.Validate() != nil || request.CurrentAuthzEpoch == 0 || !validHostname(request.PreviewHostname) || request.RequestBytes > MaximumSessionBytes || request.Now.IsZero() {
		return PreviewSession{}, ErrUnauthorized
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return PreviewSession{}, err
	}
	defer tx.Rollback()
	var tenantID TenantID
	var sessionID SessionID
	var audienceKey string
	var mode GrantMode
	var authzEpoch uint64
	var expires string
	var consumed, revoked sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT tenant_id,session_id,audience_key,grant_mode,authz_epoch,expires_at,consumed_at,revoked_at FROM site_preview_token_grants_v1 WHERE token_digest=?`, request.TokenDigest).
		Scan(&tenantID, &sessionID, &audienceKey, &mode, &authzEpoch, &expires, &consumed, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return PreviewSession{}, ErrUnauthorized
	}
	if err != nil {
		return PreviewSession{}, err
	}
	grantExpiry, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || audienceKey != request.Audience.Key() || authzEpoch != request.CurrentAuthzEpoch || revoked.Valid || !request.Now.UTC().Before(grantExpiry) || mode == GrantOneUse && consumed.Valid {
		return PreviewSession{}, ErrUnauthorized
	}
	var encoded []byte
	err = tx.QueryRowContext(ctx, `SELECT session_json FROM site_preview_sessions_v1 WHERE tenant_id=? AND session_id=?`, tenantID, sessionID).Scan(&encoded)
	if err != nil {
		return PreviewSession{}, ErrUnauthorized
	}
	session, err := repository.decodeSession(encoded, tenantID, sessionID)
	if err != nil {
		return PreviewSession{}, err
	}
	if session.PreviewHostname != request.PreviewHostname || session.Audience != request.Audience || session.AuthzEpoch != request.CurrentAuthzEpoch {
		return PreviewSession{}, ErrUnauthorized
	}
	if session.State == SessionRevoked {
		return PreviewSession{}, ErrRevoked
	}
	if session.State != SessionActive {
		if session.State == SessionExhausted {
			return PreviewSession{}, ErrBudgetExhausted
		}
		return PreviewSession{}, ErrExpired
	}
	if !request.Now.UTC().Before(session.ExpiresAt) || request.Now.UTC().Sub(session.LastUsedAt) > session.Limits.IdleTTL {
		return PreviewSession{}, ErrExpired
	}
	if session.ConsumedRequests == session.Limits.MaxRequests || request.RequestBytes > session.Limits.MaxBytes-session.ConsumedBytes {
		return PreviewSession{}, ErrBudgetExhausted
	}
	if mode == GrantOneUse {
		result, updateErr := tx.ExecContext(ctx, `UPDATE site_preview_token_grants_v1 SET consumed_at=? WHERE token_digest=? AND consumed_at IS NULL AND revoked_at IS NULL`, timestamp(request.Now), request.TokenDigest)
		if updateErr != nil {
			return PreviewSession{}, updateErr
		}
		if updateErr = requireOne(result); updateErr != nil {
			return PreviewSession{}, ErrUnauthorized
		}
	}
	session.ConsumedRequests++
	session.ConsumedBytes += request.RequestBytes
	session.LastUsedAt = request.Now.UTC()
	session.Generation++
	if session.ConsumedRequests == session.Limits.MaxRequests || session.ConsumedBytes == session.Limits.MaxBytes {
		session.State = SessionExhausted
	}
	encoded, err = encodeStored(session)
	if err != nil {
		return PreviewSession{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE site_preview_sessions_v1 SET state=?,generation=?,last_used_at=?,idle_expires_at=?,session_json=? WHERE tenant_id=? AND session_id=? AND state=? AND generation=?`,
		session.State, session.Generation, timestamp(session.LastUsedAt), timestamp(session.LastUsedAt.Add(session.Limits.IdleTTL)), encoded, tenantID, sessionID, SessionActive, session.Generation-1)
	if err != nil {
		return PreviewSession{}, err
	}
	if err = requireOne(result); err != nil {
		return PreviewSession{}, err
	}
	if err = tx.Commit(); err != nil {
		return PreviewSession{}, err
	}
	return session, nil
}

func (repository *Repository) RevokeSession(ctx context.Context, tenantID TenantID, sessionID SessionID, expected uint64, now time.Time, receipt Receipt) (PreviewSession, error) {
	if repository == nil || !validID(string(tenantID)) || !validID(string(sessionID)) || expected == 0 || now.IsZero() || receipt.Validate() != nil || receipt.TenantID != tenantID || receipt.ResourceID != string(sessionID) {
		return PreviewSession{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return PreviewSession{}, err
	}
	defer tx.Rollback()
	var encoded []byte
	if err = tx.QueryRowContext(ctx, `SELECT session_json FROM site_preview_sessions_v1 WHERE tenant_id=? AND session_id=?`, tenantID, sessionID).Scan(&encoded); err != nil {
		return PreviewSession{}, ErrNotFound
	}
	session, err := repository.decodeSession(encoded, tenantID, sessionID)
	if err != nil {
		return PreviewSession{}, err
	}
	if session.Generation != expected {
		return PreviewSession{}, ErrConflict
	}
	if session.State == SessionRevoked {
		return session, nil
	}
	session.State, session.RevokedAt, session.LastUsedAt, session.Generation = SessionRevoked, now.UTC(), now.UTC(), session.Generation+1
	encoded, err = encodeStored(session)
	if err != nil {
		return PreviewSession{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE site_preview_sessions_v1 SET state=?,generation=?,last_used_at=?,idle_expires_at=?,session_json=? WHERE tenant_id=? AND session_id=? AND generation=?`,
		session.State, session.Generation, timestamp(session.LastUsedAt), timestamp(session.LastUsedAt), encoded, tenantID, sessionID, expected)
	if err != nil {
		return PreviewSession{}, err
	}
	if err = requireOne(result); err != nil {
		return PreviewSession{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE site_preview_token_grants_v1 SET revoked_at=? WHERE tenant_id=? AND session_id=? AND revoked_at IS NULL`, timestamp(now), tenantID, sessionID)
	if err != nil {
		return PreviewSession{}, err
	}
	receipt.Generation = session.Generation
	encodedReceipt, err := encodeStored(receipt)
	if err != nil {
		return PreviewSession{}, err
	}
	if err = insertReceipt(ctx, tx, receipt, encodedReceipt); err != nil {
		return PreviewSession{}, err
	}
	if err = tx.Commit(); err != nil {
		return PreviewSession{}, err
	}
	return session, nil
}

func (repository *Repository) CloseSession(ctx context.Context, tenantID TenantID, sessionID SessionID, expected uint64, target SessionState, now time.Time, receipt Receipt) (PreviewSession, error) {
	if repository == nil || !validID(string(tenantID)) || !validID(string(sessionID)) || expected == 0 || (target != SessionExpired && target != SessionAmbiguous) || now.IsZero() ||
		receipt.Validate() != nil || receipt.TenantID != tenantID || receipt.ResourceID != string(sessionID) || receipt.Generation != expected+1 {
		return PreviewSession{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return PreviewSession{}, err
	}
	defer tx.Rollback()
	var encoded []byte
	if err = tx.QueryRowContext(ctx, `SELECT session_json FROM site_preview_sessions_v1 WHERE tenant_id=? AND session_id=?`, tenantID, sessionID).Scan(&encoded); err != nil {
		return PreviewSession{}, ErrNotFound
	}
	session, err := repository.decodeSession(encoded, tenantID, sessionID)
	if err != nil {
		return PreviewSession{}, err
	}
	if session.Generation != expected || session.State == SessionRevoked {
		return PreviewSession{}, ErrConflict
	}
	session.State, session.Generation, session.LastUsedAt = target, session.Generation+1, now.UTC()
	encoded, err = encodeStored(session)
	if err != nil {
		return PreviewSession{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE site_preview_sessions_v1 SET state=?,generation=?,last_used_at=?,idle_expires_at=?,session_json=? WHERE tenant_id=? AND session_id=? AND generation=?`,
		session.State, session.Generation, timestamp(session.LastUsedAt), timestamp(session.LastUsedAt), encoded, tenantID, sessionID, expected)
	if err != nil {
		return PreviewSession{}, err
	}
	if err = requireOne(result); err != nil {
		return PreviewSession{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE site_preview_token_grants_v1 SET revoked_at=? WHERE tenant_id=? AND session_id=? AND revoked_at IS NULL`, timestamp(now), tenantID, sessionID)
	if err != nil {
		return PreviewSession{}, err
	}
	encodedReceipt, err := encodeStored(receipt)
	if err != nil {
		return PreviewSession{}, err
	}
	if err = insertReceipt(ctx, tx, receipt, encodedReceipt); err != nil {
		return PreviewSession{}, err
	}
	if err = tx.Commit(); err != nil {
		return PreviewSession{}, err
	}
	return session, nil
}

func (repository *Repository) LoadRouteLease(ctx context.Context, tenantID TenantID, sessionID SessionID) (RouteLease, error) {
	if repository == nil || !validID(string(tenantID)) || !validID(string(sessionID)) {
		return RouteLease{}, ErrInvalid
	}
	var encoded []byte
	err := repository.db.QueryRowContext(ctx, `SELECT lease_json FROM site_preview_route_leases_v1 WHERE tenant_id=? AND session_id=?`, tenantID, sessionID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return RouteLease{}, ErrNotFound
	}
	if err != nil {
		return RouteLease{}, err
	}
	var lease RouteLease
	if decodeStored(encoded, &lease) != nil || lease.Validate() != nil || lease.SessionID != sessionID {
		return RouteLease{}, ErrIntegrity
	}
	return lease, nil
}

func (repository *Repository) SaveRouteLease(ctx context.Context, tenantID TenantID, lease RouteLease, expected uint64) error {
	if repository == nil || !validID(string(tenantID)) || lease.Validate() != nil || lease.Generation != expected+1 {
		return ErrInvalid
	}
	encoded, err := encodeStored(lease)
	if err != nil {
		return err
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE site_preview_route_leases_v1 SET state=?,generation=?,expires_at=?,lease_json=? WHERE tenant_id=? AND lease_id=? AND generation=?`,
		lease.State, lease.Generation, timestamp(lease.ExpiresAt), encoded, tenantID, lease.ID, expected)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func (repository *Repository) ExpirationCandidates(ctx context.Context, now time.Time, limit uint32) ([]PreviewSession, error) {
	if repository == nil || now.IsZero() || limit == 0 || limit > 500 {
		return nil, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT tenant_id,session_id,session_json FROM site_preview_sessions_v1 WHERE state=? OR (state=? AND (expires_at<=? OR idle_expires_at<=?)) ORDER BY expires_at,tenant_id,session_id LIMIT ?`,
		SessionExhausted, SessionActive, timestamp(now), timestamp(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]PreviewSession, 0, limit)
	for rows.Next() {
		var tenantID TenantID
		var sessionID SessionID
		var encoded []byte
		if err = rows.Scan(&tenantID, &sessionID, &encoded); err != nil {
			return nil, err
		}
		session, decodeErr := repository.decodeSession(encoded, tenantID, sessionID)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if !now.Before(session.ExpiresAt) || now.Sub(session.LastUsedAt) > session.Limits.IdleTTL || session.State == SessionExhausted {
			result = append(result, session)
		}
	}
	return result, rows.Err()
}

func (repository *Repository) CreateScreenshotJob(ctx context.Context, job ScreenshotJob, receipt Receipt) error {
	if repository == nil || job.Validate() != nil || job.State != ScreenshotQueued || job.Generation != 1 || receipt.Validate() != nil || receipt.TenantID != job.TenantID || receipt.ResourceID != string(job.ID) {
		return ErrInvalid
	}
	encodedJob, err := encodeStored(job)
	if err != nil {
		return err
	}
	encodedReceipt, err := encodeStored(receipt)
	if err != nil {
		return err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO site_preview_screenshot_jobs_v1(tenant_id,job_id,site_id,site_generation,state,generation,worker_id,lease_until,job_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		job.TenantID, job.ID, job.SiteID, job.SiteGeneration, job.State, job.Generation, "", nil, encodedJob, timestamp(job.CreatedAt), timestamp(job.UpdatedAt))
	if err != nil {
		return err
	}
	if err = insertReceipt(ctx, tx, receipt, encodedReceipt); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *Repository) LoadScreenshotJob(ctx context.Context, tenantID TenantID, siteID SiteID, jobID ScreenshotJobID) (ScreenshotJob, *ScreenshotArtifact, error) {
	if repository == nil || !validID(string(tenantID)) || !validID(string(siteID)) || !validID(string(jobID)) {
		return ScreenshotJob{}, nil, ErrInvalid
	}
	var encoded []byte
	err := repository.db.QueryRowContext(ctx, `SELECT job_json FROM site_preview_screenshot_jobs_v1 WHERE tenant_id=? AND site_id=? AND job_id=?`, tenantID, siteID, jobID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ScreenshotJob{}, nil, ErrNotFound
	}
	if err != nil {
		return ScreenshotJob{}, nil, err
	}
	var job ScreenshotJob
	if decodeStored(encoded, &job) != nil || job.Validate() != nil || job.TenantID != tenantID || job.SiteID != siteID || job.ID != jobID {
		return ScreenshotJob{}, nil, ErrIntegrity
	}
	var artifactJSON []byte
	err = repository.db.QueryRowContext(ctx, `SELECT artifact_json FROM site_preview_screenshot_artifacts_v1 WHERE tenant_id=? AND job_id=?`, tenantID, jobID).Scan(&artifactJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return job, nil, nil
	}
	if err != nil {
		return ScreenshotJob{}, nil, err
	}
	var artifact ScreenshotArtifact
	if decodeStored(artifactJSON, &artifact) != nil || artifact.Validate() != nil || artifact.TenantID != tenantID || artifact.SiteID != siteID || artifact.JobID != jobID || artifact.SiteGeneration != job.SiteGeneration {
		return ScreenshotJob{}, nil, ErrIntegrity
	}
	return job, &artifact, nil
}

func (repository *Repository) ClaimScreenshotJob(ctx context.Context, workerID string, now time.Time, leaseDuration time.Duration) (ScreenshotJob, error) {
	if repository == nil || !validID(workerID) || now.IsZero() || leaseDuration < 5*time.Second || leaseDuration > 5*time.Minute {
		return ScreenshotJob{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return ScreenshotJob{}, err
	}
	defer tx.Rollback()
	var tenantID TenantID
	var jobID ScreenshotJobID
	var encoded []byte
	err = tx.QueryRowContext(ctx, `SELECT tenant_id,job_id,job_json FROM site_preview_screenshot_jobs_v1 WHERE state=? OR (state=? AND lease_until<=?) ORDER BY created_at,tenant_id,job_id LIMIT 1`, ScreenshotQueued, ScreenshotRendering, timestamp(now)).Scan(&tenantID, &jobID, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ScreenshotJob{}, ErrNotFound
	}
	if err != nil {
		return ScreenshotJob{}, err
	}
	var job ScreenshotJob
	if decodeStored(encoded, &job) != nil || job.Validate() != nil || job.TenantID != tenantID || job.ID != jobID {
		return ScreenshotJob{}, ErrIntegrity
	}
	previousGeneration := job.Generation
	job.State, job.WorkerID, job.LeaseUntil, job.UpdatedAt, job.Generation = ScreenshotRendering, workerID, now.Add(leaseDuration).UTC(), now.UTC(), job.Generation+1
	encoded, err = encodeStored(job)
	if err != nil {
		return ScreenshotJob{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE site_preview_screenshot_jobs_v1 SET state=?,generation=?,worker_id=?,lease_until=?,job_json=?,updated_at=? WHERE tenant_id=? AND job_id=? AND generation=?`,
		job.State, job.Generation, job.WorkerID, timestamp(job.LeaseUntil), encoded, timestamp(job.UpdatedAt), tenantID, jobID, previousGeneration)
	if err != nil {
		return ScreenshotJob{}, err
	}
	if err = requireOne(result); err != nil {
		return ScreenshotJob{}, err
	}
	if err = tx.Commit(); err != nil {
		return ScreenshotJob{}, err
	}
	return job, nil
}

func (repository *Repository) CompleteScreenshotJob(ctx context.Context, job ScreenshotJob, expected uint64, artifact *ScreenshotArtifact, receipt Receipt) error {
	if repository == nil || job.Validate() != nil || job.Generation != expected+1 || job.State == ScreenshotQueued || job.State == ScreenshotRendering || receipt.Validate() != nil ||
		receipt.TenantID != job.TenantID || receipt.ResourceID != string(job.ID) || (job.State == ScreenshotSucceeded) != (artifact != nil) {
		return ErrInvalid
	}
	encodedJob, err := encodeStored(job)
	if err != nil {
		return err
	}
	encodedReceipt, err := encodeStored(receipt)
	if err != nil {
		return err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE site_preview_screenshot_jobs_v1 SET state=?,generation=?,worker_id=?,lease_until=NULL,job_json=?,updated_at=? WHERE tenant_id=? AND job_id=? AND state=? AND generation=? AND worker_id=?`,
		job.State, job.Generation, job.WorkerID, encodedJob, timestamp(job.UpdatedAt), job.TenantID, job.ID, ScreenshotRendering, expected, job.WorkerID)
	if err != nil {
		return err
	}
	if err = requireOne(result); err != nil {
		return err
	}
	if artifact != nil {
		if artifact.Validate() != nil || artifact.TenantID != job.TenantID || artifact.SiteID != job.SiteID || artifact.SiteGeneration != job.SiteGeneration || artifact.JobID != job.ID {
			return ErrInvalid
		}
		encodedArtifact, encodeErr := encodeStored(*artifact)
		if encodeErr != nil {
			return encodeErr
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO site_preview_screenshot_artifacts_v1(tenant_id,artifact_id,job_id,site_id,site_generation,digest,artifact_json,created_at) VALUES(?,?,?,?,?,?,?,?)`,
			artifact.TenantID, artifact.ID, artifact.JobID, artifact.SiteID, artifact.SiteGeneration, artifact.Digest, encodedArtifact, timestamp(artifact.CreatedAt))
		if err != nil {
			return err
		}
	}
	if err = insertReceipt(ctx, tx, receipt, encodedReceipt); err != nil {
		return err
	}
	return tx.Commit()
}

func insertReceipt(ctx context.Context, tx *sql.Tx, receipt Receipt, encoded []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO site_preview_receipts_v1(tenant_id,receipt_id,resource_kind,resource_id,operation,receipt_json,occurred_at) VALUES(?,?,?,?,?,?,?)`,
		receipt.TenantID, receipt.ID, receipt.ResourceKind, receipt.ResourceID, receipt.Operation, encoded, timestamp(receipt.OccurredAt))
	return err
}

func requireOne(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func timestamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
