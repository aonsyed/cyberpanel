package webmail

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sync"
	"time"
)

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS webmail_grants_v1 (
 token_digest TEXT PRIMARY KEY CHECK(length(token_digest)=64), tenant_id TEXT NOT NULL,
 user_id TEXT NOT NULL, session_id TEXT NOT NULL, mailbox_id TEXT NOT NULL, audience TEXT NOT NULL,
 authz_epoch INTEGER NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 consumed_at INTEGER, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS webmail_grants_scope_v1 ON webmail_grants_v1
 (tenant_id,user_id,session_id,mailbox_id,authz_epoch,expires_at);
CREATE TABLE IF NOT EXISTS webmail_preferences_v1 (
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, mailbox_id TEXT NOT NULL,
 revision INTEGER NOT NULL, page_size INTEGER NOT NULL, sort TEXT NOT NULL, threaded INTEGER NOT NULL,
 updated_at INTEGER NOT NULL, PRIMARY KEY(tenant_id,user_id,mailbox_id)
);
CREATE TABLE IF NOT EXISTS webmail_cursors_v1 (
 cursor_digest TEXT PRIMARY KEY CHECK(length(cursor_digest)=64), kind TEXT NOT NULL, tenant_id TEXT NOT NULL,
 user_id TEXT NOT NULL, session_id TEXT NOT NULL, mailbox_id TEXT NOT NULL, authz_epoch INTEGER NOT NULL,
 folder_name TEXT NOT NULL, uid_validity INTEGER NOT NULL, last_uid INTEGER NOT NULL,
 last_account_id TEXT NOT NULL, last_folder_name TEXT NOT NULL, sort TEXT NOT NULL, query_digest TEXT NOT NULL,
 expires_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS webmail_cursors_scope_v1 ON webmail_cursors_v1
 (tenant_id,user_id,session_id,mailbox_id,expires_at);
CREATE TABLE IF NOT EXISTS webmail_receipts_v1 (
 tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, user_digest TEXT NOT NULL, mailbox_digest TEXT NOT NULL,
 operation TEXT NOT NULL, outcome TEXT NOT NULL, item_count INTEGER NOT NULL, partial INTEGER NOT NULL,
 occurred_at INTEGER NOT NULL, PRIMARY KEY(tenant_id,request_id)
);
CREATE INDEX IF NOT EXISTS webmail_receipts_age_v1 ON webmail_receipts_v1(tenant_id,occurred_at);
`

type SQLiteRepository struct {
	db     *sql.DB
	writer sync.Mutex
}

func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &SQLiteRepository{db: db}, nil
}

func (repository *SQLiteRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil || ctx == nil {
		return ErrInvalid
	}
	_, err := repository.db.ExecContext(ctx, sqliteSchema)
	return err
}

func validDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, character := range digest {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func unixNano(value time.Time) int64 { return value.UTC().UnixNano() }

func (repository *SQLiteRepository) StoreGrant(ctx context.Context, digest string, claims GrantClaims) error {
	if repository == nil || repository.db == nil || ctx == nil || !validDigest(digest) || !claims.valid(claims.IssuedAt.Add(-time.Nanosecond)) || claims.AuthorizationEpoch > math.MaxInt64 {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = pruneAndLimitGrants(ctx, tx, claims.TenantID, claims.IssuedAt); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webmail_grants_v1
(token_digest,tenant_id,user_id,session_id,mailbox_id,audience,authz_epoch,issued_at,expires_at)
VALUES(?,?,?,?,?,?,?,?,?)`, digest, claims.TenantID, claims.UserID, claims.SessionID, claims.MailboxID,
		claims.Audience, claims.AuthorizationEpoch, unixNano(claims.IssuedAt), unixNano(claims.ExpiresAt))
	if err != nil {
		return errors.Join(ErrConflict, err)
	}
	return tx.Commit()
}

func pruneAndLimitGrants(ctx context.Context, tx *sql.Tx, tenantID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM webmail_grants_v1 WHERE tenant_id=? AND (expires_at<=? OR consumed_at IS NOT NULL OR revoked_at IS NOT NULL)`, tenantID, unixNano(now)); err != nil {
		return err
	}
	var count uint64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM webmail_grants_v1 WHERE tenant_id=? AND consumed_at IS NULL AND revoked_at IS NULL`, tenantID).Scan(&count); err != nil {
		return err
	}
	if count >= MaximumGrantsPerTenant {
		return ErrLimit
	}
	return nil
}

func (repository *SQLiteRepository) SwitchGrant(ctx context.Context, principal Principal, tenantID, previousMailboxID string, throughEpoch uint64, digest string, claims GrantClaims, now time.Time) (uint64, error) {
	if repository == nil || repository.db == nil || ctx == nil || !principal.valid() || !opaqueIDPattern.MatchString(tenantID) ||
		!opaqueIDPattern.MatchString(previousMailboxID) || throughEpoch == 0 || throughEpoch > math.MaxInt64 ||
		!validDigest(digest) || !claims.valid(now.Add(-time.Nanosecond)) || claims.TenantID != tenantID ||
		claims.UserID != principal.UserID || claims.SessionID != principal.SessionID || now.IsZero() {
		return 0, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE webmail_grants_v1 SET revoked_at=?
WHERE tenant_id=? AND user_id=? AND session_id=? AND mailbox_id=? AND authz_epoch<=?
AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>?`, unixNano(now), tenantID, principal.UserID,
		principal.SessionID, previousMailboxID, throughEpoch, unixNano(now))
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err = pruneAndLimitGrants(ctx, tx, tenantID, now); err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webmail_grants_v1
(token_digest,tenant_id,user_id,session_id,mailbox_id,audience,authz_epoch,issued_at,expires_at)
VALUES(?,?,?,?,?,?,?,?,?)`, digest, claims.TenantID, claims.UserID, claims.SessionID, claims.MailboxID,
		claims.Audience, claims.AuthorizationEpoch, unixNano(claims.IssuedAt), unixNano(claims.ExpiresAt))
	if err != nil {
		return 0, errors.Join(ErrConflict, err)
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return uint64(rows), nil
}

func (repository *SQLiteRepository) ConsumeGrant(ctx context.Context, digest string, expected GrantClaims, now time.Time) error {
	if repository == nil || repository.db == nil || ctx == nil || !validDigest(digest) || now.IsZero() ||
		!opaqueIDPattern.MatchString(expected.TenantID) || !opaqueIDPattern.MatchString(expected.UserID) ||
		!opaqueIDPattern.MatchString(expected.SessionID) || !opaqueIDPattern.MatchString(expected.MailboxID) ||
		!opaqueIDPattern.MatchString(expected.Audience) || expected.AuthorizationEpoch == 0 || expected.AuthorizationEpoch > math.MaxInt64 {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.db.ExecContext(ctx, `UPDATE webmail_grants_v1 SET consumed_at=?
WHERE token_digest=? AND tenant_id=? AND user_id=? AND session_id=? AND mailbox_id=? AND audience=?
AND authz_epoch=? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>?`, unixNano(now), digest,
		expected.TenantID, expected.UserID, expected.SessionID, expected.MailboxID, expected.Audience,
		expected.AuthorizationEpoch, unixNano(now))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrGrantInvalid
	}
	return nil
}

func (repository *SQLiteRepository) RevokeGrants(ctx context.Context, principal Principal, tenantID, mailboxID string, throughEpoch uint64, now time.Time) (uint64, error) {
	if repository == nil || repository.db == nil || ctx == nil || !principal.valid() || !opaqueIDPattern.MatchString(tenantID) ||
		!opaqueIDPattern.MatchString(mailboxID) || throughEpoch == 0 || throughEpoch > math.MaxInt64 || now.IsZero() {
		return 0, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.db.ExecContext(ctx, `UPDATE webmail_grants_v1 SET revoked_at=?
WHERE tenant_id=? AND user_id=? AND session_id=? AND mailbox_id=? AND authz_epoch<=?
AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>?`, unixNano(now), tenantID, principal.UserID,
		principal.SessionID, mailboxID, throughEpoch, unixNano(now))
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	return uint64(rows), err
}

func (repository *SQLiteRepository) GetPreferences(ctx context.Context, tenantID, userID, mailboxID string) (Preferences, error) {
	if repository == nil || repository.db == nil || ctx == nil || !opaqueIDPattern.MatchString(tenantID) ||
		!opaqueIDPattern.MatchString(userID) || !opaqueIDPattern.MatchString(mailboxID) {
		return Preferences{}, ErrInvalid
	}
	var preferences Preferences
	var threaded int
	var updatedAt int64
	err := repository.db.QueryRowContext(ctx, `SELECT revision,page_size,sort,threaded,updated_at FROM webmail_preferences_v1
WHERE tenant_id=? AND user_id=? AND mailbox_id=?`, tenantID, userID, mailboxID).Scan(&preferences.Revision,
		&preferences.PageSize, &preferences.Sort, &threaded, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Preferences{}, ErrNotFound
	}
	if err != nil {
		return Preferences{}, err
	}
	preferences.TenantID = tenantID
	preferences.UserID = userID
	preferences.MailboxID = mailboxID
	preferences.Threaded = threaded == 1
	preferences.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if threaded != 0 && threaded != 1 || !preferences.valid() {
		return Preferences{}, ErrProtocol
	}
	return preferences, nil
}

func (repository *SQLiteRepository) PutPreferences(ctx context.Context, preferences Preferences, expectedRevision uint64) (Preferences, error) {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision >= math.MaxInt64 {
		return Preferences{}, ErrInvalid
	}
	preferences.Revision = expectedRevision + 1
	preferences.UpdatedAt = time.Now().UTC()
	if !preferences.valid() {
		return Preferences{}, ErrInvalid
	}
	threaded := 0
	if preferences.Threaded {
		threaded = 1
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	var result sql.Result
	var err error
	if expectedRevision == 0 {
		result, err = repository.db.ExecContext(ctx, `INSERT OR IGNORE INTO webmail_preferences_v1
(tenant_id,user_id,mailbox_id,revision,page_size,sort,threaded,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
			preferences.TenantID, preferences.UserID, preferences.MailboxID, preferences.Revision,
			preferences.PageSize, preferences.Sort, threaded, unixNano(preferences.UpdatedAt))
	} else {
		result, err = repository.db.ExecContext(ctx, `UPDATE webmail_preferences_v1 SET revision=?,page_size=?,sort=?,threaded=?,updated_at=?
WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND revision=?`, preferences.Revision, preferences.PageSize,
			preferences.Sort, threaded, unixNano(preferences.UpdatedAt), preferences.TenantID, preferences.UserID,
			preferences.MailboxID, expectedRevision)
	}
	if err != nil {
		return Preferences{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Preferences{}, err
	}
	if rows != 1 {
		return Preferences{}, ErrConflict
	}
	return preferences, nil
}

func (repository *SQLiteRepository) StoreCursor(ctx context.Context, digest string, cursor CursorState) error {
	if repository == nil || repository.db == nil || ctx == nil || !validDigest(digest) || !cursor.valid(time.Now().UTC()) || cursor.AuthorizationEpoch > math.MaxInt64 {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM webmail_cursors_v1 WHERE tenant_id=? AND (expires_at<=? OR consumed_at IS NOT NULL)`, cursor.TenantID, unixNano(time.Now().UTC())); err != nil {
		return err
	}
	var count uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM webmail_cursors_v1 WHERE tenant_id=? AND consumed_at IS NULL`, cursor.TenantID).Scan(&count); err != nil {
		return err
	}
	if count >= MaximumCursorsPerTenant {
		return ErrLimit
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webmail_cursors_v1
(cursor_digest,kind,tenant_id,user_id,session_id,mailbox_id,authz_epoch,folder_name,uid_validity,last_uid,last_account_id,last_folder_name,sort,query_digest,expires_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, digest, cursor.Kind, cursor.TenantID, cursor.UserID, cursor.SessionID,
		cursor.MailboxID, cursor.AuthorizationEpoch, cursor.FolderName, cursor.UIDValidity, cursor.LastUID,
		cursor.LastAccountID, cursor.LastFolderName, cursor.Sort, cursor.QueryDigest, unixNano(cursor.ExpiresAt))
	if err != nil {
		return errors.Join(ErrConflict, err)
	}
	return tx.Commit()
}

func (repository *SQLiteRepository) ConsumeCursor(ctx context.Context, digest string, expected CursorState, now time.Time) (CursorState, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validDigest(digest) || now.IsZero() ||
		!opaqueIDPattern.MatchString(expected.TenantID) || !opaqueIDPattern.MatchString(expected.UserID) ||
		!opaqueIDPattern.MatchString(expected.SessionID) || expected.AuthorizationEpoch == 0 || expected.AuthorizationEpoch > math.MaxInt64 {
		return CursorState{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return CursorState{}, err
	}
	defer tx.Rollback()
	var cursor CursorState
	var expiresAt int64
	err = tx.QueryRowContext(ctx, `SELECT kind,tenant_id,user_id,session_id,mailbox_id,authz_epoch,folder_name,
uid_validity,last_uid,last_account_id,last_folder_name,sort,query_digest,expires_at FROM webmail_cursors_v1
WHERE cursor_digest=? AND consumed_at IS NULL AND expires_at>?`, digest, unixNano(now)).Scan(&cursor.Kind,
		&cursor.TenantID, &cursor.UserID, &cursor.SessionID, &cursor.MailboxID, &cursor.AuthorizationEpoch,
		&cursor.FolderName, &cursor.UIDValidity, &cursor.LastUID, &cursor.LastAccountID, &cursor.LastFolderName,
		&cursor.Sort, &cursor.QueryDigest, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CursorState{}, ErrCursorInvalid
	}
	if err != nil {
		return CursorState{}, err
	}
	cursor.ExpiresAt = time.Unix(0, expiresAt).UTC()
	if !cursor.valid(now) || cursor.Kind != expected.Kind || cursor.TenantID != expected.TenantID ||
		cursor.UserID != expected.UserID || cursor.SessionID != expected.SessionID ||
		cursor.MailboxID != expected.MailboxID || cursor.AuthorizationEpoch != expected.AuthorizationEpoch {
		return CursorState{}, ErrCursorInvalid
	}
	result, err := tx.ExecContext(ctx, `UPDATE webmail_cursors_v1 SET consumed_at=? WHERE cursor_digest=? AND consumed_at IS NULL`, unixNano(now), digest)
	if err != nil {
		return CursorState{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return CursorState{}, ErrCursorInvalid
	}
	if err = tx.Commit(); err != nil {
		return CursorState{}, err
	}
	return cursor, nil
}

func (repository *SQLiteRepository) StoreReceipt(ctx context.Context, receipt OperationReceipt) error {
	if repository == nil || repository.db == nil || ctx == nil || !receipt.valid() {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO webmail_receipts_v1
(tenant_id,request_id,user_digest,mailbox_digest,operation,outcome,item_count,partial,occurred_at)
VALUES(?,?,?,?,?,?,?,?,?)`, receipt.TenantID, receipt.RequestID, receipt.UserDigest, receipt.MailboxDigest,
		receipt.Operation, receipt.Outcome, receipt.ItemCount, receipt.Partial, unixNano(receipt.OccurredAt))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM webmail_receipts_v1 WHERE tenant_id=? AND request_id IN
(SELECT request_id FROM webmail_receipts_v1 WHERE tenant_id=? ORDER BY occurred_at DESC,request_id DESC LIMIT -1 OFFSET ?)`,
		receipt.TenantID, receipt.TenantID, MaximumReceiptsPerTenant)
	if err != nil {
		return err
	}
	return tx.Commit()
}

var _ Repository = (*SQLiteRepository)(nil)
