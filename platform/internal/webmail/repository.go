package webmail

import (
	"context"
	"database/sql"
	"encoding/json"
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
CREATE TABLE IF NOT EXISTS webmail_uploads_v1 (
 tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,blob_id TEXT NOT NULL,
 filename TEXT NOT NULL,content_type TEXT NOT NULL,size INTEGER NOT NULL,digest TEXT NOT NULL,expires_at INTEGER NOT NULL,
 PRIMARY KEY(tenant_id,user_id,mailbox_id,blob_id)
);
CREATE INDEX IF NOT EXISTS webmail_uploads_expiry_v1 ON webmail_uploads_v1(tenant_id,mailbox_id,expires_at);
CREATE TABLE IF NOT EXISTS webmail_drafts_v1 (
 tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,draft_id TEXT NOT NULL,
 revision INTEGER NOT NULL,draft_json BLOB NOT NULL,updated_at INTEGER NOT NULL,
 PRIMARY KEY(tenant_id,user_id,mailbox_id,draft_id)
);
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

func validOwner(owner BlobOwner) bool {
	return opaqueIDPattern.MatchString(owner.TenantID) && opaqueIDPattern.MatchString(owner.UserID) && opaqueIDPattern.MatchString(owner.MailboxID)
}

func (repository *SQLiteRepository) StoreUpload(ctx context.Context, blob BlobInfo) error {
	if repository == nil || repository.db == nil || ctx == nil || !validOwner(blob.Owner) || !opaqueIDPattern.MatchString(blob.ID) ||
		!safeFilename(blob.Filename) || !safeContentType(blob.ContentType) ||
		blob.Size == 0 || blob.Size > MaximumAttachmentBytes || !validDigest(blob.Digest) || blob.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM webmail_uploads_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND expires_at<=?`,
		blob.Owner.TenantID, blob.Owner.UserID, blob.Owner.MailboxID, unixNano(time.Now().UTC())); err != nil {
		return err
	}
	var count uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM webmail_uploads_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=?`,
		blob.Owner.TenantID, blob.Owner.UserID, blob.Owner.MailboxID).Scan(&count); err != nil {
		return err
	}
	if count >= MaximumUploadsPerMailbox {
		return ErrLimit
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webmail_uploads_v1
(tenant_id,user_id,mailbox_id,blob_id,filename,content_type,size,digest,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		blob.Owner.TenantID, blob.Owner.UserID, blob.Owner.MailboxID, blob.ID, blob.Filename, blob.ContentType,
		blob.Size, blob.Digest, unixNano(blob.ExpiresAt))
	if err != nil {
		return errors.Join(ErrConflict, err)
	}
	return tx.Commit()
}

func (repository *SQLiteRepository) GetUploads(ctx context.Context, owner BlobOwner, ids []string, now time.Time) ([]BlobInfo, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validOwner(owner) || len(ids) == 0 || len(ids) > MaximumComposeAttachments || now.IsZero() {
		return nil, ErrInvalid
	}
	result := make([]BlobInfo, 0, len(ids))
	seen := make(map[string]bool)
	for _, id := range ids {
		if !opaqueIDPattern.MatchString(id) || seen[id] {
			return nil, ErrInvalid
		}
		seen[id] = true
		var blob BlobInfo
		var expiresAt int64
		err := repository.db.QueryRowContext(ctx, `SELECT filename,content_type,size,digest,expires_at FROM webmail_uploads_v1
WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND blob_id=? AND expires_at>?`, owner.TenantID, owner.UserID,
			owner.MailboxID, id, unixNano(now)).Scan(&blob.Filename, &blob.ContentType, &blob.Size, &blob.Digest, &expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		blob.ID = id
		blob.Owner = owner
		blob.ExpiresAt = time.Unix(0, expiresAt).UTC()
		if blob.Size == 0 || blob.Size > MaximumAttachmentBytes || !validDigest(blob.Digest) || !safeFilename(blob.Filename) || !safeContentType(blob.ContentType) {
			return nil, ErrProtocol
		}
		result = append(result, blob)
	}
	return result, nil
}

func (repository *SQLiteRepository) DeleteUpload(ctx context.Context, owner BlobOwner, id string) error {
	if repository == nil || repository.db == nil || ctx == nil || !validOwner(owner) || !opaqueIDPattern.MatchString(id) {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.db.ExecContext(ctx, `DELETE FROM webmail_uploads_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND blob_id=?`,
		owner.TenantID, owner.UserID, owner.MailboxID, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func (repository *SQLiteRepository) PutDraft(ctx context.Context, draft Draft, expectedRevision uint64) (Draft, error) {
	owner := BlobOwner{TenantID: draft.TenantID, UserID: draft.UserID, MailboxID: draft.MailboxID}
	if repository == nil || repository.db == nil || ctx == nil || !validOwner(owner) || !opaqueIDPattern.MatchString(draft.Message.ID) || expectedRevision >= math.MaxInt64 {
		return Draft{}, ErrInvalid
	}
	draft.Revision = expectedRevision + 1
	draft.UpdatedAt = time.Now().UTC()
	encoded, err := json.Marshal(draft)
	if err != nil || len(encoded) > MaximumRenderedPartBytes {
		return Draft{}, ErrLimit
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	var result sql.Result
	if expectedRevision == 0 {
		var count uint64
		if err = repository.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webmail_drafts_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=?`,
			draft.TenantID, draft.UserID, draft.MailboxID).Scan(&count); err != nil {
			return Draft{}, err
		}
		if count >= MaximumDraftsPerMailbox {
			return Draft{}, ErrLimit
		}
		result, err = repository.db.ExecContext(ctx, `INSERT OR IGNORE INTO webmail_drafts_v1
(tenant_id,user_id,mailbox_id,draft_id,revision,draft_json,updated_at) VALUES(?,?,?,?,?,?,?)`, draft.TenantID,
			draft.UserID, draft.MailboxID, draft.Message.ID, draft.Revision, encoded, unixNano(draft.UpdatedAt))
	} else {
		result, err = repository.db.ExecContext(ctx, `UPDATE webmail_drafts_v1 SET revision=?,draft_json=?,updated_at=?
WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND draft_id=? AND revision=?`, draft.Revision, encoded,
			unixNano(draft.UpdatedAt), draft.TenantID, draft.UserID, draft.MailboxID, draft.Message.ID, expectedRevision)
	}
	if err != nil {
		return Draft{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Draft{}, err
	}
	if rows != 1 {
		return Draft{}, ErrConflict
	}
	return draft, nil
}

func (repository *SQLiteRepository) GetDraft(ctx context.Context, owner BlobOwner, id string) (Draft, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validOwner(owner) || !opaqueIDPattern.MatchString(id) {
		return Draft{}, ErrInvalid
	}
	var encoded []byte
	var revision uint64
	var updatedAt int64
	err := repository.db.QueryRowContext(ctx, `SELECT revision,draft_json,updated_at FROM webmail_drafts_v1
WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND draft_id=?`, owner.TenantID, owner.UserID, owner.MailboxID, id).Scan(&revision, &encoded, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Draft{}, ErrNotFound
	}
	if err != nil {
		return Draft{}, err
	}
	if len(encoded) > MaximumRenderedPartBytes {
		return Draft{}, ErrProtocol
	}
	var draft Draft
	if err = json.Unmarshal(encoded, &draft); err != nil || draft.TenantID != owner.TenantID || draft.UserID != owner.UserID ||
		draft.MailboxID != owner.MailboxID || draft.Message.ID != id || draft.Revision != revision || unixNano(draft.UpdatedAt) != updatedAt {
		return Draft{}, ErrProtocol
	}
	return draft, nil
}

func (repository *SQLiteRepository) DeleteDraft(ctx context.Context, owner BlobOwner, id string, expectedRevision uint64) error {
	if repository == nil || repository.db == nil || ctx == nil || !validOwner(owner) || !opaqueIDPattern.MatchString(id) || expectedRevision == 0 {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.db.ExecContext(ctx, `DELETE FROM webmail_drafts_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND draft_id=? AND revision=?`,
		owner.TenantID, owner.UserID, owner.MailboxID, id, expectedRevision)
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
	return nil
}

var _ Repository = (*SQLiteRepository)(nil)
