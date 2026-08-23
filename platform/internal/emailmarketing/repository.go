package emailmarketing

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrInvalid      = errors.New("emailmarketing: invalid input")
	ErrNotFound     = errors.New("emailmarketing: not found")
	ErrConflict     = errors.New("emailmarketing: conflict")
	ErrStale        = errors.New("emailmarketing: stale generation")
	ErrIntegrity    = errors.New("emailmarketing: integrity failure")
	ErrSuppressed   = errors.New("emailmarketing: address is suppressed")
	ErrTombstoned   = errors.New("emailmarketing: retained tombstone prevents recreation")
	ErrUnauthorized = errors.New("emailmarketing: unauthorized")
)

const (
	maxPageSize       = 500
	maxBulkMutations  = 500
	databaseTimeFormat = "2006-01-02T15:04:05.000000000Z"
)

type SQLiteRepository struct{ db *sql.DB }

func OpenSQLiteRepository(path string) (*SQLiteRepository, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &SQLiteRepository{db: db}, nil
}

func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &SQLiteRepository{db: db}, nil
}

func (r *SQLiteRepository) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

func (r *SQLiteRepository) Bootstrap(ctx context.Context) error {
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS email_marketing_lists_v1 (
			tenant_id TEXT NOT NULL, list_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation > 0),
			lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','archived','deleted')), document BLOB NOT NULL,
			updated_at TEXT NOT NULL, PRIMARY KEY(tenant_id,list_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_lists_page_v1 ON email_marketing_lists_v1(tenant_id,lifecycle,list_id)`,
		`CREATE TABLE IF NOT EXISTS email_marketing_tags_v1 (
			tenant_id TEXT NOT NULL, tag_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation > 0),
			name TEXT NOT NULL, lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','archived','deleted')),
			document BLOB NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(tenant_id,tag_id), UNIQUE(tenant_id,name)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS email_marketing_subscribers_v1 (
			tenant_id TEXT NOT NULL, subscriber_id TEXT NOT NULL, address TEXT NOT NULL, address_digest TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK(generation > 0), lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','archived','deleted')),
			document BLOB NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(tenant_id,subscriber_id), UNIQUE(tenant_id,address_digest)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_subscribers_search_v1 ON email_marketing_subscribers_v1(tenant_id,address,subscriber_id)`,
		`CREATE TABLE IF NOT EXISTS email_marketing_memberships_v1 (
			tenant_id TEXT NOT NULL, list_id TEXT NOT NULL, subscriber_id TEXT NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('subscribed','unsubscribed','archived')),
			generation INTEGER NOT NULL CHECK(generation > 0), document BLOB NOT NULL, updated_at TEXT NOT NULL,
			PRIMARY KEY(tenant_id,list_id,subscriber_id),
			FOREIGN KEY(tenant_id,list_id) REFERENCES email_marketing_lists_v1(tenant_id,list_id),
			FOREIGN KEY(tenant_id,subscriber_id) REFERENCES email_marketing_subscribers_v1(tenant_id,subscriber_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_memberships_page_v1 ON email_marketing_memberships_v1(tenant_id,list_id,status,subscriber_id)`,
		`CREATE TABLE IF NOT EXISTS email_marketing_consents_v1 (
			consent_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, list_id TEXT NOT NULL, subscriber_id TEXT NOT NULL,
			captured_at TEXT NOT NULL, recorded_at TEXT NOT NULL, evidence_digest TEXT NOT NULL, document BLOB NOT NULL
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_consents_subject_v1 ON email_marketing_consents_v1(tenant_id,list_id,subscriber_id,captured_at)`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_consents_no_update_v1 BEFORE UPDATE ON email_marketing_consents_v1 BEGIN SELECT RAISE(ABORT,'consent records are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_consents_no_delete_v1 BEFORE DELETE ON email_marketing_consents_v1 BEGIN SELECT RAISE(ABORT,'consent records are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS email_marketing_suppression_history_v1 (
			record_id TEXT PRIMARY KEY, scope TEXT NOT NULL CHECK(scope IN ('global','tenant')), tenant_id TEXT NOT NULL,
			list_id TEXT NOT NULL, subscriber_id TEXT NOT NULL, address_digest TEXT NOT NULL,
			reason TEXT NOT NULL CHECK(reason IN ('unsubscribe','complaint','hard_bounce','policy','manual')),
			action TEXT NOT NULL CHECK(action IN ('added','released')), occurred_at TEXT NOT NULL, document BLOB NOT NULL
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_suppression_subject_v1 ON email_marketing_suppression_history_v1(scope,tenant_id,address_digest,occurred_at)`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_suppression_no_update_v1 BEFORE UPDATE ON email_marketing_suppression_history_v1 BEGIN SELECT RAISE(ABORT,'suppression history is immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_suppression_no_delete_v1 BEFORE DELETE ON email_marketing_suppression_history_v1 BEGIN SELECT RAISE(ABORT,'suppression history is immutable'); END`,
		`CREATE TABLE IF NOT EXISTS email_marketing_suppression_state_v1 (
			scope TEXT NOT NULL CHECK(scope IN ('global','tenant')), tenant_id TEXT NOT NULL, address_digest TEXT NOT NULL,
			record_id TEXT NOT NULL, reason TEXT NOT NULL, occurred_at TEXT NOT NULL,
			PRIMARY KEY(scope,tenant_id,address_digest,reason),
			FOREIGN KEY(record_id) REFERENCES email_marketing_suppression_history_v1(record_id)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS email_marketing_tombstones_v1 (
			tenant_id TEXT NOT NULL, subscriber_id TEXT NOT NULL, address_digest TEXT NOT NULL,
			erased_at TEXT NOT NULL, retain_until TEXT NOT NULL, document BLOB NOT NULL,
			PRIMARY KEY(tenant_id,subscriber_id), UNIQUE(tenant_id,address_digest)
		) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_tombstones_no_update_v1 BEFORE UPDATE ON email_marketing_tombstones_v1 BEGIN SELECT RAISE(ABORT,'tombstones are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS email_marketing_import_checkpoints_v1 (
			tenant_id TEXT NOT NULL, list_id TEXT NOT NULL, batch_id TEXT NOT NULL, batch_index INTEGER NOT NULL CHECK(batch_index >= 0),
			header_digest TEXT NOT NULL, rows_seen INTEGER NOT NULL CHECK(rows_seen >= 0), rows_committed INTEGER NOT NULL CHECK(rows_committed >= 0),
			prefix_digest TEXT NOT NULL, completed INTEGER NOT NULL CHECK(completed IN (0,1)), updated_at TEXT NOT NULL,
			PRIMARY KEY(tenant_id,list_id,batch_id)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS email_marketing_unsubscribe_uses_v1 (
			token_digest TEXT PRIMARY KEY, nonce_digest TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL, list_id TEXT NOT NULL,
			subscriber_id TEXT NOT NULL, used_at TEXT NOT NULL, receipt_digest TEXT NOT NULL UNIQUE
		) STRICT`,
	}
	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) PutList(ctx context.Context, list List, expected uint64) error {
	if err := validateList(list, expected); err != nil {
		return err
	}
	document, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return putCAS(ctx, r.db, `INSERT INTO email_marketing_lists_v1(tenant_id,list_id,generation,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?)`,
		`UPDATE email_marketing_lists_v1 SET generation=?,lifecycle=?,document=?,updated_at=? WHERE tenant_id=? AND list_id=? AND generation=?`,
		expected, []any{list.TenantID, list.ID, list.Generation, list.Lifecycle, document, dbTime(list.UpdatedAt)},
		[]any{list.Generation, list.Lifecycle, document, dbTime(list.UpdatedAt), list.TenantID, list.ID, expected})
}

func (r *SQLiteRepository) GetList(ctx context.Context, tenant TenantID, id ListID) (List, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(id)) != nil {
		return List{}, ErrInvalid
	}
	var document []byte
	var generation uint64
	err := r.db.QueryRowContext(ctx, `SELECT generation,document FROM email_marketing_lists_v1 WHERE tenant_id=? AND list_id=?`, tenant, id).Scan(&generation, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return List{}, ErrNotFound
	}
	if err != nil {
		return List{}, err
	}
	var list List
	if json.Unmarshal(document, &list) != nil || list.TenantID != tenant || list.ID != id || list.Generation != generation {
		return List{}, ErrIntegrity
	}
	return list, nil
}

func (r *SQLiteRepository) ListLists(ctx context.Context, tenant TenantID, after ListID, limit int) ([]List, error) {
	if validateIdentifier(string(tenant)) != nil || (after != "" && validateIdentifier(string(after)) != nil) || limit < 1 || limit > maxPageSize {
		return nil, ErrInvalid
	}
	rows, err := r.db.QueryContext(ctx, `SELECT document FROM email_marketing_lists_v1 WHERE tenant_id=? AND list_id>? ORDER BY list_id LIMIT ?`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]List, 0, limit)
	for rows.Next() {
		var document []byte
		var list List
		if rows.Scan(&document) != nil || json.Unmarshal(document, &list) != nil || list.TenantID != tenant {
			return nil, ErrIntegrity
		}
		result = append(result, list)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) PutTag(ctx context.Context, tag Tag, expected uint64) error {
	if validateIdentifier(string(tag.TenantID)) != nil || validateIdentifier(string(tag.ID)) != nil ||
		tag.Name == "" || len(tag.Name) > maxNameBytes || validateLifecycle(tag.Lifecycle) != nil || tag.Generation != expected+1 || tag.CreatedAt.IsZero() || tag.UpdatedAt.Before(tag.CreatedAt) {
		return ErrInvalid
	}
	document, err := json.Marshal(tag)
	if err != nil {
		return err
	}
	return putCAS(ctx, r.db, `INSERT INTO email_marketing_tags_v1(tenant_id,tag_id,generation,name,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?,?)`,
		`UPDATE email_marketing_tags_v1 SET generation=?,name=?,lifecycle=?,document=?,updated_at=? WHERE tenant_id=? AND tag_id=? AND generation=?`, expected,
		[]any{tag.TenantID, tag.ID, tag.Generation, tag.Name, tag.Lifecycle, document, dbTime(tag.UpdatedAt)},
		[]any{tag.Generation, tag.Name, tag.Lifecycle, document, dbTime(tag.UpdatedAt), tag.TenantID, tag.ID, expected})
}

func (r *SQLiteRepository) PutSubscriber(ctx context.Context, subscriber Subscriber, expected uint64) error {
	if err := validateSubscriber(subscriber, expected); err != nil {
		return err
	}
	document, err := json.Marshal(subscriber)
	if err != nil {
		return err
	}
	if expected == 0 {
		var retainUntil string
		err = r.db.QueryRowContext(ctx, `SELECT retain_until FROM email_marketing_tombstones_v1 WHERE tenant_id=? AND address_digest=?`, subscriber.TenantID, subscriber.Address.Digest).Scan(&retainUntil)
		if err == nil {
			return ErrTombstoned
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	err = putCAS(ctx, r.db, `INSERT INTO email_marketing_subscribers_v1(tenant_id,subscriber_id,address,address_digest,generation,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		`UPDATE email_marketing_subscribers_v1 SET address=?,address_digest=?,generation=?,lifecycle=?,document=?,updated_at=? WHERE tenant_id=? AND subscriber_id=? AND generation=?`, expected,
		[]any{subscriber.TenantID, subscriber.ID, subscriber.Address.Normalized, subscriber.Address.Digest, subscriber.Generation, subscriber.Lifecycle, document, dbTime(subscriber.UpdatedAt)},
		[]any{subscriber.Address.Normalized, subscriber.Address.Digest, subscriber.Generation, subscriber.Lifecycle, document, dbTime(subscriber.UpdatedAt), subscriber.TenantID, subscriber.ID, expected})
	return err
}

func (r *SQLiteRepository) FindSubscriber(ctx context.Context, tenant TenantID, address AddressIdentity) (Subscriber, error) {
	if validateIdentifier(string(tenant)) != nil || !validDigest(address.Digest) {
		return Subscriber{}, ErrInvalid
	}
	return r.readSubscriber(ctx, `SELECT document FROM email_marketing_subscribers_v1 WHERE tenant_id=? AND address_digest=?`, tenant, address.Digest)
}

func (r *SQLiteRepository) GetSubscriber(ctx context.Context, tenant TenantID, id SubscriberID) (Subscriber, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(id)) != nil {
		return Subscriber{}, ErrInvalid
	}
	return r.readSubscriber(ctx, `SELECT document FROM email_marketing_subscribers_v1 WHERE tenant_id=? AND subscriber_id=?`, tenant, id)
}

func (r *SQLiteRepository) readSubscriber(ctx context.Context, query string, args ...any) (Subscriber, error) {
	var document []byte
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return Subscriber{}, ErrNotFound
	}
	if err != nil {
		return Subscriber{}, err
	}
	var subscriber Subscriber
	if json.Unmarshal(document, &subscriber) != nil {
		return Subscriber{}, ErrIntegrity
	}
	return subscriber, nil
}

func (r *SQLiteRepository) PutMembership(ctx context.Context, membership Membership, expected uint64) error {
	if err := validateMembership(membership, expected); err != nil {
		return err
	}
	document, err := json.Marshal(membership)
	if err != nil {
		return err
	}
	return putCAS(ctx, r.db, `INSERT INTO email_marketing_memberships_v1(tenant_id,list_id,subscriber_id,status,generation,document,updated_at) VALUES(?,?,?,?,?,?,?)`,
		`UPDATE email_marketing_memberships_v1 SET status=?,generation=?,document=?,updated_at=? WHERE tenant_id=? AND list_id=? AND subscriber_id=? AND generation=?`, expected,
		[]any{membership.TenantID, membership.ListID, membership.SubscriberID, membership.Status, membership.Generation, document, dbTime(membership.UpdatedAt)},
		[]any{membership.Status, membership.Generation, document, dbTime(membership.UpdatedAt), membership.TenantID, membership.ListID, membership.SubscriberID, expected})
}

// EnrollSubscriber commits the canonical tenant subscriber, list membership,
// and optional consent evidence together. A current suppression always wins.
func (r *SQLiteRepository) EnrollSubscriber(ctx context.Context, subscriber Subscriber, subscriberExpected uint64, membership Membership, membershipExpected uint64, consent *ConsentRecord) error {
	if validateSubscriber(subscriber, subscriberExpected) != nil || validateMembership(membership, membershipExpected) != nil ||
		subscriber.TenantID != membership.TenantID || subscriber.ID != membership.SubscriberID ||
		(consent != nil && (validateConsent(*consent) != nil || consent.TenantID != subscriber.TenantID || consent.ListID != membership.ListID || consent.SubscriberID != subscriber.ID)) {
		return ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if subscriberExpected == 0 {
		var present int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM email_marketing_tombstones_v1 WHERE tenant_id=? AND address_digest=?`, subscriber.TenantID, subscriber.Address.Digest).Scan(&present)
		if err == nil {
			return ErrTombstoned
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if membership.Status == MembershipSubscribed {
		active, suppressionErr := activeSuppressionTx(ctx, tx, subscriber.TenantID, subscriber.Address.Digest)
		if suppressionErr != nil {
			return suppressionErr
		}
		if active {
			return ErrSuppressed
		}
	}
	subscriberDocument, _ := json.Marshal(subscriber)
	if subscriberExpected == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_subscribers_v1(tenant_id,subscriber_id,address,address_digest,generation,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?,?,?)`, subscriber.TenantID, subscriber.ID, subscriber.Address.Normalized, subscriber.Address.Digest, subscriber.Generation, subscriber.Lifecycle, subscriberDocument, dbTime(subscriber.UpdatedAt))
		if err != nil {
			return ErrConflict
		}
	} else {
		result, updateErr := tx.ExecContext(ctx, `UPDATE email_marketing_subscribers_v1 SET address=?,address_digest=?,generation=?,lifecycle=?,document=?,updated_at=? WHERE tenant_id=? AND subscriber_id=? AND generation=?`, subscriber.Address.Normalized, subscriber.Address.Digest, subscriber.Generation, subscriber.Lifecycle, subscriberDocument, dbTime(subscriber.UpdatedAt), subscriber.TenantID, subscriber.ID, subscriberExpected)
		if updateErr != nil {
			return updateErr
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			return ErrStale
		}
	}
	membershipDocument, _ := json.Marshal(membership)
	if membershipExpected == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_memberships_v1(tenant_id,list_id,subscriber_id,status,generation,document,updated_at) VALUES(?,?,?,?,?,?,?)`, membership.TenantID, membership.ListID, membership.SubscriberID, membership.Status, membership.Generation, membershipDocument, dbTime(membership.UpdatedAt))
		if err != nil {
			return ErrConflict
		}
	} else {
		result, updateErr := tx.ExecContext(ctx, `UPDATE email_marketing_memberships_v1 SET status=?,generation=?,document=?,updated_at=? WHERE tenant_id=? AND list_id=? AND subscriber_id=? AND generation=?`, membership.Status, membership.Generation, membershipDocument, dbTime(membership.UpdatedAt), membership.TenantID, membership.ListID, membership.SubscriberID, membershipExpected)
		if updateErr != nil {
			return updateErr
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			return ErrStale
		}
	}
	if consent != nil {
		consentDocument, _ := json.Marshal(consent)
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_consents_v1(consent_id,tenant_id,list_id,subscriber_id,captured_at,recorded_at,evidence_digest,document) VALUES(?,?,?,?,?,?,?,?)`, consent.ID, consent.TenantID, consent.ListID, consent.SubscriberID, dbTime(consent.CapturedAt), dbTime(consent.RecordedAt), consent.EvidenceDigest, consentDocument)
		if err != nil {
			return ErrConflict
		}
	}
	return tx.Commit()
}

func (r *SQLiteRepository) RecordConsent(ctx context.Context, consent ConsentRecord) error {
	if err := validateConsent(consent); err != nil {
		return err
	}
	document, err := json.Marshal(consent)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO email_marketing_consents_v1(consent_id,tenant_id,list_id,subscriber_id,captured_at,recorded_at,evidence_digest,document) VALUES(?,?,?,?,?,?,?,?)`,
		consent.ID, consent.TenantID, consent.ListID, consent.SubscriberID, dbTime(consent.CapturedAt), dbTime(consent.RecordedAt), consent.EvidenceDigest, document)
	if err != nil {
		return ErrConflict
	}
	return nil
}

func (r *SQLiteRepository) LatestConsent(ctx context.Context, tenant TenantID, list ListID, subscriber SubscriberID) (ConsentRecord, error) {
	var document []byte
	err := r.db.QueryRowContext(ctx, `SELECT document FROM email_marketing_consents_v1 WHERE tenant_id=? AND list_id=? AND subscriber_id=? ORDER BY captured_at DESC,consent_id DESC LIMIT 1`, tenant, list, subscriber).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return ConsentRecord{}, ErrNotFound
	}
	if err != nil {
		return ConsentRecord{}, err
	}
	var consent ConsentRecord
	if json.Unmarshal(document, &consent) != nil {
		return ConsentRecord{}, ErrIntegrity
	}
	return consent, nil
}

func (r *SQLiteRepository) Suppress(ctx context.Context, record SuppressionRecord) error {
	if err := validateSuppression(record); err != nil || record.Action != SuppressionAdded {
		return ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertSuppression(ctx, tx, record); err != nil {
		return err
	}
	if err := setSuppressionState(ctx, tx, record); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SQLiteRepository) ReleaseSuppression(ctx context.Context, active SuppressionRecord, release SuppressionRecord, proof ResubscribeProof) error {
	if err := ValidateResubscribe(active, proof); err != nil || validateSuppression(release) != nil ||
		release.Action != SuppressionReleased || release.PriorRecordID != active.ID || release.ConsentRecordID != proof.Consent.ID ||
		release.Scope != active.Scope || release.TenantID != active.TenantID || release.AddressDigest != active.AddressDigest {
		return ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current string
	err = tx.QueryRowContext(ctx, `SELECT record_id FROM email_marketing_suppression_state_v1 WHERE scope=? AND tenant_id=? AND address_digest=? AND reason=?`, active.Scope, suppressionTenantKey(active), active.AddressDigest, active.Reason).Scan(&current)
	if err != nil || current != active.ID {
		return ErrStale
	}
	if err := insertSuppression(ctx, tx, release); err != nil {
		return err
	}
	var consentPresent int
	if err = tx.QueryRowContext(ctx, `SELECT 1 FROM email_marketing_consents_v1 WHERE consent_id=? AND tenant_id=? AND subscriber_id=?`, proof.Consent.ID, proof.Consent.TenantID, proof.Consent.SubscriberID).Scan(&consentPresent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIntegrity
		}
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM email_marketing_suppression_state_v1 WHERE scope=? AND tenant_id=? AND address_digest=? AND reason=? AND record_id=?`, active.Scope, suppressionTenantKey(active), active.AddressDigest, active.Reason, active.ID)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrStale
	}
	return tx.Commit()
}

func (r *SQLiteRepository) ActiveSuppressions(ctx context.Context, tenant TenantID, digest string) ([]SuppressionRecord, error) {
	if validateIdentifier(string(tenant)) != nil || !validDigest(digest) {
		return nil, ErrInvalid
	}
	rows, err := r.db.QueryContext(ctx, `SELECT h.document FROM email_marketing_suppression_state_v1 s JOIN email_marketing_suppression_history_v1 h ON h.record_id=s.record_id WHERE s.address_digest=? AND ((s.scope='global' AND s.tenant_id='') OR (s.scope='tenant' AND s.tenant_id=?)) ORDER BY s.scope`, digest, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SuppressionRecord
	for rows.Next() {
		var document []byte
		var record SuppressionRecord
		if rows.Scan(&document) != nil || json.Unmarshal(document, &record) != nil {
			return nil, ErrIntegrity
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

type SubscriberPage struct {
	Subscribers []Subscriber
	NextDigest  string
}

func (r *SQLiteRepository) ListSubscribers(ctx context.Context, tenant TenantID, list ListID, afterDigest string, limit int) (SubscriberPage, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(list)) != nil || (afterDigest != "" && !validDigest(afterDigest)) || limit < 1 || limit > maxPageSize {
		return SubscriberPage{}, ErrInvalid
	}
	rows, err := r.db.QueryContext(ctx, `SELECT s.document,s.address_digest FROM email_marketing_memberships_v1 m JOIN email_marketing_subscribers_v1 s ON s.tenant_id=m.tenant_id AND s.subscriber_id=m.subscriber_id WHERE m.tenant_id=? AND m.list_id=? AND s.address_digest>? ORDER BY s.address_digest LIMIT ?`, tenant, list, afterDigest, limit)
	if err != nil {
		return SubscriberPage{}, err
	}
	defer rows.Close()
	page := SubscriberPage{Subscribers: make([]Subscriber, 0, limit)}
	for rows.Next() {
		var document []byte
		var digest string
		var subscriber Subscriber
		if rows.Scan(&document, &digest) != nil || json.Unmarshal(document, &subscriber) != nil || subscriber.TenantID != tenant || subscriber.Address.Digest != digest {
			return SubscriberPage{}, ErrIntegrity
		}
		page.Subscribers = append(page.Subscribers, subscriber)
		page.NextDigest = digest
	}
	return page, rows.Err()
}

func (r *SQLiteRepository) SearchSubscribers(ctx context.Context, tenant TenantID, prefix string, limit int) ([]Subscriber, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if validateIdentifier(string(tenant)) != nil || len(prefix) < 3 || len(prefix) > 254 || limit < 1 || limit > maxPageSize {
		return nil, ErrInvalid
	}
	rows, err := r.db.QueryContext(ctx, `SELECT document FROM email_marketing_subscribers_v1 WHERE tenant_id=? AND address>=? AND address<? ORDER BY address LIMIT ?`, tenant, prefix, prefix+"\U0010ffff", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Subscriber, 0, limit)
	for rows.Next() {
		var document []byte
		var subscriber Subscriber
		if rows.Scan(&document) != nil || json.Unmarshal(document, &subscriber) != nil {
			return nil, ErrIntegrity
		}
		result = append(result, subscriber)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) EraseSubscriber(ctx context.Context, tenant TenantID, subscriberID SubscriberID, policy RetentionPolicy, now time.Time) (Tombstone, error) {
	if policy.LegalHold || now.IsZero() || now.Before(policy.EraseAddressAfter) || !policy.TombstoneRetainUntil.After(now) {
		return Tombstone{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Tombstone{}, err
	}
	defer tx.Rollback()
	var document []byte
	err = tx.QueryRowContext(ctx, `SELECT document FROM email_marketing_subscribers_v1 WHERE tenant_id=? AND subscriber_id=?`, tenant, subscriberID).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return Tombstone{}, ErrNotFound
	}
	if err != nil {
		return Tombstone{}, err
	}
	var subscriber Subscriber
	if json.Unmarshal(document, &subscriber) != nil || subscriber.Lifecycle != LifecycleDeleted || subscriber.DeleteAfter == nil || now.Before(*subscriber.DeleteAfter) {
		return Tombstone{}, ErrInvalid
	}
	tombstone := Tombstone{TenantID: tenant, SubscriberID: subscriberID, AddressDigest: subscriber.Address.Digest, ErasedAt: now.UTC(), RetainUntil: policy.TombstoneRetainUntil.UTC(), Reason: "privacy_erasure"}
	tombstoneDocument, _ := json.Marshal(tombstone)
	if _, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_tombstones_v1(tenant_id,subscriber_id,address_digest,erased_at,retain_until,document) VALUES(?,?,?,?,?,?)`, tenant, subscriberID, subscriber.Address.Digest, dbTime(now), dbTime(policy.TombstoneRetainUntil), tombstoneDocument); err != nil {
		return Tombstone{}, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM email_marketing_memberships_v1 WHERE tenant_id=? AND subscriber_id=?`, tenant, subscriberID); err != nil {
		return Tombstone{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM email_marketing_subscribers_v1 WHERE tenant_id=? AND subscriber_id=?`, tenant, subscriberID); err != nil {
		return Tombstone{}, err
	}
	if err = tx.Commit(); err != nil {
		return Tombstone{}, err
	}
	return tombstone, nil
}

func (r *SQLiteRepository) PurgeExpiredTombstones(ctx context.Context, now time.Time, limit int) (int64, error) {
	if now.IsZero() || limit < 1 || limit > maxPageSize {
		return 0, ErrInvalid
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM email_marketing_tombstones_v1 WHERE rowid IN (SELECT rowid FROM email_marketing_tombstones_v1 WHERE retain_until<=? ORDER BY retain_until LIMIT ?)`, dbTime(now), limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type BulkMutation struct {
	Subscriber Subscriber
	Membership Membership
	Consent    *ConsentRecord
}

type ImportCheckpoint struct {
	TenantID      TenantID
	ListID        ListID
	BatchID       BatchID
	BatchIndex    uint64
	HeaderDigest  string
	RowsSeen      uint64
	RowsCommitted uint64
	PrefixDigest  string
	Completed     bool
	UpdatedAt     time.Time
}

func (r *SQLiteRepository) GetImportCheckpoint(ctx context.Context, tenant TenantID, list ListID, batch BatchID) (ImportCheckpoint, error) {
	var checkpoint ImportCheckpoint
	var completed bool
	var updated string
	err := r.db.QueryRowContext(ctx, `SELECT batch_index,header_digest,rows_seen,rows_committed,prefix_digest,completed,updated_at FROM email_marketing_import_checkpoints_v1 WHERE tenant_id=? AND list_id=? AND batch_id=?`, tenant, list, batch).
		Scan(&checkpoint.BatchIndex, &checkpoint.HeaderDigest, &checkpoint.RowsSeen, &checkpoint.RowsCommitted, &checkpoint.PrefixDigest, &completed, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return ImportCheckpoint{}, ErrNotFound
	}
	if err != nil {
		return ImportCheckpoint{}, err
	}
	checkpoint.TenantID, checkpoint.ListID, checkpoint.BatchID, checkpoint.Completed = tenant, list, batch, completed
	checkpoint.UpdatedAt, err = parseDBTime(updated)
	return checkpoint, err
}

// ApplyImportBatch applies at most 500 rows and its checkpoint in one
// transaction. Repeating an already committed checkpoint is idempotent.
func (r *SQLiteRepository) ApplyImportBatch(ctx context.Context, expectedRows uint64, mutations []BulkMutation, next ImportCheckpoint) (bool, error) {
	if len(mutations) > maxBulkMutations || validateCheckpoint(next) != nil || next.RowsCommitted < expectedRows || next.RowsCommitted-expectedRows != uint64(len(mutations)) {
		return false, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var currentRows uint64
	var currentPrefix string
	err = tx.QueryRowContext(ctx, `SELECT rows_committed,prefix_digest FROM email_marketing_import_checkpoints_v1 WHERE tenant_id=? AND list_id=? AND batch_id=?`, next.TenantID, next.ListID, next.BatchID).Scan(&currentRows, &currentPrefix)
	if err == nil && currentRows == next.RowsCommitted && currentPrefix == next.PrefixDigest {
		return false, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		if expectedRows != 0 {
			return false, ErrStale
		}
	} else if err != nil {
		return false, err
	} else if currentRows != expectedRows {
		return false, ErrStale
	}
	for i := range mutations {
		if err := applyBulkMutation(ctx, tx, mutations[i], next.UpdatedAt); err != nil {
			return false, err
		}
	}
	if expectedRows == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_import_checkpoints_v1(tenant_id,list_id,batch_id,batch_index,header_digest,rows_seen,rows_committed,prefix_digest,completed,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, next.TenantID, next.ListID, next.BatchID, next.BatchIndex, next.HeaderDigest, next.RowsSeen, next.RowsCommitted, next.PrefixDigest, next.Completed, dbTime(next.UpdatedAt))
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE email_marketing_import_checkpoints_v1 SET batch_index=?,rows_seen=?,rows_committed=?,prefix_digest=?,completed=?,updated_at=? WHERE tenant_id=? AND list_id=? AND batch_id=? AND rows_committed=? AND prefix_digest=? AND header_digest=?`, next.BatchIndex, next.RowsSeen, next.RowsCommitted, next.PrefixDigest, next.Completed, dbTime(next.UpdatedAt), next.TenantID, next.ListID, next.BatchID, expectedRows, currentPrefix, next.HeaderDigest)
		if err == nil {
			affected, _ := result.RowsAffected()
			if affected != 1 {
				return false, ErrStale
			}
		}
	}
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func applyBulkMutation(ctx context.Context, tx *sql.Tx, mutation BulkMutation, now time.Time) error {
	if validateSubscriber(mutation.Subscriber, 0) != nil || mutation.Subscriber.TenantID != mutation.Membership.TenantID || mutation.Subscriber.ID != mutation.Membership.SubscriberID {
		return ErrInvalid
	}
	var existingID string
	err := tx.QueryRowContext(ctx, `SELECT subscriber_id FROM email_marketing_subscribers_v1 WHERE tenant_id=? AND address_digest=?`, mutation.Subscriber.TenantID, mutation.Subscriber.Address.Digest).Scan(&existingID)
	if errors.Is(err, sql.ErrNoRows) {
		var tombstone int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM email_marketing_tombstones_v1 WHERE tenant_id=? AND address_digest=?`, mutation.Subscriber.TenantID, mutation.Subscriber.Address.Digest).Scan(&tombstone)
		if err == nil {
			return ErrTombstoned
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		document, _ := json.Marshal(mutation.Subscriber)
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_subscribers_v1(tenant_id,subscriber_id,address,address_digest,generation,lifecycle,document,updated_at) VALUES(?,?,?,?,1,'active',?,?)`, mutation.Subscriber.TenantID, mutation.Subscriber.ID, mutation.Subscriber.Address.Normalized, mutation.Subscriber.Address.Digest, document, dbTime(now))
		existingID = string(mutation.Subscriber.ID)
	} else if err != nil {
		return err
	}
	mutation.Membership.SubscriberID = SubscriberID(existingID)
	mutation.Membership.Generation = 1
	mutation.Membership.CreatedAt, mutation.Membership.UpdatedAt = now, now
	active, err := activeSuppressionTx(ctx, tx, mutation.Membership.TenantID, mutation.Subscriber.Address.Digest)
	if err != nil {
		return err
	}
	if active {
		mutation.Membership.Status = MembershipUnsubscribed
	}
	membershipDocument, _ := json.Marshal(mutation.Membership)
	_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_memberships_v1(tenant_id,list_id,subscriber_id,status,generation,document,updated_at) VALUES(?,?,?,?,1,?,?) ON CONFLICT(tenant_id,list_id,subscriber_id) DO NOTHING`, mutation.Membership.TenantID, mutation.Membership.ListID, mutation.Membership.SubscriberID, mutation.Membership.Status, membershipDocument, dbTime(now))
	if err != nil {
		return err
	}
	if mutation.Consent != nil {
		consent := *mutation.Consent
		consent.SubscriberID = SubscriberID(existingID)
		if validateConsent(consent) != nil {
			return ErrInvalid
		}
		consentDocument, _ := json.Marshal(consent)
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_consents_v1(consent_id,tenant_id,list_id,subscriber_id,captured_at,recorded_at,evidence_digest,document) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(consent_id) DO NOTHING`, consent.ID, consent.TenantID, consent.ListID, consent.SubscriberID, dbTime(consent.CapturedAt), dbTime(consent.RecordedAt), consent.EvidenceDigest, consentDocument)
	}
	return err
}

func (r *SQLiteRepository) ConsumeUnsubscribe(ctx context.Context, claims UnsubscribeClaims, tokenDigest string, now time.Time) (bool, error) {
	if claims.Validate(now) != nil || !validDigest(tokenDigest) {
		return false, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var listGeneration, subscriberGeneration uint64
	var addressDigest string
	err = tx.QueryRowContext(ctx, `SELECT l.generation,s.generation,s.address_digest FROM email_marketing_lists_v1 l JOIN email_marketing_memberships_v1 m ON m.tenant_id=l.tenant_id AND m.list_id=l.list_id JOIN email_marketing_subscribers_v1 s ON s.tenant_id=m.tenant_id AND s.subscriber_id=m.subscriber_id WHERE l.tenant_id=? AND l.list_id=? AND s.subscriber_id=?`, claims.TenantID, claims.ListID, claims.SubscriberID).Scan(&listGeneration, &subscriberGeneration, &addressDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if listGeneration != claims.ListGeneration || subscriberGeneration != claims.SubscriberGeneration {
		return false, nil
	}
	nonceDigest := DigestEvidence([]byte(claims.Nonce))
	var present int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM email_marketing_unsubscribe_uses_v1 WHERE token_digest=? OR nonce_digest=?`, tokenDigest, nonceDigest).Scan(&present)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	recordID := "unsub:" + tokenDigest[:32]
	receiptDigest := DigestEvidence([]byte(recordID + ":" + dbTime(now)))
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO email_marketing_unsubscribe_uses_v1(token_digest,nonce_digest,tenant_id,list_id,subscriber_id,used_at,receipt_digest) VALUES(?,?,?,?,?,?,?)`, tokenDigest, nonceDigest, claims.TenantID, claims.ListID, claims.SubscriberID, dbTime(now), receiptDigest)
	if err != nil {
		return false, err
	}
	inserted, _ := result.RowsAffected()
	if inserted != 1 {
		return false, nil
	}
	record := SuppressionRecord{ID: recordID, Scope: SuppressionTenant, TenantID: claims.TenantID, ListID: claims.ListID, SubscriberID: claims.SubscriberID, AddressDigest: addressDigest, Reason: SuppressionUnsubscribe, Action: SuppressionAdded, OccurredAt: now.UTC(), EvidenceDigest: tokenDigest, ActorID: "public_unsubscribe"}
	if err = insertSuppression(ctx, tx, record); err != nil {
		return false, err
	}
	if err = setSuppressionState(ctx, tx, record); err != nil {
		return false, err
	}
	var membershipDocument []byte
	var membershipGeneration uint64
	err = tx.QueryRowContext(ctx, `SELECT generation,document FROM email_marketing_memberships_v1 WHERE tenant_id=? AND list_id=? AND subscriber_id=?`, claims.TenantID, claims.ListID, claims.SubscriberID).Scan(&membershipGeneration, &membershipDocument)
	if err != nil {
		return false, err
	}
	var membership Membership
	if json.Unmarshal(membershipDocument, &membership) != nil {
		return false, ErrIntegrity
	}
	membership.Status, membership.Generation, membership.UpdatedAt = MembershipUnsubscribed, membershipGeneration+1, now.UTC()
	membershipDocument, _ = json.Marshal(membership)
	result, err = tx.ExecContext(ctx, `UPDATE email_marketing_memberships_v1 SET status='unsubscribed',generation=?,document=?,updated_at=? WHERE tenant_id=? AND list_id=? AND subscriber_id=? AND generation=?`, membership.Generation, membershipDocument, dbTime(now), claims.TenantID, claims.ListID, claims.SubscriberID, membershipGeneration)
	if err != nil {
		return false, err
	}
	updated, _ := result.RowsAffected()
	if updated != 1 {
		return false, ErrStale
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func insertSuppression(ctx context.Context, tx *sql.Tx, record SuppressionRecord) error {
	document, _ := json.Marshal(record)
	_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_suppression_history_v1(record_id,scope,tenant_id,list_id,subscriber_id,address_digest,reason,action,occurred_at,document) VALUES(?,?,?,?,?,?,?,?,?,?)`, record.ID, record.Scope, suppressionTenantKey(record), record.ListID, record.SubscriberID, record.AddressDigest, record.Reason, record.Action, dbTime(record.OccurredAt), document)
	if err != nil {
		return ErrConflict
	}
	return nil
}

func setSuppressionState(ctx context.Context, tx *sql.Tx, record SuppressionRecord) error {
	result, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_suppression_state_v1(scope,tenant_id,address_digest,record_id,reason,occurred_at) VALUES(?,?,?,?,?,?) ON CONFLICT(scope,tenant_id,address_digest,reason) DO UPDATE SET record_id=excluded.record_id,occurred_at=excluded.occurred_at WHERE excluded.occurred_at>email_marketing_suppression_state_v1.occurred_at`, record.Scope, suppressionTenantKey(record), record.AddressDigest, record.ID, record.Reason, dbTime(record.OccurredAt))
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrStale
	}
	return nil
}

func activeSuppressionTx(ctx context.Context, tx *sql.Tx, tenant TenantID, digest string) (bool, error) {
	var present int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM email_marketing_suppression_state_v1 WHERE address_digest=? AND ((scope='global' AND tenant_id='') OR (scope='tenant' AND tenant_id=?)) LIMIT 1`, digest, tenant).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func putCAS(ctx context.Context, db *sql.DB, insert, update string, expected uint64, insertArgs, updateArgs []any) error {
	if expected == 0 {
		if _, err := db.ExecContext(ctx, insert, insertArgs...); err != nil {
			return ErrConflict
		}
		return nil
	}
	result, err := db.ExecContext(ctx, update, updateArgs...)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrStale
	}
	return nil
}

func validateList(list List, expected uint64) error {
	if validateIdentifier(string(list.TenantID)) != nil || validateIdentifier(string(list.ID)) != nil || list.Name == "" || len(list.Name) > maxNameBytes || list.Purpose == "" || len(list.Purpose) > maxPurposeBytes || validateLifecycle(list.Lifecycle) != nil || list.Generation != expected+1 || list.CreatedAt.IsZero() || list.UpdatedAt.Before(list.CreatedAt) {
		return ErrInvalid
	}
	return nil
}

func validateSubscriber(subscriber Subscriber, expected uint64) error {
	identity, err := NormalizeAddress(subscriber.Address.Normalized)
	if err != nil || identity != subscriber.Address || validateIdentifier(string(subscriber.TenantID)) != nil || validateIdentifier(string(subscriber.ID)) != nil || validateLifecycle(subscriber.Lifecycle) != nil || subscriber.Generation != expected+1 || subscriber.CreatedAt.IsZero() || subscriber.UpdatedAt.Before(subscriber.CreatedAt) {
		return ErrInvalid
	}
	tags, err := normalizeTags(subscriber.TagIDs)
	if err != nil || fmt.Sprint(tags) != fmt.Sprint(subscriber.TagIDs) || validateVerification(subscriber.Verification) != nil {
		return ErrInvalid
	}
	return nil
}

func validateVerification(verification Verification) error {
	switch verification.Provenance {
	case VerificationUnverified, VerificationSelfAsserted, VerificationDoubleOptIn, VerificationProvider, VerificationMigrated:
	default:
		return ErrInvalid
	}
	switch verification.Certainty {
	case CertaintyExact, CertaintyInferred, CertaintyUnknown:
	default:
		return ErrInvalid
	}
	if verification.EvidenceDigest != "" && !validDigest(verification.EvidenceDigest) {
		return ErrInvalid
	}
	if verification.Provenance == VerificationUnverified && (verification.VerifiedAt != nil || verification.EvidenceDigest != "") {
		return ErrInvalid
	}
	return nil
}

func validateMembership(membership Membership, expected uint64) error {
	if validateIdentifier(string(membership.TenantID)) != nil || validateIdentifier(string(membership.ListID)) != nil || validateIdentifier(string(membership.SubscriberID)) != nil || membership.Generation != expected+1 || membership.CreatedAt.IsZero() || membership.UpdatedAt.Before(membership.CreatedAt) {
		return ErrInvalid
	}
	switch membership.Status {
	case MembershipSubscribed, MembershipUnsubscribed, MembershipArchived:
		return nil
	default:
		return ErrInvalid
	}
}

func validateConsent(consent ConsentRecord) error {
	if validateIdentifier(consent.ID) != nil || validateIdentifier(string(consent.TenantID)) != nil || validateIdentifier(string(consent.ListID)) != nil || validateIdentifier(string(consent.SubscriberID)) != nil || consent.Purpose == "" || len(consent.Purpose) > maxPurposeBytes || consent.CapturedAt.IsZero() || consent.RecordedAt.Before(consent.CapturedAt) || !validDigest(consent.EvidenceDigest) || validateVerification(consent.Verification) != nil {
		return ErrInvalid
	}
	switch consent.Source {
	case ConsentWebForm, ConsentDoubleOpt, ConsentAdmin, ConsentCSV, ConsentAPI, ConsentProvider, ConsentMigrated:
		return nil
	default:
		return ErrInvalid
	}
}

func validateSuppression(record SuppressionRecord) error {
	if validateIdentifier(record.ID) != nil || validateIdentifier(string(record.ListID)) != nil || validateIdentifier(string(record.SubscriberID)) != nil || validateIdentifier(string(record.ActorID)) != nil || !validDigest(record.AddressDigest) || !validDigest(record.EvidenceDigest) || record.OccurredAt.IsZero() {
		return ErrInvalid
	}
	if record.Scope == SuppressionTenant && validateIdentifier(string(record.TenantID)) != nil || record.Scope == SuppressionGlobal && record.TenantID != "" || record.Scope != SuppressionTenant && record.Scope != SuppressionGlobal {
		return ErrInvalid
	}
	switch record.Reason {
	case SuppressionUnsubscribe, SuppressionComplaint, SuppressionHardBounce, SuppressionPolicy, SuppressionManual:
	default:
		return ErrInvalid
	}
	if record.Action != SuppressionAdded && record.Action != SuppressionReleased {
		return ErrInvalid
	}
	return nil
}

func validateCheckpoint(checkpoint ImportCheckpoint) error {
	if validateIdentifier(string(checkpoint.TenantID)) != nil || validateIdentifier(string(checkpoint.ListID)) != nil || validateIdentifier(string(checkpoint.BatchID)) != nil || !validDigest(checkpoint.HeaderDigest) || !validDigest(checkpoint.PrefixDigest) || checkpoint.RowsCommitted > checkpoint.RowsSeen || checkpoint.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

func suppressionTenantKey(record SuppressionRecord) TenantID {
	if record.Scope == SuppressionGlobal {
		return ""
	}
	return record.TenantID
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func dbTime(value time.Time) string { return value.UTC().Format(databaseTimeFormat) }

func parseDBTime(value string) (time.Time, error) { return time.Parse(databaseTimeFormat, value) }
