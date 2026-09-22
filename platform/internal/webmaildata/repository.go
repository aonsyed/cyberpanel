package webmaildata

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteRepository struct{ db *sql.DB }

func OpenSQLiteRepository(path string) (*SQLiteRepository, error) {
	if path == "" || !filepath.IsAbs(path) { return nil, ErrInvalid }
	database, err := sql.Open("sqlite", path)
	if err != nil { return nil, err }
	database.SetMaxOpenConns(1)
	return &SQLiteRepository{db: database}, nil
}

func NewSQLiteRepository(database *sql.DB) (*SQLiteRepository, error) {
	if database == nil { return nil, ErrInvalid }
	return &SQLiteRepository{db: database}, nil
}

func (repository *SQLiteRepository) Close() error {
	if repository == nil || repository.db == nil { return nil }
	return repository.db.Close()
}

func (repository *SQLiteRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil || ctx == nil { return ErrInvalid }
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS webmail_contacts_v1 (
			tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,contact_id TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK(revision>0),lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','deleted')),
			sort_name TEXT NOT NULL,search_text TEXT NOT NULL,document BLOB NOT NULL,updated_at TEXT NOT NULL,
			PRIMARY KEY(tenant_id,user_id,mailbox_id,contact_id)) STRICT`,
		`CREATE INDEX IF NOT EXISTS webmail_contacts_page_v1 ON webmail_contacts_v1(tenant_id,user_id,mailbox_id,lifecycle,sort_name,contact_id)`,
		`CREATE TABLE IF NOT EXISTS webmail_contact_addresses_v1 (
			tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,contact_id TEXT NOT NULL,address_digest TEXT NOT NULL,address TEXT NOT NULL,
			PRIMARY KEY(tenant_id,user_id,mailbox_id,contact_id,address_digest),
			UNIQUE(tenant_id,user_id,mailbox_id,address_digest),
			FOREIGN KEY(tenant_id,user_id,mailbox_id,contact_id) REFERENCES webmail_contacts_v1(tenant_id,user_id,mailbox_id,contact_id) ON DELETE CASCADE) STRICT`,
		`CREATE TABLE IF NOT EXISTS webmail_contact_tombstones_v1 (
			tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,contact_id TEXT NOT NULL,address_digest TEXT NOT NULL,
			erased_at TEXT NOT NULL,retain_until TEXT NOT NULL,reason TEXT NOT NULL,
			PRIMARY KEY(tenant_id,user_id,mailbox_id,contact_id,address_digest)) STRICT`,
		`CREATE INDEX IF NOT EXISTS webmail_contact_tombstone_lookup_v1 ON webmail_contact_tombstones_v1(tenant_id,user_id,mailbox_id,address_digest,retain_until)`,
		`CREATE TABLE IF NOT EXISTS webmail_groups_v1 (
			tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,group_id TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK(revision>0),lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','deleted')),
			name TEXT NOT NULL,document BLOB NOT NULL,updated_at TEXT NOT NULL,
			PRIMARY KEY(tenant_id,user_id,mailbox_id,group_id),UNIQUE(tenant_id,user_id,mailbox_id,name)) STRICT`,
		`CREATE INDEX IF NOT EXISTS webmail_groups_page_v1 ON webmail_groups_v1(tenant_id,user_id,mailbox_id,lifecycle,group_id)`,
		`CREATE TABLE IF NOT EXISTS webmail_preferences_v1 (
			tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),
			document BLOB NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,user_id,mailbox_id)) STRICT`,
		`CREATE TABLE IF NOT EXISTS webmail_sieve_rules_v1 (
			tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,rule_id TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK(revision>0),enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),rule_order INTEGER NOT NULL CHECK(rule_order>=0),
			document BLOB NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,user_id,mailbox_id,rule_id)) STRICT`,
		`CREATE INDEX IF NOT EXISTS webmail_sieve_rules_order_v1 ON webmail_sieve_rules_v1(tenant_id,user_id,mailbox_id,rule_order,rule_id)`,
		`CREATE TABLE IF NOT EXISTS webmail_sieve_generations_v1 (
			tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),
			digest TEXT NOT NULL,program BLOB NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(tenant_id,user_id,mailbox_id,generation),
			UNIQUE(tenant_id,user_id,mailbox_id,digest)) STRICT`,
		`CREATE TABLE IF NOT EXISTS webmail_sieve_active_v1 (
			tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>=0),
			digest TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,user_id,mailbox_id)) STRICT`,
	}
	for _, statement := range statements {
		if _, err := repository.db.ExecContext(ctx, statement); err != nil { return err }
	}
	return nil
}

func (repository *SQLiteRepository) PutContact(ctx context.Context, contact Contact, expected uint64) error {
	normalized, err := NormalizeContact(contact)
	if err != nil || normalized.Revision != expected+1 || expected >= MaximumRevision { return ErrInvalid }
	document, err := json.Marshal(normalized)
	if err != nil { return err }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	if expected == 0 {
		for _, address := range normalized.Addresses {
			var retained int
			err = transaction.QueryRowContext(ctx, `SELECT 1 FROM webmail_contact_tombstones_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND address_digest=? AND retain_until>? LIMIT 1`,
				normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, addressDigest(address.Normalized), dbTime(time.Now().UTC())).Scan(&retained)
			if err == nil { return ErrRetained }
			if !errors.Is(err, sql.ErrNoRows) { return err }
		}
		_, err = transaction.ExecContext(ctx, `INSERT INTO webmail_contacts_v1(tenant_id,user_id,mailbox_id,contact_id,revision,lifecycle,sort_name,search_text,document,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, normalized.Revision, normalized.Lifecycle, contactSortName(normalized), contactSearchText(normalized), document, dbTime(normalized.UpdatedAt))
	} else {
		var result sql.Result
		result, err = transaction.ExecContext(ctx, `UPDATE webmail_contacts_v1 SET revision=?,lifecycle=?,sort_name=?,search_text=?,document=?,updated_at=? WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=? AND revision=? AND lifecycle='active'`,
			normalized.Revision, normalized.Lifecycle, contactSortName(normalized), contactSearchText(normalized), document, dbTime(normalized.UpdatedAt), normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, expected)
		if err == nil { err = requireChanged(result) }
		if err == nil { _, err = transaction.ExecContext(ctx, `DELETE FROM webmail_contact_addresses_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=?`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID) }
	}
	if err != nil { return classifyConstraint(err) }
	for _, address := range normalized.Addresses {
		_, err = transaction.ExecContext(ctx, `INSERT INTO webmail_contact_addresses_v1(tenant_id,user_id,mailbox_id,contact_id,address_digest,address) VALUES(?,?,?,?,?,?)`,
			normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, addressDigest(address.Normalized), address.Normalized)
		if err != nil { return classifyConstraint(err) }
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) GetContact(ctx context.Context, scope Scope, id string) (Contact, error) {
	if repository == nil || repository.db == nil || ctx == nil || !scope.Valid() || !opaquePattern.MatchString(id) { return Contact{}, ErrInvalid }
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM webmail_contacts_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=? AND lifecycle='active'`, scope.TenantID, scope.UserID, scope.MailboxID, id).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return Contact{}, ErrNotFound }
	if err != nil { return Contact{}, err }
	return decodeContact(document, scope, id)
}

func (repository *SQLiteRepository) FindContactByAddress(ctx context.Context, scope Scope, address string) (Contact, error) {
	if !scope.Valid() { return Contact{}, ErrInvalid }
	normalized, err := normalizeAddress(address)
	if err != nil { return Contact{}, ErrInvalid }
	var id string
	err = repository.db.QueryRowContext(ctx, `SELECT contact_id FROM webmail_contact_addresses_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND address_digest=?`, scope.TenantID, scope.UserID, scope.MailboxID, addressDigest(normalized)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) { return Contact{}, ErrNotFound }
	if err != nil { return Contact{}, err }
	return repository.GetContact(ctx, scope, id)
}

func (repository *SQLiteRepository) ListContacts(ctx context.Context, query ContactQuery) (ContactPage, error) {
	if repository == nil || repository.db == nil || ctx == nil || !query.Scope.Valid() || query.Limit < 1 || query.Limit > MaximumPageSize || len(query.Search) > 512 { return ContactPage{}, ErrInvalid }
	search := strings.ToLower(cleanText(query.Search, 512))
	afterName, afterID, err := decodeContactCursor(query.Scope, search, query.Cursor)
	if err != nil { return ContactPage{}, err }
	rows, err := repository.db.QueryContext(ctx, `SELECT document,sort_name,contact_id FROM webmail_contacts_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND lifecycle='active' AND (?='' OR search_text LIKE '%'||?||'%') AND (sort_name>? OR (sort_name=? AND contact_id>?)) ORDER BY sort_name,contact_id LIMIT ?`,
		query.Scope.TenantID, query.Scope.UserID, query.Scope.MailboxID, search, search, afterName, afterName, afterID, query.Limit+1)
	if err != nil { return ContactPage{}, err }
	defer rows.Close()
	page := ContactPage{Contacts: make([]Contact, 0, query.Limit)}
	var lastName, lastID, returnedName, returnedID string
	for rows.Next() {
		var document []byte
		if err = rows.Scan(&document, &lastName, &lastID); err != nil { return ContactPage{}, err }
		if len(page.Contacts) == query.Limit { page.NextCursor = encodeContactCursor(query.Scope, search, returnedName, returnedID); break }
		contact, decodeErr := decodeContact(document, query.Scope, lastID)
		if decodeErr != nil { return ContactPage{}, decodeErr }
		page.Contacts = append(page.Contacts, contact)
		returnedName, returnedID = lastName, lastID
	}
	return page, rows.Err()
}

func (repository *SQLiteRepository) DeleteContact(ctx context.Context, scope Scope, id string, expected uint64, retainUntil, now time.Time, reason string) error {
	if !scope.Valid() || !opaquePattern.MatchString(id) || expected == 0 || expected >= MaximumRevision || !retainUntil.After(now) || retainUntil.Sub(now) > 10*365*24*time.Hour || cleanText(reason, 128) == "" { return ErrInvalid }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	var document []byte
	err = transaction.QueryRowContext(ctx, `SELECT document FROM webmail_contacts_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=? AND revision=? AND lifecycle='active'`, scope.TenantID, scope.UserID, scope.MailboxID, id, expected).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return ErrConflict }
	if err != nil { return err }
	contact, err := decodeContact(document, scope, id)
	if err != nil { return err }
	for _, address := range contact.Addresses {
		_, err = transaction.ExecContext(ctx, `INSERT OR IGNORE INTO webmail_contact_tombstones_v1(tenant_id,user_id,mailbox_id,contact_id,address_digest,erased_at,retain_until,reason) VALUES(?,?,?,?,?,?,?,?)`, scope.TenantID, scope.UserID, scope.MailboxID, id, addressDigest(address.Normalized), dbTime(now), dbTime(retainUntil), cleanText(reason, 128))
		if err != nil { return err }
	}
	result, err := transaction.ExecContext(ctx, `UPDATE webmail_contacts_v1 SET revision=?,lifecycle='deleted',sort_name='',search_text='',document=?,updated_at=? WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=? AND revision=?`, expected+1, []byte(`{"deleted":true}`), dbTime(now), scope.TenantID, scope.UserID, scope.MailboxID, id, expected)
	if err != nil { return err }
	if err = requireChanged(result); err != nil { return err }
	if _, err = transaction.ExecContext(ctx, `DELETE FROM webmail_contact_addresses_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=?`, scope.TenantID, scope.UserID, scope.MailboxID, id); err != nil { return err }
	return transaction.Commit()
}

func (repository *SQLiteRepository) PurgeExpiredContactTombstones(ctx context.Context, scope Scope, before time.Time, limit int) (int, error) {
	if !scope.Valid() || before.IsZero() || limit < 1 || limit > 10_000 { return 0, ErrInvalid }
	result, err := repository.db.ExecContext(ctx, `DELETE FROM webmail_contact_tombstones_v1 WHERE rowid IN (SELECT rowid FROM webmail_contact_tombstones_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND retain_until<=? ORDER BY retain_until,contact_id LIMIT ?)`, scope.TenantID, scope.UserID, scope.MailboxID, dbTime(before), limit)
	if err != nil { return 0, err }
	count, err := result.RowsAffected()
	if err != nil { return 0, err }
	return int(count), nil
}

func (repository *SQLiteRepository) MergeContacts(ctx context.Context, target Contact, targetExpected uint64, sourceID string, sourceExpected uint64, retainUntil time.Time) error {
	normalized, err := NormalizeContact(target)
	if err != nil || normalized.Revision != targetExpected+1 || targetExpected == 0 || sourceExpected == 0 || sourceID == normalized.ID || !opaquePattern.MatchString(sourceID) || !retainUntil.After(normalized.UpdatedAt) { return ErrInvalid }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	var sourceDocument []byte
	err = transaction.QueryRowContext(ctx, `SELECT document FROM webmail_contacts_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=? AND revision=? AND lifecycle='active'`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, sourceID, sourceExpected).Scan(&sourceDocument)
	if errors.Is(err, sql.ErrNoRows) { return ErrConflict }
	if err != nil { return err }
	source, err := decodeContact(sourceDocument, normalized.Scope, sourceID)
	if err != nil { return err }
	document, err := json.Marshal(normalized)
	if err != nil { return err }
	result, err := transaction.ExecContext(ctx, `UPDATE webmail_contacts_v1 SET revision=?,sort_name=?,search_text=?,document=?,updated_at=? WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=? AND revision=? AND lifecycle='active'`, normalized.Revision, contactSortName(normalized), contactSearchText(normalized), document, dbTime(normalized.UpdatedAt), normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, targetExpected)
	if err != nil { return classifyConstraint(err) }
	if err = requireChanged(result); err != nil { return err }
	if _, err = transaction.ExecContext(ctx, `DELETE FROM webmail_contact_addresses_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id IN (?,?)`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, sourceID); err != nil { return err }
	for _, address := range normalized.Addresses {
		if _, err = transaction.ExecContext(ctx, `INSERT INTO webmail_contact_addresses_v1(tenant_id,user_id,mailbox_id,contact_id,address_digest,address) VALUES(?,?,?,?,?,?)`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, addressDigest(address.Normalized), address.Normalized); err != nil { return classifyConstraint(err) }
	}
	for _, address := range source.Addresses {
		if _, err = transaction.ExecContext(ctx, `INSERT OR IGNORE INTO webmail_contact_tombstones_v1(tenant_id,user_id,mailbox_id,contact_id,address_digest,erased_at,retain_until,reason) VALUES(?,?,?,?,?,?,?,?)`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, sourceID, addressDigest(address.Normalized), dbTime(normalized.UpdatedAt), dbTime(retainUntil), "merged"); err != nil { return err }
	}
	result, err = transaction.ExecContext(ctx, `UPDATE webmail_contacts_v1 SET revision=?,lifecycle='deleted',sort_name='',search_text='',document=?,updated_at=? WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=? AND revision=?`, sourceExpected+1, []byte(`{"deleted":true}`), dbTime(normalized.UpdatedAt), normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, sourceID, sourceExpected)
	if err != nil { return err }
	if err = requireChanged(result); err != nil { return err }
	return transaction.Commit()
}

func (repository *SQLiteRepository) PutGroup(ctx context.Context, group ContactGroup, expected uint64) error {
	normalized, err := NormalizeGroup(group)
	if err != nil || normalized.Revision != expected+1 || expected >= MaximumRevision { return ErrInvalid }
	document, err := json.Marshal(normalized)
	if err != nil { return err }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	for _, contactID := range normalized.ContactIDs {
		var found int
		err = transaction.QueryRowContext(ctx, `SELECT 1 FROM webmail_contacts_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND contact_id=? AND lifecycle='active'`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, contactID).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) { return ErrNotFound }
		if err != nil { return err }
	}
	if expected == 0 {
		var count int
		if err = transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM webmail_groups_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND lifecycle='active'`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID).Scan(&count); err != nil { return err }
		if count >= MaximumGroupsPerMailbox { return ErrLimit }
		_, err = transaction.ExecContext(ctx, `INSERT INTO webmail_groups_v1(tenant_id,user_id,mailbox_id,group_id,revision,lifecycle,name,document,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, normalized.Revision, normalized.Lifecycle, strings.ToLower(normalized.Name), document, dbTime(normalized.UpdatedAt))
	} else {
		var result sql.Result
		result, err = transaction.ExecContext(ctx, `UPDATE webmail_groups_v1 SET revision=?,lifecycle=?,name=?,document=?,updated_at=? WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND group_id=? AND revision=?`, normalized.Revision, normalized.Lifecycle, strings.ToLower(normalized.Name), document, dbTime(normalized.UpdatedAt), normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, expected)
		if err == nil { err = requireChanged(result) }
	}
	if err != nil { return classifyConstraint(err) }
	return transaction.Commit()
}

func (repository *SQLiteRepository) GetGroup(ctx context.Context, scope Scope, id string) (ContactGroup, error) {
	if !scope.Valid() || !opaquePattern.MatchString(id) { return ContactGroup{}, ErrInvalid }
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM webmail_groups_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND group_id=? AND lifecycle='active'`, scope.TenantID, scope.UserID, scope.MailboxID, id).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return ContactGroup{}, ErrNotFound }
	if err != nil { return ContactGroup{}, err }
	var group ContactGroup
	if json.Unmarshal(document, &group) != nil || group.Scope != scope || group.ID != id { return ContactGroup{}, ErrIntegrity }
	return NormalizeGroup(group)
}

func (repository *SQLiteRepository) ListGroups(ctx context.Context, scope Scope, after string, limit int) ([]ContactGroup, string, error) {
	if !scope.Valid() || after != "" && !opaquePattern.MatchString(after) || limit < 1 || limit > MaximumPageSize { return nil, "", ErrInvalid }
	rows, err := repository.db.QueryContext(ctx, `SELECT group_id,document FROM webmail_groups_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND lifecycle='active' AND group_id>? ORDER BY group_id LIMIT ?`, scope.TenantID, scope.UserID, scope.MailboxID, after, limit+1)
	if err != nil { return nil, "", err }
	defer rows.Close()
	groups := make([]ContactGroup, 0, limit)
	next, returnedID := "", ""
	for rows.Next() {
		var id string
		var document []byte
		if err = rows.Scan(&id, &document); err != nil { return nil, "", err }
		if len(groups) == limit { next = returnedID; break }
		var group ContactGroup
		if json.Unmarshal(document, &group) != nil || group.Scope != scope || group.ID != id { return nil, "", ErrIntegrity }
		groups = append(groups, group)
		returnedID = id
	}
	return groups, next, rows.Err()
}

func (repository *SQLiteRepository) PutPreferences(ctx context.Context, preferences WebmailPreferences, expected uint64) error {
	normalized, err := NormalizePreferences(preferences)
	if err != nil || normalized.Revision != expected+1 || expected >= MaximumRevision { return ErrInvalid }
	document, err := json.Marshal(normalized)
	if err != nil { return err }
	if expected == 0 {
		_, err = repository.db.ExecContext(ctx, `INSERT INTO webmail_preferences_v1(tenant_id,user_id,mailbox_id,revision,document,updated_at) VALUES(?,?,?,?,?,?)`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.Revision, document, dbTime(normalized.UpdatedAt))
		return classifyConstraint(err)
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE webmail_preferences_v1 SET revision=?,document=?,updated_at=? WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND revision=?`, normalized.Revision, document, dbTime(normalized.UpdatedAt), normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, expected)
	if err != nil { return err }
	return requireChanged(result)
}

func (repository *SQLiteRepository) GetPreferences(ctx context.Context, scope Scope) (WebmailPreferences, error) {
	if !scope.Valid() { return WebmailPreferences{}, ErrInvalid }
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM webmail_preferences_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=?`, scope.TenantID, scope.UserID, scope.MailboxID).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return WebmailPreferences{}, ErrNotFound }
	if err != nil { return WebmailPreferences{}, err }
	var value WebmailPreferences
	if json.Unmarshal(document, &value) != nil || value.Scope != scope { return WebmailPreferences{}, ErrIntegrity }
	return NormalizePreferences(value)
}

func (repository *SQLiteRepository) PutSieveRule(ctx context.Context, rule SieveRule, expected uint64) error {
	normalized, err := NormalizeSieveRule(rule)
	if err != nil || normalized.Revision != expected+1 || expected >= MaximumRevision { return ErrInvalid }
	document, err := json.Marshal(normalized)
	if err != nil { return err }
	if expected == 0 {
		var count int
		if err = repository.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webmail_sieve_rules_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=?`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID).Scan(&count); err != nil { return err }
		if count >= MaximumSieveRules { return ErrLimit }
		_, err = repository.db.ExecContext(ctx, `INSERT INTO webmail_sieve_rules_v1(tenant_id,user_id,mailbox_id,rule_id,revision,enabled,rule_order,document,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, normalized.Revision, boolInt(normalized.Enabled), normalized.Order, document, dbTime(normalized.UpdatedAt))
		return classifyConstraint(err)
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE webmail_sieve_rules_v1 SET revision=?,enabled=?,rule_order=?,document=?,updated_at=? WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND rule_id=? AND revision=?`, normalized.Revision, boolInt(normalized.Enabled), normalized.Order, document, dbTime(normalized.UpdatedAt), normalized.Scope.TenantID, normalized.Scope.UserID, normalized.Scope.MailboxID, normalized.ID, expected)
	if err != nil { return err }
	return requireChanged(result)
}

func (repository *SQLiteRepository) GetSieveRule(ctx context.Context, scope Scope, id string) (SieveRule, error) {
	if !scope.Valid() || !opaquePattern.MatchString(id) { return SieveRule{}, ErrInvalid }
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT document FROM webmail_sieve_rules_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND rule_id=?`, scope.TenantID, scope.UserID, scope.MailboxID, id).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return SieveRule{}, ErrNotFound }
	if err != nil { return SieveRule{}, err }
	var rule SieveRule
	if json.Unmarshal(document, &rule) != nil || rule.Scope != scope || rule.ID != id { return SieveRule{}, ErrIntegrity }
	return NormalizeSieveRule(rule)
}

func (repository *SQLiteRepository) ListSieveRules(ctx context.Context, scope Scope) ([]SieveRule, error) {
	if !scope.Valid() { return nil, ErrInvalid }
	rows, err := repository.db.QueryContext(ctx, `SELECT document FROM webmail_sieve_rules_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? ORDER BY rule_order,rule_id LIMIT ?`, scope.TenantID, scope.UserID, scope.MailboxID, MaximumSieveRules+1)
	if err != nil { return nil, err }
	defer rows.Close()
	rules := make([]SieveRule, 0)
	for rows.Next() {
		if len(rules) == MaximumSieveRules { return nil, ErrIntegrity }
		var document []byte
		var rule SieveRule
		if rows.Scan(&document) != nil || json.Unmarshal(document, &rule) != nil || rule.Scope != scope { return nil, ErrIntegrity }
		normalized, normalizeErr := NormalizeSieveRule(rule)
		if normalizeErr != nil { return nil, ErrIntegrity }
		rules = append(rules, normalized)
	}
	return rules, rows.Err()
}

func (repository *SQLiteRepository) ReplaceSieveRulesCAS(ctx context.Context, scope Scope, rules []SieveRule, expected map[string]uint64) error {
	if !scope.Valid() || len(rules) > MaximumSieveRules || len(expected) > MaximumSieveRules || len(rules) == 0 && len(expected) == 0 { return ErrInvalid }
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	seen := map[string]bool{}
	for _, rule := range rules {
		normalized, normalizeErr := NormalizeSieveRule(rule)
		previous, found := expected[rule.ID]
		if normalizeErr != nil || normalized.Scope != scope || seen[rule.ID] || !found || normalized.Revision != previous+1 { return ErrInvalid }
		seen[rule.ID] = true
		document, marshalErr := json.Marshal(normalized)
		if marshalErr != nil { return marshalErr }
		if previous == 0 {
			_, err = transaction.ExecContext(ctx, `INSERT INTO webmail_sieve_rules_v1(tenant_id,user_id,mailbox_id,rule_id,revision,enabled,rule_order,document,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, scope.TenantID, scope.UserID, scope.MailboxID, normalized.ID, normalized.Revision, boolInt(normalized.Enabled), normalized.Order, document, dbTime(normalized.UpdatedAt))
		} else {
			var result sql.Result
			result, err = transaction.ExecContext(ctx, `UPDATE webmail_sieve_rules_v1 SET revision=?,enabled=?,rule_order=?,document=?,updated_at=? WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND rule_id=? AND revision=?`, normalized.Revision, boolInt(normalized.Enabled), normalized.Order, document, dbTime(normalized.UpdatedAt), scope.TenantID, scope.UserID, scope.MailboxID, normalized.ID, previous)
			if err == nil { err = requireChanged(result) }
		}
		if err != nil { return classifyConstraint(err) }
	}
	rows, err := transaction.QueryContext(ctx, `SELECT rule_id,revision FROM webmail_sieve_rules_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=?`, scope.TenantID, scope.UserID, scope.MailboxID)
	if err != nil { return err }
	type staleRule struct { id string; revision uint64 }
	stale := make([]staleRule, 0)
	for rows.Next() {
		var id string; var revision uint64
		if rows.Scan(&id, &revision) != nil { rows.Close(); return ErrIntegrity }
		if !seen[id] {
			previous, found := expected[id]
			if !found || revision != previous { rows.Close(); return ErrConflict }
			stale = append(stale, staleRule{id: id, revision: previous})
		}
	}
	if err = rows.Err(); err != nil { rows.Close(); return err }
	if err = rows.Close(); err != nil { return err }
	for _, rule := range stale {
		result, deleteErr := transaction.ExecContext(ctx, `DELETE FROM webmail_sieve_rules_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND rule_id=? AND revision=?`, scope.TenantID, scope.UserID, scope.MailboxID, rule.id, rule.revision)
		if deleteErr != nil { return deleteErr }
		if deleteErr = requireChanged(result); deleteErr != nil { return deleteErr }
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) StageSieveGeneration(ctx context.Context, program SieveProgram) error {
	if err := program.Validate(); err != nil { return err }
	document, err := json.Marshal(program)
	if err != nil { return err }
	_, err = repository.db.ExecContext(ctx, `INSERT INTO webmail_sieve_generations_v1(tenant_id,user_id,mailbox_id,generation,digest,program,created_at) VALUES(?,?,?,?,?,?,?)`, program.Scope.TenantID, program.Scope.UserID, program.Scope.MailboxID, program.Generation, program.Digest, document, dbTime(program.CreatedAt))
	return classifyConstraint(err)
}

func (repository *SQLiteRepository) NextSieveGeneration(ctx context.Context, scope Scope) (uint64, error) {
	if !scope.Valid() { return 0, ErrInvalid }
	var generation uint64
	if err := repository.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation),0)+1 FROM webmail_sieve_generations_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=?`, scope.TenantID, scope.UserID, scope.MailboxID).Scan(&generation); err != nil { return 0, err }
	if generation == 0 || generation > MaximumRevision { return 0, ErrLimit }
	return generation, nil
}

func (repository *SQLiteRepository) GetSieveProgram(ctx context.Context, scope Scope, generation uint64) (SieveProgram, error) {
	if !scope.Valid() || generation == 0 { return SieveProgram{}, ErrInvalid }
	var document []byte
	err := repository.db.QueryRowContext(ctx, `SELECT program FROM webmail_sieve_generations_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND generation=?`, scope.TenantID, scope.UserID, scope.MailboxID, generation).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) { return SieveProgram{}, ErrNotFound }
	if err != nil { return SieveProgram{}, err }
	var program SieveProgram
	if json.Unmarshal(document, &program) != nil || program.Scope != scope || program.Generation != generation || program.Validate() != nil { return SieveProgram{}, ErrIntegrity }
	return program, nil
}

func (repository *SQLiteRepository) ActiveSieve(ctx context.Context, scope Scope) (SieveActivation, error) {
	if !scope.Valid() { return SieveActivation{}, ErrInvalid }
	var value SieveActivation
	var updatedAt string
	value.Scope = scope
	err := repository.db.QueryRowContext(ctx, `SELECT generation,digest,updated_at FROM webmail_sieve_active_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=?`, scope.TenantID, scope.UserID, scope.MailboxID).Scan(&value.Generation, &value.Digest, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) { return SieveActivation{Scope: scope}, nil }
	if err != nil { return SieveActivation{}, err }
	value.UpdatedAt, err = parseDBTime(updatedAt)
	if err != nil { return SieveActivation{}, ErrIntegrity }
	return value, nil
}

func (repository *SQLiteRepository) ActivateSieveCAS(ctx context.Context, desired SieveActivation, expectedDigest string) error {
	if desired.Scope.Valid() && desired.Generation==0 && desired.Digest=="" && validDigest(expectedDigest) {
		result,err:=repository.db.ExecContext(ctx,`DELETE FROM webmail_sieve_active_v1 WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND digest=?`,desired.Scope.TenantID,desired.Scope.UserID,desired.Scope.MailboxID,expectedDigest)
		if err!=nil{return err};return requireChanged(result)
	}
	if !desired.Scope.Valid() || desired.Generation == 0 || !validDigest(desired.Digest) || desired.UpdatedAt.IsZero() || expectedDigest != "" && !validDigest(expectedDigest) { return ErrInvalid }
	if expectedDigest == "" {
		_, err := repository.db.ExecContext(ctx, `INSERT INTO webmail_sieve_active_v1(tenant_id,user_id,mailbox_id,generation,digest,updated_at) VALUES(?,?,?,?,?,?)`, desired.Scope.TenantID, desired.Scope.UserID, desired.Scope.MailboxID, desired.Generation, desired.Digest, dbTime(desired.UpdatedAt))
		return classifyConstraint(err)
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE webmail_sieve_active_v1 SET generation=?,digest=?,updated_at=? WHERE tenant_id=? AND user_id=? AND mailbox_id=? AND digest=?`, desired.Generation, desired.Digest, dbTime(desired.UpdatedAt), desired.Scope.TenantID, desired.Scope.UserID, desired.Scope.MailboxID, expectedDigest)
	if err != nil { return err }
	return requireChanged(result)
}

func decodeContact(document []byte, scope Scope, id string) (Contact, error) {
	var value Contact
	if json.Unmarshal(document, &value) != nil || value.Scope != scope || value.ID != id { return Contact{}, ErrIntegrity }
	normalized, err := NormalizeContact(value)
	if err != nil { return Contact{}, ErrIntegrity }
	return normalized, nil
}

func contactSortName(value Contact) string { return strings.ToLower(value.DisplayName) }

func contactSearchText(value Contact) string {
	parts := []string{value.DisplayName, value.GivenName, value.FamilyName, value.Organization}
	for _, address := range value.Addresses { parts = append(parts, address.Normalized) }
	for _, phone := range value.Phones { parts = append(parts, phone.Normalized) }
	return strings.ToLower(strings.Join(parts, " "))
}

type contactCursor struct { Query string `json:"q"`; Name string `json:"n"`; ID string `json:"i"` }

func encodeContactCursor(scope Scope, search, name, id string) string {
	digest := addressDigest(scope.TenantID + "\x00" + scope.UserID + "\x00" + scope.MailboxID + "\x00" + search)
	raw, _ := json.Marshal(contactCursor{Query: digest, Name: name, ID: id})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeContactCursor(scope Scope, search, cursor string) (string, string, error) {
	if cursor == "" { return "", "", nil }
	if len(cursor) > 2048 { return "", "", ErrInvalid }
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil { return "", "", ErrInvalid }
	var value contactCursor
	if json.Unmarshal(raw, &value) != nil || value.Query != addressDigest(scope.TenantID+"\x00"+scope.UserID+"\x00"+scope.MailboxID+"\x00"+search) || value.Name == "" || !opaquePattern.MatchString(value.ID) { return "", "", ErrInvalid }
	return value.Name, value.ID, nil
}

func requireChanged(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil { return err }
	if count != 1 { return ErrConflict }
	return nil
}

func classifyConstraint(err error) error {
	if err == nil { return nil }
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique constraint") && strings.Contains(message, "address") { return ErrDuplicate }
	if strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed") { return ErrConflict }
	return err
}

func boolInt(value bool) int { if value { return 1 }; return 0 }

func dbTime(value time.Time) string { return value.UTC().Truncate(time.Second).Format(time.RFC3339) }

func parseDBTime(value string) (time.Time, error) { return time.Parse(time.RFC3339, value) }

func validDigest(value string) bool {
	if len(value) != 64 { return false }
	_, err := hex.DecodeString(value)
	return err == nil
}
