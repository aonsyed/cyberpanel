package mailtelemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const repositoryTimeLayout = "2006-01-02T15:04:05.000000000Z"

type SQLiteRepository struct {
	db         *sql.DB
	authorizer Authorizer
	auditor    Auditor
	now        func() time.Time
	writer     sync.Mutex
}

func NewSQLiteRepository(db *sql.DB, authorizer Authorizer, auditor Auditor) (*SQLiteRepository, error) {
	if db == nil || authorizer == nil || auditor == nil {
		return nil, ErrInvalid
	}
	return &SQLiteRepository{db: db, authorizer: authorizer, auditor: auditor, now: time.Now}, nil
}

func (repository *SQLiteRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil || ctx == nil {
		return ErrInvalid
	}
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS mail_telemetry_schema_v1 (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL CHECK(version = 1)) STRICT`,
		`INSERT OR IGNORE INTO mail_telemetry_schema_v1(singleton, version) VALUES(1, 1)`,
		`CREATE TABLE IF NOT EXISTS mail_log_policies_v1 (
			policy_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, domain_id TEXT NOT NULL, mailbox_id TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK(revision > 0), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), document BLOB NOT NULL,
			created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(tenant_id, domain_id, mailbox_id)) STRICT`,
		`CREATE INDEX IF NOT EXISTS mail_log_policies_scope_v1 ON mail_log_policies_v1(tenant_id, domain_id, mailbox_id)`,
		`CREATE TABLE IF NOT EXISTS mail_telemetry_events_v1 (
			event_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, domain_id TEXT NOT NULL, mailbox_id TEXT NOT NULL,
			policy_id TEXT NOT NULL, policy_revision INTEGER NOT NULL CHECK(policy_revision >= 0), retain_until TEXT NOT NULL,
			source_id TEXT NOT NULL, source_generation INTEGER NOT NULL, source_cursor TEXT NOT NULL, occurred_at TEXT NOT NULL,
			category TEXT NOT NULL, direction TEXT NOT NULL, result TEXT NOT NULL, evidence TEXT NOT NULL, record_digest TEXT NOT NULL,
			document BLOB NOT NULL, UNIQUE(source_id, source_generation, source_cursor)) STRICT`,
		`CREATE INDEX IF NOT EXISTS mail_telemetry_events_search_v1 ON mail_telemetry_events_v1(tenant_id, domain_id, mailbox_id, occurred_at, event_id)`,
		`CREATE INDEX IF NOT EXISTS mail_telemetry_events_retention_v1 ON mail_telemetry_events_v1(tenant_id, policy_id, evidence, retain_until, event_id)`,
		`CREATE TABLE IF NOT EXISTS mail_telemetry_gaps_v1 (
			gap_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL, source_generation INTEGER NOT NULL,
			first_at TEXT NOT NULL, last_at TEXT NOT NULL, code TEXT NOT NULL, count INTEGER NOT NULL CHECK(count > 0), document BLOB NOT NULL) STRICT`,
		`CREATE INDEX IF NOT EXISTS mail_telemetry_gaps_scope_v1 ON mail_telemetry_gaps_v1(tenant_id, first_at, gap_id)`,
		`CREATE TABLE IF NOT EXISTS mail_telemetry_aggregates_v1 (
			bucket_kind TEXT NOT NULL CHECK(bucket_kind IN ('hour','day')), bucket_start TEXT NOT NULL, tenant_id TEXT NOT NULL,
			domain_id TEXT NOT NULL, mailbox_id TEXT NOT NULL, sampled INTEGER NOT NULL CHECK(sampled >= 0), inbound INTEGER NOT NULL CHECK(inbound >= 0),
			outbound INTEGER NOT NULL CHECK(outbound >= 0), internal_count INTEGER NOT NULL CHECK(internal_count >= 0),
			delivery_count INTEGER NOT NULL CHECK(delivery_count >= 0), delivery_denominator INTEGER NOT NULL CHECK(delivery_denominator >= 0),
			rejection_count INTEGER NOT NULL CHECK(rejection_count >= 0), rejection_denominator INTEGER NOT NULL CHECK(rejection_denominator >= 0),
			deferral_count INTEGER NOT NULL CHECK(deferral_count >= 0), deferral_denominator INTEGER NOT NULL CHECK(deferral_denominator >= 0),
			bounce_count INTEGER NOT NULL CHECK(bounce_count >= 0), bounce_denominator INTEGER NOT NULL CHECK(bounce_denominator >= 0),
			spam_count INTEGER NOT NULL CHECK(spam_count >= 0), spam_denominator INTEGER NOT NULL CHECK(spam_denominator >= 0),
			malware_count INTEGER NOT NULL CHECK(malware_count >= 0), malware_denominator INTEGER NOT NULL CHECK(malware_denominator >= 0),
			quota_count INTEGER NOT NULL CHECK(quota_count >= 0), quota_denominator INTEGER NOT NULL CHECK(quota_denominator >= 0),
			auth_count INTEGER NOT NULL CHECK(auth_count >= 0), auth_denominator INTEGER NOT NULL CHECK(auth_denominator >= 0),
			PRIMARY KEY(bucket_kind, bucket_start, tenant_id, domain_id, mailbox_id)) STRICT`,
		`CREATE INDEX IF NOT EXISTS mail_telemetry_aggregates_query_v1 ON mail_telemetry_aggregates_v1(tenant_id, domain_id, mailbox_id, bucket_kind, bucket_start)`,
		`CREATE TABLE IF NOT EXISTS mail_telemetry_cursors_v1 (
			source_id TEXT PRIMARY KEY, source_generation INTEGER NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0),
			last_record_digest TEXT NOT NULL, document BLOB NOT NULL, updated_at TEXT NOT NULL) STRICT`,
		`CREATE TABLE IF NOT EXISTS mail_telemetry_export_jobs_v1 (
			export_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0),
			state TEXT NOT NULL CHECK(state IN ('pending','running','complete','failed')), document BLOB NOT NULL, updated_at TEXT NOT NULL) STRICT`,
		`CREATE INDEX IF NOT EXISTS mail_telemetry_export_jobs_scope_v1 ON mail_telemetry_export_jobs_v1(tenant_id, export_id)`,
		`CREATE TABLE IF NOT EXISTS mail_telemetry_holds_v1 (
			hold_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, domain_id TEXT NOT NULL, mailbox_id TEXT NOT NULL,
			start_at TEXT NOT NULL, end_at TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), document BLOB NOT NULL) STRICT`,
		`CREATE INDEX IF NOT EXISTS mail_telemetry_holds_scope_v1 ON mail_telemetry_holds_v1(tenant_id, domain_id, mailbox_id, start_at, end_at)`,
		`CREATE TABLE IF NOT EXISTS mail_telemetry_purge_receipts_v1 (
			plan_digest TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL, deleted_count INTEGER NOT NULL CHECK(deleted_count >= 0),
			first_at TEXT NOT NULL, last_at TEXT NOT NULL, document BLOB NOT NULL, completed_at TEXT NOT NULL) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS mail_telemetry_purge_receipts_no_update_v1 BEFORE UPDATE ON mail_telemetry_purge_receipts_v1 BEGIN SELECT RAISE(ABORT, 'purge receipts are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS mail_telemetry_purge_receipts_no_delete_v1 BEFORE DELETE ON mail_telemetry_purge_receipts_v1 BEGIN SELECT RAISE(ABORT, 'purge receipts are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS mail_telemetry_policy_audit_v1 (
			audit_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL, actor_id TEXT NOT NULL,
			action TEXT NOT NULL, request_digest TEXT NOT NULL, document BLOB NOT NULL, occurred_at TEXT NOT NULL) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS mail_telemetry_policy_audit_no_update_v1 BEFORE UPDATE ON mail_telemetry_policy_audit_v1 BEGIN SELECT RAISE(ABORT, 'policy audit is immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS mail_telemetry_policy_audit_no_delete_v1 BEFORE DELETE ON mail_telemetry_policy_audit_v1 BEGIN SELECT RAISE(ABORT, 'policy audit is immutable'); END`,
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	for _, statement := range statements {
		if _, err = transaction.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	var version uint8
	if err = transaction.QueryRowContext(ctx, `SELECT version FROM mail_telemetry_schema_v1 WHERE singleton = 1`).Scan(&version); err != nil || version != 1 {
		return errors.Join(ErrIntegrity, err)
	}
	return transaction.Commit()
}

func repositoryTime(value time.Time) string {
	if value.IsZero() { return "" }
	return value.UTC().Format(repositoryTimeLayout)
}

func encodeDocument(value any, maximum int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maximum {
		return nil, ErrLimit
	}
	return encoded, nil
}

func decodeDocument(encoded []byte, maximum int, target any) error {
	if len(encoded) == 0 || len(encoded) > maximum {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func changedExactlyOne(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func scanPolicy(row interface{ Scan(...any) error }) (Policy, error) {
	var tenant TenantID
	var policyID PolicyID
	var revision uint64
	var document []byte
	if err := row.Scan(&tenant, &policyID, &revision, &document); err != nil {
		return Policy{}, err
	}
	var policy Policy
	if decodeDocument(document, 64<<10, &policy) != nil || policy.Validate() != nil || policy.TenantID != tenant || policy.ID != policyID || policy.Revision != revision {
		return Policy{}, ErrIntegrity
	}
	return policy, nil
}

func (repository *SQLiteRepository) PutPolicy(ctx context.Context, actor Actor, policy Policy, expectedRevision uint64) error {
	if repository == nil || ctx == nil || !actor.valid() || policy.Validate() != nil || actor.TenantID != policy.TenantID || policy.Revision != expectedRevision+1 || expectedRevision > MaximumRevision-1 {
		return ErrInvalid
	}
	if repository.authorizer.AuthorizePolicy(ctx, actor, policy.TenantID, policy.DomainID, policy.MailboxID, true) != nil {
		return ErrUnauthorized
	}
	document, err := encodeDocument(policy, 64<<10)
	if err != nil {
		return err
	}
	requestHash := sha256.Sum256(document)
	requestDigest := hex.EncodeToString(requestHash[:])
	audit := AuditRecord{Action: "mail_log_policy.mutate", Actor: actor, TenantID: policy.TenantID, ResourceID: string(policy.ID), At: repository.now().UTC(), RequestDigest: requestDigest, Outcome: "authorized", EvidenceDigest: digestParts(string(policy.ID), requestDigest, actor.SubjectID)}
	if err = repository.auditor.RecordMailTelemetryAudit(ctx, audit); err != nil {
		return err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if expectedRevision == 0 {
		_, err = transaction.ExecContext(ctx, `INSERT INTO mail_log_policies_v1(policy_id, tenant_id, domain_id, mailbox_id, revision, enabled, document, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, policy.ID, policy.TenantID, policy.DomainID, policy.MailboxID, policy.Revision, policy.Enabled, document, repositoryTime(policy.CreatedAt), repositoryTime(policy.UpdatedAt))
	} else {
		previous, loadErr := scanPolicy(transaction.QueryRowContext(ctx, `SELECT tenant_id, policy_id, revision, document FROM mail_log_policies_v1 WHERE policy_id = ? AND tenant_id = ?`, policy.ID, policy.TenantID))
		if loadErr != nil {
			if errors.Is(loadErr, sql.ErrNoRows) {
				return ErrNotFound
			}
			return loadErr
		}
		if previous.Revision != expectedRevision || previous.CreatedAt.UTC() != policy.CreatedAt.UTC() || previous.DomainID != policy.DomainID || previous.MailboxID != policy.MailboxID || !policy.EvidenceFloor.atLeast(previous.EvidenceFloor) || policy.Retention.SecurityFloor < previous.Retention.SecurityFloor || policy.Retention.AuditFloor < previous.Retention.AuditFloor {
			return ErrConflict
		}
		var result sql.Result
		result, err = transaction.ExecContext(ctx, `UPDATE mail_log_policies_v1 SET revision = ?, enabled = ?, document = ?, updated_at = ? WHERE policy_id = ? AND tenant_id = ? AND revision = ?`, policy.Revision, policy.Enabled, document, repositoryTime(policy.UpdatedAt), policy.ID, policy.TenantID, expectedRevision)
		if err == nil {
			err = changedExactlyOne(result)
		}
	}
	if err != nil {
		return errors.Join(ErrConflict, err)
	}
	auditDocument, err := encodeDocument(audit, 32<<10)
	if err != nil {
		return err
	}
	auditID := "audit-" + digestParts(string(policy.ID), fmt.Sprint(policy.Revision), requestDigest)[:24]
	if _, err = transaction.ExecContext(ctx, `INSERT INTO mail_telemetry_policy_audit_v1(audit_id, tenant_id, policy_id, actor_id, action, request_digest, document, occurred_at) VALUES(?,?,?,?,?,?,?,?)`, auditID, policy.TenantID, policy.ID, actor.SubjectID, audit.Action, requestDigest, auditDocument, repositoryTime(audit.At)); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *SQLiteRepository) GetPolicy(ctx context.Context, actor Actor, tenant TenantID, policyID PolicyID) (Policy, error) {
	if repository == nil || ctx == nil || !actor.valid() || !validID(string(policyID)) {
		return Policy{}, ErrInvalid
	}
	if actor.TenantID != tenant { return Policy{}, ErrNotFound }
	policy, err := scanPolicy(repository.db.QueryRowContext(ctx, `SELECT tenant_id, policy_id, revision, document FROM mail_log_policies_v1 WHERE tenant_id = ? AND policy_id = ?`, tenant, policyID))
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, err
	}
	if repository.authorizer.AuthorizePolicy(ctx, actor, tenant, policy.DomainID, policy.MailboxID, false) != nil {
		return Policy{}, ErrNotFound
	}
	return policy, nil
}

func (repository *SQLiteRepository) EffectiveMailLogPolicy(ctx context.Context, tenant TenantID, domain DomainID, mailbox MailboxID) (Policy, error) {
	if repository == nil || ctx == nil || !validID(string(tenant)) || domain != "" && !validID(string(domain)) || mailbox != "" && !validID(string(mailbox)) {
		return Policy{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT tenant_id, policy_id, revision, document FROM mail_log_policies_v1 WHERE tenant_id = ? AND (domain_id = ? OR domain_id = '') AND (mailbox_id = ? OR mailbox_id = '') ORDER BY CASE WHEN mailbox_id <> '' THEN 0 WHEN domain_id <> '' THEN 1 ELSE 2 END LIMIT 2`, tenant, domain, mailbox)
	if err != nil {
		return Policy{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return Policy{}, ErrNotFound
	}
	return scanPolicy(rows)
}

type aggregateDelta struct {
	sampled, inbound, outbound, internal uint64
	deliveryCount, deliveryDenominator uint64
	rejectionCount, rejectionDenominator uint64
	deferralCount, deferralDenominator uint64
	bounceCount, bounceDenominator uint64
	spamCount, spamDenominator uint64
	malwareCount, malwareDenominator uint64
	quotaCount, quotaDenominator uint64
	authCount, authDenominator uint64
}

func deltaFor(event Event) aggregateDelta {
	delta := aggregateDelta{sampled: 1}
	switch event.Direction {
	case DirectionInbound:
		delta.inbound = 1
	case DirectionOutbound:
		delta.outbound = 1
	case DirectionInternal:
		delta.internal = 1
	}
	mailOutcome := event.Category == CategoryDelivery || event.Category == CategoryRejection || event.Category == CategoryDeferral || event.Category == CategoryBounce
	if mailOutcome {
		delta.deliveryDenominator, delta.rejectionDenominator, delta.deferralDenominator, delta.bounceDenominator = 1, 1, 1, 1
	}
	switch event.Category {
	case CategoryDelivery:
		if event.Result == ResultDelivered { delta.deliveryCount = 1 }
	case CategoryRejection:
		delta.rejectionCount = 1
	case CategoryDeferral:
		delta.deferralCount = 1
	case CategoryBounce:
		delta.bounceCount = 1
	case CategorySpam:
		delta.spamDenominator = 1
		if event.Result == ResultDetected || event.Result == ResultQuarantined || event.Result == ResultRejected { delta.spamCount = 1 }
	case CategoryMalware:
		delta.malwareDenominator = 1
		if event.Result == ResultDetected || event.Result == ResultQuarantined || event.Result == ResultRejected { delta.malwareCount = 1 }
	case CategoryQuota:
		delta.quotaDenominator, delta.quotaCount = 1, 1
	case CategoryAuth:
		delta.authDenominator = 1
		if event.Result == ResultFailed || event.Result == ResultRejected { delta.authCount = 1 }
	}
	return delta
}

func aggregateInsert(ctx context.Context, transaction *sql.Tx, event Event, kind string, start time.Time, domain DomainID, mailbox MailboxID) error {
	d := deltaFor(event)
	_, err := transaction.ExecContext(ctx, `INSERT INTO mail_telemetry_aggregates_v1(
		bucket_kind,bucket_start,tenant_id,domain_id,mailbox_id,sampled,inbound,outbound,internal_count,
		delivery_count,delivery_denominator,rejection_count,rejection_denominator,deferral_count,deferral_denominator,bounce_count,bounce_denominator,
		spam_count,spam_denominator,malware_count,malware_denominator,quota_count,quota_denominator,auth_count,auth_denominator)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(bucket_kind,bucket_start,tenant_id,domain_id,mailbox_id) DO UPDATE SET
		sampled=sampled+excluded.sampled,inbound=inbound+excluded.inbound,outbound=outbound+excluded.outbound,internal_count=internal_count+excluded.internal_count,
		delivery_count=delivery_count+excluded.delivery_count,delivery_denominator=delivery_denominator+excluded.delivery_denominator,
		rejection_count=rejection_count+excluded.rejection_count,rejection_denominator=rejection_denominator+excluded.rejection_denominator,
		deferral_count=deferral_count+excluded.deferral_count,deferral_denominator=deferral_denominator+excluded.deferral_denominator,
		bounce_count=bounce_count+excluded.bounce_count,bounce_denominator=bounce_denominator+excluded.bounce_denominator,
		spam_count=spam_count+excluded.spam_count,spam_denominator=spam_denominator+excluded.spam_denominator,
		malware_count=malware_count+excluded.malware_count,malware_denominator=malware_denominator+excluded.malware_denominator,
		quota_count=quota_count+excluded.quota_count,quota_denominator=quota_denominator+excluded.quota_denominator,
		auth_count=auth_count+excluded.auth_count,auth_denominator=auth_denominator+excluded.auth_denominator`,
		kind, repositoryTime(start), event.TenantID, domain, mailbox, d.sampled, d.inbound, d.outbound, d.internal,
		d.deliveryCount, d.deliveryDenominator, d.rejectionCount, d.rejectionDenominator, d.deferralCount, d.deferralDenominator, d.bounceCount, d.bounceDenominator,
		d.spamCount, d.spamDenominator, d.malwareCount, d.malwareDenominator, d.quotaCount, d.quotaDenominator, d.authCount, d.authDenominator)
	return err
}

func (repository *SQLiteRepository) PutEvent(ctx context.Context, event Event) (bool, error) {
	if repository == nil || ctx == nil || event.Validate() != nil {
		return false, ErrInvalid
	}
	document, err := encodeDocument(event, 128<<10)
	if err != nil { return false, err }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return false, err }
	defer transaction.Rollback()
	var existingID EventID
	var existingDigest string
	var existingDocument []byte
	existingErr := transaction.QueryRowContext(ctx, `SELECT event_id,record_digest,document FROM mail_telemetry_events_v1 WHERE source_id=? AND source_generation=? AND source_cursor=?`, event.SourceID, event.SourceGeneration, event.SourceCursor).Scan(&existingID, &existingDigest, &existingDocument)
	if existingErr == nil {
		if existingID != event.ID || existingDigest != event.Provenance.RecordDigest || !bytes.Equal(existingDocument, document) { return false, ErrIntegrity }
		return false, nil
	}
	if !errors.Is(existingErr, sql.ErrNoRows) { return false, existingErr }
	if event.Evidence == EvidenceOrdinary {
		policy, loadErr := scanPolicy(transaction.QueryRowContext(ctx, `SELECT tenant_id,policy_id,revision,document FROM mail_log_policies_v1 WHERE tenant_id=? AND policy_id=?`, event.TenantID, event.PolicyID))
		if loadErr != nil || policy.Revision < event.PolicyRevision { return false, ErrIntegrity }
		var storedBytes int64
		if loadErr = transaction.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(document)),0) FROM mail_telemetry_events_v1 WHERE tenant_id=? AND policy_id=? AND evidence=?`, event.TenantID, event.PolicyID, EvidenceOrdinary).Scan(&storedBytes); loadErr != nil { return false, loadErr }
		if storedBytes < 0 || storedBytes+int64(len(document)) > policy.Retention.StorageBytes { return false, ErrLimit }
	}
	result, err := transaction.ExecContext(ctx, `INSERT OR IGNORE INTO mail_telemetry_events_v1(event_id,tenant_id,domain_id,mailbox_id,policy_id,policy_revision,retain_until,source_id,source_generation,source_cursor,occurred_at,category,direction,result,evidence,record_digest,document) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, event.ID, event.TenantID, event.DomainID, event.MailboxID, event.PolicyID, event.PolicyRevision, repositoryTime(event.RetainUntil), event.SourceID, event.SourceGeneration, event.SourceCursor, repositoryTime(event.OccurredAt), event.Category, event.Direction, event.Result, event.Evidence, event.Provenance.RecordDigest, document)
	if err != nil { return false, err }
	rows, err := result.RowsAffected()
	if err != nil { return false, err }
	if rows == 0 {
		err = transaction.QueryRowContext(ctx, `SELECT event_id,record_digest,document FROM mail_telemetry_events_v1 WHERE source_id=? AND source_generation=? AND source_cursor=?`, event.SourceID, event.SourceGeneration, event.SourceCursor).Scan(&existingID, &existingDigest, &existingDocument)
		if err != nil || existingID != event.ID || existingDigest != event.Provenance.RecordDigest || !bytes.Equal(existingDocument, document) { return false, ErrIntegrity }
		return false, nil
	}
	hour := event.OccurredAt.UTC().Truncate(time.Hour)
	day := time.Date(hour.Year(), hour.Month(), hour.Day(), 0, 0, 0, 0, time.UTC)
	scopes := [][2]string{{string(event.DomainID), ""}}
	if event.MailboxID != "" { scopes = append(scopes, [2]string{string(event.DomainID), string(event.MailboxID)}) }
	for _, scope := range scopes {
		if err = aggregateInsert(ctx, transaction, event, "hour", hour, DomainID(scope[0]), MailboxID(scope[1])); err != nil { return false, err }
		if err = aggregateInsert(ctx, transaction, event, "day", day, DomainID(scope[0]), MailboxID(scope[1])); err != nil { return false, err }
	}
	if err = transaction.Commit(); err != nil { return false, err }
	return true, nil
}

func (repository *SQLiteRepository) PutGap(ctx context.Context, gap ParseGap) error {
	if repository == nil || ctx == nil || !gap.valid() { return ErrInvalid }
	document, err := encodeDocument(gap, 32<<10)
	if err != nil { return err }
	result, err := repository.db.ExecContext(ctx, `INSERT OR IGNORE INTO mail_telemetry_gaps_v1(gap_id,tenant_id,source_id,source_generation,first_at,last_at,code,count,document) VALUES(?,?,?,?,?,?,?,?,?)`, gap.ID, gap.TenantID, gap.SourceID, gap.SourceGeneration, repositoryTime(gap.FirstAt), repositoryTime(gap.LastAt), gap.Code, gap.Count, document)
	if err != nil { return err }
	rows, err := result.RowsAffected()
	if err != nil { return err }
	if rows == 0 {
		var existing []byte
		if err = repository.db.QueryRowContext(ctx, `SELECT document FROM mail_telemetry_gaps_v1 WHERE gap_id=?`, gap.ID).Scan(&existing); err != nil || !bytes.Equal(existing, document) { return ErrIntegrity }
	}
	return nil
}

func scanEvent(row interface{ Scan(...any) error }) (Event, error) {
	var document []byte
	if err := row.Scan(&document); err != nil { return Event{}, err }
	var event Event
	if decodeDocument(document, 128<<10, &event) != nil || event.Validate() != nil { return Event{}, ErrIntegrity }
	return event, nil
}

func (repository *SQLiteRepository) SearchEvents(ctx context.Context, actor Actor, query EventQuery) (EventPage, error) {
	if repository == nil || ctx == nil || !actor.valid() { return EventPage{}, ErrInvalid }
	if actor.TenantID != query.TenantID { return EventPage{}, ErrNotFound }
	if query.validate(actor) != nil { return EventPage{}, ErrInvalid }
	if repository.authorizer.AuthorizeTelemetry(ctx, actor, query.TenantID, query.DomainID, query.MailboxID, false) != nil { return EventPage{}, ErrNotFound }
	arguments := []any{query.TenantID, repositoryTime(query.Start), repositoryTime(query.End)}
	where := `tenant_id=? AND occurred_at>=? AND occurred_at<?`
	if query.DomainID != "" { where += ` AND domain_id=?`; arguments = append(arguments, query.DomainID) }
	if query.MailboxID != "" { where += ` AND mailbox_id=?`; arguments = append(arguments, query.MailboxID) }
	if query.AfterID != "" { where += ` AND (occurred_at>? OR (occurred_at=? AND event_id>?))`; arguments = append(arguments, repositoryTime(query.AfterAt), repositoryTime(query.AfterAt), query.AfterID) }
	if len(query.Categories) > 0 {
		placeholders := make([]string, len(query.Categories))
		for index, category := range query.Categories { placeholders[index] = "?"; arguments = append(arguments, category) }
		where += ` AND category IN (` + strings.Join(placeholders, ",") + `)`
	}
	arguments = append(arguments, int(query.Limit)+1)
	rows, err := repository.db.QueryContext(ctx, `SELECT document FROM mail_telemetry_events_v1 WHERE `+where+` ORDER BY occurred_at,event_id LIMIT ?`, arguments...)
	if err != nil { return EventPage{}, err }
	defer rows.Close()
	page := EventPage{Events: make([]Event, 0, query.Limit)}
	for rows.Next() {
		event, scanErr := scanEvent(rows)
		if scanErr != nil { return EventPage{}, scanErr }
		if event.TenantID != query.TenantID { return EventPage{}, ErrIntegrity }
		if len(page.Events) == int(query.Limit) { page.NextAt = page.Events[len(page.Events)-1].OccurredAt; page.NextEventID = page.Events[len(page.Events)-1].ID; break }
		page.Events = append(page.Events, event)
	}
	if err = rows.Err(); err != nil { return EventPage{}, err }
	page.Missing, err = repository.searchGaps(ctx, query.TenantID, query.Start, query.End, 64)
	return page, err
}

type EventStreamSink interface {
	WriteMailTelemetryEvent(context.Context, Event) error
	WriteMailTelemetryGap(context.Context, ParseGap) error
	CloseMailTelemetryStream(context.Context, StreamSummary) error
}

type StreamSummary struct {
	Events uint32
	Gaps uint32
	NextAt time.Time
	NextEventID EventID
	Truncated bool
}

func (repository *SQLiteRepository) StreamEvents(ctx context.Context, actor Actor, query EventQuery, maximumRows uint32, sink EventStreamSink) (StreamSummary, error) {
	if repository == nil || ctx == nil || sink == nil || !actor.valid() || maximumRows == 0 || maximumRows > 10_000 { return StreamSummary{}, ErrInvalid }
	if actor.TenantID != query.TenantID { return StreamSummary{}, ErrNotFound }
	if query.validate(actor) != nil { return StreamSummary{}, ErrInvalid }
	summary := StreamSummary{}
	writeGaps := true
	for {
		remaining := maximumRows-summary.Events
		if remaining == 0 { summary.Truncated = true; break }
		if remaining < uint32(query.Limit) { query.Limit = uint16(remaining) }
		page, err := repository.SearchEvents(ctx, actor, query)
		if err != nil { return summary, err }
		if writeGaps {
			for _, gap := range page.Missing {
				if err = sink.WriteMailTelemetryGap(ctx, gap); err != nil { return summary, err }
				summary.Gaps++
			}
			writeGaps = false
		}
		for _, event := range page.Events {
			if err = sink.WriteMailTelemetryEvent(ctx, event); err != nil { return summary, err }
			summary.Events++
		}
		if page.NextEventID == "" { summary.NextAt, summary.NextEventID = time.Time{}, ""; break }
		summary.NextAt, summary.NextEventID = page.NextAt, page.NextEventID
		query.AfterAt, query.AfterID = page.NextAt, page.NextEventID
	}
	return summary, sink.CloseMailTelemetryStream(ctx, summary)
}

func (repository *SQLiteRepository) searchGaps(ctx context.Context, tenant TenantID, start, end time.Time, limit int) ([]ParseGap, error) {
	rows, err := repository.db.QueryContext(ctx, `SELECT document FROM mail_telemetry_gaps_v1 WHERE (tenant_id=? OR tenant_id='') AND last_at>=? AND first_at<? ORDER BY first_at,gap_id LIMIT ?`, tenant, repositoryTime(start), repositoryTime(end), limit)
	if err != nil { return nil, err }
	defer rows.Close()
	gaps := make([]ParseGap, 0, limit)
	for rows.Next() {
		var document []byte
		var gap ParseGap
		if rows.Scan(&document) != nil || decodeDocument(document, 32<<10, &gap) != nil || !gap.valid() { return nil, ErrIntegrity }
		gaps = append(gaps, gap)
	}
	return gaps, rows.Err()
}

func (repository *SQLiteRepository) Statistics(ctx context.Context, actor Actor, tenant TenantID, domain DomainID, mailbox MailboxID, start, end time.Time) (Statistics, error) {
	if repository == nil || ctx == nil || !actor.valid() || !validID(string(tenant)) || domain != "" && !validID(string(domain)) || mailbox != "" && !validID(string(mailbox)) || start.IsZero() || !end.After(start) || end.Sub(start) > MaximumSearchWindow || start != start.UTC().Truncate(time.Hour) || end != end.UTC().Truncate(time.Hour) { return Statistics{}, ErrInvalid }
	if actor.TenantID != tenant { return Statistics{}, ErrNotFound }
	if repository.authorizer.AuthorizeTelemetry(ctx, actor, tenant, domain, mailbox, false) != nil { return Statistics{}, ErrNotFound }
	statistics := Statistics{TenantID: tenant, DomainID: domain, MailboxID: mailbox, WindowStart: start.UTC(), WindowEnd: end.UTC()}
	err := repository.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(sampled),0),COALESCE(SUM(inbound),0),COALESCE(SUM(outbound),0),COALESCE(SUM(internal_count),0),
		COALESCE(SUM(delivery_count),0),COALESCE(SUM(delivery_denominator),0),COALESCE(SUM(rejection_count),0),COALESCE(SUM(rejection_denominator),0),
		COALESCE(SUM(deferral_count),0),COALESCE(SUM(deferral_denominator),0),COALESCE(SUM(bounce_count),0),COALESCE(SUM(bounce_denominator),0),
		COALESCE(SUM(spam_count),0),COALESCE(SUM(spam_denominator),0),COALESCE(SUM(malware_count),0),COALESCE(SUM(malware_denominator),0),
		COALESCE(SUM(quota_count),0),COALESCE(SUM(quota_denominator),0),COALESCE(SUM(auth_count),0),COALESCE(SUM(auth_denominator),0)
		FROM mail_telemetry_aggregates_v1 WHERE bucket_kind='hour' AND tenant_id=? AND domain_id=? AND mailbox_id=? AND bucket_start>=? AND bucket_start<?`, tenant, domain, mailbox, repositoryTime(start), repositoryTime(end)).Scan(
		&statistics.SampledEvents, &statistics.Inbound, &statistics.Outbound, &statistics.Internal,
		&statistics.Delivery.Count, &statistics.Delivery.Denominator, &statistics.Rejection.Count, &statistics.Rejection.Denominator,
		&statistics.Deferral.Count, &statistics.Deferral.Denominator, &statistics.Bounce.Count, &statistics.Bounce.Denominator,
		&statistics.Spam.Count, &statistics.Spam.Denominator, &statistics.Malware.Count, &statistics.Malware.Denominator,
		&statistics.Quota.Count, &statistics.Quota.Denominator, &statistics.Auth.Count, &statistics.Auth.Denominator)
	if err != nil { return Statistics{}, err }
	statistics.Missing, err = repository.searchGaps(ctx, tenant, start, end, 64)
	return statistics, err
}

func (repository *SQLiteRepository) LoadCheckpoint(ctx context.Context, source SourceID) (CursorCheckpoint, error) {
	if repository == nil || ctx == nil || !validID(string(source)) { return CursorCheckpoint{}, ErrInvalid }
	var document []byte
	var generation, revision uint64
	err := repository.db.QueryRowContext(ctx, `SELECT source_generation,revision,document FROM mail_telemetry_cursors_v1 WHERE source_id=?`, source).Scan(&generation, &revision, &document)
	if errors.Is(err, sql.ErrNoRows) { return CursorCheckpoint{}, ErrNotFound }
	if err != nil { return CursorCheckpoint{}, err }
	var checkpoint CursorCheckpoint
	if decodeDocument(document, 32<<10, &checkpoint) != nil || !checkpoint.valid() || checkpoint.SourceID != source || checkpoint.SourceGeneration != generation || checkpoint.Revision != revision { return CursorCheckpoint{}, ErrIntegrity }
	return checkpoint, nil
}

func (repository *SQLiteRepository) PutCheckpoint(ctx context.Context, checkpoint CursorCheckpoint, expectedRevision uint64) error {
	if repository == nil || ctx == nil || !checkpoint.valid() || checkpoint.Revision != expectedRevision+1 { return ErrInvalid }
	document, err := encodeDocument(checkpoint, 32<<10)
	if err != nil { return err }
	if expectedRevision == 0 {
		_, err = repository.db.ExecContext(ctx, `INSERT INTO mail_telemetry_cursors_v1(source_id,source_generation,revision,last_record_digest,document,updated_at) VALUES(?,?,?,?,?,?)`, checkpoint.SourceID, checkpoint.SourceGeneration, checkpoint.Revision, checkpoint.LastRecordDigest, document, repositoryTime(checkpoint.UpdatedAt))
		if err != nil { return errors.Join(ErrConflict, err) }
		return nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE mail_telemetry_cursors_v1 SET source_generation=?,revision=?,last_record_digest=?,document=?,updated_at=? WHERE source_id=? AND revision=?`, checkpoint.SourceGeneration, checkpoint.Revision, checkpoint.LastRecordDigest, document, repositoryTime(checkpoint.UpdatedAt), checkpoint.SourceID, expectedRevision)
	if err != nil { return err }
	return changedExactlyOne(result)
}

type RetentionHold struct {
	ID string `json:"id"`
	TenantID TenantID `json:"tenant_id"`
	DomainID DomainID `json:"domain_id,omitempty"`
	MailboxID MailboxID `json:"mailbox_id,omitempty"`
	Start time.Time `json:"start"`
	End time.Time `json:"end"`
	ReasonDigest string `json:"reason_digest"`
	Revision uint64 `json:"revision"`
}

func (hold RetentionHold) valid() bool { return validID(hold.ID) && validID(string(hold.TenantID)) && (hold.DomainID == "" || validID(string(hold.DomainID))) && (hold.MailboxID == "" || validID(string(hold.MailboxID))) && !hold.Start.IsZero() && hold.End.After(hold.Start) && hold.End.Sub(hold.Start) <= 10*365*24*time.Hour && validDigest(hold.ReasonDigest) && hold.Revision > 0 }

func (repository *SQLiteRepository) PutRetentionHold(ctx context.Context, actor Actor, hold RetentionHold, expectedRevision uint64) error {
	if repository == nil || ctx == nil || !actor.valid() || actor.TenantID != hold.TenantID || !hold.valid() || hold.Revision != expectedRevision+1 { return ErrInvalid }
	if repository.authorizer.AuthorizePolicy(ctx, actor, hold.TenantID, hold.DomainID, hold.MailboxID, true) != nil { return ErrUnauthorized }
	document, err := encodeDocument(hold, 32<<10)
	if err != nil { return err }
	if expectedRevision == 0 {
		_, err = repository.db.ExecContext(ctx, `INSERT INTO mail_telemetry_holds_v1(hold_id,tenant_id,domain_id,mailbox_id,start_at,end_at,revision,document) VALUES(?,?,?,?,?,?,?,?)`, hold.ID, hold.TenantID, hold.DomainID, hold.MailboxID, repositoryTime(hold.Start), repositoryTime(hold.End), hold.Revision, document)
		if err != nil { return ErrConflict }
		return nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE mail_telemetry_holds_v1 SET start_at=?,end_at=?,revision=?,document=? WHERE hold_id=? AND tenant_id=? AND revision=?`, repositoryTime(hold.Start), repositoryTime(hold.End), hold.Revision, document, hold.ID, hold.TenantID, expectedRevision)
	if err != nil { return err }
	return changedExactlyOne(result)
}

type PurgePlan struct {
	TenantID TenantID `json:"tenant_id"`
	PolicyID PolicyID `json:"policy_id"`
	PolicyRevision uint64 `json:"policy_revision"`
	Cutoff time.Time `json:"cutoff"`
	EventIDs []EventID `json:"event_ids"`
	FirstAt time.Time `json:"first_at,omitempty"`
	LastAt time.Time `json:"last_at,omitempty"`
	Digest string `json:"digest"`
}

func (repository *SQLiteRepository) BuildPurgePlan(ctx context.Context, actor Actor, policy Policy, now time.Time, limit uint16) (PurgePlan, error) {
	if repository == nil || ctx == nil || !actor.valid() || actor.TenantID != policy.TenantID || policy.Validate() != nil || now.IsZero() || limit == 0 || limit > MaximumPageSize { return PurgePlan{}, ErrInvalid }
	if repository.authorizer.AuthorizePolicy(ctx, actor, policy.TenantID, policy.DomainID, policy.MailboxID, true) != nil { return PurgePlan{}, ErrUnauthorized }
	cutoff := now.UTC()
	arguments := []any{policy.TenantID, policy.ID, EvidenceOrdinary, repositoryTime(cutoff), policy.DomainID, policy.DomainID, policy.MailboxID, policy.MailboxID, policy.TenantID, int(limit)}
	rows, err := repository.db.QueryContext(ctx, `SELECT event_id,occurred_at FROM mail_telemetry_events_v1 e WHERE e.tenant_id=? AND e.policy_id=? AND e.evidence=? AND e.retain_until<>'' AND e.retain_until<=? AND (?='' OR e.domain_id=?) AND (?='' OR e.mailbox_id=?) AND NOT EXISTS(SELECT 1 FROM mail_telemetry_holds_v1 h WHERE h.tenant_id=? AND (h.domain_id='' OR h.domain_id=e.domain_id) AND (h.mailbox_id='' OR h.mailbox_id=e.mailbox_id) AND h.start_at<=e.occurred_at AND h.end_at>e.occurred_at) ORDER BY e.occurred_at,e.event_id LIMIT ?`, arguments...)
	if err != nil { return PurgePlan{}, err }
	defer rows.Close()
	plan := PurgePlan{TenantID: policy.TenantID, PolicyID: policy.ID, PolicyRevision: policy.Revision, Cutoff: cutoff, EventIDs: make([]EventID, 0, limit)}
	for rows.Next() {
		var id EventID
		var atRaw string
		if err = rows.Scan(&id, &atRaw); err != nil { return PurgePlan{}, err }
		at, parseErr := time.Parse(repositoryTimeLayout, atRaw)
		if parseErr != nil || !validID(string(id)) { return PurgePlan{}, ErrIntegrity }
		if len(plan.EventIDs) == 0 { plan.FirstAt = at }
		plan.LastAt = at
		plan.EventIDs = append(plan.EventIDs, id)
	}
	if err = rows.Err(); err != nil { return PurgePlan{}, err }
	identity := strings.Builder{}
	identity.WriteString(string(plan.TenantID)); identity.WriteByte(0); identity.WriteString(string(plan.PolicyID)); identity.WriteByte(0); identity.WriteString(fmt.Sprint(plan.PolicyRevision)); identity.WriteByte(0); identity.WriteString(repositoryTime(plan.Cutoff))
	for _, id := range plan.EventIDs { identity.WriteByte(0); identity.WriteString(string(id)) }
	plan.Digest = digestParts(identity.String())
	return plan, nil
}

type PurgeReceipt struct {
	PlanDigest string `json:"plan_digest"`
	TenantID TenantID `json:"tenant_id"`
	PolicyID PolicyID `json:"policy_id"`
	Deleted uint64 `json:"deleted"`
	FirstAt time.Time `json:"first_at,omitempty"`
	LastAt time.Time `json:"last_at,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}

func (repository *SQLiteRepository) ApplyPurgePlan(ctx context.Context, actor Actor, plan PurgePlan) (PurgeReceipt, error) {
	if repository == nil || ctx == nil || !actor.valid() || actor.TenantID != plan.TenantID || !validDigest(plan.Digest) || !validID(string(plan.PolicyID)) || plan.PolicyRevision == 0 || len(plan.EventIDs) > MaximumPageSize { return PurgeReceipt{}, ErrInvalid }
	policy, err := repository.GetPolicy(ctx, actor, plan.TenantID, plan.PolicyID)
	if err != nil { return PurgeReceipt{}, err }
	if policy.Revision != plan.PolicyRevision { return PurgeReceipt{}, ErrConflict }
	rebuilt, err := repository.BuildPurgePlan(ctx, actor, policy, plan.Cutoff, uint16(maxInt(1, len(plan.EventIDs))))
	if err != nil || rebuilt.Digest != plan.Digest { return PurgeReceipt{}, ErrConflict }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return PurgeReceipt{}, err }
	defer transaction.Rollback()
	for _, eventID := range plan.EventIDs {
		result, deleteErr := transaction.ExecContext(ctx, `DELETE FROM mail_telemetry_events_v1 WHERE event_id=? AND tenant_id=? AND policy_id=? AND evidence=? AND retain_until<>'' AND retain_until<=? AND (?='' OR domain_id=?) AND (?='' OR mailbox_id=?) AND NOT EXISTS(SELECT 1 FROM mail_telemetry_holds_v1 h WHERE h.tenant_id=? AND (h.domain_id='' OR h.domain_id=mail_telemetry_events_v1.domain_id) AND (h.mailbox_id='' OR h.mailbox_id=mail_telemetry_events_v1.mailbox_id) AND h.start_at<=mail_telemetry_events_v1.occurred_at AND h.end_at>mail_telemetry_events_v1.occurred_at)`, eventID, plan.TenantID, policy.ID, EvidenceOrdinary, repositoryTime(plan.Cutoff), policy.DomainID, policy.DomainID, policy.MailboxID, policy.MailboxID, plan.TenantID)
		if deleteErr != nil || changedExactlyOne(result) != nil { return PurgeReceipt{}, ErrConflict }
	}
	receipt := PurgeReceipt{PlanDigest: plan.Digest, TenantID: plan.TenantID, PolicyID: plan.PolicyID, Deleted: uint64(len(plan.EventIDs)), FirstAt: plan.FirstAt, LastAt: plan.LastAt, CompletedAt: repository.now().UTC()}
	document, err := encodeDocument(receipt, 32<<10)
	if err != nil { return PurgeReceipt{}, err }
	if _, err = transaction.ExecContext(ctx, `INSERT INTO mail_telemetry_purge_receipts_v1(plan_digest,tenant_id,policy_id,deleted_count,first_at,last_at,document,completed_at) VALUES(?,?,?,?,?,?,?,?)`, receipt.PlanDigest, receipt.TenantID, receipt.PolicyID, receipt.Deleted, repositoryTime(receipt.FirstAt), repositoryTime(receipt.LastAt), document, repositoryTime(receipt.CompletedAt)); err != nil { return PurgeReceipt{}, err }
	if err = transaction.Commit(); err != nil { return PurgeReceipt{}, err }
	return receipt, nil
}

func maxInt(left, right int) int { if left > right { return left }; return right }
