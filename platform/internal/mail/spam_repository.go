package mail

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type SpamPolicyCASReceipt struct {
	Scope              SpamScope `json:"scope"`
	ExpectedGeneration uint64    `json:"expected_generation"`
	ResultGeneration   uint64    `json:"result_generation"`
	ExpectedRevision   uint64    `json:"expected_revision"`
	ResultRevision     uint64    `json:"result_revision"`
	PolicyDigest       string    `json:"policy_digest"`
	SnapshotDigest     string    `json:"snapshot_digest"`
	OccurredAt         time.Time `json:"occurred_at"`
}

type SpamPolicyListFilter struct {
	TenantID string
	Kind     SpamScopeKind
	DomainID DomainID
	Query    string
	After    SpamScope
	Limit    uint16
}

type SpamQuarantineFilter struct {
	TenantID  string
	DomainID  DomainID
	MailboxID MailboxID
	State     SpamQuarantineState
	Query     string
	After     SpamQuarantineID
	Limit     uint16
	ExpiresBefore time.Time
}

type SpamQuarantineClaim struct {
	OperationID        string
	RequestDigest      string
	ActorID            string
	TenantID           string
	DomainID           DomainID
	MailboxID          MailboxID
	ItemID             SpamQuarantineID
	ObjectID           SpamObjectID
	Action             SpamQuarantineAction
	EffectKey          string
	ExpectedGeneration uint64
	MaxFeedbackPerHour uint16
	OccurredAt         time.Time
}

type SpamQuarantineCompletion struct {
	OperationID    string
	RequestDigest  string
	TenantID       string
	ArtifactDigest string
	EffectDigest   string
	CompletedAt    time.Time
}

type SpamRepository interface {
	PutSpamPolicy(context.Context, SpamPolicy, uint64, uint64) (SpamPolicySnapshot, SpamPolicyCASReceipt, error)
	SpamSnapshot(context.Context, string) (SpamPolicySnapshot, error)
	SpamSnapshotGeneration(context.Context, string, uint64) (SpamPolicySnapshot, error)
	ListSpamPolicies(context.Context, SpamPolicyListFilter) ([]SpamPolicy, SpamScope, error)
	RegisterSpamQuarantine(context.Context, SpamQuarantineItem) error
	SpamQuarantine(context.Context, string, SpamQuarantineID) (SpamQuarantineItem, error)
	ListSpamQuarantine(context.Context, SpamQuarantineFilter) ([]SpamQuarantineItem, SpamQuarantineID, error)
	BeginSpamQuarantine(context.Context, SpamQuarantineClaim) (SpamQuarantineReceipt, bool, error)
	CompleteSpamQuarantine(context.Context, SpamQuarantineCompletion) (SpamQuarantineReceipt, error)
}

type SQLSpamRepository struct {
	DB     *sql.DB
	writer sync.Mutex
}

func NewSQLSpamRepository(db *sql.DB) (*SQLSpamRepository, error) {
	if db == nil {
		return nil, ErrInvalidCommand
	}
	repository := &SQLSpamRepository{DB: db}
	if err := repository.initialize(context.Background()); err != nil {
		return nil, err
	}
	return repository, nil
}

func (repository *SQLSpamRepository) initialize(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`CREATE TABLE IF NOT EXISTS mail_spam_tenant_heads_v1 (tenant_id TEXT PRIMARY KEY, generation INTEGER NOT NULL CHECK(generation > 0), updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS mail_spam_policy_heads_v1 (tenant_id TEXT NOT NULL, scope_kind TEXT NOT NULL, domain_id TEXT NOT NULL, mailbox_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), generation INTEGER NOT NULL CHECK(generation > 0), digest TEXT NOT NULL, policy_json BLOB NOT NULL, PRIMARY KEY(tenant_id,scope_kind,domain_id,mailbox_id))`,
		`CREATE TABLE IF NOT EXISTS mail_spam_policy_history_v1 (tenant_id TEXT NOT NULL, scope_kind TEXT NOT NULL, domain_id TEXT NOT NULL, mailbox_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), generation INTEGER NOT NULL CHECK(generation > 0), digest TEXT NOT NULL, policy_json BLOB NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,scope_kind,domain_id,mailbox_id,revision))`,
		`CREATE TABLE IF NOT EXISTS mail_spam_generation_history_v1 (tenant_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation > 0), snapshot_digest TEXT NOT NULL, snapshot_json BLOB NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,generation))`,
		`CREATE TRIGGER IF NOT EXISTS mail_spam_policy_history_no_update_v1 BEFORE UPDATE ON mail_spam_policy_history_v1 BEGIN SELECT RAISE(ABORT,'immutable spam policy history'); END`,
		`CREATE TRIGGER IF NOT EXISTS mail_spam_policy_history_no_delete_v1 BEFORE DELETE ON mail_spam_policy_history_v1 BEGIN SELECT RAISE(ABORT,'immutable spam policy history'); END`,
		`CREATE TRIGGER IF NOT EXISTS mail_spam_generation_history_no_update_v1 BEFORE UPDATE ON mail_spam_generation_history_v1 BEGIN SELECT RAISE(ABORT,'immutable spam generation history'); END`,
		`CREATE TRIGGER IF NOT EXISTS mail_spam_generation_history_no_delete_v1 BEFORE DELETE ON mail_spam_generation_history_v1 BEGIN SELECT RAISE(ABORT,'immutable spam generation history'); END`,
		`CREATE TABLE IF NOT EXISTS mail_spam_quarantine_v1 (tenant_id TEXT NOT NULL, item_id TEXT NOT NULL, object_id TEXT NOT NULL UNIQUE, domain_id TEXT NOT NULL, mailbox_id TEXT NOT NULL, verdict TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation > 0), state TEXT NOT NULL, retain_until TEXT NOT NULL, item_json BLOB NOT NULL, PRIMARY KEY(tenant_id,item_id))`,
		`CREATE TABLE IF NOT EXISTS mail_spam_quarantine_history_v1 (tenant_id TEXT NOT NULL, item_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation > 0), item_json BLOB NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,item_id,generation))`,
		`CREATE TRIGGER IF NOT EXISTS mail_spam_quarantine_history_no_update_v1 BEFORE UPDATE ON mail_spam_quarantine_history_v1 BEGIN SELECT RAISE(ABORT,'immutable spam quarantine history'); END`,
		`CREATE TRIGGER IF NOT EXISTS mail_spam_quarantine_history_no_delete_v1 BEFORE DELETE ON mail_spam_quarantine_history_v1 BEGIN SELECT RAISE(ABORT,'immutable spam quarantine history'); END`,
		`CREATE TABLE IF NOT EXISTS mail_spam_quarantine_receipts_v1 (tenant_id TEXT NOT NULL, operation_id TEXT NOT NULL, item_id TEXT NOT NULL, object_id TEXT NOT NULL, action TEXT NOT NULL, effect_key TEXT NOT NULL, request_digest TEXT NOT NULL, completed INTEGER NOT NULL CHECK(completed IN (0,1)), receipt_json BLOB NOT NULL, occurred_at TEXT NOT NULL, PRIMARY KEY(tenant_id,operation_id))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS mail_spam_quarantine_delivery_effect_v1 ON mail_spam_quarantine_receipts_v1(tenant_id,item_id,effect_key) WHERE effect_key <> ''`,
		`CREATE TRIGGER IF NOT EXISTS mail_spam_quarantine_receipt_no_delete_v1 BEFORE DELETE ON mail_spam_quarantine_receipts_v1 BEGIN SELECT RAISE(ABORT,'immutable spam quarantine receipt'); END`,
		`CREATE TRIGGER IF NOT EXISTS mail_spam_quarantine_receipt_binding_v1 BEFORE UPDATE ON mail_spam_quarantine_receipts_v1 WHEN OLD.tenant_id <> NEW.tenant_id OR OLD.operation_id <> NEW.operation_id OR OLD.item_id <> NEW.item_id OR OLD.object_id <> NEW.object_id OR OLD.action <> NEW.action OR OLD.effect_key <> NEW.effect_key OR OLD.request_digest <> NEW.request_digest OR OLD.completed <> 0 OR NEW.completed <> 1 BEGIN SELECT RAISE(ABORT,'invalid spam quarantine receipt transition'); END`,
	}
	for _, statement := range statements {
		if _, err := repository.DB.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (repository *SQLSpamRepository) PutSpamPolicy(ctx context.Context, policy SpamPolicy, expectedGeneration, expectedRevision uint64) (SpamPolicySnapshot, SpamPolicyCASReceipt, error) {
	if repository == nil || repository.DB == nil || ctx == nil || expectedGeneration == ^uint64(0) || expectedRevision == ^uint64(0) {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, ErrInvalidCommand
	}
	normalized, err := NormalizeSpamPolicy(policy)
	if err != nil || normalized.Generation != expectedGeneration+1 || normalized.Revision != expectedRevision+1 {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, ErrInvalidCommand
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	defer tx.Rollback()
	currentGeneration, exists, err := spamTenantGeneration(ctx, tx, normalized.Scope.TenantID)
	if err != nil || exists && currentGeneration != expectedGeneration || !exists && expectedGeneration != 0 {
		if err != nil {
			return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
		}
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, ErrConflict
	}
	currentRevision, exists, err := spamPolicyRevision(ctx, tx, normalized.Scope)
	if err != nil || exists && currentRevision != expectedRevision || !exists && expectedRevision != 0 {
		if err != nil {
			return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
		}
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, ErrConflict
	}
	if normalized.Scope.Kind != SpamScopeGlobal {
		parent, parentErr := loadSpamParent(ctx, tx, normalized.Scope)
		if parentErr != nil || ValidateSpamChild(parent, normalized) != nil {
			if parentErr != nil {
				return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, parentErr
			}
			return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, ErrConflict
		}
	}
	policyRaw, err := json.Marshal(normalized)
	if err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	policyDigest, err := SpamPolicyDigest(normalized)
	if err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mail_spam_policy_history_v1(tenant_id,scope_kind,domain_id,mailbox_id,revision,generation,digest,policy_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, normalized.Scope.TenantID, normalized.Scope.Kind, normalized.Scope.DomainID, normalized.Scope.MailboxID, normalized.Revision, normalized.Generation, policyDigest, policyRaw, normalized.UpdatedAt.Format(time.RFC3339)); err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mail_spam_policy_heads_v1(tenant_id,scope_kind,domain_id,mailbox_id,revision,generation,digest,policy_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,scope_kind,domain_id,mailbox_id) DO UPDATE SET revision=excluded.revision,generation=excluded.generation,digest=excluded.digest,policy_json=excluded.policy_json`, normalized.Scope.TenantID, normalized.Scope.Kind, normalized.Scope.DomainID, normalized.Scope.MailboxID, normalized.Revision, normalized.Generation, policyDigest, policyRaw); err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	if err = rebaseSpamDescendants(ctx, tx, normalized); err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mail_spam_tenant_heads_v1(tenant_id,generation,updated_at) VALUES(?,?,?) ON CONFLICT(tenant_id) DO UPDATE SET generation=excluded.generation,updated_at=excluded.updated_at WHERE generation=?`, normalized.Scope.TenantID, normalized.Generation, normalized.UpdatedAt.Format(time.RFC3339), expectedGeneration); err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	snapshot, err := loadSpamSnapshot(ctx, tx, normalized.Scope.TenantID, normalized.Generation, normalized.UpdatedAt)
	if err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	snapshotRaw, err := json.Marshal(snapshot)
	if err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	snapshotDigest := spamBytesDigest(snapshotRaw)
	if _, err = tx.ExecContext(ctx, `INSERT INTO mail_spam_generation_history_v1(tenant_id,generation,snapshot_digest,snapshot_json,created_at) VALUES(?,?,?,?,?)`, normalized.Scope.TenantID, normalized.Generation, snapshotDigest, snapshotRaw, normalized.UpdatedAt.Format(time.RFC3339)); err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return SpamPolicySnapshot{}, SpamPolicyCASReceipt{}, err
	}
	receipt := SpamPolicyCASReceipt{Scope: normalized.Scope, ExpectedGeneration: expectedGeneration, ResultGeneration: normalized.Generation, ExpectedRevision: expectedRevision, ResultRevision: normalized.Revision, PolicyDigest: policyDigest, SnapshotDigest: snapshotDigest, OccurredAt: normalized.UpdatedAt}
	return snapshot, receipt, nil
}

func (repository *SQLSpamRepository) SpamSnapshot(ctx context.Context, tenantID string) (SpamPolicySnapshot, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenantID) {
		return SpamPolicySnapshot{}, ErrInvalidCommand
	}
	var raw []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM mail_spam_generation_history_v1 WHERE tenant_id=? ORDER BY generation DESC LIMIT 1`, tenantID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SpamPolicySnapshot{}, ErrNotFound
	}
	if err != nil {
		return SpamPolicySnapshot{}, err
	}
	return decodeSpamSnapshot(raw)
}

func (repository *SQLSpamRepository) SpamSnapshotGeneration(ctx context.Context, tenantID string, generation uint64) (SpamPolicySnapshot, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenantID) || generation == 0 {
		return SpamPolicySnapshot{}, ErrInvalidCommand
	}
	var raw []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM mail_spam_generation_history_v1 WHERE tenant_id=? AND generation=?`, tenantID, generation).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SpamPolicySnapshot{}, ErrNotFound
	}
	if err != nil {
		return SpamPolicySnapshot{}, err
	}
	return decodeSpamSnapshot(raw)
}

func (repository *SQLSpamRepository) ListSpamPolicies(ctx context.Context, filter SpamPolicyListFilter) ([]SpamPolicy, SpamScope, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(filter.TenantID) || filter.Limit == 0 || filter.Limit > SpamMaximumListLimit || filter.Query != strings.ToLower(strings.TrimSpace(filter.Query)) || len(filter.Query) > 160 || strings.ContainsAny(filter.Query, "%_\x00") || filter.Kind != "" && filter.Kind != SpamScopeGlobal && filter.Kind != SpamScopeDomain && filter.Kind != SpamScopeMailbox || filter.After.Kind != "" && filter.After.Validate() != nil {
		return nil, SpamScope{}, ErrInvalidCommand
	}
	if filter.DomainID != "" && !validOpaque(string(filter.DomainID)) || filter.After.Kind != "" && filter.After.TenantID != filter.TenantID {
		return nil, SpamScope{}, ErrInvalidCommand
	}
	query := `SELECT policy_json FROM mail_spam_policy_heads_v1 WHERE tenant_id=? AND (?='' OR scope_kind=?) AND (?='' OR domain_id=?) AND (?='' OR lower(domain_id||' '||mailbox_id) LIKE ?) AND (scope_kind,domain_id,mailbox_id)>(?,?,?) ORDER BY scope_kind,domain_id,mailbox_id LIMIT ?`
	afterKind, afterDomain, afterMailbox := "", "", ""
	if filter.After.Kind != "" {
		afterKind, afterDomain, afterMailbox = string(filter.After.Kind), string(filter.After.DomainID), string(filter.After.MailboxID)
	}
	rows, err := repository.DB.QueryContext(ctx, query, filter.TenantID, filter.Kind, filter.Kind, filter.DomainID, filter.DomainID, filter.Query, "%"+filter.Query+"%", afterKind, afterDomain, afterMailbox, filter.Limit)
	if err != nil {
		return nil, SpamScope{}, err
	}
	defer rows.Close()
	result := make([]SpamPolicy, 0, filter.Limit)
	var cursor SpamScope
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, SpamScope{}, err
		}
		policy, decodeErr := decodeSpamPolicy(raw)
		if decodeErr != nil {
			return nil, SpamScope{}, decodeErr
		}
		result = append(result, policy)
		cursor = policy.Scope
	}
	return result, cursor, rows.Err()
}

func (repository *SQLSpamRepository) RegisterSpamQuarantine(ctx context.Context, item SpamQuarantineItem) error {
	if repository == nil || repository.DB == nil || ctx == nil || item.Validate() != nil || item.State != SpamQuarantineHeld || item.Generation != 1 {
		return ErrInvalidCommand
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO mail_spam_quarantine_v1(tenant_id,item_id,object_id,domain_id,mailbox_id,verdict,generation,state,retain_until,item_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, item.TenantID, item.ID, item.ObjectID, item.DomainID, item.MailboxID, item.Verdict, item.Generation, item.State, item.RetainUntil.Format(time.RFC3339), raw); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mail_spam_quarantine_history_v1(tenant_id,item_id,generation,item_json,created_at) VALUES(?,?,?,?,?)`, item.TenantID, item.ID, item.Generation, raw, item.CreatedAt.Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *SQLSpamRepository) SpamQuarantine(ctx context.Context, tenantID string, itemID SpamQuarantineID) (SpamQuarantineItem, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenantID) || !validSpamID(string(itemID), "spamq_") {
		return SpamQuarantineItem{}, ErrInvalidCommand
	}
	var raw []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT item_json FROM mail_spam_quarantine_v1 WHERE tenant_id=? AND item_id=?`, tenantID, itemID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SpamQuarantineItem{}, ErrNotFound
	}
	if err != nil {
		return SpamQuarantineItem{}, err
	}
	return decodeSpamQuarantine(raw)
}

func (repository *SQLSpamRepository) ListSpamQuarantine(ctx context.Context, filter SpamQuarantineFilter) ([]SpamQuarantineItem, SpamQuarantineID, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(filter.TenantID) || filter.Limit == 0 || filter.Limit > SpamMaximumListLimit || filter.DomainID != "" && !validOpaque(string(filter.DomainID)) || filter.MailboxID != "" && !validOpaque(string(filter.MailboxID)) || filter.After != "" && !validSpamID(string(filter.After), "spamq_") || !filter.ExpiresBefore.IsZero() && !canonicalSpamTime(filter.ExpiresBefore) || !validSpamQuarantineStateFilter(filter.State) || filter.Query != strings.ToLower(strings.TrimSpace(filter.Query)) || len(filter.Query) > 160 || strings.ContainsAny(filter.Query, "%_\x00") {
		return nil, "", ErrInvalidCommand
	}
	expires := ""
	if !filter.ExpiresBefore.IsZero() {
		expires = filter.ExpiresBefore.Format(time.RFC3339)
	}
	rows, err := repository.DB.QueryContext(ctx, `SELECT item_json FROM mail_spam_quarantine_v1 WHERE tenant_id=? AND (?='' OR domain_id=?) AND (?='' OR mailbox_id=?) AND (?='' OR state=?) AND (?='' OR lower(item_id||' '||object_id||' '||verdict) LIKE ?) AND item_id>? AND (?='' OR retain_until<=?) ORDER BY item_id LIMIT ?`, filter.TenantID, filter.DomainID, filter.DomainID, filter.MailboxID, filter.MailboxID, filter.State, filter.State, filter.Query, "%"+filter.Query+"%", filter.After, expires, expires, filter.Limit)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	result := make([]SpamQuarantineItem, 0, filter.Limit)
	var cursor SpamQuarantineID
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, "", err
		}
		item, decodeErr := decodeSpamQuarantine(raw)
		if decodeErr != nil {
			return nil, "", decodeErr
		}
		result = append(result, item)
		cursor = item.ID
	}
	return result, cursor, rows.Err()
}

func (repository *SQLSpamRepository) BeginSpamQuarantine(ctx context.Context, claim SpamQuarantineClaim) (SpamQuarantineReceipt, bool, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validSpamQuarantineClaim(claim) {
		return SpamQuarantineReceipt{}, false, ErrInvalidCommand
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return SpamQuarantineReceipt{}, false, err
	}
	defer tx.Rollback()
	if prior, found, loadErr := loadSpamReceipt(ctx, tx, claim.TenantID, claim.OperationID); loadErr != nil {
		return SpamQuarantineReceipt{}, false, loadErr
	} else if found {
		if prior.RequestDigest != claim.RequestDigest || prior.ItemID != claim.ItemID || prior.ObjectID != claim.ObjectID || prior.Action != claim.Action || prior.ActorID != claim.ActorID || prior.EffectKey != claim.EffectKey {
			return SpamQuarantineReceipt{}, false, ErrConflict
		}
		return prior, false, tx.Commit()
	}
	item, err := loadSpamQuarantineTx(ctx, tx, claim.TenantID, claim.ItemID)
	if err != nil {
		return SpamQuarantineReceipt{}, false, err
	}
	if item.TenantID != claim.TenantID || item.DomainID != claim.DomainID || item.MailboxID != claim.MailboxID || item.ObjectID != claim.ObjectID || item.Generation != claim.ExpectedGeneration || item.State != SpamQuarantineHeld {
		return SpamQuarantineReceipt{}, false, ErrConflict
	}
	if item.Malware && (claim.Action == SpamQuarantineRelease || claim.Action == SpamQuarantineDeliver) {
		return SpamQuarantineReceipt{}, false, ErrUnauthorized
	}
	if claim.EffectKey != "" {
		var existingOperation string
		effectErr := tx.QueryRowContext(ctx, `SELECT operation_id FROM mail_spam_quarantine_receipts_v1 WHERE tenant_id=? AND item_id=? AND effect_key=?`, claim.TenantID, claim.ItemID, claim.EffectKey).Scan(&existingOperation)
		if effectErr == nil {
			return SpamQuarantineReceipt{}, false, ErrConflict
		}
		if !errors.Is(effectErr, sql.ErrNoRows) {
			return SpamQuarantineReceipt{}, false, effectErr
		}
	}
	if claim.Action == SpamQuarantineFalsePositive {
		var feedback uint64
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_spam_quarantine_receipts_v1 WHERE tenant_id=? AND action=? AND occurred_at>=?`, claim.TenantID, SpamQuarantineFalsePositive, claim.OccurredAt.Add(-time.Hour).Format(time.RFC3339)).Scan(&feedback); err != nil {
			return SpamQuarantineReceipt{}, false, err
		}
		if feedback >= uint64(claim.MaxFeedbackPerHour) {
			return SpamQuarantineReceipt{}, false, ErrRateLimited
		}
	}
	receipt := SpamQuarantineReceipt{OperationID: claim.OperationID, RequestDigest: claim.RequestDigest, ItemID: claim.ItemID, ObjectID: claim.ObjectID, Action: claim.Action, ActorID: claim.ActorID, EffectKey: claim.EffectKey, PreviousGeneration: item.Generation, ResultGeneration: item.Generation, State: item.State, OccurredAt: claim.OccurredAt}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return SpamQuarantineReceipt{}, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mail_spam_quarantine_receipts_v1(tenant_id,operation_id,item_id,object_id,action,effect_key,request_digest,completed,receipt_json,occurred_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, claim.TenantID, claim.OperationID, claim.ItemID, claim.ObjectID, claim.Action, claim.EffectKey, claim.RequestDigest, 0, raw, claim.OccurredAt.Format(time.RFC3339)); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return SpamQuarantineReceipt{}, false, ErrConflict
		}
		return SpamQuarantineReceipt{}, false, err
	}
	return receipt, true, tx.Commit()
}

func (repository *SQLSpamRepository) CompleteSpamQuarantine(ctx context.Context, completion SpamQuarantineCompletion) (SpamQuarantineReceipt, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(completion.TenantID) || !validOpaque(completion.OperationID) || !validSpamDigest(completion.RequestDigest) || !validSpamDigest(completion.ArtifactDigest) || !validSpamDigest(completion.EffectDigest) || !canonicalSpamTime(completion.CompletedAt) {
		return SpamQuarantineReceipt{}, ErrInvalidCommand
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	defer tx.Rollback()
	receipt, found, err := loadSpamReceipt(ctx, tx, completion.TenantID, completion.OperationID)
	if err != nil || !found {
		if err != nil {
			return SpamQuarantineReceipt{}, err
		}
		return SpamQuarantineReceipt{}, ErrNotFound
	}
	if receipt.RequestDigest != completion.RequestDigest {
		return SpamQuarantineReceipt{}, ErrConflict
	}
	if receipt.Completed {
		if receipt.ArtifactDigest != completion.ArtifactDigest || receipt.EffectDigest != completion.EffectDigest {
			return SpamQuarantineReceipt{}, ErrConflict
		}
		return receipt, tx.Commit()
	}
	item, err := loadSpamQuarantineTx(ctx, tx, completion.TenantID, receipt.ItemID)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if item.ObjectID != receipt.ObjectID || item.Generation != receipt.PreviousGeneration || item.State != SpamQuarantineHeld || item.ObjectDigest != completion.ArtifactDigest {
		return SpamQuarantineReceipt{}, ErrConflict
	}
	nextState := item.State
	switch receipt.Action {
	case SpamQuarantineAccess, SpamQuarantineFalsePositive:
	case SpamQuarantineRelease:
		nextState = SpamQuarantineReleased
	case SpamQuarantineDeliver:
		nextState = SpamQuarantineDelivered
	case SpamQuarantineDelete:
		nextState = SpamQuarantineDeleted
	default:
		return SpamQuarantineReceipt{}, ErrInvalidReceipt
	}
	if nextState != item.State {
		item.State = nextState
		item.Generation++
		item.UpdatedAt = completion.CompletedAt
		itemRaw, marshalErr := json.Marshal(item)
		if marshalErr != nil {
			return SpamQuarantineReceipt{}, marshalErr
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE mail_spam_quarantine_v1 SET generation=?,state=?,item_json=? WHERE tenant_id=? AND item_id=? AND generation=? AND state=?`, item.Generation, item.State, itemRaw, item.TenantID, item.ID, receipt.PreviousGeneration, SpamQuarantineHeld)
		if updateErr != nil {
			return SpamQuarantineReceipt{}, updateErr
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return SpamQuarantineReceipt{}, ErrConflict
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mail_spam_quarantine_history_v1(tenant_id,item_id,generation,item_json,created_at) VALUES(?,?,?,?,?)`, item.TenantID, item.ID, item.Generation, itemRaw, completion.CompletedAt.Format(time.RFC3339)); err != nil {
			return SpamQuarantineReceipt{}, err
		}
	}
	receipt.ResultGeneration = item.Generation
	receipt.State = nextState
	receipt.ArtifactDigest = completion.ArtifactDigest
	receipt.EffectDigest = completion.EffectDigest
	receipt.Completed = true
	receipt.OccurredAt = completion.CompletedAt
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mail_spam_quarantine_receipts_v1 SET completed=1,receipt_json=?,occurred_at=? WHERE tenant_id=? AND operation_id=? AND completed=0`, receiptRaw, completion.CompletedAt.Format(time.RFC3339), completion.TenantID, completion.OperationID); err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return SpamQuarantineReceipt{}, err
	}
	return receipt, nil
}

type spamSQLQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func spamTenantGeneration(ctx context.Context, queryer spamSQLQueryer, tenantID string) (uint64, bool, error) {
	var generation uint64
	err := queryer.QueryRowContext(ctx, `SELECT generation FROM mail_spam_tenant_heads_v1 WHERE tenant_id=?`, tenantID).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return generation, err == nil, err
}

func spamPolicyRevision(ctx context.Context, queryer spamSQLQueryer, scope SpamScope) (uint64, bool, error) {
	var revision uint64
	err := queryer.QueryRowContext(ctx, `SELECT revision FROM mail_spam_policy_heads_v1 WHERE tenant_id=? AND scope_kind=? AND domain_id=? AND mailbox_id=?`, scope.TenantID, scope.Kind, scope.DomainID, scope.MailboxID).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return revision, err == nil, err
}

func loadSpamParent(ctx context.Context, queryer spamSQLQueryer, scope SpamScope) (SpamPolicy, error) {
	parentScope := SpamScope{TenantID: scope.TenantID, Kind: SpamScopeGlobal}
	if scope.Kind == SpamScopeMailbox {
		parentScope = SpamScope{TenantID: scope.TenantID, Kind: SpamScopeDomain, DomainID: scope.DomainID}
		var exists int
		err := queryer.QueryRowContext(ctx, `SELECT 1 FROM mail_spam_policy_heads_v1 WHERE tenant_id=? AND scope_kind=? AND domain_id=? AND mailbox_id=''`, scope.TenantID, SpamScopeDomain, scope.DomainID).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			parentScope = SpamScope{TenantID: scope.TenantID, Kind: SpamScopeGlobal}
		} else if err != nil {
			return SpamPolicy{}, err
		}
	}
	var raw []byte
	err := queryer.QueryRowContext(ctx, `SELECT policy_json FROM mail_spam_policy_heads_v1 WHERE tenant_id=? AND scope_kind=? AND domain_id=? AND mailbox_id=?`, parentScope.TenantID, parentScope.Kind, parentScope.DomainID, parentScope.MailboxID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SpamPolicy{}, ErrConflict
	}
	if err != nil {
		return SpamPolicy{}, err
	}
	return decodeSpamPolicy(raw)
}

func loadSpamSnapshot(ctx context.Context, queryer spamSQLQueryer, tenantID string, generation uint64, createdAt time.Time) (SpamPolicySnapshot, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT policy_json FROM mail_spam_policy_heads_v1 WHERE tenant_id=? ORDER BY scope_kind,domain_id,mailbox_id`, tenantID)
	if err != nil {
		return SpamPolicySnapshot{}, err
	}
	defer rows.Close()
	snapshot := SpamPolicySnapshot{TenantID: tenantID, Generation: generation, CreatedAt: createdAt}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return SpamPolicySnapshot{}, err
		}
		policy, decodeErr := decodeSpamPolicy(raw)
		if decodeErr != nil {
			return SpamPolicySnapshot{}, decodeErr
		}
		snapshot.Policies = append(snapshot.Policies, policy)
	}
	if err = rows.Err(); err != nil {
		return SpamPolicySnapshot{}, err
	}
	return NormalizeSpamSnapshot(snapshot)
}

func rebaseSpamDescendants(ctx context.Context, tx *sql.Tx, parent SpamPolicy) error {
	if parent.Scope.Kind == SpamScopeMailbox {
		return nil
	}
	childKind := SpamScopeDomain
	domainID := DomainID("")
	if parent.Scope.Kind == SpamScopeDomain {
		childKind = SpamScopeMailbox
		domainID = parent.Scope.DomainID
	}
	rows, err := tx.QueryContext(ctx, `SELECT policy_json FROM mail_spam_policy_heads_v1 WHERE tenant_id=? AND scope_kind=? AND (?='' OR domain_id=?) ORDER BY domain_id,mailbox_id`, parent.Scope.TenantID, childKind, domainID, domainID)
	if err != nil {
		return err
	}
	children := make([]SpamPolicy, 0)
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		child, decodeErr := decodeSpamPolicy(raw)
		if decodeErr != nil {
			rows.Close()
			return decodeErr
		}
		children = append(children, child)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	parentDigest, err := SpamPolicyDigest(parent)
	if err != nil {
		return err
	}
	for _, child := range children {
		child.ParentRevision = parent.Revision
		child.ParentDigest = parentDigest
		child.Revision++
		child.Generation = parent.Generation
		child.UpdatedAt = parent.UpdatedAt
		if err = ValidateSpamChild(parent, child); err != nil {
			return err
		}
		childRaw, marshalErr := json.Marshal(child)
		if marshalErr != nil {
			return marshalErr
		}
		childDigest, digestErr := SpamPolicyDigest(child)
		if digestErr != nil {
			return digestErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mail_spam_policy_history_v1(tenant_id,scope_kind,domain_id,mailbox_id,revision,generation,digest,policy_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, child.Scope.TenantID, child.Scope.Kind, child.Scope.DomainID, child.Scope.MailboxID, child.Revision, child.Generation, childDigest, childRaw, child.UpdatedAt.Format(time.RFC3339)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mail_spam_policy_heads_v1 SET revision=?,generation=?,digest=?,policy_json=? WHERE tenant_id=? AND scope_kind=? AND domain_id=? AND mailbox_id=?`, child.Revision, child.Generation, childDigest, childRaw, child.Scope.TenantID, child.Scope.Kind, child.Scope.DomainID, child.Scope.MailboxID); err != nil {
			return err
		}
		if child.Scope.Kind == SpamScopeDomain {
			if err = rebaseSpamDescendants(ctx, tx, child); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadSpamQuarantineTx(ctx context.Context, queryer spamSQLQueryer, tenantID string, itemID SpamQuarantineID) (SpamQuarantineItem, error) {
	var raw []byte
	err := queryer.QueryRowContext(ctx, `SELECT item_json FROM mail_spam_quarantine_v1 WHERE tenant_id=? AND item_id=?`, tenantID, itemID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SpamQuarantineItem{}, ErrNotFound
	}
	if err != nil {
		return SpamQuarantineItem{}, err
	}
	return decodeSpamQuarantine(raw)
}

func loadSpamReceipt(ctx context.Context, queryer spamSQLQueryer, tenantID, operationID string) (SpamQuarantineReceipt, bool, error) {
	var raw []byte
	err := queryer.QueryRowContext(ctx, `SELECT receipt_json FROM mail_spam_quarantine_receipts_v1 WHERE tenant_id=? AND operation_id=?`, tenantID, operationID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SpamQuarantineReceipt{}, false, nil
	}
	if err != nil {
		return SpamQuarantineReceipt{}, false, err
	}
	var receipt SpamQuarantineReceipt
	if err = strictJSON(raw, &receipt); err != nil || receipt.OperationID != operationID || receipt.RequestDigest == "" {
		return SpamQuarantineReceipt{}, false, errors.Join(ErrInvalidReceipt, err)
	}
	return receipt, true, nil
}

func decodeSpamPolicy(raw []byte) (SpamPolicy, error) {
	var policy SpamPolicy
	if err := strictJSON(raw, &policy); err != nil {
		return SpamPolicy{}, errors.Join(ErrInvalidReceipt, err)
	}
	policy, err := NormalizeSpamPolicy(policy)
	if err != nil {
		return SpamPolicy{}, errors.Join(ErrInvalidReceipt, err)
	}
	return policy, nil
}

func decodeSpamSnapshot(raw []byte) (SpamPolicySnapshot, error) {
	var snapshot SpamPolicySnapshot
	if err := strictJSON(raw, &snapshot); err != nil {
		return SpamPolicySnapshot{}, errors.Join(ErrInvalidReceipt, err)
	}
	snapshot, err := NormalizeSpamSnapshot(snapshot)
	if err != nil {
		return SpamPolicySnapshot{}, errors.Join(ErrInvalidReceipt, err)
	}
	return snapshot, nil
}

func decodeSpamQuarantine(raw []byte) (SpamQuarantineItem, error) {
	var item SpamQuarantineItem
	if err := strictJSON(raw, &item); err != nil || item.Validate() != nil {
		return SpamQuarantineItem{}, errors.Join(ErrInvalidReceipt, err)
	}
	return item, nil
}

func validSpamQuarantineClaim(claim SpamQuarantineClaim) bool {
	if !validOpaque(claim.OperationID) || !validSpamDigest(claim.RequestDigest) || !validOpaque(claim.ActorID) || !validOpaque(claim.TenantID) || !validOpaque(string(claim.DomainID)) || !validOpaque(string(claim.MailboxID)) || !validSpamID(string(claim.ItemID), "spamq_") || !validSpamID(string(claim.ObjectID), "spamobj_") || claim.ExpectedGeneration == 0 || !canonicalSpamTime(claim.OccurredAt) {
		return false
	}
	switch claim.Action {
	case SpamQuarantineAccess:
		return claim.EffectKey == "" && claim.MaxFeedbackPerHour == 0
	case SpamQuarantineFalsePositive:
		return validOpaque(claim.EffectKey) && claim.MaxFeedbackPerHour > 0 && claim.MaxFeedbackPerHour <= SpamMaximumFeedbackPerHour
	case SpamQuarantineRelease, SpamQuarantineDeliver, SpamQuarantineDelete:
		return validOpaque(claim.EffectKey) && claim.MaxFeedbackPerHour == 0
	default:
		return false
	}
}

func validSpamQuarantineStateFilter(state SpamQuarantineState) bool {
	return state == "" || state == SpamQuarantineHeld || state == SpamQuarantineReleased || state == SpamQuarantineDelivered || state == SpamQuarantineDeleted
}

func spamBytesDigest(raw []byte) string {
	return fmt.Sprintf("%x", sha256Sum(raw))
}

func sha256Sum(raw []byte) [32]byte {
	// Kept local so the repository never needs to retain request or message data.
	return sha256.Sum256(raw)
}
