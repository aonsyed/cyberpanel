package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

const AutoresponderSchema = `
CREATE TABLE IF NOT EXISTS mail_autoresponders_v1 (
    tenant_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
    state TEXT NOT NULL,
    rule_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, rule_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS mail_autoresponders_scope_v1
    ON mail_autoresponders_v1 (tenant_id, domain_id, mailbox_id, rule_id);
CREATE TABLE IF NOT EXISTS mail_autoresponder_reply_ledger_v1 (
    tenant_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    sender_digest TEXT NOT NULL,
    rule_generation INTEGER NOT NULL CHECK (rule_generation > 0),
    last_replied_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, rule_id, sender_digest),
    FOREIGN KEY (tenant_id, rule_id) REFERENCES mail_autoresponders_v1 (tenant_id, rule_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS mail_autoresponder_reply_age_v1
    ON mail_autoresponder_reply_ledger_v1 (tenant_id, rule_id, last_replied_at);
`

const maximumAutoresponderJSON = 64 << 10

type AutoresponderRepository interface {
	Create(context.Context, AutoresponderRule) (AutoresponderRule, error)
	Get(context.Context, string, AutoresponderID) (AutoresponderRule, bool, error)
	List(context.Context, string, DomainID, MailboxID, AutoresponderID, uint32) ([]AutoresponderRule, AutoresponderID, error)
	Update(context.Context, AutoresponderRule, uint64) (AutoresponderRule, error)
	Delete(context.Context, string, AutoresponderID, uint64) error
	ClaimReply(context.Context, string, AutoresponderID, uint64, Address, time.Time) (bool, error)
}

type SQLAutoresponderRepository struct {
	DB *sql.DB
	writer sync.Mutex
}

func NewSQLAutoresponderRepository(db *sql.DB) (*SQLAutoresponderRepository, error) {
	if db == nil {
		return nil, ErrInvalidCommand
	}
	return &SQLAutoresponderRepository{DB: db}, nil
}

func (repository *SQLAutoresponderRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.DB == nil || ctx == nil {
		return ErrInvalidCommand
	}
	_, err := repository.DB.ExecContext(ctx, AutoresponderSchema)
	return err
}

func (repository *SQLAutoresponderRepository) Create(ctx context.Context, rule AutoresponderRule) (AutoresponderRule, error) {
	if repository == nil || repository.DB == nil || ctx == nil || rule.Generation != 1 {
		return AutoresponderRule{}, ErrInvalidCommand
	}
	if err := rule.Validate(); err != nil {
		return AutoresponderRule{}, err
	}
	raw, err := encodeAutoresponderRule(rule)
	if err != nil {
		return AutoresponderRule{}, err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.DB.ExecContext(ctx, `INSERT INTO mail_autoresponders_v1
        (tenant_id,rule_id,domain_id,mailbox_id,generation,enabled,state,rule_json,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT (tenant_id,rule_id) DO NOTHING`, rule.TenantID, rule.ID, rule.DomainID, rule.MailboxID, rule.Generation, rule.Enabled, rule.State, raw, autoresponderTimestamp(rule.CreatedAt), autoresponderTimestamp(rule.UpdatedAt))
	if err != nil {
		return AutoresponderRule{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return AutoresponderRule{}, err
	}
	if inserted != 1 {
		return AutoresponderRule{}, ErrConflict
	}
	return rule, nil
}

func (repository *SQLAutoresponderRepository) Get(ctx context.Context, tenant string, ruleID AutoresponderID) (AutoresponderRule, bool, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(ruleID)) {
		return AutoresponderRule{}, false, ErrInvalidCommand
	}
	return loadAutoresponderRule(ctx, repository.DB, tenant, ruleID)
}

func (repository *SQLAutoresponderRepository) List(ctx context.Context, tenant string, domainID DomainID, mailboxID MailboxID, after AutoresponderID, limit uint32) ([]AutoresponderRule, AutoresponderID, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(domainID)) || !validOpaque(string(mailboxID)) || after != "" && !validOpaque(string(after)) || limit > AutoresponderMaximumListLimit {
		return nil, "", ErrInvalidCommand
	}
	if limit == 0 {
		limit = 50
	}
	rows, err := repository.DB.QueryContext(ctx, `SELECT rule_id,rule_json FROM mail_autoresponders_v1
        WHERE tenant_id=? AND domain_id=? AND mailbox_id=? AND rule_id>? ORDER BY rule_id ASC LIMIT ?`, tenant, domainID, mailboxID, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	rules := make([]AutoresponderRule, 0, limit)
	for rows.Next() {
		var storedID AutoresponderID
		var raw []byte
		if err = rows.Scan(&storedID, &raw); err != nil {
			return nil, "", err
		}
		var rule AutoresponderRule
		if err = decodeAutoresponderJSON(raw, &rule); err != nil || rule.ID != storedID || rule.TenantID != tenant || rule.DomainID != domainID || rule.MailboxID != mailboxID || rule.Validate() != nil {
			return nil, "", ErrInvalidReceipt
		}
		rules = append(rules, rule)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	var next AutoresponderID
	if len(rules) > int(limit) {
		rules = rules[:limit]
		next = rules[len(rules)-1].ID
	}
	return rules, next, nil
}

func (repository *SQLAutoresponderRepository) Update(ctx context.Context, rule AutoresponderRule, expected uint64) (AutoresponderRule, error) {
	if repository == nil || repository.DB == nil || ctx == nil || expected == 0 || expected >= AutoresponderMaximumGeneration || rule.Generation != expected+1 {
		return AutoresponderRule{}, ErrInvalidCommand
	}
	if err := rule.Validate(); err != nil {
		return AutoresponderRule{}, err
	}
	raw, err := encodeAutoresponderRule(rule)
	if err != nil {
		return AutoresponderRule{}, err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.DB.ExecContext(ctx, `UPDATE mail_autoresponders_v1 SET
        domain_id=?,mailbox_id=?,generation=?,enabled=?,state=?,rule_json=?,updated_at=?
		WHERE tenant_id=? AND rule_id=? AND domain_id=? AND mailbox_id=? AND generation=? AND created_at=? AND updated_at<=?`, rule.DomainID, rule.MailboxID, rule.Generation, rule.Enabled, rule.State, raw, autoresponderTimestamp(rule.UpdatedAt), rule.TenantID, rule.ID, rule.DomainID, rule.MailboxID, expected, autoresponderTimestamp(rule.CreatedAt), autoresponderTimestamp(rule.UpdatedAt))
	if err != nil {
		return AutoresponderRule{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return AutoresponderRule{}, err
	}
	if changed != 1 {
		return AutoresponderRule{}, ErrConflict
	}
	return rule, nil
}

func (repository *SQLAutoresponderRepository) Delete(ctx context.Context, tenant string, ruleID AutoresponderID, expected uint64) error {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(ruleID)) || expected == 0 || expected > AutoresponderMaximumGeneration {
		return ErrInvalidCommand
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM mail_autoresponder_reply_ledger_v1 WHERE tenant_id=? AND rule_id=?`, tenant, ruleID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM mail_autoresponders_v1 WHERE tenant_id=? AND rule_id=? AND generation=?`, tenant, ruleID, expected)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (repository *SQLAutoresponderRepository) ClaimReply(ctx context.Context, tenant string, ruleID AutoresponderID, expected uint64, sender Address, at time.Time) (bool, error) {
	sender = Address(strings.ToLower(strings.TrimSpace(string(sender))))
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(ruleID)) || expected == 0 || expected > AutoresponderMaximumGeneration || ValidateAddress(sender) != nil || at.IsZero() {
		return false, ErrInvalidCommand
	}
	at = at.UTC().Truncate(time.Second)
	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	rule, found, err := loadAutoresponderRule(ctx, tx, tenant, ruleID)
	if err != nil {
		return false, err
	}
	if !found {
		return false, ErrNotFound
	}
	if rule.Generation != expected {
		return false, ErrConflict
	}
	if !rule.EffectiveAt(at) || !rule.SenderAllowed(sender) {
		return false, nil
	}
	digest := autoresponderSenderDigest(sender)
	cutoff := at.Add(-rule.Settings.RepeatInterval)
	result, err := tx.ExecContext(ctx, `INSERT INTO mail_autoresponder_reply_ledger_v1
        (tenant_id,rule_id,sender_digest,rule_generation,last_replied_at) VALUES(?,?,?,?,?)
        ON CONFLICT (tenant_id,rule_id,sender_digest) DO UPDATE SET
        rule_generation=excluded.rule_generation,last_replied_at=excluded.last_replied_at
        WHERE mail_autoresponder_reply_ledger_v1.last_replied_at<=?`, tenant, ruleID, digest, rule.Generation, autoresponderTimestamp(at), autoresponderTimestamp(cutoff))
	if err != nil {
		return false, err
	}
	claimed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return claimed == 1, nil
}

type autoresponderQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadAutoresponderRule(ctx context.Context, source autoresponderQueryer, tenant string, ruleID AutoresponderID) (AutoresponderRule, bool, error) {
	var storedTenant string
	var storedID AutoresponderID
	var generation uint64
	var raw []byte
	err := source.QueryRowContext(ctx, `SELECT tenant_id,rule_id,generation,rule_json FROM mail_autoresponders_v1 WHERE tenant_id=? AND rule_id=?`, tenant, ruleID).Scan(&storedTenant, &storedID, &generation, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return AutoresponderRule{}, false, nil
	}
	if err != nil {
		return AutoresponderRule{}, false, err
	}
	var rule AutoresponderRule
	if err = decodeAutoresponderJSON(raw, &rule); err != nil || storedTenant != tenant || storedID != ruleID || rule.TenantID != tenant || rule.ID != ruleID || rule.Generation != generation || rule.Validate() != nil {
		return AutoresponderRule{}, false, ErrInvalidReceipt
	}
	return rule, true, nil
}

func encodeAutoresponderRule(rule AutoresponderRule) ([]byte, error) {
	raw, err := json.Marshal(rule)
	if err != nil || len(raw) == 0 || len(raw) > maximumAutoresponderJSON {
		return nil, ErrInvalidCommand
	}
	return raw, nil
}

func decodeAutoresponderJSON(raw []byte, target *AutoresponderRule) error {
	if len(raw) == 0 || len(raw) > maximumAutoresponderJSON || target == nil {
		return ErrInvalidReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidReceipt
	}
	return nil
}

func autoresponderSenderDigest(sender Address) string {
	digest := sha256.Sum256([]byte("mail-autoresponder-sender-v1\x00" + string(sender)))
	return hex.EncodeToString(digest[:])
}

func autoresponderTimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
