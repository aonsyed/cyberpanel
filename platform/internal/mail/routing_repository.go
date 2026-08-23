package mail

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"
)

const RoutingSchema = `
CREATE TABLE IF NOT EXISTS mail_routing_domain_versions_v1 (
    tenant_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
    domain_name TEXT NOT NULL,
    policy_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id,domain_id,generation)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mail_routing_domain_heads_v1 (
    tenant_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
    PRIMARY KEY (tenant_id,domain_id),
    FOREIGN KEY (tenant_id,domain_id,generation)
        REFERENCES mail_routing_domain_versions_v1 (tenant_id,domain_id,generation)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mail_routing_rule_versions_v1 (
    tenant_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    domain_generation INTEGER NOT NULL CHECK (domain_generation > 0),
    state TEXT NOT NULL CHECK (state IN ('enabled','disabled','deleted')),
    search_key TEXT NOT NULL,
    rule_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id,domain_id,rule_id,revision)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mail_routing_rule_heads_v1 (
    tenant_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (tenant_id,domain_id,rule_id),
    FOREIGN KEY (tenant_id,domain_id,rule_id,revision)
        REFERENCES mail_routing_rule_versions_v1 (tenant_id,domain_id,rule_id,revision)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mail_routing_generation_receipts_v1 (
    operation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    snapshot_digest TEXT NOT NULL,
    receipt_digest TEXT NOT NULL,
    receipt_json BLOB NOT NULL,
    occurred_at TEXT NOT NULL,
    UNIQUE (tenant_id,domain_id,generation)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS mail_routing_rule_list_v1
    ON mail_routing_rule_heads_v1 (tenant_id,domain_id,rule_id);
CREATE TRIGGER IF NOT EXISTS mail_routing_domain_version_no_update_v1
BEFORE UPDATE ON mail_routing_domain_versions_v1 BEGIN
    SELECT RAISE(ABORT,'routing domain versions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS mail_routing_domain_version_no_delete_v1
BEFORE DELETE ON mail_routing_domain_versions_v1 BEGIN
    SELECT RAISE(ABORT,'routing domain versions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS mail_routing_rule_version_no_update_v1
BEFORE UPDATE ON mail_routing_rule_versions_v1 BEGIN
    SELECT RAISE(ABORT,'routing rule versions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS mail_routing_rule_version_no_delete_v1
BEFORE DELETE ON mail_routing_rule_versions_v1 BEGIN
    SELECT RAISE(ABORT,'routing rule versions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS mail_routing_receipt_no_update_v1
BEFORE UPDATE ON mail_routing_generation_receipts_v1 BEGIN
    SELECT RAISE(ABORT,'routing receipts are immutable');
END;
CREATE TRIGGER IF NOT EXISTS mail_routing_receipt_no_delete_v1
BEFORE DELETE ON mail_routing_generation_receipts_v1 BEGIN
    SELECT RAISE(ABORT,'routing receipts are immutable');
END;
`

type RoutingPolicyMutation struct {
	OperationID            string
	ExpectedGeneration     uint64
	ExpectedPolicyRevision uint64
	Policy                 RoutingDomainPolicy
}

type RoutingRuleMutation struct {
	OperationID        string
	ExpectedGeneration uint64
	ExpectedRevision   uint64
	Rule               RoutingRule
}

type RoutingRepository interface {
	PutRoutingPolicy(context.Context, RoutingPolicyMutation) (RoutingGenerationReceipt, error)
	MutateRoutingRule(context.Context, RoutingRuleMutation) (RoutingGenerationReceipt, error)
	RoutingSnapshot(context.Context, string, DomainID) (RoutingSnapshot, error)
	GetRoutingRule(context.Context, string, DomainID, RoutingRuleID) (RoutingRule, bool, error)
	ListRoutingRules(context.Context, string, DomainID, RoutingRuleID, string, uint32) ([]RoutingRule, error)
}

type SQLRoutingRepository struct {
	DB     *sql.DB
	writer sync.Mutex
}

func NewSQLRoutingRepository(db *sql.DB) (*SQLRoutingRepository, error) {
	if db == nil {
		return nil, ErrInvalidCommand
	}
	return &SQLRoutingRepository{DB: db}, nil
}

func (repository *SQLRoutingRepository) BootstrapRouting(ctx context.Context) error {
	if repository == nil || repository.DB == nil || ctx == nil {
		return ErrInvalidCommand
	}
	var mode string
	if err := repository.DB.QueryRowContext(ctx, `PRAGMA journal_mode=WAL`).Scan(&mode); err != nil || strings.ToLower(mode) != "wal" {
		return errors.Join(ErrInvalidReceipt, err)
	}
	for _, pragma := range []string{`PRAGMA synchronous=FULL`, `PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=5000`} {
		if _, err := repository.DB.ExecContext(ctx, pragma); err != nil {
			return err
		}
	}
	_, err := repository.DB.ExecContext(ctx, RoutingSchema)
	return err
}

func (repository *SQLRoutingRepository) PutRoutingPolicy(ctx context.Context, mutation RoutingPolicyMutation) (RoutingGenerationReceipt, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(mutation.OperationID) || mutation.Policy.Validate() != nil || mutation.Policy.Generation != mutation.ExpectedGeneration+1 || mutation.Policy.Revision != mutation.ExpectedPolicyRevision+1 {
		return RoutingGenerationReceipt{}, ErrInvalidCommand
	}
	var receipt RoutingGenerationReceipt
	err := repository.immediateRouting(ctx, func(connection *sql.Conn) error {
		current, found, loadErr := loadRoutingPolicy(ctx, connection, mutation.Policy.TenantID, mutation.Policy.DomainID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			if mutation.ExpectedGeneration != 0 || mutation.ExpectedPolicyRevision != 0 || mutation.Policy.Generation != 1 || mutation.Policy.Revision != 1 || !mutation.Policy.CreatedAt.Equal(mutation.Policy.UpdatedAt) {
				return ErrConflict
			}
		} else {
			if current.Generation != mutation.ExpectedGeneration || current.Revision != mutation.ExpectedPolicyRevision || current.TenantID != mutation.Policy.TenantID || current.DomainID != mutation.Policy.DomainID || current.DomainName != mutation.Policy.DomainName || !current.CreatedAt.Equal(mutation.Policy.CreatedAt) || mutation.Policy.UpdatedAt.Before(current.UpdatedAt) {
				return ErrConflict
			}
		}
		rules, rulesErr := loadRoutingRuleHeads(ctx, connection, mutation.Policy.TenantID, mutation.Policy.DomainID)
		if rulesErr != nil {
			return rulesErr
		}
		snapshot, snapshotErr := NewRoutingSnapshot(mutation.Policy, rules)
		if snapshotErr != nil {
			return snapshotErr
		}
		if insertErr := insertRoutingPolicyVersion(ctx, connection, mutation.Policy); insertErr != nil {
			return insertErr
		}
		if !found {
			_, loadErr = connection.ExecContext(ctx, `INSERT INTO mail_routing_domain_heads_v1
                    (tenant_id,domain_id,generation,policy_revision) VALUES(?,?,?,?)`, mutation.Policy.TenantID, mutation.Policy.DomainID, mutation.Policy.Generation, mutation.Policy.Revision)
		} else {
			var result sql.Result
			result, loadErr = connection.ExecContext(ctx, `UPDATE mail_routing_domain_heads_v1 SET generation=?,policy_revision=?
                    WHERE tenant_id=? AND domain_id=? AND generation=? AND policy_revision=?`, mutation.Policy.Generation, mutation.Policy.Revision, mutation.Policy.TenantID, mutation.Policy.DomainID, mutation.ExpectedGeneration, mutation.ExpectedPolicyRevision)
			if loadErr == nil {
				var changed int64
				changed, loadErr = result.RowsAffected()
				if loadErr == nil && changed != 1 {
					loadErr = ErrConflict
				}
			}
		}
		if loadErr != nil {
			return loadErr
		}
		receipt, loadErr = newRoutingGenerationReceipt(mutation.OperationID, snapshot)
		if loadErr != nil {
			return loadErr
		}
		return insertRoutingGenerationReceipt(ctx, connection, receipt)
	})
	return receipt, err
}

func (repository *SQLRoutingRepository) MutateRoutingRule(ctx context.Context, mutation RoutingRuleMutation) (RoutingGenerationReceipt, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(mutation.OperationID) || mutation.Rule.Validate() != nil || mutation.Rule.DomainGeneration != mutation.ExpectedGeneration+1 || mutation.Rule.Revision != mutation.ExpectedRevision+1 {
		return RoutingGenerationReceipt{}, ErrInvalidCommand
	}
	var receipt RoutingGenerationReceipt
	err := repository.immediateRouting(ctx, func(connection *sql.Conn) error {
		policy, found, loadErr := loadRoutingPolicy(ctx, connection, mutation.Rule.TenantID, mutation.Rule.DomainID)
		if loadErr != nil {
			return loadErr
		}
		if !found || policy.Generation != mutation.ExpectedGeneration || policy.DomainName != mutation.Rule.DomainName || mutation.Rule.UpdatedAt.Before(policy.UpdatedAt) {
			return ErrConflict
		}
		previous, ruleFound, loadErr := loadRoutingRule(ctx, connection, mutation.Rule.TenantID, mutation.Rule.DomainID, mutation.Rule.ID)
		if loadErr != nil {
			return loadErr
		}
		if transitionErr := validateRoutingRuleTransition(previous, ruleFound, mutation.Rule, mutation.ExpectedRevision); transitionErr != nil {
			return transitionErr
		}
		rules, rulesErr := loadRoutingRuleHeads(ctx, connection, mutation.Rule.TenantID, mutation.Rule.DomainID)
		if rulesErr != nil {
			return rulesErr
		}
		replaced := false
		for index := range rules {
			if rules[index].ID == mutation.Rule.ID {
				rules[index] = mutation.Rule
				replaced = true
				break
			}
		}
		if !replaced {
			rules = append(rules, mutation.Rule)
		}
		nextPolicy := policy
		nextPolicy.Generation = mutation.ExpectedGeneration + 1
		nextPolicy.UpdatedAt = mutation.Rule.UpdatedAt
		if nextPolicy.Validate() != nil {
			return ErrInvalidCommand
		}
		snapshot, snapshotErr := NewRoutingSnapshot(nextPolicy, rules)
		if snapshotErr != nil {
			return snapshotErr
		}
		if insertErr := insertRoutingRuleVersion(ctx, connection, mutation.Rule); insertErr != nil {
			return insertErr
		}
		if !ruleFound {
			_, loadErr = connection.ExecContext(ctx, `INSERT INTO mail_routing_rule_heads_v1
                    (tenant_id,domain_id,rule_id,revision) VALUES(?,?,?,?)`, mutation.Rule.TenantID, mutation.Rule.DomainID, mutation.Rule.ID, mutation.Rule.Revision)
		} else {
			var result sql.Result
			result, loadErr = connection.ExecContext(ctx, `UPDATE mail_routing_rule_heads_v1 SET revision=?
                    WHERE tenant_id=? AND domain_id=? AND rule_id=? AND revision=?`, mutation.Rule.Revision, mutation.Rule.TenantID, mutation.Rule.DomainID, mutation.Rule.ID, mutation.ExpectedRevision)
			if loadErr == nil {
				var changed int64
				changed, loadErr = result.RowsAffected()
				if loadErr == nil && changed != 1 {
					loadErr = ErrConflict
				}
			}
		}
		if loadErr != nil {
			return loadErr
		}
		if loadErr = insertRoutingPolicyVersion(ctx, connection, nextPolicy); loadErr != nil {
			return loadErr
		}
		result, loadErr := connection.ExecContext(ctx, `UPDATE mail_routing_domain_heads_v1 SET generation=?
            WHERE tenant_id=? AND domain_id=? AND generation=? AND policy_revision=?`, nextPolicy.Generation, nextPolicy.TenantID, nextPolicy.DomainID, mutation.ExpectedGeneration, policy.Revision)
		if loadErr != nil {
			return loadErr
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil || changed != 1 {
			return errors.Join(ErrConflict, rowsErr)
		}
		receipt, loadErr = newRoutingGenerationReceipt(mutation.OperationID, snapshot)
		if loadErr != nil {
			return loadErr
		}
		return insertRoutingGenerationReceipt(ctx, connection, receipt)
	})
	return receipt, err
}

func (repository *SQLRoutingRepository) RoutingSnapshot(ctx context.Context, tenant string, domain DomainID) (RoutingSnapshot, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(domain)) {
		return RoutingSnapshot{}, ErrInvalidCommand
	}
	transaction, err := repository.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelSerializable})
	if err != nil {
		return RoutingSnapshot{}, err
	}
	defer transaction.Rollback()
	policy, found, err := loadRoutingPolicy(ctx, transaction, tenant, domain)
	if err != nil {
		return RoutingSnapshot{}, err
	}
	if !found {
		return RoutingSnapshot{}, ErrNotFound
	}
	rules, err := loadRoutingRuleHeads(ctx, transaction, tenant, domain)
	if err != nil {
		return RoutingSnapshot{}, err
	}
	snapshot, err := NewRoutingSnapshot(policy, rules)
	if err != nil {
		return RoutingSnapshot{}, err
	}
	var receiptRaw []byte
	err = transaction.QueryRowContext(ctx, `SELECT receipt_json FROM mail_routing_generation_receipts_v1
        WHERE tenant_id=? AND domain_id=? AND generation=?`, tenant, domain, policy.Generation).Scan(&receiptRaw)
	if err != nil {
		return RoutingSnapshot{}, err
	}
	var receipt RoutingGenerationReceipt
	if decodeRoutingValue(receiptRaw, 32<<10, &receipt) != nil || receipt.Validate() != nil || receipt.SnapshotDigest != snapshot.Digest {
		return RoutingSnapshot{}, ErrInvalidReceipt
	}
	if err = transaction.Commit(); err != nil {
		return RoutingSnapshot{}, err
	}
	return snapshot, nil
}

func (repository *SQLRoutingRepository) GetRoutingRule(ctx context.Context, tenant string, domain DomainID, id RoutingRuleID) (RoutingRule, bool, error) {
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(domain)) || !validOpaque(string(id)) {
		return RoutingRule{}, false, ErrInvalidCommand
	}
	return loadRoutingRule(ctx, repository.DB, tenant, domain, id)
}

func (repository *SQLRoutingRepository) ListRoutingRules(ctx context.Context, tenant string, domain DomainID, after RoutingRuleID, search string, limit uint32) ([]RoutingRule, error) {
	search = strings.ToLower(strings.TrimSpace(search))
	if repository == nil || repository.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(domain)) || after != "" && !validOpaque(string(after)) || len(search) > 160 || strings.ContainsAny(search, "\x00\r\n\t") || limit == 0 || limit > RoutingMaximumList {
		return nil, ErrInvalidCommand
	}
	rows, err := repository.DB.QueryContext(ctx, `SELECT v.rule_json FROM mail_routing_rule_heads_v1 h
        JOIN mail_routing_rule_versions_v1 v ON v.tenant_id=h.tenant_id AND v.domain_id=h.domain_id AND v.rule_id=h.rule_id AND v.revision=h.revision
        WHERE h.tenant_id=? AND h.domain_id=? AND h.rule_id>? AND (?='' OR instr(v.search_key,?)>0)
        ORDER BY h.rule_id LIMIT ?`, tenant, domain, after, search, search, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := make([]RoutingRule, 0, limit)
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var rule RoutingRule
		if decodeRoutingValue(raw, 64<<10, &rule) != nil || rule.Validate() != nil || rule.TenantID != tenant || rule.DomainID != domain {
			return nil, ErrInvalidReceipt
		}
		rules = append(rules, rule)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

type routingQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type routingRowsQueryer interface {
	routingQueryer
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (repository *SQLRoutingRepository) immediateRouting(ctx context.Context, operation func(*sql.Conn) error) error {
	repository.writer.Lock()
	defer repository.writer.Unlock()
	connection, err := repository.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	for _, pragma := range []string{`PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=5000`} {
		if _, err = connection.ExecContext(ctx, pragma); err != nil {
			return err
		}
	}
	if _, err = connection.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = connection.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	if err = operation(connection); err != nil {
		return err
	}
	if _, err = connection.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}

func loadRoutingPolicy(ctx context.Context, source routingQueryer, tenant string, domain DomainID) (RoutingDomainPolicy, bool, error) {
	var raw []byte
	err := source.QueryRowContext(ctx, `SELECT v.policy_json FROM mail_routing_domain_heads_v1 h
        JOIN mail_routing_domain_versions_v1 v ON v.tenant_id=h.tenant_id AND v.domain_id=h.domain_id AND v.generation=h.generation
        WHERE h.tenant_id=? AND h.domain_id=?`, tenant, domain).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return RoutingDomainPolicy{}, false, nil
	}
	if err != nil {
		return RoutingDomainPolicy{}, false, err
	}
	var policy RoutingDomainPolicy
	if decodeRoutingValue(raw, 32<<10, &policy) != nil || policy.Validate() != nil || policy.TenantID != tenant || policy.DomainID != domain {
		return RoutingDomainPolicy{}, false, ErrInvalidReceipt
	}
	return policy, true, nil
}

func loadRoutingRule(ctx context.Context, source routingQueryer, tenant string, domain DomainID, id RoutingRuleID) (RoutingRule, bool, error) {
	var raw []byte
	err := source.QueryRowContext(ctx, `SELECT v.rule_json FROM mail_routing_rule_heads_v1 h
        JOIN mail_routing_rule_versions_v1 v ON v.tenant_id=h.tenant_id AND v.domain_id=h.domain_id AND v.rule_id=h.rule_id AND v.revision=h.revision
        WHERE h.tenant_id=? AND h.domain_id=? AND h.rule_id=?`, tenant, domain, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return RoutingRule{}, false, nil
	}
	if err != nil {
		return RoutingRule{}, false, err
	}
	var rule RoutingRule
	if decodeRoutingValue(raw, 64<<10, &rule) != nil || rule.Validate() != nil || rule.TenantID != tenant || rule.DomainID != domain || rule.ID != id {
		return RoutingRule{}, false, ErrInvalidReceipt
	}
	return rule, true, nil
}

func loadRoutingRuleHeads(ctx context.Context, source routingRowsQueryer, tenant string, domain DomainID) ([]RoutingRule, error) {
	rows, err := source.QueryContext(ctx, `SELECT v.rule_json FROM mail_routing_rule_heads_v1 h
        JOIN mail_routing_rule_versions_v1 v ON v.tenant_id=h.tenant_id AND v.domain_id=h.domain_id AND v.rule_id=h.rule_id AND v.revision=h.revision
        WHERE h.tenant_id=? AND h.domain_id=? ORDER BY h.rule_id LIMIT ?`, tenant, domain, RoutingMaximumRules+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := make([]RoutingRule, 0)
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var rule RoutingRule
		if decodeRoutingValue(raw, 64<<10, &rule) != nil || rule.Validate() != nil || rule.TenantID != tenant || rule.DomainID != domain {
			return nil, ErrInvalidReceipt
		}
		rules = append(rules, rule)
		if len(rules) > int(RoutingMaximumRules) {
			return nil, ErrRateLimited
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func insertRoutingPolicyVersion(ctx context.Context, connection *sql.Conn, policy RoutingDomainPolicy) error {
	raw, err := encodeRoutingValue(policy, 32<<10)
	if err != nil {
		return err
	}
	_, err = connection.ExecContext(ctx, `INSERT INTO mail_routing_domain_versions_v1
        (tenant_id,domain_id,generation,policy_revision,domain_name,policy_json,created_at) VALUES(?,?,?,?,?,?,?)`, policy.TenantID, policy.DomainID, policy.Generation, policy.Revision, policy.DomainName, raw, routingTimestamp(policy.UpdatedAt))
	return err
}

func insertRoutingRuleVersion(ctx context.Context, connection *sql.Conn, rule RoutingRule) error {
	raw, err := encodeRoutingValue(rule, 64<<10)
	if err != nil {
		return err
	}
	searchKey := string(rule.Source)
	if rule.Kind == RoutingPattern {
		searchKey = string(rule.Pattern.Kind) + ":" + rule.Pattern.Literal
	}
	_, err = connection.ExecContext(ctx, `INSERT INTO mail_routing_rule_versions_v1
        (tenant_id,domain_id,rule_id,revision,domain_generation,state,search_key,rule_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, rule.TenantID, rule.DomainID, rule.ID, rule.Revision, rule.DomainGeneration, rule.State, searchKey, raw, routingTimestamp(rule.UpdatedAt))
	return err
}

func newRoutingGenerationReceipt(operation string, snapshot RoutingSnapshot) (RoutingGenerationReceipt, error) {
	receipt := RoutingGenerationReceipt{OperationID: operation, TenantID: snapshot.Policy.TenantID, DomainID: snapshot.Policy.DomainID, Generation: snapshot.Policy.Generation, SnapshotDigest: snapshot.Digest, OccurredAt: snapshot.Policy.UpdatedAt}
	digest, err := routingDigest("mail-routing-generation-receipt-v1", receipt)
	if err != nil {
		return RoutingGenerationReceipt{}, err
	}
	receipt.ReceiptDigest = digest
	return receipt, receipt.Validate()
}

func insertRoutingGenerationReceipt(ctx context.Context, connection *sql.Conn, receipt RoutingGenerationReceipt) error {
	if receipt.Validate() != nil {
		return ErrInvalidReceipt
	}
	raw, err := encodeRoutingValue(receipt, 32<<10)
	if err != nil {
		return err
	}
	_, err = connection.ExecContext(ctx, `INSERT INTO mail_routing_generation_receipts_v1
        (operation_id,tenant_id,domain_id,generation,snapshot_digest,receipt_digest,receipt_json,occurred_at) VALUES(?,?,?,?,?,?,?,?)`, receipt.OperationID, receipt.TenantID, receipt.DomainID, receipt.Generation, receipt.SnapshotDigest, receipt.ReceiptDigest, raw, routingTimestamp(receipt.OccurredAt))
	return err
}

func validateRoutingRuleTransition(previous RoutingRule, found bool, next RoutingRule, expected uint64) error {
	if !found {
		if expected != 0 || next.Revision != 1 || next.State == RoutingRuleDeleted || !next.CreatedAt.Equal(next.UpdatedAt) {
			return ErrConflict
		}
		return nil
	}
	if previous.Revision != expected || next.Revision != expected+1 || previous.State == RoutingRuleDeleted || previous.ID != next.ID || previous.TenantID != next.TenantID || previous.DomainID != next.DomainID || previous.DomainName != next.DomainName || !previous.CreatedAt.Equal(next.CreatedAt) || next.UpdatedAt.Before(previous.UpdatedAt) {
		return ErrConflict
	}
	switch previous.State {
	case RoutingRuleEnabled:
		if next.State != RoutingRuleEnabled && next.State != RoutingRuleDisabled && next.State != RoutingRuleDeleted {
			return ErrConflict
		}
	case RoutingRuleDisabled:
		if next.State != RoutingRuleEnabled && next.State != RoutingRuleDisabled && next.State != RoutingRuleDeleted {
			return ErrConflict
		}
	default:
		return ErrConflict
	}
	return nil
}

func routingTimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
