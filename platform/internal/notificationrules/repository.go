package notificationrules

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sync"
	"time"
)

const (
	createSchemaVersion = `CREATE TABLE IF NOT EXISTS notification_rules_schema_v1 (
singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL CHECK (version = 1))`
	insertSchemaVersion = `INSERT OR IGNORE INTO notification_rules_schema_v1(singleton, version) VALUES (1, 1)`
	createRules = `CREATE TABLE IF NOT EXISTS notification_rules_v1 (
tenant_id TEXT NOT NULL, rule_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK (revision > 0),
priority INTEGER NOT NULL, enabled INTEGER NOT NULL CHECK (enabled IN (0,1)), rule_json BLOB NOT NULL,
updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, rule_id))`
	createRuleOrder = `CREATE INDEX IF NOT EXISTS notification_rules_order_v1 ON notification_rules_v1(tenant_id, priority DESC, rule_id)`
	createDeliveries = `CREATE TABLE IF NOT EXISTS notification_delivery_state_v1 (
tenant_id TEXT NOT NULL, delivery_id TEXT NOT NULL, rule_id TEXT NOT NULL, event_id TEXT NOT NULL,
status TEXT NOT NULL, revision INTEGER NOT NULL CHECK (revision > 0), next_attempt_at TEXT NOT NULL,
state_json BLOB NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, delivery_id))`
	createDeliveryDue = `CREATE INDEX IF NOT EXISTS notification_delivery_due_v1 ON notification_delivery_state_v1(tenant_id, status, next_attempt_at, delivery_id)`
	createDedup = `CREATE TABLE IF NOT EXISTS notification_dedup_state_v1 (
tenant_id TEXT NOT NULL, rule_id TEXT NOT NULL, stage INTEGER NOT NULL, destination_kind TEXT NOT NULL,
destination_id TEXT NOT NULL, dedup_digest TEXT NOT NULL, revision INTEGER NOT NULL CHECK (revision > 0),
last_delivered_at TEXT NOT NULL, rate_window_started TEXT NOT NULL, state_json BLOB NOT NULL, updated_at TEXT NOT NULL,
PRIMARY KEY (tenant_id, rule_id, stage, destination_kind, destination_id, dedup_digest))`
)

const fixedTimeLayout = "2006-01-02T15:04:05.000000000Z"

type SQLiteRepository struct {
	db     *sql.DB
	now    func() time.Time
	writer sync.Mutex
}

func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	if db == nil { return nil, ErrInvalid }
	return &SQLiteRepository{db: db, now: time.Now}, nil
}

func (repository *SQLiteRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil || ctx == nil { return ErrInvalid }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	for _, statement := range []string{createSchemaVersion, insertSchemaVersion, createRules, createRuleOrder, createDeliveries, createDeliveryDue, createDedup} {
		if _, err = transaction.ExecContext(ctx, statement); err != nil { return err }
	}
	var version uint8
	if err = transaction.QueryRowContext(ctx, `SELECT version FROM notification_rules_schema_v1 WHERE singleton = 1`).Scan(&version); err != nil || version != 1 {
		return errors.Join(ErrIntegrity, err)
	}
	return transaction.Commit()
}

func encodeBounded(value any, maximum int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil { return nil, err }
	if len(encoded) == 0 || len(encoded) > maximum { return nil, ErrLimit }
	return encoded, nil
}

func decodeBounded(encoded []byte, maximum int, target any) error {
	if len(encoded) == 0 || len(encoded) > maximum { return ErrIntegrity }
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return ErrIntegrity }
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF { return ErrIntegrity }
	return nil
}

func storedTime(value time.Time) string {
	if value.IsZero() { return "" }
	return value.UTC().Format(fixedTimeLayout)
}

func validTenantAndID(tenantID, id string) bool {
	return opaquePattern.MatchString(tenantID) && opaquePattern.MatchString(id)
}

type rowScanner interface { Scan(...any) error }

func scanRule(row rowScanner, tenantID, ruleID string) (Rule, error) {
	var revision uint64
	var encoded []byte
	var updatedRaw string
	if err := row.Scan(&revision, &encoded, &updatedRaw); err != nil { return Rule{}, err }
	var rule Rule
	if decodeBounded(encoded, MaximumRuleJSONBytes, &rule) != nil || rule.TenantID != tenantID || rule.ID != ruleID || rule.Revision != revision || storedTime(rule.UpdatedAt) != updatedRaw || rule.ValidateStored() != nil {
		return Rule{}, ErrIntegrity
	}
	return rule, nil
}

func (repository *SQLiteRepository) GetRule(ctx context.Context, tenantID, ruleID string) (Rule, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validTenantAndID(tenantID, ruleID) { return Rule{}, ErrInvalid }
	rule, err := scanRule(repository.db.QueryRowContext(ctx, `SELECT revision, rule_json, updated_at FROM notification_rules_v1 WHERE tenant_id = ? AND rule_id = ?`, tenantID, ruleID), tenantID, ruleID)
	if errors.Is(err, sql.ErrNoRows) { return Rule{}, ErrNotFound }
	return rule, err
}

func (repository *SQLiteRepository) ListRules(ctx context.Context, tenantID string, request RulePageRequest) (RulePage, error) {
	if repository == nil || repository.db == nil || ctx == nil || !opaquePattern.MatchString(tenantID) || request.Limit == 0 || request.Limit > MaximumPageSize || request.AfterID != "" && !opaquePattern.MatchString(request.AfterID) {
		return RulePage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT rule_id, revision, rule_json, updated_at FROM notification_rules_v1
WHERE tenant_id = ? AND rule_id > ? ORDER BY rule_id ASC LIMIT ?`, tenantID, request.AfterID, int(request.Limit)+1)
	if err != nil { return RulePage{}, err }
	defer rows.Close()
	rules := make([]Rule, 0, request.Limit)
	for rows.Next() {
		var ruleID string
		var revision uint64
		var encoded []byte
		var updatedRaw string
		if err = rows.Scan(&ruleID, &revision, &encoded, &updatedRaw); err != nil { return RulePage{}, err }
		if len(rules) == int(request.Limit) {
			page := RulePage{Rules: rules, NextAfterID: rules[len(rules)-1].ID}
			return page, rows.Close()
		}
		var rule Rule
		if decodeBounded(encoded, MaximumRuleJSONBytes, &rule) != nil || rule.TenantID != tenantID || rule.ID != ruleID || rule.Revision != revision || storedTime(rule.UpdatedAt) != updatedRaw || rule.ValidateStored() != nil {
			return RulePage{}, ErrIntegrity
		}
		rules = append(rules, rule)
	}
	if err = rows.Err(); err != nil { return RulePage{}, err }
	return RulePage{Rules: rules}, nil
}

func changed(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil { return err }
	if rows != 1 { return ErrConflict }
	return nil
}

func (repository *SQLiteRepository) UpsertRule(ctx context.Context, rule Rule, expectedRevision uint64) (Rule, error) {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision >= uint64(math.MaxInt64) || rule.ValidateConfiguration() != nil { return Rule{}, ErrInvalid }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	rule.Revision = expectedRevision + 1
	rule.UpdatedAt = repository.now().UTC()
	if rule.ValidateStored() != nil { return Rule{}, ErrInvalid }
	encoded, err := encodeBounded(rule, MaximumRuleJSONBytes)
	if err != nil { return Rule{}, err }
	if expectedRevision == 0 {
		result, insertErr := repository.db.ExecContext(ctx, `INSERT INTO notification_rules_v1
(tenant_id, rule_id, revision, priority, enabled, rule_json, updated_at)
SELECT ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM notification_rules_v1 WHERE tenant_id = ?) < ?`,
			rule.TenantID, rule.ID, rule.Revision, rule.Priority, rule.Enabled, encoded, storedTime(rule.UpdatedAt), rule.TenantID, MaximumRulesPerTenant)
		if insertErr != nil {
			if _, getErr := repository.GetRule(ctx, rule.TenantID, rule.ID); getErr == nil { return Rule{}, ErrConflict }
			return Rule{}, insertErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil { return Rule{}, rowsErr }
		if rows == 0 {
			if _, getErr := repository.GetRule(ctx, rule.TenantID, rule.ID); getErr == nil { return Rule{}, ErrConflict }
			return Rule{}, ErrLimit
		}
		return rule, nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE notification_rules_v1 SET revision = ?, priority = ?, enabled = ?, rule_json = ?, updated_at = ? WHERE tenant_id = ? AND rule_id = ? AND revision = ?`,
		rule.Revision, rule.Priority, rule.Enabled, encoded, storedTime(rule.UpdatedAt), rule.TenantID, rule.ID, expectedRevision)
	if err != nil { return Rule{}, err }
	if err = changed(result); err != nil { return Rule{}, err }
	return rule, nil
}

func (repository *SQLiteRepository) DeleteRule(ctx context.Context, tenantID, ruleID string, expectedRevision uint64) error {
	if repository == nil || repository.db == nil || ctx == nil || !validTenantAndID(tenantID, ruleID) || expectedRevision == 0 || expectedRevision > uint64(math.MaxInt64) { return ErrInvalid }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.db.ExecContext(ctx, `DELETE FROM notification_rules_v1 WHERE tenant_id = ? AND rule_id = ? AND revision = ?`, tenantID, ruleID, expectedRevision)
	if err != nil { return err }
	return changed(result)
}

func scanDelivery(row rowScanner, tenantID, deliveryID string) (DeliveryState, error) {
	var revision uint64
	var encoded []byte
	var updatedRaw string
	if err := row.Scan(&revision, &encoded, &updatedRaw); err != nil { return DeliveryState{}, err }
	var state DeliveryState
	if decodeBounded(encoded, MaximumStateJSONBytes, &state) != nil || state.TenantID != tenantID || state.ID != deliveryID || state.Revision != revision || storedTime(state.UpdatedAt) != updatedRaw || state.ValidateStored() != nil {
		return DeliveryState{}, ErrIntegrity
	}
	return state, nil
}

func (repository *SQLiteRepository) GetDelivery(ctx context.Context, tenantID, deliveryID string) (DeliveryState, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validTenantAndID(tenantID, deliveryID) { return DeliveryState{}, ErrInvalid }
	state, err := scanDelivery(repository.db.QueryRowContext(ctx, `SELECT revision, state_json, updated_at FROM notification_delivery_state_v1 WHERE tenant_id = ? AND delivery_id = ?`, tenantID, deliveryID), tenantID, deliveryID)
	if errors.Is(err, sql.ErrNoRows) { return DeliveryState{}, ErrNotFound }
	return state, err
}

func (repository *SQLiteRepository) ListDueDeliveries(ctx context.Context, tenantID string, request DeliveryPageRequest) (DeliveryPage, error) {
	cursorValid := request.After.ID == "" && request.After.NextAttemptAt.IsZero() || request.After.ID != "" && !request.After.NextAttemptAt.IsZero() && opaquePattern.MatchString(request.After.ID)
	if repository == nil || repository.db == nil || ctx == nil || !opaquePattern.MatchString(tenantID) || request.Before.IsZero() || request.Limit == 0 || request.Limit > MaximumPageSize || !cursorValid {
		return DeliveryPage{}, ErrInvalid
	}
	afterTime := storedTime(request.After.NextAttemptAt)
	rows, err := repository.db.QueryContext(ctx, `SELECT delivery_id, revision, state_json, updated_at FROM notification_delivery_state_v1
WHERE tenant_id = ? AND status IN ('queued','retry') AND next_attempt_at <= ?
AND (? = '' OR next_attempt_at > ? OR (next_attempt_at = ? AND delivery_id > ?))
ORDER BY next_attempt_at ASC, delivery_id ASC LIMIT ?`, tenantID, storedTime(request.Before), afterTime, afterTime, afterTime, request.After.ID, int(request.Limit)+1)
	if err != nil { return DeliveryPage{}, err }
	defer rows.Close()
	states := make([]DeliveryState, 0, request.Limit)
	for rows.Next() {
		var deliveryID string
		var revision uint64
		var encoded []byte
		var updatedRaw string
		if err = rows.Scan(&deliveryID, &revision, &encoded, &updatedRaw); err != nil { return DeliveryPage{}, err }
		if len(states) == int(request.Limit) {
			last := states[len(states)-1]
			return DeliveryPage{States: states, Next: DeliveryCursor{NextAttemptAt: last.NextAttemptAt, ID: last.ID}}, rows.Close()
		}
		var state DeliveryState
		if decodeBounded(encoded, MaximumStateJSONBytes, &state) != nil || state.TenantID != tenantID || state.ID != deliveryID || state.Revision != revision || storedTime(state.UpdatedAt) != updatedRaw || state.ValidateStored() != nil {
			return DeliveryPage{}, ErrIntegrity
		}
		states = append(states, state)
	}
	if err = rows.Err(); err != nil { return DeliveryPage{}, err }
	return DeliveryPage{States: states}, nil
}

func (repository *SQLiteRepository) UpsertDelivery(ctx context.Context, state DeliveryState, expectedRevision uint64) (DeliveryState, error) {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision >= uint64(math.MaxInt64) { return DeliveryState{}, ErrInvalid }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	state.Revision = expectedRevision + 1
	state.UpdatedAt = repository.now().UTC()
	if !state.NextAttemptAt.IsZero() { state.NextAttemptAt = state.NextAttemptAt.UTC() }
	if !state.DeliveredAt.IsZero() { state.DeliveredAt = state.DeliveredAt.UTC() }
	if state.ValidateStored() != nil { return DeliveryState{}, ErrInvalid }
	if expectedRevision != 0 {
		existing, loadErr := repository.GetDelivery(ctx, state.TenantID, state.ID)
		if errors.Is(loadErr, ErrNotFound) { return DeliveryState{}, ErrConflict }
		if loadErr != nil { return DeliveryState{}, loadErr }
		if existing.Revision != expectedRevision || !validDeliveryTransition(existing, state) { return DeliveryState{}, ErrConflict }
	}
	encoded, err := encodeBounded(state, MaximumStateJSONBytes)
	if err != nil { return DeliveryState{}, err }
	if expectedRevision == 0 {
		result, insertErr := repository.db.ExecContext(ctx, `INSERT INTO notification_delivery_state_v1
(tenant_id, delivery_id, rule_id, event_id, status, revision, next_attempt_at, state_json, updated_at)
SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM notification_delivery_state_v1 WHERE tenant_id = ?) < ?`,
			state.TenantID, state.ID, state.RuleID, state.EventID, state.Status, state.Revision, storedTime(state.NextAttemptAt), encoded, storedTime(state.UpdatedAt), state.TenantID, MaximumDeliveryStatesPerTenant)
		if insertErr != nil {
			if _, getErr := repository.GetDelivery(ctx, state.TenantID, state.ID); getErr == nil { return DeliveryState{}, ErrConflict }
			return DeliveryState{}, insertErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil { return DeliveryState{}, rowsErr }
		if rows == 0 {
			if _, getErr := repository.GetDelivery(ctx, state.TenantID, state.ID); getErr == nil { return DeliveryState{}, ErrConflict }
			return DeliveryState{}, ErrLimit
		}
		return state, nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE notification_delivery_state_v1 SET rule_id = ?, event_id = ?, status = ?, revision = ?, next_attempt_at = ?, state_json = ?, updated_at = ? WHERE tenant_id = ? AND delivery_id = ? AND revision = ?`,
		state.RuleID, state.EventID, state.Status, state.Revision, storedTime(state.NextAttemptAt), encoded, storedTime(state.UpdatedAt), state.TenantID, state.ID, expectedRevision)
	if err != nil { return DeliveryState{}, err }
	if err = changed(result); err != nil { return DeliveryState{}, err }
	return state, nil
}

func validDeliveryTransition(existing, next DeliveryState) bool {
	if existing.TenantID != next.TenantID || existing.ID != next.ID || existing.RuleID != next.RuleID || existing.EventID != next.EventID || existing.Status == DeliveryDelivered || existing.Status == DeliverySuppressed || existing.Status == DeliveryFailed || next.Attempts < existing.Attempts || next.Attempts > existing.Attempts+1 {
		return false
	}
	if next.Status == DeliveryQueued && existing.Status != DeliveryQueued { return false }
	return true
}

func (repository *SQLiteRepository) DeleteDelivery(ctx context.Context, tenantID, deliveryID string, expectedRevision uint64) error {
	if repository == nil || repository.db == nil || ctx == nil || !validTenantAndID(tenantID, deliveryID) || expectedRevision == 0 || expectedRevision > uint64(math.MaxInt64) { return ErrInvalid }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.db.ExecContext(ctx, `DELETE FROM notification_delivery_state_v1 WHERE tenant_id = ? AND delivery_id = ? AND revision = ?`, tenantID, deliveryID, expectedRevision)
	if err != nil { return err }
	return changed(result)
}

func validDedupKey(state DedupState) bool {
	state.Revision = 1
	state.LastEventID = "event"
	state.UpdatedAt = time.Unix(1, 0).UTC()
	state.LastDeliveredAt = state.UpdatedAt
	state.RateCount = 0
	state.RateWindowStarted = time.Time{}
	return state.ValidateStored() == nil
}

func scanDedup(row rowScanner, key DedupState) (DedupState, error) {
	var revision uint64
	var encoded []byte
	var updatedRaw string
	if err := row.Scan(&revision, &encoded, &updatedRaw); err != nil { return DedupState{}, err }
	var state DedupState
	if decodeBounded(encoded, MaximumStateJSONBytes, &state) != nil || state.TenantID != key.TenantID || state.RuleID != key.RuleID || state.Stage != key.Stage || state.DestinationKind != key.DestinationKind || state.DestinationID != key.DestinationID || state.DedupDigest != key.DedupDigest || state.Revision != revision || storedTime(state.UpdatedAt) != updatedRaw || state.ValidateStored() != nil {
		return DedupState{}, ErrIntegrity
	}
	return state, nil
}

func (repository *SQLiteRepository) GetDedup(ctx context.Context, key DedupState) (DedupState, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validDedupKey(key) { return DedupState{}, ErrInvalid }
	state, err := scanDedup(repository.db.QueryRowContext(ctx, `SELECT revision, state_json, updated_at FROM notification_dedup_state_v1
WHERE tenant_id = ? AND rule_id = ? AND stage = ? AND destination_kind = ? AND destination_id = ? AND dedup_digest = ?`,
		key.TenantID, key.RuleID, key.Stage, key.DestinationKind, key.DestinationID, key.DedupDigest), key)
	if errors.Is(err, sql.ErrNoRows) { return DedupState{}, ErrNotFound }
	return state, err
}

func (repository *SQLiteRepository) UpsertDedup(ctx context.Context, state DedupState, expectedRevision uint64) (DedupState, error) {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision >= uint64(math.MaxInt64) { return DedupState{}, ErrInvalid }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	state.Revision = expectedRevision + 1
	state.UpdatedAt = repository.now().UTC()
	if !state.LastDeliveredAt.IsZero() { state.LastDeliveredAt = state.LastDeliveredAt.UTC() }
	if !state.RateWindowStarted.IsZero() { state.RateWindowStarted = state.RateWindowStarted.UTC() }
	if state.ValidateStored() != nil { return DedupState{}, ErrInvalid }
	if expectedRevision != 0 {
		existing, loadErr := repository.GetDedup(ctx, state)
		if errors.Is(loadErr, ErrNotFound) { return DedupState{}, ErrConflict }
		if loadErr != nil { return DedupState{}, loadErr }
		if existing.Revision != expectedRevision || !validDedupTransition(existing, state) { return DedupState{}, ErrConflict }
	}
	encoded, err := encodeBounded(state, MaximumStateJSONBytes)
	if err != nil { return DedupState{}, err }
	if expectedRevision == 0 {
		result, insertErr := repository.db.ExecContext(ctx, `INSERT INTO notification_dedup_state_v1
(tenant_id, rule_id, stage, destination_kind, destination_id, dedup_digest, revision, last_delivered_at, rate_window_started, state_json, updated_at)
SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM notification_dedup_state_v1 WHERE tenant_id = ?) < ?`,
			state.TenantID, state.RuleID, state.Stage, state.DestinationKind, state.DestinationID, state.DedupDigest, state.Revision,
			storedTime(state.LastDeliveredAt), storedTime(state.RateWindowStarted), encoded, storedTime(state.UpdatedAt), state.TenantID, MaximumDedupStatesPerTenant)
		if insertErr != nil {
			if _, getErr := repository.GetDedup(ctx, state); getErr == nil { return DedupState{}, ErrConflict }
			return DedupState{}, insertErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil { return DedupState{}, rowsErr }
		if rows == 0 {
			if _, getErr := repository.GetDedup(ctx, state); getErr == nil { return DedupState{}, ErrConflict }
			return DedupState{}, ErrLimit
		}
		return state, nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE notification_dedup_state_v1 SET revision = ?, last_delivered_at = ?, rate_window_started = ?, state_json = ?, updated_at = ?
WHERE tenant_id = ? AND rule_id = ? AND stage = ? AND destination_kind = ? AND destination_id = ? AND dedup_digest = ? AND revision = ?`,
		state.Revision, storedTime(state.LastDeliveredAt), storedTime(state.RateWindowStarted), encoded, storedTime(state.UpdatedAt),
		state.TenantID, state.RuleID, state.Stage, state.DestinationKind, state.DestinationID, state.DedupDigest, expectedRevision)
	if err != nil { return DedupState{}, err }
	if err = changed(result); err != nil { return DedupState{}, err }
	return state, nil
}

func validDedupTransition(existing, next DedupState) bool {
	if existing.TenantID != next.TenantID || existing.RuleID != next.RuleID || existing.Stage != next.Stage || existing.DestinationKind != next.DestinationKind || existing.DestinationID != next.DestinationID || existing.DedupDigest != next.DedupDigest || next.LastDeliveredAt.Before(existing.LastDeliveredAt) {
		return false
	}
	if next.RateWindowStarted.Equal(existing.RateWindowStarted) {
		return next.RateCount >= existing.RateCount && next.RateCount <= existing.RateCount+1
	}
	if next.RateWindowStarted.IsZero() {
		return next.RateCount == 0 && (existing.RateWindowStarted.IsZero() || next.LastDeliveredAt.After(existing.LastDeliveredAt))
	}
	return next.RateCount == 1 && (existing.RateWindowStarted.IsZero() || next.RateWindowStarted.After(existing.RateWindowStarted))
}

func (repository *SQLiteRepository) DeleteDedup(ctx context.Context, key DedupState, expectedRevision uint64) error {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision == 0 || expectedRevision > uint64(math.MaxInt64) || !validDedupKey(key) { return ErrInvalid }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.db.ExecContext(ctx, `DELETE FROM notification_dedup_state_v1 WHERE tenant_id = ? AND rule_id = ? AND stage = ? AND destination_kind = ? AND destination_id = ? AND dedup_digest = ? AND revision = ?`,
		key.TenantID, key.RuleID, key.Stage, key.DestinationKind, key.DestinationID, key.DedupDigest, expectedRevision)
	if err != nil { return err }
	return changed(result)
}

var _ Repository = (*SQLiteRepository)(nil)
