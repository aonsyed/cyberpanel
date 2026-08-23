package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const MaxPageSize = 500

// Repository persists canonical rules, evaluation state, and an event outbox.
// Callers must supply a SQLite database handle.
type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &Repository{db: db}, nil
}

func (repository *Repository) Bootstrap(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS alert_rules (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			resource_kind TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			signal_kind TEXT NOT NULL,
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			generation INTEGER NOT NULL CHECK (generation > 0),
			rule_json BLOB NOT NULL,
			updated_unix_nano INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS alert_rules_scope_idx
			ON alert_rules (tenant_id, resource_kind, resource_id, signal_kind, id)`,
		`CREATE INDEX IF NOT EXISTS alert_rules_enabled_idx
			ON alert_rules (tenant_id, enabled, id)`,
		`CREATE TABLE IF NOT EXISTS alert_states (
			rule_id TEXT PRIMARY KEY,
			generation INTEGER NOT NULL CHECK (generation > 0),
			rule_generation INTEGER NOT NULL CHECK (rule_generation > 0),
			condition TEXT NOT NULL,
			active INTEGER NOT NULL CHECK (active IN (0, 1)),
			last_observed_unix_nano INTEGER NOT NULL,
			next_due_unix_nano INTEGER NOT NULL,
			state_json BLOB NOT NULL,
			FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS alert_states_due_idx
			ON alert_states (next_due_unix_nano, rule_id)`,
		`CREATE TABLE IF NOT EXISTS alert_events (
			id TEXT PRIMARY KEY,
			rule_id TEXT NOT NULL,
			event_kind TEXT NOT NULL,
			sample_digest TEXT NOT NULL,
			event_digest TEXT NOT NULL,
			event_json BLOB NOT NULL,
			created_unix_nano INTEGER NOT NULL,
			delivered_unix_nano INTEGER,
			FOREIGN KEY (rule_id) REFERENCES alert_rules(id),
			UNIQUE (rule_id, event_kind, sample_digest)
		)`,
		`CREATE INDEX IF NOT EXISTS alert_events_pending_idx
			ON alert_events (delivered_unix_nano, id)`,
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PutRule creates a rule when expectedGeneration is zero and otherwise applies
// a generation-checked replacement. Signal kind and scope are immutable.
func (repository *Repository) PutRule(ctx context.Context, rule Rule, expectedGeneration uint64) error {
	canonical, err := CanonicalRule(rule)
	if err != nil || expectedGeneration >= maxGeneration || canonical.Generation != expectedGeneration+1 {
		return ErrInvalid
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return err
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if expectedGeneration == 0 {
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO alert_rules
			(id, tenant_id, resource_kind, resource_id, signal_kind, enabled, generation, rule_json, updated_unix_nano)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, canonical.ID, canonical.Scope.TenantID,
			canonical.Scope.ResourceKind, canonical.Scope.ResourceID, canonical.Kind,
			boolInteger(canonical.Enabled), canonical.Generation, raw, canonical.UpdatedAt.UnixNano())
		if err != nil {
			return err
		}
		if !oneRow(result) {
			return ErrConflict
		}
		state := State{RuleID: canonical.ID, RuleGeneration: canonical.Generation, Generation: 1,
			Condition: ConditionUnknown, NextDueAt: canonical.UpdatedAt.Add(canonical.Window), UpdatedAt: canonical.UpdatedAt}
		if err := insertState(ctx, tx, state); err != nil {
			return err
		}
		return tx.Commit()
	}

	previousRule, err := loadRuleQuery(ctx, tx, canonical.ID)
	if err != nil {
		return err
	}
	if previousRule.Generation != expectedGeneration {
		return ErrConflict
	}
	if previousRule.Kind != canonical.Kind || previousRule.Scope != canonical.Scope || canonical.UpdatedAt.Before(previousRule.UpdatedAt) {
		return ErrInvalid
	}
	previousState, err := loadStateQuery(ctx, tx, canonical.ID)
	if err != nil {
		return err
	}
	if !canonical.CreatedAt.Equal(previousRule.CreatedAt) || canonical.UpdatedAt.Before(previousState.LastObservedAt) {
		return ErrInvalid
	}
	if previousState.Generation == maxGeneration {
		return ErrCapacity
	}
	result, err := tx.ExecContext(ctx, `UPDATE alert_rules SET tenant_id = ?, resource_kind = ?, resource_id = ?,
		signal_kind = ?, enabled = ?, generation = ?, rule_json = ?, updated_unix_nano = ?
		WHERE id = ? AND generation = ?`, canonical.Scope.TenantID, canonical.Scope.ResourceKind,
		canonical.Scope.ResourceID, canonical.Kind, boolInteger(canonical.Enabled), canonical.Generation,
		raw, canonical.UpdatedAt.UnixNano(), canonical.ID, expectedGeneration)
	if err != nil {
		return err
	}
	if !oneRow(result) {
		return ErrConflict
	}
	previousState.RuleGeneration = canonical.Generation
	previousState.Generation++
	previousState.Condition = ConditionUnknown
	previousState.ConsecutiveBad = 0
	previousState.ConsecutiveGood = 0
	previousState.LastStatus = ""
	previousState.LastValue = nil
	previousState.LastSampleDigest = ""
	previousState.NextDueAt = canonical.UpdatedAt.Add(canonical.Window)
	previousState.UpdatedAt = canonical.UpdatedAt
	if err := updateStateCAS(ctx, tx, previousState, previousState.Generation-1); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *Repository) LoadRule(ctx context.Context, id string) (Rule, error) {
	if !idPattern.MatchString(id) {
		return Rule{}, ErrInvalid
	}
	return loadRuleQuery(ctx, repository.db, id)
}

func (repository *Repository) LoadState(ctx context.Context, ruleID string) (State, error) {
	if !idPattern.MatchString(ruleID) {
		return State{}, ErrInvalid
	}
	return loadStateQuery(ctx, repository.db, ruleID)
}

type RulePage struct {
	Rules      []Rule
	NextCursor string
}

func (repository *Repository) ListRules(ctx context.Context, tenantID string, limit int, cursor string) (RulePage, error) {
	if !idPattern.MatchString(tenantID) || !validPage(limit, cursor) {
		return RulePage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT rule_json FROM alert_rules
		WHERE tenant_id = ? AND id > ? ORDER BY id LIMIT ?`, tenantID, cursor, limit+1)
	if err != nil {
		return RulePage{}, err
	}
	defer rows.Close()
	page := RulePage{Rules: make([]Rule, 0, limit)}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return RulePage{}, err
		}
		rule, err := decodeRule(raw)
		if err != nil {
			return RulePage{}, err
		}
		if rule.Scope.TenantID != tenantID {
			return RulePage{}, ErrIntegrity
		}
		if len(page.Rules) == limit {
			page.NextCursor = page.Rules[len(page.Rules)-1].ID
			break
		}
		page.Rules = append(page.Rules, rule)
	}
	if err := rows.Err(); err != nil {
		return RulePage{}, err
	}
	return page, nil
}

type DueItem struct {
	Rule  Rule
	State State
}

type DuePage struct {
	Items      []DueItem
	NextCursor string
}

func (repository *Repository) ListDue(ctx context.Context, tenantID string, at time.Time, limit int, cursor string) (DuePage, error) {
	if !idPattern.MatchString(tenantID) || !validTimestamp(at) || !validPage(limit, cursor) {
		return DuePage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT rules.rule_json, states.state_json
		FROM alert_rules AS rules JOIN alert_states AS states ON states.rule_id = rules.id
		WHERE rules.tenant_id = ? AND rules.enabled = 1 AND rules.id > ?
		AND states.next_due_unix_nano <= ? ORDER BY rules.id LIMIT ?`, tenantID, cursor, at.UnixNano(), limit+1)
	if err != nil {
		return DuePage{}, err
	}
	defer rows.Close()
	page := DuePage{Items: make([]DueItem, 0, limit)}
	for rows.Next() {
		var ruleRaw, stateRaw []byte
		if err := rows.Scan(&ruleRaw, &stateRaw); err != nil {
			return DuePage{}, err
		}
		rule, err := decodeRule(ruleRaw)
		if err != nil {
			return DuePage{}, err
		}
		state, err := decodeState(stateRaw)
		if err != nil || rule.Scope.TenantID != tenantID || state.RuleID != rule.ID || state.RuleGeneration != rule.Generation {
			return DuePage{}, ErrIntegrity
		}
		if len(page.Items) == limit {
			page.NextCursor = page.Items[len(page.Items)-1].Rule.ID
			break
		}
		page.Items = append(page.Items, DueItem{Rule: rule, State: state})
	}
	if err := rows.Err(); err != nil {
		return DuePage{}, err
	}
	return page, nil
}

func (repository *Repository) matchRules(ctx context.Context, sample Sample, limit int) ([]Rule, error) {
	if limit < 1 || limit > MaxPageSize {
		return nil, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT rule_json FROM alert_rules
		WHERE tenant_id = ? AND resource_kind = ? AND resource_id = ? AND signal_kind = ? AND enabled = 1
		ORDER BY id LIMIT ?`, sample.Scope.TenantID, sample.Scope.ResourceKind, sample.Scope.ResourceID,
		sample.Kind, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := make([]Rule, 0, limit)
	for rows.Next() {
		if len(rules) == limit {
			return nil, ErrCapacity
		}
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		rule, err := decodeRule(raw)
		if err != nil {
			return nil, err
		}
		if rule.Kind != sample.Kind || rule.Scope != sample.Scope {
			return nil, ErrIntegrity
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

type EventPage struct {
	Events     []AlertEvent
	NextCursor string
}

func (repository *Repository) ListPendingEvents(ctx context.Context, limit int, cursor string) (EventPage, error) {
	if !validPage(limit, cursor) {
		return EventPage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT event_json, event_digest FROM alert_events
		WHERE delivered_unix_nano IS NULL AND id > ? ORDER BY id LIMIT ?`, cursor, limit+1)
	if err != nil {
		return EventPage{}, err
	}
	defer rows.Close()
	page := EventPage{Events: make([]AlertEvent, 0, limit)}
	for rows.Next() {
		var raw []byte
		var storedDigest string
		if err := rows.Scan(&raw, &storedDigest); err != nil {
			return EventPage{}, err
		}
		event, err := decodeEvent(raw)
		if err != nil {
			return EventPage{}, err
		}
		if event.Digest != storedDigest {
			return EventPage{}, ErrIntegrity
		}
		if len(page.Events) == limit {
			page.NextCursor = page.Events[len(page.Events)-1].ID
			break
		}
		page.Events = append(page.Events, event)
	}
	if err := rows.Err(); err != nil {
		return EventPage{}, err
	}
	return page, nil
}

func (repository *Repository) MarkEventDelivered(ctx context.Context, eventID, digest string, at time.Time) error {
	if !idPattern.MatchString(eventID) || !validDigest(digest) || !validTimestamp(at) {
		return ErrInvalid
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE alert_events SET delivered_unix_nano = ?
		WHERE id = ? AND event_digest = ? AND delivered_unix_nano IS NULL`, at.UnixNano(), eventID, digest)
	if err != nil {
		return err
	}
	if oneRow(result) {
		return nil
	}
	var storedDigest string
	var delivered sql.NullInt64
	err = repository.db.QueryRowContext(ctx, `SELECT event_digest, delivered_unix_nano FROM alert_events WHERE id = ?`, eventID).Scan(&storedDigest, &delivered)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if storedDigest != digest {
		return ErrIntegrity
	}
	if delivered.Valid {
		return nil
	}
	return ErrConflict
}

func (repository *Repository) advance(ctx context.Context, ruleID string, sample Sample, now time.Time) (*AlertEvent, bool, error) {
	if !idPattern.MatchString(ruleID) || !validTimestamp(now) {
		return nil, false, ErrInvalid
	}
	canonical, err := CanonicalSample(sample)
	if err != nil {
		return nil, false, err
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	rule, err := loadRuleQuery(ctx, tx, ruleID)
	if err != nil {
		return nil, false, err
	}
	if !rule.Enabled {
		return nil, false, ErrConflict
	}
	if rule.Kind != canonical.Kind || rule.Scope != canonical.Scope {
		return nil, false, ErrScope
	}
	state, err := loadStateQuery(ctx, tx, ruleID)
	if err != nil {
		return nil, false, err
	}
	if state.RuleGeneration != rule.Generation {
		return nil, false, ErrIntegrity
	}
	if !state.LastObservedAt.IsZero() && !canonical.ObservedAt.After(state.LastObservedAt) {
		if canonical.ObservedAt.Equal(state.LastObservedAt) && canonical.Digest == state.LastSampleDigest {
			event, pending, err := pendingEventForSample(ctx, tx, ruleID, canonical.Digest)
			if err != nil {
				return nil, false, err
			}
			if err := tx.Commit(); err != nil {
				return nil, false, err
			}
			return event, pending, nil
		}
		return nil, false, ErrStale
	}
	if canonical.ObservedAt.After(now) || canonical.ObservedAt.Add(rule.Window).Before(now) {
		return nil, false, ErrStale
	}
	next, event, err := advanceState(rule, state, canonical, now)
	if err != nil {
		return nil, false, err
	}
	if err := updateStateCAS(ctx, tx, next, state.Generation); err != nil {
		return nil, false, err
	}
	pending := false
	if event != nil {
		raw, err := json.Marshal(event)
		if err != nil {
			return nil, false, err
		}
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO alert_events
			(id, rule_id, event_kind, sample_digest, event_digest, event_json, created_unix_nano)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, event.ID, event.RuleID, event.Kind, event.SampleDigest,
			event.Digest, raw, event.OccurredAt.UnixNano())
		if err != nil {
			return nil, false, err
		}
		if oneRow(result) {
			pending = true
		} else {
			stored, storedPending, err := pendingEventByID(ctx, tx, event.ID)
			if err != nil {
				return nil, false, err
			}
			if stored.Digest != event.Digest {
				return nil, false, ErrIntegrity
			}
			event = &stored
			pending = storedPending
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return event, pending, nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadRuleQuery(ctx context.Context, query queryer, id string) (Rule, error) {
	var raw []byte
	var generation uint64
	if err := query.QueryRowContext(ctx, `SELECT rule_json, generation FROM alert_rules WHERE id = ?`, id).Scan(&raw, &generation); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Rule{}, ErrNotFound
		}
		return Rule{}, err
	}
	rule, err := decodeRule(raw)
	if err != nil {
		return Rule{}, err
	}
	if rule.ID != id || rule.Generation != generation {
		return Rule{}, ErrIntegrity
	}
	return rule, nil
}

func loadStateQuery(ctx context.Context, query queryer, ruleID string) (State, error) {
	var raw []byte
	var generation, ruleGeneration uint64
	if err := query.QueryRowContext(ctx, `SELECT state_json, generation, rule_generation FROM alert_states WHERE rule_id = ?`, ruleID).Scan(&raw, &generation, &ruleGeneration); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return State{}, ErrNotFound
		}
		return State{}, err
	}
	state, err := decodeState(raw)
	if err != nil {
		return State{}, err
	}
	if state.RuleID != ruleID || state.Generation != generation || state.RuleGeneration != ruleGeneration {
		return State{}, ErrIntegrity
	}
	return state, nil
}

func decodeRule(raw []byte) (Rule, error) {
	var rule Rule
	if err := json.Unmarshal(raw, &rule); err != nil {
		return Rule{}, ErrIntegrity
	}
	if err := rule.Validate(); err != nil {
		return Rule{}, ErrIntegrity
	}
	return rule, nil
}

func decodeState(raw []byte) (State, error) {
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return State{}, ErrIntegrity
	}
	if err := state.Validate(); err != nil {
		return State{}, ErrIntegrity
	}
	return state, nil
}

func decodeEvent(raw []byte) (AlertEvent, error) {
	var event AlertEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return AlertEvent{}, ErrIntegrity
	}
	digest := event.Digest
	event.Digest = ""
	canonical, err := json.Marshal(event)
	if err != nil {
		return AlertEvent{}, ErrIntegrity
	}
	sum := eventDigest(canonical)
	event.Digest = digest
	if sum != digest || event.Validate() != nil {
		return AlertEvent{}, ErrIntegrity
	}
	return event, nil
}

func insertState(ctx context.Context, tx *sql.Tx, state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO alert_states
		(rule_id, generation, rule_generation, condition, active, last_observed_unix_nano, next_due_unix_nano, state_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, state.RuleID, state.Generation, state.RuleGeneration,
		state.Condition, boolInteger(state.Active), unixNanoOrZero(state.LastObservedAt), state.NextDueAt.UnixNano(), raw)
	return err
}

func updateStateCAS(ctx context.Context, tx *sql.Tx, state State, expectedGeneration uint64) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE alert_states SET generation = ?, rule_generation = ?,
		condition = ?, active = ?, last_observed_unix_nano = ?, next_due_unix_nano = ?, state_json = ?
		WHERE rule_id = ? AND generation = ?`, state.Generation, state.RuleGeneration, state.Condition,
		boolInteger(state.Active), unixNanoOrZero(state.LastObservedAt), state.NextDueAt.UnixNano(), raw,
		state.RuleID, expectedGeneration)
	if err != nil {
		return err
	}
	if !oneRow(result) {
		return ErrConflict
	}
	return nil
}

func pendingEventForSample(ctx context.Context, tx *sql.Tx, ruleID, sampleDigest string) (*AlertEvent, bool, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM alert_events
		WHERE rule_id = ? AND sample_digest = ? ORDER BY id LIMIT 1`, ruleID, sampleDigest).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	event, pending, err := pendingEventByID(ctx, tx, id)
	if err != nil {
		return nil, false, err
	}
	if event.RuleID != ruleID || event.SampleDigest != sampleDigest {
		return nil, false, ErrIntegrity
	}
	return &event, pending, nil
}

func pendingEventByID(ctx context.Context, tx *sql.Tx, id string) (AlertEvent, bool, error) {
	var raw []byte
	var storedDigest string
	var delivered sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT event_json, event_digest, delivered_unix_nano FROM alert_events WHERE id = ?`, id).Scan(&raw, &storedDigest, &delivered); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AlertEvent{}, false, ErrIntegrity
		}
		return AlertEvent{}, false, err
	}
	event, err := decodeEvent(raw)
	if err == nil && (event.ID != id || event.Digest != storedDigest) {
		return AlertEvent{}, false, ErrIntegrity
	}
	return event, !delivered.Valid, err
}

func eventDigest(raw []byte) string {
	// Kept next to persisted-event verification so repository reads do not
	// silently trust a mutable JSON body.
	return digestBytes(raw)
}

func validPage(limit int, cursor string) bool {
	return limit > 0 && limit <= MaxPageSize && (cursor == "" || idPattern.MatchString(cursor))
}

func boolInteger(value bool) int {
	if value {
		return 1
	}
	return 0
}

func unixNanoOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixNano()
}

func oneRow(result sql.Result) bool {
	count, err := result.RowsAffected()
	return err == nil && count == 1
}
