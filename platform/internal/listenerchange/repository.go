package listenerchange

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &SQLiteRepository{db: db}, nil
}

func (repository *SQLiteRepository) Bootstrap(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS listenerchange_current (
			tenant_id TEXT NOT NULL, node_id TEXT NOT NULL, revision INTEGER NOT NULL,
			state_json BLOB NOT NULL, state_digest TEXT NOT NULL, observation_valid INTEGER NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (tenant_id, node_id), CHECK (revision > 0)
		)`,
		`CREATE TABLE IF NOT EXISTS listenerchange_plans (
			plan_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, node_id TEXT NOT NULL,
			before_revision INTEGER NOT NULL, plan_digest TEXT NOT NULL UNIQUE,
			plan_json BLOB NOT NULL, created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS listenerchange_executions (
			plan_id TEXT PRIMARY KEY REFERENCES listenerchange_plans(plan_id),
			revision INTEGER NOT NULL, state TEXT NOT NULL, attempt INTEGER NOT NULL,
			fence_token TEXT NOT NULL, lease_holder TEXT NOT NULL, lease_until TEXT NOT NULL,
			execution_json BLOB NOT NULL, updated_at TEXT NOT NULL,
			CHECK (revision > 0), CHECK (attempt >= 0)
		)`,
		`CREATE TABLE IF NOT EXISTS listenerchange_active_scopes (
			tenant_id TEXT NOT NULL, node_id TEXT NOT NULL, plan_id TEXT NOT NULL UNIQUE
				REFERENCES listenerchange_plans(plan_id),
			PRIMARY KEY (tenant_id, node_id)
		)`,
		`CREATE TABLE IF NOT EXISTS listenerchange_receipts (
			receipt_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES listenerchange_plans(plan_id),
			idempotency_key TEXT NOT NULL, phase TEXT NOT NULL, outcome TEXT NOT NULL,
			receipt_digest TEXT NOT NULL, receipt_json BLOB NOT NULL, observed_at TEXT NOT NULL,
			UNIQUE (plan_id, idempotency_key)
		)`,
		`CREATE INDEX IF NOT EXISTS listenerchange_receipts_plan_time
			ON listenerchange_receipts(plan_id, observed_at, receipt_id)`,
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("bootstrap listener change repository: %w", err)
		}
	}
	return tx.Commit()
}

func (repository *SQLiteRepository) BootstrapCurrent(ctx context.Context, current CurrentState, now time.Time) error {
	if current.Validate(now) != nil {
		return ErrStale
	}
	encoded, err := json.Marshal(current)
	if err != nil {
		return err
	}
	result, err := repository.db.ExecContext(ctx, `INSERT OR IGNORE INTO listenerchange_current
		(tenant_id, node_id, revision, state_json, state_digest, observation_valid, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?)`,
		current.Scope.TenantID, current.Scope.NodeID, int64(current.Revision), encoded, current.Digest, formatTime(current.ObservedAt))
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

func (repository *SQLiteRepository) ObserveCurrent(ctx context.Context, expectedRevision uint64, current CurrentState, now time.Time) error {
	if expectedRevision == 0 || current.Revision != expectedRevision+1 || current.Validate(now) != nil {
		return ErrStale
	}
	encoded, err := json.Marshal(current)
	if err != nil {
		return err
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE listenerchange_current SET revision = ?, state_json = ?, state_digest = ?, observation_valid = 1, updated_at = ?
		WHERE tenant_id = ? AND node_id = ? AND revision = ? AND NOT EXISTS
		(SELECT 1 FROM listenerchange_active_scopes WHERE tenant_id = ? AND node_id = ?)`,
		int64(current.Revision), encoded, current.Digest, formatTime(current.ObservedAt), current.Scope.TenantID, current.Scope.NodeID,
		int64(expectedRevision), current.Scope.TenantID, current.Scope.NodeID)
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

func (repository *SQLiteRepository) Current(ctx context.Context, scope Scope, now time.Time) (CurrentState, error) {
	if scope.Validate() != nil || !validUTC(now) {
		return CurrentState{}, ErrInvalid
	}
	var encoded []byte
	var observationValid int
	err := repository.db.QueryRowContext(ctx, `SELECT state_json, observation_valid FROM listenerchange_current WHERE tenant_id = ? AND node_id = ?`, scope.TenantID, scope.NodeID).Scan(&encoded, &observationValid)
	if errors.Is(err, sql.ErrNoRows) {
		return CurrentState{}, ErrNotFound
	}
	if err != nil {
		return CurrentState{}, err
	}
	if observationValid != 1 {
		return CurrentState{}, ErrStale
	}
	var current CurrentState
	if json.Unmarshal(encoded, &current) != nil || current.Scope != scope || current.Validate(now) != nil {
		return CurrentState{}, ErrStale
	}
	return current, nil
}

func (repository *SQLiteRepository) CreatePlan(ctx context.Context, plan ChangePlan) (Execution, error) {
	if plan.ValidateAt(plan.CreatedAt) != nil {
		return Execution{}, ErrInvalid
	}
	encodedPlan, err := json.Marshal(plan)
	if err != nil {
		return Execution{}, err
	}
	execution := Execution{
		PlanID: plan.ID, Scope: plan.Scope, State: StatePreviewed, Revision: 1,
		Boot: plan.Boot, RollbackDeadline: plan.Rollback.Deadline,
		ObservedConfigurationGeneration: plan.BeforeConfigurationGeneration,
		ObservedFirewallGeneration: plan.BeforeFirewallGeneration, UpdatedAt: plan.CreatedAt,
	}
	encodedExecution, err := json.Marshal(execution)
	if err != nil {
		return Execution{}, err
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Execution{}, err
	}
	defer tx.Rollback()
	var revision int64
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT revision, state_digest FROM listenerchange_current WHERE tenant_id = ? AND node_id = ? AND observation_valid = 1`, plan.Scope.TenantID, plan.Scope.NodeID).Scan(&revision, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return Execution{}, ErrNotFound
	}
	if err != nil {
		return Execution{}, err
	}
	if uint64(revision) != plan.BeforeRevision || digest != plan.BeforeDigest {
		return Execution{}, ErrStale
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO listenerchange_plans
		(plan_id, tenant_id, node_id, before_revision, plan_digest, plan_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		plan.ID, plan.Scope.TenantID, plan.Scope.NodeID, int64(plan.BeforeRevision), plan.Digest, encodedPlan, formatTime(plan.CreatedAt)); err != nil {
		return Execution{}, classifyConstraint(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO listenerchange_active_scopes (tenant_id, node_id, plan_id) VALUES (?, ?, ?)`, plan.Scope.TenantID, plan.Scope.NodeID, plan.ID); err != nil {
		return Execution{}, classifyConstraint(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO listenerchange_executions
		(plan_id, revision, state, attempt, fence_token, lease_holder, lease_until, execution_json, updated_at)
		VALUES (?, ?, ?, 0, '', '', '', ?, ?)`, plan.ID, int64(execution.Revision), execution.State, encodedExecution, formatTime(execution.UpdatedAt)); err != nil {
		return Execution{}, classifyConstraint(err)
	}
	if err = tx.Commit(); err != nil {
		return Execution{}, err
	}
	return execution, nil
}

func (repository *SQLiteRepository) Plan(ctx context.Context, planID PlanID) (ChangePlan, error) {
	if !validID(string(planID)) {
		return ChangePlan{}, ErrInvalid
	}
	var encoded []byte
	err := repository.db.QueryRowContext(ctx, `SELECT plan_json FROM listenerchange_plans WHERE plan_id = ?`, planID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ChangePlan{}, ErrNotFound
	}
	if err != nil {
		return ChangePlan{}, err
	}
	return decodePlan(encoded, planID)
}

func (repository *SQLiteRepository) Execution(ctx context.Context, planID PlanID) (Execution, error) {
	plan, err := repository.Plan(ctx, planID)
	if err != nil {
		return Execution{}, err
	}
	var encoded []byte
	err = repository.db.QueryRowContext(ctx, `SELECT execution_json FROM listenerchange_executions WHERE plan_id = ?`, planID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return Execution{}, ErrNotFound
	}
	if err != nil {
		return Execution{}, err
	}
	return decodeExecution(encoded, plan)
}

func (repository *SQLiteRepository) Receipts(ctx context.Context, planID PlanID, limit int) ([]OperationReceipt, error) {
	plan, err := repository.Plan(ctx, planID)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > MaximumStatusReceipts {
		return nil, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT receipt_json FROM listenerchange_receipts WHERE plan_id = ? ORDER BY observed_at DESC, receipt_id DESC LIMIT ?`, planID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]OperationReceipt, 0, limit)
	for rows.Next() {
		var encoded []byte
		var receipt OperationReceipt
		if rows.Scan(&encoded) != nil || json.Unmarshal(encoded, &receipt) != nil || receipt.Validate(plan) != nil {
			return nil, ErrStale
		}
		values = append(values, receipt)
	}
	return values, rows.Err()
}

func (repository *SQLiteRepository) Claim(ctx context.Context, planID PlanID, worker string, boot BootIdentity, now time.Time, lease time.Duration) (ChangePlan, Execution, error) {
	if !validID(string(planID)) || !validID(worker) || boot.Validate(now) != nil || lease <= 0 || lease > MaximumWorkLease {
		return ChangePlan{}, Execution{}, ErrInvalid
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return ChangePlan{}, Execution{}, err
	}
	defer tx.Rollback()
	plan, execution, err := loadForUpdate(ctx, tx, planID)
	if err != nil {
		return ChangePlan{}, Execution{}, err
	}
	if execution.State.terminal() {
		return ChangePlan{}, Execution{}, ErrConflict
	}
	if boot.MachineID != plan.Boot.MachineID {
		execution.State, execution.FailureCode, execution.UpdatedAt = StateUncertain, "machine_identity_changed", now
		execution.Boot = boot
		execution.Attempt++
		execution.Revision++
		execution.FenceToken, execution.LeaseHolder, execution.LeaseUntil = "", "", time.Time{}
		if err := storeExecution(ctx, tx, execution, execution.Revision-1, ""); err != nil {
			return ChangePlan{}, Execution{}, err
		}
		if err := tx.Commit(); err != nil {
			return ChangePlan{}, Execution{}, err
		}
		return plan, execution, ErrUncertain
	}
	if !execution.LeaseUntil.IsZero() && execution.LeaseUntil.After(now) {
		return ChangePlan{}, Execution{}, ErrConflict
	}
	if execution.Boot.BootID != boot.BootID && execution.State != StateRollingBack {
		execution.State = StateRollingBack
		execution.FailureCode = "reboot_requires_reconciliation"
		execution.ConfirmedAdministrative = nil
	}
	if !now.Before(plan.Rollback.Deadline) && execution.State != StateRollingBack {
		execution.State = StateRollingBack
		execution.FailureCode = "rollback_deadline_elapsed"
	}
	fence, err := randomID("fence-")
	if err != nil {
		return ChangePlan{}, Execution{}, err
	}
	expectedRevision := execution.Revision
	execution.Revision++
	execution.Attempt++
	execution.FenceToken, execution.LeaseHolder, execution.LeaseUntil = fence, worker, now.Add(lease)
	execution.Boot, execution.UpdatedAt = boot, now
	if err := storeExecution(ctx, tx, execution, expectedRevision, ""); err != nil {
		return ChangePlan{}, Execution{}, err
	}
	if err := tx.Commit(); err != nil {
		return ChangePlan{}, Execution{}, err
	}
	return plan, execution, nil
}

func (repository *SQLiteRepository) SaveProgress(ctx context.Context, plan ChangePlan, claimed, next Execution, receipt OperationReceipt, now time.Time) (Execution, error) {
	if plan.ValidateAt(plan.CreatedAt) != nil || claimed.PlanID != plan.ID || next.PlanID != plan.ID || claimed.FenceToken == "" || receipt.Validate(plan) != nil || receipt.FenceToken != claimed.FenceToken || receipt.Attempt != claimed.Attempt || !allowedTransition(claimed.State, next.State) || !validUTC(now) {
		return Execution{}, ErrInvalid
	}
	next.Revision, next.Attempt = claimed.Revision+1, claimed.Attempt
	next.FenceToken, next.LeaseHolder, next.LeaseUntil = "", "", time.Time{}
	next.UpdatedAt = now
	if next.Validate(plan) != nil {
		return Execution{}, ErrInvalid
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Execution{}, err
	}
	defer tx.Rollback()
	inserted, err := insertReceipt(ctx, tx, plan, receipt)
	if err != nil {
		return Execution{}, err
	}
	if !inserted {
		existing, loadErr := loadExecution(ctx, tx, plan)
		if loadErr != nil {
			return Execution{}, loadErr
		}
		return existing, tx.Commit()
	}
	if err := storeExecution(ctx, tx, next, claimed.Revision, claimed.FenceToken); err != nil {
		return Execution{}, err
	}
	if err := tx.Commit(); err != nil {
		return Execution{}, err
	}
	return next, nil
}

func (repository *SQLiteRepository) ChangeState(ctx context.Context, plan ChangePlan, claimed Execution, state ExecutionState, failureCode string, now time.Time) (Execution, error) {
	if claimed.PlanID != plan.ID || claimed.FenceToken == "" || !allowedTransition(claimed.State, state) || !validUTC(now) || failureCode != "" && !validCode(failureCode) {
		return Execution{}, ErrInvalid
	}
	next := claimed
	next.State, next.FailureCode, next.Revision, next.UpdatedAt = state, failureCode, claimed.Revision+1, now
	next.FenceToken, next.LeaseHolder, next.LeaseUntil = "", "", time.Time{}
	if next.Validate(plan) != nil {
		return Execution{}, ErrInvalid
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Execution{}, err
	}
	defer tx.Rollback()
	if err := storeExecution(ctx, tx, next, claimed.Revision, claimed.FenceToken); err != nil {
		return Execution{}, err
	}
	if state.releasesScope() {
		if _, err := tx.ExecContext(ctx, `DELETE FROM listenerchange_active_scopes WHERE tenant_id = ? AND node_id = ? AND plan_id = ?`, plan.Scope.TenantID, plan.Scope.NodeID, plan.ID); err != nil {
			return Execution{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Execution{}, err
	}
	return next, nil
}

func (repository *SQLiteRepository) Commit(ctx context.Context, plan ChangePlan, claimed Execution, current CurrentState, receipt OperationReceipt, now time.Time) (Execution, error) {
	if claimed.State != StateOldDrained || !claimed.OldDrained || !claimed.OldFirewallClosed || !claimed.RollbackFinalized || claimed.ObservedConfigurationGeneration != plan.AfterConfigurationGeneration || claimed.ObservedFirewallGeneration != plan.AfterFirewallGeneration || current.Scope != plan.Scope || current.Revision != plan.BeforeRevision+1 || current.ConfigurationGeneration != plan.AfterConfigurationGeneration || current.FirewallGeneration != plan.AfterFirewallGeneration || !slicesEqualListeners(current.Listeners, plan.Target) || current.PanelOrigin != plan.TargetOrigin || current.Certificate.Digest != plan.TargetCertificate.Digest || current.Validate(now) != nil || receipt.Validate(plan) != nil || receipt.Phase != PhaseCommit || receipt.Outcome != OutcomeSucceeded || receipt.FenceToken != claimed.FenceToken {
		return Execution{}, ErrIncomplete
	}
	encodedCurrent, err := json.Marshal(current)
	if err != nil {
		return Execution{}, err
	}
	next := claimed
	next.State, next.Revision, next.UpdatedAt = StateCommitted, claimed.Revision+1, now
	next.FenceToken, next.LeaseHolder, next.LeaseUntil = "", "", time.Time{}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Execution{}, err
	}
	defer tx.Rollback()
	inserted, err := insertReceipt(ctx, tx, plan, receipt)
	if err != nil || !inserted {
		if err != nil {
			return Execution{}, err
		}
		return Execution{}, ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE listenerchange_current SET revision = ?, state_json = ?, state_digest = ?, observation_valid = 1, updated_at = ? WHERE tenant_id = ? AND node_id = ? AND revision = ? AND state_digest = ?`,
		int64(current.Revision), encodedCurrent, current.Digest, formatTime(current.ObservedAt), plan.Scope.TenantID, plan.Scope.NodeID, int64(plan.BeforeRevision), plan.BeforeDigest)
	if err != nil {
		return Execution{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return Execution{}, ErrStale
	}
	if err := storeExecution(ctx, tx, next, claimed.Revision, claimed.FenceToken); err != nil {
		return Execution{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM listenerchange_active_scopes WHERE tenant_id = ? AND node_id = ? AND plan_id = ?`, plan.Scope.TenantID, plan.Scope.NodeID, plan.ID); err != nil {
		return Execution{}, err
	}
	if err := tx.Commit(); err != nil {
		return Execution{}, err
	}
	return next, nil
}

func (repository *SQLiteRepository) FinishRollback(ctx context.Context, plan ChangePlan, claimed Execution, receipt OperationReceipt, now time.Time) (Execution, error) {
	if claimed.State != StateRollingBack || claimed.PortsReserved || claimed.ConfigurationStaged || claimed.FirewallOpened || claimed.RollbackArmed || claimed.ShadowActive || claimed.OldDrained || claimed.OldFirewallClosed || receipt.Validate(plan) != nil || receipt.Phase != PhaseRollbackComplete || receipt.Outcome != OutcomeSucceeded || receipt.FenceToken != claimed.FenceToken {
		return Execution{}, ErrIncomplete
	}
	next := claimed
	next.State, next.Revision, next.UpdatedAt = StateRolledBack, claimed.Revision+1, now
	next.FenceToken, next.LeaseHolder, next.LeaseUntil = "", "", time.Time{}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Execution{}, err
	}
	defer tx.Rollback()
	inserted, err := insertReceipt(ctx, tx, plan, receipt)
	if err != nil || !inserted {
		if err != nil {
			return Execution{}, err
		}
		return Execution{}, ErrConflict
	}
	if err := storeExecution(ctx, tx, next, claimed.Revision, claimed.FenceToken); err != nil {
		return Execution{}, err
	}
	if claimed.ObservedConfigurationGeneration != plan.BeforeConfigurationGeneration || claimed.ObservedFirewallGeneration != plan.BeforeFirewallGeneration {
		if _, err := tx.ExecContext(ctx, `UPDATE listenerchange_current SET observation_valid = 0 WHERE tenant_id = ? AND node_id = ? AND revision = ?`, plan.Scope.TenantID, plan.Scope.NodeID, int64(plan.BeforeRevision)); err != nil {
			return Execution{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM listenerchange_active_scopes WHERE tenant_id = ? AND node_id = ? AND plan_id = ?`, plan.Scope.TenantID, plan.Scope.NodeID, plan.ID); err != nil {
		return Execution{}, err
	}
	if err := tx.Commit(); err != nil {
		return Execution{}, err
	}
	return next, nil
}

func decodePlan(encoded []byte, expected PlanID) (ChangePlan, error) {
	var plan ChangePlan
	if json.Unmarshal(encoded, &plan) != nil || plan.ID != expected || plan.ValidateAt(plan.CreatedAt) != nil {
		return ChangePlan{}, ErrStale
	}
	return plan, nil
}

func decodeExecution(encoded []byte, plan ChangePlan) (Execution, error) {
	var execution Execution
	if json.Unmarshal(encoded, &execution) != nil || execution.Validate(plan) != nil {
		return Execution{}, ErrStale
	}
	return execution, nil
}

func loadForUpdate(ctx context.Context, tx *sql.Tx, planID PlanID) (ChangePlan, Execution, error) {
	var encodedPlan, encodedExecution []byte
	err := tx.QueryRowContext(ctx, `SELECT p.plan_json, e.execution_json FROM listenerchange_plans p JOIN listenerchange_executions e ON e.plan_id = p.plan_id WHERE p.plan_id = ?`, planID).Scan(&encodedPlan, &encodedExecution)
	if errors.Is(err, sql.ErrNoRows) {
		return ChangePlan{}, Execution{}, ErrNotFound
	}
	if err != nil {
		return ChangePlan{}, Execution{}, err
	}
	plan, err := decodePlan(encodedPlan, planID)
	if err != nil {
		return ChangePlan{}, Execution{}, err
	}
	execution, err := decodeExecution(encodedExecution, plan)
	return plan, execution, err
}

func loadExecution(ctx context.Context, tx *sql.Tx, plan ChangePlan) (Execution, error) {
	var encoded []byte
	if err := tx.QueryRowContext(ctx, `SELECT execution_json FROM listenerchange_executions WHERE plan_id = ?`, plan.ID).Scan(&encoded); err != nil {
		return Execution{}, err
	}
	return decodeExecution(encoded, plan)
}

func storeExecution(ctx context.Context, tx *sql.Tx, execution Execution, expectedRevision uint64, expectedFence string) error {
	encoded, err := json.Marshal(execution)
	if err != nil {
		return err
	}
	query := `UPDATE listenerchange_executions SET revision = ?, state = ?, attempt = ?, fence_token = ?, lease_holder = ?, lease_until = ?, execution_json = ?, updated_at = ? WHERE plan_id = ? AND revision = ?`
	arguments := []any{int64(execution.Revision), execution.State, int64(execution.Attempt), execution.FenceToken, execution.LeaseHolder, formatOptionalTime(execution.LeaseUntil), encoded, formatTime(execution.UpdatedAt), execution.PlanID, int64(expectedRevision)}
	if expectedFence != "" {
		query += ` AND fence_token = ? AND lease_until >= ?`
		arguments = append(arguments, expectedFence, formatTime(execution.UpdatedAt))
	}
	result, err := tx.ExecContext(ctx, query, arguments...)
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

func insertReceipt(ctx context.Context, tx *sql.Tx, plan ChangePlan, receipt OperationReceipt) (bool, error) {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO listenerchange_receipts
		(receipt_id, plan_id, idempotency_key, phase, outcome, receipt_digest, receipt_json, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, receipt.ID, receipt.PlanID, receipt.IdempotencyKey, receipt.Phase, receipt.Outcome, receipt.Digest, encoded, formatTime(receipt.ObservedAt))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 1 {
		return true, nil
	}
	var digest string
	if err := tx.QueryRowContext(ctx, `SELECT receipt_digest FROM listenerchange_receipts WHERE plan_id = ? AND idempotency_key = ?`, plan.ID, receipt.IdempotencyKey).Scan(&digest); err != nil {
		return false, err
	}
	if digest != receipt.Digest {
		return false, ErrConflict
	}
	return false, nil
}

func allowedTransition(from, to ExecutionState) bool {
	if from == to {
		return !from.terminal()
	}
	if to == StateUncertain {
		return !from.terminal()
	}
	if to == StateRollingBack {
		return !from.terminal() && from != StateRollingBack
	}
	switch from {
	case StatePreviewed:
		return to == StateStaged
	case StateStaged:
		return to == StateValidated
	case StateValidated:
		return to == StateFirewallOpened
	case StateFirewallOpened:
		return to == StateShadowActive
	case StateShadowActive:
		return to == StateExternallyConfirmed
	case StateExternallyConfirmed:
		return to == StateOldDrained
	case StateOldDrained:
		return to == StateCommitted
	case StateRollingBack:
		return to == StateRolledBack
	default:
		return false
	}
}

func slicesEqualListeners(left, right ListenerSet) bool {
	leftDigest, leftErr := left.Digest()
	rightDigest, rightErr := right.Digest()
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func randomID(prefix string) (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func classifyConstraint(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrConflict, err)
}

func formatTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return formatTime(value)
}
