package nodeidentity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const Schema = `
CREATE TABLE IF NOT EXISTS node_identity_desired (
 tenant_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 generation INTEGER NOT NULL,
 digest TEXT NOT NULL,
 desired_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 PRIMARY KEY(tenant_id,node_id)
);
CREATE TABLE IF NOT EXISTS node_identity_observed (
 tenant_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 applied_generation INTEGER NOT NULL,
 digest TEXT NOT NULL,
 observed_json BLOB NOT NULL,
 observed_at TIMESTAMP NOT NULL,
 PRIMARY KEY(tenant_id,node_id)
);
CREATE TABLE IF NOT EXISTS node_identity_desired_history (
 tenant_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 generation INTEGER NOT NULL,
 digest TEXT NOT NULL,
 desired_json BLOB NOT NULL,
 recorded_at TIMESTAMP NOT NULL,
 PRIMARY KEY(tenant_id,node_id,revision)
);
CREATE TABLE IF NOT EXISTS node_identity_observed_history (
 tenant_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 applied_generation INTEGER NOT NULL,
 digest TEXT NOT NULL,
 observed_json BLOB NOT NULL,
 recorded_at TIMESTAMP NOT NULL,
 PRIMARY KEY(tenant_id,node_id,revision)
);
CREATE TABLE IF NOT EXISTS node_identity_plans (
 plan_id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 before_desired_revision INTEGER NOT NULL,
 before_observed_revision INTEGER NOT NULL,
 before_generation INTEGER NOT NULL,
 after_generation INTEGER NOT NULL,
 digest TEXT NOT NULL,
 plan_json BLOB NOT NULL,
 created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS node_identity_plans_scope ON node_identity_plans(tenant_id,node_id,created_at);
CREATE TABLE IF NOT EXISTS node_identity_executions (
 plan_id TEXT PRIMARY KEY,
 state TEXT NOT NULL,
 revision INTEGER NOT NULL,
 attempt INTEGER NOT NULL,
 fence INTEGER NOT NULL,
 lease_token TEXT NOT NULL DEFAULT '',
 lease_until TIMESTAMP NULL,
 execution_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 FOREIGN KEY(plan_id) REFERENCES node_identity_plans(plan_id)
);
CREATE INDEX IF NOT EXISTS node_identity_execution_claim ON node_identity_executions(state,lease_until,updated_at);
CREATE TABLE IF NOT EXISTS node_identity_receipts (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 plan_id TEXT NOT NULL,
 phase TEXT NOT NULL,
 fence INTEGER NOT NULL,
 outcome TEXT NOT NULL,
 digest TEXT NOT NULL,
 receipt_json BLOB NOT NULL,
 finished_at TIMESTAMP NOT NULL,
 UNIQUE(plan_id,phase,fence),
 FOREIGN KEY(plan_id) REFERENCES node_identity_plans(plan_id)
);
CREATE INDEX IF NOT EXISTS node_identity_receipts_plan ON node_identity_receipts(plan_id,sequence);
`

type Repository struct {
	DB *sql.DB
}

type Snapshot struct {
	Desired  DesiredIdentity  `json:"desired"`
	Observed ObservedIdentity `json:"observed"`
}

func (repository Repository) Bootstrap(ctx context.Context) error {
	if repository.DB == nil || ctx == nil {
		return ErrInvalid
	}
	_, err := repository.DB.ExecContext(ctx, Schema)
	return err
}

func (repository Repository) Create(ctx context.Context, desired DesiredIdentity, observed ObservedIdentity) error {
	if repository.DB == nil || ctx == nil || desired.Validate() != nil || desired.Revision != 1 || desired.Generation != 1 || observed.Scope != desired.Scope || observed.Revision != 1 || observed.AppliedGeneration != 1 || observed.Validate(desired.Spec, observed.ObservedAt) != nil || !observed.CoreMatches(desired.Spec) {
		return ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = insertDesiredTx(ctx, tx, desired, false); err != nil {
		return err
	}
	if err = insertObservedTx(ctx, tx, observed, false); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository Repository) Snapshot(ctx context.Context, scope Scope, now time.Time) (Snapshot, error) {
	if repository.DB == nil || ctx == nil || scope.Validate() != nil || !validUTC(now) {
		return Snapshot{}, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return Snapshot{}, err
	}
	defer tx.Rollback()
	desired, err := loadDesiredTx(ctx, tx, scope)
	if err != nil {
		return Snapshot{}, err
	}
	observed, err := loadObservedStructuralTx(ctx, tx, scope, desired.Spec)
	if err != nil {
		return Snapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Desired: desired, Observed: observed}, nil
}

func (repository Repository) CompareAndSwapDesired(ctx context.Context, expectedRevision uint64, next DesiredIdentity) error {
	if repository.DB == nil || ctx == nil || expectedRevision == 0 || next.Validate() != nil || next.Revision != expectedRevision+1 {
		return ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	active, err := blockedExecutionTx(ctx, tx, next.Scope)
	if err != nil {
		return err
	}
	if active {
		return ErrConflict
	}
	current, err := loadDesiredTx(ctx, tx, next.Scope)
	if err != nil {
		return err
	}
	currentObserved, err := loadObservedStructuralTx(ctx, tx, next.Scope, current.Spec)
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision || next.Generation != current.Generation+1 || !next.UpdatedAt.After(current.UpdatedAt) {
		return ErrStale
	}
	rebasedObserved, err := NewObservedIdentity(next.Scope, currentObserved.Revision+1, currentObserved.AppliedGeneration, next.Spec, currentObserved.Values, currentObserved.Certificate, currentObserved.Listeners, currentObserved.DNS, currentObserved.Mail, currentObserved.ObservedAt, currentObserved.ValidUntil)
	if err != nil {
		return err
	}
	if err = updateDesiredTx(ctx, tx, current, next); err != nil {
		return err
	}
	if err = updateObservedTx(ctx, tx, currentObserved, rebasedObserved); err != nil {
		return err
	}
	if err = pruneHistoryTx(ctx, tx, "node_identity_desired_history", next.Scope); err != nil {
		return err
	}
	if err = pruneHistoryTx(ctx, tx, "node_identity_observed_history", next.Scope); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository Repository) CompareAndSwapObserved(ctx context.Context, expectedRevision uint64, next ObservedIdentity, now time.Time) error {
	if repository.DB == nil || ctx == nil || expectedRevision == 0 || !validUTC(now) || next.Revision != expectedRevision+1 {
		return ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	active, err := activeExecutionTx(ctx, tx, next.Scope)
	if err != nil {
		return err
	}
	if active {
		return ErrConflict
	}
	desired, err := loadDesiredTx(ctx, tx, next.Scope)
	if err != nil {
		return err
	}
	current, err := loadObservedTx(ctx, tx, next.Scope, desired.Spec, currentValidationTime(now, desired.UpdatedAt))
	if err != nil && !errors.Is(err, ErrStale) {
		return err
	}
	if errors.Is(err, ErrStale) {
		current, err = loadObservedStructuralTx(ctx, tx, next.Scope, desired.Spec)
		if err != nil {
			return err
		}
	}
	if current.Revision != expectedRevision || next.Scope != desired.Scope || next.AppliedGeneration > desired.Generation || next.Validate(desired.Spec, now) != nil || !next.ObservedAt.After(current.ObservedAt) {
		return ErrStale
	}
	if err = updateObservedTx(ctx, tx, current, next); err != nil {
		return err
	}
	if err = pruneHistoryTx(ctx, tx, "node_identity_observed_history", next.Scope); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository Repository) DesiredHistory(ctx context.Context, scope Scope) ([]DesiredIdentity, error) {
	if repository.DB == nil || ctx == nil || scope.Validate() != nil {
		return nil, ErrInvalid
	}
	rows, err := repository.DB.QueryContext(ctx, `SELECT desired_json FROM node_identity_desired_history WHERE tenant_id=? AND node_id=? ORDER BY revision DESC LIMIT ?`, scope.TenantID, scope.NodeID, HistoryLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]DesiredIdentity, 0, HistoryLimit)
	for rows.Next() {
		var encoded []byte
		if err = rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var desired DesiredIdentity
		if json.Unmarshal(encoded, &desired) != nil || desired.Scope != scope || desired.Validate() != nil {
			return nil, ErrConflict
		}
		values = append(values, desired)
	}
	return values, rows.Err()
}

func (repository Repository) SavePlan(ctx context.Context, plan ChangePlan, now time.Time) error {
	if repository.DB == nil || ctx == nil || plan.ValidateAt(now) != nil {
		return ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	desired, err := loadDesiredTx(ctx, tx, plan.Scope)
	if err != nil {
		return err
	}
	observed, err := loadObservedTx(ctx, tx, plan.Scope, desired.Spec, now)
	if err != nil {
		return err
	}
	if desired.Revision != plan.BeforeDesiredRevision || desired.Generation != plan.BeforeGeneration || desired.Digest != plan.BeforeDesiredDigest || observed.Revision != plan.BeforeObservedRevision || observed.Digest != plan.BeforeObservationDigest || plan.AfterGeneration != desired.Generation+1 {
		return ErrStale
	}
	beforeSpecDigest, _ := plan.Before.Digest()
	if beforeSpecDigest != desired.SpecDigest {
		return ErrStale
	}
	active, err := blockedExecutionTx(ctx, tx, plan.Scope)
	if err != nil {
		return err
	}
	if active {
		return ErrConflict
	}
	encodedPlan, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO node_identity_plans(plan_id,tenant_id,node_id,before_desired_revision,before_observed_revision,before_generation,after_generation,digest,plan_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, plan.ID, plan.Scope.TenantID, plan.Scope.NodeID, plan.BeforeDesiredRevision, plan.BeforeObservedRevision, plan.BeforeGeneration, plan.AfterGeneration, plan.Digest, encodedPlan, plan.CreatedAt); err != nil {
		return err
	}
	execution := Execution{PlanID: plan.ID, State: ExecutionQueued, Revision: 1, UpdatedAt: now}
	if execution.Validate() != nil {
		return ErrInvalid
	}
	encodedExecution, err := json.Marshal(execution)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO node_identity_executions(plan_id,state,revision,attempt,fence,execution_json,updated_at) VALUES(?,?,?,?,?,?,?)`, plan.ID, execution.State, execution.Revision, 0, 0, encodedExecution, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository Repository) Plan(ctx context.Context, id PlanID) (ChangePlan, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) {
		return ChangePlan{}, ErrInvalid
	}
	var encoded []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT plan_json FROM node_identity_plans WHERE plan_id=?`, id).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ChangePlan{}, ErrNotFound
	}
	if err != nil {
		return ChangePlan{}, err
	}
	return decodePlan(encoded, id)
}

func (repository Repository) Execution(ctx context.Context, id PlanID) (Execution, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) {
		return Execution{}, ErrInvalid
	}
	var encoded []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT execution_json FROM node_identity_executions WHERE plan_id=?`, id).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return Execution{}, ErrNotFound
	}
	if err != nil {
		return Execution{}, err
	}
	return decodeExecution(encoded, id)
}

func (repository Repository) Claim(ctx context.Context, id PlanID, worker string, duration time.Duration, now time.Time) (ChangePlan, ExecutionLease, bool, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) || !validID(worker) || duration < 5*time.Second || duration > MaximumLease || !validUTC(now) {
		return ChangePlan{}, ExecutionLease{}, false, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ChangePlan{}, ExecutionLease{}, false, err
	}
	defer tx.Rollback()
	plan, err := loadPlanTx(ctx, tx, id)
	if err != nil {
		return ChangePlan{}, ExecutionLease{}, false, err
	}
	execution, err := loadExecutionTx(ctx, tx, id)
	if err != nil {
		return ChangePlan{}, ExecutionLease{}, false, err
	}
	if terminalState(execution.State) {
		return plan, ExecutionLease{}, false, ErrConflict
	}
	if execution.LeaseToken != "" && execution.LeaseUntil.After(now) {
		return plan, ExecutionLease{}, false, tx.Commit()
	}
	if execution.Fence == ^uint64(0) || execution.Attempt == ^uint32(0) || execution.Revision == ^uint64(0) {
		return ChangePlan{}, ExecutionLease{}, false, ErrConflict
	}
	previousRevision, previousFence, previousToken := execution.Revision, execution.Fence, execution.LeaseToken
	token, err := newLeaseToken()
	if err != nil {
		return ChangePlan{}, ExecutionLease{}, false, err
	}
	execution.Revision, execution.Attempt, execution.Fence = execution.Revision+1, execution.Attempt+1, execution.Fence+1
	execution.LeaseToken, execution.LeaseUntil, execution.UpdatedAt = token, now.Add(duration), now
	if err = updateExecutionTx(ctx, tx, execution, previousRevision, previousFence, previousToken); err != nil {
		return ChangePlan{}, ExecutionLease{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return ChangePlan{}, ExecutionLease{}, false, err
	}
	return plan, ExecutionLease{Execution: execution, Token: token, Fence: execution.Fence, Until: execution.LeaseUntil}, true, nil
}

func (repository Repository) Receipts(ctx context.Context, plan ChangePlan, now time.Time) ([]ExecutionReceipt, error) {
	if repository.DB == nil || ctx == nil || plan.ValidateAt(plan.CreatedAt) != nil || !validUTC(now) {
		return nil, ErrInvalid
	}
	rows, err := repository.DB.QueryContext(ctx, `SELECT receipt_json FROM node_identity_receipts WHERE plan_id=? ORDER BY sequence`, plan.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	receipts := make([]ExecutionReceipt, 0, 8)
	for rows.Next() {
		var encoded []byte
		if err = rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var receipt ExecutionReceipt
		if json.Unmarshal(encoded, &receipt) != nil || receipt.Validate(plan, now) != nil {
			return nil, ErrConflict
		}
		receipts = append(receipts, receipt)
	}
	return receipts, rows.Err()
}

type Transition struct {
	Next                ExecutionState
	Activated           bool
	IrreversibleCrossed bool
	Ambiguous           bool
	ErrorCode           string
}

func (repository Repository) RecordTransition(ctx context.Context, plan ChangePlan, lease ExecutionLease, receipt ExecutionReceipt, transition Transition, now time.Time) (Execution, error) {
	if repository.DB == nil || ctx == nil || lease.Execution.Validate() != nil || lease.Execution.PlanID != plan.ID || lease.Token != lease.Execution.LeaseToken || lease.Fence != lease.Execution.Fence || !lease.Until.Equal(lease.Execution.LeaseUntil) || receipt.Validate(plan, now) != nil || receipt.Fence != lease.Fence || receipt.Attempt != lease.Execution.Attempt || receipt.Phase != phaseForState(lease.Execution.State) || now.After(lease.Until) || !validTransition(lease.Execution, receipt, transition) {
		return Execution{}, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Execution{}, err
	}
	defer tx.Rollback()
	current, err := loadExecutionTx(ctx, tx, plan.ID)
	if err != nil {
		return Execution{}, err
	}
	if current.Revision != lease.Execution.Revision || current.Fence != lease.Fence || current.LeaseToken != lease.Token || current.State != lease.Execution.State || current.LeaseUntil.Before(now) {
		return Execution{}, ErrStale
	}
	if err = insertReceiptTx(ctx, tx, receipt); err != nil {
		return Execution{}, err
	}
	previousRevision, previousFence, previousToken := current.Revision, current.Fence, current.LeaseToken
	current.State, current.Revision = transition.Next, current.Revision+1
	current.LeaseToken, current.LeaseUntil, current.UpdatedAt = "", time.Time{}, now
	current.Activated = current.Activated || transition.Activated
	current.IrreversibleCrossed = current.IrreversibleCrossed || transition.IrreversibleCrossed
	current.Ambiguous, current.LastErrorCode = transition.Ambiguous, transition.ErrorCode
	if err = updateExecutionTx(ctx, tx, current, previousRevision, previousFence, previousToken); err != nil {
		return Execution{}, err
	}
	if err = tx.Commit(); err != nil {
		return Execution{}, err
	}
	return current, nil
}

func (repository Repository) Release(ctx context.Context, lease ExecutionLease, now time.Time) error {
	if repository.DB == nil || ctx == nil || lease.Execution.Validate() != nil || lease.Token != lease.Execution.LeaseToken || lease.Fence != lease.Execution.Fence || !validUTC(now) {
		return ErrInvalid
	}
	execution := lease.Execution
	previousRevision, previousFence, previousToken := execution.Revision, execution.Fence, execution.LeaseToken
	execution.Revision, execution.LeaseToken, execution.LeaseUntil, execution.UpdatedAt = execution.Revision+1, "", time.Time{}, now
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = updateExecutionTx(ctx, tx, execution, previousRevision, previousFence, previousToken); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository Repository) Commit(ctx context.Context, plan ChangePlan, lease ExecutionLease, receipt ExecutionReceipt, desired DesiredIdentity, observed ObservedIdentity, now time.Time) (Execution, error) {
	afterSpecDigest, digestErr := plan.After.Digest()
	if repository.DB == nil || ctx == nil || digestErr != nil || lease.Execution.Validate() != nil || lease.Execution.State != ExecutionProbed || lease.Token != lease.Execution.LeaseToken || lease.Fence != lease.Execution.Fence || !lease.Until.Equal(lease.Execution.LeaseUntil) || receipt.Phase != PhaseCommit || receipt.Validate(plan, now) != nil || receipt.Fence != lease.Fence || receipt.Attempt != lease.Execution.Attempt || desired.Scope != plan.Scope || desired.Revision != plan.BeforeDesiredRevision+1 || desired.Generation != plan.AfterGeneration || desired.SpecDigest != afterSpecDigest || desired.Validate() != nil || observed.Scope != plan.Scope || observed.Revision != plan.BeforeObservedRevision+1 || observed.AppliedGeneration != plan.AfterGeneration || observed.Validate(plan.After, now) != nil || !observed.AllMatched() || receipt.Commit.DesiredDigest != desired.Digest || receipt.Commit.ObservedDigest != observed.Digest || now.After(lease.Until) {
		return Execution{}, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Execution{}, err
	}
	defer tx.Rollback()
	currentDesired, err := loadDesiredTx(ctx, tx, plan.Scope)
	if err != nil {
		return Execution{}, err
	}
	currentObserved, err := loadObservedStructuralTx(ctx, tx, plan.Scope, currentDesired.Spec)
	if err != nil {
		return Execution{}, err
	}
	execution, err := loadExecutionTx(ctx, tx, plan.ID)
	if err != nil {
		return Execution{}, err
	}
	if currentDesired.Revision != plan.BeforeDesiredRevision || currentDesired.Generation != plan.BeforeGeneration || currentDesired.Digest != plan.BeforeDesiredDigest || currentObserved.Revision != plan.BeforeObservedRevision || currentObserved.Digest != plan.BeforeObservationDigest || execution.Revision != lease.Execution.Revision || execution.Fence != lease.Fence || execution.LeaseToken != lease.Token || execution.State != ExecutionProbed || execution.LeaseUntil.Before(now) {
		return Execution{}, ErrStale
	}
	var probeJSON []byte
	if err = tx.QueryRowContext(ctx, `SELECT receipt_json FROM node_identity_receipts WHERE plan_id=? AND phase=? AND outcome=? ORDER BY sequence DESC LIMIT 1`, plan.ID, PhaseProbe, OutcomeSucceeded).Scan(&probeJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Execution{}, ErrIncomplete
		}
		return Execution{}, err
	}
	var probeReceipt ExecutionReceipt
	if json.Unmarshal(probeJSON, &probeReceipt) != nil || probeReceipt.Validate(plan, now) != nil || probeReceipt.Probe == nil || probeReceipt.Probe.Observed == nil || probeReceipt.Probe.Observed.Digest != observed.Digest {
		return Execution{}, ErrConflict
	}
	if err = insertReceiptTx(ctx, tx, receipt); err != nil {
		return Execution{}, err
	}
	if err = updateDesiredTx(ctx, tx, currentDesired, desired); err != nil {
		return Execution{}, err
	}
	if err = updateObservedTx(ctx, tx, currentObserved, observed); err != nil {
		return Execution{}, err
	}
	previousRevision, previousFence, previousToken := execution.Revision, execution.Fence, execution.LeaseToken
	execution.State, execution.Revision, execution.LeaseToken, execution.LeaseUntil, execution.UpdatedAt = ExecutionCompleted, execution.Revision+1, "", time.Time{}, now
	execution.LastErrorCode = ""
	if err = updateExecutionTx(ctx, tx, execution, previousRevision, previousFence, previousToken); err != nil {
		return Execution{}, err
	}
	if err = pruneHistoryTx(ctx, tx, "node_identity_desired_history", plan.Scope); err != nil {
		return Execution{}, err
	}
	if err = pruneHistoryTx(ctx, tx, "node_identity_observed_history", plan.Scope); err != nil {
		return Execution{}, err
	}
	if err = tx.Commit(); err != nil {
		return Execution{}, err
	}
	return execution, nil
}

func validTransition(execution Execution, receipt ExecutionReceipt, transition Transition) bool {
	if !validExecutionState(transition.Next) || transition.Ambiguous != (transition.Next == ExecutionAmbiguous) || transition.IrreversibleCrossed && !transition.Activated || transition.ErrorCode != "" && !validErrorCode(transition.ErrorCode) {
		return false
	}
	if receipt.Outcome == OutcomeSucceeded {
		expected := map[ExecutionState]ExecutionState{ExecutionQueued: ExecutionStaged, ExecutionStaged: ExecutionPreflighted, ExecutionPreflighted: ExecutionActivated, ExecutionActivated: ExecutionProbed, ExecutionCompensating: ExecutionCompensated}
		return transition.Next == expected[execution.State] && transition.ErrorCode == ""
	}
	switch execution.State {
	case ExecutionQueued:
		return transition.Next == ExecutionFailed || transition.Next == ExecutionAmbiguous
	case ExecutionStaged, ExecutionPreflighted:
		return transition.Next == ExecutionCompensating || transition.Next == ExecutionAmbiguous
	case ExecutionActivated:
		return transition.Next == ExecutionCompensating || transition.Next == ExecutionAmbiguous || transition.Next == ExecutionIrreversible
	case ExecutionCompensating:
		return transition.Next == ExecutionAmbiguous || transition.Next == ExecutionIrreversible
	default:
		return false
	}
}

func insertDesiredTx(ctx context.Context, tx *sql.Tx, desired DesiredIdentity, update bool) error {
	encoded, err := json.Marshal(desired)
	if err != nil {
		return err
	}
	if update {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO node_identity_desired(tenant_id,node_id,revision,generation,digest,desired_json,updated_at) VALUES(?,?,?,?,?,?,?)`, desired.Scope.TenantID, desired.Scope.NodeID, desired.Revision, desired.Generation, desired.Digest, encoded, desired.UpdatedAt); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO node_identity_desired_history(tenant_id,node_id,revision,generation,digest,desired_json,recorded_at) VALUES(?,?,?,?,?,?,?)`, desired.Scope.TenantID, desired.Scope.NodeID, desired.Revision, desired.Generation, desired.Digest, encoded, desired.UpdatedAt)
	return err
}

func insertObservedTx(ctx context.Context, tx *sql.Tx, observed ObservedIdentity, update bool) error {
	encoded, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	if update {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO node_identity_observed(tenant_id,node_id,revision,applied_generation,digest,observed_json,observed_at) VALUES(?,?,?,?,?,?,?)`, observed.Scope.TenantID, observed.Scope.NodeID, observed.Revision, observed.AppliedGeneration, observed.Digest, encoded, observed.ObservedAt); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO node_identity_observed_history(tenant_id,node_id,revision,applied_generation,digest,observed_json,recorded_at) VALUES(?,?,?,?,?,?,?)`, observed.Scope.TenantID, observed.Scope.NodeID, observed.Revision, observed.AppliedGeneration, observed.Digest, encoded, observed.ObservedAt)
	return err
}

func updateDesiredTx(ctx context.Context, tx *sql.Tx, current, next DesiredIdentity) error {
	encoded, err := json.Marshal(next)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE node_identity_desired SET revision=?,generation=?,digest=?,desired_json=?,updated_at=? WHERE tenant_id=? AND node_id=? AND revision=? AND generation=? AND digest=?`, next.Revision, next.Generation, next.Digest, encoded, next.UpdatedAt, next.Scope.TenantID, next.Scope.NodeID, current.Revision, current.Generation, current.Digest)
	if err != nil {
		return err
	}
	if err = requireOne(result); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO node_identity_desired_history(tenant_id,node_id,revision,generation,digest,desired_json,recorded_at) VALUES(?,?,?,?,?,?,?)`, next.Scope.TenantID, next.Scope.NodeID, next.Revision, next.Generation, next.Digest, encoded, next.UpdatedAt)
	return err
}

func updateObservedTx(ctx context.Context, tx *sql.Tx, current, next ObservedIdentity) error {
	encoded, err := json.Marshal(next)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE node_identity_observed SET revision=?,applied_generation=?,digest=?,observed_json=?,observed_at=? WHERE tenant_id=? AND node_id=? AND revision=? AND digest=?`, next.Revision, next.AppliedGeneration, next.Digest, encoded, next.ObservedAt, next.Scope.TenantID, next.Scope.NodeID, current.Revision, current.Digest)
	if err != nil {
		return err
	}
	if err = requireOne(result); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO node_identity_observed_history(tenant_id,node_id,revision,applied_generation,digest,observed_json,recorded_at) VALUES(?,?,?,?,?,?,?)`, next.Scope.TenantID, next.Scope.NodeID, next.Revision, next.AppliedGeneration, next.Digest, encoded, next.ObservedAt)
	return err
}

func loadDesiredTx(ctx context.Context, tx *sql.Tx, scope Scope) (DesiredIdentity, error) {
	var encoded []byte
	err := tx.QueryRowContext(ctx, `SELECT desired_json FROM node_identity_desired WHERE tenant_id=? AND node_id=?`, scope.TenantID, scope.NodeID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return DesiredIdentity{}, ErrNotFound
	}
	if err != nil {
		return DesiredIdentity{}, err
	}
	var desired DesiredIdentity
	if json.Unmarshal(encoded, &desired) != nil || desired.Scope != scope || desired.Validate() != nil {
		return DesiredIdentity{}, ErrConflict
	}
	return desired, nil
}

func loadObservedTx(ctx context.Context, tx *sql.Tx, scope Scope, desired IdentitySpec, now time.Time) (ObservedIdentity, error) {
	observed, err := loadObservedStructuralTx(ctx, tx, scope, desired)
	if err != nil {
		return ObservedIdentity{}, err
	}
	if observed.Validate(desired, now) != nil {
		return ObservedIdentity{}, ErrStale
	}
	return observed, nil
}

func loadObservedStructuralTx(ctx context.Context, tx *sql.Tx, scope Scope, desired IdentitySpec) (ObservedIdentity, error) {
	var encoded []byte
	err := tx.QueryRowContext(ctx, `SELECT observed_json FROM node_identity_observed WHERE tenant_id=? AND node_id=?`, scope.TenantID, scope.NodeID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ObservedIdentity{}, ErrNotFound
	}
	if err != nil {
		return ObservedIdentity{}, err
	}
	var observed ObservedIdentity
	if json.Unmarshal(encoded, &observed) != nil || observed.Scope != scope || observed.Validate(desired, observed.ObservedAt) != nil {
		return ObservedIdentity{}, ErrConflict
	}
	return observed, nil
}

func loadPlanTx(ctx context.Context, tx *sql.Tx, id PlanID) (ChangePlan, error) {
	var encoded []byte
	err := tx.QueryRowContext(ctx, `SELECT plan_json FROM node_identity_plans WHERE plan_id=?`, id).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ChangePlan{}, ErrNotFound
	}
	if err != nil {
		return ChangePlan{}, err
	}
	return decodePlan(encoded, id)
}

func decodePlan(encoded []byte, id PlanID) (ChangePlan, error) {
	var plan ChangePlan
	if json.Unmarshal(encoded, &plan) != nil || plan.ID != id || plan.ValidateAt(plan.CreatedAt) != nil {
		return ChangePlan{}, ErrConflict
	}
	return plan, nil
}

func loadExecutionTx(ctx context.Context, tx *sql.Tx, id PlanID) (Execution, error) {
	var encoded []byte
	err := tx.QueryRowContext(ctx, `SELECT execution_json FROM node_identity_executions WHERE plan_id=?`, id).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return Execution{}, ErrNotFound
	}
	if err != nil {
		return Execution{}, err
	}
	return decodeExecution(encoded, id)
}

func decodeExecution(encoded []byte, id PlanID) (Execution, error) {
	var execution Execution
	if json.Unmarshal(encoded, &execution) != nil || execution.PlanID != id || execution.Validate() != nil {
		return Execution{}, ErrConflict
	}
	return execution, nil
}

func updateExecutionTx(ctx context.Context, tx *sql.Tx, execution Execution, expectedRevision, expectedFence uint64, expectedToken string) error {
	if execution.Validate() != nil || execution.Revision != expectedRevision+1 {
		return ErrInvalid
	}
	encoded, err := json.Marshal(execution)
	if err != nil {
		return err
	}
	var lease any
	if execution.LeaseUntil.IsZero() {
		lease = nil
	} else {
		lease = execution.LeaseUntil
	}
	result, err := tx.ExecContext(ctx, `UPDATE node_identity_executions SET state=?,revision=?,attempt=?,fence=?,lease_token=?,lease_until=?,execution_json=?,updated_at=? WHERE plan_id=? AND revision=? AND fence=? AND lease_token=?`, execution.State, execution.Revision, execution.Attempt, execution.Fence, execution.LeaseToken, lease, encoded, execution.UpdatedAt, execution.PlanID, expectedRevision, expectedFence, expectedToken)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func insertReceiptTx(ctx context.Context, tx *sql.Tx, receipt ExecutionReceipt) error {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO node_identity_receipts(plan_id,phase,fence,outcome,digest,receipt_json,finished_at) VALUES(?,?,?,?,?,?,?)`, receipt.PlanID, receipt.Phase, receipt.Fence, receipt.Outcome, receipt.Digest, encoded, receipt.FinishedAt)
	return err
}

func pruneHistoryTx(ctx context.Context, tx *sql.Tx, table string, scope Scope) error {
	if table != "node_identity_desired_history" && table != "node_identity_observed_history" {
		return ErrInvalid
	}
	query := `DELETE FROM ` + table + ` WHERE tenant_id=? AND node_id=? AND revision NOT IN (SELECT revision FROM ` + table + ` WHERE tenant_id=? AND node_id=? ORDER BY revision DESC LIMIT ?)`
	_, err := tx.ExecContext(ctx, query, scope.TenantID, scope.NodeID, scope.TenantID, scope.NodeID, HistoryLimit)
	return err
}

func activeExecutionTx(ctx context.Context, tx *sql.Tx, scope Scope) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM node_identity_executions e JOIN node_identity_plans p ON p.plan_id=e.plan_id WHERE p.tenant_id=? AND p.node_id=? AND e.state NOT IN (?,?,?,?,?)`, scope.TenantID, scope.NodeID, ExecutionCompleted, ExecutionFailed, ExecutionCompensated, ExecutionAmbiguous, ExecutionIrreversible).Scan(&count)
	return count != 0, err
}

func blockedExecutionTx(ctx context.Context, tx *sql.Tx, scope Scope) (bool, error) {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM node_identity_executions e JOIN node_identity_plans p ON p.plan_id=e.plan_id JOIN node_identity_observed o ON o.tenant_id=p.tenant_id AND o.node_id=p.node_id WHERE p.tenant_id=? AND p.node_id=? AND (e.state NOT IN (?,?,?,?,?) OR (e.state IN (?,?) AND p.before_observed_revision>=o.revision))`, scope.TenantID, scope.NodeID, ExecutionCompleted, ExecutionFailed, ExecutionCompensated, ExecutionAmbiguous, ExecutionIrreversible, ExecutionAmbiguous, ExecutionIrreversible).Scan(&count)
	return count != 0, err
}

func newLeaseToken() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "identity-lease-" + hex.EncodeToString(value[:]), nil
}

func requireOne(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrStale
	}
	return nil
}

func currentValidationTime(now, minimum time.Time) time.Time {
	if now.Before(minimum) {
		return minimum
	}
	return now
}
