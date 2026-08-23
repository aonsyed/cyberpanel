package packagemaint

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

const packageMaintenanceSchema = `
CREATE TABLE IF NOT EXISTS package_maintenance_inventories (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  manager TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation > 0),
  content_digest TEXT NOT NULL,
  inventory_json BLOB NOT NULL,
  captured_at TEXT NOT NULL,
  UNIQUE(node_id, manager, generation)
);
CREATE INDEX IF NOT EXISTS package_maintenance_inventory_latest
  ON package_maintenance_inventories(node_id, manager, generation DESC);
CREATE TABLE IF NOT EXISTS package_maintenance_plans (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  manager TEXT NOT NULL,
  inventory_id TEXT NOT NULL,
  inventory_generation INTEGER NOT NULL,
  inventory_digest TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation > 0),
  plan_digest TEXT NOT NULL UNIQUE,
  plan_json BLOB NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  UNIQUE(node_id, manager, generation),
  FOREIGN KEY(inventory_id) REFERENCES package_maintenance_inventories(id)
);
CREATE TABLE IF NOT EXISTS package_maintenance_operations (
  id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL,
  plan_digest TEXT NOT NULL,
  plan_generation INTEGER NOT NULL,
  inventory_generation INTEGER NOT NULL,
  inventory_digest TEXT NOT NULL,
  state TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation > 0),
  fence INTEGER NOT NULL CHECK (fence > 0),
  operation_json BLOB NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(plan_id) REFERENCES package_maintenance_plans(id)
);
CREATE TABLE IF NOT EXISTS package_maintenance_audit (
  id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  record_json BLOB NOT NULL,
  observed_at TEXT NOT NULL,
  FOREIGN KEY(operation_id) REFERENCES package_maintenance_operations(id)
);`

const (
	maximumInventoryJSON = 64 << 20
	maximumPlanJSON      = 16 << 20
	maximumOperationJSON = 16 << 20
	maximumAuditJSON     = 1 << 20
)

// SQLRepository persists content-addressed inventory and immutable plans, and
// performs every operation transition with generation/state compare-and-swap.
type SQLRepository struct {
	db     *sql.DB
	writer sync.Mutex
}

func NewSQLRepository(db *sql.DB) (*SQLRepository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &SQLRepository{db: db}, nil
}

func (repository *SQLRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	_, err := repository.db.ExecContext(ctx, packageMaintenanceSchema)
	return err
}

func (repository *SQLRepository) SaveInventory(ctx context.Context, snapshot InventorySnapshot, expectedGeneration uint64) error {
	if repository == nil || repository.db == nil || snapshot.Validate() != nil || snapshot.Generation != expectedGeneration+1 {
		return ErrInvalid
	}
	encoded, err := boundedJSON(snapshot, maximumInventoryJSON)
	if err != nil {
		return err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var current uint64
	var previousCaptured string
	err = transaction.QueryRowContext(ctx, `SELECT generation,captured_at FROM package_maintenance_inventories WHERE node_id=? AND manager=? ORDER BY generation DESC LIMIT 1`, snapshot.NodeID, string(snapshot.Manager)).Scan(&current, &previousCaptured)
	if errors.Is(err, sql.ErrNoRows) {
		current, err = 0, nil
	}
	if err != nil {
		return err
	}
	if current != expectedGeneration {
		return ErrConflict
	}
	if current != 0 {
		capturedAt, parseErr := time.Parse(timeLayout, previousCaptured)
		if parseErr != nil || !snapshot.CapturedAt.After(capturedAt) {
			return ErrConflict
		}
	}
	var active int
	if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_maintenance_operations o JOIN package_maintenance_plans p ON p.id=o.plan_id WHERE p.node_id=? AND p.manager=? AND o.state IN (?,?,?)`, snapshot.NodeID, string(snapshot.Manager), string(OperationAuthorized), string(OperationRunning), string(OperationVerifying)).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return ErrConflict
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO package_maintenance_inventories(id,node_id,manager,generation,content_digest,inventory_json,captured_at) VALUES(?,?,?,?,?,?,?)`, snapshot.ID, snapshot.NodeID, string(snapshot.Manager), snapshot.Generation, snapshot.ContentDigest, encoded, snapshot.CapturedAt.UTC().Format(timeLayout))
	if isConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *SQLRepository) LatestInventory(ctx context.Context, nodeID string, manager Manager) (InventorySnapshot, error) {
	if repository == nil || repository.db == nil || !safeID.MatchString(nodeID) || !validManager(manager) {
		return InventorySnapshot{}, ErrInvalid
	}
	return scanInventory(repository.db.QueryRowContext(ctx, `SELECT inventory_json FROM package_maintenance_inventories WHERE node_id=? AND manager=? ORDER BY generation DESC LIMIT 1`, nodeID, string(manager)))
}

func (repository *SQLRepository) Inventory(ctx context.Context, id string) (InventorySnapshot, error) {
	if repository == nil || repository.db == nil || !safeID.MatchString(id) {
		return InventorySnapshot{}, ErrInvalid
	}
	return scanInventory(repository.db.QueryRowContext(ctx, `SELECT inventory_json FROM package_maintenance_inventories WHERE id=?`, id))
}

func (repository *SQLRepository) PutPlan(ctx context.Context, plan MaintenancePlan) error {
	if repository == nil || repository.db == nil || plan.Validate() != nil {
		return ErrInvalid
	}
	encoded, err := boundedJSON(plan, maximumPlanJSON)
	if err != nil {
		return err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	latest, err := scanInventory(transaction.QueryRowContext(ctx, `SELECT inventory_json FROM package_maintenance_inventories WHERE node_id=? AND manager=? ORDER BY generation DESC LIMIT 1`, plan.NodeID, string(plan.Manager)))
	if err != nil {
		return err
	}
	if latest.ID != plan.InventoryID || latest.Generation != plan.InventoryGeneration || latest.ContentDigest != plan.InventoryDigest || plan.CreatedAt.Before(latest.CapturedAt) {
		return ErrStaleInventory
	}
	if err := validatePlanAgainstInventory(plan, latest); err != nil {
		return err
	}
	var active int
	if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_maintenance_operations o JOIN package_maintenance_plans p ON p.id=o.plan_id WHERE p.node_id=? AND p.manager=? AND o.state IN (?,?,?)`, plan.NodeID, string(plan.Manager), string(OperationAuthorized), string(OperationRunning), string(OperationVerifying)).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return ErrConflict
	}
	var currentGeneration uint64
	err = transaction.QueryRowContext(ctx, `SELECT generation FROM package_maintenance_plans WHERE node_id=? AND manager=? ORDER BY generation DESC LIMIT 1`, plan.NodeID, string(plan.Manager)).Scan(&currentGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		currentGeneration, err = 0, nil
	}
	if err != nil {
		return err
	}
	if currentGeneration >= plan.Generation {
		var existing []byte
		loadErr := transaction.QueryRowContext(ctx, `SELECT plan_json FROM package_maintenance_plans WHERE id=?`, plan.ID).Scan(&existing)
		if loadErr == nil && bytes.Equal(existing, encoded) {
			return transaction.Commit()
		}
		return ErrConflict
	}
	if plan.Generation != currentGeneration+1 {
		return ErrConflict
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO package_maintenance_plans(id,node_id,manager,inventory_id,inventory_generation,inventory_digest,generation,plan_digest,plan_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, plan.ID, plan.NodeID, string(plan.Manager), plan.InventoryID, plan.InventoryGeneration, plan.InventoryDigest, plan.Generation, plan.Digest, encoded, plan.CreatedAt.UTC().Format(timeLayout), plan.ExpiresAt.UTC().Format(timeLayout))
	if isConstraint(err) {
		var existing []byte
		loadErr := transaction.QueryRowContext(ctx, `SELECT plan_json FROM package_maintenance_plans WHERE id=?`, plan.ID).Scan(&existing)
		if loadErr == nil && bytes.Equal(existing, encoded) {
			return transaction.Commit()
		}
		return ErrConflict
	}
	if err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *SQLRepository) Plan(ctx context.Context, id string) (MaintenancePlan, error) {
	if repository == nil || repository.db == nil || !safeID.MatchString(id) {
		return MaintenancePlan{}, ErrInvalid
	}
	return scanPlan(repository.db.QueryRowContext(ctx, `SELECT plan_json FROM package_maintenance_plans WHERE id=?`, id))
}

func (repository *SQLRepository) LatestPlan(ctx context.Context, nodeID string, manager Manager) (MaintenancePlan, error) {
	if repository == nil || repository.db == nil || !safeID.MatchString(nodeID) || !validManager(manager) {
		return MaintenancePlan{}, ErrInvalid
	}
	return scanPlan(repository.db.QueryRowContext(ctx, `SELECT plan_json FROM package_maintenance_plans WHERE node_id=? AND manager=? ORDER BY generation DESC LIMIT 1`, nodeID, string(manager)))
}

func (repository *SQLRepository) Admit(ctx context.Context, operation MaintenanceOperation, audit AuditRecord) (MaintenanceOperation, error) {
	if repository == nil || repository.db == nil || validateOperation(operation) != nil || operation.State != OperationAdmitted || operation.Generation != 1 || validateAudit(audit, operation.ID) != nil {
		return MaintenanceOperation{}, ErrInvalid
	}
	encoded, err := boundedJSON(operation, maximumOperationJSON)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	defer transaction.Rollback()
	plan, err := scanPlan(transaction.QueryRowContext(ctx, `SELECT plan_json FROM package_maintenance_plans WHERE id=?`, operation.PlanID))
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if plan.Digest != operation.PlanDigest || plan.Generation != operation.PlanGeneration || plan.InventoryGeneration != operation.InventoryGeneration || plan.InventoryDigest != operation.InventoryDigest {
		return MaintenanceOperation{}, ErrStalePlan
	}
	latestPlan, err := scanPlan(transaction.QueryRowContext(ctx, `SELECT plan_json FROM package_maintenance_plans WHERE node_id=? AND manager=? ORDER BY generation DESC LIMIT 1`, plan.NodeID, string(plan.Manager)))
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if latestPlan.ID != plan.ID || latestPlan.Generation != plan.Generation || latestPlan.Digest != plan.Digest {
		return MaintenanceOperation{}, ErrStalePlan
	}
	latest, err := scanInventory(transaction.QueryRowContext(ctx, `SELECT inventory_json FROM package_maintenance_inventories WHERE node_id=? AND manager=? ORDER BY generation DESC LIMIT 1`, plan.NodeID, string(plan.Manager)))
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if latest.Generation != operation.InventoryGeneration || latest.ContentDigest != operation.InventoryDigest {
		return MaintenanceOperation{}, ErrStaleInventory
	}
	if err := validatePlanAgainstInventory(plan, latest); err != nil {
		return MaintenanceOperation{}, err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO package_maintenance_operations(id,plan_id,plan_digest,plan_generation,inventory_generation,inventory_digest,state,generation,fence,operation_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, operation.ID, operation.PlanID, operation.PlanDigest, operation.PlanGeneration, operation.InventoryGeneration, operation.InventoryDigest, string(operation.State), operation.Generation, operation.Fence, encoded, operation.UpdatedAt.UTC().Format(timeLayout))
	if isConstraint(err) {
		existing, loadErr := scanOperation(transaction.QueryRowContext(ctx, `SELECT operation_json FROM package_maintenance_operations WHERE id=?`, operation.ID))
		if loadErr == nil && existing.PlanDigest == operation.PlanDigest && existing.AcceptanceAuthorization.Digest == operation.AcceptanceAuthorization.Digest && existing.Fence == operation.Fence {
			return existing, transaction.Commit()
		}
		return MaintenanceOperation{}, ErrConflict
	}
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if err := insertAudit(ctx, transaction, audit); err != nil {
		return MaintenanceOperation{}, err
	}
	if err := transaction.Commit(); err != nil {
		return MaintenanceOperation{}, err
	}
	return operation, nil
}

func (repository *SQLRepository) Operation(ctx context.Context, id string) (MaintenanceOperation, error) {
	if repository == nil || repository.db == nil || !safeID.MatchString(id) {
		return MaintenanceOperation{}, ErrInvalid
	}
	return scanOperation(repository.db.QueryRowContext(ctx, `SELECT operation_json FROM package_maintenance_operations WHERE id=?`, id))
}

// LatestOperation returns the newest durable apply record for a package
// manager. It is intentionally read-only: reconciliation and API retries use
// the stored outcome rather than inferring success or replaying an effect.
func (repository *SQLRepository) LatestOperation(ctx context.Context, nodeID string, manager Manager) (MaintenanceOperation, error) {
	if repository == nil || repository.db == nil || !safeID.MatchString(nodeID) || !validManager(manager) {
		return MaintenanceOperation{}, ErrInvalid
	}
	return scanOperation(repository.db.QueryRowContext(ctx, `SELECT o.operation_json
FROM package_maintenance_operations o
JOIN package_maintenance_plans p ON p.id=o.plan_id
WHERE p.node_id=? AND p.manager=?
ORDER BY p.generation DESC,o.updated_at DESC,o.id DESC
LIMIT 1`, nodeID, string(manager)))
}

func (repository *SQLRepository) Transition(ctx context.Context, id string, expectedGeneration uint64, from, to OperationState, commit AuthorizationEvidence, receipt ExecutionReceipt, audit AuditRecord) (MaintenanceOperation, error) {
	if repository == nil || repository.db == nil || !safeID.MatchString(id) || expectedGeneration == 0 || !transitionAllowed(from, to) || validateAudit(audit, id) != nil {
		return MaintenanceOperation{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	defer transaction.Rollback()
	operation, err := scanOperation(transaction.QueryRowContext(ctx, `SELECT operation_json FROM package_maintenance_operations WHERE id=?`, id))
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if operation.Generation != expectedGeneration || operation.State != from {
		return MaintenanceOperation{}, ErrConflict
	}
	if to == OperationAuthorized || to == OperationRunning {
		if err := ensureCurrentOperation(ctx, transaction, operation); err != nil {
			return MaintenanceOperation{}, err
		}
	}
	if commit.DecisionID != "" {
		operation.CommitAuthorization = commit
	}
	if receipt.EffectID != "" {
		operation.Receipt = receipt
	}
	operation.State = to
	operation.Generation++
	operation.UpdatedAt = audit.ObservedAt.UTC()
	if terminalOperation(to) {
		operation.CompletedAt = audit.ObservedAt.UTC()
	}
	if validateOperation(operation) != nil {
		return MaintenanceOperation{}, ErrInvalid
	}
	encoded, err := boundedJSON(operation, maximumOperationJSON)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	result, err := transaction.ExecContext(ctx, `UPDATE package_maintenance_operations SET state=?,generation=?,operation_json=?,updated_at=? WHERE id=? AND state=? AND generation=?`, string(to), operation.Generation, encoded, operation.UpdatedAt.Format(timeLayout), id, string(from), expectedGeneration)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return MaintenanceOperation{}, ErrConflict
	}
	if err := insertAudit(ctx, transaction, audit); err != nil {
		return MaintenanceOperation{}, err
	}
	if err := transaction.Commit(); err != nil {
		return MaintenanceOperation{}, err
	}
	return operation, nil
}

func ensureCurrentOperation(ctx context.Context, transaction *sql.Tx, operation MaintenanceOperation) error {
	plan, err := scanPlan(transaction.QueryRowContext(ctx, `SELECT plan_json FROM package_maintenance_plans WHERE id=?`, operation.PlanID))
	if err != nil {
		return err
	}
	if plan.Digest != operation.PlanDigest || plan.Generation != operation.PlanGeneration {
		return ErrStalePlan
	}
	latestPlan, err := scanPlan(transaction.QueryRowContext(ctx, `SELECT plan_json FROM package_maintenance_plans WHERE node_id=? AND manager=? ORDER BY generation DESC LIMIT 1`, plan.NodeID, string(plan.Manager)))
	if err != nil {
		return err
	}
	if latestPlan.ID != plan.ID || latestPlan.Generation != plan.Generation || latestPlan.Digest != plan.Digest {
		return ErrStalePlan
	}
	latestInventory, err := scanInventory(transaction.QueryRowContext(ctx, `SELECT inventory_json FROM package_maintenance_inventories WHERE node_id=? AND manager=? ORDER BY generation DESC LIMIT 1`, plan.NodeID, string(plan.Manager)))
	if err != nil {
		return err
	}
	if latestInventory.Generation != operation.InventoryGeneration || latestInventory.ContentDigest != operation.InventoryDigest {
		return ErrStaleInventory
	}
	var active int
	if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_maintenance_operations o JOIN package_maintenance_plans p ON p.id=o.plan_id WHERE p.node_id=? AND p.manager=? AND o.id<>? AND o.state IN (?,?,?)`, plan.NodeID, string(plan.Manager), operation.ID, string(OperationAuthorized), string(OperationRunning), string(OperationVerifying)).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return ErrConflict
	}
	return nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanInventory(row rowScanner) (InventorySnapshot, error) {
	var encoded []byte
	if err := row.Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return InventorySnapshot{}, ErrNotFound
		}
		return InventorySnapshot{}, err
	}
	var value InventorySnapshot
	if strictBoundedJSON(encoded, &value, maximumInventoryJSON) != nil || value.Validate() != nil {
		return InventorySnapshot{}, ErrInvalid
	}
	return value, nil
}

func scanPlan(row rowScanner) (MaintenancePlan, error) {
	var encoded []byte
	if err := row.Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MaintenancePlan{}, ErrNotFound
		}
		return MaintenancePlan{}, err
	}
	var value MaintenancePlan
	if strictBoundedJSON(encoded, &value, maximumPlanJSON) != nil || value.Validate() != nil {
		return MaintenancePlan{}, ErrInvalid
	}
	return value, nil
}

func scanOperation(row rowScanner) (MaintenanceOperation, error) {
	var encoded []byte
	if err := row.Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MaintenanceOperation{}, ErrNotFound
		}
		return MaintenanceOperation{}, err
	}
	var value MaintenanceOperation
	if strictBoundedJSON(encoded, &value, maximumOperationJSON) != nil || validateOperation(value) != nil {
		return MaintenanceOperation{}, ErrInvalid
	}
	return value, nil
}

func insertAudit(ctx context.Context, transaction *sql.Tx, value AuditRecord) error {
	encoded, err := boundedJSON(value, maximumAuditJSON)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO package_maintenance_audit(id,operation_id,action,outcome,record_json,observed_at) VALUES(?,?,?,?,?,?)`, value.ID, value.OperationID, value.Action, value.Outcome, encoded, value.ObservedAt.UTC().Format(timeLayout))
	if isConstraint(err) {
		return ErrConflict
	}
	return err
}

func boundedJSON(value any, maximum int64) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || int64(len(encoded)) > maximum {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func strictBoundedJSON(encoded []byte, target any, maximum int64) error {
	if len(encoded) == 0 || int64(len(encoded)) > maximum {
		return ErrInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(encoded), maximum+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func isConstraint(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed")
}

func transitionAllowed(from, to OperationState) bool {
	switch from {
	case OperationAdmitted:
		return to == OperationAuthorized || to == OperationFailed
	case OperationAuthorized:
		return to == OperationRunning || to == OperationFailed
	case OperationRunning:
		return to == OperationVerifying || to == OperationFailed || to == OperationRecoveryRequired
	case OperationVerifying:
		return to == OperationSucceeded || to == OperationFailed || to == OperationRecoveryRequired || to == OperationRecovered
	case OperationRecoveryRequired:
		return to == OperationRecovered || to == OperationFailed
	default:
		return false
	}
}

func terminalOperation(state OperationState) bool {
	return state == OperationSucceeded || state == OperationFailed || state == OperationRecovered
}

const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"
