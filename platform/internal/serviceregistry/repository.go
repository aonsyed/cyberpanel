package serviceregistry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type OperationState string

const (
	OperationAdmitted    OperationState = "admitted"
	OperationRunning     OperationState = "running"
	OperationSucceeded   OperationState = "succeeded"
	OperationFailed      OperationState = "failed"
	OperationCompensated OperationState = "compensated"
	OperationAmbiguous   OperationState = "ambiguous"
)

type Operation struct {
	ID                string                  `json:"id"`
	PlanID            string                  `json:"plan_id"`
	PlanDigest        string                  `json:"plan_digest"`
	State             OperationState          `json:"state"`
	Version           uint64                  `json:"version"`
	Authorization     AuthorizationEvidence   `json:"authorization"`
	Maintenance       *MaintenanceEvidence    `json:"maintenance,omitempty"`
	ReceiptID         string                  `json:"receipt_id,omitempty"`
	CreatedAt         time.Time               `json:"created_at"`
	UpdatedAt         time.Time               `json:"updated_at"`
}

type Repository interface {
	Desired(context.Context, string, ServiceID) (DesiredState, error)
	PutDesired(context.Context, DesiredState, uint64) error
	Observed(context.Context, string, ServiceID) (ServiceObservation, error)
	PutObserved(context.Context, ServiceObservation, uint64) error
	Plan(context.Context, string) (LifecyclePlan, error)
	PutPlan(context.Context, LifecyclePlan) error
	Operation(context.Context, string) (Operation, error)
	AdmitOperation(context.Context, Operation, AuditEvent) error
	TransitionOperation(context.Context, string, OperationState, uint64, OperationState, string, AuditEvent) (Operation, error)
	PutReceipt(context.Context, LifecycleReceipt, AuditEvent) error
	Receipt(context.Context, string) (LifecycleReceipt, error)
	AppendAudit(context.Context, AuditEvent) error
}

type SQLiteRepository struct {
	db       *sql.DB
	registry *Registry
}

func NewSQLiteRepository(db *sql.DB, registry *Registry) (*SQLiteRepository, error) {
	if db == nil || registry == nil {
		return nil, fmt.Errorf("%w: incomplete repository dependencies", ErrInvalid)
	}
	return &SQLiteRepository{db: db, registry: registry}, nil
}

func (r *SQLiteRepository) Init(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS service_desired (
			node_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			digest TEXT NOT NULL,
			payload BLOB NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (node_id, service_id)
		)`,
		`CREATE TABLE IF NOT EXISTS service_observed (
			node_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			evidence_digest TEXT NOT NULL,
			payload BLOB NOT NULL,
			observed_at TEXT NOT NULL,
			PRIMARY KEY (node_id, service_id)
		)`,
		`CREATE TABLE IF NOT EXISTS service_plan_heads (
			node_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			plan_id TEXT NOT NULL,
			plan_digest TEXT NOT NULL,
			PRIMARY KEY (node_id, service_id)
		)`,
		`CREATE TABLE IF NOT EXISTS service_plans (
			plan_id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			digest TEXT NOT NULL UNIQUE,
			payload BLOB NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS service_operations (
			operation_id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			plan_digest TEXT NOT NULL,
			state TEXT NOT NULL,
			version INTEGER NOT NULL CHECK (version > 0),
			authorization_payload BLOB NOT NULL,
			maintenance_payload BLOB,
			receipt_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY (plan_id) REFERENCES service_plans(plan_id)
		)`,
		`CREATE TABLE IF NOT EXISTS service_receipts (
			receipt_id TEXT PRIMARY KEY,
			operation_id TEXT NOT NULL UNIQUE,
			plan_id TEXT NOT NULL,
			plan_digest TEXT NOT NULL,
			outcome TEXT NOT NULL,
			evidence_digest TEXT NOT NULL,
			payload BLOB NOT NULL,
			completed_at TEXT NOT NULL,
			FOREIGN KEY (operation_id) REFERENCES service_operations(operation_id)
		)`,
		`CREATE TABLE IF NOT EXISTS service_audit (
			event_id TEXT PRIMARY KEY,
			operation_id TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			resource TEXT NOT NULL,
			request_digest TEXT NOT NULL,
			evidence_digest TEXT NOT NULL,
			occurred_at TEXT NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize service registry repository: %w", err)
		}
	}
	return nil
}

func boundedJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: encode repository payload: %v", ErrInvalid, err)
	}
	if len(b) == 0 || len(b) > MaxEvidenceBytes {
		return nil, fmt.Errorf("%w: repository payload exceeds %d bytes", ErrInvalid, MaxEvidenceBytes)
	}
	return b, nil
}

func decodeBoundedJSON(data []byte, dst any) error {
	if len(data) == 0 || len(data) > MaxEvidenceBytes {
		return fmt.Errorf("%w: stored payload exceeds bounds", ErrInvalid)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("%w: decode stored payload: %v", ErrInvalid, err)
	}
	return nil
}

func currentGeneration(ctx context.Context, tx *sql.Tx, table, nodeID string, serviceID ServiceID) (uint64, bool, error) {
	var query string
	switch table {
	case "service_desired", "service_observed":
		query = "SELECT generation FROM " + table + " WHERE node_id = ? AND service_id = ?"
	default:
		return 0, false, fmt.Errorf("%w: invalid generation table", ErrInvalid)
	}
	var generation uint64
	err := tx.QueryRowContext(ctx, query, nodeID, serviceID).Scan(&generation)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return generation, true, nil
}

func (r *SQLiteRepository) Desired(ctx context.Context, nodeID string, serviceID ServiceID) (DesiredState, error) {
	var payload []byte
	if err := r.db.QueryRowContext(ctx,
		`SELECT payload FROM service_desired WHERE node_id = ? AND service_id = ?`, nodeID, serviceID,
	).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return DesiredState{}, ErrNotFound
		}
		return DesiredState{}, err
	}
	var state DesiredState
	if err := decodeBoundedJSON(payload, &state); err != nil {
		return DesiredState{}, err
	}
	sealed, err := SealDesiredState(state)
	_, known := r.registry.Definition(state.ServiceID)
	if err != nil || sealed.Digest != state.Digest || !known || state.DefinitionDigest != r.registry.Digest() {
		return DesiredState{}, fmt.Errorf("%w: desired state digest mismatch", ErrInvalid)
	}
	return state, nil
}

func (r *SQLiteRepository) PutDesired(ctx context.Context, state DesiredState, expectedGeneration uint64) error {
	sealed, err := SealDesiredState(state)
	_, known := r.registry.Definition(state.ServiceID)
	if err != nil || sealed.Digest != state.Digest || state.Generation != expectedGeneration+1 || !known || state.DefinitionDigest != r.registry.Digest() {
		return fmt.Errorf("%w: desired state generation or digest", ErrStale)
	}
	payload, err := boundedJSON(state)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, exists, err := currentGeneration(ctx, tx, "service_desired", state.NodeID, state.ServiceID)
	if err != nil {
		return err
	}
	if current != expectedGeneration || exists != (expectedGeneration != 0) {
		return ErrConflict
	}
	var result sql.Result
	if !exists {
		result, err = tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO service_desired(node_id, service_id, generation, digest, payload, updated_at) VALUES(?, ?, ?, ?, ?, ?)`,
			state.NodeID, state.ServiceID, state.Generation, state.Digest, payload, state.UpdatedAt.UTC().Format(time.RFC3339Nano))
	} else {
		result, err = tx.ExecContext(ctx,
			`UPDATE service_desired SET generation = ?, digest = ?, payload = ?, updated_at = ? WHERE node_id = ? AND service_id = ? AND generation = ?`,
			state.Generation, state.Digest, payload, state.UpdatedAt.UTC().Format(time.RFC3339Nano), state.NodeID, state.ServiceID, expectedGeneration)
	}
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (r *SQLiteRepository) Observed(ctx context.Context, nodeID string, serviceID ServiceID) (ServiceObservation, error) {
	var payload []byte
	if err := r.db.QueryRowContext(ctx,
		`SELECT payload FROM service_observed WHERE node_id = ? AND service_id = ?`, nodeID, serviceID,
	).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return ServiceObservation{}, ErrNotFound
		}
		return ServiceObservation{}, err
	}
	var state ServiceObservation
	if err := decodeBoundedJSON(payload, &state); err != nil {
		return ServiceObservation{}, err
	}
	if err := ValidateObservation(state); err != nil {
		return ServiceObservation{}, err
	}
	if _, known := r.registry.Definition(state.ServiceID); !known || state.DefinitionDigest != r.registry.Digest() {
		return ServiceObservation{}, fmt.Errorf("%w: observation registry binding", ErrInvalid)
	}
	return state, nil
}

func (r *SQLiteRepository) PutObserved(ctx context.Context, state ServiceObservation, expectedGeneration uint64) error {
	if err := ValidateObservation(state); err != nil {
		return err
	}
	if state.Generation != expectedGeneration+1 {
		return fmt.Errorf("%w: observation generation", ErrStale)
	}
	if _, known := r.registry.Definition(state.ServiceID); !known || state.DefinitionDigest != r.registry.Digest() {
		return fmt.Errorf("%w: observation registry binding", ErrInvalid)
	}
	payload, err := boundedJSON(state)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, exists, err := currentGeneration(ctx, tx, "service_observed", state.NodeID, state.ServiceID)
	if err != nil {
		return err
	}
	if current != expectedGeneration || exists != (expectedGeneration != 0) {
		return ErrConflict
	}
	var result sql.Result
	if !exists {
		result, err = tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO service_observed(node_id, service_id, generation, evidence_digest, payload, observed_at) VALUES(?, ?, ?, ?, ?, ?)`,
			state.NodeID, state.ServiceID, state.Generation, state.EvidenceDigest, payload, state.ObservedAt.UTC().Format(time.RFC3339Nano))
	} else {
		result, err = tx.ExecContext(ctx,
			`UPDATE service_observed SET generation = ?, evidence_digest = ?, payload = ?, observed_at = ? WHERE node_id = ? AND service_id = ? AND generation = ?`,
			state.Generation, state.EvidenceDigest, payload, state.ObservedAt.UTC().Format(time.RFC3339Nano), state.NodeID, state.ServiceID, expectedGeneration)
	}
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (r *SQLiteRepository) Plan(ctx context.Context, id string) (LifecyclePlan, error) {
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM service_plans WHERE plan_id = ?`, id).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return LifecyclePlan{}, ErrNotFound
		}
		return LifecyclePlan{}, err
	}
	var plan LifecyclePlan
	if err := decodeBoundedJSON(payload, &plan); err != nil {
		return LifecyclePlan{}, err
	}
	sealed, err := SealPlan(plan)
	if err != nil || sealed.Digest != plan.Digest || plan.RegistryDigest != r.registry.Digest() || plan.SupportDigest != r.registry.SupportDigest() {
		return LifecyclePlan{}, fmt.Errorf("%w: stored plan digest", ErrInvalid)
	}
	if err := r.registry.validateStepOrder(plan); err != nil {
		return LifecyclePlan{}, err
	}
	return plan, nil
}

func (r *SQLiteRepository) PutPlan(ctx context.Context, plan LifecyclePlan) error {
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	sealed, err := SealPlan(plan)
	if err != nil || sealed.Digest != plan.Digest || plan.RegistryDigest != r.registry.Digest() || plan.SupportDigest != r.registry.SupportDigest() {
		return fmt.Errorf("%w: plan digest mismatch", ErrInvalid)
	}
	if err := r.registry.validateStepOrder(plan); err != nil {
		return err
	}
	payload, err := boundedJSON(plan)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var desiredGeneration uint64
	var desiredPayload []byte
	err = tx.QueryRowContext(ctx, `SELECT generation, payload FROM service_desired WHERE node_id = ? AND service_id = ?`, plan.NodeID, plan.Target).Scan(&desiredGeneration, &desiredPayload)
	if err == sql.ErrNoRows {
		desiredGeneration = 0
	} else if err != nil {
		return err
	}
	var observedGeneration uint64
	var observedPayload []byte
	err = tx.QueryRowContext(ctx, `SELECT generation, payload FROM service_observed WHERE node_id = ? AND service_id = ?`, plan.NodeID, plan.Target).Scan(&observedGeneration, &observedPayload)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: target observation missing", ErrStale)
		}
		return err
	}
	if desiredGeneration != plan.ExpectedDesiredGeneration || observedGeneration != plan.ExpectedObservedGeneration {
		return ErrStale
	}
	if desiredGeneration != 0 {
		var desired DesiredState
		if err := decodeBoundedJSON(desiredPayload, &desired); err != nil {
			return err
		}
		if desired.ConfigGeneration != plan.ExpectedConfigGeneration || desired.DefinitionDigest != plan.RegistryDigest {
			return ErrStale
		}
	}
	var observed ServiceObservation
	if err := decodeBoundedJSON(observedPayload, &observed); err != nil {
		return err
	}
	if observed.ConfigGeneration != plan.ExpectedConfigGeneration || observed.DefinitionDigest != plan.RegistryDigest {
		return ErrStale
	}
	checked := make(map[ServiceID]bool)
	for _, step := range plan.Steps {
		if checked[step.ServiceID] {
			continue
		}
		checked[step.ServiceID] = true
		var generation uint64
		var stepPayload []byte
		if err := tx.QueryRowContext(ctx, `SELECT generation, payload FROM service_observed WHERE node_id = ? AND service_id = ?`, plan.NodeID, step.ServiceID).Scan(&generation, &stepPayload); err != nil {
			if err == sql.ErrNoRows {
				return ErrStale
			}
			return err
		}
		var stepObservation ServiceObservation
		if err := decodeBoundedJSON(stepPayload, &stepObservation); err != nil {
			return err
		}
		if generation != step.ExpectedObservedGeneration || stepObservation.ConfigGeneration != step.ExpectedConfigGeneration || stepObservation.DefinitionDigest != plan.RegistryDigest {
			return ErrStale
		}
	}
	var head uint64
	err = tx.QueryRowContext(ctx, `SELECT generation FROM service_plan_heads WHERE node_id = ? AND service_id = ?`, plan.NodeID, plan.Target).Scan(&head)
	headExists := true
	if err == sql.ErrNoRows {
		headExists = false
		head = 0
	} else if err != nil {
		return err
	}
	if plan.Generation != head+1 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO service_plans(plan_id, node_id, service_id, generation, digest, payload, created_at, expires_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		plan.ID, plan.NodeID, plan.Target, plan.Generation, plan.Digest, payload, plan.CreatedAt.UTC().Format(time.RFC3339Nano), plan.ExpiresAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("persist immutable service plan: %w", err)
	}
	var result sql.Result
	if !headExists {
		result, err = tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO service_plan_heads(node_id, service_id, generation, plan_id, plan_digest) VALUES(?, ?, ?, ?, ?)`,
			plan.NodeID, plan.Target, plan.Generation, plan.ID, plan.Digest)
	} else {
		result, err = tx.ExecContext(ctx,
			`UPDATE service_plan_heads SET generation = ?, plan_id = ?, plan_digest = ? WHERE node_id = ? AND service_id = ? AND generation = ?`,
			plan.Generation, plan.ID, plan.Digest, plan.NodeID, plan.Target, head)
	}
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (r *SQLiteRepository) Operation(ctx context.Context, id string) (Operation, error) {
	var operation Operation
	var authPayload, maintenancePayload []byte
	var state string
	var createdAt, updatedAt string
	err := r.db.QueryRowContext(ctx,
		`SELECT plan_id, plan_digest, state, version, authorization_payload, maintenance_payload, receipt_id, created_at, updated_at FROM service_operations WHERE operation_id = ?`, id,
	).Scan(&operation.PlanID, &operation.PlanDigest, &state, &operation.Version, &authPayload, &maintenancePayload, &operation.ReceiptID, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return Operation{}, ErrNotFound
		}
		return Operation{}, err
	}
	operation.ID = id
	operation.State = OperationState(state)
	if !validGeneration(operation.Version) {
		return Operation{}, fmt.Errorf("%w: invalid operation version", ErrInvalid)
	}
	if err := decodeBoundedJSON(authPayload, &operation.Authorization); err != nil {
		return Operation{}, err
	}
	if len(maintenancePayload) != 0 {
		var maintenance MaintenanceEvidence
		if err := decodeBoundedJSON(maintenancePayload, &maintenance); err != nil {
			return Operation{}, err
		}
		operation.Maintenance = &maintenance
	}
	operation.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Operation{}, fmt.Errorf("%w: operation created timestamp", ErrInvalid)
	}
	operation.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return Operation{}, fmt.Errorf("%w: operation updated timestamp", ErrInvalid)
	}
	return operation, nil
}

func validateAudit(event AuditEvent) error {
	if !validID(event.ID) || !validID(event.OperationID) || !validID(event.ActorID) || event.Kind == "" || event.Resource == "" || event.RequestDigest == "" || event.EvidenceDigest == "" || event.OccurredAt.IsZero() {
		return fmt.Errorf("%w: incomplete audit event", ErrInvalid)
	}
	return nil
}

func insertAudit(ctx context.Context, tx *sql.Tx, event AuditEvent) error {
	if err := validateAudit(event); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO service_audit(event_id, operation_id, actor_id, kind, resource, request_digest, evidence_digest, occurred_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.OperationID, event.ActorID, event.Kind, event.Resource, event.RequestDigest, event.EvidenceDigest, event.OccurredAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (r *SQLiteRepository) AdmitOperation(ctx context.Context, operation Operation, audit AuditEvent) error {
	if !validID(operation.ID) || !validID(operation.PlanID) || operation.PlanDigest == "" || operation.State != OperationAdmitted || operation.Version != 1 || operation.CreatedAt.IsZero() || operation.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: invalid admitted operation", ErrInvalid)
	}
	authPayload, err := boundedJSON(operation.Authorization)
	if err != nil {
		return err
	}
	var maintenancePayload []byte
	if operation.Maintenance != nil {
		maintenancePayload, err = boundedJSON(operation.Maintenance)
		if err != nil {
			return err
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var storedDigest string
	if err := tx.QueryRowContext(ctx, `SELECT digest FROM service_plans WHERE plan_id = ?`, operation.PlanID).Scan(&storedDigest); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	if storedDigest != operation.PlanDigest {
		return ErrStale
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO service_operations(operation_id, plan_id, plan_digest, state, version, authorization_payload, maintenance_payload, receipt_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, '', ?, ?)`,
		operation.ID, operation.PlanID, operation.PlanDigest, operation.State, operation.Version, authPayload, maintenancePayload, operation.CreatedAt.UTC().Format(time.RFC3339Nano), operation.UpdatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("persist admitted operation: %w", err)
	}
	if err := insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func validTransition(from, to OperationState) bool {
	switch from {
	case OperationAdmitted:
		return to == OperationRunning || to == OperationFailed
	case OperationRunning:
		return to == OperationSucceeded || to == OperationFailed || to == OperationCompensated || to == OperationAmbiguous
	default:
		return false
	}
}

func (r *SQLiteRepository) TransitionOperation(ctx context.Context, id string, expected OperationState, expectedVersion uint64, next OperationState, receiptID string, audit AuditEvent) (Operation, error) {
	if !validID(id) || !validTransition(expected, next) || !validGeneration(expectedVersion) || expectedVersion == MaxGeneration {
		return Operation{}, fmt.Errorf("%w: invalid operation transition", ErrInvalid)
	}
	if receiptID != "" && !validID(receiptID) {
		return Operation{}, fmt.Errorf("%w: invalid receipt id", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, err
	}
	defer tx.Rollback()
	now := audit.OccurredAt.UTC()
	result, err := tx.ExecContext(ctx,
		`UPDATE service_operations SET state = ?, version = ?, receipt_id = ?, updated_at = ? WHERE operation_id = ? AND state = ? AND version = ?`,
		next, expectedVersion+1, receiptID, now.Format(time.RFC3339Nano), id, expected, expectedVersion)
	if err != nil {
		return Operation{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return Operation{}, ErrConflict
	}
	if err := insertAudit(ctx, tx, audit); err != nil {
		return Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, err
	}
	return r.Operation(ctx, id)
}

func (r *SQLiteRepository) PutReceipt(ctx context.Context, receipt LifecycleReceipt, audit AuditEvent) error {
	if !validID(receipt.ID) || !validID(receipt.OperationID) || !validID(receipt.PlanID) || receipt.PlanDigest == "" || receipt.Outcome == "" || receipt.EvidenceDigest == "" || len(receipt.Steps) > MaxPlanSteps || receipt.CompletedAt.IsZero() {
		return fmt.Errorf("%w: invalid lifecycle receipt", ErrInvalid)
	}
	sealed, err := SealLifecycleReceipt(receipt)
	if err != nil || sealed.EvidenceDigest != receipt.EvidenceDigest {
		return fmt.Errorf("%w: lifecycle receipt evidence digest", ErrInvalid)
	}
	payload, err := boundedJSON(receipt)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var planID, planDigest string
	if err := tx.QueryRowContext(ctx, `SELECT plan_id, plan_digest FROM service_operations WHERE operation_id = ?`, receipt.OperationID).Scan(&planID, &planDigest); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	if planID != receipt.PlanID || planDigest != receipt.PlanDigest {
		return ErrStale
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO service_receipts(receipt_id, operation_id, plan_id, plan_digest, outcome, evidence_digest, payload, completed_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		receipt.ID, receipt.OperationID, receipt.PlanID, receipt.PlanDigest, receipt.Outcome, receipt.EvidenceDigest, payload, receipt.CompletedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("persist immutable lifecycle receipt: %w", err)
	}
	if err := insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SQLiteRepository) Receipt(ctx context.Context, id string) (LifecycleReceipt, error) {
	var payload []byte
	if err := r.db.QueryRowContext(ctx, `SELECT payload FROM service_receipts WHERE receipt_id = ?`, id).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return LifecycleReceipt{}, ErrNotFound
		}
		return LifecycleReceipt{}, err
	}
	var receipt LifecycleReceipt
	if err := decodeBoundedJSON(payload, &receipt); err != nil {
		return LifecycleReceipt{}, err
	}
	sealed, err := SealLifecycleReceipt(receipt)
	if err != nil || sealed.EvidenceDigest != receipt.EvidenceDigest {
		return LifecycleReceipt{}, fmt.Errorf("%w: stored lifecycle receipt digest", ErrInvalid)
	}
	return receipt, nil
}

func (r *SQLiteRepository) AppendAudit(ctx context.Context, event AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertAudit(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
