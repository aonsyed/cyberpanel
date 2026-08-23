package rebootcontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const MaxPageSize = 500

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
		`CREATE TABLE IF NOT EXISTS reboot_plans (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			plan_digest TEXT NOT NULL,
			storage_digest TEXT NOT NULL,
			plan_json BLOB NOT NULL,
			requested_unix_nano INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS reboot_plans_node_idx ON reboot_plans (node_id, id)`,
		`CREATE TABLE IF NOT EXISTS reboot_states (
			plan_id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			phase TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			fence INTEGER NOT NULL CHECK (fence > 0),
			controller_id TEXT NOT NULL,
			storage_digest TEXT NOT NULL,
			state_json BLOB NOT NULL,
			updated_unix_nano INTEGER NOT NULL,
			FOREIGN KEY (plan_id) REFERENCES reboot_plans(id)
		)`,
		`CREATE INDEX IF NOT EXISTS reboot_states_phase_idx ON reboot_states (phase, plan_id)`,
		`CREATE TABLE IF NOT EXISTS reboot_node_locks (
			node_id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL UNIQUE,
			fence INTEGER NOT NULL CHECK (fence > 0)
		)`,
		`CREATE TABLE IF NOT EXISTS reboot_receipts (
			id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			idempotency_key TEXT NOT NULL,
			command_digest TEXT NOT NULL,
			storage_digest TEXT NOT NULL,
			receipt_json BLOB NOT NULL,
			created_unix_nano INTEGER NOT NULL,
			UNIQUE (plan_id, idempotency_key),
			FOREIGN KEY (plan_id) REFERENCES reboot_plans(id)
		)`,
		`CREATE INDEX IF NOT EXISTS reboot_receipts_plan_idx ON reboot_receipts (plan_id, id)`,
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

func (repository *Repository) CreatePlan(ctx context.Context, plan Plan, controllerID, idempotencyKey string) (State, Receipt, error) {
	canonical, err := CanonicalPlan(plan)
	if err != nil || !identifierPattern.MatchString(controllerID) || !identifierPattern.MatchString(idempotencyKey) {
		return State{}, Receipt{}, ErrInvalid
	}
	commandDigest := digestStrings("request", canonical.Digest, controllerID, idempotencyKey)
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return State{}, Receipt{}, err
	}
	defer tx.Rollback()
	if receipt, found, err := loadReceiptByKey(ctx, tx, canonical.ID, idempotencyKey); err != nil {
		return State{}, Receipt{}, err
	} else if found {
		if receipt.CommandDigest != commandDigest {
			return State{}, Receipt{}, ErrIntegrity
		}
		state, err := loadStateQuery(ctx, tx, canonical.ID)
		if err != nil {
			return State{}, Receipt{}, err
		}
		if err := tx.Commit(); err != nil {
			return State{}, Receipt{}, err
		}
		return state, receipt, nil
	}
	planRaw, planStorageDigest, err := encodePlan(canonical)
	if err != nil {
		return State{}, Receipt{}, err
	}
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO reboot_plans
		(id, node_id, plan_digest, storage_digest, plan_json, requested_unix_nano)
		VALUES (?, ?, ?, ?, ?, ?)`, canonical.ID, canonical.NodeID, canonical.Digest,
		planStorageDigest, planRaw, canonical.RequestedAt.UnixNano())
	if err != nil {
		return State{}, Receipt{}, err
	}
	if !oneRow(result) {
		stored, loadErr := loadPlanQuery(ctx, tx, canonical.ID)
		if loadErr != nil || stored.Digest != canonical.Digest {
			return State{}, Receipt{}, ErrConflict
		}
		return State{}, Receipt{}, ErrConflict
	}
	receipt, err := buildReceipt(ReceiptRequested, canonical.ID, canonical.NodeID, PhaseRequested,
		PhaseRequested, 1, 1, idempotencyKey, commandDigest, canonical.Digest, OutcomeNone, nil, canonical.RequestedAt)
	if err != nil {
		return State{}, Receipt{}, err
	}
	state := State{PlanID: canonical.ID, NodeID: canonical.NodeID, Phase: PhaseRequested,
		Generation: 1, Fence: 1, ControllerID: controllerID, LastReceiptDigest: receipt.Digest,
		UpdatedAt: canonical.RequestedAt}
	if err := insertState(ctx, tx, state); err != nil {
		return State{}, Receipt{}, err
	}
	if err := insertReceipt(ctx, tx, receipt); err != nil {
		return State{}, Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return State{}, Receipt{}, err
	}
	return state, receipt, nil
}

func (repository *Repository) Transition(ctx context.Context, command Transition) (State, Receipt, error) {
	canonical, commandDigest, err := canonicalTransition(command)
	if err != nil {
		return State{}, Receipt{}, err
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return State{}, Receipt{}, err
	}
	defer tx.Rollback()
	if receipt, found, err := loadReceiptByKey(ctx, tx, canonical.PlanID, canonical.IdempotencyKey); err != nil {
		return State{}, Receipt{}, err
	} else if found {
		if receipt.CommandDigest != commandDigest {
			return State{}, Receipt{}, ErrIntegrity
		}
		state, err := loadStateQuery(ctx, tx, canonical.PlanID)
		if err != nil {
			return State{}, Receipt{}, err
		}
		if err := tx.Commit(); err != nil {
			return State{}, Receipt{}, err
		}
		return state, receipt, nil
	}
	plan, err := loadPlanQuery(ctx, tx, canonical.PlanID)
	if err != nil {
		return State{}, Receipt{}, err
	}
	state, err := loadStateQuery(ctx, tx, canonical.PlanID)
	if err != nil {
		return State{}, Receipt{}, err
	}
	if state.NodeID != plan.NodeID {
		return State{}, Receipt{}, ErrIntegrity
	}
	if state.Generation != canonical.ExpectedGeneration || state.Fence != canonical.Fence || state.ControllerID != canonical.ControllerID || state.Phase != canonical.From {
		return State{}, Receipt{}, ErrConflict
	}
	if canonical.At.Before(state.UpdatedAt) || state.Generation == maxGeneration || !allowedTransition(canonical.From, canonical.To) {
		return State{}, Receipt{}, ErrInvalid
	}
	if canonical.To == PhaseAdmitted {
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO reboot_node_locks (node_id, plan_id, fence) VALUES (?, ?, ?)`, plan.NodeID, plan.ID, state.Fence)
		if err != nil {
			return State{}, Receipt{}, err
		}
		if !oneRow(result) {
			return State{}, Receipt{}, ErrConflict
		}
	} else if state.Phase != PhaseRequested {
		if err := verifyNodeLock(ctx, tx, plan.NodeID, plan.ID, state.Fence); err != nil {
			return State{}, Receipt{}, err
		}
	}
	next := state
	next.Phase = canonical.To
	next.Generation++
	next.UpdatedAt = canonical.At
	if canonical.MarkerDigest != "" {
		next.MarkerDigest = canonical.MarkerDigest
	}
	next.Outcome = canonical.Outcome
	next.RecoverySteps = append([]RecoveryStep(nil), canonical.RecoverySteps...)
	receipt, err := buildReceipt(ReceiptTransition, plan.ID, plan.NodeID, canonical.From, canonical.To,
		next.Generation, next.Fence, canonical.IdempotencyKey, commandDigest, canonical.EvidenceDigest,
		canonical.Outcome, canonical.RecoverySteps, canonical.At)
	if err != nil {
		return State{}, Receipt{}, err
	}
	next.LastReceiptDigest = receipt.Digest
	if canonical.To == PhaseCheckpointed {
		next.CheckpointReceiptDigest = receipt.Digest
	}
	if err := updateStateCAS(ctx, tx, next, state.Generation, state.Fence); err != nil {
		return State{}, Receipt{}, err
	}
	if canonical.To == PhaseSucceeded {
		result, err := tx.ExecContext(ctx, `DELETE FROM reboot_node_locks WHERE node_id = ? AND plan_id = ? AND fence = ?`, plan.NodeID, plan.ID, state.Fence)
		if err != nil {
			return State{}, Receipt{}, err
		}
		if !oneRow(result) {
			return State{}, Receipt{}, ErrIntegrity
		}
	}
	if err := insertReceipt(ctx, tx, receipt); err != nil {
		return State{}, Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return State{}, Receipt{}, err
	}
	return next, receipt, nil
}

// AcquireFence transfers control before arming. Once a marker is armed its
// embedded fence is immutable, so takeover must proceed through recovery.
func (repository *Repository) AcquireFence(ctx context.Context, planID string, expectedGeneration, expectedFence uint64, controllerID, idempotencyKey string, at time.Time) (State, Receipt, error) {
	if !identifierPattern.MatchString(planID) || expectedGeneration == 0 || expectedFence == 0 || !identifierPattern.MatchString(controllerID) || !identifierPattern.MatchString(idempotencyKey) || !validTimestamp(at) {
		return State{}, Receipt{}, ErrInvalid
	}
	commandDigest := digestStrings("fence", planID, controllerID, idempotencyKey,
		uintString(expectedGeneration), uintString(expectedFence), timeString(at))
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return State{}, Receipt{}, err
	}
	defer tx.Rollback()
	if receipt, found, err := loadReceiptByKey(ctx, tx, planID, idempotencyKey); err != nil {
		return State{}, Receipt{}, err
	} else if found {
		if receipt.CommandDigest != commandDigest {
			return State{}, Receipt{}, ErrIntegrity
		}
		state, err := loadStateQuery(ctx, tx, planID)
		if err != nil {
			return State{}, Receipt{}, err
		}
		if err := tx.Commit(); err != nil {
			return State{}, Receipt{}, err
		}
		return state, receipt, nil
	}
	plan, err := loadPlanQuery(ctx, tx, planID)
	if err != nil {
		return State{}, Receipt{}, err
	}
	state, err := loadStateQuery(ctx, tx, planID)
	if err != nil {
		return State{}, Receipt{}, err
	}
	if state.NodeID != plan.NodeID {
		return State{}, Receipt{}, ErrIntegrity
	}
	if state.Generation != expectedGeneration || state.Fence != expectedFence || state.Generation == maxGeneration || state.Fence == maxGeneration || at.Before(state.UpdatedAt) {
		return State{}, Receipt{}, ErrConflict
	}
	if state.Phase != PhaseRequested && state.Phase != PhaseAdmitted && state.Phase != PhaseDraining && state.Phase != PhaseCheckpointed {
		return State{}, Receipt{}, ErrInvalid
	}
	next := state
	next.Generation++
	next.Fence++
	next.ControllerID = controllerID
	next.UpdatedAt = at
	receipt, err := buildReceipt(ReceiptFenceAcquired, plan.ID, plan.NodeID, state.Phase, state.Phase,
		next.Generation, next.Fence, idempotencyKey, commandDigest, plan.Digest, OutcomeNone, nil, at)
	if err != nil {
		return State{}, Receipt{}, err
	}
	next.LastReceiptDigest = receipt.Digest
	if err := updateStateCAS(ctx, tx, next, state.Generation, state.Fence); err != nil {
		return State{}, Receipt{}, err
	}
	if state.Phase != PhaseRequested {
		result, err := tx.ExecContext(ctx, `UPDATE reboot_node_locks SET fence = ? WHERE node_id = ? AND plan_id = ? AND fence = ?`, next.Fence, plan.NodeID, plan.ID, state.Fence)
		if err != nil {
			return State{}, Receipt{}, err
		}
		if !oneRow(result) {
			return State{}, Receipt{}, ErrIntegrity
		}
	}
	if err := insertReceipt(ctx, tx, receipt); err != nil {
		return State{}, Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return State{}, Receipt{}, err
	}
	return next, receipt, nil
}

func (repository *Repository) LoadPlan(ctx context.Context, id string) (Plan, error) {
	if !identifierPattern.MatchString(id) {
		return Plan{}, ErrInvalid
	}
	return loadPlanQuery(ctx, repository.db, id)
}

func (repository *Repository) LoadState(ctx context.Context, planID string) (State, error) {
	if !identifierPattern.MatchString(planID) {
		return State{}, ErrInvalid
	}
	return loadStateQuery(ctx, repository.db, planID)
}

type ReceiptPage struct {
	Receipts   []Receipt
	NextCursor string
}

func (repository *Repository) ListReceipts(ctx context.Context, planID string, limit int, cursor string) (ReceiptPage, error) {
	if !identifierPattern.MatchString(planID) || limit < 1 || limit > MaxPageSize || cursor != "" && !identifierPattern.MatchString(cursor) {
		return ReceiptPage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT id, command_digest, storage_digest, receipt_json
		FROM reboot_receipts WHERE plan_id = ? AND id > ? ORDER BY id LIMIT ?`, planID, cursor, limit+1)
	if err != nil {
		return ReceiptPage{}, err
	}
	defer rows.Close()
	page := ReceiptPage{Receipts: make([]Receipt, 0, limit)}
	for rows.Next() {
		var id, commandDigest, storageDigest string
		var raw []byte
		if err := rows.Scan(&id, &commandDigest, &storageDigest, &raw); err != nil {
			return ReceiptPage{}, err
		}
		receipt, err := decodeReceipt(raw, storageDigest)
		if err != nil || receipt.ID != id || receipt.PlanID != planID || receipt.CommandDigest != commandDigest {
			return ReceiptPage{}, ErrIntegrity
		}
		if len(page.Receipts) == limit {
			page.NextCursor = page.Receipts[len(page.Receipts)-1].ID
			break
		}
		page.Receipts = append(page.Receipts, receipt)
	}
	if err := rows.Err(); err != nil {
		return ReceiptPage{}, err
	}
	return page, nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadPlanQuery(ctx context.Context, query queryer, id string) (Plan, error) {
	var planDigest, storageDigest string
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT plan_digest, storage_digest, plan_json FROM reboot_plans WHERE id = ?`, id).
		Scan(&planDigest, &storageDigest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	if err != nil {
		return Plan{}, err
	}
	if !validDigest(storageDigest) || digestBytes(raw) != storageDigest {
		return Plan{}, ErrIntegrity
	}
	var plan Plan
	if err := json.Unmarshal(raw, &plan); err != nil || plan.ID != id || plan.Digest != planDigest || plan.Validate() != nil {
		return Plan{}, ErrIntegrity
	}
	return plan, nil
}

func loadStateQuery(ctx context.Context, query queryer, planID string) (State, error) {
	var phase string
	var generation, fence uint64
	var storageDigest string
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT phase, generation, fence, storage_digest, state_json FROM reboot_states WHERE plan_id = ?`, planID).
		Scan(&phase, &generation, &fence, &storageDigest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return State{}, ErrNotFound
	}
	if err != nil {
		return State{}, err
	}
	if !validDigest(storageDigest) || digestBytes(raw) != storageDigest {
		return State{}, ErrIntegrity
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil || state.PlanID != planID || string(state.Phase) != phase || state.Generation != generation || state.Fence != fence || state.Validate() != nil {
		return State{}, ErrIntegrity
	}
	return state, nil
}

func loadReceiptByKey(ctx context.Context, query queryer, planID, key string) (Receipt, bool, error) {
	var storageDigest string
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT storage_digest, receipt_json FROM reboot_receipts
		WHERE plan_id = ? AND idempotency_key = ?`, planID, key).Scan(&storageDigest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	receipt, err := decodeReceipt(raw, storageDigest)
	return receipt, err == nil, err
}

func encodePlan(plan Plan) ([]byte, string, error) {
	raw, err := json.Marshal(plan)
	if err != nil {
		return nil, "", err
	}
	return raw, digestBytes(raw), nil
}

func insertState(ctx context.Context, tx *sql.Tx, state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO reboot_states
		(plan_id, node_id, phase, generation, fence, controller_id, storage_digest, state_json, updated_unix_nano)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, state.PlanID, state.NodeID, state.Phase, state.Generation,
		state.Fence, state.ControllerID, digestBytes(raw), raw, state.UpdatedAt.UnixNano())
	return err
}

func updateStateCAS(ctx context.Context, tx *sql.Tx, state State, expectedGeneration, expectedFence uint64) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE reboot_states SET phase = ?, generation = ?, fence = ?,
		controller_id = ?, storage_digest = ?, state_json = ?, updated_unix_nano = ?
		WHERE plan_id = ? AND generation = ? AND fence = ?`, state.Phase, state.Generation, state.Fence,
		state.ControllerID, digestBytes(raw), raw, state.UpdatedAt.UnixNano(), state.PlanID, expectedGeneration, expectedFence)
	if err != nil {
		return err
	}
	if !oneRow(result) {
		return ErrConflict
	}
	return nil
}

func insertReceipt(ctx context.Context, tx *sql.Tx, receipt Receipt) error {
	if err := verifyReceipt(receipt); err != nil {
		return err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO reboot_receipts
		(id, plan_id, idempotency_key, command_digest, storage_digest, receipt_json, created_unix_nano)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, receipt.ID, receipt.PlanID, receipt.IdempotencyKey,
		receipt.CommandDigest, digestBytes(raw), raw, receipt.CreatedAt.UnixNano())
	return err
}

func decodeReceipt(raw []byte, storageDigest string) (Receipt, error) {
	if !validDigest(storageDigest) || digestBytes(raw) != storageDigest {
		return Receipt{}, ErrIntegrity
	}
	var receipt Receipt
	if err := json.Unmarshal(raw, &receipt); err != nil || verifyReceipt(receipt) != nil {
		return Receipt{}, ErrIntegrity
	}
	return receipt, nil
}

func buildReceipt(kind ReceiptKind, planID, nodeID string, from, to Phase, generation, fence uint64,
	idempotencyKey, commandDigest, evidenceDigest string, outcome OutcomeReason, recovery []RecoveryStep, at time.Time) (Receipt, error) {
	id := "rebootrcpt_" + digestStrings(planID, idempotencyKey, commandDigest)[:48]
	receipt := Receipt{ID: id, Kind: kind, PlanID: planID, NodeID: nodeID, From: from, To: to,
		Generation: generation, Fence: fence, IdempotencyKey: idempotencyKey, CommandDigest: commandDigest,
		EvidenceDigest: evidenceDigest, Outcome: outcome, RecoverySteps: append([]RecoveryStep(nil), recovery...), CreatedAt: at}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return Receipt{}, err
	}
	receipt.Digest = digestBytes(raw)
	return receipt, verifyReceipt(receipt)
}

func verifyReceipt(receipt Receipt) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	expectedID := "rebootrcpt_" + digestStrings(receipt.PlanID, receipt.IdempotencyKey, receipt.CommandDigest)[:48]
	if receipt.ID != expectedID {
		return ErrIntegrity
	}
	digest := receipt.Digest
	receipt.Digest = ""
	raw, err := json.Marshal(receipt)
	if err != nil || digestBytes(raw) != digest {
		return ErrIntegrity
	}
	return nil
}

func canonicalTransition(command Transition) (Transition, string, error) {
	command.At = command.At.UTC()
	steps, err := canonicalRecoverySteps(command.RecoverySteps)
	if err != nil {
		return Transition{}, "", err
	}
	command.RecoverySteps = steps
	if !identifierPattern.MatchString(command.PlanID) || !command.From.Valid() || !command.To.Valid() || command.ExpectedGeneration == 0 || command.ExpectedGeneration >= maxGeneration || command.Fence == 0 || command.Fence > maxGeneration || !identifierPattern.MatchString(command.ControllerID) || !identifierPattern.MatchString(command.IdempotencyKey) || !validDigest(command.EvidenceDigest) || command.MarkerDigest != "" && !validDigest(command.MarkerDigest) || !command.Outcome.Valid() || !validTimestamp(command.At) {
		return Transition{}, "", ErrInvalid
	}
	if command.To == PhaseArmed && command.MarkerDigest == "" || command.To.Terminal() && command.Outcome == OutcomeNone || !command.To.Terminal() && (command.Outcome != OutcomeNone || len(command.RecoverySteps) != 0) {
		return Transition{}, "", ErrInvalid
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return Transition{}, "", err
	}
	return command, digestBytes(raw), nil
}

func allowedTransition(from, to Phase) bool {
	if from.Terminal() {
		return false
	}
	if to == PhaseFailed || to == PhaseUncertain {
		return true
	}
	switch from {
	case PhaseRequested:
		return to == PhaseAdmitted
	case PhaseAdmitted:
		return to == PhaseDraining
	case PhaseDraining:
		return to == PhaseCheckpointed
	case PhaseCheckpointed:
		return to == PhaseArmed
	case PhaseArmed:
		return to == PhaseRebootDispatched
	case PhaseRebootDispatched:
		return to == PhaseReconciling
	case PhaseReconciling:
		return to == PhaseSucceeded
	default:
		return false
	}
}

func digestStrings(values ...string) string {
	return digestBytes([]byte(strings.Join(values, "\x00")))
}

func uintString(value uint64) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func timeString(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func oneRow(result sql.Result) bool {
	count, err := result.RowsAffected()
	return err == nil && count == 1
}

func verifyNodeLock(ctx context.Context, query queryer, nodeID, planID string, fence uint64) error {
	var storedPlan string
	var storedFence uint64
	err := query.QueryRowContext(ctx, `SELECT plan_id, fence FROM reboot_node_locks WHERE node_id = ?`, nodeID).Scan(&storedPlan, &storedFence)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (storedPlan != planID || storedFence != fence) {
		return ErrIntegrity
	}
	return err
}
