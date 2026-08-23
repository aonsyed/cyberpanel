package diagnosticsrepair

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

type Repository struct { db *sql.DB }

func NewRepository(db *sql.DB) (*Repository, error) { if db == nil { return nil, ErrInvalid }; return &Repository{db}, nil }

func (repository *Repository) Bootstrap(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS diagnostic_runs (
			id TEXT PRIMARY KEY, scope_key TEXT NOT NULL, state TEXT NOT NULL, run_digest TEXT NOT NULL UNIQUE,
			storage_digest TEXT NOT NULL, run_json BLOB NOT NULL, completed_unix_nano INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS diagnostic_runs_scope_idx ON diagnostic_runs (scope_key, completed_unix_nano, id)`,
		`CREATE TABLE IF NOT EXISTS diagnostic_findings (
			run_id TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, code TEXT NOT NULL,
			storage_digest TEXT NOT NULL, finding_json BLOB NOT NULL, PRIMARY KEY (run_id, id),
			FOREIGN KEY (run_id) REFERENCES diagnostic_runs(id))`,
		`CREATE INDEX IF NOT EXISTS diagnostic_findings_query_idx ON diagnostic_findings (run_id, kind, severity, id)`,
		`CREATE TABLE IF NOT EXISTS repair_plans (
			id TEXT PRIMARY KEY, run_id TEXT NOT NULL, scope_key TEXT NOT NULL, owner_id TEXT NOT NULL, controller_id TEXT NOT NULL,
			definition_digest TEXT NOT NULL UNIQUE, state TEXT NOT NULL, generation INTEGER NOT NULL CHECK (generation > 0),
			fence INTEGER NOT NULL CHECK (fence > 0), storage_digest TEXT NOT NULL, plan_json BLOB NOT NULL,
			updated_unix_nano INTEGER NOT NULL, FOREIGN KEY (run_id) REFERENCES diagnostic_runs(id))`,
		`CREATE INDEX IF NOT EXISTS repair_plans_query_idx ON repair_plans (state, updated_unix_nano, id)`,
		`CREATE TABLE IF NOT EXISTS repair_scope_locks (
			scope_key TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, fence INTEGER NOT NULL CHECK (fence > 0))`,
		`CREATE TABLE IF NOT EXISTS repair_approvals (
			id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, definition_digest TEXT NOT NULL, storage_digest TEXT NOT NULL,
			approval_json BLOB NOT NULL, approved_unix_nano INTEGER NOT NULL, FOREIGN KEY (plan_id) REFERENCES repair_plans(id))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS repair_approvals_plan_idx ON repair_approvals (plan_id)`,
		`CREATE TABLE IF NOT EXISTS repair_receipts (
			id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, kind TEXT NOT NULL,
			command_digest TEXT NOT NULL, storage_digest TEXT NOT NULL, receipt_json BLOB NOT NULL,
			created_unix_nano INTEGER NOT NULL, UNIQUE (plan_id, idempotency_key), FOREIGN KEY (plan_id) REFERENCES repair_plans(id))`,
		`CREATE INDEX IF NOT EXISTS repair_receipts_plan_idx ON repair_receipts (plan_id, id)`,
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	for _, statement := range statements { if _, err := tx.ExecContext(ctx, statement); err != nil { return err } }
	return tx.Commit()
}

func (repository *Repository) SaveRun(ctx context.Context, run DiagnosticRun) error {
	run, err := verifyStoredRun(run)
	if err != nil { return err }
	raw, storage, err := encodeStored(run)
	if err != nil || len(raw) > 16<<20 { if err != nil { return err }; return ErrCapacity }
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO diagnostic_runs
		(id, scope_key, state, run_digest, storage_digest, run_json, completed_unix_nano) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		run.ID, run.Scope.key(), run.State, run.Digest, storage, raw, run.CompletedAt.UnixNano())
	if err != nil { return err }
	if !oneRow(result) {
		stored, err := loadRun(ctx, tx, run.ID)
		if err != nil || stored.Digest != run.Digest { return ErrConflict }
		return tx.Commit()
	}
	for _, observation := range run.Observations {
		for _, finding := range observation.Findings {
			findingRaw, findingStorage, err := encodeStored(finding)
			if err != nil { return err }
			if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_findings
				(run_id, id, kind, severity, code, storage_digest, finding_json) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				run.ID, finding.ID, finding.Kind, finding.Severity, finding.Code, findingStorage, findingRaw); err != nil { return err }
		}
	}
	return tx.Commit()
}

func (repository *Repository) GetRun(ctx context.Context, runID string) (DiagnosticRun, error) {
	if !identifierPattern.MatchString(runID) { return DiagnosticRun{}, ErrInvalid }
	return loadRun(ctx, repository.db, runID)
}

func (repository *Repository) ListRuns(ctx context.Context, scope Scope, afterCompleted time.Time, afterID string, limit int) ([]DiagnosticRun, error) {
	if scope.Validate() != nil || !validTime(afterCompleted) || afterID != "" && !identifierPattern.MatchString(afterID) || limit <= 0 || limit > MaxPageSize { return nil, ErrInvalid }
	rows, err := repository.db.QueryContext(ctx, `SELECT storage_digest, run_json FROM diagnostic_runs
		WHERE scope_key = ? AND (completed_unix_nano > ? OR (completed_unix_nano = ? AND id > ?))
		ORDER BY completed_unix_nano, id LIMIT ?`, scope.key(), afterCompleted.UTC().UnixNano(), afterCompleted.UTC().UnixNano(), afterID, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	runs := make([]DiagnosticRun, 0, limit)
	for rows.Next() {
		var storage string
		var raw []byte
		if err := rows.Scan(&storage, &raw); err != nil { return nil, err }
		run, err := decodeRun(raw, storage)
		if err != nil { return nil, err }
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (repository *Repository) QueryFindings(ctx context.Context, runID string, kind DiagnosticKind, severity Severity, afterID string, limit int) ([]Finding, error) {
	if !identifierPattern.MatchString(runID) || kind != "" && !kind.Valid() || severity != "" && !severity.Valid() ||
		afterID != "" && !validDigest(afterID) || limit <= 0 || limit > MaxPageSize { return nil, ErrInvalid }
	rows, err := repository.db.QueryContext(ctx, `SELECT storage_digest, finding_json FROM diagnostic_findings
		WHERE run_id = ? AND (? = '' OR kind = ?) AND (? = '' OR severity = ?) AND id > ? ORDER BY id LIMIT ?`,
		runID, string(kind), string(kind), string(severity), string(severity), afterID, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	findings := make([]Finding, 0, limit)
	for rows.Next() {
		var storage string
		var raw []byte
		if err := rows.Scan(&storage, &raw); err != nil { return nil, err }
		if digestBytes(raw) != storage { return nil, ErrIntegrity }
		var finding Finding
		if json.Unmarshal(raw, &finding) != nil { return nil, ErrIntegrity }
		canonical, err := canonicalFinding(finding, 32)
		if err != nil || canonical.ID != finding.ID || canonical.Digest != finding.Digest { return nil, ErrIntegrity }
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

type Approval struct {
	ID                  string    `json:"id"`
	PlanID              string    `json:"plan_id"`
	DefinitionDigest    string    `json:"definition_digest"`
	OwnerID             string    `json:"owner_id"`
	Approver             string    `json:"approver"`
	HighAssurance        bool      `json:"high_assurance"`
	StepUpProofDigest    string    `json:"step_up_proof_digest"`
	DecisionDigest       string    `json:"decision_digest"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	Digest               string    `json:"digest"`
}

func CanonicalApproval(approval Approval, plan RepairPlan, now time.Time) (Approval, error) {
	if !identifierPattern.MatchString(approval.ID) || approval.PlanID != plan.ID || approval.DefinitionDigest != plan.DefinitionDigest ||
		approval.OwnerID != plan.OwnerID || !identifierPattern.MatchString(approval.Approver) || !approval.HighAssurance ||
		!validDigest(approval.StepUpProofDigest) || approval.DecisionDigest != digestParts("approve-repair", plan.DefinitionDigest, plan.OwnerID) ||
		!validTime(approval.IssuedAt) || !validTime(approval.ExpiresAt) || !approval.ExpiresAt.After(approval.IssuedAt) ||
		now.Before(approval.IssuedAt) || !now.Before(approval.ExpiresAt) { return Approval{}, ErrUnauthorized }
	approval.IssuedAt, approval.ExpiresAt = approval.IssuedAt.UTC(), approval.ExpiresAt.UTC()
	claimed := approval.Digest
	approval.Digest = ""
	digest, err := digestJSON(approval)
	if err != nil || claimed != digest { return Approval{}, ErrIntegrity }
	approval.Digest = digest
	return approval, nil
}

func (repository *Repository) GetApproval(ctx context.Context, planID string) (Approval, error) {
	if !identifierPattern.MatchString(planID) { return Approval{}, ErrInvalid }
	var storage string
	var raw []byte
	err := repository.db.QueryRowContext(ctx, `SELECT storage_digest, approval_json FROM repair_approvals
		WHERE plan_id = ? ORDER BY approved_unix_nano DESC, id DESC LIMIT 1`, planID).Scan(&storage, &raw)
	if errors.Is(err, sql.ErrNoRows) { return Approval{}, ErrNotFound }
	if err != nil { return Approval{}, err }
	return decodeApproval(raw, storage)
}

type ReceiptKind string

const (
	ReceiptPlanCreated   ReceiptKind = "plan_created"
	ReceiptApproved      ReceiptKind = "approved"
	ReceiptExecution     ReceiptKind = "execution_started"
	ReceiptSnapshot      ReceiptKind = "snapshot"
	ReceiptStep          ReceiptKind = "step"
	ReceiptCompensation  ReceiptKind = "compensation"
	ReceiptSucceeded     ReceiptKind = "succeeded"
	ReceiptRolledBack    ReceiptKind = "rolled_back"
	ReceiptFailed        ReceiptKind = "failed"
	ReceiptUncertain     ReceiptKind = "uncertain"
	ReceiptFenced        ReceiptKind = "fenced"
)

func (kind ReceiptKind) Valid() bool {
	switch kind {
	case ReceiptPlanCreated, ReceiptApproved, ReceiptExecution, ReceiptSnapshot, ReceiptStep, ReceiptCompensation,
		ReceiptSucceeded, ReceiptRolledBack, ReceiptFailed, ReceiptUncertain, ReceiptFenced: return true
	default: return false
	}
}

type Receipt struct {
	ID             string      `json:"id"`
	PlanID         string      `json:"plan_id"`
	Kind           ReceiptKind `json:"kind"`
	StepID         string      `json:"step_id,omitempty"`
	From           PlanState   `json:"from"`
	To             PlanState   `json:"to"`
	Generation     uint64      `json:"generation"`
	Fence          uint64      `json:"fence"`
	IdempotencyKey string      `json:"idempotency_key"`
	CommandDigest  string      `json:"command_digest"`
	EvidenceDigest string      `json:"evidence_digest"`
	CreatedAt      time.Time   `json:"created_at"`
	Digest         string      `json:"digest"`
}

func (repository *Repository) createPlan(ctx context.Context, plan RepairPlan, idempotencyKey string) (RepairPlan, Receipt, error) {
	plan, err := CanonicalPlan(plan)
	if err != nil || plan.State != PlanPreview || plan.Generation != 1 || plan.Fence != 1 || !identifierPattern.MatchString(idempotencyKey) { return RepairPlan{}, Receipt{}, ErrInvalid }
	commandDigest := digestParts("create-plan", plan.DefinitionDigest, idempotencyKey)
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return RepairPlan{}, Receipt{}, err }
	defer tx.Rollback()
	if receipt, found, err := loadReceiptByKey(ctx, tx, plan.ID, idempotencyKey); err != nil { return RepairPlan{}, Receipt{}, err
	} else if found {
		if receipt.CommandDigest != commandDigest { return RepairPlan{}, Receipt{}, ErrIntegrity }
		stored, err := loadPlan(ctx, tx, plan.ID)
		if err := tx.Commit(); err != nil { return RepairPlan{}, Receipt{}, err }
		return stored, receipt, err
	}
	if _, err := loadRun(ctx, tx, plan.RunID); err != nil { return RepairPlan{}, Receipt{}, err }
	receipt, err := buildReceipt(plan, ReceiptPlanCreated, "", PlanPreview, idempotencyKey, commandDigest, plan.DefinitionDigest, plan.CreatedAt)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	plan.LastReceiptDigest = receipt.Digest
	plan.Digest = ""
	plan, err = CanonicalPlan(plan)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	raw, storage, err := encodeStored(plan)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	_, err = tx.ExecContext(ctx, `INSERT INTO repair_plans
		(id, run_id, scope_key, owner_id, controller_id, definition_digest, state, generation, fence, storage_digest, plan_json, updated_unix_nano)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, plan.ID, plan.RunID, plan.Scope.key(), plan.OwnerID, plan.ControllerID, plan.DefinitionDigest,
		plan.State, plan.Generation, plan.Fence, storage, raw, plan.UpdatedAt.UnixNano())
	if err != nil { return RepairPlan{}, Receipt{}, err }
	if err := insertReceipt(ctx, tx, receipt); err != nil { return RepairPlan{}, Receipt{}, err }
	if err := tx.Commit(); err != nil { return RepairPlan{}, Receipt{}, err }
	return plan, receipt, nil
}

func (repository *Repository) approve(ctx context.Context, planID string, expectedGeneration, fence uint64, approval Approval,
	idempotencyKey string, at time.Time) (RepairPlan, Receipt, error) {
	if !identifierPattern.MatchString(planID) || expectedGeneration == 0 || fence == 0 || !identifierPattern.MatchString(idempotencyKey) || !validTime(at) { return RepairPlan{}, Receipt{}, ErrInvalid }
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return RepairPlan{}, Receipt{}, err }
	defer tx.Rollback()
	plan, err := loadPlan(ctx, tx, planID)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	approval, err = CanonicalApproval(approval, plan, at.UTC())
	if err != nil { return RepairPlan{}, Receipt{}, err }
	commandDigest := digestParts("approve", plan.DefinitionDigest, approval.Digest, idempotencyKey)
	if receipt, found, err := loadReceiptByKey(ctx, tx, plan.ID, idempotencyKey); err != nil { return RepairPlan{}, Receipt{}, err
	} else if found {
		if receipt.CommandDigest != commandDigest { return RepairPlan{}, Receipt{}, ErrIntegrity }
		if err := tx.Commit(); err != nil { return RepairPlan{}, Receipt{}, err }
		return plan, receipt, nil
	}
	if plan.State != PlanPreview || plan.Generation != expectedGeneration || plan.Fence != fence { return RepairPlan{}, Receipt{}, ErrConflict }
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO repair_scope_locks (scope_key, plan_id, fence) VALUES (?, ?, ?)`, plan.Scope.key(), plan.ID, plan.Fence)
	if err != nil || !oneRow(result) { return RepairPlan{}, Receipt{}, ErrConflict }
	approvalRaw, approvalStorage, err := encodeStored(approval)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	if _, err := tx.ExecContext(ctx, `INSERT INTO repair_approvals
		(id, plan_id, definition_digest, storage_digest, approval_json, approved_unix_nano) VALUES (?, ?, ?, ?, ?, ?)`,
		approval.ID, plan.ID, plan.DefinitionDigest, approvalStorage, approvalRaw, approval.IssuedAt.UnixNano()); err != nil { return RepairPlan{}, Receipt{}, err }
	return transitionInTx(ctx, tx, plan, planTransition{ExpectedGeneration: expectedGeneration, Fence: fence,
		From: PlanPreview, To: PlanApproved, Kind: ReceiptApproved, IdempotencyKey: idempotencyKey,
		CommandDigest: commandDigest, EvidenceDigest: approval.Digest, At: at.UTC()}, true)
}

type planTransition struct {
	ExpectedGeneration uint64
	Fence              uint64
	From               PlanState
	To                 PlanState
	Kind               ReceiptKind
	StepID             string
	IdempotencyKey     string
	CommandDigest      string
	EvidenceDigest     string
	AmbiguousEvidence  string
	RecoverySteps      []string
	SnapshotReference  string
	SnapshotEvidence   string
	Execution          *StepExecution
	Compensation       *StepExecution
	At                 time.Time
}

func (repository *Repository) transition(ctx context.Context, planID string, command planTransition) (RepairPlan, Receipt, error) {
	if !identifierPattern.MatchString(planID) { return RepairPlan{}, Receipt{}, ErrInvalid }
	command, err := canonicalPlanTransition(command)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return RepairPlan{}, Receipt{}, err }
	defer tx.Rollback()
	if receipt, found, err := loadReceiptByKey(ctx, tx, planID, command.IdempotencyKey); err != nil { return RepairPlan{}, Receipt{}, err
	} else if found {
		if receipt.CommandDigest != command.CommandDigest { return RepairPlan{}, Receipt{}, ErrIntegrity }
		plan, err := loadPlan(ctx, tx, planID)
		if err := tx.Commit(); err != nil { return RepairPlan{}, Receipt{}, err }
		return plan, receipt, err
	}
	plan, err := loadPlan(ctx, tx, planID)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	return transitionInTx(ctx, tx, plan, command, true)
}

func (repository *Repository) fence(ctx context.Context, planID, fromController, toController, idempotencyKey string,
	expectedGeneration, expectedFence uint64, evidenceDigest string, at time.Time) (RepairPlan, Receipt, error) {
	if !identifierPattern.MatchString(planID) || !identifierPattern.MatchString(fromController) || !identifierPattern.MatchString(toController) ||
		!identifierPattern.MatchString(idempotencyKey) || expectedGeneration == 0 || expectedGeneration >= maxGeneration ||
		expectedFence == 0 || expectedFence >= maxGeneration || !validDigest(evidenceDigest) || !validTime(at) { return RepairPlan{}, Receipt{}, ErrInvalid }
	at = at.UTC()
	commandDigest := digestParts("fence-plan", planID, fromController, toController, uintString(expectedGeneration), uintString(expectedFence), evidenceDigest)
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return RepairPlan{}, Receipt{}, err }
	defer tx.Rollback()
	if receipt, found, err := loadReceiptByKey(ctx, tx, planID, idempotencyKey); err != nil { return RepairPlan{}, Receipt{}, err
	} else if found {
		if receipt.CommandDigest != commandDigest { return RepairPlan{}, Receipt{}, ErrIntegrity }
		plan, err := loadPlan(ctx, tx, planID)
		if err := tx.Commit(); err != nil { return RepairPlan{}, Receipt{}, err }
		return plan, receipt, err
	}
	plan, err := loadPlan(ctx, tx, planID)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	if plan.Generation != expectedGeneration || plan.Fence != expectedFence || plan.ControllerID != fromController ||
		plan.State != PlanPreview && plan.State != PlanApproved && plan.State != PlanExecuting { return RepairPlan{}, Receipt{}, ErrConflict }
	next := plan
	next.Generation, next.Fence, next.ControllerID, next.UpdatedAt = plan.Generation+1, plan.Fence+1, toController, at
	receipt, err := buildReceipt(next, ReceiptFenced, "", plan.State, idempotencyKey, commandDigest, evidenceDigest, at)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	next.LastReceiptDigest, next.Digest = receipt.Digest, ""
	next, err = CanonicalPlan(next)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	if plan.State != PlanPreview {
		result, err := tx.ExecContext(ctx, `UPDATE repair_scope_locks SET fence = ? WHERE scope_key = ? AND plan_id = ? AND fence = ?`,
			next.Fence, plan.Scope.key(), plan.ID, plan.Fence)
		if err != nil || !oneRow(result) { return RepairPlan{}, Receipt{}, ErrConflict }
	}
	raw, storage, err := encodeStored(next)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	result, err := tx.ExecContext(ctx, `UPDATE repair_plans SET generation = ?, fence = ?, controller_id = ?, storage_digest = ?, plan_json = ?, updated_unix_nano = ?
		WHERE id = ? AND generation = ? AND fence = ? AND controller_id = ?`, next.Generation, next.Fence, next.ControllerID,
		storage, raw, next.UpdatedAt.UnixNano(), plan.ID, plan.Generation, plan.Fence, plan.ControllerID)
	if err != nil || !oneRow(result) { return RepairPlan{}, Receipt{}, ErrConflict }
	if err := insertReceipt(ctx, tx, receipt); err != nil { return RepairPlan{}, Receipt{}, err }
	if err := tx.Commit(); err != nil { return RepairPlan{}, Receipt{}, err }
	return next, receipt, nil
}

func transitionInTx(ctx context.Context, tx *sql.Tx, plan RepairPlan, command planTransition, commit bool) (RepairPlan, Receipt, error) {
	if plan.Generation != command.ExpectedGeneration || plan.Fence != command.Fence || plan.State != command.From ||
		plan.Generation >= maxGeneration || !validPlanTransition(command.From, command.To, command.Kind) { return RepairPlan{}, Receipt{}, ErrConflict }
	next := plan
	next.State, next.Generation, next.UpdatedAt = command.To, plan.Generation+1, command.At
	if command.AmbiguousEvidence != "" { next.AmbiguousEvidence = command.AmbiguousEvidence }
	if len(command.RecoverySteps) > 0 { next.RecoverySteps = append([]string(nil), command.RecoverySteps...) }
	if command.SnapshotReference != "" { next.SnapshotReference, next.SnapshotEvidence = command.SnapshotReference, command.SnapshotEvidence }
	if command.Execution != nil { next.ExecutedSteps = append(next.ExecutedSteps, *command.Execution) }
	if command.Compensation != nil { next.CompensatedSteps = append(next.CompensatedSteps, *command.Compensation) }
	receipt, err := buildReceipt(next, command.Kind, command.StepID, command.From, command.IdempotencyKey,
		command.CommandDigest, command.EvidenceDigest, command.At)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	next.LastReceiptDigest = receipt.Digest
	next.Digest = ""
	next, err = CanonicalPlan(next)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	raw, storage, err := encodeStored(next)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	result, err := tx.ExecContext(ctx, `UPDATE repair_plans SET state = ?, generation = ?, fence = ?, controller_id = ?, storage_digest = ?, plan_json = ?, updated_unix_nano = ?
		WHERE id = ? AND generation = ? AND fence = ? AND controller_id = ?`, next.State, next.Generation, next.Fence, next.ControllerID, storage, raw,
		next.UpdatedAt.UnixNano(), next.ID, plan.Generation, plan.Fence, plan.ControllerID)
	if err != nil || !oneRow(result) { return RepairPlan{}, Receipt{}, ErrConflict }
	if err := insertReceipt(ctx, tx, receipt); err != nil { return RepairPlan{}, Receipt{}, err }
	if next.State == PlanSucceeded || next.State == PlanRolledBack || next.State == PlanFailed {
		result, err := tx.ExecContext(ctx, `DELETE FROM repair_scope_locks WHERE scope_key = ? AND plan_id = ? AND fence = ?`, next.Scope.key(), next.ID, next.Fence)
		if err != nil || !oneRow(result) { return RepairPlan{}, Receipt{}, ErrIntegrity }
	}
	if commit { if err := tx.Commit(); err != nil { return RepairPlan{}, Receipt{}, err } }
	return next, receipt, nil
}

func canonicalPlanTransition(command planTransition) (planTransition, error) {
	if command.ExpectedGeneration == 0 || command.ExpectedGeneration >= maxGeneration || command.Fence == 0 || command.Fence > maxGeneration ||
		!command.From.Valid() || !command.To.Valid() || !command.Kind.Valid() || !identifierPattern.MatchString(command.IdempotencyKey) ||
		!validDigest(command.CommandDigest) || !validDigest(command.EvidenceDigest) || command.StepID != "" && !validDigest(command.StepID) ||
		command.AmbiguousEvidence != "" && !validDigest(command.AmbiguousEvidence) || len(command.RecoverySteps) > 32 || !validTime(command.At) {
		return planTransition{}, ErrInvalid
	}
	if command.SnapshotReference != "" && (!identifierPattern.MatchString(command.SnapshotReference) || !validDigest(command.SnapshotEvidence)) { return planTransition{}, ErrInvalid }
	if command.Execution != nil && (!validDigest(command.Execution.StepID) || !validDigest(command.Execution.ReceiptDigest) || !validDigest(command.Execution.EvidenceDigest)) { return planTransition{}, ErrInvalid }
	if command.Compensation != nil && (!validDigest(command.Compensation.StepID) || !validDigest(command.Compensation.ReceiptDigest) || !validDigest(command.Compensation.EvidenceDigest)) { return planTransition{}, ErrInvalid }
	if command.Kind == ReceiptSnapshot && command.SnapshotReference == "" || command.Kind != ReceiptSnapshot && command.SnapshotReference != "" ||
		command.Kind == ReceiptStep && command.Execution == nil || command.Kind != ReceiptStep && command.Execution != nil ||
		command.Kind == ReceiptCompensation && command.Compensation == nil || command.Kind != ReceiptCompensation && command.Compensation != nil { return planTransition{}, ErrInvalid }
	command.RecoverySteps = append([]string(nil), command.RecoverySteps...)
	sort.Strings(command.RecoverySteps)
	for index, step := range command.RecoverySteps {
		if !identifierPattern.MatchString(step) || index > 0 && command.RecoverySteps[index-1] == step { return planTransition{}, ErrInvalid }
	}
	command.At = command.At.UTC()
	return command, nil
}

func validPlanTransition(from, to PlanState, kind ReceiptKind) bool {
	if from == PlanPreview && to == PlanApproved { return kind == ReceiptApproved }
	if from == PlanApproved && to == PlanExecuting { return kind == ReceiptExecution }
	if from != PlanExecuting { return false }
	if to == PlanExecuting { return kind == ReceiptSnapshot || kind == ReceiptStep || kind == ReceiptCompensation }
	if to == PlanSucceeded { return kind == ReceiptSucceeded }
	if to == PlanRolledBack { return kind == ReceiptRolledBack }
	if to == PlanFailed { return kind == ReceiptFailed }
	return to == PlanUncertain && kind == ReceiptUncertain
}

func (repository *Repository) GetPlan(ctx context.Context, planID string) (RepairPlan, error) {
	if !identifierPattern.MatchString(planID) { return RepairPlan{}, ErrInvalid }
	return loadPlan(ctx, repository.db, planID)
}

func (repository *Repository) ListPlans(ctx context.Context, state PlanState, afterUpdated time.Time, afterID string, limit int) ([]RepairPlan, error) {
	if state != "" && !state.Valid() || !validTime(afterUpdated) || afterID != "" && !identifierPattern.MatchString(afterID) || limit <= 0 || limit > MaxPageSize { return nil, ErrInvalid }
	rows, err := repository.db.QueryContext(ctx, `SELECT storage_digest, plan_json FROM repair_plans
		WHERE (? = '' OR state = ?) AND (updated_unix_nano > ? OR (updated_unix_nano = ? AND id > ?))
		ORDER BY updated_unix_nano, id LIMIT ?`, string(state), string(state), afterUpdated.UTC().UnixNano(), afterUpdated.UTC().UnixNano(), afterID, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	plans := make([]RepairPlan, 0, limit)
	for rows.Next() {
		var storage string
		var raw []byte
		if err := rows.Scan(&storage, &raw); err != nil { return nil, err }
		plan, err := decodePlan(raw, storage)
		if err != nil { return nil, err }
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}

func (repository *Repository) ListReceipts(ctx context.Context, planID, afterID string, limit int) ([]Receipt, error) {
	if !identifierPattern.MatchString(planID) || afterID != "" && !validDigest(afterID) || limit <= 0 || limit > MaxPageSize { return nil, ErrInvalid }
	rows, err := repository.db.QueryContext(ctx, `SELECT storage_digest, receipt_json FROM repair_receipts
		WHERE plan_id = ? AND id > ? ORDER BY id LIMIT ?`, planID, afterID, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	receipts := make([]Receipt, 0, limit)
	for rows.Next() {
		var storage string
		var raw []byte
		if err := rows.Scan(&storage, &raw); err != nil { return nil, err }
		receipt, err := decodeReceipt(raw, storage)
		if err != nil { return nil, err }
		receipts = append(receipts, receipt)
	}
	return receipts, rows.Err()
}

type queryer interface { QueryRowContext(context.Context, string, ...any) *sql.Row }

func loadRun(ctx context.Context, query queryer, id string) (DiagnosticRun, error) {
	var storage string
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT storage_digest, run_json FROM diagnostic_runs WHERE id = ?`, id).Scan(&storage, &raw)
	if errors.Is(err, sql.ErrNoRows) { return DiagnosticRun{}, ErrNotFound }
	if err != nil { return DiagnosticRun{}, err }
	return decodeRun(raw, storage)
}

func decodeRun(raw []byte, storage string) (DiagnosticRun, error) {
	if digestBytes(raw) != storage { return DiagnosticRun{}, ErrIntegrity }
	var run DiagnosticRun
	if json.Unmarshal(raw, &run) != nil { return DiagnosticRun{}, ErrIntegrity }
	return verifyStoredRun(run)
}

func verifyStoredRun(run DiagnosticRun) (DiagnosticRun, error) {
	run, err := CanonicalRun(run)
	if err != nil { return DiagnosticRun{}, err }
	for observationIndex := range run.Observations {
		observation := run.Observations[observationIndex]
		for findingIndex := range observation.Findings {
			canonical, err := canonicalFinding(observation.Findings[findingIndex], 32)
			if err != nil || canonical.ID != observation.Findings[findingIndex].ID || canonical.Digest != observation.Findings[findingIndex].Digest { return DiagnosticRun{}, ErrIntegrity }
		}
		claimed := observation.Digest
		observation.Digest = ""
		digest, err := digestJSON(observation)
		if err != nil || claimed != digest { return DiagnosticRun{}, ErrIntegrity }
	}
	return run, nil
}

func loadPlan(ctx context.Context, query queryer, id string) (RepairPlan, error) {
	var storage string
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT storage_digest, plan_json FROM repair_plans WHERE id = ?`, id).Scan(&storage, &raw)
	if errors.Is(err, sql.ErrNoRows) { return RepairPlan{}, ErrNotFound }
	if err != nil { return RepairPlan{}, err }
	return decodePlan(raw, storage)
}

func decodePlan(raw []byte, storage string) (RepairPlan, error) {
	if digestBytes(raw) != storage { return RepairPlan{}, ErrIntegrity }
	var plan RepairPlan
	if json.Unmarshal(raw, &plan) != nil { return RepairPlan{}, ErrIntegrity }
	return CanonicalPlan(plan)
}

func loadReceiptByKey(ctx context.Context, query queryer, planID, key string) (Receipt, bool, error) {
	var storage string
	var raw []byte
	err := query.QueryRowContext(ctx, `SELECT storage_digest, receipt_json FROM repair_receipts WHERE plan_id = ? AND idempotency_key = ?`, planID, key).Scan(&storage, &raw)
	if errors.Is(err, sql.ErrNoRows) { return Receipt{}, false, nil }
	if err != nil { return Receipt{}, false, err }
	receipt, err := decodeReceipt(raw, storage)
	return receipt, true, err
}

func buildReceipt(plan RepairPlan, kind ReceiptKind, stepID string, from PlanState, key, commandDigest, evidence string, at time.Time) (Receipt, error) {
	receipt := Receipt{PlanID: plan.ID, Kind: kind, StepID: stepID, From: from, To: plan.State,
		Generation: plan.Generation, Fence: plan.Fence, IdempotencyKey: key, CommandDigest: commandDigest,
		EvidenceDigest: evidence, CreatedAt: at.UTC()}
	receipt.ID = digestParts("repair-receipt", plan.ID, key, commandDigest)
	digest, err := digestJSON(receipt)
	if err != nil { return Receipt{}, err }
	receipt.Digest = digest
	return receipt, nil
}

func decodeReceipt(raw []byte, storage string) (Receipt, error) {
	if digestBytes(raw) != storage { return Receipt{}, ErrIntegrity }
	var receipt Receipt
	if json.Unmarshal(raw, &receipt) != nil { return Receipt{}, ErrIntegrity }
	claimed := receipt.Digest
	receipt.Digest = ""
	digest, err := digestJSON(receipt)
	receipt.Digest = claimed
	if err != nil || claimed != digest || !validDigest(receipt.ID) || !identifierPattern.MatchString(receipt.PlanID) ||
		!receipt.Kind.Valid() || receipt.StepID != "" && !validDigest(receipt.StepID) || !receipt.From.Valid() || !receipt.To.Valid() ||
		receipt.Generation == 0 || receipt.Fence == 0 || !identifierPattern.MatchString(receipt.IdempotencyKey) ||
		!validDigest(receipt.CommandDigest) || !validDigest(receipt.EvidenceDigest) || !validTime(receipt.CreatedAt) { return Receipt{}, ErrIntegrity }
	return receipt, nil
}

func decodeApproval(raw []byte, storage string) (Approval, error) {
	if digestBytes(raw) != storage { return Approval{}, ErrIntegrity }
	var approval Approval
	if json.Unmarshal(raw, &approval) != nil { return Approval{}, ErrIntegrity }
	claimed := approval.Digest
	approval.Digest = ""
	digest, err := digestJSON(approval)
	approval.Digest = claimed
	if err != nil || claimed != digest || !identifierPattern.MatchString(approval.ID) ||
		!identifierPattern.MatchString(approval.PlanID) || !validDigest(approval.DefinitionDigest) ||
		!identifierPattern.MatchString(approval.OwnerID) || !identifierPattern.MatchString(approval.Approver) ||
		!approval.HighAssurance || !validDigest(approval.StepUpProofDigest) || !validDigest(approval.DecisionDigest) ||
		!validTime(approval.IssuedAt) || !validTime(approval.ExpiresAt) || !approval.ExpiresAt.After(approval.IssuedAt) { return Approval{}, ErrIntegrity }
	approval.IssuedAt, approval.ExpiresAt = approval.IssuedAt.UTC(), approval.ExpiresAt.UTC()
	return approval, nil
}

func insertReceipt(ctx context.Context, tx *sql.Tx, receipt Receipt) error {
	raw, storage, err := encodeStored(receipt)
	if err != nil { return err }
	_, err = tx.ExecContext(ctx, `INSERT INTO repair_receipts
		(id, plan_id, idempotency_key, kind, command_digest, storage_digest, receipt_json, created_unix_nano)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, receipt.ID, receipt.PlanID, receipt.IdempotencyKey, receipt.Kind,
		receipt.CommandDigest, storage, raw, receipt.CreatedAt.UnixNano())
	return err
}

func encodeStored(value any) ([]byte, string, error) {
	raw, err := json.Marshal(value)
	if err != nil { return nil, "", err }
	return raw, digestBytes(raw), nil
}

func digestBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func oneRow(result sql.Result) bool { rows, err := result.RowsAffected(); return err == nil && rows == 1 }
