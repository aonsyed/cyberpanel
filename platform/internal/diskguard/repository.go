package diskguard

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
)

const Schema = `
CREATE TABLE IF NOT EXISTS diskguard_policies (
 id TEXT PRIMARY KEY, filesystem_id TEXT NOT NULL UNIQUE, generation INTEGER NOT NULL,
 digest TEXT NOT NULL, policy_json BLOB NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS diskguard_observations (
 id TEXT PRIMARY KEY, filesystem_id TEXT NOT NULL, generation INTEGER NOT NULL,
 digest TEXT NOT NULL, observation_json BLOB NOT NULL, observed_at TEXT NOT NULL,
 UNIQUE(filesystem_id,generation)
);
CREATE INDEX IF NOT EXISTS diskguard_observations_current ON diskguard_observations(filesystem_id,generation DESC);
CREATE TABLE IF NOT EXISTS diskguard_plans (
 id TEXT PRIMARY KEY, filesystem_id TEXT NOT NULL, policy_id TEXT NOT NULL,
 policy_generation INTEGER NOT NULL, observation_id TEXT NOT NULL, state TEXT NOT NULL,
 generation INTEGER NOT NULL, input_digest TEXT NOT NULL, digest TEXT NOT NULL,
 plan_json BLOB NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS diskguard_plans_filesystem ON diskguard_plans(filesystem_id,state,id);
CREATE TABLE IF NOT EXISTS diskguard_idempotency (
 idempotency_key TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, input_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS diskguard_approvals (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL,
 generation INTEGER NOT NULL, digest TEXT NOT NULL, approval_json BLOB NOT NULL,
 expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS diskguard_receipts (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL,
 state TEXT NOT NULL, generation INTEGER NOT NULL, digest TEXT NOT NULL,
 receipt_json BLOB NOT NULL, updated_at TEXT NOT NULL
);
`

type SQLiteRepository struct {
	DB *sql.DB
}

func (repository SQLiteRepository) Initialize(ctx context.Context) error {
	if repository.DB == nil || ctx == nil {
		return ErrInvalid
	}
	_, err := repository.DB.ExecContext(ctx, Schema)
	return err
}

func (repository SQLiteRepository) SavePolicy(ctx context.Context, policy WatermarkPolicy, expectedGeneration uint64) error {
	if repository.DB == nil || ctx == nil || policy.Validate() != nil || policy.Generation != expectedGeneration+1 {
		return ErrInvalid
	}
	raw, err := marshalResource(policy)
	if err != nil {
		return err
	}
	if expectedGeneration == 0 {
		_, err = repository.DB.ExecContext(ctx, `INSERT INTO diskguard_policies(id,filesystem_id,generation,digest,policy_json,updated_at) VALUES(?,?,?,?,?,?)`, policy.ID, policy.FilesystemID, policy.Generation, policy.Digest, raw, policy.UpdatedAt)
		return err
	}
	current, err := repository.LoadPolicy(ctx, policy.ID)
	if err != nil {
		return err
	}
	if current.Generation != expectedGeneration {
		return ErrStaleGeneration
	}
	if current.FilesystemID != policy.FilesystemID || !current.CreatedAt.Equal(policy.CreatedAt) {
		return ErrConflict
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE diskguard_policies SET filesystem_id=?,generation=?,digest=?,policy_json=?,updated_at=? WHERE id=? AND generation=?`, policy.FilesystemID, policy.Generation, policy.Digest, raw, policy.UpdatedAt, policy.ID, expectedGeneration)
	if err != nil {
		return err
	}
	return requireCAS(result)
}

func (repository SQLiteRepository) LoadPolicy(ctx context.Context, id string) (WatermarkPolicy, error) {
	if repository.DB == nil || ctx == nil || !validID(id) {
		return WatermarkPolicy{}, ErrInvalid
	}
	var raw []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT policy_json FROM diskguard_policies WHERE id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return WatermarkPolicy{}, ErrNotFound
	}
	if err != nil {
		return WatermarkPolicy{}, err
	}
	var policy WatermarkPolicy
	if strictDecode(raw, &policy) != nil || policy.Validate() != nil {
		return WatermarkPolicy{}, ErrIntegrity
	}
	return policy, nil
}

func (repository SQLiteRepository) SaveObservation(ctx context.Context, observation FilesystemObservation) error {
	if repository.DB == nil || ctx == nil || observation.Validate() != nil {
		return ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT digest FROM diskguard_observations WHERE id=?`, observation.ID).Scan(&digest)
	if err == nil {
		if digest != observation.Digest {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var maximum sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT MAX(generation) FROM diskguard_observations WHERE filesystem_id=?`, observation.FilesystemID).Scan(&maximum); err != nil {
		return err
	}
	expected := uint64(0)
	if maximum.Valid {
		expected = uint64(maximum.Int64)
	}
	if observation.Generation != expected+1 {
		return ErrStaleGeneration
	}
	var existingID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM diskguard_observations WHERE filesystem_id=? AND generation=?`, observation.FilesystemID, observation.Generation).Scan(&existingID)
	if err == nil {
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	raw, err := marshalResource(observation)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO diskguard_observations(id,filesystem_id,generation,digest,observation_json,observed_at) VALUES(?,?,?,?,?,?)`, observation.ID, observation.FilesystemID, observation.Generation, observation.Digest, raw, observation.ObservedAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (repository SQLiteRepository) LoadObservation(ctx context.Context, id string) (FilesystemObservation, error) {
	if repository.DB == nil || ctx == nil || !validID(id) {
		return FilesystemObservation{}, ErrInvalid
	}
	var raw []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT observation_json FROM diskguard_observations WHERE id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return FilesystemObservation{}, ErrNotFound
	}
	if err != nil {
		return FilesystemObservation{}, err
	}
	var observation FilesystemObservation
	if strictDecode(raw, &observation) != nil || observation.Validate() != nil {
		return FilesystemObservation{}, ErrIntegrity
	}
	return observation, nil
}

func (repository SQLiteRepository) AdmitPlan(ctx context.Context, plan Plan) (Plan, bool, error) {
	if repository.DB == nil || ctx == nil || plan.Validate() != nil || plan.Generation != 1 || plan.State != PlanPlanned && plan.State != PlanCompleted {
		return Plan{}, false, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil {
		return Plan{}, false, err
	}
	defer tx.Rollback()
	var existingID, inputDigest string
	err = tx.QueryRowContext(ctx, `SELECT plan_id,input_digest FROM diskguard_idempotency WHERE idempotency_key=?`, plan.IdempotencyKey).Scan(&existingID, &inputDigest)
	if err == nil {
		if existingID != plan.ID || inputDigest != plan.InputDigest {
			return Plan{}, false, ErrConflict
		}
		existing, loadErr := loadPlanTx(ctx, tx, existingID)
		if loadErr != nil {
			return Plan{}, false, loadErr
		}
		if err = tx.Commit(); err != nil {
			return Plan{}, false, err
		}
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Plan{}, false, err
	}
	raw, err := marshalResource(plan)
	if err != nil {
		return Plan{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO diskguard_plans(id,filesystem_id,policy_id,policy_generation,observation_id,state,generation,input_digest,digest,plan_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, plan.ID, plan.FilesystemID, plan.PolicyID, plan.PolicyGeneration, plan.ObservationID, plan.State, plan.Generation, plan.InputDigest, plan.Digest, raw, plan.UpdatedAt)
	if err != nil {
		return Plan{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO diskguard_idempotency(idempotency_key,plan_id,input_digest) VALUES(?,?,?)`, plan.IdempotencyKey, plan.ID, plan.InputDigest)
	if err != nil {
		return Plan{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return Plan{}, false, err
	}
	return plan, true, nil
}

func (repository SQLiteRepository) LoadPlan(ctx context.Context, id string) (Plan, error) {
	if repository.DB == nil || ctx == nil || !validID(id) {
		return Plan{}, ErrInvalid
	}
	var raw []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT plan_json FROM diskguard_plans WHERE id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	if strictDecode(raw, &plan) != nil || plan.Validate() != nil {
		return Plan{}, ErrIntegrity
	}
	return plan, nil
}

func (repository SQLiteRepository) UpdatePlan(ctx context.Context, plan Plan, expectedGeneration uint64) error {
	if repository.DB == nil || ctx == nil || plan.Validate() != nil || plan.Generation != expectedGeneration+1 {
		return ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := loadPlanTx(ctx, tx, plan.ID)
	if err != nil {
		return err
	}
	if current.Generation != expectedGeneration {
		return ErrStaleGeneration
	}
	if !allowedPlanTransition(current.State, plan.State) || planIntentDigest(current) != planIntentDigest(plan) {
		return ErrConflict
	}
	raw, err := marshalResource(plan)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE diskguard_plans SET state=?,generation=?,digest=?,plan_json=?,updated_at=? WHERE id=? AND generation=?`, plan.State, plan.Generation, plan.Digest, raw, plan.UpdatedAt, plan.ID, expectedGeneration)
	if err != nil {
		return err
	}
	if err = requireCAS(result); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository SQLiteRepository) SaveApproval(ctx context.Context, approval Approval) error {
	if repository.DB == nil || ctx == nil || approval.Validate() != nil || approval.Generation != 1 {
		return ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	plan, err := loadPlanTx(ctx, tx, approval.PlanID)
	if err != nil {
		return err
	}
	if !plan.RequiresApproval || plan.Digest != approval.PlanDigest || plan.State != PlanPlanned {
		return ErrConflict
	}
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT digest FROM diskguard_approvals WHERE id=? OR plan_id=?`, approval.ID, approval.PlanID).Scan(&digest)
	if err == nil {
		if digest != approval.Digest {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	raw, err := marshalResource(approval)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO diskguard_approvals(id,plan_id,plan_digest,generation,digest,approval_json,expires_at) VALUES(?,?,?,?,?,?,?)`, approval.ID, approval.PlanID, approval.PlanDigest, approval.Generation, approval.Digest, raw, approval.ExpiresAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (repository SQLiteRepository) LoadApproval(ctx context.Context, id string) (Approval, error) {
	if repository.DB == nil || ctx == nil || !validID(id) {
		return Approval{}, ErrInvalid
	}
	var raw []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT approval_json FROM diskguard_approvals WHERE id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	if err != nil {
		return Approval{}, err
	}
	var approval Approval
	if strictDecode(raw, &approval) != nil || approval.Validate() != nil {
		return Approval{}, ErrIntegrity
	}
	return approval, nil
}

func (repository SQLiteRepository) LoadReceipt(ctx context.Context, planID string) (ExecutionReceipt, error) {
	if repository.DB == nil || ctx == nil || !validID(planID) {
		return ExecutionReceipt{}, ErrInvalid
	}
	var raw []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT receipt_json FROM diskguard_receipts WHERE plan_id=?`, planID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutionReceipt{}, ErrNotFound
	}
	if err != nil {
		return ExecutionReceipt{}, err
	}
	var receipt ExecutionReceipt
	if strictDecode(raw, &receipt) != nil || receipt.Validate() != nil {
		return ExecutionReceipt{}, ErrIntegrity
	}
	return receipt, nil
}

func (repository SQLiteRepository) SaveReceipt(ctx context.Context, receipt ExecutionReceipt, expectedGeneration uint64) error {
	if repository.DB == nil || ctx == nil || receipt.Validate() != nil || receipt.Generation != expectedGeneration+1 {
		return ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	plan, err := loadPlanTx(ctx, tx, receipt.PlanID)
	if err != nil {
		return err
	}
	raw, err := marshalResource(receipt)
	if err != nil {
		return err
	}
	if expectedGeneration == 0 {
		if plan.Digest != receipt.PlanDigest {
			var approvalDigest string
			approvalErr := tx.QueryRowContext(ctx, `SELECT plan_digest FROM diskguard_approvals WHERE plan_id=?`, plan.ID).Scan(&approvalDigest)
			if approvalErr != nil || approvalDigest != receipt.PlanDigest {
				return ErrConflict
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO diskguard_receipts(id,plan_id,plan_digest,state,generation,digest,receipt_json,updated_at) VALUES(?,?,?,?,?,?,?,?)`, receipt.ID, receipt.PlanID, receipt.PlanDigest, receipt.State, receipt.Generation, receipt.Digest, raw, receipt.UpdatedAt)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	current, err := loadReceiptTx(ctx, tx, receipt.PlanID)
	if err != nil {
		return err
	}
	if current.Generation != expectedGeneration {
		return ErrStaleGeneration
	}
	if !validReceiptTransition(current, receipt) {
		return ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE diskguard_receipts SET state=?,generation=?,digest=?,receipt_json=?,updated_at=? WHERE plan_id=? AND generation=?`, receipt.State, receipt.Generation, receipt.Digest, raw, receipt.UpdatedAt, receipt.PlanID, expectedGeneration)
	if err != nil {
		return err
	}
	if err = requireCAS(result); err != nil {
		return err
	}
	return tx.Commit()
}

func loadPlanTx(ctx context.Context, tx *sql.Tx, id string) (Plan, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT plan_json FROM diskguard_plans WHERE id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	if strictDecode(raw, &plan) != nil || plan.Validate() != nil {
		return Plan{}, ErrIntegrity
	}
	return plan, nil
}

func loadReceiptTx(ctx context.Context, tx *sql.Tx, planID string) (ExecutionReceipt, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT receipt_json FROM diskguard_receipts WHERE plan_id=?`, planID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutionReceipt{}, ErrNotFound
	}
	if err != nil {
		return ExecutionReceipt{}, err
	}
	var receipt ExecutionReceipt
	if strictDecode(raw, &receipt) != nil || receipt.Validate() != nil {
		return ExecutionReceipt{}, ErrIntegrity
	}
	return receipt, nil
}

func allowedPlanTransition(from, to PlanState) bool {
	switch from {
	case PlanPlanned:
		return to == PlanApproved || to == PlanExecuting || to == PlanBlocked
	case PlanApproved:
		return to == PlanExecuting || to == PlanBlocked
	case PlanExecuting:
		return to == PlanCompleted || to == PlanPartial || to == PlanAmbiguous || to == PlanBlocked
	default:
		return false
	}
}

func planIntentDigest(plan Plan) string {
	plan.State, plan.Generation, plan.UpdatedAt, plan.Digest = "", 0, plan.CreatedAt, ""
	digest, _ := digestValue(plan)
	return digest
}

func validReceiptTransition(current, next ExecutionReceipt) bool {
	if current.ID != next.ID || current.PlanID != next.PlanID || current.PlanDigest != next.PlanDigest || len(next.Actions) != len(current.Actions)+1 || next.NextSequence < current.NextSequence && next.NextSequence != 0 {
		return false
	}
	for index := range current.Actions {
		if current.Actions[index] != next.Actions[index] {
			return false
		}
	}
	if current.State == PlanExecuting {
		return next.State == PlanExecuting || next.State == PlanCompleted || next.State == PlanPartial || next.State == PlanAmbiguous || next.State == PlanBlocked
	}
	return false
}

func marshalResource(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > 16<<20 {
		return nil, ErrLimit
	}
	return raw, nil
}

func strictDecode(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > 16<<20 {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrIntegrity
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func requireCAS(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrStaleGeneration
	}
	return nil
}
