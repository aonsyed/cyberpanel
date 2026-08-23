package recoveryproof

import (
	"context"
	"database/sql"
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
		return nil, fmt.Errorf("%w: nil database", ErrInvalid)
	}
	return &SQLiteRepository{db: db}, nil
}

func (r *SQLiteRepository) Initialize(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS recoveryproof_plans (
			tenant_id TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			digest TEXT NOT NULL,
			body BLOB NOT NULL,
			created_at_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, plan_id)
		)`,
		`CREATE TABLE IF NOT EXISTS recoveryproof_schedules (
			tenant_id TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			next_due_at_ns INTEGER NOT NULL,
			digest TEXT NOT NULL,
			body BLOB NOT NULL,
			updated_at_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, plan_id),
			FOREIGN KEY (tenant_id, plan_id)
				REFERENCES recoveryproof_plans (tenant_id, plan_id)
		)`,
		`CREATE INDEX IF NOT EXISTS recoveryproof_schedules_due
			ON recoveryproof_schedules (next_due_at_ns, tenant_id, plan_id)`,
		`CREATE TABLE IF NOT EXISTS recoveryproof_drills (
			tenant_id TEXT NOT NULL,
			drill_id TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			occurrence_key TEXT NOT NULL,
			state TEXT NOT NULL,
			generation INTEGER NOT NULL,
			fence_token INTEGER NOT NULL,
			lease_id TEXT NOT NULL,
			lease_expires_at_ns INTEGER NOT NULL,
			digest TEXT NOT NULL,
			body BLOB NOT NULL,
			scheduled_at_ns INTEGER NOT NULL,
			updated_at_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, drill_id),
			UNIQUE (tenant_id, plan_id, occurrence_key),
			FOREIGN KEY (tenant_id, plan_id)
				REFERENCES recoveryproof_plans (tenant_id, plan_id)
		)`,
		`CREATE INDEX IF NOT EXISTS recoveryproof_drills_list
			ON recoveryproof_drills (tenant_id, scheduled_at_ns, drill_id)`,
		`CREATE INDEX IF NOT EXISTS recoveryproof_drills_state
			ON recoveryproof_drills (tenant_id, state, updated_at_ns, drill_id)`,
		`CREATE TABLE IF NOT EXISTS recoveryproof_receipts (
			tenant_id TEXT NOT NULL,
			receipt_id TEXT NOT NULL,
			drill_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			digest TEXT NOT NULL,
			body BLOB NOT NULL,
			created_at_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, receipt_id),
			FOREIGN KEY (tenant_id, drill_id)
				REFERENCES recoveryproof_drills (tenant_id, drill_id)
		)`,
		`CREATE INDEX IF NOT EXISTS recoveryproof_receipts_drill
			ON recoveryproof_receipts (tenant_id, drill_id, created_at_ns, receipt_id)`,
		`CREATE TABLE IF NOT EXISTS recoveryproof_proofs (
			tenant_id TEXT NOT NULL,
			proof_id TEXT NOT NULL,
			drill_id TEXT NOT NULL,
			outcome TEXT NOT NULL,
			digest TEXT NOT NULL,
			body BLOB NOT NULL,
			created_at_ns INTEGER NOT NULL,
			retain_until_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, proof_id),
			UNIQUE (tenant_id, drill_id),
			FOREIGN KEY (tenant_id, drill_id)
				REFERENCES recoveryproof_drills (tenant_id, drill_id)
		)`,
		`CREATE INDEX IF NOT EXISTS recoveryproof_proofs_retention
			ON recoveryproof_proofs (retain_until_ns, tenant_id, proof_id)`,
		`CREATE TABLE IF NOT EXISTS recoveryproof_idempotency (
			tenant_id TEXT NOT NULL,
			idempotency_key TEXT NOT NULL,
			operation TEXT NOT NULL,
			request_digest TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			response_digest TEXT NOT NULL,
			created_at_ns INTEGER NOT NULL,
			PRIMARY KEY (tenant_id, idempotency_key, operation)
		)`,
	}
	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("recoveryproof: initialize repository: %w", err)
		}
	}
	return nil
}

func (r *SQLiteRepository) CreatePlan(
	ctx context.Context,
	plan DrillPlan,
) (DrillPlan, ScheduleState, error) {
	sealed, err := SealPlan(plan)
	if err != nil {
		return DrillPlan{}, ScheduleState{}, err
	}
	schedule, err := SealScheduleState(ScheduleState{
		TenantID:   sealed.TenantID,
		PlanID:     sealed.ID,
		PlanDigest: sealed.Digest,
		Generation: 1,
		NextDueAt:  sealed.Schedule.FirstDueAt,
		UpdatedAt:  sealed.CreatedAt,
	})
	if err != nil {
		return DrillPlan{}, ScheduleState{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return DrillPlan{}, ScheduleState{}, fmt.Errorf("recoveryproof: begin plan creation: %w", err)
	}
	defer tx.Rollback()
	planBody, _ := json.Marshal(sealed)
	_, err = tx.ExecContext(ctx, `INSERT INTO recoveryproof_plans (
		tenant_id, plan_id, generation, digest, body, created_at_ns
	) VALUES (?, ?, ?, ?, ?, ?)`, string(sealed.TenantID), string(sealed.ID),
		sealed.Generation, sealed.Digest, planBody, sealed.CreatedAt.UnixNano())
	if err != nil {
		existing, getErr := getPlanTx(ctx, tx, sealed.TenantID, sealed.ID)
		if getErr != nil || existing.Digest != sealed.Digest {
			return DrillPlan{}, ScheduleState{}, ErrConflict
		}
		existingSchedule, getErr := getScheduleTx(ctx, tx, sealed.TenantID, sealed.ID)
		if getErr != nil {
			return DrillPlan{}, ScheduleState{}, getErr
		}
		if err := tx.Commit(); err != nil {
			return DrillPlan{}, ScheduleState{}, fmt.Errorf("recoveryproof: commit existing plan: %w", err)
		}
		return existing, existingSchedule, nil
	}
	scheduleBody, _ := json.Marshal(schedule)
	if _, err := tx.ExecContext(ctx, `INSERT INTO recoveryproof_schedules (
		tenant_id, plan_id, generation, next_due_at_ns, digest, body, updated_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?)`, string(schedule.TenantID), string(schedule.PlanID),
		schedule.Generation, schedule.NextDueAt.UnixNano(), schedule.Digest, scheduleBody,
		schedule.UpdatedAt.UnixNano()); err != nil {
		return DrillPlan{}, ScheduleState{}, fmt.Errorf("recoveryproof: create plan schedule: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return DrillPlan{}, ScheduleState{}, fmt.Errorf("recoveryproof: commit plan creation: %w", err)
	}
	return sealed, schedule, nil
}

func (r *SQLiteRepository) GetPlan(
	ctx context.Context,
	tenantID TenantID,
	planID PlanID,
) (DrillPlan, error) {
	var body []byte
	err := r.db.QueryRowContext(ctx, `SELECT body FROM recoveryproof_plans
		WHERE tenant_id = ? AND plan_id = ?`, string(tenantID), string(planID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return DrillPlan{}, ErrNotFound
	}
	if err != nil {
		return DrillPlan{}, fmt.Errorf("recoveryproof: get plan: %w", err)
	}
	return decodePlan(body, tenantID, planID)
}

func (r *SQLiteRepository) GetSchedule(
	ctx context.Context,
	tenantID TenantID,
	planID PlanID,
) (ScheduleState, error) {
	var body []byte
	err := r.db.QueryRowContext(ctx, `SELECT body FROM recoveryproof_schedules
		WHERE tenant_id = ? AND plan_id = ?`, string(tenantID), string(planID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return ScheduleState{}, ErrNotFound
	}
	if err != nil {
		return ScheduleState{}, fmt.Errorf("recoveryproof: get schedule: %w", err)
	}
	return decodeSchedule(body, tenantID, planID)
}

type DuePlan struct {
	Plan     DrillPlan
	Schedule ScheduleState
	Missed   bool
}

func (r *SQLiteRepository) ListDuePlans(
	ctx context.Context,
	now time.Time,
	limit int,
) ([]DuePlan, error) {
	if now.IsZero() || limit <= 0 || limit > MaximumListItems {
		return nil, fmt.Errorf("%w: due plan query", ErrInvalid)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT p.body, s.body
		FROM recoveryproof_schedules s
		JOIN recoveryproof_plans p ON p.tenant_id = s.tenant_id AND p.plan_id = s.plan_id
		WHERE s.next_due_at_ns <= ?
		ORDER BY s.next_due_at_ns ASC, s.tenant_id ASC, s.plan_id ASC
		LIMIT ?`, canonicalTime(now).UnixNano(), limit)
	if err != nil {
		return nil, fmt.Errorf("recoveryproof: list due plans: %w", err)
	}
	defer rows.Close()
	result := make([]DuePlan, 0, limit)
	for rows.Next() {
		var planBody, scheduleBody []byte
		if err := rows.Scan(&planBody, &scheduleBody); err != nil {
			return nil, fmt.Errorf("recoveryproof: scan due plan: %w", err)
		}
		var rawPlan DrillPlan
		if err := json.Unmarshal(planBody, &rawPlan); err != nil {
			return nil, ErrIntegrity
		}
		plan, err := decodePlan(planBody, rawPlan.TenantID, rawPlan.ID)
		if err != nil {
			return nil, err
		}
		schedule, err := decodeSchedule(scheduleBody, plan.TenantID, plan.ID)
		if err != nil {
			return nil, err
		}
		result = append(result, DuePlan{
			Plan:     plan,
			Schedule: schedule,
			Missed:   now.After(schedule.NextDueAt.Add(plan.Schedule.MaximumLateness)),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recoveryproof: iterate due plans: %w", err)
	}
	return result, nil
}

type OccurrenceRequest struct {
	TenantID                  TenantID
	PlanID                    PlanID
	ExpectedScheduleGeneration uint64
	ScheduledAt               time.Time
	RecoveryPoint             RecoveryPoint
	IdempotencyKey            string
	CreatedAt                 time.Time
}

func (r *SQLiteRepository) CreateOccurrence(
	ctx context.Context,
	request OccurrenceRequest,
) (Drill, ScheduleState, error) {
	if !validLocalID(string(request.TenantID)) || !validLocalID(string(request.PlanID)) ||
		request.ExpectedScheduleGeneration == 0 || request.ScheduledAt.IsZero() ||
		!validLocalID(request.IdempotencyKey) || request.CreatedAt.IsZero() {
		return Drill{}, ScheduleState{}, fmt.Errorf("%w: occurrence request", ErrInvalid)
	}
	if err := request.RecoveryPoint.Validate(); err != nil {
		return Drill{}, ScheduleState{}, err
	}
	request.ScheduledAt = canonicalTime(request.ScheduledAt)
	request.CreatedAt = canonicalTime(request.CreatedAt)
	requestDigest, err := canonicalDigest(request)
	if err != nil {
		return Drill{}, ScheduleState{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Drill{}, ScheduleState{}, fmt.Errorf("recoveryproof: begin occurrence: %w", err)
	}
	defer tx.Rollback()
	if drill, schedule, found, err := lookupOccurrenceIdempotency(
		ctx,
		tx,
		request.TenantID,
		request.IdempotencyKey,
		requestDigest,
	); err != nil {
		return Drill{}, ScheduleState{}, err
	} else if found {
		if err := tx.Commit(); err != nil {
			return Drill{}, ScheduleState{}, fmt.Errorf("recoveryproof: commit idempotent occurrence: %w", err)
		}
		return drill, schedule, nil
	}
	plan, err := getPlanTx(ctx, tx, request.TenantID, request.PlanID)
	if err != nil {
		return Drill{}, ScheduleState{}, err
	}
	if request.RecoveryPoint.Consistency != plan.Consistency ||
		!sameComponents(request.RecoveryPoint.Components, plan.Components) {
		return Drill{}, ScheduleState{}, fmt.Errorf("%w: occurrence recovery declaration", ErrInvalid)
	}
	schedule, err := getScheduleTx(ctx, tx, request.TenantID, request.PlanID)
	if err != nil {
		return Drill{}, ScheduleState{}, err
	}
	if schedule.Generation != request.ExpectedScheduleGeneration ||
		!schedule.NextDueAt.Equal(request.ScheduledAt) || schedule.PlanDigest != plan.Digest ||
		request.CreatedAt.Before(schedule.UpdatedAt) || request.CreatedAt.Before(request.ScheduledAt) {
		return Drill{}, ScheduleState{}, ErrStaleGeneration
	}
	occurrenceKey, err := OccurrenceKey(plan.Digest, request.ScheduledAt)
	if err != nil {
		return Drill{}, ScheduleState{}, err
	}
	drillID := DrillID("drill:" + occurrenceKey[:32])
	drill, err := SealDrill(Drill{
		ID:            drillID,
		TenantID:      request.TenantID,
		PlanID:        request.PlanID,
		PlanDigest:    plan.Digest,
		OccurrenceKey: occurrenceKey,
		ScheduledAt:   request.ScheduledAt,
		RecoveryPoint: request.RecoveryPoint,
		State:         StatePlanned,
		Generation:    1,
		CreatedAt:     request.CreatedAt,
		UpdatedAt:     request.CreatedAt,
	})
	if err != nil {
		return Drill{}, ScheduleState{}, err
	}
	drillBody, _ := json.Marshal(drill)
	if _, err := tx.ExecContext(ctx, `INSERT INTO recoveryproof_drills (
		tenant_id, drill_id, plan_id, occurrence_key, state, generation, fence_token,
		lease_id, lease_expires_at_ns, digest, body, scheduled_at_ns, updated_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(drill.TenantID), string(drill.ID), string(drill.PlanID), drill.OccurrenceKey,
		string(drill.State), drill.Generation, 0, "", int64(0), drill.Digest, drillBody,
		drill.ScheduledAt.UnixNano(), drill.UpdatedAt.UnixNano()); err != nil {
		return Drill{}, ScheduleState{}, fmt.Errorf("recoveryproof: insert occurrence: %w", err)
	}
	receipt, err := SealReceipt(Receipt{
		ID:              ReceiptID("receipt:occ:" + occurrenceKey[:32]),
		TenantID:        drill.TenantID,
		DrillID:         drill.ID,
		Kind:            ReceiptOccurrence,
		FromState:       StatePlanned,
		ToState:         StatePlanned,
		DrillGeneration: drill.Generation,
		StatusCode:      "occurrence_created",
		CreatedAt:       request.CreatedAt,
	})
	if err != nil {
		return Drill{}, ScheduleState{}, err
	}
	if err := insertReceiptTx(ctx, tx, receipt); err != nil {
		return Drill{}, ScheduleState{}, err
	}
	nextSchedule, err := SealScheduleState(ScheduleState{
		TenantID:          schedule.TenantID,
		PlanID:            schedule.PlanID,
		PlanDigest:        schedule.PlanDigest,
		Generation:        schedule.Generation + 1,
		NextDueAt:         plan.Schedule.NextAfter(request.ScheduledAt),
		LastScheduledAt:   request.ScheduledAt,
		LastOccurrenceKey: occurrenceKey,
		UpdatedAt:         request.CreatedAt,
	})
	if err != nil {
		return Drill{}, ScheduleState{}, err
	}
	scheduleBody, _ := json.Marshal(nextSchedule)
	result, err := tx.ExecContext(ctx, `UPDATE recoveryproof_schedules SET
		generation = ?, next_due_at_ns = ?, digest = ?, body = ?, updated_at_ns = ?
		WHERE tenant_id = ? AND plan_id = ? AND generation = ? AND digest = ?`,
		nextSchedule.Generation, nextSchedule.NextDueAt.UnixNano(), nextSchedule.Digest,
		scheduleBody, nextSchedule.UpdatedAt.UnixNano(), string(schedule.TenantID),
		string(schedule.PlanID), schedule.Generation, schedule.Digest)
	if err != nil {
		return Drill{}, ScheduleState{}, fmt.Errorf("recoveryproof: advance schedule: %w", err)
	}
	if err := requireOneRow(result); err != nil {
		return Drill{}, ScheduleState{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recoveryproof_idempotency (
		tenant_id, idempotency_key, operation, request_digest, resource_id,
		response_digest, created_at_ns
	) VALUES (?, ?, 'create_occurrence', ?, ?, ?, ?)`, string(request.TenantID),
		request.IdempotencyKey, requestDigest, string(drill.ID), drill.Digest,
		request.CreatedAt.UnixNano()); err != nil {
		return Drill{}, ScheduleState{}, fmt.Errorf("recoveryproof: record occurrence idempotency: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Drill{}, ScheduleState{}, fmt.Errorf("recoveryproof: commit occurrence: %w", err)
	}
	return drill, nextSchedule, nil
}

func (r *SQLiteRepository) GetDrill(
	ctx context.Context,
	tenantID TenantID,
	drillID DrillID,
) (Drill, error) {
	var body []byte
	err := r.db.QueryRowContext(ctx, `SELECT body FROM recoveryproof_drills
		WHERE tenant_id = ? AND drill_id = ?`, string(tenantID), string(drillID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return Drill{}, ErrNotFound
	}
	if err != nil {
		return Drill{}, fmt.Errorf("recoveryproof: get drill: %w", err)
	}
	return decodeDrill(body, tenantID, drillID)
}

type TransitionRequest struct {
	Current Drill
	Next    Drill
	Receipt Receipt
	Proof   *ProofManifest
	Now     time.Time
}

func (r *SQLiteRepository) TransitionCAS(
	ctx context.Context,
	request TransitionRequest,
) (Drill, Receipt, error) {
	if request.Now.IsZero() {
		return Drill{}, Receipt{}, fmt.Errorf("%w: transition time", ErrInvalid)
	}
	request.Now = canonicalTime(request.Now)
	next, err := SealDrill(request.Next)
	if err != nil {
		return Drill{}, Receipt{}, err
	}
	receipt, err := SealReceipt(request.Receipt)
	if err != nil {
		return Drill{}, Receipt{}, err
	}
	if request.Current.Generation+1 != next.Generation || !DrillIdentityEqual(request.Current, next) ||
		!transitionAllowed(request.Current.State, next.State) || receipt.TenantID != next.TenantID ||
		receipt.DrillID != next.ID || receipt.FromState != request.Current.State ||
		receipt.ToState != next.State || receipt.DrillGeneration != next.Generation ||
		next.UpdatedAt.Before(request.Current.UpdatedAt) || receipt.CreatedAt.Before(request.Current.UpdatedAt) {
		return Drill{}, Receipt{}, fmt.Errorf("%w: transition binding", ErrInvalid)
	}
	if request.Current.State == StatePlanned && next.State == StateAdmitted {
		if next.Fence.Token != request.Current.Fence.Token+1 || !validLocalID(next.Fence.LeaseID) ||
			!next.Fence.ExpiresAt.After(request.Now) || receipt.FenceToken != next.Fence.Token {
			return Drill{}, Receipt{}, ErrFenceLost
		}
	} else if request.Current.State == StatePlanned {
		if next.Fence != request.Current.Fence || receipt.FenceToken != 0 {
			return Drill{}, Receipt{}, ErrFenceLost
		}
	} else if next.Fence.Token != request.Current.Fence.Token ||
		next.Fence.LeaseID != request.Current.Fence.LeaseID ||
		!request.Now.Before(request.Current.Fence.ExpiresAt) ||
		receipt.FenceToken != request.Current.Fence.Token {
		return Drill{}, Receipt{}, ErrFenceLost
	}
	var proofDigest string
	if request.Proof != nil {
		if err := ValidateSignedProof(*request.Proof); err != nil {
			return Drill{}, Receipt{}, err
		}
		if !next.State.terminal() || request.Proof.TenantID != next.TenantID ||
			request.Proof.DrillID != next.ID || request.Proof.DrillDigest != request.Current.Digest ||
			request.Proof.PlanID != next.PlanID || request.Proof.PlanDigest != next.PlanDigest ||
			request.Proof.Outcome != next.State {
			return Drill{}, Receipt{}, fmt.Errorf("%w: proof transition binding", ErrInvalid)
		}
		proofDigest, err = ProofDigest(*request.Proof)
		if err != nil || next.ProofDigest != proofDigest {
			return Drill{}, Receipt{}, ErrIntegrity
		}
	} else if next.State.terminal() {
		return Drill{}, Receipt{}, fmt.Errorf("%w: terminal transition without proof", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Drill{}, Receipt{}, fmt.Errorf("recoveryproof: begin transition: %w", err)
	}
	defer tx.Rollback()
	current, err := getDrillTx(ctx, tx, request.Current.TenantID, request.Current.ID)
	if err != nil {
		return Drill{}, Receipt{}, err
	}
	if current.Generation != request.Current.Generation || current.Digest != request.Current.Digest ||
		current.Fence.Token != request.Current.Fence.Token {
		return Drill{}, Receipt{}, ErrStaleGeneration
	}
	if request.Proof != nil {
		proofBody, _ := json.Marshal(request.Proof)
		if _, err := tx.ExecContext(ctx, `INSERT INTO recoveryproof_proofs (
			tenant_id, proof_id, drill_id, outcome, digest, body, created_at_ns, retain_until_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, string(request.Proof.TenantID), request.Proof.ID,
			string(request.Proof.DrillID), string(request.Proof.Outcome), proofDigest, proofBody,
			request.Proof.CreatedAt.UnixNano(), request.Proof.RetainUntil.UnixNano()); err != nil {
			return Drill{}, Receipt{}, fmt.Errorf("recoveryproof: insert proof: %w", err)
		}
	}
	if err := insertReceiptTx(ctx, tx, receipt); err != nil {
		return Drill{}, Receipt{}, err
	}
	nextBody, _ := json.Marshal(next)
	leaseExpires := int64(0)
	if !next.Fence.ExpiresAt.IsZero() {
		leaseExpires = next.Fence.ExpiresAt.UnixNano()
	}
	result, err := tx.ExecContext(ctx, `UPDATE recoveryproof_drills SET
		state = ?, generation = ?, fence_token = ?, lease_id = ?, lease_expires_at_ns = ?,
		digest = ?, body = ?, updated_at_ns = ?
		WHERE tenant_id = ? AND drill_id = ? AND generation = ? AND digest = ? AND fence_token = ?`,
		string(next.State), next.Generation, next.Fence.Token, next.Fence.LeaseID, leaseExpires,
		next.Digest, nextBody, next.UpdatedAt.UnixNano(), string(current.TenantID),
		string(current.ID), current.Generation, current.Digest, current.Fence.Token)
	if err != nil {
		return Drill{}, Receipt{}, fmt.Errorf("recoveryproof: update transition: %w", err)
	}
	if err := requireOneRow(result); err != nil {
		return Drill{}, Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Drill{}, Receipt{}, fmt.Errorf("recoveryproof: commit transition: %w", err)
	}
	return next, receipt, nil
}

// RecordReceiptCAS durably records an external phase outcome without changing
// drill state. It is fenced to the exact current generation and lease.
func (r *SQLiteRepository) RecordReceiptCAS(
	ctx context.Context,
	current Drill,
	receipt Receipt,
	now time.Time,
) (Receipt, error) {
	if now.IsZero() || current.State == StatePlanned || current.State.terminal() ||
		canonicalTime(now).Before(current.UpdatedAt) ||
		!canonicalTime(now).Before(current.Fence.ExpiresAt) {
		return Receipt{}, ErrFenceLost
	}
	sealed, err := SealReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if sealed.TenantID != current.TenantID || sealed.DrillID != current.ID ||
		sealed.FromState != current.State || sealed.ToState != current.State ||
		sealed.DrillGeneration != current.Generation || sealed.FenceToken != current.Fence.Token {
		return Receipt{}, fmt.Errorf("%w: phase receipt binding", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Receipt{}, fmt.Errorf("recoveryproof: begin phase receipt: %w", err)
	}
	defer tx.Rollback()
	stored, err := getDrillTx(ctx, tx, current.TenantID, current.ID)
	if err != nil {
		return Receipt{}, err
	}
	if stored.Generation != current.Generation || stored.Digest != current.Digest ||
		stored.Fence.Token != current.Fence.Token || stored.Fence.LeaseID != current.Fence.LeaseID {
		return Receipt{}, ErrStaleGeneration
	}
	if err := insertReceiptTx(ctx, tx, sealed); err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, fmt.Errorf("recoveryproof: commit phase receipt: %w", err)
	}
	return sealed, nil
}

type DrillCursor struct {
	ScheduledAt time.Time
	DrillID     DrillID
}

type DrillPage struct {
	Items      []DrillProjection
	NextCursor *DrillCursor
}

func (r *SQLiteRepository) ListDrills(
	ctx context.Context,
	tenantID TenantID,
	cursor *DrillCursor,
	limit int,
) (DrillPage, error) {
	if !validLocalID(string(tenantID)) || limit <= 0 || limit > MaximumListItems {
		return DrillPage{}, fmt.Errorf("%w: drill list", ErrInvalid)
	}
	scheduledAfter := int64(-1 << 63)
	idAfter := ""
	if cursor != nil {
		if cursor.ScheduledAt.IsZero() || !validLocalID(string(cursor.DrillID)) {
			return DrillPage{}, fmt.Errorf("%w: drill cursor", ErrInvalid)
		}
		scheduledAfter = canonicalTime(cursor.ScheduledAt).UnixNano()
		idAfter = string(cursor.DrillID)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT body FROM recoveryproof_drills
		WHERE tenant_id = ? AND (
			scheduled_at_ns > ? OR (scheduled_at_ns = ? AND drill_id > ?)
		)
		ORDER BY scheduled_at_ns ASC, drill_id ASC
		LIMIT ?`, string(tenantID), scheduledAfter, scheduledAfter, idAfter, limit+1)
	if err != nil {
		return DrillPage{}, fmt.Errorf("recoveryproof: list drills: %w", err)
	}
	defer rows.Close()
	items := make([]DrillProjection, 0, limit+1)
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return DrillPage{}, fmt.Errorf("recoveryproof: scan drill list: %w", err)
		}
		var raw Drill
		if err := json.Unmarshal(body, &raw); err != nil {
			return DrillPage{}, ErrIntegrity
		}
		drill, err := decodeDrill(body, tenantID, raw.ID)
		if err != nil {
			return DrillPage{}, err
		}
		items = append(items, projectDrill(drill))
	}
	if err := rows.Err(); err != nil {
		return DrillPage{}, fmt.Errorf("recoveryproof: iterate drill list: %w", err)
	}
	page := DrillPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		page.Items = items[:limit]
		page.NextCursor = &DrillCursor{ScheduledAt: last.ScheduledAt, DrillID: last.DrillID}
	}
	return page, nil
}

func (r *SQLiteRepository) GetProof(
	ctx context.Context,
	tenantID TenantID,
	drillID DrillID,
) (ProofManifest, error) {
	var storedDigest string
	var body []byte
	err := r.db.QueryRowContext(ctx, `SELECT digest, body FROM recoveryproof_proofs
		WHERE tenant_id = ? AND drill_id = ?`, string(tenantID), string(drillID)).Scan(&storedDigest, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return ProofManifest{}, ErrNotFound
	}
	if err != nil {
		return ProofManifest{}, fmt.Errorf("recoveryproof: get proof: %w", err)
	}
	proof, err := decodeProof(body, tenantID, drillID)
	if err != nil {
		return ProofManifest{}, err
	}
	digest, err := ProofDigest(proof)
	if err != nil || digest != storedDigest {
		return ProofManifest{}, ErrIntegrity
	}
	return proof, nil
}

type ProofReference struct {
	TenantID   TenantID
	ProofID    string
	DrillID    DrillID
	Digest     string
	RetainUntil time.Time
}

func (r *SQLiteRepository) ListExpiredProofs(
	ctx context.Context,
	now time.Time,
	limit int,
) ([]ProofReference, error) {
	if now.IsZero() || limit <= 0 || limit > MaximumListItems {
		return nil, fmt.Errorf("%w: expired proof query", ErrInvalid)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT tenant_id, proof_id, drill_id, digest, retain_until_ns
		FROM recoveryproof_proofs WHERE retain_until_ns <= ?
		ORDER BY retain_until_ns ASC, tenant_id ASC, proof_id ASC LIMIT ?`,
		canonicalTime(now).UnixNano(), limit)
	if err != nil {
		return nil, fmt.Errorf("recoveryproof: list expired proofs: %w", err)
	}
	defer rows.Close()
	result := make([]ProofReference, 0, limit)
	for rows.Next() {
		var tenant, proofID, drillID, digest string
		var retainUntil int64
		if err := rows.Scan(&tenant, &proofID, &drillID, &digest, &retainUntil); err != nil {
			return nil, fmt.Errorf("recoveryproof: scan expired proof: %w", err)
		}
		if !validLocalID(tenant) || !validLocalID(proofID) || !validLocalID(drillID) || !validDigest(digest) {
			return nil, ErrIntegrity
		}
		result = append(result, ProofReference{
			TenantID:    TenantID(tenant),
			ProofID:     proofID,
			DrillID:     DrillID(drillID),
			Digest:      digest,
			RetainUntil: time.Unix(0, retainUntil).UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recoveryproof: iterate expired proofs: %w", err)
	}
	return result, nil
}

func getPlanTx(ctx context.Context, tx *sql.Tx, tenantID TenantID, planID PlanID) (DrillPlan, error) {
	var body []byte
	err := tx.QueryRowContext(ctx, `SELECT body FROM recoveryproof_plans
		WHERE tenant_id = ? AND plan_id = ?`, string(tenantID), string(planID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return DrillPlan{}, ErrNotFound
	}
	if err != nil {
		return DrillPlan{}, fmt.Errorf("recoveryproof: get plan transaction: %w", err)
	}
	return decodePlan(body, tenantID, planID)
}

func getScheduleTx(ctx context.Context, tx *sql.Tx, tenantID TenantID, planID PlanID) (ScheduleState, error) {
	var body []byte
	err := tx.QueryRowContext(ctx, `SELECT body FROM recoveryproof_schedules
		WHERE tenant_id = ? AND plan_id = ?`, string(tenantID), string(planID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return ScheduleState{}, ErrNotFound
	}
	if err != nil {
		return ScheduleState{}, fmt.Errorf("recoveryproof: get schedule transaction: %w", err)
	}
	return decodeSchedule(body, tenantID, planID)
}

func getDrillTx(ctx context.Context, tx *sql.Tx, tenantID TenantID, drillID DrillID) (Drill, error) {
	var body []byte
	err := tx.QueryRowContext(ctx, `SELECT body FROM recoveryproof_drills
		WHERE tenant_id = ? AND drill_id = ?`, string(tenantID), string(drillID)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return Drill{}, ErrNotFound
	}
	if err != nil {
		return Drill{}, fmt.Errorf("recoveryproof: get drill transaction: %w", err)
	}
	return decodeDrill(body, tenantID, drillID)
}

func lookupOccurrenceIdempotency(
	ctx context.Context,
	tx *sql.Tx,
	tenantID TenantID,
	key string,
	requestDigest string,
) (Drill, ScheduleState, bool, error) {
	var storedRequest, resourceID, responseDigest string
	err := tx.QueryRowContext(ctx, `SELECT request_digest, resource_id, response_digest
		FROM recoveryproof_idempotency
		WHERE tenant_id = ? AND idempotency_key = ? AND operation = 'create_occurrence'`,
		string(tenantID), key).Scan(&storedRequest, &resourceID, &responseDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return Drill{}, ScheduleState{}, false, nil
	}
	if err != nil {
		return Drill{}, ScheduleState{}, false, fmt.Errorf("recoveryproof: read idempotency: %w", err)
	}
	if storedRequest != requestDigest || !validLocalID(resourceID) || !validDigest(responseDigest) {
		return Drill{}, ScheduleState{}, false, ErrConflict
	}
	drill, err := getDrillTx(ctx, tx, tenantID, DrillID(resourceID))
	if err != nil {
		return Drill{}, ScheduleState{}, false, ErrIntegrity
	}
	schedule, err := getScheduleTx(ctx, tx, tenantID, drill.PlanID)
	if err != nil {
		return Drill{}, ScheduleState{}, false, err
	}
	return drill, schedule, true, nil
}

func insertReceiptTx(ctx context.Context, tx *sql.Tx, receipt Receipt) error {
	body, _ := json.Marshal(receipt)
	_, err := tx.ExecContext(ctx, `INSERT INTO recoveryproof_receipts (
		tenant_id, receipt_id, drill_id, kind, digest, body, created_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?)`, string(receipt.TenantID), string(receipt.ID),
		string(receipt.DrillID), string(receipt.Kind), receipt.Digest, body,
		receipt.CreatedAt.UnixNano())
	if err != nil {
		var existingDigest string
		getErr := tx.QueryRowContext(ctx, `SELECT digest FROM recoveryproof_receipts
			WHERE tenant_id = ? AND receipt_id = ?`, string(receipt.TenantID),
			string(receipt.ID)).Scan(&existingDigest)
		if getErr == nil && existingDigest == receipt.Digest {
			return nil
		}
		if getErr == nil {
			return ErrConflict
		}
		return fmt.Errorf("recoveryproof: insert receipt: %w", err)
	}
	return nil
}

func decodePlan(body []byte, tenantID TenantID, planID PlanID) (DrillPlan, error) {
	var plan DrillPlan
	if err := json.Unmarshal(body, &plan); err != nil {
		return DrillPlan{}, ErrIntegrity
	}
	sealed, err := SealPlan(plan)
	if err != nil || sealed.Digest != plan.Digest || plan.TenantID != tenantID || plan.ID != planID {
		return DrillPlan{}, ErrIntegrity
	}
	return plan, nil
}

func decodeSchedule(body []byte, tenantID TenantID, planID PlanID) (ScheduleState, error) {
	var schedule ScheduleState
	if err := json.Unmarshal(body, &schedule); err != nil {
		return ScheduleState{}, ErrIntegrity
	}
	sealed, err := SealScheduleState(schedule)
	if err != nil || sealed.Digest != schedule.Digest || schedule.TenantID != tenantID ||
		schedule.PlanID != planID {
		return ScheduleState{}, ErrIntegrity
	}
	return schedule, nil
}

func decodeDrill(body []byte, tenantID TenantID, drillID DrillID) (Drill, error) {
	var drill Drill
	if err := json.Unmarshal(body, &drill); err != nil {
		return Drill{}, ErrIntegrity
	}
	sealed, err := SealDrill(drill)
	if err != nil || sealed.Digest != drill.Digest || drill.TenantID != tenantID || drill.ID != drillID {
		return Drill{}, ErrIntegrity
	}
	return drill, nil
}

func decodeProof(body []byte, tenantID TenantID, drillID DrillID) (ProofManifest, error) {
	var proof ProofManifest
	if err := json.Unmarshal(body, &proof); err != nil {
		return ProofManifest{}, ErrIntegrity
	}
	if err := ValidateSignedProof(proof); err != nil || proof.TenantID != tenantID || proof.DrillID != drillID {
		return ProofManifest{}, ErrIntegrity
	}
	return proof, nil
}

func requireOneRow(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("recoveryproof: inspect CAS result: %w", err)
	}
	if count != 1 {
		return ErrStaleGeneration
	}
	return nil
}
