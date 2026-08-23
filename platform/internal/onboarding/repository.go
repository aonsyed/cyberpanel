package onboarding

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

const Schema = `
CREATE TABLE IF NOT EXISTS onboarding_wizards (
 id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 owner_id TEXT NOT NULL,
 state TEXT NOT NULL,
 revision INTEGER NOT NULL,
 plan_generation INTEGER NOT NULL,
 current_step TEXT NOT NULL,
 irreversible_crossed INTEGER NOT NULL,
 wizard_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 UNIQUE(tenant_id,node_id)
);
CREATE TABLE IF NOT EXISTS onboarding_answers (
 wizard_id TEXT NOT NULL,
 step TEXT NOT NULL,
 revision INTEGER NOT NULL,
 digest TEXT NOT NULL,
 answer_json BLOB NOT NULL,
 created_at TIMESTAMP NOT NULL,
 PRIMARY KEY(wizard_id,revision),
 FOREIGN KEY(wizard_id) REFERENCES onboarding_wizards(id)
);
CREATE INDEX IF NOT EXISTS onboarding_answers_step ON onboarding_answers(wizard_id,step,revision);
CREATE TABLE IF NOT EXISTS onboarding_plans (
 wizard_id TEXT NOT NULL,
 generation INTEGER NOT NULL,
 source_revision INTEGER NOT NULL,
 digest TEXT NOT NULL,
 plan_json BLOB NOT NULL,
 created_at TIMESTAMP NOT NULL,
 PRIMARY KEY(wizard_id,generation),
 FOREIGN KEY(wizard_id) REFERENCES onboarding_wizards(id)
);
CREATE TABLE IF NOT EXISTS onboarding_intents (
 wizard_id TEXT NOT NULL,
 plan_generation INTEGER NOT NULL,
 sequence INTEGER NOT NULL,
 intent_id TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL,
 attempt INTEGER NOT NULL,
 fence INTEGER NOT NULL,
 lease_token TEXT NOT NULL DEFAULT '',
 lease_until TIMESTAMP NULL,
 record_json BLOB NOT NULL,
 updated_at TIMESTAMP NOT NULL,
 PRIMARY KEY(wizard_id,plan_generation,sequence),
 FOREIGN KEY(wizard_id,plan_generation) REFERENCES onboarding_plans(wizard_id,generation)
);
CREATE INDEX IF NOT EXISTS onboarding_intents_claim ON onboarding_intents(wizard_id,plan_generation,state,sequence,lease_until);
CREATE TABLE IF NOT EXISTS onboarding_manifests (
 wizard_id TEXT PRIMARY KEY,
 plan_generation INTEGER NOT NULL,
 digest TEXT NOT NULL,
 manifest_json BLOB NOT NULL,
 completed_at TIMESTAMP NOT NULL,
 FOREIGN KEY(wizard_id,plan_generation) REFERENCES onboarding_plans(wizard_id,generation)
);
`

type Repository struct {
	DB *sql.DB
}

func (repository Repository) Bootstrap(ctx context.Context) error {
	if repository.DB == nil || ctx == nil {
		return ErrInvalid
	}
	_, err := repository.DB.ExecContext(ctx, Schema)
	return err
}

func (repository Repository) Create(ctx context.Context, wizard Wizard) error {
	if repository.DB == nil || ctx == nil || wizard.Validate() != nil || wizard.State != StateCollecting || wizard.Revision != 1 || wizard.PlanGeneration != 0 || wizard.CurrentStep != StepHostname || wizard.IrreversibleCrossed {
		return ErrInvalid
	}
	encoded, err := json.Marshal(wizard)
	if err != nil {
		return err
	}
	_, err = repository.DB.ExecContext(ctx, `INSERT INTO onboarding_wizards(id,tenant_id,node_id,owner_id,state,revision,plan_generation,current_step,irreversible_crossed,wizard_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, wizard.ID, wizard.Scope.TenantID, wizard.Scope.NodeID, wizard.Scope.OwnerID, wizard.State, wizard.Revision, wizard.PlanGeneration, wizard.CurrentStep, 0, encoded, wizard.UpdatedAt)
	return err
}

func (repository Repository) Wizard(ctx context.Context, id WizardID) (Wizard, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) {
		return Wizard{}, ErrInvalid
	}
	var encoded []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT wizard_json FROM onboarding_wizards WHERE id=?`, id).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return Wizard{}, ErrNotFound
	}
	if err != nil {
		return Wizard{}, err
	}
	return decodeWizard(encoded, id)
}

func (repository Repository) Answers(ctx context.Context, id WizardID) (map[Step]AnswerRecord, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) {
		return nil, ErrInvalid
	}
	rows, err := repository.DB.QueryContext(ctx, `SELECT answer_json FROM onboarding_answers WHERE wizard_id=? ORDER BY revision`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	answers := make(map[Step]AnswerRecord, len(configurationSteps)+1)
	for rows.Next() {
		var encoded []byte
		if err = rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var record AnswerRecord
		if json.Unmarshal(encoded, &record) != nil || record.Validate() != nil || record.WizardID != id {
			return nil, ErrConflict
		}
		answers[record.Step] = record
	}
	return answers, rows.Err()
}

func (repository Repository) AppendAnswer(ctx context.Context, id WizardID, expectedRevision uint64, record AnswerRecord) (Wizard, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) || expectedRevision == 0 || record.Validate() != nil || record.WizardID != id || record.Revision != expectedRevision+1 {
		return Wizard{}, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Wizard{}, err
	}
	defer tx.Rollback()
	wizard, err := loadWizardTx(ctx, tx, id)
	if err != nil {
		return Wizard{}, err
	}
	if wizard.Revision != expectedRevision {
		return Wizard{}, ErrStale
	}
	step := record.Step
	if step == StepFinalClaim {
		if wizard.State != StateReview || wizard.CurrentStep != StepFinalClaim || wizard.PlanGeneration == 0 {
			return Wizard{}, ErrConflict
		}
		plan, planErr := loadPlanTx(ctx, tx, id, wizard.PlanGeneration)
		if planErr != nil {
			return Wizard{}, planErr
		}
		claim := record.Answer.FinalClaim
		warnings := make([]WarningCode, 0, len(plan.Warnings))
		for _, warning := range plan.Warnings {
			warnings = append(warnings, warning.Code)
		}
		if claim == nil || claim.PlanGeneration != plan.Generation || claim.PlanDigest != plan.Digest || !slices.Equal(claim.AcknowledgedWarnings, warnings) {
			return Wizard{}, ErrConflict
		}
		wizard.State = StateReady
	} else {
		if wizard.State != StateCollecting || wizard.PlanGeneration != 0 || stepIndex(step) < 0 || stepIndex(step) > stepIndex(wizard.CurrentStep) {
			return Wizard{}, ErrConflict
		}
		if step == wizard.CurrentStep {
			index := stepIndex(step)
			if index+1 < len(configurationSteps) {
				wizard.CurrentStep = configurationSteps[index+1]
			} else {
				wizard.CurrentStep = StepFinalClaim
			}
		}
	}
	encodedRecord, err := json.Marshal(record)
	if err != nil {
		return Wizard{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO onboarding_answers(wizard_id,step,revision,digest,answer_json,created_at) VALUES(?,?,?,?,?,?)`, record.WizardID, record.Step, record.Revision, record.Digest, encodedRecord, record.CreatedAt); err != nil {
		return Wizard{}, err
	}
	previous := wizard.Revision
	wizard.Revision, wizard.UpdatedAt = record.Revision, record.CreatedAt
	if err = updateWizardTx(ctx, tx, wizard, previous); err != nil {
		return Wizard{}, err
	}
	if err = tx.Commit(); err != nil {
		return Wizard{}, err
	}
	return wizard, nil
}

func (repository Repository) SavePlan(ctx context.Context, id WizardID, expectedRevision uint64, plan ReviewPlan, now time.Time) (Wizard, error) {
	if repository.DB == nil || ctx == nil || plan.Validate() != nil || plan.WizardID != id || plan.SourceRevision != expectedRevision || now.Location() != time.UTC || now.Before(plan.CreatedAt) {
		return Wizard{}, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Wizard{}, err
	}
	defer tx.Rollback()
	wizard, err := loadWizardTx(ctx, tx, id)
	if err != nil {
		return Wizard{}, err
	}
	if wizard.Revision != expectedRevision || wizard.State != StateCollecting && wizard.State != StateReview && wizard.State != StateReady || wizard.IrreversibleCrossed || wizard.CurrentStep != StepFinalClaim || plan.Generation != wizard.PlanGeneration+1 || plan.Scope != wizard.Scope {
		return Wizard{}, ErrStale
	}
	encodedPlan, err := json.Marshal(plan)
	if err != nil {
		return Wizard{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO onboarding_plans(wizard_id,generation,source_revision,digest,plan_json,created_at) VALUES(?,?,?,?,?,?)`, id, plan.Generation, plan.SourceRevision, plan.Digest, encodedPlan, plan.CreatedAt); err != nil {
		return Wizard{}, err
	}
	for sequence, intent := range plan.Intents {
		record := IntentRecord{Intent: intent, State: IntentPending, UpdatedAt: now}
		if record.Validate() != nil {
			return Wizard{}, ErrInvalid
		}
		encoded, marshalErr := json.Marshal(record)
		if marshalErr != nil {
			return Wizard{}, marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO onboarding_intents(wizard_id,plan_generation,sequence,intent_id,state,attempt,fence,record_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, id, plan.Generation, sequence, intent.ID, record.State, 0, 0, encoded, now); err != nil {
			return Wizard{}, err
		}
	}
	previous := wizard.Revision
	wizard.Revision, wizard.PlanGeneration, wizard.State, wizard.CurrentStep, wizard.UpdatedAt = expectedRevision+1, plan.Generation, StateReview, StepFinalClaim, now
	if err = updateWizardTx(ctx, tx, wizard, previous); err != nil {
		return Wizard{}, err
	}
	if err = tx.Commit(); err != nil {
		return Wizard{}, err
	}
	return wizard, nil
}

func (repository Repository) Plan(ctx context.Context, id WizardID, generation uint64) (ReviewPlan, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) || generation == 0 {
		return ReviewPlan{}, ErrInvalid
	}
	var encoded []byte
	err := repository.DB.QueryRowContext(ctx, `SELECT plan_json FROM onboarding_plans WHERE wizard_id=? AND generation=?`, id, generation).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ReviewPlan{}, ErrNotFound
	}
	if err != nil {
		return ReviewPlan{}, err
	}
	return decodePlan(encoded, id, generation)
}

func (repository Repository) ClaimNext(ctx context.Context, id WizardID, planGeneration uint64, worker string, leaseDuration time.Duration, crossFrontier bool, now time.Time) (Wizard, IntentLease, bool, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) || planGeneration == 0 || !validID(worker) || leaseDuration < 5*time.Second || leaseDuration > MaximumIntentLease || now.Location() != time.UTC {
		return Wizard{}, IntentLease{}, false, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	defer tx.Rollback()
	wizard, err := loadWizardTx(ctx, tx, id)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	if wizard.PlanGeneration != planGeneration || wizard.State != StateReady && wizard.State != StateApplying {
		return Wizard{}, IntentLease{}, false, ErrConflict
	}
	plan, err := loadPlanTx(ctx, tx, id, planGeneration)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	records, err := loadIntentRecordsTx(ctx, tx, plan, now)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	var candidate *IntentRecord
	for index := range records {
		record := &records[index]
		switch record.State {
		case IntentObserved:
			continue
		case IntentPending:
			candidate = record
		case IntentDispatching:
			if record.LeaseUntil.After(now) {
				return wizard, IntentLease{}, false, tx.Commit()
			}
			candidate = record
		default:
			return Wizard{}, IntentLease{}, false, ErrConflict
		}
		break
	}
	if candidate == nil {
		return wizard, IntentLease{}, false, tx.Commit()
	}
	if candidate.Intent.Step == StepFinalClaim && !crossFrontier {
		return Wizard{}, IntentLease{}, false, ErrIrreversible
	}
	previousState, previousFence := candidate.State, candidate.Fence
	if candidate.Fence == ^uint64(0) || candidate.Attempt == ^uint32(0) {
		return Wizard{}, IntentLease{}, false, ErrConflict
	}
	token, err := newLeaseToken()
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	candidate.State, candidate.Attempt, candidate.Fence = IntentDispatching, candidate.Attempt+1, candidate.Fence+1
	candidate.LeaseToken, candidate.LeaseUntil, candidate.UpdatedAt = token, now.Add(leaseDuration), now
	encodedRecord, err := json.Marshal(candidate)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE onboarding_intents SET state=?,attempt=?,fence=?,lease_token=?,lease_until=?,record_json=?,updated_at=? WHERE wizard_id=? AND plan_generation=? AND intent_id=? AND state=? AND fence=? AND (lease_until IS NULL OR lease_until<=?)`, candidate.State, candidate.Attempt, candidate.Fence, token, candidate.LeaseUntil, encodedRecord, now, id, planGeneration, candidate.Intent.ID, previousState, previousFence, now)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	if err = requireOne(result); err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	previousRevision := wizard.Revision
	changed := false
	if wizard.State == StateReady {
		wizard.State, changed = StateApplying, true
	}
	if candidate.Intent.Step == StepFinalClaim && !wizard.IrreversibleCrossed {
		wizard.IrreversibleCrossed, wizard.IrreversibleCrossedAt, changed = true, now, true
	}
	if changed {
		wizard.Revision, wizard.UpdatedAt = wizard.Revision+1, now
		if err = updateWizardTx(ctx, tx, wizard, previousRevision); err != nil {
			return Wizard{}, IntentLease{}, false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	lease := IntentLease{Record: *candidate, Token: token, Fence: candidate.Fence, Until: candidate.LeaseUntil}
	return wizard, lease, true, nil
}

func (repository Repository) RecordReceipt(ctx context.Context, plan ReviewPlan, lease IntentLease, receipt OperationReceipt, now time.Time) error {
	if repository.DB == nil || ctx == nil || plan.Validate() != nil || lease.Record.Validate() != nil || lease.Record.State != IntentDispatching || lease.Token != lease.Record.LeaseToken || lease.Fence != lease.Record.Fence || !lease.Until.Equal(lease.Record.LeaseUntil) || receipt.Validate(plan, lease.Record.Intent, now) != nil || receipt.Fence != lease.Fence || now.Location() != time.UTC || now.After(lease.Until) {
		return ErrInvalid
	}
	record := lease.Record
	record.State, record.LeaseToken, record.LeaseUntil, record.Receipt, record.UpdatedAt = IntentObserved, "", time.Time{}, &receipt, now
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE onboarding_intents SET state=?,lease_token='',lease_until=NULL,record_json=?,updated_at=? WHERE wizard_id=? AND plan_generation=? AND intent_id=? AND state=? AND fence=? AND lease_token=? AND lease_until>=?`, record.State, encoded, now, plan.WizardID, plan.Generation, record.Intent.ID, IntentDispatching, lease.Fence, lease.Token, now)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func (repository Repository) ReleaseDispatch(ctx context.Context, lease IntentLease, now time.Time) error {
	return repository.releaseLease(ctx, lease, IntentDispatching, IntentPending, now)
}

func (repository Repository) ClaimCompensation(ctx context.Context, id WizardID, planGeneration uint64, worker string, leaseDuration time.Duration, now time.Time) (Wizard, IntentLease, bool, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) || planGeneration == 0 || !validID(worker) || leaseDuration < 5*time.Second || leaseDuration > MaximumIntentLease || now.Location() != time.UTC {
		return Wizard{}, IntentLease{}, false, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	defer tx.Rollback()
	wizard, err := loadWizardTx(ctx, tx, id)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	if wizard.PlanGeneration != planGeneration || wizard.IrreversibleCrossed || wizard.State != StateReady && wizard.State != StateApplying && wizard.State != StateCompensating {
		return Wizard{}, IntentLease{}, false, ErrIrreversible
	}
	plan, err := loadPlanTx(ctx, tx, id, planGeneration)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	records, err := loadIntentRecordsTx(ctx, tx, plan, now)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	var candidate *IntentRecord
	for index := len(records) - 1; index >= 0; index-- {
		record := &records[index]
		switch record.State {
		case IntentPending, IntentCompensated:
			continue
		case IntentObserved:
			if !record.Intent.Reversible {
				return Wizard{}, IntentLease{}, false, ErrIrreversible
			}
			candidate = record
		case IntentCompensating:
			if record.LeaseUntil.After(now) {
				return wizard, IntentLease{}, false, tx.Commit()
			}
			candidate = record
		case IntentDispatching:
			return Wizard{}, IntentLease{}, false, ErrConflict
		default:
			return Wizard{}, IntentLease{}, false, ErrConflict
		}
		break
	}
	previousRevision := wizard.Revision
	if candidate == nil {
		wizard.State, wizard.Revision, wizard.UpdatedAt = StateCompensated, wizard.Revision+1, now
		if err = updateWizardTx(ctx, tx, wizard, previousRevision); err != nil {
			return Wizard{}, IntentLease{}, false, err
		}
		return wizard, IntentLease{}, false, tx.Commit()
	}
	previousState, previousFence := candidate.State, candidate.Fence
	if candidate.Fence == ^uint64(0) || candidate.Attempt == ^uint32(0) {
		return Wizard{}, IntentLease{}, false, ErrConflict
	}
	token, err := newLeaseToken()
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	candidate.State, candidate.Attempt, candidate.Fence = IntentCompensating, candidate.Attempt+1, candidate.Fence+1
	candidate.LeaseToken, candidate.LeaseUntil, candidate.UpdatedAt = token, now.Add(leaseDuration), now
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE onboarding_intents SET state=?,attempt=?,fence=?,lease_token=?,lease_until=?,record_json=?,updated_at=? WHERE wizard_id=? AND plan_generation=? AND intent_id=? AND state=? AND fence=? AND (lease_until IS NULL OR lease_until<=?)`, candidate.State, candidate.Attempt, candidate.Fence, token, candidate.LeaseUntil, encoded, now, id, planGeneration, candidate.Intent.ID, previousState, previousFence, now)
	if err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	if err = requireOne(result); err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	if wizard.State != StateCompensating {
		wizard.State, wizard.Revision, wizard.UpdatedAt = StateCompensating, wizard.Revision+1, now
		if err = updateWizardTx(ctx, tx, wizard, previousRevision); err != nil {
			return Wizard{}, IntentLease{}, false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Wizard{}, IntentLease{}, false, err
	}
	return wizard, IntentLease{Record: *candidate, Token: token, Fence: candidate.Fence, Until: candidate.LeaseUntil}, true, nil
}

func (repository Repository) RecordCompensation(ctx context.Context, plan ReviewPlan, lease IntentLease, receipt CompensationReceipt, now time.Time) error {
	if repository.DB == nil || ctx == nil || plan.Validate() != nil || lease.Record.Validate() != nil || lease.Record.State != IntentCompensating || lease.Record.Receipt == nil || lease.Token != lease.Record.LeaseToken || lease.Fence != lease.Record.Fence || !lease.Until.Equal(lease.Record.LeaseUntil) || receipt.Validate(plan, lease.Record.Intent, *lease.Record.Receipt, now) != nil || receipt.Fence != lease.Fence || now.Location() != time.UTC || now.After(lease.Until) {
		return ErrInvalid
	}
	record := lease.Record
	record.State, record.LeaseToken, record.LeaseUntil, record.Compensation, record.UpdatedAt = IntentCompensated, "", time.Time{}, &receipt, now
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE onboarding_intents SET state=?,lease_token='',lease_until=NULL,record_json=?,updated_at=? WHERE wizard_id=? AND plan_generation=? AND intent_id=? AND state=? AND fence=? AND lease_token=? AND lease_until>=?`, record.State, encoded, now, plan.WizardID, plan.Generation, record.Intent.ID, IntentCompensating, lease.Fence, lease.Token, now)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func (repository Repository) ReleaseCompensation(ctx context.Context, lease IntentLease, now time.Time) error {
	return repository.releaseLease(ctx, lease, IntentCompensating, IntentObserved, now)
}

func (repository Repository) Bundle(ctx context.Context, id WizardID, planGeneration uint64, now time.Time) (Wizard, ReviewPlan, []IntentRecord, error) {
	if repository.DB == nil || ctx == nil || !validID(string(id)) || planGeneration == 0 || now.Location() != time.UTC {
		return Wizard{}, ReviewPlan{}, nil, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return Wizard{}, ReviewPlan{}, nil, err
	}
	defer tx.Rollback()
	wizard, err := loadWizardTx(ctx, tx, id)
	if err != nil {
		return Wizard{}, ReviewPlan{}, nil, err
	}
	plan, err := loadPlanTx(ctx, tx, id, planGeneration)
	if err != nil {
		return Wizard{}, ReviewPlan{}, nil, err
	}
	records, err := loadIntentRecordsTx(ctx, tx, plan, now)
	if err != nil {
		return Wizard{}, ReviewPlan{}, nil, err
	}
	if err = tx.Commit(); err != nil {
		return Wizard{}, ReviewPlan{}, nil, err
	}
	return wizard, plan, records, nil
}

func (repository Repository) CommitManifest(ctx context.Context, expectedRevision uint64, manifest CompletionManifest) (Wizard, error) {
	if repository.DB == nil || ctx == nil || expectedRevision == 0 {
		return Wizard{}, ErrInvalid
	}
	tx, err := repository.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Wizard{}, err
	}
	defer tx.Rollback()
	wizard, err := loadWizardTx(ctx, tx, manifest.WizardID)
	if err != nil {
		return Wizard{}, err
	}
	plan, err := loadPlanTx(ctx, tx, manifest.WizardID, manifest.PlanGeneration)
	if err != nil || manifest.Validate(plan) != nil {
		return Wizard{}, ErrInvalid
	}
	if wizard.Revision != expectedRevision || wizard.State != StateApplying || !wizard.IrreversibleCrossed || wizard.PlanGeneration != manifest.PlanGeneration || !wizard.IrreversibleCrossedAt.Equal(manifest.FrontierCrossedAt) {
		return Wizard{}, ErrStale
	}
	records, err := loadIntentRecordsTx(ctx, tx, plan, manifest.CompletedAt)
	if err != nil {
		return Wizard{}, err
	}
	for index, record := range records {
		if record.State != IntentObserved || record.Receipt == nil || record.Receipt.Validate(plan, record.Intent, manifest.CompletedAt) != nil || manifest.Receipts[index].ReceiptDigest != record.Receipt.Digest || manifest.Receipts[index].ObservedGeneration != record.Receipt.ObservedGeneration {
			return Wizard{}, ErrIncomplete
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return Wizard{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO onboarding_manifests(wizard_id,plan_generation,digest,manifest_json,completed_at) VALUES(?,?,?,?,?)`, manifest.WizardID, manifest.PlanGeneration, manifest.Digest, encoded, manifest.CompletedAt); err != nil {
		return Wizard{}, err
	}
	previous := wizard.Revision
	wizard.State, wizard.Revision, wizard.UpdatedAt = StateCompleted, wizard.Revision+1, manifest.CompletedAt
	if err = updateWizardTx(ctx, tx, wizard, previous); err != nil {
		return Wizard{}, err
	}
	if err = tx.Commit(); err != nil {
		return Wizard{}, err
	}
	return wizard, nil
}

func (repository Repository) releaseLease(ctx context.Context, lease IntentLease, expected, next IntentState, now time.Time) error {
	if repository.DB == nil || ctx == nil || lease.Record.Validate() != nil || lease.Record.State != expected || lease.Token != lease.Record.LeaseToken || lease.Fence != lease.Record.Fence || now.Location() != time.UTC {
		return ErrInvalid
	}
	record := lease.Record
	record.State, record.LeaseToken, record.LeaseUntil, record.UpdatedAt = next, "", time.Time{}, now
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	result, err := repository.DB.ExecContext(ctx, `UPDATE onboarding_intents SET state=?,lease_token='',lease_until=NULL,record_json=?,updated_at=? WHERE wizard_id=? AND plan_generation=? AND intent_id=? AND state=? AND fence=? AND lease_token=?`, next, encoded, now, record.Intent.WizardID, record.Intent.PlanGeneration, record.Intent.ID, expected, lease.Fence, lease.Token)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func loadWizardTx(ctx context.Context, tx *sql.Tx, id WizardID) (Wizard, error) {
	var encoded []byte
	err := tx.QueryRowContext(ctx, `SELECT wizard_json FROM onboarding_wizards WHERE id=?`, id).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return Wizard{}, ErrNotFound
	}
	if err != nil {
		return Wizard{}, err
	}
	return decodeWizard(encoded, id)
}

func decodeWizard(encoded []byte, id WizardID) (Wizard, error) {
	var wizard Wizard
	if json.Unmarshal(encoded, &wizard) != nil || wizard.ID != id || wizard.Validate() != nil {
		return Wizard{}, ErrConflict
	}
	return wizard, nil
}

func loadPlanTx(ctx context.Context, tx *sql.Tx, id WizardID, generation uint64) (ReviewPlan, error) {
	var encoded []byte
	err := tx.QueryRowContext(ctx, `SELECT plan_json FROM onboarding_plans WHERE wizard_id=? AND generation=?`, id, generation).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return ReviewPlan{}, ErrNotFound
	}
	if err != nil {
		return ReviewPlan{}, err
	}
	return decodePlan(encoded, id, generation)
}

func decodePlan(encoded []byte, id WizardID, generation uint64) (ReviewPlan, error) {
	var plan ReviewPlan
	if json.Unmarshal(encoded, &plan) != nil || plan.WizardID != id || plan.Generation != generation || plan.Validate() != nil {
		return ReviewPlan{}, ErrConflict
	}
	return plan, nil
}

func loadIntentRecordsTx(ctx context.Context, tx *sql.Tx, plan ReviewPlan, now time.Time) ([]IntentRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT record_json FROM onboarding_intents WHERE wizard_id=? AND plan_generation=? ORDER BY sequence`, plan.WizardID, plan.Generation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]IntentRecord, 0, len(plan.Intents))
	for rows.Next() {
		var encoded []byte
		if err = rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var record IntentRecord
		if json.Unmarshal(encoded, &record) != nil || record.Validate() != nil {
			return nil, ErrConflict
		}
		records = append(records, record)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(records) != len(plan.Intents) {
		return nil, ErrConflict
	}
	for index := range records {
		if records[index].Intent.ID != plan.Intents[index].ID {
			return nil, ErrConflict
		}
		if records[index].Receipt != nil && records[index].Receipt.Validate(plan, records[index].Intent, now) != nil {
			return nil, ErrConflict
		}
		if records[index].Compensation != nil && (records[index].Receipt == nil || records[index].Compensation.Validate(plan, records[index].Intent, *records[index].Receipt, now) != nil) {
			return nil, ErrConflict
		}
	}
	return records, nil
}

func updateWizardTx(ctx context.Context, tx *sql.Tx, wizard Wizard, expectedRevision uint64) error {
	if wizard.Validate() != nil || wizard.Revision != expectedRevision+1 {
		return ErrInvalid
	}
	encoded, err := json.Marshal(wizard)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE onboarding_wizards SET state=?,revision=?,plan_generation=?,current_step=?,irreversible_crossed=?,wizard_json=?,updated_at=? WHERE id=? AND revision=?`, wizard.State, wizard.Revision, wizard.PlanGeneration, wizard.CurrentStep, boolInteger(wizard.IrreversibleCrossed), encoded, wizard.UpdatedAt, wizard.ID, expectedRevision)
	if err != nil {
		return err
	}
	return requireOne(result)
}

func newLeaseToken() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "lease-" + hex.EncodeToString(value[:]), nil
}

func boolInteger(value bool) int {
	if value {
		return 1
	}
	return 0
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
