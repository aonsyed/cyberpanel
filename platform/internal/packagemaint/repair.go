package packagemaint

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type RepairPlan struct {
	ID string `json:"id"`
	NodeID string `json:"node_id"`
	Manager Manager `json:"manager"`
	RepairCode string `json:"repair_code"`
	InventoryID string `json:"inventory_id"`
	InventoryDigest string `json:"inventory_digest"`
	InventoryGeneration uint64 `json:"inventory_generation"`
	PolicyDigest string `json:"policy_digest"`
	MaintenanceOccurrenceID string `json:"maintenance_occurrence_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Digest string `json:"digest"`
}

func SealRepairPlan(plan *RepairPlan) error {
	if plan == nil { return ErrInvalid }
	provided := plan.Digest; plan.Digest = ""
	if !safeID.MatchString(plan.ID) || !safeID.MatchString(plan.NodeID) || !validManager(plan.Manager) || !safeID.MatchString(plan.InventoryID) || !validDigest(plan.InventoryDigest) || plan.InventoryGeneration == 0 || plan.InventoryGeneration >= uint64(1<<63-1) || !validDigest(plan.PolicyDigest) || !safeID.MatchString(plan.MaintenanceOccurrenceID) || plan.CreatedAt.IsZero() || plan.CreatedAt.Location() != time.UTC || !plan.ExpiresAt.After(plan.CreatedAt) || plan.ExpiresAt.Sub(plan.CreatedAt) > 30*time.Minute || plan.Manager == ManagerAPT && plan.RepairCode != "dpkg-audit" || plan.Manager == ManagerDNF && plan.RepairCode != "rpm-verifydb" { return ErrInvalid }
	digest, err := canonicalDigest(plan); if err != nil { return err }; plan.Digest = digest
	if provided != "" && provided != digest { return ErrConflict }; return nil
}

func (plan RepairPlan) Validate() error { copy := plan; if SealRepairPlan(&copy) != nil || copy != plan { return ErrInvalid }; return nil }

type RepairRequest struct { Plan RepairPlan `json:"plan"`; Authorization AuthorizationEvidence `json:"authorization"` }
type RepairResult struct {
	PlanID string `json:"plan_id"`; PlanDigest string `json:"plan_digest"`; State string `json:"state"`
	Command CommandReceipt `json:"command"`; After InventorySnapshot `json:"after"`
	ObservedAt time.Time `json:"observed_at"`; Digest string `json:"digest"`
}
type RepairRecord struct { Plan RepairPlan `json:"plan"`; Request *RepairRequest `json:"request,omitempty"`; Result *RepairResult `json:"result,omitempty"`; State string `json:"state"` }

func (request RepairRequest) Validate() error {
	if request.Plan.Validate() != nil || validateEvidenceStored(request.Authorization, AssurancePhishingResistant) != nil || request.Authorization.PolicyDigest != request.Plan.PolicyDigest || request.Authorization.Scope != "package-maintenance:repair:"+request.Plan.ID { return ErrUnauthorized }
	expected := RepairAuthorizationRequest(request.Plan, request.Authorization.ActorID)
	if request.Authorization.RequestDigest != expected.RequestDigest { return ErrUnauthorized }; return nil
}

func RepairAuthorizationRequest(plan RepairPlan, actor string) AuthorizationRequest {
	request := AuthorizationRequest{Boundary: BoundaryCommit, OperationID: plan.ID, ActorID: actor, Scope: "package-maintenance:repair:"+plan.ID, PlanID: plan.ID, PlanDigest: plan.Digest, PlanGeneration: plan.InventoryGeneration, MinimumAssurance: AssurancePhishingResistant, Irreversible: true}
	request.RequestDigest, _ = canonicalDigest(request); return request
}

func sealRepairResult(result *RepairResult) error { result.Digest = ""; digest, err := canonicalDigest(result); result.Digest = digest; return err }
func (result RepairResult) Validate(plan RepairPlan) error {
	copy := result; if sealRepairResult(&copy) != nil || copy.Digest != result.Digest || result.PlanID != plan.ID || result.PlanDigest != plan.Digest || result.ObservedAt.IsZero() || result.State != "succeeded" && result.State != "failed" && result.State != "ambiguous" { return ErrInvalid }
	if result.State != "ambiguous" && (result.After.Validate() != nil || result.After.NodeID != plan.NodeID || result.After.Manager != plan.Manager || result.After.Generation != plan.InventoryGeneration+1) { return ErrInvalid }
	if result.State == "succeeded" {
		if result.Command.ExitCode != 0 || result.Command.StartedAt.IsZero() || result.Command.CompletedAt.Before(result.Command.StartedAt) || !validDigest(result.Command.ArgvDigest) || !validDigest(result.Command.OutputDigest) { return ErrInvalid }
		for _, lock := range result.After.Locks { if lock.Held || lock.RepairCode != "" { return ErrRecoveryRequired } }
	}
	return nil
}

func (repository *SQLRepository) BootstrapRepair(ctx context.Context) error {
	_, err := repository.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS package_maintenance_repairs(id TEXT PRIMARY KEY,node_id TEXT NOT NULL,manager TEXT NOT NULL,state TEXT NOT NULL,plan_digest TEXT NOT NULL,record_json BLOB NOT NULL)`); return err
}

func (repository *SQLRepository) SaveRepairPlan(ctx context.Context, plan RepairPlan) error {
	if plan.Validate() != nil { return ErrInvalid }
	record := RepairRecord{Plan: plan, State: "planned"}; raw, err := json.Marshal(record); if err != nil { return err }
	_, err = repository.db.ExecContext(ctx, `INSERT INTO package_maintenance_repairs(id,node_id,manager,state,plan_digest,record_json) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,plan.ID,plan.NodeID,string(plan.Manager),record.State,plan.Digest,raw)
	if err != nil { return err }; stored, err := repository.Repair(ctx,plan.ID); if err != nil { return err }; if stored.Plan != plan { return ErrConflict }; return nil
}

func scanRepair(scanner interface{ Scan(...any) error }) (RepairRecord,error) {
	var raw []byte; var state,digest string
	if err := scanner.Scan(&raw,&state,&digest); errors.Is(err,sql.ErrNoRows) { return RepairRecord{},ErrNotFound } else if err != nil { return RepairRecord{},err }
	var record RepairRecord
	if json.Unmarshal(raw,&record) != nil || record.Plan.Validate() != nil || record.Plan.Digest != digest || record.State != state || state != "planned" && state != "executing" && state != "succeeded" && state != "failed" && state != "ambiguous" { return RepairRecord{},ErrInvalid }
	if state != "planned" && (record.Request == nil || record.Request.Validate() != nil || record.Request.Plan != record.Plan) { return RepairRecord{},ErrInvalid }
	if state == "succeeded" || state == "failed" || state == "ambiguous" { if record.Result == nil || record.Result.Validate(record.Plan) != nil || record.Result.State != state { return RepairRecord{},ErrInvalid } }
	return record,nil
}

func (repository *SQLRepository) Repair(ctx context.Context,id string) (RepairRecord,error) { if !safeID.MatchString(id) { return RepairRecord{},ErrInvalid }; record,err := scanRepair(repository.db.QueryRowContext(ctx,`SELECT record_json,state,plan_digest FROM package_maintenance_repairs WHERE id=?`,id)); if err == nil && record.Plan.ID != id { return RepairRecord{},ErrInvalid }; return record,err }
func (repository *SQLRepository) LatestRepair(ctx context.Context,node string,manager Manager) (RepairRecord,error) { record,err := scanRepair(repository.db.QueryRowContext(ctx,`SELECT record_json,state,plan_digest FROM package_maintenance_repairs WHERE node_id=? AND manager=? ORDER BY rowid DESC LIMIT 1`,node,string(manager))); if err == nil && (record.Plan.NodeID != node || record.Plan.Manager != manager) { return RepairRecord{},ErrInvalid }; return record,err }
func (repository *SQLRepository) RepairBlocked(ctx context.Context,node string,manager Manager) error {
	var count int; err := repository.db.QueryRowContext(ctx,`SELECT COUNT(*) FROM package_maintenance_repairs WHERE node_id=? AND manager=? AND state IN ('executing','ambiguous')`,node,string(manager)).Scan(&count); if err != nil { return err }; if count != 0 { return ErrRecoveryRequired }; return nil
}

func (repository *SQLRepository) StartRepair(ctx context.Context,request RepairRequest) (RepairRecord,error) {
	if request.Validate() != nil { return RepairRecord{},ErrInvalid }
	repository.writer.Lock(); defer repository.writer.Unlock()
	tx,err := repository.db.BeginTx(ctx,nil); if err != nil { return RepairRecord{},err }; defer tx.Rollback()
	record,err := scanRepair(tx.QueryRowContext(ctx,`SELECT record_json,state,plan_digest FROM package_maintenance_repairs WHERE id=?`,request.Plan.ID)); if err != nil { return RepairRecord{},err }
	if record.Plan != request.Plan || record.State != "planned" { return RepairRecord{},ErrConflict }
	var active int
	if err = tx.QueryRowContext(ctx,`SELECT (SELECT COUNT(*) FROM package_maintenance_repairs WHERE state IN ('executing','ambiguous')) + (SELECT COUNT(*) FROM package_maintenance_operations WHERE state IN ('authorized','running','verifying'))`).Scan(&active); err != nil { return RepairRecord{},err }; if active != 0 { return RepairRecord{},ErrLocked }
	record.State,record.Request = "executing",&request; raw,err := json.Marshal(record); if err != nil { return RepairRecord{},err }
	changed,err := tx.ExecContext(ctx,`UPDATE package_maintenance_repairs SET state='executing',record_json=? WHERE id=? AND state='planned' AND plan_digest=?`,raw,request.Plan.ID,request.Plan.Digest); if err != nil { return RepairRecord{},err }; count,err := changed.RowsAffected(); if err != nil || count != 1 { return RepairRecord{},ErrConflict }
	if err = tx.Commit(); err != nil { return RepairRecord{},err }; return record,nil
}

func (repository *SQLRepository) FinishRepair(ctx context.Context,result RepairResult) (RepairRecord,error) {
	record,err := repository.Repair(ctx,result.PlanID); if err != nil { return record,err }
	if result.Validate(record.Plan) != nil { return record,ErrInvalid }
	if record.Result != nil { if record.Result.Digest == result.Digest { return record,nil }; return record,ErrConflict }
	if record.State != "executing" { return record,ErrConflict }
	record.State,record.Result = result.State,&result; raw,err := json.Marshal(record); if err != nil { return record,err }
	changed,err := repository.db.ExecContext(ctx,`UPDATE package_maintenance_repairs SET state=?,record_json=? WHERE id=? AND state='executing' AND plan_digest=?`,record.State,raw,record.Plan.ID,record.Plan.Digest); if err != nil { return record,err }; count,err := changed.RowsAffected(); if err != nil || count != 1 { return record,ErrConflict }; return record,nil
}
