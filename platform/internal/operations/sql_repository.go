package operations

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

const (
	createOperationResourcesTable = `CREATE TABLE IF NOT EXISTS panel_operation_resources (
kind TEXT NOT NULL,
resource_id TEXT NOT NULL,
node_id TEXT NOT NULL,
tenant_id TEXT NOT NULL,
site_id TEXT NOT NULL,
parent_id TEXT NOT NULL,
physical_key TEXT NOT NULL,
generation INTEGER NOT NULL CHECK (generation > 0),
spec_json BLOB NOT NULL,
status_json BLOB NOT NULL,
updated_at TEXT NOT NULL,
PRIMARY KEY (kind, resource_id)
)`
	createOperationPhysicalKeyIndex = `CREATE UNIQUE INDEX IF NOT EXISTS panel_operation_resource_physical_key
ON panel_operation_resources(kind, parent_id, physical_key) WHERE physical_key <> ''`
	createOperationReceiptsTable = `CREATE TABLE IF NOT EXISTS panel_operation_receipts (
node_id TEXT NOT NULL,
tenant_id TEXT NOT NULL,
scope_kind TEXT NOT NULL,
scope_id TEXT NOT NULL,
command_id TEXT NOT NULL,
command_digest TEXT NOT NULL,
status TEXT NOT NULL,
accepted_at TEXT NOT NULL,
receipt_json BLOB NOT NULL,
PRIMARY KEY (node_id, tenant_id, scope_kind, scope_id, command_id)
)`
	maximumResourceJSON = 1 << 20
	maximumReceiptJSON = 8 << 20
)

// SQLRepository persists operations in the panel-owned SQLite handle. It owns
// a process-local writer lock and executes only the fixed statements in this
// file; callers cannot provide SQL or a database path.
type SQLRepository struct {
	db *sql.DB
	writer sync.Mutex
}

func NewSQLRepository(db *sql.DB) (*SQLRepository, error) {
	if db == nil { return nil, errors.New("operations control database is required") }
	return &SQLRepository{db: db}, nil
}

func (repository *SQLRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil { return errors.New("operations repository is required") }
	repository.writer.Lock(); defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil); if err != nil { return err }; defer transaction.Rollback()
	for _, statement := range []string{createOperationResourcesTable, createOperationPhysicalKeyIndex, createOperationReceiptsTable} {
		if _, err := transaction.ExecContext(ctx, statement); err != nil { return err }
	}
	return transaction.Commit()
}

func (repository *SQLRepository) LookupOperation(ctx context.Context, scope OperationScope, commandID string) (OperationReceipt, bool, error) {
	if repository == nil || repository.db == nil || scope.NodeID.IsZero() || scope.ID.IsZero() || commandID == "" { return OperationReceipt{}, false, ErrInvalidCommand }
	row := repository.db.QueryRowContext(ctx, `SELECT receipt_json FROM panel_operation_receipts
WHERE node_id = ? AND tenant_id = ? AND scope_kind = ? AND scope_id = ? AND command_id = ?`,
		scope.NodeID.String(), scope.TenantID.String(), string(scope.Kind), scope.ID.String(), commandID)
	receipt, err := scanOperationReceipt(row)
	if errors.Is(err, sql.ErrNoRows) { return OperationReceipt{}, false, nil }
	if err != nil { return OperationReceipt{}, false, err }
	return receipt, true, nil
}

func (repository *SQLRepository) LoadResource(ctx context.Context, kind ResourceKind, id ResourceID) (ResourceEnvelope, error) {
	if repository == nil || repository.db == nil || id.IsZero() { return ResourceEnvelope{}, ErrInvalidResource }
	row := repository.db.QueryRowContext(ctx, `SELECT node_id, tenant_id, site_id, parent_id, physical_key, generation, spec_json, status_json
FROM panel_operation_resources WHERE kind = ? AND resource_id = ?`, string(kind), id.String())
	envelope, err := scanOperationResource(kind, id, row)
	if errors.Is(err, sql.ErrNoRows) { return ResourceEnvelope{}, ErrNotFound }
	return envelope, err
}

func (repository *SQLRepository) Admit(ctx context.Context, admission Admission) (AdmissionResult, error) {
	if repository == nil || repository.db == nil || validateAdmission(admission) != nil { return AdmissionResult{}, ErrInvalidReceipt }
	repository.writer.Lock(); defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil); if err != nil { return AdmissionResult{}, err }; defer transaction.Rollback()
	existing, found, err := lookupOperationTx(ctx, transaction, admission.Scope, admission.CommandID)
	if err != nil { return AdmissionResult{}, err }
	if found {
		if existing.CommandDigest != admission.CommandDigest { return AdmissionResult{Kind: AdmissionConflict}, nil }
		return AdmissionResult{Kind: AdmissionExistingSame, Receipt: existing}, nil
	}
	for _, mutation := range admission.Mutations {
		conflict, err := applyResourceMutation(ctx, transaction, mutation, admission.AcceptedAt)
		if err != nil { return AdmissionResult{}, err }
		if conflict { return AdmissionResult{Kind: AdmissionConflict}, nil }
	}
	receipt := OperationReceipt{CommandID: admission.CommandID, CommandDigest: admission.CommandDigest, Scope: admission.Scope,
		Status: OperationAccepted, AcceptedAt: admission.AcceptedAt.UTC(), Request: admission.Request,
		Mutations: cloneMutations(admission.Mutations), Rollback: cloneMutations(admission.Rollback),
		Success: append([]ObservedResource(nil), admission.Success...), Restored: append([]ObservedResource(nil), admission.Restored...)}
	encoded, err := json.Marshal(receipt); if err != nil || len(encoded) > maximumReceiptJSON { return AdmissionResult{}, ErrInvalidReceipt }
	_, err = transaction.ExecContext(ctx, `INSERT INTO panel_operation_receipts
(node_id, tenant_id, scope_kind, scope_id, command_id, command_digest, status, accepted_at, receipt_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, admission.Scope.NodeID.String(), admission.Scope.TenantID.String(), string(admission.Scope.Kind), admission.Scope.ID.String(),
		admission.CommandID, admission.CommandDigest, string(OperationAccepted), admission.AcceptedAt.UTC().Format(time.RFC3339Nano), encoded)
	if err != nil { return AdmissionResult{}, err }
	if err := transaction.Commit(); err != nil { return AdmissionResult{}, err }
	return AdmissionResult{Kind: AdmissionNew, Receipt: receipt}, nil
}

func (repository *SQLRepository) Complete(ctx context.Context, completion Completion) (OperationReceipt, error) {
	if repository == nil || repository.db == nil || completion.Scope.NodeID.IsZero() || completion.Scope.ID.IsZero() { return OperationReceipt{}, ErrInvalidReceipt }
	repository.writer.Lock(); defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil); if err != nil { return OperationReceipt{}, err }; defer transaction.Rollback()
	receipt, found, err := lookupOperationTx(ctx, transaction, completion.Scope, completion.CommandID)
	if err != nil { return OperationReceipt{}, err }
	if !found { return OperationReceipt{}, ErrNotFound }
	if receipt.CommandDigest != completion.CommandDigest || receipt.Scope != completion.Scope { return OperationReceipt{}, ErrIdempotency }
	if terminalOperation(receipt.Status) { return receipt, transaction.Commit() }
	if !validCompletionStatus(completion.Status) || completion.Status == OperationAmbiguous && len(completion.Observed) != 0 { return OperationReceipt{}, ErrInvalidReceipt }
	completedAt := time.Now().UTC()
	if completion.Status == OperationRejected || completion.Status == OperationCompensated {
		for _, mutation := range receipt.Rollback {
			conflict, err := applyResourceMutation(ctx, transaction, mutation, completedAt)
			if err != nil { return OperationReceipt{}, err }
			if conflict { return OperationReceipt{}, ErrConflict }
		}
	}
	for _, observation := range completion.Observed {
		if !observationBelongsToCompletion(observation, receipt, completion.Status) { return OperationReceipt{}, ErrInvalidReceipt }
		statusJSON, err := json.Marshal(observation.Status); if err != nil { return OperationReceipt{}, err }
		result, err := transaction.ExecContext(ctx, `UPDATE panel_operation_resources SET status_json = ?,
physical_key = CASE WHEN ? = 'deleted' THEN '' ELSE physical_key END, updated_at = ?
WHERE kind = ? AND resource_id = ? AND generation = ?`, statusJSON, string(observation.Status.Lifecycle), completedAt.Format(time.RFC3339Nano),
			string(observation.Kind), observation.ID.String(), observation.Generation)
		if err != nil { return OperationReceipt{}, err }
		rows, err := result.RowsAffected(); if err != nil || rows != 1 { return OperationReceipt{}, ErrConflict }
	}
	receipt.Status, receipt.Effect, receipt.Compensation = completion.Status, completion.Effect, completion.Compensation
	if completion.Status == OperationApplied { receipt.Success = append([]ObservedResource(nil), completion.Observed...) }
	if completion.Status == OperationRejected || completion.Status == OperationCompensated { receipt.Restored = append([]ObservedResource(nil), completion.Observed...) }
	if validateStoredReceipt(receipt, receipt.CommandID, receipt.CommandDigest, receipt.Scope) != nil { return OperationReceipt{}, ErrInvalidReceipt }
	encoded, err := json.Marshal(receipt); if err != nil || len(encoded) > maximumReceiptJSON { return OperationReceipt{}, ErrInvalidReceipt }
	result, err := transaction.ExecContext(ctx, `UPDATE panel_operation_receipts SET status = ?, receipt_json = ?
WHERE node_id = ? AND tenant_id = ? AND scope_kind = ? AND scope_id = ? AND command_id = ? AND command_digest = ?`,
		string(completion.Status), encoded, completion.Scope.NodeID.String(), completion.Scope.TenantID.String(), string(completion.Scope.Kind), completion.Scope.ID.String(), completion.CommandID, completion.CommandDigest)
	if err != nil { return OperationReceipt{}, err }
	rows, err := result.RowsAffected(); if err != nil || rows != 1 { return OperationReceipt{}, ErrConflict }
	if err := transaction.Commit(); err != nil { return OperationReceipt{}, err }
	return receipt, nil
}

type rowScanner interface { Scan(...any) error }

func scanOperationReceipt(row rowScanner) (OperationReceipt, error) {
	var encoded []byte
	if err := row.Scan(&encoded); err != nil { return OperationReceipt{}, err }
	if len(encoded) == 0 || len(encoded) > maximumReceiptJSON { return OperationReceipt{}, ErrInvalidReceipt }
	var receipt OperationReceipt
	if strictJSON(encoded, &receipt) != nil { return OperationReceipt{}, fmt.Errorf("decode operations receipt: %w", ErrInvalidReceipt) }
	return receipt, nil
}

func scanOperationResource(kind ResourceKind, id ResourceID, row rowScanner) (ResourceEnvelope, error) {
	var nodeRaw, tenantRaw, siteRaw, parentRaw, physicalKey string
	var generation uint64
	var specJSON, statusJSON []byte
	if err := row.Scan(&nodeRaw, &tenantRaw, &siteRaw, &parentRaw, &physicalKey, &generation, &specJSON, &statusJSON); err != nil { return ResourceEnvelope{}, err }
	if len(specJSON) == 0 || len(specJSON) > maximumResourceJSON || len(statusJSON) == 0 || len(statusJSON) > 4096 { return ResourceEnvelope{}, ErrInvalidResource }
	nodeID, err := NewResourceID(nodeRaw); if err != nil { return ResourceEnvelope{}, ErrInvalidResource }
	metadata := Metadata{ID: id, NodeID: nodeID, Generation: generation}
	if tenantRaw != "" { tenantID, err := site.NewTenantID(tenantRaw); if err != nil { return ResourceEnvelope{}, ErrInvalidResource }; metadata.TenantID = tenantID }
	if siteRaw != "" { siteID, err := site.NewSiteID(siteRaw); if err != nil { return ResourceEnvelope{}, ErrInvalidResource }; metadata.SiteID = siteID }
	if strictJSON(statusJSON, &metadata.Status) != nil || !validStatus(metadata.Status) { return ResourceEnvelope{}, ErrInvalidResource }
	var parentID ResourceID
	if parentRaw != "" { parentID, err = NewResourceID(parentRaw); if err != nil { return ResourceEnvelope{}, ErrInvalidResource } }
	envelope := ResourceEnvelope{Kind: kind, Metadata: metadata, ParentID: parentID, PhysicalKey: physicalKey, Spec: append([]byte(nil), specJSON...)}
	if _, err := DecodeResource(envelope); err != nil { return ResourceEnvelope{}, err }
	return envelope, nil
}

func lookupOperationTx(ctx context.Context, transaction *sql.Tx, scope OperationScope, commandID string) (OperationReceipt, bool, error) {
	row := transaction.QueryRowContext(ctx, `SELECT receipt_json FROM panel_operation_receipts
WHERE node_id = ? AND tenant_id = ? AND scope_kind = ? AND scope_id = ? AND command_id = ?`,
		scope.NodeID.String(), scope.TenantID.String(), string(scope.Kind), scope.ID.String(), commandID)
	receipt, err := scanOperationReceipt(row)
	if errors.Is(err, sql.ErrNoRows) { return OperationReceipt{}, false, nil }
	if err != nil { return OperationReceipt{}, false, err }
	return receipt, true, nil
}

func applyResourceMutation(ctx context.Context, transaction *sql.Tx, mutation ResourceMutation, now time.Time) (bool, error) {
	if mutation.Kind != MutationUpsert || mutation.Resource.Metadata.ID.IsZero() || len(mutation.Resource.Spec) > maximumResourceJSON { return false, ErrInvalidResource }
	if _, err := DecodeResource(mutation.Resource); err != nil { return false, err }
	resource := mutation.Resource
	statusJSON, err := json.Marshal(resource.Metadata.Status); if err != nil { return false, err }
	if mutation.ExpectedGeneration == 0 {
		_, err := transaction.ExecContext(ctx, `INSERT INTO panel_operation_resources
(kind, resource_id, node_id, tenant_id, site_id, parent_id, physical_key, generation, spec_json, status_json, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, string(resource.Kind), resource.Metadata.ID.String(), resource.Metadata.NodeID.String(), resource.Metadata.TenantID.String(),
			resource.Metadata.SiteID.String(), resource.ParentID.String(), resource.PhysicalKey, resource.Metadata.Generation, []byte(resource.Spec), statusJSON, now.UTC().Format(time.RFC3339Nano))
		if err != nil { if isConstraintError(err) { return true, nil }; return false, err }
		return false, nil
	}
	if resource.Metadata.Generation != mutation.ExpectedGeneration+1 { return false, ErrConflict }
	result, err := transaction.ExecContext(ctx, `UPDATE panel_operation_resources SET node_id = ?, tenant_id = ?, site_id = ?, parent_id = ?, physical_key = ?,
generation = ?, spec_json = ?, status_json = ?, updated_at = ? WHERE kind = ? AND resource_id = ? AND generation = ?`,
		resource.Metadata.NodeID.String(), resource.Metadata.TenantID.String(), resource.Metadata.SiteID.String(), resource.ParentID.String(), resource.PhysicalKey,
		resource.Metadata.Generation, []byte(resource.Spec), statusJSON, now.UTC().Format(time.RFC3339Nano), string(resource.Kind), resource.Metadata.ID.String(), mutation.ExpectedGeneration)
	if err != nil { if isConstraintError(err) { return true, nil }; return false, err }
	rows, err := result.RowsAffected(); if err != nil { return false, err }
	return rows != 1, nil
}

func validateAdmission(admission Admission) error {
	if admission.CommandID == "" || !validSHA256(admission.CommandDigest) || admission.Scope.NodeID.IsZero() || admission.Scope.ID.IsZero() || admission.AcceptedAt.IsZero() ||
		validateEffectRequest(admission.Request) != nil || admission.Request.Scope != admission.Scope || len(admission.Mutations) != len(admission.Rollback) ||
		len(admission.Mutations) != len(admission.Success) || len(admission.Mutations) != len(admission.Restored) { return ErrInvalidReceipt }
	for index := range admission.Mutations { if !validRollbackPair(admission.Mutations[index], admission.Rollback[index]) { return ErrInvalidReceipt } }
	return nil
}

func validCompletionStatus(status OperationStatus) bool { return status == OperationApplied || status == OperationRejected || status == OperationCompensated || status == OperationAmbiguous }

func observationBelongsToCompletion(observation ObservedResource, receipt OperationReceipt, status OperationStatus) bool {
	if observation.ID.IsZero() || observation.Generation == 0 || !validStatus(observation.Status) { return false }
	mutations := receipt.Mutations
	if status == OperationRejected || status == OperationCompensated { mutations = receipt.Rollback }
	for _, mutation := range mutations {
		if mutation.Resource.Kind == observation.Kind && mutation.Resource.Metadata.ID == observation.ID && mutation.Resource.Metadata.Generation == observation.Generation { return true }
	}
	return false
}

func strictJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded)); decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return err }
	if err := decoder.Decode(&struct{}{}); err != io.EOF { return ErrInvalidResource }
	return nil
}

func isConstraintError(err error) bool {
	if err == nil { return false }
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "constraint") || strings.Contains(message, "unique")
}
