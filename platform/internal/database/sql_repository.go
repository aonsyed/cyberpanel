package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

const (
	createResourcesTable = `CREATE TABLE IF NOT EXISTS panel_database_resources (
kind TEXT NOT NULL,
resource_id TEXT NOT NULL,
tenant_id TEXT NOT NULL,
site_id TEXT NOT NULL,
parent_id TEXT NOT NULL,
physical_name TEXT NOT NULL,
generation INTEGER NOT NULL CHECK (generation > 0),
spec_json BLOB NOT NULL,
status_json BLOB NOT NULL,
updated_at TEXT NOT NULL,
PRIMARY KEY (kind, resource_id)
)`
	createPhysicalNameIndex = `CREATE UNIQUE INDEX IF NOT EXISTS panel_database_resource_physical_name
ON panel_database_resources(kind, parent_id, physical_name) WHERE physical_name <> ''`
	createOperationsTable = `CREATE TABLE IF NOT EXISTS panel_database_operations (
scope_tenant_id TEXT NOT NULL,
scope_kind TEXT NOT NULL,
scope_id TEXT NOT NULL,
command_id TEXT NOT NULL,
command_digest TEXT NOT NULL,
status TEXT NOT NULL,
accepted_at TEXT NOT NULL,
receipt_json BLOB NOT NULL,
PRIMARY KEY (scope_tenant_id, scope_kind, scope_id, command_id)
)`
)

// SQLRepository is the one-writer SQLite control repository. The injected
// database handle is configured and owned by paneld; this type never opens a
// caller-selected path and never executes caller-provided SQL.
type SQLRepository struct {
	db     *sql.DB
	writer sync.Mutex
}

func NewSQLRepository(db *sql.DB) (*SQLRepository, error) {
	if db == nil { return nil, errors.New("database control handle is required") }
	return &SQLRepository{db: db}, nil
}

func (repository *SQLRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil { return errors.New("database repository is required") }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer transaction.Rollback()
	for _, statement := range []string{createResourcesTable, createPhysicalNameIndex, createOperationsTable, createTransferPromotionsTable} {
		if _, err := transaction.ExecContext(ctx, statement); err != nil { return err }
	}
	return transaction.Commit()
}

// EnsureBootstrapResources installs the node-local MariaDB instance and its
// loopback policy exactly once. Existing rows must be byte-for-byte identical;
// bootstrap never overwrites operator state.
func (repository *SQLRepository) EnsureBootstrapResources(ctx context.Context, resources ...Resource) error {
	if repository==nil||repository.db==nil||len(resources)==0{return ErrInvalidResource};repository.writer.Lock();defer repository.writer.Unlock();transaction,err:=repository.db.BeginTx(ctx,nil);if err!=nil{return err};defer transaction.Rollback();now:=time.Now().UTC()
	for _,resource:=range resources{envelope,encodeErr:=EncodeResource(resource);if encodeErr!=nil{return encodeErr};status,marshalErr:=json.Marshal(envelope.Metadata.Status);if marshalErr!=nil{return marshalErr};var storedSpec,storedStatus []byte;var generation uint64;scanErr:=transaction.QueryRowContext(ctx,`SELECT generation,spec_json,status_json FROM panel_database_resources WHERE kind=? AND resource_id=?`,string(envelope.Kind),envelope.Metadata.ID.String()).Scan(&generation,&storedSpec,&storedStatus);if scanErr==nil{if generation!=envelope.Metadata.Generation||!jsonBytesEqual(storedSpec,envelope.Spec)||!jsonBytesEqual(storedStatus,status){return ErrConflict};continue};if !errors.Is(scanErr,sql.ErrNoRows){return scanErr};if _,insertErr:=transaction.ExecContext(ctx,`INSERT INTO panel_database_resources(kind,resource_id,tenant_id,site_id,parent_id,physical_name,generation,spec_json,status_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,string(envelope.Kind),envelope.Metadata.ID.String(),envelope.Metadata.TenantID.String(),envelope.Metadata.SiteID.String(),envelope.ParentID.String(),envelope.PhysicalName,envelope.Metadata.Generation,[]byte(envelope.Spec),status,now.Format(time.RFC3339Nano));insertErr!=nil{return insertErr}}
	return transaction.Commit()
}

func jsonBytesEqual(left,right []byte)bool{var leftValue,rightValue any;if json.Unmarshal(left,&leftValue)!=nil||json.Unmarshal(right,&rightValue)!=nil{return false};leftCanonical,_:=json.Marshal(leftValue);rightCanonical,_:=json.Marshal(rightValue);return string(leftCanonical)==string(rightCanonical)}

func (repository *SQLRepository) LookupOperation(ctx context.Context, scope OperationScope, commandID string) (OperationReceipt, bool, error) {
	if repository == nil || repository.db == nil || scope.ID.IsZero() { return OperationReceipt{}, false, ErrInvalidCommand }
	row := repository.db.QueryRowContext(ctx, `SELECT receipt_json FROM panel_database_operations
WHERE scope_tenant_id = ? AND scope_kind = ? AND scope_id = ? AND command_id = ?`,
		scope.TenantID.String(), string(scope.Kind), scope.ID.String(), commandID)
	receipt, err := scanOperation(row)
	if errors.Is(err, sql.ErrNoRows) { return OperationReceipt{}, false, nil }
	if err != nil { return OperationReceipt{}, false, err }
	return receipt, true, nil
}

func (repository *SQLRepository) LoadResource(ctx context.Context, kind ResourceKind, id ResourceID) (ResourceEnvelope, error) {
	if repository == nil || repository.db == nil || id.IsZero() { return ResourceEnvelope{}, ErrInvalidResource }
	row := repository.db.QueryRowContext(ctx, `SELECT tenant_id, site_id, parent_id, physical_name, generation, spec_json, status_json
FROM panel_database_resources WHERE kind = ? AND resource_id = ?`, string(kind), id.String())
	envelope, err := scanResource(kind, id, row)
	if errors.Is(err, sql.ErrNoRows) { return ResourceEnvelope{}, ErrNotFound }
	return envelope, err
}

// ListDatabases returns tenant-owned database resources in stable resource-ID
// order. The cursor is the last resource ID observed by the caller; no SQL or
// physical database identifier crosses this query boundary.
func (repository *SQLRepository) ListDatabases(ctx context.Context, tenant site.TenantID, cursor string, limit uint16) ([]Database, string, uint64, error) {
	if repository == nil || repository.db == nil || tenant.String() == "" || len(cursor) > 128 { return nil, "", 0, ErrInvalidResource }
	if limit == 0 { limit = 100 }; if limit > 500 { return nil, "", 0, ErrInvalidResource }
	var total uint64
	if err := repository.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_database_resources WHERE kind=? AND tenant_id=? AND json_extract(status_json,'$.lifecycle')<>'deleted'`, string(KindDatabase), tenant.String()).Scan(&total); err != nil { return nil, "", 0, err }
	rows, err := repository.db.QueryContext(ctx, `SELECT resource_id,site_id,parent_id,physical_name,generation,spec_json,status_json FROM panel_database_resources WHERE kind=? AND tenant_id=? AND resource_id>? AND json_extract(status_json,'$.lifecycle')<>'deleted' ORDER BY resource_id LIMIT ?`, string(KindDatabase), tenant.String(), cursor, int(limit)+1)
	if err != nil { return nil, "", 0, err }; defer rows.Close()
	values := make([]Database,0,limit); next := ""
	for rows.Next() {
		var idRaw,siteRaw,parentRaw,physical string; var generation uint64; var spec,status []byte
		if err=rows.Scan(&idRaw,&siteRaw,&parentRaw,&physical,&generation,&spec,&status);err!=nil{return nil,"",0,err}
		if len(values)==int(limit){next=values[len(values)-1].ID.String();break}
		id,parseErr:=NewResourceID(idRaw);if parseErr!=nil{return nil,"",0,ErrInvalidResource};siteID,parseErr:=site.NewSiteID(siteRaw);if parseErr!=nil{return nil,"",0,ErrInvalidResource};parent,parseErr:=NewResourceID(parentRaw);if parseErr!=nil{return nil,"",0,ErrInvalidResource}
		metadata:=Metadata{ID:id,TenantID:tenant,SiteID:siteID,Generation:generation};if json.Unmarshal(status,&metadata.Status)!=nil{return nil,"",0,ErrInvalidResource}
		resource,decodeErr:=DecodeResource(ResourceEnvelope{Kind:KindDatabase,Metadata:metadata,ParentID:parent,PhysicalName:physical,Spec:spec});if decodeErr!=nil{return nil,"",0,decodeErr};databaseValue,ok:=resource.(*Database);if !ok{return nil,"",0,ErrInvalidResource};values=append(values,*databaseValue)
	}
	if err=rows.Err();err!=nil{return nil,"",0,err};return values,next,total,nil
}

// ListDatabaseInstances returns the installation-owned MariaDB placement
// catalog. Secret references remain inside the domain resource; API adapters
// must project only non-secret connection and health metadata.
func (repository *SQLRepository) ListDatabaseInstances(ctx context.Context, cursor string, limit uint16) ([]DatabaseInstance, string, uint64, error) {
	if repository == nil || repository.db == nil || len(cursor) > 128 {
		return nil, "", 0, ErrInvalidResource
	}
	if limit == 0 {
		limit = 100
	}
	if limit > 500 {
		return nil, "", 0, ErrInvalidResource
	}
	var total uint64
	if err := repository.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_database_resources
WHERE kind=? AND tenant_id='' AND json_extract(status_json,'$.lifecycle')<>'deleted'`, string(KindDatabaseInstance)).Scan(&total); err != nil {
		return nil, "", 0, err
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT resource_id,generation,spec_json,status_json
FROM panel_database_resources
WHERE kind=? AND tenant_id='' AND resource_id>? AND json_extract(status_json,'$.lifecycle')<>'deleted'
ORDER BY resource_id LIMIT ?`, string(KindDatabaseInstance), cursor, int(limit)+1)
	if err != nil {
		return nil, "", 0, err
	}
	defer rows.Close()
	values := make([]DatabaseInstance, 0, limit)
	next := ""
	for rows.Next() {
		var idRaw string
		var generation uint64
		var spec, statusJSON []byte
		if err = rows.Scan(&idRaw, &generation, &spec, &statusJSON); err != nil {
			return nil, "", 0, err
		}
		if len(values) == int(limit) {
			next = values[len(values)-1].ID.String()
			break
		}
		id, parseErr := NewResourceID(idRaw)
		if parseErr != nil {
			return nil, "", 0, ErrInvalidResource
		}
		metadata := Metadata{ID: id, Generation: generation}
		if json.Unmarshal(statusJSON, &metadata.Status) != nil {
			return nil, "", 0, ErrInvalidResource
		}
		resource, decodeErr := DecodeResource(ResourceEnvelope{Kind: KindDatabaseInstance, Metadata: metadata, Spec: spec})
		if decodeErr != nil {
			return nil, "", 0, decodeErr
		}
		instance, ok := resource.(*DatabaseInstance)
		if !ok {
			return nil, "", 0, ErrInvalidResource
		}
		values = append(values, *instance)
	}
	if err = rows.Err(); err != nil {
		return nil, "", 0, err
	}
	return values, next, total, nil
}

func (repository *SQLRepository) DatabasePrincipalCount(ctx context.Context, tenant site.TenantID, databaseID ResourceID) (uint64,error) {
	if repository==nil||repository.db==nil||tenant.String()==""||databaseID.IsZero(){return 0,ErrInvalidResource};var count uint64
	err:=repository.db.QueryRowContext(ctx,`SELECT COUNT(DISTINCT json_extract(spec_json,'$.principal_id')) FROM panel_database_resources WHERE kind=? AND tenant_id=? AND parent_id=? AND json_extract(status_json,'$.lifecycle')<>'deleted'`,string(KindGrantSet),tenant.String(),databaseID.String()).Scan(&count);return count,err
}

func (repository *SQLRepository) Admit(ctx context.Context, admission Admission) (AdmissionResult, error) {
	if repository == nil || repository.db == nil || validateAdmission(admission) != nil { return AdmissionResult{}, ErrInvalidReceipt }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return AdmissionResult{}, err }
	defer transaction.Rollback()

	existing, found, err := lookupOperationTx(ctx, transaction, admission.Scope, admission.CommandID)
	if err != nil { return AdmissionResult{}, err }
	if found {
		if existing.CommandDigest != admission.CommandDigest {
			return AdmissionResult{Kind: AdmissionConflict}, nil
		}
		return AdmissionResult{Kind: AdmissionExistingSame, Receipt: existing}, nil
	}

	for _, mutation := range admission.Mutations {
		conflict, err := applyMutation(ctx, transaction, mutation, admission.AcceptedAt)
		if err != nil { return AdmissionResult{}, err }
		if conflict { return AdmissionResult{Kind: AdmissionConflict}, nil }
	}
	receipt := OperationReceipt{
		CommandID: admission.CommandID, CommandDigest: admission.CommandDigest, Scope: admission.Scope,
		Status: OperationAccepted, AcceptedAt: admission.AcceptedAt.UTC(), Request: admission.Request,
		Mutations: append([]ResourceMutation(nil), admission.Mutations...), Rollback: append([]ResourceMutation(nil), admission.Rollback...),
		Success: append([]ObservedResource(nil), admission.Success...),
		Compensated: append([]ObservedResource(nil), admission.Compensated...),
	}
	encoded, err := json.Marshal(receipt)
	if err != nil { return AdmissionResult{}, err }
	if _, err := transaction.ExecContext(ctx, `INSERT INTO panel_database_operations
(scope_tenant_id, scope_kind, scope_id, command_id, command_digest, status, accepted_at, receipt_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, admission.Scope.TenantID.String(), string(admission.Scope.Kind), admission.Scope.ID.String(),
		admission.CommandID, admission.CommandDigest, string(OperationAccepted), admission.AcceptedAt.UTC().Format(time.RFC3339Nano), encoded); err != nil {
		return AdmissionResult{}, err
	}
	if err := transaction.Commit(); err != nil { return AdmissionResult{}, err }
	return AdmissionResult{Kind: AdmissionNew, Receipt: receipt}, nil
}

func (repository *SQLRepository) Complete(ctx context.Context, completion Completion) (OperationReceipt, error) {
	if repository == nil || repository.db == nil || completion.Scope.ID.IsZero() { return OperationReceipt{}, ErrInvalidReceipt }
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil { return OperationReceipt{}, err }
	defer transaction.Rollback()

	receipt, found, err := lookupOperationTx(ctx, transaction, completion.Scope, completion.CommandID)
	if err != nil { return OperationReceipt{}, err }
	if !found { return OperationReceipt{}, ErrNotFound }
	if receipt.CommandDigest != completion.CommandDigest || receipt.Scope != completion.Scope { return OperationReceipt{}, ErrIdempotency }
	if terminalOperation(receipt.Status) { return receipt, transaction.Commit() }
	if !validCompletionStatus(completion.Status) { return OperationReceipt{}, ErrInvalidReceipt }
	if completion.Status == OperationAmbiguous && len(completion.Observed) != 0 { return OperationReceipt{}, ErrInvalidReceipt }

	completedAt := time.Now().UTC()
	if completion.Status == OperationRejected || completion.Status == OperationCompensated {
		for _, mutation := range receipt.Rollback {
			conflict, err := applyMutation(ctx, transaction, mutation, completedAt)
			if err != nil { return OperationReceipt{}, err }
			if conflict { return OperationReceipt{}, ErrConflict }
		}
	}

	for _, observation := range completion.Observed {
		if !observationBelongsToCompletion(observation, receipt, completion.Status) { return OperationReceipt{}, ErrInvalidReceipt }
		encoded, err := json.Marshal(observation.Status)
		if err != nil { return OperationReceipt{}, err }
		result, err := transaction.ExecContext(ctx, `UPDATE panel_database_resources SET status_json = ?,
physical_name = CASE WHEN ? = 'deleted' THEN '' ELSE physical_name END, updated_at = ?
WHERE kind = ? AND resource_id = ? AND generation = ?`, encoded, string(observation.Status.Lifecycle), completedAt.Format(time.RFC3339Nano),
			string(observation.Kind), observation.ID.String(), observation.Generation)
		if err != nil { return OperationReceipt{}, err }
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 { return OperationReceipt{}, ErrConflict }
	}
	receipt.Status, receipt.Effect, receipt.Compensation = completion.Status, completion.Effect, completion.Compensation
	if completion.Status == OperationApplied { receipt.Success = append([]ObservedResource(nil), completion.Observed...) }
	if completion.Status == OperationRejected || completion.Status == OperationCompensated {
		receipt.Compensated = append([]ObservedResource(nil), completion.Observed...)
	}
	if err := validateStoredOperation(receipt, receipt.CommandID, receipt.CommandDigest, receipt.Scope); err != nil {
		return OperationReceipt{}, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil { return OperationReceipt{}, err }
	result, err := transaction.ExecContext(ctx, `UPDATE panel_database_operations SET status = ?, receipt_json = ?
WHERE scope_tenant_id = ? AND scope_kind = ? AND scope_id = ? AND command_id = ? AND command_digest = ?`,
		string(completion.Status), encoded, completion.Scope.TenantID.String(), string(completion.Scope.Kind), completion.Scope.ID.String(),
		completion.CommandID, completion.CommandDigest)
	if err != nil { return OperationReceipt{}, err }
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 { return OperationReceipt{}, ErrConflict }
	if err := transaction.Commit(); err != nil { return OperationReceipt{}, err }
	return receipt, nil
}

type rowScanner interface { Scan(...any) error }

func scanOperation(row rowScanner) (OperationReceipt, error) {
	var encoded []byte
	if err := row.Scan(&encoded); err != nil { return OperationReceipt{}, err }
	var receipt OperationReceipt
	if err := json.Unmarshal(encoded, &receipt); err != nil { return OperationReceipt{}, fmt.Errorf("decode database operation: %w", err) }
	return receipt, nil
}

func scanResource(kind ResourceKind, id ResourceID, row rowScanner) (ResourceEnvelope, error) {
	var tenantRaw, siteRaw, parentRaw, physicalName string
	var generation uint64
	var spec, statusJSON []byte
	if err := row.Scan(&tenantRaw, &siteRaw, &parentRaw, &physicalName, &generation, &spec, &statusJSON); err != nil {
		return ResourceEnvelope{}, err
	}
	metadata := Metadata{ID: id, Generation: generation}
	if tenantRaw != "" {
		tenantID, err := site.NewTenantID(tenantRaw)
		if err != nil { return ResourceEnvelope{}, ErrInvalidResource }
		metadata.TenantID = tenantID
	}
	if siteRaw != "" {
		siteID, err := site.NewSiteID(siteRaw)
		if err != nil { return ResourceEnvelope{}, ErrInvalidResource }
		metadata.SiteID = siteID
	}
	if err := json.Unmarshal(statusJSON, &metadata.Status); err != nil || !validStatus(metadata.Status) { return ResourceEnvelope{}, ErrInvalidResource }
	var parent ResourceID
	if parentRaw != "" {
		parsed, err := NewResourceID(parentRaw)
		if err != nil { return ResourceEnvelope{}, ErrInvalidResource }
		parent = parsed
	}
	envelope := ResourceEnvelope{Kind: kind, Metadata: metadata, ParentID: parent, PhysicalName: physicalName, Spec: append([]byte(nil), spec...)}
	if _, err := DecodeResource(envelope); err != nil { return ResourceEnvelope{}, err }
	return envelope, nil
}

func lookupOperationTx(ctx context.Context, transaction *sql.Tx, scope OperationScope, commandID string) (OperationReceipt, bool, error) {
	row := transaction.QueryRowContext(ctx, `SELECT receipt_json FROM panel_database_operations
WHERE scope_tenant_id = ? AND scope_kind = ? AND scope_id = ? AND command_id = ?`,
		scope.TenantID.String(), string(scope.Kind), scope.ID.String(), commandID)
	receipt, err := scanOperation(row)
	if errors.Is(err, sql.ErrNoRows) { return OperationReceipt{}, false, nil }
	if err != nil { return OperationReceipt{}, false, err }
	return receipt, true, nil
}

func applyMutation(ctx context.Context, transaction *sql.Tx, mutation ResourceMutation, now time.Time) (bool, error) {
	if mutation.Kind != MutationUpsert || mutation.Resource.Metadata.ID.IsZero() { return false, ErrInvalidResource }
	if _, err := DecodeResource(mutation.Resource); err != nil { return false, err }
	status, err := json.Marshal(mutation.Resource.Metadata.Status)
	if err != nil { return false, err }
	resource := mutation.Resource
	if mutation.ExpectedGeneration == 0 {
		_, err := transaction.ExecContext(ctx, `INSERT INTO panel_database_resources
(kind, resource_id, tenant_id, site_id, parent_id, physical_name, generation, spec_json, status_json, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, string(resource.Kind), resource.Metadata.ID.String(), resource.Metadata.TenantID.String(),
			resource.Metadata.SiteID.String(), resource.ParentID.String(), resource.PhysicalName, resource.Metadata.Generation,
			[]byte(resource.Spec), status, now.UTC().Format(time.RFC3339Nano))
		if err != nil {
			if isConstraintError(err) { return true, nil }
			return false, err
		}
		return false, nil
	}
	if resource.Metadata.Generation != mutation.ExpectedGeneration+1 { return false, ErrConflict }
	result, err := transaction.ExecContext(ctx, `UPDATE panel_database_resources SET tenant_id = ?, site_id = ?, parent_id = ?,
physical_name = ?, generation = ?, spec_json = ?, status_json = ?, updated_at = ?
WHERE kind = ? AND resource_id = ? AND generation = ?`, resource.Metadata.TenantID.String(), resource.Metadata.SiteID.String(),
		resource.ParentID.String(), resource.PhysicalName, resource.Metadata.Generation, []byte(resource.Spec), status,
		now.UTC().Format(time.RFC3339Nano), string(resource.Kind), resource.Metadata.ID.String(), mutation.ExpectedGeneration)
	if err != nil {
		if isConstraintError(err) { return true, nil }
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil { return false, err }
	return rows != 1, nil
}

func validateAdmission(admission Admission) error {
	if admission.CommandID == "" || !validSHA256(admission.CommandDigest) || admission.Scope.ID.IsZero() || admission.AcceptedAt.IsZero() ||
		validateEffectRequest(admission.Request) != nil || admission.Request.Scope != admission.Scope || len(admission.Mutations) == 0 ||
		len(admission.Rollback) != len(admission.Mutations) || len(admission.Success) == 0 || len(admission.Compensated) == 0 {
		return ErrInvalidReceipt
	}
	for index := range admission.Mutations {
		if !validRollbackPair(admission.Mutations[index], admission.Rollback[index]) { return ErrInvalidReceipt }
	}
	return nil
}

func validCompletionStatus(status OperationStatus) bool {
	return status == OperationApplied || status == OperationCompensated || status == OperationRejected || status == OperationAmbiguous
}

func observationBelongsToCompletion(observation ObservedResource, receipt OperationReceipt, status OperationStatus) bool {
	if observation.ID.IsZero() || observation.Generation == 0 || !validStatus(observation.Status) { return false }
	mutations := receipt.Mutations
	if status == OperationRejected || status == OperationCompensated { mutations = receipt.Rollback }
	for _, mutation := range mutations {
		if mutation.Resource.Kind == observation.Kind && mutation.Resource.Metadata.ID == observation.ID && mutation.Resource.Metadata.Generation == observation.Generation {
			return true
		}
	}
	return false
}

func validRollbackPair(mutation, rollback ResourceMutation) bool {
	if mutation.Kind != MutationUpsert || rollback.Kind != MutationUpsert ||
		mutation.Resource.Kind != rollback.Resource.Kind || mutation.Resource.Metadata.ID != rollback.Resource.Metadata.ID ||
		mutation.Resource.Metadata.Generation == 0 || rollback.ExpectedGeneration != mutation.Resource.Metadata.Generation ||
		rollback.Resource.Metadata.Generation != mutation.Resource.Metadata.Generation+1 {
		return false
	}
	if mutation.ExpectedGeneration == 0 {
		if mutation.Resource.Metadata.Generation != 1 { return false }
	} else if mutation.Resource.Metadata.Generation != mutation.ExpectedGeneration+1 {
		return false
	}
	if _, err := DecodeResource(mutation.Resource); err != nil { return false }
	if _, err := DecodeResource(rollback.Resource); err != nil { return false }
	return true
}

func isConstraintError(err error) bool {
	if err == nil { return false }
	message := err.Error()
	return containsFold(message, "constraint") || containsFold(message, "unique")
}

func containsFold(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		match := true
		for offset := 0; offset < len(fragment); offset++ {
			left, right := value[index+offset], fragment[offset]
			if left >= 'A' && left <= 'Z' { left += 'a' - 'A' }
			if right >= 'A' && right <= 'Z' { right += 'a' - 'A' }
			if left != right { match = false; break }
		}
		if match { return true }
	}
	return false
}
