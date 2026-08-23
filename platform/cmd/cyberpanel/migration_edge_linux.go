//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	localmigration "github.com/aonsyed/cyberpanel/platform/internal/migration/localruntime"
)

type migrationEdge struct {
	runtime *localmigration.Runtime
	now     func() time.Time
}

func newMigrationEdge(runtime *localmigration.Runtime, now func() time.Time) (*migrationEdge, error) {
	if runtime == nil || runtime.Repository == nil || runtime.Scopes == nil || runtime.Orchestrator == nil {
		return nil, migration.ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &migrationEdge{runtime: runtime, now: now}, nil
}

func (*migrationEdge) MigrationCapabilities() apiserver.MigrationEdgeCapabilities {
	return apiserver.MigrationEdgeCapabilities{List:true,Inspect:true,Create:true,Cancel:true,Inventory:true,Plan:true,Sync:true,Cutover:true}
}

func (edge *migrationEdge) ListMigrationProviders(ctx context.Context, call apiserver.EdgeCall) ([]apiserver.MigrationProviderProjection, error) {
	if edge == nil || edge.runtime == nil || ctx == nil || strings.TrimSpace(call.TenantID) == "" {
		return nil, migration.ErrInvalid
	}
	providers := []apiserver.MigrationProviderProjection{{Source:"cyberpanel", Transport:"mutual_tls_extractor", EndpointScheme:"https", NetworkRequired:true, CreationOperation:"migration.create"}}
	if edge.runtime.CPanelAvailable() {
		providers = append(providers, apiserver.MigrationProviderProjection{Source:"cpanel", Transport:"local_quarantine", EndpointScheme:"file", NetworkRequired:false, CreationOperation:"migration.create"})
	}
	if edge.runtime.CyberPanelBackupAvailable() {
		providers = append(providers, apiserver.MigrationProviderProjection{Source:"cyberpanel_backup", Transport:"local_quarantine", EndpointScheme:"file", NetworkRequired:false, CreationOperation:"migration.create"})
	}
	return providers, nil
}

func (edge *migrationEdge) ListMigrations(ctx context.Context, call apiserver.EdgeCall, payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.MigrationProjection], error) {
	if edge == nil || edge.runtime == nil || ctx == nil || strings.TrimSpace(call.TenantID) == "" {
		return apiserver.EdgePage[apiserver.MigrationProjection]{}, migration.ErrInvalid
	}
	limit := payload.Limit
	if limit == 0 {
		limit = 50
	}
	values, next, total, err := edge.runtime.Scopes.List(ctx, call.TenantID, limit, payload.Cursor)
	if err != nil {
		return apiserver.EdgePage[apiserver.MigrationProjection]{}, err
	}
	items := make([]apiserver.MigrationProjection, 0, len(values))
	for _, value := range values {
		items = append(items, edge.projection(ctx, value.Migration, value.Scope))
	}
	return apiserver.EdgePage[apiserver.MigrationProjection]{Items: items, NextCursor: next, Total: total}, nil
}

func (edge *migrationEdge) InspectMigration(ctx context.Context, call apiserver.EdgeCall) (apiserver.MigrationProjection, error) {
	if edge == nil || edge.runtime == nil || ctx == nil || strings.TrimSpace(call.TenantID) == "" || call.ExpectedGeneration != 0 {
		return apiserver.MigrationProjection{}, migration.ErrInvalid
	}
	id, err := migration.NewID(call.ResourceID)
	if err != nil {
		return apiserver.MigrationProjection{}, err
	}
	scope, err := edge.runtime.Scopes.Load(ctx, call.TenantID, id)
	if err != nil {
		return apiserver.MigrationProjection{}, err
	}
	value, err := edge.runtime.Repository.Migration(ctx, id)
	if err != nil {
		return apiserver.MigrationProjection{}, err
	}
	return edge.projection(ctx, value, scope), nil
}

func (edge *migrationEdge) InspectMigrationChunkGC(ctx context.Context, call apiserver.EdgeCall, payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.MigrationChunkGCProjection], error) {
	if edge == nil || edge.runtime == nil || edge.runtime.Scopes == nil || ctx == nil || strings.TrimSpace(call.TenantID) == "" || call.ExpectedGeneration != 0 {
		return apiserver.EdgePage[apiserver.MigrationChunkGCProjection]{}, migration.ErrInvalid
	}
	id, err := migration.NewID(call.ResourceID)
	if err != nil {
		return apiserver.EdgePage[apiserver.MigrationChunkGCProjection]{}, err
	}
	limit := payload.Limit
	if limit == 0 {
		limit = 50
	}
	values, next, total, err := edge.runtime.Scopes.InspectAmbiguousChunkGC(ctx, call.TenantID, id, limit, payload.Cursor)
	if err != nil {
		if errors.Is(err, migration.ErrAmbiguous) {
			return apiserver.EdgePage[apiserver.MigrationChunkGCProjection]{}, migration.ErrBlocked
		}
		return apiserver.EdgePage[apiserver.MigrationChunkGCProjection]{}, err
	}
	items := make([]apiserver.MigrationChunkGCProjection, 0, len(values))
	for _, value := range values {
		items = append(items, migrationChunkGCAmbiguityProjection(value))
	}
	return apiserver.EdgePage[apiserver.MigrationChunkGCProjection]{Items:items, NextCursor:next, Total:total}, nil
}

func (edge *migrationEdge) ReconcileMigrationChunkGC(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MigrationChunkGCReconcilePayload) (apiserver.EdgeMutation[apiserver.MigrationChunkGCProjection], error) {
	if edge == nil || edge.runtime == nil || edge.runtime.Scopes == nil || edge.runtime.Chunks == nil || ctx == nil || strings.TrimSpace(call.TenantID) == "" || strings.TrimSpace(call.CommandID) == "" || strings.TrimSpace(call.PrincipalID) == "" || call.ExpectedGeneration == 0 {
		return apiserver.EdgeMutation[apiserver.MigrationChunkGCProjection]{}, migration.ErrInvalid
	}
	if call.Assurance < identity.AssuranceMFA {
		return apiserver.EdgeMutation[apiserver.MigrationChunkGCProjection]{}, identity.ErrAssuranceRequired
	}
	id, err := migration.NewID(call.ResourceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationChunkGCProjection]{}, err
	}
	epoch, err := strconv.ParseUint(payload.ObjectEpoch, 10, 64)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationChunkGCProjection]{}, migration.ErrInvalid
	}
	receipt, err := edge.runtime.Scopes.ReconcileAmbiguousChunkGC(ctx, edge.runtime.Chunks, migration.ChunkGCReconcileCommand{MigrationID:id, TenantID:call.TenantID, Digest:payload.Digest, ObjectEpoch:epoch, EvidenceDigest:payload.EvidenceDigest, Resolution:migration.ChunkGCResolution(payload.Resolution), ExpectedGeneration:call.ExpectedGeneration, ActorID:call.PrincipalID, CommandID:call.CommandID})
	if err != nil {
		if errors.Is(err, migration.ErrAmbiguous) {
			return apiserver.EdgeMutation[apiserver.MigrationChunkGCProjection]{}, migration.ErrBlocked
		}
		return apiserver.EdgeMutation[apiserver.MigrationChunkGCProjection]{}, err
	}
	projection := migrationChunkGCReconciliationProjection(receipt)
	return apiserver.EdgeMutation[apiserver.MigrationChunkGCProjection]{OperationID:call.CommandID, State:"reconciled", Generation:receipt.ScopeGeneration, Resource:projection}, nil
}

func (edge *migrationEdge) CreateMigration(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MigrationCreatePayload) (apiserver.EdgeMutation[apiserver.MigrationProjection], error) {
	if edge == nil || edge.runtime == nil || ctx == nil || strings.TrimSpace(call.TenantID) == "" || strings.TrimSpace(call.CommandID) == "" {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrInvalid
	}
	source := migration.SourceKind(payload.Source)
	if err := validateMigrationEndpoint(source, payload.SourceEndpoint); err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	var id migration.ID
	sourceEndpoint := payload.SourceEndpoint
	switch source {
	case migration.SourceCyberPanel:
		id = migrationID(call.CommandID, call.TenantID)
	case migration.SourceCPanel:
		admission, err := edge.runtime.AdmitCPanel(ctx, call.TenantID, payload.SourceEndpoint)
		if err != nil {
			return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
		}
		if admission.Manifest.Source != migration.SourceCPanel || !admission.Manifest.MigrationID.Valid() {
			return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrInvalid
		}
		id = admission.Manifest.MigrationID
		sourceEndpoint = admission.SourceEndpoint
	case migration.SourceCyberPanelBackup:
		admission, err := edge.runtime.AdmitCyberPanelBackup(ctx, call.TenantID, payload.SourceEndpoint)
		if err != nil {
			return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
		}
		if admission.Manifest.Source != migration.SourceCyberPanelBackup || !admission.Manifest.MigrationID.Valid() {
			return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrInvalid
		}
		id = admission.Manifest.MigrationID
		sourceEndpoint = admission.SourceEndpoint
	default:
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrInvalid
	}
	now := edge.now().UTC()
	scope := migration.RuntimeScope{MigrationID: id, TenantID: call.TenantID, SourceEndpoint: sourceEndpoint, Generation: 1, LastCommandID: call.CommandID, UpdatedAt: now}
	createdScope, err := edge.runtime.Scopes.Create(ctx, scope)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	scope, err = edge.runtime.Scopes.Load(ctx, call.TenantID, id)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	value, loadErr := edge.runtime.Repository.Migration(ctx, id)
	if loadErr == nil {
		if value.Source != source {
			return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrConflict
		}
		return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
	}
	if !errors.Is(loadErr, migration.ErrNotFound) {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, loadErr
	}
	value, err = edge.runtime.Orchestrator.Create(ctx, id, source, call.CommandID)
	if err != nil {
		if createdScope {
			_ = edge.runtime.Scopes.RemoveUnstarted(ctx, call.TenantID, id, call.CommandID)
		}
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
}

func (edge *migrationEdge) CancelMigration(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.MigrationProjection], error) {
	value, scope, err := edge.loadScoped(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if value.Phase == migration.PhaseCanceled {
		return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
	}
	if value.Phase == migration.PhaseFailedTerminal && value.ErrorCode == migration.CancelReconciliationRequiredCode {
		return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
	}
	scope, err = edge.runtime.Scopes.Claim(ctx, call.TenantID, value.ID, call.ExpectedGeneration, call.CommandID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	value, err = edge.runtime.Orchestrator.Cancel(ctx, value.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
}

func (edge *migrationEdge) Inventory(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MigrationInventoryPayload) (apiserver.EdgeMutation[apiserver.MigrationProjection], error) {
	value, scope, err := edge.loadScoped(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if value.Phase == migration.PhaseInventoried && !payload.Refresh {
		return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
	}
	if payload.Refresh && value.Phase != migration.PhaseCreated && value.Phase != migration.PhaseDiscovering && value.Phase != migration.PhasePausedRetryable {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrBlocked
	}
	scope, err = edge.runtime.Scopes.Claim(ctx, call.TenantID, value.ID, call.ExpectedGeneration, call.CommandID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	_, err = edge.runtime.Orchestrator.Inventory(ctx, value.ID)
	value, loadErr := edge.runtime.Repository.Migration(ctx, value.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if loadErr != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, loadErr
	}
	return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
}

func (edge *migrationEdge) Plan(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MigrationPlanPayload) (apiserver.EdgeMutation[apiserver.MigrationProjection], error) {
	value, scope, err := edge.loadScoped(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if payload.CollisionPolicy != "" && payload.CollisionPolicy != "fail" {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrBlocked
	}
	if value.Phase == migration.PhasePlanned && value.PlanDigest != "" {
		return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
	}
	scope, err = edge.runtime.Scopes.Claim(ctx, call.TenantID, value.ID, call.ExpectedGeneration, call.CommandID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	planID := migrationPlanID(value.ID, call.CommandID)
	_, planErr := edge.runtime.Orchestrator.DryRun(ctx, value.ID, planID)
	value, loadErr := edge.runtime.Repository.Migration(ctx, value.ID)
	if loadErr != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, loadErr
	}
	if planErr != nil && !errors.Is(planErr, migration.ErrBlocked) {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, planErr
	}
	projection := edge.projection(ctx, value, scope)
	if errors.Is(planErr, migration.ErrBlocked) {
		projection.State = "blocked"
	}
	return migrationMutation(call.CommandID, value, scope, projection), nil
}

func (edge *migrationEdge) Sync(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MigrationSyncPayload) (apiserver.EdgeMutation[apiserver.MigrationProjection], error) {
	value, scope, err := edge.loadScoped(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if value.Phase == migration.PhaseQuiescing || value.Phase == migration.PhaseFinalSync || value.Phase == migration.PhaseCutoverReady || value.Phase == migration.PhaseCutoverCommitting || value.Phase == migration.PhaseVerifying || value.Phase == migration.PhaseCommitted || value.Phase == migration.PhaseCleanup {
		return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
	}
	if value.Phase != migration.PhasePlanned && value.Phase != migration.PhaseReady && value.Phase != migration.PhaseBaseSync && value.Phase != migration.PhasePausedRetryable {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrConflict
	}
	plan, err := edge.runtime.Repository.Plan(ctx, value.PlanDigest)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if len(plan.Unsupported) != 0 {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrBlocked
	}
	manifest, err := edge.runtime.Repository.Manifest(ctx, value.ManifestRoot)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	required, err := migrationTransferBytes(manifest)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if payload.MaximumBytes != 0 && required > payload.MaximumBytes {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrCapacity
	}
	scope, err = edge.runtime.Scopes.Claim(ctx, call.TenantID, value.ID, call.ExpectedGeneration, call.CommandID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if value.Phase == migration.PhasePlanned {
		approvalDigest := migrationApprovalDigest("base-sync", call, value.ID, plan.DryRunDigest, "", payload.MaximumBytes)
		value, err = edge.runtime.Orchestrator.Approve(ctx, value.ID, approvalDigest)
		if err != nil {
			return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
		}
	}
	value, err = edge.runtime.Orchestrator.BaseSync(ctx, value.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
}

func (edge *migrationEdge) Cutover(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MigrationCutoverPayload) (apiserver.EdgeMutation[apiserver.MigrationProjection], error) {
	if !validMigrationApprovalRef(payload.ApprovalRef) {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrInvalid
	}
	value, scope, err := edge.loadScoped(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if value.Phase == migration.PhaseCleanup || value.Phase == migration.PhaseRolledBack {
		return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
	}
	if value.Phase != migration.PhaseQuiescing && value.Phase != migration.PhaseFinalSync && value.Phase != migration.PhaseCutoverReady && value.Phase != migration.PhaseCutoverCommitting && value.Phase != migration.PhaseVerifying && value.Phase != migration.PhaseCommitted && value.Phase != migration.PhasePausedRetryable {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrConflict
	}
	plan, err := edge.runtime.Repository.Plan(ctx, value.PlanDigest)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if plan.ApprovedAt == nil || plan.ApprovedAt.IsZero() || !validMigrationDigest(plan.ApprovalDigest) || len(plan.Unsupported) != 0 {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrBlocked
	}
	scope, err = edge.runtime.Scopes.Claim(ctx, call.TenantID, value.ID, call.ExpectedGeneration, call.CommandID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	if err = edge.bindCutoverApproval(ctx, call, value, plan, payload.ApprovalRef); err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	value, err = edge.runtime.Orchestrator.Cutover(ctx, value.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	return migrationMutation(call.CommandID, value, scope, edge.projection(ctx, value, scope)), nil
}

type migrationCutoverApprovalReceipt struct {
	Version        uint8     `json:"version"`
	PlanDigest     string    `json:"plan_digest"`
	ApprovalDigest string    `json:"approval_digest"`
	AuthorizedBy   string    `json:"authorized_by"`
	AuthorizedAt   time.Time `json:"authorized_at"`
}

func (edge *migrationEdge) bindCutoverApproval(ctx context.Context, call apiserver.EdgeCall, value migration.Migration, plan migration.Plan, approvalRef string) error {
	digest := migrationApprovalDigest("cutover", call, value.ID, plan.DryRunDigest, approvalRef, 0)
	receipt := migrationCutoverApprovalReceipt{Version:1,PlanDigest:plan.DryRunDigest,ApprovalDigest:digest,AuthorizedBy:call.PrincipalID,AuthorizedAt:edge.now().UTC()}
	var existing migrationCutoverApprovalReceipt
	if err := edge.runtime.Repository.Receipt(ctx, value.ID, "cutover_approval", &existing); err == nil {
		if existing.Version != 1 || existing.PlanDigest != receipt.PlanDigest || existing.ApprovalDigest != receipt.ApprovalDigest || existing.AuthorizedBy != receipt.AuthorizedBy || existing.AuthorizedAt.IsZero() {
			return migration.ErrConflict
		}
		return nil
	} else if !errors.Is(err, migration.ErrNotFound) {
		return err
	}
	return edge.runtime.Repository.PutReceipt(ctx, value.ID, "cutover_approval", receipt)
}

func migrationTransferBytes(manifest migration.Manifest) (uint64, error) {
	var total uint64
	for _, chunk := range manifest.Chunks {
		if total > ^uint64(0)-chunk.Size {
			return 0, migration.ErrCapacity
		}
		total += chunk.Size
	}
	return total, nil
}

func migrationApprovalDigest(kind string, call apiserver.EdgeCall, id migration.ID, planDigest, approvalRef string, maximumBytes uint64) string {
	sessionID, credentialID, commandID, authzEpoch := call.SessionID, call.CredentialID, call.CommandID, call.AuthzEpoch
	if kind == "cutover" {
		// The human change reference is the resumable cutover authority. A
		// retry after a fenced pause necessarily has a new API command/session,
		// so those transport identities must not invalidate the same approval.
		sessionID, credentialID, commandID, authzEpoch = "", "", "", 0
	}
	raw, _ := json.Marshal(struct {
		Domain        string `json:"domain"`
		Kind          string `json:"kind"`
		MigrationID   string `json:"migration_id"`
		PlanDigest    string `json:"plan_digest"`
		ApprovalRef   string `json:"approval_ref,omitempty"`
		TenantID      string `json:"tenant_id"`
		PrincipalID   string `json:"principal_id"`
		SessionID     string `json:"session_id"`
		CredentialID  string `json:"credential_id"`
		CommandID     string `json:"command_id"`
		AuthzEpoch    uint64 `json:"authz_epoch"`
		MaximumBytes  uint64 `json:"maximum_bytes,omitempty"`
	}{"cyberpanel-migration-approval-v1",kind,id.String(),planDigest,approvalRef,call.TenantID,call.PrincipalID,sessionID,credentialID,commandID,authzEpoch,maximumBytes})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validMigrationApprovalRef(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' && character != '_' && character != '.' && character != ':' {
			return false
		}
	}
	return true
}

func validMigrationDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func (edge *migrationEdge) loadScoped(ctx context.Context, call apiserver.EdgeCall) (migration.Migration, migration.RuntimeScope, error) {
	if edge == nil || edge.runtime == nil || ctx == nil || strings.TrimSpace(call.TenantID) == "" || call.ExpectedGeneration == 0 {
		return migration.Migration{}, migration.RuntimeScope{}, migration.ErrInvalid
	}
	id, err := migration.NewID(call.ResourceID)
	if err != nil {
		return migration.Migration{}, migration.RuntimeScope{}, err
	}
	scope, err := edge.runtime.Scopes.Load(ctx, call.TenantID, id)
	if err != nil {
		return migration.Migration{}, migration.RuntimeScope{}, err
	}
	if scope.Generation != call.ExpectedGeneration {
		return migration.Migration{}, migration.RuntimeScope{}, migration.ErrConflict
	}
	value, err := edge.runtime.Repository.Migration(ctx, id)
	return value, scope, err
}

func (edge *migrationEdge) projection(ctx context.Context, value migration.Migration, scope migration.RuntimeScope) apiserver.MigrationProjection {
	state := migrationState(value)
	var resourcesTotal, resourcesCompleted, resourceErrors, bytesTransferred, objectsTransferred uint64
	if value.PlanDigest != "" {
		if plan, err := edge.runtime.Repository.Plan(ctx, value.PlanDigest); err == nil {
			resourcesTotal = uint64(len(plan.Mappings))
			if value.Phase == migration.PhasePlanned && len(plan.Unsupported) > 0 {
				state = "blocked"
			}
		}
	}
	updated := value.UpdatedAt
	if scope.UpdatedAt.After(updated) {
		updated = scope.UpdatedAt
	}
	if progress, err := edge.runtime.Repository.Progress(ctx, value.ID); err == nil {
		if uint64(len(progress)) > resourcesTotal {
			resourcesTotal = uint64(len(progress))
		}
		for _, item := range progress {
			bytesTransferred = saturatingMigrationTotal(bytesTransferred, item.BytesTransferred)
			objectsTransferred = saturatingMigrationTotal(objectsTransferred, item.ObjectsTransferred)
			if item.ErrorCode != "" {
				resourceErrors++
			} else {
				resourcesCompleted++
			}
			if item.UpdatedAt.After(updated) {
				updated = item.UpdatedAt
			}
		}
	}
	errorCode, errorMessage := redactedMigrationError(value, state)
	if resourceErrors > 0 && errorCode == "" {
		errorCode, errorMessage = "MIGRATION_RESOURCE_ERRORS", "One or more resources require operator attention. Sensitive source details are available only in local audit evidence."
	}
	var rollbackDeadline *time.Time
	if !value.RollbackDeadline.IsZero() {
		deadline := value.RollbackDeadline
		rollbackDeadline = &deadline
	}
	return apiserver.MigrationProjection{ID:value.ID.String(),Source:string(value.Source),State:state,Phase:string(value.Phase),Progress:migrationProgress(value),ResourcesTotal:resourcesTotal,ResourcesCompleted:resourcesCompleted,ResourceErrors:resourceErrors,BytesTransferred:bytesTransferred,ObjectsTransferred:objectsTransferred,ErrorCode:errorCode,ErrorMessage:errorMessage,Cancelable:edge.migrationCancelable(ctx,value),Generation:scope.Generation,CreatedAt:value.CreatedAt,UpdatedAt:updated,RollbackDeadline:rollbackDeadline}
}

func (edge *migrationEdge) migrationCancelable(ctx context.Context, value migration.Migration) bool {
	if edge == nil || edge.runtime == nil || ctx == nil {
		return false
	}
	switch value.Phase {
	case migration.PhaseCreated, migration.PhaseDiscovering, migration.PhaseInventoried, migration.PhasePlanned, migration.PhaseReady, migration.PhaseBaseSync, migration.PhaseBlockedPolicy:
		return true
	case migration.PhaseQuiescing, migration.PhasePausedRetryable:
		var fence migration.SourceFence
		return errors.Is(edge.runtime.Repository.Receipt(ctx, value.ID, "source_fence", &fence), migration.ErrNotFound)
	default:
		return false
	}
}

func saturatingMigrationTotal(total, value uint64) uint64 {
	if total > ^uint64(0)-value {
		return ^uint64(0)
	}
	return total + value
}

func redactedMigrationError(value migration.Migration, state string) (string, string) {
	switch value.ErrorCode {
	case migration.CancelReconciliationRequiredCode:
		return "MIGRATION_ROLLBACK_REQUIRED", "Cancellation crossed the guarded migration frontier. Imported target resources were preserved and require explicit reconciliation or rollback."
	case "DISCOVERY_FAILED", "SOURCE_QUIESCE_FAILED", "SOURCE_COMMIT_FAILED":
		return "MIGRATION_SOURCE_UNAVAILABLE", "The approved source agent could not complete the requested stage. Sensitive connection details are retained only in local audit evidence."
	case "SOURCE_GENERATION_MOVED":
		return "MIGRATION_SOURCE_CHANGED", "The source changed after the approved snapshot and must be inventoried again."
	case "MANIFEST_REJECTED", "FINAL_DELTA_REJECTED":
		return "MIGRATION_SOURCE_DATA_REJECTED", "Signed source data failed target validation. Raw source fields are not exposed through this API."
	case "CHUNK_STAGE_FAILED", "FINAL_CHUNK_STAGE_FAILED":
		return "MIGRATION_TRANSFER_FAILED", "Encrypted migration data could not be staged completely."
	case "TARGET_PREPARE_FAILED", "RESOURCE_IMPORT_FAILED", "FINAL_APPLY_FAILED":
		return "MIGRATION_IMPORT_FAILED", "The target could not materialize all approved resources in quarantine."
	case "DARK_VERIFY_FAILED", "POST_WRITE_VERIFY_FAILED":
		return "MIGRATION_VERIFICATION_FAILED", "Target verification did not satisfy the approved migration plan."
	case "ACTIVATION_AMBIGUOUS", "ACTIVATION_RECEIPT_INVALID":
		return "MIGRATION_ACTIVATION_UNCERTAIN", "Activation requires operator reconciliation before any retry or cancellation."
	case "":
		if state == "blocked" {
			return "MIGRATION_BLOCKED", "The source inventory contains unsupported or unresolved items. No provider compatibility is implied."
		}
		if value.Phase == migration.PhaseFailedTerminal {
			return "MIGRATION_FAILED", "The migration stopped and requires operator review. Sensitive runtime details are retained only in local audit evidence."
		}
		return "", ""
	default:
		return "MIGRATION_REQUIRES_ATTENTION", "The migration requires operator review. Sensitive runtime details are retained only in local audit evidence."
	}
}

func migrationMutation(operationID string, value migration.Migration, scope migration.RuntimeScope, projection apiserver.MigrationProjection) apiserver.EdgeMutation[apiserver.MigrationProjection] {
	return apiserver.EdgeMutation[apiserver.MigrationProjection]{OperationID: operationID, State: projection.State, Generation: scope.Generation, Resource: projection}
}

func migrationChunkGCAmbiguityProjection(value migration.ChunkGCAmbiguity) apiserver.MigrationChunkGCProjection {
	return apiserver.MigrationChunkGCProjection{MigrationID:value.MigrationID.String(), TenantID:value.TenantID, Digest:value.Digest, Size:value.Size, ObjectEpoch:strconv.FormatUint(value.ObjectEpoch, 10), State:"ambiguous", Materialized:value.Materialized, QuarantineAfter:value.QuarantineAfter, StartedAt:value.StartedAt, AmbiguousEvidenceDigest:value.EvidenceDigest, Generation:value.ScopeGeneration}
}

func migrationChunkGCReconciliationProjection(receipt migration.ChunkGCReconciliationReceipt) apiserver.MigrationChunkGCProjection {
	state, observation := "deleted", "absent"
	if receipt.ObservedPresent {
		state, observation = "active", "present"
	}
	reconciledAt := receipt.ReconciledAt
	return apiserver.MigrationChunkGCProjection{MigrationID:receipt.MigrationID.String(), TenantID:receipt.TenantID, Digest:receipt.Digest, Size:receipt.Size, ObjectEpoch:strconv.FormatUint(receipt.ObjectEpoch, 10), State:state, Materialized:receipt.ObservedPresent, QuarantineAfter:receipt.QuarantineAfter, StartedAt:receipt.StartedAt, AmbiguousEvidenceDigest:receipt.AmbiguousEvidenceDigest, Resolution:string(receipt.Resolution), Observation:observation, ReconciledAt:&reconciledAt, ReconciliationEvidenceDigest:receipt.EvidenceDigest, Generation:receipt.ScopeGeneration}
}

func migrationID(commandID, tenantID string) migration.ID {
	sum := sha256.Sum256([]byte("cyberpanel-migration-v1\x00" + tenantID + "\x00" + commandID))
	id, _ := migration.NewID("migration_" + hex.EncodeToString(sum[:24]))
	return id
}

func migrationPlanID(id migration.ID, commandID string) migration.ID {
	sum := sha256.Sum256([]byte("cyberpanel-migration-plan-v1\x00" + id.String() + "\x00" + commandID))
	planID, _ := migration.NewID("plan_" + hex.EncodeToString(sum[:24]))
	return planID
}

func validateMigrationEndpoint(source migration.SourceKind, endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 2048 {
		return migration.ErrInvalid
	}
	switch source {
	case migration.SourceCyberPanel:
		if parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return migration.ErrInvalid
		}
	case migration.SourceCPanel, migration.SourceCyberPanelBackup:
		path := parsed.Path
		if parsed.Scheme != "file" || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || (&url.URL{Scheme:"file", Path:path}).String() != endpoint {
			return migration.ErrInvalid
		}
	default:
		return migration.ErrInvalid
	}
	return nil
}

func migrationState(value migration.Migration) string {
	if value.ErrorCode == migration.CancelReconciliationRequiredCode {
		return "rollback_required"
	}
	switch value.Phase {
	case migration.PhaseCreated, migration.PhaseDiscovering, migration.PhaseInventoried, migration.PhasePlanned, migration.PhaseReady:
		return "pending"
	case migration.PhaseBaseSync, migration.PhaseQuiescing, migration.PhaseFinalSync, migration.PhaseCutoverReady, migration.PhaseCutoverCommitting, migration.PhaseVerifying, migration.PhaseCommitted:
		return "running"
	case migration.PhaseCleanup:
		return "completed"
	case migration.PhasePausedRetryable:
		return "paused"
	case migration.PhaseBlockedPolicy:
		return "blocked"
	case migration.PhaseRolledBack:
		return "rolled_back"
	case migration.PhaseCanceled:
		return "canceled"
	default:
		return "failed"
	}
}

func migrationProgress(value migration.Migration) uint8 {
	phase := value.Phase
	if phase == migration.PhaseCanceled && strings.HasPrefix(value.LastCheckpoint, "canceled:") {
		phase = migration.Phase(strings.TrimPrefix(value.LastCheckpoint, "canceled:"))
	}
	switch phase {
	case migration.PhaseCreated: return 0
	case migration.PhaseDiscovering: return 5
	case migration.PhaseInventoried: return 15
	case migration.PhasePlanned: return 25
	case migration.PhaseReady: return 30
	case migration.PhaseBaseSync: return 55
	case migration.PhaseQuiescing: return 70
	case migration.PhaseFinalSync: return 78
	case migration.PhaseCutoverReady: return 84
	case migration.PhaseCutoverCommitting: return 90
	case migration.PhaseVerifying: return 95
	case migration.PhaseCommitted: return 98
	case migration.PhaseCleanup: return 100
	case migration.PhaseRolledBack, migration.PhaseFailedTerminal: return 100
	default: return 0
	}
}

var _ apiserver.MigrationEdgeService = (*migrationEdge)(nil)
var _ apiserver.MigrationProviderDiscoveryEdgeService = (*migrationEdge)(nil)
