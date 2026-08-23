//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
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
	return apiserver.MigrationEdgeCapabilities{List:true,Create:true,Inventory:true,Plan:true,Sync:true,Cutover:true}
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

func (edge *migrationEdge) CreateMigration(ctx context.Context, call apiserver.EdgeCall, payload apiserver.MigrationCreatePayload) (apiserver.EdgeMutation[apiserver.MigrationProjection], error) {
	if edge == nil || edge.runtime == nil || ctx == nil || strings.TrimSpace(call.TenantID) == "" || strings.TrimSpace(call.CommandID) == "" {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrInvalid
	}
	if err := validateMigrationEndpoint(payload.SourceEndpoint); err != nil {
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, err
	}
	var source migration.SourceKind
	switch payload.Source {
	case string(migration.SourceCyberPanel):
		source = migration.SourceCyberPanel
	case string(migration.SourceCPanel):
		source = migration.SourceCPanel
	case string(migration.SourceCanonical):
		source = migration.SourceCanonical
	default:
		return apiserver.EdgeMutation[apiserver.MigrationProjection]{}, migration.ErrInvalid
	}
	id := migrationID(call.CommandID, call.TenantID)
	now := edge.now().UTC()
	scope := migration.RuntimeScope{MigrationID: id, TenantID: call.TenantID, SourceEndpoint: payload.SourceEndpoint, Generation: 1, LastCommandID: call.CommandID, UpdatedAt: now}
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
	state := migrationState(value.Phase)
	if value.Phase == migration.PhasePlanned && value.PlanDigest != "" {
		if plan, err := edge.runtime.Repository.Plan(ctx, value.PlanDigest); err == nil && len(plan.Unsupported) > 0 {
			state = "blocked"
		}
	}
	updated := value.UpdatedAt
	if scope.UpdatedAt.After(updated) {
		updated = scope.UpdatedAt
	}
	return apiserver.MigrationProjection{ID: value.ID.String(), Source: string(value.Source), State: state, Phase: string(value.Phase), Progress: migrationProgress(value.Phase), Generation: scope.Generation, UpdatedAt: updated}
}

func migrationMutation(operationID string, value migration.Migration, scope migration.RuntimeScope, projection apiserver.MigrationProjection) apiserver.EdgeMutation[apiserver.MigrationProjection] {
	return apiserver.EdgeMutation[apiserver.MigrationProjection]{OperationID: operationID, State: projection.State, Generation: scope.Generation, Resource: projection}
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

func validateMigrationEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" || len(endpoint) > 2048 {
		return migration.ErrInvalid
	}
	return nil
}

func migrationState(phase migration.Phase) string {
	switch phase {
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
	default:
		return "failed"
	}
}

func migrationProgress(phase migration.Phase) uint8 {
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
