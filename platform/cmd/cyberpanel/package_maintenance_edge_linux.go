//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/maintenance"
	"github.com/aonsyed/cyberpanel/platform/internal/packagemaint"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

// packageMaintenancePlanResolver is a fixed, release-pinned native resolver.
// It selects pending security advisories from the sealed inventory; API
// callers cannot supply package names, repository locations, or solver data.
type packageMaintenancePlanResolver interface {
	ResolveSecurityUpdates(context.Context, packagemaint.InventorySnapshot) (packagemaint.SolverAttestation, error)
	ResolveIndividualUpdate(context.Context, packagemaint.InventorySnapshot, string, string) (packagemaint.SolverAttestation, error)
}

type packageMaintenanceLinuxEdge struct {
	repository *packagemaint.SQLRepository
	inventory  packagemaint.InventoryProvider
	resolver   packageMaintenancePlanResolver
	catalog    *packagemaint.LinuxRuntimeCatalog
	holds      packagemaint.PackageHoldExecutor
	service    packagemaint.Service
	nodeID     string
	manager    packagemaint.Manager
	now        func() time.Time
}

type packageMaintenanceWindowAdmission struct {
	evaluator   *maintenance.Evaluator
	occurrences *maintenance.Repository
	nodeID      string
	manager     packagemaint.Manager
}

const packageMaintenanceMaximumGeneration = uint64(1<<63 - 1)

func newPackageMaintenanceLinuxEdge(repository *packagemaint.SQLRepository, inventory packagemaint.InventoryProvider,
	resolver packageMaintenancePlanResolver, authorizer packagemaint.Authorizer, executor packagemaint.MaintenanceExecutor,
	maintenanceGate packagemaint.MaintenanceGate, rebootRequirements packagemaint.RebootRequirementPublisher,
	nodeID string, manager packagemaint.Manager, now func() time.Time) (*packageMaintenanceLinuxEdge, error) {
	holds, supportsHolds := executor.(packagemaint.PackageHoldExecutor)
	if repository == nil || inventory == nil || resolver == nil || authorizer == nil || executor == nil || !supportsHolds ||
		maintenanceGate == nil || rebootRequirements == nil || !validPackageMaintenanceRuntimeID(nodeID) || manager != packagemaint.ManagerAPT && manager != packagemaint.ManagerDNF {
		return nil, packagemaint.ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	edge := &packageMaintenanceLinuxEdge{repository: repository, inventory: inventory, resolver: resolver,
		nodeID: nodeID, manager: manager, holds: holds, now: now}
	edge.service = packagemaint.Service{Store: repository, Authorizer: authorizer, Executor: executor, Maintenance: maintenanceGate, RebootRequirements: rebootRequirements, Now: now}
	return edge, nil
}

func assemblePackageMaintenanceEdge(ctx context.Context, database *sql.DB, now func() time.Time) (*packageMaintenanceLinuxEdge, error) {
	if ctx == nil || database == nil {
		return nil, packagemaint.ErrInvalid
	}
	configured, err := packagemaint.LinuxRuntimeConfigured()
	if err != nil {
		return nil, err
	}
	if !configured {
		return nil, nil
	}
	if now == nil {
		now = time.Now
	}
	catalog, err := packagemaint.LoadDefaultLinuxRuntimeCatalog(now().UTC())
	if err != nil {
		return nil, fmt.Errorf("load signed package-maintenance catalog: %w", err)
	}
	manager, err := packagemaint.DetectLinuxManager()
	if err != nil || manager != catalog.Manager {
		return nil, fmt.Errorf("package-maintenance support tuple is unavailable: %w", packagemaint.ErrUnsupported)
	}
	repository, err := packagemaint.NewSQLRepository(database)
	if err != nil {
		return nil, err
	}
	if err = repository.Bootstrap(ctx); err != nil {
		return nil, err
	}
	rebootRepository, err := rebootcontrol.NewRepository(database)
	if err != nil {
		return nil, err
	}
	if err = rebootRepository.Bootstrap(ctx); err != nil {
		return nil, err
	}
	rebootRequirements := &packageRebootRequirementPublisher{repository: rebootRepository, nodeID: catalog.NodeID}
	maintenanceRepository, err := maintenance.NewRepository(database)
	if err != nil {
		return nil, err
	}
	if err = maintenanceRepository.Bootstrap(ctx); err != nil {
		return nil, err
	}
	maintenanceEvaluator, err := maintenance.NewEvaluator(maintenanceRepository, maintenance.EvaluatorConfig{})
	if err != nil {
		return nil, err
	}
	client, err := packagemaint.NewLocalLinuxClient()
	if err != nil {
		return nil, fmt.Errorf("connect package-maintenance executor: %w", err)
	}
	material, err := secrets.NewLocalMaterialClient()
	if err != nil {
		return nil, fmt.Errorf("connect package-maintenance authorization broker: %w", err)
	}
	authorizer, err := packagemaint.NewProtectedLinuxAuthorizer(material, catalog, now)
	if err != nil {
		return nil, err
	}
	maintenanceGate := &packageMaintenanceWindowAdmission{evaluator: maintenanceEvaluator, occurrences: maintenanceRepository,
		nodeID: catalog.NodeID, manager: catalog.Manager}
	edge, err := newPackageMaintenanceLinuxEdge(repository, client, client, authorizer, client, maintenanceGate, rebootRequirements,
		catalog.NodeID, catalog.Manager, now)
	if err != nil {
		return nil, err
	}
	edge.catalog = catalog
	operation, err := repository.LatestOperation(ctx, catalog.NodeID, catalog.Manager)
	if errors.Is(err, packagemaint.ErrNotFound) {
		return edge, nil
	}
	if err != nil {
		return nil, err
	}
	if operation.State != packagemaint.OperationAuthorized && operation.State != packagemaint.OperationRunning &&
		operation.State != packagemaint.OperationVerifying {
		return edge, nil
	}
	reconciled, reconcileErr := edge.service.ReconcileRestart(ctx, operation.ID)
	if reconcileErr != nil && reconciled.State != packagemaint.OperationFailed &&
		reconciled.State != packagemaint.OperationRecoveryRequired && reconciled.State != packagemaint.OperationRecovered {
		return nil, fmt.Errorf("reconcile package-maintenance operation %s: %w", operation.ID, reconcileErr)
	}
	return edge, nil
}

func (*packageMaintenanceLinuxEdge) PackageMaintenanceCapabilities() apiserver.PackageMaintenanceEdgeCapabilities {
	return apiserver.PackageMaintenanceEdgeCapabilities{List: true, Refresh: true, Plan: true, Apply: true, Packages: true, Holds: true}
}

func (edge *packageMaintenanceLinuxEdge) ListPackageMaintenancePackages(ctx context.Context, call apiserver.EdgeCall,
	payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.PackageMaintenancePackageProjection], error) {
	if edge == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" || call.ExpectedGeneration != 0 ||
		call.PrincipalID == "" || call.CredentialID == "" {
		return apiserver.EdgePage[apiserver.PackageMaintenancePackageProjection]{}, packagemaint.ErrInvalid
	}
	snapshot, err := edge.repository.LatestInventory(ctx, edge.nodeID, edge.manager)
	if err != nil { return apiserver.EdgePage[apiserver.PackageMaintenancePackageProjection]{}, err }
	items := make([]apiserver.PackageMaintenancePackageProjection, 0, len(snapshot.Packages))
	for _, installed := range snapshot.Packages { items = append(items, projectPackageMaintenancePackage(snapshot, installed)) }
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	start := 0
	for start < len(items) && items[start].ID <= payload.Cursor { start++ }
	limit := int(payload.Limit); if limit == 0 { limit = 100 }
	end := start + limit; if end > len(items) { end = len(items) }
	next := ""; if end < len(items) && end > start { next = items[end-1].ID }
	for index := start; index < end; index++ { items[index] = edge.withIndividualUpdates(snapshot, items[index]) }
	return apiserver.EdgePage[apiserver.PackageMaintenancePackageProjection]{Items: append([]apiserver.PackageMaintenancePackageProjection(nil), items[start:end]...), NextCursor: next, Total: uint64(len(items))}, nil
}

func (edge *packageMaintenanceLinuxEdge) GetPackageMaintenancePackage(ctx context.Context, call apiserver.EdgeCall) (apiserver.PackageMaintenancePackageProjection, error) {
	if edge == nil || ctx == nil || call.TenantID != "" || !validPackageMaintenanceRuntimeID(call.ResourceID) ||
		call.ExpectedGeneration != 0 || call.PrincipalID == "" || call.CredentialID == "" {
		return apiserver.PackageMaintenancePackageProjection{}, packagemaint.ErrInvalid
	}
	snapshot, err := edge.repository.LatestInventory(ctx, edge.nodeID, edge.manager)
	if err != nil { return apiserver.PackageMaintenancePackageProjection{}, err }
	projection, err := packageMaintenancePackageByID(snapshot, call.ResourceID)
	if err != nil { return projection, err }
	return edge.withIndividualUpdates(snapshot, projection), nil
}

func (edge *packageMaintenanceLinuxEdge) withIndividualUpdates(snapshot packagemaint.InventorySnapshot, projection apiserver.PackageMaintenancePackageProjection) apiserver.PackageMaintenancePackageProjection {
	projection.SupportedUpdates = []apiserver.PackageMaintenanceUpdateOption{}
	if projection.Held || edge.catalog == nil { return projection }
	for _, option := range edge.catalog.IndividualUpdateOptions(snapshot, projection.ID, edge.now().UTC()) {
		projection.SupportedUpdates = append(projection.SupportedUpdates, apiserver.PackageMaintenanceUpdateOption{Label: option.Label, Value: option.Value})
	}
	if len(projection.SupportedUpdates) > 0 { projection.Type = "update_available" }
	return projection
}

func (edge *packageMaintenanceLinuxEdge) HoldPackageMaintenancePackage(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection], error) {
	return edge.setPackageHold(ctx, call, packagemaint.PackageHold)
}

func (edge *packageMaintenanceLinuxEdge) UnholdPackageMaintenancePackage(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection], error) {
	return edge.setPackageHold(ctx, call, packagemaint.PackageUnhold)
}

func (edge *packageMaintenanceLinuxEdge) setPackageHold(ctx context.Context, call apiserver.EdgeCall,
	action packagemaint.PackageHoldAction) (apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection], error) {
	if err := edge.validateMutation(ctx, call, true); err != nil || call.AuthzEpoch == 0 {
		if err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, err }
		return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, packagemaint.ErrUnauthorized
	}
	effectID := "pkghold_" + packageMaintenanceDigest(call.CommandID, call.IdempotencyKey, string(action), call.ResourceID)[:40]
	operation, err := edge.repository.PackageHoldOperation(ctx, effectID)
	var snapshot packagemaint.InventorySnapshot
	var projection apiserver.PackageMaintenancePackageProjection
	if errors.Is(err, packagemaint.ErrNotFound) {
		snapshot, err = edge.repository.LatestInventory(ctx, edge.nodeID, edge.manager)
		if err != nil || snapshot.Generation != call.ExpectedGeneration {
			if err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, err }
			return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, packagemaint.ErrStaleInventory
		}
		projection, err = packageMaintenancePackageByID(snapshot, call.ResourceID)
		if err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, err }
		scope := "package-maintenance:" + string(action) + ":" + effectID
		authorization := packagemaint.AuthorizationRequest{Boundary: packagemaint.BoundaryAcceptance, OperationID: effectID,
			ActorID: call.PrincipalID, Scope: scope, PlanID: snapshot.ID, PlanDigest: snapshot.ContentDigest,
			PlanGeneration: snapshot.Generation, MinimumAssurance: packagemaint.AssuranceMFA}
		encoded, encodeErr := json.Marshal(authorization); if encodeErr != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, encodeErr }
		digest := sha256.Sum256(encoded); authorization.RequestDigest = hex.EncodeToString(digest[:])
		evidence, authorizeErr := edge.service.Authorizer.Authorize(ctx, authorization)
		if authorizeErr != nil || evidence.ActorID != call.PrincipalID || evidence.Scope != scope || evidence.RequestDigest != authorization.RequestDigest || evidence.AuthorizationEpoch != call.AuthzEpoch {
			return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, packagemaint.ErrUnauthorized
		}
		request := packagemaint.PackageHoldRequest{EffectID: effectID, NodeID: edge.nodeID, Manager: edge.manager, Action: action,
			PackageName: projection.Name, Architecture: projection.Architecture, InstalledVersion: projection.InstalledVersion,
			RepositoryID: projection.RepositoryID, ProvenanceDigest: projection.InstalledProvenanceDigest,
			InventoryID: snapshot.ID, InventoryGeneration: snapshot.Generation, InventoryDigest: snapshot.ContentDigest,
			Authorization: evidence, RequestedAt: edge.now().UTC()}
		if err = packagemaint.SealPackageHoldRequest(&request); err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, err }
		operation, err = edge.repository.AdmitPackageHold(ctx, packagemaint.PackageHoldOperation{ID: effectID, Request: request,
			State: packagemaint.PackageHoldAdmitted, Generation: 1, CreatedAt: edge.now().UTC(), UpdatedAt: edge.now().UTC()})
	} else if err == nil {
		if operation.Request.Action != action || operation.Request.InventoryGeneration != call.ExpectedGeneration {
			return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, packagemaint.ErrConflict
		}
		snapshot, err = edge.repository.Inventory(ctx, operation.Request.InventoryID)
		if err == nil { projection, err = packageMaintenancePackageByID(snapshot, call.ResourceID) }
		if err == nil && (projection.Name != operation.Request.PackageName || projection.Architecture != operation.Request.Architecture || projection.InstalledVersion != operation.Request.InstalledVersion) {
			err = packagemaint.ErrConflict
		}
	}
	if err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, err }
	if operation.Request.Authorization.ActorID != call.PrincipalID || operation.Request.Authorization.AuthorizationEpoch != call.AuthzEpoch {
		return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, packagemaint.ErrUnauthorized
	}
	if operation.State == packagemaint.PackageHoldAdmitted { operation, err = edge.repository.StartPackageHold(ctx, operation.ID, edge.now().UTC()) }
	if err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, err }
	if operation.State == packagemaint.PackageHoldRunning {
		receipt, after, effectErr := edge.holds.SetPackageHold(ctx, operation.Request)
		if receipt.EffectID == "" && errors.Is(effectErr, packagemaint.ErrAmbiguous) {
			return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, effectErr
		}
		state, failure := packagemaint.PackageHoldSucceeded, ""
		if effectErr != nil { state, failure = packagemaint.PackageHoldFailed, "effect_rejected" }
		if receipt.EffectID != "" {
			latest, latestErr := edge.repository.LatestInventory(ctx, edge.nodeID, edge.manager)
			if latestErr != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, latestErr }
			if latest.ID == snapshot.ID { err = edge.repository.SaveInventory(ctx, after, snapshot.Generation) } else if latest.ID != after.ID { err = packagemaint.ErrStaleInventory }
			if err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, err }
			if receipt.Outcome == packagemaint.OutcomeAmbiguous { state, failure = packagemaint.PackageHoldAmbiguous, "ambiguous" }
		}
		operation, err = edge.repository.FinishPackageHold(ctx, operation.ID, state, receipt, failure, edge.now().UTC())
		if err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, err }
	}
	latest, err := edge.repository.LatestInventory(ctx, edge.nodeID, edge.manager)
	if err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{}, err }
	resultSnapshot := latest
	if operation.Receipt.AfterInventoryID != "" { resultSnapshot, err = edge.repository.Inventory(ctx, operation.Receipt.AfterInventoryID) }
	if err == nil { projection, err = packageMaintenancePackageByID(resultSnapshot, call.ResourceID) }
	projection.HoldOperationID, projection.HoldOutcome, projection.HoldReceiptDigest = operation.ID, string(operation.Receipt.Outcome), operation.Receipt.EvidenceDigest
	return apiserver.EdgeMutation[apiserver.PackageMaintenancePackageProjection]{OperationID: operation.ID, State: string(operation.State), Generation: projection.Generation, Resource: projection}, err
}

func packageMaintenancePackageByID(snapshot packagemaint.InventorySnapshot, id string) (apiserver.PackageMaintenancePackageProjection, error) {
	for _, installed := range snapshot.Packages {
		projection := projectPackageMaintenancePackage(snapshot, installed)
		if projection.ID == id { return projection, nil }
	}
	return apiserver.PackageMaintenancePackageProjection{}, packagemaint.ErrNotFound
}

func projectPackageMaintenancePackage(snapshot packagemaint.InventorySnapshot, installed packagemaint.Package) apiserver.PackageMaintenancePackageProjection {
	security := packagemaint.SecurityNone
	if installed.PendingSecurity { security = packageMaintenanceSecurity(snapshot.Advisories, installed) }
	result := apiserver.PackageMaintenancePackageProjection{ID: packagemaint.InventoryPackageResourceID(snapshot, installed),
		Type: "unheld", NodeID: snapshot.NodeID, Manager: string(snapshot.Manager), Name: installed.Name, Architecture: installed.Architecture,
		InstalledVersion: installed.InstalledVersion, CandidateVersion: installed.CandidateVersion, PendingSecurity: installed.PendingSecurity,
		Security: string(security), RepositoryID: installed.RepositoryID,
		InstalledProvenanceDigest: installed.ProvenanceDigest, InventoryID: snapshot.ID, InventoryDigest: snapshot.ContentDigest,
		Generation: snapshot.Generation, UpdatedAt: snapshot.CapturedAt}
	for _, repository := range snapshot.Repositories { if repository.ID == installed.RepositoryID { result.RepositoryOrigin, result.RepositorySuite, result.RepositoryComponent, result.RepositoryEnabled, result.RepositoryMetadataRevision, result.RepositorySignature, result.RepositorySigningKeyID, result.RepositoryDigest = repository.Origin, repository.Suite, repository.Component, repository.Enabled, repository.MetadataRevision, string(repository.Signature), repository.SigningKeyID, repository.Digest } }
	for _, provenance := range snapshot.Provenance {
		if provenance.Digest == installed.ProvenanceDigest { result.InstalledProvenanceSignature, result.InstalledProvenanceSigningKeyID, result.InstalledVendor, result.LocalArtifact = string(provenance.Signature), provenance.SigningKeyID, provenance.Vendor, provenance.LocalArtifact }
		if provenance.PackageName == installed.Name && provenance.Architecture == installed.Architecture && provenance.Version == installed.CandidateVersion && provenance.RepositoryID == installed.RepositoryID { result.CandidateProvenanceDigest, result.CandidateProvenanceSignature = provenance.Digest, string(provenance.Signature) }
	}
	for _, hold := range snapshot.Holds { if hold.PackageName == installed.Name { result.Type, result.Held, result.HoldKind, result.HoldSource = "held", true, hold.Kind, hold.Source } }
	return result
}

func (edge *packageMaintenanceLinuxEdge) ListPackageMaintenance(ctx context.Context, call apiserver.EdgeCall,
	payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.PackageMaintenanceProjection], error) {
	if edge == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" || call.ExpectedGeneration != 0 ||
		call.PrincipalID == "" || call.CredentialID == "" || payload.Cursor != "" {
		return apiserver.EdgePage[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrInvalid
	}
	snapshot, err := edge.repository.LatestInventory(ctx, edge.nodeID, edge.manager)
	if errors.Is(err, packagemaint.ErrNotFound) {
		return apiserver.EdgePage[apiserver.PackageMaintenanceProjection]{Items: []apiserver.PackageMaintenanceProjection{}, Total: 0}, nil
	}
	if err != nil {
		return apiserver.EdgePage[apiserver.PackageMaintenanceProjection]{}, err
	}
	projection, err := edge.projection(ctx, snapshot)
	if err != nil {
		return apiserver.EdgePage[apiserver.PackageMaintenanceProjection]{}, err
	}
	return apiserver.EdgePage[apiserver.PackageMaintenanceProjection]{Items: []apiserver.PackageMaintenanceProjection{projection}, Total: 1}, nil
}

func (edge *packageMaintenanceLinuxEdge) RefreshPackageMaintenance(ctx context.Context,
	call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection], error) {
	if err := edge.validateMutation(ctx, call, false); err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	expectedGeneration := uint64(0)
	latest, err := edge.repository.LatestInventory(ctx, edge.nodeID, edge.manager)
	if err == nil {
		expectedGeneration = latest.Generation
	} else if !errors.Is(err, packagemaint.ErrNotFound) {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	if expectedGeneration >= packageMaintenanceMaximumGeneration {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrConflict
	}
	operation, operationErr := edge.latestOperation(ctx)
	if operationErr != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, operationErr
	}
	if packageMaintenanceOperationInFlight(operation.State) {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrConflict
	}
	snapshot, err := edge.inventory.Snapshot(ctx, packagemaint.InventoryRequest{NodeID: edge.nodeID, Manager: edge.manager, Generation: expectedGeneration + 1})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	if err = edge.repository.SaveInventory(ctx, snapshot, expectedGeneration); err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	projection, err := edge.projection(ctx, snapshot)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{OperationID: call.CommandID, State: "observed",
		Generation: projection.Generation, Resource: projection}, nil
}

func (edge *packageMaintenanceLinuxEdge) PlanPackageMaintenance(ctx context.Context, call apiserver.EdgeCall,
	payload apiserver.PackageMaintenancePlanPayload) (apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection], error) {
	if err := edge.validateMutation(ctx, call, true); err != nil || payload.ValidForSeconds < 60 || payload.ValidForSeconds > 86400 {
		if err != nil {
			return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
		}
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrInvalid
	}
	snapshot, err := edge.repository.LatestInventory(ctx, edge.nodeID, edge.manager)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	if snapshot.Generation != call.ExpectedGeneration {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrStaleInventory
	}
	individual := payload.TransactionReference != ""
	if individual {
		if !validPackageMaintenanceRuntimeID(payload.TransactionReference) { return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrInvalid }
		if _, err = packageMaintenancePackageByID(snapshot, call.ResourceID); err != nil { return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err }
	} else if snapshot.ID != call.ResourceID {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrStaleInventory
	}
	summary := summarizePackageMaintenanceInventory(snapshot)
	if summary.repositoryHealth != "healthy" || summary.blockedSecurity != 0 {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrUnauthorized
	}
	if summary.databaseStatus != "ready" {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrLocked
	}
	if !individual && summary.availableSecurity == 0 {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrUnsupported
	}
	operation, operationErr := edge.latestOperation(ctx)
	if operationErr != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, operationErr
	}
	if operation.State == packagemaint.OperationRecoveryRequired {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrRecoveryRequired
	}
	if packageMaintenanceOperationInFlight(operation.State) {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrConflict
	}
	planGeneration := uint64(1)
	latestPlan, planErr := edge.repository.LatestPlan(ctx, edge.nodeID, edge.manager)
	if planErr == nil {
		if latestPlan.Generation >= packageMaintenanceMaximumGeneration {
			return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrConflict
		}
		if latestPlan.InventoryID == snapshot.ID && latestPlan.InventoryDigest == snapshot.ContentDigest && edge.now().UTC().Before(latestPlan.ExpiresAt) {
			return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrConflict
		}
		planGeneration = latestPlan.Generation + 1
	} else if !errors.Is(planErr, packagemaint.ErrNotFound) {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, planErr
	}
	var attestation packagemaint.SolverAttestation
	if individual {
		attestation, err = edge.resolver.ResolveIndividualUpdate(ctx, snapshot, payload.TransactionReference, call.ResourceID)
	} else {
		attestation, err = edge.resolver.ResolveSecurityUpdates(ctx, snapshot)
	}
	if err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	planner := packagemaint.Planner{Now: edge.now}
	plan, err := planner.Build(snapshot, packagemaint.PlanRequest{Generation: planGeneration,
		ValidFor: time.Duration(payload.ValidForSeconds) * time.Second,
		MaintenanceOccurrenceID: payload.MaintenanceOccurrenceID, Attestation: attestation})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	if !individual && !packageMaintenanceSecurityOnly(snapshot, plan) {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrUnsupported
	}
	if err = edge.service.AdmitMaintenance(ctx, packagemaint.MaintenanceAdmissionRequest{
		RequestID: "pkgmw_" + packageMaintenanceDigest("plan", call.CommandID, plan.ID)[:32],
		OccurrenceID: plan.MaintenanceOccurrenceID, NodeID: plan.NodeID, Manager: plan.Manager,
		ExpectedDuration: packagemaint.MaintenanceExecutionDuration, At: edge.now().UTC()}); err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	if err = edge.repository.PutPlan(ctx, plan); err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	projection, err := edge.projection(ctx, snapshot)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{OperationID: call.CommandID, State: "planned",
		Generation: projection.Generation, Resource: projection}, nil
}

func (edge *packageMaintenanceLinuxEdge) ApplyPackageMaintenance(ctx context.Context,
	call apiserver.EdgeCall, payload apiserver.PackageMaintenanceApplyPayload) (apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection], error) {
	if err := edge.validateMutation(ctx, call, true); err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	plan, err := edge.repository.Plan(ctx, call.ResourceID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	if plan.NodeID != edge.nodeID || plan.Manager != edge.manager || plan.Generation != call.ExpectedGeneration ||
		payload.MaintenanceOccurrenceID != plan.MaintenanceOccurrenceID || !edge.now().UTC().Before(plan.ExpiresAt) {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrStalePlan
	}
	latestPlan, err := edge.repository.LatestPlan(ctx, edge.nodeID, edge.manager)
	if err != nil || latestPlan.ID != plan.ID || latestPlan.Generation != plan.Generation || latestPlan.Digest != plan.Digest {
		if err != nil {
			return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
		}
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrStalePlan
	}
	snapshot, err := edge.repository.LatestInventory(ctx, edge.nodeID, edge.manager)
	if err != nil || snapshot.ID != plan.InventoryID || snapshot.Generation != plan.InventoryGeneration || snapshot.ContentDigest != plan.InventoryDigest {
		if err != nil {
			return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
		}
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrStaleInventory
	}
	operationID := packageMaintenanceOperationID(call, plan)
	operation, err := edge.repository.Operation(ctx, operationID)
	if errors.Is(err, packagemaint.ErrNotFound) {
		latestOperation, latestErr := edge.latestOperation(ctx)
		if latestErr != nil {
			return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, latestErr
		}
		if latestOperation.ID != "" && latestOperation.PlanID == plan.ID {
			return edge.operationMutation(ctx, snapshot, latestOperation)
		}
		if packageMaintenanceOperationInFlight(latestOperation.State) {
			return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrConflict
		}
		operation, err = edge.service.Admit(ctx, packagemaint.AdmissionRequest{OperationID: operationID, PlanID: plan.ID,
			MaintenanceOccurrenceID: payload.MaintenanceOccurrenceID, ActorID: call.PrincipalID, Fence: plan.Generation})
	}
	if err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	if operation.PlanID != plan.ID || operation.PlanDigest != plan.Digest || operation.AcceptanceAuthorization.ActorID != call.PrincipalID {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, packagemaint.ErrUnauthorized
	}
	if operation.State != packagemaint.OperationAdmitted {
		return edge.operationMutation(ctx, snapshot, operation)
	}
	operation, applyErr := edge.service.Apply(ctx, operation.ID, call.PrincipalID)
	if applyErr != nil && !packageMaintenanceDurableResult(operation.State) {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, applyErr
	}
	return edge.operationMutation(ctx, snapshot, operation)
}

func (edge *packageMaintenanceLinuxEdge) validateMutation(ctx context.Context, call apiserver.EdgeCall, existing bool) error {
	if edge == nil || ctx == nil || call.TenantID != "" || call.PrincipalID == "" || call.CredentialID == "" ||
		call.IdempotencyKey == "" || call.CommandID == "" {
		return packagemaint.ErrInvalid
	}
	if existing {
		if !validPackageMaintenanceRuntimeID(call.ResourceID) || call.ExpectedGeneration == 0 {
			return packagemaint.ErrInvalid
		}
	} else if call.ResourceID != "" || call.ExpectedGeneration != 0 {
		return packagemaint.ErrInvalid
	}
	return nil
}

func (edge *packageMaintenanceLinuxEdge) latestOperation(ctx context.Context) (packagemaint.MaintenanceOperation, error) {
	operation, err := edge.repository.LatestOperation(ctx, edge.nodeID, edge.manager)
	if errors.Is(err, packagemaint.ErrNotFound) {
		return packagemaint.MaintenanceOperation{}, nil
	}
	return operation, err
}

func (edge *packageMaintenanceLinuxEdge) operationMutation(ctx context.Context, snapshot packagemaint.InventorySnapshot,
	operation packagemaint.MaintenanceOperation) (apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection], error) {
	projection, err := edge.projection(ctx, snapshot)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{}, err
	}
	return apiserver.EdgeMutation[apiserver.PackageMaintenanceProjection]{OperationID: operation.ID,
		State: string(operation.State), Generation: projection.Generation, Resource: projection}, nil
}

func (edge *packageMaintenanceLinuxEdge) projection(ctx context.Context,
	snapshot packagemaint.InventorySnapshot) (apiserver.PackageMaintenanceProjection, error) {
	if snapshot.NodeID != edge.nodeID || snapshot.Manager != edge.manager {
		return apiserver.PackageMaintenanceProjection{}, packagemaint.ErrInvalid
	}
	plan, planErr := edge.repository.LatestPlan(ctx, edge.nodeID, edge.manager)
	if errors.Is(planErr, packagemaint.ErrNotFound) {
		plan = packagemaint.MaintenancePlan{}
	} else if planErr != nil {
		return apiserver.PackageMaintenanceProjection{}, planErr
	}
	operation, err := edge.latestOperation(ctx)
	if err != nil {
		return apiserver.PackageMaintenanceProjection{}, err
	}
	return projectPackageMaintenance(snapshot, plan, operation, edge.now().UTC()), nil
}

type packageMaintenanceInventorySummary struct {
	repositoryHealth  string
	enabledRepositories uint64
	verifiedRepositories uint64
	blockedRepositories uint64
	availableSecurity uint64
	blockedSecurity   uint64
	highestSecurity   packagemaint.SecurityClass
	databaseStatus    string
}

func summarizePackageMaintenanceInventory(snapshot packagemaint.InventorySnapshot) packageMaintenanceInventorySummary {
	summary := packageMaintenanceInventorySummary{repositoryHealth: "unknown", highestSecurity: packagemaint.SecurityNone,
		databaseStatus: "ready"}
	repositories := make(map[string]packagemaint.Repository, len(snapshot.Repositories))
	for _, repository := range snapshot.Repositories {
		repositories[repository.ID] = repository
		if !repository.Enabled {
			continue
		}
		summary.enabledRepositories++
		if repository.Signature == packagemaint.SignatureVerified && repository.SigningKeyID != "" && repository.MetadataRevision != "" {
			summary.verifiedRepositories++
		} else {
			summary.blockedRepositories++
		}
	}
	if summary.enabledRepositories > 0 && summary.blockedRepositories == 0 {
		summary.repositoryHealth = "healthy"
	} else if summary.enabledRepositories > 0 {
		summary.repositoryHealth = "blocked"
	}
	for _, installed := range snapshot.Packages {
		if !installed.PendingSecurity {
			continue
		}
		if trustedPackageMaintenanceCandidate(installed, repositories, snapshot.Provenance) {
			summary.availableSecurity++
			summary.highestSecurity = higherPackageMaintenanceSecurity(summary.highestSecurity,
				packageMaintenanceSecurity(snapshot.Advisories, installed))
		} else {
			summary.blockedSecurity++
		}
	}
	for _, lock := range snapshot.Locks {
		if lock.RepairCode != "" {
			summary.databaseStatus = "repair_required"
		} else if lock.Held && summary.databaseStatus == "ready" {
			summary.databaseStatus = "locked"
		}
	}
	return summary
}

func trustedPackageMaintenanceCandidate(installed packagemaint.Package, repositories map[string]packagemaint.Repository,
	provenance []packagemaint.Provenance) bool {
	if installed.CandidateVersion == "" || installed.RepositoryID == "" {
		return false
	}
	repository, found := repositories[installed.RepositoryID]
	if !found || !repository.Enabled || repository.Signature != packagemaint.SignatureVerified || repository.SigningKeyID == "" {
		return false
	}
	for _, source := range provenance {
		if source.PackageName == installed.Name && source.Architecture == installed.Architecture &&
			source.Version == installed.CandidateVersion && source.RepositoryID == installed.RepositoryID &&
			source.Signature == packagemaint.SignatureVerified && source.SigningKeyID == repository.SigningKeyID && !source.LocalArtifact {
			return true
		}
	}
	return false
}

func packageMaintenanceSecurity(advisories []packagemaint.Advisory,
	installed packagemaint.Package) packagemaint.SecurityClass {
	result := packagemaint.SecurityNone
	found := false
	for _, advisory := range advisories {
		if advisory.CorrectedVersion != "" && advisory.CorrectedVersion != installed.CandidateVersion {
			continue
		}
		for _, packageName := range advisory.PackageNames {
			if packageName == installed.Name {
				result = higherPackageMaintenanceSecurity(result, advisory.Security)
				found = true
			}
		}
	}
	if !found {
		return packagemaint.SecurityUnknown
	}
	return result
}

func higherPackageMaintenanceSecurity(left, right packagemaint.SecurityClass) packagemaint.SecurityClass {
	rank := map[packagemaint.SecurityClass]int{packagemaint.SecurityNone: 0, packagemaint.SecurityLow: 1,
		packagemaint.SecurityModerate: 2, packagemaint.SecurityHigh: 3, packagemaint.SecurityCritical: 4,
		packagemaint.SecurityUnknown: 5}
	if rank[right] > rank[left] {
		return right
	}
	return left
}

func projectPackageMaintenance(snapshot packagemaint.InventorySnapshot, plan packagemaint.MaintenancePlan,
	operation packagemaint.MaintenanceOperation, now time.Time) apiserver.PackageMaintenanceProjection {
	summary := summarizePackageMaintenanceInventory(snapshot)
	projection := apiserver.PackageMaintenanceProjection{ID: snapshot.ID, Type: "blocked", NodeID: snapshot.NodeID,
		Manager: string(snapshot.Manager), RepositoryHealth: summary.repositoryHealth,
		EnabledRepositories: summary.enabledRepositories, VerifiedRepositories: summary.verifiedRepositories,
		BlockedRepositories: summary.blockedRepositories, SecurityUpdatesAvailable: summary.availableSecurity,
		SecurityUpdatesBlocked: summary.blockedSecurity, HighestSecurity: string(summary.highestSecurity),
		PackageDatabaseStatus: summary.databaseStatus, RebootRequired: snapshot.RebootRequired,
		InventoryID: snapshot.ID, InventoryDigest: snapshot.ContentDigest, PlanStatus: "blocked",
		ApplyStatus: "blocked", RollbackStatus: "not_available", RecoveryStatus: "not_required",
		Generation: snapshot.Generation, UpdatedAt: snapshot.CapturedAt}
	if summary.repositoryHealth != "healthy" {
		projection.PlanStatus = "blocked_repository"
	} else if summary.blockedSecurity != 0 {
		projection.PlanStatus = "blocked_provenance"
	} else if summary.databaseStatus != "ready" {
		projection.PlanStatus = "blocked_package_database"
	} else if summary.availableSecurity == 0 {
		projection.PlanStatus = "no_security_updates"
	} else {
		projection.Type = "ready_to_plan"
		projection.PlanStatus = "ready"
	}
	currentPlan := plan.ID != "" && plan.InventoryID == snapshot.ID && plan.InventoryGeneration == snapshot.Generation &&
		plan.InventoryDigest == snapshot.ContentDigest
	if plan.ID != "" {
		for _, change := range plan.Changes { projection.PlannedChanges = append(projection.PlannedChanges, change.Name + ":" + change.Architecture + " " + change.FromVersion + " → " + change.ToVersion + " (" + string(change.Action) + ")") }
		for _, service := range plan.Services { projection.PlannedServices = append(projection.PlannedServices, service.ServiceID + ": " + string(service.Action)) }
		projection.PlanID = plan.ID
		projection.PlanDigest = plan.Digest
		projection.MaintenanceOccurrenceID = plan.MaintenanceOccurrenceID
		projection.PlannedReboot = string(plan.Reboot)
		projection.RecoveryKind = string(plan.Recovery.Kind)
		projection.RecoveryRequired = plan.Recovery.Required
		projection.RecoveryInstructions = append([]string(nil), plan.Recovery.Instructions...)
		if plan.Recovery.Eligible {
			projection.RollbackStatus = "eligible_unproven"
			projection.RecoveryStatus = "eligible_unproven"
		}
		if plan.CreatedAt.After(projection.UpdatedAt) {
			projection.UpdatedAt = plan.CreatedAt
		}
		if !currentPlan {
			projection.PlanStatus = "stale"
		} else if !now.Before(plan.ExpiresAt) {
			projection.PlanStatus = "expired"
		} else {
			projection.ID = plan.ID
			projection.Type = "planned"
			projection.Generation = plan.Generation
			projection.PlanStatus = "planned"
			projection.ApplyStatus = "awaiting_commit"
		}
	}
	currentOperation := operation.ID != "" && currentPlan && operation.PlanID == plan.ID && operation.PlanDigest == plan.Digest
	if operation.ID != "" {
		projection.OperationID = operation.ID
		projection.OperationState = string(operation.State)
		projection.OperationOutcome = string(operation.Receipt.Outcome)
		if operation.UpdatedAt.After(projection.UpdatedAt) {
			projection.UpdatedAt = operation.UpdatedAt
		}
		if operation.Receipt.Snapshot.SnapshotID != "" {
			projection.SnapshotID = operation.Receipt.Snapshot.SnapshotID
			projection.RollbackStatus = "recovery_point_created"
			projection.RecoveryStatus = "recovery_point_created"
			projection.RecoveryEvidence = operation.Receipt.Snapshot.Digest
		}
		if operation.Receipt.Recovery.Attempted {
			projection.RecoveryEvidence = operation.Receipt.Recovery.EvidenceDigest
			projection.RecoveryInstructions = append([]string(nil), operation.Receipt.Recovery.Instructions...)
			if operation.Receipt.Recovery.Restored {
				projection.RollbackStatus = "restored"
				projection.RecoveryStatus = "restored"
			} else {
				projection.RollbackStatus = "manual_recovery_required"
				projection.RecoveryStatus = "manual_recovery_required"
			}
		}
	}
	if currentOperation {
		projection.ID = operation.ID
		projection.Generation = operation.Generation
		switch operation.State {
		case packagemaint.OperationAdmitted:
			projection.Type, projection.ApplyStatus = "applying", "admitted"
		case packagemaint.OperationAuthorized:
			projection.Type, projection.ApplyStatus = "applying", "authorized"
		case packagemaint.OperationRunning, packagemaint.OperationVerifying:
			projection.Type, projection.ApplyStatus = "applying", "in_progress"
		case packagemaint.OperationSucceeded:
			projection.Type, projection.ApplyStatus = "complete", "confirmed"
		case packagemaint.OperationFailed:
			projection.Type, projection.ApplyStatus = "failed", "failed"
		case packagemaint.OperationRecovered:
			projection.Type, projection.ApplyStatus = "complete", "recovered"
			projection.RollbackStatus, projection.RecoveryStatus = "restored", "restored"
		case packagemaint.OperationRecoveryRequired:
			projection.Type = "recovery"
			projection.RecoveryRequired = true
			if operation.Receipt.Outcome == packagemaint.OutcomeAmbiguous {
				projection.ApplyStatus = "ambiguous"
				projection.RollbackStatus = "ambiguous"
				projection.RecoveryStatus = "ambiguous"
				projection.Ambiguous = true
			} else {
				projection.ApplyStatus = "recovery_required"
				projection.RollbackStatus = "manual_recovery_required"
				projection.RecoveryStatus = "manual_recovery_required"
			}
		}
	} else if operation.State == packagemaint.OperationRecoveryRequired {
		projection.ID = operation.ID
		projection.Type = "recovery"
		projection.Generation = operation.Generation
		projection.PlanStatus = "blocked_recovery"
		projection.ApplyStatus = "recovery_required"
		projection.RecoveryRequired = true
		if operation.Receipt.Outcome == packagemaint.OutcomeAmbiguous {
			projection.ApplyStatus = "ambiguous"
			projection.RollbackStatus = "ambiguous"
			projection.RecoveryStatus = "ambiguous"
			projection.Ambiguous = true
		}
	}
	return projection
}

func packageMaintenanceSecurityOnly(snapshot packagemaint.InventorySnapshot, plan packagemaint.MaintenancePlan) bool {
	repositories := make(map[string]packagemaint.Repository, len(snapshot.Repositories))
	for _, repository := range snapshot.Repositories {
		repositories[repository.ID] = repository
	}
	expected := make(map[string]string)
	for _, installed := range snapshot.Packages {
		if installed.PendingSecurity && trustedPackageMaintenanceCandidate(installed, repositories, snapshot.Provenance) {
			expected[installed.Name+"\x00"+installed.Architecture] = installed.CandidateVersion
		}
	}
	selected := make(map[string]struct{})
	for _, change := range plan.Changes {
		if !change.Selected {
			continue
		}
		key := change.Name + "\x00" + change.Architecture
		target, exists := expected[key]
		if change.Action != packagemaint.ChangeUpgrade && change.Action != packagemaint.ChangeReinstall ||
			change.Security == packagemaint.SecurityNone || !exists || change.ToVersion != target {
			return false
		}
		selected[key] = struct{}{}
	}
	return len(selected) > 0 && len(selected) == len(expected) && plan.Security != packagemaint.SecurityNone
}

func packageMaintenanceOperationInFlight(state packagemaint.OperationState) bool {
	return state == packagemaint.OperationAdmitted || state == packagemaint.OperationAuthorized ||
		state == packagemaint.OperationRunning || state == packagemaint.OperationVerifying
}

func packageMaintenanceDurableResult(state packagemaint.OperationState) bool {
	return state == packagemaint.OperationAuthorized || state == packagemaint.OperationRunning ||
		state == packagemaint.OperationVerifying || state == packagemaint.OperationSucceeded ||
		state == packagemaint.OperationFailed || state == packagemaint.OperationRecoveryRequired ||
		state == packagemaint.OperationRecovered
}

func packageMaintenanceOperationID(call apiserver.EdgeCall, plan packagemaint.MaintenancePlan) string {
	sum := sha256.Sum256([]byte("cyberpanel-package-maintenance-operation-v1\x00" + call.CommandID + "\x00" +
		call.IdempotencyKey + "\x00" + plan.Digest))
	return "pkgop_" + hex.EncodeToString(sum[:24])
}

func packageMaintenanceDigest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (admission *packageMaintenanceWindowAdmission) AdmitPackageMaintenance(ctx context.Context,
	request packagemaint.MaintenanceAdmissionRequest) error {
	if admission == nil || admission.evaluator == nil || admission.occurrences == nil || ctx == nil ||
		request.NodeID != admission.nodeID || request.Manager != admission.manager {
		return packagemaint.ErrInvalid
	}
	decision, err := admission.evaluator.Admit(ctx, maintenance.AdmissionRequest{
		ID: "pkgmw_" + packageMaintenanceDigest(request.RequestID, request.OccurrenceID)[:32],
		Target: maintenance.Target{TenantID: maintenance.InstallationTenantID, NodeID: request.NodeID,
			ResourceKind: "package_maintenance", ResourceID: string(request.Manager)},
		OperationClass: maintenance.OperationSecurity, ExpectedDuration: request.ExpectedDuration, At: request.At.UTC()})
	if err != nil || decision.Kind != maintenance.DecisionAllow || decision.OccurrenceID != request.OccurrenceID {
		return packagemaint.ErrUnauthorized
	}
	occurrence, err := admission.occurrences.LoadOccurrence(ctx, decision.OccurrenceID)
	if err != nil || occurrence.ID != request.OccurrenceID || occurrence.StartsAt.After(request.At) ||
		occurrence.EndsAt.Before(request.At.Add(request.ExpectedDuration)) {
		return packagemaint.ErrUnauthorized
	}
	return nil
}

func validPackageMaintenanceRuntimeID(value string) bool {
	if value == "" || len(value) > 160 {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '-' || character == '_' || character == '.' || character == ':') {
			continue
		}
		return false
	}
	return true
}

var _ apiserver.PackageMaintenanceEdgeService = (*packageMaintenanceLinuxEdge)(nil)
var _ apiserver.PackageMaintenanceEdgeCapabilityProvider = (*packageMaintenanceLinuxEdge)(nil)
