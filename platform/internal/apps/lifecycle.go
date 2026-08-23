package apps

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type DiscoveryRequest struct {
	CommandID         CommandID `json:"command_id"`
	TenantID         TenantID `json:"tenant_id"`
	SiteID           SiteID `json:"site_id"`
	SiteUID          SiteUID `json:"site_uid"`
	SiteGeneration   uint64 `json:"site_generation"`
	IsolationProfile string `json:"isolation_profile"`
	Root             RelativePath `json:"root"`
	Kinds            []ApplicationKind `json:"kinds"`
	MaximumDepth     uint8 `json:"maximum_depth"`
	MaximumCandidates uint16 `json:"maximum_candidates"`
}

type AdoptionRequest struct {
	CommandID         CommandID `json:"command_id"`
	TenantID         TenantID `json:"tenant_id"`
	ProjectID        ProjectID `json:"project_id,omitempty"`
	SiteID           SiteID `json:"site_id"`
	SiteUID          SiteUID `json:"site_uid"`
	SiteGeneration   uint64 `json:"site_generation"`
	IsolationProfile string `json:"isolation_profile"`
	InstallationID   InstallationID `json:"installation_id"`
	Recipe           RecipeReference `json:"recipe"`
	CatalogTarget    CatalogTarget `json:"catalog_target"`
	Candidate        DiscoveryCandidate `json:"candidate"`
	RuntimeID        string `json:"runtime_id"`
	Database         DatabaseBinding `json:"database"`
}

type RepairRequest struct {
	CommandID          CommandID `json:"command_id"`
	InstallationID     InstallationID `json:"installation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Actions            []RepairAction `json:"actions"`
	ExpectedInventoryDigest string `json:"expected_inventory_digest"`
	SiteGeneration     uint64 `json:"site_generation"`
	IsolationProfile   string `json:"isolation_profile"`
}

type RemovalRequest struct {
	CommandID          CommandID `json:"command_id"`
	InstallationID     InstallationID `json:"installation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Disposition        RemovalDisposition `json:"disposition"`
	SiteGeneration     uint64 `json:"site_generation"`
	IsolationProfile   string `json:"isolation_profile"`
}

type LifecycleCoordinator struct {
	Store      ApplicationStore
	Catalog    DefinitionCatalog
	Executor   SiteApplicationExecutor
	Recovery   RecoveryPointProvider
	Databases  DatabaseProvisioner
	Secrets    SecretIssuer
	Now        func() time.Time
}

func (coordinator LifecycleCoordinator) now() time.Time {
	if coordinator.Now != nil { return coordinator.Now().UTC() }
	return time.Now().UTC()
}

func (coordinator LifecycleCoordinator) Discover(ctx context.Context, request DiscoveryRequest) ([]DiscoveryCandidate, error) {
	if coordinator.Store == nil || coordinator.Executor == nil || len(request.Kinds) == 0 || request.MaximumDepth == 0 || request.MaximumDepth > 16 || request.MaximumCandidates == 0 || request.MaximumCandidates > 1000 { return nil, ErrInvalid }
	for _, kind := range request.Kinds { if !kind.Valid() { return nil, ErrInvalid } }
	digest, err := requestDigest(request)
	if err != nil { return nil, err }
	operation := Operation{CommandID: request.CommandID, Kind: "discover", TenantID: request.TenantID, SiteID: request.SiteID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	operation, created, err := coordinator.Store.AdmitOperation(ctx, operation)
	if err != nil { return nil, err }
	if !created { return nil, ErrConflict }
	scope := SiteExecutionScope{TenantID: request.TenantID, SiteID: request.SiteID, SiteUID: request.SiteUID, Root: request.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	if err := scope.Validate(); err != nil { return nil, coordinator.fail(ctx, operation, "scope", err) }
	candidates, receipt, err := coordinator.Executor.Discover(ctx, DiscoveryExecution{Scope: scope, Kinds: request.Kinds, MaximumDepth: request.MaximumDepth, MaximumCandidates: request.MaximumCandidates})
	if err != nil { return nil, coordinator.fail(ctx, operation, "execute", err) }
	if err := receipt.Validate("discover", scope, ""); err != nil { return nil, coordinator.fail(ctx, operation, "receipt", err) }
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if !candidate.Kind.Valid() || !candidate.DatabaseReachable || !candidate.OwnershipValid || !validDigest(candidate.EvidenceDigest) || !versionPattern.MatchString(candidate.Version) {
			return nil, coordinator.fail(ctx, operation, "candidate", ErrIntegrity)
		}
		key := candidate.Root.String()
		if _, exists := seen[key]; exists { return nil, coordinator.fail(ctx, operation, "candidate", ErrAmbiguousDiscovery) }
		seen[key] = struct{}{}
	}
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, coordinator.now()
	if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return nil, err }
	return candidates, nil
}

func (coordinator LifecycleCoordinator) Adopt(ctx context.Context, request AdoptionRequest) (ApplicationInstallation, error) {
	if coordinator.Store == nil || coordinator.Catalog == nil || coordinator.Executor == nil { return ApplicationInstallation{}, ErrInvalid }
	if !request.Candidate.DatabaseReachable || !request.Candidate.OwnershipValid || !validDigest(request.Candidate.EvidenceDigest) { return ApplicationInstallation{}, ErrPolicyDenied }
	digest, err := requestDigest(request)
	if err != nil { return ApplicationInstallation{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "adopt", TenantID: request.TenantID, SiteID: request.SiteID, InstallationID: request.InstallationID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	operation, created, err := coordinator.Store.AdmitOperation(ctx, operation)
	if err != nil { return ApplicationInstallation{}, err }
	if !created {
		if operation.State == OperationCommitted { return coordinator.Store.LoadInstallation(ctx, request.InstallationID) }
		return ApplicationInstallation{}, ErrConflict
	}
	definition, err := coordinator.Catalog.Resolve(ctx, request.Recipe, request.CatalogTarget)
	if err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "catalog", err) }
	if definition.Kind != request.Candidate.Kind || !definition.Lifecycle.Adopt { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "catalog", ErrUnsupported) }
	scope := SiteExecutionScope{TenantID: request.TenantID, SiteID: request.SiteID, SiteUID: request.SiteUID, Root: request.Candidate.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	receipt, err := coordinator.Executor.Adopt(ctx, AdoptExecution{Scope: scope, Installation: request.InstallationID, Definition: definition, Candidate: request.Candidate, Database: request.Database})
	if err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "execute", err) }
	if err := receipt.Validate("adopt", scope, request.InstallationID); err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "receipt", err) }
	installation := ApplicationInstallation{ID: request.InstallationID, TenantID: request.TenantID, ProjectID: request.ProjectID, SiteID: request.SiteID, SiteUID: request.SiteUID, DefinitionID: definition.ID, Recipe: definition.Recipe, Kind: definition.Kind, Root: request.Candidate.Root, RuntimeID: request.RuntimeID, DatabaseBindingID: request.Database.ID, StorageMode: definition.StorageMode, State: InstallationActive, Health: HealthObservation{State: HealthUnknown}, Generation: 1, CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	if err := coordinator.Store.CreateInstallation(ctx, installation); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "persist", err) }
	inventory, health, inspectReceipt, err := coordinator.Executor.Inspect(ctx, InspectExecution{Scope: scope, Installation: installation.ID, Kind: installation.Kind, RecipeDigest: definition.Recipe.RecipeDigest, Deep: true})
	if err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "inspect", err) }
	if err := inspectReceipt.Validate("inspect", scope, installation.ID); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "inspect_receipt", err) }
	if err := coordinator.Store.SaveInventory(ctx, inventory); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "inventory", err) }
	previousGeneration := installation.Generation
	installation.Health, installation.Generation, installation.UpdatedAt = health, installation.Generation+1, coordinator.now()
	if health.State != HealthHealthy { installation.State = InstallationDegraded }
	if err := coordinator.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "health", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, coordinator.now()
	if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return ApplicationInstallation{}, err }
	return installation, nil
}

func (coordinator LifecycleCoordinator) Inspect(ctx context.Context, installationID InstallationID, siteGeneration uint64, isolationProfile string, deep bool) (ComponentInventory, HealthObservation, error) {
	installation, err := coordinator.Store.LoadInstallation(ctx, installationID)
	if err != nil { return ComponentInventory{}, HealthObservation{}, err }
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: isolationProfile, ResourceGeneration: siteGeneration}
	inventory, health, receipt, err := coordinator.Executor.Inspect(ctx, InspectExecution{Scope: scope, Installation: installation.ID, Kind: installation.Kind, RecipeDigest: installation.Recipe.RecipeDigest, Deep: deep})
	if err != nil { return ComponentInventory{}, HealthObservation{}, err }
	if err := receipt.Validate("inspect", scope, installation.ID); err != nil { return ComponentInventory{}, HealthObservation{}, err }
	if err := coordinator.Store.SaveInventory(ctx, inventory); err != nil { return ComponentInventory{}, HealthObservation{}, err }
	previousGeneration := installation.Generation
	installation.Health, installation.Generation, installation.UpdatedAt = health, installation.Generation+1, coordinator.now()
	if health.State == HealthHealthy && installation.State == InstallationDegraded { installation.State = InstallationActive }
	if health.State == HealthUnhealthy && installation.State == InstallationActive { installation.State = InstallationDegraded }
	if err := coordinator.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return ComponentInventory{}, HealthObservation{}, err }
	return inventory, health, nil
}

func (coordinator LifecycleCoordinator) Repair(ctx context.Context, request RepairRequest) (ApplicationInstallation, error) {
	installation, err := coordinator.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return ApplicationInstallation{}, err }
	if installation.Generation != request.ExpectedGeneration || len(request.Actions) == 0 || !validDigest(request.ExpectedInventoryDigest) { return ApplicationInstallation{}, ErrStaleGeneration }
	digest, err := requestDigest(request)
	if err != nil { return ApplicationInstallation{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "repair", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	operation, created, err := coordinator.Store.AdmitOperation(ctx, operation)
	if err != nil { return ApplicationInstallation{}, err }
	if !created { return ApplicationInstallation{}, ErrConflict }
	recoveryPoint, _, err := coordinator.Recovery.CreateRecoveryPoint(ctx, RecoveryRequest{TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, Purpose: "application_repair", Consistency: "application_consistent", Required: true})
	if err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "recovery_point", err) }
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	receipt, err := coordinator.Executor.Repair(ctx, RepairExecution{Scope: scope, Installation: installation.ID, DefinitionID: installation.DefinitionID, Kind: installation.Kind, Recipe: installation.Recipe, Actions: request.Actions, RecoveryPointID: recoveryPoint, ExpectedInventoryDigest: request.ExpectedInventoryDigest})
	if err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "execute", err) }
	if err := receipt.Validate("repair", scope, installation.ID); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "receipt", err) }
	inventory, health, inspectReceipt, err := coordinator.Executor.Inspect(ctx, InspectExecution{Scope: scope, Installation: installation.ID, Kind: installation.Kind, RecipeDigest: installation.Recipe.RecipeDigest, Deep: true})
	if err != nil || health.State != HealthHealthy { if err == nil { err = ErrIntegrity }; return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "verify", err) }
	if err := inspectReceipt.Validate("inspect", scope, installation.ID); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "verify_receipt", err) }
	if err := coordinator.Store.SaveInventory(ctx, inventory); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "inventory", err) }
	previousGeneration := installation.Generation
	installation.Health, installation.State, installation.Generation, installation.UpdatedAt = health, InstallationActive, installation.Generation+1, coordinator.now()
	if err := coordinator.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "persist", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, coordinator.now()
	if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return ApplicationInstallation{}, err }
	return installation, nil
}

func (coordinator LifecycleCoordinator) Remove(ctx context.Context, request RemovalRequest) (ApplicationInstallation, error) {
	installation, err := coordinator.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return ApplicationInstallation{}, err }
	if installation.Generation != request.ExpectedGeneration || request.Disposition != RemovalQuarantine && request.Disposition != RemovalPurge { return ApplicationInstallation{}, ErrStaleGeneration }
	digest, err := requestDigest(request)
	if err != nil { return ApplicationInstallation{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "remove", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	operation, created, err := coordinator.Store.AdmitOperation(ctx, operation)
	if err != nil { return ApplicationInstallation{}, err }
	if !created { return ApplicationInstallation{}, ErrConflict }
	recoveryPoint, _, err := coordinator.Recovery.CreateRecoveryPoint(ctx, RecoveryRequest{TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, Purpose: "application_removal", Consistency: "application_consistent", Required: true})
	if err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "recovery_point", err) }
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	execution := RemovalExecution{Scope: scope, Installation: installation.ID, DefinitionID: installation.DefinitionID, RecoveryPointID: recoveryPoint, Disposition: request.Disposition}
	previousGeneration := installation.Generation
	next := InstallationQuarantined
	if request.Disposition == RemovalPurge { next = InstallationRemoving }
	if err := installation.Transition(next, coordinator.now()); err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "transition", err) }
	if err := coordinator.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "transition", err) }
	var receipt ExecutionReceipt
	if request.Disposition == RemovalQuarantine { receipt, err = coordinator.Executor.Quarantine(ctx, execution) } else { receipt, err = coordinator.Executor.Remove(ctx, execution) }
	if err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "execute", err) }
	expectedOperation := "quarantine"
	if request.Disposition == RemovalPurge { expectedOperation = "remove" }
	if err := receipt.Validate(expectedOperation, scope, installation.ID); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "receipt", err) }
	if request.Disposition == RemovalPurge {
		previousGeneration = installation.Generation
		if err := installation.Transition(InstallationRemoved, coordinator.now()); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "removed", err) }
		if err := coordinator.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "removed", err) }
		if coordinator.Databases != nil && installation.DatabaseBindingID != "" { _ = coordinator.Databases.RevokeApplicationDatabase(ctx, installation.DatabaseBindingID) }
		if coordinator.Secrets != nil { for _, secret := range installation.SecretRefs { _ = coordinator.Secrets.RevokeApplicationSecret(ctx, secret) } }
	}
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, coordinator.now()
	if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return ApplicationInstallation{}, err }
	return installation, nil
}

func (coordinator LifecycleCoordinator) fail(ctx context.Context, operation Operation, stage string, cause error) error {
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, stage, cause.Error(), coordinator.now()
	_ = coordinator.Store.UpdateOperation(ctx, operation)
	return cause
}

func (coordinator LifecycleCoordinator) recovery(ctx context.Context, operation Operation, stage string, cause error) error {
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationRecoveryRequired, stage, cause.Error(), coordinator.now()
	_ = coordinator.Store.UpdateOperation(ctx, operation)
	return errors.Join(ErrRecoveryRequired, cause)
}

func requireLifecycleDependencies(store ApplicationStore, executor SiteApplicationExecutor) error {
	if store == nil || executor == nil { return fmt.Errorf("%w: lifecycle dependencies", ErrInvalid) }
	return nil
}
