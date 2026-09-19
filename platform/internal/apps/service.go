package apps

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type InstallRequest struct {
	CommandID       CommandID `json:"command_id"`
	TenantID        TenantID `json:"tenant_id"`
	ProjectID       ProjectID `json:"project_id,omitempty"`
	SiteID          SiteID `json:"site_id"`
	SiteUID         SiteUID `json:"site_uid"`
	SiteGeneration  uint64 `json:"site_generation"`
	IsolationProfile string `json:"isolation_profile"`
	InstallationID  InstallationID `json:"installation_id"`
	Recipe           RecipeReference `json:"recipe"`
	CatalogTarget    CatalogTarget `json:"catalog_target"`
	Root             RelativePath `json:"root"`
	RuntimeID        string `json:"runtime_id"`
	CanonicalURL     string `json:"canonical_url"`
	Administrator    AdministratorBootstrap `json:"administrator"`
	Title            string `json:"title"`
	Locale           string `json:"locale"`
	Timezone         string `json:"timezone"`
	ReleaseID        ReleaseID `json:"release_id"`
}

func (request InstallRequest) Validate(now time.Time) error {
	if err := requireID("command", string(request.CommandID)); err != nil { return err }
	if err := requireID("tenant", string(request.TenantID)); err != nil { return err }
	if request.ProjectID != "" { if err := requireID("project", string(request.ProjectID)); err != nil { return err } }
	if err := requireID("site", string(request.SiteID)); err != nil { return err }
	if err := requireID("installation", string(request.InstallationID)); err != nil { return err }
	if err := requireID("release", string(request.ReleaseID)); err != nil { return err }
	if request.SiteUID < 1000 || request.SiteGeneration == 0 || !validID(request.IsolationProfile) || request.RuntimeID == "" || request.CanonicalURL == "" || request.Locale == "" || request.Timezone == "" {
		return fmt.Errorf("%w: install request", ErrInvalid)
	}
	if err := request.Recipe.Validate(now); err != nil { return err }
	if err := request.CatalogTarget.Validate(); err != nil { return err }
	return request.Administrator.Validate()
}

type ApplicationService struct {
	Store       ApplicationStore
	Catalog     DefinitionCatalog
	Databases   DatabaseProvisioner
	Secrets     SecretIssuer
	Executor    SiteApplicationExecutor
	Snapshots   SnapshotProvider
	Recovery    RecoveryPointProvider
	Routes      ApplicationRouteController
	Now         func() time.Time
}

func (service ApplicationService) now() time.Time {
	if service.Now != nil { return service.Now().UTC() }
	return time.Now().UTC()
}

func (service ApplicationService) Install(ctx context.Context, request InstallRequest) (ApplicationInstallation, error) {
	now := service.now()
	if err := request.Validate(now); err != nil { return ApplicationInstallation{}, err }
	if service.Store == nil || service.Catalog == nil || service.Databases == nil || service.Secrets == nil || service.Executor == nil {
		return ApplicationInstallation{}, fmt.Errorf("%w: application service dependencies", ErrInvalid)
	}
	digest, err := requestDigest(request)
	if err != nil { return ApplicationInstallation{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "install", TenantID: request.TenantID, SiteID: request.SiteID, InstallationID: request.InstallationID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: now, UpdatedAt: now}
	operation, created, err := service.Store.AdmitOperation(ctx, operation)
	if err != nil { return ApplicationInstallation{}, err }
	if !created {
		if operation.State == OperationCommitted { return service.Store.LoadInstallation(ctx, request.InstallationID) }
		if operation.State == OperationRecoveryRequired { return ApplicationInstallation{}, ErrRecoveryRequired }
		return ApplicationInstallation{}, ErrConflict
	}
	definition, err := service.Catalog.Resolve(ctx, request.Recipe, request.CatalogTarget)
	if err != nil { return ApplicationInstallation{}, service.fail(ctx, operation, "catalog", err) }
	secretRefs := []SecretRef{request.Administrator.PasswordRef}
	installation := ApplicationInstallation{ID: request.InstallationID, TenantID: request.TenantID, ProjectID: request.ProjectID, SiteID: request.SiteID, SiteUID: request.SiteUID, DefinitionID: definition.ID, Recipe: definition.Recipe, Kind: definition.Kind, Root: request.Root, RuntimeID: request.RuntimeID, StorageMode: definition.StorageMode, State: InstallationPending, Health: HealthObservation{State: HealthUnknown}, SecretRefs:append([]SecretRef(nil),secretRefs...), Generation: 1, CreatedAt: now, UpdatedAt: now}
	if err := service.Store.CreateInstallation(ctx, installation); err != nil { return ApplicationInstallation{}, service.fail(ctx, operation, "persist_installation", err) }
	previousGeneration := installation.Generation
	if err := installation.Transition(InstallationInstalling, service.now()); err != nil { return ApplicationInstallation{}, service.fail(ctx, operation, "transition", err) }
	if err := service.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return ApplicationInstallation{}, service.fail(ctx, operation, "transition", err) }
	operation.State, operation.Stage, operation.UpdatedAt = OperationExecuting, "provision_database", service.now()
	if err := service.Store.UpdateOperation(ctx, operation); err != nil { return ApplicationInstallation{}, err }
	database, err := service.Databases.ProvisionApplicationDatabase(ctx, request.TenantID, request.SiteID, request.InstallationID, definition.Kind)
	if err != nil { return ApplicationInstallation{}, service.fail(ctx, operation, "provision_database", err) }
	installation.DatabaseBindingID = database.ID
	configurationSecret, err := service.Secrets.IssueApplicationSecret(ctx, request.TenantID, request.SiteID, request.InstallationID, "configuration")
	if err != nil {
		_ = service.Databases.RevokeApplicationDatabase(ctx, database.ID)
		return ApplicationInstallation{}, service.fail(ctx, operation, "issue_secret", err)
	}
	secretRefs = append(secretRefs, configurationSecret)
	installation.SecretRefs = secretRefs
	scope := SiteExecutionScope{TenantID: request.TenantID, SiteID: request.SiteID, SiteUID: request.SiteUID, Root: request.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	execution := InstallExecution{Scope: scope, Installation: request.InstallationID, Definition: definition, RuntimeID: request.RuntimeID, Database: database, Administrator: request.Administrator, CanonicalURL: request.CanonicalURL, Locale: request.Locale, Timezone: request.Timezone, Title: request.Title, ReleaseID: request.ReleaseID}
	if err := execution.Validate(service.now()); err != nil { return ApplicationInstallation{}, service.compensateInstall(ctx, operation, database.ID, secretRefs, err) }
	operation.Stage, operation.UpdatedAt = "execute_install", service.now()
	if err := service.Store.UpdateOperation(ctx, operation); err != nil { return ApplicationInstallation{}, err }
	receipt, err := service.Executor.Install(ctx, execution)
	if err != nil { return ApplicationInstallation{}, service.compensateInstall(ctx, operation, database.ID, secretRefs, err) }
	if err := receipt.Validate("install", scope, request.InstallationID); err != nil { return ApplicationInstallation{}, service.compensateInstall(ctx, operation, database.ID, secretRefs, err) }
	release := Release{ID: request.ReleaseID, InstallationID: request.InstallationID, ProductVersion: definition.Recipe.ProductVersion, ContentDigest: receipt.OutputDigest, RecipeDigest: definition.Recipe.RecipeDigest, CreatedAt: receipt.CompletedAt, PromotedAt: receipt.CompletedAt, RetainedUntil: receipt.CompletedAt.Add(30 * 24 * time.Hour)}
	if err := service.Store.SaveRelease(ctx, release); err != nil { return ApplicationInstallation{}, service.failRecovery(ctx, operation, "persist_release", err) }
	inventory, health, inspectReceipt, err := service.Executor.Inspect(ctx, InspectExecution{Scope: scope, Installation: request.InstallationID, Kind: definition.Kind, RecipeDigest: definition.Recipe.RecipeDigest, Deep: true})
	if err != nil { return ApplicationInstallation{}, service.failRecovery(ctx, operation, "inspect", err) }
	if err := inspectReceipt.Validate("inspect", scope, request.InstallationID); err != nil { return ApplicationInstallation{}, service.failRecovery(ctx, operation, "inspect", err) }
	if health.State != HealthHealthy { return ApplicationInstallation{}, service.failRecovery(ctx, operation, "health", ErrIntegrity) }
	if err := service.Store.SaveInventory(ctx, inventory); err != nil { return ApplicationInstallation{}, service.failRecovery(ctx, operation, "persist_inventory", err) }
	if err := service.Secrets.RevokeApplicationSecret(ctx, request.Administrator.PasswordRef); err != nil { return ApplicationInstallation{}, service.failRecovery(ctx, operation, "revoke_administrator_bootstrap", err) }
	installation.SecretRefs = []SecretRef{configurationSecret}
	previousGeneration = installation.Generation
	installation.ActiveReleaseID, installation.Health = release.ID, health
	if err := installation.Transition(InstallationActive, service.now()); err != nil { return ApplicationInstallation{}, service.failRecovery(ctx, operation, "activate", err) }
	if err := service.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return ApplicationInstallation{}, service.failRecovery(ctx, operation, "activate", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, service.now()
	if err := service.Store.UpdateOperation(ctx, operation); err != nil { return ApplicationInstallation{}, err }
	return installation, nil
}

func (service ApplicationService) compensateInstall(ctx context.Context, operation Operation, databaseID DatabaseBindingID, secrets []SecretRef, cause error) error {
	// A disconnected caller must not cancel cleanup of already-created resources.
	// Keep request values, but impose a separate finite recovery budget.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationCompensating, "compensating", cause.Error(), service.now()
	compensationErr := service.Store.UpdateOperation(ctx, operation)
	for _, secret := range secrets { compensationErr = errors.Join(compensationErr, service.Secrets.RevokeApplicationSecret(ctx, secret)) }
	compensationErr = errors.Join(compensationErr, service.Databases.RevokeApplicationDatabase(ctx, databaseID))
	if compensationErr != nil { return service.failRecovery(ctx, operation, "compensation", errors.Join(cause, compensationErr)) }
	operation.State, operation.Stage, operation.UpdatedAt = OperationCompensated, "compensated", service.now()
	if err := service.Store.UpdateOperation(ctx, operation); err != nil {
		return service.failRecovery(ctx, operation, "persist_compensation", errors.Join(cause, err))
	}
	return cause
}

func (service ApplicationService) fail(ctx context.Context, operation Operation, stage string, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, stage, cause.Error(), service.now()
	if err := service.Store.UpdateOperation(ctx, operation); err != nil {
		return errors.Join(ErrRecoveryRequired, cause, err)
	}
	return cause
}

func (service ApplicationService) failRecovery(ctx context.Context, operation Operation, stage string, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationRecoveryRequired, stage, cause.Error(), service.now()
	persistenceErr := service.Store.UpdateOperation(ctx, operation)
	return errors.Join(ErrRecoveryRequired, cause, persistenceErr)
}

type UpdateRequest struct {
	CommandID         CommandID `json:"command_id"`
	DeploymentID      DeploymentID `json:"deployment_id"`
	InstallationID    InstallationID `json:"installation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	TargetRecipe      RecipeReference `json:"target_recipe"`
	CatalogTarget     CatalogTarget `json:"catalog_target"`
	TargetReleaseID   ReleaseID `json:"target_release_id"`
	TargetContentDigest string `json:"target_content_digest"`
	Components        []ComponentRelease `json:"components,omitempty"`
	SiteGeneration    uint64 `json:"site_generation"`
	IsolationProfile  string `json:"isolation_profile"`
}

func (service ApplicationService) Update(ctx context.Context, request UpdateRequest) (Deployment, error) {
	installation, err := service.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return Deployment{}, err }
	if installation.State != InstallationActive && installation.State != InstallationDegraded { return Deployment{}, ErrConflict }
	if installation.Generation != request.ExpectedGeneration || !validDigest(request.TargetContentDigest) { return Deployment{}, ErrStaleGeneration }
	digest, err := requestDigest(request)
	if err != nil { return Deployment{}, err }
	now := service.now()
	operation := Operation{CommandID: request.CommandID, Kind: "update", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: now, UpdatedAt: now}
	operation, created, err := service.Store.AdmitOperation(ctx, operation)
	if err != nil { return Deployment{}, err }
	if !created {
		if operation.State == OperationCommitted { return service.Store.LoadDeployment(ctx, request.DeploymentID) }
		if operation.State == OperationRecoveryRequired { return Deployment{}, ErrRecoveryRequired }
		return Deployment{}, ErrConflict
	}
	definition, err := service.Catalog.Resolve(ctx, request.TargetRecipe, request.CatalogTarget)
	if err != nil { return Deployment{}, service.fail(ctx, operation, "catalog", err) }
	if definition.Kind != installation.Kind || definition.Artifact.Digest != request.TargetContentDigest { return Deployment{}, service.fail(ctx, operation, "catalog", ErrConflict) }
	recoveryPoint, frontier, err := service.Recovery.CreateRecoveryPoint(ctx, RecoveryRequest{TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, Purpose: "application_update", Consistency: "application_consistent", Required: true})
	if err != nil { return Deployment{}, service.fail(ctx, operation, "recovery_point", err) }
	if err := service.Recovery.VerifyRecoveryPoint(ctx, recoveryPoint); err != nil { return Deployment{}, service.fail(ctx, operation, "verify_recovery_point", err) }
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	snapshot, err := service.Snapshots.CreateApplicationSnapshot(ctx, SnapshotRequest{Scope: scope, Installation: installation.ID, Purpose: SnapshotApplicationUpdate, IncludeFiles: true, IncludeDatabase: true, IncludeUploads: true, StableRequired: true, MaximumBytes: 128 << 30})
	if err != nil { return Deployment{}, service.fail(ctx, operation, "snapshot", err) }
	if err := service.Snapshots.VerifyApplicationSnapshot(ctx, snapshot.ID); err != nil { return Deployment{}, service.fail(ctx, operation, "verify_snapshot", err) }
	shadow, err := service.Routes.CreateShadowRoute(ctx, installation.SiteID, installation.ID, request.TargetReleaseID)
	if err != nil { return Deployment{}, service.fail(ctx, operation, "shadow_route", err) }
	targetRelease := Release{ID: request.TargetReleaseID, InstallationID: installation.ID, ProductVersion: definition.Recipe.ProductVersion, ContentDigest: request.TargetContentDigest, RecipeDigest: definition.Recipe.RecipeDigest, SnapshotID: snapshot.ID, CreatedAt: service.now(), RetainedUntil: service.now().Add(30 * 24 * time.Hour)}
	deployment := Deployment{ID: request.DeploymentID, CommandID: request.CommandID, InstallationID: installation.ID, ExpectedGeneration: request.ExpectedGeneration, FromReleaseID: installation.ActiveReleaseID, TargetRelease: targetRelease, RecoveryPointID: recoveryPoint, SnapshotID: snapshot.ID, State: DeploymentPrepared, WriteFrontier: frontier, CreatedAt: service.now(), UpdatedAt: service.now()}
	if err := service.Store.CreateDeployment(ctx, deployment); err != nil { return Deployment{}, service.fail(ctx, operation, "persist_deployment", err) }
	previousGeneration := installation.Generation
	if err := installation.Transition(InstallationUpdating, service.now()); err != nil { return Deployment{}, service.fail(ctx, operation, "transition", err) }
	if err := service.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return Deployment{}, service.fail(ctx, operation, "transition", err) }
	execution := UpdateExecution{Scope: scope, Installation: installation.ID, Definition: definition, FromReleaseID: deployment.FromReleaseID, TargetRelease: targetRelease, SnapshotID: snapshot.ID, RecoveryPointID: recoveryPoint, Components: request.Components, ShadowBinding: shadow, WriteFence: true}
	if receipt, err := service.Executor.PrepareUpdate(ctx, execution); err != nil || receipt.Validate("prepare_update", scope, installation.ID) != nil {
		if err == nil { err = ErrIntegrity }
		return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err)
	}
	deployment.State, deployment.UpdatedAt = DeploymentUpdating, service.now()
	_ = service.Store.UpdateDeployment(ctx, deployment)
	applyReceipt, err := service.Executor.ApplyUpdate(ctx, execution)
	if err != nil { return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err) }
	if err := applyReceipt.Validate("apply_update", scope, installation.ID); err != nil { return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err) }
	deployment.WriteFrontier, deployment.Irreversible, deployment.State, deployment.UpdatedAt = applyReceipt.WriteFrontier, applyReceipt.Irreversible, DeploymentProbing, service.now()
	_ = service.Store.UpdateDeployment(ctx, deployment)
	health, probeReceipt, err := service.Executor.ProbeUpdate(ctx, execution)
	if err != nil || health.State != HealthHealthy {
		if err == nil { err = ErrIntegrity }
		return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err)
	}
	if err := probeReceipt.Validate("probe_update", scope, installation.ID); err != nil { return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err) }
	promotion := PromotionExecution{Scope: scope, Installation: installation.ID, FromReleaseID: deployment.FromReleaseID, ToReleaseID: targetRelease.ID, SnapshotID: snapshot.ID, ExpectedHealthDigest: probeReceipt.OutputDigest, WriteFrontier: deployment.WriteFrontier}
	deployment.State, deployment.UpdatedAt = DeploymentPromoting, service.now()
	_ = service.Store.UpdateDeployment(ctx, deployment)
	if err := service.Routes.ActivateReleaseRoute(ctx, installation.SiteID, installation.ID, targetRelease.ID, shadow); err != nil { return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err) }
	promoteReceipt, err := service.Executor.Promote(ctx, promotion)
	if err != nil || promoteReceipt.Validate("promote", scope, installation.ID) != nil {
		if err == nil { err = ErrIntegrity }
		return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err)
	}
	inventory, promotedHealth, inspectReceipt, err := service.Executor.Inspect(ctx, InspectExecution{Scope: scope, Installation: installation.ID, Kind: definition.Kind, RecipeDigest: definition.Recipe.RecipeDigest, Deep: true})
	if err != nil || promotedHealth.State != HealthHealthy {
		if err == nil { err = ErrIntegrity }
		return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err)
	}
	if err := inspectReceipt.Validate("inspect", scope, installation.ID); err != nil { return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err) }
	if err := service.Store.SaveInventory(ctx, inventory); err != nil { return Deployment{}, service.rollbackUpdate(ctx, operation, installation, deployment, execution, shadow, err) }
	health = promotedHealth
	targetRelease.PromotedAt = service.now()
	if err := service.Store.SaveRelease(ctx, targetRelease); err != nil { return Deployment{}, service.failRecovery(ctx, operation, "persist_release", err) }
	previousGeneration = installation.Generation
	installation.PreviousReleaseID, installation.ActiveReleaseID, installation.Health = deployment.FromReleaseID, targetRelease.ID, health
	installation.DefinitionID, installation.Recipe, installation.StorageMode = definition.ID, definition.Recipe, definition.StorageMode
	if err := installation.Transition(InstallationActive, service.now()); err != nil { return Deployment{}, service.failRecovery(ctx, operation, "activate", err) }
	if err := service.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return Deployment{}, service.failRecovery(ctx, operation, "activate", err) }
	deployment.State, deployment.UpdatedAt = DeploymentCommitted, service.now()
	if err := service.Store.UpdateDeployment(ctx, deployment); err != nil { return Deployment{}, service.failRecovery(ctx, operation, "persist_commit", err) }
	_ = service.Routes.RemoveShadowRoute(ctx, installation.SiteID, installation.ID, targetRelease.ID)
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", promoteReceipt.OutputDigest, service.now()
	if err := service.Store.UpdateOperation(ctx, operation); err != nil { return Deployment{}, err }
	return deployment, nil
}

func (service ApplicationService) rollbackUpdate(ctx context.Context, operation Operation, installation ApplicationInstallation, deployment Deployment, execution UpdateExecution, shadow string, cause error) error {
	if deployment.Irreversible {
		deployment.State, deployment.Failure, deployment.UpdatedAt = DeploymentRecoveryNeeded, cause.Error(), service.now()
		_ = service.Store.UpdateDeployment(ctx, deployment)
		return service.failRecovery(ctx, operation, "update_frontier", errors.Join(ErrIrreversibleFrontier, cause))
	}
	deployment.State, deployment.Failure, deployment.UpdatedAt = DeploymentRollingBack, cause.Error(), service.now()
	_ = service.Store.UpdateDeployment(ctx, deployment)
	promotion := PromotionExecution{Scope: execution.Scope, Installation: installation.ID, FromReleaseID: execution.TargetRelease.ID, ToReleaseID: deployment.FromReleaseID, SnapshotID: deployment.SnapshotID, WriteFrontier: deployment.WriteFrontier}
	err := service.Routes.RestoreReleaseRoute(ctx, installation.SiteID, installation.ID, deployment.FromReleaseID)
	if _, rollbackErr := service.Executor.Rollback(ctx, promotion); rollbackErr != nil { err = errors.Join(err, rollbackErr) }
	_ = service.Routes.RemoveShadowRoute(ctx, installation.SiteID, installation.ID, execution.TargetRelease.ID)
	if err != nil { return service.failRecovery(ctx, operation, "rollback", errors.Join(cause, err)) }
	deployment.State, deployment.UpdatedAt = DeploymentRolledBack, service.now()
	_ = service.Store.UpdateDeployment(ctx, deployment)
	previousGeneration := installation.Generation
	installation.State, installation.Health.State, installation.Generation, installation.UpdatedAt = InstallationDegraded, HealthDegraded, installation.Generation+1, service.now()
	_ = service.Store.UpdateInstallation(ctx, installation, previousGeneration)
	return service.fail(ctx, operation, "rolled_back", cause)
}
