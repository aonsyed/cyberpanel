package apps

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type StagingCoordinator struct {
	Store     interface { ApplicationStore; StagingStore }
	Snapshots SnapshotProvider
	Recovery  RecoveryPointProvider
	Databases DatabaseProvisioner
	Executor  StagingExecutor
	Now       func() time.Time
}

func (coordinator StagingCoordinator) CreateClone(ctx context.Context, request CloneRequest, sourceScope, targetScope SiteExecutionScope) (ApplicationInstallation, StagingRelation, error) {
	if err := request.Validate(coordinator.now()); err != nil { return ApplicationInstallation{}, StagingRelation{}, err }
	if coordinator.Store == nil || coordinator.Snapshots == nil || coordinator.Databases == nil || coordinator.Executor == nil { return ApplicationInstallation{}, StagingRelation{}, ErrInvalid }
	source, err := coordinator.Store.LoadInstallation(ctx, request.Source.ID)
	if err != nil { return ApplicationInstallation{}, StagingRelation{}, err }
	if source.Generation != request.Source.Generation || source.TenantID != request.TenantID || source.SiteID != sourceScope.SiteID || sourceScope.Root.String() != source.Root.String() || targetScope.SiteID != request.TargetSiteID || targetScope.SiteUID != request.TargetSiteUID || targetScope.Root.String() != request.TargetRoot.String() { return ApplicationInstallation{}, StagingRelation{}, ErrConflict }
	digest, err := requestDigest(request)
	if err != nil { return ApplicationInstallation{}, StagingRelation{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "clone", TenantID: source.TenantID, SiteID: request.TargetSiteID, InstallationID: request.TargetInstallationID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	operation, created, err := coordinator.Store.AdmitOperation(ctx, operation)
	if err != nil { return ApplicationInstallation{}, StagingRelation{}, err }
	if !created {
		if operation.State == OperationCommitted {
			installation, installationErr := coordinator.Store.LoadInstallation(ctx, request.TargetInstallationID)
			relation, relationErr := coordinator.Store.LoadStagingRelation(ctx, request.RelationID)
			if installationErr == nil && relationErr == nil { return installation, relation, nil }
			return ApplicationInstallation{}, StagingRelation{}, errors.Join(ErrRecoveryRequired, installationErr, relationErr)
		}
		if operation.State == OperationRecoveryRequired { return ApplicationInstallation{}, StagingRelation{}, ErrRecoveryRequired }
		return ApplicationInstallation{}, StagingRelation{}, ErrConflict
	}
	snapshot, err := coordinator.Snapshots.CreateApplicationSnapshot(ctx, SnapshotRequest{Scope: sourceScope, Installation: source.ID, Purpose: SnapshotStagingSource, IncludeFiles: true, IncludeDatabase: true, IncludeUploads: true, StableRequired: true, MaximumBytes: 256 << 30})
	if err != nil { return ApplicationInstallation{}, StagingRelation{}, coordinator.fail(ctx, operation, StagingSync{}, "source_snapshot", err) }
	defer func() { _ = coordinator.Snapshots.ReleaseApplicationSnapshot(context.WithoutCancel(ctx), snapshot.ID) }()
	if err := coordinator.Snapshots.VerifyApplicationSnapshot(ctx, snapshot.ID); err != nil { return ApplicationInstallation{}, StagingRelation{}, coordinator.fail(ctx, operation, StagingSync{}, "verify_source_snapshot", err) }
	database, err := coordinator.Databases.ProvisionApplicationDatabase(ctx, request.TenantID, request.TargetSiteID, request.TargetInstallationID, source.Kind)
	if err != nil { return ApplicationInstallation{}, StagingRelation{}, coordinator.fail(ctx, operation, StagingSync{}, "database", err) }
	rewrite := IdentityRewrite{SourceURL: request.SourceURL, TargetURL: request.TargetURL, Application: source.Kind, SerializedDataAware: source.Kind == ApplicationWordPress, RewriteFiles: true, RewriteDatabase: true, PreserveGUIDs: source.Kind == ApplicationWordPress}
	cloneExecution := CloneExecution{SourceScope: sourceScope, TargetScope: targetScope, SourceInstallationID: source.ID, TargetInstallationID: request.TargetInstallationID, SourceSnapshot: snapshot, TargetDatabase: database, Selection: request.Selection, Rewrite: rewrite, SuppressMail: true, DenyExternalActions: true}
	receipt, err := coordinator.Executor.CreateClone(ctx, cloneExecution)
	if err != nil { _ = coordinator.Databases.RevokeApplicationDatabase(ctx, database.ID); return ApplicationInstallation{}, StagingRelation{}, coordinator.fail(ctx, operation, StagingSync{}, "clone", err) }
	if err := receipt.Validate("create_clone", targetScope, request.TargetInstallationID); err != nil { _ = coordinator.Databases.RevokeApplicationDatabase(ctx, database.ID); return ApplicationInstallation{}, StagingRelation{}, coordinator.fail(ctx, operation, StagingSync{}, "clone_receipt", err) }
	health, probeReceipt, err := coordinator.Executor.ProbeClone(ctx, cloneExecution)
	if err != nil || health.State != HealthHealthy {
		if err == nil { err = ErrIntegrity }
		_ = coordinator.Databases.RevokeApplicationDatabase(ctx, database.ID)
		return ApplicationInstallation{}, StagingRelation{}, coordinator.fail(ctx, operation, StagingSync{}, "probe", err)
	}
	if err := probeReceipt.Validate("probe_clone", targetScope, request.TargetInstallationID); err != nil { return ApplicationInstallation{}, StagingRelation{}, coordinator.fail(ctx, operation, StagingSync{}, "probe_receipt", err) }
	now := coordinator.now()
	installation := ApplicationInstallation{ID: request.TargetInstallationID, TenantID: source.TenantID, ProjectID: request.TargetProjectID, SiteID: request.TargetSiteID, SiteUID: request.TargetSiteUID, DefinitionID: source.DefinitionID, Recipe: source.Recipe, Kind: source.Kind, Root: request.TargetRoot, RuntimeID: request.TargetRuntimeID, DatabaseBindingID: database.ID, SecretRefs: []SecretRef{database.PasswordRef}, StorageMode: source.StorageMode, State: InstallationActive, ActiveReleaseID: source.ActiveReleaseID, Health: health, Generation: 1, CreatedAt: now, UpdatedAt: now}
	if err := coordinator.Store.CreateInstallation(ctx, installation); err != nil { return ApplicationInstallation{}, StagingRelation{}, coordinator.recovery(ctx, operation, StagingSync{}, "persist_installation", err) }
	relation := StagingRelation{ID: request.RelationID, SourceInstallationID: source.ID, TargetInstallationID: installation.ID, SourceSiteID: source.SiteID, TargetSiteID: installation.SiteID, MailSuppressed: true, ExternalActionsDenied: true, AccessPolicyID: request.AccessPolicyID, Generation: 1, CreatedAt: now}
	if err := coordinator.Store.CreateStagingRelation(ctx, relation); err != nil { return ApplicationInstallation{}, StagingRelation{}, coordinator.recovery(ctx, operation, StagingSync{}, "persist_relation", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, now
	if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return ApplicationInstallation{}, StagingRelation{}, err }
	return installation, relation, nil
}

func (coordinator StagingCoordinator) now() time.Time {
	if coordinator.Now != nil { return coordinator.Now().UTC() }
	return time.Now().UTC()
}

func (coordinator StagingCoordinator) Synchronize(ctx context.Context, request StagingRequest, sourceScope, targetScope SiteExecutionScope) (StagingSync, error) {
	if err := request.Validate(); err != nil { return StagingSync{}, err }
	if coordinator.Store == nil || coordinator.Snapshots == nil || coordinator.Recovery == nil || coordinator.Executor == nil { return StagingSync{}, ErrInvalid }
	relation, err := coordinator.Store.LoadStagingRelation(ctx, request.RelationID)
	if err != nil { return StagingSync{}, err }
	sourceID, targetID := relation.SourceInstallationID, relation.TargetInstallationID
	if request.Direction == SyncPullToSource { sourceID, targetID = targetID, sourceID }
	source, err := coordinator.Store.LoadInstallation(ctx, sourceID)
	if err != nil { return StagingSync{}, err }
	target, err := coordinator.Store.LoadInstallation(ctx, targetID)
	if err != nil { return StagingSync{}, err }
	if source.Generation != request.ExpectedSourceGeneration || target.Generation != request.ExpectedTargetGeneration { return StagingSync{}, ErrStaleGeneration }
	if source.Kind != request.Application || target.Kind != request.Application || sourceScope.SiteID != source.SiteID || targetScope.SiteID != target.SiteID { return StagingSync{}, ErrConflict }
	digest, err := requestDigest(request)
	if err != nil { return StagingSync{}, err }
	now := coordinator.now()
	operation := Operation{CommandID: request.CommandID, Kind: "staging_sync", TenantID: source.TenantID, SiteID: target.SiteID, InstallationID: target.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: now, UpdatedAt: now}
	operation, created, err := coordinator.Store.AdmitOperation(ctx, operation)
	if err != nil { return StagingSync{}, err }
	if !created {
		if operation.State == OperationCommitted { return coordinator.Store.LoadStagingSync(ctx, request.ID) }
		if operation.State == OperationRecoveryRequired { return StagingSync{}, ErrRecoveryRequired }
		return StagingSync{}, ErrConflict
	}
	sync := StagingSync{ID: request.ID, CommandID: request.CommandID, RelationID: relation.ID, Direction: request.Direction, Scope: request.Scope, Selection: request.Selection, ExpectedSourceGeneration: source.Generation, ExpectedTargetGeneration: target.Generation, State: SyncSnapshotting, CreatedAt: now, UpdatedAt: now}
	if err := coordinator.Store.CreateStagingSync(ctx, sync); err != nil { return StagingSync{}, coordinator.fail(ctx, operation, sync, "persist", err) }
	sourceSnapshot, err := coordinator.Snapshots.CreateApplicationSnapshot(ctx, SnapshotRequest{Scope: sourceScope, Installation: source.ID, Purpose: SnapshotStagingSource, IncludeFiles: request.Scope != SyncDatabase, IncludeDatabase: request.Scope != SyncFiles && request.Scope != SyncUploads, IncludeUploads: request.Scope == SyncEverything || request.Scope == SyncUploads || request.Selection.IncludeUploads, StableRequired: true, MaximumBytes: 256 << 30})
	if err != nil { return StagingSync{}, coordinator.fail(ctx, operation, sync, "source_snapshot", err) }
	targetSnapshot, err := coordinator.Snapshots.CreateApplicationSnapshot(ctx, SnapshotRequest{Scope: targetScope, Installation: target.ID, Purpose: SnapshotStagingTarget, IncludeFiles: request.Scope != SyncDatabase, IncludeDatabase: request.Scope != SyncFiles && request.Scope != SyncUploads, IncludeUploads: request.Scope == SyncEverything || request.Scope == SyncUploads || request.Selection.IncludeUploads, StableRequired: true, MaximumBytes: 256 << 30})
	if err != nil { return StagingSync{}, coordinator.fail(ctx, operation, sync, "target_snapshot", err) }
	if err := coordinator.Snapshots.VerifyApplicationSnapshot(ctx, sourceSnapshot.ID); err != nil { return StagingSync{}, coordinator.fail(ctx, operation, sync, "verify_source_snapshot", err) }
	if err := coordinator.Snapshots.VerifyApplicationSnapshot(ctx, targetSnapshot.ID); err != nil { return StagingSync{}, coordinator.fail(ctx, operation, sync, "verify_target_snapshot", err) }
	recoveryPoint, frontier, err := coordinator.Recovery.CreateRecoveryPoint(ctx, RecoveryRequest{TenantID: target.TenantID, SiteID: target.SiteID, InstallationID: target.ID, Purpose: "staging_sync", Consistency: "application_consistent", Required: true})
	if err != nil { return StagingSync{}, coordinator.fail(ctx, operation, sync, "recovery_point", err) }
	if err := coordinator.Recovery.VerifyRecoveryPoint(ctx, recoveryPoint); err != nil { return StagingSync{}, coordinator.fail(ctx, operation, sync, "verify_recovery_point", err) }
	sync.SourceSnapshotID, sync.TargetRecoveryPointID, sync.WriteFrontier, sync.State, sync.UpdatedAt = sourceSnapshot.ID, recoveryPoint, frontier, SyncTransforming, coordinator.now()
	if err := coordinator.Store.UpdateStagingSync(ctx, sync); err != nil { return StagingSync{}, coordinator.fail(ctx, operation, sync, "persist_snapshot", err) }
	rewrite := IdentityRewrite{SourceURL: request.SourceURL, TargetURL: request.TargetURL, Application: request.Application, SerializedDataAware: request.Application == ApplicationWordPress, RewriteFiles: request.Scope != SyncDatabase, RewriteDatabase: request.Scope != SyncFiles && request.Scope != SyncUploads, PreserveGUIDs: request.Application == ApplicationWordPress}
	execution := SyncExecution{SourceScope: sourceScope, TargetScope: targetScope, Sync: sync, SourceSnapshot: sourceSnapshot, TargetSnapshot: targetSnapshot, Rewrite: rewrite, WriteFence: true}
	applyReceipt, err := coordinator.Executor.ApplySync(ctx, execution)
	if err != nil { return StagingSync{}, coordinator.rollback(ctx, operation, sync, execution, err) }
	if err := applyReceipt.Validate("staging_sync", targetScope, target.ID); err != nil { return StagingSync{}, coordinator.rollback(ctx, operation, sync, execution, err) }
	sync.WriteFrontier, sync.State, sync.UpdatedAt = applyReceipt.WriteFrontier, SyncTransforming, coordinator.now()
	if _, err := coordinator.Executor.RewriteApplicationIdentity(ctx, execution); err != nil { return StagingSync{}, coordinator.rollback(ctx, operation, sync, execution, err) }
	sync.State, sync.UpdatedAt = SyncProbing, coordinator.now()
	_ = coordinator.Store.UpdateStagingSync(ctx, sync)
	health, probeReceipt, err := coordinator.Executor.ProbeSynchronizedApplication(ctx, execution)
	if err != nil || health.State != HealthHealthy {
		if err == nil { err = ErrIntegrity }
		return StagingSync{}, coordinator.rollback(ctx, operation, sync, execution, err)
	}
	if err := probeReceipt.Validate("probe_staging_sync", targetScope, target.ID); err != nil { return StagingSync{}, coordinator.rollback(ctx, operation, sync, execution, err) }
	previousGeneration := target.Generation
	target.Health, target.Generation, target.UpdatedAt = health, target.Generation+1, coordinator.now()
	if err := coordinator.Store.UpdateInstallation(ctx, target, previousGeneration); err != nil { return StagingSync{}, coordinator.recovery(ctx, operation, sync, "target_generation", err) }
	sync.State, sync.UpdatedAt = SyncCommitted, coordinator.now()
	if err := coordinator.Store.UpdateStagingSync(ctx, sync); err != nil { return StagingSync{}, coordinator.recovery(ctx, operation, sync, "commit", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", probeReceipt.OutputDigest, coordinator.now()
	if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return StagingSync{}, err }
	return sync, nil
}

func (coordinator StagingCoordinator) rollback(ctx context.Context, operation Operation, sync StagingSync, execution SyncExecution, cause error) error {
	sync.State, sync.Failure, sync.UpdatedAt = SyncRollingBack, cause.Error(), coordinator.now()
	_ = coordinator.Store.UpdateStagingSync(ctx, sync)
	_, err := coordinator.Executor.RollbackSync(ctx, execution)
	if err != nil { return coordinator.recovery(ctx, operation, sync, "rollback", errors.Join(cause, err)) }
	sync.State, sync.UpdatedAt = SyncRolledBack, coordinator.now()
	_ = coordinator.Store.UpdateStagingSync(ctx, sync)
	return coordinator.fail(ctx, operation, sync, "rolled_back", cause)
}

func (coordinator StagingCoordinator) fail(ctx context.Context, operation Operation, sync StagingSync, stage string, cause error) error {
	sync.State, sync.Failure, sync.UpdatedAt = SyncFailed, cause.Error(), coordinator.now()
	if sync.ID != "" { _ = coordinator.Store.UpdateStagingSync(ctx, sync) }
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, stage, cause.Error(), coordinator.now()
	_ = coordinator.Store.UpdateOperation(ctx, operation)
	return cause
}

func (coordinator StagingCoordinator) recovery(ctx context.Context, operation Operation, sync StagingSync, stage string, cause error) error {
	sync.State, sync.Failure, sync.UpdatedAt = SyncRecoveryNeeded, cause.Error(), coordinator.now()
	if sync.ID != "" { _ = coordinator.Store.UpdateStagingSync(ctx, sync) }
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationRecoveryRequired, stage, cause.Error(), coordinator.now()
	_ = coordinator.Store.UpdateOperation(ctx, operation)
	return errors.Join(ErrRecoveryRequired, cause)
}

type ScanCoordinator struct {
	Store     interface { ApplicationStore; ScanStore }
	Snapshots SnapshotProvider
	Providers map[string]ScannerProvider
	Now       func() time.Time
}

func (coordinator ScanCoordinator) now() time.Time {
	if coordinator.Now != nil { return coordinator.Now().UTC() }
	return time.Now().UTC()
}

func (coordinator ScanCoordinator) Run(ctx context.Context, run ScanRun, scope SiteExecutionScope, consent *DataEgressConsent) (ScanResult, error) {
	return coordinator.run(ctx,run,scope,consent,true)
}

func (coordinator ScanCoordinator) RunVerification(ctx context.Context, run ScanRun, scope SiteExecutionScope, consent *DataEgressConsent) (ScanResult, error) {
	return coordinator.run(ctx,run,scope,consent,false)
}

func (coordinator ScanCoordinator) run(ctx context.Context, run ScanRun, scope SiteExecutionScope, consent *DataEgressConsent, admitOperation bool) (ScanResult, error) {
	provider, exists := coordinator.Providers[run.ProviderID]
	if !exists || provider == nil || coordinator.Store == nil || coordinator.Snapshots == nil { return ScanResult{}, ErrUnsupported }
	if provider.Kind() != ScannerLocal {
		if consent == nil { return ScanResult{}, ErrPolicyDenied }
		if err := consent.Validate(coordinator.now()); err != nil { return ScanResult{}, err }
		if provider.Kind() == ScannerExternalAI && consent.Purpose != "application_security_scan" { return ScanResult{}, ErrPolicyDenied }
	}
	if run.ProviderKind != provider.Kind() || provider.ID() != run.ProviderID { return ScanResult{}, ErrConflict }
	digest, err := requestDigest(run)
	if err != nil { return ScanResult{}, err }
	operation := Operation{CommandID: run.CommandID, Kind: "security_scan", TenantID: run.TenantID, SiteID: run.SiteID, InstallationID: run.InstallationID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	if admitOperation {
		var created bool
		operation, created, err = coordinator.Store.AdmitOperation(ctx, operation)
		if err != nil { return ScanResult{}, err }
		if !created {
			if operation.State == OperationCommitted { persisted, err := coordinator.Store.LoadScan(ctx, run.ID); return ScanResult{RunID: persisted.ID, FilesScanned: persisted.FilesScanned, BytesScanned: persisted.BytesScanned, CompletedAt: persisted.CompletedAt}, err }
			return ScanResult{}, ErrConflict
		}
	}
	run.State, run.CreatedAt, run.UpdatedAt = ScanSnapshotting, coordinator.now(), coordinator.now()
	if err := coordinator.Store.CreateScan(ctx, run); err != nil { return ScanResult{}, err }
	snapshot, err := coordinator.Snapshots.CreateApplicationSnapshot(ctx, SnapshotRequest{Scope: scope, Installation: run.InstallationID, Purpose: SnapshotScan, IncludeFiles: true, IncludeDatabase: run.Mode == ScanFull || run.Mode == ScanCustom || run.Mode == ScanPostRestore, IncludeUploads: true, StableRequired: true, MaximumBytes: run.Budget.MaximumBytes})
	if err != nil { return ScanResult{}, coordinator.failScan(ctx, operation, run, "snapshot", err) }
	if err := coordinator.Snapshots.VerifyApplicationSnapshot(ctx, snapshot.ID); err != nil { return ScanResult{}, coordinator.failScan(ctx, operation, run, "verify_snapshot", err) }
	run.SnapshotID, run.SnapshotDigest, run.State, run.StartedAt, run.UpdatedAt = snapshot.ID, snapshot.ManifestDigest, ScanRunning, coordinator.now(), coordinator.now()
	if err := run.Validate(); err != nil { return ScanResult{}, coordinator.failScan(ctx, operation, run, "validate", err) }
	if err := coordinator.Store.UpdateScan(ctx, run); err != nil { return ScanResult{}, err }
	result, err := provider.Scan(ctx, ScanRequest{Scope: scope, InstallationID: run.InstallationID, RunID: run.ID, Snapshot: snapshot, Mode: run.Mode, CustomPaths: run.CustomPaths, Budget: run.Budget, RulesVersion: run.RulesVersion}, consent)
	if err != nil { return ScanResult{}, coordinator.failScan(ctx, operation, run, "scan", err) }
	if result.RunID != run.ID || !validDigest(result.ResultDigest) || result.CompletedAt.IsZero() || result.FilesScanned > run.Budget.MaximumFiles || result.BytesScanned > run.Budget.MaximumBytes { return ScanResult{}, coordinator.failScan(ctx, operation, run, "provider_receipt", ErrIntegrity) }
	for _, finding := range result.Findings {
		if finding.ScanRunID != run.ID || finding.TenantID != run.TenantID || finding.SiteID != run.SiteID || finding.InstallationID != run.InstallationID { return ScanResult{}, coordinator.failScan(ctx, operation, run, "finding_scope", ErrIntegrity) }
	}
	if err := coordinator.Store.SaveFindings(ctx, run.ID, result.Findings); err != nil { return ScanResult{}, coordinator.failScan(ctx, operation, run, "persist_findings", err) }
	run.State, run.Progress, run.FilesScanned, run.BytesScanned, run.Findings, run.CompletedAt, run.UpdatedAt = ScanCompleted, 100, result.FilesScanned, result.BytesScanned, uint64(len(result.Findings)), result.CompletedAt, coordinator.now()
	if err := coordinator.Store.UpdateScan(ctx, run); err != nil { return ScanResult{}, err }
	if admitOperation { operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", result.ResultDigest, coordinator.now();if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return ScanResult{}, err } }
	return result, nil
}

func (coordinator ScanCoordinator) failScan(ctx context.Context, operation Operation, run ScanRun, stage string, cause error) error {
	run.State, run.Failure, run.UpdatedAt = ScanFailed, cause.Error(), coordinator.now()
	_ = coordinator.Store.UpdateScan(ctx, run)
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, stage, cause.Error(), coordinator.now()
	if operation.CommandID!=""{_ = coordinator.Store.UpdateOperation(ctx, operation)}
	return cause
}

type RemediationCoordinator struct {
	Store     interface { ApplicationStore; ScanStore }
	Snapshots SnapshotProvider
	Recovery  RecoveryPointProvider
	Executor  RemediationExecutor
	Scanner   ScanCoordinator
	Now       func() time.Time
}

func (coordinator RemediationCoordinator) now() time.Time {
	if coordinator.Now != nil { return coordinator.Now().UTC() }
	return time.Now().UTC()
}

func (coordinator RemediationCoordinator) Apply(ctx context.Context, plan RemediationPlan, scope SiteExecutionScope, verificationRun ScanRun, consent *DataEgressConsent) (RemediationPlan, error) {
	if err := plan.Validate(); err != nil { return RemediationPlan{}, err }
	if plan.State != RemediationApproved || coordinator.Store == nil || coordinator.Snapshots == nil || coordinator.Recovery == nil || coordinator.Executor == nil { return RemediationPlan{}, ErrPolicyDenied }
	digest, err := requestDigest(plan)
	if err != nil { return RemediationPlan{}, err }
	operation := Operation{CommandID: plan.CommandID, Kind: "security_remediation", TenantID: plan.TenantID, SiteID: plan.SiteID, InstallationID: plan.InstallationID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	operation, created, err := coordinator.Store.AdmitOperation(ctx, operation)
	if err != nil { return RemediationPlan{}, err }
	if !created {
		if operation.State == OperationCommitted { return coordinator.Store.LoadRemediation(ctx, plan.ID) }
		return RemediationPlan{}, ErrConflict
	}
	recoveryPoint, _, err := coordinator.Recovery.CreateRecoveryPoint(ctx, RecoveryRequest{TenantID: plan.TenantID, SiteID: plan.SiteID, InstallationID: plan.InstallationID, Purpose: "security_remediation", Consistency: "application_consistent", Required: true})
	if err != nil { return RemediationPlan{}, err }
	if recoveryPoint != plan.RecoveryPointID { return RemediationPlan{}, ErrConflict }
	if err := coordinator.Recovery.VerifyRecoveryPoint(ctx, recoveryPoint); err != nil { return RemediationPlan{}, err }
	snapshot, err := coordinator.Snapshots.CreateApplicationSnapshot(ctx, SnapshotRequest{Scope: scope, Installation: plan.InstallationID, Purpose: SnapshotRemediation, IncludeFiles: true, IncludeDatabase: true, IncludeUploads: true, StableRequired: true, MaximumBytes: 256 << 30})
	if err != nil { return RemediationPlan{}, err }
	plan.State, plan.Generation, plan.UpdatedAt = RemediationExecuting, plan.Generation+1, coordinator.now()
	if err := coordinator.Store.UpdateRemediation(ctx, plan); err != nil { return RemediationPlan{}, err }
	execution := RemediationExecution{Scope: scope, InstallationID: plan.InstallationID, Plan: plan, SnapshotID: snapshot.ID}
	if _, err := coordinator.Executor.ApplyRemediation(ctx, execution); err != nil { return RemediationPlan{}, coordinator.rollbackRemediation(ctx, operation, plan, execution, err) }
	plan.State, plan.Generation, plan.UpdatedAt = RemediationVerifying, plan.Generation+1, coordinator.now()
	if err := coordinator.Store.UpdateRemediation(ctx, plan); err != nil { return RemediationPlan{}, err }
	result, err := coordinator.Scanner.RunVerification(ctx, verificationRun, scope, consent)
	if err != nil || len(result.Findings) != 0 {
		if err == nil { err = fmt.Errorf("%w: post-remediation findings remain", ErrIntegrity) }
		return RemediationPlan{}, coordinator.rollbackRemediation(ctx, operation, plan, execution, err)
	}
	plan.State, plan.PostScanRunID, plan.Generation, plan.UpdatedAt = RemediationCommitted, verificationRun.ID, plan.Generation+1, coordinator.now()
	if err := coordinator.Store.UpdateRemediation(ctx, plan); err != nil { return RemediationPlan{}, err }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", result.ResultDigest, coordinator.now()
	if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return RemediationPlan{}, err }
	return plan, nil
}

func (coordinator RemediationCoordinator) rollbackRemediation(ctx context.Context, operation Operation, plan RemediationPlan, execution RemediationExecution, cause error) error {
	_, rollbackErr := coordinator.Executor.RollbackRemediation(ctx, execution)
	if rollbackErr != nil {
		operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationRecoveryRequired, "rollback", errors.Join(cause, rollbackErr).Error(), coordinator.now()
		_ = coordinator.Store.UpdateOperation(ctx, operation)
		return errors.Join(ErrRecoveryRequired, cause, rollbackErr)
	}
	plan.State, plan.Failure, plan.Generation, plan.UpdatedAt = RemediationRolledBack, cause.Error(), plan.Generation+1, coordinator.now()
	_ = coordinator.Store.UpdateRemediation(ctx, plan)
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, "rolled_back", cause.Error(), coordinator.now()
	_ = coordinator.Store.UpdateOperation(ctx, operation)
	return cause
}
