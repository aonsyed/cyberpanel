package apps

import (
	"context"
	"fmt"
	"time"
)

type PolicyService struct {
	Applications ApplicationStore
	Scans interface {
		SaveScanPolicy(context.Context, ScanPolicy, uint64) error
		LoadScanPolicy(context.Context, InstallationID) (ScanPolicy, error)
	}
	Now func() time.Time
}

func (service PolicyService) now() time.Time {
	if service.Now != nil { return service.Now().UTC() }
	return time.Now().UTC()
}

func (service PolicyService) ConfigureUpdates(ctx context.Context, commandID CommandID, policy UpdatePolicy, expectedPolicyGeneration, expectedInstallationGeneration uint64) (UpdatePolicy, error) {
	if service.Applications == nil { return UpdatePolicy{}, ErrInvalid }
	if err := policy.Validate(); err != nil { return UpdatePolicy{}, err }
	installation, err := service.Applications.LoadInstallation(ctx, policy.InstallationID)
	if err != nil { return UpdatePolicy{}, err }
	if installation.Generation != expectedInstallationGeneration || policy.Generation != expectedPolicyGeneration+1 { return UpdatePolicy{}, ErrStaleGeneration }
	digest, err := requestDigest(policy)
	if err != nil { return UpdatePolicy{}, err }
	operation := Operation{CommandID: commandID, Kind: "application_update_policy", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: service.now(), UpdatedAt: service.now()}
	operation, created, err := service.Applications.AdmitOperation(ctx, operation)
	if err != nil { return UpdatePolicy{}, err }
	if !created {
		if operation.State == OperationCommitted { return service.Applications.LoadUpdatePolicy(ctx, installation.ID) }
		return UpdatePolicy{}, ErrConflict
	}
	if err := service.Applications.SaveUpdatePolicy(ctx, policy, expectedPolicyGeneration); err != nil { return UpdatePolicy{}, service.fail(ctx, operation, "persist", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", digest, service.now()
	if err := service.Applications.UpdateOperation(ctx, operation); err != nil { return UpdatePolicy{}, err }
	return policy, nil
}

func (service PolicyService) ConfigureScans(ctx context.Context, commandID CommandID, policy ScanPolicy, expectedPolicyGeneration, expectedInstallationGeneration uint64) (ScanPolicy, error) {
	if service.Applications == nil || service.Scans == nil { return ScanPolicy{}, ErrInvalid }
	if err := policy.Validate(); err != nil { return ScanPolicy{}, err }
	installation, err := service.Applications.LoadInstallation(ctx, policy.InstallationID)
	if err != nil { return ScanPolicy{}, err }
	if installation.Generation != expectedInstallationGeneration || policy.Generation != expectedPolicyGeneration+1 { return ScanPolicy{}, ErrStaleGeneration }
	digest, err := requestDigest(policy)
	if err != nil { return ScanPolicy{}, err }
	operation := Operation{CommandID: commandID, Kind: "application_scan_policy", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: service.now(), UpdatedAt: service.now()}
	operation, created, err := service.Applications.AdmitOperation(ctx, operation)
	if err != nil { return ScanPolicy{}, err }
	if !created {
		if operation.State == OperationCommitted { return service.Scans.LoadScanPolicy(ctx, installation.ID) }
		return ScanPolicy{}, ErrConflict
	}
	if err := service.Scans.SaveScanPolicy(ctx, policy, expectedPolicyGeneration); err != nil { return ScanPolicy{}, service.fail(ctx, operation, "persist", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", digest, service.now()
	if err := service.Applications.UpdateOperation(ctx, operation); err != nil { return ScanPolicy{}, err }
	return policy, nil
}

func (service PolicyService) ConfigureBackup(ctx context.Context, commandID CommandID, profile ApplicationBackupProfile, expectedProfileGeneration, expectedInstallationGeneration uint64, store ApplicationBackupStore) (ApplicationBackupProfile, error) {
	if service.Applications == nil || store == nil { return ApplicationBackupProfile{}, ErrInvalid }
	if err := profile.Validate(); err != nil { return ApplicationBackupProfile{}, err }
	installation, err := service.Applications.LoadInstallation(ctx, profile.InstallationID)
	if err != nil { return ApplicationBackupProfile{}, err }
	if installation.Generation != expectedInstallationGeneration || profile.Generation != expectedProfileGeneration+1 { return ApplicationBackupProfile{}, ErrStaleGeneration }
	digest, err := requestDigest(profile)
	if err != nil { return ApplicationBackupProfile{}, err }
	operation := Operation{CommandID: commandID, Kind: "application_backup_policy", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: service.now(), UpdatedAt: service.now()}
	operation, created, err := service.Applications.AdmitOperation(ctx, operation)
	if err != nil { return ApplicationBackupProfile{}, err }
	if !created {
		if operation.State == OperationCommitted { return store.LoadApplicationBackupProfile(ctx, profile.ID) }
		return ApplicationBackupProfile{}, ErrConflict
	}
	if err := store.SaveApplicationBackupProfile(ctx, profile, expectedProfileGeneration); err != nil { return ApplicationBackupProfile{}, service.fail(ctx, operation, "persist", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", digest, service.now()
	if err := service.Applications.UpdateOperation(ctx, operation); err != nil { return ApplicationBackupProfile{}, err }
	return profile, nil
}

func (service PolicyService) fail(ctx context.Context, operation Operation, stage string, cause error) error {
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, stage, cause.Error(), service.now()
	_ = service.Applications.UpdateOperation(ctx, operation)
	return fmt.Errorf("%s: %w", stage, cause)
}
