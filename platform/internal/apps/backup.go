package apps

import (
	"context"
	"fmt"
	"time"
)

type ApplicationBackupProfileID string

type BackupDestinationKind string

const (
	BackupLocal  BackupDestinationKind = "local"
	BackupRemote BackupDestinationKind = "remote"
)

type ApplicationBackupProfile struct {
	ID             ApplicationBackupProfileID `json:"id"`
	InstallationID InstallationID `json:"installation_id"`
	RepositoryID   string `json:"repository_id"`
	Destination    BackupDestinationKind `json:"destination"`
	Schedule       string `json:"schedule,omitempty"`
	Enabled        bool `json:"enabled"`
	RetentionCount uint32 `json:"retention_count"`
	RetentionDays  uint32 `json:"retention_days"`
	Consistency    string `json:"consistency"`
	IncludeFiles   bool `json:"include_files"`
	IncludeDatabase bool `json:"include_database"`
	IncludeUploads bool `json:"include_uploads"`
	Verify         bool `json:"verify"`
	Generation     uint64 `json:"generation"`
}

func (profile ApplicationBackupProfile) Validate() error {
	if err := requireID("backup profile", string(profile.ID)); err != nil { return err }
	if err := requireID("installation", string(profile.InstallationID)); err != nil { return err }
	if !validID(profile.RepositoryID) || profile.Destination != BackupLocal && profile.Destination != BackupRemote || profile.RetentionCount == 0 && profile.RetentionDays == 0 || profile.Consistency != "application_consistent" && profile.Consistency != "database_consistent" && profile.Consistency != "crash_consistent" || !profile.IncludeFiles && !profile.IncludeDatabase || profile.Generation == 0 {
		return fmt.Errorf("%w: application backup profile", ErrInvalid)
	}
	if profile.Enabled && profile.Schedule == "" { return fmt.Errorf("%w: backup schedule", ErrInvalid) }
	return nil
}

type ApplicationBackupRequest struct {
	CommandID        CommandID `json:"command_id"`
	InstallationID   InstallationID `json:"installation_id"`
	ProfileID        ApplicationBackupProfileID `json:"profile_id"`
	RecoveryPointID  RecoveryPointID `json:"recovery_point_id"`
	OnDemand         bool `json:"on_demand"`
	SiteGeneration   uint64 `json:"site_generation"`
	IsolationProfile string `json:"isolation_profile"`
}

type ApplicationRecoveryPoint struct {
	ID              RecoveryPointID `json:"id"`
	InstallationID  InstallationID `json:"installation_id"`
	ProfileID       ApplicationBackupProfileID `json:"profile_id"`
	RepositoryID    string `json:"repository_id"`
	SnapshotID      SnapshotID `json:"snapshot_id"`
	ManifestDigest  string `json:"manifest_digest"`
	WriteFrontier   uint64 `json:"write_frontier"`
	Consistency     string `json:"consistency"`
	Verified        bool `json:"verified"`
	CreatedAt       time.Time `json:"created_at"`
	CommittedAt     time.Time `json:"committed_at"`
}

type ApplicationRestoreRequest struct {
	CommandID          CommandID `json:"command_id"`
	InstallationID     InstallationID `json:"installation_id"`
	RecoveryPointID    RecoveryPointID `json:"recovery_point_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	SiteGeneration     uint64 `json:"site_generation"`
	IsolationProfile   string `json:"isolation_profile"`
	PointInTime        time.Time `json:"point_in_time,omitempty"`
}

type ApplicationBackupProvider interface {
	CommitApplicationSnapshot(context.Context, ApplicationBackupProfile, Snapshot, RecoveryPointID) (ApplicationRecoveryPoint, error)
	VerifyApplicationRecoveryPoint(context.Context, ApplicationRecoveryPoint) error
	RestoreApplicationRecoveryPoint(context.Context, ApplicationRecoveryPoint, SiteExecutionScope, time.Time) (ExecutionReceipt, error)
	RollbackApplicationRestore(context.Context, ApplicationRecoveryPoint, SiteExecutionScope, SnapshotID) (ExecutionReceipt, error)
}

type ApplicationBackupStore interface {
	SaveApplicationBackupProfile(context.Context, ApplicationBackupProfile, uint64) error
	LoadApplicationBackupProfile(context.Context, ApplicationBackupProfileID) (ApplicationBackupProfile, error)
	SaveApplicationRecoveryPoint(context.Context, ApplicationRecoveryPoint) error
	LoadApplicationRecoveryPoint(context.Context, RecoveryPointID) (ApplicationRecoveryPoint, error)
}

type ApplicationBackupCoordinator struct {
	Store interface { ApplicationStore; ApplicationBackupStore }
	Snapshots SnapshotProvider
	Provider ApplicationBackupProvider
	Now func() time.Time
}

func (coordinator ApplicationBackupCoordinator) now() time.Time {
	if coordinator.Now != nil { return coordinator.Now().UTC() }
	return time.Now().UTC()
}

func (coordinator ApplicationBackupCoordinator) Capture(ctx context.Context, request ApplicationBackupRequest) (ApplicationRecoveryPoint, error) {
	if coordinator.Store == nil || coordinator.Snapshots == nil || coordinator.Provider == nil { return ApplicationRecoveryPoint{}, ErrInvalid }
	installation, err := coordinator.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return ApplicationRecoveryPoint{}, err }
	profile, err := coordinator.Store.LoadApplicationBackupProfile(ctx, request.ProfileID)
	if err != nil { return ApplicationRecoveryPoint{}, err }
	if profile.InstallationID != installation.ID || !request.OnDemand && !profile.Enabled { return ApplicationRecoveryPoint{}, ErrPolicyDenied }
	digest, err := requestDigest(request)
	if err != nil { return ApplicationRecoveryPoint{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "application_backup", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	operation, created, err := coordinator.Store.AdmitOperation(ctx, operation)
	if err != nil { return ApplicationRecoveryPoint{}, err }
	if !created {
		if operation.State == OperationCommitted { return coordinator.Store.LoadApplicationRecoveryPoint(ctx, request.RecoveryPointID) }
		return ApplicationRecoveryPoint{}, ErrConflict
	}
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	snapshot, err := coordinator.Snapshots.CreateApplicationSnapshot(ctx, SnapshotRequest{Scope: scope, Installation: installation.ID, Purpose: SnapshotPurpose("application_backup"), IncludeFiles: profile.IncludeFiles, IncludeDatabase: profile.IncludeDatabase, IncludeUploads: profile.IncludeUploads, StableRequired: profile.Consistency == "application_consistent", MaximumBytes: 512 << 30})
	if err != nil { return ApplicationRecoveryPoint{}, coordinator.fail(ctx, operation, "snapshot", err) }
	if err := coordinator.Snapshots.VerifyApplicationSnapshot(ctx, snapshot.ID); err != nil { return ApplicationRecoveryPoint{}, coordinator.fail(ctx, operation, "verify_snapshot", err) }
	point, err := coordinator.Provider.CommitApplicationSnapshot(ctx, profile, snapshot, request.RecoveryPointID)
	if err != nil { return ApplicationRecoveryPoint{}, coordinator.fail(ctx, operation, "commit", err) }
	if point.ID != request.RecoveryPointID || point.InstallationID != installation.ID || point.SnapshotID != snapshot.ID || point.ManifestDigest != snapshot.ManifestDigest || !point.Verified || point.CommittedAt.IsZero() { return ApplicationRecoveryPoint{}, coordinator.fail(ctx, operation, "provider_receipt", ErrIntegrity) }
	if profile.Verify { if err := coordinator.Provider.VerifyApplicationRecoveryPoint(ctx, point); err != nil { return ApplicationRecoveryPoint{}, coordinator.fail(ctx, operation, "verify_recovery_point", err) } }
	if err := coordinator.Store.SaveApplicationRecoveryPoint(ctx, point); err != nil { return ApplicationRecoveryPoint{}, coordinator.fail(ctx, operation, "persist", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", point.ManifestDigest, coordinator.now()
	if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return ApplicationRecoveryPoint{}, err }
	return point, nil
}

func (coordinator ApplicationBackupCoordinator) Restore(ctx context.Context, request ApplicationRestoreRequest) (ApplicationInstallation, error) {
	installation, err := coordinator.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return ApplicationInstallation{}, err }
	if installation.Generation != request.ExpectedGeneration { return ApplicationInstallation{}, ErrStaleGeneration }
	point, err := coordinator.Store.LoadApplicationRecoveryPoint(ctx, request.RecoveryPointID)
	if err != nil { return ApplicationInstallation{}, err }
	if point.InstallationID != installation.ID || !point.Verified { return ApplicationInstallation{}, ErrPolicyDenied }
	digest, err := requestDigest(request)
	if err != nil { return ApplicationInstallation{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "application_restore", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: coordinator.now(), UpdatedAt: coordinator.now()}
	operation, created, err := coordinator.Store.AdmitOperation(ctx, operation)
	if err != nil { return ApplicationInstallation{}, err }
	if !created { return ApplicationInstallation{}, ErrConflict }
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	rollbackSnapshot, err := coordinator.Snapshots.CreateApplicationSnapshot(ctx, SnapshotRequest{Scope: scope, Installation: installation.ID, Purpose: SnapshotPurpose("pre_restore"), IncludeFiles: true, IncludeDatabase: true, IncludeUploads: true, StableRequired: true, MaximumBytes: 512 << 30})
	if err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "rollback_snapshot", err) }
	receipt, err := coordinator.Provider.RestoreApplicationRecoveryPoint(ctx, point, scope, request.PointInTime)
	if err != nil { return ApplicationInstallation{}, coordinator.fail(ctx, operation, "restore", err) }
	if err := receipt.Validate("application_restore", scope, installation.ID); err != nil {
		_, _ = coordinator.Provider.RollbackApplicationRestore(ctx, point, scope, rollbackSnapshot.ID)
		return ApplicationInstallation{}, coordinator.fail(ctx, operation, "receipt", err)
	}
	previousGeneration := installation.Generation
	installation.Generation, installation.UpdatedAt, installation.Health = installation.Generation+1, coordinator.now(), HealthObservation{State: HealthUnknown, CheckedAt: coordinator.now()}
	if err := coordinator.Store.UpdateInstallation(ctx, installation, previousGeneration); err != nil { return ApplicationInstallation{}, coordinator.recovery(ctx, operation, "persist", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, coordinator.now()
	if err := coordinator.Store.UpdateOperation(ctx, operation); err != nil { return ApplicationInstallation{}, err }
	return installation, nil
}

func (coordinator ApplicationBackupCoordinator) fail(ctx context.Context, operation Operation, stage string, cause error) error {
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, stage, cause.Error(), coordinator.now()
	_ = coordinator.Store.UpdateOperation(ctx, operation)
	return cause
}

func (coordinator ApplicationBackupCoordinator) recovery(ctx context.Context, operation Operation, stage string, cause error) error {
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationRecoveryRequired, stage, cause.Error(), coordinator.now()
	_ = coordinator.Store.UpdateOperation(ctx, operation)
	return fmt.Errorf("%w: %v", ErrRecoveryRequired, cause)
}
