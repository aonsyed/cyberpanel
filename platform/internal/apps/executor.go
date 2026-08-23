package apps

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SiteExecutionScope is resolved from the node's site registry. The executor
// independently checks the site-to-UID binding and derives all host paths from
// SiteID and Root; callers cannot supply a host path, executable, or UID name.
type SiteExecutionScope struct {
	TenantID          TenantID `json:"tenant_id"`
	SiteID            SiteID `json:"site_id"`
	SiteUID           SiteUID `json:"site_uid"`
	Root              RelativePath `json:"root"`
	IsolationProfile  string `json:"isolation_profile"`
	ResourceGeneration uint64 `json:"resource_generation"`
}

func (scope SiteExecutionScope) Validate() error {
	if err := requireID("tenant", string(scope.TenantID)); err != nil { return err }
	if err := requireID("site", string(scope.SiteID)); err != nil { return err }
	if scope.SiteUID < 1000 || !validID(scope.IsolationProfile) || scope.ResourceGeneration == 0 {
		return fmt.Errorf("%w: site execution scope", ErrInvalid)
	}
	return nil
}

type DatabaseBinding struct {
	ID            DatabaseBindingID `json:"id"`
	Engine        string `json:"engine"`
	DatabaseName  string `json:"database_name"`
	PrincipalName string `json:"principal_name"`
	EndpointRef   string `json:"endpoint_ref"`
	PasswordRef   SecretRef `json:"password_ref"`
	TLSRequired   bool `json:"tls_required"`
}

func (binding DatabaseBinding) Validate() error {
	if err := requireID("database binding", string(binding.ID)); err != nil { return err }
	if !componentNamePattern.MatchString(binding.DatabaseName) || !componentNamePattern.MatchString(binding.PrincipalName) || !validID(binding.EndpointRef) || !validID(string(binding.PasswordRef)) {
		return fmt.Errorf("%w: database binding", ErrInvalid)
	}
	return nil
}

type AdministratorBootstrap struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	PasswordRef SecretRef `json:"password_ref"`
}

func (bootstrap AdministratorBootstrap) Validate() error {
	if len(bootstrap.Username) < 3 || len(bootstrap.Username) > 128 || strings.ContainsAny(bootstrap.Username, "\x00\r\n\t /\\") || len(bootstrap.Email) > 320 || !strings.Contains(bootstrap.Email, "@") || strings.TrimSpace(bootstrap.DisplayName) == "" || !validID(string(bootstrap.PasswordRef)) {
		return fmt.Errorf("%w: administrator bootstrap", ErrInvalid)
	}
	return nil
}

type InstallExecution struct {
	Scope        SiteExecutionScope `json:"scope"`
	Installation InstallationID `json:"installation_id"`
	Definition   ApplicationDefinition `json:"definition"`
	RuntimeID    string `json:"runtime_id"`
	Database     DatabaseBinding `json:"database"`
	Administrator AdministratorBootstrap `json:"administrator"`
	CanonicalURL string `json:"canonical_url"`
	Locale       string `json:"locale"`
	Timezone     string `json:"timezone"`
	Title        string `json:"title"`
	ReleaseID    ReleaseID `json:"release_id"`
}

func (execution InstallExecution) Validate(now time.Time) error {
	if err := execution.Scope.Validate(); err != nil { return err }
	if err := requireID("installation", string(execution.Installation)); err != nil { return err }
	if err := requireID("release", string(execution.ReleaseID)); err != nil { return err }
	if err := execution.Definition.Validate(now); err != nil { return err }
	if err := execution.Database.Validate(); err != nil { return err }
	if err := execution.Administrator.Validate(); err != nil { return err }
	if strings.TrimSpace(execution.RuntimeID) == "" || strings.TrimSpace(execution.CanonicalURL) == "" || strings.TrimSpace(execution.Locale) == "" || strings.TrimSpace(execution.Timezone) == "" || len(execution.Title) > 256 {
		return fmt.Errorf("%w: install execution", ErrInvalid)
	}
	return nil
}

type DiscoveryExecution struct {
	Scope       SiteExecutionScope `json:"scope"`
	Kinds       []ApplicationKind `json:"kinds"`
	MaximumDepth uint8 `json:"maximum_depth"`
	MaximumCandidates uint16 `json:"maximum_candidates"`
}

type AdoptExecution struct {
	Scope         SiteExecutionScope `json:"scope"`
	Installation InstallationID `json:"installation_id"`
	Definition   ApplicationDefinition `json:"definition"`
	Candidate    DiscoveryCandidate `json:"candidate"`
	Database     DatabaseBinding `json:"database"`
}

type InspectExecution struct {
	Scope         SiteExecutionScope `json:"scope"`
	Installation InstallationID `json:"installation_id"`
	Kind          ApplicationKind `json:"kind"`
	RecipeDigest  string `json:"recipe_digest"`
	Deep          bool `json:"deep"`
}

type RepairAction string

const (
	RepairPermissions RepairAction = "permissions"
	RepairConfiguration RepairAction = "configuration"
	RepairCoreFiles RepairAction = "core_files"
	RepairDatabase RepairAction = "database"
	RepairCache RepairAction = "cache"
	RepairDependencies RepairAction = "dependencies"
)

type RepairExecution struct {
	Scope         SiteExecutionScope `json:"scope"`
	Installation InstallationID `json:"installation_id"`
	DefinitionID DefinitionID `json:"definition_id"`
	Kind         ApplicationKind `json:"kind"`
	Recipe       RecipeReference `json:"recipe"`
	Actions      []RepairAction `json:"actions"`
	RecoveryPointID RecoveryPointID `json:"recovery_point_id"`
	ExpectedInventoryDigest string `json:"expected_inventory_digest"`
}

type UpdateExecution struct {
	Scope          SiteExecutionScope `json:"scope"`
	Installation  InstallationID `json:"installation_id"`
	Definition    ApplicationDefinition `json:"definition"`
	FromReleaseID ReleaseID `json:"from_release_id,omitempty"`
	TargetRelease Release `json:"target_release"`
	SnapshotID    SnapshotID `json:"snapshot_id"`
	RecoveryPointID RecoveryPointID `json:"recovery_point_id"`
	Components    []ComponentRelease `json:"components,omitempty"`
	ShadowBinding string `json:"shadow_binding"`
	WriteFence    bool `json:"write_fence"`
}

type PromotionExecution struct {
	Scope          SiteExecutionScope `json:"scope"`
	Installation  InstallationID `json:"installation_id"`
	FromReleaseID ReleaseID `json:"from_release_id,omitempty"`
	ToReleaseID   ReleaseID `json:"to_release_id"`
	SnapshotID    SnapshotID `json:"snapshot_id"`
	ExpectedHealthDigest string `json:"expected_health_digest"`
	WriteFrontier uint64 `json:"write_frontier"`
}

type RemovalExecution struct {
	Scope          SiteExecutionScope `json:"scope"`
	Installation  InstallationID `json:"installation_id"`
	DefinitionID  DefinitionID `json:"definition_id"`
	RecoveryPointID RecoveryPointID `json:"recovery_point_id"`
	Disposition    RemovalDisposition `json:"disposition"`
}

type RemovalDisposition string

const (
	RemovalQuarantine RemovalDisposition = "quarantine"
	RemovalPurge      RemovalDisposition = "purge"
)

type ExecutionReceipt struct {
	Operation       string `json:"operation"`
	SiteID          SiteID `json:"site_id"`
	SiteUID         SiteUID `json:"site_uid"`
	InstallationID  InstallationID `json:"installation_id"`
	InputDigest     string `json:"input_digest"`
	OutputDigest    string `json:"output_digest"`
	ReleaseID       ReleaseID `json:"release_id,omitempty"`
	SnapshotID      SnapshotID `json:"snapshot_id,omitempty"`
	WriteFrontier   uint64 `json:"write_frontier"`
	Irreversible    bool `json:"irreversible"`
	Attestation     string `json:"attestation"`
	CompletedAt     time.Time `json:"completed_at"`
}

func (receipt ExecutionReceipt) Validate(operation string, scope SiteExecutionScope, installation InstallationID) error {
	if receipt.Operation != operation || receipt.SiteID != scope.SiteID || receipt.SiteUID != scope.SiteUID || receipt.InstallationID != installation || !validDigest(receipt.InputDigest) || !validDigest(receipt.OutputDigest) || receipt.Attestation == "" || receipt.CompletedAt.IsZero() {
		return fmt.Errorf("%w: executor receipt", ErrIntegrity)
	}
	return nil
}

// SiteApplicationExecutor is implemented only by the site-task worker. Each
// operation maps to a fixed executable and closed request schema; no method
// accepts shell, host paths, environment maps, or an arbitrary binary.
type SiteApplicationExecutor interface {
	Install(context.Context, InstallExecution) (ExecutionReceipt, error)
	Discover(context.Context, DiscoveryExecution) ([]DiscoveryCandidate, ExecutionReceipt, error)
	Adopt(context.Context, AdoptExecution) (ExecutionReceipt, error)
	Inspect(context.Context, InspectExecution) (ComponentInventory, HealthObservation, ExecutionReceipt, error)
	Repair(context.Context, RepairExecution) (ExecutionReceipt, error)
	PrepareUpdate(context.Context, UpdateExecution) (ExecutionReceipt, error)
	ApplyUpdate(context.Context, UpdateExecution) (ExecutionReceipt, error)
	ProbeUpdate(context.Context, UpdateExecution) (HealthObservation, ExecutionReceipt, error)
	Promote(context.Context, PromotionExecution) (ExecutionReceipt, error)
	Rollback(context.Context, PromotionExecution) (ExecutionReceipt, error)
	Quarantine(context.Context, RemovalExecution) (ExecutionReceipt, error)
	Remove(context.Context, RemovalExecution) (ExecutionReceipt, error)
}

type SnapshotPurpose string

const (
	SnapshotApplicationUpdate SnapshotPurpose = "application_update"
	SnapshotStagingSource SnapshotPurpose = "staging_source"
	SnapshotStagingTarget SnapshotPurpose = "staging_target"
	SnapshotScan SnapshotPurpose = "security_scan"
	SnapshotRemediation SnapshotPurpose = "security_remediation"
)

type SnapshotRequest struct {
	Scope          SiteExecutionScope `json:"scope"`
	Installation  InstallationID `json:"installation_id"`
	Purpose        SnapshotPurpose `json:"purpose"`
	IncludeFiles   bool `json:"include_files"`
	IncludeDatabase bool `json:"include_database"`
	IncludeUploads bool `json:"include_uploads"`
	StableRequired bool `json:"stable_required"`
	MaximumBytes   uint64 `json:"maximum_bytes"`
}

type Snapshot struct {
	ID             SnapshotID `json:"id"`
	InstallationID InstallationID `json:"installation_id"`
	Purpose        SnapshotPurpose `json:"purpose"`
	ManifestDigest string `json:"manifest_digest"`
	DatabaseDigest string `json:"database_digest,omitempty"`
	WriteFrontier  uint64 `json:"write_frontier"`
	Stable         bool `json:"stable"`
	Size           uint64 `json:"size"`
	CreatedAt      time.Time `json:"created_at"`
}

type SnapshotProvider interface {
	CreateApplicationSnapshot(context.Context, SnapshotRequest) (Snapshot, error)
	VerifyApplicationSnapshot(context.Context, SnapshotID) error
	ReleaseApplicationSnapshot(context.Context, SnapshotID) error
}

type RecoveryRequest struct {
	TenantID       TenantID `json:"tenant_id"`
	SiteID         SiteID `json:"site_id"`
	InstallationID InstallationID `json:"installation_id"`
	Purpose        string `json:"purpose"`
	Consistency    string `json:"consistency"`
	Required       bool `json:"required"`
}

type RecoveryPointProvider interface {
	CreateRecoveryPoint(context.Context, RecoveryRequest) (RecoveryPointID, uint64, error)
	VerifyRecoveryPoint(context.Context, RecoveryPointID) error
}

type DatabaseProvisioner interface {
	ProvisionApplicationDatabase(context.Context, TenantID, SiteID, InstallationID, ApplicationKind) (DatabaseBinding, error)
	RevokeApplicationDatabase(context.Context, DatabaseBindingID) error
}

type SecretIssuer interface {
	IssueApplicationSecret(context.Context, TenantID, SiteID, InstallationID, string) (SecretRef, error)
	RevokeApplicationSecret(context.Context, SecretRef) error
}

type ApplicationRouteController interface {
	CreateShadowRoute(context.Context, SiteID, InstallationID, ReleaseID) (string, error)
	RemoveShadowRoute(context.Context, SiteID, InstallationID, ReleaseID) error
	ActivateReleaseRoute(context.Context, SiteID, InstallationID, ReleaseID, string) error
	RestoreReleaseRoute(context.Context, SiteID, InstallationID, ReleaseID) error
}
