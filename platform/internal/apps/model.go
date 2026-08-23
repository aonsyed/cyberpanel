// Package apps owns managed web-application installations, their immutable
// recipes, inventories, deployments, staging relations, and security scans.
//
// Host paths and command strings are deliberately absent from the public
// model. Application work is always scoped to a registered site identity and
// a canonical path relative to that site's application root.
package apps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid             = errors.New("invalid application resource")
	ErrNotFound            = errors.New("application resource not found")
	ErrConflict            = errors.New("application resource conflict")
	ErrStaleGeneration     = errors.New("stale application generation")
	ErrInvalidTransition   = errors.New("invalid application state transition")
	ErrRecipeUntrusted     = errors.New("application recipe is not trusted")
	ErrRecipeUnavailable   = errors.New("application recipe is unavailable")
	ErrUnsupported         = errors.New("application operation is unsupported")
	ErrPolicyDenied        = errors.New("application policy denied operation")
	ErrIntegrity           = errors.New("application integrity check failed")
	ErrRecoveryRequired    = errors.New("application requires recovery")
	ErrGrantConsumed       = errors.New("application login grant already consumed")
	ErrGrantExpired        = errors.New("application login grant expired")
	ErrAmbiguousDiscovery  = errors.New("application discovery is ambiguous")
	ErrIrreversibleFrontier = errors.New("application crossed an irreversible frontier")
)

type ID string
type TenantID string
type ProjectID string
type SiteID string
type SiteUID uint32
type InstallationID string
type DefinitionID string
type RecipeID string
type DatabaseBindingID string
type SecretRef string
type ReleaseID string
type DeploymentID string
type SnapshotID string
type RecoveryPointID string
type UpdatePolicyID string
type StagingRelationID string
type SyncID string
type LoginGrantID string
type ScanRunID string
type FindingID string
type RemediationPlanID string
type CommandID string

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var componentNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,191}$`)
var versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,127}$`)

func validID(value string) bool { return idPattern.MatchString(value) }

func requireID(kind, value string) error {
	if !validID(value) {
		return fmt.Errorf("%w: %s identifier", ErrInvalid, kind)
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

// RelativePath is a canonical slash-separated path beneath a site-owned root.
// It cannot be absolute, traverse upward, contain NUL, or address a platform
// path. The empty path refers to the registered application root itself.
type RelativePath struct{ value string }

func ParseRelativePath(raw string) (RelativePath, error) {
	if len(raw) > 4096 || !utf8.ValidString(raw) || strings.IndexByte(raw, 0) >= 0 || strings.Contains(raw, `\`) || strings.HasPrefix(raw, "/") {
		return RelativePath{}, fmt.Errorf("%w: relative path", ErrInvalid)
	}
	if raw == "" {
		return RelativePath{}, nil
	}
	if raw == "." || path.Clean(raw) != raw {
		return RelativePath{}, fmt.Errorf("%w: non-canonical relative path", ErrInvalid)
	}
	for _, segment := range strings.Split(raw, "/") {
		if segment == "" || segment == "." || segment == ".." || len(segment) > 255 {
			return RelativePath{}, fmt.Errorf("%w: relative path segment", ErrInvalid)
		}
	}
	return RelativePath{value: raw}, nil
}

func MustRelativePath(raw string) RelativePath {
	value, err := ParseRelativePath(raw)
	if err != nil {
		panic(err)
	}
	return value
}

func (value RelativePath) String() string { return value.value }
func (value RelativePath) IsRoot() bool   { return value.value == "" }
func (value RelativePath) MarshalJSON() ([]byte, error) { return json.Marshal(value.value) }
func (value *RelativePath) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	parsed, err := ParseRelativePath(raw)
	if err != nil {
		return err
	}
	*value = parsed
	return nil
}

type ApplicationKind string

const (
	ApplicationWordPress  ApplicationKind = "wordpress"
	ApplicationJoomla     ApplicationKind = "joomla"
	ApplicationPrestaShop ApplicationKind = "prestashop"
	ApplicationMagento    ApplicationKind = "magento_open_source"
	ApplicationMautic     ApplicationKind = "mautic"
)

func (kind ApplicationKind) Valid() bool {
	switch kind {
	case ApplicationWordPress, ApplicationJoomla, ApplicationPrestaShop, ApplicationMagento, ApplicationMautic:
		return true
	default:
		return false
	}
}

type WebEngine string

const (
	EngineOpenLiteSpeed WebEngine = "openlitespeed"
	EngineLiteSpeedEnterprise WebEngine = "litespeed_enterprise"
)

type CPUArchitecture string

const (
	ArchitectureAMD64 CPUArchitecture = "amd64"
	ArchitectureARM64 CPUArchitecture = "arm64"
)

type OperatingSystem string

const (
	OSUbuntuNoble OperatingSystem = "ubuntu_24.04"
	OSAlmaLinux9 OperatingSystem = "almalinux_9"
)

type StorageMode string

const (
	StorageManagedRelease StorageMode = "managed_release"
	StorageMutableTree StorageMode = "mutable_tree"
)

type ArtifactReference struct {
	URL       string `json:"url"`
	Digest    string `json:"sha256"`
	Size      int64  `json:"size"`
	Signature string `json:"signature,omitempty"`
}

func (reference ArtifactReference) Validate() error {
	parsed, err := url.Parse(reference.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%w: artifact URL", ErrInvalid)
	}
	if !validDigest(reference.Digest) || reference.Size <= 0 || reference.Size > 16<<30 {
		return fmt.Errorf("%w: artifact integrity", ErrInvalid)
	}
	return nil
}

type RecipeReference struct {
	ID              RecipeID `json:"id"`
	DefinitionID    DefinitionID `json:"definition_id"`
	ProductVersion  string `json:"product_version"`
	RecipeDigest    string `json:"recipe_digest"`
	Signature       string `json:"signature"`
	SigningKeyID    string `json:"signing_key_id"`
	CatalogEpoch    uint64 `json:"catalog_epoch"`
	PublishedAt     time.Time `json:"published_at"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
}

func (reference RecipeReference) Validate(now time.Time) error {
	if err := requireID("recipe", string(reference.ID)); err != nil { return err }
	if err := requireID("definition", string(reference.DefinitionID)); err != nil { return err }
	if !versionPattern.MatchString(reference.ProductVersion) || !validDigest(reference.RecipeDigest) || reference.Signature == "" || !validID(reference.SigningKeyID) || reference.CatalogEpoch == 0 || reference.PublishedAt.IsZero() {
		return fmt.Errorf("%w: recipe reference", ErrInvalid)
	}
	if reference.PublishedAt.After(now) || !reference.ExpiresAt.IsZero() && !now.Before(reference.ExpiresAt) {
		return ErrRecipeUnavailable
	}
	return nil
}

type RuntimeRequirement struct {
	PHPVersions    []string `json:"php_versions"`
	PHPExtensions  []string `json:"php_extensions"`
	DatabaseKinds  []string `json:"database_kinds"`
	MinMemoryBytes uint64 `json:"min_memory_bytes"`
	MinDiskBytes   uint64 `json:"min_disk_bytes"`
	RequiredPorts  []uint16 `json:"required_ports,omitempty"`
}

func (requirement RuntimeRequirement) Validate() error {
	if len(requirement.PHPVersions) == 0 || len(requirement.DatabaseKinds) == 0 || requirement.MinMemoryBytes == 0 || requirement.MinDiskBytes == 0 {
		return fmt.Errorf("%w: runtime requirements", ErrInvalid)
	}
	seen := map[string]struct{}{}
	for _, extension := range requirement.PHPExtensions {
		if !componentNamePattern.MatchString(extension) {
			return fmt.Errorf("%w: PHP extension", ErrInvalid)
		}
		if _, exists := seen[extension]; exists { return fmt.Errorf("%w: duplicate PHP extension", ErrInvalid) }
		seen[extension] = struct{}{}
	}
	return nil
}

type MutableStore struct {
	Name     string `json:"name"`
	Path     RelativePath `json:"path"`
	Required bool `json:"required"`
	BackedUp bool `json:"backed_up"`
}

type ProbeKind string

const (
	ProbeHTTP       ProbeKind = "http"
	ProbeCLI        ProbeKind = "application_cli"
	ProbeDatabase   ProbeKind = "database"
	ProbeIntegrity  ProbeKind = "integrity"
	ProbeBackground ProbeKind = "background_worker"
)

type ProbeDefinition struct {
	Name             string `json:"name"`
	Kind             ProbeKind `json:"kind"`
	RelativeEndpoint string `json:"relative_endpoint,omitempty"`
	ExpectedStatus   []int `json:"expected_status,omitempty"`
	Timeout          time.Duration `json:"timeout"`
	Required         bool `json:"required"`
}

type ApplicationDefinition struct {
	ID                 DefinitionID `json:"id"`
	Kind               ApplicationKind `json:"kind"`
	DisplayName        string `json:"display_name"`
	Recipe             RecipeReference `json:"recipe"`
	Artifact           ArtifactReference `json:"artifact"`
	Architectures      []CPUArchitecture `json:"architectures"`
	OperatingSystems   []OperatingSystem `json:"operating_systems"`
	WebEngines         []WebEngine `json:"web_engines"`
	StorageMode        StorageMode `json:"storage_mode"`
	Runtime            RuntimeRequirement `json:"runtime"`
	MutableStores      []MutableStore `json:"mutable_stores"`
	InstallProbes      []ProbeDefinition `json:"install_probes"`
	UpdateProbes       []ProbeDefinition `json:"update_probes"`
	BackupComponents   []string `json:"backup_components"`
	Lifecycle          LifecycleSupport `json:"lifecycle"`
	DefinitionDigest   string `json:"definition_digest"`
}

type LifecycleSupport struct {
	Install     bool `json:"install"`
	Discover    bool `json:"discover"`
	Adopt       bool `json:"adopt"`
	Update      bool `json:"update"`
	Backup      bool `json:"backup"`
	Restore     bool `json:"restore"`
	Clone       bool `json:"clone"`
	Staging     bool `json:"staging"`
	Repair      bool `json:"repair"`
	Quarantine  bool `json:"quarantine"`
	Uninstall   bool `json:"uninstall"`
}

func (definition ApplicationDefinition) Validate(now time.Time) error {
	if err := requireID("definition", string(definition.ID)); err != nil { return err }
	if !definition.Kind.Valid() || strings.TrimSpace(definition.DisplayName) == "" {
		return fmt.Errorf("%w: application definition", ErrInvalid)
	}
	if definition.Recipe.DefinitionID != definition.ID {
		return fmt.Errorf("%w: recipe definition mismatch", ErrInvalid)
	}
	if err := definition.Recipe.Validate(now); err != nil { return err }
	if err := definition.Artifact.Validate(); err != nil { return err }
	if definition.StorageMode != StorageManagedRelease && definition.StorageMode != StorageMutableTree {
		return fmt.Errorf("%w: storage mode", ErrInvalid)
	}
	if err := definition.Runtime.Validate(); err != nil { return err }
	if len(definition.Architectures) == 0 || len(definition.OperatingSystems) == 0 || len(definition.WebEngines) != 2 || len(definition.InstallProbes) == 0 || !validDigest(definition.DefinitionDigest) {
		return fmt.Errorf("%w: support matrix", ErrInvalid)
	}
	engineSet := map[WebEngine]bool{}
	for _, engine := range definition.WebEngines { engineSet[engine] = true }
	if !engineSet[EngineOpenLiteSpeed] || !engineSet[EngineLiteSpeedEnterprise] {
		return fmt.Errorf("%w: both LiteSpeed engines are required", ErrInvalid)
	}
	paths := map[string]struct{}{}
	for _, store := range definition.MutableStores {
		if !componentNamePattern.MatchString(store.Name) || store.Path.IsRoot() {
			return fmt.Errorf("%w: mutable store", ErrInvalid)
		}
		if _, exists := paths[store.Path.String()]; exists { return fmt.Errorf("%w: duplicate mutable store", ErrInvalid) }
		paths[store.Path.String()] = struct{}{}
	}
	return nil
}

type InstallationState string

const (
	InstallationPending      InstallationState = "pending"
	InstallationInstalling   InstallationState = "installing"
	InstallationActive       InstallationState = "active"
	InstallationMaintenance  InstallationState = "maintenance"
	InstallationUpdating     InstallationState = "updating"
	InstallationDegraded     InstallationState = "degraded"
	InstallationRecovery     InstallationState = "recovery_required"
	InstallationQuarantined  InstallationState = "quarantined"
	InstallationRemoving     InstallationState = "removing"
	InstallationRemoved      InstallationState = "removed"
	InstallationFailed       InstallationState = "failed"
)

func validInstallationTransition(from, to InstallationState) bool {
	switch from {
	case InstallationPending:
		return to == InstallationInstalling || to == InstallationRemoved || to == InstallationFailed
	case InstallationInstalling:
		return to == InstallationActive || to == InstallationFailed || to == InstallationRecovery
	case InstallationActive:
		return to == InstallationMaintenance || to == InstallationUpdating || to == InstallationDegraded || to == InstallationQuarantined || to == InstallationRemoving
	case InstallationMaintenance:
		return to == InstallationActive || to == InstallationUpdating || to == InstallationQuarantined || to == InstallationRemoving || to == InstallationFailed
	case InstallationUpdating:
		return to == InstallationActive || to == InstallationDegraded || to == InstallationRecovery || to == InstallationFailed
	case InstallationDegraded:
		return to == InstallationActive || to == InstallationMaintenance || to == InstallationUpdating || to == InstallationRecovery || to == InstallationQuarantined || to == InstallationRemoving
	case InstallationRecovery:
		return to == InstallationActive || to == InstallationDegraded || to == InstallationQuarantined || to == InstallationRemoving
	case InstallationQuarantined:
		return to == InstallationActive || to == InstallationRemoving
	case InstallationRemoving:
		return to == InstallationRemoved || to == InstallationFailed
	case InstallationFailed:
		return to == InstallationPending || to == InstallationRecovery || to == InstallationQuarantined || to == InstallationRemoving
	default:
		return false
	}
}

type HealthState string

const (
	HealthUnknown HealthState = "unknown"
	HealthHealthy HealthState = "healthy"
	HealthDegraded HealthState = "degraded"
	HealthUnhealthy HealthState = "unhealthy"
)

type HealthObservation struct {
	State            HealthState `json:"state"`
	CheckedAt        time.Time `json:"checked_at"`
	DefinitionDigest string `json:"definition_digest"`
	ReleaseDigest    string `json:"release_digest"`
	ProbeReceipts    []ProbeReceipt `json:"probe_receipts"`
	Summary          string `json:"summary,omitempty"`
}

type ProbeReceipt struct {
	Name       string `json:"name"`
	Passed     bool `json:"passed"`
	Digest     string `json:"digest"`
	Duration   time.Duration `json:"duration"`
	ObservedAt time.Time `json:"observed_at"`
}

type ApplicationInstallation struct {
	ID                InstallationID `json:"id"`
	TenantID          TenantID `json:"tenant_id"`
	ProjectID         ProjectID `json:"project_id,omitempty"`
	SiteID            SiteID `json:"site_id"`
	SiteUID           SiteUID `json:"site_uid"`
	DefinitionID      DefinitionID `json:"definition_id"`
	Recipe            RecipeReference `json:"recipe"`
	Kind              ApplicationKind `json:"kind"`
	Root              RelativePath `json:"root"`
	RuntimeID         string `json:"runtime_id"`
	DatabaseBindingID DatabaseBindingID `json:"database_binding_id,omitempty"`
	SecretRefs        []SecretRef `json:"secret_refs,omitempty"`
	StorageMode       StorageMode `json:"storage_mode"`
	State             InstallationState `json:"state"`
	ActiveReleaseID   ReleaseID `json:"active_release_id,omitempty"`
	PreviousReleaseID ReleaseID `json:"previous_release_id,omitempty"`
	Health            HealthObservation `json:"health"`
	Generation        uint64 `json:"generation"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (installation ApplicationInstallation) Validate(now time.Time) error {
	for kind, value := range map[string]string{
		"installation": string(installation.ID), "tenant": string(installation.TenantID), "site": string(installation.SiteID), "definition": string(installation.DefinitionID),
	} {
		if err := requireID(kind, value); err != nil { return err }
	}
	if installation.ProjectID != "" { if err := requireID("project", string(installation.ProjectID)); err != nil { return err } }
	if installation.SiteUID < 1000 || !installation.Kind.Valid() || installation.Generation == 0 || installation.CreatedAt.IsZero() || installation.UpdatedAt.IsZero() || strings.TrimSpace(installation.RuntimeID) == "" {
		return fmt.Errorf("%w: installation identity", ErrInvalid)
	}
	if installation.Recipe.DefinitionID != installation.DefinitionID || installation.StorageMode != StorageManagedRelease && installation.StorageMode != StorageMutableTree {
		return fmt.Errorf("%w: installation recipe", ErrInvalid)
	}
	if err := installation.Recipe.Validate(installation.CreatedAt); err != nil { return err }
	switch installation.State {
	case InstallationPending, InstallationInstalling, InstallationActive, InstallationMaintenance, InstallationUpdating, InstallationDegraded, InstallationRecovery, InstallationQuarantined, InstallationRemoving, InstallationRemoved, InstallationFailed:
	default: return fmt.Errorf("%w: installation state", ErrInvalid)
	}
	return nil
}

func (installation *ApplicationInstallation) Transition(next InstallationState, now time.Time) error {
	if !validInstallationTransition(installation.State, next) {
		return fmt.Errorf("%w: %s to %s", ErrInvalidTransition, installation.State, next)
	}
	installation.State = next
	installation.Generation++
	installation.UpdatedAt = now.UTC()
	return nil
}

type ComponentKind string

const (
	ComponentCore    ComponentKind = "core"
	ComponentPlugin  ComponentKind = "plugin"
	ComponentTheme   ComponentKind = "theme"
	ComponentModule  ComponentKind = "module"
	ComponentPackage ComponentKind = "package"
)

type ComponentState string

const (
	ComponentInstalled ComponentState = "installed"
	ComponentActive ComponentState = "active"
	ComponentInactive ComponentState = "inactive"
	ComponentDisabled ComponentState = "disabled"
	ComponentBroken ComponentState = "broken"
)

type Component struct {
	Kind          ComponentKind `json:"kind"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Digest        string `json:"digest"`
	State         ComponentState `json:"state"`
	UpdateVersion string `json:"update_version,omitempty"`
	UpdateDigest  string `json:"update_digest,omitempty"`
	Origin        string `json:"origin"`
	Automatic     bool `json:"automatic"`
}

func (component Component) Validate() error {
	if !componentNamePattern.MatchString(component.Name) || !versionPattern.MatchString(component.Version) || !validDigest(component.Digest) {
		return fmt.Errorf("%w: component", ErrInvalid)
	}
	if component.UpdateVersion != "" && (!versionPattern.MatchString(component.UpdateVersion) || !validDigest(component.UpdateDigest)) {
		return fmt.Errorf("%w: component update", ErrInvalid)
	}
	return nil
}

type ComponentInventory struct {
	InstallationID InstallationID `json:"installation_id"`
	Generation     uint64 `json:"generation"`
	ObservedAt     time.Time `json:"observed_at"`
	SourceDigest   string `json:"source_digest"`
	Components     []Component `json:"components"`
}

func (inventory ComponentInventory) Validate() error {
	if err := requireID("installation", string(inventory.InstallationID)); err != nil { return err }
	if inventory.Generation == 0 || inventory.ObservedAt.IsZero() || !validDigest(inventory.SourceDigest) {
		return fmt.Errorf("%w: inventory metadata", ErrInvalid)
	}
	seen := map[string]struct{}{}
	for _, component := range inventory.Components {
		if err := component.Validate(); err != nil { return err }
		key := string(component.Kind) + ":" + component.Name
		if _, exists := seen[key]; exists { return fmt.Errorf("%w: duplicate component", ErrInvalid) }
		seen[key] = struct{}{}
	}
	return nil
}

func (inventory ComponentInventory) CanonicalDigest() (string, error) {
	components := append([]Component(nil), inventory.Components...)
	sort.Slice(components, func(i, j int) bool {
		if components[i].Kind == components[j].Kind { return components[i].Name < components[j].Name }
		return components[i].Kind < components[j].Kind
	})
	payload, err := json.Marshal(components)
	if err != nil { return "", err }
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

type UpdateChannel string

const (
	UpdateSecurity UpdateChannel = "security"
	UpdateMinor UpdateChannel = "minor"
	UpdateMajor UpdateChannel = "major"
	UpdatePinned UpdateChannel = "pinned"
)

type FailurePolicy string

const (
	FailureRollback FailurePolicy = "rollback"
	FailurePause    FailurePolicy = "pause_automatic_updates"
	FailureRecover  FailurePolicy = "recovery_required"
)

type MaintenanceWindow struct {
	Timezone string `json:"timezone"`
	Weekdays []time.Weekday `json:"weekdays"`
	StartMinute uint16 `json:"start_minute"`
	DurationMinutes uint16 `json:"duration_minutes"`
}

type UpdatePolicy struct {
	ID             UpdatePolicyID `json:"id"`
	InstallationID InstallationID `json:"installation_id"`
	Channel        UpdateChannel `json:"channel"`
	AutomaticCore  bool `json:"automatic_core"`
	AutomaticPlugins []string `json:"automatic_plugins,omitempty"`
	AutomaticThemes  []string `json:"automatic_themes,omitempty"`
	Exclusions       []string `json:"exclusions,omitempty"`
	Maintenance      MaintenanceWindow `json:"maintenance"`
	Failure          FailurePolicy `json:"failure_policy"`
	FailureLimit     uint8 `json:"failure_limit"`
	ConsecutiveFailures uint8 `json:"consecutive_failures"`
	PausedUntil      time.Time `json:"paused_until,omitempty"`
	Generation       uint64 `json:"generation"`
}

func (policy UpdatePolicy) Validate() error {
	if err := requireID("update policy", string(policy.ID)); err != nil { return err }
	if err := requireID("installation", string(policy.InstallationID)); err != nil { return err }
	if policy.Generation == 0 || policy.FailureLimit == 0 || policy.Maintenance.DurationMinutes == 0 || policy.Maintenance.DurationMinutes > 1440 || policy.Maintenance.StartMinute >= 1440 || strings.TrimSpace(policy.Maintenance.Timezone) == "" {
		return fmt.Errorf("%w: update policy", ErrInvalid)
	}
	return nil
}

type DeploymentState string

const (
	DeploymentAdmitted       DeploymentState = "admitted"
	DeploymentRecovering     DeploymentState = "creating_recovery_point"
	DeploymentPrepared       DeploymentState = "prepared"
	DeploymentUpdating       DeploymentState = "updating"
	DeploymentProbing        DeploymentState = "probing"
	DeploymentPromoting      DeploymentState = "promoting"
	DeploymentCommitted      DeploymentState = "committed"
	DeploymentRollingBack    DeploymentState = "rolling_back"
	DeploymentRolledBack     DeploymentState = "rolled_back"
	DeploymentRecoveryNeeded DeploymentState = "recovery_required"
	DeploymentFailed         DeploymentState = "failed"
)

type Release struct {
	ID             ReleaseID `json:"id"`
	InstallationID InstallationID `json:"installation_id"`
	ProductVersion string `json:"product_version"`
	ContentDigest  string `json:"content_digest"`
	RecipeDigest   string `json:"recipe_digest"`
	SnapshotID     SnapshotID `json:"snapshot_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	PromotedAt     time.Time `json:"promoted_at,omitempty"`
	RetainedUntil  time.Time `json:"retained_until,omitempty"`
}

type Deployment struct {
	ID                DeploymentID `json:"id"`
	CommandID         CommandID `json:"command_id"`
	InstallationID    InstallationID `json:"installation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	FromReleaseID     ReleaseID `json:"from_release_id,omitempty"`
	TargetRelease     Release `json:"target_release"`
	RecoveryPointID   RecoveryPointID `json:"recovery_point_id,omitempty"`
	SnapshotID        SnapshotID `json:"snapshot_id,omitempty"`
	State             DeploymentState `json:"state"`
	WriteFrontier     uint64 `json:"write_frontier"`
	Irreversible      bool `json:"irreversible"`
	Failure           string `json:"failure,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type SyncScope string

const (
	SyncEverything SyncScope = "everything"
	SyncFiles      SyncScope = "files"
	SyncDatabase   SyncScope = "database"
	SyncUploads    SyncScope = "uploads"
	SyncSelected   SyncScope = "selected"
)

type Selection struct {
	Paths          []RelativePath `json:"paths,omitempty"`
	DatabaseTables []string `json:"database_tables,omitempty"`
	Components     []string `json:"components,omitempty"`
	IncludeUploads bool `json:"include_uploads"`
	RewriteIdentity bool `json:"rewrite_identity"`
}

type StagingRelation struct {
	ID                    StagingRelationID `json:"id"`
	SourceInstallationID  InstallationID `json:"source_installation_id"`
	TargetInstallationID  InstallationID `json:"target_installation_id"`
	SourceSiteID          SiteID `json:"source_site_id"`
	TargetSiteID          SiteID `json:"target_site_id"`
	MailSuppressed        bool `json:"mail_suppressed"`
	ExternalActionsDenied bool `json:"external_actions_denied"`
	AccessPolicyID        string `json:"access_policy_id"`
	Generation            uint64 `json:"generation"`
	CreatedAt             time.Time `json:"created_at"`
}

func (relation StagingRelation) Validate() error {
	if err := requireID("staging relation", string(relation.ID)); err != nil { return err }
	if err := requireID("source installation", string(relation.SourceInstallationID)); err != nil { return err }
	if err := requireID("target installation", string(relation.TargetInstallationID)); err != nil { return err }
	if err := requireID("source site", string(relation.SourceSiteID)); err != nil { return err }
	if err := requireID("target site", string(relation.TargetSiteID)); err != nil { return err }
	if relation.SourceInstallationID == relation.TargetInstallationID || relation.SourceSiteID == relation.TargetSiteID || !relation.MailSuppressed || !relation.ExternalActionsDenied || !validWebAccessPolicyID(relation.AccessPolicyID) || relation.Generation == 0 || relation.CreatedAt.IsZero() {
		return fmt.Errorf("%w: staging relation", ErrInvalid)
	}
	return nil
}

type SyncDirection string

const (
	SyncPushToTarget SyncDirection = "push_to_target"
	SyncPullToSource SyncDirection = "pull_to_source"
)

type SyncState string

const (
	SyncAdmitted SyncState = "admitted"
	SyncSnapshotting SyncState = "snapshotting"
	SyncTransforming SyncState = "transforming"
	SyncApplying SyncState = "applying"
	SyncProbing SyncState = "probing"
	SyncCommitted SyncState = "committed"
	SyncRollingBack SyncState = "rolling_back"
	SyncRolledBack SyncState = "rolled_back"
	SyncRecoveryNeeded SyncState = "recovery_required"
	SyncFailed SyncState = "failed"
)

type StagingSync struct {
	ID                 SyncID `json:"id"`
	CommandID          CommandID `json:"command_id"`
	RelationID         StagingRelationID `json:"relation_id"`
	Direction          SyncDirection `json:"direction"`
	Scope              SyncScope `json:"scope"`
	Selection          Selection `json:"selection"`
	ExpectedSourceGeneration uint64 `json:"expected_source_generation"`
	ExpectedTargetGeneration uint64 `json:"expected_target_generation"`
	SourceSnapshotID   SnapshotID `json:"source_snapshot_id,omitempty"`
	TargetRecoveryPointID RecoveryPointID `json:"target_recovery_point_id,omitempty"`
	WriteFrontier      uint64 `json:"write_frontier"`
	State              SyncState `json:"state"`
	Failure            string `json:"failure,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func (sync StagingSync) Validate() error {
	if err := requireID("sync", string(sync.ID)); err != nil { return err }
	if err := requireID("command", string(sync.CommandID)); err != nil { return err }
	if err := requireID("staging relation", string(sync.RelationID)); err != nil { return err }
	if sync.ExpectedSourceGeneration == 0 || sync.ExpectedTargetGeneration == 0 || sync.Direction != SyncPushToTarget && sync.Direction != SyncPullToSource || sync.State == "" || sync.CreatedAt.IsZero() || sync.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: staging sync", ErrInvalid)
	}
	return nil
}

type DiscoveryCandidate struct {
	Kind            ApplicationKind `json:"kind"`
	Root            RelativePath `json:"root"`
	Version         string `json:"version"`
	RuntimeID       string `json:"runtime_id"`
	DatabaseReachable bool `json:"database_reachable"`
	OwnershipValid  bool `json:"ownership_valid"`
	EvidenceDigest  string `json:"evidence_digest"`
}

type CloneRelationship struct {
	ID                   ID `json:"id"`
	SourceInstallationID InstallationID `json:"source_installation_id"`
	TargetInstallationID InstallationID `json:"target_installation_id"`
	SourceIdentity       string `json:"source_identity"`
	TargetIdentity       string `json:"target_identity"`
	CreatedAt            time.Time `json:"created_at"`
	LastSynchronizedAt   time.Time `json:"last_synchronized_at,omitempty"`
}

type OperationState string

const (
	OperationAdmitted OperationState = "admitted"
	OperationExecuting OperationState = "executing"
	OperationCompensating OperationState = "compensating"
	OperationCommitted OperationState = "committed"
	OperationFailed OperationState = "failed"
	OperationCompensated OperationState = "compensated"
	OperationRecoveryRequired OperationState = "recovery_required"
)

type Operation struct {
	CommandID      CommandID `json:"command_id"`
	Kind           string `json:"kind"`
	TenantID       TenantID `json:"tenant_id"`
	SiteID         SiteID `json:"site_id"`
	InstallationID InstallationID `json:"installation_id,omitempty"`
	RequestDigest  string `json:"request_digest"`
	State          OperationState `json:"state"`
	Stage          string `json:"stage"`
	ResultDigest   string `json:"result_digest,omitempty"`
	Failure        string `json:"failure,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type ApplicationEvent struct {
	ID             ID `json:"id"`
	TenantID       TenantID `json:"tenant_id"`
	SiteID         SiteID `json:"site_id"`
	InstallationID InstallationID `json:"installation_id,omitempty"`
	CommandID      CommandID `json:"command_id,omitempty"`
	Kind           string `json:"kind"`
	Severity       string `json:"severity"`
	ResourceGeneration uint64 `json:"resource_generation,omitempty"`
	PayloadDigest  string `json:"payload_digest"`
	OccurredAt     time.Time `json:"occurred_at"`
}

type ApplicationEventSink interface {
	PublishApplicationEvent(context.Context, ApplicationEvent) error
}

func (operation Operation) Validate() error {
	if err := requireID("command", string(operation.CommandID)); err != nil { return err }
	if err := requireID("tenant", string(operation.TenantID)); err != nil { return err }
	if err := requireID("site", string(operation.SiteID)); err != nil { return err }
	if operation.InstallationID != "" { if err := requireID("installation", string(operation.InstallationID)); err != nil { return err } }
	if !validDigest(operation.RequestDigest) || operation.Kind == "" || operation.State == "" || operation.CreatedAt.IsZero() || operation.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: operation", ErrInvalid)
	}
	return nil
}

func requestDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil { return "", err }
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
