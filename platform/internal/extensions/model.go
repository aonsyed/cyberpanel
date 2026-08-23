// Package extensions defines the signed, capability-scoped extension control
// plane. It deliberately contains no WASM engine, OCI engine, shell, host
// filesystem, host socket, or credential-material primitive.
package extensions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid      = errors.New("extensions: invalid value")
	ErrNotFound     = errors.New("extensions: not found")
	ErrConflict     = errors.New("extensions: conflict")
	ErrStale        = errors.New("extensions: stale generation")
	ErrForbidden    = errors.New("extensions: forbidden capability")
	ErrUntrusted    = errors.New("extensions: untrusted release")
	ErrIncompatible = errors.New("extensions: incompatible panel contract")
	ErrDowngrade    = errors.New("extensions: downgrade requires rollback")
	ErrAmbiguous    = errors.New("extensions: runtime outcome ambiguous")
	ErrIntegrity    = errors.New("extensions: stored state integrity failure")
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,95}$`)
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type ExtensionID string
type ReleaseID string
type CommandID string

func validID(value string) bool { return idPattern.MatchString(value) }
func validDigest(value string) bool { return digestPattern.MatchString(value) }

type Version struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
	Patch uint32 `json:"patch"`
}

func (version Version) Valid() bool { return version.Major > 0 }
func (version Version) Compare(other Version) int {
	if version.Major != other.Major { if version.Major < other.Major { return -1 }; return 1 }
	if version.Minor != other.Minor { if version.Minor < other.Minor { return -1 }; return 1 }
	if version.Patch != other.Patch { if version.Patch < other.Patch { return -1 }; return 1 }
	return 0
}

type ContractVersion struct {
	Major uint16 `json:"major"`
	Minor uint16 `json:"minor"`
}

func (version ContractVersion) Valid() bool { return version.Major > 0 }
func (version ContractVersion) Compare(other ContractVersion) int {
	if version.Major != other.Major { if version.Major < other.Major { return -1 }; return 1 }
	if version.Minor != other.Minor { if version.Minor < other.Minor { return -1 }; return 1 }
	return 0
}

type ExecutionKind string

const (
	ExecutionWASM        ExecutionKind = "wasm"
	ExecutionRootlessOCI ExecutionKind = "rootless_oci"
)

type WASMExecution struct {
	ModuleDigest     string `json:"module_digest"`
	InterfaceVersion uint16 `json:"interface_version"`
	MaximumMemory    uint64 `json:"maximum_memory_bytes"`
	MaximumFuel      uint64 `json:"maximum_fuel"`
}

func (execution WASMExecution) Validate() error {
	if !validDigest(execution.ModuleDigest) || execution.InterfaceVersion == 0 || execution.MaximumMemory < 1<<20 ||
		execution.MaximumMemory > 1<<30 || execution.MaximumFuel == 0 || execution.MaximumFuel > 1_000_000_000_000 {
		return ErrInvalid
	}
	return nil
}

type RootlessOCIExecution struct {
	ImageDigest        string `json:"image_digest"`
	Platform           string `json:"platform"`
	UID                uint32 `json:"uid"`
	GID                uint32 `json:"gid"`
	ReadOnlyRoot       bool   `json:"read_only_root"`
	NoNewPrivileges    bool   `json:"no_new_privileges"`
	DropAllCapabilities bool  `json:"drop_all_capabilities"`
	Privileged         bool   `json:"privileged"`
	HostNetwork        bool   `json:"host_network"`
	HostPID            bool   `json:"host_pid"`
	HostIPC            bool   `json:"host_ipc"`
	HostSockets        []string `json:"host_sockets,omitempty"`
}

func (execution RootlessOCIExecution) Validate() error {
	if !validDigest(execution.ImageDigest) || execution.Platform != "linux/amd64" && execution.Platform != "linux/arm64" ||
		execution.UID == 0 || execution.GID == 0 || !execution.ReadOnlyRoot || !execution.NoNewPrivileges ||
		!execution.DropAllCapabilities || execution.Privileged || execution.HostNetwork || execution.HostPID || execution.HostIPC || len(execution.HostSockets) != 0 {
		return ErrForbidden
	}
	return nil
}

type Permission string

const (
	PermissionApplicationInstall Permission = "application:install"
	PermissionApplicationManage  Permission = "application:manage"
	PermissionApplicationUpdate  Permission = "application:update"
	PermissionAuditRead          Permission = "audit:read"
	PermissionBackupCreate       Permission = "backup:create"
	PermissionCertificateManage Permission = "certificate:manage"
	PermissionContainerManage    Permission = "container:manage"
	PermissionDatabaseConsole   Permission = "database:console"
	PermissionDatabaseCreate    Permission = "database:create"
	PermissionDatabaseManage    Permission = "database:manage"
	PermissionDNSManage         Permission = "dns:manage"
	PermissionFileRead          Permission = "file:read"
	PermissionFileWrite         Permission = "file:write"
	PermissionMailManage        Permission = "mail:manage"
	PermissionOperationsObserve Permission = "operations:observe"
	PermissionSiteCreate        Permission = "site:create"
	PermissionSiteManage        Permission = "site:manage"
)

var ordinaryPermissionRegistry = map[Permission]struct{}{
	PermissionApplicationInstall: {}, PermissionApplicationManage: {}, PermissionApplicationUpdate: {}, PermissionAuditRead: {},
	PermissionBackupCreate: {}, PermissionCertificateManage: {}, PermissionContainerManage: {}, PermissionDatabaseConsole: {},
	PermissionDatabaseCreate: {}, PermissionDatabaseManage: {}, PermissionDNSManage: {}, PermissionFileRead: {}, PermissionFileWrite: {},
	PermissionMailManage: {}, PermissionOperationsObserve: {}, PermissionSiteCreate: {}, PermissionSiteManage: {},
}

func OrdinaryPermissions() []Permission {
	permissions := make([]Permission, 0, len(ordinaryPermissionRegistry))
	for permission := range ordinaryPermissionRegistry { permissions = append(permissions, permission) }
	sort.Slice(permissions, func(i, j int) bool { return permissions[i] < permissions[j] })
	return permissions
}

type CapabilityScope string

const (
	ScopeInstallation CapabilityScope = "installation"
	ScopeTenant       CapabilityScope = "tenant"
	ScopeSite         CapabilityScope = "site"
	ScopeResource     CapabilityScope = "resource"
)

type CapabilityRequest struct {
	Permission Permission      `json:"permission"`
	APIVersion string          `json:"api_version"`
	Scope      CapabilityScope `json:"scope"`
}

func (request CapabilityRequest) Validate() error {
	if _, ok := ordinaryPermissionRegistry[request.Permission]; !ok { return ErrForbidden }
	if request.APIVersion != "panel.cyberpanel.io/v1" { return ErrIncompatible }
	switch request.Scope { case ScopeInstallation, ScopeTenant, ScopeSite, ScopeResource: return nil; default: return ErrInvalid }
}

type HostCall string

const (
	HostCallAPIInvoke     HostCall = "api.invoke"
	HostCallEventEmit     HostCall = "event.emit"
	HostCallStateRead     HostCall = "state.read"
	HostCallStateWrite    HostCall = "state.write"
	HostCallTelemetryEmit HostCall = "telemetry.emit"
	HostCallClockRead     HostCall = "clock.read"
)

func validHostCall(call HostCall) bool {
	switch call { case HostCallAPIInvoke, HostCallEventEmit, HostCallStateRead, HostCallStateWrite, HostCallTelemetryEmit, HostCallClockRead: return true; default: return false }
}

type DataMode string
type DataScope string

const (
	DataRead      DataMode = "read"
	DataReadWrite DataMode = "read_write"
	DataInstallation DataScope = "installation"
	DataTenant       DataScope = "tenant"
	DataSite         DataScope = "site"
)

type DataDeclaration struct {
	Class string    `json:"class"`
	Mode  DataMode  `json:"mode"`
	Scope DataScope `json:"scope"`
}

func (declaration DataDeclaration) Validate() error {
	if !namePattern.MatchString(declaration.Class) || declaration.Mode != DataRead && declaration.Mode != DataReadWrite ||
		declaration.Scope != DataInstallation && declaration.Scope != DataTenant && declaration.Scope != DataSite { return ErrInvalid }
	return nil
}

type EgressDeclaration struct {
	Origin  string   `json:"origin"`
	Methods []string `json:"methods"`
}

func (declaration EgressDeclaration) Validate() error {
	parsed, err := url.Parse(declaration.Origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return ErrForbidden
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") { return ErrForbidden }
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && (address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast()) { return ErrForbidden }
	if len(declaration.Methods) == 0 || len(declaration.Methods) > 5 { return ErrInvalid }
	previous := ""
	for _, method := range declaration.Methods {
		if method != "DELETE" && method != "GET" && method != "PATCH" && method != "POST" && method != "PUT" || method <= previous { return ErrInvalid }
		previous = method
	}
	return nil
}

type HealthDeclaration struct {
	Kind     string        `json:"kind"`
	Path     string        `json:"path,omitempty"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Failures uint8         `json:"failures"`
}

func (health HealthDeclaration) Validate(kind ExecutionKind) error {
	if health.Interval < time.Second || health.Interval > 10*time.Minute || health.Timeout <= 0 || health.Timeout >= health.Interval || health.Failures == 0 { return ErrInvalid }
	if kind == ExecutionWASM { if health.Kind != "host_call" || health.Path != "" { return ErrForbidden }; return nil }
	if kind == ExecutionRootlessOCI && health.Kind == "http" && strings.HasPrefix(health.Path, "/") && !strings.Contains(health.Path, "..") { return nil }
	return ErrForbidden
}

type TelemetryDeclaration struct {
	Metrics          []string `json:"metrics,omitempty"`
	Logs             []string `json:"logs,omitempty"`
	Traces           []string `json:"traces,omitempty"`
	MaximumPerMinute uint32   `json:"maximum_per_minute"`
}

func (telemetry TelemetryDeclaration) Validate() error {
	if telemetry.MaximumPerMinute == 0 || telemetry.MaximumPerMinute > 100000 { return ErrInvalid }
	for _, values := range [][]string{telemetry.Metrics, telemetry.Logs, telemetry.Traces} {
		if len(values) > 128 { return ErrInvalid }
		previous := ""
		for _, value := range values { if !namePattern.MatchString(value) || value <= previous { return ErrInvalid }; previous = value }
	}
	return nil
}

type OwnedDataClass struct {
	Name       string    `json:"name"`
	Scope      DataScope `json:"scope"`
	Backup     bool      `json:"backup"`
	Migratable bool      `json:"migratable"`
}

func (class OwnedDataClass) Validate() error {
	if !namePattern.MatchString(class.Name) || class.Scope != DataInstallation && class.Scope != DataTenant && class.Scope != DataSite { return ErrInvalid }
	return nil
}

type BackupDeclaration struct {
	Consistency string   `json:"consistency"`
	DataClasses []string `json:"data_classes,omitempty"`
}

type MigrationDeclaration struct {
	SchemaVersion uint32   `json:"schema_version"`
	Strategy      string   `json:"strategy"`
	DataClasses   []string `json:"data_classes,omitempty"`
}

type ExtensionManifest struct {
	SchemaVersion   uint32               `json:"schema_version"`
	ID              ExtensionID          `json:"id"`
	Version         Version              `json:"version"`
	Digest          string               `json:"digest"`
	DisplayName     string               `json:"display_name"`
	Publisher       string               `json:"publisher"`
	MinimumContract ContractVersion      `json:"minimum_contract"`
	MaximumContract ContractVersion      `json:"maximum_contract"`
	Execution       ExecutionKind        `json:"execution"`
	WASM            *WASMExecution       `json:"wasm,omitempty"`
	RootlessOCI     *RootlessOCIExecution `json:"rootless_oci,omitempty"`
	Capabilities    []CapabilityRequest  `json:"capabilities"`
	HostCalls       []HostCall            `json:"host_calls"`
	DataAccess      []DataDeclaration     `json:"data_access,omitempty"`
	Egress          []EgressDeclaration  `json:"egress,omitempty"`
	Health          HealthDeclaration     `json:"health"`
	Telemetry       TelemetryDeclaration  `json:"telemetry"`
	OwnedData       []OwnedDataClass      `json:"owned_data,omitempty"`
	Backup          BackupDeclaration     `json:"backup"`
	Migration       MigrationDeclaration  `json:"migration"`
}

func (manifest ExtensionManifest) Validate() error {
	if manifest.SchemaVersion != 1 || !validID(string(manifest.ID)) || !manifest.Version.Valid() || !validDigest(manifest.Digest) ||
		strings.TrimSpace(manifest.DisplayName) == "" || len(manifest.DisplayName) > 128 || !namePattern.MatchString(manifest.Publisher) ||
		!manifest.MinimumContract.Valid() || !manifest.MaximumContract.Valid() || manifest.MinimumContract.Compare(manifest.MaximumContract) > 0 {
		return ErrInvalid
	}
	switch manifest.Execution {
	case ExecutionWASM:
		if manifest.WASM == nil || manifest.RootlessOCI != nil || manifest.WASM.Validate() != nil { return ErrForbidden }
	case ExecutionRootlessOCI:
		if manifest.WASM != nil || manifest.RootlessOCI == nil || manifest.RootlessOCI.Validate() != nil { return ErrForbidden }
	default:
		return ErrInvalid
	}
	if len(manifest.Capabilities) > 128 || len(manifest.HostCalls) == 0 || len(manifest.HostCalls) > 16 || len(manifest.DataAccess) > 128 || len(manifest.Egress) > 64 || len(manifest.OwnedData) > 128 { return ErrInvalid }
	for index, capability := range manifest.Capabilities { if capability.Validate() != nil || index > 0 && capabilityKey(manifest.Capabilities[index-1]) >= capabilityKey(capability) { return ErrForbidden } }
	for index, call := range manifest.HostCalls { if !validHostCall(call) || index > 0 && manifest.HostCalls[index-1] >= call { return ErrForbidden } }
	for index, declaration := range manifest.DataAccess { if declaration.Validate() != nil || index > 0 && dataKey(manifest.DataAccess[index-1]) >= dataKey(declaration) { return ErrInvalid } }
	for index, declaration := range manifest.Egress { if declaration.Validate() != nil || index > 0 && manifest.Egress[index-1].Origin >= declaration.Origin { return ErrForbidden } }
	if manifest.Health.Validate(manifest.Execution) != nil || manifest.Telemetry.Validate() != nil { return ErrInvalid }
	owned := map[string]OwnedDataClass{}
	for index, class := range manifest.OwnedData { if class.Validate() != nil || index > 0 && manifest.OwnedData[index-1].Name >= class.Name { return ErrInvalid }; owned[class.Name] = class }
	if manifest.Backup.Consistency != "none" && manifest.Backup.Consistency != "crash_consistent" && manifest.Backup.Consistency != "application_consistent" { return ErrInvalid }
	if !validClassList(manifest.Backup.DataClasses, owned, func(class OwnedDataClass) bool { return class.Backup }) { return ErrInvalid }
	if manifest.Migration.SchemaVersion == 0 || manifest.Migration.Strategy != "none" && manifest.Migration.Strategy != "runtime_host_call" ||
		!validClassList(manifest.Migration.DataClasses, owned, func(class OwnedDataClass) bool { return class.Migratable }) { return ErrInvalid }
	if digestExtensionManifest(manifest) != manifest.Digest { return ErrIntegrity }
	return nil
}

func validClassList(values []string, owned map[string]OwnedDataClass, allowed func(OwnedDataClass) bool) bool {
	previous := ""
	for _, value := range values { class, ok := owned[value]; if !ok || !allowed(class) || value <= previous { return false }; previous = value }
	return true
}

func capabilityKey(value CapabilityRequest) string { return string(value.Permission) + "\x00" + value.APIVersion + "\x00" + string(value.Scope) }
func dataKey(value DataDeclaration) string { return value.Class + "\x00" + string(value.Scope) + "\x00" + string(value.Mode) }

type ExtensionRelease struct {
	ID               ReleaseID        `json:"id"`
	ExtensionID      ExtensionID      `json:"extension_id"`
	Version          Version          `json:"version"`
	Digest           string           `json:"digest"`
	ArtifactDigest   string           `json:"artifact_digest"`
	SBOMDigest       string           `json:"sbom_digest"`
	ProvenanceDigest string           `json:"provenance_digest"`
	SigningKeyID     string           `json:"signing_key_id"`
	Signature        string           `json:"signature"`
	PublishedAt      time.Time        `json:"published_at"`
	DeprecatedAt     *time.Time       `json:"deprecated_at,omitempty"`
	Manifest         ExtensionManifest `json:"manifest"`
}

func (release ExtensionRelease) Validate() error {
	if !validID(string(release.ID)) || !validID(string(release.ExtensionID)) || !release.Version.Valid() || !validDigest(release.Digest) ||
		!validDigest(release.ArtifactDigest) || !validDigest(release.SBOMDigest) || !validDigest(release.ProvenanceDigest) ||
		!namePattern.MatchString(release.SigningKeyID) || release.Signature == "" || release.PublishedAt.IsZero() || release.Manifest.Validate() != nil ||
		release.Manifest.ID != release.ExtensionID || release.Manifest.Version != release.Version || release.DeprecatedAt != nil && release.DeprecatedAt.Before(release.PublishedAt) {
		return ErrInvalid
	}
	if digestExtensionRelease(release) != release.Digest { return ErrIntegrity }
	return nil
}

type InstallationState string

const (
	StateInstalled   InstallationState = "installed"
	StateEnabled     InstallationState = "enabled"
	StateSuspended   InstallationState = "suspended"
	StateDisabled    InstallationState = "disabled"
	StateDegraded    InstallationState = "degraded"
	StateUninstalled InstallationState = "uninstalled"
)

type DataPolicy string

const (
	DataPreserve DataPolicy = "preserve"
	DataDelete   DataPolicy = "delete"
)

type HealthState string

const (
	HealthUnknown     HealthState = "unknown"
	HealthHealthy     HealthState = "healthy"
	HealthDegraded    HealthState = "degraded"
	HealthUnavailable HealthState = "unavailable"
)

type HealthObservation struct {
	State      HealthState `json:"state"`
	Reason     string      `json:"reason,omitempty"`
	CrashCount uint64      `json:"crash_count"`
	ObservedAt time.Time   `json:"observed_at"`
}

type ExtensionInstallation struct {
	ID                  ExtensionID          `json:"id"`
	Current             ExtensionRelease     `json:"current"`
	Previous            *ExtensionRelease    `json:"previous,omitempty"`
	GrantedCapabilities []CapabilityRequest  `json:"granted_capabilities"`
	Configuration       json.RawMessage      `json:"configuration"`
	ConfigurationDigest string               `json:"configuration_digest"`
	State               InstallationState    `json:"state"`
	DataPolicy          DataPolicy           `json:"data_policy"`
	RuntimeObjectIDs    []string             `json:"runtime_object_ids,omitempty"`
	Health              HealthObservation    `json:"health"`
	Generation          uint64               `json:"generation"`
	CreatedAt           time.Time            `json:"created_at"`
	UpdatedAt           time.Time            `json:"updated_at"`
	UninstalledAt       *time.Time           `json:"uninstalled_at,omitempty"`
}

func (installation ExtensionInstallation) Validate() error {
	if !validID(string(installation.ID)) || installation.Current.ExtensionID != installation.ID || installation.Current.Validate() != nil ||
		installation.Generation == 0 || installation.CreatedAt.IsZero() || installation.UpdatedAt.IsZero() || installation.UpdatedAt.Before(installation.CreatedAt) ||
		validateConfiguration(installation.Configuration) != nil || digestBytes(installation.Configuration) != installation.ConfigurationDigest ||
		!sameCapabilities(installation.GrantedCapabilities, installation.Current.Manifest.Capabilities) {
		return ErrInvalid
	}
	if installation.Previous != nil && (installation.Previous.ExtensionID != installation.ID || installation.Previous.Validate() != nil || installation.Previous.Digest == installation.Current.Digest) { return ErrInvalid }
	switch installation.State { case StateInstalled, StateEnabled, StateSuspended, StateDisabled, StateDegraded: if installation.UninstalledAt != nil { return ErrInvalid }; case StateUninstalled: if installation.UninstalledAt == nil || installation.DataPolicy != DataPreserve && installation.DataPolicy != DataDelete { return ErrInvalid }; default: return ErrInvalid }
	if installation.Health.State != HealthUnknown && installation.Health.State != HealthHealthy && installation.Health.State != HealthDegraded && installation.Health.State != HealthUnavailable { return ErrInvalid }
	previous := ""
	for _, id := range installation.RuntimeObjectIDs { if !validRuntimeID(id) || id <= previous { return ErrInvalid }; previous = id }
	return nil
}

func validRuntimeID(value string) bool { return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n\t /\\") }

type CapabilityApproval struct {
	ReleaseDigest string              `json:"release_digest"`
	Capabilities []CapabilityRequest `json:"capabilities"`
	ApprovedBy    string              `json:"approved_by"`
	ApprovedAt    time.Time           `json:"approved_at"`
	Digest        string              `json:"digest"`
}

func (approval CapabilityApproval) Validate(release ExtensionRelease, now time.Time) error {
	if approval.ReleaseDigest != release.Digest || !validID(approval.ApprovedBy) || approval.ApprovedAt.IsZero() || approval.ApprovedAt.After(now.Add(time.Minute)) ||
		approval.ApprovedAt.Before(now.Add(-24*time.Hour)) || !sameCapabilities(approval.Capabilities, release.Manifest.Capabilities) ||
		digestCapabilityApproval(approval) != approval.Digest { return ErrForbidden }
	return nil
}

func sameCapabilities(left, right []CapabilityRequest) bool {
	if len(left) != len(right) { return false }
	for index := range left { if left[index] != right[index] { return false } }
	return true
}

func capabilitiesExpanded(current, requested []CapabilityRequest) bool {
	existing := make(map[CapabilityRequest]struct{}, len(current))
	for _, capability := range current { existing[capability] = struct{}{} }
	for _, capability := range requested { if _, ok := existing[capability]; !ok { return true } }
	return false
}

func validateConfiguration(configuration json.RawMessage) error {
	if len(configuration) == 0 { configuration = json.RawMessage(`{}`) }
	if len(configuration) > 256<<10 || configuration[0] != '{' { return ErrInvalid }
	decoder := json.NewDecoder(bytes.NewReader(configuration))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF { return ErrInvalid }
	if forbiddenConfiguration(document) { return ErrForbidden }
	return nil
}

func forbiddenConfiguration(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(key)
			for _, denied := range []string{"credential", "password", "private_key", "root", "secret", "socket", "token"} { if strings.Contains(normalized, denied) { return true } }
			if forbiddenConfiguration(child) { return true }
		}
	case []any:
		for _, child := range typed { if forbiddenConfiguration(child) { return true } }
	}
	return false
}

func cloneRelease(release ExtensionRelease) ExtensionRelease {
	release.Manifest.Capabilities = append([]CapabilityRequest(nil), release.Manifest.Capabilities...)
	release.Manifest.HostCalls = append([]HostCall(nil), release.Manifest.HostCalls...)
	release.Manifest.DataAccess = append([]DataDeclaration(nil), release.Manifest.DataAccess...)
	release.Manifest.Egress = append([]EgressDeclaration(nil), release.Manifest.Egress...)
	for index := range release.Manifest.Egress { release.Manifest.Egress[index].Methods = append([]string(nil), release.Manifest.Egress[index].Methods...) }
	release.Manifest.OwnedData = append([]OwnedDataClass(nil), release.Manifest.OwnedData...)
	release.Manifest.Backup.DataClasses = append([]string(nil), release.Manifest.Backup.DataClasses...)
	release.Manifest.Migration.DataClasses = append([]string(nil), release.Manifest.Migration.DataClasses...)
	if release.Manifest.RootlessOCI != nil { copy := *release.Manifest.RootlessOCI; copy.HostSockets = append([]string(nil), copy.HostSockets...); release.Manifest.RootlessOCI = &copy }
	if release.Manifest.WASM != nil { copy := *release.Manifest.WASM; release.Manifest.WASM = &copy }
	return release
}

func cloneInstallation(installation ExtensionInstallation) ExtensionInstallation {
	installation.Current = cloneRelease(installation.Current)
	if installation.Previous != nil { copy := cloneRelease(*installation.Previous); installation.Previous = &copy }
	installation.GrantedCapabilities = append([]CapabilityRequest(nil), installation.GrantedCapabilities...)
	installation.Configuration = append(json.RawMessage(nil), installation.Configuration...)
	installation.RuntimeObjectIDs = append([]string(nil), installation.RuntimeObjectIDs...)
	return installation
}

func digestBytes(value []byte) string { sum := sha256.Sum256(value); return "sha256:" + hex.EncodeToString(sum[:]) }
func digestJSON(value any) string { content, _ := json.Marshal(value); return digestBytes(content) }
