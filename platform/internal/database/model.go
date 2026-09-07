// Package database defines canonical MariaDB resources and their durable
// command boundary. It intentionally exposes neither tenant-authored SQL nor
// process execution primitives.
package database

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

var (
	ErrInvalidResource    = errors.New("invalid database resource")
	ErrInvalidCommand     = errors.New("invalid database command")
	ErrUnauthorized       = errors.New("database command is not authorized")
	ErrNotFound           = errors.New("database resource not found")
	ErrConflict           = errors.New("database resource generation conflict")
	ErrIdempotency        = errors.New("database command ID was reused with another payload")
	ErrInvalidReceipt     = errors.New("invalid database operation receipt")
	ErrInvalidEffect      = errors.New("invalid MariaDB effect receipt")
	ErrAmbiguous          = errors.New("MariaDB effect outcome is ambiguous")
	ErrCompensationFailed = errors.New("MariaDB compensation could not be proven")
)

type ResourceID struct{ value string }
type SecretRef struct{ value string }
type SQLIdentifier struct{ value string }

func NewResourceID(raw string) (ResourceID, error) {
	value, err := parseOpaqueID(raw)
	return ResourceID{value: value}, err
}

func NewSecretRef(raw string) (SecretRef, error) {
	value, err := parseOpaqueID(raw)
	return SecretRef{value: value}, err
}

// ParseSQLIdentifier accepts a deliberately smaller subset than MariaDB. This
// makes identifiers safe to map through a privileged adapter without quoting
// rules becoming part of the public API.
func ParseSQLIdentifier(raw string) (SQLIdentifier, error) {
	if raw == "" || len(raw) > 64 || !asciiLetter(raw[0]) {
		return SQLIdentifier{}, errors.New("SQL identifier must start with an ASCII letter and contain at most 64 bytes")
	}
	for index := 1; index < len(raw); index++ {
		character := raw[index]
		if !asciiLetter(character) && !asciiDigit(character) && character != '_' {
			return SQLIdentifier{}, errors.New("SQL identifier contains an unsafe character")
		}
	}
	return SQLIdentifier{value: raw}, nil
}

func parseOpaqueID(raw string) (string, error) {
	if raw == "" || len(raw) > 128 || !asciiAlphaNumeric(raw[0]) || !asciiAlphaNumeric(raw[len(raw)-1]) {
		return "", errors.New("identifier must contain 1 through 128 safe ASCII characters")
	}
	for index := 0; index < len(raw); index++ {
		character := raw[index]
		if !asciiAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
			return "", errors.New("identifier contains an unsafe character")
		}
	}
	return raw, nil
}

func asciiLetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}
func asciiDigit(value byte) bool { return value >= '0' && value <= '9' }
func asciiAlphaNumeric(value byte) bool {
	return asciiLetter(value) || asciiDigit(value)
}

func (id ResourceID) String() string       { return id.value }
func (ref SecretRef) String() string       { return ref.value }
func (id SQLIdentifier) String() string    { return id.value }
func (id ResourceID) IsZero() bool         { return id.value == "" }
func (ref SecretRef) IsZero() bool         { return ref.value == "" }
func (id SQLIdentifier) IsZero() bool      { return id.value == "" }
func (id ResourceID) MarshalJSON() ([]byte, error) { return json.Marshal(id.value) }
func (ref SecretRef) MarshalJSON() ([]byte, error) { return json.Marshal(ref.value) }
func (id SQLIdentifier) MarshalJSON() ([]byte, error) { return json.Marshal(id.value) }
func (id *ResourceID) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil { return err }
	parsed, err := NewResourceID(raw)
	if err == nil { *id = parsed }
	return err
}
func (ref *SecretRef) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil { return err }
	parsed, err := NewSecretRef(raw)
	if err == nil { *ref = parsed }
	return err
}
func (id *SQLIdentifier) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil { return err }
	parsed, err := ParseSQLIdentifier(raw)
	if err == nil { *id = parsed }
	return err
}

type ResourceKind string

const (
	KindDatabaseInstance    ResourceKind = "database_instance"
	KindDatabase            ResourceKind = "database"
	KindPrincipal           ResourceKind = "database_principal"
	KindGrantSet            ResourceKind = "grant_set"
	KindNetworkPolicy       ResourceKind = "network_access_policy"
	KindConsoleSession      ResourceKind = "database_workspace_session"
	KindTuningProfile       ResourceKind = "database_tuning_profile"
	KindDatabaseUpgrade     ResourceKind = "database_upgrade"
)

type Lifecycle string
type Health string
type Reconciliation string

const (
	LifecycleProvisioning Lifecycle = "provisioning"
	LifecycleReady        Lifecycle = "ready"
	LifecycleUpdating     Lifecycle = "updating"
	LifecycleDisabling    Lifecycle = "disabling"
	LifecycleQuarantined  Lifecycle = "quarantined"
	LifecycleDeleting     Lifecycle = "deleting"
	LifecycleDeleted      Lifecycle = "deleted"

	HealthUnknown     Health = "unknown"
	HealthHealthy     Health = "healthy"
	HealthDegraded    Health = "degraded"
	HealthUnavailable Health = "unavailable"

	ReconciliationPending   Reconciliation = "pending"
	ReconciliationInSync    Reconciliation = "in_sync"
	ReconciliationDrifted   Reconciliation = "drifted"
	ReconciliationFailed    Reconciliation = "failed"
	ReconciliationAmbiguous Reconciliation = "ambiguous"
)

type ResourceStatus struct {
	Lifecycle         Lifecycle      `json:"lifecycle"`
	Health            Health         `json:"health"`
	Reconciliation    Reconciliation `json:"reconciliation"`
	ObservedGeneration uint64        `json:"observed_generation,omitempty"`
	ProofDigest       string         `json:"proof_digest,omitempty"`
	MessageCode       string         `json:"message_code,omitempty"`
}

type Metadata struct {
	ID         ResourceID     `json:"id"`
	TenantID   site.TenantID  `json:"tenant_id,omitempty"`
	SiteID     site.SiteID    `json:"site_id,omitempty"`
	Generation uint64         `json:"generation"`
	Status     ResourceStatus `json:"status"`
}

type Placement string

const (
	PlacementLocal    Placement = "local"
	PlacementExternal Placement = "external"
)

type Endpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

type MariaDBVersion struct {
	Major uint16 `json:"major"`
	Minor uint16 `json:"minor"`
	Patch uint16 `json:"patch,omitempty"`
}

type InstanceCapacity struct {
	StorageBytes   uint64 `json:"storage_bytes"`
	MemoryBytes    uint64 `json:"memory_bytes"`
	MaxConnections uint32 `json:"max_connections"`
}

type ExternalInstance struct {
	Endpoint          Endpoint  `json:"endpoint"`
	ServerName        string    `json:"server_name"`
	PinnedCASecretRef SecretRef `json:"pinned_ca_secret_ref"`
	AdminSecretRef    SecretRef `json:"admin_secret_ref"`
	CredentialAudience ResourceID `json:"credential_audience"`
	RequiredTLS       TLSMode   `json:"required_tls"`
}

type DatabaseInstance struct {
	Metadata
	Placement       Placement        `json:"placement"`
	Version         MariaDBVersion   `json:"version"`
	LocalServiceRef ResourceID       `json:"local_service_ref,omitempty"`
	External        *ExternalInstance `json:"external,omitempty"`
	NetworkPolicyID ResourceID       `json:"network_policy_id"`
	Capacity        InstanceCapacity `json:"capacity"`
}

func (resource DatabaseInstance) Kind() ResourceKind { return KindDatabaseInstance }
func (resource DatabaseInstance) Meta() Metadata     { return resource.Metadata }
func (resource DatabaseInstance) Validate() error {
	if err := validateMetadata(resource.Metadata, false); err != nil { return err }
	if resource.Version.Major == 0 || resource.Capacity.MaxConnections == 0 || resource.NetworkPolicyID.IsZero() {
		return ErrInvalidResource
	}
	switch resource.Placement {
	case PlacementLocal:
		if resource.LocalServiceRef.IsZero() || resource.External != nil { return ErrInvalidResource }
	case PlacementExternal:
		if !resource.LocalServiceRef.IsZero() || resource.External == nil || validateExternal(*resource.External) != nil { return ErrInvalidResource }
	default:
		return ErrInvalidResource
	}
	return nil
}

type Database struct {
	Metadata
	InstanceID ResourceID     `json:"instance_id"`
	Name       SQLIdentifier  `json:"name"`
	Charset    SQLIdentifier  `json:"charset"`
	Collation  SQLIdentifier  `json:"collation"`
	QuotaBytes uint64         `json:"quota_bytes"`
}

func (resource Database) Kind() ResourceKind { return KindDatabase }
func (resource Database) Meta() Metadata     { return resource.Metadata }
func (resource Database) Validate() error {
	if err := validateMetadata(resource.Metadata, true); err != nil { return err }
	if resource.InstanceID.IsZero() || resource.Name.IsZero() || resource.Charset.IsZero() || resource.Collation.IsZero() || resource.QuotaBytes == 0 {
		return ErrInvalidResource
	}
	return nil
}

type HostScope string

const (
	HostScopeLoopback HostScope = "loopback"
	HostScopePolicy   HostScope = "network_policy"
)

type DatabasePrincipal struct {
	Metadata
	InstanceID         ResourceID    `json:"instance_id"`
	Name               SQLIdentifier `json:"name"`
	HostScope          HostScope     `json:"host_scope"`
	NetworkPolicyID    ResourceID    `json:"network_policy_id,omitempty"`
	CredentialSecretRef SecretRef    `json:"credential_secret_ref"`
	CredentialFormat PrincipalCredentialFormat `json:"credential_format,omitempty"`
	Disabled           bool         `json:"disabled"`
}

func (resource DatabasePrincipal) Kind() ResourceKind { return KindPrincipal }
func (resource DatabasePrincipal) Meta() Metadata     { return resource.Metadata }
func (resource DatabasePrincipal) Validate() error {
	if err := validateMetadata(resource.Metadata, true); err != nil { return err }
	if resource.CredentialFormat!="" && resource.CredentialFormat!=CredentialFormatNativeHash { return ErrInvalidResource }
	if resource.InstanceID.IsZero() || resource.Name.IsZero() || resource.CredentialSecretRef.IsZero() { return ErrInvalidResource }
	switch resource.HostScope {
	case HostScopeLoopback:
		if !resource.NetworkPolicyID.IsZero() { return ErrInvalidResource }
	case HostScopePolicy:
		if resource.NetworkPolicyID.IsZero() { return ErrInvalidResource }
	default:
		return ErrInvalidResource
	}
	return nil
}

type GrantScope string
type Privilege string

const (
	GrantScopeDatabase GrantScope = "database"
	GrantScopeTable    GrantScope = "table"
	GrantScopeRoutine  GrantScope = "routine"

	PrivilegeSelect          Privilege = "select"
	PrivilegeInsert          Privilege = "insert"
	PrivilegeUpdate          Privilege = "update"
	PrivilegeDelete          Privilege = "delete"
	PrivilegeCreate          Privilege = "create"
	PrivilegeAlter           Privilege = "alter"
	PrivilegeIndex           Privilege = "index"
	PrivilegeDrop            Privilege = "drop"
	PrivilegeCreateTemporary Privilege = "create_temporary_tables"
	PrivilegeExecute         Privilege = "execute"
	PrivilegeCreateView      Privilege = "create_view"
	PrivilegeShowView        Privilege = "show_view"
	PrivilegeTrigger         Privilege = "trigger"
	PrivilegeEvent           Privilege = "event"
)

type Grant struct {
	Scope      GrantScope    `json:"scope"`
	ObjectName SQLIdentifier `json:"object_name,omitempty"`
	Privileges []Privilege  `json:"privileges"`
}

type GrantSet struct {
	Metadata
	InstanceID  ResourceID `json:"instance_id"`
	DatabaseID  ResourceID `json:"database_id"`
	PrincipalID ResourceID `json:"principal_id"`
	Grants      []Grant    `json:"grants"`
}

func (resource GrantSet) Kind() ResourceKind { return KindGrantSet }
func (resource GrantSet) Meta() Metadata     { return resource.Metadata }
func (resource GrantSet) Validate() error {
	if err := validateMetadata(resource.Metadata, true); err != nil { return err }
	if resource.InstanceID.IsZero() || resource.DatabaseID.IsZero() || resource.PrincipalID.IsZero() || len(resource.Grants) == 0 || len(resource.Grants) > 128 {
		return ErrInvalidResource
	}
	seen := make(map[string]struct{}, len(resource.Grants))
	for _, grant := range resource.Grants {
		if err := validateGrant(grant); err != nil { return err }
		key := string(grant.Scope) + "\x00" + grant.ObjectName.String()
		if _, exists := seen[key]; exists { return ErrInvalidResource }
		seen[key] = struct{}{}
	}
	return nil
}

type TLSMode string
type VerificationLevel string
type NetworkInterface string

const (
	TLSRequired TLSMode = "required"
	TLSMutual   TLSMode = "mutual"

	VerifyStructural         VerificationLevel = "structural"
	VerifyLocalEndToEnd      VerificationLevel = "local_end_to_end"
	VerifyClientConfirmed    VerificationLevel = "client_confirmed"
	VerifyIndependentExternal VerificationLevel = "independent_external"

	InterfaceLoopback NetworkInterface = "loopback"
	InterfacePrivate  NetworkInterface = "private"
	InterfacePublic   NetworkInterface = "public"
)

type NetworkAccessPolicy struct {
	Metadata
	InstanceID       ResourceID        `json:"instance_id"`
	Interfaces       []NetworkInterface `json:"interfaces"`
	AllowedCIDRs     []netip.Prefix    `json:"allowed_cidrs"`
	TLS              TLSMode           `json:"tls"`
	Verification     VerificationLevel `json:"verification"`
	HighRiskApproval ResourceID         `json:"high_risk_approval,omitempty"`
}

func (resource NetworkAccessPolicy) Kind() ResourceKind { return KindNetworkPolicy }
func (resource NetworkAccessPolicy) Meta() Metadata     { return resource.Metadata }
func (resource NetworkAccessPolicy) Validate() error {
	if err := validateMetadata(resource.Metadata, false); err != nil { return err }
	if resource.InstanceID.IsZero() || len(resource.Interfaces) == 0 || len(resource.Interfaces) > 3 || len(resource.AllowedCIDRs) > 256 {
		return ErrInvalidResource
	}
	if resource.TLS != TLSRequired && resource.TLS != TLSMutual { return ErrInvalidResource }
	if !validVerification(resource.Verification) { return ErrInvalidResource }
	interfaces := make(map[NetworkInterface]struct{}, len(resource.Interfaces))
	for _, value := range resource.Interfaces {
		if value != InterfaceLoopback && value != InterfacePrivate && value != InterfacePublic { return ErrInvalidResource }
		if _, exists := interfaces[value]; exists { return ErrInvalidResource }
		interfaces[value] = struct{}{}
	}
	seen := make(map[string]struct{}, len(resource.AllowedCIDRs))
	for _, prefix := range resource.AllowedCIDRs {
		if !prefix.IsValid() || prefix != prefix.Masked() { return ErrInvalidResource }
		if prefix.Bits() == 0 && resource.HighRiskApproval.IsZero() { return ErrUnauthorized }
		key := prefix.String()
		if _, exists := seen[key]; exists { return ErrInvalidResource }
		seen[key] = struct{}{}
	}
	return nil
}

type SessionLimits struct {
	StatementTimeout time.Duration `json:"statement_timeout"`
	MaxRows          uint32        `json:"max_rows"`
	MaxResultBytes   uint64        `json:"max_result_bytes"`
	MaxConnections   uint16        `json:"max_connections"`
}

type DatabaseWorkspaceSession struct {
	Metadata
	DatabaseID      ResourceID    `json:"database_id"`
	PrincipalID     ResourceID    `json:"principal_id"`
	SessionSecretRef SecretRef    `json:"session_secret_ref"`
	ExpiresAt       time.Time     `json:"expires_at"`
	Limits          SessionLimits `json:"limits"`
}

func (resource DatabaseWorkspaceSession) Kind() ResourceKind { return KindConsoleSession }
func (resource DatabaseWorkspaceSession) Meta() Metadata     { return resource.Metadata }
func (resource DatabaseWorkspaceSession) Validate() error {
	if err := validateMetadata(resource.Metadata, true); err != nil { return err }
	if resource.DatabaseID.IsZero() || resource.PrincipalID.IsZero() || resource.SessionSecretRef.IsZero() || resource.ExpiresAt.IsZero() ||
		resource.Limits.StatementTimeout <= 0 || resource.Limits.StatementTimeout > 2*time.Minute || resource.Limits.MaxRows == 0 ||
		resource.Limits.MaxRows > 100000 || resource.Limits.MaxResultBytes == 0 || resource.Limits.MaxResultBytes > 64<<20 ||
		resource.Limits.MaxConnections == 0 || resource.Limits.MaxConnections > 8 {
		return ErrInvalidResource
	}
	return nil
}

type FlushMethod string

const (
	FlushFsync   FlushMethod = "fsync"
	FlushODirect FlushMethod = "o_direct"
)

type TuningSettings struct {
	BufferPoolBytes   uint64      `json:"buffer_pool_bytes"`
	MaxConnections    uint32      `json:"max_connections"`
	TempTableBytes    uint64      `json:"temp_table_bytes"`
	SlowQueryMillis   uint32      `json:"slow_query_millis"`
	FlushMethod       FlushMethod `json:"flush_method"`
}

type TuningProfile struct {
	Metadata
	InstanceID ResourceID      `json:"instance_id"`
	Version    MariaDBVersion  `json:"version"`
	Settings   TuningSettings  `json:"settings"`
	ApprovalRef ResourceID     `json:"approval_ref"`
}

func (resource TuningProfile) Kind() ResourceKind { return KindTuningProfile }
func (resource TuningProfile) Meta() Metadata     { return resource.Metadata }
func (resource TuningProfile) Validate() error {
	if err := validateMetadata(resource.Metadata, false); err != nil { return err }
	settings := resource.Settings
	if resource.InstanceID.IsZero() || resource.Version.Major == 0 || resource.ApprovalRef.IsZero() || settings.BufferPoolBytes < 64<<20 ||
		settings.MaxConnections == 0 || settings.MaxConnections > 100000 || settings.TempTableBytes < 1<<20 ||
		settings.SlowQueryMillis == 0 || (settings.FlushMethod != FlushFsync && settings.FlushMethod != FlushODirect) {
		return ErrInvalidResource
	}
	return nil
}

type UpgradePhase string

const (
	UpgradeRequested  UpgradePhase = "requested"
	UpgradePreflight  UpgradePhase = "preflight"
	UpgradePrepared   UpgradePhase = "prepared"
	UpgradeCutover    UpgradePhase = "cutover"
	UpgradeVerifying  UpgradePhase = "verifying"
	UpgradeComplete   UpgradePhase = "complete"
	UpgradeFailed     UpgradePhase = "failed"
)

type DatabaseUpgrade struct {
	Metadata
	InstanceID      ResourceID      `json:"instance_id"`
	From            MariaDBVersion `json:"from"`
	To              MariaDBVersion `json:"to"`
	RecoveryPointRef ResourceID     `json:"recovery_point_ref"`
	MaintenanceRef  ResourceID      `json:"maintenance_ref"`
	ApprovalRef     ResourceID      `json:"approval_ref"`
	Phase           UpgradePhase    `json:"phase"`
}

func (resource DatabaseUpgrade) Kind() ResourceKind { return KindDatabaseUpgrade }
func (resource DatabaseUpgrade) Meta() Metadata     { return resource.Metadata }
func (resource DatabaseUpgrade) Validate() error {
	if err := validateMetadata(resource.Metadata, false); err != nil { return err }
	if resource.InstanceID.IsZero() || resource.From.Major == 0 || resource.To.Major == 0 || compareVersion(resource.From, resource.To) >= 0 ||
		resource.RecoveryPointRef.IsZero() || resource.MaintenanceRef.IsZero() || resource.ApprovalRef.IsZero() || !validUpgradePhase(resource.Phase) {
		return ErrInvalidResource
	}
	return nil
}

type Resource interface {
	Kind() ResourceKind
	Meta() Metadata
	Validate() error
}

type ResourceEnvelope struct {
	Kind         ResourceKind   `json:"kind"`
	Metadata     Metadata       `json:"metadata"`
	ParentID     ResourceID     `json:"parent_id,omitempty"`
	PhysicalName string         `json:"physical_name,omitempty"`
	Spec         json.RawMessage `json:"spec"`
}

func EncodeResource(resource Resource) (ResourceEnvelope, error) {
	if resource == nil || resource.Validate() != nil { return ResourceEnvelope{}, ErrInvalidResource }
	encoded, err := json.Marshal(resource)
	if err != nil { return ResourceEnvelope{}, err }
	envelope := ResourceEnvelope{Kind: resource.Kind(), Metadata: resource.Meta(), Spec: encoded}
	switch value := resource.(type) {
	case Database:
		envelope.ParentID, envelope.PhysicalName = value.InstanceID, value.Name.String()
	case DatabasePrincipal:
		envelope.ParentID, envelope.PhysicalName = value.InstanceID, value.Name.String()
	case GrantSet:
		envelope.ParentID = value.DatabaseID
	case NetworkAccessPolicy:
		envelope.ParentID = value.InstanceID
	case DatabaseWorkspaceSession:
		envelope.ParentID = value.DatabaseID
	case TuningProfile:
		envelope.ParentID = value.InstanceID
	case DatabaseUpgrade:
		envelope.ParentID = value.InstanceID
	}
	return envelope, nil
}

func DecodeResource(envelope ResourceEnvelope) (Resource, error) {
	var resource Resource
	switch envelope.Kind {
	case KindDatabaseInstance:
		resource = &DatabaseInstance{}
	case KindDatabase:
		resource = &Database{}
	case KindPrincipal:
		resource = &DatabasePrincipal{}
	case KindGrantSet:
		resource = &GrantSet{}
	case KindNetworkPolicy:
		resource = &NetworkAccessPolicy{}
	case KindConsoleSession:
		resource = &DatabaseWorkspaceSession{}
	case KindTuningProfile:
		resource = &TuningProfile{}
	case KindDatabaseUpgrade:
		resource = &DatabaseUpgrade{}
	default:
		return nil, ErrInvalidResource
	}
	if err := json.Unmarshal(envelope.Spec, resource); err != nil { return nil, ErrInvalidResource }
	setResourceStatus(resource, envelope.Metadata.Status)
	if resource.Meta().ID != envelope.Metadata.ID || resource.Meta().Generation != envelope.Metadata.Generation || resource.Validate() != nil {
		return nil, ErrInvalidResource
	}
	return resource, nil
}

func setResourceStatus(resource Resource, status ResourceStatus) {
	switch value := resource.(type) {
	case *DatabaseInstance: value.Status = status
	case *Database: value.Status = status
	case *DatabasePrincipal: value.Status = status
	case *GrantSet: value.Status = status
	case *NetworkAccessPolicy: value.Status = status
	case *DatabaseWorkspaceSession: value.Status = status
	case *TuningProfile: value.Status = status
	case *DatabaseUpgrade: value.Status = status
	}
}

func validateMetadata(metadata Metadata, tenantScoped bool) error {
	if metadata.ID.IsZero() || metadata.Generation == 0 || !validStatus(metadata.Status) { return ErrInvalidResource }
	if tenantScoped {
		if metadata.TenantID.String() == "" || metadata.SiteID.String() == "" { return ErrInvalidResource }
	} else if metadata.SiteID.String() != "" {
		return ErrInvalidResource
	}
	return nil
}

func validStatus(status ResourceStatus) bool {
	switch status.Lifecycle {
	case LifecycleProvisioning, LifecycleReady, LifecycleUpdating, LifecycleDisabling, LifecycleQuarantined, LifecycleDeleting, LifecycleDeleted:
	default: return false
	}
	switch status.Health {
	case HealthUnknown, HealthHealthy, HealthDegraded, HealthUnavailable:
	default: return false
	}
	switch status.Reconciliation {
	case ReconciliationPending, ReconciliationInSync, ReconciliationDrifted, ReconciliationFailed, ReconciliationAmbiguous:
	default: return false
	}
	return status.ProofDigest == "" || validSHA256(status.ProofDigest)
}

func validateExternal(external ExternalInstance) error {
	if external.Endpoint.Port == 0 || !validHost(external.Endpoint.Host) || !validDNSName(external.ServerName) || external.PinnedCASecretRef.IsZero() ||
		external.AdminSecretRef.IsZero() || external.CredentialAudience.IsZero() || (external.RequiredTLS != TLSRequired && external.RequiredTLS != TLSMutual) {
		return ErrInvalidResource
	}
	return nil
}

func validHost(raw string) bool {
	if address, err := netip.ParseAddr(raw); err == nil { return address.Zone() == "" }
	return validDNSName(raw)
}

func validDNSName(raw string) bool {
	if raw == "" || len(raw) > 253 || strings.HasPrefix(raw, ".") || strings.ContainsAny(raw, " /\\:@") { return false }
	if strings.HasSuffix(raw, ".") { raw = strings.TrimSuffix(raw, ".") }
	for _, label := range strings.Split(raw, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' { return false }
		for index := 0; index < len(label); index++ {
			if !asciiAlphaNumeric(label[index]) && label[index] != '-' { return false }
		}
	}
	return true
}

func validateGrant(grant Grant) error {
	if grant.Scope != GrantScopeDatabase && grant.Scope != GrantScopeTable && grant.Scope != GrantScopeRoutine { return ErrInvalidResource }
	if grant.Scope == GrantScopeDatabase && !grant.ObjectName.IsZero() || grant.Scope != GrantScopeDatabase && grant.ObjectName.IsZero() { return ErrInvalidResource }
	if len(grant.Privileges) == 0 || len(grant.Privileges) > 32 { return ErrInvalidResource }
	privileges := append([]Privilege(nil), grant.Privileges...)
	sort.Slice(privileges, func(left, right int) bool { return privileges[left] < privileges[right] })
	for index, privilege := range privileges {
		if !validPrivilege(privilege) || index > 0 && privileges[index-1] == privilege { return ErrInvalidResource }
	}
	return nil
}

func validPrivilege(privilege Privilege) bool {
	switch privilege {
	case PrivilegeSelect, PrivilegeInsert, PrivilegeUpdate, PrivilegeDelete, PrivilegeCreate, PrivilegeAlter, PrivilegeIndex,
		PrivilegeDrop, PrivilegeCreateTemporary, PrivilegeExecute, PrivilegeCreateView, PrivilegeShowView, PrivilegeTrigger, PrivilegeEvent:
		return true
	default:
		return false
	}
}

func validVerification(level VerificationLevel) bool {
	return level == VerifyStructural || level == VerifyLocalEndToEnd || level == VerifyClientConfirmed || level == VerifyIndependentExternal
}

func compareVersion(left, right MariaDBVersion) int {
	if left.Major != right.Major { if left.Major < right.Major { return -1 }; return 1 }
	if left.Minor != right.Minor { if left.Minor < right.Minor { return -1 }; return 1 }
	if left.Patch != right.Patch { if left.Patch < right.Patch { return -1 }; return 1 }
	return 0
}

func validUpgradePhase(phase UpgradePhase) bool {
	switch phase {
	case UpgradeRequested, UpgradePreflight, UpgradePrepared, UpgradeCutover, UpgradeVerifying, UpgradeComplete, UpgradeFailed:
		return true
	default:
		return false
	}
}

func validSHA256(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}
