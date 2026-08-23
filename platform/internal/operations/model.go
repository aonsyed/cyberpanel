// Package operations owns canonical host-operation resources and the closed
// boundary to privileged node executors. Tenant callers never supply command
// lines, filesystem paths, unit names, firewall syntax, or package-manager
// arguments.
package operations

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

var (
	ErrInvalidResource    = errors.New("invalid operations resource")
	ErrInvalidCommand     = errors.New("invalid operations command")
	ErrUnauthorized       = errors.New("operations command is not authorized")
	ErrNotFound           = errors.New("operations resource not found")
	ErrConflict           = errors.New("operations resource generation conflict")
	ErrIdempotency        = errors.New("operations command ID was reused with another payload")
	ErrInvalidReceipt     = errors.New("invalid operations receipt")
	ErrInvalidEffect      = errors.New("invalid privileged operations effect")
	ErrCompensationFailed = errors.New("operations compensation could not be proven")
)

type ResourceID struct{ value string }
type SecretRef struct{ value string }

func NewResourceID(raw string) (ResourceID, error) {
	value, err := safeOpaque(raw, 128)
	return ResourceID{value: value}, err
}

func NewSecretRef(raw string) (SecretRef, error) {
	value, err := safeOpaque(raw, 128)
	return SecretRef{value: value}, err
}

func safeOpaque(raw string, maximum int) (string, error) {
	if raw == "" || len(raw) > maximum || !alphaNumeric(raw[0]) || !alphaNumeric(raw[len(raw)-1]) {
		return "", ErrInvalidResource
	}
	for index := range raw {
		value := raw[index]
		if !alphaNumeric(value) && value != '-' && value != '_' && value != '.' { return "", ErrInvalidResource }
	}
	return raw, nil
}

func alphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func (id ResourceID) String() string { return id.value }
func (id ResourceID) IsZero() bool { return id.value == "" }
func (ref SecretRef) String() string { return ref.value }
func (ref SecretRef) IsZero() bool { return ref.value == "" }
func (id ResourceID) MarshalJSON() ([]byte, error) { return json.Marshal(id.value) }
func (ref SecretRef) MarshalJSON() ([]byte, error) { return json.Marshal(ref.value) }
func (id *ResourceID) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil { return err }
	if raw == "" { *id = ResourceID{}; return nil }
	parsed, err := NewResourceID(raw)
	if err == nil { *id = parsed }
	return err
}
func (ref *SecretRef) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil { return err }
	if raw == "" { *ref = SecretRef{}; return nil }
	parsed, err := NewSecretRef(raw)
	if err == nil { *ref = parsed }
	return err
}

type ResourceKind string

const (
	KindResourceProfile   ResourceKind = "resource_profile"
	KindTransferAccount   ResourceKind = "transfer_account"
	KindFirewallPolicy    ResourceKind = "firewall_policy"
	KindSSHPolicy         ResourceKind = "ssh_policy"
	KindSSHKey            ResourceKind = "ssh_key"
	KindWAFPolicy         ResourceKind = "waf_policy"
	KindServicePolicy     ResourceKind = "service_policy"
	KindPackageTransaction ResourceKind = "package_transaction"
	KindManagedService    ResourceKind = "managed_service"
)

type Lifecycle string
type Health string
type Reconciliation string

const (
	LifecycleProvisioning Lifecycle = "provisioning"
	LifecycleReady Lifecycle = "ready"
	LifecycleUpdating Lifecycle = "updating"
	LifecycleDisabled Lifecycle = "disabled"
	LifecycleDeleting Lifecycle = "deleting"
	LifecycleDeleted Lifecycle = "deleted"
	LifecycleQuarantined Lifecycle = "quarantined"

	HealthUnknown Health = "unknown"
	HealthHealthy Health = "healthy"
	HealthDegraded Health = "degraded"
	HealthUnavailable Health = "unavailable"

	ReconciliationPending Reconciliation = "pending"
	ReconciliationInSync Reconciliation = "in_sync"
	ReconciliationDrifted Reconciliation = "drifted"
	ReconciliationFailed Reconciliation = "failed"
	ReconciliationAmbiguous Reconciliation = "ambiguous"
)

type ResourceStatus struct {
	Lifecycle Lifecycle `json:"lifecycle"`
	Health Health `json:"health"`
	Reconciliation Reconciliation `json:"reconciliation"`
	ObservedGeneration uint64 `json:"observed_generation,omitempty"`
	ProofDigest string `json:"proof_digest,omitempty"`
	MessageCode string `json:"message_code,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type Metadata struct {
	ID ResourceID `json:"id"`
	NodeID ResourceID `json:"node_id"`
	TenantID site.TenantID `json:"tenant_id,omitempty"`
	SiteID site.SiteID `json:"site_id,omitempty"`
	Generation uint64 `json:"generation"`
	Status ResourceStatus `json:"status"`
}

type ScopeKind string

const (
	ScopeNode ScopeKind = "node"
	ScopeTenant ScopeKind = "tenant"
	ScopeSite ScopeKind = "site"
)

type EnforcementScope struct {
	Kind ScopeKind `json:"kind"`
	NodeID ResourceID `json:"node_id"`
	TenantID site.TenantID `json:"tenant_id,omitempty"`
	SiteID site.SiteID `json:"site_id,omitempty"`
}

func (scope EnforcementScope) Validate() error {
	if scope.NodeID.IsZero() { return ErrInvalidResource }
	switch scope.Kind {
	case ScopeNode:
		if scope.TenantID.String() != "" || scope.SiteID.String() != "" { return ErrInvalidResource }
	case ScopeTenant:
		if scope.TenantID.String() == "" || scope.SiteID.String() != "" { return ErrInvalidResource }
	case ScopeSite:
		if scope.TenantID.String() == "" || scope.SiteID.String() == "" { return ErrInvalidResource }
	default:
		return ErrInvalidResource
	}
	return nil
}

type CgroupLimits struct {
	Binding CgroupBinding `json:"binding"`
	CPUQuotaMicros uint64 `json:"cpu_quota_micros"`
	CPUPeriodMicros uint64 `json:"cpu_period_micros"`
	MemoryHighBytes uint64 `json:"memory_high_bytes"`
	MemoryMaxBytes uint64 `json:"memory_max_bytes"`
	SwapMaxBytes uint64 `json:"swap_max_bytes"`
	TasksMax uint64 `json:"tasks_max"`
	IOReadBytesPerSecond uint64 `json:"io_read_bytes_per_second"`
	IOWriteBytesPerSecond uint64 `json:"io_write_bytes_per_second"`
}

type CgroupMode string

const CgroupSystemdScopeV2 CgroupMode = "systemd_scope_cgroup_v2"

type CgroupBinding struct {
	Mode CgroupMode `json:"mode"`
	ScopeID ResourceID `json:"scope_id"`
	DelegatePHP bool `json:"delegate_php"`
	DelegateWebWorkers bool `json:"delegate_web_workers"`
}

type ProjectQuota struct {
	VolumeRef ResourceID `json:"volume_ref"`
	ProjectID uint32 `json:"project_id"`
	SpaceSoftBytes uint64 `json:"space_soft_bytes"`
	SpaceHardBytes uint64 `json:"space_hard_bytes"`
	InodeSoft uint64 `json:"inode_soft"`
	InodeHard uint64 `json:"inode_hard"`
	GracePeriod time.Duration `json:"grace_period"`
}

type TransferLimit struct {
	MonthlyBytes uint64 `json:"monthly_bytes"`
	ResetDayUTC uint8 `json:"reset_day_utc"`
	Enforcement TransferEnforcement `json:"enforcement"`
}

type TransferEnforcement string

const (
	TransferMeasure TransferEnforcement = "measure"
	TransferThrottle TransferEnforcement = "throttle"
	TransferSuspend TransferEnforcement = "suspend"
)

type PHPConcurrency struct {
	MaxWorkers uint32 `json:"max_workers"`
	MaxRequestsPerWorker uint32 `json:"max_requests_per_worker"`
	RequestTimeout time.Duration `json:"request_timeout"`
}

type AccountingQuality string

const (
	AccountingExact AccountingQuality = "exact"
	AccountingAttributed AccountingQuality = "attributed"
	AccountingEstimated AccountingQuality = "estimated"
	AccountingUnavailable AccountingQuality = "unavailable"
)

type AccountingCoverage struct {
	Web AccountingQuality `json:"web"`
	PHP AccountingQuality `json:"php"`
	Database AccountingQuality `json:"database"`
	Mail AccountingQuality `json:"mail"`
	Limitations []AccountingLimitation `json:"limitations,omitempty"`
}

type AccountingLimitation string

const (
	LimitationSharedDatabase AccountingLimitation = "shared_database_not_kernel_isolated"
	LimitationSharedWeb AccountingLimitation = "shared_web_listener_not_kernel_isolated"
	LimitationSharedMail AccountingLimitation = "shared_mail_pipeline_not_kernel_isolated"
	LimitationEncryptedTraffic AccountingLimitation = "encrypted_transfer_requires_application_counters"
)

type ResourceProfile struct {
	Metadata
	Scope EnforcementScope `json:"scope"`
	Cgroup CgroupLimits `json:"cgroup"`
	Quota ProjectQuota `json:"quota"`
	Transfer TransferLimit `json:"transfer"`
	PHP PHPConcurrency `json:"php"`
	Accounting AccountingCoverage `json:"accounting"`
}

func (resource ResourceProfile) Kind() ResourceKind { return KindResourceProfile }
func (resource ResourceProfile) Meta() Metadata { return resource.Metadata }
func (resource ResourceProfile) Validate() error {
	if validateMetadata(resource.Metadata) != nil || resource.Scope.Validate() != nil || resource.Scope.NodeID != resource.NodeID { return ErrInvalidResource }
	if resource.Scope.TenantID.String() != resource.TenantID.String() || resource.Scope.SiteID.String() != resource.SiteID.String() { return ErrInvalidResource }
	limits := resource.Cgroup
	if limits.Binding.Mode != CgroupSystemdScopeV2 || limits.Binding.ScopeID.IsZero() || limits.CPUQuotaMicros == 0 || limits.CPUPeriodMicros < 1000 || limits.CPUQuotaMicros > limits.CPUPeriodMicros*1024 ||
		limits.MemoryHighBytes == 0 || limits.MemoryMaxBytes < limits.MemoryHighBytes || limits.TasksMax == 0 { return ErrInvalidResource }
	quota := resource.Quota
	if quota.VolumeRef.IsZero() || quota.ProjectID == 0 || quota.SpaceSoftBytes == 0 || quota.SpaceHardBytes < quota.SpaceSoftBytes || quota.InodeSoft == 0 || quota.InodeHard < quota.InodeSoft || quota.GracePeriod < 0 { return ErrInvalidResource }
	if resource.Transfer.MonthlyBytes == 0 || resource.Transfer.ResetDayUTC < 1 || resource.Transfer.ResetDayUTC > 28 ||
		(resource.Transfer.Enforcement != TransferMeasure && resource.Transfer.Enforcement != TransferThrottle && resource.Transfer.Enforcement != TransferSuspend) { return ErrInvalidResource }
	if resource.PHP.MaxWorkers == 0 || resource.PHP.MaxRequestsPerWorker == 0 || resource.PHP.RequestTimeout <= 0 || resource.PHP.RequestTimeout > 30*time.Minute { return ErrInvalidResource }
	if !validCoverage(resource.Accounting) { return ErrInvalidResource }
	return nil
}

type TransferAccount struct {
	Metadata
	Scope EnforcementScope `json:"scope"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd time.Time `json:"period_end"`
	IngressBytes uint64 `json:"ingress_bytes"`
	EgressBytes uint64 `json:"egress_bytes"`
	LastSampleAt time.Time `json:"last_sample_at"`
	CounterEpoch ResourceID `json:"counter_epoch"`
}

func (resource TransferAccount) Kind() ResourceKind { return KindTransferAccount }
func (resource TransferAccount) Meta() Metadata { return resource.Metadata }
func (resource TransferAccount) Validate() error {
	if validateMetadata(resource.Metadata) != nil || resource.Scope.Validate() != nil || resource.Scope.NodeID != resource.NodeID ||
		!validMonthlyPeriod(resource.PeriodStart, resource.PeriodEnd) || resource.LastSampleAt.Before(resource.PeriodStart) || resource.LastSampleAt.After(resource.PeriodEnd) || resource.CounterEpoch.IsZero() { return ErrInvalidResource }
	return nil
}

type FirewallBackend string
type FirewallAction string
type NetworkProtocol string
type AddressFamily string

const (
	FirewallNFTables FirewallBackend = "nftables"
	FirewallFirewalld FirewallBackend = "firewalld"
	FirewallAccept FirewallAction = "accept"
	FirewallDrop FirewallAction = "drop"
	FirewallReject FirewallAction = "reject"
	ProtocolTCP NetworkProtocol = "tcp"
	ProtocolUDP NetworkProtocol = "udp"
	ProtocolICMP NetworkProtocol = "icmp"
	FamilyIPv4 AddressFamily = "ipv4"
	FamilyIPv6 AddressFamily = "ipv6"
)

type PortRange struct { From uint16 `json:"from"`; To uint16 `json:"to"` }

type FirewallRule struct {
	ID ResourceID `json:"id"`
	Priority uint16 `json:"priority"`
	Family AddressFamily `json:"family"`
	Protocol NetworkProtocol `json:"protocol"`
	Sources []netip.Prefix `json:"sources,omitempty"`
	DestinationPorts []PortRange `json:"destination_ports,omitempty"`
	Action FirewallAction `json:"action"`
	RatePerMinute uint32 `json:"rate_per_minute,omitempty"`
	Log bool `json:"log"`
}

type FirewallPolicy struct {
	Metadata
	Backend FirewallBackend `json:"backend"`
	DefaultInbound FirewallAction `json:"default_inbound"`
	DefaultForward FirewallAction `json:"default_forward"`
	DefaultOutbound FirewallAction `json:"default_outbound"`
	Rules []FirewallRule `json:"rules"`
	ManagementProbe ManagementProbe `json:"management_probe"`
}

type ManagementProbe struct {
	SourceCIDRs []netip.Prefix `json:"source_cidrs"`
	Port uint16 `json:"port"`
	MinimumSuccesses uint8 `json:"minimum_successes"`
}

func (resource FirewallPolicy) Kind() ResourceKind { return KindFirewallPolicy }
func (resource FirewallPolicy) Meta() Metadata { return resource.Metadata }
func (resource FirewallPolicy) Validate() error {
	if validateNodeMetadata(resource.Metadata) != nil || (resource.Backend != FirewallNFTables && resource.Backend != FirewallFirewalld) ||
		!validFirewallAction(resource.DefaultInbound) || !validFirewallAction(resource.DefaultForward) || !validFirewallAction(resource.DefaultOutbound) ||
		len(resource.Rules) > 4096 || resource.ManagementProbe.Port == 0 || resource.ManagementProbe.MinimumSuccesses == 0 || resource.ManagementProbe.MinimumSuccesses > 8 || len(resource.ManagementProbe.SourceCIDRs) == 0 || len(resource.ManagementProbe.SourceCIDRs) > 32 { return ErrInvalidResource }
	seen := make(map[string]struct{}, len(resource.Rules)); priorities := make(map[uint16]struct{}, len(resource.Rules))
	for _, rule := range resource.Rules {
		if validateFirewallRule(rule) != nil { return ErrInvalidResource }
		if _, exists := seen[rule.ID.String()]; exists { return ErrInvalidResource }; seen[rule.ID.String()] = struct{}{}
		if _, exists := priorities[rule.Priority]; exists { return ErrInvalidResource }; priorities[rule.Priority] = struct{}{}
	}
	for _, prefix := range resource.ManagementProbe.SourceCIDRs { if !validPrefix(prefix) { return ErrInvalidResource } }
	return nil
}

type SSHAuthentication string

const (
	SSHKeysOnly SSHAuthentication = "keys_only"
	SSHKeysAndMFA SSHAuthentication = "keys_and_mfa"
)

type SSHPolicy struct {
	Metadata
	Port uint16 `json:"port"`
	Authentication SSHAuthentication `json:"authentication"`
	AllowRoot bool `json:"allow_root"`
	AllowTCPForwarding bool `json:"allow_tcp_forwarding"`
	AllowAgentForwarding bool `json:"allow_agent_forwarding"`
	IdleTimeout time.Duration `json:"idle_timeout"`
	MaxAuthTries uint8 `json:"max_auth_tries"`
	MaxSessions uint16 `json:"max_sessions"`
	AllowedGroups []ResourceID `json:"allowed_groups"`
	ManagementProbe ManagementProbe `json:"management_probe"`
}

func (resource SSHPolicy) Kind() ResourceKind { return KindSSHPolicy }
func (resource SSHPolicy) Meta() Metadata { return resource.Metadata }
func (resource SSHPolicy) Validate() error {
	if validateNodeMetadata(resource.Metadata) != nil || resource.Port == 0 ||
		(resource.Authentication != SSHKeysOnly && resource.Authentication != SSHKeysAndMFA) || resource.IdleTimeout <= 0 || resource.IdleTimeout > 24*time.Hour ||
		resource.MaxAuthTries == 0 || resource.MaxAuthTries > 20 || resource.MaxSessions == 0 || resource.ManagementProbe.Port != resource.Port || resource.ManagementProbe.MinimumSuccesses == 0 || resource.ManagementProbe.MinimumSuccesses > 8 || len(resource.ManagementProbe.SourceCIDRs) == 0 || len(resource.ManagementProbe.SourceCIDRs) > 32 { return ErrInvalidResource }
	for _, group := range resource.AllowedGroups { if group.IsZero() { return ErrInvalidResource } }
	return nil
}

type SSHKeyAlgorithm string

const (
	SSHED25519 SSHKeyAlgorithm = "ssh-ed25519"
	SSHECDSA256 SSHKeyAlgorithm = "ecdsa-sha2-nistp256"
	SSHRSA SSHKeyAlgorithm = "ssh-rsa"
)

type SSHKey struct {
	Metadata
	PrincipalID ResourceID `json:"principal_id"`
	Algorithm string `json:"algorithm"`
	PublicBlob string `json:"public_blob"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Restrictions SSHKeyRestrictions `json:"restrictions"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type SSHKeyRestrictions struct {
	SourceCIDRs []netip.Prefix `json:"source_cidrs,omitempty"`
	PermitPTY bool `json:"permit_pty"`
	PermitPortForwarding bool `json:"permit_port_forwarding"`
	PermitAgentForwarding bool `json:"permit_agent_forwarding"`
}

func (resource SSHKey) Kind() ResourceKind { return KindSSHKey }
func (resource SSHKey) Meta() Metadata { return resource.Metadata }
func (resource SSHKey) Validate() error {
	if validateMetadata(resource.Metadata) != nil || resource.PrincipalID.IsZero() || len(resource.PublicBlob) < 32 || len(resource.PublicBlob) > 16384 ||
		!validSHA256(resource.FingerprintSHA256) || (resource.Algorithm != string(SSHED25519) && resource.Algorithm != string(SSHECDSA256) && resource.Algorithm != string(SSHRSA)) { return ErrInvalidResource }
	if strings.ContainsAny(resource.PublicBlob, "\r\n\x00") { return ErrInvalidResource }
	for _, prefix := range resource.Restrictions.SourceCIDRs { if !validPrefix(prefix) { return ErrInvalidResource } }
	return nil
}

type WAFEngine string
type WAFMode string
type WAFPhase uint8
type WAFOperator string
type WAFTarget string
type WAFAction string

const (
	WAFModSecurity WAFEngine = "modsecurity_v3"
	WAFDisabled WAFMode = "disabled"
	WAFDetectionOnly WAFMode = "detection_only"
	WAFBlocking WAFMode = "blocking"
	WAFOperatorRegex WAFOperator = "regex"
	WAFOperatorContains WAFOperator = "contains"
	WAFOperatorEquals WAFOperator = "equals"
	WAFTargetURI WAFTarget = "request_uri"
	WAFTargetArgs WAFTarget = "arguments"
	WAFTargetHeaders WAFTarget = "request_headers"
	WAFTargetBody WAFTarget = "request_body"
	WAFActionDeny WAFAction = "deny"
	WAFActionLog WAFAction = "log"
	WAFActionPass WAFAction = "pass"
)

type WAFPack struct {
	Provider ResourceID `json:"provider"`
	Name ResourceID `json:"name"`
	Version string `json:"version"`
	ContentDigest string `json:"content_digest"`
	SecretRef SecretRef `json:"secret_ref,omitempty"`
}

type WAFRule struct {
	ID uint32 `json:"id"`
	Phase WAFPhase `json:"phase"`
	Target WAFTarget `json:"target"`
	Operator WAFOperator `json:"operator"`
	Pattern string `json:"pattern"`
	Actions []WAFAction `json:"actions"`
	Severity uint8 `json:"severity"`
}

type WAFExclusion struct {
	RuleIDs []uint32 `json:"rule_ids"`
	RequestPathPrefix string `json:"request_path_prefix,omitempty"`
	ArgumentNames []string `json:"argument_names,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	ReasonCode ResourceID `json:"reason_code"`
}

type WAFPolicy struct {
	Metadata
	Engine WAFEngine `json:"engine"`
	Mode WAFMode `json:"mode"`
	Hostnames []site.Hostname `json:"hostnames,omitempty"`
	CRS *WAFPack `json:"crs,omitempty"`
	ProviderPacks []WAFPack `json:"provider_packs,omitempty"`
	CustomRules []WAFRule `json:"custom_rules,omitempty"`
	Exclusions []WAFExclusion `json:"exclusions,omitempty"`
	RequestBodyLimitBytes uint64 `json:"request_body_limit_bytes"`
	AuditSamplingBasisPoints uint16 `json:"audit_sampling_basis_points"`
}

func (resource WAFPolicy) Kind() ResourceKind { return KindWAFPolicy }
func (resource WAFPolicy) Meta() Metadata { return resource.Metadata }
func (resource WAFPolicy) Validate() error {
	if validateMetadata(resource.Metadata) != nil || resource.Engine != WAFModSecurity ||
		(resource.Mode != WAFDisabled && resource.Mode != WAFDetectionOnly && resource.Mode != WAFBlocking) || resource.RequestBodyLimitBytes > 1<<30 ||
		(resource.AuditSamplingBasisPoints != 0 && resource.AuditSamplingBasisPoints != 10000) || len(resource.Hostnames) > 64 || len(resource.ProviderPacks) > 32 || len(resource.CustomRules) > 4096 || len(resource.Exclusions) > 1024 { return ErrInvalidResource }
	scoped := resource.TenantID.String() != "" || resource.SiteID.String() != ""
	if scoped {
		if resource.TenantID.String() == "" || resource.SiteID.String() == "" || len(resource.Hostnames) == 0 || resource.CRS != nil || len(resource.ProviderPacks) != 0 || len(resource.CustomRules) != 0 || len(resource.Exclusions) == 0 || resource.Mode != WAFDisabled || resource.RequestBodyLimitBytes != 0 || resource.AuditSamplingBasisPoints != 0 { return ErrInvalidResource }
	} else if len(resource.Hostnames) != 0 || resource.RequestBodyLimitBytes == 0 { return ErrInvalidResource }
	hostnames := make(map[string]struct{}, len(resource.Hostnames))
	for _, hostname := range resource.Hostnames { if hostname.String() == "" { return ErrInvalidResource }; if _, exists := hostnames[hostname.String()]; exists { return ErrInvalidResource }; hostnames[hostname.String()] = struct{}{} }
	if resource.CRS != nil && validateWAFPack(*resource.CRS) != nil { return ErrInvalidResource }
	packs := make(map[string]struct{}, len(resource.ProviderPacks))
	for _, pack := range resource.ProviderPacks { if validateWAFPack(pack) != nil { return ErrInvalidResource }; key := pack.Provider.String()+"\x00"+pack.Name.String(); if _, exists := packs[key]; exists { return ErrInvalidResource }; packs[key] = struct{}{} }
	rules := make(map[uint32]struct{}, len(resource.CustomRules))
	for _, rule := range resource.CustomRules { if validateWAFRule(rule) != nil { return ErrInvalidResource }; if _, exists := rules[rule.ID]; exists { return ErrInvalidResource }; rules[rule.ID] = struct{}{} }
	for _, exclusion := range resource.Exclusions { if validateWAFExclusion(exclusion) != nil { return ErrInvalidResource } }
	return nil
}

type ServiceName string
type ServiceDesiredState string

const (
	ServiceWebEnterprise ServiceName = "litespeed_enterprise"
	ServiceWebOpenLiteSpeed ServiceName = "openlitespeed"
	ServiceMariaDB ServiceName = "mariadb"
	ServicePostfix ServiceName = "postfix"
	ServiceDovecot ServiceName = "dovecot"
	ServicePowerDNS ServiceName = "powerdns"
	ServicePureFTPd ServiceName = "pureftpd"
	ServiceRedis ServiceName = "redis"
	ServiceElasticsearch ServiceName = "elasticsearch"
	ServicePanel ServiceName = "panel"
	ServiceRunning ServiceDesiredState = "running"
	ServiceStopped ServiceDesiredState = "stopped"
	ServiceReloaded ServiceDesiredState = "reloaded"
)

type ServicePolicy struct {
	Metadata
	Service ServiceName `json:"service"`
	Desired ServiceDesiredState `json:"desired"`
	EnabledAtBoot bool `json:"enabled_at_boot"`
	HealthProbe ServiceHealthProbe `json:"health_probe"`
	RestartLimit uint8 `json:"restart_limit"`
	RestartWindow time.Duration `json:"restart_window"`
}

type ServiceHealthProbe struct {
	Kind ProbeKind `json:"kind"`
	Port uint16 `json:"port,omitempty"`
	ExpectedProtocol ProtocolProof `json:"expected_protocol,omitempty"`
}

type ProbeKind string
type ProtocolProof string

const (
	ProbeSystemd ProbeKind = "systemd"
	ProbeTCP ProbeKind = "tcp"
	ProbeHTTP ProbeKind = "http"
	ProbeMariaDB ProbeKind = "mariadb"
	ProbeRedis ProbeKind = "redis"
	ProbeElasticsearch ProbeKind = "elasticsearch"
	ProofHTTP ProtocolProof = "http"
	ProofMySQL ProtocolProof = "mysql"
	ProofRedis ProtocolProof = "redis"
	ProofElasticsearch ProtocolProof = "elasticsearch"
)

func (resource ServicePolicy) Kind() ResourceKind { return KindServicePolicy }
func (resource ServicePolicy) Meta() Metadata { return resource.Metadata }
func (resource ServicePolicy) Validate() error {
	if validateNodeMetadata(resource.Metadata) != nil || !validService(resource.Service) ||
		(resource.Desired != ServiceRunning && resource.Desired != ServiceStopped) ||
		validateProbe(resource.HealthProbe) != nil || resource.RestartLimit > 20 || resource.RestartWindow <= 0 || resource.RestartWindow > 24*time.Hour { return ErrInvalidResource }
	return nil
}

type PackageManager string
type PackageAction string
type PackageRisk string

const (
	PackageAPT PackageManager = "apt"
	PackageDNF PackageManager = "dnf"
	PackageInstall PackageAction = "install"
	PackageRemove PackageAction = "remove"
	PackageUpgrade PackageAction = "upgrade"
	RiskRoutine PackageRisk = "routine"
	RiskKernel PackageRisk = "kernel"
	RiskDatabase PackageRisk = "database"
	RiskWebEngine PackageRisk = "web_engine"
)

type PackageSelection struct {
	Name ResourceID `json:"name"`
	Architecture ResourceID `json:"architecture"`
	FromVersion string `json:"from_version,omitempty"`
	ToVersion string `json:"to_version,omitempty"`
	Action PackageAction `json:"action"`
}

type PackageTransaction struct {
	Metadata
	Manager PackageManager `json:"manager"`
	Selections []PackageSelection `json:"selections"`
	Risk PackageRisk `json:"risk"`
	RefreshMetadata bool `json:"refresh_metadata"`
	SecurityOnly bool `json:"security_only"`
	RecoveryPointRef ResourceID `json:"recovery_point_ref"`
	MaintenanceRef ResourceID `json:"maintenance_ref"`
	ApprovalRef ResourceID `json:"approval_ref"`
	AllowReboot bool `json:"allow_reboot"`
}

func (resource PackageTransaction) Kind() ResourceKind { return KindPackageTransaction }
func (resource PackageTransaction) Meta() Metadata { return resource.Metadata }
func (resource PackageTransaction) Validate() error {
	if validateNodeMetadata(resource.Metadata) != nil || (resource.Manager != PackageAPT && resource.Manager != PackageDNF) || len(resource.Selections) == 0 || len(resource.Selections) > 512 ||
		(resource.Risk != RiskRoutine && resource.Risk != RiskKernel && resource.Risk != RiskDatabase && resource.Risk != RiskWebEngine) || resource.RecoveryPointRef.IsZero() || resource.MaintenanceRef.IsZero() || resource.ApprovalRef.IsZero() { return ErrInvalidResource }
	for _, selection := range resource.Selections {
		if selection.Name.IsZero() || selection.Architecture.IsZero() || (selection.Action != PackageInstall && selection.Action != PackageRemove && selection.Action != PackageUpgrade) ||
			len(selection.FromVersion) > 128 || len(selection.ToVersion) > 128 || strings.ContainsAny(selection.FromVersion+selection.ToVersion, "\r\n\x00") { return ErrInvalidResource }
	}
	return nil
}

type ManagedServiceKind string

const (
	ManagedRedis ManagedServiceKind = "redis"
	ManagedElasticsearch ManagedServiceKind = "elasticsearch"
)

type RedisSettings struct {
	MemoryMaxBytes uint64 `json:"memory_max_bytes"`
	MaxClients uint32 `json:"max_clients"`
	EvictionPolicy RedisEvictionPolicy `json:"eviction_policy"`
	Persistence RedisPersistence `json:"persistence"`
	TLS bool `json:"tls"`
	CredentialSecretRef SecretRef `json:"credential_secret_ref"`
	Runtime RedisRuntimeSupport `json:"runtime"`
}

type RedisRuntimeSupport struct {
	OSFamily string `json:"os_family"`
	OSVersion string `json:"os_version"`
	Architecture string `json:"architecture"`
	RedisVersion string `json:"redis_version"`
	PackageChannel string `json:"package_channel"`
	QualificationDigest string `json:"qualification_digest"`
}

type RedisEvictionPolicy string
type RedisPersistence string

const (
	RedisNoEviction RedisEvictionPolicy = "noeviction"
	RedisAllKeysLRU RedisEvictionPolicy = "allkeys-lru"
	RedisVolatileLRU RedisEvictionPolicy = "volatile-lru"
	RedisRDB RedisPersistence = "rdb"
	RedisAOF RedisPersistence = "aof"
	RedisRDBAOF RedisPersistence = "rdb_aof"
)

type ElasticsearchSettings struct {
	HeapBytes uint64 `json:"heap_bytes"`
	StorageBytes uint64 `json:"storage_bytes"`
	MaxShards uint32 `json:"max_shards"`
	TLS bool `json:"tls"`
	CredentialSecretRef SecretRef `json:"credential_secret_ref"`
	SnapshotRepositoryRef ResourceID `json:"snapshot_repository_ref"`
}

type ManagedService struct {
	Metadata
	KindName ManagedServiceKind `json:"kind_name"`
	Desired ServiceDesiredState `json:"desired"`
	Redis *RedisSettings `json:"redis,omitempty"`
	Elasticsearch *ElasticsearchSettings `json:"elasticsearch,omitempty"`
	TenantDedicated bool `json:"tenant_dedicated"`
}

func (resource ManagedService) Kind() ResourceKind { return KindManagedService }
func (resource ManagedService) Meta() Metadata { return resource.Metadata }
func (resource ManagedService) Validate() error {
	if validateMetadata(resource.Metadata) != nil || (resource.Desired != ServiceRunning && resource.Desired != ServiceStopped) || resource.TenantDedicated != (resource.TenantID.String() != "") { return ErrInvalidResource }
	switch resource.KindName {
	case ManagedRedis:
		if resource.Redis == nil || resource.Elasticsearch != nil || validateRedis(*resource.Redis) != nil { return ErrInvalidResource }
	case ManagedElasticsearch:
		if resource.Elasticsearch == nil || resource.Redis != nil || validateElasticsearch(*resource.Elasticsearch) != nil { return ErrInvalidResource }
	default:
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
	Kind ResourceKind `json:"kind"`
	Metadata Metadata `json:"metadata"`
	ParentID ResourceID `json:"parent_id,omitempty"`
	PhysicalKey string `json:"physical_key,omitempty"`
	Spec json.RawMessage `json:"spec"`
}

func EncodeResource(resource Resource) (ResourceEnvelope, error) {
	if resource == nil || resource.Validate() != nil { return ResourceEnvelope{}, ErrInvalidResource }
	encoded, err := json.Marshal(resource)
	if err != nil { return ResourceEnvelope{}, err }
	envelope := ResourceEnvelope{Kind: resource.Kind(), Metadata: resource.Meta(), Spec: encoded}
	envelope.ParentID, envelope.PhysicalKey, err = resourcePlacement(resource)
	if err != nil { return ResourceEnvelope{}, err }
	return envelope, nil
}

func DecodeResource(envelope ResourceEnvelope) (Resource, error) {
	var resource Resource
	switch envelope.Kind {
	case KindResourceProfile: resource = &ResourceProfile{}
	case KindTransferAccount: resource = &TransferAccount{}
	case KindFirewallPolicy: resource = &FirewallPolicy{}
	case KindSSHPolicy: resource = &SSHPolicy{}
	case KindSSHKey: resource = &SSHKey{}
	case KindWAFPolicy: resource = &WAFPolicy{}
	case KindServicePolicy: resource = &ServicePolicy{}
	case KindPackageTransaction: resource = &PackageTransaction{}
	case KindManagedService: resource = &ManagedService{}
	default: return nil, ErrInvalidResource
	}
	if len(envelope.Spec) == 0 || len(envelope.Spec) > 1<<20 || json.Unmarshal(envelope.Spec, resource) != nil { return nil, ErrInvalidResource }
	setStatus(resource, envelope.Metadata.Status)
	metadata := resource.Meta()
	if metadata.ID != envelope.Metadata.ID || metadata.NodeID != envelope.Metadata.NodeID || metadata.TenantID.String() != envelope.Metadata.TenantID.String() ||
		metadata.SiteID.String() != envelope.Metadata.SiteID.String() || metadata.Generation != envelope.Metadata.Generation || resource.Validate() != nil { return nil, ErrInvalidResource }
	parentID, physicalKey, err := resourcePlacement(resource)
	if err != nil || parentID != envelope.ParentID || envelope.PhysicalKey != physicalKey && !(envelope.PhysicalKey == "" && metadata.Status.Lifecycle == LifecycleDeleted) { return nil, ErrInvalidResource }
	return resource, nil
}

func resourcePlacement(resource Resource) (ResourceID, string, error) {
	switch value := resource.(type) {
	case ResourceProfile: return value.NodeID, scopeKey(value.Scope), nil
	case *ResourceProfile: return value.NodeID, scopeKey(value.Scope), nil
	case TransferAccount: return value.NodeID, scopeKey(value.Scope)+":"+value.PeriodStart.UTC().Format("2006-01"), nil
	case *TransferAccount: return value.NodeID, scopeKey(value.Scope)+":"+value.PeriodStart.UTC().Format("2006-01"), nil
	case FirewallPolicy: return value.NodeID, "firewall", nil
	case *FirewallPolicy: return value.NodeID, "firewall", nil
	case SSHPolicy: return value.NodeID, "ssh-policy", nil
	case *SSHPolicy: return value.NodeID, "ssh-policy", nil
	case SSHKey: return value.PrincipalID, value.FingerprintSHA256, nil
	case *SSHKey: return value.PrincipalID, value.FingerprintSHA256, nil
	case WAFPolicy: return value.NodeID, "waf:"+value.SiteID.String(), nil
	case *WAFPolicy: return value.NodeID, "waf:"+value.SiteID.String(), nil
	case ServicePolicy: return value.NodeID, string(value.Service), nil
	case *ServicePolicy: return value.NodeID, string(value.Service), nil
	case PackageTransaction: return value.NodeID, "", nil
	case *PackageTransaction: return value.NodeID, "", nil
	case ManagedService: return value.NodeID, string(value.KindName)+":"+value.TenantID.String(), nil
	case *ManagedService: return value.NodeID, string(value.KindName)+":"+value.TenantID.String(), nil
	default: return ResourceID{}, "", ErrInvalidResource
	}
}

func RewriteResource(resource Resource, generation uint64, status ResourceStatus) (Resource, error) {
	metadata := resource.Meta(); metadata.Generation, metadata.Status = generation, status
	switch value := resource.(type) {
	case *ResourceProfile: copy := *value; copy.Metadata = metadata; return copy, nil
	case *TransferAccount: copy := *value; copy.Metadata = metadata; return copy, nil
	case *FirewallPolicy: copy := *value; copy.Metadata = metadata; return copy, nil
	case *SSHPolicy: copy := *value; copy.Metadata = metadata; return copy, nil
	case *SSHKey: copy := *value; copy.Metadata = metadata; return copy, nil
	case *WAFPolicy: copy := *value; copy.Metadata = metadata; return copy, nil
	case *ServicePolicy: copy := *value; copy.Metadata = metadata; return copy, nil
	case *PackageTransaction: copy := *value; copy.Metadata = metadata; return copy, nil
	case *ManagedService: copy := *value; copy.Metadata = metadata; return copy, nil
	default: return nil, ErrInvalidResource
	}
}

func setStatus(resource Resource, status ResourceStatus) {
	switch value := resource.(type) {
	case *ResourceProfile: value.Status = status
	case *TransferAccount: value.Status = status
	case *FirewallPolicy: value.Status = status
	case *SSHPolicy: value.Status = status
	case *SSHKey: value.Status = status
	case *WAFPolicy: value.Status = status
	case *ServicePolicy: value.Status = status
	case *PackageTransaction: value.Status = status
	case *ManagedService: value.Status = status
	}
}

func scopeKey(scope EnforcementScope) string {
	return string(scope.Kind)+":"+scope.TenantID.String()+":"+scope.SiteID.String()
}

func validateMetadata(metadata Metadata) error {
	if metadata.ID.IsZero() || metadata.NodeID.IsZero() || metadata.Generation == 0 || !validStatus(metadata.Status) { return ErrInvalidResource }
	if metadata.SiteID.String() != "" && metadata.TenantID.String() == "" { return ErrInvalidResource }
	return nil
}

func validateNodeMetadata(metadata Metadata) error {
	if validateMetadata(metadata) != nil || metadata.TenantID.String() != "" || metadata.SiteID.String() != "" { return ErrInvalidResource }
	return nil
}

func validStatus(status ResourceStatus) bool {
	switch status.Lifecycle { case LifecycleProvisioning, LifecycleReady, LifecycleUpdating, LifecycleDisabled, LifecycleDeleting, LifecycleDeleted, LifecycleQuarantined: default: return false }
	switch status.Health { case HealthUnknown, HealthHealthy, HealthDegraded, HealthUnavailable: default: return false }
	switch status.Reconciliation { case ReconciliationPending, ReconciliationInSync, ReconciliationDrifted, ReconciliationFailed, ReconciliationAmbiguous: default: return false }
	return status.ProofDigest == "" || validSHA256(status.ProofDigest)
}

func validSHA256(value string) bool {
	if len(value) != 64 { return false }
	for index := range value { if !(value[index] >= '0' && value[index] <= '9' || value[index] >= 'a' && value[index] <= 'f') { return false } }
	return true
}

func validCoverage(coverage AccountingCoverage) bool {
	for _, quality := range []AccountingQuality{coverage.Web, coverage.PHP, coverage.Database, coverage.Mail} {
		if quality != AccountingExact && quality != AccountingAttributed && quality != AccountingEstimated && quality != AccountingUnavailable { return false }
	}
	seen := map[AccountingLimitation]struct{}{}
	for _, limitation := range coverage.Limitations {
		switch limitation { case LimitationSharedDatabase, LimitationSharedWeb, LimitationSharedMail, LimitationEncryptedTraffic: default: return false }
		if _, exists := seen[limitation]; exists { return false }; seen[limitation] = struct{}{}
	}
	return true
}

func validFirewallAction(action FirewallAction) bool { return action == FirewallAccept || action == FirewallDrop || action == FirewallReject }
func validPrefix(prefix netip.Prefix) bool { return prefix.IsValid() && prefix == prefix.Masked() }

func validMonthlyPeriod(start, end time.Time) bool {
	start = start.UTC(); end = end.UTC()
	if start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 || start.Nanosecond() != 0 || end.Hour() != 0 || end.Minute() != 0 || end.Second() != 0 || end.Nanosecond() != 0 { return false }
	return end.Equal(start.AddDate(0, 1, 0))
}
func validateFirewallRule(rule FirewallRule) error {
	if rule.ID.IsZero() || rule.Priority == 0 || !validFirewallAction(rule.Action) || (rule.Family != FamilyIPv4 && rule.Family != FamilyIPv6) ||
		(rule.Protocol != ProtocolTCP && rule.Protocol != ProtocolUDP && rule.Protocol != ProtocolICMP) || len(rule.Sources) > 256 || len(rule.DestinationPorts) > 64 { return ErrInvalidResource }
	for _, prefix := range rule.Sources { if !validPrefix(prefix) || prefix.Addr().Is4() != (rule.Family == FamilyIPv4) { return ErrInvalidResource } }
	for _, ports := range rule.DestinationPorts { if ports.From == 0 || ports.To < ports.From || rule.Protocol == ProtocolICMP { return ErrInvalidResource } }
	return nil
}

func validateWAFPack(pack WAFPack) error {
	if pack.Provider.IsZero() || pack.Name.IsZero() || len(pack.Version) == 0 || len(pack.Version) > 128 || !validSHA256(pack.ContentDigest) || strings.ContainsAny(pack.Version, "\r\n\x00") { return ErrInvalidResource }
	return nil
}

func validateWAFRule(rule WAFRule) error {
	if rule.ID == 0 || rule.Phase < 1 || rule.Phase > 5 || (rule.Target != WAFTargetURI && rule.Target != WAFTargetArgs && rule.Target != WAFTargetHeaders && rule.Target != WAFTargetBody) ||
		(rule.Operator != WAFOperatorRegex && rule.Operator != WAFOperatorContains && rule.Operator != WAFOperatorEquals) || len(rule.Pattern) == 0 || len(rule.Pattern) > 8192 || strings.ContainsAny(rule.Pattern, "\r\n\x00") || len(rule.Actions) == 0 || len(rule.Actions) > 3 || rule.Severity > 7 || rule.ID >= 990000000 { return ErrInvalidResource }
	seen := map[WAFAction]struct{}{}; disruptive := 0
	for _, action := range rule.Actions { if action != WAFActionDeny && action != WAFActionLog && action != WAFActionPass { return ErrInvalidResource }; if _, exists := seen[action]; exists { return ErrInvalidResource }; seen[action] = struct{}{}; if action == WAFActionDeny || action == WAFActionPass { disruptive++ } }
	if disruptive != 1 { return ErrInvalidResource }
	if rule.Operator == WAFOperatorRegex { if _, err := regexp.Compile(rule.Pattern); err != nil { return ErrInvalidResource } }
	return nil
}

func validateWAFExclusion(exclusion WAFExclusion) error {
	if len(exclusion.RuleIDs) == 0 || len(exclusion.RuleIDs) > 256 || exclusion.ReasonCode.IsZero() || exclusion.ExpiresAt.IsZero() || len(exclusion.RequestPathPrefix) > 2048 || strings.ContainsAny(exclusion.RequestPathPrefix, "\r\n\x00") { return ErrInvalidResource }
	for _, name := range exclusion.ArgumentNames { if _, err := safeOpaque(name, 128); err != nil { return ErrInvalidResource } }
	return nil
}

func validService(service ServiceName) bool {
	switch service { case ServiceWebEnterprise, ServiceWebOpenLiteSpeed, ServiceMariaDB, ServicePostfix, ServiceDovecot, ServicePowerDNS, ServicePureFTPd, ServiceRedis, ServiceElasticsearch, ServicePanel: return true }
	return false
}

func validateProbe(probe ServiceHealthProbe) error {
	switch probe.Kind {
	case ProbeSystemd:
		if probe.Port != 0 || probe.ExpectedProtocol != "" { return ErrInvalidResource }
	case ProbeTCP:
		if probe.Port == 0 || probe.ExpectedProtocol != "" { return ErrInvalidResource }
	case ProbeHTTP:
		if probe.Port == 0 || probe.ExpectedProtocol != ProofHTTP { return ErrInvalidResource }
	case ProbeMariaDB:
		if probe.Port == 0 || probe.ExpectedProtocol != ProofMySQL { return ErrInvalidResource }
	case ProbeRedis:
		if probe.Port == 0 || probe.ExpectedProtocol != ProofRedis { return ErrInvalidResource }
	case ProbeElasticsearch:
		if probe.Port == 0 || probe.ExpectedProtocol != ProofElasticsearch { return ErrInvalidResource }
	default: return ErrInvalidResource
	}
	return nil
}

func validateRedis(settings RedisSettings) error {
	if settings.MemoryMaxBytes < 16<<20 || settings.MaxClients == 0 || settings.CredentialSecretRef.IsZero() ||
		(settings.EvictionPolicy != RedisNoEviction && settings.EvictionPolicy != RedisAllKeysLRU && settings.EvictionPolicy != RedisVolatileLRU) ||
		(settings.Persistence != RedisRDB && settings.Persistence != RedisAOF && settings.Persistence != RedisRDBAOF) || validateRedisRuntimeSupport(settings.Runtime) != nil { return ErrInvalidResource }
	return nil
}

func validateRedisRuntimeSupport(support RedisRuntimeSupport) error {
	major,_,_:=strings.Cut(support.RedisVersion,".")
	if !validateManagedRedisVersion(support.RedisVersion) || (major!="7"&&major!="8") || support.PackageChannel != "stable" ||
		(support.Architecture != "amd64" && support.Architecture != "arm64") || !validSHA256(support.QualificationDigest) { return ErrInvalidResource }
	if support.OSFamily == "ubuntu" && (support.OSVersion == "22.04" || support.OSVersion == "24.04") { return nil }
	if support.OSFamily == "almalinux" && (support.OSVersion == "8" || support.OSVersion == "9") { return nil }
	return ErrInvalidResource
}

func validateElasticsearch(settings ElasticsearchSettings) error {
	if settings.HeapBytes < 256<<20 || settings.StorageBytes < 1<<30 || settings.MaxShards == 0 || settings.CredentialSecretRef.IsZero() || settings.SnapshotRepositoryRef.IsZero() { return ErrInvalidResource }
	return nil
}

func canonicalStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
