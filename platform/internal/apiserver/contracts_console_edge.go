package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/mailtelemetry"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
)

// EdgeCall is the complete authority and concurrency context passed from the
// authenticated API edge to a domain adapter. Domain adapters never receive a
// shell command, host path, native configuration document, or SQL fragment.
type EdgeCall struct {
	CommandID          string                  `json:"command_id"`
	IdempotencyKey     string                  `json:"idempotency_key,omitempty"`
	TenantID           string                  `json:"tenant_id,omitempty"`
	ResourceID         string                  `json:"resource_id,omitempty"`
	ExpectedGeneration uint64                  `json:"expected_generation,omitempty"`
	PrincipalID        string                  `json:"principal_id"`
	SessionID          string                  `json:"session_id,omitempty"`
	CredentialID       string                  `json:"credential_id"`
	AuthzEpoch         uint64                  `json:"authz_epoch"`
	Assurance          identity.AssuranceLevel `json:"assurance"`
	Origin             string                  `json:"origin,omitempty"`
	CSRFBinding        string                  `json:"csrf_binding,omitempty"`
}

type EdgePagePayload struct {
	Limit  uint16 `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

type EdgePage[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Total      uint64 `json:"total,omitempty"`
}

type EdgeMutation[T any] struct {
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Generation  uint64 `json:"generation,omitempty"`
	Resource    T      `json:"resource"`
}

type DashboardNodeProjection struct {
	ID              string    `json:"id"`
	Hostname        string    `json:"hostname"`
	Health          string    `json:"health"`
	Version         string    `json:"version"`
	Architecture    string    `json:"architecture"`
	OperatingSystem string    `json:"operating_system"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type DashboardCountProjection struct {
	Sites       uint64 `json:"sites"`
	Databases   uint64 `json:"databases"`
	Mailboxes   uint64 `json:"mailboxes"`
	Containers  uint64 `json:"containers"`
	Findings    uint64 `json:"findings"`
	Operations  uint64 `json:"operations"`
}

type DashboardSummary struct {
	Node       DashboardNodeProjection  `json:"node"`
	Counts     DashboardCountProjection `json:"counts"`
	Warnings   []string                 `json:"warnings"`
	GeneratedAt time.Time               `json:"generated_at"`
}

type HostingSiteProjection struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	ProjectID       string    `json:"project_id"`
	PrimaryHostname string    `json:"primary_hostname"`
	PHPProfile      string    `json:"php_profile"`
	Lifecycle       string    `json:"lifecycle"`
	DiskUsage       uint64    `json:"disk_usage"`
	Bandwidth       uint64    `json:"bandwidth"`
	Generation      uint64    `json:"generation"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type HostingBindingProjection struct {
	ID             string    `json:"id"`
	SiteID         string    `json:"site_id"`
	Hostname       string    `json:"hostname"`
	Relationship   string    `json:"relationship"`
	RedirectTarget string    `json:"redirect_target,omitempty"`
	TLS            string    `json:"tls"`
	Routing        string    `json:"routing"`
	AccessPolicyRef string   `json:"access_policy_ref,omitempty"`
	AccessPolicyState string `json:"access_policy_state,omitempty"`
	AccessPolicyGeneration uint64 `json:"access_policy_generation,omitempty"`
	Generation     uint64    `json:"generation"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type HostingClonePayload struct {
	PrimaryHostname string `json:"primary_hostname"`
	ProjectID       string `json:"project_id"`
	DatabaseInstanceID string `json:"database_instance_id"`
	CopyDatabase    bool   `json:"copy_database"`
	AccessCredentialRef string `json:"access_credential_ref"`
	DatabaseClientCertificate string `json:"database_client_certificate,omitempty"`
	DatabaseClientKey string `json:"database_client_key,omitempty"`
}

type ApplicationCloneMaterial struct {
	DatabaseClientCertificate []byte `json:"-"`
	DatabaseClientKey []byte `json:"-"`
}

func takeApplicationCloneMaterial(payload *HostingClonePayload) ApplicationCloneMaterial {
	material:=ApplicationCloneMaterial{[]byte(payload.DatabaseClientCertificate),[]byte(payload.DatabaseClientKey)}
	payload.DatabaseClientCertificate,payload.DatabaseClientKey="",""
	return material
}

func (material ApplicationCloneMaterial) clear() {
	clearSecret(material.DatabaseClientCertificate)
	clearSecret(material.DatabaseClientKey)
}

type HostingPreviewPayload struct {
	TTLSeconds      uint32 `json:"ttl_seconds,omitempty"`
	MaximumRequests uint32 `json:"maximum_requests,omitempty"`
}

type HostingPreviewGrant struct {
	ID              string    `json:"id"`
	URL             string    `json:"url"`
	Hostname        string    `json:"hostname"`
	RequestBudget   uint32    `json:"request_budget"`
	SiteGeneration  uint64    `json:"site_generation"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type HostingBindingPayload struct {
	SiteID         string `json:"site_id"`
	Hostname       string `json:"hostname"`
	Relationship   string `json:"relationship"`
	RedirectTarget string `json:"redirect_target,omitempty"`
}

type HostingAccessPolicyPayload struct {
	Enabled       bool   `json:"enabled"`
	CredentialRef string `json:"credential_ref,omitempty"`
}

type DatabaseProjection struct {
	ConsolePrincipals []DatabasePrincipalOption `json:"console_principals"`
	ID         string    `json:"id"`
	SiteID     string    `json:"site_id"`
	Name       string    `json:"name"`
	Instance   string    `json:"instance"`
	Size       uint64    `json:"size"`
	Principals uint64    `json:"principals"`
	Status     string    `json:"status"`
	Generation uint64    `json:"generation"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type DatabaseCreateManagedPayload struct {
	SiteID       string `json:"site_id"`
	InstanceID   string `json:"instance_id"`
	Name         string `json:"name"`
	Charset      string `json:"charset"`
	Collation    string `json:"collation"`
	QuotaBytes   uint64 `json:"quota_bytes"`
}

type DatabasePrincipalCreateManagedPayload struct {
	Name       string   `json:"name"`
	Password   string   `json:"password"`
	HostScope  string   `json:"host_scope"`
	Privileges []string `json:"privileges"`
}

type DatabasePrincipalProjection struct {
	ID              string   `json:"id"`
	DatabaseID      string   `json:"database_id"`
	Name            string   `json:"name"`
	HostScope       string   `json:"host_scope"`
	NetworkPolicyID string   `json:"network_policy_id,omitempty"`
	Privileges      []string `json:"privileges"`
	Status          string   `json:"status"`
	Generation      uint64   `json:"generation"`
}

type DatabaseNetworkConfigureManagedPayload struct {
	Interfaces       []string `json:"interfaces"`
	AllowedCIDRs     []string `json:"allowed_cidrs"`
	TLSMode          string   `json:"tls_mode"`
	Verification     string   `json:"verification"`
	HighRiskApproval string   `json:"high_risk_approval"`
}

type DatabaseNetworkPolicyProjection struct {
	ID           string   `json:"id"`
	InstanceID   string   `json:"instance_id"`
	Interfaces   []string `json:"interfaces"`
	AllowedCIDRs []string `json:"allowed_cidrs"`
	TLS          string   `json:"tls"`
	Verification string   `json:"verification"`
	Status       string   `json:"status"`
	Generation   uint64   `json:"generation"`
}

// DatabaseInstanceProjection deliberately omits protected secret references.
// Operators can inspect placement, pinned endpoint identity, capacity, and
// observed state without gaining a material-broker lookup handle.
type DatabaseInstanceProjection struct {
	ID             string `json:"id"`
	Placement      string `json:"placement"`
	Endpoint       string `json:"endpoint"`
	ServerName     string `json:"server_name,omitempty"`
	TLS            string `json:"tls"`
	Version        string `json:"version"`
	StorageBytes   uint64 `json:"storage_bytes"`
	MemoryBytes    uint64 `json:"memory_bytes"`
	MaxConnections uint32 `json:"max_connections"`
	Health         string `json:"health"`
	Status         string `json:"status"`
	Reachable      bool   `json:"reachable"`
	TLSVerified    bool   `json:"tls_verified"`
	ProofDigest    string `json:"proof_digest,omitempty"`
	ObservedAt     time.Time `json:"observed_at,omitempty"`
	Generation     uint64 `json:"generation"`
}

type DatabaseExternalEnrollmentPayload struct {
	ID                       string `json:"id"`
	Host                     string `json:"host"`
	Port                     uint16 `json:"port"`
	TLSMode                  string `json:"tls_mode"`
	VersionMajor             uint16 `json:"version_major"`
	VersionMinor             uint16 `json:"version_minor"`
	VersionPatch             uint16 `json:"version_patch,omitempty"`
	NetworkPolicyID          string `json:"network_policy_id"`
	StorageBytes             uint64 `json:"storage_bytes"`
	MemoryBytes              uint64 `json:"memory_bytes"`
	MaxConnections           uint32 `json:"max_connections"`
	AdministratorUsername    string `json:"administrator_username"`
	AdministratorPassword    string `json:"administrator_password"`
	ClientCertificatePEM     string `json:"client_certificate_pem,omitempty"`
	ClientKeyPEM             string `json:"client_key_pem,omitempty"`
	CertificateAuthorityPEM  string `json:"certificate_authority_pem"`
	ApprovalRef              string `json:"approval_ref"`
}

type DatabaseExternalEnrollmentSecrets struct {
	AdministratorPassword   []byte
	ClientCertificatePEM    []byte
	ClientKeyPEM            []byte
	CertificateAuthorityPEM []byte
}

type AccessCredentialProjection struct {
	ID         string    `json:"id"`
	SiteID     string    `json:"site_id"`
	Label      string    `json:"label"`
	Kind       string    `json:"kind"`
	State      string    `json:"state"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	Generation uint64    `json:"generation"`
}

type AccessCredentialCreatePayload struct {
	SiteID       string `json:"site_id"`
	Kind         string `json:"kind"`
	Label        string `json:"label"`
	PublicKey    string `json:"public_key,omitempty"`
	Secret       string `json:"secret,omitempty"`
	Permission   string `json:"permission,omitempty"`
	ExpiresInSec uint32 `json:"expires_in_seconds,omitempty"`
}

type AccessCredentialRotatePayload struct {
	Secret string `json:"secret"`
}

type AccessTerminalPayload struct {
	Columns     uint16 `json:"columns,omitempty"`
	Rows        uint16 `json:"rows,omitempty"`
	ClientNonce string `json:"client_nonce"`
}

type AccessTerminalGrant struct {
	ID                 string    `json:"id"`
	Endpoint           string    `json:"endpoint"`
	OneTimeToken       string    `json:"one_time_token"`
	HostKeyFingerprint string    `json:"host_key_fingerprint"`
	ExpiresAt          time.Time `json:"expires_at"`
}

type AccessFileWritePayload struct {
	SiteID      string `json:"site_id,omitempty"`
	RelativePath string `json:"relative_path"`
	ContentBase64 string `json:"content_base64"`
	IfMatch     string `json:"if_match,omitempty"`
}

type ApplicationProjection struct {
	ID         string    `json:"id"`
	SiteID     string    `json:"site_id"`
	Hostname   string    `json:"hostname"`
	Type       string    `json:"type"`
	Version    string    `json:"version"`
	Health     string    `json:"health"`
	Updates    uint64    `json:"updates"`
	Generation uint64    `json:"generation"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type ApplicationInstallEdgePayload struct {
	SiteID      string `json:"site_id"`
	DatabaseInstanceID string `json:"database_instance_id"`
	Application string `json:"application"`
	Version     string `json:"version"`
	RecipeID    string `json:"recipe_id,omitempty"`
	AdministratorUsername string `json:"administrator_username"`
	AdministratorEmail string `json:"administrator_email"`
	AdministratorDisplayName string `json:"administrator_display_name"`
	AdministratorPassword string `json:"administrator_password"`
	DatabaseClientCertificate string `json:"database_client_certificate,omitempty"`
	DatabaseClientKey string `json:"database_client_key,omitempty"`
	Locale string `json:"locale,omitempty"`
	Timezone string `json:"timezone,omitempty"`
	Title string `json:"title,omitempty"`
}

type ApplicationInstallMaterial struct {
	AdministratorPassword []byte `json:"-"`
	DatabaseClientCertificate []byte `json:"-"`
	DatabaseClientKey []byte `json:"-"`
}

func takeApplicationInstallMaterial(payload *ApplicationInstallEdgePayload) ApplicationInstallMaterial {
	material:=ApplicationInstallMaterial{[]byte(payload.AdministratorPassword),[]byte(payload.DatabaseClientCertificate),[]byte(payload.DatabaseClientKey)}
	payload.AdministratorPassword,payload.DatabaseClientCertificate,payload.DatabaseClientKey="","",""
	return material
}

func (material ApplicationInstallMaterial) clear() {
	clearSecret(material.AdministratorPassword)
	clearSecret(material.DatabaseClientCertificate)
	clearSecret(material.DatabaseClientKey)
}

type ApplicationDiscoveryEdgePayload struct {
	Root string `json:"root,omitempty"`
	Applications EdgeStringList `json:"applications,omitempty"`
	MaximumDepth uint8 `json:"maximum_depth,omitempty"`
	MaximumCandidates uint16 `json:"maximum_candidates,omitempty"`
}

type ApplicationAdoptEdgePayload struct {
	Candidate apps.DiscoveryCandidate `json:"candidate"`
	RecipeID string `json:"recipe_id,omitempty"`
}

type ApplicationDiscoveryEdgeResult struct {
	Candidates []apps.DiscoveryCandidate `json:"candidates"`
	Generation uint64 `json:"generation"`
}

type ApplicationUpdateEdgePayload struct {
	Version  string `json:"version,omitempty"`
	RecipeID string `json:"recipe_id,omitempty"`
}

type ApplicationScanPayload struct {
	Mode       string `json:"mode,omitempty"`
	ProviderID string `json:"provider_id,omitempty"`
}

type ApplicationAutologinPayload struct {
	WordPressUserID uint64 `json:"wordpress_user_id,omitempty"`
	TTLSeconds      uint32 `json:"ttl_seconds,omitempty"`
	BridgeDigest    string `json:"bridge_digest"`
	BridgeSignature string `json:"bridge_signature"`
	SigningKeyID    string `json:"signing_key_id"`
}

type ApplicationCachePurgePayload struct {
	Scope  string         `json:"scope,omitempty"`
	Values EdgeStringList `json:"values,omitempty"`
}

type ApplicationGrant struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

type BackupPolicyCreatePayload struct {
	Name         string `json:"name,omitempty"`
	Scope        string `json:"scope"`
	Schedule     string `json:"schedule"`
	RepositoryID string `json:"repository_id"`
	Retention    string `json:"retention"`
	Consistency backup.ConsistencyClass `json:"consistency"`
	Components []backup.ComponentKind `json:"components"`
}

type BackupRestorePlanPayload struct {
	RecoveryPointID string            `json:"recovery_point_id"`
	TargetScope     string            `json:"target_scope"`
	DomainMapping   map[string]string `json:"domain_mapping,omitempty"`
}

type BackupPolicyProjection struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Scope        string    `json:"scope"`
	Schedule     string    `json:"schedule"`
	RepositoryID string    `json:"repository_id"`
	Retention    string    `json:"retention"`
	State        string    `json:"state"`
	Generation   uint64    `json:"generation"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type BackupRestorePlanProjection struct {
	ID              string            `json:"id"`
	RecoveryPointID string            `json:"recovery_point_id"`
	TargetScope     string            `json:"target_scope"`
	DomainMapping   map[string]string `json:"domain_mapping,omitempty"`
	RequiredBytes   uint64            `json:"required_bytes"`
	PlanDigest      string            `json:"plan_digest"`
	Generation      uint64            `json:"generation"`
}

type DNSZoneImportPayload struct {
	RecordSets []DNSRecordSetInput `json:"record_sets"`
	Replace    bool                `json:"replace"`
}

type DNSRecordSetInput struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	TTL    uint32   `json:"ttl"`
	Values []string `json:"values"`
}

type DNSSECConfigurePayload struct {
	Enabled           bool          `json:"enabled"`
	Algorithm         string        `json:"algorithm,omitempty"`
	SignatureValidity time.Duration `json:"signature_validity,omitempty"`
	RolloverAfter     time.Duration `json:"rollover_after,omitempty"`
	PrepublishFor     time.Duration `json:"prepublish_for,omitempty"`
}

type DNSZoneMutationProjection struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Serial     uint64 `json:"serial"`
	DNSSEC     string `json:"dnssec"`
	Generation uint64 `json:"generation"`
}

type CertificateIssueEdgePayload struct {
	Consumer  string         `json:"consumer"`
	Names     EdgeStringList `json:"names"`
	Challenge string         `json:"challenge"`
}

type EdgeStringList []string

func (values *EdgeStringList) UnmarshalJSON(content []byte) error {
	var items []string
	if err := json.Unmarshal(content, &items); err == nil { *values=append((*values)[:0], items...); return nil }
	var text string
	if err := json.Unmarshal(content, &text); err != nil { return invalid("string list") }
	items = strings.FieldsFunc(text, func(character rune) bool { return character==',' || character==';' || character=='\n' || character=='\r' || character=='\t' || character==' ' })
	*values=append((*values)[:0], items...)
	return nil
}

type CertificateDeployEdgePayload struct {
	Consumer string `json:"consumer"`
}

type CertificateEdgeProjection struct {
	ID         string    `json:"id"`
	Consumer   string    `json:"consumer"`
	Names      []string  `json:"names"`
	State      string    `json:"state"`
	NotAfter   time.Time `json:"not_after,omitempty"`
	Generation uint64    `json:"generation"`
}

type MailDiagnosticPayload struct {
	Depth string `json:"depth,omitempty"`
}

type MailRouteProjection struct {
	ID         string    `json:"id"`
	DomainID   string    `json:"domain_id"`
	Source     string    `json:"source"`
	Targets    []string  `json:"targets"`
	Kind       string    `json:"kind"`
	State      string    `json:"state"`
	Generation uint64    `json:"generation"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type MailDiagnosticProjection struct {
	ID          string    `json:"id"`
	ResourceID  string    `json:"resource_id"`
	State       string    `json:"state"`
	Checks      []string  `json:"checks"`
	Findings    []string  `json:"findings"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type MailTelemetryHealth struct {
	State             string    `json:"state"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
	ObservedAt        time.Time `json:"observed_at,omitempty"`
	LastIngestAt      time.Time `json:"last_ingest_at,omitempty"`
}

type MailTelemetryQueryPayload struct {
	DomainID    string                   `json:"domain_id,omitempty"`
	MailboxID   string                   `json:"mailbox_id,omitempty"`
	Categories  []mailtelemetry.Category `json:"categories,omitempty"`
	Start       time.Time                `json:"start,omitempty"`
	End         time.Time                `json:"end,omitempty"`
	Limit       uint16                   `json:"limit,omitempty"`
	Cursor      string                   `json:"cursor,omitempty"`
	MaximumRows uint16                   `json:"maximum_rows,omitempty"`
}

type MailTelemetryEventProjection struct {
	mailtelemetry.Event
	IngestionState string `json:"ingestion_state"`
}

type MailTelemetryEventPage struct {
	Items      []MailTelemetryEventProjection `json:"items"`
	NextCursor string                         `json:"next_cursor,omitempty"`
	Missing    []mailtelemetry.ParseGap       `json:"missing,omitempty"`
	Truncated  bool                           `json:"truncated,omitempty"`
	Health     MailTelemetryHealth            `json:"health"`
}

type MailTelemetryStatisticsPayload struct {
	DomainID  string    `json:"domain_id,omitempty"`
	MailboxID string    `json:"mailbox_id,omitempty"`
	Start     time.Time `json:"start,omitempty"`
	End       time.Time `json:"end,omitempty"`
}

type MailTelemetryStatisticsResult struct {
	Statistics mailtelemetry.Statistics `json:"statistics"`
	Health     MailTelemetryHealth      `json:"health"`
}

type MailTelemetryPolicyMutationPayload struct {
	Action                string `json:"-"`
	PolicyID              string `json:"policy_id,omitempty"`
	DomainID              string `json:"domain_id,omitempty"`
	MailboxID             string `json:"mailbox_id,omitempty"`
	RetentionDays         uint32 `json:"retention_days,omitempty"`
	ProviderRetentionDays uint32 `json:"provider_retention_days,omitempty"`
	StorageBytes          int64  `json:"storage_bytes,omitempty"`
	ExportAllowed         *bool  `json:"export_allowed,omitempty"`
	BackupHistory         *bool  `json:"backup_history,omitempty"`
	MigrationHistory      *bool  `json:"migration_history,omitempty"`
}

type MailTelemetryPolicyProjection struct {
	ID                    string    `json:"id"`
	DomainID              string    `json:"domain_id,omitempty"`
	MailboxID             string    `json:"mailbox_id,omitempty"`
	State                 string    `json:"state"`
	RetentionDays         uint32    `json:"retention_days"`
	ProviderRetentionDays uint32    `json:"provider_retention_days"`
	SecurityRetentionDays uint32    `json:"security_retention_days"`
	AuditRetentionDays    uint32    `json:"audit_retention_days"`
	StorageBytes          int64     `json:"storage_bytes"`
	ExportAllowed         bool      `json:"export_allowed"`
	BackupHistory         bool      `json:"backup_history"`
	MigrationHistory      bool      `json:"migration_history"`
	Generation            uint64    `json:"generation"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type MailTelemetryPolicyPage struct {
	Items      []MailTelemetryPolicyProjection `json:"items"`
	NextCursor string                          `json:"next_cursor,omitempty"`
	Health     MailTelemetryHealth             `json:"health"`
}

type MailTelemetryPurgePayload struct {
	Limit uint16 `json:"limit,omitempty"`
}

type MailAbusePagePayload struct {
	Kind   string `json:"-"`
	Limit  uint16 `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

type MailAbuseProjection struct {
	ID                 string    `json:"id"`
	Kind               string    `json:"kind"`
	DomainID           string    `json:"domain_id,omitempty"`
	MailboxID          string    `json:"mailbox_id,omitempty"`
	Pattern            string    `json:"pattern,omitempty"`
	Action             string    `json:"action,omitempty"`
	State              string    `json:"state"`
	SourcePseudonym    string    `json:"source_pseudonym"`
	ProtectedSourceRef string    `json:"protected_source_ref,omitempty"`
	Observed           uint64    `json:"observed,omitempty"`
	DistinctTargets    uint64    `json:"distinct_targets,omitempty"`
	EvidenceDigest     string    `json:"evidence_digest"`
	BodyDigest         string    `json:"body_digest,omitempty"`
	MissingData        bool      `json:"missing_data,omitempty"`
	ProposedBy         string    `json:"proposed_by,omitempty"`
	ApprovedBy         string    `json:"approved_by,omitempty"`
	OwnerReceiptID     string    `json:"owner_receipt_id,omitempty"`
	Generation         uint64    `json:"generation"`
	OccurredAt         time.Time `json:"occurred_at"`
	ExpiresAt          time.Time `json:"expires_at,omitempty"`
}

type MailAbusePage struct {
	Items      []MailAbuseProjection `json:"items"`
	NextCursor string                `json:"next_cursor,omitempty"`
	Health     MailTelemetryHealth   `json:"health"`
}

type MailAbuseReviewPayload struct {
	Action           string    `json:"-"`
	ApprovedDigest   string    `json:"approved_digest,omitempty"`
	EvidenceRef      string    `json:"evidence_ref,omitempty"`
	RecoveryIntentID string    `json:"recovery_intent_id,omitempty"`
	ReasonDigest     string    `json:"reason_digest,omitempty"`
	AllowUntil       time.Time `json:"allow_until,omitempty"`
}

type WebmailDirectoryPayload struct {
	Session   mail.MailSession `json:"session"`
	MailboxID mail.MailboxID   `json:"mailbox_id,omitempty"`
	Limit     uint16           `json:"limit,omitempty"`
	Cursor    string           `json:"cursor,omitempty"`
}

type WebmailReplyPayload struct {
	Session   mail.MailSession `json:"session"`
	MailboxID mail.MailboxID   `json:"mailbox_id,omitempty"`
	MessageID mail.MessageID   `json:"message_id"`
	To        []mail.Address   `json:"to"`
	CC        []mail.Address   `json:"cc,omitempty"`
	Subject   string           `json:"subject"`
	Text      string           `json:"text"`
}

type ContainerProjection struct {
	ID           string    `json:"id"`
	SiteID       string    `json:"site_id"`
	Name         string    `json:"name"`
	Image        string    `json:"image"`
	Lifecycle    string    `json:"lifecycle"`
	Health       string    `json:"health"`
	RestartCount uint64    `json:"restart_count"`
	Generation   uint64    `json:"generation"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ContainerCreateEdgePayload struct {
	SiteID      string `json:"site_id"`
	Image       string `json:"image"`
	Recipe      string `json:"recipe,omitempty"`
	MemoryBytes uint64 `json:"memory_bytes"`
}

type ContainerExecPayload struct {
	CommandID  string   `json:"command_id"`
	Arguments  []string `json:"arguments,omitempty"`
	TTLSeconds uint32   `json:"ttl_seconds,omitempty"`
	// Token is generated by the trusted client and is never returned or
	// persisted by the control plane. Only its SHA-256 digest is stored with
	// the one-time grant.
	Token      string   `json:"token"`
}

type ContainerExecGrant struct {
	ID        string    `json:"id"`
	Endpoint  string    `json:"endpoint"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ContainerLogPayload struct {
	Start  time.Time `json:"start,omitempty"`
	End    time.Time `json:"end,omitempty"`
	Cursor string    `json:"cursor,omitempty"`
	Limit  uint16    `json:"limit,omitempty"`
}

type ContainerLogPage struct {
	Lines      []string `json:"lines"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type OperationsServiceProjection struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ActiveState  string    `json:"active_state"`
	SubState     string    `json:"sub_state"`
	RestartCount uint64    `json:"restart_count"`
	Health       string    `json:"health"`
	Generation   uint64    `json:"generation"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type OperationsDiagnosticPayload struct {
	Depth string    `json:"depth,omitempty"`
	Since time.Time `json:"since,omitempty"`
}

type SecurityFindingProjection struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Severity       string    `json:"severity"`
	ResourceKind   string    `json:"resource_kind"`
	ResourceID     string    `json:"resource_id"`
	Summary        string    `json:"summary"`
	State          string    `json:"state"`
	EvidenceDigest string    `json:"evidence_digest"`
	Generation     uint64    `json:"generation"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type SecurityScanPayload struct {
	Scope string `json:"scope,omitempty"`
	Depth string `json:"depth,omitempty"`
}

type SecurityRemediationPayload struct {
	Strategy       string `json:"strategy"`
	EvidenceDigest string `json:"evidence_digest"`
}

type SecuritySuppressPayload struct {
	Reason         string    `json:"reason"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	EvidenceDigest string    `json:"evidence_digest"`
}

type FleetNodeProjection struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	State               string    `json:"state"`
	PeerID              string    `json:"peer_id,omitempty"`
	CentralEndpoint     string    `json:"central_endpoint,omitempty"`
	CAFingerprint       string    `json:"ca_fingerprint,omitempty"`
	AuthorityEpoch      uint64    `json:"authority_epoch,omitempty"`
	EnrollmentExpiresAt time.Time `json:"enrollment_expires_at,omitempty"`
	Roles               []string  `json:"roles"`
	Architecture        string    `json:"architecture"`
	Version             string    `json:"version"`
	FailureDomain       string    `json:"failure_domain"`
	LastSeenAt          time.Time `json:"last_seen_at,omitempty"`
	UpdatedAt           time.Time `json:"updated_at,omitempty"`
	Generation          uint64    `json:"generation"`
}

type HAWriterAuthorityProjection struct {
	LeaseID            string    `json:"lease_id"`
	ResourceID         string    `json:"resource_id"`
	HolderNodeID       string    `json:"holder_node_id"`
	State              string    `json:"state"`
	EnforcedWritePaths []string  `json:"enforced_write_paths"`
	Generation         uint64    `json:"generation"`
	ExpiresAt          time.Time `json:"expires_at"`
	Current            bool      `json:"current"`
}

type HATopologyStatusProjection struct {
	ID                   string                        `json:"id"`
	SelectedNodeID       string                        `json:"selected_node_id"`
	Name                 string                        `json:"name"`
	State                string                        `json:"state"`
	CoordinatorID        string                        `json:"coordinator_id"`
	MinimumManagers      uint8                         `json:"minimum_managers"`
	AutomaticFailoverConfigured bool                    `json:"automatic_failover_configured"`
	RequiredFenceClasses []string                      `json:"required_fence_classes"`
	Nodes                []FleetNodeProjection         `json:"nodes"`
	WriterAuthorities    []HAWriterAuthorityProjection `json:"writer_authorities"`
	Generation           uint64                        `json:"generation"`
	UpdatedAt            time.Time                     `json:"updated_at"`
}

type HAHealthObservationProjection struct {
	ObserverNodeID   string          `json:"observer_node_id"`
	State            string          `json:"state"`
	Checks           map[string]bool `json:"checks"`
	Latency          time.Duration   `json:"latency"`
	BootID           string          `json:"boot_id"`
	CapabilityDigest string         `json:"capability_digest"`
	ObservedAt       time.Time       `json:"observed_at"`
	ValidUntil       time.Time       `json:"valid_until"`
	Sequence         uint64          `json:"sequence"`
	Fresh            bool            `json:"fresh"`
}

type HANodeHealthProjection struct {
	ID                string                          `json:"id"`
	NodeState         string                          `json:"node_state"`
	Status            string                          `json:"status"`
	Asymmetric        bool                            `json:"asymmetric"`
	FreshObservations uint64                          `json:"fresh_observations"`
	StaleObservations uint64                          `json:"stale_observations"`
	Observations      []HAHealthObservationProjection `json:"observations"`
	Generation        uint64                          `json:"generation"`
}

type FleetEnrollPayload struct {
	PeerID              string `json:"peer_id"`
	CentralEndpoint     string `json:"central_endpoint"`
	EnrollmentToken     string `json:"enrollment_token"`
	CentralFingerprint string `json:"central_fingerprint"`
}

type HANodeDrainPayload struct {
	Deadline time.Time `json:"deadline,omitempty"`
	Force    bool      `json:"force"`
}

type HAPromotionPlanPayload struct {
	ProtectedResourceID   string        `json:"protected_resource_id,omitempty"`
	WriterLeaseGeneration uint64       `json:"writer_lease_generation,omitempty"`
	CandidateNodeID        string        `json:"candidate_node_id"`
	MaximumDataLoss        time.Duration `json:"maximum_data_loss"`
}

type HAPromotionExecutePayload struct {
	PromotionID            string `json:"promotion_id"`
	WriterLeaseGeneration  uint64 `json:"writer_lease_generation"`
	PlanDigest             string `json:"plan_digest"`
	QuorumEvidence         string `json:"quorum_evidence"`
	FenceProviderBindings  string `json:"fence_provider_bindings,omitempty"`
}

type HAPromotionApprovalPayload struct {
	ApprovalID          string    `json:"approval_id"`
	PlanDigest          string    `json:"plan_digest"`
	FenceChallenge      string    `json:"fence_challenge"`
	TenantAuthzEpoch    uint64    `json:"tenant_authz_epoch"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Signature           string    `json:"signature"`
}

type HAPromotionApprovalProjection struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	PromotionID         string    `json:"promotion_id"`
	ActorID             string    `json:"actor_id"`
	PlanDigest          string    `json:"plan_digest"`
	FenceChallenge      string    `json:"fence_challenge"`
	PromotionGeneration uint64    `json:"promotion_generation"`
	AcceptedAt          time.Time `json:"accepted_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type HAPromotionEffectProjection struct {
	Sequence      uint32    `json:"sequence"`
	EffectID      string    `json:"effect_id"`
	Kind          string    `json:"kind"`
	Outcome       string    `json:"outcome"`
	ReceiptDigest string    `json:"receipt_digest,omitempty"`
	Frontier      uint64    `json:"frontier,omitempty"`
	Irreversible  bool      `json:"irreversible"`
	Failure       string    `json:"failure,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
}

type HAPromotionProjection struct {
	ID                    string        `json:"id"`
	ResourceID            string        `json:"resource_id"`
	PreviousWriterNodeID  string        `json:"previous_writer_node_id"`
	CandidateNodeID       string        `json:"candidate_node_id"`
	WriterLeaseGeneration uint64       `json:"writer_lease_generation"`
	MaximumDataLoss       time.Duration `json:"maximum_data_loss"`
	PotentialDataLoss     bool          `json:"potential_data_loss"`
	PlanDigest            string        `json:"plan_digest"`
	State                 string        `json:"state"`
	RunID                 string        `json:"run_id,omitempty"`
	Step                  string        `json:"step,omitempty"`
	Effects               []HAPromotionEffectProjection `json:"effects,omitempty"`
	ReconciliationRequired bool         `json:"reconciliation_required"`
	ReconciliationReason  string        `json:"reconciliation_reason,omitempty"`
	Failure               string        `json:"failure,omitempty"`
	Generation            uint64        `json:"generation"`
}

type MigrationProjection struct {
	ID                 string    `json:"id"`
	Source             string    `json:"source"`
	State              string    `json:"state"`
	Phase              string    `json:"phase"`
	Progress           uint8     `json:"progress"`
	ResourcesTotal     uint64    `json:"resources_total,omitempty"`
	ResourcesCompleted uint64    `json:"resources_completed,omitempty"`
	ResourceErrors     uint64    `json:"resource_errors,omitempty"`
	BytesTransferred   uint64    `json:"bytes_transferred,omitempty"`
	ObjectsTransferred uint64    `json:"objects_transferred,omitempty"`
	ErrorCode          string    `json:"error_code,omitempty"`
	ErrorMessage       string    `json:"error_message,omitempty"`
	Cancelable         bool      `json:"cancelable"`
	Generation         uint64    `json:"generation"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	RollbackDeadline   *time.Time `json:"rollback_deadline,omitempty"`
}

type MigrationProviderProjection struct {
	Source             string `json:"source"`
	Transport          string `json:"transport"`
	EndpointScheme     string `json:"endpoint_scheme"`
	NetworkRequired    bool   `json:"network_required"`
	CreationOperation  string `json:"creation_operation"`
}

type MigrationChunkGCProjection struct {
	MigrationID                  string     `json:"migration_id"`
	TenantID                     string     `json:"tenant_id"`
	Digest                       string     `json:"digest"`
	Size                         uint64     `json:"size"`
	ObjectEpoch                  string     `json:"object_epoch"`
	State                        string     `json:"state"`
	Materialized                 bool       `json:"materialized"`
	QuarantineAfter              time.Time  `json:"quarantine_after"`
	StartedAt                    time.Time  `json:"started_at"`
	AmbiguousEvidenceDigest      string     `json:"ambiguous_evidence_digest"`
	Resolution                   string     `json:"resolution,omitempty"`
	Observation                  string     `json:"observation,omitempty"`
	ReconciledAt                 *time.Time `json:"reconciled_at,omitempty"`
	ReconciliationEvidenceDigest string     `json:"reconciliation_evidence_digest,omitempty"`
	Generation                   uint64     `json:"generation"`
}

type MigrationCreatePayload struct {
	Source         string `json:"source"`
	SourceEndpoint string `json:"source_endpoint"`
}

type MigrationInventoryPayload struct {
	Refresh bool `json:"refresh"`
}

type MigrationPlanPayload struct {
	CollisionPolicy string `json:"collision_policy,omitempty"`
}

type MigrationSyncPayload struct {
	MaximumBytes uint64 `json:"maximum_bytes,omitempty"`
}

type MigrationCutoverPayload struct {
	ApprovalRef string `json:"approval_ref"`
}

type MigrationChunkGCReconcilePayload struct {
	Digest         string `json:"digest"`
	ObjectEpoch    string `json:"object_epoch"`
	EvidenceDigest string `json:"evidence_digest"`
	Resolution     string `json:"resolution"`
}

type IdentityTenantProjection struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ParentID   string    `json:"parent_tenant_id,omitempty"`
	PlanID     string    `json:"plan_id"`
	State      string    `json:"state"`
	Generation uint64    `json:"generation"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type IdentityMembershipProjection struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	PrincipalID string    `json:"principal_id"`
	DisplayName string    `json:"display_name"`
	RoleIDs     []string  `json:"role_ids"`
	State       string    `json:"state"`
	Generation  uint64    `json:"generation"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type IdentityRoleBindingProjection struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	PrincipalID string    `json:"principal_id"`
	RoleID      string    `json:"role_id"`
	ScopeKind   string    `json:"scope_kind"`
	ResourceID  string    `json:"resource_id,omitempty"`
	Generation  uint64    `json:"generation"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type IdentityInvitationProjection struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	IntendedEmail   string     `json:"intended_email"`
	InviterID       string     `json:"inviter_id"`
	RoleID          string     `json:"role_id"`
	RoleCeiling     []string   `json:"role_ceiling"`
	ScopeKind       string     `json:"scope_kind"`
	ResourceID      string     `json:"resource_id,omitempty"`
	State           string     `json:"state"`
	Generation      uint64     `json:"generation"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	LastDeliveredAt *time.Time `json:"last_delivered_at,omitempty"`
}

type IdentityTenantCreatePayload struct {
	Name           string `json:"name"`
	ParentTenantID string `json:"parent_tenant_id,omitempty"`
	PlanID         string `json:"plan_id"`
}

type IdentityEntitlementPayload struct {
	PlanID string            `json:"plan_id"`
	Limits map[string]uint64 `json:"limits,omitempty"`
}

type IdentityInvitationCreatePayload struct {
	IntendedEmail string    `json:"intended_email"`
	RoleID        string    `json:"role_id"`
	ScopeKind     string    `json:"scope_kind"`
	ResourceID    string    `json:"resource_id,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type IdentityInvitationAcceptPayload struct {
	Token string `json:"token"`
}

type WebEngineProjection struct {
	ID           string    `json:"id"`
	Edition      string    `json:"edition"`
	Version      string    `json:"version"`
	Channel      string    `json:"channel"`
	License      string    `json:"license"`
	LicenseState string    `json:"license_state"`
	Workers      uint32    `json:"workers"`
	Connections  uint32    `json:"connections"`
	Health       string    `json:"health"`
	Generation   uint64    `json:"generation"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type WebEngineLicensePayload struct {
	Edition       string `json:"edition"`
	LicenseSecret string `json:"license_secret"`
}

type WebEngineTuningPayload struct {
	WorkerProcesses uint16 `json:"worker_processes,omitempty"`
	MaxConnections  uint32 `json:"max_connections,omitempty"`
	KeepAliveSeconds uint32 `json:"keep_alive_seconds,omitempty"`
}

type WebEngineUpgradePayload struct {
	Version string `json:"version"`
	Channel string `json:"channel,omitempty"`
}

const WebEngineRemoveConfirmation = "REMOVE node-webengine"

type WebEngineRemovePayload struct {
	Confirmation string `json:"confirmation"`
}

type WebEnginePHPProfilePayload struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Extensions []string `json:"extensions,omitempty"`
	MemoryBytes uint64  `json:"memory_bytes,omitempty"`
}

type WebEnginePHPProfileProjection struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Extensions  []string `json:"extensions,omitempty"`
	MemoryBytes uint64   `json:"memory_bytes,omitempty"`
	State       string   `json:"state"`
	Generation  uint64   `json:"generation"`
}

type IntegrationProjection struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Provider   string    `json:"provider"`
	Name       string    `json:"name"`
	State      string    `json:"state"`
	Health     string    `json:"health"`
	Generation uint64    `json:"generation"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type IntegrationCreatePayload struct {
	Provider   string `json:"provider"`
	Name       string `json:"name"`
	Credential string `json:"credential"`
}

type IntegrationRotatePayload struct {
	Credential string `json:"credential"`
}

type IntegrationHealthPayload struct {
	Deep bool `json:"deep,omitempty"`
}

type DashboardEdgeService interface {
	Summary(context.Context, EdgeCall) (DashboardSummary, error)
}

type HostingEdgeService interface {
	ListSites(context.Context, EdgeCall, EdgePagePayload) (EdgePage[HostingSiteProjection], error)
	GetSite(context.Context, EdgeCall) (HostingSiteProjection, error)
	ListBindings(context.Context, EdgeCall, EdgePagePayload) (EdgePage[HostingBindingProjection], error)
	CreateBinding(context.Context, EdgeCall, HostingBindingPayload) (EdgeMutation[HostingBindingProjection], error)
	DeleteBinding(context.Context, EdgeCall) (EdgeMutation[HostingBindingProjection], error)
}

type HostingCloneEdgeService interface {
	CloneSite(context.Context, EdgeCall, HostingClonePayload, ApplicationCloneMaterial) (EdgeMutation[HostingSiteProjection], error)
}

type HostingPreviewEdgeService interface {
	IssuePreview(context.Context, EdgeCall, HostingPreviewPayload) (HostingPreviewGrant, error)
}

type HostingAccessPolicyEdgeService interface {
	ConfigureAccessPolicy(context.Context, EdgeCall, HostingAccessPolicyPayload) (EdgeMutation[HostingBindingProjection], error)
}

type DatabaseEdgeService interface {
	ListDatabases(context.Context, EdgeCall, EdgePagePayload) (EdgePage[DatabaseProjection], error)
	CreateManagedDatabase(context.Context, EdgeCall, DatabaseCreateManagedPayload) (EdgeMutation[DatabaseProjection], error)
	CreateManagedPrincipal(context.Context, EdgeCall, DatabasePrincipalCreateManagedPayload, []byte) (EdgeMutation[DatabasePrincipalProjection], error)
	ListDatabaseInstances(context.Context, EdgeCall, EdgePagePayload) (EdgePage[DatabaseInstanceProjection], error)
	InspectDatabaseInstance(context.Context, EdgeCall) (DatabaseInstanceProjection, error)
	ConfigureDatabaseInstanceNetwork(context.Context, EdgeCall, DatabaseNetworkConfigureManagedPayload) (EdgeMutation[DatabaseNetworkPolicyProjection], error)
	EnrollExternalDatabaseInstance(context.Context, EdgeCall, DatabaseExternalEnrollmentPayload, DatabaseExternalEnrollmentSecrets) (EdgeMutation[DatabaseInstanceProjection], error)
}

type AccessEdgeService interface {
	ListCredentials(context.Context, EdgeCall, EdgePagePayload) (EdgePage[AccessCredentialProjection], error)
	CreateCredential(context.Context, EdgeCall, AccessCredentialCreatePayload, []byte) (EdgeMutation[AccessCredentialProjection], error)
	RotateCredential(context.Context, EdgeCall, AccessCredentialRotatePayload, []byte) (EdgeMutation[AccessCredentialProjection], error)
	RevokeCredential(context.Context, EdgeCall) (EdgeMutation[AccessCredentialProjection], error)
	IssueTerminal(context.Context, EdgeCall, AccessTerminalPayload) (AccessTerminalGrant, error)
	WriteFile(context.Context, EdgeCall, AccessFileWritePayload) (EdgeMutation[struct{}], error)
}

type ApplicationEdgeService interface {
	ListApplications(context.Context, EdgeCall, EdgePagePayload) (EdgePage[ApplicationProjection], error)
	DiscoverApplications(context.Context, EdgeCall, ApplicationDiscoveryEdgePayload) (ApplicationDiscoveryEdgeResult, error)
	AdoptApplication(context.Context, EdgeCall, ApplicationAdoptEdgePayload) (EdgeMutation[ApplicationProjection], error)
	InstallApplication(context.Context, EdgeCall, ApplicationInstallEdgePayload, ApplicationInstallMaterial) (EdgeMutation[ApplicationProjection], error)
	UpdateApplication(context.Context, EdgeCall, ApplicationUpdateEdgePayload) (EdgeMutation[ApplicationProjection], error)
	RemoveApplication(context.Context, EdgeCall) (EdgeMutation[ApplicationProjection], error)
	ScanApplication(context.Context, EdgeCall, ApplicationScanPayload) (EdgeMutation[ApplicationProjection], error)
	IssueWordPressAutologin(context.Context, EdgeCall, ApplicationAutologinPayload) (ApplicationGrant, error)
	PurgeWordPressCache(context.Context, EdgeCall, ApplicationCachePurgePayload) (EdgeMutation[ApplicationProjection], error)
}

type ApplicationEdgeCapabilities struct{List,Discover,Adopt,Install,Update,Remove,Scan,Autologin,CachePurge bool}
type ApplicationEdgeCapabilityProvider interface{ApplicationCapabilities() ApplicationEdgeCapabilities}

type BackupEdgeService interface {
	CreatePolicy(context.Context, EdgeCall, BackupPolicyCreatePayload) (EdgeMutation[BackupPolicyProjection], error)
	PlanRestore(context.Context, EdgeCall, BackupRestorePlanPayload) (EdgeMutation[BackupRestorePlanProjection], error)
}

type DNSEdgeService interface {
	ImportZone(context.Context, EdgeCall, DNSZoneImportPayload) (EdgeMutation[DNSZoneMutationProjection], error)
	ConfigureDNSSEC(context.Context, EdgeCall, DNSSECConfigurePayload) (EdgeMutation[DNSZoneMutationProjection], error)
}

type CertificateEdgeService interface {
	IssueCertificate(context.Context, EdgeCall, CertificateIssueEdgePayload) (EdgeMutation[CertificateEdgeProjection], error)
	IssueSiteCertificate(context.Context, EdgeCall, CertificateIssueEdgePayload) (EdgeMutation[CertificateEdgeProjection], error)
	DeployCertificate(context.Context, EdgeCall, CertificateDeployEdgePayload) (EdgeMutation[CertificateEdgeProjection], error)
}

type MailEdgeService interface {
	ListRoutes(context.Context, EdgeCall, EdgePagePayload) (EdgePage[MailRouteProjection], error)
	RunDiagnostic(context.Context, EdgeCall, MailDiagnosticPayload) (EdgeMutation[MailDiagnosticProjection], error)
	SearchTelemetry(context.Context, EdgeCall, MailTelemetryQueryPayload) (MailTelemetryEventPage, error)
	StreamTelemetry(context.Context, EdgeCall, MailTelemetryQueryPayload) (MailTelemetryEventPage, error)
	TelemetryStatistics(context.Context, EdgeCall, MailTelemetryStatisticsPayload) (MailTelemetryStatisticsResult, error)
	ListTelemetryPolicies(context.Context, EdgeCall, EdgePagePayload) (MailTelemetryPolicyPage, error)
	GetTelemetryPolicy(context.Context, EdgeCall) (MailTelemetryPolicyProjection, error)
	MutateTelemetryPolicy(context.Context, EdgeCall, MailTelemetryPolicyMutationPayload) (EdgeMutation[MailTelemetryPolicyProjection], error)
	ExportTelemetry(context.Context, EdgeCall, MailTelemetryQueryPayload) (EdgeMutation[mailtelemetry.ExportJob], error)
	PurgeTelemetry(context.Context, EdgeCall, MailTelemetryPurgePayload) (EdgeMutation[mailtelemetry.PurgeReceipt], error)
	ListMailAbuse(context.Context, EdgeCall, MailAbusePagePayload) (MailAbusePage, error)
	InspectMailAbuse(context.Context, EdgeCall) (MailAbuseProjection, error)
	ReviewMailAbuse(context.Context, EdgeCall, MailAbuseReviewPayload) (EdgeMutation[MailAbuseProjection], error)
}

type WebmailEdgeService interface {
	ListContacts(context.Context, EdgeCall, mail.MailSession, EdgePagePayload) (EdgePage[mail.Contact], error)
	ListSieveRules(context.Context, EdgeCall, mail.MailSession, EdgePagePayload) (EdgePage[mail.SieveRule], error)
}

type ContainerEdgeService interface {
	ListWorkloads(context.Context, EdgeCall, EdgePagePayload) (EdgePage[ContainerProjection], error)
	CreateWorkload(context.Context, EdgeCall, ContainerCreateEdgePayload) (EdgeMutation[ContainerProjection], error)
	RestartWorkload(context.Context, EdgeCall) (EdgeMutation[ContainerProjection], error)
	DeleteWorkload(context.Context, EdgeCall) (EdgeMutation[ContainerProjection], error)
	IssueExec(context.Context, EdgeCall, ContainerExecPayload) (ContainerExecGrant, error)
	QueryLogs(context.Context, EdgeCall, ContainerLogPayload) (ContainerLogPage, error)
}

type OperationsEdgeService interface {
	ListServices(context.Context, EdgeCall, EdgePagePayload) (EdgePage[OperationsServiceProjection], error)
	RestartService(context.Context, EdgeCall) (EdgeMutation[OperationsServiceProjection], error)
	StopService(context.Context, EdgeCall) (EdgeMutation[OperationsServiceProjection], error)
	RunDiagnostic(context.Context, EdgeCall, OperationsDiagnosticPayload) (EdgeMutation[OperationsServiceProjection], error)
}

type SecurityEdgeService interface {
	ListFindings(context.Context, EdgeCall, EdgePagePayload) (EdgePage[SecurityFindingProjection], error)
	GetFinding(context.Context, EdgeCall) (SecurityFindingProjection, error)
	StartScan(context.Context, EdgeCall, SecurityScanPayload) (EdgeMutation[SecurityFindingProjection], error)
	ApplyRemediation(context.Context, EdgeCall, SecurityRemediationPayload) (EdgeMutation[SecurityFindingProjection], error)
	SuppressFinding(context.Context, EdgeCall, SecuritySuppressPayload) (EdgeMutation[SecurityFindingProjection], error)
}

type FleetEdgeService interface {
	ListNodes(context.Context, EdgeCall, EdgePagePayload) (EdgePage[FleetNodeProjection], error)
	GetNode(context.Context, EdgeCall) (FleetNodeProjection, error)
	EnrollNode(context.Context, EdgeCall, FleetEnrollPayload, []byte) (EdgeMutation[FleetNodeProjection], error)
	RevokeNode(context.Context, EdgeCall) (EdgeMutation[FleetNodeProjection], error)
}

type HAEdgeService interface {
	TopologyStatus(context.Context, EdgeCall) (HATopologyStatusProjection, error)
	NodeHealth(context.Context, EdgeCall) (HANodeHealthProjection, error)
	DrainNode(context.Context, EdgeCall, HANodeDrainPayload) (EdgeMutation[FleetNodeProjection], error)
	PlanPromotion(context.Context, EdgeCall, HAPromotionPlanPayload) (EdgeMutation[HAPromotionProjection], error)
	ExecutePromotion(context.Context, EdgeCall, HAPromotionExecutePayload) (EdgeMutation[HAPromotionProjection], error)
}

type HAPromotionApprovalEdgeService interface {
	ApprovePromotion(context.Context, EdgeCall, HAPromotionApprovalPayload) (EdgeMutation[HAPromotionApprovalProjection], error)
}

type MigrationEdgeService interface {
	ListMigrations(context.Context, EdgeCall, EdgePagePayload) (EdgePage[MigrationProjection], error)
	InspectMigration(context.Context, EdgeCall) (MigrationProjection, error)
	CreateMigration(context.Context, EdgeCall, MigrationCreatePayload) (EdgeMutation[MigrationProjection], error)
	CancelMigration(context.Context, EdgeCall) (EdgeMutation[MigrationProjection], error)
	Inventory(context.Context, EdgeCall, MigrationInventoryPayload) (EdgeMutation[MigrationProjection], error)
	Plan(context.Context, EdgeCall, MigrationPlanPayload) (EdgeMutation[MigrationProjection], error)
	Sync(context.Context, EdgeCall, MigrationSyncPayload) (EdgeMutation[MigrationProjection], error)
	Cutover(context.Context, EdgeCall, MigrationCutoverPayload) (EdgeMutation[MigrationProjection], error)
}

type MigrationProviderDiscoveryEdgeService interface {
	ListMigrationProviders(context.Context, EdgeCall) ([]MigrationProviderProjection, error)
}

type MigrationChunkGCEdgeService interface {
	InspectMigrationChunkGC(context.Context, EdgeCall, EdgePagePayload) (EdgePage[MigrationChunkGCProjection], error)
	ReconcileMigrationChunkGC(context.Context, EdgeCall, MigrationChunkGCReconcilePayload) (EdgeMutation[MigrationChunkGCProjection], error)
}

// MigrationEdgeCapabilities lets a concrete runtime keep destructive stages
// unbound until every authority required by that stage is present. Implementors
// that do not expose this optional interface retain the complete legacy surface.
type MigrationEdgeCapabilities struct {
	List, Inspect, Create, Cancel, Inventory, Plan, Sync, Cutover bool
}

type MigrationEdgeCapabilityProvider interface {
	MigrationCapabilities() MigrationEdgeCapabilities
}

type IdentityEdgeService interface {
	ListMemberships(context.Context, EdgeCall, EdgePagePayload) (EdgePage[IdentityMembershipProjection], error)
	ListRoleBindings(context.Context, EdgeCall, EdgePagePayload) (EdgePage[IdentityRoleBindingProjection], error)
	ConfigureEntitlement(context.Context, EdgeCall, IdentityEntitlementPayload) (EdgeMutation[IdentityTenantProjection], error)
	ListInvitations(context.Context, EdgeCall, EdgePagePayload) (EdgePage[IdentityInvitationProjection], error)
	GetInvitation(context.Context, EdgeCall) (IdentityInvitationProjection, error)
	CreateInvitation(context.Context, EdgeCall, IdentityInvitationCreatePayload) (EdgeMutation[IdentityInvitationProjection], error)
	ResendInvitation(context.Context, EdgeCall) (EdgeMutation[IdentityInvitationProjection], error)
	AcceptInvitation(context.Context, EdgeCall, IdentityInvitationAcceptPayload, []byte) (EdgeMutation[IdentityInvitationProjection], error)
	ExpireInvitation(context.Context, EdgeCall) (EdgeMutation[IdentityInvitationProjection], error)
	RevokeInvitation(context.Context, EdgeCall) (EdgeMutation[IdentityInvitationProjection], error)
}

type WebEngineEdgeService interface {
	ListInstallations(context.Context, EdgeCall, EdgePagePayload) (EdgePage[WebEngineProjection], error)
	ConfigureLicense(context.Context, EdgeCall, WebEngineLicensePayload, []byte) (EdgeMutation[WebEngineProjection], error)
	ConfigureTuning(context.Context, EdgeCall, WebEngineTuningPayload) (EdgeMutation[WebEngineProjection], error)
	Upgrade(context.Context, EdgeCall, WebEngineUpgradePayload) (EdgeMutation[WebEngineProjection], error)
	Remove(context.Context, EdgeCall, WebEngineRemovePayload) (EdgeMutation[WebEngineProjection], error)
	CreatePHPProfile(context.Context, EdgeCall, WebEnginePHPProfilePayload) (EdgeMutation[WebEnginePHPProfileProjection], error)
}

type WebEngineEdgeCapabilities struct{List,License,Tuning,Upgrade,Remove,PHPProfile bool}
type WebEngineEdgeCapabilityProvider interface{WebEngineCapabilities() WebEngineEdgeCapabilities}

type IntegrationEdgeService interface {
	ListBindings(context.Context, EdgeCall, EdgePagePayload) (EdgePage[IntegrationProjection], error)
	CreateBinding(context.Context, EdgeCall, IntegrationCreatePayload, []byte) (EdgeMutation[IntegrationProjection], error)
	RotateBinding(context.Context, EdgeCall, IntegrationRotatePayload, []byte) (EdgeMutation[IntegrationProjection], error)
	CheckBinding(context.Context, EdgeCall, IntegrationHealthPayload) (EdgeMutation[IntegrationProjection], error)
	DeleteBinding(context.Context, EdgeCall) (EdgeMutation[IntegrationProjection], error)
}

func registerConsoleEdgeContracts(registry *Registry) error {
	password := identity.AssurancePassword
	mfa := identity.AssuranceMFA
	phishingResistant := identity.AssurancePhishingResistant
	definitions := []Operation{
		consoleOperation("dashboard.summary", "operations:observe", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantOrInstallationListScope),

		consoleOperation("hosting.site.list", "site:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantListScope),
		consoleOperation("hosting.site.get", "site:manage", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantResourceReadScope),
		consoleOperation("hosting.site.clone", "site:create", password, true, func() any { return &HostingClonePayload{} }, validateHostingClone, edgeTenantExistingMutationScope),
		consoleOperation("hosting.site.preview.issue", "site:manage", password, true, func() any { return &HostingPreviewPayload{} }, validateHostingPreview, edgeTenantExistingMutationScope),
		consoleOperation("hosting.site.suspend", "site:manage", password, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("hosting.site.resume", "site:manage", password, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("hosting.site.delete", "site:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("hosting.binding.list", "site:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantListScope),
		consoleOperation("hosting.binding.create", "site:manage", password, true, func() any { return &HostingBindingPayload{} }, validateHostingBinding, edgeTenantCreateScope),
		consoleOperation("hosting.binding.delete", "site:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("hosting.binding.access_policy", "site:manage", mfa, true, func() any { return &HostingAccessPolicyPayload{} }, validateHostingAccessPolicy, edgeTenantExistingMutationScope),

		consoleOperation("database.database.list", "database:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantListScope),
		consoleOperation("database.database.create_managed", "database:create", password, true, func() any { return &DatabaseCreateManagedPayload{} }, validateDatabaseCreateManaged, edgeTenantCreateScope),
		consoleOperation("database.principal.create_managed", "database:manage", password, true, func() any { return &DatabasePrincipalCreateManagedPayload{} }, validateDatabasePrincipalCreateManaged, edgeTenantExistingMutationScope),
		consoleOperation("database.console.issue", "database:console", mfa, true, func() any { return &DatabaseConsoleIssuePayload{} }, validateDatabaseConsoleIssue, edgeTenantExistingMutationScope),
		consoleOperation("database.instance.list", "database:admin", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeInstallationListScope),
		consoleOperation("database.instance.health", "database:admin", password, false, func() any { return &EmptyPayload{} }, nil, edgeInstallationResourceReadScope),
		consoleOperation("database.instance.network.configure", "database:admin", phishingResistant, true, func() any { return &DatabaseNetworkConfigureManagedPayload{} }, validateDatabaseNetworkConfigureManaged, edgeInstallationExistingMutationScope),
		consoleOperation("database.instance.enroll_external", "database:admin", mfa, true, func() any { return &DatabaseExternalEnrollmentPayload{} }, validateDatabaseExternalEnrollment, edgeInstallationCreateScope),

		consoleOperation("access.credential.list", "access:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantListScope),
		consoleOperation("access.credential.create", "access:manage", mfa, true, func() any { return &AccessCredentialCreatePayload{} }, validateAccessCredentialCreate, edgeTenantCreateScope),
		consoleOperation("access.credential.rotate", "access:manage", mfa, true, func() any { return &AccessCredentialRotatePayload{} }, validateAccessCredentialRotate, edgeTenantExistingMutationScope),
		consoleOperation("access.credential.revoke", "access:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("access.terminal.issue", "access:terminal", mfa, true, func() any { return &AccessTerminalPayload{} }, validateAccessTerminal, edgeTenantExistingMutationScope),
		consoleOperation("access.file.write", "file:write", password, true, func() any { return &AccessFileWritePayload{} }, validateAccessFileWrite, edgeTenantExistingMutationScope),

		consoleOperation("apps.instance.list", "application:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantListScope),
		consoleOperation("apps.discovery.scan", "application:manage", password, true, func() any { return &ApplicationDiscoveryEdgePayload{} }, validateApplicationDiscoveryEdge, edgeTenantExistingMutationScope),
		consoleOperation("apps.discovery.adopt", "application:install", mfa, true, func() any { return &ApplicationAdoptEdgePayload{} }, validateApplicationAdoptEdge, edgeTenantExistingMutationScope),
		consoleOperation("apps.instance.install", "application:install", mfa, true, func() any { return &ApplicationInstallEdgePayload{} }, validateApplicationInstall, edgeTenantCreateScope),
		consoleOperation("apps.instance.update", "application:update", mfa, true, func() any { return &ApplicationUpdateEdgePayload{} }, validateApplicationUpdate, edgeTenantExistingMutationScope),
		consoleOperation("apps.instance.remove", "application:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("apps.scan.start", "application:manage", password, true, func() any { return &ApplicationScanPayload{} }, validateApplicationScan, edgeTenantExistingMutationScope),
		consoleOperation("apps.wordpress.autologin.issue", "application:manage", mfa, true, func() any { return &ApplicationAutologinPayload{} }, validateApplicationAutologin, edgeTenantExistingMutationScope),
		consoleOperation("apps.wordpress.cache.purge", "application:manage", password, true, func() any { return &ApplicationCachePurgePayload{} }, validateApplicationCachePurge, edgeTenantExistingMutationScope),

		consoleOperation("backup.policy.create", "backup:manage", mfa, true, func() any { return &BackupPolicyCreatePayload{} }, validateBackupPolicyCreate, edgeTenantCreateScope),
		consoleOperation("backup.restore.plan", "backup:restore", mfa, true, func() any { return &BackupRestorePlanPayload{} }, validateBackupRestorePlan, edgeTenantExistingMutationScope),

		consoleOperation("dns.zone.import", "dns:manage", mfa, true, func() any { return &DNSZoneImportPayload{} }, validateDNSZoneImport, edgeTenantExistingMutationScope),
		consoleOperation("dns.dnssec.configure", "dns:manage", mfa, true, func() any { return &DNSSECConfigurePayload{} }, validateDNSSECConfigure, edgeTenantExistingMutationScope),

		consoleOperation("certificate.issue", "certificate:manage", mfa, true, func() any { return &CertificateIssueEdgePayload{} }, validateCertificateIssueEdge, edgeTenantCreateScope),
		consoleOperation("certificate.site.issue", "certificate:manage", mfa, true, func() any { return &CertificateIssueEdgePayload{} }, validateCertificateIssueEdge, edgeTenantExistingMutationScope),
		consoleOperation("certificate.deploy", "certificate:manage", mfa, true, func() any { return &CertificateDeployEdgePayload{} }, validateCertificateDeployEdge, edgeTenantExistingMutationScope),

		consoleOperation("mail.route.list", "mail:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantResourceReadScope),
		consoleOperation("mail.diagnostic.run", "mail:manage", password, true, func() any { return &MailDiagnosticPayload{} }, validateMailDiagnostic, edgeTenantExistingMutationScope),
		consoleOperation("mail.telemetry.event.search", "mail:manage", password, false, func() any { return &MailTelemetryQueryPayload{} }, validateMailTelemetryQuery, edgeTenantListScope),
		consoleOperation("mail.telemetry.event.stream", "mail:manage", password, false, func() any { return &MailTelemetryQueryPayload{} }, validateMailTelemetryQuery, edgeTenantListScope),
		consoleOperation("mail.telemetry.statistics", "mail:manage", password, false, func() any { return &MailTelemetryStatisticsPayload{} }, validateMailTelemetryStatistics, edgeTenantListScope),
		consoleOperation("mail.telemetry.policy.list", "mail:manage", password, false, func() any { return &EdgePagePayload{} }, validateMailTelemetryPage, edgeTenantListScope),
		consoleOperation("mail.telemetry.policy.get", "mail:manage", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantResourceReadScope),
		consoleOperation("mail.telemetry.policy.create", "mail:manage", mfa, true, func() any { return &MailTelemetryPolicyMutationPayload{} }, validateMailTelemetryPolicyMutation, edgeTenantCreateScope),
		consoleOperation("mail.telemetry.policy.update", "mail:manage", mfa, true, func() any { return &MailTelemetryPolicyMutationPayload{} }, validateMailTelemetryPolicyUpdate, edgeTenantExistingMutationScope),
		consoleOperation("mail.telemetry.policy.enable", "mail:manage", mfa, true, func() any { return &MailTelemetryPolicyMutationPayload{} }, validateMailTelemetryPolicyToggle, edgeTenantExistingMutationScope),
		consoleOperation("mail.telemetry.policy.disable", "mail:manage", mfa, true, func() any { return &MailTelemetryPolicyMutationPayload{} }, validateMailTelemetryPolicyToggle, edgeTenantExistingMutationScope),
		consoleOperation("mail.telemetry.export", "mail:manage", mfa, true, func() any { return &MailTelemetryQueryPayload{} }, validateMailTelemetryQuery, edgeTenantExistingMutationScope),
		consoleOperation("mail.telemetry.purge", "mail:manage", mfa, true, func() any { return &MailTelemetryPurgePayload{} }, validateMailTelemetryPurge, edgeTenantExistingMutationScope),
		consoleOperation("mail.abuse.finding.list", "security:observe", password, false, func() any { return &MailAbusePagePayload{} }, validateMailAbusePage, edgeTenantListScope),
		consoleOperation("mail.abuse.intent.list", "security:observe", password, false, func() any { return &MailAbusePagePayload{} }, validateMailAbusePage, edgeTenantListScope),
		consoleOperation("mail.abuse.intent.get", "security:observe", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantResourceReadScope),
		consoleOperation("mail.abuse.intent.approve", "security:manage", phishingResistant, true, func() any { return &MailAbuseReviewPayload{} }, validateMailAbuseApproval, edgeTenantExistingMutationScope),
		consoleOperation("mail.abuse.intent.recover", "security:manage", phishingResistant, true, func() any { return &MailAbuseReviewPayload{} }, validateMailAbuseRecovery, edgeTenantExistingMutationScope),
		consoleOperation("webmail.contact.list", "mail:manage", password, false, func() any { return &WebmailDirectoryPayload{} }, validateWebmailDirectory, webmailScope),
		consoleOperation("webmail.sieve.list", "mail:manage", password, false, func() any { return &WebmailDirectoryPayload{} }, validateWebmailDirectory, webmailScope),
		consoleOperation("webmail.message.reply", "mail:manage", password, true, func() any { return &WebmailReplyPayload{} }, validateWebmailReply, webmailScope),

		consoleOperation("container.workload.list", "container:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantListScope),
		consoleOperation("container.workload.create", "container:manage", mfa, true, func() any { return &ContainerCreateEdgePayload{} }, validateContainerCreate, edgeTenantCreateScope),
		consoleOperation("container.workload.restart", "container:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("container.workload.delete", "container:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("container.exec.issue", "container:manage", mfa, true, func() any { return &ContainerExecPayload{} }, validateContainerExec, edgeTenantExistingMutationScope),
		consoleOperation("container.logs.query", "container:manage", password, false, func() any { return &ContainerLogPayload{} }, validateContainerLogs, edgeTenantResourceReadScope),

		consoleOperation("operations.service.list", "operations:observe", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantOrInstallationListScope),
		consoleOperation("operations.service.restart", "operations:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantOrInstallationExistingMutationScope),
		consoleOperation("operations.service.stop", "operations:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantOrInstallationExistingMutationScope),
		consoleOperation("operations.diagnostic.run", "operations:observe", password, true, func() any { return &OperationsDiagnosticPayload{} }, validateOperationsDiagnostic, edgeTenantOrInstallationExistingMutationScope),

		consoleOperation("security.finding.list", "security:observe", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantOrInstallationListScope),
		consoleOperation("security.finding.get", "security:observe", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantOrInstallationResourceReadScope),
		consoleOperation("security.scan.start", "security:manage", mfa, true, func() any { return &SecurityScanPayload{} }, validateSecurityScan, edgeTenantOrInstallationCreateScope),
		consoleOperation("security.remediation.apply", "security:manage", mfa, true, func() any { return &SecurityRemediationPayload{} }, validateSecurityRemediation, edgeTenantOrInstallationExistingMutationScope),
		consoleOperation("security.finding.suppress", "security:manage", mfa, true, func() any { return &SecuritySuppressPayload{} }, validateSecuritySuppress, edgeTenantOrInstallationExistingMutationScope),

		consoleOperation("fleet.node.list", "fleet:observe", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeInstallationListScope),
		consoleOperation("fleet.node.get", "fleet:observe", password, false, func() any { return &EmptyPayload{} }, nil, edgeInstallationResourceReadScope),
		consoleOperation("fleet.node.enroll", "fleet:manage", mfa, true, func() any { return &FleetEnrollPayload{} }, validateFleetEnroll, edgeInstallationCreateScope),
		consoleOperation("fleet.node.revoke", "fleet:manage", phishingResistant, true, func() any { return &EmptyPayload{} }, nil, edgeInstallationExistingMutationScope),
		consoleOperation("ha.topology.status", "fleet:observe", password, false, func() any { return &EmptyPayload{} }, nil, edgeInstallationResourceReadScope),
		consoleOperation("ha.node.health", "fleet:observe", password, false, func() any { return &EmptyPayload{} }, nil, edgeInstallationResourceReadScope),
		consoleOperation("ha.node.drain", "ha:manage", mfa, true, func() any { return &HANodeDrainPayload{} }, validateHANodeDrain, edgeInstallationExistingMutationScope),
		consoleOperation("ha.promotion.plan", "ha:manage", phishingResistant, true, func() any { return &HAPromotionPlanPayload{} }, validateHAPromotionPlan, edgeInstallationExistingMutationScope),
		consoleOperation("ha.promotion.approval.submit", "ha:manage", phishingResistant, true, func() any { return &HAPromotionApprovalPayload{} }, validateHAPromotionApproval, edgeTenantExistingMutationScope),
		consoleOperation("ha.promotion.execute", "ha:manage", phishingResistant, true, func() any { return &HAPromotionExecutePayload{} }, validateHAPromotionExecute, edgeInstallationExistingMutationScope),

		consoleOperation("migration.provider.list", "migration:manage", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantListScope),
		consoleOperation("migration.list", "migration:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantListScope),
		consoleOperation("migration.inspect", "migration:manage", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantResourceReadScope),
		consoleOperation("migration.chunk_gc.inspect", "migration:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantResourceReadScope),
		consoleOperation("migration.chunk_gc.reconcile", "migration:manage", mfa, true, func() any { return &MigrationChunkGCReconcilePayload{} }, validateMigrationChunkGCReconcile, edgeTenantExistingMutationScope),
		consoleOperation("migration.create", "migration:manage", mfa, true, func() any { return &MigrationCreatePayload{} }, validateMigrationCreate, edgeTenantCreateScope),
		consoleOperation("migration.cancel", "migration:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("migration.inventory", "migration:manage", password, true, func() any { return &MigrationInventoryPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("migration.plan", "migration:manage", mfa, true, func() any { return &MigrationPlanPayload{} }, validateMigrationPlan, edgeTenantExistingMutationScope),
		consoleOperation("migration.sync", "migration:manage", mfa, true, func() any { return &MigrationSyncPayload{} }, validateMigrationSync, edgeTenantExistingMutationScope),
		consoleOperation("migration.cutover", "migration:manage", phishingResistant, true, func() any { return &MigrationCutoverPayload{} }, validateMigrationCutover, edgeTenantExistingMutationScope),

		consoleOperation("identity.membership.list", "identity:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantResourceReadScope),
		consoleOperation("identity.role_binding.list", "identity:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantResourceReadScope),
		consoleOperation("identity.entitlement.configure", "identity:manage", mfa, true, func() any { return &IdentityEntitlementPayload{} }, validateIdentityEntitlement, edgeTenantExistingMutationScope),
		consoleOperation("identity.invitation.list", "identity:manage", password, false, func() any { return &EdgePagePayload{} }, validateIdentityInvitationPage, edgeTenantListScope),
		consoleOperation("identity.invitation.get", "identity:manage", password, false, func() any { return &EmptyPayload{} }, nil, edgeTenantResourceReadScope),
		consoleOperation("identity.invitation.create", "identity:manage", mfa, true, func() any { return &IdentityInvitationCreatePayload{} }, validateIdentityInvitationCreate, edgeTenantCreateScope),
		consoleOperation("identity.invitation.resend", "identity:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		{Name:"identity.invitation.accept", Assurance:password, Auth:AuthRequired, SelfService:true, Mutating:true, MaximumBodyBytes:4096, NewPayload:func() any { return &IdentityInvitationAcceptPayload{} }, ValidatePayload:validateIdentityInvitationAccept, ResolveScope:edgeTenantExistingMutationScope},
		consoleOperation("identity.invitation.expire", "identity:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("identity.invitation.revoke", "identity:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),

		consoleOperation("webengine.installation.list", "webengine:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeInstallationListScope),
		consoleOperation("webengine.license.configure", "webengine:manage", mfa, true, func() any { return &WebEngineLicensePayload{} }, validateWebEngineLicense, edgeInstallationExistingMutationScope),
		consoleOperation("webengine.tuning.configure", "webengine:manage", mfa, true, func() any { return &WebEngineTuningPayload{} }, validateWebEngineTuning, edgeInstallationExistingMutationScope),
		consoleOperation("webengine.upgrade", "webengine:manage", mfa, true, func() any { return &WebEngineUpgradePayload{} }, validateWebEngineUpgrade, edgeInstallationExistingMutationScope),
		consoleOperation("webengine.remove", "webengine:manage", phishingResistant, true, func() any { return &WebEngineRemovePayload{} }, validateWebEngineRemove, edgeInstallationExistingMutationScope),
		consoleOperation("webengine.php_profile.create", "webengine:manage", mfa, true, func() any { return &WebEnginePHPProfilePayload{} }, validateWebEnginePHPProfile, edgeInstallationCreateScope),

		consoleOperation("integration.binding.list", "integration:manage", password, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeTenantListScope),
		consoleOperation("integration.binding.create", "integration:manage", mfa, true, func() any { return &IntegrationCreatePayload{} }, validateIntegrationCreate, edgeTenantCreateScope),
		consoleOperation("integration.binding.rotate", "integration:manage", mfa, true, func() any { return &IntegrationRotatePayload{} }, validateIntegrationRotate, edgeTenantExistingMutationScope),
		consoleOperation("integration.binding.health", "integration:manage", password, true, func() any { return &IntegrationHealthPayload{} }, nil, edgeTenantExistingMutationScope),
		consoleOperation("integration.binding.delete", "integration:manage", mfa, true, func() any { return &EmptyPayload{} }, nil, edgeTenantExistingMutationScope),
	}
	for _, definition := range definitions {
		if err := register(registry, definition); err != nil { return err }
	}
	return nil
}

func consoleOperation(name, permission string, assurance identity.AssuranceLevel, mutating bool, payload func() any, validate func(any) error, scope ScopeResolver) Operation {
	return Operation{Name:name, Permission:identity.MustPermission(permission), Assurance:assurance, Auth:AuthRequired, Mutating:mutating, NewPayload:payload, ValidatePayload:validate, ResolveScope:scope}
}

func validateEdgePage(value any) error {
	payload := value.(*EdgePagePayload)
	if payload.Limit == 0 { payload.Limit = 100 }
	if payload.Limit > 500 || len(payload.Cursor) > 1024 || strings.ContainsAny(payload.Cursor, "\x00\r\n\t") { return invalid("page") }
	return nil
}

func validateDatabaseCreateManaged(value any) error {
	payload := value.(*DatabaseCreateManagedPayload)
	if _, err := site.NewSiteID(payload.SiteID); err != nil {
		return invalid("database site")
	}
	if _, err := database.NewResourceID(payload.InstanceID); err != nil {
		return invalid("database instance")
	}
	if _, err := database.ParseSQLIdentifier(payload.Name); err != nil {
		return invalid("database name")
	}
	if _, err := database.ParseSQLIdentifier(payload.Charset); err != nil {
		return invalid("database charset")
	}
	if _, err := database.ParseSQLIdentifier(payload.Collation); err != nil {
		return invalid("database collation")
	}
	if payload.QuotaBytes == 0 || payload.QuotaBytes > 1<<60 {
		return invalid("database quota")
	}
	return nil
}

func validateDatabasePrincipalCreateManaged(value any) error {
	payload := value.(*DatabasePrincipalCreateManagedPayload)
	if _, err := database.ParseSQLIdentifier(payload.Name); err != nil {
		return invalid("database principal name")
	}
	if len(payload.Password) < 12 || len(payload.Password) > 4096 || strings.IndexByte(payload.Password, 0) >= 0 {
		return invalid("database principal password")
	}
	if payload.HostScope != string(database.HostScopeLoopback) && payload.HostScope != string(database.HostScopePolicy) {
		return invalid("database principal host scope")
	}
	if len(payload.Privileges) == 0 || len(payload.Privileges) > 14 {
		return invalid("database principal privileges")
	}
	seen := make(map[string]struct{}, len(payload.Privileges))
	for _, privilege := range payload.Privileges {
		switch database.Privilege(privilege) {
		case database.PrivilegeSelect, database.PrivilegeInsert, database.PrivilegeUpdate, database.PrivilegeDelete,
			database.PrivilegeCreate, database.PrivilegeAlter, database.PrivilegeIndex, database.PrivilegeDrop,
			database.PrivilegeCreateTemporary, database.PrivilegeExecute, database.PrivilegeCreateView,
			database.PrivilegeShowView, database.PrivilegeTrigger, database.PrivilegeEvent:
		default:
			return invalid("database principal privilege")
		}
		if _, exists := seen[privilege]; exists {
			return invalid("duplicate database principal privilege")
		}
		seen[privilege] = struct{}{}
	}
	return nil
}

func validateDatabaseNetworkConfigureManaged(value any) error {
	payload := value.(*DatabaseNetworkConfigureManagedPayload)
	if len(payload.Interfaces) == 0 || len(payload.Interfaces) > 3 || len(payload.AllowedCIDRs) > 256 {
		return invalid("database network policy")
	}
	interfaces := make(map[string]struct{}, len(payload.Interfaces))
	for _, networkInterface := range payload.Interfaces {
		switch database.NetworkInterface(networkInterface) {
		case database.InterfaceLoopback, database.InterfacePrivate, database.InterfacePublic:
		default:
			return invalid("database network interface")
		}
		if _, exists := interfaces[networkInterface]; exists {
			return invalid("duplicate database network interface")
		}
		interfaces[networkInterface] = struct{}{}
	}
	prefixes := make(map[string]struct{}, len(payload.AllowedCIDRs))
	for _, raw := range payload.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() {
			return invalid("database network prefix")
		}
		if _, exists := prefixes[prefix.String()]; exists {
			return invalid("duplicate database network prefix")
		}
		prefixes[prefix.String()] = struct{}{}
	}
	if payload.TLSMode != string(database.TLSRequired) && payload.TLSMode != string(database.TLSMutual) {
		return invalid("database network TLS")
	}
	switch database.VerificationLevel(payload.Verification) {
	case database.VerifyStructural, database.VerifyLocalEndToEnd, database.VerifyClientConfirmed, database.VerifyIndependentExternal:
	default:
		return invalid("database network verification")
	}
	if _, err := database.NewResourceID(payload.HighRiskApproval); err != nil {
		return invalid("database network approval")
	}
	return nil
}

func validateDatabaseExternalEnrollment(value any) error {
	payload := value.(*DatabaseExternalEnrollmentPayload)
	if _, err := database.NewResourceID(payload.ID); err != nil {
		return invalid("database instance id")
	}
	if _, err := database.NewResourceID(payload.NetworkPolicyID); err != nil {
		return invalid("database network policy id")
	}
	if _, err := database.NewResourceID(payload.ApprovalRef); err != nil {
		return invalid("database approval")
	}
	if _, err := database.ParseSQLIdentifier(payload.AdministratorUsername); err != nil {
		return invalid("database administrator")
	}
	if payload.Port == 0 || !safeEdgeText(payload.Host, 253) || strings.ContainsAny(payload.Host, " /\\@") ||
		(payload.TLSMode != string(database.TLSRequired) && payload.TLSMode != string(database.TLSMutual)) ||
		payload.VersionMajor == 0 || payload.StorageBytes == 0 || payload.MemoryBytes == 0 || payload.MaxConnections == 0 ||
		len(payload.AdministratorPassword) == 0 || len(payload.AdministratorPassword) > 64<<10 || strings.IndexByte(payload.AdministratorPassword, 0) >= 0 ||
		len(payload.CertificateAuthorityPEM) == 0 || len(payload.CertificateAuthorityPEM) > 64<<10 ||
		len(payload.ClientCertificatePEM) > 64<<10 || len(payload.ClientKeyPEM) > 64<<10 {
		return invalid("external database enrollment")
	}
	mutual := payload.TLSMode == string(database.TLSMutual)
	if mutual != (payload.ClientCertificatePEM != "" && payload.ClientKeyPEM != "") ||
		!mutual && (payload.ClientCertificatePEM != "" || payload.ClientKeyPEM != "") {
		return invalid("external database TLS material")
	}
	return nil
}

func validateHostingClone(value any) error {
	payload := value.(*HostingClonePayload)
	if !validApplicationClientIdentityInput(payload.DatabaseClientCertificate,payload.DatabaseClientKey) { return invalid("clone database client identity") }
	if !validMailHostname(payload.PrimaryHostname) || !validEdgeID(payload.ProjectID) || !validEdgeID(payload.DatabaseInstanceID) || !payload.CopyDatabase || !validEdgeID(payload.AccessCredentialRef) { return invalid("site clone") }
	return nil
}

func validateHostingPreview(value any) error {
	payload := value.(*HostingPreviewPayload)
	if payload.TTLSeconds == 0 { payload.TTLSeconds = 900 }
	if payload.MaximumRequests == 0 { payload.MaximumRequests = 128 }
	if payload.TTLSeconds < 60 || payload.TTLSeconds > 3600 || payload.MaximumRequests > 4096 { return invalid("site preview") }
	return nil
}

func validateHostingBinding(value any) error {
	payload := value.(*HostingBindingPayload)
	if !validEdgeID(payload.SiteID) || !validMailHostname(payload.Hostname) { return invalid("domain binding") }
	switch payload.Relationship {
	case "alias", "child":
		if payload.RedirectTarget != "" { return invalid("domain binding") }
	case "redirect":
		if !validMailHostname(payload.RedirectTarget) { return invalid("redirect target") }
	default:
		return invalid("domain relationship")
	}
	return nil
}

func validateHostingAccessPolicy(value any) error {
	payload := value.(*HostingAccessPolicyPayload)
	if payload.Enabled && !validEdgeID(payload.CredentialRef) || !payload.Enabled && payload.CredentialRef != "" { return invalid("access policy") }
	return nil
}

func validateAccessCredentialCreate(value any) error {
	payload := value.(*AccessCredentialCreatePayload)
	if !validEdgeID(payload.SiteID) || !safeEdgeText(payload.Label, 128) { return invalid("access credential") }
	switch payload.Kind {
	case "ssh_key":
		if len(payload.PublicKey) < 32 || len(payload.PublicKey) > 32768 || payload.Secret != "" { return invalid("SSH credential") }
	case "ftps":
		if len(payload.Secret) < 12 || len(payload.Secret) > 1024 || payload.PublicKey != "" { return invalid("FTPS credential") }
	case "terminal":
		if payload.PublicKey != "" || payload.Secret != "" { return invalid("terminal credential") }
	default:
		return invalid("access credential kind")
	}
	if payload.Permission != "" && payload.Permission != "read_only" && payload.Permission != "read_write" && payload.Permission != "terminal" { return invalid("access permission") }
	if payload.ExpiresInSec > 31*24*60*60 { return invalid("access expiry") }
	return nil
}

func validateAccessCredentialRotate(value any) error {
	payload := value.(*AccessCredentialRotatePayload)
	if len(payload.Secret) < 12 || len(payload.Secret) > 1024 || strings.ContainsRune(payload.Secret, 0) { return invalid("credential secret") }
	return nil
}

func validateAccessTerminal(value any) error {
	payload := value.(*AccessTerminalPayload)
	if payload.Columns == 0 { payload.Columns = 120 }
	if payload.Rows == 0 { payload.Rows = 36 }
	if payload.Columns < 20 || payload.Columns > 500 || payload.Rows < 5 || payload.Rows > 250 || !validEdgeNonce(payload.ClientNonce) { return invalid("terminal request") }
	return nil
}

func validateAccessFileWrite(value any) error {
	payload := value.(*AccessFileWritePayload)
	if payload.SiteID != "" && !validEdgeID(payload.SiteID) || !validRelativeName(payload.RelativePath) || len(payload.ContentBase64) == 0 || len(payload.ContentBase64) > 12<<20 || len(payload.IfMatch) > 256 || strings.ContainsAny(payload.IfMatch, "\x00\r\n") { return invalid("file write") }
	content, err := base64.StdEncoding.Strict().DecodeString(payload.ContentBase64)
	if err != nil || len(content) > 8<<20 { clearSecret(content); return invalid("file content") }
	clearSecret(content)
	return nil
}

func validateApplicationInstall(value any) error {
	payload := value.(*ApplicationInstallEdgePayload)
	if !validApplicationClientIdentityInput(payload.DatabaseClientCertificate,payload.DatabaseClientKey) { return invalid("application database client identity") }
	if payload.DatabaseClientCertificate!="" && payload.Application!="wordpress" { return invalid("application database TLS support") }
	if !validEdgeID(payload.SiteID) || !validEdgeID(payload.DatabaseInstanceID) || !validEdgeID(payload.Version) || payload.RecipeID!=""&&!validEdgeID(payload.RecipeID) || !safeEdgeText(payload.AdministratorUsername,128) || !strings.Contains(payload.AdministratorEmail,"@") || !safeEdgeText(payload.AdministratorEmail,320) || !safeEdgeText(payload.AdministratorDisplayName,256) || len(payload.AdministratorPassword)<12 || len(payload.AdministratorPassword)>4096 || payload.Locale!=""&&!safeEdgeText(payload.Locale,64) || payload.Timezone!=""&&!safeEdgeText(payload.Timezone,128) || payload.Title!=""&&!safeEdgeText(payload.Title,256) { return invalid("application install") }
	switch payload.Application { case "wordpress", "joomla", "prestashop", "magento", "mautic": default: return invalid("application kind") }
	return nil
}

func validApplicationClientIdentityInput(certificate,key string) bool {
	return (certificate=="")== (key=="") && len(certificate)<=64<<10 && len(key)<=64<<10 && !strings.ContainsRune(certificate,0) && !strings.ContainsRune(key,0)
}

func validateApplicationDiscoveryEdge(value any) error {
	payload := value.(*ApplicationDiscoveryEdgePayload)
	if payload.MaximumDepth == 0 { payload.MaximumDepth = 4 }
	if payload.MaximumCandidates == 0 { payload.MaximumCandidates = 32 }
	if payload.MaximumDepth > 16 || payload.MaximumCandidates > 1000 { return invalid("application discovery budget") }
	if _, err := apps.ParseRelativePath(payload.Root); err != nil { return invalid("application discovery root") }
	if len(payload.Applications) == 0 { payload.Applications = EdgeStringList{"joomla", "prestashop", "mautic", "magento"} }
	if len(payload.Applications) > 4 { return invalid("application discovery kind") }
	seen := map[string]bool{}
	for _, application := range payload.Applications {
		switch application { case "joomla", "prestashop", "mautic", "magento", "magento_open_source": default: return invalid("application discovery kind") }
		canonical:=application;if canonical=="magento_open_source"{canonical="magento"};if seen[canonical] { return invalid("application discovery kind") }
		seen[canonical] = true
	}
	return nil
}

func validateApplicationAdoptEdge(value any) error {
	payload := value.(*ApplicationAdoptEdgePayload)
	if payload.Candidate.Validate() != nil || payload.RecipeID != "" && !validEdgeID(payload.RecipeID) { return invalid("application adoption") }
	return nil
}

func validateApplicationUpdate(value any) error {
	payload := value.(*ApplicationUpdateEdgePayload)
	if payload.RecipeID==""&&payload.Version=="" || payload.RecipeID!=""&&!validEdgeID(payload.RecipeID) || payload.Version!=""&&!validEdgeID(payload.Version) { return invalid("application update") }
	return nil
}

func validateApplicationScan(value any) error {
	payload := value.(*ApplicationScanPayload)
	if payload.Mode == "" { payload.Mode = "full" }
	switch payload.Mode { case "quick", "full", "integrity", "integrity_comparison": default: return invalid("application scan mode") }
	if payload.ProviderID != "" && !validEdgeID(payload.ProviderID) { return invalid("application scan provider") }
	return nil
}

func validateApplicationAutologin(value any) error {
	payload := value.(*ApplicationAutologinPayload)
	if payload.TTLSeconds == 0 { payload.TTLSeconds = 90 }
	if payload.WordPressUserID == 0 || payload.TTLSeconds < 30 || payload.TTLSeconds > 120 || !validDigestReference(payload.BridgeDigest) || len(payload.BridgeSignature) != 128 || !validEdgeID(payload.SigningKeyID) { return invalid("autologin grant") }
	if _, err := hex.DecodeString(payload.BridgeSignature); err != nil { return invalid("autologin bridge signature") }
	return nil
}

func validateApplicationCachePurge(value any) error {
	payload := value.(*ApplicationCachePurgePayload)
	if payload.Scope == "" { payload.Scope = "all" }
	if payload.Scope == "url" { payload.Scope="path" }
	if payload.Scope != "all" && payload.Scope != "path" && payload.Scope != "tag" || len(payload.Values) > 1000 { return invalid("cache purge") }
	for _, item := range payload.Values { if !safeEdgeText(item, 2048) { return invalid("cache purge value") } }
	if payload.Scope != "all" && len(payload.Values) == 0 { return invalid("cache purge value") }
	return nil
}

func validateBackupPolicyCreate(value any) error {
	payload := value.(*BackupPolicyCreatePayload)
	if payload.Name != "" && !safeEdgeText(payload.Name, 128) || !validEdgeID(payload.Scope) || !safeSchedule(payload.Schedule) || !validEdgeID(payload.RepositoryID) || !safeEdgeText(payload.Retention, 256) { return invalid("backup policy") }
	return ValidateLocalBackupPolicy(backup.BackupPolicySpec{ID:backup.PolicyID(payload.Scope),Scope:payload.Scope,Repositories:[]backup.RepositoryID{backup.RepositoryID(payload.RepositoryID)},RequiredCopies:1,Consistency:payload.Consistency,Components:payload.Components})
}

func validateBackupRestorePlan(value any) error {
	payload := value.(*BackupRestorePlanPayload)
	if !validEdgeID(payload.RecoveryPointID) || !validEdgeID(payload.TargetScope) || len(payload.DomainMapping) > 10000 { return invalid("restore plan") }
	for source, target := range payload.DomainMapping { if !validMailHostname(source) || !validMailHostname(target) { return invalid("restore domain mapping") } }
	return nil
}

func validateDNSZoneImport(value any) error {
	payload := value.(*DNSZoneImportPayload)
	if len(payload.RecordSets) == 0 && !payload.Replace || len(payload.RecordSets) > 10000 { return invalid("DNS import") }
	for _, set := range payload.RecordSets {
		if !validDNSOwner(set.Name) || !validDNSRecordType(set.Type) || set.TTL < 30 || set.TTL > 2147483647 || len(set.Values) == 0 || len(set.Values) > 1000 { return invalid("DNS record set") }
		for _, record := range set.Values { if !safeEdgeText(record, 4096) { return invalid("DNS record") } }
	}
	return nil
}

func validateDNSSECConfigure(value any) error {
	payload := value.(*DNSSECConfigurePayload)
	if !payload.Enabled {
		if payload.Algorithm != "" || payload.SignatureValidity != 0 || payload.RolloverAfter != 0 || payload.PrepublishFor != 0 { return invalid("DNSSEC disable") }
		return nil
	}
	if payload.Algorithm == "" { payload.Algorithm = "ecdsa_p256_sha256" }
	if payload.Algorithm != "ecdsa_p256_sha256" && payload.Algorithm != "ed25519" { return invalid("DNSSEC algorithm") }
	if payload.SignatureValidity == 0 { payload.SignatureValidity = 14*24*time.Hour }
	if payload.RolloverAfter == 0 { payload.RolloverAfter = 90*24*time.Hour }
	if payload.PrepublishFor == 0 { payload.PrepublishFor = 7*24*time.Hour }
	if payload.SignatureValidity < 24*time.Hour || payload.SignatureValidity > 90*24*time.Hour || payload.RolloverAfter < 7*24*time.Hour || payload.PrepublishFor < time.Hour || payload.PrepublishFor >= payload.RolloverAfter { return invalid("DNSSEC policy") }
	return nil
}

func validateCertificateIssueEdge(value any) error {
	payload := value.(*CertificateIssueEdgePayload)
	if !validEdgeID(payload.Consumer) || len(payload.Names) == 0 || len(payload.Names) > 100 { return invalid("certificate issuance") }
	for _, name := range payload.Names { if !validMailHostname(strings.TrimPrefix(name, "*.")) { return invalid("certificate name") } }
	if payload.Challenge != "http-01" && payload.Challenge != "dns-01" { return invalid("certificate challenge") }
	return nil
}

func validateCertificateDeployEdge(value any) error {
	payload := value.(*CertificateDeployEdgePayload)
	if !validEdgeID(payload.Consumer) { return invalid("certificate consumer") }
	return nil
}

func validateMailDiagnostic(value any) error {
	payload := value.(*MailDiagnosticPayload)
	if payload.Depth == "" { payload.Depth = "standard" }
	if payload.Depth != "quick" && payload.Depth != "standard" && payload.Depth != "deep" { return invalid("mail diagnostic") }
	return nil
}

func validMailTelemetryScope(domainID, mailboxID string) bool {
	return (domainID == "" || validEdgeID(domainID)) && (mailboxID == "" || validEdgeID(mailboxID)) && (mailboxID == "" || domainID != "")
}

func validMailTelemetryWindow(start, end time.Time, requireHours bool) bool {
	effectiveEnd := end.UTC()
	if effectiveEnd.IsZero() {
		effectiveEnd = time.Now().UTC()
		if requireHours { effectiveEnd = effectiveEnd.Truncate(time.Hour).Add(time.Hour) }
	}
	effectiveStart := start.UTC()
	if effectiveStart.IsZero() { effectiveStart = effectiveEnd.Add(-24*time.Hour) }
	if !effectiveEnd.After(effectiveStart) || effectiveEnd.Sub(effectiveStart) > mailtelemetry.MaximumSearchWindow { return false }
	return !requireHours || effectiveStart.Equal(effectiveStart.Truncate(time.Hour)) && effectiveEnd.Equal(effectiveEnd.Truncate(time.Hour))
}

func validateMailTelemetryQuery(value any) error {
	payload := value.(*MailTelemetryQueryPayload)
	if payload.Limit == 0 { payload.Limit = 100 }
	if payload.MaximumRows == 0 { payload.MaximumRows = mailtelemetry.MaximumPageSize }
	if !validMailTelemetryScope(payload.DomainID, payload.MailboxID) || !validMailTelemetryWindow(payload.Start, payload.End, false) || payload.Limit > mailtelemetry.MaximumPageSize || payload.MaximumRows > mailtelemetry.MaximumPageSize || len(payload.Cursor) > 1024 || strings.ContainsAny(payload.Cursor, "\x00\r\n") || len(payload.Categories) > mailtelemetry.MaximumPolicyCategories { return invalid("mail telemetry query") }
	sort.Slice(payload.Categories, func(left, right int) bool { return payload.Categories[left] < payload.Categories[right] })
	for index, category := range payload.Categories {
		if !category.Valid() || index > 0 && payload.Categories[index-1] == category { return invalid("mail telemetry category") }
	}
	return nil
}

func validateMailTelemetryPage(value any) error {
	payload := value.(*EdgePagePayload)
	if payload.Limit == 0 { payload.Limit = 100 }
	if payload.Limit > mailtelemetry.MaximumPageSize || len(payload.Cursor) > 1024 || strings.ContainsAny(payload.Cursor, "\x00\r\n\t") { return invalid("mail telemetry page") }
	return nil
}

func validateMailTelemetryStatistics(value any) error {
	payload := value.(*MailTelemetryStatisticsPayload)
	if payload.DomainID == "" || !validMailTelemetryScope(payload.DomainID, payload.MailboxID) || !validMailTelemetryWindow(payload.Start, payload.End, true) { return invalid("mail telemetry statistics") }
	return nil
}

func validateMailTelemetryPolicyMutation(value any) error {
	payload := value.(*MailTelemetryPolicyMutationPayload)
	if payload.PolicyID != "" && !validEdgeID(payload.PolicyID) || !validMailTelemetryScope(payload.DomainID, payload.MailboxID) || payload.RetentionDays > 3650 || payload.ProviderRetentionDays > 3650 || payload.RetentionDays > 0 && payload.ProviderRetentionDays > 0 && payload.ProviderRetentionDays < payload.RetentionDays || payload.StorageBytes < 0 || payload.StorageBytes > 1<<50 || payload.StorageBytes > 0 && payload.StorageBytes < 1<<20 { return invalid("mail telemetry policy") }
	return nil
}

func validateMailTelemetryPolicyUpdate(value any) error {
	payload := value.(*MailTelemetryPolicyMutationPayload)
	if err := validateMailTelemetryPolicyMutation(value); err != nil { return err }
	if payload.PolicyID != "" || payload.DomainID != "" || payload.MailboxID != "" || payload.RetentionDays == 0 || payload.ProviderRetentionDays == 0 || payload.StorageBytes == 0 || payload.ExportAllowed == nil || payload.BackupHistory == nil || payload.MigrationHistory == nil { return invalid("mail telemetry policy update") }
	return nil
}

func validateMailTelemetryPolicyToggle(value any) error {
	payload := value.(*MailTelemetryPolicyMutationPayload)
	if payload.PolicyID != "" || payload.DomainID != "" || payload.MailboxID != "" || payload.RetentionDays != 0 || payload.ProviderRetentionDays != 0 || payload.StorageBytes != 0 || payload.ExportAllowed != nil || payload.BackupHistory != nil || payload.MigrationHistory != nil { return invalid("mail telemetry policy toggle") }
	return nil
}

func validateMailTelemetryPurge(value any) error {
	payload := value.(*MailTelemetryPurgePayload)
	if payload.Limit == 0 { payload.Limit = mailtelemetry.MaximumPageSize }
	if payload.Limit > mailtelemetry.MaximumPageSize { return invalid("mail telemetry purge") }
	return nil
}

func validateMailAbusePage(value any) error {
	payload := value.(*MailAbusePagePayload)
	if payload.Limit == 0 { payload.Limit = 100 }
	if payload.Limit > mailtelemetry.MaximumPageSize || len(payload.Cursor) > 1024 || strings.ContainsAny(payload.Cursor, "\x00\r\n") { return invalid("mail abuse page") }
	return nil
}

func validateMailAbuseApproval(value any) error {
	payload := value.(*MailAbuseReviewPayload)
	payload.ApprovedDigest = strings.ToLower(strings.TrimSpace(payload.ApprovedDigest))
	if !validDigestReference(payload.ApprovedDigest) || !validEdgeID(payload.EvidenceRef) || payload.RecoveryIntentID != "" || payload.ReasonDigest != "" || !payload.AllowUntil.IsZero() { return invalid("mail abuse approval") }
	return nil
}

func validateMailAbuseRecovery(value any) error {
	payload := value.(*MailAbuseReviewPayload)
	payload.ReasonDigest = strings.ToLower(strings.TrimSpace(payload.ReasonDigest))
	now := time.Now().UTC()
	if payload.RecoveryIntentID != "" && !validEdgeID(payload.RecoveryIntentID) || !validDigestReference(payload.ReasonDigest) || payload.AllowUntil.IsZero() || !payload.AllowUntil.After(now) || payload.AllowUntil.Sub(now) > mailtelemetry.MaximumBanLifetime || payload.ApprovedDigest != "" || payload.EvidenceRef != "" { return invalid("mail abuse recovery") }
	return nil
}

func mapMailTelemetryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mailtelemetry.ErrInvalid), errors.Is(err, operations.ErrInvalidResource), errors.Is(err, operations.ErrInvalidCommand):
		return ErrInvalidRequest
	case errors.Is(err, mailtelemetry.ErrUnauthorized), errors.Is(err, mailtelemetry.ErrProtected), errors.Is(err, operations.ErrUnauthorized):
		return ErrForbidden
	case errors.Is(err, mailtelemetry.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, operations.ErrNotFound):
		return ErrOperationUnavailable
	case errors.Is(err, mailtelemetry.ErrConflict), errors.Is(err, operations.ErrConflict), errors.Is(err, operations.ErrIdempotency):
		return ErrConflict
	case errors.Is(err, mailtelemetry.ErrLimit):
		return ErrResponseTooLarge
	case errors.Is(err, mailtelemetry.ErrGap), errors.Is(err, mailtelemetry.ErrIntegrity), errors.Is(err, operations.ErrInvalidReceipt), errors.Is(err, operations.ErrInvalidEffect), errors.Is(err, operations.ErrCompensationFailed):
		return ErrUnavailable
	default:
		return mapMailError(err)
	}
}

func validateWebmailDirectory(value any) error {
	payload := value.(*WebmailDirectoryPayload)
	if validateWebmailSession(payload.Session) != nil || !validOptionalMailbox(payload.MailboxID) || payload.Limit > 500 || len(payload.Cursor) > 1024 || strings.ContainsAny(payload.Cursor, "\x00\r\n") { return invalid("webmail directory") }
	if payload.Limit == 0 { payload.Limit = 100 }
	return nil
}

func validateWebmailReply(value any) error {
	payload := value.(*WebmailReplyPayload)
	message := mail.ComposeMessage{To:payload.To, CC:payload.CC, Subject:payload.Subject, Text:payload.Text, InReplyTo:payload.MessageID}
	if validateWebmailSession(payload.Session) != nil || !validOptionalMailbox(payload.MailboxID) || !safeMailOpaque(string(payload.MessageID)) || !safeCompose(message) { return invalid("webmail reply") }
	return nil
}

func validateContainerCreate(value any) error {
	payload := value.(*ContainerCreateEdgePayload)
	if !validEdgeID(payload.SiteID) || !validContainerImage(payload.Image) || payload.Recipe != "" && !validEdgeID(payload.Recipe) || payload.MemoryBytes < 64<<20 || payload.MemoryBytes > 1<<40 { return invalid("container workload") }
	return nil
}

func validateContainerExec(value any) error {
	payload := value.(*ContainerExecPayload)
	if !validEdgeID(payload.CommandID) || len(payload.Arguments) > 128 { return invalid("container exec") }
	for _, argument := range payload.Arguments { if !safeEdgeText(argument, 4096) { return invalid("container exec argument") } }
	if payload.TTLSeconds == 0 { payload.TTLSeconds = 60 }
	if payload.TTLSeconds < 15 || payload.TTLSeconds > 300 || len(payload.Token)<43 || len(payload.Token)>512 || strings.ContainsAny(payload.Token,"\x00\r\n\t ") { return invalid("container exec lifetime") }
	return nil
}

func validateContainerLogs(value any) error {
	payload := value.(*ContainerLogPayload)
	if payload.Limit == 0 { payload.Limit = 500 }
	if payload.Limit > 5000 || len(payload.Cursor) > 1024 || strings.ContainsAny(payload.Cursor, "\x00\r\n") || !payload.Start.IsZero() && !payload.End.IsZero() && payload.End.Before(payload.Start) { return invalid("container logs") }
	return nil
}

func validateOperationsDiagnostic(value any) error {
	payload := value.(*OperationsDiagnosticPayload)
	if payload.Depth == "" { payload.Depth = "standard" }
	if payload.Depth != "quick" && payload.Depth != "standard" && payload.Depth != "deep" { return invalid("service diagnostic") }
	return nil
}

func validateSecurityScan(value any) error {
	payload := value.(*SecurityScanPayload)
	if payload.Depth == "" { payload.Depth = "standard" }
	if payload.Scope != "" && !validEdgeID(payload.Scope) || payload.Depth != "quick" && payload.Depth != "standard" && payload.Depth != "deep" { return invalid("security scan") }
	return nil
}

func validateSecurityRemediation(value any) error {
	payload := value.(*SecurityRemediationPayload)
	if !validEdgeID(payload.Strategy) || !validDigestReference(payload.EvidenceDigest) { return invalid("security remediation") }
	return nil
}

func validateSecuritySuppress(value any) error {
	payload := value.(*SecuritySuppressPayload)
	if !safeEdgeText(payload.Reason, 1024) || !validDigestReference(payload.EvidenceDigest) || !payload.ExpiresAt.IsZero() && !payload.ExpiresAt.After(time.Now()) { return invalid("finding suppression") }
	return nil
}

func validateFleetEnroll(value any) error {
	payload := value.(*FleetEnrollPayload)
	payload.PeerID = strings.TrimSpace(payload.PeerID)
	payload.CentralEndpoint = strings.TrimSpace(payload.CentralEndpoint)
	payload.CentralFingerprint = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(payload.CentralFingerprint)), "sha256:")
	if _, err := federation.NewID(payload.PeerID); err != nil || !validFederationEndpoint(payload.CentralEndpoint) || len(payload.EnrollmentToken) < 32 || len(payload.EnrollmentToken) > 4096 || !validDigestReference(payload.CentralFingerprint) { return invalid("fleet enrollment") }
	return nil
}

func validFederationEndpoint(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Hostname() != "" && parsed.User == nil && parsed.Fragment == "" && parsed.RawQuery == "" && len(value) <= 2048
}

func validateHANodeDrain(value any) error {
	payload := value.(*HANodeDrainPayload)
	if !payload.Deadline.IsZero() && !payload.Deadline.After(time.Now()) { return invalid("node drain deadline") }
	return nil
}

func validateHAPromotionPlan(value any) error {
	payload := value.(*HAPromotionPlanPayload)
	explicitWriterContext := payload.ProtectedResourceID != "" || payload.WriterLeaseGeneration != 0
	if !validEdgeID(payload.CandidateNodeID) || payload.MaximumDataLoss < 0 || payload.MaximumDataLoss > 24*time.Hour || explicitWriterContext && (!validEdgeID(payload.ProtectedResourceID) || payload.WriterLeaseGeneration == 0) { return invalid("promotion plan") }
	return nil
}

func validateHAPromotionApproval(value any) error {
	payload := value.(*HAPromotionApprovalPayload)
	now := time.Now().UTC()
	if !validEdgeID(payload.ApprovalID) || !validDigestReference(payload.PlanDigest) || payload.FenceChallenge != payload.PlanDigest || payload.TenantAuthzEpoch == 0 || payload.IssuedAt.IsZero() || payload.IssuedAt.After(now) || !payload.ExpiresAt.After(payload.IssuedAt) || payload.ExpiresAt.Sub(payload.IssuedAt) > ha.MaximumPromotionApprovalLifetime || !now.Before(payload.ExpiresAt) || len(payload.Signature) < 64 || len(payload.Signature) > 4096 {
		return invalid("promotion approval")
	}
	return nil
}

func validateHAPromotionExecute(value any) error {
	payload := value.(*HAPromotionExecutePayload)
	if !validEdgeID(payload.PromotionID) || payload.WriterLeaseGeneration == 0 || !validDigestReference(payload.PlanDigest) || len(payload.QuorumEvidence) == 0 || len(payload.QuorumEvidence) > 64<<10 || len(payload.FenceProviderBindings) > 4096 {
		return invalid("promotion execution")
	}
	var quorum ha.QuorumObservation
	if json.Unmarshal([]byte(payload.QuorumEvidence), &quorum) != nil || quorum.Validate(time.Now().UTC()) != nil {
		return invalid("promotion quorum evidence")
	}
	return nil
}

func mapHAEdgeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ha.ErrLeaseLost), errors.Is(err, ha.ErrCheckpointStale):
		return ErrConflict
	case errors.Is(err, ha.ErrFenceFailed), errors.Is(err, ha.ErrSplitBrainRisk), errors.Is(err, ha.ErrDataLossApproval), errors.Is(err, ha.ErrIrreversibleFrontier), errors.Is(err, ha.ErrReconciliationRequired):
		return ErrUnavailable
	default:
		return mapDomainError(err)
	}
}

func validateMigrationCreate(value any) error {
	payload := value.(*MigrationCreatePayload)
	switch payload.Source {
	case "cyberpanel":
		if !validApprovedEndpoint(payload.SourceEndpoint) { return invalid("migration source endpoint") }
	case "cpanel", "cyberpanel_backup":
		if !validMigrationIntakeEndpoint(payload.SourceEndpoint) { return invalid("migration source endpoint") }
	default:
		return invalid("migration source")
	}
	return nil
}

func validMigrationIntakeEndpoint(value string) bool {
	if len(value) == 0 || len(value) > 2048 { return false }
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" { return false }
	path := parsed.Path
	return filepath.IsAbs(path) && filepath.Clean(path) == path && (&url.URL{Scheme:"file", Path:path}).String() == value
}

func validateMigrationPlan(value any) error {
	payload := value.(*MigrationPlanPayload)
	if payload.CollisionPolicy == "" { payload.CollisionPolicy = "fail" }
	if payload.CollisionPolicy != "fail" && payload.CollisionPolicy != "rename" && payload.CollisionPolicy != "replace" { return invalid("migration collision policy") }
	return nil
}

func validateMigrationSync(value any) error {
	payload := value.(*MigrationSyncPayload)
	if payload.MaximumBytes > 1<<50 { return invalid("migration sync budget") }
	return nil
}

func validateMigrationCutover(value any) error {
	payload := value.(*MigrationCutoverPayload)
	if !validEdgeID(payload.ApprovalRef) { return invalid("migration approval") }
	return nil
}

func validateMigrationChunkGCReconcile(value any) error {
	payload := value.(*MigrationChunkGCReconcilePayload)
	if !validDigestReference(payload.Digest) || !validDigestReference(payload.EvidenceDigest) || payload.Resolution != "confirm_deleted" && payload.Resolution != "retain_present" || !validPositiveInt64Text(payload.ObjectEpoch) {
		return invalid("migration chunk GC reconciliation")
	}
	return nil
}

func validPositiveInt64Text(value string) bool {
	if len(value) == 0 || len(value) > 19 || value[0] == '0' || len(value) == 19 && value > "9223372036854775807" { return false }
	for _, character := range value { if character < '0' || character > '9' { return false } }
	return true
}

func validateIdentityTenantCreate(value any) error {
	payload := value.(*IdentityTenantCreatePayload)
	if !safeEdgeText(payload.Name, 128) || payload.ParentTenantID != "" && !validEdgeID(payload.ParentTenantID) || !validEdgeID(payload.PlanID) { return invalid("tenant") }
	return nil
}

func validateIdentityEntitlement(value any) error {
	payload := value.(*IdentityEntitlementPayload)
	if !validEdgeID(payload.PlanID) || len(payload.Limits) > 128 { return invalid("entitlement") }
	for name, limit := range payload.Limits { if !validEdgeID(name) || limit > 1<<60 { return invalid("entitlement limit") } }
	return nil
}

func validateIdentityInvitationPage(value any) error {
	if err := validateEdgePage(value); err != nil { return err }
	if value.(*EdgePagePayload).Limit > 200 { return invalid("invitation page") }
	return nil
}

func validateIdentityInvitationCreate(value any) error {
	payload := value.(*IdentityInvitationCreatePayload)
	if !safeEdgeText(payload.IntendedEmail, 254) || !strings.Contains(payload.IntendedEmail, "@") || !validEdgeID(payload.RoleID) || payload.ExpiresAt.IsZero() {
		return invalid("invitation")
	}
	switch payload.ScopeKind {
	case "tenant":
		if payload.ResourceID != "" { return invalid("invitation scope") }
	case "project", "site":
		if !validEdgeID(payload.ResourceID) { return invalid("invitation scope") }
	default:
		return invalid("invitation scope")
	}
	return nil
}

func validateIdentityInvitationAccept(value any) error {
	payload := value.(*IdentityInvitationAcceptPayload)
	if len(payload.Token) < 40 || len(payload.Token) > 128 || strings.ContainsAny(payload.Token, "\x00\r\n\t ") {
		return invalid("invitation token")
	}
	return nil
}

func validateWebEngineLicense(value any) error {
	payload := value.(*WebEngineLicensePayload)
	if payload.Edition != "litespeed_enterprise" && payload.Edition != "openlitespeed" || payload.Edition == "litespeed_enterprise" && (len(payload.LicenseSecret) < 12 || len(payload.LicenseSecret) > 8192) || payload.Edition == "openlitespeed" && payload.LicenseSecret != "" { return invalid("web engine license") }
	return nil
}

func validateWebEngineTuning(value any) error {
	payload := value.(*WebEngineTuningPayload)
	if payload.WorkerProcesses == 0 && payload.MaxConnections == 0 && payload.KeepAliveSeconds == 0 || payload.WorkerProcesses > 1024 || payload.MaxConnections > 10_000_000 || payload.KeepAliveSeconds > 3600 { return invalid("web engine tuning") }
	return nil
}

func validateWebEngineUpgrade(value any) error {
	payload := value.(*WebEngineUpgradePayload)
	if !validVersion(payload.Version) || payload.Channel != "" && payload.Channel != "stable" && payload.Channel != "pinned" { return invalid("web engine upgrade") }
	return nil
}

func validateWebEngineRemove(value any) error {
	payload := value.(*WebEngineRemovePayload)
	if payload.Confirmation != WebEngineRemoveConfirmation { return invalid("web engine removal confirmation") }
	return nil
}

func validateWebEnginePHPProfile(value any) error {
	payload := value.(*WebEnginePHPProfilePayload)
	if !validEdgeID(payload.Name) || !validVersion(payload.Version) || len(payload.Extensions) > 256 || payload.MemoryBytes > 1<<40 { return invalid("PHP profile") }
	for _, extension := range payload.Extensions { if !validEdgeID(extension) { return invalid("PHP extension") } }
	return nil
}

func validateIntegrationCreate(value any) error {
	payload := value.(*IntegrationCreatePayload)
	if !validIntegrationProvider(payload.Provider) || !safeEdgeText(payload.Name, 128) || len(payload.Credential) < 12 || len(payload.Credential) > 64<<10 || strings.ContainsRune(payload.Credential, 0) { return invalid("integration binding") }
	return nil
}

func validateIntegrationRotate(value any) error {
	payload := value.(*IntegrationRotatePayload)
	if len(payload.Credential) < 12 || len(payload.Credential) > 64<<10 || strings.ContainsRune(payload.Credential, 0) { return invalid("integration credential") }
	return nil
}

func edgeTenantListScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if request.ResourceID != "" || request.ExpectedGeneration != 0 { return identity.Scope{}, invalid("tenant list scope") }
	return tenantScope(request, value)
}

func edgeTenantResourceReadScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !validEdgeID(request.ResourceID) || request.ExpectedGeneration != 0 { return identity.Scope{}, invalid("tenant resource scope") }
	return tenantScope(request, value)
}

func edgeTenantCreateScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if request.ResourceID != "" || request.ExpectedGeneration != 0 { return identity.Scope{}, invalid("tenant create scope") }
	return tenantScope(request, value)
}

func edgeTenantExistingMutationScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !validEdgeID(request.ResourceID) || request.ExpectedGeneration == 0 { return identity.Scope{}, invalid("tenant resource generation") }
	return tenantScope(request, value)
}

func edgeInstallationListScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if request.TenantID != "" || request.ResourceID != "" || request.ExpectedGeneration != 0 { return identity.Scope{}, invalid("installation list scope") }
	return installationScope(request, value)
}

func edgeInstallationResourceReadScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if request.TenantID != "" || !validEdgeID(request.ResourceID) || request.ExpectedGeneration != 0 { return identity.Scope{}, invalid("installation resource scope") }
	return installationScope(request, value)
}

func edgeInstallationCreateScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if request.TenantID != "" || request.ResourceID != "" || request.ExpectedGeneration != 0 { return identity.Scope{}, invalid("installation create scope") }
	return installationScope(request, value)
}

func edgeInstallationExistingMutationScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if request.TenantID != "" || !validEdgeID(request.ResourceID) || request.ExpectedGeneration == 0 { return identity.Scope{}, invalid("installation resource generation") }
	return installationScope(request, value)
}

func edgeTenantOrInstallationListScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if request.ResourceID != "" || request.ExpectedGeneration != 0 { return identity.Scope{}, invalid("list scope") }
	return tenantOrInstallationScope(request, value)
}

func edgeTenantOrInstallationResourceReadScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !validEdgeID(request.ResourceID) || request.ExpectedGeneration != 0 { return identity.Scope{}, invalid("resource scope") }
	return tenantOrInstallationScope(request, value)
}

func edgeTenantOrInstallationCreateScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if request.ResourceID != "" || request.ExpectedGeneration != 0 { return identity.Scope{}, invalid("create scope") }
	return tenantOrInstallationScope(request, value)
}

func edgeTenantOrInstallationExistingMutationScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !validEdgeID(request.ResourceID) || request.ExpectedGeneration == 0 { return identity.Scope{}, invalid("resource generation") }
	return tenantOrInstallationScope(request, value)
}

func validEdgeID(value string) bool {
	if value == "" || len(value) > 128 || !edgeAlphaNumeric(value[0]) || !edgeAlphaNumeric(value[len(value)-1]) { return false }
	for index := range value {
		character := value[index]
		if !edgeAlphaNumeric(character) && character != '-' && character != '_' && character != '.' && character != ':' { return false }
	}
	return true
}

func edgeAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func safeEdgeText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validEdgeNonce(value string) bool {
	if len(value) < 16 || len(value) > 256 { return false }
	for index := range value {
		character := value[index]
		if !edgeAlphaNumeric(character) && character != '-' && character != '_' { return false }
	}
	return true
}

func validRelativeName(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\\") { return false }
	for _, segment := range strings.Split(value, "/") { if segment == "" || segment == "." || segment == ".." || len(segment) > 255 { return false } }
	return true
}

func safeSchedule(value string) bool {
	if len(value) < 5 || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n;|&$`") { return false }
	fields := strings.Fields(value)
	return len(fields) == 5 || len(fields) == 6
}

func validDNSOwner(value string) bool {
	if value == "@" { return true }
	return validMailHostname(strings.TrimPrefix(value, "*."))
}

func validDNSRecordType(value string) bool {
	switch strings.ToUpper(value) { case "A", "AAAA", "CAA", "CNAME", "MX", "NAPTR", "NS", "PTR", "SRV", "SSHFP", "TLSA", "TXT": return true }
	return false
}

func validContainerImage(value string) bool {
	if len(value) < 72 || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n\t @") { return false }
	separator := strings.LastIndex(value, "@sha256:")
	if separator < 1 || len(value[separator+8:]) != 64 { return false }
	for _, character := range value[separator+8:] { if character < '0' || character > '9' && character < 'a' || character > 'f' { return false } }
	return true
}

func validDigestReference(value string) bool {
	if len(value) != 64 { return false }
	for _, character := range value { if character < '0' || character > '9' && character < 'a' || character > 'f' { return false } }
	return true
}

func validFingerprint(value string) bool {
	raw := strings.TrimPrefix(value, "sha256:")
	return validDigestReference(strings.ToLower(raw))
}

func validApprovedEndpoint(value string) bool {
	if validEdgeID(value) { return true }
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.User == nil && parsed.Hostname() != "" && parsed.Fragment == "" && len(value) <= 2048
}

func validVersion(value string) bool {
	if value == "" || len(value) > 128 { return false }
	for index := range value {
		character := value[index]
		if !edgeAlphaNumeric(character) && !strings.ContainsRune(".+_~-", rune(character)) { return false }
	}
	return true
}

func validIntegrationProvider(value string) bool {
	switch value {
	case "cloudflare", "aws_s3", "wasabi_s3", "backblaze_b2_s3", "google_drive", "sftp", "notification_smtp", "notification_webhook", "container_registry", "security_scanner":
		return true
	default:
		return false
	}
}

func edgeCall(inv Invocation) EdgeCall {
	csrfBinding:=""
	if inv.Meta.Origin!=""&&inv.Actor.SessionID.String()!="" { sum:=sha256.Sum256([]byte(inv.Meta.Origin+"\x00"+inv.Meta.UserAgentDigest+"\x00"+inv.Actor.SessionID.String()+"\x00"+inv.Actor.CredentialID.String()));csrfBinding=hex.EncodeToString(sum[:]) }
	return EdgeCall{CommandID:commandID(inv), IdempotencyKey:inv.IdempotencyKey, TenantID:inv.Request.TenantID, ResourceID:inv.Request.ResourceID, ExpectedGeneration:inv.Request.ExpectedGeneration, PrincipalID:inv.Actor.PrincipalID.String(),SessionID:inv.Actor.SessionID.String(),CredentialID:inv.Actor.CredentialID.String(),AuthzEpoch:inv.Actor.AuthzEpoch,Assurance:inv.Actor.Assurance,Origin:inv.Meta.Origin,CSRFBinding:csrfBinding}
}

func edgeOperationResult[T any](status int, result EdgeMutation[T]) OperationResult {
	return OperationResult{Status:status, Value:result, Generation:result.Generation}
}

func hostingSiteProjection(aggregate site.Site) HostingSiteProjection {
	primary := ""
	for _, binding := range aggregate.Bindings() { if binding.Kind == site.BindingPrimary { primary=binding.Hostname.String(); break } }
	return HostingSiteProjection{ID:aggregate.ID().String(),TenantID:aggregate.TenantID().String(),ProjectID:aggregate.ProjectID().String(),PrimaryHostname:primary,PHPProfile:string(aggregate.PHPProfile()),Lifecycle:string(aggregate.Lifecycle()),Generation:aggregate.Generation()}
}

func hostingBindingProjection(aggregate site.Site, binding site.DomainBinding) HostingBindingProjection {
	routing := "maintenance"; if aggregate.Lifecycle()==site.LifecycleActive { routing="serving" }; if aggregate.Lifecycle()==site.LifecyclePurging||aggregate.Lifecycle()==site.LifecycleDeleted { routing="withdrawn" }
	return HostingBindingProjection{ID:aggregate.ID().String()+":"+binding.Hostname.String(),SiteID:aggregate.ID().String(),Hostname:binding.Hostname.String(),Relationship:string(binding.Kind),RedirectTarget:binding.RedirectTarget.String(),TLS:"unmanaged",Routing:routing,Generation:aggregate.Generation()}
}

func hostingBindingProjectionFromReceipt(receipt service.OperationReceipt, selected site.DomainBinding) HostingBindingProjection {
	return HostingBindingProjection{ID:receipt.Scope.SiteID.String()+":"+selected.Hostname.String(),SiteID:receipt.Scope.SiteID.String(),Hostname:selected.Hostname.String(),Relationship:string(selected.Kind),RedirectTarget:selected.RedirectTarget.String(),TLS:"unmanaged",Routing:hostingRouting(receipt.Request.Projection.Lifecycle),Generation:receipt.Request.Projection.Generation}
}

func hostingRouting(lifecycle site.Lifecycle) string {
	if lifecycle==site.LifecycleActive { return "serving" }
	if lifecycle==site.LifecyclePurging||lifecycle==site.LifecycleDeleted { return "withdrawn" }
	return "maintenance"
}

func domainBindingFromPayload(payload HostingBindingPayload) (site.DomainBinding,error) {
	hostname, err := site.ParseHostname(payload.Hostname); if err != nil { return site.DomainBinding{},ErrInvalidRequest }
	binding := site.DomainBinding{Hostname:hostname}
	switch payload.Relationship {
	case "alias": binding.Kind=site.BindingAlias
	case "child": binding.Kind=site.BindingChild
	case "redirect":
		binding.Kind=site.BindingRedirect; binding.RedirectStatus=site.RedirectStatusPermanent301
		binding.RedirectTarget,err=site.ParseHostname(payload.RedirectTarget); if err != nil { return site.DomainBinding{},ErrInvalidRequest }
	default: return site.DomainBinding{},ErrInvalidRequest
	}
	return binding,nil
}

func bindConsoleEdgeContracts(registry *Registry, services DomainServices) error {
	if services.DashboardEdge != nil {
		if err := registry.Bind("dashboard.summary", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.DashboardEdge.Summary(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
	}
	if services.HostingEdge != nil {
		if err := registry.Bind("hosting.site.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.HostingEdge.ListSites(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("hosting.site.get", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.HostingEdge.GetSite(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err }
		if err := registry.Bind("hosting.binding.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.HostingEdge.ListBindings(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("hosting.binding.create", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.HostingEdge.CreateBinding(ctx, edgeCall(inv), *value.(*HostingBindingPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("hosting.binding.delete", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.HostingEdge.DeleteBinding(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
	}
	if services.HostingCloneEdge != nil { if err:=registry.Bind("hosting.site.clone",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*HostingClonePayload);material:=takeApplicationCloneMaterial(payload);defer material.clear();result,err:=services.HostingCloneEdge.CloneSite(ctx,edgeCall(inv),*payload,material);if err!=nil{return OperationResult{},mapDomainError(err)};return edgeOperationResult(http.StatusAccepted,result),nil});err!=nil{return err} }
	if services.HostingPreviewEdge != nil { if err:=registry.Bind("hosting.site.preview.issue",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=services.HostingPreviewEdge.IssuePreview(ctx,edgeCall(inv),*value.(*HostingPreviewPayload));if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusCreated,Value:result},nil});err!=nil{return err} }
	if services.HostingAccessPolicyEdge != nil { if err:=registry.Bind("hosting.binding.access_policy",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=services.HostingAccessPolicyEdge.ConfigureAccessPolicy(ctx,edgeCall(inv),*value.(*HostingAccessPolicyPayload));if err!=nil{return OperationResult{},mapDomainError(err)};return edgeOperationResult(http.StatusOK,result),nil});err!=nil{return err} }
	if services.Hosting != nil {
		if services.HostingQuery != nil && services.HostingEdge == nil {
			if err := registry.Bind("hosting.site.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				tenant, err := site.NewTenantID(inv.Request.TenantID); if err != nil { return OperationResult{}, ErrInvalidRequest }
				page := value.(*EdgePagePayload)
				aggregates, next, total, err := services.HostingQuery.List(ctx, tenant, page.Cursor, int(page.Limit)); if err != nil { return OperationResult{}, mapHostingError(err) }
				items := make([]HostingSiteProjection, 0, len(aggregates)); for _, aggregate := range aggregates { items = append(items, hostingSiteProjection(aggregate)) }
				return OperationResult{Status:http.StatusOK, Value:EdgePage[HostingSiteProjection]{Items:items, NextCursor:next, Total:total}}, nil
			}); err != nil { return err }
			if err := registry.Bind("hosting.site.get", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
				tenant, err := site.NewTenantID(inv.Request.TenantID); if err != nil { return OperationResult{}, ErrInvalidRequest }
				id, err := site.NewSiteID(inv.Request.ResourceID); if err != nil { return OperationResult{}, ErrInvalidRequest }
				aggregate, err := services.HostingQuery.Load(ctx, tenant, id); if err != nil { return OperationResult{}, mapHostingError(err) }
				projection := hostingSiteProjection(aggregate)
				return OperationResult{Status:http.StatusOK, Value:projection, Generation:projection.Generation}, nil
			}); err != nil { return err }
			if err := registry.Bind("hosting.binding.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				tenant, err := site.NewTenantID(inv.Request.TenantID); if err != nil { return OperationResult{}, ErrInvalidRequest }
				page := value.(*EdgePagePayload)
				aggregates, _, _, err := services.HostingQuery.List(ctx, tenant, "", 500); if err != nil { return OperationResult{}, mapHostingError(err) }
				bindings := make([]HostingBindingProjection, 0); for _, aggregate := range aggregates { for _, binding := range aggregate.Bindings() { if binding.Kind != site.BindingPrimary { bindings = append(bindings, hostingBindingProjection(aggregate, binding)) } } }
				sort.Slice(bindings, func(i,j int) bool { return bindings[i].ID < bindings[j].ID })
				start := 0; if page.Cursor != "" { for start < len(bindings) && bindings[start].ID <= page.Cursor { start++ } }
				end := start+int(page.Limit); if end > len(bindings) { end=len(bindings) }; next := ""; if end < len(bindings) && end > start { next=bindings[end-1].ID }
				return OperationResult{Status:http.StatusOK, Value:EdgePage[HostingBindingProjection]{Items:append([]HostingBindingProjection(nil),bindings[start:end]...),NextCursor:next,Total:uint64(len(bindings))}}, nil
			}); err != nil { return err }
			if err := registry.Bind("hosting.binding.create", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				payload := value.(*HostingBindingPayload); tenant, err := site.NewTenantID(inv.Request.TenantID); if err != nil { return OperationResult{}, ErrInvalidRequest }
				siteID, err := site.NewSiteID(payload.SiteID); if err != nil { return OperationResult{}, ErrInvalidRequest }
				aggregate, err := services.HostingQuery.Load(ctx, tenant, siteID); if err != nil { return OperationResult{}, mapHostingError(err) }
				binding, err := domainBindingFromPayload(*payload); if err != nil { return OperationResult{}, err }
				command := service.AttachDomainBinding{CommandID:commandID(inv),Actor:service.Actor{TenantID:tenant},TenantID:tenant,SiteID:siteID,ExpectedGeneration:aggregate.Generation(),Binding:binding}
				receipt, err := services.Hosting.Handle(ctx, command); if err != nil { return OperationResult{}, mapHostingError(err) }
				projection := hostingBindingProjectionFromReceipt(receipt,binding)
				return edgeOperationResult(http.StatusCreated, EdgeMutation[HostingBindingProjection]{OperationID:receipt.CommandID,State:string(receipt.Status),Generation:projection.Generation,Resource:projection}), nil
			}); err != nil { return err }
			if err := registry.Bind("hosting.binding.delete", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
				siteRaw, hostnameRaw, found := strings.Cut(inv.Request.ResourceID, ":"); if !found { return OperationResult{}, ErrInvalidRequest }
				tenant, err := site.NewTenantID(inv.Request.TenantID); if err != nil { return OperationResult{}, ErrInvalidRequest }; siteID, err := site.NewSiteID(siteRaw); if err != nil { return OperationResult{}, ErrInvalidRequest }; hostname, err := site.ParseHostname(hostnameRaw); if err != nil { return OperationResult{}, ErrInvalidRequest }
				command := service.DetachDomainBinding{CommandID:commandID(inv),Actor:service.Actor{TenantID:tenant},TenantID:tenant,SiteID:siteID,ExpectedGeneration:inv.Request.ExpectedGeneration,Hostname:hostname}
				receipt, err := services.Hosting.Handle(ctx, command); if err != nil { return OperationResult{}, mapHostingError(err) }
				projection := HostingBindingProjection{ID:inv.Request.ResourceID,SiteID:siteRaw,Hostname:hostnameRaw,Routing:"withdrawn",Generation:receipt.Request.Projection.Generation}
				return edgeOperationResult(http.StatusOK, EdgeMutation[HostingBindingProjection]{OperationID:receipt.CommandID,State:string(receipt.Status),Generation:projection.Generation,Resource:projection}), nil
			}); err != nil { return err }
		}
		for name, action := range map[string]string{"hosting.site.suspend":"suspend", "hosting.site.resume":"resume", "hosting.site.delete":"begin_delete"} {
			name, action := name, action
			if err := registry.Bind(name, func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
				tenant, err := site.NewTenantID(inv.Request.TenantID); if err != nil { return OperationResult{}, ErrInvalidRequest }
				siteID, err := site.NewSiteID(inv.Request.ResourceID); if err != nil { return OperationResult{}, ErrInvalidRequest }
				var command service.Command
				switch action {
				case "suspend": command = service.SuspendSite{CommandID:commandID(inv), Actor:service.Actor{TenantID:tenant}, TenantID:tenant, SiteID:siteID, ExpectedGeneration:inv.Request.ExpectedGeneration}
				case "resume": command = service.ResumeSite{CommandID:commandID(inv), Actor:service.Actor{TenantID:tenant}, TenantID:tenant, SiteID:siteID, ExpectedGeneration:inv.Request.ExpectedGeneration}
				case "begin_delete": command = service.BeginDelete{CommandID:commandID(inv), Actor:service.Actor{TenantID:tenant}, TenantID:tenant, SiteID:siteID, ExpectedGeneration:inv.Request.ExpectedGeneration}
				}
				receipt, err := services.Hosting.Handle(ctx, command); if err != nil { return OperationResult{}, mapHostingError(err) }
				return OperationResult{Status:http.StatusOK, Value:receipt, Generation:receipt.Request.Projection.Generation}, nil
			}); err != nil { return err }
		}
	}
	if services.DatabaseEdge != nil {
		if err := registry.Bind("database.database.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.DatabaseEdge.ListDatabases(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("database.database.create_managed", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.DatabaseEdge.CreateManagedDatabase(ctx, edgeCall(inv), *value.(*DatabaseCreateManagedPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("database.principal.create_managed", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*DatabasePrincipalCreateManagedPayload)
			password := []byte(payload.Password)
			payload.Password = ""
			defer clearSecret(password)
			result, err := services.DatabaseEdge.CreateManagedPrincipal(ctx, edgeCall(inv), *payload, password); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("database.instance.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.DatabaseEdge.ListDatabaseInstances(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("database.instance.health", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.DatabaseEdge.InspectDatabaseInstance(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err }
		if err := registry.Bind("database.instance.network.configure", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.DatabaseEdge.ConfigureDatabaseInstanceNetwork(ctx, edgeCall(inv), *value.(*DatabaseNetworkConfigureManagedPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
		if err := registry.Bind("database.instance.enroll_external", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*DatabaseExternalEnrollmentPayload)
			material := DatabaseExternalEnrollmentSecrets{
				AdministratorPassword: []byte(payload.AdministratorPassword),
				ClientCertificatePEM: []byte(payload.ClientCertificatePEM),
				ClientKeyPEM: []byte(payload.ClientKeyPEM),
				CertificateAuthorityPEM: []byte(payload.CertificateAuthorityPEM),
			}
			payload.AdministratorPassword = ""
			payload.ClientCertificatePEM = ""
			payload.ClientKeyPEM = ""
			payload.CertificateAuthorityPEM = ""
			defer clearSecret(material.AdministratorPassword)
			defer clearSecret(material.ClientCertificatePEM)
			defer clearSecret(material.ClientKeyPEM)
			defer clearSecret(material.CertificateAuthorityPEM)
			result, err := services.DatabaseEdge.EnrollExternalDatabaseInstance(ctx, edgeCall(inv), *payload, material)
			if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
	}
	if err := bindManagedDatabaseConsole(registry, services); err != nil { return err }
	if services.AccessEdge != nil {
		if err := registry.Bind("access.credential.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.AccessEdge.ListCredentials(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("access.credential.create", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*AccessCredentialCreatePayload); secret := []byte(payload.Secret); payload.Secret = ""; defer clearSecret(secret)
			result, err := services.AccessEdge.CreateCredential(ctx, edgeCall(inv), *payload, secret); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("access.credential.rotate", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*AccessCredentialRotatePayload); secret := []byte(payload.Secret); payload.Secret = ""; defer clearSecret(secret)
			result, err := services.AccessEdge.RotateCredential(ctx, edgeCall(inv), *payload, secret); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
		if err := registry.Bind("access.credential.revoke", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.AccessEdge.RevokeCredential(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
		if err := registry.Bind("access.terminal.issue", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.AccessEdge.IssueTerminal(ctx, edgeCall(inv), *value.(*AccessTerminalPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusCreated, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("access.file.write", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.AccessEdge.WriteFile(ctx, edgeCall(inv), *value.(*AccessFileWritePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
	}
	if services.ApplicationEdge != nil {
		capabilities:=ApplicationEdgeCapabilities{List:true,Discover:true,Adopt:true,Install:true,Update:true,Remove:true,Scan:true,Autologin:true,CachePurge:true};if provider,ok:=services.ApplicationEdge.(ApplicationEdgeCapabilityProvider);ok{capabilities=provider.ApplicationCapabilities()}
		if capabilities.List { if err := registry.Bind("apps.instance.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ApplicationEdge.ListApplications(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err } }
		if capabilities.Discover { if err := registry.Bind("apps.discovery.scan", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ApplicationEdge.DiscoverApplications(ctx, edgeCall(inv), *value.(*ApplicationDiscoveryEdgePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err } }
		if capabilities.Adopt { if err := registry.Bind("apps.discovery.adopt", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ApplicationEdge.AdoptApplication(ctx, edgeCall(inv), *value.(*ApplicationAdoptEdgePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err } }
		if capabilities.Install { if err := registry.Bind("apps.instance.install", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload:=value.(*ApplicationInstallEdgePayload);material:=takeApplicationInstallMaterial(payload);defer material.clear()
			result, err := services.ApplicationEdge.InstallApplication(ctx, edgeCall(inv), *payload, material); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err } }
		if capabilities.Update { if err := registry.Bind("apps.instance.update", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ApplicationEdge.UpdateApplication(ctx, edgeCall(inv), *value.(*ApplicationUpdateEdgePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
		if capabilities.Remove { if err := registry.Bind("apps.instance.remove", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.ApplicationEdge.RemoveApplication(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
		if capabilities.Scan { if err := registry.Bind("apps.scan.start", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ApplicationEdge.ScanApplication(ctx, edgeCall(inv), *value.(*ApplicationScanPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
		if capabilities.Autologin { if err := registry.Bind("apps.wordpress.autologin.issue", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ApplicationEdge.IssueWordPressAutologin(ctx, edgeCall(inv), *value.(*ApplicationAutologinPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusCreated, Value:result}, nil
		}); err != nil { return err } }
		if capabilities.CachePurge { if err := registry.Bind("apps.wordpress.cache.purge", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ApplicationEdge.PurgeWordPressCache(ctx, edgeCall(inv), *value.(*ApplicationCachePurgePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
	}
	return bindConsoleEdgeContractsTwo(registry, services)
}

func bindConsoleEdgeContractsTwo(registry *Registry, services DomainServices) error {
	if services.BackupEdge != nil {
		if err := registry.Bind("backup.policy.create", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.BackupEdge.CreatePolicy(ctx, edgeCall(inv), *value.(*BackupPolicyCreatePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("backup.restore.plan", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.BackupEdge.PlanRestore(ctx, edgeCall(inv), *value.(*BackupRestorePlanPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
	}
	if services.DNSEdge != nil {
		if err := registry.Bind("dns.zone.import", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.DNSEdge.ImportZone(ctx, edgeCall(inv), *value.(*DNSZoneImportPayload)); if err != nil { return OperationResult{}, mapDNSError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("dns.dnssec.configure", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.DNSEdge.ConfigureDNSSEC(ctx, edgeCall(inv), *value.(*DNSSECConfigurePayload)); if err != nil { return OperationResult{}, mapDNSError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
	}
	if services.CertificateEdge != nil {
		if err := registry.Bind("certificate.issue", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.CertificateEdge.IssueCertificate(ctx, edgeCall(inv), *value.(*CertificateIssueEdgePayload)); if err != nil { return OperationResult{}, mapCertificateError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("certificate.site.issue", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.CertificateEdge.IssueSiteCertificate(ctx, edgeCall(inv), *value.(*CertificateIssueEdgePayload)); if err != nil { return OperationResult{}, mapCertificateError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("certificate.deploy", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.CertificateEdge.DeployCertificate(ctx, edgeCall(inv), *value.(*CertificateDeployEdgePayload)); if err != nil { return OperationResult{}, mapCertificateError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
	}
	if services.MailEdge != nil {
		if err := registry.Bind("mail.route.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MailEdge.ListRoutes(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapMailError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("mail.diagnostic.run", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MailEdge.RunDiagnostic(ctx, edgeCall(inv), *value.(*MailDiagnosticPayload)); if err != nil { return OperationResult{}, mapMailError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("mail.telemetry.event.search", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MailEdge.SearchTelemetry(ctx, edgeCall(inv), *value.(*MailTelemetryQueryPayload)); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("mail.telemetry.event.stream", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MailEdge.StreamTelemetry(ctx, edgeCall(inv), *value.(*MailTelemetryQueryPayload)); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("mail.telemetry.statistics", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MailEdge.TelemetryStatistics(ctx, edgeCall(inv), *value.(*MailTelemetryStatisticsPayload)); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("mail.telemetry.policy.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MailEdge.ListTelemetryPolicies(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("mail.telemetry.policy.get", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.MailEdge.GetTelemetryPolicy(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err }
		bindPolicyMutation := func(name, action string, status int) error {
			return registry.Bind(name, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				payload := value.(*MailTelemetryPolicyMutationPayload); payload.Action = action
				result, err := services.MailEdge.MutateTelemetryPolicy(ctx, edgeCall(inv), *payload); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
				return edgeOperationResult(status, result), nil
			})
		}
		if err := bindPolicyMutation("mail.telemetry.policy.create", "create", http.StatusCreated); err != nil { return err }
		if err := bindPolicyMutation("mail.telemetry.policy.update", "update", http.StatusAccepted); err != nil { return err }
		if err := bindPolicyMutation("mail.telemetry.policy.enable", "enable", http.StatusAccepted); err != nil { return err }
		if err := bindPolicyMutation("mail.telemetry.policy.disable", "disable", http.StatusAccepted); err != nil { return err }
		if err := registry.Bind("mail.telemetry.export", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MailEdge.ExportTelemetry(ctx, edgeCall(inv), *value.(*MailTelemetryQueryPayload)); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("mail.telemetry.purge", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MailEdge.PurgeTelemetry(ctx, edgeCall(inv), *value.(*MailTelemetryPurgePayload)); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		bindAbusePage := func(name, kind string) error {
			return registry.Bind(name, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				payload := value.(*MailAbusePagePayload); payload.Kind = kind
				result, err := services.MailEdge.ListMailAbuse(ctx, edgeCall(inv), *payload); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
				return OperationResult{Status:http.StatusOK, Value:result}, nil
			})
		}
		if err := bindAbusePage("mail.abuse.finding.list", "findings"); err != nil { return err }
		if err := bindAbusePage("mail.abuse.intent.list", "intents"); err != nil { return err }
		if err := registry.Bind("mail.abuse.intent.get", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.MailEdge.InspectMailAbuse(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err }
		bindAbuseReview := func(name, action string) error {
			return registry.Bind(name, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				payload := value.(*MailAbuseReviewPayload); payload.Action = action
				result, err := services.MailEdge.ReviewMailAbuse(ctx, edgeCall(inv), *payload); if err != nil { return OperationResult{}, mapMailTelemetryError(err) }
				return edgeOperationResult(http.StatusAccepted, result), nil
			})
		}
		if err := bindAbuseReview("mail.abuse.intent.approve", "approve"); err != nil { return err }
		if err := bindAbuseReview("mail.abuse.intent.recover", "recover"); err != nil { return err }
	}
	if services.WebmailEdge != nil && services.Webmail != nil {
		if err := registry.Bind("webmail.contact.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*WebmailDirectoryPayload); session, err := boundWebmailSession(ctx, services.Webmail, inv, payload.Session, payload.MailboxID); if err != nil { return OperationResult{}, err }
			result, err := services.WebmailEdge.ListContacts(ctx, edgeCall(inv), session, EdgePagePayload{Limit:payload.Limit, Cursor:payload.Cursor}); if err != nil { return OperationResult{}, mapMailError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("webmail.sieve.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*WebmailDirectoryPayload); session, err := boundWebmailSession(ctx, services.Webmail, inv, payload.Session, payload.MailboxID); if err != nil { return OperationResult{}, err }
			result, err := services.WebmailEdge.ListSieveRules(ctx, edgeCall(inv), session, EdgePagePayload{Limit:payload.Limit, Cursor:payload.Cursor}); if err != nil { return OperationResult{}, mapMailError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
	}
	if services.Webmail != nil {
		if err := registry.Bind("webmail.message.reply", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*WebmailReplyPayload); session, err := boundWebmailSession(ctx, services.Webmail, inv, payload.Session, payload.MailboxID); if err != nil { return OperationResult{}, err }
			message := mail.ComposeMessage{To:payload.To, CC:payload.CC, Subject:payload.Subject, Text:payload.Text, InReplyTo:payload.MessageID}
			queueID, err := services.Webmail.Send(ctx, session, message); if err != nil { return OperationResult{}, mapMailError(err) }
			return OperationResult{Status:http.StatusAccepted, Value:map[string]mail.QueueID{"queue_id":queueID}}, nil
		}); err != nil { return err }
	}
	if services.ContainerEdge != nil {
		if err := registry.Bind("container.workload.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ContainerEdge.ListWorkloads(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("container.workload.create", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ContainerEdge.CreateWorkload(ctx, edgeCall(inv), *value.(*ContainerCreateEdgePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("container.workload.restart", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.ContainerEdge.RestartWorkload(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("container.workload.delete", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.ContainerEdge.DeleteWorkload(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("container.exec.issue", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ContainerEdge.IssueExec(ctx, edgeCall(inv), *value.(*ContainerExecPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusCreated, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("container.logs.query", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ContainerEdge.QueryLogs(ctx, edgeCall(inv), *value.(*ContainerLogPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
	}
	return bindConsoleEdgeContractsThree(registry, services)
}

func bindConsoleEdgeContractsThree(registry *Registry, services DomainServices) error {
	if services.OperationsEdge != nil {
		if err := registry.Bind("operations.service.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.OperationsEdge.ListServices(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("operations.service.restart", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.OperationsEdge.RestartService(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("operations.service.stop", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.OperationsEdge.StopService(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("operations.diagnostic.run", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.OperationsEdge.RunDiagnostic(ctx, edgeCall(inv), *value.(*OperationsDiagnosticPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
	}
	if services.SecurityEdge != nil {
		if err := registry.Bind("security.finding.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.SecurityEdge.ListFindings(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("security.finding.get", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.SecurityEdge.GetFinding(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err }
		if err := registry.Bind("security.scan.start", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.SecurityEdge.StartScan(ctx, edgeCall(inv), *value.(*SecurityScanPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("security.remediation.apply", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.SecurityEdge.ApplyRemediation(ctx, edgeCall(inv), *value.(*SecurityRemediationPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("security.finding.suppress", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.SecurityEdge.SuppressFinding(ctx, edgeCall(inv), *value.(*SecuritySuppressPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
	}
	if services.FleetEdge != nil {
		if err := registry.Bind("fleet.node.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.FleetEdge.ListNodes(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("fleet.node.get", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.FleetEdge.GetNode(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err }
		if err := registry.Bind("fleet.node.enroll", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*FleetEnrollPayload); token := []byte(payload.EnrollmentToken); payload.EnrollmentToken = ""; defer clearSecret(token)
			// The token remains out of EdgeCall and can only be consumed by the
			// explicit enrollment adapter through this bounded payload lifetime.
			result, err := services.FleetEdge.EnrollNode(ctx, edgeCall(inv), *payload, token); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("fleet.node.revoke", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.FleetEdge.RevokeNode(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
	}
	if services.HAEdge != nil {
		if err := registry.Bind("ha.topology.status", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.HAEdge.TopologyStatus(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapHAEdgeError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err }
		if err := registry.Bind("ha.node.health", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.HAEdge.NodeHealth(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapHAEdgeError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err }
		if err := registry.Bind("ha.node.drain", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.HAEdge.DrainNode(ctx, edgeCall(inv), *value.(*HANodeDrainPayload)); if err != nil { return OperationResult{}, mapHAEdgeError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("ha.promotion.plan", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.HAEdge.PlanPromotion(ctx, edgeCall(inv), *value.(*HAPromotionPlanPayload)); if err != nil { return OperationResult{}, mapHAEdgeError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if approvals, ok := services.HAEdge.(HAPromotionApprovalEdgeService); ok {
			if err := registry.Bind("ha.promotion.approval.submit", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				result, err := approvals.ApprovePromotion(ctx, edgeCall(inv), *value.(*HAPromotionApprovalPayload)); if err != nil { return OperationResult{}, mapHAEdgeError(err) }
				return edgeOperationResult(http.StatusCreated, result), nil
			}); err != nil { return err }
		}
		if err := registry.Bind("ha.promotion.execute", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.HAEdge.ExecutePromotion(ctx, edgeCall(inv), *value.(*HAPromotionExecutePayload)); if err != nil { return OperationResult{}, mapHAEdgeError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
	}
	if services.MigrationEdge != nil {
		if discovery, ok := services.MigrationEdge.(MigrationProviderDiscoveryEdgeService); ok { if err := registry.Bind("migration.provider.list", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := discovery.ListMigrationProviders(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err } }
		capabilities := MigrationEdgeCapabilities{List:true,Inspect:true,Create:true,Cancel:true,Inventory:true,Plan:true,Sync:true,Cutover:true}
		if provider, ok := services.MigrationEdge.(MigrationEdgeCapabilityProvider); ok { capabilities=provider.MigrationCapabilities() }
		if capabilities.List { if err := registry.Bind("migration.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MigrationEdge.ListMigrations(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err } }
		if capabilities.Inspect { if err := registry.Bind("migration.inspect", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.MigrationEdge.InspectMigration(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result, Generation:result.Generation}, nil
		}); err != nil { return err } }
		if chunkGC, ok := services.MigrationEdge.(MigrationChunkGCEdgeService); ok {
			if err := registry.Bind("migration.chunk_gc.inspect", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				result, err := chunkGC.InspectMigrationChunkGC(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
				return OperationResult{Status:http.StatusOK, Value:result}, nil
			}); err != nil { return err }
			if err := registry.Bind("migration.chunk_gc.reconcile", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
				result, err := chunkGC.ReconcileMigrationChunkGC(ctx, edgeCall(inv), *value.(*MigrationChunkGCReconcilePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
				return edgeOperationResult(http.StatusOK, result), nil
			}); err != nil { return err }
		}
		if capabilities.Create { if err := registry.Bind("migration.create", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MigrationEdge.CreateMigration(ctx, edgeCall(inv), *value.(*MigrationCreatePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err } }
		if capabilities.Cancel { if err := registry.Bind("migration.cancel", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.MigrationEdge.CancelMigration(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err } }
		if capabilities.Inventory { if err := registry.Bind("migration.inventory", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MigrationEdge.Inventory(ctx, edgeCall(inv), *value.(*MigrationInventoryPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
		if capabilities.Plan { if err := registry.Bind("migration.plan", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MigrationEdge.Plan(ctx, edgeCall(inv), *value.(*MigrationPlanPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
		if capabilities.Sync { if err := registry.Bind("migration.sync", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MigrationEdge.Sync(ctx, edgeCall(inv), *value.(*MigrationSyncPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
		if capabilities.Cutover { if err := registry.Bind("migration.cutover", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.MigrationEdge.Cutover(ctx, edgeCall(inv), *value.(*MigrationCutoverPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
	}
	return bindConsoleEdgeContractsFour(registry, services)
}

func bindConsoleEdgeContractsFour(registry *Registry, services DomainServices) error {
	if services.IdentityEdge != nil {
		if err := registry.Bind("identity.membership.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.IdentityEdge.ListMemberships(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("identity.role_binding.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.IdentityEdge.ListRoleBindings(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("identity.entitlement.configure", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.IdentityEdge.ConfigureEntitlement(ctx, edgeCall(inv), *value.(*IdentityEntitlementPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
		if err := registry.Bind("identity.invitation.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.IdentityEdge.ListInvitations(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("identity.invitation.get", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.IdentityEdge.GetInvitation(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("identity.invitation.create", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.IdentityEdge.CreateInvitation(ctx, edgeCall(inv), *value.(*IdentityInvitationCreatePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("identity.invitation.resend", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.IdentityEdge.ResendInvitation(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
		if err := registry.Bind("identity.invitation.accept", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*IdentityInvitationAcceptPayload); token := []byte(payload.Token); payload.Token = ""; defer clearSecret(token)
			result, err := services.IdentityEdge.AcceptInvitation(ctx, edgeCall(inv), *payload, token); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
		if err := registry.Bind("identity.invitation.expire", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.IdentityEdge.ExpireInvitation(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
		if err := registry.Bind("identity.invitation.revoke", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.IdentityEdge.RevokeInvitation(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
	}
	if services.WebEngineEdge != nil {
		capabilities:=WebEngineEdgeCapabilities{List:true,License:true,Tuning:true,Upgrade:true,Remove:true,PHPProfile:true};if provider,ok:=services.WebEngineEdge.(WebEngineEdgeCapabilityProvider);ok{capabilities=provider.WebEngineCapabilities()}
		if capabilities.List { if err := registry.Bind("webengine.installation.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.WebEngineEdge.ListInstallations(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err } }
		if capabilities.License { if err := registry.Bind("webengine.license.configure", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*WebEngineLicensePayload); secret := []byte(payload.LicenseSecret); payload.LicenseSecret = ""; defer clearSecret(secret)
			result, err := services.WebEngineEdge.ConfigureLicense(ctx, edgeCall(inv), *payload, secret); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
		if capabilities.Tuning { if err := registry.Bind("webengine.tuning.configure", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.WebEngineEdge.ConfigureTuning(ctx, edgeCall(inv), *value.(*WebEngineTuningPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
		if capabilities.Upgrade { if err := registry.Bind("webengine.upgrade", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.WebEngineEdge.Upgrade(ctx, edgeCall(inv), *value.(*WebEngineUpgradePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err } }
		if capabilities.Remove { if err := registry.Bind("webengine.remove", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.WebEngineEdge.Remove(ctx, edgeCall(inv), *value.(*WebEngineRemovePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err } }
		if capabilities.PHPProfile { if err := registry.Bind("webengine.php_profile.create", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.WebEngineEdge.CreatePHPProfile(ctx, edgeCall(inv), *value.(*WebEnginePHPProfilePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err } }
	}
	if services.IntegrationEdge != nil {
		if err := registry.Bind("integration.binding.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.IntegrationEdge.ListBindings(ctx, edgeCall(inv), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
		if err := registry.Bind("integration.binding.create", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*IntegrationCreatePayload); secret := []byte(payload.Credential); payload.Credential = ""; defer clearSecret(secret)
			result, err := services.IntegrationEdge.CreateBinding(ctx, edgeCall(inv), *payload, secret); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusCreated, result), nil
		}); err != nil { return err }
		if err := registry.Bind("integration.binding.rotate", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			payload := value.(*IntegrationRotatePayload); secret := []byte(payload.Credential); payload.Credential = ""; defer clearSecret(secret)
			result, err := services.IntegrationEdge.RotateBinding(ctx, edgeCall(inv), *payload, secret); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
		if err := registry.Bind("integration.binding.health", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.IntegrationEdge.CheckBinding(ctx, edgeCall(inv), *value.(*IntegrationHealthPayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
		if err := registry.Bind("integration.binding.delete", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.IntegrationEdge.DeleteBinding(ctx, edgeCall(inv)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusOK, result), nil
		}); err != nil { return err }
	}
	return nil
}
