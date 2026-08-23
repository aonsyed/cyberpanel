package integrations

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type ExternalControllerOwnership struct {
	BindingID BindingID `json:"binding_id"`
	Subsystems []string `json:"subsystems"`
	ActionClasses []string `json:"action_classes"`
	AutonomousActions []string `json:"autonomous_actions"`
	DisabledPanelWriters []string `json:"disabled_panel_writers"`
	VendorControlEndpoints []EndpointPolicy `json:"vendor_control_endpoints"`
	CompromiseImpact string `json:"compromise_impact"`
	Generation uint64 `json:"generation"`
}

type ImunifyLicense struct { Kind string `json:"kind"`; SecretRef SecretRef `json:"secret_ref"`; MaskedIdentity string `json:"masked_identity"`; State string `json:"state"`; ExpiresAt time.Time `json:"expires_at,omitempty"`; LastValidatedAt time.Time `json:"last_validated_at"` }
type ImunifyStatus struct { Version string `json:"version"`; AgentHealthy bool `json:"agent_healthy"`; SignaturesVersion string `json:"signatures_version"`; SignaturesUpdatedAt time.Time `json:"signatures_updated_at"`; WAFOwnership bool `json:"waf_ownership"`; WebShield bool `json:"webshield"`; LicenseState string `json:"license_state"`; ObservedAt time.Time `json:"observed_at"` }
type ImunifySubject struct { TenantID TenantID `json:"tenant_id"`; SiteID string `json:"site_id"`; SiteUID uint32 `json:"site_uid"`; Domains []string `json:"domains"`; Generation uint64 `json:"generation"` }
type ImunifyScanRequest struct { EffectID EffectID `json:"effect_id"`; Subject ImunifySubject `json:"subject"`; Mode string `json:"mode"`; StableSnapshotRef string `json:"stable_snapshot_ref"`; BudgetRef string `json:"budget_ref"` }
type ImunifyFinding struct { ID string `json:"id"`; SiteID string `json:"site_id"`; RelativePath string `json:"relative_path"`; ContentDigest string `json:"content_digest"`; Signature string `json:"signature"`; Severity string `json:"severity"`; Confidence float64 `json:"confidence"`; EvidenceRef string `json:"evidence_ref"`; State string `json:"state"`; ObservedAt time.Time `json:"observed_at"` }
type ImunifyAction struct { EffectID EffectID `json:"effect_id"`; FindingID string `json:"finding_id"`; Action string `json:"action"`; ExpectedContentDigest string `json:"expected_content_digest"`; RecoveryPointRef string `json:"recovery_point_ref"`; Approved bool `json:"approved"` }
type ImunifyReceipt struct { EffectID EffectID `json:"effect_id"`; Action string `json:"action"`; ProviderObjectID string `json:"provider_object_id"`; OutputDigest string `json:"output_digest"`; CompletedAt time.Time `json:"completed_at"` }

type ImunifyProvider interface {
	Provider
	Install(context.Context, ProviderBinding, ExternalControllerOwnership, ImunifyLicense) (ImunifyReceipt, error)
	ValidateLicense(context.Context, ProviderBinding, ImunifyLicense) (ImunifyLicense, error)
	Status(context.Context, ProviderBinding) (ImunifyStatus, error)
	RegisterSubject(context.Context, ProviderBinding, ImunifySubject) (ImunifyReceipt, error)
	UnregisterSubject(context.Context, ProviderBinding, ImunifySubject) (ImunifyReceipt, error)
	StartScan(context.Context, ProviderBinding, ImunifyScanRequest) (ImunifyReceipt, error)
	ListFindings(context.Context, ProviderBinding, ImunifySubject, PageRequest) ([]ImunifyFinding, string, error)
	ApplyAction(context.Context, ProviderBinding, ImunifyAction) (ImunifyReceipt, error)
	RestoreQuarantine(context.Context, ProviderBinding, ImunifyAction) (ImunifyReceipt, error)
	SetWAFOwnership(context.Context, ProviderBinding, bool, EffectID) (ImunifyReceipt, error)
	Uninstall(context.Context, ProviderBinding, ExternalControllerOwnership, EffectID) (ImunifyReceipt, error)
}

type OCIReference struct { Registry string `json:"registry"`; Repository string `json:"repository"`; Tag string `json:"tag,omitempty"`; Digest string `json:"digest,omitempty"` }
func (reference OCIReference) Validate() error { if reference.Registry != "registry-1.docker.io" && reference.Registry != "docker.io" || !namePattern.MatchString(reference.Repository) || reference.Tag == "" && !validDigest(strings.TrimPrefix(reference.Digest, "sha256:")) { return ErrInvalid }; return nil }
type OCIManifest struct { Reference OCIReference `json:"reference"`; ResolvedDigest string `json:"resolved_digest"`; MediaType string `json:"media_type"`; Platforms []string `json:"platforms"`; Size int64 `json:"size"`; SignatureState string `json:"signature_state"`; SBOMRef string `json:"sbom_ref,omitempty"`; VulnerabilityRef string `json:"vulnerability_ref,omitempty"`; ObservedAt time.Time `json:"observed_at"` }
type DockerHubProvider interface { Provider; Search(context.Context, ProviderBinding, string, PageRequest) ([]OCIReference, string, error); ListTags(context.Context, ProviderBinding, string, PageRequest) ([]string, string, error); Resolve(context.Context, ProviderBinding, OCIReference) (OCIManifest, error); AuthorizePull(context.Context, ProviderBinding, OCIManifest, string, time.Time) (string, error) }

type NotificationSeverity string
const ( NotifyInfo NotificationSeverity = "info"; NotifyWarning NotificationSeverity = "warning"; NotifyError NotificationSeverity = "error"; NotifyCritical NotificationSeverity = "critical" )
type Notification struct { ID ID `json:"id"`; TenantID TenantID `json:"tenant_id,omitempty"`; Kind string `json:"kind"`; Severity NotificationSeverity `json:"severity"`; Subject string `json:"subject"`; TemplateID string `json:"template_id"`; TemplateVersion uint32 `json:"template_version"`; DataRef string `json:"data_ref"`; DataDigest string `json:"data_digest"`; DedupeKey string `json:"dedupe_key"`; OccurredAt time.Time `json:"occurred_at"`; ExpiresAt time.Time `json:"expires_at,omitempty"` }
func (notification Notification) Validate() error { if !validID(string(notification.ID)) || notification.TenantID != "" && !validID(string(notification.TenantID)) || notification.Kind == "" || notification.Subject == "" || !validID(notification.TemplateID) || notification.TemplateVersion == 0 || !validDigest(notification.DataDigest) || !validID(notification.DedupeKey) || notification.OccurredAt.IsZero() { return ErrInvalid }; return nil }

type NotificationRoute struct { ID ID `json:"id"`; BindingID BindingID `json:"binding_id"`; MinimumSeverity NotificationSeverity `json:"minimum_severity"`; Kinds []string `json:"kinds,omitempty"`; RecipientRefs []string `json:"recipient_refs"`; QuietStart string `json:"quiet_start,omitempty"`; QuietEnd string `json:"quiet_end,omitempty"`; Timezone string `json:"timezone,omitempty"`; RatePerHour uint32 `json:"rate_per_hour"`; Enabled bool `json:"enabled"`; Generation uint64 `json:"generation"` }
type NotificationAttemptState string
const ( AttemptPending NotificationAttemptState = "pending"; AttemptDelivering NotificationAttemptState = "delivering"; AttemptDelivered NotificationAttemptState = "delivered"; AttemptRetry NotificationAttemptState = "retry"; AttemptFailed NotificationAttemptState = "failed"; AttemptExpired NotificationAttemptState = "expired" )
type NotificationAttempt struct { ID DeliveryID `json:"id"`; NotificationID ID `json:"notification_id"`; RouteID ID `json:"route_id"`; BindingID BindingID `json:"binding_id"`; Attempt uint32 `json:"attempt"`; IdempotencyKey string `json:"idempotency_key"`; State NotificationAttemptState `json:"state"`; NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`; ProviderReceipt string `json:"provider_receipt,omitempty"`; Failure string `json:"failure,omitempty"`; CreatedAt time.Time `json:"created_at"`; UpdatedAt time.Time `json:"updated_at"` }

type SMTPNotificationTarget struct { From string `json:"from"`; Recipients []string `json:"recipients"`; Host string `json:"host"`; Port uint16 `json:"port"`; ServerName string `json:"server_name"`; TLS RelayTLSMode `json:"tls"` }
type WebhookNotificationTarget struct { Endpoint EndpointPolicy `json:"endpoint"`; Audience string `json:"audience"`; SigningKeyRef SecretRef `json:"signing_key_ref"`; SigningAlgorithm string `json:"signing_algorithm"`; KeyVersion uint64 `json:"key_version"` }
type NotificationEnvelope struct { DeliveryID DeliveryID `json:"delivery_id"`; Notification Notification `json:"notification"`; Audience string `json:"audience"`; IssuedAt time.Time `json:"issued_at"`; ExpiresAt time.Time `json:"expires_at"`; BodyDigest string `json:"body_digest"`; Signature string `json:"signature"`; SigningKeyID string `json:"signing_key_id"`; SigningKeyVersion uint64 `json:"signing_key_version"` }
type NotificationReceipt struct { DeliveryID DeliveryID `json:"delivery_id"`; ProviderReceipt string `json:"provider_receipt"`; ReceiptDigest string `json:"receipt_digest"`; DeliveredAt time.Time `json:"delivered_at"` }
type NotificationProvider interface { Provider; DeliverSMTP(context.Context, ProviderBinding, SMTPNotificationTarget, NotificationEnvelope) (NotificationReceipt, error); DeliverWebhook(context.Context, ProviderBinding, WebhookNotificationTarget, NotificationEnvelope) (NotificationReceipt, error) }

type NotificationSigner interface { SignNotification(context.Context, SecretRef, uint64, []byte) (string, string, error) }

func ValidateExternalOwnership(ownership ExternalControllerOwnership) error {
	if !validID(string(ownership.BindingID)) || ownership.Generation == 0 || len(ownership.Subsystems) == 0 || len(ownership.ActionClasses) == 0 || ownership.CompromiseImpact != "host_compromise" { return ErrInvalid }
	seen := map[string]bool{}; for _, subsystem := range ownership.Subsystems { if !namePattern.MatchString(subsystem) || seen[subsystem] { return ErrInvalid }; seen[subsystem] = true }
	for _, endpoint := range ownership.VendorControlEndpoints { if err := endpoint.Validate(); err != nil { return err } }
	return nil
}

func ValidateImunifyAction(action ImunifyAction) error { if !validID(string(action.EffectID)) || !validID(action.FindingID) || !validDigest(action.ExpectedContentDigest) || action.RecoveryPointRef == "" || !action.Approved { return ErrPolicyDenied }; switch action.Action { case "quarantine", "cleanup", "restore", "ignore_exact": return nil; default: return fmt.Errorf("%w: Imunify action", ErrUnsupported) } }
