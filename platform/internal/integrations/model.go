// Package integrations owns external provider bindings and normalized provider
// effects. It stores secret references only and exposes closed, versioned
// provider contracts rather than arbitrary HTTP or command execution.
package integrations

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid = errors.New("invalid integration resource")
	ErrNotFound = errors.New("integration resource not found")
	ErrConflict = errors.New("integration conflict")
	ErrStaleGeneration = errors.New("stale integration generation")
	ErrUnavailable = errors.New("integration provider unavailable")
	ErrUnauthorized = errors.New("integration credential rejected")
	ErrRateLimited = errors.New("integration rate limited")
	ErrPartial = errors.New("integration effect partially applied")
	ErrAmbiguous = errors.New("integration effect is ambiguous")
	ErrUnsupported = errors.New("integration capability unsupported")
	ErrIntegrity = errors.New("integration receipt integrity failure")
	ErrPolicyDenied = errors.New("integration policy denied")
)

type ID string
type TenantID string
type BindingID string
type SecretRef string
type EffectID string
type CommandID string
type DeliveryID string

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,191}$`)

func validID(value string) bool { return idPattern.MatchString(value) }
func requireID(kind, value string) error { if !validID(value) { return fmt.Errorf("%w: %s identifier", ErrInvalid, kind) }; return nil }
func validDigest(value string) bool { if len(value) != sha256.Size*2 { return false }; _, err := hex.DecodeString(value); return err == nil && strings.ToLower(value) == value }

type ProviderKind string

const (
	ProviderCloudflare ProviderKind = "cloudflare"
	ProviderAWSS3 ProviderKind = "aws_s3"
	ProviderWasabi ProviderKind = "wasabi_s3"
	ProviderBackblaze ProviderKind = "backblaze_b2_s3"
	ProviderDigitalOcean ProviderKind = "digitalocean_spaces"
	ProviderMinIO ProviderKind = "minio"
	ProviderGenericS3 ProviderKind = "generic_s3"
	ProviderGoogleDrive ProviderKind = "google_drive"
	ProviderSFTP ProviderKind = "sftp"
	ProviderExternalMail ProviderKind = "external_mail_relay"
	ProviderImunify ProviderKind = "imunify"
	ProviderDockerHub ProviderKind = "docker_hub"
	ProviderNotificationSMTP ProviderKind = "notification_smtp"
	ProviderNotificationWebhook ProviderKind = "notification_webhook"
)

func (kind ProviderKind) Valid() bool {
	switch kind {
	case ProviderCloudflare, ProviderAWSS3, ProviderWasabi, ProviderBackblaze, ProviderDigitalOcean, ProviderMinIO, ProviderGenericS3, ProviderGoogleDrive, ProviderSFTP, ProviderExternalMail, ProviderImunify, ProviderDockerHub, ProviderNotificationSMTP, ProviderNotificationWebhook:
		return true
	default: return false
	}
}

type Capability string

const (
	CapabilityHealth Capability = "health"
	CapabilityRotateCredential Capability = "credential.rotate"
	CapabilityDNSZones Capability = "dns.zones"
	CapabilityDNSRRsets Capability = "dns.rrsets"
	CapabilityDNSProxy Capability = "dns.proxy"
	CapabilityDNSChallenge Capability = "dns.acme_challenge"
	CapabilityAtomicCAS Capability = "concurrency.atomic_cas"
	CapabilityObserveApply Capability = "concurrency.observe_apply"
	CapabilityObjectList Capability = "object.list"
	CapabilityObjectMultipart Capability = "object.multipart"
	CapabilityObjectResume Capability = "object.resume"
	CapabilityObjectLock Capability = "object.lock"
	CapabilityObjectVersioning Capability = "object.versioning"
	CapabilityObjectChecksum Capability = "object.checksum"
	CapabilityMailRelay Capability = "mail.relay"
	CapabilityMailEvents Capability = "mail.events"
	CapabilitySecurityScan Capability = "security.scan"
	CapabilitySecurityQuarantine Capability = "security.quarantine"
	CapabilitySecurityRemediate Capability = "security.remediate"
	CapabilitySecurityWAF Capability = "security.waf"
	CapabilityOCIResolve Capability = "oci.resolve_digest"
	CapabilityOCIPull Capability = "oci.pull"
	CapabilityOCISignature Capability = "oci.signature"
	CapabilityOCISBOM Capability = "oci.sbom"
	CapabilityOCIVulnerability Capability = "oci.vulnerability"
	CapabilityNotify Capability = "notification.deliver"
)

type CapabilitySet struct {
	SchemaVersion uint32 `json:"schema_version"`
	ProviderVersion string `json:"provider_version"`
	Capabilities []Capability `json:"capabilities"`
	DiscoveredAt time.Time `json:"discovered_at"`
	Digest string `json:"digest"`
}

func (set CapabilitySet) Has(capability Capability) bool { for _, current := range set.Capabilities { if current == capability { return true } }; return false }

func (set CapabilitySet) Validate() error {
	if set.SchemaVersion == 0 || set.ProviderVersion == "" || set.DiscoveredAt.IsZero() || !validDigest(set.Digest) { return fmt.Errorf("%w: capability set", ErrInvalid) }
	seen := map[Capability]struct{}{}
	for _, capability := range set.Capabilities { if capability == "" { return ErrInvalid }; if _, exists := seen[capability]; exists { return ErrInvalid }; seen[capability] = struct{}{} }
	return nil
}

type BindingState string

const (
	BindingPending BindingState = "pending"
	BindingActive BindingState = "active"
	BindingSuspended BindingState = "suspended"
	BindingDegraded BindingState = "degraded"
	BindingRevoked BindingState = "revoked"
	BindingDeleting BindingState = "deleting"
	BindingDeleted BindingState = "deleted"
)

type EndpointPolicy struct {
	URL string `json:"url"`
	ServerName string `json:"server_name"`
	PinnedCARef string `json:"pinned_ca_ref,omitempty"`
	PinnedPublicKey string `json:"pinned_public_key,omitempty"`
	AllowPublicInternet bool `json:"allow_public_internet"`
	DenyPrivateRanges bool `json:"deny_private_ranges"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
	MaximumRedirects uint8 `json:"maximum_redirects"`
}

func (policy EndpointPolicy) Validate() error {
	parsed, err := url.Parse(policy.URL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || policy.MaximumRedirects > 2 { return fmt.Errorf("%w: endpoint", ErrInvalid) }
	switch parsed.Scheme { case "https": if policy.ServerName==""{return ErrInvalid};case "sftp": if policy.ServerName==""||policy.PinnedPublicKey==""||policy.MaximumRedirects!=0{return ErrPolicyDenied};case "smtp+tls": if policy.ServerName==""||policy.MaximumRedirects!=0{return ErrInvalid};case "local": if parsed.Host!="imunify"||policy.ServerName!="imunify"||policy.AllowPublicInternet||len(policy.AllowedCIDRs)>0||policy.MaximumRedirects!=0{return ErrPolicyDenied};return nil;default:return fmt.Errorf("%w: endpoint scheme",ErrInvalid) }
	if !policy.AllowPublicInternet&&len(policy.AllowedCIDRs)==0{return ErrPolicyDenied}
	if policy.AllowPublicInternet&&!policy.DenyPrivateRanges{return ErrPolicyDenied}
	if net.ParseIP(parsed.Hostname()) != nil && len(policy.AllowedCIDRs) == 0 { return ErrPolicyDenied }
	for _, raw := range policy.AllowedCIDRs { _, network, err := net.ParseCIDR(raw); if err != nil || network.String() != raw { return ErrInvalid } }
	return nil
}

type CredentialPurpose string

const (
	PurposeDNS CredentialPurpose = "dns"
	PurposeBackup CredentialPurpose = "backup"
	PurposeMailRelay CredentialPurpose = "mail_relay"
	PurposeSecurity CredentialPurpose = "security"
	PurposeRegistry CredentialPurpose = "registry"
	PurposeNotification CredentialPurpose = "notification"
)

type ProviderBinding struct {
	ID BindingID `json:"id"`
	TenantID TenantID `json:"tenant_id,omitempty"`
	Kind ProviderKind `json:"kind"`
	DisplayName string `json:"display_name"`
	Purpose CredentialPurpose `json:"purpose"`
	SecretRef SecretRef `json:"secret_ref"`
	SecretVersion uint64 `json:"secret_version"`
	SecretBindingDigest string `json:"secret_binding_digest"`
	Endpoint EndpointPolicy `json:"endpoint"`
	Capabilities CapabilitySet `json:"capabilities"`
	State BindingState `json:"state"`
	Generation uint64 `json:"generation"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (binding ProviderBinding) Validate() error {
	if err := requireID("binding", string(binding.ID)); err != nil { return err }
	if binding.TenantID != "" { if err := requireID("tenant", string(binding.TenantID)); err != nil { return err } }
	if !binding.Kind.Valid() || strings.TrimSpace(binding.DisplayName) == "" || !validID(string(binding.SecretRef)) || binding.SecretVersion == 0 || !validDigest(binding.SecretBindingDigest) || binding.Generation == 0 || binding.CreatedAt.IsZero() || binding.UpdatedAt.IsZero() { return fmt.Errorf("%w: provider binding", ErrInvalid) }
	if err := binding.Endpoint.Validate(); err != nil { return err }
	if err := binding.Capabilities.Validate(); err != nil { return err }
	switch binding.State { case BindingPending, BindingActive, BindingSuspended, BindingDegraded, BindingRevoked, BindingDeleting, BindingDeleted: default: return ErrInvalid }
	return nil
}

type HealthState string
const ( HealthUnknown HealthState = "unknown"; HealthHealthy HealthState = "healthy"; HealthDegraded HealthState = "degraded"; HealthUnavailable HealthState = "unavailable" )

type ProviderHealth struct {
	BindingID BindingID `json:"binding_id"`
	State HealthState `json:"state"`
	Latency time.Duration `json:"latency"`
	CredentialValid bool `json:"credential_valid"`
	CapabilitiesDigest string `json:"capabilities_digest"`
	RateLimitRemaining int64 `json:"rate_limit_remaining"`
	RateLimitReset time.Time `json:"rate_limit_reset,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	StaleAfter time.Time `json:"stale_after"`
	Reason string `json:"reason,omitempty"`
}

type ErrorClass string
const ( ErrorInvalid ErrorClass = "invalid"; ErrorUnauthorized ErrorClass = "unauthorized"; ErrorRateLimited ErrorClass = "rate_limited"; ErrorUnavailable ErrorClass = "unavailable"; ErrorConflict ErrorClass = "conflict"; ErrorPartial ErrorClass = "partial"; ErrorAmbiguous ErrorClass = "ambiguous"; ErrorPermanent ErrorClass = "permanent" )

type ProviderError struct {
	Class ErrorClass
	Operation string
	Code string
	RetryAfter time.Duration
	PartialReceipt string
	Cause error
}

func (providerError *ProviderError) Error() string { return fmt.Sprintf("provider %s failed (%s/%s)", providerError.Operation, providerError.Class, providerError.Code) }
func (providerError *ProviderError) Unwrap() error { return providerError.Cause }

type EffectState string
const ( EffectAdmitted EffectState = "admitted"; EffectApplying EffectState = "applying"; EffectObserving EffectState = "observing"; EffectCommitted EffectState = "committed"; EffectConflict EffectState = "conflict"; EffectPartial EffectState = "partial"; EffectAmbiguous EffectState = "ambiguous"; EffectCompensating EffectState = "compensating"; EffectCompensated EffectState = "compensated"; EffectFailed EffectState = "failed" )

type ProviderEffect struct {
	ID EffectID `json:"id"`
	CommandID CommandID `json:"command_id"`
	BindingID BindingID `json:"binding_id"`
	Kind string `json:"kind"`
	Resource string `json:"resource"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestDigest string `json:"request_digest"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
	BeforeDigest string `json:"before_digest,omitempty"`
	OutputDigest string `json:"output_digest,omitempty"`
	ObservedDigest string `json:"observed_digest,omitempty"`
	ProviderReceipt string `json:"provider_receipt,omitempty"`
	State EffectState `json:"state"`
	Attempt uint32 `json:"attempt"`
	Failure string `json:"failure,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (effect ProviderEffect) Validate() error {
	if err := requireID("effect", string(effect.ID)); err != nil { return err }; if err := requireID("command", string(effect.CommandID)); err != nil { return err }; if err := requireID("binding", string(effect.BindingID)); err != nil { return err }
	if effect.Kind == "" || effect.Resource == "" || !validID(effect.IdempotencyKey) || !validDigest(effect.RequestDigest) || effect.State == "" || effect.CreatedAt.IsZero() || effect.UpdatedAt.IsZero() { return ErrInvalid }
	return nil
}

func capabilityDigest(capabilities []Capability) string {
	values := append([]Capability(nil), capabilities...); sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	digest := sha256.Sum256([]byte(strings.Join(func() []string { result := make([]string, len(values)); for index := range values { result[index] = string(values[index]) }; return result }(), "\n")))
	return hex.EncodeToString(digest[:])
}
