// Package maildelivery owns provider-neutral outbound-delivery policy and the
// hardened local SMTP relay boundary. It never stores reusable credentials or
// raw message content in its authority repository.
package maildelivery

import (
	"context"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid         = errors.New("maildelivery: invalid value")
	ErrNotFound        = errors.New("maildelivery: not found")
	ErrConflict        = errors.New("maildelivery: conflict")
	ErrStale           = errors.New("maildelivery: stale generation")
	ErrDenied          = errors.New("maildelivery: denied")
	ErrUnavailable     = errors.New("maildelivery: unavailable")
	ErrAmbiguous       = errors.New("maildelivery: submission outcome ambiguous")
	ErrBackpressure    = errors.New("maildelivery: backpressure")
	ErrSuppressed      = errors.New("maildelivery: recipient suppressed")
	ErrWebhookRejected = errors.New("maildelivery: webhook rejected")
)

const (
	AdapterContractVersion = 1
	MaximumWebhookBodyBytes = 512 << 10
	MaximumMessageBytes     = 64 << 20
	MaximumRecipients       = 100
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type BindingID string
type TenantID string
type DomainID string
type CampaignID string
type MessageID string
type QueueID string
type PlanID string
type RotationID string
type DeliveryID string
type ActorID string

func validID(value string) bool { return identifierPattern.MatchString(value) }
func validDigest(value string) bool { return sha256Pattern.MatchString(value) }

type ProviderAdapterRef struct {
	Kind            string `json:"kind"`
	ContractVersion uint32 `json:"contract_version"`
	AdapterVersion  string `json:"adapter_version"`
}

func (reference ProviderAdapterRef) Validate() error {
	kind := strings.ToLower(reference.Kind)
	if !validID(reference.Kind) || reference.ContractVersion != AdapterContractVersion || !validID(reference.AdapterVersion) ||
		kind == "mock" || kind == "noop" || kind == "placeholder" || strings.Contains(kind, "mock") || strings.Contains(kind, "no-op") {
		return ErrInvalid
	}
	return nil
}

type EncryptedCredentialReference struct {
	Reference               string `json:"reference"`
	Version                 uint64 `json:"version"`
	EncryptionContextDigest string `json:"encryption_context_digest"`
	Purpose                 string `json:"purpose"`
}

func (reference EncryptedCredentialReference) Validate() error {
	if !validID(reference.Reference) || reference.Version == 0 || !validDigest(reference.EncryptionContextDigest) ||
		(reference.Purpose != "maildelivery_provider" && reference.Purpose != "maildelivery_smtp_auth") {
		return ErrInvalid
	}
	return nil
}

type BindingLifecycle string

const (
	BindingDisabled           BindingLifecycle = "disabled"
	BindingPendingVerification BindingLifecycle = "pending_verification"
	BindingEnabled            BindingLifecycle = "enabled"
	BindingRotating           BindingLifecycle = "rotating"
	BindingRevoked            BindingLifecycle = "revoked"
)

type VerificationState string

const (
	VerificationPending  VerificationState = "pending"
	VerificationVerified VerificationState = "verified"
	VerificationDrifted  VerificationState = "drifted"
	VerificationFailed   VerificationState = "failed"
)

type DNSRecordKind string

const (
	DNSRecordSPF        DNSRecordKind = "spf"
	DNSRecordDKIM       DNSRecordKind = "dkim"
	DNSRecordReturnPath DNSRecordKind = "return_path"
	DNSRecordTracking   DNSRecordKind = "tracking"
	DNSRecordProvider   DNSRecordKind = "provider"
)

type DNSRecordPlan struct {
	Kind     DNSRecordKind `json:"kind"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Required bool `json:"required"`
}

func (record DNSRecordPlan) Validate() error {
	if record.Kind != DNSRecordSPF && record.Kind != DNSRecordDKIM && record.Kind != DNSRecordReturnPath &&
		record.Kind != DNSRecordTracking && record.Kind != DNSRecordProvider {
		return ErrInvalid
	}
	if len(record.Name) == 0 || len(record.Name) > 253 || len(record.Type) == 0 || len(record.Type) > 16 ||
		len(record.Value) == 0 || len(record.Value) > 4096 || strings.ContainsAny(record.Name+record.Type+record.Value, "\x00\r\n") {
		return ErrInvalid
	}
	return nil
}

type DNSPlan struct {
	ID             PlanID `json:"id"`
	BindingID      BindingID `json:"binding_id"`
	BindingGeneration uint64 `json:"binding_generation"`
	TenantID       TenantID `json:"tenant_id"`
	DomainID       DomainID `json:"domain_id"`
	Domain         string `json:"domain"`
	Revision       uint64 `json:"revision"`
	ProviderVersion string `json:"provider_version"`
	Records        []DNSRecordPlan `json:"records"`
	State          VerificationState `json:"state"`
	EvidenceDigest string `json:"evidence_digest,omitempty"`
	ObservedAt     time.Time `json:"observed_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func (plan DNSPlan) Validate() error {
	if !validID(string(plan.ID)) || !validID(string(plan.BindingID)) || !validID(string(plan.TenantID)) ||
		!validID(string(plan.DomainID)) || plan.BindingGeneration == 0 || !validHostname(plan.Domain) || plan.Revision == 0 || !validID(plan.ProviderVersion) ||
		len(plan.Records) == 0 || len(plan.Records) > 64 || plan.CreatedAt.IsZero() {
		return ErrInvalid
	}
	if plan.State != VerificationPending && plan.State != VerificationVerified && plan.State != VerificationDrifted && plan.State != VerificationFailed {
		return ErrInvalid
	}
	if plan.State == VerificationVerified && (plan.ObservedAt.IsZero() || !validDigest(plan.EvidenceDigest)) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(plan.Records))
	required := map[DNSRecordKind]bool{DNSRecordSPF: false, DNSRecordDKIM: false, DNSRecordReturnPath: false, DNSRecordTracking: false}
	for _, record := range plan.Records {
		if record.Validate() != nil {
			return ErrInvalid
		}
		key := string(record.Kind) + "\x00" + record.Name + "\x00" + record.Type
		if _, exists := seen[key]; exists {
			return ErrInvalid
		}
		seen[key] = struct{}{}
		if record.Required {
			required[record.Kind] = true
		}
	}
	if !required[DNSRecordSPF] || !required[DNSRecordDKIM] || !required[DNSRecordReturnPath] || !required[DNSRecordTracking] {
		return ErrInvalid
	}
	return nil
}

type SendingDomain struct {
	ID                 DomainID `json:"id"`
	Name               string `json:"name"`
	ActiveDNSPlanID    PlanID `json:"active_dns_plan_id"`
	Verification       VerificationState `json:"verification"`
	VerifiedAt         time.Time `json:"verified_at,omitempty"`
	LastCheckedAt      time.Time `json:"last_checked_at"`
	VerificationDigest string `json:"verification_digest,omitempty"`
}

func (domain SendingDomain) Validate() error {
	if !validID(string(domain.ID)) || !validHostname(domain.Name) || !validID(string(domain.ActiveDNSPlanID)) || domain.LastCheckedAt.IsZero() {
		return ErrInvalid
	}
	if domain.Verification != VerificationPending && domain.Verification != VerificationVerified &&
		domain.Verification != VerificationDrifted && domain.Verification != VerificationFailed {
		return ErrInvalid
	}
	if domain.Verification == VerificationVerified && (domain.VerifiedAt.IsZero() || !validDigest(domain.VerificationDigest)) {
		return ErrInvalid
	}
	return nil
}

func validHostname(value string) bool {
	if value != strings.ToLower(strings.TrimSuffix(value, ".")) || !hostnamePattern.MatchString(value) || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

type MailStream string

const (
	StreamTransactional MailStream = "transactional"
	StreamCampaign      MailStream = "campaign"
)

type RouteTarget string

const (
	RouteLocal    RouteTarget = "local"
	RouteExternal RouteTarget = "external"
	RouteReject   RouteTarget = "reject"
)

type FallbackPolicy string

const (
	FallbackNone     FallbackPolicy = "none"
	FallbackToLocal  FallbackPolicy = "to_local"
	FallbackExternal FallbackPolicy = "to_external"
)

type RouteRule struct {
	DomainID  DomainID `json:"domain_id,omitempty"`
	Stream    MailStream `json:"stream"`
	CampaignID CampaignID `json:"campaign_id,omitempty"`
	Primary   RouteTarget `json:"primary"`
	Fallback  FallbackPolicy `json:"fallback"`
}

func (rule RouteRule) Validate() error {
	if rule.DomainID != "" && !validID(string(rule.DomainID)) || rule.CampaignID != "" && !validID(string(rule.CampaignID)) {
		return ErrInvalid
	}
	if rule.Stream != StreamTransactional && rule.Stream != StreamCampaign || rule.CampaignID != "" && rule.Stream != StreamCampaign {
		return ErrInvalid
	}
	if rule.Primary != RouteLocal && rule.Primary != RouteExternal && rule.Primary != RouteReject {
		return ErrInvalid
	}
	if rule.Fallback != FallbackNone && rule.Fallback != FallbackToLocal && rule.Fallback != FallbackExternal {
		return ErrInvalid
	}
	if rule.Primary == RouteLocal && rule.Fallback == FallbackToLocal || rule.Primary == RouteExternal && rule.Fallback == FallbackExternal ||
		rule.Primary == RouteReject && rule.Fallback != FallbackNone {
		return ErrInvalid
	}
	return nil
}

type RateRetryPolicy struct {
	MessagesPerMinute uint32 `json:"messages_per_minute"`
	Burst             uint32 `json:"burst"`
	MaximumAttempts   uint16 `json:"maximum_attempts"`
	InitialBackoff    time.Duration `json:"initial_backoff"`
	MaximumBackoff    time.Duration `json:"maximum_backoff"`
	QueueLimit        uint32 `json:"queue_limit"`
	QueueRetention    time.Duration `json:"queue_retention"`
}

func (policy RateRetryPolicy) Validate() error {
	if policy.MessagesPerMinute == 0 || policy.MessagesPerMinute > 1000000 || policy.Burst == 0 || policy.Burst > policy.MessagesPerMinute ||
		policy.MaximumAttempts == 0 || policy.MaximumAttempts > 32 || policy.InitialBackoff < time.Second ||
		policy.MaximumBackoff < policy.InitialBackoff || policy.MaximumBackoff > 48*time.Hour || policy.QueueLimit == 0 ||
		policy.QueueLimit > 1000000 || policy.QueueRetention < time.Minute || policy.QueueRetention > 30*24*time.Hour {
		return ErrInvalid
	}
	return nil
}

type SuppressionPolicy struct {
	HardBounceThreshold uint16 `json:"hard_bounce_threshold"`
	ComplaintThreshold  uint16 `json:"complaint_threshold"`
	HonorGlobal         bool `json:"honor_global"`
	HonorTenant         bool `json:"honor_tenant"`
	RecheckBeforeSend   bool `json:"recheck_before_send"`
}

func (policy SuppressionPolicy) Validate() error {
	if policy.HardBounceThreshold == 0 || policy.HardBounceThreshold > 10 || policy.ComplaintThreshold == 0 ||
		policy.ComplaintThreshold > 10 || !policy.HonorGlobal || !policy.HonorTenant || !policy.RecheckBeforeSend {
		return ErrInvalid
	}
	return nil
}

type DeliveryPolicy struct {
	Transactional       RateRetryPolicy `json:"transactional"`
	Campaign            RateRetryPolicy `json:"campaign"`
	Suppression         SuppressionPolicy `json:"suppression"`
	TransactionalReserve uint32 `json:"transactional_reserve"`
	CircuitFailures     uint16 `json:"circuit_failures"`
	CircuitOpenFor      time.Duration `json:"circuit_open_for"`
	HalfOpenProbes      uint16 `json:"half_open_probes"`
}

func (policy DeliveryPolicy) Validate() error {
	if policy.Transactional.Validate() != nil || policy.Campaign.Validate() != nil || policy.Suppression.Validate() != nil ||
		policy.TransactionalReserve == 0 || policy.TransactionalReserve >= policy.Transactional.QueueLimit || policy.CircuitFailures == 0 ||
		policy.CircuitFailures > 100 || policy.CircuitOpenFor < time.Second || policy.CircuitOpenFor > 24*time.Hour ||
		policy.HalfOpenProbes == 0 || policy.HalfOpenProbes > 32 {
		return ErrInvalid
	}
	return nil
}

type ProviderHealth string

const (
	ProviderHealthy     ProviderHealth = "healthy"
	ProviderDegraded    ProviderHealth = "degraded"
	ProviderUnavailable ProviderHealth = "unavailable"
	ProviderUnknown     ProviderHealth = "unknown"
)

type ProviderObservation struct {
	Health          ProviderHealth `json:"health"`
	CredentialState string `json:"credential_state"`
	QuotaLimit      uint64 `json:"quota_limit,omitempty"`
	QuotaUsed       uint64 `json:"quota_used,omitempty"`
	RateLimit       uint64 `json:"rate_limit,omitempty"`
	RateRemaining   uint64 `json:"rate_remaining,omitempty"`
	RateResetsAt    time.Time `json:"rate_resets_at,omitempty"`
	UsageCount      uint64 `json:"usage_count,omitempty"`
	CostMicrounits  uint64 `json:"cost_microunits,omitempty"`
	Currency        string `json:"currency,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
	StaleAfter      time.Time `json:"stale_after"`
	EvidenceDigest  string `json:"evidence_digest"`
}

func (observation ProviderObservation) Validate() error {
	if observation.Health != ProviderHealthy && observation.Health != ProviderDegraded && observation.Health != ProviderUnavailable && observation.Health != ProviderUnknown {
		return ErrInvalid
	}
	if observation.CredentialState == "" || len(observation.CredentialState) > 64 || observation.ObservedAt.IsZero() ||
		!observation.StaleAfter.After(observation.ObservedAt) || !validDigest(observation.EvidenceDigest) ||
		observation.QuotaLimit != 0 && observation.QuotaUsed > observation.QuotaLimit ||
		observation.RateLimit != 0 && observation.RateRemaining > observation.RateLimit ||
		observation.RateLimit == 0 && !observation.RateResetsAt.IsZero() || observation.RateLimit != 0 && observation.RateResetsAt.IsZero() ||
		observation.CostMicrounits != 0 && len(observation.Currency) != 3 || len(observation.Currency) > 3 {
		return ErrInvalid
	}
	return nil
}

type SecretPortability string

const (
	SecretPortable       SecretPortability = "portable_protected_reference"
	SecretReauthorization SecretPortability = "reauthorization_required"
)

type BackupSemantics struct {
	Portability SecretPortability `json:"portability"`
	ProtectedReferenceIncluded bool `json:"protected_reference_included"`
	ReauthorizeOnRestore bool `json:"reauthorize_on_restore"`
}

func (semantics BackupSemantics) Validate() error {
	if semantics.Portability == SecretPortable {
		if !semantics.ProtectedReferenceIncluded || semantics.ReauthorizeOnRestore {
			return ErrInvalid
		}
		return nil
	}
	if semantics.Portability != SecretReauthorization || semantics.ProtectedReferenceIncluded || !semantics.ReauthorizeOnRestore {
		return ErrInvalid
	}
	return nil
}

type ProviderBinding struct {
	ID             BindingID `json:"id"`
	TenantID       TenantID `json:"tenant_id"`
	Generation     uint64 `json:"generation"`
	Adapter        ProviderAdapterRef `json:"adapter"`
	Credential     EncryptedCredentialReference `json:"credential"`
	Lifecycle      BindingLifecycle `json:"lifecycle"`
	Domains        []SendingDomain `json:"domains"`
	Routes         []RouteRule `json:"routes"`
	Policy         DeliveryPolicy `json:"policy"`
	Observation    ProviderObservation `json:"observation"`
	Backup         BackupSemantics `json:"backup"`
	ConsentRevision uint64 `json:"consent_revision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (binding ProviderBinding) Validate() error {
	if !validID(string(binding.ID)) || !validID(string(binding.TenantID)) || binding.Generation == 0 ||
		binding.Adapter.Validate() != nil || binding.Credential.Validate() != nil || binding.Policy.Validate() != nil ||
		binding.Observation.Validate() != nil || binding.Backup.Validate() != nil || binding.ConsentRevision == 0 ||
		binding.CreatedAt.IsZero() || binding.UpdatedAt.Before(binding.CreatedAt) || len(binding.Domains) == 0 || len(binding.Domains) > 1000 ||
		len(binding.Routes) == 0 || len(binding.Routes) > 10000 {
		return ErrInvalid
	}
	if binding.Lifecycle != BindingDisabled && binding.Lifecycle != BindingPendingVerification && binding.Lifecycle != BindingEnabled &&
		binding.Lifecycle != BindingRotating && binding.Lifecycle != BindingRevoked {
		return ErrInvalid
	}
	domains := make(map[DomainID]struct{}, len(binding.Domains))
	for _, domain := range binding.Domains {
		if domain.Validate() != nil {
			return ErrInvalid
		}
		if _, exists := domains[domain.ID]; exists {
			return ErrInvalid
		}
		domains[domain.ID] = struct{}{}
	}
	keys := make([]string, 0, len(binding.Routes))
	for _, rule := range binding.Routes {
		if rule.Validate() != nil {
			return ErrInvalid
		}
		if rule.DomainID != "" {
			if _, exists := domains[rule.DomainID]; !exists {
				return ErrInvalid
			}
		}
		keys = append(keys, string(rule.DomainID)+"\x00"+string(rule.Stream)+"\x00"+string(rule.CampaignID))
	}
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	for index := range sorted {
		if sorted[index] != keys[index] || index > 0 && sorted[index] == sorted[index-1] {
			return ErrInvalid
		}
	}
	return nil
}

type RotationState string

const (
	RotationPrepared RotationState = "prepared"
	RotationOverlapping RotationState = "overlapping"
	RotationReloaded RotationState = "dependents_reloaded"
	RotationRevoked RotationState = "old_revoked"
	RotationFailed RotationState = "failed"
)

type CredentialRotation struct {
	ID             RotationID `json:"id"`
	BindingID      BindingID `json:"binding_id"`
	TenantID       TenantID `json:"tenant_id"`
	Sequence       uint64 `json:"sequence"`
	OldVersion     uint64 `json:"old_version"`
	NewVersion     uint64 `json:"new_version"`
	OverlapUntil   time.Time `json:"overlap_until"`
	State          RotationState `json:"state"`
	ReloadReceiptDigest string `json:"reload_receipt_digest,omitempty"`
	ProviderReceiptDigest string `json:"provider_receipt_digest,omitempty"`
	OccurredAt     time.Time `json:"occurred_at"`
}

func (rotation CredentialRotation) Validate() error {
	if !validID(string(rotation.ID)) || !validID(string(rotation.BindingID)) || !validID(string(rotation.TenantID)) ||
		rotation.Sequence == 0 || rotation.OldVersion == 0 || rotation.NewVersion <= rotation.OldVersion || rotation.OverlapUntil.IsZero() || rotation.OccurredAt.IsZero() {
		return ErrInvalid
	}
	if rotation.State != RotationPrepared && rotation.State != RotationOverlapping && rotation.State != RotationReloaded &&
		rotation.State != RotationRevoked && rotation.State != RotationFailed {
		return ErrInvalid
	}
	if rotation.ReloadReceiptDigest != "" && !validDigest(rotation.ReloadReceiptDigest) ||
		rotation.ProviderReceiptDigest != "" && !validDigest(rotation.ProviderReceiptDigest) {
		return ErrInvalid
	}
	if (rotation.State == RotationPrepared || rotation.State == RotationOverlapping) && !rotation.OverlapUntil.After(rotation.OccurredAt) ||
		rotation.OverlapUntil.After(rotation.OccurredAt.Add(30*24*time.Hour)) ||
		rotation.State == RotationOverlapping && rotation.ProviderReceiptDigest == "" ||
		rotation.State == RotationReloaded && rotation.ReloadReceiptDigest == "" ||
		rotation.State == RotationRevoked && (rotation.ReloadReceiptDigest == "" || rotation.ProviderReceiptDigest == "") {
		return ErrInvalid
	}
	return nil
}

type CredentialRevocation struct {
	ID string `json:"id"`
	BindingID BindingID `json:"binding_id"`
	TenantID TenantID `json:"tenant_id"`
	CredentialVersion uint64 `json:"credential_version"`
	ProviderReceiptDigest string `json:"provider_receipt_digest"`
	RevokedAt time.Time `json:"revoked_at"`
}

func (revocation CredentialRevocation) Validate() error {
	if !validID(revocation.ID) || !validID(string(revocation.BindingID)) || !validID(string(revocation.TenantID)) ||
		revocation.CredentialVersion == 0 || !validDigest(revocation.ProviderReceiptDigest) || revocation.RevokedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type SubmissionState string

const (
	SubmissionPending   SubmissionState = "pending"
	SubmissionAccepted  SubmissionState = "accepted"
	SubmissionAmbiguous SubmissionState = "ambiguous"
	SubmissionAbsent    SubmissionState = "authoritatively_absent"
	SubmissionFailed    SubmissionState = "failed"
)

type MessageIdentity struct {
	TenantID            TenantID `json:"tenant_id"`
	MessageID           MessageID `json:"message_id"`
	IdempotencyKey      string `json:"idempotency_key"`
	BindingID           BindingID `json:"binding_id"`
	BindingGeneration   uint64 `json:"binding_generation"`
	ProviderMessageID   string `json:"provider_message_id,omitempty"`
	State               SubmissionState `json:"state"`
	SuppressionGeneration uint64 `json:"suppression_generation"`
	Generation          uint64 `json:"generation"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func (identity MessageIdentity) Validate() error {
	if !validID(string(identity.TenantID)) || !validID(string(identity.MessageID)) || !validID(identity.IdempotencyKey) ||
		!validID(string(identity.BindingID)) || identity.BindingGeneration == 0 || identity.SuppressionGeneration == 0 ||
		identity.Generation == 0 || identity.UpdatedAt.IsZero() || identity.ProviderMessageID != "" && len(identity.ProviderMessageID) > 256 {
		return ErrInvalid
	}
	if identity.State != SubmissionPending && identity.State != SubmissionAccepted && identity.State != SubmissionAmbiguous &&
		identity.State != SubmissionAbsent && identity.State != SubmissionFailed {
		return ErrInvalid
	}
	return nil
}

type QueueState string

const (
	QueueWaiting QueueState = "waiting"
	QueueClaimed QueueState = "claimed"
	QueueDone    QueueState = "done"
	QueueExpired QueueState = "expired"
)

type ReconciliationItem struct {
	ID           QueueID `json:"id"`
	TenantID     TenantID `json:"tenant_id"`
	MessageID    MessageID `json:"message_id"`
	BindingID    BindingID `json:"binding_id"`
	Stream       MailStream `json:"stream"`
	State        QueueState `json:"state"`
	Attempt      uint16 `json:"attempt"`
	Generation   uint64 `json:"generation"`
	NotBefore    time.Time `json:"not_before"`
	ExpiresAt    time.Time `json:"expires_at"`
	LeaseOwner   string `json:"lease_owner,omitempty"`
	LeaseExpires time.Time `json:"lease_expires,omitempty"`
	LastCode     string `json:"last_code,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (item ReconciliationItem) Validate() error {
	if !validID(string(item.ID)) || !validID(string(item.TenantID)) || !validID(string(item.MessageID)) ||
		!validID(string(item.BindingID)) || item.Stream != StreamTransactional && item.Stream != StreamCampaign || item.Generation == 0 ||
		item.NotBefore.IsZero() || item.CreatedAt.IsZero() || item.NotBefore.Before(item.CreatedAt) || !item.ExpiresAt.After(item.NotBefore) ||
		item.UpdatedAt.Before(item.CreatedAt) || item.Attempt > 32 ||
		len(item.LastCode) > 128 || strings.ContainsAny(item.LastCode, "\x00\r\n") {
		return ErrInvalid
	}
	if item.State != QueueWaiting && item.State != QueueClaimed && item.State != QueueDone && item.State != QueueExpired {
		return ErrInvalid
	}
	if item.State == QueueClaimed && (!validID(item.LeaseOwner) || item.LeaseExpires.IsZero()) {
		return ErrInvalid
	}
	if item.State != QueueClaimed && (item.LeaseOwner != "" || !item.LeaseExpires.IsZero()) {
		return ErrInvalid
	}
	return nil
}

type EventType string

const (
	EventDelivered   EventType = "delivered"
	EventDeferred    EventType = "deferred"
	EventBounced     EventType = "bounced"
	EventComplained  EventType = "complained"
	EventSuppressed  EventType = "suppressed"
	EventRejected    EventType = "rejected"
	EventReputation  EventType = "reputation"
	EventUsage       EventType = "usage"
)

type NormalizedProviderEvent struct {
	SchemaVersion    uint32 `json:"schema_version"`
	ProviderEventID  string `json:"provider_event_id"`
	DeliveryID       DeliveryID `json:"delivery_id"`
	TenantID         TenantID `json:"tenant_id"`
	DomainID         DomainID `json:"domain_id"`
	BindingID        BindingID `json:"binding_id"`
	MessageID        MessageID `json:"message_id,omitempty"`
	ProviderMessageID string `json:"provider_message_id,omitempty"`
	Type              EventType `json:"type"`
	ReasonCode        string `json:"reason_code,omitempty"`
	OccurredAt        time.Time `json:"occurred_at"`
	ReceivedAt        time.Time `json:"received_at"`
	PayloadDigest     string `json:"payload_digest"`
}

func (event NormalizedProviderEvent) Validate() error {
	if event.SchemaVersion != 1 || !validID(event.ProviderEventID) || !validID(string(event.DeliveryID)) ||
		!validID(string(event.TenantID)) || !validID(string(event.DomainID)) || !validID(string(event.BindingID)) ||
		event.MessageID != "" && !validID(string(event.MessageID)) || len(event.ProviderMessageID) > 256 ||
		len(event.ReasonCode) > 128 || strings.ContainsAny(event.ReasonCode, "\x00\r\n") || event.OccurredAt.IsZero() ||
		event.ReceivedAt.IsZero() || event.OccurredAt.After(event.ReceivedAt.Add(5*time.Minute)) || !validDigest(event.PayloadDigest) {
		return ErrInvalid
	}
	switch event.Type {
	case EventDelivered, EventDeferred, EventBounced, EventComplained, EventSuppressed, EventRejected, EventReputation, EventUsage:
		return nil
	default:
		return ErrInvalid
	}
}

type DomainVerificationRequest struct {
	Binding ProviderBinding
	Domain SendingDomain
	Plan DNSPlan
}

type DomainVerificationResult struct {
	State VerificationState
	EvidenceDigest string
	ObservedAt time.Time
}

type SubmitEnvelope struct {
	TenantID       TenantID
	DomainID       DomainID
	MessageID      MessageID
	IdempotencyKey string
	Stream         MailStream
	CampaignID     CampaignID
	MailFrom       string
	Recipients     []string
	Size           int64
}

type SubmitRequest struct {
	Envelope SubmitEnvelope
	Content io.Reader
}

type SubmitResult struct {
	State             SubmissionState
	ProviderMessageID string
	AcceptedAt        time.Time
	RetryAfter        time.Duration
	Code              string
	MayHaveSubmitted  bool
}

type QueryResult struct {
	State                SubmissionState
	ProviderMessageID    string
	ObservedAt           time.Time
	AuthoritativeAbsence bool
}

type CredentialRotationRequest struct {
	Binding ProviderBinding
	Rotation CredentialRotation
}

type RawProviderEvent struct {
	BindingID BindingID
	TenantID TenantID
	DomainID DomainID
	DeliveryID DeliveryID
	SchemaVersion uint32
	ReceivedAt time.Time
	PayloadDigest string
	Body []byte
}

// ProviderAdapterV1 is deliberately provider-neutral. A release cannot claim
// EDL-015 until a separately named adapter qualifies this complete contract.
type ProviderAdapterV1 interface {
	Reference() ProviderAdapterRef
	VerifyDomain(context.Context, DomainVerificationRequest) (DomainVerificationResult, error)
	ObserveHealthAndLimits(context.Context, ProviderBinding) (ProviderObservation, error)
	Submit(context.Context, SubmitRequest) (SubmitResult, error)
	QueryByIdempotency(context.Context, ProviderBinding, string) (QueryResult, error)
	RotateCredential(context.Context, CredentialRotationRequest) (CredentialRotation, error)
	RevokeCredential(context.Context, ProviderBinding, uint64) (CredentialRevocation, error)
	NormalizeEvent(context.Context, RawProviderEvent) (NormalizedProviderEvent, error)
}

type SubmissionAdapterV1 interface {
	Submit(context.Context, SubmitRequest) (SubmitResult, error)
	QueryByIdempotency(context.Context, ProviderBinding, string) (QueryResult, error)
}

type AuthorizationAction string

const (
	AuthorizeBindingWrite AuthorizationAction = "binding.write"
	AuthorizeDNSPlanWrite AuthorizationAction = "dns_plan.write"
	AuthorizeCredentialRotate AuthorizationAction = "credential.rotate"
	AuthorizeCredentialRevoke AuthorizationAction = "credential.revoke"
	AuthorizeRouteEvaluate AuthorizationAction = "route.evaluate"
	AuthorizeSubmit AuthorizationAction = "message.submit"
	AuthorizeWebhookIngest AuthorizationAction = "webhook.ingest"
	AuthorizeInspect AuthorizationAction = "delivery.inspect"
)

type AuthorizationRequest struct {
	Actor ActorID
	TenantID TenantID
	BindingID BindingID
	Action AuthorizationAction
	AuthorizationEpoch uint64
	HighRisk bool
	IntentDigest string
}

func (request AuthorizationRequest) Validate() error {
	if !validID(string(request.Actor)) || !validID(string(request.TenantID)) || request.BindingID != "" && !validID(string(request.BindingID)) ||
		request.AuthorizationEpoch == 0 || !validDigest(request.IntentDigest) {
		return ErrInvalid
	}
	switch request.Action {
	case AuthorizeBindingWrite, AuthorizeDNSPlanWrite, AuthorizeCredentialRotate, AuthorizeCredentialRevoke,
		AuthorizeRouteEvaluate, AuthorizeSubmit, AuthorizeWebhookIngest, AuthorizeInspect:
		return nil
	default:
		return ErrInvalid
	}
}

type Authorizer interface {
	AuthorizeMailDelivery(context.Context, AuthorizationRequest) error
}

type StepUpVerifier interface {
	VerifyMailDeliveryStepUp(context.Context, AuthorizationRequest, string, time.Time) error
}

type ConsentRequest struct {
	TenantID TenantID
	BindingID BindingID
	Revision uint64
	Purpose string
	DataClasses []string
	Destination string
	Region string
}

func (request ConsentRequest) Validate() error {
	if !validID(string(request.TenantID)) || !validID(string(request.BindingID)) || request.Revision == 0 ||
		request.Purpose != "outbound_mail_delivery" || len(request.DataClasses) == 0 || len(request.DataClasses) > 32 ||
		len(request.Destination) == 0 || len(request.Destination) > 256 || len(request.Region) == 0 || len(request.Region) > 64 {
		return ErrInvalid
	}
	for _, class := range request.DataClasses {
		if !validID(class) {
			return ErrInvalid
		}
	}
	return nil
}

type ConsentVerifier interface {
	VerifyMailDeliveryConsent(context.Context, ConsentRequest) error
}

type AuditRecord struct {
	Actor ActorID `json:"actor"`
	TenantID TenantID `json:"tenant_id"`
	BindingID BindingID `json:"binding_id,omitempty"`
	Action AuthorizationAction `json:"action"`
	ResourceID string `json:"resource_id"`
	Generation uint64 `json:"generation,omitempty"`
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
	Outcome string `json:"outcome"`
	IntentDigest string `json:"intent_digest"`
	OccurredAt time.Time `json:"occurred_at"`
}

func (record AuditRecord) Validate() error {
	request := AuthorizationRequest{Actor: record.Actor, TenantID: record.TenantID, BindingID: record.BindingID,
		Action: record.Action, AuthorizationEpoch: record.AuthorizationEpoch, IntentDigest: record.IntentDigest}
	if request.Validate() != nil || len(record.ResourceID) == 0 || len(record.ResourceID) > 256 || len(record.Outcome) == 0 ||
		len(record.Outcome) > 64 || strings.ContainsAny(record.ResourceID+record.Outcome, "\x00\r\n") || record.OccurredAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type AuditSink interface {
	RecordMailDelivery(context.Context, AuditRecord) error
}
