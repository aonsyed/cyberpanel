package providerpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid   = errors.New("provider policy: invalid input")
	ErrNotFound  = errors.New("provider policy: not found")
	ErrConflict  = errors.New("provider policy: conflict")
	ErrStale     = errors.New("provider policy: stale generation")
	ErrDenied    = errors.New("provider policy: denied")
	ErrDeferred  = errors.New("provider policy: deferred")
	ErrIntegrity = errors.New("provider policy: integrity failure")
)

const (
	MaximumRequestBytes     int64 = 64 << 20
	MaximumRetentionDays          = 3650
	MaximumConcurrency            = 64
	MaximumRateCapacity           = 10000
	MaximumRetryAttempts          = 20
	MaximumStaleness              = 24 * time.Hour
)

type TenantID string
type ProviderID string
type BindingID string
type ActorID string
type SecretReferenceID string
type PermitID string
type WorkflowID string
type ObservationID string

type Lifecycle string

const (
	LifecycleEnabled   Lifecycle = "enabled"
	LifecycleSuspended Lifecycle = "suspended"
	LifecycleDeleting  Lifecycle = "deleting"
)

type OperationRisk string

const (
	RiskRead   OperationRisk = "read"
	RiskWrite  OperationRisk = "write"
	RiskDelete OperationRisk = "delete"
)

func (risk OperationRisk) rank() int {
	switch risk {
	case RiskRead:
		return 1
	case RiskWrite:
		return 2
	case RiskDelete:
		return 3
	default:
		return 0
	}
}

type SecretReference struct {
	Purpose   string            `json:"purpose"`
	Reference SecretReferenceID `json:"reference"`
	Version   uint64            `json:"version"`
}

func (reference SecretReference) Validate() error {
	if !validName(reference.Purpose) || !validID(string(reference.Reference)) || reference.Version == 0 {
		return ErrInvalid
	}
	return nil
}

type CapabilityScope struct {
	Capability string   `json:"capability"`
	Resources  []string `json:"resources"`
	MaximumRisk OperationRisk `json:"maximum_risk"`
}

func (scope CapabilityScope) Validate() error {
	if !validName(scope.Capability) || scope.MaximumRisk.rank() == 0 || len(scope.Resources) == 0 || len(scope.Resources) > 128 || !sortedUnique(scope.Resources) {
		return ErrInvalid
	}
	for _, resource := range scope.Resources {
		if !validResource(resource) {
			return ErrInvalid
		}
	}
	return nil
}

type RetentionCommitment struct {
	MaximumDays          int  `json:"maximum_days"`
	DeleteOnDisconnect   bool `json:"delete_on_disconnect"`
	DeletionSLAHours     int  `json:"deletion_sla_hours"`
	ProviderProofRequired bool `json:"provider_proof_required"`
}

func (commitment RetentionCommitment) Validate() error {
	if commitment.MaximumDays < 0 || commitment.MaximumDays > MaximumRetentionDays || commitment.DeletionSLAHours < 0 || commitment.DeletionSLAHours > MaximumRetentionDays*24 ||
		commitment.DeleteOnDisconnect && commitment.DeletionSLAHours == 0 {
		return ErrInvalid
	}
	return nil
}

type ResiliencePolicy struct {
	ConcurrencyLimit      int           `json:"concurrency_limit"`
	RateCapacity          int           `json:"rate_capacity"`
	RateRefillPerMinute   int           `json:"rate_refill_per_minute"`
	FailureThreshold      int           `json:"failure_threshold"`
	OpenDuration          time.Duration `json:"open_duration"`
	HalfOpenProbeLimit    int           `json:"half_open_probe_limit"`
	MaximumRetryAttempts  int           `json:"maximum_retry_attempts"`
	MaximumHealthStaleness time.Duration `json:"maximum_health_staleness"`
}

func (policy ResiliencePolicy) Validate() error {
	if policy.ConcurrencyLimit < 1 || policy.ConcurrencyLimit > MaximumConcurrency || policy.RateCapacity < 1 || policy.RateCapacity > MaximumRateCapacity ||
		policy.RateRefillPerMinute < 1 || policy.RateRefillPerMinute > MaximumRateCapacity || policy.FailureThreshold < 1 || policy.FailureThreshold > 100 ||
		policy.OpenDuration < time.Second || policy.OpenDuration > 24*time.Hour || policy.HalfOpenProbeLimit < 1 || policy.HalfOpenProbeLimit > policy.ConcurrencyLimit ||
		policy.MaximumRetryAttempts < 0 || policy.MaximumRetryAttempts > MaximumRetryAttempts || policy.MaximumHealthStaleness < time.Second || policy.MaximumHealthStaleness > MaximumStaleness {
		return ErrInvalid
	}
	return nil
}

type Binding struct {
	ID                     BindingID          `json:"id"`
	TenantID               TenantID           `json:"tenant_id"`
	ProviderID             ProviderID         `json:"provider_id"`
	Purpose                string             `json:"purpose"`
	AllowedDataClasses     []string           `json:"allowed_data_classes"`
	MaximumRequestBytes    int64              `json:"maximum_request_bytes"`
	Destination            string             `json:"destination"`
	Region                 string             `json:"region"`
	Retention              RetentionCommitment `json:"retention"`
	EgressConsentRevision  uint64             `json:"egress_consent_revision"`
	SecretReferences       []SecretReference  `json:"secret_references"`
	Scopes                 []CapabilityScope  `json:"scopes"`
	Resilience             ResiliencePolicy   `json:"resilience"`
	Lifecycle              Lifecycle          `json:"lifecycle"`
	Generation             uint64             `json:"generation"`
	CreatedAt              time.Time          `json:"created_at"`
	UpdatedAt              time.Time          `json:"updated_at"`
}

func (binding Binding) Validate() error {
	if !validID(string(binding.ID)) || !validID(string(binding.TenantID)) || !validID(string(binding.ProviderID)) || !validName(binding.Purpose) ||
		len(binding.AllowedDataClasses) == 0 || len(binding.AllowedDataClasses) > 64 || !sortedUnique(binding.AllowedDataClasses) || binding.MaximumRequestBytes < 1 || binding.MaximumRequestBytes > MaximumRequestBytes ||
		!validDestination(binding.Destination) || !validRegion(binding.Region) || binding.Retention.Validate() != nil || binding.EgressConsentRevision == 0 ||
		len(binding.SecretReferences) > 32 || len(binding.Scopes) == 0 || len(binding.Scopes) > 128 || binding.Resilience.Validate() != nil || binding.Generation == 0 ||
		binding.CreatedAt.IsZero() || binding.UpdatedAt.Before(binding.CreatedAt) {
		return ErrInvalid
	}
	switch binding.Lifecycle {
	case LifecycleEnabled, LifecycleSuspended, LifecycleDeleting:
	default:
		return ErrInvalid
	}
	for _, class := range binding.AllowedDataClasses {
		if !validName(class) {
			return ErrInvalid
		}
	}
	lastPurpose := ""
	for _, reference := range binding.SecretReferences {
		if reference.Validate() != nil || reference.Purpose <= lastPurpose {
			return ErrInvalid
		}
		lastPurpose = reference.Purpose
	}
	lastCapability := ""
	for _, scope := range binding.Scopes {
		if scope.Validate() != nil || scope.Capability <= lastCapability {
			return ErrInvalid
		}
		lastCapability = scope.Capability
	}
	return nil
}

type ConsentRecord struct {
	BindingID       BindingID `json:"binding_id"`
	TenantID        TenantID  `json:"tenant_id"`
	Revision        uint64    `json:"revision"`
	Purpose         string    `json:"purpose"`
	DataClasses     []string  `json:"data_classes"`
	Destination     string    `json:"destination"`
	Region          string    `json:"region"`
	TermsDigest     string    `json:"terms_digest"`
	Actor           ActorID   `json:"actor"`
	GrantedAt       time.Time `json:"granted_at"`
	RecordDigest    string    `json:"record_digest"`
}

func (record ConsentRecord) Validate() error {
	if !validID(string(record.BindingID)) || !validID(string(record.TenantID)) || record.Revision == 0 || !validName(record.Purpose) ||
		len(record.DataClasses) == 0 || !sortedUnique(record.DataClasses) || !validDestination(record.Destination) || !validRegion(record.Region) ||
		!validDigest(record.TermsDigest) || !validID(string(record.Actor)) || record.GrantedAt.IsZero() || !validDigest(record.RecordDigest) || consentDigest(record) != record.RecordDigest {
		return ErrIntegrity
	}
	for _, class := range record.DataClasses {
		if !validName(class) {
			return ErrInvalid
		}
	}
	return nil
}

func NewConsentRecord(binding Binding, revision uint64, termsDigest string, actor ActorID, grantedAt time.Time) (ConsentRecord, error) {
	record := ConsentRecord{BindingID: binding.ID, TenantID: binding.TenantID, Revision: revision, Purpose: binding.Purpose,
		DataClasses: append([]string(nil), binding.AllowedDataClasses...), Destination: binding.Destination, Region: binding.Region,
		TermsDigest: termsDigest, Actor: actor, GrantedAt: grantedAt.UTC()}
	record.RecordDigest = consentDigest(record)
	if binding.Validate() != nil || record.Validate() != nil {
		return ConsentRecord{}, ErrInvalid
	}
	return record, nil
}

func consentDigest(record ConsentRecord) string {
	record.RecordDigest = ""
	encoded, _ := json.Marshal(record)
	return digest(encoded)
}

type RedactedBinding struct {
	ID                    BindingID          `json:"id"`
	TenantID              TenantID           `json:"tenant_id"`
	ProviderID            ProviderID         `json:"provider_id"`
	Purpose               string             `json:"purpose"`
	AllowedDataClasses    []string           `json:"allowed_data_classes"`
	MaximumRequestBytes   int64              `json:"maximum_request_bytes"`
	Destination           string             `json:"destination"`
	Region                string             `json:"region"`
	Retention             RetentionCommitment `json:"retention"`
	EgressConsentRevision uint64             `json:"egress_consent_revision"`
	SecretPurposes        []string           `json:"secret_purposes"`
	Scopes                []CapabilityScope  `json:"scopes"`
	Resilience            ResiliencePolicy   `json:"resilience"`
	Lifecycle             Lifecycle          `json:"lifecycle"`
	Generation            uint64             `json:"generation"`
	ProjectionDigest      string             `json:"projection_digest"`
}

func RedactBinding(binding Binding) (RedactedBinding, error) {
	if binding.Validate() != nil {
		return RedactedBinding{}, ErrInvalid
	}
	projection := RedactedBinding{ID: binding.ID, TenantID: binding.TenantID, ProviderID: binding.ProviderID, Purpose: binding.Purpose,
		AllowedDataClasses: append([]string(nil), binding.AllowedDataClasses...), MaximumRequestBytes: binding.MaximumRequestBytes,
		Destination: binding.Destination, Region: binding.Region, Retention: binding.Retention, EgressConsentRevision: binding.EgressConsentRevision,
		Scopes: cloneScopes(binding.Scopes), Resilience: binding.Resilience, Lifecycle: binding.Lifecycle, Generation: binding.Generation}
	for _, reference := range binding.SecretReferences {
		projection.SecretPurposes = append(projection.SecretPurposes, reference.Purpose)
	}
	encoded, _ := json.Marshal(projection)
	projection.ProjectionDigest = digest(encoded)
	return projection, nil
}

func cloneScopes(scopes []CapabilityScope) []CapabilityScope {
	result := make([]CapabilityScope, len(scopes))
	for index, scope := range scopes {
		result[index] = scope
		result[index].Resources = append([]string(nil), scope.Resources...)
	}
	return result
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func validID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && (character == '-' || character == '_' || character == '.') {
			continue
		}
		return false
	}
	return true
}

func validName(value string) bool { return validID(value) }

func validDestination(value string) bool {
	if len(value) < 1 || len(value) > 256 || strings.ContainsAny(value, "@/?#\\") || strings.ToLower(value) != value {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if !validID(part) {
			return false
		}
	}
	return true
}

func validRegion(value string) bool { return validID(value) }

func validResource(value string) bool {
	if len(value) < 1 || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") || strings.Contains(value, "..") {
		return false
	}
	return value == "*" || strings.HasPrefix(value, "/") && !strings.HasSuffix(value, "/")
}

func sortedUnique(values []string) bool {
	return sort.StringsAreSorted(values) && len(values) == len(uniqueStrings(values))
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}
