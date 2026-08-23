package providerpolicy

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"
)

type DecisionKind string

const (
	DecisionAllow DecisionKind = "allow"
	DecisionDeny  DecisionKind = "deny"
	DecisionDefer DecisionKind = "defer"
)

type DecisionCode string

const (
	CodeAllowed                 DecisionCode = "allowed"
	CodeInvalidRequest          DecisionCode = "invalid_request"
	CodeTenantMismatch          DecisionCode = "tenant_mismatch"
	CodeStaleBinding            DecisionCode = "stale_binding"
	CodeConsentMismatch         DecisionCode = "consent_mismatch"
	CodeBindingNotEnabled       DecisionCode = "binding_not_enabled"
	CodePurposeDenied           DecisionCode = "purpose_denied"
	CodeDataClassDenied         DecisionCode = "data_class_denied"
	CodeByteLimitExceeded       DecisionCode = "byte_limit_exceeded"
	CodeCapabilityDenied        DecisionCode = "capability_denied"
	CodeResourceDenied          DecisionCode = "resource_denied"
	CodeRiskDenied              DecisionCode = "risk_denied"
	CodeSecretPurposeDenied     DecisionCode = "secret_purpose_denied"
	CodeSecretVersionStale      DecisionCode = "secret_version_stale"
	CodeHealthStale             DecisionCode = "health_stale"
	CodeProviderUnavailable     DecisionCode = "provider_unavailable"
	CodeRetryBudgetExhausted    DecisionCode = "retry_budget_exhausted"
	CodeConcurrencyLimited      DecisionCode = "concurrency_limited"
	CodeRateLimited             DecisionCode = "rate_limited"
	CodeCircuitOpen             DecisionCode = "circuit_open"
	CodeHalfOpenProbeRequired   DecisionCode = "half_open_probe_required"
	CodeHalfOpenProbeLimited    DecisionCode = "half_open_probe_limited"
)

type AdmissionRequest struct {
	BindingID          BindingID    `json:"binding_id"`
	BindingGeneration uint64       `json:"binding_generation"`
	ConsentRevision   uint64       `json:"consent_revision"`
	Actor              ActorID      `json:"actor"`
	TenantID           TenantID     `json:"tenant_id"`
	Purpose            string       `json:"purpose"`
	DataClass          string       `json:"data_class"`
	Bytes              int64        `json:"bytes"`
	Capability         string       `json:"capability"`
	Resource           string       `json:"resource"`
	Risk               OperationRisk `json:"risk"`
	SecretPurpose      string       `json:"secret_purpose,omitempty"`
	SecretVersion      uint64       `json:"secret_version,omitempty"`
	Attempt            int          `json:"attempt"`
	HalfOpenProbe      bool         `json:"half_open_probe"`
}

func (request AdmissionRequest) Validate() error {
	if !validID(string(request.BindingID)) || request.BindingGeneration == 0 || request.ConsentRevision == 0 || !validID(string(request.Actor)) ||
		!validID(string(request.TenantID)) || !validName(request.Purpose) || !validName(request.DataClass) || request.Bytes < 0 || request.Bytes > MaximumRequestBytes ||
		!validName(request.Capability) || !validResource(request.Resource) || request.Risk.rank() == 0 || request.Attempt < 0 || request.Attempt > MaximumRetryAttempts ||
		(request.SecretPurpose == "") != (request.SecretVersion == 0) || request.SecretPurpose != "" && !validName(request.SecretPurpose) {
		return ErrInvalid
	}
	return nil
}

type ProviderHealth string

const (
	HealthHealthy     ProviderHealth = "healthy"
	HealthDegraded    ProviderHealth = "degraded"
	HealthUnavailable ProviderHealth = "unavailable"
	HealthUnknown     ProviderHealth = "unknown"
)

type HealthSnapshot struct {
	Status       ProviderHealth `json:"status"`
	ObservedAt   time.Time      `json:"observed_at"`
	RetryAfter   time.Duration  `json:"retry_after"`
	EvidenceDigest string       `json:"evidence_digest,omitempty"`
}

func (health HealthSnapshot) Validate() error {
	switch health.Status {
	case HealthHealthy, HealthDegraded, HealthUnavailable, HealthUnknown:
	default:
		return ErrInvalid
	}
	if health.ObservedAt.IsZero() || health.RetryAfter < 0 || health.RetryAfter > 24*time.Hour || health.EvidenceDigest != "" && !validDigest(health.EvidenceDigest) {
		return ErrInvalid
	}
	return nil
}

type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

type RuntimeSnapshot struct {
	Generation        uint64       `json:"generation"`
	Inflight          int          `json:"inflight"`
	Tokens            float64      `json:"tokens"`
	RefilledAt        time.Time    `json:"refilled_at"`
	Circuit           CircuitState `json:"circuit"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	OpenedUntil       time.Time    `json:"opened_until,omitempty"`
	HalfOpenInflight  int          `json:"half_open_inflight"`
}

func (snapshot RuntimeSnapshot) Validate(policy ResiliencePolicy) error {
	if policy.Validate() != nil || snapshot.Generation == 0 || snapshot.Inflight < 0 || snapshot.Inflight > policy.ConcurrencyLimit || snapshot.Tokens < 0 || snapshot.Tokens > float64(policy.RateCapacity)+0.000001 ||
		snapshot.RefilledAt.IsZero() || snapshot.ConsecutiveFailures < 0 || snapshot.HalfOpenInflight < 0 || snapshot.HalfOpenInflight > policy.HalfOpenProbeLimit {
		return ErrInvalid
	}
	switch snapshot.Circuit {
	case CircuitClosed:
		if snapshot.HalfOpenInflight != 0 {
			return ErrInvalid
		}
	case CircuitOpen:
		if snapshot.OpenedUntil.IsZero() || snapshot.HalfOpenInflight != 0 {
			return ErrInvalid
		}
	case CircuitHalfOpen:
	default:
		return ErrInvalid
	}
	return nil
}

type AdmissionEvidence struct {
	BindingID          BindingID     `json:"binding_id"`
	BindingGeneration uint64        `json:"binding_generation"`
	ConsentRevision   uint64        `json:"consent_revision"`
	Actor              ActorID       `json:"actor"`
	TenantID           TenantID      `json:"tenant_id"`
	Purpose            string        `json:"purpose"`
	DataClass          string        `json:"data_class"`
	Bytes              int64         `json:"bytes"`
	Capability         string        `json:"capability"`
	ResourceDigest     string        `json:"resource_digest"`
	Risk               OperationRisk `json:"risk"`
	SecretPurpose      string        `json:"secret_purpose,omitempty"`
	SecretVersion      uint64        `json:"secret_version,omitempty"`
	Health             ProviderHealth `json:"health"`
	HealthObservedAt   time.Time     `json:"health_observed_at"`
	RuntimeGeneration  uint64        `json:"runtime_generation"`
	Circuit            CircuitState  `json:"circuit"`
	Attempt            int           `json:"attempt"`
	EvaluatedAt        time.Time     `json:"evaluated_at"`
	Facts              []string      `json:"facts"`
	Digest             string        `json:"digest"`
}

type AdmissionDecision struct {
	Kind       DecisionKind      `json:"kind"`
	Code       DecisionCode      `json:"code"`
	RetryAfter time.Duration     `json:"retry_after"`
	Evidence   AdmissionEvidence `json:"evidence"`
}

func EvaluateAdmission(binding Binding, request AdmissionRequest, health HealthSnapshot, runtime RuntimeSnapshot, now time.Time) AdmissionDecision {
	now = now.UTC()
	evidence := AdmissionEvidence{BindingID: request.BindingID, BindingGeneration: request.BindingGeneration, ConsentRevision: request.ConsentRevision,
		Actor: request.Actor, TenantID: request.TenantID, Purpose: request.Purpose, DataClass: request.DataClass, Bytes: request.Bytes,
		Capability: request.Capability, ResourceDigest: digest([]byte(request.Resource)), Risk: request.Risk, SecretPurpose: request.SecretPurpose,
		SecretVersion: request.SecretVersion, Health: health.Status, HealthObservedAt: health.ObservedAt.UTC(), RuntimeGeneration: runtime.Generation,
		Circuit: runtime.Circuit, Attempt: request.Attempt, EvaluatedAt: now}
	decide := func(kind DecisionKind, code DecisionCode, retryAfter time.Duration, fact string) AdmissionDecision {
		evidence.Facts = append(evidence.Facts, fact)
		sort.Strings(evidence.Facts)
		evidence.Digest = ""
		encoded, _ := json.Marshal(evidence)
		evidence.Digest = digest(encoded)
		return AdmissionDecision{Kind: kind, Code: code, RetryAfter: clampRetry(retryAfter), Evidence: evidence}
	}
	if binding.Validate() != nil || request.Validate() != nil || health.Validate() != nil || runtime.Validate(binding.Resilience) != nil || now.IsZero() {
		return decide(DecisionDeny, CodeInvalidRequest, 0, "validation_failed")
	}
	evidence.Facts = append(evidence.Facts, "models_valid")
	if request.BindingID != binding.ID || request.TenantID != binding.TenantID {
		return decide(DecisionDeny, CodeTenantMismatch, 0, "tenant_or_binding_mismatch")
	}
	if request.BindingGeneration != binding.Generation {
		return decide(DecisionDeny, CodeStaleBinding, 0, "binding_generation_mismatch")
	}
	if request.ConsentRevision != binding.EgressConsentRevision {
		return decide(DecisionDeny, CodeConsentMismatch, 0, "consent_revision_mismatch")
	}
	if binding.Lifecycle != LifecycleEnabled {
		return decide(DecisionDeny, CodeBindingNotEnabled, 0, "lifecycle_"+string(binding.Lifecycle))
	}
	if request.Purpose != binding.Purpose {
		return decide(DecisionDeny, CodePurposeDenied, 0, "purpose_mismatch")
	}
	if !contains(binding.AllowedDataClasses, request.DataClass) {
		return decide(DecisionDeny, CodeDataClassDenied, 0, "data_class_out_of_scope")
	}
	if request.Bytes > binding.MaximumRequestBytes {
		return decide(DecisionDeny, CodeByteLimitExceeded, 0, "binding_byte_limit")
	}
	scope, found := findScope(binding.Scopes, request.Capability)
	if !found {
		return decide(DecisionDeny, CodeCapabilityDenied, 0, "capability_out_of_scope")
	}
	if !resourceAllowed(scope.Resources, request.Resource) {
		return decide(DecisionDeny, CodeResourceDenied, 0, "resource_out_of_scope")
	}
	if request.Risk.rank() > scope.MaximumRisk.rank() {
		return decide(DecisionDeny, CodeRiskDenied, 0, "risk_exceeds_scope")
	}
	if request.SecretPurpose != "" {
		reference, ok := findSecret(binding.SecretReferences, request.SecretPurpose)
		if !ok {
			return decide(DecisionDeny, CodeSecretPurposeDenied, 0, "secret_purpose_out_of_scope")
		}
		if request.SecretVersion != reference.Version {
			return decide(DecisionDeny, CodeSecretVersionStale, 0, "secret_version_mismatch")
		}
	}
	if request.Attempt > binding.Resilience.MaximumRetryAttempts {
		return decide(DecisionDeny, CodeRetryBudgetExhausted, 0, "retry_budget_exhausted")
	}
	staleness := now.Sub(health.ObservedAt)
	if staleness < 0 || staleness > binding.Resilience.MaximumHealthStaleness {
		return decide(DecisionDefer, CodeHealthStale, time.Second, "health_observation_stale")
	}
	if health.Status == HealthUnavailable || health.Status == HealthUnknown {
		return decide(DecisionDefer, CodeProviderUnavailable, maxDuration(health.RetryAfter, time.Second), "provider_not_healthy")
	}
	if runtime.Inflight >= binding.Resilience.ConcurrencyLimit {
		return decide(DecisionDefer, CodeConcurrencyLimited, time.Second, "concurrency_limit")
	}
	refilledTokens := refillTokens(runtime.Tokens, runtime.RefilledAt, now, binding.Resilience)
	if refilledTokens < 1 {
		return decide(DecisionDefer, CodeRateLimited, tokenRetryAfter(refilledTokens, binding.Resilience), "token_bucket_empty")
	}
	if runtime.Circuit == CircuitOpen {
		if now.Before(runtime.OpenedUntil) {
			return decide(DecisionDefer, CodeCircuitOpen, runtime.OpenedUntil.Sub(now), "circuit_open")
		}
		if !request.HalfOpenProbe {
			return decide(DecisionDefer, CodeHalfOpenProbeRequired, 0, "half_open_probe_required")
		}
	}
	if runtime.Circuit == CircuitHalfOpen {
		if !request.HalfOpenProbe {
			return decide(DecisionDefer, CodeHalfOpenProbeRequired, time.Second, "half_open_probe_required")
		}
		if runtime.HalfOpenInflight >= binding.Resilience.HalfOpenProbeLimit {
			return decide(DecisionDefer, CodeHalfOpenProbeLimited, time.Second, "half_open_probe_limit")
		}
	}
	evidence.Facts = append(evidence.Facts, "binding_scope_matched", "consent_current", "health_current", "resilience_capacity_available")
	return decide(DecisionAllow, CodeAllowed, 0, "admitted")
}

func findScope(scopes []CapabilityScope, capability string) (CapabilityScope, bool) {
	index := sort.Search(len(scopes), func(index int) bool { return scopes[index].Capability >= capability })
	return func() (CapabilityScope, bool) {
		if index < len(scopes) && scopes[index].Capability == capability {
			return scopes[index], true
		}
		return CapabilityScope{}, false
	}()
}

func findSecret(references []SecretReference, purpose string) (SecretReference, bool) {
	index := sort.Search(len(references), func(index int) bool { return references[index].Purpose >= purpose })
	if index < len(references) && references[index].Purpose == purpose {
		return references[index], true
	}
	return SecretReference{}, false
}

func resourceAllowed(scopes []string, resource string) bool {
	for _, scope := range scopes {
		if scope == "*" || scope == resource || strings.HasSuffix(scope, "/*") && strings.HasPrefix(resource, strings.TrimSuffix(scope, "*")) {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func refillTokens(current float64, refilledAt, now time.Time, policy ResiliencePolicy) float64 {
	if !now.After(refilledAt) {
		return current
	}
	added := now.Sub(refilledAt).Minutes() * float64(policy.RateRefillPerMinute)
	return math.Min(float64(policy.RateCapacity), current+added)
}

func tokenRetryAfter(tokens float64, policy ResiliencePolicy) time.Duration {
	seconds := (1 - tokens) / float64(policy.RateRefillPerMinute) * 60
	return clampRetry(time.Duration(math.Ceil(seconds*1000)) * time.Millisecond)
}

func clampRetry(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	if value > 24*time.Hour {
		return 24 * time.Hour
	}
	return value
}

func maxDuration(first, second time.Duration) time.Duration {
	if first > second {
		return first
	}
	return second
}

type Permit struct {
	ID                PermitID `json:"id"`
	BindingID         BindingID `json:"binding_id"`
	TenantID          TenantID `json:"tenant_id"`
	RuntimeGeneration uint64 `json:"runtime_generation"`
	HalfOpenProbe     bool `json:"half_open_probe"`
	AcquiredAt        time.Time `json:"acquired_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	FenceDigest       string `json:"fence_digest"`
	FenceToken        string `json:"-"`
}

func (permit Permit) Validate() error {
	if !validID(string(permit.ID)) || !validID(string(permit.BindingID)) || !validID(string(permit.TenantID)) || permit.RuntimeGeneration == 0 ||
		permit.AcquiredAt.IsZero() || !permit.ExpiresAt.After(permit.AcquiredAt) || !validDigest(permit.FenceDigest) || len(permit.FenceToken) != 64 ||
		digest([]byte(permit.FenceToken)) != permit.FenceDigest {
		return ErrInvalid
	}
	return nil
}

type OperationOutcome string

const (
	OutcomeSuccess   OperationOutcome = "success"
	OutcomeTransient OperationOutcome = "transient_failure"
	OutcomePermanent OperationOutcome = "permanent_failure"
)

type DriftKind string

const (
	DriftCapability DriftKind = "capability"
	DriftConsent    DriftKind = "consent"
	DriftDestination DriftKind = "destination"
	DriftRegion     DriftKind = "region"
	DriftRetention  DriftKind = "retention"
)

type Observation struct {
	ID             ObservationID `json:"id"`
	BindingID      BindingID `json:"binding_id"`
	TenantID       TenantID `json:"tenant_id"`
	Health         ProviderHealth `json:"health"`
	Drift          []DriftKind `json:"drift"`
	ExpectedDigest string `json:"expected_digest"`
	ObservedDigest string `json:"observed_digest"`
	RetryAfter     time.Duration `json:"retry_after"`
	ObservedAt     time.Time `json:"observed_at"`
	Digest         string `json:"digest"`
}

func (observation Observation) Validate() error {
	if !validID(string(observation.ID)) || !validID(string(observation.BindingID)) || !validID(string(observation.TenantID)) ||
		(HealthSnapshot{Status: observation.Health, ObservedAt: observation.ObservedAt, RetryAfter: observation.RetryAfter}).Validate() != nil ||
		!validDigest(observation.ExpectedDigest) || !validDigest(observation.ObservedDigest) || len(observation.Drift) > 16 || !sort.SliceIsSorted(observation.Drift, func(i, j int) bool { return observation.Drift[i] < observation.Drift[j] }) ||
		!validDigest(observation.Digest) || observationDigest(observation) != observation.Digest {
		return ErrIntegrity
	}
	for index, item := range observation.Drift {
		switch item {
		case DriftCapability, DriftConsent, DriftDestination, DriftRegion, DriftRetention:
		default:
			return ErrInvalid
		}
		if index > 0 && observation.Drift[index-1] == item {
			return ErrInvalid
		}
	}
	return nil
}

func observationDigest(observation Observation) string {
	observation.Digest = ""
	encoded, _ := json.Marshal(observation)
	return digest(encoded)
}

type WorkflowKind string
type WorkflowState string

const (
	WorkflowDeletion        WorkflowKind = "deletion"
	WorkflowReauthorization WorkflowKind = "reauthorization"
	WorkflowPending         WorkflowState = "pending"
	WorkflowAwaitingProof   WorkflowState = "awaiting_proof"
	WorkflowCompleted       WorkflowState = "completed"
	WorkflowFailed          WorkflowState = "failed"
)

type LifecycleWorkflow struct {
	ID                    WorkflowID `json:"id"`
	BindingID             BindingID `json:"binding_id"`
	TenantID              TenantID `json:"tenant_id"`
	Kind                  WorkflowKind `json:"kind"`
	State                 WorkflowState `json:"state"`
	BindingGeneration     uint64 `json:"binding_generation"`
	DeleteProviderData    bool `json:"delete_provider_data"`
	NewSecretReferences   []SecretReference `json:"new_secret_references,omitempty"`
	SecretsTransferred    bool `json:"secrets_transferred"`
	ProviderProofDigest   string `json:"provider_proof_digest,omitempty"`
	Reason                string `json:"reason"`
	Actor                 ActorID `json:"actor"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	Generation            uint64 `json:"generation"`
	Digest                string `json:"digest"`
}

func (workflow LifecycleWorkflow) Validate() error {
	if !validID(string(workflow.ID)) || !validID(string(workflow.BindingID)) || !validID(string(workflow.TenantID)) || workflow.BindingGeneration == 0 ||
		workflow.SecretsTransferred || len(workflow.Reason) < 1 || len(workflow.Reason) > 512 || !validID(string(workflow.Actor)) || workflow.CreatedAt.IsZero() ||
		workflow.UpdatedAt.Before(workflow.CreatedAt) || workflow.Generation == 0 || workflow.ProviderProofDigest != "" && !validDigest(workflow.ProviderProofDigest) ||
		!validDigest(workflow.Digest) || workflowDigest(workflow) != workflow.Digest {
		return ErrInvalid
	}
	switch workflow.State {
	case WorkflowPending, WorkflowAwaitingProof, WorkflowCompleted, WorkflowFailed:
	default:
		return ErrInvalid
	}
	switch workflow.Kind {
	case WorkflowDeletion:
		if len(workflow.NewSecretReferences) != 0 {
			return ErrInvalid
		}
	case WorkflowReauthorization:
		if workflow.DeleteProviderData || len(workflow.NewSecretReferences) == 0 || len(workflow.NewSecretReferences) > 32 {
			return ErrInvalid
		}
		last := ""
		for _, reference := range workflow.NewSecretReferences {
			if reference.Validate() != nil || reference.Purpose <= last {
				return ErrInvalid
			}
			last = reference.Purpose
		}
	default:
		return ErrInvalid
	}
	return nil
}

func SealWorkflow(workflow LifecycleWorkflow) LifecycleWorkflow {
	workflow.SecretsTransferred = false
	workflow.Digest = workflowDigest(workflow)
	return workflow
}

func workflowDigest(workflow LifecycleWorkflow) string {
	workflow.Digest = ""
	encoded, _ := json.Marshal(workflow)
	return digest(encoded)
}
