package maildelivery

import (
	"context"
	"errors"
	"time"
)

type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

type CircuitSnapshot struct {
	State               CircuitState
	ConsecutiveFailures uint16
	OpenedUntil         time.Time
	HalfOpenInflight    uint16
	Generation          uint64
}

func (snapshot CircuitSnapshot) Validate(policy DeliveryPolicy) error {
	if policy.Validate() != nil || snapshot.Generation == 0 || snapshot.ConsecutiveFailures > policy.CircuitFailures ||
		snapshot.HalfOpenInflight > policy.HalfOpenProbes {
		return ErrInvalid
	}
	switch snapshot.State {
	case CircuitClosed:
		if !snapshot.OpenedUntil.IsZero() || snapshot.HalfOpenInflight != 0 {
			return ErrInvalid
		}
	case CircuitOpen:
		if snapshot.OpenedUntil.IsZero() || snapshot.HalfOpenInflight != 0 {
			return ErrInvalid
		}
	case CircuitHalfOpen:
		if snapshot.OpenedUntil.IsZero() {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type CircuitOutcome string

const (
	CircuitSucceeded CircuitOutcome = "succeeded"
	CircuitFailed    CircuitOutcome = "failed"
	CircuitAmbiguous CircuitOutcome = "ambiguous"
)

func AdmitCircuit(snapshot CircuitSnapshot, policy DeliveryPolicy, now time.Time) (CircuitSnapshot, bool, error) {
	if snapshot.Validate(policy) != nil || now.IsZero() {
		return CircuitSnapshot{}, false, ErrInvalid
	}
	now = now.UTC()
	next := snapshot
	if next.State == CircuitOpen && !now.Before(next.OpenedUntil) {
		next.State = CircuitHalfOpen
		next.HalfOpenInflight = 0
		next.Generation++
	}
	if next.State == CircuitOpen || next.State == CircuitHalfOpen && next.HalfOpenInflight >= policy.HalfOpenProbes {
		return next, false, nil
	}
	if next.State == CircuitHalfOpen {
		next.HalfOpenInflight++
		next.Generation++
	}
	return next, true, nil
}

func RecordCircuitOutcome(snapshot CircuitSnapshot, policy DeliveryPolicy, outcome CircuitOutcome, now time.Time) (CircuitSnapshot, error) {
	if snapshot.Validate(policy) != nil || now.IsZero() {
		return CircuitSnapshot{}, ErrInvalid
	}
	next := snapshot
	next.Generation++
	if next.State == CircuitHalfOpen && next.HalfOpenInflight > 0 {
		next.HalfOpenInflight--
	}
	switch outcome {
	case CircuitSucceeded:
		next.State = CircuitClosed
		next.ConsecutiveFailures = 0
		next.OpenedUntil = time.Time{}
		next.HalfOpenInflight = 0
	case CircuitFailed, CircuitAmbiguous:
		if next.ConsecutiveFailures < policy.CircuitFailures {
			next.ConsecutiveFailures++
		}
		if next.State == CircuitHalfOpen || next.ConsecutiveFailures >= policy.CircuitFailures {
			next.State = CircuitOpen
			next.OpenedUntil = now.UTC().Add(policy.CircuitOpenFor)
			next.HalfOpenInflight = 0
		}
	default:
		return CircuitSnapshot{}, ErrInvalid
	}
	return next, nil
}

type SuppressionSnapshot struct {
	TenantID TenantID
	MessageID MessageID
	RecipientDigest string
	Generation uint64
	Suppressed bool
	Reason string
	ObservedAt time.Time
}

func (snapshot SuppressionSnapshot) Validate(tenantID TenantID, messageID MessageID) error {
	if snapshot.TenantID != tenantID || snapshot.MessageID != messageID || !validDigest(snapshot.RecipientDigest) ||
		snapshot.Generation == 0 || snapshot.ObservedAt.IsZero() || len(snapshot.Reason) > 128 {
		return ErrInvalid
	}
	return nil
}

type CapacitySnapshot struct {
	ExternalQueued uint32
	LocalQueued uint32
	ExternalLimit uint32
	LocalLimit uint32
	LocalTransactionalReserve uint32
	ObservedAt time.Time
}

func (snapshot CapacitySnapshot) Validate() error {
	if snapshot.ExternalLimit == 0 || snapshot.LocalLimit == 0 || snapshot.ExternalQueued > snapshot.ExternalLimit ||
		snapshot.LocalQueued > snapshot.LocalLimit || snapshot.LocalTransactionalReserve == 0 ||
		snapshot.LocalTransactionalReserve >= snapshot.LocalLimit || snapshot.ObservedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type RouteRequest struct {
	TenantID TenantID
	DomainID DomainID
	MessageID MessageID
	Stream MailStream
	CampaignID CampaignID
	Suppression SuppressionSnapshot
	ExistingIdentity *MessageIdentity
	Capacity CapacitySnapshot
	Circuit CircuitSnapshot
	Now time.Time
}

type RouteDecision struct {
	Target RouteTarget
	BindingID BindingID
	BindingGeneration uint64
	Rule RouteRule
	Code string
	MustReconcile bool
	SuppressionGeneration uint64
	CircuitGeneration uint64
}

func EvaluateRoute(binding ProviderBinding, request RouteRequest) (RouteDecision, error) {
	decision := RouteDecision{Target: RouteReject, Code: "policy_denied"}
	if binding.Validate() != nil || request.TenantID != binding.TenantID || !validID(string(request.DomainID)) ||
		!validID(string(request.MessageID)) || request.Stream != StreamTransactional && request.Stream != StreamCampaign ||
		request.CampaignID != "" && (!validID(string(request.CampaignID)) || request.Stream != StreamCampaign) || request.Now.IsZero() ||
		request.Suppression.Validate(request.TenantID, request.MessageID) != nil || request.Capacity.Validate() != nil ||
		request.Circuit.Validate(binding.Policy) != nil {
		return decision, ErrInvalid
	}
	decision.SuppressionGeneration = request.Suppression.Generation
	decision.CircuitGeneration = request.Circuit.Generation
	if request.Suppression.Suppressed {
		decision.Code = "suppressed"
		return decision, ErrSuppressed
	}
	if request.ExistingIdentity != nil {
		identity := *request.ExistingIdentity
		if identity.Validate() != nil || identity.TenantID != request.TenantID || identity.MessageID != request.MessageID ||
			request.Suppression.Generation < identity.SuppressionGeneration {
			return decision, ErrConflict
		}
		decision.BindingID = identity.BindingID
		decision.BindingGeneration = identity.BindingGeneration
		decision.Target = RouteExternal
		switch identity.State {
		case SubmissionAccepted:
			decision.Target = RouteReject
			decision.Code = "already_accepted"
			return decision, nil
		case SubmissionAmbiguous:
			decision.Target = RouteReject
			decision.Code = "identity_pinned_reconcile"
			decision.MustReconcile = true
			return decision, ErrAmbiguous
		case SubmissionPending, SubmissionAbsent, SubmissionFailed:
			decision.Code = "identity_pinned"
			return decision, nil
		default:
			return decision, ErrConflict
		}
	}
	rule, found := selectRoute(binding.Routes, request.DomainID, request.Stream, request.CampaignID)
	if !found {
		decision.Code = "no_explicit_route"
		return decision, ErrDenied
	}
	decision.Rule = rule
	decision.BindingID = binding.ID
	decision.BindingGeneration = binding.Generation
	available := func(target RouteTarget) bool {
		switch target {
		case RouteExternal:
			if binding.Lifecycle != BindingEnabled || domainVerified(binding, request.DomainID) == false ||
				binding.Observation.Health == ProviderUnavailable || binding.Observation.Health == ProviderUnknown ||
				request.Now.After(binding.Observation.StaleAfter) || request.Circuit.State == CircuitOpen {
				return false
			}
			if request.Capacity.ExternalQueued >= request.Capacity.ExternalLimit {
				return false
			}
			if request.Stream == StreamCampaign && request.Capacity.ExternalLimit-request.Capacity.ExternalQueued <= binding.Policy.TransactionalReserve {
				return false
			}
			return true
		case RouteLocal:
			if request.Capacity.LocalQueued >= request.Capacity.LocalLimit {
				return false
			}
			if request.Stream == StreamCampaign && request.Capacity.LocalLimit-request.Capacity.LocalQueued <= request.Capacity.LocalTransactionalReserve {
				return false
			}
			return true
		default:
			return false
		}
	}
	if available(rule.Primary) {
		decision.Target = rule.Primary
		decision.Code = "primary"
		return decision, nil
	}
	fallback := RouteReject
	if rule.Fallback == FallbackToLocal {
		fallback = RouteLocal
	} else if rule.Fallback == FallbackExternal {
		fallback = RouteExternal
	}
	if fallback != RouteReject && available(fallback) {
		decision.Target = fallback
		decision.Code = "explicit_fallback"
		return decision, nil
	}
	decision.Code = "backpressure"
	return decision, ErrBackpressure
}

func domainVerified(binding ProviderBinding, domainID DomainID) bool {
	for _, domain := range binding.Domains {
		if domain.ID == domainID {
			return domain.Verification == VerificationVerified
		}
	}
	return false
}

func selectRoute(rules []RouteRule, domainID DomainID, stream MailStream, campaignID CampaignID) (RouteRule, bool) {
	best := -1
	var selected RouteRule
	for _, rule := range rules {
		if rule.Stream != stream || rule.DomainID != "" && rule.DomainID != domainID || rule.CampaignID != "" && rule.CampaignID != campaignID {
			continue
		}
		score := 0
		if rule.DomainID != "" {
			score += 2
		}
		if rule.CampaignID != "" {
			score += 4
		}
		if score > best {
			best = score
			selected = rule
		}
	}
	return selected, best >= 0
}

type ProviderSubmissionError interface {
	error
	MayHaveSubmitted() bool
}

type SubmissionResolution struct {
	Result SubmitResult
	QueriedBeforeSubmit bool
	Submitted bool
	NeedsReconciliation bool
}

// SubmitSafely performs at most one submit. An ambiguous prior attempt is
// queried first and is never resent unless the provider gives authoritative
// absence evidence. Unknown transport errors fail closed as ambiguous.
func SubmitSafely(ctx context.Context, adapter SubmissionAdapterV1, binding ProviderBinding, request SubmitRequest, prior *MessageIdentity) (SubmissionResolution, error) {
	resolution := SubmissionResolution{}
	if adapter == nil || binding.Validate() != nil || validateSubmitRequest(request) != nil || request.Envelope.TenantID != binding.TenantID {
		return resolution, ErrInvalid
	}
	if prior != nil {
		if prior.Validate() != nil || prior.TenantID != request.Envelope.TenantID || prior.MessageID != request.Envelope.MessageID ||
			prior.IdempotencyKey != request.Envelope.IdempotencyKey || prior.BindingID != binding.ID {
			return resolution, ErrConflict
		}
		if prior.State == SubmissionAccepted {
			resolution.Result = SubmitResult{State: SubmissionAccepted, ProviderMessageID: prior.ProviderMessageID, Code: "already_accepted"}
			return resolution, nil
		}
		if prior.State == SubmissionAmbiguous {
			resolution.QueriedBeforeSubmit = true
			query, err := adapter.QueryByIdempotency(ctx, binding, prior.IdempotencyKey)
			if err != nil {
				resolution.NeedsReconciliation = true
				resolution.Result = SubmitResult{State: SubmissionAmbiguous, Code: "query_failed", MayHaveSubmitted: true}
				return resolution, errors.Join(ErrAmbiguous, err)
			}
			if query.State == SubmissionAccepted && query.ProviderMessageID != "" {
				resolution.Result = SubmitResult{State: SubmissionAccepted, ProviderMessageID: query.ProviderMessageID, AcceptedAt: query.ObservedAt, Code: "reconciled"}
				return resolution, nil
			}
			if !query.AuthoritativeAbsence || query.State != SubmissionAbsent {
				resolution.NeedsReconciliation = true
				resolution.Result = SubmitResult{State: SubmissionAmbiguous, Code: "query_inconclusive", MayHaveSubmitted: true}
				return resolution, ErrAmbiguous
			}
		}
	}
	result, err := adapter.Submit(ctx, request)
	resolution.Submitted = true
	if err != nil {
		ambiguous := true
		var submissionError ProviderSubmissionError
		if errors.As(err, &submissionError) {
			ambiguous = submissionError.MayHaveSubmitted()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			ambiguous = true
		}
		if ambiguous {
			resolution.NeedsReconciliation = true
			resolution.Result = SubmitResult{State: SubmissionAmbiguous, Code: "submit_ambiguous", MayHaveSubmitted: true}
			return resolution, errors.Join(ErrAmbiguous, err)
		}
		resolution.Result = SubmitResult{State: SubmissionFailed, Code: "submit_failed"}
		return resolution, err
	}
	if result.MayHaveSubmitted || result.State == SubmissionAmbiguous {
		result.State = SubmissionAmbiguous
		result.MayHaveSubmitted = true
		resolution.Result = result
		resolution.NeedsReconciliation = true
		return resolution, ErrAmbiguous
	}
	if result.State != SubmissionAccepted || result.ProviderMessageID == "" || result.AcceptedAt.IsZero() || result.RetryAfter < 0 || len(result.Code) > 128 {
		resolution.Result = SubmitResult{State: SubmissionAmbiguous, Code: "invalid_provider_receipt", MayHaveSubmitted: true}
		resolution.NeedsReconciliation = true
		return resolution, ErrAmbiguous
	}
	resolution.Result = result
	return resolution, nil
}

func validateSubmitRequest(request SubmitRequest) error {
	envelope := request.Envelope
	if request.Content == nil || !validID(string(envelope.TenantID)) || !validID(string(envelope.DomainID)) ||
		!validID(string(envelope.MessageID)) || !validID(envelope.IdempotencyKey) ||
		envelope.Stream != StreamTransactional && envelope.Stream != StreamCampaign || envelope.CampaignID != "" && !validID(string(envelope.CampaignID)) ||
		envelope.Size <= 0 || envelope.Size > MaximumMessageBytes || len(envelope.Recipients) == 0 || len(envelope.Recipients) > MaximumRecipients {
		return ErrInvalid
	}
	return nil
}
