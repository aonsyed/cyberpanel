package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/maildelivery"
)

type MailDeliveryBindingPayload struct {
	Binding maildelivery.ProviderBinding `json:"binding"`
	Consent maildelivery.ConsentRequest `json:"consent"`
	StepUpProofDigest string `json:"step_up_proof_digest"`
}

type MailDeliveryDomainVerifyPayload struct {
	Plan maildelivery.DNSPlan `json:"plan"`
	StepUpProofDigest string `json:"step_up_proof_digest"`
}

type MailDeliveryRoutePayload struct {
	DomainID maildelivery.DomainID `json:"domain_id"`
	MessageID maildelivery.MessageID `json:"message_id"`
	Stream maildelivery.MailStream `json:"stream"`
	CampaignID maildelivery.CampaignID `json:"campaign_id,omitempty"`
}

type MailDeliveryRouteResult struct {
	Target maildelivery.RouteTarget `json:"target"`
	BindingID maildelivery.BindingID `json:"binding_id"`
	BindingGeneration uint64 `json:"binding_generation"`
	Rule maildelivery.RouteRule `json:"rule"`
	Code string `json:"code"`
	MustReconcile bool `json:"must_reconcile"`
	SuppressionGeneration uint64 `json:"suppression_generation"`
	CircuitGeneration uint64 `json:"circuit_generation"`
}

type MailDeliveryRotatePayload struct {
	Desired maildelivery.ProviderBinding `json:"desired"`
	OverlapSeconds uint32 `json:"overlap_seconds"`
	RelaySpec maildelivery.PostfixRelaySpec `json:"relay_spec"`
	ExpectedActiveRelayGeneration string `json:"expected_active_relay_generation,omitempty"`
	StepUpProofDigest string `json:"step_up_proof_digest"`
}

type MailDeliveryStatusPayload struct {
	EventLimit uint16 `json:"event_limit,omitempty"`
	Before time.Time `json:"before,omitempty"`
}

type MailDeliveryRelayStatusPayload struct {
	Generation maildelivery.PostfixRelayGeneration `json:"generation"`
}

func registerMailDeliveryContracts(registry *Registry) error {
	manage := identity.MustPermission("mail:manage")
	definitions := []Operation{
		{Name: "mail.delivery.binding.put", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true,
			NewPayload: func() any { return &MailDeliveryBindingPayload{} }, ValidatePayload: validateMailDeliveryBinding, ResolveScope: mailDeliveryMutationScope},
		{Name: "mail.delivery.binding.get", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired,
			NewPayload: func() any { return &EmptyPayload{} }, ResolveScope: mailDeliveryReadScope},
		{Name: "mail.delivery.domain.verify", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true,
			NewPayload: func() any { return &MailDeliveryDomainVerifyPayload{} }, ValidatePayload: validateMailDeliveryDomainVerify, ResolveScope: mailDeliveryExistingScope},
		{Name: "mail.delivery.route.evaluate", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired,
			NewPayload: func() any { return &MailDeliveryRoutePayload{} }, ValidatePayload: validateMailDeliveryRoute, ResolveScope: mailDeliveryReadScope},
		{Name: "mail.delivery.credential.rotate", Permission: manage, Assurance: identity.AssuranceMFA, Auth: AuthRequired, Mutating: true,
			NewPayload: func() any { return &MailDeliveryRotatePayload{} }, ValidatePayload: validateMailDeliveryRotate, ResolveScope: mailDeliveryRotationScope},
		{Name: "mail.delivery.events.list", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired,
			NewPayload: func() any { return &MailDeliveryStatusPayload{} }, ValidatePayload: validateMailDeliveryStatus, ResolveScope: mailDeliveryReadScope},
		{Name: "mail.delivery.status", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired,
			NewPayload: func() any { return &MailDeliveryStatusPayload{} }, ValidatePayload: validateMailDeliveryStatus, ResolveScope: mailDeliveryReadScope},
		{Name: "mail.delivery.relay.status", Permission: manage, Assurance: identity.AssurancePassword, Auth: AuthRequired,
			NewPayload: func() any { return &MailDeliveryRelayStatusPayload{} }, ValidatePayload: validateMailDeliveryRelayStatus, ResolveScope: mailDeliveryReadScope},
	}
	for _, definition := range definitions {
		if err := register(registry, definition); err != nil {
			return err
		}
	}
	return nil
}

func bindMailDelivery(registry *Registry, services DomainServices) error {
	service := services.MailDelivery
	if service == nil {
		return nil
	}
	if err := registry.Bind("mail.delivery.binding.put", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		payload := value.(*MailDeliveryBindingPayload)
		operation := mailDeliveryOperation(invocation, payload.StepUpProofDigest)
		binding, err := service.PutBinding(ctx, maildelivery.PutBindingCommand{Operation: operation, Binding: payload.Binding,
			ExpectedGeneration: invocation.Request.ExpectedGeneration, Consent: payload.Consent})
		if err != nil {
			return OperationResult{}, mapMailDeliveryError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: binding, Generation: binding.Generation}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("mail.delivery.binding.get", func(ctx context.Context, invocation Invocation, _ any) (OperationResult, error) {
		status, err := service.Status(ctx, mailDeliveryOperation(invocation, ""), maildelivery.BindingID(invocation.Request.ResourceID), 0, time.Time{})
		if err != nil {
			return OperationResult{}, mapMailDeliveryError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: status.Binding, Generation: status.Binding.Generation}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("mail.delivery.domain.verify", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		payload := value.(*MailDeliveryDomainVerifyPayload)
		binding, plan, err := service.VerifyDomain(ctx, maildelivery.VerifyDomainCommand{Operation: mailDeliveryOperation(invocation, payload.StepUpProofDigest),
			BindingID: maildelivery.BindingID(invocation.Request.ResourceID), ExpectedGeneration: invocation.Request.ExpectedGeneration, Plan: payload.Plan})
		if err != nil {
			return OperationResult{}, mapMailDeliveryError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: map[string]any{"binding": binding, "dns_plan": plan}, Generation: binding.Generation}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("mail.delivery.route.evaluate", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		payload := value.(*MailDeliveryRoutePayload)
		decision, err := service.Route(ctx, maildelivery.RouteCommand{Operation: mailDeliveryOperation(invocation, ""),
			BindingID: maildelivery.BindingID(invocation.Request.ResourceID), DomainID: payload.DomainID, MessageID: payload.MessageID,
			Stream: payload.Stream, CampaignID: payload.CampaignID})
		if err != nil && !errors.Is(err, maildelivery.ErrAmbiguous) {
			return OperationResult{}, mapMailDeliveryError(err)
		}
		result := MailDeliveryRouteResult{Target: decision.Target, BindingID: decision.BindingID, BindingGeneration: decision.BindingGeneration,
			Rule: decision.Rule, Code: decision.Code, MustReconcile: decision.MustReconcile,
			SuppressionGeneration: decision.SuppressionGeneration, CircuitGeneration: decision.CircuitGeneration}
		return OperationResult{Status: http.StatusOK, Value: result}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("mail.delivery.credential.rotate", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		payload := value.(*MailDeliveryRotatePayload)
		result, err := service.RotateCredential(ctx, maildelivery.RotateCredentialCommand{Operation: mailDeliveryOperation(invocation, payload.StepUpProofDigest),
			BindingID: maildelivery.BindingID(invocation.Request.ResourceID), ExpectedGeneration: invocation.Request.ExpectedGeneration,
			Desired: payload.Desired, Overlap: time.Duration(payload.OverlapSeconds) * time.Second, RelaySpec: payload.RelaySpec,
			ExpectedActiveRelayGeneration: payload.ExpectedActiveRelayGeneration})
		if err != nil {
			return OperationResult{}, mapMailDeliveryError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: result, Generation: result.Binding.Generation}, nil
	}); err != nil {
		return err
	}
	statusHandler := func(eventsOnly bool) OperationHandler {
		return func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
			payload := value.(*MailDeliveryStatusPayload)
			status, err := service.Status(ctx, mailDeliveryOperation(invocation, ""), maildelivery.BindingID(invocation.Request.ResourceID), payload.EventLimit, payload.Before)
			if err != nil {
				return OperationResult{}, mapMailDeliveryError(err)
			}
			if eventsOnly {
				return OperationResult{Status: http.StatusOK, Value: status.Events, Generation: status.Binding.Generation}, nil
			}
			return OperationResult{Status: http.StatusOK, Value: status, Generation: status.Binding.Generation}, nil
		}
	}
	if err := registry.Bind("mail.delivery.events.list", statusHandler(true)); err != nil {
		return err
	}
	if err := registry.Bind("mail.delivery.status", statusHandler(false)); err != nil {
		return err
	}
	return registry.Bind("mail.delivery.relay.status", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		observation, err := service.ReconcileRelay(ctx, mailDeliveryOperation(invocation, ""), maildelivery.BindingID(invocation.Request.ResourceID),
			value.(*MailDeliveryRelayStatusPayload).Generation)
		if err != nil {
			return OperationResult{}, mapMailDeliveryError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: observation}, nil
	})
}

func validateMailDeliveryBinding(value any) error {
	payload := value.(*MailDeliveryBindingPayload)
	if payload.Binding.Validate() != nil || payload.Consent.Validate() != nil || !validDigestReference(payload.StepUpProofDigest) ||
		payload.Consent.TenantID != payload.Binding.TenantID || payload.Consent.BindingID != payload.Binding.ID ||
		payload.Consent.Revision != payload.Binding.ConsentRevision {
		return invalid("mail delivery binding")
	}
	return nil
}

func validateMailDeliveryDomainVerify(value any) error {
	payload := value.(*MailDeliveryDomainVerifyPayload)
	if payload.Plan.Validate() != nil || !validDigestReference(payload.StepUpProofDigest) {
		return invalid("mail delivery domain verification")
	}
	return nil
}

func validateMailDeliveryRoute(value any) error {
	payload := value.(*MailDeliveryRoutePayload)
	if !safeMailOpaque(string(payload.DomainID)) || !safeMailOpaque(string(payload.MessageID)) ||
		payload.Stream != maildelivery.StreamTransactional && payload.Stream != maildelivery.StreamCampaign ||
		payload.CampaignID != "" && !safeMailOpaque(string(payload.CampaignID)) {
		return invalid("mail delivery route")
	}
	return nil
}

func validateMailDeliveryRotate(value any) error {
	payload := value.(*MailDeliveryRotatePayload)
	if payload.OverlapSeconds < 60 || payload.OverlapSeconds > 30*24*60*60 || payload.Desired.Validate() != nil ||
		payload.Desired.Adapter.Kind == maildelivery.LocalSMTPAdapterKind && payload.RelaySpec.Validate() != nil ||
		!validDigestReference(payload.StepUpProofDigest) ||
		payload.ExpectedActiveRelayGeneration != "" && !safeMailOpaque(payload.ExpectedActiveRelayGeneration) {
		return invalid("mail delivery credential rotation")
	}
	return nil
}

func validateMailDeliveryStatus(value any) error {
	payload := value.(*MailDeliveryStatusPayload)
	if payload.EventLimit > 500 || !payload.Before.IsZero() && payload.Before.After(time.Now().UTC().Add(time.Minute)) {
		return invalid("mail delivery status")
	}
	return nil
}

func validateMailDeliveryRelayStatus(value any) error {
	if value.(*MailDeliveryRelayStatusPayload).Generation.Validate() != nil {
		return invalid("mail delivery relay generation")
	}
	return nil
}

func mailDeliveryMutationScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !safeMailOpaque(request.ResourceID) {
		return identity.Scope{}, invalid("mail delivery binding scope")
	}
	payload := value.(*MailDeliveryBindingPayload)
	if string(payload.Binding.ID) != request.ResourceID || payload.Binding.Generation != request.ExpectedGeneration+1 {
		return identity.Scope{}, invalid("mail delivery binding generation")
	}
	return tenantScope(request, value)
}

func mailDeliveryExistingScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !safeMailOpaque(request.ResourceID) || request.ExpectedGeneration == 0 {
		return identity.Scope{}, invalid("mail delivery generation")
	}
	return tenantScope(request, value)
}

func mailDeliveryRotationScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !safeMailOpaque(request.ResourceID) || request.ExpectedGeneration == 0 || request.ExpectedGeneration > ^uint64(0)-2 {
		return identity.Scope{}, invalid("mail delivery rotation generation")
	}
	payload := value.(*MailDeliveryRotatePayload)
	if string(payload.Desired.ID) != request.ResourceID || payload.Desired.Generation != request.ExpectedGeneration+2 ||
		payload.Desired.Adapter.Kind == maildelivery.LocalSMTPAdapterKind && payload.RelaySpec.Generation != request.ExpectedGeneration+1 {
		return identity.Scope{}, invalid("mail delivery rotation binding")
	}
	return tenantScope(request, value)
}

func mailDeliveryReadScope(request RequestEnvelope, value any) (identity.Scope, error) {
	if !safeMailOpaque(request.ResourceID) || request.ExpectedGeneration != 0 {
		return identity.Scope{}, invalid("mail delivery read scope")
	}
	return tenantScope(request, value)
}

func mailDeliveryOperation(invocation Invocation, stepUp string) maildelivery.OperationContext {
	hash := sha256.New()
	for _, value := range []string{invocation.Request.Operation, invocation.Request.RequestID, invocation.Request.TenantID,
		invocation.Request.ResourceID, strconv.FormatUint(invocation.Request.ExpectedGeneration, 10), invocation.Actor.PrincipalID.String(),
		invocation.IdempotencyKey, string(invocation.Request.Payload)} {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	return maildelivery.OperationContext{Actor: maildelivery.ActorID(invocation.Actor.PrincipalID.String()), TenantID: maildelivery.TenantID(invocation.Request.TenantID),
		AuthorizationEpoch: invocation.Actor.AuthzEpoch, IntentDigest: hex.EncodeToString(hash.Sum(nil)), StepUpProofDigest: stepUp, At: time.Now().UTC()}
}

func mapMailDeliveryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, maildelivery.ErrInvalid):
		return ErrInvalidRequest
	case errors.Is(err, maildelivery.ErrDenied), errors.Is(err, maildelivery.ErrSuppressed):
		return ErrForbidden
	case errors.Is(err, maildelivery.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, maildelivery.ErrConflict), errors.Is(err, maildelivery.ErrStale):
		return ErrConflict
	case errors.Is(err, maildelivery.ErrBackpressure):
		return ErrRateLimited
	case errors.Is(err, maildelivery.ErrUnavailable), errors.Is(err, maildelivery.ErrAmbiguous), errors.Is(err, maildelivery.ErrWebhookRejected):
		return ErrUnavailable
	default:
		return err
	}
}
