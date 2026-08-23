package maildelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

const LocalSMTPAdapterKind = "local_smtp"

type OperationContext struct {
	Actor ActorID
	TenantID TenantID
	AuthorizationEpoch uint64
	IntentDigest string
	StepUpProofDigest string
	At time.Time
}

func (operation OperationContext) Validate() error {
	if !validID(string(operation.Actor)) || !validID(string(operation.TenantID)) || operation.AuthorizationEpoch == 0 ||
		!validDigest(operation.IntentDigest) || operation.StepUpProofDigest != "" && !validDigest(operation.StepUpProofDigest) || operation.At.IsZero() {
		return ErrInvalid
	}
	return nil
}

type ProviderResolver interface {
	ResolveMailDeliveryProvider(context.Context, ProviderAdapterRef) (ProviderAdapterV1, error)
}

type DomainVerifier interface {
	VerifyDomain(context.Context, DomainVerificationRequest) (DomainVerificationResult, error)
}

type CredentialLifecycle interface {
	RotateCredential(context.Context, CredentialRotationRequest) (CredentialRotation, error)
	RevokeCredential(context.Context, ProviderBinding, uint64) (CredentialRevocation, error)
}

// LocalSMTPCredentialLifecycle records a prepared overlap. The relay activation
// consumes the new encrypted reference; revocation stays unavailable unless a
// secret authority is explicitly supplied by the deployment.
type LocalSMTPCredentialLifecycle struct{}

func (LocalSMTPCredentialLifecycle) RotateCredential(_ context.Context, request CredentialRotationRequest) (CredentialRotation, error) {
	if request.Binding.Validate() != nil || request.Binding.Adapter.Kind != LocalSMTPAdapterKind || request.Rotation.Validate() != nil ||
		request.Rotation.BindingID != request.Binding.ID || request.Rotation.TenantID != request.Binding.TenantID ||
		request.Rotation.OldVersion != request.Binding.Credential.Version || request.Rotation.State != RotationPrepared {
		return CredentialRotation{}, ErrInvalid
	}
	return request.Rotation, nil
}

func (LocalSMTPCredentialLifecycle) RevokeCredential(context.Context, ProviderBinding, uint64) (CredentialRevocation, error) {
	return CredentialRevocation{}, ErrUnavailable
}

type SuppressionReader interface {
	CurrentSuppression(context.Context, TenantID, MessageID) (SuppressionSnapshot, error)
}

type RoutingRuntime interface {
	MailDeliveryRuntime(context.Context, ProviderBinding, MailStream) (CapacitySnapshot, CircuitSnapshot, error)
	CommitMailDeliveryCircuit(context.Context, BindingID, uint64, CircuitSnapshot) error
}

type LocalBindingResolver interface {
	ResolveLocalMailDeliveryBinding(context.Context, TenantID, DomainID) (ProviderBinding, error)
}

type ProviderEventReader interface {
	ListProviderEvents(context.Context, TenantID, BindingID, time.Time, uint16) ([]NormalizedProviderEvent, error)
}

type ServiceConfig struct {
	Repository Repository
	Authorizer Authorizer
	StepUp StepUpVerifier
	Consent ConsentVerifier
	Audit AuditSink
	Providers ProviderResolver
	LocalDomainVerifier DomainVerifier
	LocalCredentials CredentialLifecycle
	LocalSMTP SubmissionAdapterV1
	LocalBindings LocalBindingResolver
	Suppressions SuppressionReader
	Runtime RoutingRuntime
	Relay PostfixRelayController
	Webhook WebhookVerifier
	Now func() time.Time
}

type Service struct {
	repository Repository
	authorizer Authorizer
	stepUp StepUpVerifier
	consent ConsentVerifier
	audit AuditSink
	providers ProviderResolver
	localDomainVerifier DomainVerifier
	localCredentials CredentialLifecycle
	localSMTP SubmissionAdapterV1
	localBindings LocalBindingResolver
	suppressions SuppressionReader
	runtime RoutingRuntime
	relay PostfixRelayController
	webhook WebhookVerifier
	now func() time.Time
}

func NewService(configuration ServiceConfig) (*Service, error) {
	if configuration.Repository == nil || configuration.Authorizer == nil || configuration.StepUp == nil ||
		configuration.Consent == nil || configuration.Audit == nil {
		return nil, ErrInvalid
	}
	if configuration.Now == nil {
		configuration.Now = time.Now
	}
	return &Service{repository: configuration.Repository, authorizer: configuration.Authorizer, stepUp: configuration.StepUp,
		consent: configuration.Consent, audit: configuration.Audit, providers: configuration.Providers,
		localDomainVerifier: configuration.LocalDomainVerifier, localCredentials: configuration.LocalCredentials,
		localSMTP: configuration.LocalSMTP, localBindings: configuration.LocalBindings, suppressions: configuration.Suppressions,
		runtime: configuration.Runtime, relay: configuration.Relay, webhook: configuration.Webhook, now: configuration.Now}, nil
}

func (service *Service) Bootstrap(ctx context.Context) error {
	if service == nil {
		return ErrInvalid
	}
	return service.repository.Bootstrap(ctx)
}

type PutBindingCommand struct {
	Operation OperationContext
	Binding ProviderBinding
	ExpectedGeneration uint64
	Consent ConsentRequest
}

func (service *Service) PutBinding(ctx context.Context, command PutBindingCommand) (ProviderBinding, error) {
	if service == nil || command.Operation.Validate() != nil || command.Binding.Validate() != nil || command.Consent.Validate() != nil ||
		command.Binding.TenantID != command.Operation.TenantID || command.Binding.Generation != command.ExpectedGeneration+1 ||
		command.Consent.TenantID != command.Binding.TenantID || command.Consent.BindingID != command.Binding.ID ||
		command.Consent.Revision != command.Binding.ConsentRevision {
		return ProviderBinding{}, ErrInvalid
	}
	if err := service.authorize(ctx, command.Operation, command.Binding.ID, AuthorizeBindingWrite, true); err != nil {
		return ProviderBinding{}, err
	}
	if err := service.consent.VerifyMailDeliveryConsent(ctx, command.Consent); err != nil {
		return ProviderBinding{}, errors.Join(ErrDenied, err)
	}
	if err := service.repository.PutBinding(ctx, command.Binding, command.ExpectedGeneration); err != nil {
		return ProviderBinding{}, err
	}
	if err := service.record(ctx, command.Operation, command.Binding.ID, AuthorizeBindingWrite, string(command.Binding.ID), command.Binding.Generation, "applied"); err != nil {
		return command.Binding, errors.Join(ErrAmbiguous, err)
	}
	return command.Binding, nil
}

type VerifyDomainCommand struct {
	Operation OperationContext
	BindingID BindingID
	ExpectedGeneration uint64
	Plan DNSPlan
}

func (service *Service) VerifyDomain(ctx context.Context, command VerifyDomainCommand) (ProviderBinding, DNSPlan, error) {
	if service == nil || command.Operation.Validate() != nil || !validID(string(command.BindingID)) || command.ExpectedGeneration == 0 ||
		command.Plan.Validate() != nil || command.Plan.TenantID != command.Operation.TenantID || command.Plan.BindingID != command.BindingID ||
		command.Plan.BindingGeneration != command.ExpectedGeneration {
		return ProviderBinding{}, DNSPlan{}, ErrInvalid
	}
	if err := service.authorize(ctx, command.Operation, command.BindingID, AuthorizeDNSPlanWrite, true); err != nil {
		return ProviderBinding{}, DNSPlan{}, err
	}
	binding, err := service.repository.LoadBinding(ctx, command.Operation.TenantID, command.BindingID)
	if err != nil || binding.Generation != command.ExpectedGeneration {
		if err == nil {
			err = ErrStale
		}
		return ProviderBinding{}, DNSPlan{}, err
	}
	domain, index, found := bindingDomain(binding, command.Plan.DomainID)
	if !found || domain.Name != command.Plan.Domain {
		return ProviderBinding{}, DNSPlan{}, ErrConflict
	}
	verifier, err := service.domainVerifier(ctx, binding)
	if err != nil {
		return ProviderBinding{}, DNSPlan{}, err
	}
	result, err := verifier.VerifyDomain(ctx, DomainVerificationRequest{Binding: binding, Domain: domain, Plan: command.Plan})
	if err != nil {
		return ProviderBinding{}, DNSPlan{}, err
	}
	if result.State != VerificationPending && result.State != VerificationVerified && result.State != VerificationDrifted && result.State != VerificationFailed ||
		result.ObservedAt.IsZero() || result.State == VerificationVerified && !validDigest(result.EvidenceDigest) {
		return ProviderBinding{}, DNSPlan{}, ErrConflict
	}
	plan := command.Plan
	plan.State = result.State
	plan.EvidenceDigest = result.EvidenceDigest
	plan.ObservedAt = result.ObservedAt.UTC()
	if err = service.repository.AppendDNSPlan(ctx, plan); err != nil {
		return ProviderBinding{}, DNSPlan{}, err
	}
	binding.Domains[index].ActiveDNSPlanID = plan.ID
	binding.Domains[index].Verification = result.State
	binding.Domains[index].LastCheckedAt = result.ObservedAt.UTC()
	binding.Domains[index].VerificationDigest = result.EvidenceDigest
	binding.Domains[index].VerifiedAt = time.Time{}
	if result.State == VerificationVerified {
		binding.Domains[index].VerifiedAt = result.ObservedAt.UTC()
	}
	binding.Generation++
	binding.UpdatedAt = service.currentTime()
	if err = service.repository.PutBinding(ctx, binding, command.ExpectedGeneration); err != nil {
		return ProviderBinding{}, plan, errors.Join(ErrAmbiguous, err)
	}
	if err = service.record(ctx, command.Operation, binding.ID, AuthorizeDNSPlanWrite, string(plan.ID), binding.Generation, string(result.State)); err != nil {
		return binding, plan, errors.Join(ErrAmbiguous, err)
	}
	return binding, plan, nil
}

type RouteCommand struct {
	Operation OperationContext
	BindingID BindingID
	DomainID DomainID
	MessageID MessageID
	Stream MailStream
	CampaignID CampaignID
}

func (service *Service) Route(ctx context.Context, command RouteCommand) (RouteDecision, error) {
	if service == nil || command.Operation.Validate() != nil || !validID(string(command.BindingID)) || !validID(string(command.DomainID)) ||
		!validID(string(command.MessageID)) || command.Stream != StreamTransactional && command.Stream != StreamCampaign {
		return RouteDecision{}, ErrInvalid
	}
	if err := service.authorize(ctx, command.Operation, command.BindingID, AuthorizeRouteEvaluate, false); err != nil {
		return RouteDecision{}, err
	}
	binding, request, err := service.routingRequest(ctx, command)
	if err != nil {
		return RouteDecision{}, err
	}
	return EvaluateRoute(binding, request)
}

type SubmitCommand struct {
	Route RouteCommand
	Envelope SubmitEnvelope
	Content io.Reader
}

type DeliverySubmission struct {
	Decision RouteDecision `json:"decision"`
	Identity MessageIdentity `json:"identity"`
	Resolution SubmissionResolution `json:"resolution"`
}

func (service *Service) Submit(ctx context.Context, command SubmitCommand) (DeliverySubmission, error) {
	var submission DeliverySubmission
	if service == nil || command.Route.Operation.Validate() != nil || command.Content == nil || command.Envelope.TenantID != command.Route.Operation.TenantID ||
		command.Envelope.DomainID != command.Route.DomainID || command.Envelope.MessageID != command.Route.MessageID ||
		command.Envelope.Stream != command.Route.Stream || command.Envelope.CampaignID != command.Route.CampaignID {
		return submission, ErrInvalid
	}
	if err := service.authorize(ctx, command.Route.Operation, command.Route.BindingID, AuthorizeSubmit, false); err != nil {
		return submission, err
	}
	binding, routeRequest, err := service.routingRequest(ctx, command.Route)
	if err != nil {
		return submission, err
	}
	decision, routeErr := EvaluateRoute(binding, routeRequest)
	submission.Decision = decision
	if routeErr != nil && !errors.Is(routeErr, ErrAmbiguous) {
		return submission, routeErr
	}
	if decision.Code == "already_accepted" && routeRequest.ExistingIdentity != nil {
		submission.Identity = *routeRequest.ExistingIdentity
		return submission, nil
	}
	targetBinding, adapter, err := service.submissionAdapter(ctx, binding, command.Route.DomainID, decision, routeRequest.ExistingIdentity)
	if err != nil {
		return submission, err
	}
	identity := routeRequest.ExistingIdentity
	if identity == nil {
		created := MessageIdentity{TenantID: command.Envelope.TenantID, MessageID: command.Envelope.MessageID,
			IdempotencyKey: command.Envelope.IdempotencyKey, BindingID: targetBinding.ID, BindingGeneration: targetBinding.Generation,
			State: SubmissionPending, SuppressionGeneration: routeRequest.Suppression.Generation, Generation: 1, UpdatedAt: service.currentTime()}
		if err = service.repository.PutMessageIdentity(ctx, created, 0); err != nil {
			return submission, err
		}
		identity = &created
	}
	request := SubmitRequest{Envelope: command.Envelope, Content: command.Content}
	resolution, submitErr := SubmitSafely(ctx, adapter, targetBinding, request, identity)
	updated := *identity
	updated.Generation++
	updated.UpdatedAt = service.currentTime()
	updated.State = resolution.Result.State
	updated.ProviderMessageID = resolution.Result.ProviderMessageID
	if updated.State == "" {
		updated.State = SubmissionAmbiguous
	}
	if err = service.repository.PutMessageIdentity(ctx, updated, identity.Generation); err != nil {
		return submission, errors.Join(ErrAmbiguous, submitErr, err)
	}
	submission.Identity = updated
	submission.Resolution = resolution
	if resolution.NeedsReconciliation {
		policy := targetBinding.Policy.Transactional
		if command.Envelope.Stream == StreamCampaign {
			policy = targetBinding.Policy.Campaign
		}
		queueTime := service.currentTime()
		queue := ReconciliationItem{ID: QueueID(derivedID("reconcile", string(updated.TenantID), string(updated.MessageID))),
			TenantID: updated.TenantID, MessageID: updated.MessageID, BindingID: updated.BindingID, Stream: command.Envelope.Stream,
			State: QueueWaiting, Generation: 1, NotBefore: queueTime, ExpiresAt: queueTime.Add(policy.QueueRetention),
			CreatedAt: queueTime, UpdatedAt: queueTime, LastCode: resolution.Result.Code}
		if enqueueErr := service.repository.EnqueueReconciliation(ctx, queue, policy.QueueLimit); enqueueErr != nil && !errors.Is(enqueueErr, ErrConflict) {
			return submission, errors.Join(ErrAmbiguous, submitErr, enqueueErr)
		}
	}
	outcome := CircuitSucceeded
	if submitErr != nil {
		outcome = CircuitFailed
		if errors.Is(submitErr, ErrAmbiguous) {
			outcome = CircuitAmbiguous
		}
	}
	var circuitErr error
	if decision.Target == RouteExternal && targetBinding.ID == binding.ID {
		var nextCircuit CircuitSnapshot
		nextCircuit, circuitErr = RecordCircuitOutcome(routeRequest.Circuit, binding.Policy, outcome, service.currentTime())
		if circuitErr == nil {
			circuitErr = service.runtime.CommitMailDeliveryCircuit(ctx, binding.ID, routeRequest.Circuit.Generation, nextCircuit)
		}
	}
	auditErr := service.record(ctx, command.Route.Operation, updated.BindingID, AuthorizeSubmit, string(updated.MessageID), updated.Generation, string(updated.State))
	if submitErr != nil || circuitErr != nil || auditErr != nil {
		if circuitErr != nil {
			circuitErr = errors.Join(ErrAmbiguous, circuitErr)
		}
		if auditErr != nil {
			auditErr = errors.Join(ErrAmbiguous, auditErr)
		}
		return submission, errors.Join(submitErr, circuitErr, auditErr)
	}
	return submission, nil
}

type RotateCredentialCommand struct {
	Operation OperationContext
	BindingID BindingID
	ExpectedGeneration uint64
	Desired ProviderBinding
	Overlap time.Duration
	RelaySpec PostfixRelaySpec
	ExpectedActiveRelayGeneration string
}

type RotationResult struct {
	Binding ProviderBinding `json:"binding"`
	Rotation CredentialRotation `json:"rotation"`
	Generation PostfixRelayGeneration `json:"relay_generation,omitempty"`
	Stage PostfixRelayStageReceipt `json:"relay_stage,omitempty"`
	Validation PostfixRelayValidationReceipt `json:"relay_validation,omitempty"`
	Activation PostfixRelayActivationReceipt `json:"relay_activation,omitempty"`
}

func (service *Service) RotateCredential(ctx context.Context, command RotateCredentialCommand) (RotationResult, error) {
	var result RotationResult
	if service == nil || command.Operation.Validate() != nil || !validID(string(command.BindingID)) || command.ExpectedGeneration == 0 ||
		command.Desired.Validate() != nil || command.Desired.ID != command.BindingID || command.Desired.TenantID != command.Operation.TenantID ||
		command.ExpectedGeneration > ^uint64(0)-2 || command.Desired.Generation != command.ExpectedGeneration+2 ||
		command.Overlap < time.Minute || command.Overlap > 30*24*time.Hour {
		return result, ErrInvalid
	}
	if err := service.authorize(ctx, command.Operation, command.BindingID, AuthorizeCredentialRotate, true); err != nil {
		return result, err
	}
	current, err := service.repository.LoadBinding(ctx, command.Operation.TenantID, command.BindingID)
	if err != nil || current.Generation != command.ExpectedGeneration || command.Desired.Credential.Version <= current.Credential.Version ||
		command.Desired.Credential.Version > ^uint64(0)/2 ||
		command.Desired.CreatedAt != current.CreatedAt || command.Desired.Adapter != current.Adapter ||
		command.Desired.Lifecycle != BindingEnabled && command.Desired.Lifecycle != BindingDisabled {
		if err == nil {
			err = ErrStale
		}
		return result, err
	}
	rotating := command.Desired
	rotating.Generation = command.ExpectedGeneration + 1
	rotating.Lifecycle = BindingRotating
	rotating.UpdatedAt = service.currentTime()
	if rotating.Validate() != nil || current.Adapter.Kind == LocalSMTPAdapterKind && (command.RelaySpec.Validate() != nil ||
		command.RelaySpec.BindingID != rotating.ID || command.RelaySpec.TenantID != rotating.TenantID ||
		command.RelaySpec.Generation != rotating.Generation || command.RelaySpec.Credential != rotating.Credential) {
		return result, ErrInvalid
	}
	lifecycle, err := service.credentialLifecycle(ctx, current)
	if err != nil {
		return result, err
	}
	if current.Adapter.Kind == LocalSMTPAdapterKind && service.relay == nil {
		return result, ErrUnavailable
	}
	if err = service.repository.PutBinding(ctx, rotating, command.ExpectedGeneration); err != nil {
		return result, err
	}
	result.Binding = rotating
	prepared := CredentialRotation{ID: derivedID("rotation", string(rotating.ID), command.Operation.IntentDigest), BindingID: rotating.ID,
		TenantID: rotating.TenantID, Sequence: rotating.Credential.Version*2 - 1, OldVersion: current.Credential.Version, NewVersion: rotating.Credential.Version,
		OverlapUntil: service.currentTime().Add(command.Overlap), State: RotationPrepared, OccurredAt: service.currentTime()}
	rotation, err := lifecycle.RotateCredential(ctx, CredentialRotationRequest{Binding: current, Rotation: prepared})
	if err != nil || rotation.Validate() != nil || rotation.BindingID != current.ID || rotation.TenantID != current.TenantID ||
		rotation.ID != prepared.ID || rotation.Sequence != prepared.Sequence || rotation.OldVersion != current.Credential.Version ||
		rotation.NewVersion != rotating.Credential.Version || rotation.OverlapUntil != prepared.OverlapUntil {
		return result, errors.Join(ErrAmbiguous, err)
	}
	result.Rotation = rotation
	if err = service.repository.AppendCredentialRotation(ctx, rotation); err != nil {
		return result, errors.Join(ErrAmbiguous, err)
	}
	if current.Adapter.Kind == LocalSMTPAdapterKind {
		result.Generation, err = service.relay.RenderPostfixRelay(ctx, command.RelaySpec)
		if err == nil {
			result.Stage, err = service.relay.StagePostfixRelay(ctx, result.Generation)
		}
		if err == nil {
			result.Validation, err = service.relay.ValidatePostfixRelay(ctx, result.Generation, result.Stage)
		}
		if err == nil {
			result.Activation, err = service.relay.ActivatePostfixRelay(ctx, result.Generation, result.Stage, result.Validation, command.ExpectedActiveRelayGeneration)
		}
		if err != nil {
			return result, err
		}
		reloaded := rotation
		reloaded.ID = RotationID(derivedID("rotation", string(rotating.ID), command.Operation.IntentDigest, "reloaded"))
		reloaded.Sequence++
		reloaded.State = RotationReloaded
		reloaded.ReloadReceiptDigest = result.Activation.ActivationDigest
		reloaded.OccurredAt = service.currentTime()
		if reloaded.Validate() != nil {
			return result, ErrConflict
		}
		if err = service.repository.AppendCredentialRotation(ctx, reloaded); err != nil {
			return result, errors.Join(ErrAmbiguous, err)
		}
		result.Rotation = reloaded
	}
	final := rotating
	final.Generation++
	final.Lifecycle = command.Desired.Lifecycle
	final.UpdatedAt = service.currentTime()
	if err = service.repository.PutBinding(ctx, final, rotating.Generation); err != nil {
		return result, errors.Join(ErrAmbiguous, err)
	}
	result.Binding = final
	if err = service.record(ctx, command.Operation, final.ID, AuthorizeCredentialRotate, string(result.Rotation.ID), final.Generation, "activated"); err != nil {
		return result, errors.Join(ErrAmbiguous, err)
	}
	return result, nil
}

type ProviderStatus struct {
	Binding ProviderBinding `json:"binding"`
	DNSPlans []DNSPlan `json:"dns_plans"`
	Events []NormalizedProviderEvent `json:"events,omitempty"`
}

func (service *Service) Status(ctx context.Context, operation OperationContext, bindingID BindingID, eventLimit uint16, before time.Time) (ProviderStatus, error) {
	var status ProviderStatus
	if service == nil || operation.Validate() != nil || !validID(string(bindingID)) || eventLimit > 500 {
		return status, ErrInvalid
	}
	if err := service.authorize(ctx, operation, bindingID, AuthorizeInspect, false); err != nil {
		return status, err
	}
	binding, err := service.repository.LoadBinding(ctx, operation.TenantID, bindingID)
	if err != nil {
		return status, err
	}
	status.Binding = binding
	for _, domain := range binding.Domains {
		plan, loadErr := service.repository.LoadDNSPlan(ctx, operation.TenantID, domain.ActiveDNSPlanID)
		if errors.Is(loadErr, ErrNotFound) && domain.Verification == VerificationPending {
			continue
		}
		if loadErr != nil {
			return status, loadErr
		}
		status.DNSPlans = append(status.DNSPlans, plan)
	}
	if eventLimit > 0 {
		reader, ok := service.repository.(ProviderEventReader)
		if !ok {
			return status, ErrUnavailable
		}
		status.Events, err = reader.ListProviderEvents(ctx, operation.TenantID, bindingID, before, eventLimit)
		if err != nil {
			return status, err
		}
	}
	return status, err
}

func (service *Service) ReconcileRelay(ctx context.Context, operation OperationContext, bindingID BindingID, generation PostfixRelayGeneration) (PostfixRelayObservation, error) {
	if service == nil || service.relay == nil || operation.Validate() != nil || !validID(string(bindingID)) ||
		generation.Validate() != nil || generation.Spec.BindingID != bindingID || generation.Spec.TenantID != operation.TenantID {
		return PostfixRelayObservation{}, ErrInvalid
	}
	if err := service.authorize(ctx, operation, bindingID, AuthorizeInspect, false); err != nil {
		return PostfixRelayObservation{}, err
	}
	return service.relay.ObservePostfixRelay(ctx, generation)
}

func (service *Service) IngestProviderWebhook(ctx context.Context, request SignedProviderWebhook) (NormalizedProviderEvent, error) {
	if service == nil || service.providers == nil {
		return NormalizedProviderEvent{}, ErrWebhookRejected
	}
	binding, err := service.repository.LoadBinding(ctx, request.TenantID, request.BindingID)
	if err != nil {
		return NormalizedProviderEvent{}, ErrWebhookRejected
	}
	adapter, err := service.providers.ResolveMailDeliveryProvider(ctx, binding.Adapter)
	if err != nil || adapter == nil || adapter.Reference() != binding.Adapter {
		return NormalizedProviderEvent{}, ErrWebhookRejected
	}
	return IngestProviderWebhook(ctx, service.webhook, adapter, service.repository, request)
}

func (repository *SQLiteRepository) ListProviderEvents(ctx context.Context, tenantID TenantID, bindingID BindingID, before time.Time, limit uint16) ([]NormalizedProviderEvent, error) {
	if repository == nil || repository.db == nil || !validID(string(tenantID)) || !validID(string(bindingID)) || limit == 0 || limit > 500 {
		return nil, ErrInvalid
	}
	if before.IsZero() {
		before = time.Now().UTC().Add(time.Minute)
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT document FROM maildelivery_provider_events_v1 WHERE tenant_id=? AND binding_id=? AND received_at<? ORDER BY received_at DESC,provider_event_id DESC LIMIT ?`,
		tenantID, bindingID, formatDatabaseTime(before), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]NormalizedProviderEvent, 0, limit)
	for rows.Next() {
		var document []byte
		var event NormalizedProviderEvent
		if rows.Scan(&document) != nil || decodeStrict(document, &event) != nil || event.Validate() != nil || event.TenantID != tenantID || event.BindingID != bindingID {
			return nil, ErrConflict
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (service *Service) routingRequest(ctx context.Context, command RouteCommand) (ProviderBinding, RouteRequest, error) {
	binding, err := service.repository.LoadBinding(ctx, command.Operation.TenantID, command.BindingID)
	if err != nil {
		return ProviderBinding{}, RouteRequest{}, err
	}
	if service.suppressions == nil || service.runtime == nil {
		return ProviderBinding{}, RouteRequest{}, ErrUnavailable
	}
	suppression, err := service.suppressions.CurrentSuppression(ctx, command.Operation.TenantID, command.MessageID)
	if err != nil {
		return ProviderBinding{}, RouteRequest{}, err
	}
	capacity, circuit, err := service.runtime.MailDeliveryRuntime(ctx, binding, command.Stream)
	if err != nil {
		return ProviderBinding{}, RouteRequest{}, err
	}
	var existing *MessageIdentity
	identity, identityErr := service.repository.LoadMessageIdentity(ctx, command.Operation.TenantID, command.MessageID)
	if identityErr == nil {
		existing = &identity
	} else if !errors.Is(identityErr, ErrNotFound) {
		return ProviderBinding{}, RouteRequest{}, identityErr
	}
	request := RouteRequest{TenantID: command.Operation.TenantID, DomainID: command.DomainID, MessageID: command.MessageID,
		Stream: command.Stream, CampaignID: command.CampaignID, Suppression: suppression, ExistingIdentity: existing,
		Capacity: capacity, Circuit: circuit, Now: service.currentTime()}
	return binding, request, nil
}

func (service *Service) submissionAdapter(ctx context.Context, current ProviderBinding, domainID DomainID, decision RouteDecision, identity *MessageIdentity) (ProviderBinding, SubmissionAdapterV1, error) {
	target := current
	if identity != nil {
		loaded, err := service.repository.LoadBindingGeneration(ctx, identity.TenantID, identity.BindingID, identity.BindingGeneration)
		if err != nil {
			return ProviderBinding{}, nil, err
		}
		target = loaded
	} else if decision.Target == RouteLocal && current.Adapter.Kind != LocalSMTPAdapterKind {
		if service.localBindings == nil {
			return ProviderBinding{}, nil, ErrUnavailable
		}
		loaded, err := service.localBindings.ResolveLocalMailDeliveryBinding(ctx, current.TenantID, domainID)
		if err != nil {
			return ProviderBinding{}, nil, err
		}
		target = loaded
	}
	if target.Adapter.Kind == LocalSMTPAdapterKind {
		if service.localSMTP == nil {
			return ProviderBinding{}, nil, ErrUnavailable
		}
		return target, service.localSMTP, nil
	}
	if service.providers == nil {
		return ProviderBinding{}, nil, ErrUnavailable
	}
	adapter, err := service.providers.ResolveMailDeliveryProvider(ctx, target.Adapter)
	if err != nil || adapter == nil || adapter.Reference() != target.Adapter {
		return ProviderBinding{}, nil, errors.Join(ErrUnavailable, err)
	}
	return target, adapter, nil
}

func (service *Service) domainVerifier(ctx context.Context, binding ProviderBinding) (DomainVerifier, error) {
	if binding.Adapter.Kind == LocalSMTPAdapterKind {
		if service.localDomainVerifier == nil {
			return nil, ErrUnavailable
		}
		return service.localDomainVerifier, nil
	}
	if service.providers == nil {
		return nil, ErrUnavailable
	}
	adapter, err := service.providers.ResolveMailDeliveryProvider(ctx, binding.Adapter)
	if err != nil || adapter == nil || adapter.Reference() != binding.Adapter {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return adapter, nil
}

func (service *Service) credentialLifecycle(ctx context.Context, binding ProviderBinding) (CredentialLifecycle, error) {
	if binding.Adapter.Kind == LocalSMTPAdapterKind {
		if service.localCredentials != nil {
			return service.localCredentials, nil
		}
		return LocalSMTPCredentialLifecycle{}, nil
	}
	if service.providers == nil {
		return nil, ErrUnavailable
	}
	adapter, err := service.providers.ResolveMailDeliveryProvider(ctx, binding.Adapter)
	if err != nil || adapter == nil || adapter.Reference() != binding.Adapter {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return adapter, nil
}

func (service *Service) authorize(ctx context.Context, operation OperationContext, bindingID BindingID, action AuthorizationAction, highRisk bool) error {
	request := AuthorizationRequest{Actor: operation.Actor, TenantID: operation.TenantID, BindingID: bindingID, Action: action,
		AuthorizationEpoch: operation.AuthorizationEpoch, HighRisk: highRisk, IntentDigest: operation.IntentDigest}
	if request.Validate() != nil {
		return ErrInvalid
	}
	if err := service.authorizer.AuthorizeMailDelivery(ctx, request); err != nil {
		return errors.Join(ErrDenied, err)
	}
	if highRisk {
		if operation.StepUpProofDigest == "" {
			return ErrDenied
		}
		if err := service.stepUp.VerifyMailDeliveryStepUp(ctx, request, operation.StepUpProofDigest, operation.At); err != nil {
			return errors.Join(ErrDenied, err)
		}
	}
	return nil
}

func (service *Service) record(ctx context.Context, operation OperationContext, bindingID BindingID, action AuthorizationAction, resourceID string, generation uint64, outcome string) error {
	record := AuditRecord{Actor: operation.Actor, TenantID: operation.TenantID, BindingID: bindingID, Action: action,
		ResourceID: resourceID, Generation: generation, AuthorizationEpoch: operation.AuthorizationEpoch, Outcome: outcome,
		IntentDigest: operation.IntentDigest, OccurredAt: service.currentTime()}
	if record.Validate() != nil {
		return ErrInvalid
	}
	return service.audit.RecordMailDelivery(ctx, record)
}

func (service *Service) currentTime() time.Time {
	return service.now().UTC()
}

func bindingDomain(binding ProviderBinding, domainID DomainID) (SendingDomain, int, bool) {
	for index, domain := range binding.Domains {
		if domain.ID == domainID {
			return domain, index, true
		}
	}
	return SendingDomain{}, 0, false
}

func derivedID(prefix string, values ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(prefix))
	for _, value := range values {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	return prefix + "_" + hex.EncodeToString(hash.Sum(nil))[:48]
}
