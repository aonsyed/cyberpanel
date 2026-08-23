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
	ProviderConsumerReleaseDigest string
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
	providerConsumerReleaseDigest string
	now func() time.Time
}

func (service *Service) SupportsRouting() bool {
	return service != nil && service.suppressions != nil && service.runtime != nil
}

func (service *Service) SupportsProviderEvents() bool {
	return service != nil && service.providers != nil && service.webhook != nil
}

func (service *Service) SupportsLocalRelayControl() bool {
	return service != nil && service.relay != nil
}

func NewService(configuration ServiceConfig) (*Service, error) {
	if configuration.Repository == nil || configuration.Authorizer == nil || configuration.StepUp == nil ||
		configuration.Consent == nil || configuration.Audit == nil {
		return nil, ErrInvalid
	}
	if configuration.ProviderConsumerReleaseDigest != "" && !validDigest(configuration.ProviderConsumerReleaseDigest) {
		return nil, ErrInvalid
	}
	if configuration.Now == nil {
		configuration.Now = time.Now
	}
	return &Service{repository: configuration.Repository, authorizer: configuration.Authorizer, stepUp: configuration.StepUp,
		consent: configuration.Consent, audit: configuration.Audit, providers: configuration.Providers,
		localDomainVerifier: configuration.LocalDomainVerifier, localCredentials: configuration.LocalCredentials,
		localSMTP: configuration.LocalSMTP, localBindings: configuration.LocalBindings, suppressions: configuration.Suppressions,
		runtime: configuration.Runtime, relay: configuration.Relay, webhook: configuration.Webhook,
		providerConsumerReleaseDigest: configuration.ProviderConsumerReleaseDigest, now: configuration.Now}, nil
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
	if command.Binding.Adapter.Kind == LocalSMTPAdapterKind {
		if service.localSMTP == nil || service.localDomainVerifier == nil {
			return ProviderBinding{}, ErrUnavailable
		}
	} else {
		if service.providers == nil {
			return ProviderBinding{}, ErrUnavailable
		}
		provider, err := service.providers.ResolveMailDeliveryProvider(ctx, command.Binding.Adapter)
		if err != nil || provider == nil || provider.Reference() != command.Binding.Adapter {
			return ProviderBinding{}, errors.Join(ErrUnavailable, err)
		}
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
	if current.Adapter == CyberMailProviderReferenceV1() && command.Desired.Credential.Version != current.Credential.Version+1 {
		return result, ErrInvalid
	}
	rotating := command.Desired
	rotating.Generation = command.ExpectedGeneration + 1
	rotating.Lifecycle = BindingRotating
	rotating.UpdatedAt = service.currentTime()
	cyberMailRotation := current.Adapter == CyberMailProviderReferenceV1()
	if cyberMailRotation {
		// The new protected-material binding digest exists only after the
		// provider password has been stored. Keep the durable rotating state
		// on the last resolvable reference until activation returns that digest.
		rotating.Credential = current.Credential
	}
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
		TenantID: rotating.TenantID, Sequence: command.Desired.Credential.Version*2 - 1, OldVersion: current.Credential.Version, NewVersion: command.Desired.Credential.Version,
		OverlapUntil: service.currentTime().Add(command.Overlap), State: RotationPrepared, OccurredAt: service.currentTime()}
	rotation, err := lifecycle.RotateCredential(ctx, CredentialRotationRequest{Binding: current, Rotation: prepared})
	if err != nil || rotation.Validate() != nil || rotation.BindingID != current.ID || rotation.TenantID != current.TenantID ||
		rotation.ID != prepared.ID || rotation.Sequence != prepared.Sequence || rotation.OldVersion != current.Credential.Version ||
		rotation.NewVersion != command.Desired.Credential.Version || rotation.OverlapUntil != prepared.OverlapUntil {
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
	if cyberMailRotation {
		resolver, ok := lifecycle.(interface {
			ActivatedCyberMailCredentialReference(TenantID, BindingID, uint64) (EncryptedCredentialReference, error)
		})
		if !ok {
			return result, errors.Join(ErrAmbiguous, ErrUnsupported)
		}
		activated, resolveErr := resolver.ActivatedCyberMailCredentialReference(final.TenantID, final.ID, command.Desired.Credential.Version)
		if resolveErr != nil || activated.Reference != command.Desired.Credential.Reference || activated.Purpose != command.Desired.Credential.Purpose {
			return result, errors.Join(ErrAmbiguous, resolveErr)
		}
		final.Credential = activated
	}
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

type ProviderCapability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type ProviderSecretProfile struct {
	Purpose               string   `json:"purpose"`
	ReferencePurpose      string   `json:"reference_purpose"`
	AdapterID             string   `json:"adapter_id"`
	AdapterVersion        string   `json:"adapter_version"`
	Account               string   `json:"account"`
	Origin                string   `json:"origin"`
	ResourceKind          string   `json:"resource_kind"`
	ResourceGeneration    uint64   `json:"resource_generation"`
	Operations            []string `json:"operations"`
	MaterialFields        []string `json:"material_fields"`
	ConsumerReleaseDigest string   `json:"consumer_release_digest"`
}

type ProviderCapabilities struct {
	Adapter      ProviderAdapterRef    `json:"adapter"`
	APIEndpoint  string                `json:"api_endpoint"`
	SMTPHost     string                `json:"smtp_host"`
	SMTPPort     uint16                `json:"smtp_port"`
	Secret       ProviderSecretProfile `json:"secret"`
	Consent      ProviderConsentProfile `json:"consent"`
	Capabilities []ProviderCapability  `json:"capabilities"`
}

type ProviderConsentProfile struct {
	Purpose     string   `json:"purpose"`
	Destination string   `json:"destination"`
	DataClasses []string `json:"data_classes"`
}

func (service *Service) ProviderCapabilities(ctx context.Context, operation OperationContext, bindingID BindingID) (ProviderCapabilities, error) {
	if service == nil || operation.Validate() != nil || !validID(string(bindingID)) {
		return ProviderCapabilities{}, ErrInvalid
	}
	if service.providers == nil || service.providerConsumerReleaseDigest == "" {
		return ProviderCapabilities{}, ErrUnavailable
	}
	if err := service.authorize(ctx, operation, bindingID, AuthorizeInspect, false); err != nil {
		return ProviderCapabilities{}, err
	}
	provider, err := service.providers.ResolveMailDeliveryProvider(ctx, CyberMailProviderReferenceV1())
	if err != nil || provider == nil || provider.Reference() != CyberMailProviderReferenceV1() {
		return ProviderCapabilities{}, errors.Join(ErrUnavailable, err)
	}
	return ProviderCapabilities{
		Adapter: CyberMailProviderReferenceV1(), APIEndpoint: CyberMailAPIBaseURL, SMTPHost: CyberMailSMTPHost, SMTPPort: CyberMailSMTPPort,
		Secret: ProviderSecretProfile{Purpose: "mail_relay", ReferencePurpose: "maildelivery_provider",
			AdapterID: CyberMailAdapterKind, AdapterVersion: CyberMailAdapterVersionV1, Account: CyberMailAdapterKind,
			Origin: CyberMailAPIBaseURL, ResourceKind: "mail_relay", ResourceGeneration: 1,
			Operations: []string{"authenticate", "rotate"},
			MaterialFields: []string{"api_key", "email", "smtp_credential_id", "smtp_password", "smtp_username"},
			ConsumerReleaseDigest: service.providerConsumerReleaseDigest},
		Consent: ProviderConsentProfile{Purpose: "outbound_mail_delivery", Destination: CyberMailAPIBaseURL,
			DataClasses: []string{"delivery_metadata", "mail_content", "recipient_address", "sender_address"}},
		Capabilities: []ProviderCapability{
			{Name: "account.health", Available: true},
			{Name: "delivery.logs", Available: true},
			{Name: "dns.plan", Available: false, Reason: "return_path_and_tracking_records_not_documented"},
			{Name: "domain.enroll", Available: false, Reason: "complete_dns_plan_unavailable"},
			{Name: "domain.list", Available: true},
			{Name: "domain.remove", Available: true},
			{Name: "domain.verify", Available: true},
			{Name: "events.webhook", Available: false, Reason: "signature_and_event_schema_not_documented"},
			{Name: "relay.query", Available: false, Reason: "idempotency_query_not_documented"},
			{Name: "relay.submit", Available: true},
			{Name: "smtp.list", Available: true},
			{Name: "smtp.revoke", Available: true},
			{Name: "smtp.rotate", Available: true},
			{Name: "stats.account", Available: true},
			{Name: "stats.domains", Available: true},
		},
	}, nil
}

func (service *Service) ProviderDomains(ctx context.Context, operation OperationContext, bindingID BindingID, page CyberMailPageRequest) (CyberMailDomainPage, uint64, error) {
	binding, adapter, err := service.cyberMailProvider(ctx, operation, bindingID)
	if err != nil {
		return CyberMailDomainPage{}, 0, err
	}
	result, err := adapter.ListDomains(ctx, binding, page)
	return result, binding.Generation, err
}

type ProviderAnalyticsKind string

const (
	ProviderAnalyticsAccountStatistics ProviderAnalyticsKind = "account_statistics"
	ProviderAnalyticsDomainStatistics  ProviderAnalyticsKind = "domain_statistics"
	ProviderAnalyticsDeliveryLogs      ProviderAnalyticsKind = "delivery_logs"
	ProviderAnalyticsSMTPCredentials   ProviderAnalyticsKind = "smtp_credentials"
)

type ProviderAnalyticsRequest struct {
	Kind     ProviderAnalyticsKind `json:"kind"`
	DomainID DomainID              `json:"domain_id,omitempty"`
	Page     uint32                `json:"page"`
	PerPage  uint16                `json:"per_page"`
	Status   string                `json:"status,omitempty"`
	Days     uint8                 `json:"days,omitempty"`
}

type ProviderAnalytics struct {
	Kind              ProviderAnalyticsKind           `json:"kind"`
	BindingGeneration uint64                          `json:"binding_generation"`
	Statistics        *CyberMailStatistics            `json:"statistics,omitempty"`
	DomainStatistics  *CyberMailDomainStatisticsPage  `json:"domain_statistics,omitempty"`
	DeliveryLogs      *CyberMailDeliveryLogPage       `json:"delivery_logs,omitempty"`
	SMTPCredentials   *CyberMailSMTPCredentialPage    `json:"smtp_credentials,omitempty"`
}

func (service *Service) ProviderAnalytics(ctx context.Context, operation OperationContext, bindingID BindingID, request ProviderAnalyticsRequest) (ProviderAnalytics, error) {
	binding, adapter, err := service.cyberMailProvider(ctx, operation, bindingID)
	if err != nil {
		return ProviderAnalytics{}, err
	}
	result := ProviderAnalytics{Kind: request.Kind, BindingGeneration: binding.Generation}
	page := CyberMailPageRequest{Page: request.Page, PerPage: request.PerPage}
	switch request.Kind {
	case ProviderAnalyticsAccountStatistics:
		value, fetchErr := adapter.Statistics(ctx, binding)
		result.Statistics = &value
		err = fetchErr
	case ProviderAnalyticsDomainStatistics:
		value, fetchErr := adapter.ListDomainStatistics(ctx, binding, page)
		result.DomainStatistics = &value
		err = fetchErr
	case ProviderAnalyticsDeliveryLogs:
		value, fetchErr := adapter.ListDeliveryLogs(ctx, binding, CyberMailDeliveryLogRequest{DomainID: request.DomainID,
			Page: request.Page, PerPage: request.PerPage, Status: request.Status, Days: request.Days})
		result.DeliveryLogs = &value
		err = fetchErr
	case ProviderAnalyticsSMTPCredentials:
		value, fetchErr := adapter.ListSMTPCredentials(ctx, binding, page)
		result.SMTPCredentials = &value
		err = fetchErr
	default:
		return ProviderAnalytics{}, ErrInvalid
	}
	if err != nil {
		return ProviderAnalytics{}, err
	}
	return result, nil
}

type SyncProviderHealthCommand struct {
	Operation          OperationContext
	BindingID          BindingID
	ExpectedGeneration uint64
}

func (service *Service) SyncProviderHealth(ctx context.Context, command SyncProviderHealthCommand) (ProviderBinding, error) {
	if service == nil || command.Operation.Validate() != nil || !validID(string(command.BindingID)) ||
		command.ExpectedGeneration == 0 || command.ExpectedGeneration == ^uint64(0) || service.providers == nil {
		return ProviderBinding{}, ErrInvalid
	}
	if err := service.authorize(ctx, command.Operation, command.BindingID, AuthorizeBindingWrite, false); err != nil {
		return ProviderBinding{}, err
	}
	binding, err := service.repository.LoadBinding(ctx, command.Operation.TenantID, command.BindingID)
	if err != nil {
		return ProviderBinding{}, err
	}
	if binding.Generation != command.ExpectedGeneration {
		return ProviderBinding{}, ErrStale
	}
	provider, err := service.providers.ResolveMailDeliveryProvider(ctx, binding.Adapter)
	if err != nil || provider == nil || provider.Reference() != binding.Adapter {
		return ProviderBinding{}, errors.Join(ErrUnavailable, err)
	}
	observation, err := provider.ObserveHealthAndLimits(ctx, binding)
	if err != nil {
		return ProviderBinding{}, err
	}
	binding.Observation = observation
	binding.Generation++
	binding.UpdatedAt = service.currentTime()
	if err = service.repository.PutBinding(ctx, binding, command.ExpectedGeneration); err != nil {
		return ProviderBinding{}, err
	}
	if err = service.record(ctx, command.Operation, binding.ID, AuthorizeBindingWrite, string(binding.ID), binding.Generation, "observed"); err != nil {
		return binding, errors.Join(ErrAmbiguous, err)
	}
	return binding, nil
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
	if eventLimit > 0 && !service.SupportsProviderEvents() {
		return status, ErrUnsupported
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

func (service *Service) cyberMailProvider(ctx context.Context, operation OperationContext, bindingID BindingID) (ProviderBinding, *CyberMailAdapterV1, error) {
	if service == nil || service.providers == nil || operation.Validate() != nil || !validID(string(bindingID)) {
		return ProviderBinding{}, nil, ErrInvalid
	}
	if err := service.authorize(ctx, operation, bindingID, AuthorizeInspect, false); err != nil {
		return ProviderBinding{}, nil, err
	}
	binding, err := service.repository.LoadBinding(ctx, operation.TenantID, bindingID)
	if err != nil {
		return ProviderBinding{}, nil, err
	}
	if binding.Adapter != CyberMailProviderReferenceV1() {
		return ProviderBinding{}, nil, ErrUnsupported
	}
	provider, err := service.providers.ResolveMailDeliveryProvider(ctx, binding.Adapter)
	if err != nil {
		return ProviderBinding{}, nil, errors.Join(ErrUnavailable, err)
	}
	adapter, ok := provider.(*CyberMailAdapterV1)
	if !ok || adapter == nil || adapter.Reference() != binding.Adapter {
		return ProviderBinding{}, nil, ErrIntegrity
	}
	return binding, adapter, nil
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

// ResolveCyberMailBinding keeps relay submission tenant/domain scoped and
// rejects ambiguous bindings instead of choosing by insertion order.
func (repository *SQLiteRepository) ResolveCyberMailBinding(ctx context.Context, tenantID TenantID, domainID DomainID) (ProviderBinding, error) {
	if repository == nil || repository.db == nil || !validID(string(tenantID)) || !validID(string(domainID)) {
		return ProviderBinding{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT document FROM maildelivery_bindings_v1 WHERE tenant_id=? AND adapter_kind=? ORDER BY binding_id LIMIT 1001`, tenantID, CyberMailAdapterKind)
	if err != nil {
		return ProviderBinding{}, err
	}
	defer rows.Close()
	var matched ProviderBinding
	found := false
	count := 0
	for rows.Next() {
		count++
		var document []byte
		var binding ProviderBinding
		if count > 1000 || rows.Scan(&document) != nil || decodeStrict(document, &binding) != nil || validateCyberMailBinding(binding) != nil || binding.TenantID != tenantID {
			return ProviderBinding{}, ErrConflict
		}
		if _, _, ok := bindingDomain(binding, domainID); !ok {
			continue
		}
		if found {
			return ProviderBinding{}, ErrConflict
		}
		matched, found = binding, true
	}
	if err = rows.Err(); err != nil {
		return ProviderBinding{}, err
	}
	if !found {
		return ProviderBinding{}, ErrNotFound
	}
	return matched, nil
}

// ResolveCyberMailCredentialBinding is intentionally exact and unique across
// tenants because SMTPSecretResolver receives only the protected reference.
func (repository *SQLiteRepository) ResolveCyberMailCredentialBinding(ctx context.Context, reference EncryptedCredentialReference) (ProviderBinding, error) {
	if repository == nil || repository.db == nil || reference.Validate() != nil {
		return ProviderBinding{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT document FROM maildelivery_bindings_v1 WHERE adapter_kind=? AND credential_version=? ORDER BY binding_id LIMIT 1001`, CyberMailAdapterKind, reference.Version)
	if err != nil {
		return ProviderBinding{}, err
	}
	defer rows.Close()
	var matched ProviderBinding
	found := false
	count := 0
	for rows.Next() {
		count++
		var document []byte
		var binding ProviderBinding
		if count > 1000 || rows.Scan(&document) != nil || decodeStrict(document, &binding) != nil || validateCyberMailBinding(binding) != nil {
			return ProviderBinding{}, ErrConflict
		}
		if binding.Credential != reference {
			continue
		}
		if found {
			return ProviderBinding{}, ErrConflict
		}
		matched, found = binding, true
	}
	if err = rows.Err(); err != nil {
		return ProviderBinding{}, err
	}
	if !found {
		return ProviderBinding{}, ErrNotFound
	}
	return matched, nil
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
