package providerpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

type AuthorizationAction string

const (
	AuthorizeBindingWrite       AuthorizationAction = "binding.write"
	AuthorizeBindingRead        AuthorizationAction = "binding.read"
	AuthorizeAdmissionEvaluate  AuthorizationAction = "admission.evaluate"
	AuthorizeCapacityReserve    AuthorizationAction = "capacity.reserve"
	AuthorizeCapacityComplete   AuthorizationAction = "capacity.complete"
	AuthorizeObservationWrite   AuthorizationAction = "observation.write"
	AuthorizeWorkflowWrite      AuthorizationAction = "workflow.write"
)

type AuthorizationRequest struct {
	Actor      ActorID             `json:"actor"`
	TenantID   TenantID            `json:"tenant_id"`
	BindingID  BindingID           `json:"binding_id,omitempty"`
	ProviderID ProviderID          `json:"provider_id,omitempty"`
	Action     AuthorizationAction `json:"action"`
	Risk       OperationRisk       `json:"risk"`
}

func (request AuthorizationRequest) Validate() error {
	if !validID(string(request.Actor)) || !validID(string(request.TenantID)) || request.BindingID != "" && !validID(string(request.BindingID)) ||
		request.ProviderID != "" && !validID(string(request.ProviderID)) || request.Risk.rank() == 0 {
		return ErrInvalid
	}
	switch request.Action {
	case AuthorizeBindingWrite, AuthorizeBindingRead, AuthorizeAdmissionEvaluate, AuthorizeCapacityReserve, AuthorizeCapacityComplete, AuthorizeObservationWrite, AuthorizeWorkflowWrite:
		return nil
	default:
		return ErrInvalid
	}
}

type Authorizer interface {
	AuthorizeProviderPolicy(context.Context, AuthorizationRequest) error
}

type StepUpRequest struct {
	Actor       ActorID             `json:"actor"`
	TenantID    TenantID            `json:"tenant_id"`
	BindingID   BindingID           `json:"binding_id"`
	Action      AuthorizationAction `json:"action"`
	AssertionID string              `json:"assertion_id"`
	Revision    uint64              `json:"revision"`
}

func (request StepUpRequest) Validate() error {
	if !validID(string(request.Actor)) || !validID(string(request.TenantID)) || !validID(string(request.BindingID)) ||
		!validID(request.AssertionID) || request.Revision == 0 || request.Action != AuthorizeBindingWrite && request.Action != AuthorizeWorkflowWrite {
		return ErrInvalid
	}
	return nil
}

type StepUpVerifier interface {
	VerifyProviderPolicyStepUp(context.Context, StepUpRequest) error
}

type AuditRecord struct {
	Actor          ActorID             `json:"actor"`
	TenantID       TenantID            `json:"tenant_id"`
	BindingID      BindingID           `json:"binding_id,omitempty"`
	ProviderID     ProviderID          `json:"provider_id,omitempty"`
	Action         AuthorizationAction `json:"action"`
	Risk           OperationRisk       `json:"risk"`
	Outcome        string              `json:"outcome"`
	ResourceDigest string              `json:"resource_digest,omitempty"`
	EvidenceDigest string              `json:"evidence_digest,omitempty"`
	Generation     uint64              `json:"generation,omitempty"`
	OccurredAt     time.Time           `json:"occurred_at"`
	Digest         string              `json:"digest"`
}

func (record AuditRecord) Validate() error {
	if (AuthorizationRequest{Actor: record.Actor, TenantID: record.TenantID, BindingID: record.BindingID, ProviderID: record.ProviderID, Action: record.Action, Risk: record.Risk}).Validate() != nil ||
		len(record.Outcome) < 1 || len(record.Outcome) > 128 || record.ResourceDigest != "" && !validDigest(record.ResourceDigest) ||
		record.EvidenceDigest != "" && !validDigest(record.EvidenceDigest) || record.OccurredAt.IsZero() || !validDigest(record.Digest) || auditDigest(record) != record.Digest {
		return ErrIntegrity
	}
	return nil
}

func auditDigest(record AuditRecord) string {
	record.Digest = ""
	encoded, _ := json.Marshal(record)
	return digest(encoded)
}

type AuditSink interface {
	RecordProviderPolicy(context.Context, AuditRecord) error
}

type Repository interface {
	Bootstrap(context.Context) error
	PutBinding(context.Context, Binding, uint64, *ConsentRecord) error
	LoadBinding(context.Context, TenantID, BindingID) (Binding, error)
	ListBindings(context.Context, TenantID, int) ([]Binding, error)
	LoadConsent(context.Context, TenantID, BindingID, uint64) (ConsentRecord, error)
	Runtime(context.Context, Binding, time.Time) (RuntimeSnapshot, error)
	Acquire(context.Context, Binding, AdmissionRequest, uint64, time.Time, time.Duration) (Permit, error)
	Complete(context.Context, Binding, Permit, OperationOutcome, time.Time) (RuntimeSnapshot, error)
	RecordObservation(context.Context, Observation) error
	LatestObservation(context.Context, TenantID, BindingID) (Observation, error)
	BeginWorkflow(context.Context, Binding, uint64, LifecycleWorkflow) error
	LoadWorkflow(context.Context, TenantID, WorkflowID) (LifecycleWorkflow, error)
	TransitionWorkflow(context.Context, LifecycleWorkflow, uint64, *Binding, uint64) error
}

type Service struct {
	repository Repository
	authorizer Authorizer
	stepUp     StepUpVerifier
	audit      AuditSink
	now        func() time.Time
}

func NewService(repository Repository, authorizer Authorizer, stepUp StepUpVerifier, audit AuditSink, now func() time.Time) (*Service, error) {
	if repository == nil || authorizer == nil || stepUp == nil || audit == nil {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &Service{repository: repository, authorizer: authorizer, stepUp: stepUp, audit: audit, now: now}, nil
}

func (service *Service) Bootstrap(ctx context.Context) error { return service.repository.Bootstrap(ctx) }

func (service *Service) PutBinding(ctx context.Context, actor ActorID, binding Binding, expectedGeneration uint64, consent *ConsentRecord, stepUp StepUpRequest) (RedactedBinding, error) {
	authorization := AuthorizationRequest{Actor: actor, TenantID: binding.TenantID, BindingID: binding.ID, ProviderID: binding.ProviderID, Action: AuthorizeBindingWrite, Risk: RiskWrite}
	if binding.Validate() != nil || binding.Generation != expectedGeneration+1 || stepUp.Validate() != nil || stepUp.Actor != actor || stepUp.TenantID != binding.TenantID || stepUp.BindingID != binding.ID || stepUp.Action != AuthorizeBindingWrite {
		return RedactedBinding{}, ErrInvalid
	}
	if consent != nil && consent.Actor != actor {
		return RedactedBinding{}, ErrInvalid
	}
	if err := service.authorize(ctx, authorization); err != nil {
		return RedactedBinding{}, err
	}
	if err := service.stepUp.VerifyProviderPolicyStepUp(ctx, stepUp); err != nil {
		service.recordAudit(ctx, authorization, "step_up_denied", "", "", expectedGeneration)
		return RedactedBinding{}, ErrDenied
	}
	if err := service.repository.PutBinding(ctx, binding, expectedGeneration, consent); err != nil {
		service.recordAudit(ctx, authorization, "write_failed", "", "", expectedGeneration)
		return RedactedBinding{}, err
	}
	projection, err := RedactBinding(binding)
	if err != nil {
		return RedactedBinding{}, err
	}
	if err = service.recordAudit(ctx, authorization, "written", projection.ProjectionDigest, consentRecordDigest(consent), binding.Generation); err != nil {
		return RedactedBinding{}, err
	}
	return projection, nil
}

func (service *Service) InspectBinding(ctx context.Context, actor ActorID, tenantID TenantID, bindingID BindingID) (RedactedBinding, error) {
	authorization := AuthorizationRequest{Actor: actor, TenantID: tenantID, BindingID: bindingID, Action: AuthorizeBindingRead, Risk: RiskRead}
	if err := service.authorize(ctx, authorization); err != nil {
		return RedactedBinding{}, err
	}
	binding, err := service.repository.LoadBinding(ctx, tenantID, bindingID)
	if err != nil {
		return RedactedBinding{}, err
	}
	projection, err := RedactBinding(binding)
	if err != nil {
		return RedactedBinding{}, err
	}
	if err = service.recordAudit(ctx, authorization, "read", projection.ProjectionDigest, "", binding.Generation); err != nil {
		return RedactedBinding{}, err
	}
	return projection, nil
}

func (service *Service) ListBindings(ctx context.Context, actor ActorID, tenantID TenantID, limit int) ([]RedactedBinding, error) {
	authorization := AuthorizationRequest{Actor: actor, TenantID: tenantID, Action: AuthorizeBindingRead, Risk: RiskRead}
	if err := service.authorize(ctx, authorization); err != nil {
		return nil, err
	}
	bindings, err := service.repository.ListBindings(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	projections := make([]RedactedBinding, 0, len(bindings))
	for _, binding := range bindings {
		projection, projectErr := RedactBinding(binding)
		if projectErr != nil {
			return nil, projectErr
		}
		projections = append(projections, projection)
	}
	encoded, _ := json.Marshal(projections)
	if err = service.recordAudit(ctx, authorization, "listed", digest(encoded), "", 0); err != nil {
		return nil, err
	}
	return projections, nil
}

func (service *Service) Admit(ctx context.Context, actor ActorID, request AdmissionRequest) (AdmissionDecision, error) {
	authorization := AuthorizationRequest{Actor: actor, TenantID: request.TenantID, BindingID: request.BindingID, Action: AuthorizeAdmissionEvaluate, Risk: request.Risk}
	if actor != request.Actor || request.Validate() != nil {
		return AdmissionDecision{}, ErrInvalid
	}
	if err := service.authorize(ctx, authorization); err != nil {
		return AdmissionDecision{}, err
	}
	binding, err := service.repository.LoadBinding(ctx, request.TenantID, request.BindingID)
	if err != nil {
		return AdmissionDecision{}, err
	}
	if _, err = service.repository.LoadConsent(ctx, binding.TenantID, binding.ID, binding.EgressConsentRevision); err != nil {
		return AdmissionDecision{}, ErrIntegrity
	}
	now := service.now().UTC()
	observation, observationErr := service.repository.LatestObservation(ctx, binding.TenantID, binding.ID)
	health := HealthSnapshot{Status: HealthUnknown, ObservedAt: binding.UpdatedAt.UTC()}
	if observationErr == nil {
		health = HealthSnapshot{Status: observation.Health, ObservedAt: observation.ObservedAt, RetryAfter: observation.RetryAfter, EvidenceDigest: observation.Digest}
	} else if !errors.Is(observationErr, ErrNotFound) {
		return AdmissionDecision{}, observationErr
	}
	runtime, err := service.repository.Runtime(ctx, binding, now)
	if err != nil {
		return AdmissionDecision{}, err
	}
	decision := EvaluateAdmission(binding, request, health, runtime, now)
	if err = service.recordAudit(ctx, authorization, "decision_"+string(decision.Kind)+"_"+string(decision.Code), "", decision.Evidence.Digest, binding.Generation); err != nil {
		return AdmissionDecision{}, err
	}
	return decision, nil
}

func (service *Service) Reserve(ctx context.Context, actor ActorID, request AdmissionRequest, lease time.Duration) (Permit, AdmissionDecision, error) {
	decision, err := service.Admit(ctx, actor, request)
	if err != nil {
		return Permit{}, AdmissionDecision{}, err
	}
	if decision.Kind != DecisionAllow {
		if decision.Kind == DecisionDefer {
			return Permit{}, decision, ErrDeferred
		}
		return Permit{}, decision, ErrDenied
	}
	authorization := AuthorizationRequest{Actor: actor, TenantID: request.TenantID, BindingID: request.BindingID, Action: AuthorizeCapacityReserve, Risk: request.Risk}
	if err = service.authorize(ctx, authorization); err != nil {
		return Permit{}, decision, err
	}
	binding, err := service.repository.LoadBinding(ctx, request.TenantID, request.BindingID)
	if err != nil {
		return Permit{}, decision, err
	}
	permit, err := service.repository.Acquire(ctx, binding, request, decision.Evidence.RuntimeGeneration, service.now().UTC(), lease)
	if err != nil {
		return Permit{}, decision, err
	}
	if err = service.recordAudit(ctx, authorization, "reserved", permit.FenceDigest, decision.Evidence.Digest, binding.Generation); err != nil {
		return Permit{}, decision, err
	}
	return permit, decision, nil
}

func (service *Service) Complete(ctx context.Context, actor ActorID, permit Permit, outcome OperationOutcome) (RuntimeSnapshot, error) {
	authorization := AuthorizationRequest{Actor: actor, TenantID: permit.TenantID, BindingID: permit.BindingID, Action: AuthorizeCapacityComplete, Risk: RiskWrite}
	if permit.Validate() != nil {
		return RuntimeSnapshot{}, ErrInvalid
	}
	if err := service.authorize(ctx, authorization); err != nil {
		return RuntimeSnapshot{}, err
	}
	binding, err := service.repository.LoadBinding(ctx, permit.TenantID, permit.BindingID)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	runtime, err := service.repository.Complete(ctx, binding, permit, outcome, service.now().UTC())
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	if err = service.recordAudit(ctx, authorization, "completed_"+string(outcome), permit.FenceDigest, "", runtime.Generation); err != nil {
		return RuntimeSnapshot{}, err
	}
	return runtime, nil
}

func (service *Service) RecordObservation(ctx context.Context, actor ActorID, observation Observation) (Observation, error) {
	authorization := AuthorizationRequest{Actor: actor, TenantID: observation.TenantID, BindingID: observation.BindingID, Action: AuthorizeObservationWrite, Risk: RiskWrite}
	observation.ObservedAt = observation.ObservedAt.UTC()
	observation.Digest = observationDigest(observation)
	if observation.Validate() != nil {
		return Observation{}, ErrInvalid
	}
	if err := service.authorize(ctx, authorization); err != nil {
		return Observation{}, err
	}
	if _, err := service.repository.LoadBinding(ctx, observation.TenantID, observation.BindingID); err != nil {
		return Observation{}, err
	}
	if err := service.repository.RecordObservation(ctx, observation); err != nil {
		return Observation{}, err
	}
	if err := service.recordAudit(ctx, authorization, "observed_"+string(observation.Health), observation.Digest, observation.ObservedDigest, 0); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

type BeginWorkflowRequest struct {
	ID                  WorkflowID
	TenantID            TenantID
	BindingID           BindingID
	ExpectedGeneration  uint64
	Reason              string
	DeleteProviderData  bool
	NewSecretReferences []SecretReference
	StepUp              StepUpRequest
}

func (service *Service) BeginDeletion(ctx context.Context, actor ActorID, request BeginWorkflowRequest) (LifecycleWorkflow, error) {
	return service.beginWorkflow(ctx, actor, request, WorkflowDeletion)
}

func (service *Service) BeginReauthorization(ctx context.Context, actor ActorID, request BeginWorkflowRequest) (LifecycleWorkflow, error) {
	return service.beginWorkflow(ctx, actor, request, WorkflowReauthorization)
}

func (service *Service) beginWorkflow(ctx context.Context, actor ActorID, request BeginWorkflowRequest, kind WorkflowKind) (LifecycleWorkflow, error) {
	authorization := AuthorizationRequest{Actor: actor, TenantID: request.TenantID, BindingID: request.BindingID, Action: AuthorizeWorkflowWrite, Risk: RiskDelete}
	if request.StepUp.Validate() != nil || request.StepUp.Actor != actor || request.StepUp.TenantID != request.TenantID || request.StepUp.BindingID != request.BindingID || request.StepUp.Action != AuthorizeWorkflowWrite {
		return LifecycleWorkflow{}, ErrInvalid
	}
	if err := service.authorize(ctx, authorization); err != nil {
		return LifecycleWorkflow{}, err
	}
	if err := service.stepUp.VerifyProviderPolicyStepUp(ctx, request.StepUp); err != nil {
		service.recordAudit(ctx, authorization, "step_up_denied", "", "", request.ExpectedGeneration)
		return LifecycleWorkflow{}, ErrDenied
	}
	binding, err := service.repository.LoadBinding(ctx, request.TenantID, request.BindingID)
	if err != nil {
		return LifecycleWorkflow{}, err
	}
	if binding.Generation != request.ExpectedGeneration || binding.Lifecycle == LifecycleDeleting {
		return LifecycleWorkflow{}, ErrStale
	}
	if kind == WorkflowDeletion {
		if len(request.NewSecretReferences) != 0 || binding.Retention.DeleteOnDisconnect && !request.DeleteProviderData {
			return LifecycleWorkflow{}, ErrInvalid
		}
		binding.Lifecycle = LifecycleDeleting
	} else {
		if request.DeleteProviderData || !newSecretSet(binding.SecretReferences, request.NewSecretReferences) {
			return LifecycleWorkflow{}, ErrInvalid
		}
		binding.Lifecycle = LifecycleSuspended
	}
	now := service.now().UTC()
	binding.Generation++
	binding.UpdatedAt = now
	workflow := SealWorkflow(LifecycleWorkflow{ID: request.ID, BindingID: binding.ID, TenantID: binding.TenantID, Kind: kind, State: WorkflowPending,
		BindingGeneration: binding.Generation, DeleteProviderData: request.DeleteProviderData, NewSecretReferences: cloneSecrets(request.NewSecretReferences),
		SecretsTransferred: false, Reason: request.Reason, Actor: actor, CreatedAt: now, UpdatedAt: now, Generation: 1})
	if workflow.Validate() != nil {
		return LifecycleWorkflow{}, ErrInvalid
	}
	if err = service.repository.BeginWorkflow(ctx, binding, request.ExpectedGeneration, workflow); err != nil {
		return LifecycleWorkflow{}, err
	}
	if err = service.recordAudit(ctx, authorization, "workflow_started_"+string(kind), workflow.Digest, "", binding.Generation); err != nil {
		return LifecycleWorkflow{}, err
	}
	return workflow, nil
}

type TransitionWorkflowRequest struct {
	TenantID          TenantID
	WorkflowID        WorkflowID
	ExpectedGeneration uint64
	State             WorkflowState
	ProviderProofDigest string
	StepUp            StepUpRequest
}

func (service *Service) TransitionWorkflow(ctx context.Context, actor ActorID, request TransitionWorkflowRequest) (LifecycleWorkflow, error) {
	workflow, err := service.repository.LoadWorkflow(ctx, request.TenantID, request.WorkflowID)
	if err != nil {
		return LifecycleWorkflow{}, err
	}
	authorization := AuthorizationRequest{Actor: actor, TenantID: request.TenantID, BindingID: workflow.BindingID, Action: AuthorizeWorkflowWrite, Risk: RiskDelete}
	if workflow.Generation != request.ExpectedGeneration || !validTransition(workflow.State, request.State) {
		return LifecycleWorkflow{}, ErrStale
	}
	if err = service.authorize(ctx, authorization); err != nil {
		return LifecycleWorkflow{}, err
	}
	if request.State == WorkflowCompleted {
		if request.StepUp.Validate() != nil || request.StepUp.Actor != actor || request.StepUp.TenantID != request.TenantID || request.StepUp.BindingID != workflow.BindingID || request.StepUp.Action != AuthorizeWorkflowWrite {
			return LifecycleWorkflow{}, ErrInvalid
		}
		if err = service.stepUp.VerifyProviderPolicyStepUp(ctx, request.StepUp); err != nil {
			return LifecycleWorkflow{}, ErrDenied
		}
	}
	binding, err := service.repository.LoadBinding(ctx, workflow.TenantID, workflow.BindingID)
	if err != nil {
		return LifecycleWorkflow{}, err
	}
	if workflow.Kind == WorkflowDeletion && request.State == WorkflowCompleted && (workflow.DeleteProviderData || binding.Retention.ProviderProofRequired) && !validDigest(request.ProviderProofDigest) {
		return LifecycleWorkflow{}, ErrInvalid
	}
	if request.ProviderProofDigest != "" && !validDigest(request.ProviderProofDigest) {
		return LifecycleWorkflow{}, ErrInvalid
	}
	now := service.now().UTC()
	workflow.State = request.State
	workflow.ProviderProofDigest = request.ProviderProofDigest
	workflow.Actor = actor
	workflow.UpdatedAt = now
	workflow.Generation++
	workflow = SealWorkflow(workflow)
	var updatedBinding *Binding
	expectedBindingGeneration := uint64(0)
	if workflow.Kind == WorkflowReauthorization && workflow.State == WorkflowCompleted {
		expectedBindingGeneration = binding.Generation
		binding.SecretReferences = cloneSecrets(workflow.NewSecretReferences)
		binding.Lifecycle = LifecycleEnabled
		binding.Generation++
		binding.UpdatedAt = now
		updatedBinding = &binding
	}
	if err = service.repository.TransitionWorkflow(ctx, workflow, request.ExpectedGeneration, updatedBinding, expectedBindingGeneration); err != nil {
		return LifecycleWorkflow{}, err
	}
	if err = service.recordAudit(ctx, authorization, "workflow_"+string(workflow.State), workflow.Digest, request.ProviderProofDigest, workflow.Generation); err != nil {
		return LifecycleWorkflow{}, err
	}
	return workflow, nil
}

func validTransition(current, next WorkflowState) bool {
	return current == WorkflowPending && (next == WorkflowAwaitingProof || next == WorkflowFailed) ||
		current == WorkflowAwaitingProof && (next == WorkflowCompleted || next == WorkflowFailed)
}

func newSecretSet(current, replacement []SecretReference) bool {
	if len(replacement) == 0 || len(replacement) > 32 {
		return false
	}
	last := ""
	changed := len(current) != len(replacement)
	for index, reference := range replacement {
		if reference.Validate() != nil || reference.Purpose <= last {
			return false
		}
		last = reference.Purpose
		if index >= len(current) || current[index] != reference {
			changed = true
		}
	}
	return changed
}

func cloneSecrets(references []SecretReference) []SecretReference {
	return append([]SecretReference(nil), references...)
}

func (service *Service) authorize(ctx context.Context, request AuthorizationRequest) error {
	if request.Validate() != nil {
		return ErrInvalid
	}
	if err := service.authorizer.AuthorizeProviderPolicy(ctx, request); err != nil {
		service.recordAudit(ctx, request, "authorization_denied", "", "", 0)
		return ErrDenied
	}
	return nil
}

func (service *Service) recordAudit(ctx context.Context, request AuthorizationRequest, outcome, resourceDigest, evidenceDigest string, generation uint64) error {
	record := AuditRecord{Actor: request.Actor, TenantID: request.TenantID, BindingID: request.BindingID, ProviderID: request.ProviderID, Action: request.Action,
		Risk: request.Risk, Outcome: outcome, ResourceDigest: resourceDigest, EvidenceDigest: evidenceDigest, Generation: generation, OccurredAt: service.now().UTC()}
	record.Digest = auditDigest(record)
	if record.Validate() != nil {
		return ErrIntegrity
	}
	return service.audit.RecordProviderPolicy(ctx, record)
}

func consentRecordDigest(consent *ConsentRecord) string {
	if consent == nil {
		return ""
	}
	return consent.RecordDigest
}

func SortBindingInput(binding *Binding) {
	if binding == nil {
		return
	}
	sort.Strings(binding.AllowedDataClasses)
	sort.Slice(binding.SecretReferences, func(i, j int) bool { return binding.SecretReferences[i].Purpose < binding.SecretReferences[j].Purpose })
	for index := range binding.Scopes {
		sort.Strings(binding.Scopes[index].Resources)
	}
	sort.Slice(binding.Scopes, func(i, j int) bool { return binding.Scopes[i].Capability < binding.Scopes[j].Capability })
}
