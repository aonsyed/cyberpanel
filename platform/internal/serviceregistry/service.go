package serviceregistry

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Clock interface {
	Now() time.Time
}

type IDSource interface {
	NewID(prefix string) (string, error)
}

type AuthorizationRequest struct {
	ActorID            string
	NodeID             string
	ServiceID          ServiceID
	Action             Action
	PlanID             string
	PlanDigest         string
	PhishingResistant  bool
	RequestedAt        time.Time
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (AuthorizationEvidence, error)
}

type MaintenanceRequest struct {
	ActorID     string
	NodeID      string
	ServiceID   ServiceID
	Action      Action
	PlanID      string
	PlanDigest  string
	RequestedAt time.Time
}

type MaintenanceGate interface {
	AuthorizeMaintenance(context.Context, MaintenanceRequest) (MaintenanceEvidence, error)
}

type ConsumerInventory interface {
	Snapshot(context.Context, string, ServiceID) (ConsumerSnapshot, error)
}

type PackageAction string

const (
	PackageInstall PackageAction = "install_profile"
	PackageRemove  PackageAction = "remove_profile"
	PackageRepair  PackageAction = "repair_profile"
)

type PackageDelegation struct {
	OperationID             string        `json:"operation_id"`
	LifecyclePlanID         string        `json:"lifecycle_plan_id"`
	LifecyclePlanDigest     string        `json:"lifecycle_plan_digest"`
	NodeID                  string        `json:"node_id"`
	ServiceID               ServiceID     `json:"service_id"`
	ProfileID               string        `json:"profile_id"`
	Action                  PackageAction `json:"action"`
	ExpectedConfigGeneration uint64        `json:"expected_config_generation"`
}

type PackageDelegationReceipt struct {
	ReceiptID     string `json:"receipt_id"`
	PlanDigest   string `json:"plan_digest"`
	ProfileID    string `json:"profile_id"`
	Outcome      string `json:"outcome"`
	EvidenceDigest string `json:"evidence_digest"`
}

type PackageMaintenance interface {
	Delegate(context.Context, PackageDelegation) (PackageDelegationReceipt, error)
}

type ExecutionRequest struct {
	Operation Operation
	Plan      LifecyclePlan
}

type Executor interface {
	Execute(context.Context, ExecutionRequest) (LifecycleReceipt, error)
}

type AdmitRequest struct {
	OperationID string
	ActorID     string
	PlanID      string
}

type Service struct {
	registry    *Registry
	repository  Repository
	authorizer  Authorizer
	maintenance MaintenanceGate
	consumers   ConsumerInventory
	executor    Executor
	clock       Clock
	ids         IDSource
}

func NewService(registry *Registry, repository Repository, authorizer Authorizer, maintenance MaintenanceGate, consumers ConsumerInventory, executor Executor, clock Clock, ids IDSource) (*Service, error) {
	if registry == nil || repository == nil || authorizer == nil || maintenance == nil || consumers == nil || executor == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: incomplete service dependencies", ErrInvalid)
	}
	return &Service{
		registry:    registry,
		repository:  repository,
		authorizer:  authorizer,
		maintenance: maintenance,
		consumers:   consumers,
		executor:    executor,
		clock:       clock,
		ids:         ids,
	}, nil
}

func (s *Service) verifyConsumers(ctx context.Context, plan LifecyclePlan, now time.Time) error {
	if !requiresConsumerSnapshot(plan.Action) {
		return nil
	}
	snapshot, err := s.consumers.Snapshot(ctx, plan.NodeID, plan.Target)
	if err != nil {
		return fmt.Errorf("%w: consumer inventory unavailable", ErrStale)
	}
	sealed, err := SealConsumerSnapshot(snapshot)
	if err != nil || sealed.EvidenceDigest != snapshot.EvidenceDigest || snapshot.NodeID != plan.NodeID || snapshot.ServiceID != plan.Target || snapshot.Generation != plan.ConsumerSnapshotGeneration || snapshot.EvidenceDigest != plan.ConsumerSnapshotDigest || snapshot.ObservedAt.After(now) || now.Sub(snapshot.ObservedAt) > 5*time.Minute {
		return fmt.Errorf("%w: consumer inventory changed", ErrStale)
	}
	expectedExternal := make(map[string]ConsumerBinding)
	for _, consumer := range plan.Consumers {
		if consumer.Kind != "registered_service" {
			expectedExternal[consumer.ID] = consumer
		}
	}
	for _, consumer := range snapshot.Consumers {
		if (plan.Action == ActionStop && consumer.Active) || plan.Action == ActionRemove {
			return ErrConsumersPresent
		}
		included := consumer.Active
		expected, wasIncluded := expectedExternal[consumer.ID]
		if included != wasIncluded || (included && (expected.Kind != consumer.Kind || expected.ServiceID != consumer.ServiceID || expected.Active != consumer.Active || expected.EvidenceRef != consumer.EvidenceRef)) {
			return fmt.Errorf("%w: external consumer set changed", ErrStale)
		}
		delete(expectedExternal, consumer.ID)
	}
	if len(expectedExternal) != 0 {
		return fmt.Errorf("%w: external consumer set changed", ErrStale)
	}
	expectedRegistered := make(map[string]ConsumerBinding)
	for _, consumer := range plan.Consumers {
		if consumer.Kind == "registered_service" {
			expectedRegistered[consumer.ID] = consumer
		}
	}
	for _, consumerID := range s.registry.consumersOf(plan.Target) {
		observed, observeErr := s.repository.Observed(ctx, plan.NodeID, consumerID)
		if observeErr != nil {
			return fmt.Errorf("%w: registered consumer state unavailable", ErrStale)
		}
		included := observed.Active == ActiveActive || (plan.Action == ActionRemove && observed.Install == InstallInstalled)
		if (plan.Action == ActionStop || plan.Action == ActionRemove) && included {
			return ErrConsumersPresent
		}
		id := "service:" + string(consumerID)
		expected, wasIncluded := expectedRegistered[id]
		if included != wasIncluded || (included && (expected.ServiceID != consumerID || expected.Active != (observed.Active == ActiveActive) || expected.EvidenceRef != observed.EvidenceDigest)) {
			return fmt.Errorf("%w: registered consumer state changed", ErrStale)
		}
		delete(expectedRegistered, id)
	}
	if len(expectedRegistered) != 0 {
		return fmt.Errorf("%w: registered consumer set changed", ErrStale)
	}
	return nil
}

func (s *Service) verifyGenerations(ctx context.Context, plan LifecyclePlan) error {
	if plan.ExpectedDesiredGeneration == 0 {
		_, err := s.repository.Desired(ctx, plan.NodeID, plan.Target)
		if err == nil {
			return ErrStale
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
	} else {
		desired, err := s.repository.Desired(ctx, plan.NodeID, plan.Target)
		if err != nil {
			return err
		}
		if desired.Generation != plan.ExpectedDesiredGeneration || desired.ConfigGeneration != plan.ExpectedConfigGeneration || desired.DefinitionDigest != plan.RegistryDigest {
			return ErrStale
		}
	}
	for _, step := range plan.Steps {
		observed, err := s.repository.Observed(ctx, plan.NodeID, step.ServiceID)
		if err != nil {
			return err
		}
		if observed.Generation != step.ExpectedObservedGeneration || observed.ConfigGeneration != step.ExpectedConfigGeneration || observed.DefinitionDigest != plan.RegistryDigest {
			return ErrStale
		}
	}
	return nil
}

func (s *Service) requiresPhishingResistance(plan LifecyclePlan) bool {
	definition, ok := s.registry.Definition(plan.Target)
	if !ok {
		return true
	}
	if plan.Action == ActionInstall || plan.Action == ActionRemove || plan.Action == ActionRepair {
		return true
	}
	return definition.Capabilities.Critical && (plan.Action == ActionStop || plan.Action == ActionRestart || plan.Action == ActionDisable)
}

func (s *Service) newAudit(operationID, actorID, kind, resource, requestDigest, evidenceDigest string, now time.Time) (AuditEvent, error) {
	id, err := s.ids.NewID("audit")
	if err != nil {
		return AuditEvent{}, fmt.Errorf("allocate audit id: %w", err)
	}
	event := AuditEvent{
		ID:             id,
		OperationID:    operationID,
		ActorID:        actorID,
		Kind:           kind,
		Resource:       resource,
		RequestDigest:  requestDigest,
		EvidenceDigest: evidenceDigest,
		OccurredAt:     now.UTC(),
	}
	if err := validateAudit(event); err != nil {
		return AuditEvent{}, err
	}
	return event, nil
}

func (s *Service) Admit(ctx context.Context, request AdmitRequest) (Operation, error) {
	if !validID(request.OperationID) || !validID(request.ActorID) || !validID(request.PlanID) {
		return Operation{}, fmt.Errorf("%w: invalid admission request", ErrInvalid)
	}
	now := s.clock.Now().UTC()
	plan, err := s.repository.Plan(ctx, request.PlanID)
	if err != nil {
		return Operation{}, err
	}
	if err := s.registry.ValidateExecutablePlan(plan, now); err != nil {
		return Operation{}, err
	}
	if err := s.verifyGenerations(ctx, plan); err != nil {
		return Operation{}, err
	}
	if err := s.verifyConsumers(ctx, plan, now); err != nil {
		return Operation{}, err
	}
	phishingResistant := s.requiresPhishingResistance(plan)
	auth, err := s.authorizer.Authorize(ctx, AuthorizationRequest{
		ActorID:           request.ActorID,
		NodeID:            plan.NodeID,
		ServiceID:         plan.Target,
		Action:            plan.Action,
		PlanID:            plan.ID,
		PlanDigest:        plan.Digest,
		PhishingResistant: phishingResistant,
		RequestedAt:       now,
	})
	if err != nil {
		return Operation{}, fmt.Errorf("%w: authorization denied", ErrUnauthorized)
	}
	if err := ValidateAuthorization(auth, plan, now, phishingResistant); err != nil {
		return Operation{}, err
	}
	var maintenance *MaintenanceEvidence
	if plan.RequiresMaintenance {
		evidence, err := s.maintenance.AuthorizeMaintenance(ctx, MaintenanceRequest{
			ActorID:     request.ActorID,
			NodeID:      plan.NodeID,
			ServiceID:   plan.Target,
			Action:      plan.Action,
			PlanID:      plan.ID,
			PlanDigest:  plan.Digest,
			RequestedAt: now,
		})
		if err != nil {
			return Operation{}, fmt.Errorf("%w: maintenance denied", ErrMaintenanceRequired)
		}
		if err := ValidateMaintenance(evidence, plan, now); err != nil {
			return Operation{}, err
		}
		maintenance = &evidence
	}
	operation := Operation{
		ID:            request.OperationID,
		PlanID:        plan.ID,
		PlanDigest:    plan.Digest,
		State:         OperationAdmitted,
		Version:       1,
		Authorization: auth,
		Maintenance:   maintenance,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	audit, err := s.newAudit(operation.ID, request.ActorID, "service.operation.admitted", plan.NodeID+":"+string(plan.Target), plan.Digest, auth.Digest, now)
	if err != nil {
		return Operation{}, err
	}
	if err := s.repository.AdmitOperation(ctx, operation, audit); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func (s *Service) Execute(ctx context.Context, operationID string) (LifecycleReceipt, error) {
	if !validID(operationID) {
		return LifecycleReceipt{}, fmt.Errorf("%w: invalid operation id", ErrInvalid)
	}
	operation, err := s.repository.Operation(ctx, operationID)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	if operation.State != OperationAdmitted {
		return LifecycleReceipt{}, fmt.Errorf("%w: operation is %s", ErrConflict, operation.State)
	}
	plan, err := s.repository.Plan(ctx, operation.PlanID)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	now := s.clock.Now().UTC()
	if operation.PlanDigest != plan.Digest {
		return LifecycleReceipt{}, ErrStale
	}
	if err := s.registry.ValidateExecutablePlan(plan, now); err != nil {
		return LifecycleReceipt{}, err
	}
	if err := s.verifyGenerations(ctx, plan); err != nil {
		return LifecycleReceipt{}, err
	}
	if err := s.verifyConsumers(ctx, plan, now); err != nil {
		return LifecycleReceipt{}, err
	}
	if err := ValidateAuthorization(operation.Authorization, plan, now, s.requiresPhishingResistance(plan)); err != nil {
		return LifecycleReceipt{}, err
	}
	if plan.RequiresMaintenance {
		if operation.Maintenance == nil {
			return LifecycleReceipt{}, ErrMaintenanceRequired
		}
		if err := ValidateMaintenance(*operation.Maintenance, plan, now); err != nil {
			return LifecycleReceipt{}, err
		}
	}
	startAudit, err := s.newAudit(operation.ID, operation.Authorization.ActorID, "service.operation.started", plan.NodeID+":"+string(plan.Target), plan.Digest, operation.Authorization.Digest, now)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	operation, err = s.repository.TransitionOperation(ctx, operation.ID, OperationAdmitted, operation.Version, OperationRunning, "", startAudit)
	if err != nil {
		return LifecycleReceipt{}, err
	}

	receipt, executionErr := s.executor.Execute(ctx, ExecutionRequest{Operation: operation, Plan: plan})
	sealedReceipt, sealErr := SealLifecycleReceipt(receipt)
	if sealErr != nil || sealedReceipt.EvidenceDigest != receipt.EvidenceDigest || receipt.OperationID != operation.ID || receipt.PlanID != plan.ID || receipt.PlanDigest != plan.Digest {
		failureEvidence, _ := digestValue(struct {
			OperationID string `json:"operation_id"`
			PlanDigest  string `json:"plan_digest"`
			Class       string `json:"class"`
		}{operation.ID, plan.Digest, normalizedErrorClass(executionErr)})
		failureAudit, auditErr := s.newAudit(operation.ID, operation.Authorization.ActorID, "service.operation.ambiguous", plan.NodeID+":"+string(plan.Target), plan.Digest, failureEvidence, s.clock.Now().UTC())
		if auditErr == nil {
			_, _ = s.repository.TransitionOperation(ctx, operation.ID, OperationRunning, operation.Version, OperationAmbiguous, "", failureAudit)
		}
		return LifecycleReceipt{}, fmt.Errorf("%w: executor did not return a bound receipt", ErrAmbiguous)
	}
	receiptAudit, err := s.newAudit(operation.ID, operation.Authorization.ActorID, "service.receipt.recorded", plan.NodeID+":"+string(plan.Target), plan.Digest, receipt.EvidenceDigest, receipt.CompletedAt)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	if err := s.repository.PutReceipt(ctx, receipt, receiptAudit); err != nil {
		return LifecycleReceipt{}, err
	}
	next := OperationSucceeded
	switch receipt.Outcome {
	case "confirmed":
		next = OperationSucceeded
	case "compensated":
		next = OperationCompensated
	case "failed":
		next = OperationFailed
	default:
		next = OperationAmbiguous
	}
	finishAudit, err := s.newAudit(operation.ID, operation.Authorization.ActorID, "service.operation."+string(next), plan.NodeID+":"+string(plan.Target), plan.Digest, receipt.EvidenceDigest, receipt.CompletedAt)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	if _, err := s.repository.TransitionOperation(ctx, operation.ID, OperationRunning, operation.Version, next, receipt.ID, finishAudit); err != nil {
		return LifecycleReceipt{}, err
	}
	if executionErr != nil {
		return receipt, executionErr
	}
	if next != OperationSucceeded {
		return receipt, fmt.Errorf("service operation ended %s", next)
	}
	return receipt, nil
}

func normalizedErrorClass(err error) string {
	switch {
	case err == nil:
		return "missing_receipt"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, ErrStale):
		return "stale"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrAmbiguous):
		return "ambiguous"
	default:
		return "execution_failed"
	}
}
