package redisservice

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Clock interface {
	Now() time.Time
}

type IDSource interface {
	NewID(string) (string, error)
}

type AuthorizationRequest struct {
	ActorID            string
	PlanID             string
	PlanDigest         string
	InstanceID         InstanceID
	Action             PlanAction
	MFARequired        bool
	PhishingResistant  bool
	RequestedAt        time.Time
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (AuthorizationEvidence, error)
}

type MaintenanceRequest struct {
	ActorID     string
	PlanID      string
	PlanDigest  string
	NodeID      string
	InstanceID  InstanceID
	Action      PlanAction
	RequestedAt time.Time
}

type MaintenanceGate interface {
	AuthorizeMaintenance(context.Context, MaintenanceRequest) (MaintenanceEvidence, error)
}

type RemapGuard interface {
	VerifyRestoreSafe(context.Context, InstanceID, *RemapPlan, ConsumerSnapshot) error
	WithRestoreFence(context.Context, InstanceID, *RemapPlan, ConsumerSnapshot, func() error) error
}

type PackageAction string

const (
	PackageInstall PackageAction = "install_profile"
	PackageRemove  PackageAction = "remove_profile"
)

type PackageDelegation struct {
	OperationID                       string        `json:"operation_id"`
	LifecyclePlanID                   string        `json:"lifecycle_plan_id"`
	LifecyclePlanDigest               string        `json:"lifecycle_plan_digest"`
	InstanceID                        InstanceID    `json:"instance_id"`
	ConsumerSnapshotGeneration uint64 `json:"consumer_snapshot_generation"`
	ConsumerSnapshotDigest     string        `json:"consumer_snapshot_digest,omitempty"`
	RecoveryArtifactID         string        `json:"recovery_artifact_id,omitempty"`
	ProfileID                  string        `json:"profile_id"`
	Action                     PackageAction `json:"action"`
	RedisVersion               string        `json:"redis_version"`
	SupportDigest              string        `json:"support_digest"`
}

type PackageReceipt struct {
	ID             string `json:"id"`
	PlanDigest     string `json:"plan_digest"`
	ProfileID      string `json:"profile_id"`
	Outcome        string `json:"outcome"`
	EvidenceDigest string `json:"evidence_digest"`
}

type PackageMaintenance interface {
	Delegate(context.Context, PackageDelegation) (PackageReceipt, error)
}

type ExecutionRequest struct {
	Operation Operation
	Plan      LifecyclePlan
	Spec      InstanceSpec
	Observed  InstanceObservation
	Consumers *ConsumerSnapshot
}

type ExecutionResult struct {
	Receipt   LifecycleReceipt
	Artifacts []ArtifactDescriptor
}

type Runtime interface {
	Execute(context.Context, ExecutionRequest) (ExecutionResult, error)
}

type Observer interface {
	Observe(context.Context, InstanceSpec, uint64) (InstanceObservation, error)
}

type AdmitRequest struct {
	OperationID string
	ActorID     string
	PlanID      string
}

type Service struct {
	repository  Repository
	support     SupportCatalog
	authorizer  Authorizer
	maintenance MaintenanceGate
	remaps      RemapGuard
	runtime     Runtime
	clock       Clock
	ids         IDSource
}

func NewService(repository Repository, support SupportCatalog, authorizer Authorizer, maintenance MaintenanceGate, remaps RemapGuard, runtime Runtime, clock Clock, ids IDSource) (*Service, error) {
	if repository == nil || support == nil || authorizer == nil || maintenance == nil || remaps == nil || runtime == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: incomplete service dependencies", ErrInvalid)
	}
	return &Service{repository: repository, support: support, authorizer: authorizer, maintenance: maintenance, remaps: remaps, runtime: runtime, clock: clock, ids: ids}, nil
}

func planContains(plan LifecyclePlan, kind StepKind) bool {
	for _, step := range plan.Steps {
		if step.Kind == kind {
			return true
		}
	}
	return false
}

func phishingResistanceRequired(plan LifecyclePlan) bool {
	return plan.Action == ActionRemove || plan.Action == ActionRestore || planContains(plan, StepInstall)
}

func validateAuthorization(evidence AuthorizationEvidence, plan LifecyclePlan, now time.Time) error {
	sealed, err := SealAuthorization(evidence)
	if err != nil || sealed.Digest != evidence.Digest || evidence.PlanID != plan.ID || evidence.PlanDigest != plan.Digest || evidence.Action != plan.Action || evidence.IssuedAt.After(now) || !now.Before(evidence.ExpiresAt) {
		return fmt.Errorf("%w: authorization evidence binding", ErrUnauthorized)
	}
	if plan.RequiresStepUp && (evidence.MFAAt.IsZero() || evidence.MFAAt.After(now) || now.Sub(evidence.MFAAt) > 15*time.Minute) {
		return fmt.Errorf("%w: recent MFA required", ErrUnauthorized)
	}
	if phishingResistanceRequired(plan) && (evidence.PhishingResistantAt.IsZero() || evidence.PhishingResistantAt.After(now) || now.Sub(evidence.PhishingResistantAt) > 15*time.Minute) {
		return fmt.Errorf("%w: recent phishing-resistant step-up required", ErrUnauthorized)
	}
	return nil
}

func validateMaintenance(evidence MaintenanceEvidence, plan LifecyclePlan, now time.Time) error {
	sealed, err := SealMaintenance(evidence)
	if err != nil || sealed.Digest != evidence.Digest || evidence.PlanID != plan.ID || evidence.PlanDigest != plan.Digest || evidence.NodeID != plan.NodeID || now.Before(evidence.StartsAt) || !now.Before(evidence.EndsAt) {
		return fmt.Errorf("%w: maintenance evidence binding", ErrMaintenanceRequired)
	}
	return nil
}

func sameArtifact(left, right ArtifactDescriptor) bool {
	leftDigest, leftErr := digestValue(left)
	rightDigest, rightErr := digestValue(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}

func validateBackupArtifacts(spec InstanceSpec, artifacts []ArtifactDescriptor) error {
	expected := make(map[ArtifactKind]bool, 2)
	if spec.Persistence.RDB != RDBDisabled {
		expected[ArtifactRDB] = true
	}
	if spec.Backup.IncludeAOF && spec.Persistence.AOF != AOFDisabled {
		expected[ArtifactAOF] = true
	}
	if len(expected) == 0 || len(artifacts) != len(expected) {
		return fmt.Errorf("%w: incomplete backup artifact set", ErrAmbiguous)
	}
	groupID := ""
	seen := make(map[ArtifactKind]bool, len(artifacts))
	for _, artifact := range artifacts {
		if validateArtifact(artifact) != nil || artifact.InstanceID != spec.ID || artifact.RedisVersion != spec.Support.RedisVersion || artifact.ConfigGeneration != spec.ConfigGeneration || !expected[artifact.Kind] || seen[artifact.Kind] {
			return fmt.Errorf("%w: unbound backup artifact", ErrInvalid)
		}
		if groupID == "" {
			groupID = artifact.GroupID
		} else if artifact.GroupID != groupID {
			return fmt.Errorf("%w: split backup artifact group", ErrInvalid)
		}
		seen[artifact.Kind] = true
	}
	return nil
}

func receiptMatchesPlan(receipt LifecycleReceipt, plan LifecyclePlan) bool {
	if len(receipt.Steps) == 0 || len(receipt.Steps) > len(plan.Steps) || (receipt.Outcome == "confirmed" && len(receipt.Steps) != len(plan.Steps)) {
		return false
	}
	for index, step := range receipt.Steps {
		if step.Index != index || step.Kind != plan.Steps[index].Kind {
			return false
		}
	}
	return true
}

func (s *Service) verifyPlanState(ctx context.Context, plan LifecyclePlan, now time.Time) (InstanceSpec, InstanceObservation, *ConsumerSnapshot, error) {
	sealed, err := SealLifecyclePlan(plan)
	if err != nil || sealed.Digest != plan.Digest || now.Before(plan.CreatedAt) || !now.Before(plan.ExpiresAt) {
		return InstanceSpec{}, InstanceObservation{}, nil, fmt.Errorf("%w: immutable plan binding", ErrStale)
	}
	spec, err := s.repository.Spec(ctx, plan.InstanceID)
	if err != nil {
		return InstanceSpec{}, InstanceObservation{}, nil, err
	}
	sealedSpec, sealSpecErr := SealInstanceSpec(spec)
	if sealSpecErr != nil || sealedSpec.Digest != spec.Digest || spec.Generation != plan.ExpectedSpecGeneration || spec.Digest != plan.TargetSpecDigest || spec.NodeID != plan.NodeID {
		return InstanceSpec{}, InstanceObservation{}, nil, ErrStale
	}
	if err := s.support.Qualify(ctx, spec.Support); err != nil {
		return InstanceSpec{}, InstanceObservation{}, nil, fmt.Errorf("%w: support tuple no longer qualified", ErrUnsupported)
	}
	observed, err := s.repository.Observation(ctx, plan.InstanceID)
	if err != nil {
		return InstanceSpec{}, InstanceObservation{}, nil, err
	}
	sealedObserved, sealObservedErr := SealObservation(observed)
	if sealObservedErr != nil || sealedObserved.EvidenceDigest != observed.EvidenceDigest || observed.Generation != plan.ExpectedObservedGeneration || observed.ConfigGeneration != plan.ExpectedConfigGeneration || observed.NodeID != plan.NodeID {
		return InstanceSpec{}, InstanceObservation{}, nil, ErrStale
	}
	if plan.Recovery.PriorConfigGeneration != observed.ConfigGeneration || plan.Recovery.PriorConfigDigest != observed.ActualConfigDigest {
		return InstanceSpec{}, InstanceObservation{}, nil, ErrStale
	}
	var consumers *ConsumerSnapshot
	if plan.ConsumerSnapshotGeneration != 0 {
		snapshot, snapshotErr := s.repository.ConsumerSnapshot(ctx, plan.InstanceID)
		if snapshotErr != nil {
			return InstanceSpec{}, InstanceObservation{}, nil, snapshotErr
		}
		sealedSnapshot, sealErr := SealConsumerSnapshot(snapshot)
		if sealErr != nil || sealedSnapshot.EvidenceDigest != snapshot.EvidenceDigest || snapshot.Generation != plan.ConsumerSnapshotGeneration || snapshot.EvidenceDigest != plan.ConsumerSnapshotDigest || snapshot.ObservedAt.After(now) || now.Sub(snapshot.ObservedAt) > 5*time.Minute {
			return InstanceSpec{}, InstanceObservation{}, nil, fmt.Errorf("%w: consumer snapshot changed", ErrStale)
		}
		if plan.Action == ActionRemove && len(snapshot.Consumers) != 0 {
			return InstanceSpec{}, InstanceObservation{}, nil, ErrConsumersPresent
		}
		if plan.Action == ActionRestore {
			active := make([]string, 0, len(snapshot.Consumers))
			for _, consumer := range snapshot.Consumers {
				if consumer.Active {
					active = append(active, consumer.ID)
				}
			}
			sort.Strings(active)
			if len(active) != 0 {
				if plan.Remap == nil || plan.Remap.Generation != snapshot.Generation || strings.Join(active, "\x00") != strings.Join(plan.Remap.ConsumerIDs, "\x00") {
					return InstanceSpec{}, InstanceObservation{}, nil, ErrConsumersPresent
				}
			}
			if remapErr := s.remaps.VerifyRestoreSafe(ctx, plan.InstanceID, plan.Remap, snapshot); remapErr != nil {
				return InstanceSpec{}, InstanceObservation{}, nil, fmt.Errorf("%w: restore consumer safety not proven", ErrConsumersPresent)
			}
		}
		consumers = &snapshot
	}
	if plan.Artifact != nil {
		artifact, artifactErr := s.repository.Artifact(ctx, plan.Artifact.ID)
		if artifactErr != nil || !sameArtifact(artifact, *plan.Artifact) {
			return InstanceSpec{}, InstanceObservation{}, nil, fmt.Errorf("%w: restore artifact changed", ErrStale)
		}
	}
	if plan.Recovery.RecoveryArtifactRef != "" {
		recovery, recoveryErr := s.repository.Artifact(ctx, plan.Recovery.RecoveryArtifactRef)
		if recoveryErr != nil || compatibleArtifact(spec, recovery) != nil || recovery.InstanceID != plan.InstanceID || recovery.ConfigGeneration != observed.ConfigGeneration || (observed.ActualVersion != "" && recovery.RedisVersion != observed.ActualVersion) || (plan.Artifact != nil && recovery.ID == plan.Artifact.ID) {
			return InstanceSpec{}, InstanceObservation{}, nil, fmt.Errorf("%w: recovery artifact is unavailable or unbound", ErrStale)
		}
	}
	return spec, observed, consumers, nil
}

func (s *Service) audit(operationID, actorID, kind string, plan LifecyclePlan, evidence string, at time.Time) (AuditEvent, error) {
	id, err := s.ids.NewID("redis-audit")
	if err != nil {
		return AuditEvent{}, err
	}
	event := AuditEvent{ID: id, OperationID: operationID, ActorID: actorID, Kind: kind, Resource: "redis:" + string(plan.InstanceID), RequestDigest: plan.Digest, EvidenceDigest: evidence, OccurredAt: at.UTC()}
	if err := validateAudit(event); err != nil {
		return AuditEvent{}, err
	}
	return event, nil
}

func (s *Service) markAmbiguous(ctx context.Context, operation Operation, plan LifecyclePlan, class string) {
	evidence, err := digestValue(struct {
		OperationID string `json:"operation_id"`
		PlanDigest  string `json:"plan_digest"`
		Class       string `json:"class"`
	}{operation.ID, plan.Digest, class})
	if err != nil {
		return
	}
	audit, err := s.audit(operation.ID, operation.Authorization.ActorID, "redis.operation.ambiguous", plan, evidence, s.clock.Now().UTC())
	if err == nil {
		_, _ = s.repository.TransitionOperation(ctx, operation.ID, OperationRunning, operation.Version, OperationAmbiguous, "", audit)
	}
}

func (s *Service) Admit(ctx context.Context, request AdmitRequest) (Operation, error) {
	if !validID(request.OperationID) || !validID(request.ActorID) || !validID(request.PlanID) {
		return Operation{}, fmt.Errorf("%w: admission request", ErrInvalid)
	}
	now := s.clock.Now().UTC()
	plan, err := s.repository.Plan(ctx, request.PlanID)
	if err != nil {
		return Operation{}, err
	}
	if _, _, _, err := s.verifyPlanState(ctx, plan, now); err != nil {
		return Operation{}, err
	}
	authorization, err := s.authorizer.Authorize(ctx, AuthorizationRequest{
		ActorID: request.ActorID, PlanID: plan.ID, PlanDigest: plan.Digest, InstanceID: plan.InstanceID,
		Action: plan.Action, MFARequired: plan.RequiresStepUp, PhishingResistant: phishingResistanceRequired(plan), RequestedAt: now,
	})
	if err != nil {
		return Operation{}, fmt.Errorf("%w: authorization denied", ErrUnauthorized)
	}
	if err := validateAuthorization(authorization, plan, now); err != nil {
		return Operation{}, err
	}
	if authorization.ActorID != request.ActorID {
		return Operation{}, fmt.Errorf("%w: authorization actor mismatch", ErrUnauthorized)
	}
	var maintenance *MaintenanceEvidence
	if plan.RequiresMaintenance {
		evidence, maintenanceErr := s.maintenance.AuthorizeMaintenance(ctx, MaintenanceRequest{
			ActorID: request.ActorID, PlanID: plan.ID, PlanDigest: plan.Digest, NodeID: plan.NodeID,
			InstanceID: plan.InstanceID, Action: plan.Action, RequestedAt: now,
		})
		if maintenanceErr != nil {
			return Operation{}, fmt.Errorf("%w: maintenance denied", ErrMaintenanceRequired)
		}
		if err := validateMaintenance(evidence, plan, now); err != nil {
			return Operation{}, err
		}
		maintenance = &evidence
	}
	operation := Operation{
		ID: request.OperationID, PlanID: plan.ID, PlanDigest: plan.Digest, State: OperationAdmitted, Version: 1,
		Authorization: authorization, Maintenance: maintenance, CreatedAt: now, UpdatedAt: now,
	}
	audit, err := s.audit(operation.ID, request.ActorID, "redis.operation.admitted", plan, authorization.Digest, now)
	if err != nil {
		return Operation{}, err
	}
	if err := s.repository.AdmitOperation(ctx, operation, audit); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func normalizedErrorClass(err error) string {
	switch {
	case err == nil:
		return "missing_receipt"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, ErrStale):
		return "stale"
	case errors.Is(err, ErrConsumersPresent):
		return "consumers"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrAmbiguous):
		return "ambiguous"
	default:
		return "execution_failed"
	}
}

func (s *Service) Execute(ctx context.Context, operationID string) (LifecycleReceipt, error) {
	if !validID(operationID) {
		return LifecycleReceipt{}, fmt.Errorf("%w: operation id", ErrInvalid)
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
	spec, observed, consumers, err := s.verifyPlanState(ctx, plan, now)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	if operation.PlanDigest != plan.Digest || validateAuthorization(operation.Authorization, plan, now) != nil {
		return LifecycleReceipt{}, ErrUnauthorized
	}
	if plan.RequiresMaintenance {
		if operation.Maintenance == nil || validateMaintenance(*operation.Maintenance, plan, now) != nil {
			return LifecycleReceipt{}, ErrMaintenanceRequired
		}
	}
	startAudit, err := s.audit(operation.ID, operation.Authorization.ActorID, "redis.operation.started", plan, operation.Authorization.Digest, now)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	operation, err = s.repository.TransitionOperation(ctx, operation.ID, OperationAdmitted, operation.Version, OperationRunning, "", startAudit)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	result, executionErr := s.runtime.Execute(ctx, ExecutionRequest{Operation: operation, Plan: plan, Spec: spec, Observed: observed, Consumers: consumers})
	receipt := result.Receipt
	sealedReceipt, sealErr := SealLifecycleReceipt(receipt)
	if sealErr != nil || sealedReceipt.EvidenceDigest != receipt.EvidenceDigest || receipt.OperationID != operation.ID || receipt.PlanID != plan.ID || receipt.PlanDigest != plan.Digest || !receiptMatchesPlan(receipt, plan) || ((executionErr == nil) != (receipt.Outcome == "confirmed")) {
		s.markAmbiguous(ctx, operation, plan, normalizedErrorClass(executionErr))
		return LifecycleReceipt{}, fmt.Errorf("%w: runtime did not return a bound receipt", ErrAmbiguous)
	}
	if plan.Action == ActionBackup {
		if err := validateBackupArtifacts(spec, result.Artifacts); err != nil {
			s.markAmbiguous(ctx, operation, plan, "artifact_binding")
			return LifecycleReceipt{}, err
		}
	}
	if plan.Action != ActionBackup && len(result.Artifacts) != 0 {
		s.markAmbiguous(ctx, operation, plan, "unexpected_artifact")
		return LifecycleReceipt{}, fmt.Errorf("%w: unexpected execution artifacts", ErrInvalid)
	}
	for _, artifact := range result.Artifacts {
		if artifact.InstanceID != plan.InstanceID || validateArtifact(artifact) != nil {
			s.markAmbiguous(ctx, operation, plan, "artifact_binding")
			return LifecycleReceipt{}, fmt.Errorf("%w: unbound backup artifact", ErrInvalid)
		}
		if err := s.repository.PutArtifact(ctx, artifact); err != nil {
			s.markAmbiguous(ctx, operation, plan, "artifact_persistence")
			return LifecycleReceipt{}, err
		}
	}
	receiptAudit, err := s.audit(operation.ID, operation.Authorization.ActorID, "redis.receipt.recorded", plan, receipt.EvidenceDigest, receipt.CompletedAt)
	if err != nil {
		s.markAmbiguous(ctx, operation, plan, "receipt_audit")
		return LifecycleReceipt{}, err
	}
	if err := s.repository.PutReceipt(ctx, receipt, receiptAudit); err != nil {
		s.markAmbiguous(ctx, operation, plan, "receipt_persistence")
		return LifecycleReceipt{}, err
	}
	next := OperationSucceeded
	switch receipt.Outcome {
	case "confirmed":
		next = OperationSucceeded
	case "failed":
		next = OperationFailed
	case "compensated":
		next = OperationCompensated
	default:
		next = OperationAmbiguous
	}
	finishAudit, err := s.audit(operation.ID, operation.Authorization.ActorID, "redis.operation."+string(next), plan, receipt.EvidenceDigest, receipt.CompletedAt)
	if err != nil {
		s.markAmbiguous(ctx, operation, plan, "completion_audit")
		return LifecycleReceipt{}, err
	}
	if _, err := s.repository.TransitionOperation(ctx, operation.ID, OperationRunning, operation.Version, next, receipt.ID, finishAudit); err != nil {
		return LifecycleReceipt{}, err
	}
	if executionErr != nil {
		return receipt, executionErr
	}
	if next != OperationSucceeded {
		return receipt, fmt.Errorf("Redis operation ended %s", next)
	}
	return receipt, nil
}
