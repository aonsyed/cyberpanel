package diagnosticsrepair

import (
	"context"
	"sort"
	"time"
)

type Action string

const (
	ActionDiagnose Action = "diagnose"
	ActionPreview  Action = "preview"
	ActionApprove  Action = "approve"
	ActionExecute  Action = "execute"
	ActionFence    Action = "fence"
)

type Authorization struct {
	ID               string    `json:"id"`
	Subject          string    `json:"subject"`
	Action           Action    `json:"action"`
	Scope            Scope     `json:"scope"`
	ObjectID         string    `json:"object_id"`
	DefinitionDigest string    `json:"definition_digest,omitempty"`
	HighAssurance    bool      `json:"high_assurance"`
	StepUp           bool      `json:"step_up"`
	ScopeDigest      string    `json:"scope_digest"`
	ProofDigest      string    `json:"proof_digest"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	Digest           string    `json:"digest"`
}

func canonicalAuthorization(authorization Authorization, action Action, scope Scope, objectID, definitionDigest string, mutation bool, now time.Time) (Authorization, error) {
	if !identifierPattern.MatchString(authorization.ID) || !identifierPattern.MatchString(authorization.Subject) || authorization.Action != action ||
		authorization.Scope != scope || authorization.ObjectID != objectID || authorization.DefinitionDigest != definitionDigest ||
		mutation && (!authorization.HighAssurance || !authorization.StepUp) || !validDigest(authorization.ScopeDigest) ||
		!validDigest(authorization.ProofDigest) || !validTime(authorization.IssuedAt) || !validTime(authorization.ExpiresAt) ||
		!authorization.ExpiresAt.After(authorization.IssuedAt) || now.Before(authorization.IssuedAt) || !now.Before(authorization.ExpiresAt) {
		return Authorization{}, ErrUnauthorized
	}
	expected := digestParts("diagnostics-repair-scope", string(action), scope.key(), objectID, definitionDigest)
	if authorization.ScopeDigest != expected { return Authorization{}, ErrUnauthorized }
	authorization.IssuedAt, authorization.ExpiresAt = authorization.IssuedAt.UTC(), authorization.ExpiresAt.UTC()
	claimed := authorization.Digest
	authorization.Digest = ""
	digest, err := digestJSON(authorization)
	if err != nil || claimed != digest { return Authorization{}, ErrIntegrity }
	authorization.Digest = digest
	return authorization, nil
}

type AuthorizationVerifier interface { VerifyDiagnosticsRepairAuthorization(context.Context, Authorization) error }
type ApprovalVerifier interface { VerifyRepairApproval(context.Context, Approval) error }

type AuditRecord struct {
	ID                  string    `json:"id"`
	Action              Action    `json:"action"`
	ObjectID            string    `json:"object_id"`
	Scope               Scope     `json:"scope"`
	Generation          uint64    `json:"generation"`
	Fence               uint64    `json:"fence"`
	AuthorizationDigest string    `json:"authorization_digest"`
	IntentDigest        string    `json:"intent_digest"`
	At                  time.Time `json:"at"`
	Digest              string    `json:"digest"`
}

type AuditSink interface { RecordDiagnosticsRepair(context.Context, AuditRecord) error }

type MaintenanceRequest struct {
	PlanID           string        `json:"plan_id"`
	DefinitionDigest string        `json:"definition_digest"`
	Scope            Scope         `json:"scope"`
	Fence            uint64        `json:"fence"`
	RequestedAt      time.Time     `json:"requested_at"`
	ExpectedDuration time.Duration `json:"expected_duration"`
	Digest           string        `json:"digest"`
}

type MaintenanceAdmission struct {
	Allowed        bool      `json:"allowed"`
	OccurrenceID   string    `json:"occurrence_id"`
	EvidenceDigest string    `json:"evidence_digest"`
	EndsAt         time.Time `json:"ends_at"`
	Digest         string    `json:"digest"`
}

type MaintenanceGate interface { AdmitRepair(context.Context, MaintenanceRequest) (MaintenanceAdmission, error) }

type SnapshotRequest struct {
	PlanID           string        `json:"plan_id"`
	DefinitionDigest string        `json:"definition_digest"`
	Scope            Scope         `json:"scope"`
	ResourceIDs      []string      `json:"resource_ids"`
	Retention        time.Duration `json:"retention"`
	Generation       uint64        `json:"generation"`
	Fence            uint64        `json:"fence"`
	IdempotencyKey   string        `json:"idempotency_key"`
	Digest           string        `json:"digest"`
}

type SnapshotReceipt struct {
	ID              string    `json:"id"`
	OperationDigest string    `json:"operation_digest"`
	Reference       string    `json:"reference"`
	Proven          bool      `json:"proven"`
	EvidenceDigest  string    `json:"evidence_digest"`
	CreatedAt       time.Time `json:"created_at"`
	Digest          string    `json:"digest"`
}

type Snapshotter interface { SnapshotRepair(context.Context, SnapshotRequest) (SnapshotReceipt, error) }

type EffectOperation struct {
	PlanID             string       `json:"plan_id"`
	DefinitionDigest   string       `json:"definition_digest"`
	StepID             string       `json:"step_id"`
	Effect             EffectKind   `json:"effect"`
	Scope              Scope        `json:"scope"`
	ServiceID          string       `json:"service_id"`
	CanonicalGeneration uint64      `json:"canonical_generation"`
	CanonicalDigest    string       `json:"canonical_digest"`
	OwnershipModeDigest string      `json:"ownership_mode_digest,omitempty"`
	CertificateBindingDigest string `json:"certificate_binding_digest,omitempty"`
	SnapshotReference  string       `json:"snapshot_reference"`
	SnapshotEvidence   string       `json:"snapshot_evidence"`
	Generation         uint64       `json:"generation"`
	Fence              uint64       `json:"fence"`
	IdempotencyKey     string       `json:"idempotency_key"`
	Digest             string       `json:"digest"`
}

type CompensationOperation struct {
	EffectOperation EffectOperation `json:"effect_operation"`
	Compensation    Compensation    `json:"compensation"`
	EffectReceipt   string          `json:"effect_receipt"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Digest          string          `json:"digest"`
}

type EffectReceipt struct {
	ID                 string    `json:"id"`
	OperationDigest    string    `json:"operation_digest"`
	Completed          bool      `json:"completed"`
	ObservedGeneration uint64    `json:"observed_generation"`
	EvidenceDigest     string    `json:"evidence_digest"`
	CreatedAt          time.Time `json:"created_at"`
	Digest             string    `json:"digest"`
}

type EffectExecutor interface {
	Apply(context.Context, EffectOperation) (EffectReceipt, error)
	Compensate(context.Context, CompensationOperation) (EffectReceipt, error)
}

type RegisteredEffect struct { Kind EffectKind; Executor EffectExecutor }

type EffectRegistry struct { executors map[EffectKind]EffectExecutor }

func NewEffectRegistry(effects []RegisteredEffect) (*EffectRegistry, error) {
	if len(effects) == 0 || len(effects) > 6 { return nil, ErrInvalid }
	registry := &EffectRegistry{executors: make(map[EffectKind]EffectExecutor, len(effects))}
	for _, effect := range effects {
		if !effect.Kind.Valid() || effect.Executor == nil { return nil, ErrInvalid }
		if _, duplicate := registry.executors[effect.Kind]; duplicate { return nil, ErrInvalid }
		registry.executors[effect.Kind] = effect.Executor
	}
	return registry, nil
}

func (registry *EffectRegistry) executor(kind EffectKind) (EffectExecutor, bool) {
	if registry == nil { return nil, false }
	executor, found := registry.executors[kind]
	return executor, found
}

type VerificationRequest struct {
	PlanID               string     `json:"plan_id"`
	StepID               string     `json:"step_id"`
	Effect                EffectKind `json:"effect"`
	Scope                 Scope      `json:"scope"`
	ExpectedGeneration    uint64     `json:"expected_generation"`
	EffectReceiptDigest   string     `json:"effect_receipt_digest"`
	EffectEvidenceDigest  string     `json:"effect_evidence_digest"`
	Compensation          bool       `json:"compensation"`
	Fence                 uint64     `json:"fence"`
	Digest                string     `json:"digest"`
}

type VerificationReceipt struct {
	RequestDigest  string    `json:"request_digest"`
	Satisfied      bool      `json:"satisfied"`
	EvidenceDigest string    `json:"evidence_digest"`
	ObservedAt     time.Time `json:"observed_at"`
	Digest         string    `json:"digest"`
}

type OutcomeVerifier interface { VerifyRepairOutcome(context.Context, VerificationRequest) (VerificationReceipt, error) }

type ExecutionCommand struct {
	PlanID             string
	ExpectedGeneration uint64
	Fence              uint64
	ControllerID       string
	IdempotencyKey     string
	At                 time.Time
	ExpectedDuration   time.Duration
	Authorization      Authorization
}

type Coordinator struct {
	repository    *Repository
	registry      *Registry
	runner        *Runner
	planner       *Planner
	canonical     CanonicalSource
	authorization AuthorizationVerifier
	approvals     ApprovalVerifier
	audit         AuditSink
	maintenance   MaintenanceGate
	snapshots     Snapshotter
	effects       *EffectRegistry
	outcomes      OutcomeVerifier
	clock         Clock
}

func NewCoordinator(repository *Repository, registry *Registry, runner *Runner, planner *Planner, canonical CanonicalSource,
	authorization AuthorizationVerifier, approvals ApprovalVerifier, audit AuditSink, maintenance MaintenanceGate,
	snapshots Snapshotter, effects *EffectRegistry, outcomes OutcomeVerifier, clock Clock) (*Coordinator, error) {
	if repository == nil || registry == nil || runner == nil || planner == nil || canonical == nil || authorization == nil ||
		approvals == nil || audit == nil || maintenance == nil || snapshots == nil || effects == nil || outcomes == nil || clock == nil { return nil, ErrInvalid }
	return &Coordinator{repository, registry, runner, planner, canonical, authorization, approvals, audit,
		maintenance, snapshots, effects, outcomes, clock}, nil
}

func (coordinator *Coordinator) Diagnose(ctx context.Context, request RunRequest, authorization Authorization) (DiagnosticRun, error) {
	now := coordinator.clock.Now().UTC()
	authorization, err := coordinator.authorize(ctx, authorization, ActionDiagnose, request.Scope, request.ID, "", false, now)
	if err != nil { return DiagnosticRun{}, err }
	intent := digestParts("diagnose", request.ID, request.Scope.key(), uintString(request.ExpectedGeneration))
	if err := coordinator.recordAudit(ctx, ActionDiagnose, request.ID, request.Scope, 0, 0, authorization.Digest, intent, request.RequestedAt); err != nil { return DiagnosticRun{}, err }
	run, err := coordinator.runner.Run(ctx, request)
	if err != nil { return DiagnosticRun{}, err }
	if err := coordinator.repository.SaveRun(ctx, run); err != nil { return DiagnosticRun{}, err }
	return run, nil
}

func (coordinator *Coordinator) Preview(ctx context.Context, request PlanRequest, authorization Authorization, idempotencyKey string) (RepairPlan, Receipt, error) {
	storedRun, err := coordinator.repository.GetRun(ctx, request.Run.ID)
	if err != nil || storedRun.Digest != request.Run.Digest { return RepairPlan{}, Receipt{}, ErrIntegrity }
	authorization, err = coordinator.authorize(ctx, authorization, ActionPreview, request.Run.Scope, request.ID, request.Run.Digest, false, coordinator.clock.Now().UTC())
	if err != nil { return RepairPlan{}, Receipt{}, err }
	plan, err := coordinator.planner.Preview(ctx, request)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	if err := coordinator.ensureRegistered(plan); err != nil { return RepairPlan{}, Receipt{}, err }
	if err := coordinator.recordAudit(ctx, ActionPreview, plan.ID, plan.Scope, plan.Generation, plan.Fence,
		authorization.Digest, plan.DefinitionDigest, request.CreatedAt); err != nil { return RepairPlan{}, Receipt{}, err }
	return coordinator.repository.createPlan(ctx, plan, idempotencyKey)
}

func (coordinator *Coordinator) Approve(ctx context.Context, command ExecutionCommand, approval Approval) (RepairPlan, Receipt, error) {
	plan, err := coordinator.repository.GetPlan(ctx, command.PlanID)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	if err := coordinator.matchCommand(plan, command, PlanPreview); err != nil { return RepairPlan{}, Receipt{}, err }
	authorization, err := coordinator.authorize(ctx, command.Authorization, ActionApprove, plan.Scope, plan.ID,
		plan.DefinitionDigest, true, coordinator.clock.Now().UTC())
	if err != nil { return RepairPlan{}, Receipt{}, err }
	approval, err = CanonicalApproval(approval, plan, coordinator.clock.Now().UTC())
	if err != nil { return RepairPlan{}, Receipt{}, err }
	if err := coordinator.approvals.VerifyRepairApproval(ctx, approval); err != nil { return RepairPlan{}, Receipt{}, ErrUnauthorized }
	intent := digestParts("approve", plan.DefinitionDigest, approval.Digest)
	if err := coordinator.recordAudit(ctx, ActionApprove, plan.ID, plan.Scope, plan.Generation, plan.Fence,
		authorization.Digest, intent, command.At); err != nil { return RepairPlan{}, Receipt{}, err }
	return coordinator.repository.approve(ctx, plan.ID, plan.Generation, plan.Fence, approval, command.IdempotencyKey, command.At)
}

func (coordinator *Coordinator) Takeover(ctx context.Context, command ExecutionCommand, toController string) (RepairPlan, Receipt, error) {
	if !identifierPattern.MatchString(toController) || !coordinator.current(command.At) { return RepairPlan{}, Receipt{}, ErrInvalid }
	plan, err := coordinator.repository.GetPlan(ctx, command.PlanID)
	if err != nil { return RepairPlan{}, Receipt{}, err }
	if plan.Generation != command.ExpectedGeneration || plan.Fence != command.Fence || plan.ControllerID != command.ControllerID { return RepairPlan{}, Receipt{}, ErrConflict }
	authorization, err := coordinator.authorize(ctx, command.Authorization, ActionFence, plan.Scope, plan.ID,
		plan.DefinitionDigest, true, coordinator.clock.Now().UTC())
	if err != nil { return RepairPlan{}, Receipt{}, err }
	intent := digestParts("fence", plan.DefinitionDigest, command.ControllerID, toController, uintString(plan.Fence))
	if err := coordinator.recordAudit(ctx, ActionFence, plan.ID, plan.Scope, plan.Generation, plan.Fence,
		authorization.Digest, intent, command.At); err != nil { return RepairPlan{}, Receipt{}, err }
	return coordinator.repository.fence(ctx, plan.ID, command.ControllerID, toController, command.IdempotencyKey,
		plan.Generation, plan.Fence, intent, command.At)
}

func (coordinator *Coordinator) Execute(ctx context.Context, command ExecutionCommand) (RepairPlan, error) {
	plan, err := coordinator.repository.GetPlan(ctx, command.PlanID)
	if err != nil { return RepairPlan{}, err }
	if command.ExpectedGeneration == 0 || !identifierPattern.MatchString(command.ControllerID) ||
		!identifierPattern.MatchString(command.IdempotencyKey) || command.Fence == 0 || !coordinator.current(command.At) { return RepairPlan{}, ErrConflict }
	if plan.State == PlanSucceeded || plan.State == PlanRolledBack || plan.State == PlanFailed || plan.State == PlanUncertain {
		if plan.Fence != command.Fence || plan.ControllerID != command.ControllerID || command.ExpectedGeneration > plan.Generation { return RepairPlan{}, ErrConflict }
		if plan.State == PlanUncertain { return plan, ErrIntegrity }
		return plan, nil
	}
	if plan.State != PlanApproved && plan.State != PlanExecuting { return RepairPlan{}, ErrConflict }
	if plan.Fence != command.Fence || plan.ControllerID != command.ControllerID ||
		plan.State == PlanApproved && plan.Generation != command.ExpectedGeneration ||
		plan.State == PlanExecuting && command.ExpectedGeneration > plan.Generation ||
		command.ExpectedDuration <= 0 || command.ExpectedDuration > 24*time.Hour { return RepairPlan{}, ErrConflict }
	authorization, err := coordinator.authorize(ctx, command.Authorization, ActionExecute, plan.Scope, plan.ID,
		plan.DefinitionDigest, true, coordinator.clock.Now().UTC())
	if err != nil { return RepairPlan{}, err }
	if plan.State == PlanApproved {
		approval, approvalErr := coordinator.repository.GetApproval(ctx, plan.ID)
		if approvalErr != nil { return RepairPlan{}, approvalErr }
		approval, approvalErr = CanonicalApproval(approval, plan, coordinator.clock.Now().UTC())
		if approvalErr != nil { return RepairPlan{}, approvalErr }
		if approvalErr = coordinator.approvals.VerifyRepairApproval(ctx, approval); approvalErr != nil { return RepairPlan{}, ErrUnauthorized }
		if approvalErr = coordinator.revalidateFindings(ctx, plan, coordinator.clock.Now().UTC()); approvalErr != nil { return RepairPlan{}, approvalErr }
	}
	if err := coordinator.ensureRegistered(plan); err != nil { return RepairPlan{}, err }
	maintenanceEvidence, err := coordinator.admit(ctx, plan, command)
	if err != nil { return RepairPlan{}, err }
	if err := coordinator.revalidateCanonical(ctx, plan); err != nil { return RepairPlan{}, err }
	intent := digestParts("execute", plan.DefinitionDigest, authorization.Digest, maintenanceEvidence,
		command.IdempotencyKey, uintString(plan.Fence))
	if err := coordinator.recordAudit(ctx, ActionExecute, plan.ID, plan.Scope, plan.Generation, plan.Fence,
		authorization.Digest, intent, command.At); err != nil { return RepairPlan{}, err }
	if plan.State == PlanApproved {
		transition := coordinator.transition(plan, PlanApproved, PlanExecuting, ReceiptExecution, "", "start", intent, command.At)
		plan, _, err = coordinator.repository.transition(ctx, plan.ID, transition)
		if err != nil { return plan, err }
	}
	if plan.Snapshot.Required && plan.SnapshotReference == "" {
		plan, err = coordinator.takeSnapshot(ctx, plan, authorization, command.At)
		if err != nil { return coordinator.markUncertain(ctx, plan, digestParts("snapshot-ambiguous", plan.DefinitionDigest), command.At) }
	}
	for index := range plan.ExecutedSteps {
		step := plan.Steps[index]
		if err := coordinator.verifyStep(ctx, plan, step, plan.ExecutedSteps[index], false, command.At); err != nil {
			return coordinator.rollback(ctx, plan, authorization, digestParts("resume-verification-failed", step.Digest), command.At)
		}
	}
	for len(plan.ExecutedSteps) < len(plan.Steps) {
		step := plan.Steps[len(plan.ExecutedSteps)]
		plan, err = coordinator.applyStep(ctx, plan, step, authorization, command.At)
		if err != nil { return coordinator.markUncertain(ctx, plan, digestParts("effect-ambiguous", step.Digest), command.At) }
		execution := plan.ExecutedSteps[len(plan.ExecutedSteps)-1]
		if err := coordinator.verifyStep(ctx, plan, step, execution, false, command.At); err != nil {
			return coordinator.rollback(ctx, plan, authorization, digestParts("dependent-health-failed", step.Digest), command.At)
		}
	}
	evidence := digestParts("repair-succeeded", plan.DefinitionDigest, plan.LastReceiptDigest)
	transition := coordinator.transition(plan, PlanExecuting, PlanSucceeded, ReceiptSucceeded, "", "succeeded", evidence, command.At)
	next, _, err := coordinator.repository.transition(ctx, plan.ID, transition)
	if err != nil { return plan, err }
	return next, nil
}

func (coordinator *Coordinator) takeSnapshot(ctx context.Context, plan RepairPlan, authorization Authorization, at time.Time) (RepairPlan, error) {
	request := SnapshotRequest{PlanID: plan.ID, DefinitionDigest: plan.DefinitionDigest, Scope: plan.Scope,
		ResourceIDs: append([]string(nil), plan.Snapshot.ResourceIDs...), Retention: plan.Snapshot.Retention,
		Generation: plan.Generation, Fence: plan.Fence, IdempotencyKey: digestParts(plan.ID, "snapshot", uintString(plan.Fence))}
	request.Digest, _ = digestJSON(request)
	if err := coordinator.recordAudit(ctx, ActionExecute, plan.ID, plan.Scope, plan.Generation, plan.Fence,
		authorization.Digest, request.Digest, at); err != nil { return plan, err }
	receipt, err := coordinator.snapshots.SnapshotRepair(ctx, request)
	if err != nil { return plan, ErrIntegrity }
	receipt, err = canonicalSnapshotReceipt(receipt, request.Digest)
	if err != nil || !coordinator.current(receipt.CreatedAt) { return plan, ErrIntegrity }
	transition := coordinator.transition(plan, PlanExecuting, PlanExecuting, ReceiptSnapshot, "", "snapshot", receipt.Digest, at)
	transition.SnapshotReference, transition.SnapshotEvidence = receipt.Reference, receipt.EvidenceDigest
	next, _, err := coordinator.repository.transition(ctx, plan.ID, transition)
	if err != nil { return plan, err }
	return next, nil
}

func (coordinator *Coordinator) applyStep(ctx context.Context, plan RepairPlan, step RepairStep, authorization Authorization, at time.Time) (RepairPlan, error) {
	if err := coordinator.revalidateStep(ctx, plan, step); err != nil { return plan, err }
	executor, found := coordinator.effects.executor(step.Effect)
	if !found { return plan, ErrUnsupported }
	operation := effectOperation(plan, step, false)
	if err := coordinator.recordAudit(ctx, ActionExecute, plan.ID, plan.Scope, plan.Generation, plan.Fence,
		authorization.Digest, operation.Digest, at); err != nil { return plan, err }
	receipt, err := executor.Apply(ctx, operation)
	if err != nil { return plan, ErrIntegrity }
	receipt, err = canonicalEffectReceipt(receipt, operation.Digest)
	if err != nil || !coordinator.current(receipt.CreatedAt) { return plan, ErrIntegrity }
	execution := StepExecution{StepID: step.ID, ReceiptDigest: receipt.Digest, EvidenceDigest: receipt.EvidenceDigest}
	transition := coordinator.transition(plan, PlanExecuting, PlanExecuting, ReceiptStep, step.ID, "step", receipt.Digest, at)
	transition.Execution = &execution
	next, _, err := coordinator.repository.transition(ctx, plan.ID, transition)
	if err != nil { return plan, err }
	return next, nil
}

func (coordinator *Coordinator) verifyStep(ctx context.Context, plan RepairPlan, step RepairStep, execution StepExecution, compensation bool, at time.Time) error {
	expectedGeneration := step.CanonicalGeneration
	if compensation { expectedGeneration = step.ObservedGeneration }
	request := VerificationRequest{PlanID: plan.ID, StepID: step.ID, Effect: step.Effect, Scope: step.Scope,
		ExpectedGeneration: expectedGeneration, EffectReceiptDigest: execution.ReceiptDigest,
		EffectEvidenceDigest: execution.EvidenceDigest, Compensation: compensation, Fence: plan.Fence}
	request.Digest, _ = digestJSON(request)
	receipt, err := coordinator.outcomes.VerifyRepairOutcome(ctx, request)
	if err != nil || !receipt.Satisfied || receipt.RequestDigest != request.Digest || !validDigest(receipt.EvidenceDigest) ||
		!validTime(receipt.ObservedAt) || !coordinator.current(receipt.ObservedAt) { return ErrIntegrity }
	claimed := receipt.Digest
	receipt.Digest = ""
	digest, err := digestJSON(receipt)
	if err != nil || claimed != digest { return ErrIntegrity }
	kinds := coordinator.dependentKinds(step.Diagnostic)
	runID := "health-" + digestParts(plan.ID, step.ID, uintString(plan.Generation), uintString(plan.Fence), uintString(boolUint(compensation)))[:32]
	run, err := coordinator.runner.Run(ctx, RunRequest{ID: runID, Scope: plan.Scope, Kinds: kinds,
		ExpectedGeneration: expectedGeneration, RequestedAt: coordinator.clock.Now().UTC()})
	if err != nil || run.State != RunHealthy { return ErrIntegrity }
	return coordinator.repository.SaveRun(ctx, run)
}

func (coordinator *Coordinator) rollback(ctx context.Context, plan RepairPlan, authorization Authorization, causeEvidence string, at time.Time) (RepairPlan, error) {
	if plan.Irreversible.Declared || plan.SnapshotReference == "" || !validDigest(plan.SnapshotEvidence) {
		return coordinator.markUncertain(ctx, plan, causeEvidence, at)
	}
	for len(plan.CompensatedSteps) < len(plan.ExecutedSteps) {
		index := len(plan.ExecutedSteps) - 1 - len(plan.CompensatedSteps)
		step, execution := plan.Steps[index], plan.ExecutedSteps[index]
		if !step.Compensation.Required {
			compensated := StepExecution{StepID: step.ID,
				ReceiptDigest: digestParts("compensation-not-required", step.ID, execution.ReceiptDigest),
				EvidenceDigest: digestParts("non-mutating-step", step.Digest)}
			transition := coordinator.transition(plan, PlanExecuting, PlanExecuting, ReceiptCompensation,
				step.ID, "compensation", compensated.EvidenceDigest, at)
			transition.Compensation = &compensated
			next, _, transitionErr := coordinator.repository.transition(ctx, plan.ID, transition)
			if transitionErr != nil { return coordinator.markUncertain(ctx, plan, causeEvidence, at) }
			plan = next
			continue
		}
		executor, found := coordinator.effects.executor(step.Effect)
		if !found { return coordinator.markUncertain(ctx, plan, causeEvidence, at) }
		operation := effectOperation(plan, step, true)
		compensation := CompensationOperation{EffectOperation: operation, Compensation: step.Compensation,
			EffectReceipt: execution.ReceiptDigest, IdempotencyKey: digestParts(plan.ID, "compensate", step.ID, uintString(plan.Fence))}
		compensation.Digest, _ = digestJSON(compensation)
		if err := coordinator.recordAudit(ctx, ActionExecute, plan.ID, plan.Scope, plan.Generation, plan.Fence,
			authorization.Digest, compensation.Digest, at); err != nil { return coordinator.markUncertain(ctx, plan, causeEvidence, at) }
		receipt, err := executor.Compensate(ctx, compensation)
		if err != nil { return coordinator.markUncertain(ctx, plan, causeEvidence, at) }
		receipt, err = canonicalEffectReceipt(receipt, compensation.Digest)
		if err != nil || !coordinator.current(receipt.CreatedAt) { return coordinator.markUncertain(ctx, plan, causeEvidence, at) }
		compensated := StepExecution{StepID: step.ID, ReceiptDigest: receipt.Digest, EvidenceDigest: receipt.EvidenceDigest}
		transition := coordinator.transition(plan, PlanExecuting, PlanExecuting, ReceiptCompensation, step.ID, "compensation", receipt.Digest, at)
		transition.Compensation = &compensated
		next, _, transitionErr := coordinator.repository.transition(ctx, plan.ID, transition)
		if transitionErr != nil {
			return coordinator.markUncertain(ctx, plan, digestParts("compensation-persistence-ambiguous", receipt.Digest), at)
		}
		plan = next
		if err := coordinator.verifyStep(ctx, plan, step, compensated, true, at); err != nil { return coordinator.markUncertain(ctx, plan, causeEvidence, at) }
	}
	evidence := digestParts("rolled-back", causeEvidence, plan.SnapshotEvidence, plan.LastReceiptDigest)
	transition := coordinator.transition(plan, PlanExecuting, PlanRolledBack, ReceiptRolledBack, "", "rolled-back", evidence, at)
	next, _, err := coordinator.repository.transition(ctx, plan.ID, transition)
	if err != nil { return plan, err }
	return next, nil
}

func (coordinator *Coordinator) markUncertain(ctx context.Context, plan RepairPlan, evidence string, at time.Time) (RepairPlan, error) {
	if plan.State != PlanExecuting { return RepairPlan{}, ErrConflict }
	transition := coordinator.transition(plan, PlanExecuting, PlanUncertain, ReceiptUncertain, "", "uncertain", evidence, at)
	transition.AmbiguousEvidence = evidence
	transition.RecoverySteps = []string{"inspect_canonical_generation", "inspect_effect_receipt", "preserve_snapshot"}
	next, _, err := coordinator.repository.transition(ctx, plan.ID, transition)
	if err != nil { return plan, err }
	return next, ErrIntegrity
}

func (coordinator *Coordinator) revalidateCanonical(ctx context.Context, plan RepairPlan) error {
	for _, step := range plan.Steps { if err := coordinator.revalidateStep(ctx, plan, step); err != nil { return err } }
	return nil
}

func (coordinator *Coordinator) revalidateFindings(ctx context.Context, plan RepairPlan, now time.Time) error {
	run, err := coordinator.repository.GetRun(ctx, plan.RunID)
	if err != nil || run.Digest != plan.RunDigest || run.RegistryDigest != plan.RegistryDigest || run.Scope != plan.Scope { return ErrIntegrity }
	findings := indexFindings(run)
	for _, step := range plan.Steps {
		observation, found := observationFor(run, step.Diagnostic)
		if !found || observation.State != ProbeFindings || now.After(observation.FreshUntil) { return ErrStale }
		for _, findingID := range step.FindingIDs {
			finding, found := findings[findingID]
			if !found || !finding.RepairEligible || finding.Kind != step.Diagnostic || finding.Scope != step.Scope ||
				finding.OwnerID != plan.OwnerID || finding.ServiceID != step.ServiceID || finding.ObservedGeneration != step.ObservedGeneration ||
				!containsEffect(effectsForFinding(finding.Code), step.Effect) { return ErrConflict }
		}
	}
	return nil
}

func containsEffect(effects []EffectKind, target EffectKind) bool {
	for _, effect := range effects { if effect == target { return true } }
	return false
}

func (coordinator *Coordinator) revalidateStep(ctx context.Context, plan RepairPlan, step RepairStep) error {
	resource, err := coordinator.canonical.ResolveCanonical(ctx, step.Scope, step.Diagnostic)
	if err != nil { return ErrIntegrity }
	if !resource.Managed { return ErrUnmanaged }
	if resource.Validate() != nil || resource.OwnerID != plan.OwnerID || resource.ServiceID != step.ServiceID ||
		resource.Generation != step.CanonicalGeneration || resource.Digest != step.CanonicalDigest ||
		resource.OwnershipModeDigest != step.OwnershipModeDigest || resource.CertificateBindingDigest != step.CertificateBindingDigest {
		return ErrConflict
	}
	return nil
}

func (coordinator *Coordinator) ensureRegistered(plan RepairPlan) error {
	for _, step := range plan.Steps { if _, found := coordinator.effects.executor(step.Effect); !found { return ErrUnsupported } }
	return nil
}

func (coordinator *Coordinator) dependentKinds(kind DiagnosticKind) []DiagnosticKind {
	selected := map[DiagnosticKind]bool{kind: true}
	changed := true
	for changed {
		changed = false
		for _, candidate := range coordinator.registry.Order() {
			definition, _ := coordinator.registry.Definition(candidate)
			for _, dependency := range definition.Dependencies {
				if selected[dependency] && !selected[candidate] { selected[candidate], changed = true, true }
			}
		}
	}
	kinds := make([]DiagnosticKind, 0, len(selected))
	for selectedKind := range selected { kinds = append(kinds, selectedKind) }
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}

func (coordinator *Coordinator) admit(ctx context.Context, plan RepairPlan, command ExecutionCommand) (string, error) {
	if !plan.MaintenanceRequired { return digestParts("maintenance-not-required", plan.DefinitionDigest), nil }
	request := MaintenanceRequest{PlanID: plan.ID, DefinitionDigest: plan.DefinitionDigest, Scope: plan.Scope,
		Fence: plan.Fence, RequestedAt: command.At.UTC(), ExpectedDuration: command.ExpectedDuration}
	request.Digest, _ = digestJSON(request)
	admission, err := coordinator.maintenance.AdmitRepair(ctx, request)
	if err != nil || !admission.Allowed || !identifierPattern.MatchString(admission.OccurrenceID) ||
		!validDigest(admission.EvidenceDigest) || !validTime(admission.EndsAt) || admission.EndsAt.Before(command.At.Add(command.ExpectedDuration)) { return "", ErrConflict }
	admission.EndsAt = admission.EndsAt.UTC()
	claimed := admission.Digest
	admission.Digest = ""
	digest, err := digestJSON(admission)
	if err != nil || claimed != digest { return "", ErrIntegrity }
	return admission.EvidenceDigest, nil
}

func (coordinator *Coordinator) authorize(ctx context.Context, authorization Authorization, action Action, scope Scope,
	objectID, definitionDigest string, mutation bool, now time.Time) (Authorization, error) {
	authorization, err := canonicalAuthorization(authorization, action, scope, objectID, definitionDigest, mutation, now)
	if err != nil { return Authorization{}, err }
	if err := coordinator.authorization.VerifyDiagnosticsRepairAuthorization(ctx, authorization); err != nil { return Authorization{}, ErrUnauthorized }
	return authorization, nil
}

func (coordinator *Coordinator) recordAudit(ctx context.Context, action Action, objectID string, scope Scope, generation, fence uint64,
	authorizationDigest, intent string, at time.Time) error {
	record := AuditRecord{Action: action, ObjectID: objectID, Scope: scope, Generation: generation, Fence: fence,
		AuthorizationDigest: authorizationDigest, IntentDigest: intent, At: at.UTC()}
	record.ID = digestParts("diagnostics-repair-audit", string(action), objectID, uintString(generation), uintString(fence), intent)
	record.Digest, _ = digestJSON(record)
	if err := coordinator.audit.RecordDiagnosticsRepair(ctx, record); err != nil { return ErrIntegrity }
	return nil
}

func (coordinator *Coordinator) matchCommand(plan RepairPlan, command ExecutionCommand, state PlanState) error {
	if plan.State != state || plan.Generation != command.ExpectedGeneration || plan.Fence != command.Fence ||
		plan.ControllerID != command.ControllerID || !identifierPattern.MatchString(command.IdempotencyKey) || !coordinator.current(command.At) { return ErrConflict }
	return nil
}

func (coordinator *Coordinator) transition(plan RepairPlan, from, to PlanState, kind ReceiptKind, stepID, suffix, evidence string, at time.Time) planTransition {
	key := digestParts(plan.ID, suffix, stepID, uintString(plan.Fence))
	commandDigest := digestParts("plan-transition", plan.DefinitionDigest, string(from), string(to), string(kind), stepID, evidence, uintString(plan.Generation), uintString(plan.Fence))
	return planTransition{ExpectedGeneration: plan.Generation, Fence: plan.Fence, From: from, To: to, Kind: kind,
		StepID: stepID, IdempotencyKey: key, CommandDigest: commandDigest, EvidenceDigest: evidence, At: at.UTC()}
}

func effectOperation(plan RepairPlan, step RepairStep, compensation bool) EffectOperation {
	generation := step.CanonicalGeneration
	if compensation { generation = step.ObservedGeneration }
	operation := EffectOperation{PlanID: plan.ID, DefinitionDigest: plan.DefinitionDigest, StepID: step.ID,
		Effect: step.Effect, Scope: step.Scope, ServiceID: step.ServiceID, CanonicalGeneration: generation,
		CanonicalDigest: step.CanonicalDigest, OwnershipModeDigest: step.OwnershipModeDigest,
		CertificateBindingDigest: step.CertificateBindingDigest, SnapshotReference: plan.SnapshotReference,
		SnapshotEvidence: plan.SnapshotEvidence, Generation: plan.Generation, Fence: plan.Fence,
		IdempotencyKey: digestParts(plan.ID, "effect", step.ID, uintString(plan.Fence), uintString(boolUint(compensation)))}
	operation.Digest, _ = digestJSON(operation)
	return operation
}

func canonicalSnapshotReceipt(receipt SnapshotReceipt, operationDigest string) (SnapshotReceipt, error) {
	if !identifierPattern.MatchString(receipt.ID) || receipt.OperationDigest != operationDigest || !identifierPattern.MatchString(receipt.Reference) ||
		!receipt.Proven || !validDigest(receipt.EvidenceDigest) || !validTime(receipt.CreatedAt) { return SnapshotReceipt{}, ErrUnproven }
	receipt.CreatedAt = receipt.CreatedAt.UTC()
	claimed := receipt.Digest
	receipt.Digest = ""
	digest, err := digestJSON(receipt)
	if err != nil || claimed != digest { return SnapshotReceipt{}, ErrIntegrity }
	receipt.Digest = digest
	return receipt, nil
}

func canonicalEffectReceipt(receipt EffectReceipt, operationDigest string) (EffectReceipt, error) {
	if !identifierPattern.MatchString(receipt.ID) || receipt.OperationDigest != operationDigest || !receipt.Completed ||
		receipt.ObservedGeneration > maxGeneration || !validDigest(receipt.EvidenceDigest) || !validTime(receipt.CreatedAt) { return EffectReceipt{}, ErrIntegrity }
	receipt.CreatedAt = receipt.CreatedAt.UTC()
	claimed := receipt.Digest
	receipt.Digest = ""
	digest, err := digestJSON(receipt)
	if err != nil || claimed != digest { return EffectReceipt{}, ErrIntegrity }
	receipt.Digest = digest
	return receipt, nil
}

func boolUint(value bool) uint64 { if value { return 1 }; return 0 }

func (coordinator *Coordinator) current(at time.Time) bool {
	now := coordinator.clock.Now().UTC()
	return validTime(now) && validTime(at) && absoluteDuration(now.Sub(at.UTC())) <= 5*time.Minute
}
