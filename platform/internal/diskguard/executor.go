package diskguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type Actor struct {
	PrincipalID        string `json:"principal_id"`
	TenantID           string `json:"tenant_id"`
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
}

func (actor Actor) Validate() error {
	if !validID(actor.PrincipalID) || !validID(actor.TenantID) || actor.AuthorizationEpoch == 0 {
		return ErrInvalid
	}
	return nil
}

type AuthorizationRequest struct {
	Actor        Actor      `json:"actor"`
	Operation    string     `json:"operation"`
	PlanID       string     `json:"plan_id"`
	ActionID     string     `json:"action_id,omitempty"`
	FilesystemID string     `json:"filesystem_id"`
	TenantID     string     `json:"tenant_id,omitempty"`
	Destructive  bool       `json:"destructive"`
	Emergency    bool       `json:"emergency"`
	RequestDigest string    `json:"request_digest"`
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) error
}

type ApprovalVerifier interface {
	Verify(context.Context, Plan, Approval, Actor, time.Time) error
}

type StepUpVerifier interface {
	Verify(context.Context, Actor, string, time.Time) error
}

type AuditEvent struct {
	ID                 string    `json:"id"`
	Boundary           string    `json:"boundary"`
	PlanID             string    `json:"plan_id"`
	ActionID           string    `json:"action_id,omitempty"`
	PrincipalID        string    `json:"principal_id"`
	AuthorizationEpoch uint64    `json:"authorization_epoch"`
	RequestDigest      string    `json:"request_digest"`
	Outcome            string    `json:"outcome"`
	ReasonCode         string    `json:"reason_code"`
	OccurredAt         time.Time `json:"occurred_at"`
	Digest             string    `json:"digest"`
}

type Auditor interface {
	Record(context.Context, AuditEvent) error
}

type ObjectState struct {
	Exists       bool            `json:"exists"`
	DescriptorID string          `json:"descriptor_id"`
	ObjectID     string          `json:"object_id"`
	FilesystemID string          `json:"filesystem_id"`
	TenantID     string          `json:"tenant_id"`
	Class        ArtifactClass   `json:"class"`
	Protection   ProtectionClass `json:"protection"`
	Retention    RetentionClass  `json:"retention"`
	Generation   uint64          `json:"generation"`
	Digest       string          `json:"digest"`
	Bytes        uint64          `json:"bytes"`
	Inodes       uint64          `json:"inodes"`
	RetainUntil  time.Time       `json:"retain_until"`
}

func (state ObjectState) validate() error {
	if !state.Exists {
		return nil
	}
	descriptor := ArtifactDescriptor{DescriptorID:state.DescriptorID,ObjectID:state.ObjectID,FilesystemID:state.FilesystemID,TenantID:state.TenantID,Class:state.Class,Protection:state.Protection,Retention:state.Retention,Generation:state.Generation,Digest:state.Digest,Bytes:state.Bytes,Inodes:state.Inodes,CreatedAt:state.RetainUntil,RetainUntil:state.RetainUntil}
	return descriptor.Validate()
}

type ExactObjectRequest struct {
	PlanID            string `json:"plan_id"`
	ActionID          string `json:"action_id"`
	DescriptorID      string `json:"descriptor_id"`
	ObjectID          string `json:"object_id"`
	FilesystemID      string `json:"filesystem_id"`
	TenantID          string `json:"tenant_id"`
	ExpectedClass     ArtifactClass `json:"expected_class"`
	ExpectedProtection ProtectionClass `json:"expected_protection"`
	ExpectedRetention RetentionClass `json:"expected_retention"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	ExpectedDigest    string `json:"expected_digest"`
}

type BackendMutationReceipt struct {
	ActionID          string `json:"action_id"`
	DescriptorID      string `json:"descriptor_id"`
	ObjectID          string `json:"object_id"`
	Applied           bool   `json:"applied"`
	Ambiguous         bool   `json:"ambiguous"`
	ObservedGeneration uint64 `json:"observed_generation"`
	ObservedDigest    string `json:"observed_digest,omitempty"`
	ReclaimedBytes    uint64 `json:"reclaimed_bytes"`
	ReclaimedInodes   uint64 `json:"reclaimed_inodes"`
	Receipt           string `json:"receipt"`
}

type ObjectExecutor interface {
	LookupAction(context.Context, string) (BackendMutationReceipt, bool, error)
	Inspect(context.Context, string, string) (ObjectState, error)
	Expire(context.Context, ExactObjectRequest) (BackendMutationReceipt, error)
}

type WorkControlRequest struct {
	PlanID       string     `json:"plan_id"`
	ActionID     string     `json:"action_id"`
	FilesystemID string     `json:"filesystem_id"`
	Kind         ActionKind `json:"kind"`
}

type WorkControlReceipt struct {
	ActionID  string `json:"action_id"`
	Applied   bool   `json:"applied"`
	Ambiguous bool   `json:"ambiguous"`
	Receipt   string `json:"receipt"`
}

type WorkController interface {
	Apply(context.Context, WorkControlRequest) (WorkControlReceipt, error)
}

type Journal interface {
	LoadPlan(context.Context, string) (Plan, error)
	UpdatePlan(context.Context, Plan, uint64) error
	LoadPolicy(context.Context, string) (WatermarkPolicy, error)
	LoadObservation(context.Context, string) (FilesystemObservation, error)
	LoadApproval(context.Context, string) (Approval, error)
	LoadReceipt(context.Context, string) (ExecutionReceipt, error)
	SaveReceipt(context.Context, ExecutionReceipt, uint64) error
}

type ExecutionRequest struct {
	PlanID                string `json:"plan_id"`
	ExpectedPlanGeneration uint64 `json:"expected_plan_generation"`
	Actor                 Actor  `json:"actor"`
	ApprovalID            string `json:"approval_id,omitempty"`
	StepUpDigest          string `json:"step_up_digest,omitempty"`
}

type Executor struct {
	Journal          Journal
	Objects          ObjectExecutor
	Work             WorkController
	Authorizer       Authorizer
	Approvals        ApprovalVerifier
	StepUp           StepUpVerifier
	Auditor          Auditor
	Now              func() time.Time
}

func (executor Executor) Execute(ctx context.Context, request ExecutionRequest) (ExecutionReceipt, error) {
	if ctx == nil || executor.Journal == nil || executor.Objects == nil || executor.Work == nil || executor.Authorizer == nil || executor.Auditor == nil || !validID(request.PlanID) || request.ExpectedPlanGeneration == 0 || request.Actor.Validate() != nil {
		return ExecutionReceipt{}, ErrInvalid
	}
	now := executor.currentTime()
	plan, err := executor.Journal.LoadPlan(ctx, request.PlanID)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	if plan.Generation != request.ExpectedPlanGeneration {
		return ExecutionReceipt{}, ErrStaleGeneration
	}
	receipt, receiptErr := executor.Journal.LoadReceipt(ctx, plan.ID)
	if receiptErr != nil && !errors.Is(receiptErr, ErrNotFound) {
		return ExecutionReceipt{}, receiptErr
	}
	if receiptErr == nil && receipt.State != PlanExecuting {
		if plan.State == PlanExecuting {
			if plan, err = executor.transitionPlan(ctx, plan, receipt.State, now); err != nil {
				return receipt, err
			}
		}
		switch receipt.State {
		case PlanCompleted:
			return receipt, nil
		case PlanAmbiguous:
			return receipt, ErrAmbiguous
		default:
			return receipt, ErrPartial
		}
	}
	if plan.State != PlanPlanned && plan.State != PlanApproved && plan.State != PlanExecuting {
		return ExecutionReceipt{}, ErrConflict
	}
	policy, err := executor.Journal.LoadPolicy(ctx, plan.PolicyID)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	observation, err := executor.Journal.LoadObservation(ctx, plan.ObservationID)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	if policy.Generation != plan.PolicyGeneration || policy.Digest != plan.PolicyDigest || observation.Generation != plan.ObservationGeneration || observation.Digest != plan.ObservationDigest || policy.FilesystemID != plan.FilesystemID || observation.FilesystemID != plan.FilesystemID {
		return ExecutionReceipt{}, ErrStaleGeneration
	}
	uncertain := observationUncertain(observation, policy, now)
	if uncertain && (plan.Level != PressureUnknown || !onlyBlockingActions(plan.Actions)) {
		return ExecutionReceipt{}, ErrUncertainObservation
	}
	if err = executor.authorize(ctx, plan, PlanAction{}, request.Actor, now, "diskguard.execute"); err != nil {
		return ExecutionReceipt{}, err
	}
	originalPlanDigest := ""
	if plan.State == PlanPlanned {
		originalPlanDigest = plan.Digest
	}
	if receiptErr == nil {
		originalPlanDigest = receipt.PlanDigest
	}
	var approval Approval
	if plan.RequiresApproval {
		if executor.Approvals == nil || executor.StepUp == nil || !validID(request.ApprovalID) || !validDigest(request.StepUpDigest) {
			return ExecutionReceipt{}, ErrApprovalRequired
		}
		var loadErr error
		approval, loadErr = executor.Journal.LoadApproval(ctx, request.ApprovalID)
		if loadErr != nil {
			return ExecutionReceipt{}, loadErr
		}
		if approval.PlanID != plan.ID || originalPlanDigest != "" && approval.PlanDigest != originalPlanDigest || approval.PrincipalID != request.Actor.PrincipalID || approval.AuthorizationEpoch != request.Actor.AuthorizationEpoch || approval.StepUpDigest != request.StepUpDigest || now.Before(approval.ApprovedAt) || !now.Before(approval.ExpiresAt) {
			return ExecutionReceipt{}, ErrApprovalRequired
		}
		if err = executor.Approvals.Verify(ctx, plan, approval, request.Actor, now); err != nil {
			return ExecutionReceipt{}, ErrApprovalRequired
		}
		if err = executor.StepUp.Verify(ctx, request.Actor, request.StepUpDigest, now); err != nil {
			return ExecutionReceipt{}, ErrApprovalRequired
		}
	}
	if receiptErr != nil {
		receiptPlanDigest := plan.Digest
		if plan.RequiresApproval {
			receiptPlanDigest = approval.PlanDigest
		}
		receipt = ExecutionReceipt{ID:receiptID(plan.ID),PlanID:plan.ID,PlanDigest:receiptPlanDigest,State:PlanExecuting,NextSequence:1,Generation:1,CreatedAt:now,UpdatedAt:now}
		receipt, err = SealReceipt(receipt)
		if err != nil {
			return ExecutionReceipt{}, err
		}
		if err = executor.Journal.SaveReceipt(ctx, receipt, 0); err != nil {
			return ExecutionReceipt{}, err
		}
	}
	if plan.State != PlanExecuting {
		plan, err = executor.transitionPlan(ctx, plan, PlanExecuting, now)
		if err != nil {
			return receipt, err
		}
	}
	for index := len(receipt.Actions); index < len(plan.Actions); index++ {
		action := plan.Actions[index]
		now = executor.currentTime()
		if plan.Level != PressureUnknown && observationUncertain(observation, policy, now) {
			return executor.stop(ctx, plan, receipt, action, OutcomeFailed, "observation_stale", now, ErrUncertainObservation)
		}
		if action.RequiresApproval && !now.Before(approval.ExpiresAt) {
			return executor.stop(ctx, plan, receipt, action, OutcomeFailed, "approval_expired", now, ErrApprovalRequired)
		}
		if receipt.NextSequence != action.Sequence {
			return receipt, ErrIntegrity
		}
		operation := "diskguard.control_heavy_work"
		if action.Destructive {
			operation = "diskguard.expire_exact_object"
		}
		if err = executor.authorize(ctx, plan, action, request.Actor, now, operation); err != nil {
			return executor.stop(ctx, plan, receipt, action, OutcomeFailed, "authorization_denied", now, err)
		}
		actionReceipt, actionErr := executor.applyAction(ctx, plan, action, now)
		postErr := executor.auditPost(ctx, plan, action, request.Actor, actionReceipt, now)
		if postErr != nil {
			actionReceipt.Outcome, actionReceipt.FailureCode = OutcomeAmbiguous, "audit_persist_failed"
			actionErr = errors.Join(ErrAmbiguous, postErr)
		}
		receipt.Actions = append(receipt.Actions, actionReceipt)
		if actionErr != nil {
			terminal := PlanBlocked
			if actionReceipt.Outcome == OutcomeAmbiguous {
				terminal = PlanAmbiguous
			} else if hasAppliedAction(receipt.Actions) {
				terminal = PlanPartial
			}
			receipt.State, receipt.NextSequence, receipt.FailureCode = terminal, 0, actionReceipt.FailureCode
			receipt, err = executor.persistReceipt(ctx, receipt, now)
			if err != nil {
				return receipt, errors.Join(actionErr, err)
			}
			if _, err = executor.transitionPlan(ctx, plan, terminal, now); err != nil {
				return receipt, errors.Join(actionErr, err)
			}
			if terminal == PlanAmbiguous {
				return receipt, errors.Join(ErrAmbiguous, actionErr)
			}
			if terminal == PlanPartial {
				return receipt, errors.Join(ErrPartial, actionErr)
			}
			return receipt, actionErr
		}
		receipt.NextSequence = action.Sequence + 1
		if index == len(plan.Actions)-1 {
			receipt.State, receipt.NextSequence = PlanCompleted, 0
		}
		receipt, err = executor.persistReceipt(ctx, receipt, now)
		if err != nil {
			return receipt, errors.Join(ErrAmbiguous, err)
		}
	}
	if receipt.State != PlanCompleted {
		return receipt, ErrIntegrity
	}
	if _, err = executor.transitionPlan(ctx, plan, PlanCompleted, now); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func (executor Executor) applyAction(ctx context.Context, plan Plan, action PlanAction, now time.Time) (ActionReceipt, error) {
	completed := ActionReceipt{ActionID:action.ID,Sequence:action.Sequence,CompletedAt:now}
	if action.Kind != ActionExpireObject {
		backend, err := executor.Work.Apply(ctx, WorkControlRequest{PlanID:plan.ID,ActionID:action.ID,FilesystemID:action.FilesystemID,Kind:action.Kind})
		completed.BackendReceipt = backend.Receipt
		if backend.ActionID != action.ID || backend.Ambiguous || err != nil && backend.Applied || backend.Applied && (backend.Receipt == "" || len(backend.Receipt) > 4096 || strings.ContainsAny(backend.Receipt, "\x00\r\n")) {
			completed.Outcome, completed.FailureCode = OutcomeAmbiguous, "control_ambiguous"
			return completed, errors.Join(ErrAmbiguous, err)
		}
		if err != nil || !backend.Applied {
			completed.Outcome, completed.FailureCode = OutcomeFailed, "control_failed"
			if err == nil {
				err = ErrIntegrity
			}
			return completed, err
		}
		completed.Outcome = OutcomeApplied
		return completed, nil
	}
	prior, found, err := executor.Objects.LookupAction(ctx, action.ID)
	if err != nil {
		completed.Outcome, completed.FailureCode = OutcomeFailed, "lookup_failed"
		return completed, err
	}
	if found {
		return exactActionReceipt(action, prior, now)
	}
	current, err := executor.Objects.Inspect(ctx, action.DescriptorID, action.ObjectID)
	if err != nil {
		completed.Outcome, completed.FailureCode = OutcomeFailed, "inspect_failed"
		return completed, err
	}
	if !current.Exists {
		completed.Outcome, completed.FailureCode = OutcomeAmbiguous, "object_absent_without_receipt"
		return completed, ErrAmbiguous
	}
	if current.validate() != nil || current.DescriptorID != action.DescriptorID || current.ObjectID != action.ObjectID || current.FilesystemID != action.FilesystemID || current.TenantID != action.TenantID || current.Class != action.Class || current.Protection != ProtectionEligible || current.Protection != action.Protection || current.Retention != action.Retention || current.Generation != action.ExpectedGeneration || current.Digest != action.ExpectedDigest || current.Bytes != action.ExpectedBytes || current.Inodes != action.ExpectedInodes || current.RetainUntil.After(now) {
		completed.Outcome, completed.FailureCode = OutcomeFailed, "precondition_changed"
		return completed, ErrStaleGeneration
	}
	backend, err := executor.Objects.Expire(ctx, ExactObjectRequest{PlanID:plan.ID,ActionID:action.ID,DescriptorID:action.DescriptorID,ObjectID:action.ObjectID,FilesystemID:action.FilesystemID,TenantID:action.TenantID,ExpectedClass:action.Class,ExpectedProtection:action.Protection,ExpectedRetention:action.Retention,ExpectedGeneration:action.ExpectedGeneration,ExpectedDigest:action.ExpectedDigest})
	if err != nil {
		if backend.Applied || backend.Ambiguous {
			completed.Outcome, completed.FailureCode, completed.BackendReceipt = OutcomeAmbiguous, "expiration_ambiguous", backend.Receipt
			return completed, errors.Join(ErrAmbiguous, err)
		}
		completed.Outcome, completed.FailureCode = OutcomeFailed, "expiration_failed"
		return completed, err
	}
	return exactActionReceipt(action, backend, now)
}

func exactActionReceipt(action PlanAction, backend BackendMutationReceipt, now time.Time) (ActionReceipt, error) {
	receipt := ActionReceipt{ActionID:action.ID,Sequence:action.Sequence,ObservedGeneration:backend.ObservedGeneration,ObservedDigest:backend.ObservedDigest,ReclaimedBytes:backend.ReclaimedBytes,ReclaimedInodes:backend.ReclaimedInodes,BackendReceipt:backend.Receipt,CompletedAt:now}
	if backend.ActionID != action.ID || backend.DescriptorID != action.DescriptorID || backend.ObjectID != action.ObjectID || backend.Ambiguous || !backend.Applied || backend.ObservedGeneration < action.ExpectedGeneration || backend.ObservedDigest != "" && !validDigest(backend.ObservedDigest) || backend.ReclaimedBytes > action.ExpectedBytes || backend.ReclaimedInodes > action.ExpectedInodes || backend.Receipt == "" || len(backend.Receipt) > 4096 || strings.ContainsAny(backend.Receipt, "\x00\r\n") {
		receipt.Outcome, receipt.FailureCode = OutcomeAmbiguous, "expiration_ambiguous"
		return receipt, ErrAmbiguous
	}
	receipt.Outcome = OutcomeApplied
	return receipt, nil
}

func (executor Executor) authorize(ctx context.Context, plan Plan, action PlanAction, actor Actor, now time.Time, operation string) error {
	digest := plan.InputDigest
	if action.ID != "" {
		value, err := digestValue(action)
		if err != nil {
			return err
		}
		digest = value
	}
	request := AuthorizationRequest{Actor:actor,Operation:operation,PlanID:plan.ID,ActionID:action.ID,FilesystemID:plan.FilesystemID,TenantID:action.TenantID,Destructive:action.Destructive,Emergency:plan.Level==PressureEmergency,RequestDigest:digest}
	authorizationErr := executor.Authorizer.Authorize(ctx, request)
	outcome, reason := "allowed", "authorized"
	if authorizationErr != nil {
		outcome, reason = "denied", "authorization_denied"
	}
	event, err := sealAuditEvent(AuditEvent{ID:auditEventID(plan.ID,action.ID,"authorization"),Boundary:"authorization",PlanID:plan.ID,ActionID:action.ID,PrincipalID:actor.PrincipalID,AuthorizationEpoch:actor.AuthorizationEpoch,RequestDigest:digest,Outcome:outcome,ReasonCode:reason,OccurredAt:now})
	if err != nil || executor.Auditor.Record(ctx, event) != nil {
		return ErrIntegrity
	}
	if authorizationErr != nil {
		return errors.Join(ErrUnauthorized, authorizationErr)
	}
	return nil
}

func (executor Executor) auditPost(ctx context.Context, plan Plan, action PlanAction, actor Actor, receipt ActionReceipt, now time.Time) error {
	requestDigest, err := digestValue(action)
	if err != nil {
		return err
	}
	outcome := string(receipt.Outcome)
	reason := receipt.FailureCode
	if reason == "" {
		reason = "action_applied"
	}
	event, err := sealAuditEvent(AuditEvent{ID:auditEventID(plan.ID,action.ID,"result"),Boundary:"result",PlanID:plan.ID,ActionID:action.ID,PrincipalID:actor.PrincipalID,AuthorizationEpoch:actor.AuthorizationEpoch,RequestDigest:requestDigest,Outcome:outcome,ReasonCode:reason,OccurredAt:now})
	if err != nil {
		return err
	}
	return executor.Auditor.Record(ctx, event)
}

func sealAuditEvent(event AuditEvent) (AuditEvent, error) {
	if !validID(event.ID) || !validID(event.PlanID) || event.ActionID != "" && !validID(event.ActionID) || !validID(event.PrincipalID) || event.AuthorizationEpoch == 0 || !validDigest(event.RequestDigest) || event.OccurredAt.IsZero() || len(event.Boundary) > 32 || len(event.Outcome) > 32 || len(event.ReasonCode) > 128 || strings.ContainsAny(event.Boundary+event.Outcome+event.ReasonCode, "\x00\r\n") {
		return AuditEvent{}, ErrInvalid
	}
	event.OccurredAt, event.Digest = event.OccurredAt.UTC(), ""
	digest, err := digestValue(event)
	if err != nil {
		return AuditEvent{}, err
	}
	event.Digest = digest
	return event, nil
}

func (executor Executor) persistReceipt(ctx context.Context, receipt ExecutionReceipt, now time.Time) (ExecutionReceipt, error) {
	expected := receipt.Generation
	receipt.Generation, receipt.UpdatedAt = expected+1, now
	sealed, err := SealReceipt(receipt)
	if err != nil {
		return receipt, err
	}
	if err = executor.Journal.SaveReceipt(ctx, sealed, expected); err != nil {
		return receipt, err
	}
	return sealed, nil
}

func (executor Executor) currentTime() time.Time {
	if executor.Now != nil {
		return executor.Now().UTC()
	}
	return time.Now().UTC()
}

func observationUncertain(observation FilesystemObservation, policy WatermarkPolicy, now time.Time) bool {
	return now.Before(observation.ObservedAt.UTC()) || now.Sub(observation.ObservedAt.UTC()) > policy.MaximumObservationAge || basisPointsExceeded(observation.UncertaintyBytes, observation.TotalBytes, policy.MaximumUncertaintyBasisPoints) || basisPointsExceeded(observation.UncertaintyInodes, observation.TotalInodes, policy.MaximumUncertaintyBasisPoints)
}

func (executor Executor) transitionPlan(ctx context.Context, plan Plan, state PlanState, now time.Time) (Plan, error) {
	expected := plan.Generation
	plan.State, plan.Generation, plan.UpdatedAt = state, expected+1, now
	sealed, err := SealPlan(plan)
	if err != nil {
		return plan, err
	}
	if err = executor.Journal.UpdatePlan(ctx, sealed, expected); err != nil {
		return plan, err
	}
	return sealed, nil
}

func (executor Executor) stop(ctx context.Context, plan Plan, receipt ExecutionReceipt, action PlanAction, outcome ActionOutcome, code string, now time.Time, cause error) (ExecutionReceipt, error) {
	terminal := PlanBlocked
	if hasAppliedAction(receipt.Actions) {
		terminal = PlanPartial
	}
	receipt.Actions = append(receipt.Actions, ActionReceipt{ActionID:action.ID,Sequence:action.Sequence,Outcome:outcome,FailureCode:code,CompletedAt:now})
	receipt.State, receipt.NextSequence, receipt.FailureCode = terminal, 0, code
	sealed, err := executor.persistReceipt(ctx, receipt, now)
	if err != nil {
		return receipt, errors.Join(cause, err)
	}
	_, transitionErr := executor.transitionPlan(ctx, plan, terminal, now)
	if terminal == PlanPartial {
		return sealed, errors.Join(ErrPartial, cause, transitionErr)
	}
	return sealed, errors.Join(cause, transitionErr)
}

func hasAppliedAction(receipts []ActionReceipt) bool {
	for _, receipt := range receipts {
		if receipt.Outcome == OutcomeApplied {
			return true
		}
	}
	return false
}

func onlyBlockingActions(actions []PlanAction) bool {
	if len(actions) == 0 {
		return false
	}
	for _, action := range actions {
		if action.Kind != ActionBlockHeavyWork || action.Destructive {
			return false
		}
	}
	return true
}

func receiptID(planID string) string {
	sum := sha256.Sum256([]byte("diskguard-receipt-v1\x00" + planID))
	return "dgrcpt-" + hex.EncodeToString(sum[:])[:48]
}

func auditEventID(planID, actionID, boundary string) string {
	sum := sha256.Sum256([]byte("diskguard-audit-v1\x00"+planID+"\x00"+actionID+"\x00"+boundary))
	return "dgaudit-" + hex.EncodeToString(sum[:])[:48]
}

var _ Journal = SQLiteRepository{}
