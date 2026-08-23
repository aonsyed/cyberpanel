package nodeidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"
)

type Permission string

const (
	PermissionPlan    Permission = "node_identity.plan"
	PermissionExecute Permission = "node_identity.execute"
	PermissionRead    Permission = "node_identity.read"
)

type Authorizer interface {
	Authorize(context.Context, Actor, Scope, Permission) error
}

type StepUpObservation struct {
	PrincipalID PrincipalID `json:"principal_id"`
	SessionID   string      `json:"session_id"`
	VerifiedAt  time.Time   `json:"verified_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	Method      string      `json:"method"`
}

func (observation StepUpObservation) Validate(actor Actor, now time.Time) error {
	if observation.PrincipalID != actor.PrincipalID || observation.SessionID != actor.SessionID || !validUTC(now) || !validUTC(observation.VerifiedAt) || !validUTC(observation.ExpiresAt) || observation.VerifiedAt.After(now) || now.Sub(observation.VerifiedAt) > MaximumStepUpAge || !observation.ExpiresAt.After(now) || observation.ExpiresAt.After(observation.VerifiedAt.Add(MaximumStepUpAge)) || !validID(observation.Method) {
		return ErrStepUpRequired
	}
	return nil
}

type RecentStepUp interface {
	Observe(context.Context, Actor) (StepUpObservation, error)
}

type AuditAction string
type AuditOutcome string

const (
	AuditPlan    AuditAction = "plan"
	AuditExecute AuditAction = "execute"

	AuditAttempt   AuditOutcome = "attempt"
	AuditSucceeded AuditOutcome = "succeeded"
	AuditDenied    AuditOutcome = "denied"
	AuditFailed    AuditOutcome = "failed"
)

type AuditEvent struct {
	ID            string       `json:"id"`
	Scope         Scope        `json:"scope"`
	PlanID        PlanID       `json:"plan_id,omitempty"`
	Actor         Actor        `json:"actor"`
	Action        AuditAction  `json:"action"`
	Phase         ExecutionPhase `json:"phase,omitempty"`
	Outcome       AuditOutcome `json:"outcome"`
	RequestDigest string       `json:"request_digest"`
	ErrorCode     string       `json:"error_code,omitempty"`
	OccurredAt    time.Time    `json:"occurred_at"`
}

func (event AuditEvent) Validate() error {
	if !validID(event.ID) || event.Scope.Validate() != nil || event.Actor.Validate() != nil || !validDigest(event.RequestDigest) || !validUTC(event.OccurredAt) || event.Action != AuditPlan && event.Action != AuditExecute || event.Action == AuditExecute && (!validID(string(event.PlanID)) || phaseForAudit(event.Phase) == "") {
		return ErrInvalid
	}
	if event.Outcome == AuditAttempt || event.Outcome == AuditSucceeded {
		if event.ErrorCode != "" {
			return ErrInvalid
		}
	} else if event.Outcome != AuditDenied && event.Outcome != AuditFailed || !validErrorCode(event.ErrorCode) {
		return ErrInvalid
	}
	return nil
}

// AuditSink returns nil only after the event is durably appended.
type AuditSink interface {
	Append(context.Context, AuditEvent) error
}

type Coordinator struct {
	Repository    Repository
	Authorization Authorizer
	StepUp        RecentStepUp
	Executor      Executor
	Audit         AuditSink
	Now           func() time.Time
}

type RunResult struct {
	Execution Execution         `json:"execution"`
	Receipt   *ExecutionReceipt `json:"receipt,omitempty"`
	Progress  bool              `json:"progress"`
}

type ExecutionStatus struct {
	Plan       ChangePlan         `json:"plan"`
	Execution  Execution          `json:"execution"`
	Receipts   []ExecutionReceipt `json:"receipts"`
}

func (coordinator *Coordinator) Snapshot(ctx context.Context, actor Actor, scope Scope) (Snapshot, error) {
	if coordinator.invalid() || ctx == nil || actor.Validate() != nil || scope.Validate() != nil {
		return Snapshot{}, ErrInvalid
	}
	if coordinator.authorize(ctx, actor, scope, PermissionRead) != nil {
		return Snapshot{}, ErrUnauthorized
	}
	return coordinator.Repository.Snapshot(ctx, scope, coordinator.currentTime())
}

func (coordinator *Coordinator) Status(ctx context.Context, actor Actor, id PlanID) (ExecutionStatus, error) {
	if coordinator.invalid() || ctx == nil || actor.Validate() != nil || !validID(string(id)) {
		return ExecutionStatus{}, ErrInvalid
	}
	plan, err := coordinator.Repository.Plan(ctx, id)
	if err != nil {
		return ExecutionStatus{}, err
	}
	if coordinator.authorize(ctx, actor, plan.Scope, PermissionRead) != nil {
		return ExecutionStatus{}, ErrUnauthorized
	}
	execution, err := coordinator.Repository.Execution(ctx, id)
	if err != nil {
		return ExecutionStatus{}, err
	}
	receipts, err := coordinator.Repository.Receipts(ctx, plan, coordinator.currentTime())
	if err != nil {
		return ExecutionStatus{}, err
	}
	return ExecutionStatus{Plan: plan, Execution: execution, Receipts: receipts}, nil
}

func (coordinator *Coordinator) Plan(ctx context.Context, actor Actor, scope Scope, request PlanRequest) (ChangePlan, error) {
	if coordinator.invalid() || ctx == nil || actor.Validate() != nil || scope.Validate() != nil {
		return ChangePlan{}, ErrInvalid
	}
	if coordinator.authorize(ctx, actor, scope, PermissionPlan) != nil {
		return ChangePlan{}, ErrUnauthorized
	}
	if coordinator.requireStepUp(ctx, actor) != nil {
		return ChangePlan{}, ErrStepUpRequired
	}
	now := coordinator.currentTime()
	snapshot, err := coordinator.Repository.Snapshot(ctx, scope, now)
	if err != nil {
		return ChangePlan{}, err
	}
	plan, err := BuildPlan(snapshot.Desired, snapshot.Observed, request, actor.PrincipalID, now)
	if err != nil {
		return ChangePlan{}, err
	}
	if coordinator.appendAudit(ctx, AuditEvent{Scope: scope, PlanID: plan.ID, Actor: actor, Action: AuditPlan, Outcome: AuditAttempt, RequestDigest: plan.Digest, OccurredAt: now}) != nil {
		return ChangePlan{}, ErrAuditUnavailable
	}
	err = coordinator.Repository.SavePlan(ctx, plan, now)
	if auditErr := coordinator.auditResult(ctx, scope, plan.ID, actor, AuditPlan, "", plan.Digest, err); auditErr != nil {
		return ChangePlan{}, auditErr
	}
	return plan, err
}

// RunOnce performs one durable lifecycle transition. Repeated calls resume from
// immutable receipts and never run an unbounded worker loop.
func (coordinator *Coordinator) RunOnce(ctx context.Context, actor Actor, id PlanID, worker string, leaseDuration time.Duration) (RunResult, error) {
	if coordinator.invalid() || ctx == nil || actor.Validate() != nil || !validID(string(id)) || !validID(worker) {
		return RunResult{}, ErrInvalid
	}
	plan, err := coordinator.Repository.Plan(ctx, id)
	if err != nil {
		return RunResult{}, err
	}
	if coordinator.authorize(ctx, actor, plan.Scope, PermissionExecute) != nil {
		return RunResult{}, ErrUnauthorized
	}
	if coordinator.requireStepUp(ctx, actor) != nil {
		return RunResult{}, ErrStepUpRequired
	}
	now := coordinator.currentTime()
	plan, lease, claimed, err := coordinator.Repository.Claim(ctx, id, worker, leaseDuration, now)
	if err != nil || !claimed {
		if err != nil {
			return RunResult{}, err
		}
		execution, loadErr := coordinator.Repository.Execution(ctx, id)
		return RunResult{Execution: execution}, loadErr
	}
	phase := phaseForState(lease.Execution.State)
	requestDigest, _ := digestValue("execution-request", struct {
		PlanID PlanID `json:"plan_id"`
		Phase ExecutionPhase `json:"phase"`
		Fence uint64 `json:"fence"`
	}{id, phase, lease.Fence})
	if coordinator.appendAudit(ctx, AuditEvent{Scope: plan.Scope, PlanID: id, Actor: actor, Action: AuditExecute, Phase: phase, Outcome: AuditAttempt, RequestDigest: requestDigest, OccurredAt: now}) != nil {
		_ = coordinator.Repository.Release(ctx, lease, coordinator.currentTime())
		return RunResult{}, ErrAuditUnavailable
	}
	if lease.Execution.State == ExecutionQueued || lease.Execution.State == ExecutionStaged || lease.Execution.State == ExecutionPreflighted {
		if staleErr := coordinator.verifyBefore(ctx, plan, now); staleErr != nil {
			receipt := coordinator.failureReceipt(plan, lease, phase, OutcomeNotApplied, errorCode(staleErr), now, coordinator.currentTime())
			transition := failureTransition(lease.Execution, receipt, plan)
			if auditErr := coordinator.auditResult(ctx, plan.Scope, id, actor, AuditExecute, phase, requestDigest, staleErr); auditErr != nil {
				_ = coordinator.Repository.Release(ctx, lease, coordinator.currentTime())
				return RunResult{}, auditErr
			}
			execution, recordErr := coordinator.Repository.RecordTransition(ctx, plan, lease, receipt, transition, coordinator.currentTime())
			return RunResult{Execution: execution, Receipt: &receipt, Progress: recordErr == nil}, recordErr
		}
	}
	result, receipt, operationErr := coordinator.runPhase(ctx, actor, plan, lease, now)
	if phase == PhaseCommit && operationErr != nil {
		if auditErr := coordinator.auditResult(ctx, plan.Scope, id, actor, AuditExecute, phase, requestDigest, operationErr); auditErr != nil {
			_ = coordinator.Repository.Release(ctx, lease, coordinator.currentTime())
			return RunResult{}, auditErr
		}
		_ = coordinator.Repository.Release(ctx, lease, coordinator.currentTime())
		return RunResult{}, operationErr
	}
	if operationErr != nil && receipt.Outcome == OutcomeSucceeded {
		receipt.Outcome, receipt.ErrorCode = OutcomeAmbiguous, "executor_failure"
		receipt.Digest, _ = receipt.expectedDigest()
	}
	if receipt.Validate(plan, coordinator.currentTime()) != nil {
		receipt = coordinator.failureReceipt(plan, lease, phase, OutcomeAmbiguous, "executor_failure", now, coordinator.currentTime())
		operationErr = ErrConflict
	}
	if phase == PhaseCommit && receipt.Outcome == OutcomeSucceeded {
		commitResult, commitErr := coordinator.commit(ctx, actor, plan, lease, receipt, result.desired, result.observed, coordinator.currentTime())
		if auditErr := coordinator.auditResult(ctx, plan.Scope, id, actor, AuditExecute, phase, requestDigest, commitErr); auditErr != nil {
			return RunResult{}, auditErr
		}
		return commitResult, commitErr
	}
	if auditErr := coordinator.auditResult(ctx, plan.Scope, id, actor, AuditExecute, phase, requestDigest, operationErr); auditErr != nil {
		_ = coordinator.Repository.Release(ctx, lease, coordinator.currentTime())
		return RunResult{}, auditErr
	}
	transition := transitionFor(lease.Execution, receipt, plan)
	execution, err := coordinator.Repository.RecordTransition(ctx, plan, lease, receipt, transition, coordinator.currentTime())
	return RunResult{Execution: execution, Receipt: &receipt, Progress: err == nil}, err
}

type phaseResult struct {
	desired  *DesiredIdentity
	observed *ObservedIdentity
}

func (coordinator *Coordinator) runPhase(ctx context.Context, actor Actor, plan ChangePlan, lease ExecutionLease, started time.Time) (phaseResult, ExecutionReceipt, error) {
	phase := phaseForState(lease.Execution.State)
	receipts, err := coordinator.Repository.Receipts(ctx, plan, started)
	if err != nil {
		return phaseResult{}, coordinator.failureReceipt(plan, lease, phase, OutcomeAmbiguous, "conflict", started, coordinator.currentTime()), err
	}
	deadlineContext, cancel := context.WithDeadline(ctx, lease.Until)
	defer cancel()
	receipt := ExecutionReceipt{PlanID: plan.ID, PlanDigest: plan.Digest, Phase: phase, Fence: lease.Fence, Attempt: lease.Execution.Attempt, StartedAt: started}
	var operationErr error
	switch phase {
	case PhaseStage:
		value, outcome, callErr := coordinator.Executor.Stage(deadlineContext, StageRequest{PlanID: plan.ID, PlanDigest: plan.Digest, IdempotencyKey: idempotencyKey(plan.ID, phase), Before: plan.Before, After: plan.After, Effects: append([]EffectIntent(nil), plan.Effects...), Fence: lease.Fence, LeaseUntil: lease.Until})
		receipt.Stage, receipt.Outcome, operationErr = &value, normalizeOutcome(outcome, callErr), callErr
	case PhasePreflight:
		stage, found := latestStage(receipts)
		if !found {
			return phaseResult{}, coordinator.failureReceipt(plan, lease, phase, OutcomeAmbiguous, "conflict", started, coordinator.currentTime()), ErrConflict
		}
		value, outcome, callErr := coordinator.Executor.Preflight(deadlineContext, PreflightRequest{PlanID: plan.ID, PlanDigest: plan.Digest, IdempotencyKey: idempotencyKey(plan.ID, phase), Impacts: append([]ChangeImpact(nil), plan.Impacts...), Staged: stage, Fence: lease.Fence, LeaseUntil: lease.Until})
		receipt.Preflight, receipt.Outcome, operationErr = &value, normalizeOutcome(outcome, callErr), callErr
	case PhaseActivate:
		value, outcome, callErr := coordinator.Executor.Activate(deadlineContext, ActivateRequest{PlanID: plan.ID, PlanDigest: plan.Digest, IdempotencyKey: idempotencyKey(plan.ID, phase), Effects: append([]EffectIntent(nil), plan.Effects...), MakeBeforeBreak: makeBeforeBreak(plan), Fence: lease.Fence, LeaseUntil: lease.Until})
		receipt.Activation, receipt.Outcome, operationErr = &value, normalizeOutcome(outcome, callErr), callErr
	case PhaseProbe:
		value, outcome, callErr := coordinator.Executor.Probe(deadlineContext, ProbeRequest{PlanID: plan.ID, PlanDigest: plan.Digest, IdempotencyKey: idempotencyKey(plan.ID, phase), Scope: plan.Scope, After: plan.After, AfterGeneration: plan.AfterGeneration, ObservedRevision: plan.BeforeObservedRevision + 1, Fence: lease.Fence, LeaseUntil: lease.Until})
		receipt.Probe, receipt.Outcome, operationErr = &value, normalizeOutcome(outcome, callErr), callErr
	case PhaseCompensate:
		value, outcome, callErr := coordinator.Executor.Compensate(deadlineContext, CompensateRequest{PlanID: plan.ID, PlanDigest: plan.Digest, IdempotencyKey: idempotencyKey(plan.ID, phase), Before: plan.Before, Receipts: receipts, Fence: lease.Fence, LeaseUntil: lease.Until})
		receipt.Compensation, receipt.Outcome, operationErr = &value, normalizeOutcome(outcome, callErr), callErr
	case PhaseCommit:
		probe, found := latestProbe(receipts)
		if !found || probe.Observed == nil {
			return phaseResult{}, coordinator.failureReceipt(plan, lease, phase, OutcomeAmbiguous, "conflict", started, coordinator.currentTime()), ErrConflict
		}
		desired, desiredErr := NewDesiredIdentity(plan.Scope, plan.BeforeDesiredRevision+1, plan.AfterGeneration, plan.After, actor.PrincipalID, coordinator.currentTime())
		if desiredErr != nil {
			return phaseResult{}, coordinator.failureReceipt(plan, lease, phase, OutcomeAmbiguous, "conflict", started, coordinator.currentTime()), desiredErr
		}
		receipt.Commit, receipt.Outcome = &CommitResult{DesiredDigest: desired.Digest, ObservedDigest: probe.Observed.Digest}, OutcomeSucceeded
		result := phaseResult{desired: &desired, observed: probe.Observed}
		receipt.FinishedAt = coordinator.currentTime()
		receipt.Digest, _ = receipt.expectedDigest()
		return result, receipt, nil
	default:
		return phaseResult{}, coordinator.failureReceipt(plan, lease, phase, OutcomeAmbiguous, "conflict", started, coordinator.currentTime()), ErrConflict
	}
	receipt.FinishedAt = coordinator.currentTime()
	if receipt.Outcome != OutcomeSucceeded {
		if operationErr == nil {
			operationErr = ErrIncomplete
			receipt.ErrorCode = phaseErrorCode(phase)
		} else {
			receipt.ErrorCode = errorCode(operationErr)
		}
	}
	receipt.Digest, _ = receipt.expectedDigest()
	return phaseResult{}, receipt, operationErr
}

func (coordinator *Coordinator) commit(ctx context.Context, actor Actor, plan ChangePlan, lease ExecutionLease, receipt ExecutionReceipt, desired *DesiredIdentity, observed *ObservedIdentity, now time.Time) (RunResult, error) {
	if desired == nil || observed == nil || desired.UpdatedBy != actor.PrincipalID {
		return RunResult{}, ErrIncomplete
	}
	if receipt.Commit == nil || receipt.Commit.DesiredDigest != desired.Digest || receipt.Commit.ObservedDigest != observed.Digest {
		return RunResult{}, ErrConflict
	}
	execution, err := coordinator.Repository.Commit(ctx, plan, lease, receipt, *desired, *observed, now)
	if err != nil {
		_ = coordinator.Repository.Release(ctx, lease, coordinator.currentTime())
	}
	return RunResult{Execution: execution, Receipt: &receipt, Progress: err == nil}, err
}

func (coordinator *Coordinator) verifyBefore(ctx context.Context, plan ChangePlan, now time.Time) error {
	if plan.ValidateAt(now) != nil {
		return ErrStale
	}
	snapshot, err := coordinator.Repository.Snapshot(ctx, plan.Scope, now)
	if err != nil {
		return err
	}
	if snapshot.Observed.Validate(snapshot.Desired.Spec, now) != nil || snapshot.Desired.Revision != plan.BeforeDesiredRevision || snapshot.Desired.Generation != plan.BeforeGeneration || snapshot.Desired.Digest != plan.BeforeDesiredDigest || snapshot.Observed.Revision != plan.BeforeObservedRevision || snapshot.Observed.Digest != plan.BeforeObservationDigest || !snapshot.Observed.CoreMatches(snapshot.Desired.Spec) {
		return ErrStale
	}
	return nil
}

func transitionFor(execution Execution, receipt ExecutionReceipt, plan ChangePlan) Transition {
	if receipt.Outcome != OutcomeSucceeded {
		return failureTransition(execution, receipt, plan)
	}
	switch execution.State {
	case ExecutionQueued:
		return Transition{Next: ExecutionStaged}
	case ExecutionStaged:
		return Transition{Next: ExecutionPreflighted}
	case ExecutionPreflighted:
		irreversible := receipt.Activation.Rollback == RollbackIrreversible || plan.Requirements.OverallRollback == RollbackIrreversible
		return Transition{Next: ExecutionActivated, Activated: true, IrreversibleCrossed: irreversible}
	case ExecutionActivated:
		return Transition{Next: ExecutionProbed, Activated: true, IrreversibleCrossed: execution.IrreversibleCrossed}
	case ExecutionCompensating:
		return Transition{Next: ExecutionCompensated, Activated: execution.Activated, IrreversibleCrossed: execution.IrreversibleCrossed}
	default:
		return Transition{Next: ExecutionAmbiguous, Activated: execution.Activated, IrreversibleCrossed: execution.IrreversibleCrossed, Ambiguous: true, ErrorCode: "conflict"}
	}
}

func failureTransition(execution Execution, receipt ExecutionReceipt, plan ChangePlan) Transition {
	code := receipt.ErrorCode
	if code == "" {
		code = phaseErrorCode(receipt.Phase)
	}
	if receipt.Outcome == OutcomeAmbiguous {
		return Transition{Next: ExecutionAmbiguous, Activated: execution.Activated, IrreversibleCrossed: execution.IrreversibleCrossed, Ambiguous: true, ErrorCode: code}
	}
	switch execution.State {
	case ExecutionQueued:
		return Transition{Next: ExecutionFailed, ErrorCode: code}
	case ExecutionStaged, ExecutionPreflighted:
		return Transition{Next: ExecutionCompensating, ErrorCode: code}
	case ExecutionActivated:
		if execution.IrreversibleCrossed || plan.Requirements.OverallRollback == RollbackIrreversible {
			return Transition{Next: ExecutionIrreversible, Activated: true, IrreversibleCrossed: true, ErrorCode: code}
		}
		if plan.Requirements.OverallRollback == RollbackAmbiguous {
			return Transition{Next: ExecutionAmbiguous, Activated: true, Ambiguous: true, ErrorCode: code}
		}
		return Transition{Next: ExecutionCompensating, Activated: true, ErrorCode: code}
	case ExecutionCompensating:
		if execution.Activated {
			return Transition{Next: ExecutionIrreversible, Activated: true, IrreversibleCrossed: true, ErrorCode: code}
		}
		return Transition{Next: ExecutionAmbiguous, Ambiguous: true, ErrorCode: code}
	default:
		return Transition{Next: ExecutionAmbiguous, Activated: execution.Activated, IrreversibleCrossed: execution.IrreversibleCrossed, Ambiguous: true, ErrorCode: code}
	}
}

func (coordinator *Coordinator) failureReceipt(plan ChangePlan, lease ExecutionLease, phase ExecutionPhase, outcome ReceiptOutcome, code string, started, finished time.Time) ExecutionReceipt {
	receipt := ExecutionReceipt{PlanID: plan.ID, PlanDigest: plan.Digest, Phase: phase, Fence: lease.Fence, Attempt: lease.Execution.Attempt, Outcome: outcome, ErrorCode: code, StartedAt: started, FinishedAt: finished}
	switch phase {
	case PhaseStage:
		receipt.Stage = &StageResult{}
	case PhasePreflight:
		receipt.Preflight = &PreflightResult{}
	case PhaseActivate:
		receipt.Activation = &ActivationResult{}
	case PhaseProbe:
		receipt.Probe = &ProbeResult{}
	case PhaseCompensate:
		receipt.Compensation = &CompensationResult{}
	case PhaseCommit:
		receipt.Commit = &CommitResult{}
	}
	receipt.Digest, _ = receipt.expectedDigest()
	return receipt
}

func latestStage(receipts []ExecutionReceipt) (StageResult, bool) {
	for index := len(receipts) - 1; index >= 0; index-- {
		if receipts[index].Phase == PhaseStage && receipts[index].Outcome == OutcomeSucceeded && receipts[index].Stage != nil {
			return *receipts[index].Stage, true
		}
	}
	return StageResult{}, false
}

func latestProbe(receipts []ExecutionReceipt) (ProbeResult, bool) {
	for index := len(receipts) - 1; index >= 0; index-- {
		if receipts[index].Phase == PhaseProbe && receipts[index].Outcome == OutcomeSucceeded && receipts[index].Probe != nil {
			return *receipts[index].Probe, true
		}
	}
	return ProbeResult{}, false
}

func normalizeOutcome(outcome ReceiptOutcome, err error) ReceiptOutcome {
	if outcome == OutcomeSucceeded || outcome == OutcomeNotApplied || outcome == OutcomeAmbiguous {
		if err != nil && outcome == OutcomeSucceeded {
			return OutcomeAmbiguous
		}
		return outcome
	}
	if err != nil {
		return OutcomeAmbiguous
	}
	return OutcomeAmbiguous
}

func idempotencyKey(id PlanID, phase ExecutionPhase) string {
	return string(id) + ":" + string(phase)
}

func phaseErrorCode(phase ExecutionPhase) string {
	switch phase {
	case PhasePreflight:
		return "preflight_failed"
	case PhaseProbe:
		return "probe_failed"
	case PhaseCompensate:
		return "compensation_failed"
	default:
		return "executor_failure"
	}
}

func errorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrStale):
		return "stale"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrConflict):
		return "conflict"
	default:
		return "executor_failure"
	}
}

func (coordinator *Coordinator) invalid() bool {
	return coordinator == nil || coordinator.Repository.DB == nil || nilInterface(coordinator.Authorization) || nilInterface(coordinator.StepUp) || nilInterface(coordinator.Executor) || nilInterface(coordinator.Audit)
}

func (coordinator *Coordinator) authorize(ctx context.Context, actor Actor, scope Scope, permission Permission) error {
	if actor.Validate() != nil || scope.Validate() != nil || actor.TenantID != scope.TenantID || coordinator.Authorization.Authorize(ctx, actor, scope, permission) != nil {
		return ErrUnauthorized
	}
	return nil
}

func (coordinator *Coordinator) requireStepUp(ctx context.Context, actor Actor) error {
	observation, err := coordinator.StepUp.Observe(ctx, actor)
	if err != nil || observation.Validate(actor, coordinator.currentTime()) != nil {
		return ErrStepUpRequired
	}
	return nil
}

func (coordinator *Coordinator) appendAudit(ctx context.Context, event AuditEvent) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return ErrAuditUnavailable
	}
	event.ID = "identity-audit-" + marshalDigest("audit", json.RawMessage(encoded))[:40]
	if event.Validate() != nil || coordinator.Audit.Append(ctx, event) != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (coordinator *Coordinator) auditResult(ctx context.Context, scope Scope, id PlanID, actor Actor, action AuditAction, phase ExecutionPhase, requestDigest string, operationErr error) error {
	outcome, code := AuditSucceeded, ""
	if operationErr != nil {
		outcome, code = AuditFailed, errorCode(operationErr)
		if errors.Is(operationErr, ErrUnauthorized) || errors.Is(operationErr, ErrStepUpRequired) {
			outcome = AuditDenied
		}
	}
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if coordinator.appendAudit(auditContext, AuditEvent{Scope: scope, PlanID: id, Actor: actor, Action: action, Phase: phase, Outcome: outcome, RequestDigest: requestDigest, ErrorCode: code, OccurredAt: coordinator.currentTime()}) != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (coordinator *Coordinator) currentTime() time.Time {
	if coordinator != nil && coordinator.Now != nil {
		return coordinator.Now().UTC()
	}
	return time.Now().UTC()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func phaseForAudit(phase ExecutionPhase) ExecutionPhase {
	switch phase {
	case PhaseStage, PhasePreflight, PhaseActivate, PhaseProbe, PhaseCommit, PhaseCompensate:
		return phase
	default:
		return ""
	}
}

const (
	linuxHostnamePath   = "/usr/bin/hostname"
	linuxIPPath         = "/usr/sbin/ip"
	linuxTimezonePath   = "/etc/timezone"
	linuxPanelOriginPath = "/etc/cyberpanel/panel-origin"
	defaultOutputLimit  = 64 * 1024
	maximumOutputLimit  = 256 * 1024
)

type LinuxObservation struct {
	Hostname        string       `json:"hostname"`
	FQDN            string       `json:"fqdn"`
	PublicAddresses []netip.Addr `json:"public_addresses"`
	Timezone        string       `json:"timezone"`
	PanelOrigin     string       `json:"panel_origin"`
	ObservedAt      time.Time    `json:"observed_at"`
	Digest          string       `json:"digest"`
}

func (observation LinuxObservation) Validate() error {
	if !validHostLabel(observation.Hostname) || !validFQDN(observation.FQDN) || strings.Split(observation.FQDN, ".")[0] != observation.Hostname || !validPublicAddresses(observation.PublicAddresses) || !validTimezone(observation.Timezone) || !validPanelOrigin(observation.PanelOrigin, observation.FQDN) || !validUTC(observation.ObservedAt) || !validDigest(observation.Digest) {
		return ErrInvalid
	}
	copy := observation
	copy.Digest = ""
	expected, err := digestValue("linux-observation", copy)
	if err != nil || expected != observation.Digest {
		return ErrInvalid
	}
	return nil
}

func (observation LinuxObservation) Values(contact *AdministrativeContact) (ObservedValues, error) {
	if observation.Validate() != nil || contact != nil && contact.Validate() != nil {
		return ObservedValues{}, ErrInvalid
	}
	return ObservedValues{Hostname: observation.Hostname, FQDN: observation.FQDN, PublicAddresses: append([]netip.Addr(nil), observation.PublicAddresses...), Timezone: observation.Timezone, AdministrativeContact: contact, PanelOrigin: observation.PanelOrigin}, nil
}

type LinuxObserver struct {
	Timeout   time.Duration
	MaxOutput int
	Now       func() time.Time
}

func (observer LinuxObserver) Observe(ctx context.Context) (LinuxObservation, error) {
	if ctx == nil || runtime.GOOS != "linux" {
		return LinuxObservation{}, ErrUnsupported
	}
	timeout, limit, err := observer.limits()
	if err != nil {
		return LinuxObservation{}, err
	}
	shortName, err := observer.run(ctx, timeout, limit, linuxHostnamePath, "--short")
	if err != nil {
		return LinuxObservation{}, err
	}
	fqdn, err := observer.run(ctx, timeout, limit, linuxHostnamePath, "--fqdn")
	if err != nil {
		return LinuxObservation{}, err
	}
	addressJSON, err := observer.run(ctx, timeout, limit, linuxIPPath, "-json", "address", "show", "up", "scope", "global")
	if err != nil {
		return LinuxObservation{}, err
	}
	addresses, err := parseIPAddresses(addressJSON)
	if err != nil {
		return LinuxObservation{}, err
	}
	timezone, err := readFixedFile(linuxTimezonePath, limit)
	if err != nil {
		return LinuxObservation{}, err
	}
	origin, err := readFixedFile(linuxPanelOriginPath, limit)
	if err != nil {
		return LinuxObservation{}, err
	}
	now := time.Now().UTC()
	if observer.Now != nil {
		now = observer.Now().UTC()
	}
	result := LinuxObservation{Hostname: strings.TrimSpace(shortName), FQDN: strings.TrimSpace(fqdn), PublicAddresses: addresses, Timezone: strings.TrimSpace(timezone), PanelOrigin: strings.TrimSpace(origin), ObservedAt: now}
	copy := result
	copy.Digest = ""
	result.Digest, err = digestValue("linux-observation", copy)
	if err != nil || result.Validate() != nil {
		return LinuxObservation{}, ErrIncomplete
	}
	return result, nil
}

func (observer LinuxObserver) limits() (time.Duration, int, error) {
	timeout, limit := observer.Timeout, observer.MaxOutput
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	if limit == 0 {
		limit = defaultOutputLimit
	}
	if timeout < 100*time.Millisecond || timeout > 5*time.Second || limit < 1024 || limit > maximumOutputLimit {
		return 0, 0, ErrInvalid
	}
	return timeout, limit, nil
}

func (observer LinuxObserver) run(ctx context.Context, timeout time.Duration, limit int, path string, arguments ...string) (string, error) {
	hostnameArguments := path == linuxHostnamePath && len(arguments) == 1 && (arguments[0] == "--short" || arguments[0] == "--fqdn")
	ipArguments := path == linuxIPPath && slices.Equal(arguments, []string{"-json", "address", "show", "up", "scope", "global"})
	if !hostnameArguments && !ipArguments {
		return "", ErrInvalid
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, path, arguments...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Dir = "/"
	command.Stdin = strings.NewReader("")
	stdout, stderr := &boundedBuffer{limit: limit}, &boundedBuffer{limit: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil || commandContext.Err() != nil || stdout.overflow || stderr.overflow {
		return "", ErrIncomplete
	}
	return stdout.String(), nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 || len(value) > remaining {
		buffer.overflow = true
		if remaining > 0 {
			_, _ = buffer.buffer.Write(value[:remaining])
		}
		return max(remaining, 0), io.ErrShortBuffer
	}
	return buffer.buffer.Write(value)
}

func (buffer *boundedBuffer) String() string {
	return buffer.buffer.String()
}

func readFixedFile(path string, limit int) (string, error) {
	if path != linuxTimezonePath && path != linuxPanelOriginPath {
		return "", ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ErrIncomplete
	}
	defer file.Close()
	information, err := file.Stat()
	if err != nil || !information.Mode().IsRegular() || information.Size() > int64(limit) {
		return "", ErrIncomplete
	}
	value, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(value) > limit {
		return "", ErrIncomplete
	}
	return string(value), nil
}

func parseIPAddresses(value string) ([]netip.Addr, error) {
	var links []struct {
		AddressInfo []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(value), &links) != nil {
		return nil, ErrIncomplete
	}
	addresses := make([]netip.Addr, 0, 8)
	for _, link := range links {
		for _, information := range link.AddressInfo {
			if information.Scope != "global" || information.Family != "inet" && information.Family != "inet6" {
				continue
			}
			address, err := netip.ParseAddr(information.Local)
			if err != nil || !publicAddress(address) {
				continue
			}
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, func(left, right netip.Addr) int { return left.Compare(right) })
	addresses = slices.Compact(addresses)
	if !validPublicAddresses(addresses) {
		return nil, ErrIncomplete
	}
	return addresses, nil
}
