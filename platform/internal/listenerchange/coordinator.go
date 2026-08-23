package listenerchange

import (
	"context"
	"errors"
	"slices"
	"time"
)

type Coordinator struct {
	Repository   *SQLiteRepository
	Authorization Authorizer
	StepUp        StepUpVerifier
	RiskApproval  RiskApprover
	Boot          BootObserver
	Ports         PortBroker
	Listeners     ListenerBroker
	Firewall      CanonicalFirewall
	Rollback      PersistentRollback
	Confirmation  ExternalConfirmer
	Audit          AuditSink
	WorkerID       string
	Lease          time.Duration
	Now            func() time.Time
}

func NewCoordinator(repository *SQLiteRepository, authorization Authorizer, stepUp StepUpVerifier, riskApproval RiskApprover, boot BootObserver, ports PortBroker, listeners ListenerBroker, firewall CanonicalFirewall, rollback PersistentRollback, confirmation ExternalConfirmer, audit AuditSink, workerID string) (*Coordinator, error) {
	if repository == nil || authorization == nil || stepUp == nil || riskApproval == nil || boot == nil || ports == nil || listeners == nil || firewall == nil || rollback == nil || confirmation == nil || audit == nil || !validID(workerID) {
		return nil, ErrInvalid
	}
	return &Coordinator{
		Repository: repository, Authorization: authorization, StepUp: stepUp,
		RiskApproval: riskApproval, Boot: boot, Ports: ports, Listeners: listeners,
		Firewall: firewall, Rollback: rollback, Confirmation: confirmation,
		Audit: audit, WorkerID: workerID, Lease: MaximumWorkLease,
		Now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (coordinator *Coordinator) Preview(ctx context.Context, actor Actor, scope Scope, request PlanRequest) (ChangePlan, error) {
	now, err := coordinator.now()
	if err != nil || actor.Validate() != nil || scope.Validate() != nil || actor.TenantID != scope.TenantID {
		return ChangePlan{}, ErrInvalid
	}
	if err := coordinator.Authorization.Authorize(ctx, actor, scope, ActionPreview); err != nil {
		return ChangePlan{}, errors.Join(ErrUnauthorized, err)
	}
	if err := coordinator.StepUp.VerifyRecent(ctx, actor, scope, now, MaximumStepUpAge); err != nil {
		return ChangePlan{}, errors.Join(ErrStepUpRequired, err)
	}
	current, err := coordinator.Repository.Current(ctx, scope, now)
	if err != nil {
		return ChangePlan{}, err
	}
	if request.Target.Validate() != nil || request.ConfirmationPolicy.Validate() != nil || request.TargetCertificate.Validate(now) != nil || request.TargetCertificate.Origin != request.TargetOrigin {
		return ChangePlan{}, ErrInvalid
	}
	open := firewallDifference(request.Target, current.Listeners)
	closeValues := firewallDifference(current.Listeners, request.Target)
	risks := deriveRisks(current, request, open, closeValues)
	if !slices.Equal(risks, request.ApprovedRisks) {
		return ChangePlan{}, ErrRiskApproval
	}
	binding, err := confirmationBinding(current, request, risks)
	if err != nil {
		return ChangePlan{}, err
	}
	if confirmationRequired(current.Listeners, request.Target, request.ConfirmationPolicy, risks) && request.Challenge == nil {
		challenge, issueErr := coordinator.Confirmation.Issue(ctx, scope, binding, request.ConfirmationPolicy, now)
		if issueErr != nil {
			return ChangePlan{}, issueErr
		}
		request.Challenge = &challenge
	}
	plan, err := BuildPlan(current, request, actor.PrincipalID, now)
	if err != nil {
		return ChangePlan{}, err
	}
	if err := coordinator.RiskApproval.Approve(ctx, actor, scope, plan.Risks, plan.Digest); err != nil {
		return ChangePlan{}, errors.Join(ErrRiskApproval, err)
	}
	if err := coordinator.audit(ctx, actor, plan, ActionPreview, "", StatePreviewed, 0, "", "plan_admission"); err != nil {
		return ChangePlan{}, err
	}
	if _, err := coordinator.Repository.CreatePlan(ctx, plan); err != nil {
		return ChangePlan{}, err
	}
	if err := coordinator.audit(ctx, actor, plan, ActionPreview, "", StatePreviewed, 0, "", "plan_created"); err != nil {
		return plan, err
	}
	return plan, nil
}

// RunOnce claims one execution and performs at most one broker effect or durable transition.
func (coordinator *Coordinator) RunOnce(ctx context.Context, actor Actor, planID PlanID) (Execution, error) {
	now, err := coordinator.now()
	if err != nil || actor.Validate() != nil || !validID(string(planID)) {
		return Execution{}, ErrInvalid
	}
	plan, err := coordinator.Repository.Plan(ctx, planID)
	if err != nil {
		return Execution{}, err
	}
	if actor.TenantID != plan.Scope.TenantID {
		return Execution{}, ErrUnauthorized
	}
	before, err := coordinator.Repository.Execution(ctx, planID)
	if err != nil {
		return Execution{}, err
	}
	action := ActionExecute
	if before.State == StateRollingBack || !now.Before(plan.Rollback.Deadline) {
		action = ActionRollback
	}
	if err := coordinator.Authorization.Authorize(ctx, actor, plan.Scope, action); err != nil {
		return Execution{}, errors.Join(ErrUnauthorized, err)
	}
	if action == ActionExecute {
		if err := coordinator.StepUp.VerifyRecent(ctx, actor, plan.Scope, now, MaximumStepUpAge); err != nil {
			return Execution{}, errors.Join(ErrStepUpRequired, err)
		}
	}
	boot, err := coordinator.Boot.ObserveBoot(ctx, plan.Scope, now)
	if err != nil || boot.Validate(now) != nil {
		return Execution{}, ErrStale
	}
	lease := coordinator.Lease
	if lease <= 0 || lease > MaximumWorkLease {
		lease = MaximumWorkLease
	}
	plan, claimed, err := coordinator.Repository.Claim(ctx, planID, coordinator.WorkerID, boot, now, lease)
	if err != nil {
		return claimed, err
	}
	if claimed.State == StateRollingBack && action != ActionRollback {
		if err := coordinator.Authorization.Authorize(ctx, actor, plan.Scope, ActionRollback); err != nil {
			return claimed, errors.Join(ErrUnauthorized, err)
		}
		action = ActionRollback
	}
	if err := coordinator.audit(ctx, actor, plan, action, "", claimed.State, claimed.Attempt, claimed.FenceToken, "execution_claimed"); err != nil {
		return claimed, err
	}
	if claimed.State == StateRollingBack {
		return coordinator.runRollback(ctx, actor, plan, claimed, now)
	}
	switch claimed.State {
	case StatePreviewed:
		if !claimed.PortsReserved {
			return coordinator.reservePorts(ctx, actor, plan, claimed, now)
		}
		return coordinator.stageConfiguration(ctx, actor, plan, claimed, now)
	case StateStaged:
		return coordinator.validateConfiguration(ctx, actor, plan, claimed, now)
	case StateValidated:
		return coordinator.openFirewall(ctx, actor, plan, claimed, now)
	case StateFirewallOpened:
		if !claimed.RollbackArmed {
			return coordinator.armRollback(ctx, actor, plan, claimed, now)
		}
		return coordinator.activateShadow(ctx, actor, plan, claimed, now)
	case StateShadowActive:
		if !claimed.LocalValidated {
			return coordinator.probeLocal(ctx, actor, plan, claimed, now)
		}
		return coordinator.confirmExternal(ctx, actor, plan, claimed, now)
	case StateExternallyConfirmed:
		if !claimed.OldFirewallClosed {
			return coordinator.closeOldFirewall(ctx, actor, plan, claimed, now)
		}
		return coordinator.drainOld(ctx, actor, plan, claimed, now)
	case StateOldDrained:
		if !claimed.RollbackFinalized {
			return coordinator.finalizeRollback(ctx, actor, plan, claimed, now)
		}
		return coordinator.commit(ctx, actor, plan, claimed, now)
	default:
		return claimed, ErrConflict
	}
}

func (coordinator *Coordinator) Status(ctx context.Context, actor Actor, planID PlanID) (Status, error) {
	if actor.Validate() != nil || !validID(string(planID)) {
		return Status{}, ErrInvalid
	}
	plan, err := coordinator.Repository.Plan(ctx, planID)
	if err != nil {
		return Status{}, err
	}
	if actor.TenantID != plan.Scope.TenantID || coordinator.Authorization.Authorize(ctx, actor, plan.Scope, ActionPreview) != nil {
		return Status{}, ErrUnauthorized
	}
	execution, err := coordinator.Repository.Execution(ctx, planID)
	if err != nil {
		return Status{}, err
	}
	receipts, err := coordinator.Repository.Receipts(ctx, planID, MaximumStatusReceipts)
	if err != nil {
		return Status{}, err
	}
	redacted := make([]RedactedReceipt, 0, len(receipts))
	for _, receipt := range receipts {
		redacted = append(redacted, RedactedReceipt{Phase: receipt.Phase, Outcome: receipt.Outcome, FailureCode: receipt.FailureCode, ObservedAt: receipt.ObservedAt})
	}
	return Status{
		PlanID: plan.ID, State: execution.State, Revision: execution.Revision, Attempt: execution.Attempt,
		ObservedConfigurationGeneration: execution.ObservedConfigurationGeneration,
		ObservedFirewallGeneration: execution.ObservedFirewallGeneration,
		RollbackDeadline: execution.RollbackDeadline, Risks: append([]RiskReason(nil), plan.Risks...),
		Receipts: redacted, FailureCode: execution.FailureCode, UpdatedAt: execution.UpdatedAt,
	}, nil
}

func (coordinator *Coordinator) reservePorts(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	operation, err := coordinator.operation(plan, claimed, PhaseReservePorts)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseReservePorts); err != nil {
		return claimed, err
	}
	receipt, callErr := coordinator.Ports.Reserve(ctx, PortReservationRequest{Operation: operation, Current: plan.Current, Target: plan.Target})
	if receipt.Outcome == OutcomeSucceeded && !sameGenerations(receipt, claimed) { callErr = ErrStale }
	return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StatePreviewed, func(next *Execution) {
		next.PortsReserved = true
	}, now)
}

func (coordinator *Coordinator) stageConfiguration(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	operation, request, err := coordinator.listenerRequest(plan, claimed, PhaseStage)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseStage); err != nil {
		return claimed, err
	}
	receipt, callErr := coordinator.Listeners.Stage(ctx, request)
	if receipt.Outcome == OutcomeSucceeded && !sameGenerations(receipt, claimed) { callErr = ErrStale }
	return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateStaged, func(next *Execution) {
		next.ConfigurationStaged = true
	}, now)
}

func (coordinator *Coordinator) validateConfiguration(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	operation, request, err := coordinator.listenerRequest(plan, claimed, PhaseValidate)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseValidate); err != nil {
		return claimed, err
	}
	receipt, callErr := coordinator.Listeners.Validate(ctx, request)
	if receipt.Outcome == OutcomeSucceeded && !sameGenerations(receipt, claimed) { callErr = ErrStale }
	return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateValidated, func(next *Execution) {
		next.ConfigurationValidated = true
	}, now)
}

func (coordinator *Coordinator) openFirewall(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	operation, err := coordinator.operation(plan, claimed, PhaseOpenFirewall)
	if err != nil {
		return claimed, err
	}
	if len(plan.OpenFirewall) == 0 {
		receipt, receiptErr := internalReceipt(plan, claimed, operation, now, claimed.ObservedConfigurationGeneration, claimed.ObservedFirewallGeneration, operation.ExpectedDigest)
		if receiptErr != nil {
			return claimed, receiptErr
		}
		return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, nil, StateFirewallOpened, nil, now)
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseOpenFirewall); err != nil {
		return claimed, err
	}
	receipt, callErr := coordinator.Firewall.OpenExact(ctx, FirewallChangeRequest{Operation: operation, Tuples: append([]FirewallTuple(nil), plan.OpenFirewall...), ExpectedGeneration: claimed.ObservedFirewallGeneration, TargetGeneration: plan.OpenFirewallGeneration})
	if receipt.Outcome == OutcomeSucceeded && (receipt.ObservedConfigurationGeneration != claimed.ObservedConfigurationGeneration || receipt.ObservedFirewallGeneration != plan.OpenFirewallGeneration) {
		callErr = ErrStale
	}
	return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateFirewallOpened, func(next *Execution) {
		next.FirewallOpened = true
	}, now)
}

func (coordinator *Coordinator) armRollback(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	operation, err := coordinator.operation(plan, claimed, PhaseArmRollback)
	if err != nil {
		return claimed, err
	}
	if !plan.Rollback.Persistent || !plan.Rollback.Deadline.After(now) {
		return coordinator.beginRollback(ctx, actor, plan, claimed, "rollback_lease_unavailable", now)
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseArmRollback); err != nil {
		return claimed, err
	}
	result, callErr := coordinator.Rollback.Arm(ctx, RollbackLeaseRequest{Operation: operation, PlanDigest: plan.Digest, Current: plan.Current, Target: plan.Target, Deadline: plan.Rollback.Deadline, Persistent: true})
	if result.Receipt.Outcome == OutcomeSucceeded && !sameGenerations(result.Receipt, claimed) { callErr = ErrStale }
	if result.Receipt.Outcome == OutcomeSucceeded && !validID(result.Handle) {
		callErr = ErrInvalid
	}
	return coordinator.apply(ctx, actor, plan, claimed, operation, result.Receipt, callErr, StateFirewallOpened, func(next *Execution) {
		next.RollbackArmed, next.RollbackHandle = true, result.Handle
	}, now)
}

func (coordinator *Coordinator) activateShadow(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	if !claimed.RollbackArmed || !claimed.ConfigurationValidated {
		return coordinator.beginRollback(ctx, actor, plan, claimed, "activation_prerequisite_missing", now)
	}
	operation, request, err := coordinator.listenerRequest(plan, claimed, PhaseActivateShadow)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseActivateShadow); err != nil {
		return claimed, err
	}
	observation, callErr := coordinator.Listeners.ActivateShadow(ctx, request)
	receipt := observation.Receipt
	if receipt.Outcome == OutcomeSucceeded && (receipt.ObservedConfigurationGeneration != plan.AfterConfigurationGeneration || receipt.ObservedFirewallGeneration != claimed.ObservedFirewallGeneration || !observation.CurrentActive || !observation.TargetActive || !activeObservationDigest(receipt, observation.CurrentActive, observation.TargetActive)) {
		callErr = ErrStale
	}
	if receipt.Outcome == OutcomeAmbiguous && (!observation.CurrentActive || !observation.TargetActive || !activeObservationDigest(receipt, observation.CurrentActive, observation.TargetActive)) { callErr = ErrUncertain }
	return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateShadowActive, func(next *Execution) {
		next.ShadowActive = true
	}, now)
}

func (coordinator *Coordinator) probeLocal(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	operation, request, err := coordinator.listenerRequest(plan, claimed, PhaseProbeLocal)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseProbeLocal); err != nil {
		return claimed, err
	}
	observation, callErr := coordinator.Listeners.ProbeLocal(ctx, request)
	targetDigest, _ := plan.Target.Digest()
	observedDigest, digestErr := observation.ObservedListeners.Digest()
	localDigest, localDigestErr := digestValue("local-probe-observation", struct {
		Listeners ListenerSet `json:"listeners"`
		Origin string `json:"origin"`
		CertificateFingerprint string `json:"certificate_fingerprint"`
		ConfigurationGeneration uint64 `json:"configuration_generation"`
		AdministrativeObserverID string `json:"administrative_observer_id"`
		ObservedAt time.Time `json:"observed_at"`
	}{observation.ObservedListeners, observation.ObservedOrigin, observation.CertificateFingerprint, observation.ConfigurationGeneration, observation.AdministrativeObserverID, observation.Receipt.ObservedAt})
	if observation.Receipt.Outcome == OutcomeSucceeded && (digestErr != nil || localDigestErr != nil || localDigest != observation.Receipt.ObservedDigest || targetDigest != observedDigest || observation.ObservedOrigin != plan.TargetOrigin || observation.CertificateFingerprint != plan.TargetCertificate.Fingerprint || observation.ConfigurationGeneration != plan.AfterConfigurationGeneration || !sameGenerations(observation.Receipt, claimed) || !validID(observation.AdministrativeObserverID)) {
		callErr = ErrStale
	}
	evidence, evidenceErr := administrativeEvidence(plan.Target.SSH, observation.AdministrativeObserverID, observation.Receipt.ObservedAt, MaximumEvidenceAge)
	if evidenceErr != nil {
		callErr = evidenceErr
	}
	return coordinator.apply(ctx, actor, plan, claimed, operation, observation.Receipt, callErr, StateShadowActive, func(next *Execution) {
		next.LocalValidated = true
		next.ConfirmedAdministrative = &evidence
	}, now)
}

func (coordinator *Coordinator) confirmExternal(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	operation, err := coordinator.operation(plan, claimed, PhaseConfirmExternal)
	if err != nil {
		return claimed, err
	}
	if !plan.ExternalConfirmationRequired {
		receipt, receiptErr := internalReceipt(plan, claimed, operation, now, claimed.ObservedConfigurationGeneration, claimed.ObservedFirewallGeneration, operation.ExpectedDigest)
		if receiptErr != nil {
			return claimed, receiptErr
		}
		return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, nil, StateExternallyConfirmed, func(next *Execution) {
			next.ExternallyConfirmed = true
		}, now)
	}
	if plan.Challenge == nil || !plan.Challenge.ExpiresAt.After(now) {
		return coordinator.beginRollback(ctx, actor, plan, claimed, "external_challenge_expired", now)
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseConfirmExternal); err != nil {
		return claimed, err
	}
	observation, callErr := coordinator.Confirmation.Observe(ctx, operation, plan)
	if observation.Validate(plan, now) != nil {
		callErr = ErrStale
	}
	if observation.Receipt.Outcome == OutcomeSucceeded && !sameGenerations(observation.Receipt, claimed) { callErr = ErrStale }
	evidence, evidenceErr := administrativeEvidence(plan.Target.SSH, firstObserver(observation.ObserverIDs), observation.ObservedAt, plan.ConfirmationPolicy.MaximumAge)
	if evidenceErr != nil {
		callErr = evidenceErr
	}
	return coordinator.apply(ctx, actor, plan, claimed, operation, observation.Receipt, callErr, StateExternallyConfirmed, func(next *Execution) {
		next.ExternallyConfirmed = true
		next.ConfirmedAdministrative = &evidence
	}, now)
}

func (coordinator *Coordinator) closeOldFirewall(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	operation, err := coordinator.operation(plan, claimed, PhaseCloseOldFirewall)
	if err != nil {
		return claimed, err
	}
	if len(plan.CloseFirewall) == 0 {
		receipt, receiptErr := internalReceipt(plan, claimed, operation, now, claimed.ObservedConfigurationGeneration, claimed.ObservedFirewallGeneration, operation.ExpectedDigest)
		if receiptErr != nil {
			return claimed, receiptErr
		}
		return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, nil, StateExternallyConfirmed, func(next *Execution) { next.OldFirewallClosed = true }, now)
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseCloseOldFirewall); err != nil {
		return claimed, err
	}
	receipt, callErr := coordinator.Firewall.CloseExact(ctx, FirewallChangeRequest{Operation: operation, Tuples: append([]FirewallTuple(nil), plan.CloseFirewall...), ExpectedGeneration: claimed.ObservedFirewallGeneration, TargetGeneration: plan.AfterFirewallGeneration})
	if receipt.Outcome == OutcomeSucceeded && (receipt.ObservedConfigurationGeneration != claimed.ObservedConfigurationGeneration || receipt.ObservedFirewallGeneration != plan.AfterFirewallGeneration) {
		callErr = ErrStale
	}
	return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateExternallyConfirmed, func(next *Execution) { next.OldFirewallClosed = true }, now)
}

func (coordinator *Coordinator) drainOld(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	if !coordinator.mayDrain(plan, claimed, now) {
		return coordinator.beginRollback(ctx, actor, plan, claimed, "last_administrative_path_unconfirmed", now)
	}
	operation, request, err := coordinator.listenerRequest(plan, claimed, PhaseDrainOld)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseDrainOld); err != nil {
		return claimed, err
	}
	observation, callErr := coordinator.Listeners.DrainOld(ctx, request)
	if observation.Receipt.Outcome == OutcomeSucceeded && (observation.OldActive || !observation.TargetActive || !sameGenerations(observation.Receipt, claimed) || !activeObservationDigest(observation.Receipt, observation.OldActive, observation.TargetActive)) {
		callErr = ErrStale
	}
	if observation.Receipt.Outcome == OutcomeAmbiguous && (!observation.OldActive || !observation.TargetActive || !activeObservationDigest(observation.Receipt, observation.OldActive, observation.TargetActive)) {
		callErr = ErrUncertain
	}
	return coordinator.apply(ctx, actor, plan, claimed, operation, observation.Receipt, callErr, StateOldDrained, func(next *Execution) { next.OldDrained = true }, now)
}

func (coordinator *Coordinator) finalizeRollback(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	operation, err := coordinator.operation(plan, claimed, PhaseCommitRollback)
	if err != nil {
		return claimed, err
	}
	if !claimed.RollbackArmed || !validID(claimed.RollbackHandle) {
		return coordinator.beginRollback(ctx, actor, plan, claimed, "rollback_handle_missing", now)
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseCommitRollback); err != nil {
		return claimed, err
	}
	receipt, callErr := coordinator.Rollback.Finalize(ctx, RollbackLeaseRequest{Operation: operation, PlanDigest: plan.Digest, Current: plan.Current, Target: plan.Target, Deadline: plan.Rollback.Deadline, Persistent: true}, claimed.RollbackHandle)
	if receipt.Outcome == OutcomeSucceeded && !sameGenerations(receipt, claimed) { callErr = ErrStale }
	return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateOldDrained, func(next *Execution) {
		next.RollbackArmed, next.RollbackFinalized = false, true
	}, now)
}

func (coordinator *Coordinator) commit(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	if !coordinator.mayDrain(plan, claimed, now) || claimed.ConfirmedAdministrative == nil || claimed.ConfirmedAdministrative.Validate(plan.Target, now) != nil {
		return coordinator.beginRollback(ctx, actor, plan, claimed, "commit_observation_stale", now)
	}
	current := CurrentState{
		Scope: plan.Scope, Revision: plan.BeforeRevision + 1,
		ConfigurationGeneration: plan.AfterConfigurationGeneration,
		FirewallGeneration: plan.AfterFirewallGeneration, Listeners: plan.Target,
		PanelOrigin: plan.TargetOrigin, Certificate: plan.TargetCertificate,
		ConfirmedAdministrative: *claimed.ConfirmedAdministrative, Boot: claimed.Boot, ObservedAt: now,
	}
	digest, err := current.ExpectedDigest()
	if err != nil {
		return coordinator.beginRollback(ctx, actor, plan, claimed, "completion_digest_failed", now)
	}
	current.Digest = digest
	if current.Validate(now) != nil {
		return coordinator.beginRollback(ctx, actor, plan, claimed, "completion_observation_stale", now)
	}
	operation, err := coordinator.operation(plan, claimed, PhaseCommit)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseCommit); err != nil {
		return claimed, err
	}
	receipt, err := internalReceipt(plan, claimed, operation, now, plan.AfterConfigurationGeneration, plan.AfterFirewallGeneration, current.Digest)
	if err != nil {
		return claimed, err
	}
	next, err := coordinator.Repository.Commit(ctx, plan, claimed, current, receipt, now)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.afterOperation(ctx, actor, plan, next, receipt); err != nil {
		return next, err
	}
	return next, nil
}

func (coordinator *Coordinator) runRollback(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time) (Execution, error) {
	if claimed.OldDrained {
		operation, request, err := coordinator.listenerRequest(plan, claimed, PhaseRestoreOld)
		if err != nil { return claimed, err }
		if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseRestoreOld); err != nil { return claimed, err }
		observation, callErr := coordinator.Listeners.RestoreOld(ctx, request)
		if observation.Receipt.Outcome == OutcomeSucceeded && (observation.Receipt.ObservedConfigurationGeneration != claimed.ObservedConfigurationGeneration+1 || observation.Receipt.ObservedFirewallGeneration != claimed.ObservedFirewallGeneration || !observation.CurrentActive || !observation.TargetActive || !activeObservationDigest(observation.Receipt, observation.CurrentActive, observation.TargetActive)) { callErr = ErrStale }
		if observation.Receipt.Outcome == OutcomeAmbiguous && (!observation.CurrentActive || !observation.TargetActive || !activeObservationDigest(observation.Receipt, observation.CurrentActive, observation.TargetActive)) { callErr = ErrUncertain }
		return coordinator.apply(ctx, actor, plan, claimed, operation, observation.Receipt, callErr, StateRollingBack, func(next *Execution) { next.OldDrained = false }, now)
	}
	if claimed.OldFirewallClosed {
		return coordinator.rollbackFirewall(ctx, actor, plan, claimed, now, PhaseReopenOldFirewall, plan.CloseFirewall, true)
	}
	if claimed.ShadowActive {
		operation, request, err := coordinator.listenerRequest(plan, claimed, PhaseStopShadow)
		if err != nil { return claimed, err }
		if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseStopShadow); err != nil { return claimed, err }
		observation, callErr := coordinator.Listeners.StopShadow(ctx, request)
		if observation.Receipt.Outcome == OutcomeSucceeded && (!sameGenerations(observation.Receipt, claimed) || !observation.CurrentActive || observation.TargetActive || !activeObservationDigest(observation.Receipt, observation.CurrentActive, observation.TargetActive)) { callErr = ErrStale }
		if observation.Receipt.Outcome == OutcomeAmbiguous && (!observation.CurrentActive || !observation.TargetActive || !activeObservationDigest(observation.Receipt, observation.CurrentActive, observation.TargetActive)) { callErr = ErrUncertain }
		return coordinator.apply(ctx, actor, plan, claimed, operation, observation.Receipt, callErr, StateRollingBack, func(next *Execution) {
			next.ShadowActive, next.LocalValidated, next.ExternallyConfirmed = false, false, false
			next.ConfirmedAdministrative = nil
		}, now)
	}
	if claimed.FirewallOpened {
		return coordinator.rollbackFirewall(ctx, actor, plan, claimed, now, PhaseCloseNewFirewall, plan.OpenFirewall, false)
	}
	if claimed.RollbackArmed {
		operation, err := coordinator.operation(plan, claimed, PhaseFinalizeRollback)
		if err != nil { return claimed, err }
		if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseFinalizeRollback); err != nil { return claimed, err }
		receipt, callErr := coordinator.Rollback.Finalize(ctx, RollbackLeaseRequest{Operation: operation, PlanDigest: plan.Digest, Current: plan.Current, Target: plan.Target, Deadline: plan.Rollback.Deadline, Persistent: true}, claimed.RollbackHandle)
		if receipt.Outcome == OutcomeSucceeded && !sameGenerations(receipt, claimed) { callErr = ErrStale }
		return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateRollingBack, func(next *Execution) { next.RollbackArmed = false }, now)
	}
	if claimed.ConfigurationStaged {
		operation, request, err := coordinator.listenerRequest(plan, claimed, PhaseDiscardStage)
		if err != nil { return claimed, err }
		if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseDiscardStage); err != nil { return claimed, err }
		receipt, callErr := coordinator.Listeners.DiscardStage(ctx, request)
		if receipt.Outcome == OutcomeSucceeded && !sameGenerations(receipt, claimed) { callErr = ErrStale }
		return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateRollingBack, func(next *Execution) { next.ConfigurationStaged, next.ConfigurationValidated = false, false }, now)
	}
	if claimed.PortsReserved {
		operation, err := coordinator.operation(plan, claimed, PhaseReleasePorts)
		if err != nil { return claimed, err }
		if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseReleasePorts); err != nil { return claimed, err }
		receipt, callErr := coordinator.Ports.Release(ctx, PortReservationRequest{Operation: operation, Current: plan.Current, Target: plan.Target})
		if receipt.Outcome == OutcomeSucceeded && !sameGenerations(receipt, claimed) { callErr = ErrStale }
		return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateRollingBack, func(next *Execution) { next.PortsReserved = false }, now)
	}
	operation, err := coordinator.operation(plan, claimed, PhaseRollbackComplete)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, PhaseRollbackComplete); err != nil {
		return claimed, err
	}
	receipt, err := internalReceipt(plan, claimed, operation, now, claimed.ObservedConfigurationGeneration, claimed.ObservedFirewallGeneration, operation.ExpectedDigest)
	if err != nil {
		return claimed, err
	}
	next, err := coordinator.Repository.FinishRollback(ctx, plan, claimed, receipt, now)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.afterOperation(ctx, actor, plan, next, receipt); err != nil {
		return next, err
	}
	return next, nil
}

func (coordinator *Coordinator) rollbackFirewall(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, now time.Time, phase OperationPhase, tuples []FirewallTuple, reopen bool) (Execution, error) {
	operation, err := coordinator.operation(plan, claimed, phase)
	if err != nil { return claimed, err }
	if len(tuples) == 0 {
		receipt, receiptErr := internalReceipt(plan, claimed, operation, now, claimed.ObservedConfigurationGeneration, claimed.ObservedFirewallGeneration, operation.ExpectedDigest)
		if receiptErr != nil { return claimed, receiptErr }
		return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, nil, StateRollingBack, func(next *Execution) {
			if reopen { next.OldFirewallClosed = false } else { next.FirewallOpened = false }
		}, now)
	}
	if err := coordinator.beforeOperation(ctx, actor, plan, claimed, phase); err != nil { return claimed, err }
	request := FirewallChangeRequest{Operation: operation, Tuples: append([]FirewallTuple(nil), tuples...), ExpectedGeneration: claimed.ObservedFirewallGeneration, TargetGeneration: claimed.ObservedFirewallGeneration + 1}
	var receipt OperationReceipt
	var callErr error
	if reopen {
		receipt, callErr = coordinator.Firewall.OpenExact(ctx, request)
	} else {
		receipt, callErr = coordinator.Firewall.CloseExact(ctx, request)
	}
	if receipt.Outcome == OutcomeSucceeded && (receipt.ObservedConfigurationGeneration != claimed.ObservedConfigurationGeneration || receipt.ObservedFirewallGeneration != request.TargetGeneration) { callErr = ErrStale }
	return coordinator.apply(ctx, actor, plan, claimed, operation, receipt, callErr, StateRollingBack, func(next *Execution) {
		if reopen { next.OldFirewallClosed = false } else { next.FirewallOpened = false }
	}, now)
}

func (coordinator *Coordinator) apply(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, operation OperationContext, receipt OperationReceipt, callErr error, successState ExecutionState, mutate func(*Execution), now time.Time) (Execution, error) {
	valid := coordinator.validReceipt(plan, claimed, operation, receipt) == nil
	if !valid {
		return coordinator.unverifiable(ctx, actor, plan, claimed, "unverifiable_operation_result", now)
	}
	next := claimed
	next.ObservedConfigurationGeneration = receipt.ObservedConfigurationGeneration
	next.ObservedFirewallGeneration = receipt.ObservedFirewallGeneration
	resultErr := callErr
	switch receipt.Outcome {
	case OutcomeSucceeded:
		if callErr != nil {
			next.State, next.FailureCode, resultErr = StateUncertain, string(receipt.Phase)+"_unverifiable", ErrUncertain
		} else {
			next.State = successState
			if mutate != nil { mutate(&next) }
		}
	case OutcomeNotApplied:
		next.FailureCode = string(receipt.Phase) + "_not_applied"
		if claimed.State == StateRollingBack {
			next.State, resultErr = StateUncertain, ErrUncertain
		} else {
			next.State, resultErr = StateRollingBack, ErrIncomplete
		}
	case OutcomeAmbiguous:
		next.State, next.FailureCode, resultErr = StateUncertain, string(receipt.Phase)+"_ambiguous", ErrUncertain
	default:
		return coordinator.unverifiable(ctx, actor, plan, claimed, "unverifiable_operation_result", now)
	}
	saved, err := coordinator.Repository.SaveProgress(ctx, plan, claimed, next, receipt, receipt.ObservedAt)
	if err != nil {
		return claimed, err
	}
	if err := coordinator.afterOperation(ctx, actor, plan, saved, receipt); err != nil {
		return saved, err
	}
	if resultErr != nil {
		return saved, resultErr
	}
	return saved, nil
}

func (coordinator *Coordinator) beginRollback(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, code string, now time.Time) (Execution, error) {
	if err := coordinator.audit(ctx, actor, plan, ActionRollback, "", StateRollingBack, claimed.Attempt, claimed.FenceToken, code); err != nil {
		return claimed, err
	}
	next, err := coordinator.Repository.ChangeState(ctx, plan, claimed, StateRollingBack, code, now)
	if err != nil { return claimed, err }
	return next, ErrIncomplete
}

func (coordinator *Coordinator) unverifiable(ctx context.Context, actor Actor, plan ChangePlan, claimed Execution, code string, now time.Time) (Execution, error) {
	if len(code) > 96 { code = "unverifiable_operation_result" }
	action := ActionExecute
	if claimed.State == StateRollingBack { action = ActionRollback }
	if err := coordinator.audit(ctx, actor, plan, action, "", StateUncertain, claimed.Attempt, claimed.FenceToken, code); err != nil {
		return claimed, err
	}
	next, err := coordinator.Repository.ChangeState(ctx, plan, claimed, StateUncertain, code, now)
	if err != nil { return claimed, err }
	return next, ErrUncertain
}

func (coordinator *Coordinator) operation(plan ChangePlan, execution Execution, phase OperationPhase) (OperationContext, error) {
	idempotency := string(plan.ID) + ":" + string(phase)
	expected, err := digestValue("operation-expectation", struct {
		PlanDigest string         `json:"plan_digest"`
		Phase      OperationPhase `json:"phase"`
		ConfigurationGeneration uint64 `json:"configuration_generation"`
		FirewallGeneration uint64 `json:"firewall_generation"`
	}{plan.Digest, phase, execution.ObservedConfigurationGeneration, execution.ObservedFirewallGeneration})
	if err != nil || !validID(idempotency) || execution.FenceToken == "" || !execution.LeaseUntil.After(execution.UpdatedAt) {
		return OperationContext{}, ErrInvalid
	}
	return OperationContext{PlanID: plan.ID, Scope: plan.Scope, Attempt: execution.Attempt, FenceToken: execution.FenceToken, IdempotencyKey: idempotency, Boot: execution.Boot, Deadline: execution.LeaseUntil, ExpectedDigest: expected}, nil
}

func (coordinator *Coordinator) listenerRequest(plan ChangePlan, execution Execution, phase OperationPhase) (OperationContext, ListenerConfigurationRequest, error) {
	operation, err := coordinator.operation(plan, execution, phase)
	if err != nil { return OperationContext{}, ListenerConfigurationRequest{}, err }
	targetGeneration := plan.AfterConfigurationGeneration
	if phase == PhaseRestoreOld {
		targetGeneration = execution.ObservedConfigurationGeneration + 1
	} else if phase == PhaseStopShadow || phase == PhaseDiscardStage {
		targetGeneration = execution.ObservedConfigurationGeneration
	}
	return operation, ListenerConfigurationRequest{
		Operation: operation, Current: plan.Current, Target: plan.Target,
		CurrentOrigin: plan.CurrentOrigin, TargetOrigin: plan.TargetOrigin,
		CurrentCertificate: plan.CurrentCertificate, TargetCertificate: plan.TargetCertificate,
		ExpectedConfigurationGeneration: execution.ObservedConfigurationGeneration,
		TargetConfigurationGeneration: targetGeneration,
	}, nil
}

func (coordinator *Coordinator) validReceipt(plan ChangePlan, claimed Execution, operation OperationContext, receipt OperationReceipt) error {
	if receipt.Validate(plan) != nil || receipt.Phase != OperationPhase(operation.IdempotencyKey[len(string(plan.ID))+1:]) || receipt.IdempotencyKey != operation.IdempotencyKey || receipt.FenceToken != operation.FenceToken || receipt.Attempt != operation.Attempt || receipt.Boot.Digest != operation.Boot.Digest || receipt.ExpectedConfigurationGeneration != claimed.ObservedConfigurationGeneration || receipt.ExpectedFirewallGeneration != claimed.ObservedFirewallGeneration || receipt.ObservedConfigurationGeneration < claimed.ObservedConfigurationGeneration || receipt.ObservedFirewallGeneration < claimed.ObservedFirewallGeneration || receipt.ExpectedDigest != operation.ExpectedDigest || receipt.ObservedAt.Before(claimed.UpdatedAt) || receipt.ObservedAt.After(operation.Deadline) {
		return ErrStale
	}
	return nil
}

func internalReceipt(plan ChangePlan, execution Execution, operation OperationContext, now time.Time, configurationGeneration, firewallGeneration uint64, observedDigest string) (OperationReceipt, error) {
	receipt := OperationReceipt{
		PlanID: plan.ID, Scope: plan.Scope,
		Phase: OperationPhase(operation.IdempotencyKey[len(string(plan.ID))+1:]), Outcome: OutcomeSucceeded,
		IdempotencyKey: operation.IdempotencyKey, Attempt: execution.Attempt, FenceToken: execution.FenceToken,
		Boot: execution.Boot, ExpectedConfigurationGeneration: execution.ObservedConfigurationGeneration,
		ObservedConfigurationGeneration: configurationGeneration,
		ExpectedFirewallGeneration: execution.ObservedFirewallGeneration,
		ObservedFirewallGeneration: firewallGeneration, ExpectedDigest: operation.ExpectedDigest,
		ObservedDigest: observedDigest, ObservedAt: now,
	}
	id, err := digestValue("internal-receipt-id", receipt)
	if err != nil { return OperationReceipt{}, err }
	receipt.ID = "receipt-" + id[:40]
	digest, err := receipt.ExpectedDigestValue()
	if err != nil { return OperationReceipt{}, err }
	receipt.Digest = digest
	if receipt.Validate(plan) != nil { return OperationReceipt{}, ErrInvalid }
	return receipt, nil
}

func administrativeEvidence(listeners []Listener, observer string, observedAt time.Time, validity time.Duration) (AdministrativePathEvidence, error) {
	if validity <= 0 || validity > MaximumEvidenceAge { return AdministrativePathEvidence{}, ErrInvalid }
	evidence := AdministrativePathEvidence{Listeners: append([]Listener(nil), listeners...), ObserverID: observer, ObservedAt: observedAt, ValidUntil: observedAt.Add(validity)}
	digest, err := evidence.ExpectedDigest()
	if err != nil { return AdministrativePathEvidence{}, err }
	evidence.Digest = digest
	if evidence.Validate(ListenerSet{SSH: listeners}, observedAt) != nil {
		return AdministrativePathEvidence{}, ErrStale
	}
	return evidence, nil
}

func (coordinator *Coordinator) mayDrain(plan ChangePlan, execution Execution, now time.Time) bool {
	if !execution.LocalValidated || !execution.ExternallyConfirmed || execution.ConfirmedAdministrative == nil || execution.ConfirmedAdministrative.Validate(plan.Target, now) != nil || len(plan.Target.SSH) == 0 {
		return false
	}
	if sshChanged(plan.Current, plan.Target) && !plan.ExternalConfirmationRequired {
		return false
	}
	return true
}

func firstObserver(values []string) string {
	if len(values) == 0 { return "" }
	return values[0]
}

func (coordinator *Coordinator) beforeOperation(ctx context.Context, actor Actor, plan ChangePlan, execution Execution, phase OperationPhase) error {
	action := ActionExecute
	if execution.State == StateRollingBack { action = ActionRollback }
	return coordinator.audit(ctx, actor, plan, action, phase, execution.State, execution.Attempt, execution.FenceToken, "operation_started")
}

func (coordinator *Coordinator) afterOperation(ctx context.Context, actor Actor, plan ChangePlan, execution Execution, receipt OperationReceipt) error {
	action := ActionExecute
	if execution.State == StateRollingBack || execution.State == StateRolledBack || rollbackPhase(receipt.Phase) { action = ActionRollback }
	return coordinator.audit(ctx, actor, plan, action, receipt.Phase, execution.State, execution.Attempt, receipt.FenceToken, string(receipt.Outcome))
}

func (coordinator *Coordinator) audit(ctx context.Context, actor Actor, plan ChangePlan, action AuthorizationAction, phase OperationPhase, state ExecutionState, attempt uint32, fence, reason string) error {
	now, err := coordinator.now()
	if err != nil { return err }
	id, err := randomID("audit-")
	if err != nil { return err }
	event := AuditEvent{ID: id, Scope: plan.Scope, PlanID: plan.ID, Actor: actor.PrincipalID, Action: action, Phase: phase, State: state, Attempt: attempt, FenceToken: fence, ReasonCode: reason, At: now}
	if reason == string(OutcomeSucceeded) || reason == string(OutcomeNotApplied) || reason == string(OutcomeAmbiguous) {
		event.Outcome = OperationOutcome(reason)
	}
	digest, err := digestValue("audit-event", event)
	if err != nil { return err }
	event.Digest = digest
	if err := coordinator.Audit.Append(ctx, event); err != nil {
		return errors.Join(ErrAuditUnavailable, err)
	}
	return nil
}

func (coordinator *Coordinator) now() (time.Time, error) {
	if coordinator == nil || coordinator.Now == nil { return time.Time{}, ErrInvalid }
	now := coordinator.Now()
	if now.IsZero() { return time.Time{}, ErrInvalid }
	return now.UTC(), nil
}

func rollbackPhase(phase OperationPhase) bool {
	switch phase {
	case PhaseRestoreOld, PhaseStopShadow, PhaseReopenOldFirewall, PhaseCloseNewFirewall, PhaseDiscardStage, PhaseReleasePorts, PhaseRollbackComplete:
		return true
	default:
		return false
	}
}

func activeObservationDigest(receipt OperationReceipt, currentActive, targetActive bool) bool {
	expected, err := digestValue("listener-activation-observation", struct {
		CurrentActive bool `json:"current_active"`
		TargetActive bool `json:"target_active"`
		ObservedAt time.Time `json:"observed_at"`
	}{currentActive, targetActive, receipt.ObservedAt})
	return err == nil && expected == receipt.ObservedDigest
}

func sameGenerations(receipt OperationReceipt, execution Execution) bool {
	return receipt.ObservedConfigurationGeneration == execution.ObservedConfigurationGeneration && receipt.ObservedFirewallGeneration == execution.ObservedFirewallGeneration
}
