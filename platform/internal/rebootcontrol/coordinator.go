package rebootcontrol

import (
	"context"
	"encoding/json"
	"time"
)

type Dependencies struct {
	Repository       *Repository
	Maintenance      MaintenanceGate
	BootIdentity     BootIdentityProbe
	Authorization    AuthorizationVerifier
	Listeners        ListenerDrainer
	Operations       ResumableOperationCheckpointer
	SQLite           SQLiteSafety
	Markers          RecoveryMarkerStore
	Dispatcher       RebootDispatcher
	Reconciler       Reconciler
}

type Coordinator struct {
	repository    *Repository
	maintenance   MaintenanceGate
	bootIdentity  BootIdentityProbe
	authorization AuthorizationVerifier
	listeners     ListenerDrainer
	operations    ResumableOperationCheckpointer
	sqlite        SQLiteSafety
	markers       RecoveryMarkerStore
	dispatcher    RebootDispatcher
	reconciler    Reconciler
}

func NewCoordinator(dependencies Dependencies) (*Coordinator, error) {
	if dependencies.Repository == nil || dependencies.Repository.db == nil || dependencies.Maintenance == nil || dependencies.BootIdentity == nil || dependencies.Authorization == nil || dependencies.Listeners == nil || dependencies.Operations == nil || dependencies.SQLite == nil || dependencies.Markers == nil || dependencies.Dispatcher == nil || dependencies.Reconciler == nil {
		return nil, ErrInvalid
	}
	return &Coordinator{repository: dependencies.Repository, maintenance: dependencies.Maintenance,
		bootIdentity: dependencies.BootIdentity, authorization: dependencies.Authorization,
		listeners: dependencies.Listeners, operations: dependencies.Operations, sqlite: dependencies.SQLite,
		markers: dependencies.Markers, dispatcher: dependencies.Dispatcher, reconciler: dependencies.Reconciler}, nil
}

type StepCommand struct {
	PlanID            string    `json:"plan_id"`
	ExpectedGeneration uint64   `json:"expected_generation"`
	Fence             uint64    `json:"fence"`
	ControllerID      string    `json:"controller_id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	At                time.Time `json:"at"`
}

func (command StepCommand) Validate() error {
	if !identifierPattern.MatchString(command.PlanID) || command.ExpectedGeneration == 0 || command.ExpectedGeneration >= maxGeneration || command.Fence == 0 || command.Fence > maxGeneration || !identifierPattern.MatchString(command.ControllerID) || !identifierPattern.MatchString(command.IdempotencyKey) || !validTimestamp(command.At) {
		return ErrInvalid
	}
	return nil
}

func (coordinator *Coordinator) Request(ctx context.Context, plan Plan, controllerID, idempotencyKey string) (State, Receipt, error) {
	return coordinator.repository.CreatePlan(ctx, plan, controllerID, idempotencyKey)
}

func (coordinator *Coordinator) Admit(ctx context.Context, command StepCommand) (State, Receipt, error) {
	plan, state, err := coordinator.controlled(ctx, command, PhaseRequested)
	if err != nil {
		return State{}, Receipt{}, err
	}
	actual, err := coordinator.bootIdentity.CurrentBootIdentity(ctx, plan.NodeID)
	if err != nil {
		return State{}, Receipt{}, err
	}
	if actual.Validate() != nil || !sameSourceBoot(actual, plan.SourceBoot) {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeStaleBootIdentity,
			digestStrings(plan.SourceBoot.EvidenceDigest, actual.EvidenceDigest), []RecoveryStep{RecoveryVerifyBootIdentity}, ErrStaleBoot)
	}
	probe, err := coordinator.maintenance.ProbeRebootOccurrence(ctx, plan.Maintenance, plan.NodeID, command.At)
	if err != nil {
		return State{}, Receipt{}, err
	}
	if probe.Validate(plan.Maintenance) != nil || !probe.Admissible || !command.At.Before(plan.ExpiresAt) {
		return State{}, Receipt{}, ErrConflict
	}
	if err := coordinator.authorization.VerifyRebootAuthorization(ctx, plan.Authorization, plan); err != nil {
		return State{}, Receipt{}, ErrUnauthorized
	}
	if err := coordinator.authorization.VerifyRebootApproval(ctx, plan.Approval, plan); err != nil {
		return State{}, Receipt{}, ErrUnauthorized
	}
	evidence := digestStrings(actual.EvidenceDigest, probe.EvidenceDigest, plan.Authorization.Digest, plan.Approval.Digest)
	return coordinator.advance(ctx, command, state, PhaseAdmitted, evidence, "", OutcomeNone, nil)
}

func (coordinator *Coordinator) Drain(ctx context.Context, command StepCommand) (State, Receipt, error) {
	plan, state, err := coordinator.controlled(ctx, command, PhaseAdmitted)
	if err != nil {
		return State{}, Receipt{}, err
	}
	if !command.At.Before(plan.ExpiresAt) {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeMaintenanceClosed,
			plan.Maintenance.OccurrenceDigest, []RecoveryStep{RecoveryVerifyBootIdentity}, ErrConflict)
	}
	actual, err := coordinator.sourceBoot(ctx, plan)
	if err != nil {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeStaleBootIdentity,
			plan.SourceBoot.EvidenceDigest, []RecoveryStep{RecoveryVerifyBootIdentity}, err)
	}
	deadline := earlier(command.At.Add(plan.Drain.Timeout), plan.ExpiresAt)
	operation := DrainOperation{ID: deterministicOperationID("drain", plan.ID, state.Fence), PlanID: plan.ID,
		PlanDigest: plan.Digest, NodeID: plan.NodeID, Fence: state.Fence, Policy: plan.Drain, Deadline: deadline}
	operation.OperationDigest, err = typedDigest(operation)
	if err != nil {
		return State{}, Receipt{}, err
	}
	result, callErr := coordinator.listeners.DrainListeners(ctx, operation)
	if callErr != nil {
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeDrainIncomplete,
			operation.OperationDigest, []RecoveryStep{RecoveryReleaseDrain, RecoveryVerifyBootIdentity}, callErr)
	}
	if result.OperationID != operation.ID || result.Fence != state.Fence || !validDigest(result.EvidenceDigest) {
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeDrainIncomplete,
			operation.OperationDigest, []RecoveryStep{RecoveryReleaseDrain, RecoveryVerifyBootIdentity}, ErrIntegrity)
	}
	if !result.Complete || result.RemainingWork != 0 {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeDrainIncomplete,
			result.EvidenceDigest, []RecoveryStep{RecoveryReleaseDrain}, ErrConflict)
	}
	evidence := digestStrings(actual.EvidenceDigest, result.EvidenceDigest)
	return coordinator.advance(ctx, command, state, PhaseDraining, evidence, "", OutcomeNone, nil)
}

func (coordinator *Coordinator) Checkpoint(ctx context.Context, command StepCommand) (State, Receipt, error) {
	plan, state, err := coordinator.controlled(ctx, command, PhaseDraining)
	if err != nil {
		return State{}, Receipt{}, err
	}
	if !command.At.Before(plan.ExpiresAt) {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeMaintenanceClosed,
			plan.Maintenance.OccurrenceDigest, recoverySteps(plan, RecoveryReleaseDrain, RecoveryResumeOperations), ErrConflict)
	}
	actual, err := coordinator.sourceBoot(ctx, plan)
	if err != nil {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeStaleBootIdentity,
			plan.SourceBoot.EvidenceDigest, []RecoveryStep{RecoveryReleaseDrain, RecoveryVerifyBootIdentity}, err)
	}
	deadline := earlier(command.At.Add(plan.Checkpoint.Timeout), plan.ExpiresAt)
	operation := OperationCheckpoint{ID: deterministicOperationID("operations_checkpoint", plan.ID, state.Fence),
		PlanID: plan.ID, PlanDigest: plan.Digest, NodeID: plan.NodeID, Fence: state.Fence,
		Mode: plan.Checkpoint.OperationMode, MaximumOperations: plan.Checkpoint.MaximumOperations, Deadline: deadline}
	operation.OperationDigest, err = typedDigest(operation)
	if err != nil {
		return State{}, Receipt{}, err
	}
	operationResult, callErr := coordinator.operations.CheckpointOrRecordResumable(ctx, operation)
	if callErr != nil {
		return coordinator.checkpointFailure(ctx, command, state, operation.OperationDigest, callErr)
	}
	if operationResult.OperationID != operation.ID || operationResult.Fence != state.Fence || !validDigest(operationResult.EvidenceDigest) || uint64(operationResult.Checkpointed)+uint64(operationResult.ResumableRecorded)+uint64(operationResult.NonResumable) > uint64(plan.Checkpoint.MaximumOperations) {
		return coordinator.checkpointFailure(ctx, command, state, operation.OperationDigest, ErrIntegrity)
	}
	if !operationResult.Complete || operationResult.NonResumable != 0 {
		return coordinator.checkpointFailure(ctx, command, state, operationResult.EvidenceDigest, ErrConflict)
	}
	evidence := []string{actual.EvidenceDigest, operationResult.EvidenceDigest}
	for _, databaseID := range plan.Checkpoint.SQLiteDatabases {
		checkpoint, err := coordinator.sqliteOperation(ctx, plan, state, databaseID, deadline, false)
		if err != nil {
			return coordinator.checkpointFailure(ctx, command, state, digestStrings(evidence...), err)
		}
		evidence = append(evidence, checkpoint.EvidenceDigest, checkpoint.ArtifactDigest)
		backup, err := coordinator.sqliteOperation(ctx, plan, state, databaseID, deadline, true)
		if err != nil {
			return coordinator.checkpointFailure(ctx, command, state, digestStrings(evidence...), err)
		}
		evidence = append(evidence, backup.EvidenceDigest, backup.ArtifactDigest)
	}
	return coordinator.advance(ctx, command, state, PhaseCheckpointed, digestStrings(evidence...), "", OutcomeNone, nil)
}

func (coordinator *Coordinator) Arm(ctx context.Context, command StepCommand) (State, Receipt, error) {
	plan, state, err := coordinator.controlled(ctx, command, PhaseCheckpointed)
	if err != nil {
		return State{}, Receipt{}, err
	}
	actual, err := coordinator.sourceBoot(ctx, plan)
	if err != nil {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeStaleBootIdentity,
			plan.SourceBoot.EvidenceDigest, recoverySteps(plan, RecoveryReleaseDrain, RecoveryResumeOperations, RecoveryVerifyBootIdentity), err)
	}
	probe, err := coordinator.maintenance.ProbeRebootOccurrence(ctx, plan.Maintenance, plan.NodeID, command.At)
	if err != nil {
		return State{}, Receipt{}, err
	}
	if probe.Validate(plan.Maintenance) != nil || !probe.Active || !command.At.Before(plan.ExpiresAt) {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeMaintenanceClosed,
			evidenceOr(probe.EvidenceDigest, plan.Maintenance.OccurrenceDigest), recoverySteps(plan, RecoveryReleaseDrain, RecoveryResumeOperations), ErrConflict)
	}
	marker, err := buildRecoveryMarker(plan, state, state.CheckpointReceiptDigest, command.At)
	if err != nil {
		return State{}, Receipt{}, err
	}
	arm, callErr := coordinator.markers.AtomicArm(ctx, marker)
	if callErr != nil || arm.Partial || !arm.Committed || arm.ExactDigest != marker.Digest || !validDigest(arm.EvidenceDigest) {
		evidence := marker.Digest
		if validDigest(arm.EvidenceDigest) {
			evidence = arm.EvidenceDigest
		}
		failure := callErr
		if failure == nil {
			failure = ErrPartialArm
		}
		return coordinator.terminalWithMarker(ctx, command, state, PhaseUncertain, OutcomeMarkerPartial,
			evidence, marker.Digest, recoverySteps(plan, RecoveryInspectMarker, RecoveryReleaseDrain, RecoveryResumeOperations), failure)
	}
	evidence := digestStrings(actual.EvidenceDigest, probe.EvidenceDigest, arm.EvidenceDigest)
	return coordinator.advance(ctx, command, state, PhaseArmed, evidence, marker.Digest, OutcomeNone, nil)
}

func (coordinator *Coordinator) Dispatch(ctx context.Context, command StepCommand) (State, Receipt, error) {
	plan, state, err := coordinator.controlled(ctx, command, PhaseArmed)
	if err != nil {
		return State{}, Receipt{}, err
	}
	actual, err := coordinator.sourceBoot(ctx, plan)
	if err != nil {
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeStaleBootIdentity,
			state.MarkerDigest, recoverySteps(plan, RecoveryInspectMarker, RecoveryVerifyBootIdentity), err)
	}
	maintenance, err := coordinator.maintenance.ProbeRebootOccurrence(ctx, plan.Maintenance, plan.NodeID, command.At)
	if err != nil {
		return State{}, Receipt{}, err
	}
	if maintenance.Validate(plan.Maintenance) != nil || !maintenance.Active || !command.At.Before(plan.ExpiresAt) {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeMaintenanceClosed,
			evidenceOr(maintenance.EvidenceDigest, plan.Maintenance.OccurrenceDigest), recoverySteps(plan, RecoveryInspectMarker, RecoveryReleaseDrain, RecoveryResumeOperations), ErrConflict)
	}
	marker, err := coordinator.markers.Probe(ctx, plan.NodeID)
	if err != nil || !marker.Present || marker.Partial || marker.ExactDigest != state.MarkerDigest || !validDigest(marker.EvidenceDigest) {
		failure := err
		if failure == nil {
			failure = ErrPartialArm
		}
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeMarkerPartial,
			state.MarkerDigest, recoverySteps(plan, RecoveryInspectMarker, RecoveryVerifyBootIdentity), failure)
	}
	operation := RebootOperation{ID: deterministicOperationID("reboot", plan.ID, state.Fence), PlanID: plan.ID,
		PlanDigest: plan.Digest, NodeID: plan.NodeID, Fence: state.Fence, MarkerDigest: state.MarkerDigest,
		SourceBootID: plan.SourceBoot.BootID, DispatchBy: earlier(plan.ExpiresAt, plan.Maintenance.EndsAt)}
	operation.OperationDigest, err = typedDigest(operation)
	if err != nil {
		return State{}, Receipt{}, err
	}
	result, callErr := coordinator.dispatcher.DispatchReboot(ctx, operation)
	if callErr != nil || result.OperationID != operation.ID || result.Fence != state.Fence || !result.Accepted || !validDigest(result.EvidenceDigest) {
		failure := callErr
		if failure == nil {
			failure = ErrIntegrity
		}
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeDispatchUnconfirmed,
			operation.OperationDigest, recoverySteps(plan, RecoveryInspectMarker, RecoveryRetryDispatch, RecoveryVerifyBootIdentity), failure)
	}
	evidence := digestStrings(actual.EvidenceDigest, maintenance.EvidenceDigest, marker.EvidenceDigest, result.EvidenceDigest)
	return coordinator.advance(ctx, command, state, PhaseRebootDispatched, evidence, "", OutcomeNone, nil)
}

func (coordinator *Coordinator) BeginReconcile(ctx context.Context, command StepCommand) (State, Receipt, error) {
	plan, state, err := coordinator.controlled(ctx, command, PhaseRebootDispatched)
	if err != nil {
		return State{}, Receipt{}, err
	}
	marker, markerErr := coordinator.markers.Probe(ctx, plan.NodeID)
	if markerErr != nil || !marker.Present || marker.Partial || marker.ExactDigest != state.MarkerDigest || !validDigest(marker.EvidenceDigest) {
		failure := markerErr
		if failure == nil {
			failure = ErrPartialArm
		}
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeMarkerPartial,
			state.MarkerDigest, recoverySteps(plan, RecoveryInspectMarker, RecoveryVerifyBootIdentity), failure)
	}
	actual, err := coordinator.bootIdentity.CurrentBootIdentity(ctx, plan.NodeID)
	if err != nil || actual.Validate() != nil {
		if err == nil {
			err = ErrIntegrity
		}
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeStaleBootIdentity,
			marker.EvidenceDigest, recoverySteps(plan, RecoveryVerifyBootIdentity, RecoveryInspectMarker), err)
	}
	if actual.BootID == plan.SourceBoot.BootID {
		if command.At.Before(plan.ExpectedBoot.ReturnDeadline) {
			return State{}, Receipt{}, ErrStaleBoot
		}
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeBootNotChanged,
			actual.EvidenceDigest, recoverySteps(plan, RecoveryVerifyBootIdentity, RecoveryRetryDispatch, RecoveryInspectMarker), ErrStaleBoot)
	}
	if !matchesExpectedBoot(actual, plan.ExpectedBoot) {
		return coordinator.terminal(ctx, command, state, PhaseFailed, OutcomeUnexpectedKernel,
			actual.EvidenceDigest, recoverySteps(plan, RecoveryVerifyBootIdentity, RecoveryInspectMarker, RecoveryReconcileSubsystems), ErrIntegrity)
	}
	evidence := digestStrings(marker.EvidenceDigest, actual.EvidenceDigest)
	return coordinator.advance(ctx, command, state, PhaseReconciling, evidence, "", OutcomeNone, nil)
}

func (coordinator *Coordinator) CompleteReconcile(ctx context.Context, command StepCommand) (State, Receipt, error) {
	plan, state, err := coordinator.controlled(ctx, command, PhaseReconciling)
	if err != nil {
		return State{}, Receipt{}, err
	}
	actual, err := coordinator.bootIdentity.CurrentBootIdentity(ctx, plan.NodeID)
	if err != nil || actual.Validate() != nil || !matchesExpectedBoot(actual, plan.ExpectedBoot) || actual.BootID == plan.SourceBoot.BootID {
		if err == nil {
			err = ErrStaleBoot
		}
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeStaleBootIdentity,
			state.MarkerDigest, recoverySteps(plan, RecoveryVerifyBootIdentity, RecoveryInspectMarker, RecoveryReconcileSubsystems), err)
	}
	marker, err := coordinator.markers.Probe(ctx, plan.NodeID)
	if err != nil || !marker.Present || marker.Partial || marker.ExactDigest != state.MarkerDigest || !validDigest(marker.EvidenceDigest) {
		if err == nil {
			err = ErrPartialArm
		}
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeMarkerPartial,
			state.MarkerDigest, recoverySteps(plan, RecoveryInspectMarker, RecoveryReconcileSubsystems), err)
	}
	operation := ReconcileOperation{ID: deterministicOperationID("reconcile", plan.ID, state.Fence), PlanID: plan.ID,
		PlanDigest: plan.Digest, NodeID: plan.NodeID, Fence: state.Fence, ActualBootID: actual.BootID,
		KernelRelease: actual.KernelRelease, KernelDigest: actual.KernelDigest, BootSlot: actual.BootSlot,
		BootEvidenceDigest: actual.EvidenceDigest}
	operation.OperationDigest, err = typedDigest(operation)
	if err != nil {
		return State{}, Receipt{}, err
	}
	result, callErr := coordinator.reconciler.ReconcileAfterBoot(ctx, operation)
	if callErr != nil || result.OperationID != operation.ID || result.Fence != state.Fence || !validReconcileResult(result) || !result.Complete() {
		failure := callErr
		if failure == nil {
			failure = ErrIntegrity
		}
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeReconciliationFailed,
			operation.OperationDigest, recoverySteps(plan, RecoveryInspectMarker, RecoveryReconcileSubsystems), failure)
	}
	clear, callErr := coordinator.markers.ClearExact(ctx, plan.NodeID, state.MarkerDigest)
	if callErr != nil || !clear.Cleared || clear.ExactDigest != state.MarkerDigest || !validDigest(clear.EvidenceDigest) {
		failure := callErr
		if failure == nil {
			failure = ErrIntegrity
		}
		return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeMarkerClearFailed,
			result.EvidenceDigest, recoverySteps(plan, RecoveryInspectMarker, RecoveryReconcileSubsystems), failure)
	}
	evidence := digestStrings(actual.EvidenceDigest, marker.EvidenceDigest, result.EvidenceDigest, clear.EvidenceDigest)
	return coordinator.advance(ctx, command, state, PhaseSucceeded, evidence, "", OutcomeCompleted, nil)
}

func (coordinator *Coordinator) controlled(ctx context.Context, command StepCommand, phase Phase) (Plan, State, error) {
	if err := command.Validate(); err != nil {
		return Plan{}, State{}, err
	}
	plan, err := coordinator.repository.LoadPlan(ctx, command.PlanID)
	if err != nil {
		return Plan{}, State{}, err
	}
	state, err := coordinator.repository.LoadState(ctx, command.PlanID)
	if err != nil {
		return Plan{}, State{}, err
	}
	if state.NodeID != plan.NodeID {
		return Plan{}, State{}, ErrIntegrity
	}
	if state.Phase != phase || state.Generation != command.ExpectedGeneration || state.Fence != command.Fence || state.ControllerID != command.ControllerID || command.At.Before(state.UpdatedAt) {
		return Plan{}, State{}, ErrConflict
	}
	return plan, state, nil
}

func (coordinator *Coordinator) sourceBoot(ctx context.Context, plan Plan) (BootIdentity, error) {
	actual, err := coordinator.bootIdentity.CurrentBootIdentity(ctx, plan.NodeID)
	if err != nil {
		return BootIdentity{}, err
	}
	if actual.Validate() != nil || !sameSourceBoot(actual, plan.SourceBoot) {
		return actual, ErrStaleBoot
	}
	return actual, nil
}

func (coordinator *Coordinator) sqliteOperation(ctx context.Context, plan Plan, state State, databaseID string, deadline time.Time, backup bool) (SQLiteResult, error) {
	kind := "sqlite_checkpoint:" + databaseID
	if backup {
		kind = "sqlite_online_backup:" + databaseID
	}
	operation := SQLiteOperation{ID: deterministicOperationID(kind, plan.ID, state.Fence), PlanID: plan.ID,
		PlanDigest: plan.Digest, NodeID: plan.NodeID, DatabaseID: databaseID, Fence: state.Fence, Deadline: deadline}
	var err error
	operation.OperationDigest, err = typedDigest(operation)
	if err != nil {
		return SQLiteResult{}, err
	}
	var result SQLiteResult
	if backup {
		result, err = coordinator.sqlite.OnlineBackupSQLite(ctx, operation)
	} else {
		result, err = coordinator.sqlite.CheckpointSQLite(ctx, operation)
	}
	if err != nil {
		return SQLiteResult{}, err
	}
	if result.OperationID != operation.ID || result.Fence != state.Fence || result.DatabaseID != databaseID || !result.Complete || !validDigest(result.ArtifactDigest) || !validDigest(result.EvidenceDigest) {
		return SQLiteResult{}, ErrIntegrity
	}
	return result, nil
}

func (coordinator *Coordinator) checkpointFailure(ctx context.Context, command StepCommand, state State, evidence string, cause error) (State, Receipt, error) {
	if !validDigest(evidence) {
		evidence = digestStrings(command.PlanID, command.IdempotencyKey, "checkpoint_failure")
	}
	plan, err := coordinator.repository.LoadPlan(ctx, command.PlanID)
	if err != nil {
		return State{}, Receipt{}, err
	}
	return coordinator.terminal(ctx, command, state, PhaseUncertain, OutcomeCheckpointIncomplete,
		evidence, recoverySteps(plan, RecoveryReleaseDrain, RecoveryResumeOperations), cause)
}

func (coordinator *Coordinator) advance(ctx context.Context, command StepCommand, state State, to Phase, evidence, marker string, outcome OutcomeReason, steps []RecoveryStep) (State, Receipt, error) {
	transition := Transition{PlanID: command.PlanID, From: state.Phase, To: to,
		ExpectedGeneration: command.ExpectedGeneration, Fence: command.Fence, ControllerID: command.ControllerID,
		IdempotencyKey: command.IdempotencyKey, EvidenceDigest: evidence, MarkerDigest: marker,
		Outcome: outcome, RecoverySteps: steps, At: command.At}
	return coordinator.repository.Transition(ctx, transition)
}

func (coordinator *Coordinator) terminal(ctx context.Context, command StepCommand, state State, to Phase, outcome OutcomeReason, evidence string, steps []RecoveryStep, cause error) (State, Receipt, error) {
	return coordinator.terminalWithMarker(ctx, command, state, to, outcome, evidence, "", steps, cause)
}

func (coordinator *Coordinator) terminalWithMarker(ctx context.Context, command StepCommand, state State, to Phase, outcome OutcomeReason, evidence, marker string, steps []RecoveryStep, cause error) (State, Receipt, error) {
	next, receipt, err := coordinator.advance(ctx, command, state, to, evidence, marker, outcome, steps)
	if err != nil {
		return State{}, Receipt{}, err
	}
	return next, receipt, cause
}

func sameSourceBoot(actual, expected BootIdentity) bool {
	return actual.BootID == expected.BootID && actual.KernelRelease == expected.KernelRelease && actual.KernelDigest == expected.KernelDigest && actual.BootSlot == expected.BootSlot
}

func matchesExpectedBoot(actual BootIdentity, expected ExpectedBoot) bool {
	return actual.KernelRelease == expected.KernelRelease && actual.KernelDigest == expected.KernelDigest && (expected.BootSlot == "" || actual.BootSlot == expected.BootSlot)
}

func recoverySteps(plan Plan, steps ...RecoveryStep) []RecoveryStep {
	if plan.Rollback.Available() {
		if plan.Rollback.Kind == RollbackBootEntry {
			steps = append(steps, RecoveryRestoreBootEntry)
		}
		if plan.Rollback.Kind == RollbackSnapshot {
			steps = append(steps, RecoveryRestoreSnapshot)
		}
	}
	canonical, err := canonicalRecoverySteps(steps)
	if err != nil {
		return []RecoveryStep{RecoveryInspectMarker}
	}
	return canonical
}

func typedDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return digestBytes(raw), nil
}

func validReconcileResult(result ReconcileResult) bool {
	if !validDigest(result.EvidenceDigest) {
		return false
	}
	components := []ComponentResult{result.Services, result.Configuration, result.Locks, result.Schedules}
	for _, component := range components {
		if !validDigest(component.EvidenceDigest) {
			return false
		}
	}
	return result.EvidenceDigest == digestStrings(result.Services.EvidenceDigest,
		result.Configuration.EvidenceDigest, result.Locks.EvidenceDigest, result.Schedules.EvidenceDigest)
}

func earlier(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func evidenceOr(value, fallback string) string {
	if validDigest(value) {
		return value
	}
	return fallback
}
