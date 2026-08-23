package operations

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// Coordinator is a durable one-effect saga. It accepts canonical desired
// state before touching the host, verifies exact executor evidence, and only
// restores desired state after compensation is itself proven.
type Coordinator struct {
	repository Repository
	executor HostExecutor
	clock Clock
}

func NewCoordinator(repository Repository, executor HostExecutor, clock Clock) Coordinator {
	return Coordinator{repository: repository, executor: executor, clock: clock}
}

func (coordinator Coordinator) Handle(ctx context.Context, command Command) (OperationReceipt, error) {
	if coordinator.repository == nil || coordinator.executor == nil || coordinator.clock == nil { return OperationReceipt{}, ErrInvalidCommand }
	now := coordinator.clock.Now().UTC()
	if err := validateCommand(command, now); err != nil { return OperationReceipt{}, err }
	header, scope, digest := command.commandHeader(), command.commandScope(), commandDigest(command)
	stored, found, err := coordinator.repository.LookupOperation(ctx, scope, header.CommandID)
	if err != nil { return OperationReceipt{}, err }
	if found {
		if stored.CommandDigest != digest { return OperationReceipt{}, ErrIdempotency }
		if validateStoredReceipt(stored, header.CommandID, digest, scope) != nil { return OperationReceipt{}, ErrInvalidReceipt }
		if terminalOperation(stored.Status) { return cloneReceipt(stored), nil }
		return coordinator.execute(ctx, stored)
	}
	if header.Deadline.Before(now) { return OperationReceipt{}, ErrInvalidCommand }

	plan, err := coordinator.plan(ctx, command)
	if err != nil { return OperationReceipt{}, err }
	admission := Admission{CommandID: header.CommandID, CommandDigest: digest, Scope: scope, AcceptedAt: now, Request: plan.request,
		Mutations: plan.mutations, Rollback: plan.rollback, Success: plan.success, Restored: plan.restored}
	result, err := coordinator.repository.Admit(ctx, admission)
	if err != nil { return OperationReceipt{}, err }
	if result.Kind == AdmissionConflict { return OperationReceipt{}, ErrConflict }
	if result.Kind != AdmissionNew && result.Kind != AdmissionExistingSame { return OperationReceipt{}, ErrInvalidReceipt }
	accepted := result.Receipt
	if validateStoredReceipt(accepted, header.CommandID, digest, scope) != nil || !reflect.DeepEqual(accepted.Request, plan.request) ||
		!reflect.DeepEqual(accepted.Mutations, plan.mutations) || !reflect.DeepEqual(accepted.Rollback, plan.rollback) { return OperationReceipt{}, ErrInvalidReceipt }
	if terminalOperation(accepted.Status) { return cloneReceipt(accepted), nil }
	return coordinator.execute(ctx, accepted)
}

func (coordinator Coordinator) execute(ctx context.Context, accepted OperationReceipt) (OperationReceipt, error) {
	effect, effectErr := coordinator.executor.ObserveOrApply(ctx, accepted.Request)
	if !effectReceiptMatches(accepted.Request, effect) || effectErr != nil && effect.Outcome == EffectConfirmed {
		if effectErr == nil { effectErr = ErrInvalidEffect }
		return coordinator.complete(ctx, accepted, OperationAmbiguous, effect, CompensationReceipt{}, nil, effectErr)
	}
	switch effect.Outcome {
	case EffectConfirmed:
		return coordinator.complete(ctx, accepted, OperationApplied, effect, CompensationReceipt{}, withProof(accepted.Success, effect.ProofDigest, coordinator.clock.Now()), effectErr)
	case EffectRejected:
		if !effect.MutationObserved {
			return coordinator.complete(ctx, accepted, OperationRejected, effect, CompensationReceipt{}, withProof(accepted.Restored, effect.ProofDigest, coordinator.clock.Now()), effectErr)
		}
		if effect.CompensationToken.IsZero() { return coordinator.complete(ctx, accepted, OperationAmbiguous, effect, CompensationReceipt{}, nil, ErrCompensationFailed) }
		request := CompensationRequest{EffectID: effect.EffectID, RequestDigest: effect.RequestDigest, Scope: accepted.Scope, CompensationToken: effect.CompensationToken, FailureCode: effect.FailureCode}
		compensation, compensationErr := coordinator.executor.Compensate(ctx, request)
		if compensationErr != nil || !compensationReceiptMatches(request, compensation) || compensation.Outcome != EffectConfirmed {
			if compensationErr == nil { compensationErr = ErrCompensationFailed }
			return coordinator.complete(ctx, accepted, OperationAmbiguous, effect, compensation, nil, compensationErr)
		}
		return coordinator.complete(ctx, accepted, OperationCompensated, effect, compensation, withProof(accepted.Restored, compensation.ProofDigest, coordinator.clock.Now()), effectErr)
	case EffectAmbiguous:
		if effectErr == nil { effectErr = ErrInvalidEffect }
		return coordinator.complete(ctx, accepted, OperationAmbiguous, effect, CompensationReceipt{}, nil, effectErr)
	default:
		return coordinator.complete(ctx, accepted, OperationAmbiguous, effect, CompensationReceipt{}, nil, ErrInvalidEffect)
	}
}

func (coordinator Coordinator) complete(ctx context.Context, accepted OperationReceipt, status OperationStatus, effect EffectReceipt, compensation CompensationReceipt, observed []ObservedResource, outcomeErr error) (OperationReceipt, error) {
	completed, err := coordinator.repository.Complete(ctx, Completion{CommandID: accepted.CommandID, CommandDigest: accepted.CommandDigest, Scope: accepted.Scope,
		Status: status, Effect: effect, Compensation: compensation, Observed: observed})
	if err != nil {
		accepted.Status, accepted.Effect, accepted.Compensation = OperationAmbiguous, effect, compensation
		return cloneReceipt(accepted), err
	}
	if validateStoredReceipt(completed, accepted.CommandID, accepted.CommandDigest, accepted.Scope) != nil { return OperationReceipt{}, ErrInvalidReceipt }
	return cloneReceipt(completed), outcomeErr
}

type operationPlan struct {
	request EffectRequest
	mutations []ResourceMutation
	rollback []ResourceMutation
	success []ObservedResource
	restored []ObservedResource
}

func (coordinator Coordinator) plan(ctx context.Context, command Command) (operationPlan, error) {
	request := EffectRequest{Scope: command.commandScope(), Kind: command.commandKind()}
	var proposed Resource
	var expected uint64
	deleteResource := false

	switch value := command.(type) {
	case ApplyResourceProfile:
		profile := value.Profile; profile.Status = pendingStatus(LifecycleUpdating); proposed, expected = profile, value.ExpectedGeneration; request.ResourceProfile = &ResourceProfileEffect{Profile: profile}
	case ResetTransferMonth:
		account := value.Account
		if value.ExpectedGeneration != 0 {
			previousEnvelope, err := coordinator.repository.LoadResource(ctx, KindTransferAccount, account.ID); if err != nil { return operationPlan{}, err }
			previousResource, err := DecodeResource(previousEnvelope); if err != nil { return operationPlan{}, err }
			previous, ok := previousResource.(*TransferAccount)
			if !ok || previous.Generation != value.ExpectedGeneration || !account.PeriodStart.Equal(previous.PeriodEnd) || account.CounterEpoch == previous.CounterEpoch { return operationPlan{}, ErrConflict }
		}
		account.Status = pendingStatus(LifecycleUpdating); proposed, expected = account, value.ExpectedGeneration; request.TransferReset = &TransferResetEffect{Account: account}
	case RecordTransferSample:
		account := value.Account
		if value.ExpectedGeneration != 0 {
			previousEnvelope, err := coordinator.repository.LoadResource(ctx, KindTransferAccount, account.ID); if err != nil { return operationPlan{}, err }
			previousResource, err := DecodeResource(previousEnvelope); if err != nil { return operationPlan{}, err }
			previous, ok := previousResource.(*TransferAccount)
			if !ok || previous.Generation != value.ExpectedGeneration || previous.CounterEpoch != account.CounterEpoch || !previous.PeriodStart.Equal(account.PeriodStart) || !previous.PeriodEnd.Equal(account.PeriodEnd) ||
				account.IngressBytes < previous.IngressBytes || account.EgressBytes < previous.EgressBytes || account.LastSampleAt.Before(previous.LastSampleAt) { return operationPlan{}, ErrConflict }
		}
		account.Status = pendingStatus(LifecycleUpdating); proposed, expected = account, value.ExpectedGeneration; request.TransferSample = &TransferSampleEffect{Account: account}
	case ReplaceFirewallPolicy:
		policy := value.Policy; policy.Status = pendingStatus(LifecycleUpdating); proposed, expected = policy, value.ExpectedGeneration; request.FirewallPolicy = &FirewallPolicyEffect{Policy: policy, Strategy: ActivationMakeBeforeBreak}
	case ReplaceSSHPolicy:
		policy := value.Policy; policy.Status = pendingStatus(LifecycleUpdating); proposed, expected = policy, value.ExpectedGeneration; request.SSHPolicy = &SSHPolicyEffect{Policy: policy, Strategy: ActivationMakeBeforeBreak}
	case PutSSHKey:
		key := value.Key; key.Status = pendingStatus(LifecycleUpdating); proposed, expected = key, value.ExpectedGeneration; request.PutSSHKey = &PutSSHKeyEffect{Key: key}
	case DeleteSSHKey:
		envelope, err := coordinator.repository.LoadResource(ctx, KindSSHKey, value.KeyID)
		if err != nil { return operationPlan{}, err }
		resource, err := DecodeResource(envelope); if err != nil { return operationPlan{}, err }
		key, ok := resource.(*SSHKey); if !ok || key.Generation != value.ExpectedGeneration || key.TenantID.String() != value.Header.TenantID.String() { return operationPlan{}, ErrConflict }
		if !value.Header.Actor.Has(CapabilityNodeSecurity) && key.PrincipalID != value.Header.Actor.PrincipalID { return operationPlan{}, ErrUnauthorized }
		key.Generation++; key.Status = pendingStatus(LifecycleDeleting); proposed, expected, deleteResource = *key, value.ExpectedGeneration, true; request.DeleteSSHKey = &DeleteSSHKeyEffect{Key: *key}
	case ReplaceWAFPolicy:
		policy := value.Policy; policy.Status = pendingStatus(LifecycleUpdating); proposed, expected = policy, value.ExpectedGeneration; request.WAFPolicy = &WAFPolicyEffect{Policy: policy, Strategy: ActivationCompileProbeSwap}
	case SetServicePolicy:
		policy := value.Policy; policy.Status = pendingStatus(LifecycleUpdating); proposed, expected = policy, value.ExpectedGeneration; request.ServicePolicy = &ServicePolicyEffect{Policy: policy}
	case ControlService:
		envelope, err := coordinator.repository.LoadResource(ctx, KindServicePolicy, serviceResourceID(value.Service)); if err != nil { return operationPlan{}, err }
		resource, err := DecodeResource(envelope); if err != nil { return operationPlan{}, err }
		policy, ok := resource.(*ServicePolicy); if !ok || policy.Generation != value.ExpectedPolicyGeneration || policy.Service != value.Service { return operationPlan{}, ErrConflict }
		request.ServiceControl = &ServiceControlEffect{Service: value.Service, Action: value.Action, PolicyGeneration: value.ExpectedPolicyGeneration}
	case DiagnoseService:
		request.ServiceDiagnose = &ServiceDiagnoseEffect{Service: value.Service, Depth: value.Depth, Since: value.Since}
	case RepairService:
		request.ServiceRepair = &ServiceRepairEffect{Service: value.Service, Strategy: value.Strategy, DiagnosticProofDigest: value.DiagnosticProofDigest}
	case QueryMetrics:
		request.MetricsQuery = &MetricsQueryEffect{Scope: value.Scope, Names: append([]MetricName(nil), value.Names...), Start: value.Start, End: value.End, Step: value.Step, Limit: value.Limit}
	case OpenLogStream:
		request.LogQuery = &LogQueryEffect{Source: value.Source, Service: value.Service, TenantID: value.Header.TenantID.String(), SiteID: value.Header.SiteID.String(), Start: value.Start, End: value.End, MinimumSeverity: value.MinimumSeverity, Cursor: value.Cursor, Limit: value.Limit}
	case QuerySSHLogins:
		request.SSHLoginQuery = &SSHLoginQueryEffect{Start: value.Start, End: value.End, SourceCIDR: value.SourceCIDR, Limit: value.Limit}
	case QuerySSHSessions:
		request.SSHSessionQuery = &SSHSessionQueryEffect{IncludeClosedSince: value.IncludeClosedSince, Limit: value.Limit}
	case InvestigateProcess:
		request.ProcessInvestigate = &ProcessInvestigateEffect{Process: value.Process, IncludeFileDescriptors: value.IncludeFileDescriptors, IncludeNetworkSockets: value.IncludeNetworkSockets}
	case TerminateProcess:
		request.ProcessTerminate = &ProcessTerminateEffect{Process: value.Process, Signal: value.Signal, InvestigationProofDigest: value.InvestigationProofDigest, ReasonCode: value.ReasonCode}
	case RequestPackageTransaction:
		transaction := value.Transaction; transaction.Status = pendingStatus(LifecycleUpdating); proposed, expected = transaction, 0; request.PackageTransaction = &PackageTransactionEffect{Transaction: transaction}
	case ReconcileManagedService:
		service := value.Service; service.Status = pendingStatus(LifecycleUpdating); proposed, expected = service, value.ExpectedGeneration; request.ManagedService = &ManagedServiceEffect{Service: service}
	default:
		return operationPlan{}, ErrInvalidCommand
	}

	finalized, err := finalizeEffect(request)
	if err != nil { return operationPlan{}, err }
	plan := operationPlan{request: finalized}
	if proposed == nil { return plan, nil }
	envelope, err := EncodeResource(proposed)
	if err != nil { return operationPlan{}, err }
	plan.mutations = []ResourceMutation{{Kind: MutationUpsert, ExpectedGeneration: expected, Resource: envelope}}
	successStatus := readyStatus(envelope.Metadata.Generation, coordinator.clock.Now())
	if deleteResource { successStatus.Lifecycle, successStatus.Health = LifecycleDeleted, HealthUnknown }
	plan.success = []ObservedResource{{Kind: envelope.Kind, ID: envelope.Metadata.ID, Generation: envelope.Metadata.Generation, Status: successStatus}}
	plan.rollback, plan.restored, err = coordinator.buildRollback(ctx, plan.mutations)
	if err != nil { return operationPlan{}, err }
	return plan, nil
}

func (coordinator Coordinator) buildRollback(ctx context.Context, mutations []ResourceMutation) ([]ResourceMutation, []ObservedResource, error) {
	rollback := make([]ResourceMutation, 0, len(mutations)); restored := make([]ObservedResource, 0, len(mutations))
	for _, mutation := range mutations {
		var base Resource
		var err error
		if mutation.ExpectedGeneration == 0 {
			base, err = DecodeResource(mutation.Resource)
		} else {
			previous, loadErr := coordinator.repository.LoadResource(ctx, mutation.Resource.Kind, mutation.Resource.Metadata.ID)
			if loadErr != nil { return nil, nil, loadErr }
			if previous.Metadata.Generation != mutation.ExpectedGeneration { return nil, nil, ErrConflict }
			base, err = DecodeResource(previous)
		}
		if err != nil { return nil, nil, err }
		generation := mutation.Resource.Metadata.Generation+1
		status := base.Meta().Status; status.ObservedGeneration, status.ProofDigest, status.MessageCode, status.UpdatedAt = generation, "", "", coordinator.clock.Now().UTC()
		if mutation.ExpectedGeneration == 0 { status.Lifecycle, status.Health, status.Reconciliation = LifecycleDeleted, HealthUnknown, ReconciliationInSync }
		rewritten, err := RewriteResource(base, generation, status); if err != nil { return nil, nil, err }
		envelope, err := EncodeResource(rewritten); if err != nil { return nil, nil, err }
		if mutation.ExpectedGeneration == 0 { envelope.PhysicalKey = "" }
		rollback = append(rollback, ResourceMutation{Kind: MutationUpsert, ExpectedGeneration: mutation.Resource.Metadata.Generation, Resource: envelope})
		restored = append(restored, ObservedResource{Kind: envelope.Kind, ID: envelope.Metadata.ID, Generation: envelope.Metadata.Generation, Status: status})
	}
	return rollback, restored, nil
}

func withProof(source []ObservedResource, proof string, at time.Time) []ObservedResource {
	result := append([]ObservedResource(nil), source...)
	for index := range result { result[index].Status.ProofDigest, result[index].Status.ObservedGeneration, result[index].Status.UpdatedAt = proof, result[index].Generation, at.UTC() }
	return result
}

func pendingStatus(lifecycle Lifecycle) ResourceStatus { return ResourceStatus{Lifecycle: lifecycle, Health: HealthUnknown, Reconciliation: ReconciliationPending} }
func readyStatus(generation uint64, at time.Time) ResourceStatus { return ResourceStatus{Lifecycle: LifecycleReady, Health: HealthHealthy, Reconciliation: ReconciliationInSync, ObservedGeneration: generation, UpdatedAt: at.UTC()} }

func validateStoredReceipt(receipt OperationReceipt, commandID, digest string, scope OperationScope) error {
	if receipt.CommandID != commandID || receipt.CommandDigest != digest || receipt.Scope != scope || receipt.AcceptedAt.IsZero() || validateEffectRequest(receipt.Request) != nil ||
		len(receipt.Mutations) != len(receipt.Rollback) || len(receipt.Mutations) != len(receipt.Success) || len(receipt.Mutations) != len(receipt.Restored) { return ErrInvalidReceipt }
	for index := range receipt.Mutations { if !validRollbackPair(receipt.Mutations[index], receipt.Rollback[index]) { return ErrInvalidReceipt } }
	switch receipt.Status {
	case OperationAccepted, OperationAmbiguous:
		return nil
	case OperationApplied:
		if !effectReceiptMatches(receipt.Request, receipt.Effect) || receipt.Effect.Outcome != EffectConfirmed { return ErrInvalidReceipt }
	case OperationRejected:
		if !effectReceiptMatches(receipt.Request, receipt.Effect) || receipt.Effect.Outcome != EffectRejected || receipt.Effect.MutationObserved { return ErrInvalidReceipt }
	case OperationCompensated:
		request := CompensationRequest{EffectID: receipt.Effect.EffectID, RequestDigest: receipt.Effect.RequestDigest, Scope: receipt.Scope, CompensationToken: receipt.Effect.CompensationToken, FailureCode: receipt.Effect.FailureCode}
		if !effectReceiptMatches(receipt.Request, receipt.Effect) || !compensationReceiptMatches(request, receipt.Compensation) || receipt.Compensation.Outcome != EffectConfirmed { return ErrInvalidReceipt }
	default:
		return ErrInvalidReceipt
	}
	return nil
}

func terminalOperation(status OperationStatus) bool { return status == OperationApplied || status == OperationRejected || status == OperationCompensated || status == OperationAmbiguous }

func validRollbackPair(mutation, rollback ResourceMutation) bool {
	if mutation.Kind != MutationUpsert || rollback.Kind != MutationUpsert || mutation.Resource.Kind != rollback.Resource.Kind || mutation.Resource.Metadata.ID != rollback.Resource.Metadata.ID ||
		mutation.Resource.Metadata.Generation == 0 || rollback.ExpectedGeneration != mutation.Resource.Metadata.Generation || rollback.Resource.Metadata.Generation != mutation.Resource.Metadata.Generation+1 { return false }
	if mutation.ExpectedGeneration == 0 { if mutation.Resource.Metadata.Generation != 1 { return false } } else if mutation.Resource.Metadata.Generation != mutation.ExpectedGeneration+1 { return false }
	if _, err := DecodeResource(mutation.Resource); err != nil { return false }
	if _, err := DecodeResource(rollback.Resource); err != nil { return false }
	return true
}

func operationErrorEqual(left, right error) bool { return errors.Is(left, right) }
