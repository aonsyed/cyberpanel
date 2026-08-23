package database

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// Coordinator is the concrete durable saga for canonical database resources.
// It admits intent and an outbox request transactionally, executes one typed
// MariaDB effect, then records proof or exact compensation evidence.
type Coordinator struct {
	repository Repository
	executor   MariaDBExecutor
	clock      Clock
}

func NewCoordinator(repository Repository, executor MariaDBExecutor, clock Clock) Coordinator {
	return Coordinator{repository: repository, executor: executor, clock: clock}
}

func (coordinator Coordinator) Handle(ctx context.Context, command Command) (OperationReceipt, error) {
	if coordinator.repository == nil || coordinator.executor == nil || coordinator.clock == nil {
		return OperationReceipt{}, ErrInvalidCommand
	}
	now := coordinator.clock.Now().UTC()
	if err := validateCommand(command, now); err != nil { return OperationReceipt{}, err }
	header, scope, digest := command.commandHeader(), command.commandScope(), commandDigest(command)

	stored, found, err := coordinator.repository.LookupOperation(ctx, scope, header.CommandID)
	if err != nil { return OperationReceipt{}, err }
	if found {
		if stored.CommandDigest != digest { return OperationReceipt{}, ErrIdempotency }
		if err := validateStoredOperation(stored, header.CommandID, digest, scope); err != nil { return OperationReceipt{}, err }
		if terminalOperation(stored.Status) { return cloneOperation(stored), nil }
		return coordinator.execute(ctx, stored)
	}

	mutations, success, _, request, err := coordinator.plan(ctx, command)
	if err != nil { return OperationReceipt{}, err }
	rollback, compensated, err := coordinator.compensationPlan(ctx, mutations)
	if err != nil { return OperationReceipt{}, err }
	admission := Admission{
		CommandID: header.CommandID, CommandDigest: digest, Scope: scope, AcceptedAt: now,
		Request: request, Mutations: mutations, Rollback: rollback, Success: success, Compensated: compensated,
	}
	result, err := coordinator.repository.Admit(ctx, admission)
	if err != nil { return OperationReceipt{}, err }
	switch result.Kind {
	case AdmissionConflict:
		return OperationReceipt{}, ErrConflict
	case AdmissionNew, AdmissionExistingSame:
	default:
		return OperationReceipt{}, ErrInvalidReceipt
	}
	accepted := result.Receipt
	if err := validateStoredOperation(accepted, header.CommandID, digest, scope); err != nil { return OperationReceipt{}, err }
	if !reflect.DeepEqual(accepted.Request, request) || !reflect.DeepEqual(accepted.Mutations, mutations) ||
		!reflect.DeepEqual(accepted.Rollback, rollback) { return OperationReceipt{}, ErrInvalidReceipt }
	if terminalOperation(accepted.Status) { return cloneOperation(accepted), nil }
	return coordinator.execute(ctx, accepted)
}

func (coordinator Coordinator) execute(ctx context.Context, accepted OperationReceipt) (OperationReceipt, error) {
	effect, effectErr := coordinator.executor.ObserveOrApply(ctx, accepted.Request)
	if !effectReceiptMatches(accepted.Request, effect) || effectErr != nil && effect.Outcome == EffectConfirmed {
		completion := Completion{CommandID: accepted.CommandID, CommandDigest: accepted.CommandDigest, Scope: accepted.Scope,
			Status: OperationAmbiguous, Effect: effect}
		completed, completeErr := coordinator.repository.Complete(ctx, completion)
		if completeErr != nil { accepted.Status = OperationAmbiguous; accepted.Effect = effect; return cloneOperation(accepted), completeErr }
		if effectErr != nil { return cloneOperation(completed), effectErr }
		return cloneOperation(completed), ErrInvalidEffect
	}

	switch effect.Outcome {
	case EffectConfirmed:
		return coordinator.complete(ctx, accepted, OperationApplied, effect, CompensationReceipt{}, accepted.Success, effectErr)
	case EffectRejected:
		if !effect.MutationObserved {
			return coordinator.complete(ctx, accepted, OperationRejected, effect, CompensationReceipt{}, accepted.Compensated, effectErr)
		}
		if effect.CompensationToken.IsZero() {
			return coordinator.complete(ctx, accepted, OperationAmbiguous, effect, CompensationReceipt{}, nil, ErrCompensationFailed)
		}
		request := CompensationRequest{EffectID: effect.EffectID, RequestDigest: effect.RequestDigest, Scope: accepted.Scope,
			CompensationToken: effect.CompensationToken, FailureCode: effect.FailureCode}
		compensation, compensationErr := coordinator.executor.Compensate(ctx, request)
		if !compensationReceiptMatches(request, compensation) || compensationErr != nil || compensation.Outcome != EffectConfirmed {
			if compensationErr == nil { compensationErr = ErrCompensationFailed }
			return coordinator.complete(ctx, accepted, OperationAmbiguous, effect, compensation, nil, compensationErr)
		}
		return coordinator.complete(ctx, accepted, OperationCompensated, effect, compensation, accepted.Compensated, effectErr)
	case EffectAmbiguous:
		if effectErr == nil { effectErr = ErrInvalidEffect }
		return coordinator.complete(ctx, accepted, OperationAmbiguous, effect, CompensationReceipt{}, nil, effectErr)
	default:
		return coordinator.complete(ctx, accepted, OperationAmbiguous, effect, CompensationReceipt{}, nil, ErrInvalidEffect)
	}
}

func (coordinator Coordinator) complete(ctx context.Context, accepted OperationReceipt, status OperationStatus, effect EffectReceipt,
	compensation CompensationReceipt, observed []ObservedResource, outcomeErr error) (OperationReceipt, error) {
	observed = append([]ObservedResource(nil), observed...)
	proofDigest := ""
	if status == OperationApplied { proofDigest = effect.ProofDigest }
	if status == OperationCompensated { proofDigest = compensation.ProofDigest }
	for index := range observed {
		observed[index].Status.ObservedGeneration = observed[index].Generation
		observed[index].Status.ProofDigest = proofDigest
	}
	completed, err := coordinator.repository.Complete(ctx, Completion{
		CommandID: accepted.CommandID, CommandDigest: accepted.CommandDigest, Scope: accepted.Scope,
		Status: status, Effect: effect, Compensation: compensation, Observed: observed,
	})
	if err != nil {
		accepted.Status, accepted.Effect, accepted.Compensation = OperationAmbiguous, effect, compensation
		return cloneOperation(accepted), err
	}
	if validationErr := validateStoredOperation(completed, accepted.CommandID, accepted.CommandDigest, accepted.Scope); validationErr != nil {
		return OperationReceipt{}, validationErr
	}
	return cloneOperation(completed), outcomeErr
}

func (coordinator Coordinator) plan(ctx context.Context, command Command) ([]ResourceMutation, []ObservedResource, []ObservedResource, EffectRequest, error) {
	scope := command.commandScope()
	var resource Resource
	var expected uint64
	request := EffectRequest{Scope: scope}

	switch value := command.(type) {
	case CreateDatabase:
		if _, err := coordinator.loadInstance(ctx, value.Database.InstanceID); err != nil { return nil, nil, nil, EffectRequest{}, err }
		database := value.Database
		database.Status = pendingStatus(LifecycleProvisioning)
		resource, expected = database, 0
		request.Kind, request.CreateDatabase = EffectCreateDatabase, &CreateDatabaseEffect{Database: database}
	case DeleteDatabase:
		database, err := coordinator.loadDatabase(ctx, value.DatabaseID, value.Header.TenantID)
		if err != nil { return nil, nil, nil, EffectRequest{}, err }
		if database.Generation != value.ExpectedGeneration { return nil, nil, nil, EffectRequest{}, ErrConflict }
		expected = database.Generation
		database.Generation++
		database.Status = pendingStatus(LifecycleDeleting)
		resource = database
		request.Kind, request.DeleteDatabase = EffectDeleteDatabase, &DeleteDatabaseEffect{Database: database, RecoveryPointRef: value.RecoveryPointRef,
			WaiveRecovery: value.WaiveRecovery, ApprovalRef: value.ApprovalRef}
	case CreatePrincipal:
		if _, err := coordinator.loadInstance(ctx, value.Principal.InstanceID); err != nil { return nil, nil, nil, EffectRequest{}, err }
		principal := value.Principal
		principal.Status = pendingStatus(LifecycleProvisioning)
		resource, expected = principal, 0
		request.Kind, request.CreatePrincipal = EffectCreatePrincipal, &CreatePrincipalEffect{Principal: principal}
	case DeletePrincipal:
		principal, err := coordinator.loadPrincipal(ctx, value.PrincipalID, value.Header.TenantID)
		if err != nil { return nil, nil, nil, EffectRequest{}, err }
		if principal.Generation != value.ExpectedGeneration { return nil, nil, nil, EffectRequest{}, ErrConflict }
		expected = principal.Generation
		principal.Generation++
		principal.Status = pendingStatus(LifecycleDeleting)
		resource = principal
		request.Kind, request.DeletePrincipal = EffectDeletePrincipal, &DeletePrincipalEffect{Principal: principal}
	case RotatePrincipalPassword:
		principal, err := coordinator.loadPrincipal(ctx, value.PrincipalID, value.Header.TenantID)
		if err != nil { return nil, nil, nil, EffectRequest{}, err }
		if principal.Generation != value.ExpectedGeneration { return nil, nil, nil, EffectRequest{}, ErrConflict }
		expected = principal.Generation
		principal.Generation++
		principal.CredentialSecretRef = value.NewSecretRef
		principal.Status = pendingStatus(LifecycleUpdating)
		resource = principal
		request.Kind, request.RotatePassword = EffectRotatePassword, &RotatePasswordEffect{Principal: principal, NewSecretRef: value.NewSecretRef}
	case ReplaceGrantSet:
		if err := coordinator.validateGrantOwners(ctx, value.GrantSet, value.Header.TenantID); err != nil { return nil, nil, nil, EffectRequest{}, err }
		grantSet := value.GrantSet
		existing, err := coordinator.repository.LoadResource(ctx, KindGrantSet, grantSet.ID)
		if err == nil {
			if existing.Metadata.TenantID != value.Header.TenantID || grantSet.Generation != existing.Metadata.Generation+1 { return nil, nil, nil, EffectRequest{}, ErrConflict }
			expected = existing.Metadata.Generation
		} else if !errors.Is(err, ErrNotFound) { return nil, nil, nil, EffectRequest{}, err
		} else if grantSet.Generation != 1 { return nil, nil, nil, EffectRequest{}, ErrConflict }
		grantSet.Status = pendingStatus(LifecycleUpdating)
		resource = grantSet
		request.Kind, request.ReplaceGrants = EffectReplaceGrants, &ReplaceGrantsEffect{GrantSet: grantSet}
	case ReplaceRemoteCIDRs:
		if value.Policy.TenantID != value.Header.TenantID { return nil, nil, nil, EffectRequest{}, ErrUnauthorized }
		if _, err := coordinator.loadInstance(ctx, value.Policy.InstanceID); err != nil { return nil, nil, nil, EffectRequest{}, err }
		policy := value.Policy
		existing, err := coordinator.repository.LoadResource(ctx, KindNetworkPolicy, policy.ID)
		if err == nil {
			if existing.Metadata.TenantID != value.Header.TenantID || policy.Generation != existing.Metadata.Generation+1 { return nil, nil, nil, EffectRequest{}, ErrConflict }
			expected = existing.Metadata.Generation
		} else if !errors.Is(err, ErrNotFound) { return nil, nil, nil, EffectRequest{}, err
		} else if policy.Generation != 1 { return nil, nil, nil, EffectRequest{}, ErrConflict }
		policy.Status = pendingStatus(LifecycleUpdating)
		resource = policy
		request.Kind, request.ApplyNetworkPolicy = EffectApplyNetworkPolicy, &ApplyNetworkPolicyEffect{Policy: policy}
	case BindExternalInstance:
		instance := value.Instance
		instance.Status = pendingStatus(LifecycleProvisioning)
		resource, expected = instance, 0
		request.Kind, request.BindExternalInstance = EffectBindExternalInstance, &BindExternalInstanceEffect{Instance: instance}
	case OpenConsoleSession:
		if _, err := coordinator.loadDatabase(ctx, value.Session.DatabaseID, value.Header.TenantID); err != nil { return nil, nil, nil, EffectRequest{}, err }
		if _, err := coordinator.loadPrincipal(ctx, value.Session.PrincipalID, value.Header.TenantID); err != nil { return nil, nil, nil, EffectRequest{}, err }
		session := value.Session
		session.Status = pendingStatus(LifecycleProvisioning)
		resource, expected = session, 0
		request.Kind, request.OpenConsoleSession = EffectOpenConsoleSession, &OpenConsoleSessionEffect{Session: session}
	case RequestTuning:
		if _, err := coordinator.loadInstance(ctx, value.Profile.InstanceID); err != nil { return nil, nil, nil, EffectRequest{}, err }
		profile := value.Profile
		profile.Status = pendingStatus(LifecycleUpdating)
		resource, expected = profile, 0
		request.Kind, request.ApplyTuning = EffectApplyTuning, &ApplyTuningEffect{Profile: profile}
	case RequestUpgrade:
		instance, err := coordinator.loadInstance(ctx, value.Upgrade.InstanceID)
		if err != nil { return nil, nil, nil, EffectRequest{}, err }
		if compareVersion(instance.Version, value.Upgrade.From) != 0 { return nil, nil, nil, EffectRequest{}, ErrConflict }
		upgrade := value.Upgrade
		upgrade.Status = pendingStatus(LifecycleUpdating)
		resource, expected = upgrade, 0
		request.Kind, request.UpgradeDatabase = EffectUpgradeDatabase, &UpgradeDatabaseEffect{Upgrade: upgrade}
	default:
		return nil, nil, nil, EffectRequest{}, ErrInvalidCommand
	}

	envelope, err := EncodeResource(resource)
	if err != nil { return nil, nil, nil, EffectRequest{}, err }
	request, err = finalizeEffect(request)
	if err != nil { return nil, nil, nil, EffectRequest{}, err }
	mutation := ResourceMutation{Kind: MutationUpsert, ExpectedGeneration: expected, Resource: envelope}
	successStatus := readyStatus(envelope.Metadata.Generation)
	if request.Kind == EffectDeleteDatabase || request.Kind == EffectDeletePrincipal {
		successStatus.Lifecycle, successStatus.Health = LifecycleDeleted, HealthUnknown
	}
	compensatedStatus := envelope.Metadata.Status
	compensatedStatus.Reconciliation, compensatedStatus.Health = ReconciliationFailed, HealthDegraded
	if expected == 0 { compensatedStatus.Lifecycle = LifecycleDeleted } else { compensatedStatus.Lifecycle = LifecycleQuarantined }
	success := []ObservedResource{{Kind: envelope.Kind, ID: envelope.Metadata.ID, Generation: envelope.Metadata.Generation, Status: successStatus}}
	compensated := []ObservedResource{{Kind: envelope.Kind, ID: envelope.Metadata.ID, Generation: envelope.Metadata.Generation, Status: compensatedStatus}}
	return []ResourceMutation{mutation}, success, compensated, request, nil
}

// compensationPlan records the exact control-state mutation that must follow
// a proven rejection or compensation. Existing intent is restored at a new
// generation to avoid ABA; failed creates become tombstones and release their
// physical-name reservation.
func (coordinator Coordinator) compensationPlan(ctx context.Context, mutations []ResourceMutation) ([]ResourceMutation, []ObservedResource, error) {
	rollback := make([]ResourceMutation, 0, len(mutations))
	observed := make([]ObservedResource, 0, len(mutations))
	for _, mutation := range mutations {
		if mutation.Kind != MutationUpsert || mutation.Resource.Metadata.ID.IsZero() || mutation.Resource.Metadata.Generation == 0 {
			return nil, nil, ErrInvalidResource
		}

		var base Resource
		var err error
		if mutation.ExpectedGeneration == 0 {
			base, err = DecodeResource(mutation.Resource)
		} else {
			var previous ResourceEnvelope
			previous, err = coordinator.repository.LoadResource(ctx, mutation.Resource.Kind, mutation.Resource.Metadata.ID)
			if err == nil && previous.Metadata.Generation != mutation.ExpectedGeneration { err = ErrConflict }
			if err == nil { base, err = DecodeResource(previous) }
		}
		if err != nil { return nil, nil, err }

		generation := mutation.Resource.Metadata.Generation + 1
		status := base.Meta().Status
		status.ObservedGeneration = generation
		status.ProofDigest = ""
		status.MessageCode = ""
		status.Reconciliation = ReconciliationInSync
		if mutation.ExpectedGeneration == 0 {
			status.Lifecycle, status.Health = LifecycleDeleted, HealthUnknown
		}
		rewritten, err := rewriteResource(base, generation, status)
		if err != nil { return nil, nil, err }
		envelope, err := EncodeResource(rewritten)
		if err != nil { return nil, nil, err }
		if mutation.ExpectedGeneration == 0 { envelope.PhysicalName = "" }
		rollback = append(rollback, ResourceMutation{
			Kind: MutationUpsert, ExpectedGeneration: mutation.Resource.Metadata.Generation, Resource: envelope,
		})
		observed = append(observed, ObservedResource{
			Kind: envelope.Kind, ID: envelope.Metadata.ID, Generation: generation, Status: status,
		})
	}
	return rollback, observed, nil
}

func rewriteResource(resource Resource, generation uint64, status ResourceStatus) (Resource, error) {
	metadata := resource.Meta()
	metadata.Generation, metadata.Status = generation, status
	switch value := resource.(type) {
	case *DatabaseInstance:
		copy := *value; copy.Metadata = metadata; return copy, nil
	case *Database:
		copy := *value; copy.Metadata = metadata; return copy, nil
	case *DatabasePrincipal:
		copy := *value; copy.Metadata = metadata; return copy, nil
	case *GrantSet:
		copy := *value; copy.Metadata = metadata; return copy, nil
	case *NetworkAccessPolicy:
		copy := *value; copy.Metadata = metadata; return copy, nil
	case *DatabaseWorkspaceSession:
		copy := *value; copy.Metadata = metadata; return copy, nil
	case *TuningProfile:
		copy := *value; copy.Metadata = metadata; return copy, nil
	case *DatabaseUpgrade:
		copy := *value; copy.Metadata = metadata; return copy, nil
	default:
		return nil, ErrInvalidResource
	}
}

func (coordinator Coordinator) loadInstance(ctx context.Context, id ResourceID) (DatabaseInstance, error) {
	envelope, err := coordinator.repository.LoadResource(ctx, KindDatabaseInstance, id)
	if err != nil { return DatabaseInstance{}, err }
	decoded, err := DecodeResource(envelope)
	if err != nil { return DatabaseInstance{}, err }
	instance, ok := decoded.(*DatabaseInstance)
	if !ok || instance.Status.Lifecycle != LifecycleReady || instance.Status.Reconciliation != ReconciliationInSync { return DatabaseInstance{}, ErrConflict }
	return *instance, nil
}

func (coordinator Coordinator) loadDatabase(ctx context.Context, id ResourceID, tenantID interface{ String() string }) (Database, error) {
	envelope, err := coordinator.repository.LoadResource(ctx, KindDatabase, id)
	if err != nil { return Database{}, err }
	decoded, err := DecodeResource(envelope)
	if err != nil { return Database{}, err }
	database, ok := decoded.(*Database)
	if !ok || database.TenantID.String() != tenantID.String() { return Database{}, ErrUnauthorized }
	if database.Status.Lifecycle == LifecycleDeleting || database.Status.Lifecycle == LifecycleDeleted { return Database{}, ErrConflict }
	return *database, nil
}

func (coordinator Coordinator) loadPrincipal(ctx context.Context, id ResourceID, tenantID interface{ String() string }) (DatabasePrincipal, error) {
	envelope, err := coordinator.repository.LoadResource(ctx, KindPrincipal, id)
	if err != nil { return DatabasePrincipal{}, err }
	decoded, err := DecodeResource(envelope)
	if err != nil { return DatabasePrincipal{}, err }
	principal, ok := decoded.(*DatabasePrincipal)
	if !ok || principal.TenantID.String() != tenantID.String() { return DatabasePrincipal{}, ErrUnauthorized }
	if principal.Status.Lifecycle == LifecycleDeleting || principal.Status.Lifecycle == LifecycleDeleted { return DatabasePrincipal{}, ErrConflict }
	return *principal, nil
}

func (coordinator Coordinator) validateGrantOwners(ctx context.Context, grantSet GrantSet, tenantID interface{ String() string }) error {
	database, err := coordinator.loadDatabase(ctx, grantSet.DatabaseID, tenantID)
	if err != nil { return err }
	principal, err := coordinator.loadPrincipal(ctx, grantSet.PrincipalID, tenantID)
	if err != nil { return err }
	if database.InstanceID != grantSet.InstanceID || principal.InstanceID != grantSet.InstanceID || database.SiteID != grantSet.SiteID || principal.SiteID != grantSet.SiteID {
		return ErrUnauthorized
	}
	return nil
}

func validateStoredOperation(receipt OperationReceipt, commandID, digest string, scope OperationScope) error {
	if receipt.CommandID != commandID || receipt.CommandDigest != digest || receipt.Scope != scope || validateEffectRequest(receipt.Request) != nil ||
		len(receipt.Mutations) == 0 || len(receipt.Rollback) != len(receipt.Mutations) || len(receipt.Success) == 0 || len(receipt.Compensated) == 0 {
		return ErrInvalidReceipt
	}
	for index := range receipt.Mutations {
		if !validRollbackPair(receipt.Mutations[index], receipt.Rollback[index]) { return ErrInvalidReceipt }
	}
	switch receipt.Status {
	case OperationAccepted, OperationAmbiguous:
		return nil
	case OperationApplied:
		if !effectReceiptMatches(receipt.Request, receipt.Effect) || receipt.Effect.Outcome != EffectConfirmed { return ErrInvalidReceipt }
	case OperationRejected:
		if !effectReceiptMatches(receipt.Request, receipt.Effect) || receipt.Effect.Outcome != EffectRejected || receipt.Effect.MutationObserved { return ErrInvalidReceipt }
	case OperationCompensated:
		request := CompensationRequest{EffectID: receipt.Effect.EffectID, RequestDigest: receipt.Effect.RequestDigest, Scope: receipt.Scope,
			CompensationToken: receipt.Effect.CompensationToken, FailureCode: receipt.Effect.FailureCode}
		if !effectReceiptMatches(receipt.Request, receipt.Effect) || !compensationReceiptMatches(request, receipt.Compensation) || receipt.Compensation.Outcome != EffectConfirmed { return ErrInvalidReceipt }
	default:
		return ErrInvalidReceipt
	}
	return nil
}

func terminalOperation(status OperationStatus) bool {
	return status == OperationApplied || status == OperationCompensated || status == OperationRejected
}

func pendingStatus(lifecycle Lifecycle) ResourceStatus {
	return ResourceStatus{Lifecycle: lifecycle, Health: HealthUnknown, Reconciliation: ReconciliationPending}
}

func readyStatus(generation uint64) ResourceStatus {
	return ResourceStatus{Lifecycle: LifecycleReady, Health: HealthHealthy, Reconciliation: ReconciliationInSync, ObservedGeneration: generation}
}

// SystemClock is the production wall clock. It is deliberately tiny so tests
// and replay tools can supply a deterministic clock without global state.
type SystemClock struct{}
func (SystemClock) Now() time.Time { return time.Now() }
