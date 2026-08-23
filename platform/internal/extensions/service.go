package extensions

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

type Service struct {
	repository Repository
	verifier   *TrustVerifier
	runtime    Runtime
	audit      AuditSink
	now        func() time.Time
}

func NewService(repository Repository, verifier *TrustVerifier, runtime Runtime, audit AuditSink, now func() time.Time) (*Service, error) {
	if repository == nil || verifier == nil || runtime == nil || audit == nil {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &Service{repository: repository, verifier: verifier, runtime: runtime, audit: audit, now: now}, nil
}

func (service *Service) Bootstrap(ctx context.Context) error {
	return service.repository.Bootstrap(ctx)
}

type CommandMeta struct {
	CommandID          CommandID   `json:"command_id"`
	ExtensionID        ExtensionID `json:"extension_id"`
	ExpectedGeneration uint64      `json:"expected_generation"`
	Actor               string      `json:"actor"`
}

func (meta CommandMeta) validate(action LifecycleAction) error {
	if !validID(string(meta.CommandID)) || !validID(string(meta.ExtensionID)) || !validID(meta.Actor) || !validLifecycleAction(action) ||
		action == ActionInstall && meta.ExpectedGeneration != 0 || action != ActionInstall && meta.ExpectedGeneration == 0 {
		return ErrInvalid
	}
	return nil
}

type InstallCommand struct {
	CommandMeta
	Release       ExtensionRelease  `json:"release"`
	Approval      CapabilityApproval `json:"approval"`
	Configuration json.RawMessage    `json:"configuration"`
}

type EnableCommand struct{ CommandMeta }
type SuspendCommand struct{ CommandMeta }
type DisableCommand struct{ CommandMeta }

type ConfigureCommand struct {
	CommandMeta
	Configuration json.RawMessage `json:"configuration"`
}

type UpdateCommand struct {
	CommandMeta
	Release  ExtensionRelease   `json:"release"`
	Approval *CapabilityApproval `json:"approval,omitempty"`
}

type RollbackCommand struct {
	CommandMeta
	Approval *CapabilityApproval `json:"approval,omitempty"`
}

type UninstallCommand struct {
	CommandMeta
	DataPolicy DataPolicy `json:"data_policy"`
}

type PurgeCommand struct {
	CommandMeta
	DataPolicy DataPolicy `json:"data_policy"`
}

func (service *Service) Inspect(ctx context.Context, id ExtensionID) (ExtensionInstallation, error) {
	return service.repository.Load(ctx, id)
}

func (service *Service) List(ctx context.Context, cursor ExtensionID, limit uint16) (InstallationPage, error) {
	return service.repository.List(ctx, cursor, limit)
}

func (service *Service) Install(ctx context.Context, command InstallCommand) (ExtensionInstallation, OperationReceipt, error) {
	return service.mutate(ctx, command.CommandMeta, ActionInstall, command, func(now time.Time) (preparedMutation, error) {
		if command.Release.ExtensionID != command.ExtensionID {
			return preparedMutation{}, ErrInvalid
		}
		if err := service.verifier.Verify(ctx, command.Release); err != nil {
			return preparedMutation{}, err
		}
		if err := command.Approval.Validate(command.Release, now); err != nil {
			return preparedMutation{}, err
		}
		configuration, err := canonicalConfiguration(command.Configuration)
		if err != nil {
			return preparedMutation{}, err
		}
		release := cloneRelease(command.Release)
		next := ExtensionInstallation{
			ID: command.ExtensionID, Current: release, GrantedCapabilities: append([]CapabilityRequest(nil), release.Manifest.Capabilities...),
			Configuration: configuration, ConfigurationDigest: digestBytes(configuration), State: StateInstalled, DataPolicy: DataPreserve,
			Health: HealthObservation{State: HealthUnknown, ObservedAt: now}, Generation: 1, CreatedAt: now, UpdatedAt: now,
		}
		return preparedMutation{next: &next, target: &release}, nil
	})
}

func (service *Service) Enable(ctx context.Context, command EnableCommand) (ExtensionInstallation, OperationReceipt, error) {
	return service.stateMutation(ctx, command.CommandMeta, ActionEnable, command, StateEnabled, StateInstalled, StateDisabled, StateSuspended, StateDegraded)
}

func (service *Service) Suspend(ctx context.Context, command SuspendCommand) (ExtensionInstallation, OperationReceipt, error) {
	return service.stateMutation(ctx, command.CommandMeta, ActionSuspend, command, StateSuspended, StateEnabled, StateDegraded)
}

func (service *Service) Disable(ctx context.Context, command DisableCommand) (ExtensionInstallation, OperationReceipt, error) {
	return service.stateMutation(ctx, command.CommandMeta, ActionDisable, command, StateDisabled, StateInstalled, StateEnabled, StateSuspended, StateDegraded)
}

func (service *Service) Configure(ctx context.Context, command ConfigureCommand) (ExtensionInstallation, OperationReceipt, error) {
	return service.mutate(ctx, command.CommandMeta, ActionConfigure, command, func(now time.Time) (preparedMutation, error) {
		current, err := service.current(ctx, command.CommandMeta)
		if err != nil {
			return preparedMutation{}, err
		}
		if current.State == StateUninstalled {
			return preparedMutation{}, ErrConflict
		}
		configuration, err := canonicalConfiguration(command.Configuration)
		if err != nil {
			return preparedMutation{}, err
		}
		next := cloneInstallation(current)
		next.Configuration = configuration
		next.ConfigurationDigest = digestBytes(configuration)
		next.Generation++
		next.UpdatedAt = now
		return preparedMutation{current: &current, next: &next}, nil
	})
}

func (service *Service) Update(ctx context.Context, command UpdateCommand) (ExtensionInstallation, OperationReceipt, error) {
	return service.mutate(ctx, command.CommandMeta, ActionUpdate, command, func(now time.Time) (preparedMutation, error) {
		current, err := service.current(ctx, command.CommandMeta)
		if err != nil {
			return preparedMutation{}, err
		}
		if current.State == StateUninstalled || command.Release.ExtensionID != current.ID {
			return preparedMutation{}, ErrConflict
		}
		if err := service.verifier.Verify(ctx, command.Release); err != nil {
			return preparedMutation{}, err
		}
		comparison := command.Release.Version.Compare(current.Current.Version)
		if comparison < 0 {
			return preparedMutation{}, ErrDowngrade
		}
		if comparison == 0 {
			return preparedMutation{}, ErrConflict
		}
		if err := requireApproval(current.GrantedCapabilities, command.Release, command.Approval, now); err != nil {
			return preparedMutation{}, err
		}
		target := cloneRelease(command.Release)
		previous := cloneRelease(current.Current)
		next := cloneInstallation(current)
		next.Current = target
		next.Previous = &previous
		next.GrantedCapabilities = append([]CapabilityRequest(nil), target.Manifest.Capabilities...)
		next.Generation++
		next.UpdatedAt = now
		return preparedMutation{current: &current, next: &next, target: &target}, nil
	})
}

func (service *Service) Rollback(ctx context.Context, command RollbackCommand) (ExtensionInstallation, OperationReceipt, error) {
	return service.mutate(ctx, command.CommandMeta, ActionRollback, command, func(now time.Time) (preparedMutation, error) {
		current, err := service.current(ctx, command.CommandMeta)
		if err != nil {
			return preparedMutation{}, err
		}
		if current.State == StateUninstalled || current.Previous == nil {
			return preparedMutation{}, ErrConflict
		}
		target := cloneRelease(*current.Previous)
		if err := service.verifier.Verify(ctx, target); err != nil {
			return preparedMutation{}, err
		}
		if err := requireApproval(current.GrantedCapabilities, target, command.Approval, now); err != nil {
			return preparedMutation{}, err
		}
		previous := cloneRelease(current.Current)
		next := cloneInstallation(current)
		next.Current = target
		next.Previous = &previous
		next.GrantedCapabilities = append([]CapabilityRequest(nil), target.Manifest.Capabilities...)
		next.Generation++
		next.UpdatedAt = now
		return preparedMutation{current: &current, next: &next, target: &target}, nil
	})
}

func (service *Service) Uninstall(ctx context.Context, command UninstallCommand) (ExtensionInstallation, OperationReceipt, error) {
	return service.mutate(ctx, command.CommandMeta, ActionUninstall, command, func(now time.Time) (preparedMutation, error) {
		if command.DataPolicy != DataPreserve && command.DataPolicy != DataDelete {
			return preparedMutation{}, ErrInvalid
		}
		current, err := service.current(ctx, command.CommandMeta)
		if err != nil {
			return preparedMutation{}, err
		}
		if current.State == StateUninstalled {
			return preparedMutation{}, ErrConflict
		}
		next := cloneInstallation(current)
		next.State = StateUninstalled
		next.DataPolicy = command.DataPolicy
		next.UninstalledAt = &now
		next.Generation++
		next.UpdatedAt = now
		return preparedMutation{current: &current, next: &next}, nil
	})
}

func (service *Service) Purge(ctx context.Context, command PurgeCommand) (OperationReceipt, error) {
	_, receipt, err := service.mutate(ctx, command.CommandMeta, ActionPurge, command, func(time.Time) (preparedMutation, error) {
		if command.DataPolicy != DataDelete {
			return preparedMutation{}, ErrForbidden
		}
		current, err := service.current(ctx, command.CommandMeta)
		if err != nil {
			return preparedMutation{}, err
		}
		if current.State != StateUninstalled {
			return preparedMutation{}, ErrConflict
		}
		return preparedMutation{current: &current, purge: true}, nil
	})
	return receipt, err
}

func (service *Service) stateMutation(ctx context.Context, meta CommandMeta, action LifecycleAction, command any, target InstallationState, allowed ...InstallationState) (ExtensionInstallation, OperationReceipt, error) {
	return service.mutate(ctx, meta, action, command, func(now time.Time) (preparedMutation, error) {
		current, err := service.current(ctx, meta)
		if err != nil {
			return preparedMutation{}, err
		}
		permitted := false
		for _, state := range allowed {
			permitted = permitted || current.State == state
		}
		if !permitted {
			return preparedMutation{}, ErrConflict
		}
		next := cloneInstallation(current)
		next.State = target
		next.Generation++
		next.UpdatedAt = now
		return preparedMutation{current: &current, next: &next}, nil
	})
}

type preparedMutation struct {
	current *ExtensionInstallation
	next    *ExtensionInstallation
	target  *ExtensionRelease
	purge   bool
}

type mutationPreparer func(time.Time) (preparedMutation, error)

func (service *Service) mutate(ctx context.Context, meta CommandMeta, action LifecycleAction, command any, prepare mutationPreparer) (ExtensionInstallation, OperationReceipt, error) {
	if err := meta.validate(action); err != nil {
		return ExtensionInstallation{}, OperationReceipt{}, err
	}
	requestDigest := digestJSON(struct {
		Domain  string          `json:"domain"`
		Action  LifecycleAction `json:"action"`
		Command any             `json:"command"`
	}{Domain: "cyberpanel.extension.command.v1", Action: action, Command: command})
	existing, err := service.repository.Receipt(ctx, meta.CommandID, requestDigest)
	if err != nil {
		return ExtensionInstallation{}, OperationReceipt{}, err
	}
	if existing != nil {
		return service.existingResult(ctx, meta.ExtensionID, action, *existing)
	}
	now := service.now().UTC()
	prepared, err := prepare(now)
	if err != nil {
		return ExtensionInstallation{}, OperationReceipt{}, err
	}
	admission := Admission{CommandID: meta.CommandID, RequestDigest: requestDigest, Action: action, ExtensionID: meta.ExtensionID, ExpectedGeneration: meta.ExpectedGeneration, AcceptedAt: now}
	existing, err = service.repository.Admit(ctx, admission)
	if err != nil {
		return ExtensionInstallation{}, OperationReceipt{}, err
	}
	if existing != nil {
		return service.existingResult(ctx, meta.ExtensionID, action, *existing)
	}
	runtimeRequest := runtimeRequestFor(admission, prepared)
	if err := runtimeRequest.Validate(); err != nil {
		return ExtensionInstallation{}, OperationReceipt{}, err
	}
	runtimeReceipt, runtimeErr := service.runtime.Apply(ctx, runtimeRequest)
	if runtimeErr == nil {
		runtimeErr = runtimeReceipt.Validate(runtimeRequest)
	}
	if runtimeErr == nil && prepared.purge && len(runtimeReceipt.RuntimeObjectIDs) != 0 {
		runtimeErr = ErrIntegrity
	}
	if runtimeErr != nil {
		receipt := operationReceipt(admission, runtimeRequest, RuntimeReceipt{}, ReceiptAmbiguous, service.now().UTC())
		if err := service.repository.Complete(ctx, Completion{Admission: admission, Receipt: receipt}); err != nil {
			return ExtensionInstallation{}, OperationReceipt{}, errors.Join(ErrAmbiguous, runtimeErr, err)
		}
		auditErr := service.recordAudit(ctx, meta.Actor, receipt)
		return currentResult(prepared), receipt, errors.Join(ErrAmbiguous, runtimeErr, auditErr)
	}
	if prepared.next != nil {
		prepared.next.RuntimeObjectIDs = append([]string(nil), runtimeReceipt.RuntimeObjectIDs...)
		prepared.next.Health = runtimeReceipt.Health
		if (runtimeReceipt.Health.State == HealthDegraded || runtimeReceipt.Health.State == HealthUnavailable) &&
			prepared.next.State != StateSuspended && prepared.next.State != StateDisabled && prepared.next.State != StateUninstalled {
			prepared.next.State = StateDegraded
		}
		if err := prepared.next.Validate(); err != nil {
			return ExtensionInstallation{}, OperationReceipt{}, err
		}
	}
	receipt := operationReceipt(admission, runtimeRequest, runtimeReceipt, ReceiptApplied, service.now().UTC())
	if err := service.repository.Complete(ctx, Completion{Admission: admission, Next: prepared.next, Purge: prepared.purge, Receipt: receipt}); err != nil {
		return ExtensionInstallation{}, OperationReceipt{}, err
	}
	if err := service.recordAudit(ctx, meta.Actor, receipt); err != nil {
		return currentResult(prepared), receipt, err
	}
	if prepared.next == nil {
		return ExtensionInstallation{}, receipt, nil
	}
	return cloneInstallation(*prepared.next), receipt, nil
}

func runtimeRequestFor(admission Admission, prepared preparedMutation) RuntimeRequest {
	request := RuntimeRequest{CommandID: admission.CommandID, RequestDigest: admission.RequestDigest, Action: admission.Action,
		ExtensionID: admission.ExtensionID, ExpectedGeneration: admission.ExpectedGeneration, ResultGeneration: admission.ExpectedGeneration + 1, DataPolicy: DataPreserve}
	if prepared.current != nil {
		current := cloneRelease(prepared.current.Current)
		request.Current = &current
		request.Capabilities = append([]CapabilityRequest(nil), prepared.current.GrantedCapabilities...)
		request.Configuration = append(json.RawMessage(nil), prepared.current.Configuration...)
		request.ConfigurationDigest = prepared.current.ConfigurationDigest
		request.DataPolicy = prepared.current.DataPolicy
	}
	if prepared.next != nil {
		request.Capabilities = append([]CapabilityRequest(nil), prepared.next.GrantedCapabilities...)
		request.Configuration = append(json.RawMessage(nil), prepared.next.Configuration...)
		request.ConfigurationDigest = prepared.next.ConfigurationDigest
		request.DataPolicy = prepared.next.DataPolicy
	}
	if prepared.target != nil {
		target := cloneRelease(*prepared.target)
		request.Target = &target
	}
	if prepared.purge {
		request.DataPolicy = DataDelete
	}
	return request
}

func operationReceipt(admission Admission, request RuntimeRequest, runtime RuntimeReceipt, outcome ReceiptOutcome, now time.Time) OperationReceipt {
	releaseDigest := ""
	if request.Current != nil {
		releaseDigest = request.Current.Digest
	}
	if request.Target != nil {
		releaseDigest = request.Target.Digest
	}
	receipt := OperationReceipt{CommandID: admission.CommandID, RequestDigest: admission.RequestDigest, Action: admission.Action,
		ExtensionID: admission.ExtensionID, ReleaseDigest: releaseDigest, ExpectedGeneration: admission.ExpectedGeneration,
		ResultGeneration: admission.ExpectedGeneration + 1, Outcome: outcome, RecordedAt: now}
	if outcome == ReceiptApplied {
		receipt.RuntimeEvidence = runtime.EvidenceDigest
		receipt.Health = runtime.Health
	}
	receipt.Digest = digestOperationReceipt(receipt)
	return receipt
}

func (service *Service) recordAudit(ctx context.Context, actor string, receipt OperationReceipt) error {
	after := receipt.ResultGeneration
	if receipt.Outcome == ReceiptAmbiguous {
		after = receipt.ExpectedGeneration
	}
	return service.audit.RecordExtensionEvent(ctx, AuditEvent{ReceiptDigest: receipt.Digest, CommandID: receipt.CommandID, Action: receipt.Action,
		ExtensionID: receipt.ExtensionID, ReleaseDigest: receipt.ReleaseDigest, Before: receipt.ExpectedGeneration, After: after,
		Outcome: receipt.Outcome, Actor: actor, OccurredAt: receipt.RecordedAt})
}

func (service *Service) existingResult(ctx context.Context, id ExtensionID, action LifecycleAction, receipt OperationReceipt) (ExtensionInstallation, OperationReceipt, error) {
	if action == ActionPurge {
		return ExtensionInstallation{}, receipt, nil
	}
	installation, err := service.repository.Load(ctx, id)
	if receipt.Outcome == ReceiptAmbiguous {
		if errors.Is(err, ErrNotFound) {
			return ExtensionInstallation{}, receipt, ErrAmbiguous
		}
		return installation, receipt, errors.Join(ErrAmbiguous, err)
	}
	return installation, receipt, err
}

func currentResult(prepared preparedMutation) ExtensionInstallation {
	if prepared.current == nil {
		return ExtensionInstallation{}
	}
	return cloneInstallation(*prepared.current)
}

func (service *Service) current(ctx context.Context, meta CommandMeta) (ExtensionInstallation, error) {
	current, err := service.repository.Load(ctx, meta.ExtensionID)
	if err != nil {
		return ExtensionInstallation{}, err
	}
	if current.Generation != meta.ExpectedGeneration {
		return ExtensionInstallation{}, ErrStale
	}
	return current, nil
}

func canonicalConfiguration(configuration json.RawMessage) (json.RawMessage, error) {
	if len(configuration) == 0 {
		configuration = json.RawMessage(`{}`)
	}
	configuration = append(json.RawMessage(nil), configuration...)
	if err := validateConfiguration(configuration); err != nil {
		return nil, err
	}
	return configuration, nil
}

func requireApproval(current []CapabilityRequest, target ExtensionRelease, approval *CapabilityApproval, now time.Time) error {
	if !capabilitiesExpanded(current, target.Manifest.Capabilities) {
		if approval == nil {
			return nil
		}
		return approval.Validate(target, now)
	}
	if approval == nil {
		return ErrForbidden
	}
	return approval.Validate(target, now)
}

func (service *Service) DetectOrphans(ctx context.Context) ([]Orphan, error) {
	installations := make(map[ExtensionID]ExtensionInstallation)
	var cursor ExtensionID
	for {
		page, err := service.repository.List(ctx, cursor, 500)
		if err != nil {
			return nil, err
		}
		for _, installation := range page.Installations {
			installations[installation.ID] = installation
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	objects, err := service.runtime.Inventory(ctx)
	if err != nil {
		return nil, err
	}
	orphans := make([]Orphan, 0)
	currentSeen := make(map[ExtensionID]bool)
	objectIDs := make(map[string]struct{}, len(objects))
	for index := range objects {
		object := objects[index]
		if object.Validate() != nil {
			return nil, ErrIntegrity
		}
		if _, exists := objectIDs[object.ID]; exists {
			return nil, ErrIntegrity
		}
		objectIDs[object.ID] = struct{}{}
		installation, owned := installations[object.ExtensionID]
		copy := object
		if !owned || installation.State == StateUninstalled && (installation.DataPolicy != DataPreserve || object.Kind != RuntimeObjectOwnedData) {
			orphans = append(orphans, Orphan{Kind: OrphanUnownedRuntime, ExtensionID: object.ExtensionID, RuntimeObject: &copy, Detail: "runtime object has no active installation"})
			continue
		}
		if object.ReleaseDigest == installation.Current.Digest {
			if object.Kind == RuntimeObjectExecution {
				currentSeen[installation.ID] = true
			}
		} else if installation.Previous == nil || object.ReleaseDigest != installation.Previous.Digest {
			orphans = append(orphans, Orphan{Kind: OrphanStaleRelease, ExtensionID: object.ExtensionID, RuntimeObject: &copy, Detail: "runtime object is not the retained current or previous release"})
		}
		declared := make(map[string]struct{}, len(installation.Current.Manifest.OwnedData))
		for _, class := range installation.Current.Manifest.OwnedData {
			declared[class.Name] = struct{}{}
		}
		for _, class := range object.DataClasses {
			if _, ok := declared[class]; !ok {
				orphans = append(orphans, Orphan{Kind: OrphanUndeclaredData, ExtensionID: object.ExtensionID, RuntimeObject: &copy, Detail: class})
			}
		}
		if installation.State == StateUninstalled {
			continue
		}
	}
	for id, installation := range installations {
		if installation.State != StateUninstalled && !currentSeen[id] {
			orphans = append(orphans, Orphan{Kind: OrphanMissingRuntime, ExtensionID: id, Detail: "no runtime object matches the current release"})
		}
	}
	sort.Slice(orphans, func(i, j int) bool {
		if orphans[i].ExtensionID != orphans[j].ExtensionID {
			return orphans[i].ExtensionID < orphans[j].ExtensionID
		}
		if orphans[i].Kind != orphans[j].Kind {
			return orphans[i].Kind < orphans[j].Kind
		}
		return orphans[i].Detail < orphans[j].Detail
	})
	return orphans, nil
}
