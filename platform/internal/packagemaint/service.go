package packagemaint

import (
	"context"
	"errors"
	"time"
)

type AuthorizationBoundary string

const (
	BoundaryAcceptance AuthorizationBoundary = "package_maintenance_acceptance"
	BoundaryCommit     AuthorizationBoundary = "package_maintenance_commit"
	MaintenanceExecutionDuration              = 30 * time.Minute
)

type AuthorizationRequest struct {
	Boundary          AuthorizationBoundary `json:"boundary"`
	OperationID       string                `json:"operation_id"`
	ActorID           string                `json:"actor_id"`
	Scope             string                `json:"scope"`
	PlanID            string                `json:"plan_id"`
	PlanDigest        string                `json:"plan_digest"`
	PlanGeneration    uint64                `json:"plan_generation"`
	MinimumAssurance  Assurance             `json:"minimum_assurance"`
	Irreversible      bool                  `json:"irreversible"`
	RequestDigest     string                `json:"request_digest"`
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (AuthorizationEvidence, error)
}

type MaintenanceStore interface {
	LatestInventory(context.Context, string, Manager) (InventorySnapshot, error)
	Plan(context.Context, string) (MaintenancePlan, error)
	LatestPlan(context.Context, string, Manager) (MaintenancePlan, error)
	Admit(context.Context, MaintenanceOperation, AuditRecord) (MaintenanceOperation, error)
	Operation(context.Context, string) (MaintenanceOperation, error)
	Transition(context.Context, string, uint64, OperationState, OperationState, AuthorizationEvidence, ExecutionReceipt, AuditRecord) (MaintenanceOperation, error)
}

type ExecutionRequest struct {
	EffectID                 string
	Plan                     MaintenancePlan
	Inventory                InventorySnapshot
	ExpectedPlanGeneration   uint64
	ExpectedInventoryGeneration uint64
	ExpectedInventoryDigest  string
	Fence                    uint64
	Authorization            AuthorizationEvidence
}

type MaintenanceExecutor interface {
	Apply(context.Context, ExecutionRequest) (ExecutionReceipt, error)
}

type MaintenanceAdmissionRequest struct {
	RequestID        string
	OccurrenceID     string
	NodeID           string
	Manager          Manager
	ExpectedDuration time.Duration
	At               time.Time
}

type MaintenanceGate interface {
	AdmitPackageMaintenance(context.Context, MaintenanceAdmissionRequest) error
}

type RebootRequirementPublication struct {
	RequirementID string
	EvidenceDigest string
}

// RebootRequirementPublisher is deliberately passive: it observes the current
// boot identity and idempotently persists evidence, but cannot schedule or
// execute a reboot.
type RebootRequirementPublisher interface {
	CurrentBootIdentity(context.Context, string) (RebootBootIdentity, error)
	PublishRebootRequirement(context.Context, RebootRequirement) (RebootRequirementPublication, error)
}

type AdmissionRequest struct {
	OperationID            string
	PlanID                 string
	MaintenanceOccurrenceID string
	ActorID                string
	Fence                  uint64
}

type Service struct {
	Store      MaintenanceStore
	Authorizer Authorizer
	Executor   MaintenanceExecutor
	Maintenance MaintenanceGate
	RebootRequirements RebootRequirementPublisher
	Now        func() time.Time
}

func (service Service) AdmitMaintenance(ctx context.Context, request MaintenanceAdmissionRequest) error {
	if ctx == nil || service.Maintenance == nil || !safeID.MatchString(request.RequestID) || !safeID.MatchString(request.OccurrenceID) ||
		!safeID.MatchString(request.NodeID) || !validManager(request.Manager) || request.ExpectedDuration != MaintenanceExecutionDuration ||
		request.At.IsZero() || request.At.Location() != time.UTC {
		return ErrInvalid
	}
	if err := service.Maintenance.AdmitPackageMaintenance(ctx, request); err != nil {
		return ErrUnauthorized
	}
	return nil
}

func (service Service) Admit(ctx context.Context, request AdmissionRequest) (MaintenanceOperation, error) {
	if service.Store == nil || service.Authorizer == nil || service.Maintenance == nil || !safeID.MatchString(request.OperationID) || !safeID.MatchString(request.PlanID) || !safeID.MatchString(request.MaintenanceOccurrenceID) || !safeID.MatchString(request.ActorID) || request.Fence == 0 {
		return MaintenanceOperation{}, ErrInvalid
	}
	now := service.now()
	plan, inventory, err := service.currentInputs(ctx, request.PlanID, now)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if request.MaintenanceOccurrenceID != plan.MaintenanceOccurrenceID {
		return MaintenanceOperation{}, ErrUnauthorized
	}
	if err = service.AdmitMaintenance(ctx, MaintenanceAdmissionRequest{RequestID: "pkgmw_" + digestStrings("admit", request.OperationID, plan.MaintenanceOccurrenceID)[:32],
		OccurrenceID: plan.MaintenanceOccurrenceID, NodeID: plan.NodeID, Manager: plan.Manager,
		ExpectedDuration: MaintenanceExecutionDuration, At: now}); err != nil {
		return MaintenanceOperation{}, err
	}
	scope := "package-maintenance:accept:" + plan.ID
	authorizationRequest := AuthorizationRequest{
		Boundary:         BoundaryAcceptance,
		OperationID:      request.OperationID,
		ActorID:          request.ActorID,
		Scope:            scope,
		PlanID:           plan.ID,
		PlanDigest:       plan.Digest,
		PlanGeneration:   plan.Generation,
		MinimumAssurance: AssuranceMFA,
		Irreversible:     plan.Frontier.RecoveryInvalidAfter,
	}
	authorizationRequest.RequestDigest, err = canonicalDigest(authorizationRequest)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	evidence, err := service.Authorizer.Authorize(ctx, authorizationRequest)
	if err != nil {
		return MaintenanceOperation{}, ErrUnauthorized
	}
	if evidence.Scope != scope || evidence.ActorID != request.ActorID || evidence.RequestDigest != authorizationRequest.RequestDigest || evidence.Validate(AssuranceMFA, now) != nil {
		return MaintenanceOperation{}, ErrUnauthorized
	}
	operation := MaintenanceOperation{
		ID:                      request.OperationID,
		PlanID:                  plan.ID,
		PlanDigest:              plan.Digest,
		PlanGeneration:          plan.Generation,
		InventoryGeneration:     inventory.Generation,
		InventoryDigest:         inventory.ContentDigest,
		State:                   OperationAdmitted,
		Generation:              1,
		Fence:                   request.Fence,
		AcceptanceAuthorization: evidence,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	audit := makeAudit(operation.ID, operation.Generation, request.ActorID, "accept", "admitted", authorizationRequest.RequestDigest, evidence.Digest, now)
	return service.Store.Admit(ctx, operation, audit)
}

func (service Service) Apply(ctx context.Context, operationID, actorID string) (MaintenanceOperation, error) {
	if service.Store == nil || service.Authorizer == nil || service.Executor == nil || service.Maintenance == nil || !safeID.MatchString(operationID) || !safeID.MatchString(actorID) {
		return MaintenanceOperation{}, ErrInvalid
	}
	now := service.now()
	operation, err := service.Store.Operation(ctx, operationID)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if operation.State != OperationAdmitted {
		return MaintenanceOperation{}, ErrConflict
	}
	plan, inventory, err := service.currentInputs(ctx, operation.PlanID, now)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if plan.Digest != operation.PlanDigest || plan.Generation != operation.PlanGeneration {
		return MaintenanceOperation{}, ErrStalePlan
	}
	if inventory.Generation != operation.InventoryGeneration || inventory.ContentDigest != operation.InventoryDigest {
		return MaintenanceOperation{}, ErrStaleInventory
	}
	rebootBoot, err := service.rebootBootIdentity(ctx, plan)
	if err != nil {
		return operation, err
	}
	maintenanceErr := service.AdmitMaintenance(ctx, MaintenanceAdmissionRequest{RequestID: "pkgmw_" + digestStrings("apply", operation.ID, plan.MaintenanceOccurrenceID)[:32],
		OccurrenceID: plan.MaintenanceOccurrenceID, NodeID: plan.NodeID, Manager: plan.Manager,
		ExpectedDuration: MaintenanceExecutionDuration, At: now})
	if maintenanceErr != nil {
		evidence := digestStrings(operation.ID, plan.MaintenanceOccurrenceID, "maintenance-denied")
		failed, transitionErr := service.Store.Transition(ctx, operation.ID, operation.Generation, OperationAdmitted, OperationFailed,
			AuthorizationEvidence{}, ExecutionReceipt{}, makeAudit(operation.ID, operation.Generation+1, actorID,
				"maintenance-admission", "denied", plan.Digest, evidence, now))
		if transitionErr != nil {
			return MaintenanceOperation{}, transitionErr
		}
		return failed, maintenanceErr
	}
	scope := "package-maintenance:commit:" + plan.ID
	authorizationRequest := AuthorizationRequest{
		Boundary:         BoundaryCommit,
		OperationID:      operation.ID,
		ActorID:          actorID,
		Scope:            scope,
		PlanID:           plan.ID,
		PlanDigest:       plan.Digest,
		PlanGeneration:   plan.Generation,
		MinimumAssurance: AssurancePhishingResistant,
		Irreversible:     true,
	}
	authorizationRequest.RequestDigest, err = canonicalDigest(authorizationRequest)
	if err != nil {
		return MaintenanceOperation{}, err
	}
	commit, err := service.Authorizer.Authorize(ctx, authorizationRequest)
	if err != nil {
		return MaintenanceOperation{}, ErrUnauthorized
	}
	if commit.Scope != scope || commit.ActorID != actorID || commit.RequestDigest != authorizationRequest.RequestDigest || commit.Validate(AssurancePhishingResistant, now) != nil {
		return MaintenanceOperation{}, ErrUnauthorized
	}
	operation, err = service.Store.Transition(ctx, operation.ID, operation.Generation, OperationAdmitted, OperationAuthorized, commit, ExecutionReceipt{}, makeAudit(operation.ID, operation.Generation+1, actorID, "commit-authorize", "authorized", authorizationRequest.RequestDigest, commit.Digest, now))
	if err != nil {
		return MaintenanceOperation{}, err
	}
	operation, err = service.Store.Transition(ctx, operation.ID, operation.Generation, OperationAuthorized, OperationRunning, AuthorizationEvidence{}, ExecutionReceipt{}, makeAudit(operation.ID, operation.Generation+1, actorID, "execute", "started", plan.Digest, commit.Digest, service.now()))
	if err != nil {
		return MaintenanceOperation{}, err
	}
	receipt, executionErr := service.Executor.Apply(ctx, ExecutionRequest{
		EffectID:                    operation.ID,
		Plan:                        plan,
		Inventory:                   inventory,
		ExpectedPlanGeneration:      operation.PlanGeneration,
		ExpectedInventoryGeneration: operation.InventoryGeneration,
		ExpectedInventoryDigest:     operation.InventoryDigest,
		Fence:                       operation.Fence,
		Authorization:               commit,
	})
	if receipt.EffectID == "" {
		failureDigest := digestStrings(operation.ID, "preflight-failed")
		operation, transitionErr := service.Store.Transition(ctx, operation.ID, operation.Generation, OperationRunning, OperationFailed, AuthorizationEvidence{}, ExecutionReceipt{}, makeAudit(operation.ID, operation.Generation+1, actorID, "execute", "failed-before-effect", plan.Digest, failureDigest, service.now()))
		if transitionErr != nil {
			return MaintenanceOperation{}, transitionErr
		}
		if executionErr == nil {
			executionErr = ErrAmbiguous
		}
		return operation, normalizeExecutionError(executionErr)
	}
	if validateExecutionReceipt(receipt, operation, plan, commit) != nil {
		return operation, ErrAmbiguous
	}
	operation, err = service.Store.Transition(ctx, operation.ID, operation.Generation, OperationRunning, OperationVerifying, AuthorizationEvidence{}, receipt, makeAudit(operation.ID, operation.Generation+1, actorID, "verify", "observed", plan.Digest, receipt.EvidenceDigest, service.now()))
	if err != nil {
		return MaintenanceOperation{}, err
	}
	target := operationStateForOutcome(receipt.Outcome)
	if executionErr != nil && target == OperationSucceeded {
		return operation, ErrAmbiguous
	}
	if target == OperationSucceeded {
		if err = service.publishRebootRequirement(ctx, plan, receipt, rebootBoot); err != nil {
			return operation, err
		}
	}
	operation, err = service.Store.Transition(ctx, operation.ID, operation.Generation, OperationVerifying, target, AuthorizationEvidence{}, receipt, makeAudit(operation.ID, operation.Generation+1, actorID, "complete", string(receipt.Outcome), plan.Digest, receipt.EvidenceDigest, service.now()))
	if err != nil {
		return MaintenanceOperation{}, err
	}
	if executionErr != nil {
		return operation, normalizeExecutionError(executionErr)
	}
	if target != OperationSucceeded && target != OperationRecovered {
		return operation, ErrRecoveryRequired
	}
	return operation, nil
}

func (service Service) rebootBootIdentity(ctx context.Context, plan MaintenancePlan) (RebootBootIdentity, error) {
	if plan.Reboot != RebootRequired {
		return RebootBootIdentity{}, nil
	}
	if service.RebootRequirements == nil {
		return RebootBootIdentity{}, ErrUnsupported
	}
	identity, err := service.RebootRequirements.CurrentBootIdentity(ctx, plan.NodeID)
	if err != nil || identity.Validate() != nil {
		return RebootBootIdentity{}, ErrUnsupported
	}
	return identity, nil
}

func (service Service) publishRebootRequirement(ctx context.Context, plan MaintenancePlan, receipt ExecutionReceipt,
	boot RebootBootIdentity) error {
	if plan.Reboot != RebootRequired || receipt.Outcome != OutcomeConfirmed {
		return nil
	}
	requirement, err := CanonicalRebootRequirement(RebootRequirement{ID: receipt.EffectID, NodeID: plan.NodeID,
		PackageOperationID: receipt.EffectID, PackagePlanID: plan.ID, PackagePlanDigest: plan.Digest,
		PackageReceiptDigest: receipt.EvidenceDigest, MaintenanceOccurrenceID: plan.MaintenanceOccurrenceID,
		Reboot: plan.Reboot, CurrentBoot: RebootBootEvidence{RebootBootIdentity: boot, ObservedAt: receipt.ObservedAt,
			EvidenceDigest: digestStrings("package-maintenance-boot", boot.BootID, boot.KernelRelease, boot.KernelDigest)},
		AffectedServices: plan.Services, AffectedPackages: plan.Changes, ObservedAt: receipt.ObservedAt})
	if err != nil {
		return err
	}
	publication, err := service.RebootRequirements.PublishRebootRequirement(ctx, requirement)
	if err != nil || publication.RequirementID != requirement.ID || publication.EvidenceDigest != requirement.Digest {
		return ErrConflict
	}
	return nil
}

func (service Service) currentInputs(ctx context.Context, planID string, now time.Time) (MaintenancePlan, InventorySnapshot, error) {
	plan, err := service.Store.Plan(ctx, planID)
	if err != nil {
		return MaintenancePlan{}, InventorySnapshot{}, err
	}
	if !now.Before(plan.ExpiresAt) {
		return MaintenancePlan{}, InventorySnapshot{}, ErrStalePlan
	}
	if plan.CreatedAt.After(now.Add(time.Minute)) {
		return MaintenancePlan{}, InventorySnapshot{}, ErrStalePlan
	}
	latestPlan, err := service.Store.LatestPlan(ctx, plan.NodeID, plan.Manager)
	if err != nil {
		return MaintenancePlan{}, InventorySnapshot{}, err
	}
	if latestPlan.ID != plan.ID || latestPlan.Generation != plan.Generation || latestPlan.Digest != plan.Digest {
		return MaintenancePlan{}, InventorySnapshot{}, ErrStalePlan
	}
	inventory, err := service.Store.LatestInventory(ctx, plan.NodeID, plan.Manager)
	if err != nil {
		return MaintenancePlan{}, InventorySnapshot{}, err
	}
	if inventory.ID != plan.InventoryID || inventory.Generation != plan.InventoryGeneration || inventory.ContentDigest != plan.InventoryDigest {
		return MaintenancePlan{}, InventorySnapshot{}, ErrStaleInventory
	}
	return plan, inventory, nil
}

func (service Service) now() time.Time {
	if service.Now != nil {
		return service.Now().UTC()
	}
	return time.Now().UTC()
}

func validateOperation(value MaintenanceOperation) error {
	if !safeID.MatchString(value.ID) || !safeID.MatchString(value.PlanID) || !validDigest(value.PlanDigest) || value.PlanGeneration == 0 || value.InventoryGeneration == 0 || !validDigest(value.InventoryDigest) || !validOperationState(value.State) || value.Generation == 0 || value.Fence == 0 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) || validateEvidenceStored(value.AcceptanceAuthorization, AssuranceMFA) != nil || value.AcceptanceAuthorization.Scope != "package-maintenance:accept:"+value.PlanID {
		return ErrInvalid
	}
	requiresCommit := value.State == OperationAuthorized || value.State == OperationRunning || value.State == OperationVerifying || value.State == OperationSucceeded || value.State == OperationRecoveryRequired || value.State == OperationRecovered || value.State == OperationFailed && value.CommitAuthorization.DecisionID != ""
	if requiresCommit && (validateEvidenceStored(value.CommitAuthorization, AssurancePhishingResistant) != nil || value.CommitAuthorization.Scope != "package-maintenance:commit:"+value.PlanID) {
		return ErrInvalid
	}
	receiptRequired := value.State == OperationVerifying || value.State == OperationSucceeded || value.State == OperationRecoveryRequired || value.State == OperationRecovered
	if receiptRequired && value.Receipt.EffectID == "" {
		return ErrInvalid
	}
	if value.Receipt.EffectID != "" && (value.Receipt.EffectID != value.ID || value.Receipt.PlanID != value.PlanID || value.Receipt.PlanDigest != value.PlanDigest || value.Receipt.InventoryGeneration != value.InventoryGeneration || value.Receipt.BeforeInventoryDigest != value.InventoryDigest || value.Receipt.Fence != value.Fence || value.Receipt.AuthorizationDigest != value.CommitAuthorization.Digest || !validReceiptStructure(value.Receipt)) {
		return ErrInvalid
	}
	if value.State == OperationSucceeded && value.Receipt.Outcome != OutcomeConfirmed || value.State == OperationRecovered && value.Receipt.Outcome != OutcomeRecovered || value.State == OperationRecoveryRequired && value.Receipt.Outcome != OutcomeRecoveryRequired && value.Receipt.Outcome != OutcomeAmbiguous || value.State == OperationFailed && value.Receipt.EffectID != "" && value.Receipt.Outcome != OutcomeFailed {
		return ErrInvalid
	}
	if terminalOperation(value.State) && value.CompletedAt.IsZero() || !value.CompletedAt.IsZero() && value.CompletedAt.Before(value.CreatedAt) {
		return ErrInvalid
	}
	return nil
}

func validateEvidenceStored(value AuthorizationEvidence, minimum Assurance) error {
	if !safeID.MatchString(value.DecisionID) || !safeID.MatchString(value.ActorID) || !safeID.MatchString(value.Scope) || !validDigest(value.RequestDigest) || !validDigest(value.PolicyDigest) || value.AuthorizationEpoch == 0 || value.GrantID != "" && !safeID.MatchString(value.GrantID) || value.GrantedAt.IsZero() || !value.ExpiresAt.After(value.GrantedAt) || value.ExpiresAt.Sub(value.GrantedAt) > 15*time.Minute || !validDigest(value.Digest) || assuranceRank(value.Assurance) < assuranceRank(minimum) {
		return ErrUnauthorized
	}
	copyOfValue := value
	copyOfValue.Digest = ""
	digest, err := canonicalDigest(copyOfValue)
	if err != nil || digest != value.Digest {
		return ErrUnauthorized
	}
	return nil
}

func validateAudit(value AuditRecord, operationID string) error {
	if !safeID.MatchString(value.ID) || value.OperationID != operationID || !safeID.MatchString(value.ActorID) || !safeID.MatchString(value.Action) || !safeID.MatchString(value.Outcome) || !validDigest(value.RequestDigest) || !validDigest(value.EvidenceDigest) || value.ObservedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

func makeAudit(operationID string, generation uint64, actorID, action, outcome, requestDigest, evidenceDigest string, now time.Time) AuditRecord {
	identity := digestStrings(operationID, action, outcome, requestDigest, evidenceDigest, now.UTC().Format(timeLayout))
	return AuditRecord{
		ID:             "audit_" + identity[:32],
		OperationID:    operationID,
		ActorID:        actorID,
		Action:         action,
		Outcome:        outcome,
		RequestDigest:  requestDigest,
		EvidenceDigest: evidenceDigest,
		ObservedAt:     now.UTC(),
	}
}

func validateExecutionReceipt(receipt ExecutionReceipt, operation MaintenanceOperation, plan MaintenancePlan, authorization AuthorizationEvidence) error {
	if !validReceiptStructure(receipt) || receipt.EffectID != operation.ID || receipt.PlanID != plan.ID || receipt.PlanDigest != plan.Digest || receipt.InventoryGeneration != operation.InventoryGeneration || receipt.BeforeInventoryDigest != operation.InventoryDigest || receipt.Fence != operation.Fence || receipt.AuthorizationDigest != authorization.Digest {
		return ErrInvalid
	}
	return nil
}

func validReceiptStructure(receipt ExecutionReceipt) bool {
	if !safeID.MatchString(receipt.EffectID) || !safeID.MatchString(receipt.PlanID) || !validDigest(receipt.PlanDigest) || receipt.InventoryGeneration == 0 || !validDigest(receipt.BeforeInventoryDigest) || receipt.AfterInventoryDigest != "" && !validDigest(receipt.AfterInventoryDigest) || receipt.Fence == 0 || !validDigest(receipt.AuthorizationDigest) || !validOutcome(receipt.Outcome) || len(receipt.Commands) > MaximumChanges+8 || !validDigest(receipt.EvidenceDigest) || receipt.ObservedAt.IsZero() {
		return false
	}
	if receipt.IrreversibleCrossed && len(receipt.Commands) == 0 || receipt.Outcome == OutcomeConfirmed && (len(receipt.Commands) == 0 || receipt.AfterInventoryDigest == "") || receipt.Outcome == OutcomeRecovered && receipt.AfterInventoryDigest == "" {
		return false
	}
	if receipt.Outcome == OutcomeRecovered && (!receipt.Recovery.Attempted || !receipt.Recovery.Restored) {
		return false
	}
	for _, command := range receipt.Commands {
		if !allowedReceiptExecutable(command.Executable) || !validDigest(command.ArgvDigest) || !validDigest(command.OutputDigest) || command.StartedAt.IsZero() || command.CompletedAt.Before(command.StartedAt) || command.ExitCode < -1 || command.ExitCode > 255 {
			return false
		}
	}
	if receipt.Snapshot.SnapshotID != "" && (receipt.Snapshot.Kind != RecoveryFilesystem && receipt.Snapshot.Kind != RecoveryProvider || !safeID.MatchString(receipt.Snapshot.SnapshotID) || !validDigest(receipt.Snapshot.ScopeDigest) || !validDigest(receipt.Snapshot.Digest) || receipt.Snapshot.CreatedAt.IsZero()) {
		return false
	}
	if len(receipt.ObservedPackages) > MaximumChanges || len(receipt.ServiceProbes) > MaximumServiceImpacts || len(receipt.Recovery.Instructions) > 32 {
		return false
	}
	for _, observed := range receipt.ObservedPackages {
		if !safePackage.MatchString(observed.Name) || !safeArchitecture.MatchString(observed.Architecture) || observed.Version != "" && !safeVersion.MatchString(observed.Version) || observed.Present && observed.Version == "" {
			return false
		}
	}
	for _, probe := range receipt.ServiceProbes {
		if !safeID.MatchString(probe.ServiceID) || !safeID.MatchString(probe.ProbeID) || !validDigest(probe.EvidenceDigest) || probe.ObservedAt.IsZero() {
			return false
		}
	}
	if receipt.Recovery.Attempted && (!safeID.MatchString(receipt.Recovery.SnapshotID) || !validDigest(receipt.Recovery.EvidenceDigest) || receipt.Recovery.ObservedAt.IsZero()) {
		return false
	}
	for _, instruction := range receipt.Recovery.Instructions {
		if !safeID.MatchString(instruction) {
			return false
		}
	}
	copyOfReceipt := receipt
	copyOfReceipt.EvidenceDigest = ""
	digest, err := canonicalDigest(copyOfReceipt)
	return err == nil && digest == receipt.EvidenceDigest
}

func normalizeExecutionError(err error) error {
	for _, known := range []error{ErrInvalid, ErrConflict, ErrStaleInventory, ErrStalePlan, ErrUnauthorized, ErrUnsupported, ErrLocked, ErrRecoveryRequired, ErrAmbiguous} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrAmbiguous
}

func allowedReceiptExecutable(value string) bool {
	switch value {
	case "/usr/bin/apt-get", "/usr/bin/dnf", "/usr/bin/dpkg", "/usr/bin/dpkg-query", "/usr/bin/rpm", "/usr/bin/apt-mark":
		return true
	default:
		return false
	}
}

func validOperationState(value OperationState) bool {
	switch value {
	case OperationAdmitted, OperationAuthorized, OperationRunning, OperationVerifying, OperationSucceeded, OperationFailed, OperationRecoveryRequired, OperationRecovered:
		return true
	default:
		return false
	}
}

func validOutcome(value ExecutionOutcome) bool {
	return value == OutcomeConfirmed || value == OutcomeFailed || value == OutcomeRecovered || value == OutcomeRecoveryRequired || value == OutcomeAmbiguous
}

func operationStateForOutcome(value ExecutionOutcome) OperationState {
	switch value {
	case OutcomeConfirmed:
		return OperationSucceeded
	case OutcomeRecovered:
		return OperationRecovered
	case OutcomeRecoveryRequired, OutcomeAmbiguous:
		return OperationRecoveryRequired
	default:
		return OperationFailed
	}
}
