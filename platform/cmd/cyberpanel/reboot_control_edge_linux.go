//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/packagemaint"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// rebootControlLinuxAuthority is the protected assembly boundary. Its plan
// resolver binds an existing maintenance occurrence, current boot evidence,
// step-up authorization, and an independent approval. Preflight proves the
// node may leave its HA writer role at the exact reboot fence. No method takes
// a command, executable, shutdown mode, or caller-selected power operation.
type rebootControlLinuxAuthority interface {
	ResolveRebootPlan(context.Context, rebootControlPlanRequest) (rebootcontrol.Plan, error)
	PreflightReboot(context.Context, rebootControlPreflightRequest) (rebootControlReadiness, error)
	ReleaseBeforeArm(context.Context, rebootControlReleaseRequest) (rebootControlReleaseResult, error)
	ReconcileAmbiguousReboot(context.Context, rebootControlAmbiguousRequest) (rebootControlAmbiguousResult, error)
	CurrentBootIdentity(context.Context, string) (rebootcontrol.BootIdentity, error)
}

type rebootControlPlanRequest struct {
	Call                     apiserver.EdgeCall
	PlanID                   string
	Reason                   rebootcontrol.PlanReason
	MaintenanceOccurrenceID  string
	DrainMode                rebootcontrol.DrainMode
	ExpectedReturn           time.Duration
	PackageOperation         packagemaint.MaintenanceOperation
	PackagePlan              packagemaint.MaintenancePlan
	PackageInventory         packagemaint.InventorySnapshot
	RequestedAt              time.Time
}

type rebootControlPreflightRequest struct {
	Call        apiserver.EdgeCall
	Plan        rebootcontrol.Plan
	State       rebootcontrol.State
	RequestedAt time.Time
}

type rebootControlReadiness struct {
	PlanID                     string
	PlanDigest                 string
	RebootFence                uint64
	MaintenanceOccurrenceDigest string
	ApprovalDigest             string
	WriterAuthorityDigest      string
	MaintenanceAdmissible      bool
	HAWriterSafe               bool
	EvidenceDigest             string
	Blockers                   []string
}

type rebootControlReleaseRequest struct {
	Call        apiserver.EdgeCall
	Plan        rebootcontrol.Plan
	State       rebootcontrol.State
	RequestedAt time.Time
}

type rebootControlReleaseResult struct {
	PlanID            string
	RebootFence       uint64
	DrainReleased     bool
	OperationsResumed bool
	EvidenceDigest    string
}

type rebootControlAmbiguousRequest struct {
	Call        apiserver.EdgeCall
	Plan        rebootcontrol.Plan
	State       rebootcontrol.State
	RequestedAt time.Time
}

// The authority may return Complete only after reconciling all subsystems and
// clearing the exact recovery marker. It must observe; it must not redispatch.
type rebootControlAmbiguousResult struct {
	PlanID                string
	RebootFence           uint64
	MarkerDigest          string
	ActualBoot            rebootcontrol.BootIdentity
	SubsystemsReconciled  bool
	MarkerCleared         bool
	WriterAuthorityDigest string
	EvidenceDigest        string
}

type rebootControlLinuxEdge struct {
	coordinator *rebootcontrol.Coordinator
	repository  *rebootcontrol.Repository
	packages    *packagemaint.SQLRepository
	authority   rebootControlLinuxAuthority
	nodeID      string
	controllerID string
	manager     packagemaint.Manager
	now         func() time.Time
}

func newRebootControlLinuxEdge(coordinator *rebootcontrol.Coordinator, repository *rebootcontrol.Repository,
	packages *packagemaint.SQLRepository, authority rebootControlLinuxAuthority, nodeID, controllerID string,
	manager packagemaint.Manager, now func() time.Time) (*rebootControlLinuxEdge, error) {
	if coordinator == nil || repository == nil || packages == nil || authority == nil ||
		!validRebootControlRuntimeID(nodeID) || !validRebootControlRuntimeID(controllerID) ||
		manager != packagemaint.ManagerAPT && manager != packagemaint.ManagerDNF {
		return nil, rebootcontrol.ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &rebootControlLinuxEdge{coordinator: coordinator, repository: repository, packages: packages,
		authority: authority, nodeID: nodeID, controllerID: controllerID, manager: manager, now: now}, nil
}

func (edge *rebootControlLinuxEdge) RebootControlCapabilities() apiserver.RebootControlEdgeCapabilities {
	if edge == nil {
		return apiserver.RebootControlEdgeCapabilities{}
	}
	return apiserver.RebootControlEdgeCapabilities{List: true, Schedule: true, Execute: true, Cancel: true, Reconcile: true}
}

func (edge *rebootControlLinuxEdge) ListRebootControls(ctx context.Context, call apiserver.EdgeCall,
	payload apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.RebootControlProjection], error) {
	if edge == nil || ctx == nil || call.TenantID != "" || call.ResourceID != "" || call.ExpectedGeneration != 0 ||
		call.PrincipalID == "" || call.CredentialID == "" {
		return apiserver.EdgePage[apiserver.RebootControlProjection]{}, rebootcontrol.ErrInvalid
	}
	limit := int(payload.Limit)
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > rebootcontrol.MaxPageSize {
		return apiserver.EdgePage[apiserver.RebootControlProjection]{}, rebootcontrol.ErrInvalid
	}
	stored, err := edge.repository.ListPlanStates(ctx, edge.nodeID, limit, payload.Cursor)
	if err != nil {
		return apiserver.EdgePage[apiserver.RebootControlProjection]{}, err
	}
	page := apiserver.EdgePage[apiserver.RebootControlProjection]{Items: make([]apiserver.RebootControlProjection, 0, limit), NextCursor: stored.NextCursor}
	representedInventories := make(map[string]struct{}, len(stored.Items))
	for _, item := range stored.Items {
		projection, projectErr := edge.projection(ctx, item.Plan, item.State)
		if projectErr != nil {
			return apiserver.EdgePage[apiserver.RebootControlProjection]{}, projectErr
		}
		page.Items = append(page.Items, projection)
		if item.State.Phase != rebootcontrol.PhaseCancelled && item.State.Phase != rebootcontrol.PhaseSucceeded {
			representedInventories[item.Plan.Packages.InventoryDigest] = struct{}{}
		}
	}
	if payload.Cursor == "" && page.NextCursor == "" && len(page.Items) < limit {
		snapshot, inventoryErr := edge.packages.LatestInventory(ctx, edge.nodeID, edge.manager)
		_, represented := representedInventories[snapshot.ContentDigest]
		if inventoryErr == nil && snapshot.RebootRequired && !represented {
			page.Items = append(page.Items, rebootRequiredProjection(snapshot))
		} else if inventoryErr != nil && !errors.Is(inventoryErr, packagemaint.ErrNotFound) {
			return apiserver.EdgePage[apiserver.RebootControlProjection]{}, inventoryErr
		}
	}
	return page, nil
}

func (edge *rebootControlLinuxEdge) ScheduleReboot(ctx context.Context, call apiserver.EdgeCall,
	payload apiserver.RebootControlSchedulePayload) (apiserver.EdgeMutation[apiserver.RebootControlProjection], error) {
	if err := edge.validateMutation(ctx, call, false, identity.AssuranceMFA); err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	switch payload.Reason {
	case rebootcontrol.ReasonKernelUpdate, rebootcontrol.ReasonPackageUpdate,
		rebootcontrol.ReasonSecurityResponse, rebootcontrol.ReasonRecovery:
	default:
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrInvalid
	}
	if payload.ExpectedReturnSeconds == 0 {
		payload.ExpectedReturnSeconds = 1800
	}
	if !validRebootControlRuntimeID(payload.RequirementReference) || !validRebootControlRuntimeID(payload.MaintenanceOccurrence) ||
		payload.DrainMode != rebootcontrol.DrainGraceful && payload.DrainMode != rebootcontrol.DrainRequired ||
		payload.ExpectedReturnSeconds < 60 || payload.ExpectedReturnSeconds > 86400 {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrInvalid
	}
	now := edge.now().UTC()
	operation, packagePlan, inventory, err := edge.packageEvidence(ctx, payload)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	planID := rebootControlID(call.CommandID)
	storedPlan, loadErr := edge.repository.LoadPlan(ctx, planID)
	if loadErr == nil {
		if storedPlan.NodeID != edge.nodeID || storedPlan.Reason != payload.Reason ||
			storedPlan.Packages.TransactionID != operation.ID || storedPlan.Packages.TransactionDigest != operation.Receipt.EvidenceDigest ||
			storedPlan.Maintenance.OccurrenceID != payload.MaintenanceOccurrence || storedPlan.Drain.Mode != payload.DrainMode ||
			!storedPlan.ExpectedBoot.ReturnDeadline.Equal(storedPlan.RequestedAt.Add(time.Duration(payload.ExpectedReturnSeconds)*time.Second)) ||
			storedPlan.Authorization.Subject != call.PrincipalID {
			return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrConflict
		}
		state, stateErr := edge.repository.LoadState(ctx, planID)
		if stateErr != nil {
			return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, stateErr
		}
		return edge.mutation(ctx, call.CommandID, storedPlan, state)
	}
	if !errors.Is(loadErr, rebootcontrol.ErrNotFound) {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, loadErr
	}
	duration := time.Duration(payload.ExpectedReturnSeconds) * time.Second
	plan, err := edge.authority.ResolveRebootPlan(ctx, rebootControlPlanRequest{Call: call, PlanID: planID, Reason: payload.Reason,
		MaintenanceOccurrenceID: payload.MaintenanceOccurrence, DrainMode: payload.DrainMode, ExpectedReturn: duration,
		PackageOperation: operation, PackagePlan: packagePlan, PackageInventory: inventory, RequestedAt: now})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	canonical, err := rebootcontrol.CanonicalPlan(plan)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	if canonical.ID != planID || canonical.NodeID != edge.nodeID || canonical.Reason != payload.Reason ||
		canonical.Maintenance.OccurrenceID != payload.MaintenanceOccurrence || canonical.Drain.Mode != payload.DrainMode ||
		canonical.Packages.InventoryDigest != packagePlan.InventoryDigest || canonical.Packages.TransactionID != operation.ID ||
		canonical.Packages.TransactionDigest != operation.Receipt.EvidenceDigest || canonical.Authorization.Subject != call.PrincipalID ||
		!canonical.RequestedAt.Equal(now) || !canonical.ExpectedBoot.ReturnDeadline.Equal(now.Add(duration)) {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrIntegrity
	}
	if canonical.Reason == rebootcontrol.ReasonKernelUpdate && canonical.Kernel.CurrentRelease == canonical.Kernel.NextRelease && canonical.Kernel.CurrentDigest == canonical.Kernel.NextDigest {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrIntegrity
	}
	state, _, err := edge.coordinator.Request(ctx, canonical, edge.controllerID, rebootControlStepKey(call.IdempotencyKey, "request"))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	return edge.mutation(ctx, call.CommandID, canonical, state)
}

func (edge *rebootControlLinuxEdge) ExecuteReboot(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.RebootControlProjection], error) {
	if err := edge.validateMutation(ctx, call, true, identity.AssurancePhishingResistant); err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	plan, state, err := edge.controlled(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	readiness, err := edge.authority.PreflightReboot(ctx, rebootControlPreflightRequest{Call: call, Plan: plan, State: state, RequestedAt: edge.now().UTC()})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	if readiness.PlanID != plan.ID || readiness.PlanDigest != plan.Digest || readiness.RebootFence != state.Fence ||
		readiness.MaintenanceOccurrenceDigest != plan.Maintenance.OccurrenceDigest || readiness.ApprovalDigest != plan.Approval.Digest ||
		!validRebootControlDigest(readiness.WriterAuthorityDigest) || !validRebootControlDigest(readiness.EvidenceDigest) ||
		!readiness.MaintenanceAdmissible || !readiness.HAWriterSafe || len(readiness.Blockers) != 0 {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrUnauthorized
	}
	for {
		command := edge.stepCommand(call, state, "execute:"+string(state.Phase))
		switch state.Phase {
		case rebootcontrol.PhaseRequested:
			state, _, err = edge.coordinator.Admit(ctx, command)
		case rebootcontrol.PhaseAdmitted:
			state, _, err = edge.coordinator.Drain(ctx, command)
		case rebootcontrol.PhaseDraining:
			state, _, err = edge.coordinator.Checkpoint(ctx, command)
		case rebootcontrol.PhaseCheckpointed:
			state, _, err = edge.coordinator.Arm(ctx, command)
		case rebootcontrol.PhaseArmed:
			state, _, err = edge.coordinator.Dispatch(ctx, command)
		default:
			return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrConflict
		}
		if err != nil {
			return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
		}
		if state.Phase == rebootcontrol.PhaseRebootDispatched {
			break
		}
	}
	return edge.mutation(ctx, call.CommandID, plan, state)
}

func (edge *rebootControlLinuxEdge) CancelReboot(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.RebootControlProjection], error) {
	if err := edge.validateMutation(ctx, call, true, identity.AssurancePhishingResistant); err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	plan, state, err := edge.controlled(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	switch state.Phase {
	case rebootcontrol.PhaseRequested, rebootcontrol.PhaseAdmitted, rebootcontrol.PhaseDraining, rebootcontrol.PhaseCheckpointed:
	default:
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrConflict
	}
	result, err := edge.authority.ReleaseBeforeArm(ctx, rebootControlReleaseRequest{Call: call, Plan: plan, State: state, RequestedAt: edge.now().UTC()})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	if result.PlanID != plan.ID || result.RebootFence != state.Fence || !result.DrainReleased ||
		!result.OperationsResumed || !validRebootControlDigest(result.EvidenceDigest) {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrIntegrity
	}
	state, _, err = edge.coordinator.Cancel(ctx, edge.stepCommand(call, state, "cancel"), result.EvidenceDigest)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	return edge.mutation(ctx, call.CommandID, plan, state)
}

func (edge *rebootControlLinuxEdge) ReconcileReboot(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.RebootControlProjection], error) {
	if err := edge.validateMutation(ctx, call, true, identity.AssurancePhishingResistant); err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	plan, state, err := edge.controlled(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	switch state.Phase {
	case rebootcontrol.PhaseRebootDispatched:
		state, _, err = edge.coordinator.BeginReconcile(ctx, edge.stepCommand(call, state, "reconcile:begin"))
		if err == nil {
			state, _, err = edge.coordinator.CompleteReconcile(ctx, edge.stepCommand(call, state, "reconcile:complete"))
		}
	case rebootcontrol.PhaseReconciling:
		state, _, err = edge.coordinator.CompleteReconcile(ctx, edge.stepCommand(call, state, "reconcile:complete"))
	case rebootcontrol.PhaseUncertain:
		if state.MarkerDigest == "" || state.CheckpointReceiptDigest == "" {
			return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrConflict
		}
		var result rebootControlAmbiguousResult
		result, err = edge.authority.ReconcileAmbiguousReboot(ctx, rebootControlAmbiguousRequest{Call: call, Plan: plan, State: state, RequestedAt: edge.now().UTC()})
		if err == nil {
			if result.PlanID != plan.ID || result.RebootFence != state.Fence || result.MarkerDigest != state.MarkerDigest ||
				!result.SubsystemsReconciled || !result.MarkerCleared || !validRebootControlDigest(result.WriterAuthorityDigest) ||
				!validRebootControlDigest(result.EvidenceDigest) {
				return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrIntegrity
			}
			state, _, err = edge.coordinator.ResolveAmbiguousReboot(ctx, edge.stepCommand(call, state, "reconcile:ambiguous"), result.ActualBoot, result.EvidenceDigest)
		}
	default:
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, rebootcontrol.ErrConflict
	}
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	return edge.mutation(ctx, call.CommandID, plan, state)
}

func (edge *rebootControlLinuxEdge) packageEvidence(ctx context.Context, payload apiserver.RebootControlSchedulePayload) (packagemaint.MaintenanceOperation, packagemaint.MaintenancePlan, packagemaint.InventorySnapshot, error) {
	operation, err := edge.packages.Operation(ctx, payload.RequirementReference)
	if err != nil {
		return packagemaint.MaintenanceOperation{}, packagemaint.MaintenancePlan{}, packagemaint.InventorySnapshot{}, err
	}
	plan, err := edge.packages.Plan(ctx, operation.PlanID)
	if err != nil {
		return operation, packagemaint.MaintenancePlan{}, packagemaint.InventorySnapshot{}, err
	}
	inventory, err := edge.packages.Inventory(ctx, plan.InventoryID)
	if err != nil {
		return operation, plan, packagemaint.InventorySnapshot{}, err
	}
	if plan.NodeID != edge.nodeID || plan.Manager != edge.manager || inventory.NodeID != edge.nodeID || inventory.Manager != edge.manager ||
		operation.PlanDigest != plan.Digest || operation.PlanGeneration != plan.Generation || operation.InventoryDigest != plan.InventoryDigest ||
		inventory.Generation != plan.InventoryGeneration || inventory.ContentDigest != plan.InventoryDigest ||
		(operation.State != packagemaint.OperationSucceeded && operation.State != packagemaint.OperationRecovered) ||
		(operation.Receipt.Outcome != packagemaint.OutcomeConfirmed && operation.Receipt.Outcome != packagemaint.OutcomeRecovered) ||
		operation.Receipt.PlanID != plan.ID || operation.Receipt.PlanDigest != plan.Digest || !validRebootControlDigest(operation.Receipt.EvidenceDigest) ||
		operation.Receipt.InventoryGeneration != plan.InventoryGeneration || operation.Receipt.BeforeInventoryDigest != plan.InventoryDigest ||
		operation.Receipt.Fence != operation.Fence ||
		plan.Reboot != packagemaint.RebootRequired && !inventory.RebootRequired {
		return operation, plan, inventory, rebootcontrol.ErrIntegrity
	}
	if payload.Reason == rebootcontrol.ReasonSecurityResponse && (plan.Security == packagemaint.SecurityNone || plan.Security == packagemaint.SecurityUnknown) {
		return operation, plan, inventory, rebootcontrol.ErrUnauthorized
	}
	if payload.Reason == rebootcontrol.ReasonRecovery && (operation.State != packagemaint.OperationRecovered || operation.Receipt.Outcome != packagemaint.OutcomeRecovered) {
		return operation, plan, inventory, rebootcontrol.ErrConflict
	}
	return operation, plan, inventory, nil
}

func (edge *rebootControlLinuxEdge) controlled(ctx context.Context, call apiserver.EdgeCall) (rebootcontrol.Plan, rebootcontrol.State, error) {
	plan, err := edge.repository.LoadPlan(ctx, call.ResourceID)
	if err != nil {
		return rebootcontrol.Plan{}, rebootcontrol.State{}, err
	}
	state, err := edge.repository.LoadState(ctx, call.ResourceID)
	if err != nil {
		return rebootcontrol.Plan{}, rebootcontrol.State{}, err
	}
	if plan.NodeID != edge.nodeID || state.NodeID != edge.nodeID || state.Generation != call.ExpectedGeneration || state.ControllerID != edge.controllerID {
		return rebootcontrol.Plan{}, rebootcontrol.State{}, rebootcontrol.ErrConflict
	}
	return plan, state, nil
}

func (edge *rebootControlLinuxEdge) validateMutation(ctx context.Context, call apiserver.EdgeCall, existing bool, assurance identity.AssuranceLevel) error {
	if edge == nil || ctx == nil || call.TenantID != "" || call.PrincipalID == "" || call.CredentialID == "" ||
		call.CommandID == "" || call.IdempotencyKey == "" {
		return rebootcontrol.ErrInvalid
	}
	if call.Assurance < assurance {
		return rebootcontrol.ErrUnauthorized
	}
	if existing {
		if !validRebootControlRuntimeID(call.ResourceID) || call.ExpectedGeneration == 0 {
			return rebootcontrol.ErrInvalid
		}
	} else if call.ResourceID != "" || call.ExpectedGeneration != 0 {
		return rebootcontrol.ErrInvalid
	}
	return nil
}

func (edge *rebootControlLinuxEdge) stepCommand(call apiserver.EdgeCall, state rebootcontrol.State, step string) rebootcontrol.StepCommand {
	return rebootcontrol.StepCommand{PlanID: state.PlanID, ExpectedGeneration: state.Generation, Fence: state.Fence,
		ControllerID: edge.controllerID, IdempotencyKey: rebootControlStepKey(call.IdempotencyKey, step), At: edge.now().UTC()}
}

func (edge *rebootControlLinuxEdge) mutation(ctx context.Context, operationID string, plan rebootcontrol.Plan,
	state rebootcontrol.State) (apiserver.EdgeMutation[apiserver.RebootControlProjection], error) {
	projection, err := edge.projection(ctx, plan, state)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.RebootControlProjection]{}, err
	}
	return apiserver.EdgeMutation[apiserver.RebootControlProjection]{OperationID: operationID, State: string(state.Phase),
		Generation: state.Generation, Resource: projection}, nil
}

func (edge *rebootControlLinuxEdge) projection(ctx context.Context, plan rebootcontrol.Plan, state rebootcontrol.State) (apiserver.RebootControlProjection, error) {
	if plan.Validate() != nil || state.Validate() != nil || plan.ID != state.PlanID || plan.NodeID != state.NodeID {
		return apiserver.RebootControlProjection{}, rebootcontrol.ErrIntegrity
	}
	now := edge.now().UTC()
	actual, bootErr := edge.authority.CurrentBootIdentity(ctx, plan.NodeID)
	if bootErr != nil || actual.Validate() != nil {
		actual = rebootcontrol.BootIdentity{}
	}
	maintenanceStatus := "scheduled"
	if !now.Before(plan.Maintenance.StartsAt) && now.Before(plan.Maintenance.EndsAt) {
		maintenanceStatus = "active"
	} else if !now.Before(plan.Maintenance.EndsAt) {
		maintenanceStatus = "closed"
	}
	drainReady := rebootDrainReady(state.Phase)
	quiesceReady := rebootQuiesceReady(state.Phase)
	bootStatus := "unavailable"
	if actual.BootID != "" {
		bootStatus = "source_current"
		if actual.BootID != plan.SourceBoot.BootID {
			bootStatus = "unexpected"
			if rebootMatchesExpected(actual, plan.ExpectedBoot) {
				bootStatus = "confirmed"
			}
		}
	}
	recovery := make([]string, len(state.RecoverySteps))
	for index, step := range state.RecoverySteps {
		recovery[index] = string(step)
	}
	projection := apiserver.RebootControlProjection{ID: plan.ID, Type: rebootControlType(state.Phase, maintenanceStatus), NodeID: plan.NodeID,
		Required: state.Phase != rebootcontrol.PhaseSucceeded && state.Phase != rebootcontrol.PhaseCancelled,
		Reasons: []apiserver.RebootRequiredReasonProjection{{Code: plan.Reason, Source: "package_maintenance", Reference: plan.Packages.TransactionID,
			EvidenceDigest: plan.Packages.TransactionDigest, ObservedAt: plan.RequestedAt}},
		MaintenanceOccurrenceID: plan.Maintenance.OccurrenceID, MaintenanceStartsAt: plan.Maintenance.StartsAt,
		MaintenanceEndsAt: plan.Maintenance.EndsAt, MaintenanceStatus: maintenanceStatus, Phase: string(state.Phase), Outcome: string(state.Outcome),
		DrainStatus: rebootDrainStatus(state.Phase), DrainReady: drainReady, QuiesceStatus: rebootQuiesceStatus(state.Phase), QuiesceReady: quiesceReady,
		ApprovalStatus: rebootApprovalStatus(state.Phase), SourceBootID: plan.SourceBoot.BootID, ObservedBootID: actual.BootID,
		BootConfirmationStatus: bootStatus, CurrentKernel: plan.Kernel.CurrentRelease, ExpectedKernel: plan.Kernel.NextRelease,
		ObservedKernel: actual.KernelRelease, Ambiguous: state.Phase == rebootcontrol.PhaseUncertain,
		CanExecute: maintenanceStatus == "active" && rebootExecutable(state.Phase), CanCancel: rebootCancellable(state.Phase),
		CanReconcile: state.Phase == rebootcontrol.PhaseRebootDispatched || state.Phase == rebootcontrol.PhaseReconciling || state.Phase == rebootcontrol.PhaseUncertain,
		Generation: state.Generation, Fence: state.Fence, RecoverySteps: recovery, UpdatedAt: state.UpdatedAt}
	return projection, nil
}

func rebootRequiredProjection(snapshot packagemaint.InventorySnapshot) apiserver.RebootControlProjection {
	return apiserver.RebootControlProjection{ID: "reboot_required_" + snapshot.ContentDigest[:48], Type: "required_unscheduled",
		NodeID: snapshot.NodeID, Required: true, Reasons: []apiserver.RebootRequiredReasonProjection{{Code: rebootcontrol.ReasonPackageUpdate,
			Source: "package_inventory", Reference: snapshot.ID, EvidenceDigest: snapshot.ContentDigest, ObservedAt: snapshot.CapturedAt}},
		MaintenanceStatus: "unscheduled", Phase: "unscheduled", DrainStatus: "pending", QuiesceStatus: "pending",
		ApprovalStatus: "not_requested", BootConfirmationStatus: "not_expected", Generation: snapshot.Generation, UpdatedAt: snapshot.CapturedAt}
}

func rebootControlType(phase rebootcontrol.Phase, maintenance string) string {
	switch phase {
	case rebootcontrol.PhaseRequested, rebootcontrol.PhaseAdmitted:
		if maintenance == "active" {
			return "ready"
		}
		return "scheduled"
	case rebootcontrol.PhaseDraining, rebootcontrol.PhaseCheckpointed:
		return "executing"
	case rebootcontrol.PhaseArmed:
		return "armed"
	case rebootcontrol.PhaseRebootDispatched:
		return "reboot_dispatched"
	case rebootcontrol.PhaseReconciling:
		return "reconciling"
	case rebootcontrol.PhaseSucceeded:
		return "completed"
	case rebootcontrol.PhaseCancelled:
		return "cancelled"
	case rebootcontrol.PhaseUncertain:
		return "ambiguous"
	default:
		return "failed"
	}
}

func rebootDrainReady(phase rebootcontrol.Phase) bool {
	return phase == rebootcontrol.PhaseDraining || phase == rebootcontrol.PhaseCheckpointed || phase == rebootcontrol.PhaseArmed ||
		phase == rebootcontrol.PhaseRebootDispatched || phase == rebootcontrol.PhaseReconciling || phase == rebootcontrol.PhaseSucceeded
}

func rebootQuiesceReady(phase rebootcontrol.Phase) bool {
	return phase == rebootcontrol.PhaseCheckpointed || phase == rebootcontrol.PhaseArmed || phase == rebootcontrol.PhaseRebootDispatched ||
		phase == rebootcontrol.PhaseReconciling || phase == rebootcontrol.PhaseSucceeded
}

func rebootDrainStatus(phase rebootcontrol.Phase) string {
	if rebootDrainReady(phase) {
		return "ready"
	}
	if phase == rebootcontrol.PhaseCancelled {
		return "released"
	}
	return "pending"
}

func rebootQuiesceStatus(phase rebootcontrol.Phase) string {
	if rebootQuiesceReady(phase) {
		return "ready"
	}
	if phase == rebootcontrol.PhaseCancelled {
		return "resumed"
	}
	return "pending"
}

func rebootApprovalStatus(phase rebootcontrol.Phase) string {
	if phase == rebootcontrol.PhaseRequested {
		return "bound_pending_verification"
	}
	if phase == rebootcontrol.PhaseCancelled {
		return "cancelled"
	}
	return "verified_at_admission"
}

func rebootExecutable(phase rebootcontrol.Phase) bool {
	return phase == rebootcontrol.PhaseRequested || phase == rebootcontrol.PhaseAdmitted || phase == rebootcontrol.PhaseDraining ||
		phase == rebootcontrol.PhaseCheckpointed || phase == rebootcontrol.PhaseArmed
}

func rebootCancellable(phase rebootcontrol.Phase) bool {
	return phase == rebootcontrol.PhaseRequested || phase == rebootcontrol.PhaseAdmitted ||
		phase == rebootcontrol.PhaseDraining || phase == rebootcontrol.PhaseCheckpointed
}

func rebootMatchesExpected(actual rebootcontrol.BootIdentity, expected rebootcontrol.ExpectedBoot) bool {
	return actual.KernelRelease == expected.KernelRelease && actual.KernelDigest == expected.KernelDigest &&
		(expected.BootSlot == "" || actual.BootSlot == expected.BootSlot)
}

func rebootControlID(commandID string) string {
	sum := sha256.Sum256([]byte("controlled-reboot\x00" + commandID))
	return "reboot_" + hex.EncodeToString(sum[:])[:48]
}

func rebootControlStepKey(idempotencyKey, step string) string {
	sum := sha256.Sum256([]byte(idempotencyKey + "\x00" + step))
	return "reboot_step_" + hex.EncodeToString(sum[:])[:48]
}

func validRebootControlRuntimeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' ||
			index > 0 && (character == '-' || character == '_' || character == '.' || character == ':') {
			continue
		}
		return false
	}
	return true
}

func validRebootControlDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

var _ apiserver.RebootControlEdgeService = (*rebootControlLinuxEdge)(nil)
var _ apiserver.RebootControlEdgeCapabilityProvider = (*rebootControlLinuxEdge)(nil)
