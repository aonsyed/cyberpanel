// Package rebootcontrol coordinates controlled, recoverable host reboots. It
// defines typed operations only; it never constructs or executes raw shell.
package rebootcontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid       = errors.New("invalid reboot-control resource")
	ErrNotFound      = errors.New("reboot-control resource not found")
	ErrConflict      = errors.New("reboot-control generation or admission conflict")
	ErrStaleBoot     = errors.New("reboot-control boot identity is stale")
	ErrIntegrity     = errors.New("reboot-control integrity failure")
	ErrPartialArm    = errors.New("reboot-control recovery marker was only partially armed")
	ErrUnproven      = errors.New("reboot-control rollback capability is unproven")
	ErrUnauthorized  = errors.New("reboot-control authorization rejected")
	ErrCapacity      = errors.New("reboot-control capacity exceeded")
)

const maxGeneration = uint64(1<<63 - 1)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type PlanReason string

const (
	ReasonKernelUpdate       PlanReason = "kernel_update"
	ReasonPackageUpdate      PlanReason = "package_update"
	ReasonSecurityResponse   PlanReason = "security_response"
	ReasonRecovery           PlanReason = "recovery"
	ReasonOperatorMaintenance PlanReason = "operator_maintenance"
)

func (reason PlanReason) Valid() bool {
	return reason == ReasonKernelUpdate || reason == ReasonPackageUpdate || reason == ReasonSecurityResponse || reason == ReasonRecovery || reason == ReasonOperatorMaintenance
}

type BootIdentity struct {
	BootID         string    `json:"boot_id"`
	KernelRelease  string    `json:"kernel_release"`
	KernelDigest   string    `json:"kernel_digest"`
	BootSlot       string    `json:"boot_slot,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
	EvidenceDigest string    `json:"evidence_digest"`
}

func (identity BootIdentity) Validate() error {
	if !identifierPattern.MatchString(identity.BootID) || !identifierPattern.MatchString(identity.KernelRelease) || identity.BootSlot != "" && !identifierPattern.MatchString(identity.BootSlot) || !validDigest(identity.KernelDigest) || !validDigest(identity.EvidenceDigest) || !validTimestamp(identity.ObservedAt) {
		return ErrInvalid
	}
	return nil
}

type MaintenanceBinding struct {
	OccurrenceID     string    `json:"occurrence_id"`
	OccurrenceDigest string    `json:"occurrence_digest"`
	StartsAt         time.Time `json:"starts_at"`
	EndsAt           time.Time `json:"ends_at"`
}

func (binding MaintenanceBinding) Validate() error {
	if !identifierPattern.MatchString(binding.OccurrenceID) || !validDigest(binding.OccurrenceDigest) || !validTimestamp(binding.StartsAt) || !validTimestamp(binding.EndsAt) || !binding.EndsAt.After(binding.StartsAt) {
		return ErrInvalid
	}
	return nil
}

type PackageState struct {
	InventoryDigest string `json:"inventory_digest"`
	TransactionID   string `json:"transaction_id"`
	TransactionDigest string `json:"transaction_digest"`
}

func (state PackageState) Validate() error {
	if !validDigest(state.InventoryDigest) || !identifierPattern.MatchString(state.TransactionID) || !validDigest(state.TransactionDigest) {
		return ErrInvalid
	}
	return nil
}

type KernelState struct {
	CurrentRelease string `json:"current_release"`
	CurrentDigest  string `json:"current_digest"`
	NextRelease    string `json:"next_release"`
	NextDigest     string `json:"next_digest"`
	NextBootSlot   string `json:"next_boot_slot,omitempty"`
}

func (state KernelState) Validate() error {
	if !identifierPattern.MatchString(state.CurrentRelease) || !identifierPattern.MatchString(state.NextRelease) || !validDigest(state.CurrentDigest) || !validDigest(state.NextDigest) || state.NextBootSlot != "" && !identifierPattern.MatchString(state.NextBootSlot) {
		return ErrInvalid
	}
	return nil
}

type ExpectedBoot struct {
	RequireBootIDChange bool      `json:"require_boot_id_change"`
	KernelRelease       string    `json:"kernel_release"`
	KernelDigest        string    `json:"kernel_digest"`
	BootSlot            string    `json:"boot_slot,omitempty"`
	ReturnDeadline      time.Time `json:"return_deadline"`
}

func (expected ExpectedBoot) Validate() error {
	if !expected.RequireBootIDChange || !identifierPattern.MatchString(expected.KernelRelease) || !validDigest(expected.KernelDigest) || expected.BootSlot != "" && !identifierPattern.MatchString(expected.BootSlot) || !validTimestamp(expected.ReturnDeadline) {
		return ErrInvalid
	}
	return nil
}

type RollbackKind string

const (
	RollbackNone      RollbackKind = "none"
	RollbackBootEntry RollbackKind = "boot_entry"
	RollbackSnapshot  RollbackKind = "snapshot"
)

type RollbackCapability struct {
	Kind           RollbackKind `json:"kind"`
	Proven         bool         `json:"proven"`
	Reference      string       `json:"reference,omitempty"`
	EvidenceDigest string       `json:"evidence_digest,omitempty"`
}

func (capability RollbackCapability) Validate() error {
	switch capability.Kind {
	case RollbackNone:
		if capability.Proven || capability.Reference != "" || capability.EvidenceDigest != "" {
			return ErrUnproven
		}
	case RollbackBootEntry, RollbackSnapshot:
		if !capability.Proven || !identifierPattern.MatchString(capability.Reference) || !validDigest(capability.EvidenceDigest) {
			return ErrUnproven
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (capability RollbackCapability) Available() bool {
	return capability.Kind != RollbackNone && capability.Proven && capability.Validate() == nil
}

type DrainMode string

const (
	DrainGraceful DrainMode = "graceful"
	DrainRequired DrainMode = "required"
)

type DrainPolicy struct {
	Mode           DrainMode     `json:"mode"`
	ListenerGroups []string      `json:"listener_groups"`
	Timeout        time.Duration `json:"timeout"`
	RejectNewWork  bool          `json:"reject_new_work"`
}

func (policy DrainPolicy) Validate() error {
	if policy.Mode != DrainGraceful && policy.Mode != DrainRequired || !policy.RejectNewWork || policy.Timeout < time.Second || policy.Timeout > 30*time.Minute || len(policy.ListenerGroups) == 0 || len(policy.ListenerGroups) > 128 {
		return ErrInvalid
	}
	for index, group := range policy.ListenerGroups {
		if !identifierPattern.MatchString(group) || index > 0 && policy.ListenerGroups[index-1] >= group {
			return ErrInvalid
		}
	}
	return nil
}

type OperationCheckpointMode string

const CheckpointOrRecordResumable OperationCheckpointMode = "checkpoint_or_record_resumable"

type CheckpointPolicy struct {
	SQLiteDatabases    []string               `json:"sqlite_databases"`
	RequireOnlineBackup bool                  `json:"require_online_backup"`
	OperationMode      OperationCheckpointMode `json:"operation_mode"`
	MaximumOperations  uint32                 `json:"maximum_operations"`
	Timeout            time.Duration          `json:"timeout"`
}

func (policy CheckpointPolicy) Validate() error {
	if !policy.RequireOnlineBackup || policy.OperationMode != CheckpointOrRecordResumable || policy.MaximumOperations == 0 || policy.MaximumOperations > 100000 || policy.Timeout < time.Second || policy.Timeout > 30*time.Minute || len(policy.SQLiteDatabases) == 0 || len(policy.SQLiteDatabases) > 128 {
		return ErrInvalid
	}
	for index, database := range policy.SQLiteDatabases {
		if !identifierPattern.MatchString(database) || index > 0 && policy.SQLiteDatabases[index-1] >= database {
			return ErrInvalid
		}
	}
	return nil
}

type AssuranceLevel string

const AssuranceStepUp AssuranceLevel = "step_up"

type Authorization struct {
	ID          string         `json:"id"`
	Issuer      string         `json:"issuer"`
	Subject     string         `json:"subject"`
	Assurance   AssuranceLevel `json:"assurance"`
	ScopeDigest string         `json:"scope_digest"`
	IssuedAt    time.Time      `json:"issued_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	ProofDigest string         `json:"proof_digest"`
	Digest      string         `json:"digest"`
}

type Approval struct {
	ID          string    `json:"id"`
	Approver    string    `json:"approver"`
	Role        string    `json:"role"`
	PlanScopeDigest string `json:"plan_scope_digest"`
	ApprovedAt  time.Time `json:"approved_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	ProofDigest string    `json:"proof_digest"`
	Digest      string    `json:"digest"`
}

type Plan struct {
	ID            string             `json:"id"`
	NodeID        string             `json:"node_id"`
	Reason        PlanReason         `json:"reason"`
	SourceBoot    BootIdentity       `json:"source_boot"`
	Maintenance   MaintenanceBinding `json:"maintenance"`
	Packages      PackageState       `json:"packages"`
	Kernel        KernelState        `json:"kernel"`
	ExpectedBoot  ExpectedBoot       `json:"expected_boot"`
	Rollback      RollbackCapability `json:"rollback"`
	Drain         DrainPolicy        `json:"drain"`
	Checkpoint    CheckpointPolicy   `json:"checkpoint"`
	Authorization Authorization      `json:"authorization"`
	Approval      Approval           `json:"approval"`
	RequestedAt   time.Time          `json:"requested_at"`
	ExpiresAt     time.Time          `json:"expires_at"`
	Digest        string             `json:"digest"`
}

func CanonicalPlan(plan Plan) (Plan, error) {
	plan.RequestedAt = plan.RequestedAt.UTC()
	plan.ExpiresAt = plan.ExpiresAt.UTC()
	plan.SourceBoot.ObservedAt = plan.SourceBoot.ObservedAt.UTC()
	plan.Maintenance.StartsAt = plan.Maintenance.StartsAt.UTC()
	plan.Maintenance.EndsAt = plan.Maintenance.EndsAt.UTC()
	plan.ExpectedBoot.ReturnDeadline = plan.ExpectedBoot.ReturnDeadline.UTC()
	plan.Authorization.IssuedAt = plan.Authorization.IssuedAt.UTC()
	plan.Authorization.ExpiresAt = plan.Authorization.ExpiresAt.UTC()
	plan.Approval.ApprovedAt = plan.Approval.ApprovedAt.UTC()
	plan.Approval.ExpiresAt = plan.Approval.ExpiresAt.UTC()
	plan.Drain.ListenerGroups = append([]string(nil), plan.Drain.ListenerGroups...)
	sort.Strings(plan.Drain.ListenerGroups)
	plan.Checkpoint.SQLiteDatabases = append([]string(nil), plan.Checkpoint.SQLiteDatabases...)
	sort.Strings(plan.Checkpoint.SQLiteDatabases)
	authorization, err := canonicalAuthorization(plan.Authorization)
	if err != nil {
		return Plan{}, err
	}
	plan.Authorization = authorization
	approval, err := canonicalApproval(plan.Approval)
	if err != nil {
		return Plan{}, err
	}
	plan.Approval = approval
	provided := plan.Digest
	plan.Digest = ""
	if err := validatePlan(plan, false); err != nil {
		return Plan{}, err
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, err
	}
	plan.Digest = digestBytes(raw)
	if provided != "" && provided != plan.Digest {
		return Plan{}, ErrIntegrity
	}
	return plan, validatePlan(plan, true)
}

func (plan Plan) Validate() error {
	if err := validatePlan(plan, true); err != nil {
		return err
	}
	digest := plan.Digest
	plan.Digest = ""
	raw, err := json.Marshal(plan)
	if err != nil || digestBytes(raw) != digest {
		return ErrIntegrity
	}
	return nil
}

// PlanScopeDigest is the exact immutable scope an authorization and approval
// must bind before the remaining credential fields are attached.
func PlanScopeDigest(plan Plan) (string, error) {
	plan.RequestedAt = plan.RequestedAt.UTC()
	plan.ExpiresAt = plan.ExpiresAt.UTC()
	plan.SourceBoot.ObservedAt = plan.SourceBoot.ObservedAt.UTC()
	plan.Maintenance.StartsAt = plan.Maintenance.StartsAt.UTC()
	plan.Maintenance.EndsAt = plan.Maintenance.EndsAt.UTC()
	plan.ExpectedBoot.ReturnDeadline = plan.ExpectedBoot.ReturnDeadline.UTC()
	plan.Drain.ListenerGroups = append([]string(nil), plan.Drain.ListenerGroups...)
	sort.Strings(plan.Drain.ListenerGroups)
	plan.Checkpoint.SQLiteDatabases = append([]string(nil), plan.Checkpoint.SQLiteDatabases...)
	sort.Strings(plan.Checkpoint.SQLiteDatabases)
	if !identifierPattern.MatchString(plan.ID) || !identifierPattern.MatchString(plan.NodeID) || !plan.Reason.Valid() || plan.SourceBoot.Validate() != nil || plan.Maintenance.Validate() != nil || plan.Packages.Validate() != nil || plan.Kernel.Validate() != nil || plan.ExpectedBoot.Validate() != nil || plan.Rollback.Validate() != nil || plan.Drain.Validate() != nil || plan.Checkpoint.Validate() != nil || !validTimestamp(plan.RequestedAt) || !validTimestamp(plan.ExpiresAt) {
		return "", ErrInvalid
	}
	return planScopeDigest(plan), nil
}

func validatePlan(plan Plan, requireDigest bool) error {
	if !identifierPattern.MatchString(plan.ID) || !identifierPattern.MatchString(plan.NodeID) || !plan.Reason.Valid() || plan.SourceBoot.Validate() != nil || plan.Maintenance.Validate() != nil || plan.Packages.Validate() != nil || plan.Kernel.Validate() != nil || plan.ExpectedBoot.Validate() != nil || plan.Rollback.Validate() != nil || plan.Drain.Validate() != nil || plan.Checkpoint.Validate() != nil {
		return ErrInvalid
	}
	if !validTimestamp(plan.RequestedAt) || !validTimestamp(plan.ExpiresAt) || !plan.ExpiresAt.After(plan.RequestedAt) || !plan.ExpiresAt.After(plan.Maintenance.StartsAt) || plan.SourceBoot.ObservedAt.After(plan.RequestedAt) || plan.ExpiresAt.After(plan.Maintenance.EndsAt) || !plan.ExpectedBoot.ReturnDeadline.After(plan.RequestedAt) || plan.ExpectedBoot.ReturnDeadline.Sub(plan.Maintenance.EndsAt) > 24*time.Hour {
		return ErrInvalid
	}
	if plan.Kernel.CurrentRelease != plan.SourceBoot.KernelRelease || plan.Kernel.CurrentDigest != plan.SourceBoot.KernelDigest || plan.ExpectedBoot.KernelRelease != plan.Kernel.NextRelease || plan.ExpectedBoot.KernelDigest != plan.Kernel.NextDigest || plan.ExpectedBoot.BootSlot != plan.Kernel.NextBootSlot {
		return ErrIntegrity
	}
	authorization, authorizationErr := canonicalAuthorization(plan.Authorization)
	approval, approvalErr := canonicalApproval(plan.Approval)
	scopeDigest := planScopeDigest(plan)
	if authorizationErr != nil || approvalErr != nil || authorization != plan.Authorization || approval != plan.Approval || plan.Authorization.ScopeDigest != scopeDigest || plan.Approval.PlanScopeDigest != scopeDigest || plan.Authorization.ExpiresAt.Before(plan.ExpiresAt) || plan.Approval.ExpiresAt.Before(plan.ExpiresAt) || plan.Authorization.IssuedAt.After(plan.RequestedAt) || plan.Approval.ApprovedAt.After(plan.RequestedAt) || plan.Authorization.Subject == plan.Approval.Approver {
		return ErrUnauthorized
	}
	if requireDigest && !validDigest(plan.Digest) {
		return ErrInvalid
	}
	return nil
}

type Phase string

const (
	PhaseRequested        Phase = "requested"
	PhaseAdmitted         Phase = "admitted"
	PhaseDraining         Phase = "draining"
	PhaseCheckpointed     Phase = "checkpointed"
	PhaseArmed            Phase = "armed"
	PhaseRebootDispatched Phase = "reboot_dispatched"
	PhaseReconciling      Phase = "reconciling"
	PhaseSucceeded        Phase = "succeeded"
	PhaseCancelled        Phase = "cancelled"
	PhaseFailed           Phase = "failed"
	PhaseUncertain        Phase = "uncertain"
)

func (phase Phase) Valid() bool {
	switch phase {
	case PhaseRequested, PhaseAdmitted, PhaseDraining, PhaseCheckpointed, PhaseArmed,
		PhaseRebootDispatched, PhaseReconciling, PhaseSucceeded, PhaseCancelled, PhaseFailed, PhaseUncertain:
		return true
	default:
		return false
	}
}

func (phase Phase) Terminal() bool {
	return phase == PhaseSucceeded || phase == PhaseCancelled || phase == PhaseFailed || phase == PhaseUncertain
}

type OutcomeReason string

const (
	OutcomeNone                 OutcomeReason = ""
	OutcomeCompleted            OutcomeReason = "completed"
	OutcomeCancelled            OutcomeReason = "cancelled_before_arm"
	OutcomeStaleBootIdentity    OutcomeReason = "stale_boot_identity"
	OutcomeMaintenanceClosed    OutcomeReason = "maintenance_closed"
	OutcomeDrainIncomplete      OutcomeReason = "drain_incomplete"
	OutcomeCheckpointIncomplete OutcomeReason = "checkpoint_incomplete"
	OutcomeMarkerPartial        OutcomeReason = "marker_partial"
	OutcomeDispatchUnconfirmed  OutcomeReason = "dispatch_unconfirmed"
	OutcomeBootNotChanged       OutcomeReason = "boot_not_changed"
	OutcomeUnexpectedKernel     OutcomeReason = "unexpected_kernel"
	OutcomeReconciliationFailed OutcomeReason = "reconciliation_failed"
	OutcomeMarkerClearFailed    OutcomeReason = "marker_clear_failed"
)

func (reason OutcomeReason) Valid() bool {
	switch reason {
	case OutcomeNone, OutcomeCompleted, OutcomeCancelled, OutcomeStaleBootIdentity, OutcomeMaintenanceClosed,
		OutcomeDrainIncomplete, OutcomeCheckpointIncomplete, OutcomeMarkerPartial,
		OutcomeDispatchUnconfirmed, OutcomeBootNotChanged, OutcomeUnexpectedKernel,
		OutcomeReconciliationFailed, OutcomeMarkerClearFailed:
		return true
	default:
		return false
	}
}

type RecoveryStep string

const (
	RecoveryInspectMarker       RecoveryStep = "inspect_recovery_marker"
	RecoveryVerifyBootIdentity  RecoveryStep = "verify_boot_identity"
	RecoveryRetryDispatch       RecoveryStep = "retry_typed_reboot_dispatch"
	RecoveryRestoreBootEntry    RecoveryStep = "restore_proven_boot_entry"
	RecoveryRestoreSnapshot     RecoveryStep = "restore_proven_snapshot"
	RecoveryReleaseDrain        RecoveryStep = "release_listener_drain"
	RecoveryResumeOperations    RecoveryStep = "resume_checkpointed_operations"
	RecoveryReconcileSubsystems RecoveryStep = "reconcile_subsystems"
)

func (step RecoveryStep) Valid() bool {
	switch step {
	case RecoveryInspectMarker, RecoveryVerifyBootIdentity, RecoveryRetryDispatch,
		RecoveryRestoreBootEntry, RecoveryRestoreSnapshot, RecoveryReleaseDrain,
		RecoveryResumeOperations, RecoveryReconcileSubsystems:
		return true
	default:
		return false
	}
}

type State struct {
	PlanID            string         `json:"plan_id"`
	NodeID            string         `json:"node_id"`
	Phase             Phase          `json:"phase"`
	Generation        uint64         `json:"generation"`
	Fence             uint64         `json:"fence"`
	ControllerID      string         `json:"controller_id"`
	LastReceiptDigest string         `json:"last_receipt_digest,omitempty"`
	CheckpointReceiptDigest string   `json:"checkpoint_receipt_digest,omitempty"`
	MarkerDigest      string         `json:"marker_digest,omitempty"`
	Outcome           OutcomeReason  `json:"outcome,omitempty"`
	RecoverySteps     []RecoveryStep `json:"recovery_steps,omitempty"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

func (state State) Validate() error {
	if !identifierPattern.MatchString(state.PlanID) || !identifierPattern.MatchString(state.NodeID) || !state.Phase.Valid() || state.Generation == 0 || state.Generation > maxGeneration || state.Fence == 0 || state.Fence > maxGeneration || !identifierPattern.MatchString(state.ControllerID) || !validTimestamp(state.UpdatedAt) || !validDigest(state.LastReceiptDigest) || state.CheckpointReceiptDigest != "" && !validDigest(state.CheckpointReceiptDigest) || state.MarkerDigest != "" && !validDigest(state.MarkerDigest) || !state.Outcome.Valid() || len(state.RecoverySteps) > 32 {
		return ErrInvalid
	}
	if (state.Phase == PhaseArmed || state.Phase == PhaseRebootDispatched || state.Phase == PhaseReconciling || state.Phase == PhaseSucceeded) && state.MarkerDigest == "" {
		return ErrInvalid
	}
	if (state.Phase == PhaseCheckpointed || state.Phase == PhaseArmed || state.Phase == PhaseRebootDispatched || state.Phase == PhaseReconciling || state.Phase == PhaseSucceeded) && state.CheckpointReceiptDigest == "" {
		return ErrInvalid
	}
	for index, step := range state.RecoverySteps {
		if !step.Valid() || index > 0 && state.RecoverySteps[index-1] >= step {
			return ErrInvalid
		}
	}
	if state.Phase.Terminal() {
		if state.Outcome == OutcomeNone || state.Phase == PhaseSucceeded && state.Outcome != OutcomeCompleted ||
			state.Phase == PhaseCancelled && state.Outcome != OutcomeCancelled ||
			state.Phase != PhaseSucceeded && state.Phase != PhaseCancelled && len(state.RecoverySteps) == 0 {
			return ErrInvalid
		}
	} else if state.Outcome != OutcomeNone || len(state.RecoverySteps) != 0 {
		return ErrInvalid
	}
	return nil
}

type ReceiptKind string

const (
	ReceiptRequested    ReceiptKind = "requested"
	ReceiptTransition   ReceiptKind = "transition"
	ReceiptFenceAcquired ReceiptKind = "fence_acquired"
)

type Receipt struct {
	ID              string         `json:"id"`
	Kind            ReceiptKind    `json:"kind"`
	PlanID          string         `json:"plan_id"`
	NodeID          string         `json:"node_id"`
	From            Phase          `json:"from"`
	To              Phase          `json:"to"`
	Generation      uint64         `json:"generation"`
	Fence           uint64         `json:"fence"`
	IdempotencyKey  string         `json:"idempotency_key"`
	CommandDigest   string         `json:"command_digest"`
	EvidenceDigest  string         `json:"evidence_digest"`
	Outcome         OutcomeReason  `json:"outcome,omitempty"`
	RecoverySteps   []RecoveryStep `json:"recovery_steps,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	Digest          string         `json:"digest"`
}

func (receipt Receipt) Validate() error {
	if !identifierPattern.MatchString(receipt.ID) || (receipt.Kind != ReceiptRequested && receipt.Kind != ReceiptTransition && receipt.Kind != ReceiptFenceAcquired) || !identifierPattern.MatchString(receipt.PlanID) || !identifierPattern.MatchString(receipt.NodeID) || !receipt.From.Valid() || !receipt.To.Valid() || receipt.Generation == 0 || receipt.Generation > maxGeneration || receipt.Fence == 0 || receipt.Fence > maxGeneration || !identifierPattern.MatchString(receipt.IdempotencyKey) || !validDigest(receipt.CommandDigest) || !validDigest(receipt.EvidenceDigest) || !validTimestamp(receipt.CreatedAt) || !validDigest(receipt.Digest) || !receipt.Outcome.Valid() || len(receipt.RecoverySteps) > 32 {
		return ErrInvalid
	}
	for index, step := range receipt.RecoverySteps {
		if !step.Valid() || index > 0 && receipt.RecoverySteps[index-1] >= step {
			return ErrInvalid
		}
	}
	if receipt.To.Terminal() {
		if receipt.Outcome == OutcomeNone || receipt.To == PhaseSucceeded && receipt.Outcome != OutcomeCompleted ||
			receipt.To == PhaseCancelled && receipt.Outcome != OutcomeCancelled ||
			receipt.To != PhaseSucceeded && receipt.To != PhaseCancelled && len(receipt.RecoverySteps) == 0 {
			return ErrInvalid
		}
	} else if receipt.Outcome != OutcomeNone || len(receipt.RecoverySteps) != 0 {
		return ErrInvalid
	}
	return nil
}

type Transition struct {
	PlanID            string         `json:"plan_id"`
	From              Phase          `json:"from"`
	To                Phase          `json:"to"`
	ExpectedGeneration uint64        `json:"expected_generation"`
	Fence             uint64         `json:"fence"`
	ControllerID      string         `json:"controller_id"`
	IdempotencyKey    string         `json:"idempotency_key"`
	EvidenceDigest    string         `json:"evidence_digest"`
	MarkerDigest      string         `json:"marker_digest,omitempty"`
	Outcome           OutcomeReason  `json:"outcome,omitempty"`
	RecoverySteps     []RecoveryStep `json:"recovery_steps,omitempty"`
	At                time.Time      `json:"at"`
}

func canonicalRecoverySteps(steps []RecoveryStep) ([]RecoveryStep, error) {
	steps = append([]RecoveryStep(nil), steps...)
	sort.Slice(steps, func(left, right int) bool { return steps[left] < steps[right] })
	for index, step := range steps {
		if !step.Valid() || index > 0 && steps[index-1] == step {
			return nil, ErrInvalid
		}
	}
	return steps, nil
}

func canonicalAuthorization(value Authorization) (Authorization, error) {
	value.IssuedAt = value.IssuedAt.UTC()
	value.ExpiresAt = value.ExpiresAt.UTC()
	provided := value.Digest
	value.Digest = ""
	if !identifierPattern.MatchString(value.ID) || !identifierPattern.MatchString(value.Issuer) || !identifierPattern.MatchString(value.Subject) || value.Assurance != AssuranceStepUp || !validDigest(value.ScopeDigest) || !validDigest(value.ProofDigest) || !validTimestamp(value.IssuedAt) || !validTimestamp(value.ExpiresAt) || !value.ExpiresAt.After(value.IssuedAt) {
		return Authorization{}, ErrUnauthorized
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return Authorization{}, err
	}
	value.Digest = digestBytes(raw)
	if provided != "" && provided != value.Digest {
		return Authorization{}, ErrIntegrity
	}
	return value, nil
}

func canonicalApproval(value Approval) (Approval, error) {
	value.ApprovedAt = value.ApprovedAt.UTC()
	value.ExpiresAt = value.ExpiresAt.UTC()
	provided := value.Digest
	value.Digest = ""
	if !identifierPattern.MatchString(value.ID) || !identifierPattern.MatchString(value.Approver) || !identifierPattern.MatchString(value.Role) || !validDigest(value.PlanScopeDigest) || !validDigest(value.ProofDigest) || !validTimestamp(value.ApprovedAt) || !validTimestamp(value.ExpiresAt) || !value.ExpiresAt.After(value.ApprovedAt) {
		return Approval{}, ErrUnauthorized
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return Approval{}, err
	}
	value.Digest = digestBytes(raw)
	if provided != "" && provided != value.Digest {
		return Approval{}, ErrIntegrity
	}
	return value, nil
}

func planScopeDigest(plan Plan) string {
	value := struct {
		ID          string             `json:"id"`
		NodeID      string             `json:"node_id"`
		Reason      PlanReason         `json:"reason"`
		SourceBoot  BootIdentity       `json:"source_boot"`
		Maintenance MaintenanceBinding `json:"maintenance"`
		Packages    PackageState       `json:"packages"`
		Kernel      KernelState        `json:"kernel"`
		Expected    ExpectedBoot       `json:"expected_boot"`
		Rollback    RollbackCapability `json:"rollback"`
		Drain       DrainPolicy        `json:"drain"`
		Checkpoint  CheckpointPolicy   `json:"checkpoint"`
		RequestedAt time.Time          `json:"requested_at"`
		ExpiresAt   time.Time          `json:"expires_at"`
	}{plan.ID, plan.NodeID, plan.Reason, plan.SourceBoot, plan.Maintenance, plan.Packages, plan.Kernel,
		plan.ExpectedBoot, plan.Rollback, plan.Drain, plan.Checkpoint, plan.RequestedAt, plan.ExpiresAt}
	raw, _ := json.Marshal(value)
	return digestBytes(raw)
}

func validTimestamp(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && time.Unix(0, value.UnixNano()).UTC().Equal(value)
}

func validDigest(value string) bool {
	return len(value) == sha256.Size*2 && strings.Trim(value, "0123456789abcdef") == ""
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
