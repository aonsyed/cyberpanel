package rebootcontrol

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type MaintenanceProbe struct {
	OccurrenceID     string    `json:"occurrence_id"`
	OccurrenceDigest string    `json:"occurrence_digest"`
	Admissible       bool      `json:"admissible"`
	Active           bool      `json:"active"`
	EndsAt           time.Time `json:"ends_at"`
	EvidenceDigest   string    `json:"evidence_digest"`
}

func (probe MaintenanceProbe) Validate(binding MaintenanceBinding) error {
	if probe.OccurrenceID != binding.OccurrenceID || probe.OccurrenceDigest != binding.OccurrenceDigest || !validDigest(probe.EvidenceDigest) || !validTimestamp(probe.EndsAt) || !probe.EndsAt.Equal(binding.EndsAt) {
		return ErrIntegrity
	}
	return nil
}

type MaintenanceGate interface {
	ProbeRebootOccurrence(context.Context, MaintenanceBinding, string, time.Time) (MaintenanceProbe, error)
}

type BootIdentityProbe interface {
	CurrentBootIdentity(context.Context, string) (BootIdentity, error)
}

type AuthorizationVerifier interface {
	VerifyRebootAuthorization(context.Context, Authorization, Plan) error
	VerifyRebootApproval(context.Context, Approval, Plan) error
}

type DrainOperation struct {
	ID             string      `json:"id"`
	PlanID         string      `json:"plan_id"`
	PlanDigest     string      `json:"plan_digest"`
	NodeID         string      `json:"node_id"`
	Fence          uint64      `json:"fence"`
	Policy         DrainPolicy `json:"policy"`
	Deadline       time.Time   `json:"deadline"`
	OperationDigest string     `json:"operation_digest"`
}

type DrainResult struct {
	OperationID    string `json:"operation_id"`
	Fence          uint64 `json:"fence"`
	Complete       bool   `json:"complete"`
	RemainingWork  uint64 `json:"remaining_work"`
	EvidenceDigest string `json:"evidence_digest"`
}

type ListenerDrainer interface {
	DrainListeners(context.Context, DrainOperation) (DrainResult, error)
}

type OperationCheckpoint struct {
	ID              string                   `json:"id"`
	PlanID          string                   `json:"plan_id"`
	PlanDigest      string                   `json:"plan_digest"`
	NodeID          string                   `json:"node_id"`
	Fence           uint64                   `json:"fence"`
	Mode            OperationCheckpointMode `json:"mode"`
	MaximumOperations uint32                 `json:"maximum_operations"`
	Deadline        time.Time                `json:"deadline"`
	OperationDigest string                   `json:"operation_digest"`
}

type OperationCheckpointResult struct {
	OperationID       string `json:"operation_id"`
	Fence             uint64 `json:"fence"`
	Complete          bool   `json:"complete"`
	Checkpointed      uint32 `json:"checkpointed"`
	ResumableRecorded uint32 `json:"resumable_recorded"`
	NonResumable      uint32 `json:"non_resumable"`
	EvidenceDigest    string `json:"evidence_digest"`
}

type ResumableOperationCheckpointer interface {
	CheckpointOrRecordResumable(context.Context, OperationCheckpoint) (OperationCheckpointResult, error)
}

type SQLiteOperation struct {
	ID              string    `json:"id"`
	PlanID          string    `json:"plan_id"`
	PlanDigest      string    `json:"plan_digest"`
	NodeID          string    `json:"node_id"`
	DatabaseID      string    `json:"database_id"`
	Fence           uint64    `json:"fence"`
	Deadline        time.Time `json:"deadline"`
	OperationDigest string    `json:"operation_digest"`
}

type SQLiteResult struct {
	OperationID    string `json:"operation_id"`
	Fence          uint64 `json:"fence"`
	DatabaseID     string `json:"database_id"`
	Complete       bool   `json:"complete"`
	ArtifactDigest string `json:"artifact_digest"`
	EvidenceDigest string `json:"evidence_digest"`
}

type SQLiteSafety interface {
	CheckpointSQLite(context.Context, SQLiteOperation) (SQLiteResult, error)
	OnlineBackupSQLite(context.Context, SQLiteOperation) (SQLiteResult, error)
}

type RecoveryMarker struct {
	PlanID                  string             `json:"plan_id"`
	PlanDigest              string             `json:"plan_digest"`
	NodeID                  string             `json:"node_id"`
	Fence                   uint64             `json:"fence"`
	SourceBootID            string             `json:"source_boot_id"`
	MaintenanceOccurrenceID string             `json:"maintenance_occurrence_id"`
	MaintenanceDigest       string             `json:"maintenance_digest"`
	ExpectedBoot            ExpectedBoot       `json:"expected_boot"`
	Rollback                RollbackCapability `json:"rollback"`
	CheckpointReceiptDigest string             `json:"checkpoint_receipt_digest"`
	RebootOperationID       string             `json:"reboot_operation_id"`
	ArmedAt                 time.Time          `json:"armed_at"`
	Digest                  string             `json:"digest"`
}

func buildRecoveryMarker(plan Plan, state State, checkpointReceiptDigest string, at time.Time) (RecoveryMarker, error) {
	marker := RecoveryMarker{PlanID: plan.ID, PlanDigest: plan.Digest, NodeID: plan.NodeID, Fence: state.Fence,
		SourceBootID: plan.SourceBoot.BootID, MaintenanceOccurrenceID: plan.Maintenance.OccurrenceID,
		MaintenanceDigest: plan.Maintenance.OccurrenceDigest, ExpectedBoot: plan.ExpectedBoot,
		Rollback: plan.Rollback, CheckpointReceiptDigest: checkpointReceiptDigest,
		RebootOperationID: deterministicOperationID("reboot", plan.ID, state.Fence), ArmedAt: at}
	raw, err := json.Marshal(marker)
	if err != nil {
		return RecoveryMarker{}, err
	}
	marker.Digest = digestBytes(raw)
	return marker, marker.Validate()
}

func (marker RecoveryMarker) Validate() error {
	if !identifierPattern.MatchString(marker.PlanID) || !identifierPattern.MatchString(marker.NodeID) || marker.Fence == 0 || marker.Fence > maxGeneration || !validDigest(marker.PlanDigest) || !identifierPattern.MatchString(marker.SourceBootID) || !identifierPattern.MatchString(marker.MaintenanceOccurrenceID) || !validDigest(marker.MaintenanceDigest) || marker.ExpectedBoot.Validate() != nil || marker.Rollback.Validate() != nil || !validDigest(marker.CheckpointReceiptDigest) || !identifierPattern.MatchString(marker.RebootOperationID) || !validTimestamp(marker.ArmedAt) || !validDigest(marker.Digest) {
		return ErrInvalid
	}
	digest := marker.Digest
	marker.Digest = ""
	raw, err := json.Marshal(marker)
	if err != nil || digestBytes(raw) != digest {
		return ErrIntegrity
	}
	return nil
}

type MarkerArmResult struct {
	Committed      bool   `json:"committed"`
	Partial        bool   `json:"partial"`
	ExactDigest    string `json:"exact_digest"`
	EvidenceDigest string `json:"evidence_digest"`
}

type MarkerProbe struct {
	Present        bool   `json:"present"`
	Partial        bool   `json:"partial"`
	ExactDigest    string `json:"exact_digest,omitempty"`
	EvidenceDigest string `json:"evidence_digest"`
}

type MarkerClearResult struct {
	Cleared        bool   `json:"cleared"`
	ExactDigest    string `json:"exact_digest"`
	EvidenceDigest string `json:"evidence_digest"`
}

// RecoveryMarkerStore must make AtomicArm durable as one replace-and-sync
// operation. A returned Partial result is never considered armed.
type RecoveryMarkerStore interface {
	AtomicArm(context.Context, RecoveryMarker) (MarkerArmResult, error)
	Probe(context.Context, string) (MarkerProbe, error)
	ClearExact(context.Context, string, string) (MarkerClearResult, error)
}

type RebootOperation struct {
	ID              string    `json:"id"`
	PlanID          string    `json:"plan_id"`
	PlanDigest      string    `json:"plan_digest"`
	NodeID          string    `json:"node_id"`
	Fence           uint64    `json:"fence"`
	MarkerDigest    string    `json:"marker_digest"`
	SourceBootID    string    `json:"source_boot_id"`
	DispatchBy      time.Time `json:"dispatch_by"`
	OperationDigest string    `json:"operation_digest"`
}

type RebootDispatchResult struct {
	OperationID    string `json:"operation_id"`
	Fence          uint64 `json:"fence"`
	Accepted       bool   `json:"accepted"`
	EvidenceDigest string `json:"evidence_digest"`
}

// RebootDispatcher consumes only a typed, deterministic operation and must
// treat Operation.ID idempotently. No command string is part of this contract.
type RebootDispatcher interface {
	DispatchReboot(context.Context, RebootOperation) (RebootDispatchResult, error)
}

type ReconcileOperation struct {
	ID              string       `json:"id"`
	PlanID          string       `json:"plan_id"`
	PlanDigest      string       `json:"plan_digest"`
	NodeID          string       `json:"node_id"`
	Fence           uint64       `json:"fence"`
	ActualBootID    string       `json:"actual_boot_id"`
	KernelRelease   string       `json:"kernel_release"`
	KernelDigest    string       `json:"kernel_digest"`
	BootSlot        string       `json:"boot_slot,omitempty"`
	BootEvidenceDigest string    `json:"boot_evidence_digest"`
	OperationDigest string       `json:"operation_digest"`
}

type ComponentResult struct {
	Complete       bool   `json:"complete"`
	EvidenceDigest string `json:"evidence_digest"`
}

type ReconcileResult struct {
	OperationID    string          `json:"operation_id"`
	Fence          uint64          `json:"fence"`
	Services       ComponentResult `json:"services"`
	Configuration  ComponentResult `json:"configuration"`
	Locks          ComponentResult `json:"locks"`
	Schedules      ComponentResult `json:"schedules"`
	EvidenceDigest string          `json:"evidence_digest"`
}

func (result ReconcileResult) Complete() bool {
	return result.Services.Complete && result.Configuration.Complete && result.Locks.Complete && result.Schedules.Complete
}

type Reconciler interface {
	ReconcileAfterBoot(context.Context, ReconcileOperation) (ReconcileResult, error)
}

func deterministicOperationID(kind, planID string, fence uint64) string {
	input := strings.Join([]string{kind, planID, strconv.FormatUint(fence, 10)}, "\x00")
	digest := digestBytes([]byte(input))
	return "rebootop_" + digest[:48]
}
