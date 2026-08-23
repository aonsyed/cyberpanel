package recoveryproof

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type Signer interface {
	Sign(context.Context, TenantID, string) (Signature, error)
}

type Action string

const (
	ActionPlanCreate Action = "recoveryproof.plan.create"
	ActionDrillRun   Action = "recoveryproof.drill.run"
	ActionProofRead  Action = "recoveryproof.proof.read"
	ActionProofExport Action = "recoveryproof.proof.export"
)

type Actor struct {
	TenantID   TenantID
	PrincipalID PrincipalID
}

type Authorizer interface {
	Authorize(context.Context, Actor, Action, DrillPlan, *Drill) error
}

type AuditEvent struct {
	ID          string      `json:"id"`
	TenantID    TenantID    `json:"tenant_id"`
	PrincipalID PrincipalID `json:"principal_id"`
	Action      Action      `json:"action"`
	PlanID      PlanID      `json:"plan_id"`
	DrillID     DrillID     `json:"drill_id,omitempty"`
	Generation  uint64      `json:"generation,omitempty"`
	FenceToken  uint64      `json:"fence_token,omitempty"`
	Outcome     string      `json:"outcome"`
	ReasonCode  string      `json:"reason_code"`
	OccurredAt  time.Time   `json:"occurred_at"`
}

type Auditor interface {
	Record(context.Context, AuditEvent) error
}

type CapacityRequest struct {
	TenantID       TenantID
	PlanID         PlanID
	DrillID        DrillID
	Components     []Component
	IsolationClass string
	MaximumBytes   int64
	MaximumInodes  int64
}

type CapacityDecision struct {
	TenantID       TenantID
	DrillID        DrillID
	Admitted       bool
	ReasonCode     string
	ReservedBytes  int64
	ReservedInodes int64
	ReservationID  string
	Generation     uint64
	Digest         string
	ExpiresAt      time.Time
	Uncertain      bool
}

type CapacityAdmission interface {
	Admit(context.Context, CapacityRequest) (CapacityDecision, error)
}

type MaintenanceRequest struct {
	TenantID   TenantID
	PlanID     PlanID
	DrillID    DrillID
	ScheduledAt time.Time
	MaximumRun time.Duration
}

type MaintenanceDecision struct {
	TenantID   TenantID
	DrillID    DrillID
	Admitted   bool
	ReasonCode string
	WindowID   string
	Generation uint64
	Digest     string
	StartsAt   time.Time
	EndsAt     time.Time
	Uncertain  bool
}

type MaintenanceAdmission interface {
	Admit(context.Context, MaintenanceRequest) (MaintenanceDecision, error)
}

type RecoveryPointObservation struct {
	RecoveryPoint     RecoveryPoint
	ArtifactIntegrity bool
	OwnershipVerified bool
	ObservedCheckpoint time.Time
	CheckpointEvidence EvidenceID
	Evidence          []EvidenceReference
	ObservedAt        time.Time
}

type BackupCatalog interface {
	InspectRecoveryPoint(context.Context, TenantID, RecoveryPoint) (RecoveryPointObservation, error)
}

type AllocationRequest struct {
	TenantID    TenantID
	DrillID     DrillID
	Fence       Fence
	Policy      DestinationPolicy
	Capacity    CapacityDecision
	Effects     EffectProhibitions
}

type AllocationResult struct {
	Destination IsolatedDestination
	Resources   []ExactResourceReceipt
	Evidence    []EvidenceReference
	StartedAt   time.Time
	CompletedAt time.Time
}

type DestinationObservation struct {
	Destination IsolatedDestination
	OwnedByDrill bool
	NonRouted   bool
	ProductionEndpointCount uint32
	ObservedAt  time.Time
	Evidence    []EvidenceReference
}

type CleanupRequest struct {
	TenantID    TenantID
	DrillID     DrillID
	Fence       Fence
	Destination IsolatedDestination
	Resources   []ExactResourceReceipt
	Effects     EffectProhibitions
}

type CleanupResult struct {
	Resources   []ExactResourceReceipt
	Evidence    []EvidenceReference
	StartedAt   time.Time
	CompletedAt time.Time
	Complete    bool
	Ambiguous   bool
}

// IsolationManager has no route, promote, wildcard, prefix, or shared-resource
// mutation operation. Cleanup accepts only exact drill-owned descriptors.
type IsolationManager interface {
	Allocate(context.Context, AllocationRequest) (AllocationResult, error)
	Observe(context.Context, TenantID, DrillID, IsolatedDestination) (DestinationObservation, error)
	CleanupExact(context.Context, CleanupRequest) (CleanupResult, error)
}

type RestoreRequest struct {
	TenantID      TenantID
	DrillID       DrillID
	Fence         Fence
	RecoveryPoint RecoveryPoint
	Destination   IsolatedDestination
	Components    []Component
	Consistency   Consistency
	Effects       EffectProhibitions
}

type RestoreResult struct {
	OperationID       string
	RecoveryDigest    string
	DestinationDigest string
	Components        []Component
	StartedAt         time.Time
	CompletedAt       time.Time
	ObservedCheckpoint time.Time
	CheckpointEvidence EvidenceID
	Resources         []ExactResourceReceipt
	Evidence          []EvidenceReference
}

// RestoreEngine can write only to the supplied isolated destination. There is
// intentionally no production restore or promotion method in this boundary.
type RestoreEngine interface {
	RestoreIsolated(context.Context, RestoreRequest) (RestoreResult, error)
}

type ProbeRequest struct {
	TenantID      TenantID
	DrillID       DrillID
	Fence         Fence
	Kind          CheckKind
	Destination   IsolatedDestination
	RecoveryPoint RecoveryPoint
	ReadOnly      bool
	Effects       EffectProhibitions
}

type ProbeResult struct {
	Kind        CheckKind
	Status      CheckStatus
	StartedAt   time.Time
	CompletedAt time.Time
	Evidence    []EvidenceReference
	Findings    []Finding
	ObservedCheckpoint time.Time
	CheckpointEvidence EvidenceID
}

// ProbeSuite exposes only closed, read-only verification checks.
type ProbeSuite interface {
	Probe(context.Context, ProbeRequest) (ProbeResult, error)
}

type AlertKind string

const (
	AlertStale  AlertKind = "stale_proof"
	AlertMissed AlertKind = "missed_occurrence"
	AlertFailed AlertKind = "failed_proof"
)

type Alert struct {
	ID         string    `json:"id"`
	TenantID   TenantID  `json:"tenant_id"`
	PlanID     PlanID    `json:"plan_id"`
	DrillID    DrillID   `json:"drill_id,omitempty"`
	Kind       AlertKind `json:"kind"`
	ReasonCode string    `json:"reason_code"`
	EvidenceDigest string `json:"evidence_digest,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type AlertSink interface {
	Notify(context.Context, Alert) error
}

type DrillProjection struct {
	TenantID       TenantID         `json:"tenant_id"`
	PlanID         PlanID           `json:"plan_id"`
	DrillID        DrillID          `json:"drill_id"`
	OccurrenceKey  string           `json:"occurrence_key"`
	ScheduledAt    time.Time        `json:"scheduled_at"`
	State          DrillState       `json:"state"`
	Generation     uint64           `json:"generation"`
	ActualRPO      MeasuredDuration `json:"actual_rpo"`
	ActualRTO      MeasuredDuration `json:"actual_rto"`
	FindingCount   int              `json:"finding_count"`
	EvidenceCount  int              `json:"evidence_count"`
	ProofDigest    string           `json:"proof_digest,omitempty"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

func projectDrill(drill Drill) DrillProjection {
	return DrillProjection{
		TenantID:      drill.TenantID,
		PlanID:        drill.PlanID,
		DrillID:       drill.ID,
		OccurrenceKey: drill.OccurrenceKey,
		ScheduledAt:   drill.ScheduledAt,
		State:         drill.State,
		Generation:    drill.Generation,
		ActualRPO:     drill.ActualRPO,
		ActualRTO:     drill.ActualRTO,
		FindingCount:  len(drill.Findings),
		EvidenceCount: len(drill.Evidence),
		ProofDigest:   drill.ProofDigest,
		UpdatedAt:     drill.UpdatedAt,
	}
}

type ExportBundle struct {
	TenantID    TenantID         `json:"tenant_id"`
	GeneratedAt time.Time        `json:"generated_at"`
	Items       []DrillProjection `json:"items"`
	NextCursor  *DrillCursor     `json:"next_cursor,omitempty"`
	Digest      string           `json:"digest"`
	Signature   Signature        `json:"signature"`
}

func SignProjectionExport(
	ctx context.Context,
	tenantID TenantID,
	generatedAt time.Time,
	items []DrillProjection,
	nextCursor *DrillCursor,
	signer Signer,
) (ExportBundle, error) {
	if signer == nil || !validLocalID(string(tenantID)) || generatedAt.IsZero() ||
		len(items) > MaximumExportItems {
		return ExportBundle{}, fmt.Errorf("%w: projection export", ErrInvalid)
	}
	rows := append([]DrillProjection(nil), items...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ScheduledAt.Equal(rows[j].ScheduledAt) {
			return rows[i].DrillID < rows[j].DrillID
		}
		return rows[i].ScheduledAt.Before(rows[j].ScheduledAt)
	})
	for _, row := range rows {
		if row.TenantID != tenantID || !validLocalID(string(row.DrillID)) ||
			!validLocalID(string(row.PlanID)) || !validDigest(row.OccurrenceKey) ||
			!row.State.valid() || row.Generation == 0 || row.ScheduledAt.IsZero() ||
			row.UpdatedAt.IsZero() || row.FindingCount < 0 || row.EvidenceCount < 0 ||
			(row.ProofDigest != "" && !validDigest(row.ProofDigest)) ||
			validateMeasurement(row.ActualRPO) != nil || validateMeasurement(row.ActualRTO) != nil {
			return ExportBundle{}, fmt.Errorf("%w: projection row", ErrInvalid)
		}
	}
	var cursorCopy *DrillCursor
	if nextCursor != nil {
		copied := *nextCursor
		copied.ScheduledAt = canonicalTime(copied.ScheduledAt)
		cursorCopy = &copied
	}
	bundle := ExportBundle{
		TenantID:    tenantID,
		GeneratedAt: canonicalTime(generatedAt),
		Items:       rows,
		NextCursor:  cursorCopy,
	}
	if nextCursor != nil && (nextCursor.ScheduledAt.IsZero() ||
		!validLocalID(string(nextCursor.DrillID))) {
		return ExportBundle{}, fmt.Errorf("%w: export cursor", ErrInvalid)
	}
	digest, err := canonicalDigest(bundle)
	if err != nil {
		return ExportBundle{}, err
	}
	signature, err := signer.Sign(ctx, tenantID, digest)
	if err != nil {
		return ExportBundle{}, fmt.Errorf("recoveryproof: sign projection export: %w", err)
	}
	if !validLocalID(signature.Algorithm) || !validLocalID(signature.KeyID) ||
		signature.KeyVersion == 0 || signature.Value == "" || len(signature.Value) > 16384 {
		return ExportBundle{}, fmt.Errorf("%w: export signature", ErrInvalid)
	}
	bundle.Digest = digest
	bundle.Signature = signature
	return bundle, nil
}

const (
	MaximumListItems   = 500
	MaximumExportItems = 1000
)
