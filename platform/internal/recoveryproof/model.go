// Package recoveryproof coordinates isolated, non-destructive restore drills
// and records durable evidence of measured recovery capability.
package recoveryproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid         = errors.New("recoveryproof: invalid value")
	ErrNotFound        = errors.New("recoveryproof: not found")
	ErrConflict        = errors.New("recoveryproof: conflict")
	ErrStaleGeneration = errors.New("recoveryproof: stale generation")
	ErrFenceLost       = errors.New("recoveryproof: fence lost")
	ErrUnauthorized    = errors.New("recoveryproof: unauthorized")
	ErrAdmission       = errors.New("recoveryproof: admission denied")
	ErrIntegrity       = errors.New("recoveryproof: integrity failure")
	ErrUncertain       = errors.New("recoveryproof: outcome uncertain")
	ErrProofFailed     = errors.New("recoveryproof: verification failed")
	ErrLimit           = errors.New("recoveryproof: bound exceeded")
	ErrProhibited      = errors.New("recoveryproof: destructive effect prohibited")
)

type TenantID string
type PlanID string
type DrillID string
type PrincipalID string
type NamespaceID string
type ReceiptID string
type EvidenceID string

type Component string

const (
	ComponentArtifacts     Component = "artifacts"
	ComponentConfiguration Component = "configuration"
	ComponentDatabase      Component = "database"
	ComponentMail          Component = "mail"
	ComponentApplication   Component = "application"
)

func (v Component) valid() bool {
	switch v {
	case ComponentArtifacts, ComponentConfiguration, ComponentDatabase,
		ComponentMail, ComponentApplication:
		return true
	default:
		return false
	}
}

type Consistency string

const (
	ConsistencyApplication Consistency = "application_consistent"
	ConsistencyComponent   Consistency = "component_consistent"
	ConsistencyCrash       Consistency = "crash_consistent"
)

func (v Consistency) valid() bool {
	return v == ConsistencyApplication || v == ConsistencyComponent || v == ConsistencyCrash
}

type BackupIdentity struct {
	Provider   string `json:"provider"`
	BackupID   string `json:"backup_id"`
	Generation uint64 `json:"generation"`
	Digest     string `json:"digest"`
}

type RecoveryPointIdentity struct {
	RecoveryPointID string    `json:"recovery_point_id"`
	Generation      uint64    `json:"generation"`
	Digest          string    `json:"digest"`
	CreatedAt       time.Time `json:"created_at"`
}

type RecoveryPoint struct {
	Backup      BackupIdentity        `json:"backup"`
	Point       RecoveryPointIdentity `json:"point"`
	Components []Component           `json:"components"`
	Consistency Consistency           `json:"consistency"`
}

func (r RecoveryPoint) Validate() error {
	if !validLocalID(r.Backup.Provider) || !validLocalID(r.Backup.BackupID) ||
		r.Backup.Generation == 0 || !validDigest(r.Backup.Digest) ||
		!validLocalID(r.Point.RecoveryPointID) || r.Point.Generation == 0 ||
		!validDigest(r.Point.Digest) || r.Point.CreatedAt.IsZero() || !r.Consistency.valid() {
		return fmt.Errorf("%w: recovery point identity", ErrInvalid)
	}
	return validateComponents(r.Components)
}

type CheckKind string

const (
	CheckArtifactIntegrity CheckKind = "artifact_integrity"
	CheckOwnership         CheckKind = "ownership"
	CheckConfiguration     CheckKind = "configuration"
	CheckDatabase          CheckKind = "database"
	CheckMail              CheckKind = "mail"
	CheckApplication       CheckKind = "application"
)

var requiredChecks = []CheckKind{
	CheckArtifactIntegrity,
	CheckOwnership,
	CheckConfiguration,
	CheckDatabase,
	CheckMail,
	CheckApplication,
}

func (v CheckKind) valid() bool {
	switch v {
	case CheckArtifactIntegrity, CheckOwnership, CheckConfiguration,
		CheckDatabase, CheckMail, CheckApplication:
		return true
	default:
		return false
	}
}

type EffectProhibitions struct {
	ProductionWrites bool `json:"production_writes_prohibited"`
	Promotion        bool `json:"promotion_prohibited"`
	Routing          bool `json:"routing_prohibited"`
	SharedMutation   bool `json:"shared_mutation_prohibited"`
}

func StrictEffectProhibitions() EffectProhibitions {
	return EffectProhibitions{
		ProductionWrites: true,
		Promotion:        true,
		Routing:          true,
		SharedMutation:   true,
	}
}

func (p EffectProhibitions) strict() bool {
	return p.ProductionWrites && p.Promotion && p.Routing && p.SharedMutation
}

type DestinationPolicy struct {
	IsolationClass string             `json:"isolation_class"`
	Ephemeral      bool               `json:"ephemeral"`
	NewNamespace   bool               `json:"new_namespace"`
	NonRouted      bool               `json:"non_routed"`
	Effects        EffectProhibitions `json:"effects"`
}

func (p DestinationPolicy) Validate() error {
	if !validLocalID(p.IsolationClass) || !p.Ephemeral || !p.NewNamespace ||
		!p.NonRouted || !p.Effects.strict() {
		return ErrProhibited
	}
	return nil
}

type SchedulePolicy struct {
	FirstDueAt      time.Time     `json:"first_due_at"`
	Interval        time.Duration `json:"interval"`
	MaximumLateness time.Duration `json:"maximum_lateness"`
}

func (p SchedulePolicy) Validate() error {
	if p.FirstDueAt.IsZero() || p.Interval < time.Hour || p.Interval > 365*24*time.Hour ||
		p.MaximumLateness <= 0 || p.MaximumLateness > p.Interval {
		return fmt.Errorf("%w: schedule policy", ErrInvalid)
	}
	return nil
}

func (p SchedulePolicy) NextAfter(scheduledAt time.Time) time.Time {
	return canonicalTime(scheduledAt).Add(p.Interval)
}

type RetentionPolicy struct {
	ProofRetention    time.Duration `json:"proof_retention"`
	EvidenceRetention time.Duration `json:"evidence_retention"`
}

func (p RetentionPolicy) Validate() error {
	if p.ProofRetention < 24*time.Hour || p.ProofRetention > 10*365*24*time.Hour ||
		p.EvidenceRetention < p.ProofRetention || p.EvidenceRetention > 10*365*24*time.Hour {
		return fmt.Errorf("%w: retention policy", ErrInvalid)
	}
	return nil
}

type DrillPlan struct {
	ID            PlanID            `json:"id"`
	TenantID      TenantID          `json:"tenant_id"`
	Name          string            `json:"name"`
	Components    []Component       `json:"components"`
	Consistency   Consistency       `json:"consistency"`
	RPOTarget     time.Duration     `json:"rpo_target"`
	Destination   DestinationPolicy `json:"destination"`
	Checklist     []CheckKind       `json:"checklist"`
	Schedule      SchedulePolicy    `json:"schedule"`
	Retention     RetentionPolicy   `json:"retention"`
	Generation    uint64            `json:"generation"`
	CreatedAt     time.Time         `json:"created_at"`
	Digest        string            `json:"digest"`
}

func SealPlan(plan DrillPlan) (DrillPlan, error) {
	if !validLocalID(string(plan.ID)) || !validLocalID(string(plan.TenantID)) ||
		!safeLabel(plan.Name) || !plan.Consistency.valid() || plan.RPOTarget <= 0 ||
		plan.RPOTarget > 30*24*time.Hour || plan.Generation != 1 || plan.CreatedAt.IsZero() {
		return DrillPlan{}, fmt.Errorf("%w: drill plan", ErrInvalid)
	}
	if err := validateComponents(plan.Components); err != nil {
		return DrillPlan{}, err
	}
	if !sameChecks(plan.Checklist, requiredChecks) {
		return DrillPlan{}, fmt.Errorf("%w: verification checklist", ErrInvalid)
	}
	if err := plan.Destination.Validate(); err != nil {
		return DrillPlan{}, err
	}
	if err := plan.Schedule.Validate(); err != nil {
		return DrillPlan{}, err
	}
	if err := plan.Retention.Validate(); err != nil {
		return DrillPlan{}, err
	}
	plan.CreatedAt = canonicalTime(plan.CreatedAt)
	plan.Schedule.FirstDueAt = canonicalTime(plan.Schedule.FirstDueAt)
	plan.Digest = ""
	digest, err := canonicalDigest(plan)
	if err != nil {
		return DrillPlan{}, err
	}
	plan.Digest = digest
	return plan, nil
}

type ScheduleState struct {
	TenantID         TenantID `json:"tenant_id"`
	PlanID           PlanID   `json:"plan_id"`
	PlanDigest       string   `json:"plan_digest"`
	Generation       uint64   `json:"generation"`
	NextDueAt        time.Time `json:"next_due_at"`
	LastScheduledAt  time.Time `json:"last_scheduled_at,omitempty"`
	LastOccurrenceKey string  `json:"last_occurrence_key,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
	Digest           string   `json:"digest"`
}

func SealScheduleState(state ScheduleState) (ScheduleState, error) {
	if !validLocalID(string(state.TenantID)) || !validLocalID(string(state.PlanID)) ||
		!validDigest(state.PlanDigest) || state.Generation == 0 || state.NextDueAt.IsZero() ||
		state.UpdatedAt.IsZero() || state.UpdatedAt.After(state.NextDueAt.Add(10*365*24*time.Hour)) {
		return ScheduleState{}, fmt.Errorf("%w: schedule state", ErrInvalid)
	}
	if state.Generation > 1 && (state.LastScheduledAt.IsZero() || !validDigest(state.LastOccurrenceKey)) {
		return ScheduleState{}, fmt.Errorf("%w: schedule occurrence", ErrInvalid)
	}
	state.NextDueAt = canonicalTime(state.NextDueAt)
	state.LastScheduledAt = canonicalTime(state.LastScheduledAt)
	state.UpdatedAt = canonicalTime(state.UpdatedAt)
	state.Digest = ""
	digest, err := canonicalDigest(state)
	if err != nil {
		return ScheduleState{}, err
	}
	state.Digest = digest
	return state, nil
}

type DrillState string

const (
	StatePlanned   DrillState = "planned"
	StateAdmitted  DrillState = "admitted"
	StateRestoring DrillState = "restoring"
	StateVerifying DrillState = "verifying"
	StateCleaning  DrillState = "cleaning"
	StateProved    DrillState = "proved"
	StateFailed    DrillState = "failed"
	StateUncertain DrillState = "uncertain"
)

func (s DrillState) valid() bool {
	switch s {
	case StatePlanned, StateAdmitted, StateRestoring, StateVerifying,
		StateCleaning, StateProved, StateFailed, StateUncertain:
		return true
	default:
		return false
	}
}

func (s DrillState) terminal() bool {
	return s == StateProved || s == StateFailed || s == StateUncertain
}

func transitionAllowed(from, to DrillState) bool {
	switch from {
	case StatePlanned:
		return to == StateAdmitted || to == StateFailed || to == StateUncertain
	case StateAdmitted:
		return to == StateRestoring || to == StateCleaning || to == StateFailed || to == StateUncertain
	case StateRestoring:
		return to == StateVerifying || to == StateCleaning || to == StateUncertain
	case StateVerifying:
		return to == StateCleaning || to == StateUncertain
	case StateCleaning:
		return to == StateProved || to == StateFailed || to == StateUncertain
	default:
		return false
	}
}

type Fence struct {
	Token     uint64    `json:"token"`
	LeaseID   string    `json:"lease_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type IsolatedDestination struct {
	NamespaceID NamespaceID        `json:"namespace_id"`
	AllocationID string            `json:"allocation_id"`
	TenantID    TenantID           `json:"tenant_id"`
	DrillID     DrillID            `json:"drill_id"`
	Generation uint64              `json:"generation"`
	Digest     string              `json:"digest"`
	CreatedAt  time.Time           `json:"created_at"`
	NonRouted  bool                `json:"non_routed"`
	Ephemeral  bool                `json:"ephemeral"`
	NewlyAllocated bool            `json:"newly_allocated"`
	ProductionEndpointCount uint32 `json:"production_endpoint_count"`
	Effects     EffectProhibitions `json:"effects"`
}

func (d IsolatedDestination) Validate(tenantID TenantID, drillID DrillID) error {
	if !validLocalID(string(d.NamespaceID)) || !validLocalID(d.AllocationID) ||
		d.TenantID != tenantID || d.DrillID != drillID || d.Generation == 0 ||
		!validDigest(d.Digest) || d.CreatedAt.IsZero() || !d.NonRouted || !d.Ephemeral ||
		!d.NewlyAllocated || d.ProductionEndpointCount != 0 || !d.Effects.strict() {
		return ErrProhibited
	}
	return nil
}

type Phase string

const (
	PhaseAdmission    Phase = "admission"
	PhaseAllocation   Phase = "allocation"
	PhaseRestore      Phase = "restore"
	PhaseVerification Phase = "verification"
	PhaseCleanup      Phase = "cleanup"
)

type PhaseTiming struct {
	Phase       Phase         `json:"phase"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Elapsed     time.Duration `json:"elapsed"`
}

func NewPhaseTiming(phase Phase, startedAt, completedAt time.Time) (PhaseTiming, error) {
	startedAt = canonicalTime(startedAt)
	completedAt = canonicalTime(completedAt)
	if startedAt.IsZero() || completedAt.Before(startedAt) {
		return PhaseTiming{}, fmt.Errorf("%w: phase timing", ErrInvalid)
	}
	return PhaseTiming{
		Phase:       phase,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Elapsed:     completedAt.Sub(startedAt),
	}, nil
}

type CheckStatus string

const (
	CheckPassed    CheckStatus = "passed"
	CheckFailed    CheckStatus = "failed"
	CheckUncertain CheckStatus = "uncertain"
)

type CheckResult struct {
	Kind        CheckKind    `json:"kind"`
	Status      CheckStatus  `json:"status"`
	StartedAt   time.Time    `json:"started_at"`
	CompletedAt time.Time    `json:"completed_at"`
	EvidenceIDs []EvidenceID `json:"evidence_ids"`
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	Code        string       `json:"code"`
	Severity    Severity     `json:"severity"`
	Check       CheckKind    `json:"check,omitempty"`
	Count       uint64       `json:"count"`
	EvidenceIDs []EvidenceID `json:"evidence_ids,omitempty"`
}

type EvidenceReference struct {
	ID          EvidenceID `json:"id"`
	Kind        string     `json:"kind"`
	Digest      string     `json:"digest"`
	Size        int64      `json:"size"`
	Redacted    bool       `json:"redacted"`
	RetainUntil time.Time  `json:"retain_until"`
}

type MeasuredDuration struct {
	Known           bool          `json:"known"`
	Value           time.Duration `json:"value,omitempty"`
	BasisEvidenceID EvidenceID    `json:"basis_evidence_id,omitempty"`
}

type Drill struct {
	ID              DrillID              `json:"id"`
	TenantID        TenantID             `json:"tenant_id"`
	PlanID          PlanID               `json:"plan_id"`
	PlanDigest      string               `json:"plan_digest"`
	OccurrenceKey   string               `json:"occurrence_key"`
	ScheduledAt     time.Time            `json:"scheduled_at"`
	RecoveryPoint   RecoveryPoint        `json:"recovery_point"`
	State           DrillState           `json:"state"`
	Generation      uint64               `json:"generation"`
	Fence           Fence                `json:"fence"`
	Destination     *IsolatedDestination `json:"destination,omitempty"`
	PhaseTimings    []PhaseTiming        `json:"phase_timings,omitempty"`
	Checks          []CheckResult        `json:"checks,omitempty"`
	Findings        []Finding            `json:"findings,omitempty"`
	Evidence        []EvidenceReference  `json:"evidence,omitempty"`
	ObservedCheckpoint time.Time         `json:"observed_checkpoint,omitempty"`
	ActualRPO       MeasuredDuration     `json:"actual_rpo"`
	ActualRTO       MeasuredDuration     `json:"actual_rto"`
	ProofDigest     string               `json:"proof_digest,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
	Digest          string               `json:"digest"`
}

func SealDrill(drill Drill) (Drill, error) {
	if !validLocalID(string(drill.ID)) || !validLocalID(string(drill.TenantID)) ||
		!validLocalID(string(drill.PlanID)) || !validDigest(drill.PlanDigest) ||
		!validDigest(drill.OccurrenceKey) || drill.ScheduledAt.IsZero() ||
		!drill.State.valid() || drill.Generation == 0 || drill.CreatedAt.IsZero() ||
		drill.UpdatedAt.Before(drill.CreatedAt) {
		return Drill{}, fmt.Errorf("%w: drill identity", ErrInvalid)
	}
	if err := drill.RecoveryPoint.Validate(); err != nil {
		return Drill{}, err
	}
	if drill.State == StatePlanned || ((drill.State == StateFailed || drill.State == StateUncertain) && drill.Fence.Token == 0) {
		if drill.Fence.Token != 0 || drill.Fence.LeaseID != "" || !drill.Fence.ExpiresAt.IsZero() {
			return Drill{}, fmt.Errorf("%w: planned drill fence", ErrInvalid)
		}
	} else if drill.Fence.Token == 0 || !validLocalID(drill.Fence.LeaseID) || drill.Fence.ExpiresAt.IsZero() {
		return Drill{}, fmt.Errorf("%w: active drill fence", ErrInvalid)
	}
	if drill.Destination != nil {
		if err := drill.Destination.Validate(drill.TenantID, drill.ID); err != nil {
			return Drill{}, err
		}
	}
	if (drill.State == StateRestoring || drill.State == StateVerifying ||
		drill.State == StateProved) && drill.Destination == nil {
		return Drill{}, fmt.Errorf("%w: drill destination", ErrInvalid)
	}
	if len(drill.PhaseTimings) > 16 || len(drill.Checks) > len(requiredChecks) ||
		len(drill.Findings) > 256 || len(drill.Evidence) > 512 {
		return Drill{}, ErrLimit
	}
	if err := validateFindings(drill.Findings); err != nil {
		return Drill{}, err
	}
	if err := validateEvidence(drill.Evidence); err != nil {
		return Drill{}, err
	}
	if err := validatePhaseTimings(drill.PhaseTimings); err != nil {
		return Drill{}, err
	}
	if err := validateCheckResults(drill.Checks, false); err != nil {
		return Drill{}, err
	}
	if err := validateMeasurement(drill.ActualRPO); err != nil {
		return Drill{}, fmt.Errorf("%w: measured RPO", ErrInvalid)
	}
	if err := validateMeasurement(drill.ActualRTO); err != nil {
		return Drill{}, fmt.Errorf("%w: measured RTO", ErrInvalid)
	}
	if drill.ActualRPO.Known && drill.ObservedCheckpoint.IsZero() {
		return Drill{}, fmt.Errorf("%w: RPO checkpoint", ErrInvalid)
	}
	if drill.State.terminal() && !validDigest(drill.ProofDigest) {
		return Drill{}, fmt.Errorf("%w: terminal proof digest", ErrInvalid)
	}
	if drill.State == StateProved && (!drill.ActualRPO.Known || !drill.ActualRTO.Known) {
		return Drill{}, fmt.Errorf("%w: proved drill measurements", ErrInvalid)
	}
	drill.ScheduledAt = canonicalTime(drill.ScheduledAt)
	drill.Fence.ExpiresAt = canonicalTime(drill.Fence.ExpiresAt)
	drill.ObservedCheckpoint = canonicalTime(drill.ObservedCheckpoint)
	drill.CreatedAt = canonicalTime(drill.CreatedAt)
	drill.UpdatedAt = canonicalTime(drill.UpdatedAt)
	drill.Digest = ""
	digest, err := canonicalDigest(drill)
	if err != nil {
		return Drill{}, err
	}
	drill.Digest = digest
	return drill, nil
}

func DrillIdentityEqual(a, b Drill) bool {
	aRecovery, aErr := canonicalDigest(a.RecoveryPoint)
	bRecovery, bErr := canonicalDigest(b.RecoveryPoint)
	return aErr == nil && bErr == nil && aRecovery == bRecovery &&
		a.ID == b.ID && a.TenantID == b.TenantID && a.PlanID == b.PlanID &&
		a.PlanDigest == b.PlanDigest && a.OccurrenceKey == b.OccurrenceKey &&
		a.ScheduledAt.Equal(b.ScheduledAt) && a.CreatedAt.Equal(b.CreatedAt)
}

type ReceiptKind string

const (
	ReceiptOccurrence   ReceiptKind = "occurrence"
	ReceiptAdmission    ReceiptKind = "admission"
	ReceiptAllocation   ReceiptKind = "allocation"
	ReceiptRestore      ReceiptKind = "restore"
	ReceiptVerification ReceiptKind = "verification"
	ReceiptCleanup      ReceiptKind = "cleanup"
	ReceiptProof        ReceiptKind = "proof"
)

func (k ReceiptKind) valid() bool {
	switch k {
	case ReceiptOccurrence, ReceiptAdmission, ReceiptAllocation, ReceiptRestore,
		ReceiptVerification, ReceiptCleanup, ReceiptProof:
		return true
	default:
		return false
	}
}

type ResourceStatus string

const (
	ResourceCreated   ResourceStatus = "created"
	ResourceVerified  ResourceStatus = "verified"
	ResourceDeleted   ResourceStatus = "deleted"
	ResourceAbsent    ResourceStatus = "already_absent"
	ResourceAmbiguous ResourceStatus = "ambiguous"
)

type ExactResourceReceipt struct {
	DescriptorID string         `json:"descriptor_id"`
	ObjectID     string         `json:"object_id"`
	TenantID     TenantID       `json:"tenant_id"`
	DrillID      DrillID        `json:"drill_id"`
	Generation   uint64         `json:"generation"`
	Digest       string         `json:"digest"`
	Status       ResourceStatus `json:"status"`
}

type Receipt struct {
	ID               ReceiptID             `json:"id"`
	TenantID         TenantID              `json:"tenant_id"`
	DrillID          DrillID               `json:"drill_id"`
	Kind             ReceiptKind           `json:"kind"`
	FromState        DrillState            `json:"from_state"`
	ToState          DrillState            `json:"to_state"`
	DrillGeneration  uint64                `json:"drill_generation"`
	FenceToken       uint64                `json:"fence_token"`
	StatusCode       string                `json:"status_code"`
	EvidenceDigests  []string              `json:"evidence_digests,omitempty"`
	Resources        []ExactResourceReceipt `json:"resources,omitempty"`
	CreatedAt        time.Time             `json:"created_at"`
	Digest           string                `json:"digest"`
}

func SealReceipt(receipt Receipt) (Receipt, error) {
	if !validLocalID(string(receipt.ID)) || !validLocalID(string(receipt.TenantID)) ||
		!validLocalID(string(receipt.DrillID)) || !receipt.Kind.valid() || !receipt.FromState.valid() ||
		!receipt.ToState.valid() || receipt.DrillGeneration == 0 ||
		!validReason(receipt.StatusCode) || receipt.CreatedAt.IsZero() ||
		len(receipt.EvidenceDigests) > 1024 || len(receipt.Resources) > 512 {
		return Receipt{}, fmt.Errorf("%w: receipt", ErrInvalid)
	}
	for _, digest := range receipt.EvidenceDigests {
		if !validDigest(digest) {
			return Receipt{}, fmt.Errorf("%w: receipt evidence digest", ErrInvalid)
		}
	}
	for _, resource := range receipt.Resources {
		if !validLocalID(resource.DescriptorID) || !validLocalID(resource.ObjectID) ||
			resource.TenantID != receipt.TenantID || resource.DrillID != receipt.DrillID ||
			resource.Generation == 0 || !validDigest(resource.Digest) {
			return Receipt{}, fmt.Errorf("%w: exact resource receipt", ErrInvalid)
		}
		switch resource.Status {
		case ResourceCreated, ResourceVerified, ResourceDeleted, ResourceAbsent, ResourceAmbiguous:
		default:
			return Receipt{}, fmt.Errorf("%w: exact resource status", ErrInvalid)
		}
	}
	receipt.CreatedAt = canonicalTime(receipt.CreatedAt)
	receipt.Digest = ""
	digest, err := canonicalDigest(receipt)
	if err != nil {
		return Receipt{}, err
	}
	receipt.Digest = digest
	return receipt, nil
}

type Signature struct {
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	KeyVersion uint64 `json:"key_version"`
	Value      string `json:"value"`
}

type ProofManifest struct {
	ID                 string              `json:"id"`
	TenantID           TenantID            `json:"tenant_id"`
	DrillID            DrillID             `json:"drill_id"`
	DrillDigest        string              `json:"drill_digest"`
	PlanID             PlanID              `json:"plan_id"`
	PlanDigest         string              `json:"plan_digest"`
	RecoveryPoint      RecoveryPoint       `json:"recovery_point"`
	DestinationDigest  string              `json:"destination_digest"`
	Checklist          []CheckResult       `json:"checklist"`
	PhaseTimings       []PhaseTiming       `json:"phase_timings"`
	ObservedCheckpoint time.Time           `json:"observed_checkpoint,omitempty"`
	ActualRPO          MeasuredDuration    `json:"actual_rpo"`
	ActualRTO          MeasuredDuration    `json:"actual_rto"`
	Findings           []Finding           `json:"findings,omitempty"`
	Evidence           []EvidenceReference `json:"evidence,omitempty"`
	Outcome            DrillState          `json:"outcome"`
	CreatedAt          time.Time           `json:"created_at"`
	RetainUntil        time.Time           `json:"retain_until"`
	PayloadDigest      string              `json:"payload_digest"`
	Signature          Signature           `json:"signature"`
}

func SignProof(ctx context.Context, proof ProofManifest, signer Signer) (ProofManifest, error) {
	if signer == nil || !validLocalID(proof.ID) || !validLocalID(string(proof.TenantID)) ||
		!validLocalID(string(proof.DrillID)) || !validDigest(proof.DrillDigest) ||
		!validLocalID(string(proof.PlanID)) || !validDigest(proof.PlanDigest) ||
		!proof.Outcome.terminal() ||
		proof.CreatedAt.IsZero() || !proof.RetainUntil.After(proof.CreatedAt) {
		return ProofManifest{}, fmt.Errorf("%w: proof manifest", ErrInvalid)
	}
	if err := proof.RecoveryPoint.Validate(); err != nil {
		return ProofManifest{}, err
	}
	if len(proof.Checklist) != len(requiredChecks) || len(proof.PhaseTimings) > 16 ||
		len(proof.Findings) > 256 || len(proof.Evidence) > 512 {
		return ProofManifest{}, ErrLimit
	}
	if proof.Outcome == StateProved && !validDigest(proof.DestinationDigest) {
		return ProofManifest{}, fmt.Errorf("%w: proved destination", ErrInvalid)
	}
	if proof.Outcome != StateProved && proof.DestinationDigest != "" && !validDigest(proof.DestinationDigest) {
		return ProofManifest{}, fmt.Errorf("%w: proof destination", ErrInvalid)
	}
	if err := validateCheckResults(proof.Checklist, true); err != nil {
		return ProofManifest{}, err
	}
	if err := validatePhaseTimings(proof.PhaseTimings); err != nil {
		return ProofManifest{}, err
	}
	if err := validateFindings(proof.Findings); err != nil {
		return ProofManifest{}, err
	}
	if err := validateEvidence(proof.Evidence); err != nil {
		return ProofManifest{}, err
	}
	proof.CreatedAt = canonicalTime(proof.CreatedAt)
	proof.RetainUntil = canonicalTime(proof.RetainUntil)
	proof.ObservedCheckpoint = canonicalTime(proof.ObservedCheckpoint)
	proof.PayloadDigest = ""
	proof.Signature = Signature{}
	digest, err := canonicalDigest(proof)
	if err != nil {
		return ProofManifest{}, err
	}
	signature, err := signer.Sign(ctx, proof.TenantID, digest)
	if err != nil {
		return ProofManifest{}, fmt.Errorf("recoveryproof: sign proof: %w", err)
	}
	if !validLocalID(signature.Algorithm) || !validLocalID(signature.KeyID) ||
		signature.KeyVersion == 0 || signature.Value == "" || len(signature.Value) > 16384 {
		return ProofManifest{}, fmt.Errorf("%w: proof signature", ErrInvalid)
	}
	proof.PayloadDigest = digest
	proof.Signature = signature
	if err := ValidateSignedProof(proof); err != nil {
		return ProofManifest{}, err
	}
	return proof, nil
}

func ValidateSignedProof(proof ProofManifest) error {
	if !validLocalID(proof.ID) || !validLocalID(string(proof.TenantID)) ||
		!validLocalID(string(proof.DrillID)) || !validDigest(proof.DrillDigest) ||
		!validLocalID(string(proof.PlanID)) || !validDigest(proof.PlanDigest) ||
		!proof.Outcome.terminal() || proof.CreatedAt.IsZero() ||
		!proof.RetainUntil.After(proof.CreatedAt) || !validDigest(proof.PayloadDigest) ||
		!validLocalID(proof.Signature.Algorithm) || !validLocalID(proof.Signature.KeyID) ||
		proof.Signature.KeyVersion == 0 || proof.Signature.Value == "" ||
		len(proof.Signature.Value) > 16384 {
		return fmt.Errorf("%w: signed proof envelope", ErrInvalid)
	}
	if proof.Outcome == StateProved && (!validDigest(proof.DestinationDigest) ||
		!proof.ActualRPO.Known || !proof.ActualRTO.Known) {
		return fmt.Errorf("%w: proved proof envelope", ErrInvalid)
	}
	if err := validateMeasurement(proof.ActualRPO); err != nil {
		return err
	}
	if err := validateMeasurement(proof.ActualRTO); err != nil {
		return err
	}
	if proof.ActualRPO.Known && proof.ObservedCheckpoint.IsZero() {
		return fmt.Errorf("%w: proof RPO checkpoint", ErrInvalid)
	}
	if proof.Outcome != StateProved && proof.DestinationDigest != "" &&
		!validDigest(proof.DestinationDigest) {
		return fmt.Errorf("%w: signed proof destination", ErrInvalid)
	}
	if err := proof.RecoveryPoint.Validate(); err != nil {
		return err
	}
	if err := validateCheckResults(proof.Checklist, true); err != nil {
		return err
	}
	if err := validatePhaseTimings(proof.PhaseTimings); err != nil {
		return err
	}
	if err := validateFindings(proof.Findings); err != nil {
		return err
	}
	if err := validateEvidence(proof.Evidence); err != nil {
		return err
	}
	evidenceIDs := make(map[EvidenceID]struct{}, len(proof.Evidence))
	for _, item := range proof.Evidence {
		evidenceIDs[item.ID] = struct{}{}
	}
	for _, check := range proof.Checklist {
		for _, evidenceID := range check.EvidenceIDs {
			if _, found := evidenceIDs[evidenceID]; !found {
				return fmt.Errorf("%w: check evidence binding", ErrInvalid)
			}
		}
	}
	for _, finding := range proof.Findings {
		for _, evidenceID := range finding.EvidenceIDs {
			if _, found := evidenceIDs[evidenceID]; !found {
				return fmt.Errorf("%w: finding evidence binding", ErrInvalid)
			}
		}
	}
	if proof.ActualRPO.Known {
		if _, found := evidenceIDs[proof.ActualRPO.BasisEvidenceID]; !found {
			return fmt.Errorf("%w: RPO evidence binding", ErrInvalid)
		}
	}
	if proof.ActualRTO.Known {
		if _, found := evidenceIDs[proof.ActualRTO.BasisEvidenceID]; !found {
			return fmt.Errorf("%w: RTO evidence binding", ErrInvalid)
		}
	}
	unsigned := proof
	unsigned.PayloadDigest = ""
	unsigned.Signature = Signature{}
	digest, err := canonicalDigest(unsigned)
	if err != nil || digest != proof.PayloadDigest {
		return ErrIntegrity
	}
	return nil
}

func ProofDigest(proof ProofManifest) (string, error) { return canonicalDigest(proof) }

func OccurrenceKey(planDigest string, scheduledAt time.Time) (string, error) {
	if !validDigest(planDigest) || scheduledAt.IsZero() {
		return "", fmt.Errorf("%w: occurrence key", ErrInvalid)
	}
	return canonicalDigest(struct {
		PlanDigest  string    `json:"plan_digest"`
		ScheduledAt time.Time `json:"scheduled_at"`
	}{PlanDigest: planDigest, ScheduledAt: canonicalTime(scheduledAt)})
}

var (
	localIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	reasonPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

func validLocalID(value string) bool { return localIDPattern.MatchString(value) }

func validReason(value string) bool { return reasonPattern.MatchString(value) }

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func safeLabel(value string) bool {
	if value == "" || len(value) > 160 || strings.ContainsAny(value, "\r\n") {
		return false
	}
	for _, current := range value {
		if current < 0x20 || current == 0x7f {
			return false
		}
	}
	return true
}

func validateComponents(values []Component) error {
	if len(values) == 0 || len(values) > 16 {
		return fmt.Errorf("%w: components", ErrInvalid)
	}
	last := ""
	for _, value := range values {
		if !value.valid() || string(value) <= last {
			return fmt.Errorf("%w: component ordering", ErrInvalid)
		}
		last = string(value)
	}
	return nil
}

func sameChecks(actual, expected []CheckKind) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func validatePhaseTimings(timings []PhaseTiming) error {
	for _, timing := range timings {
		switch timing.Phase {
		case PhaseAdmission, PhaseAllocation, PhaseRestore, PhaseVerification, PhaseCleanup:
		default:
			return fmt.Errorf("%w: phase", ErrInvalid)
		}
		if timing.StartedAt.IsZero() || timing.CompletedAt.Before(timing.StartedAt) ||
			timing.Elapsed != timing.CompletedAt.Sub(timing.StartedAt) {
			return fmt.Errorf("%w: measured phase timing", ErrInvalid)
		}
	}
	return nil
}

func validateCheckResults(results []CheckResult, complete bool) error {
	if complete && len(results) != len(requiredChecks) {
		return fmt.Errorf("%w: complete checklist", ErrInvalid)
	}
	seen := make(map[CheckKind]struct{}, len(results))
	for index, result := range results {
		if !result.Kind.valid() || len(result.EvidenceIDs) > 32 ||
			result.StartedAt.IsZero() || result.CompletedAt.Before(result.StartedAt) {
			return fmt.Errorf("%w: check result", ErrInvalid)
		}
		switch result.Status {
		case CheckPassed, CheckFailed, CheckUncertain:
		default:
			return fmt.Errorf("%w: check status", ErrInvalid)
		}
		if _, duplicate := seen[result.Kind]; duplicate {
			return fmt.Errorf("%w: duplicate check", ErrInvalid)
		}
		seen[result.Kind] = struct{}{}
		if complete && result.Kind != requiredChecks[index] {
			return fmt.Errorf("%w: checklist order", ErrInvalid)
		}
		for _, evidenceID := range result.EvidenceIDs {
			if !validLocalID(string(evidenceID)) {
				return fmt.Errorf("%w: check evidence", ErrInvalid)
			}
		}
	}
	return nil
}

func validateFindings(findings []Finding) error {
	for _, finding := range findings {
		if !validReason(finding.Code) || finding.Count == 0 || len(finding.EvidenceIDs) > 32 {
			return fmt.Errorf("%w: finding", ErrInvalid)
		}
		switch finding.Severity {
		case SeverityInfo, SeverityWarning, SeverityCritical:
		default:
			return fmt.Errorf("%w: finding severity", ErrInvalid)
		}
		if finding.Check != "" && !finding.Check.valid() {
			return fmt.Errorf("%w: finding check", ErrInvalid)
		}
		for _, id := range finding.EvidenceIDs {
			if !validLocalID(string(id)) {
				return fmt.Errorf("%w: finding evidence", ErrInvalid)
			}
		}
	}
	return nil
}

func validateEvidence(evidence []EvidenceReference) error {
	seen := make(map[EvidenceID]struct{}, len(evidence))
	for _, item := range evidence {
		if !validLocalID(string(item.ID)) || !validLocalID(item.Kind) || !validDigest(item.Digest) ||
			item.Size < 0 || !item.Redacted || item.RetainUntil.IsZero() {
			return fmt.Errorf("%w: evidence reference", ErrInvalid)
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return fmt.Errorf("%w: duplicate evidence", ErrInvalid)
		}
		seen[item.ID] = struct{}{}
	}
	return nil
}

func validateMeasurement(value MeasuredDuration) error {
	if !value.Known {
		if value.Value != 0 || value.BasisEvidenceID != "" {
			return fmt.Errorf("%w: unknown measurement carries value", ErrInvalid)
		}
		return nil
	}
	if value.Value < 0 || !validLocalID(string(value.BasisEvidenceID)) {
		return fmt.Errorf("%w: measured duration", ErrInvalid)
	}
	return nil
}

func canonicalDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: canonical encoding", ErrInvalid)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Round(0)
}
