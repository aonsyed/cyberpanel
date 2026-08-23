// Package diskguard owns deterministic disk-pressure plans and their guarded
// execution journal. It deliberately has no path-based or wildcard mutation API.
package diskguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid              = errors.New("invalid disk guard resource")
	ErrNotFound             = errors.New("disk guard resource not found")
	ErrConflict             = errors.New("disk guard conflict")
	ErrStaleGeneration      = errors.New("stale disk guard generation")
	ErrUncertainObservation = errors.New("disk observation is stale or uncertain")
	ErrProtected            = errors.New("disk artifact is protected")
	ErrApprovalRequired     = errors.New("disk guard approval required")
	ErrUnauthorized         = errors.New("disk guard authorization denied")
	ErrAmbiguous            = errors.New("disk guard mutation is ambiguous")
	ErrPartial              = errors.New("disk guard plan partially applied")
	ErrIntegrity            = errors.New("disk guard evidence integrity failure")
	ErrLimit                = errors.New("disk guard bound exceeded")
)

var guardIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func validID(value string) bool { return guardIDPattern.MatchString(value) }
func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type FilesystemObservation struct {
	ID                string    `json:"id"`
	FilesystemID      string    `json:"filesystem_id"`
	Generation        uint64    `json:"generation"`
	TotalBytes        uint64    `json:"total_bytes"`
	FreeBytes         uint64    `json:"free_bytes"`
	UncertaintyBytes  uint64    `json:"uncertainty_bytes"`
	TotalInodes       uint64    `json:"total_inodes"`
	FreeInodes        uint64    `json:"free_inodes"`
	UncertaintyInodes uint64    `json:"uncertainty_inodes"`
	ObservedAt        time.Time `json:"observed_at"`
	SourceDigest      string    `json:"source_digest"`
	Digest            string    `json:"digest"`
}

func (observation FilesystemObservation) Validate() error {
	if !validID(observation.ID) || !validID(observation.FilesystemID) || observation.Generation == 0 || observation.TotalBytes == 0 || observation.FreeBytes > observation.TotalBytes || observation.UncertaintyBytes > observation.TotalBytes || observation.TotalInodes == 0 || observation.FreeInodes > observation.TotalInodes || observation.UncertaintyInodes > observation.TotalInodes || observation.ObservedAt.IsZero() || !validDigest(observation.SourceDigest) || !validDigest(observation.Digest) {
		return ErrInvalid
	}
	sealed := observation
	sealed.Digest = ""
	digest, err := digestValue(sealed)
	if err != nil || digest != observation.Digest {
		return ErrIntegrity
	}
	return nil
}

func SealObservation(observation FilesystemObservation) (FilesystemObservation, error) {
	observation.ObservedAt = observation.ObservedAt.UTC()
	observation.Digest = ""
	digest, err := digestValue(observation)
	if err != nil {
		return FilesystemObservation{}, err
	}
	observation.Digest = digest
	if err = observation.Validate(); err != nil {
		return FilesystemObservation{}, err
	}
	return observation, nil
}

type Reserve struct {
	Bytes  uint64 `json:"bytes"`
	Inodes uint64 `json:"inodes"`
}

type ProtectedReserves struct {
	Audit    Reserve `json:"audit"`
	Recovery Reserve `json:"recovery"`
	Rollback Reserve `json:"rollback"`
}

func (reserves ProtectedReserves) totals() (uint64, uint64, error) {
	if reserves.Audit.Bytes == 0 || reserves.Audit.Inodes == 0 || reserves.Recovery.Bytes == 0 || reserves.Recovery.Inodes == 0 || reserves.Rollback.Bytes == 0 || reserves.Rollback.Inodes == 0 {
		return 0, 0, ErrInvalid
	}
	bytes, ok := addUint64(reserves.Audit.Bytes, reserves.Recovery.Bytes, reserves.Rollback.Bytes)
	if !ok {
		return 0, 0, ErrInvalid
	}
	inodes, ok := addUint64(reserves.Audit.Inodes, reserves.Recovery.Inodes, reserves.Rollback.Inodes)
	if !ok {
		return 0, 0, ErrInvalid
	}
	return bytes, inodes, nil
}

type PressureLevel string

const (
	PressureNormal    PressureLevel = "normal"
	PressureLow       PressureLevel = "low"
	PressureHigh      PressureLevel = "high"
	PressureCritical  PressureLevel = "critical"
	PressureEmergency PressureLevel = "emergency"
	PressureUnknown   PressureLevel = "unknown"
)

func (level PressureLevel) Valid() bool {
	switch level {
	case PressureNormal, PressureLow, PressureHigh, PressureCritical, PressureEmergency, PressureUnknown:
		return true
	default:
		return false
	}
}

type Watermark struct {
	Level              PressureLevel `json:"level"`
	MinimumUsableBytes uint64        `json:"minimum_usable_bytes"`
	MinimumUsableInodes uint64       `json:"minimum_usable_inodes"`
}

type WatermarkPolicy struct {
	ID                              string            `json:"id"`
	FilesystemID                    string            `json:"filesystem_id"`
	Generation                      uint64            `json:"generation"`
	Reserves                        ProtectedReserves `json:"reserves"`
	Low                             Watermark         `json:"low"`
	High                            Watermark         `json:"high"`
	Critical                        Watermark         `json:"critical"`
	Emergency                       Watermark         `json:"emergency"`
	RecoveryTargetBytes             uint64            `json:"recovery_target_bytes"`
	RecoveryTargetInodes            uint64            `json:"recovery_target_inodes"`
	MaximumObservationAge           time.Duration     `json:"maximum_observation_age"`
	MaximumUncertaintyBasisPoints   uint16            `json:"maximum_uncertainty_basis_points"`
	MaximumCandidates               uint32            `json:"maximum_candidates"`
	MaximumActions                  uint16            `json:"maximum_actions"`
	MaximumReclaimBytes             uint64            `json:"maximum_reclaim_bytes"`
	CreatedAt                       time.Time         `json:"created_at"`
	UpdatedAt                       time.Time         `json:"updated_at"`
	Digest                          string            `json:"digest"`
}

func (policy WatermarkPolicy) Validate() error {
	if !validID(policy.ID) || !validID(policy.FilesystemID) || policy.Generation == 0 || policy.ReservesInvalid() || policy.Low.Level != PressureLow || policy.High.Level != PressureHigh || policy.Critical.Level != PressureCritical || policy.Emergency.Level != PressureEmergency || policy.Low.MinimumUsableBytes <= policy.High.MinimumUsableBytes || policy.High.MinimumUsableBytes <= policy.Critical.MinimumUsableBytes || policy.Critical.MinimumUsableBytes <= policy.Emergency.MinimumUsableBytes || policy.Low.MinimumUsableInodes <= policy.High.MinimumUsableInodes || policy.High.MinimumUsableInodes <= policy.Critical.MinimumUsableInodes || policy.Critical.MinimumUsableInodes <= policy.Emergency.MinimumUsableInodes || policy.Emergency.MinimumUsableBytes == 0 || policy.Emergency.MinimumUsableInodes == 0 || policy.RecoveryTargetBytes < policy.Low.MinimumUsableBytes || policy.RecoveryTargetInodes < policy.Low.MinimumUsableInodes || policy.MaximumObservationAge < 5*time.Second || policy.MaximumObservationAge > 15*time.Minute || policy.MaximumUncertaintyBasisPoints > 2000 || policy.MaximumCandidates == 0 || policy.MaximumCandidates > 10000 || policy.MaximumActions == 0 || policy.MaximumActions > 500 || uint32(policy.MaximumActions) > policy.MaximumCandidates || policy.MaximumReclaimBytes == 0 || policy.CreatedAt.IsZero() || policy.UpdatedAt.Before(policy.CreatedAt) || !validDigest(policy.Digest) {
		return ErrInvalid
	}
	sealed := policy
	sealed.Digest = ""
	digest, err := digestValue(sealed)
	if err != nil || digest != policy.Digest {
		return ErrIntegrity
	}
	return nil
}

func (policy WatermarkPolicy) ReservesInvalid() bool {
	_, _, err := policy.Reserves.totals()
	return err != nil
}

func SealPolicy(policy WatermarkPolicy) (WatermarkPolicy, error) {
	policy.CreatedAt, policy.UpdatedAt = policy.CreatedAt.UTC(), policy.UpdatedAt.UTC()
	policy.Digest = ""
	digest, err := digestValue(policy)
	if err != nil {
		return WatermarkPolicy{}, err
	}
	policy.Digest = digest
	if err = policy.Validate(); err != nil {
		return WatermarkPolicy{}, err
	}
	return policy, nil
}

type ProtectionClass string
type ArtifactClass string
type RetentionClass string

const (
	ProtectionProtected ProtectionClass = "protected"
	ProtectionEvidence  ProtectionClass = "evidence"
	ProtectionEligible  ProtectionClass = "eligible"
)

const (
	ArtifactAudit            ArtifactClass = "audit"
	ArtifactRecovery         ArtifactClass = "recovery"
	ArtifactRollback         ArtifactClass = "rollback"
	ArtifactSecurityEvidence ArtifactClass = "security_evidence"
	ArtifactOperationEvidence ArtifactClass = "operation_evidence"
	ArtifactCache            ArtifactClass = "cache"
	ArtifactTemporary        ArtifactClass = "temporary"
	ArtifactLog              ArtifactClass = "log"
	ArtifactGeneral          ArtifactClass = "artifact"
	ArtifactBackup           ArtifactClass = "backup"
)

const (
	RetentionEphemeral RetentionClass = "ephemeral"
	RetentionShort     RetentionClass = "short"
	RetentionStandard  RetentionClass = "standard"
	RetentionExtended  RetentionClass = "extended"
	RetentionAudit     RetentionClass = "audit"
	RetentionRecovery  RetentionClass = "recovery"
	RetentionRollback  RetentionClass = "rollback"
	RetentionLegalHold RetentionClass = "legal_hold"
)

type ArtifactDescriptor struct {
	DescriptorID   string          `json:"descriptor_id"`
	ObjectID       string          `json:"object_id"`
	FilesystemID   string          `json:"filesystem_id"`
	TenantID       string          `json:"tenant_id"`
	Class          ArtifactClass   `json:"class"`
	Protection     ProtectionClass `json:"protection"`
	Retention      RetentionClass  `json:"retention"`
	Generation     uint64          `json:"generation"`
	Digest         string          `json:"digest"`
	Bytes          uint64          `json:"bytes"`
	Inodes         uint64          `json:"inodes"`
	CreatedAt      time.Time       `json:"created_at"`
	RetainUntil    time.Time       `json:"retain_until"`
}

func (descriptor ArtifactDescriptor) Validate() error {
	if !validID(descriptor.DescriptorID) || !validID(descriptor.ObjectID) || !validID(descriptor.FilesystemID) || !validID(descriptor.TenantID) || descriptor.Generation == 0 || !validDigest(descriptor.Digest) || descriptor.Bytes == 0 && descriptor.Inodes == 0 || descriptor.CreatedAt.IsZero() || descriptor.RetainUntil.Before(descriptor.CreatedAt) || !descriptor.classificationValid() {
		return ErrInvalid
	}
	return nil
}

func (descriptor ArtifactDescriptor) classificationValid() bool {
	switch descriptor.Class {
	case ArtifactAudit:
		return descriptor.Protection == ProtectionProtected && descriptor.Retention == RetentionAudit
	case ArtifactRecovery:
		return descriptor.Protection == ProtectionProtected && descriptor.Retention == RetentionRecovery
	case ArtifactRollback:
		return descriptor.Protection == ProtectionProtected && descriptor.Retention == RetentionRollback
	case ArtifactSecurityEvidence, ArtifactOperationEvidence:
		return descriptor.Protection == ProtectionEvidence && (descriptor.Retention == RetentionStandard || descriptor.Retention == RetentionExtended || descriptor.Retention == RetentionLegalHold)
	case ArtifactCache, ArtifactTemporary:
		return descriptor.Protection == ProtectionEligible && descriptor.Retention == RetentionEphemeral
	case ArtifactLog, ArtifactGeneral:
		return descriptor.Protection == ProtectionEligible && (descriptor.Retention == RetentionShort || descriptor.Retention == RetentionStandard || descriptor.Retention == RetentionExtended)
	case ArtifactBackup:
		return descriptor.Protection == ProtectionEligible && (descriptor.Retention == RetentionStandard || descriptor.Retention == RetentionExtended)
	default:
		return false
	}
}

type ActionKind string

const (
	ActionExpireObject     ActionKind = "expire_object"
	ActionThrottleHeavyWork ActionKind = "throttle_heavy_work"
	ActionBlockHeavyWork   ActionKind = "block_heavy_work"
)

type ReasonCode string

const (
	ReasonObservationStale       ReasonCode = "observation_stale"
	ReasonObservationUncertain   ReasonCode = "observation_uncertain"
	ReasonNoPressure             ReasonCode = "no_pressure"
	ReasonReserveEncroached      ReasonCode = "protected_reserve_encroached"
	ReasonLowBytes               ReasonCode = "low_bytes"
	ReasonLowInodes              ReasonCode = "low_inodes"
	ReasonHighBytes              ReasonCode = "high_bytes"
	ReasonHighInodes             ReasonCode = "high_inodes"
	ReasonCriticalBytes          ReasonCode = "critical_bytes"
	ReasonCriticalInodes         ReasonCode = "critical_inodes"
	ReasonEmergencyBytes         ReasonCode = "emergency_bytes"
	ReasonEmergencyInodes        ReasonCode = "emergency_inodes"
	ReasonExpiredCache           ReasonCode = "expired_cache"
	ReasonExpiredTemporary       ReasonCode = "expired_temporary"
	ReasonExpiredLog             ReasonCode = "expired_log"
	ReasonExpiredArtifact        ReasonCode = "expired_artifact"
	ReasonExpiredBackup          ReasonCode = "expired_backup"
	ReasonHeavyWorkThrottled     ReasonCode = "heavy_work_throttled"
	ReasonHeavyWorkBlocked       ReasonCode = "heavy_work_blocked"
	ReasonInsufficientReclaimable ReasonCode = "insufficient_reclaimable"
	ReasonEmergencyApproval     ReasonCode = "emergency_approval_required"
)

func (reason ReasonCode) Valid() bool {
	switch reason {
	case ReasonObservationStale, ReasonObservationUncertain, ReasonNoPressure, ReasonReserveEncroached, ReasonLowBytes, ReasonLowInodes, ReasonHighBytes, ReasonHighInodes, ReasonCriticalBytes, ReasonCriticalInodes, ReasonEmergencyBytes, ReasonEmergencyInodes, ReasonExpiredCache, ReasonExpiredTemporary, ReasonExpiredLog, ReasonExpiredArtifact, ReasonExpiredBackup, ReasonHeavyWorkThrottled, ReasonHeavyWorkBlocked, ReasonInsufficientReclaimable, ReasonEmergencyApproval:
		return true
	default:
		return false
	}
}

type PlanAction struct {
	Sequence           uint16          `json:"sequence"`
	ID                 string          `json:"id"`
	Kind               ActionKind      `json:"kind"`
	DescriptorID       string          `json:"descriptor_id,omitempty"`
	ObjectID           string          `json:"object_id,omitempty"`
	FilesystemID       string          `json:"filesystem_id"`
	TenantID           string          `json:"tenant_id,omitempty"`
	Class              ArtifactClass   `json:"class,omitempty"`
	Protection         ProtectionClass `json:"protection,omitempty"`
	Retention          RetentionClass  `json:"retention,omitempty"`
	ExpectedGeneration uint64          `json:"expected_generation,omitempty"`
	ExpectedDigest     string          `json:"expected_digest,omitempty"`
	ExpectedBytes      uint64          `json:"expected_bytes,omitempty"`
	ExpectedInodes     uint64          `json:"expected_inodes,omitempty"`
	Reason             ReasonCode      `json:"reason"`
	Destructive        bool            `json:"destructive"`
	RequiresApproval   bool            `json:"requires_approval"`
}

func (action PlanAction) Validate() error {
	if action.Sequence == 0 || !validID(action.ID) || !validID(action.FilesystemID) || !action.Reason.Valid() {
		return ErrInvalid
	}
	switch action.Kind {
	case ActionExpireObject:
		if !validID(action.DescriptorID) || !validID(action.ObjectID) || !validID(action.TenantID) || action.Protection != ProtectionEligible || action.ExpectedGeneration == 0 || !validDigest(action.ExpectedDigest) || action.ExpectedBytes == 0 && action.ExpectedInodes == 0 || !action.Destructive {
			return ErrInvalid
		}
	case ActionThrottleHeavyWork, ActionBlockHeavyWork:
		if action.DescriptorID != "" || action.ObjectID != "" || action.TenantID != "" || action.Class != "" || action.Protection != "" || action.Retention != "" || action.ExpectedGeneration != 0 || action.ExpectedDigest != "" || action.ExpectedBytes != 0 || action.ExpectedInodes != 0 || action.Destructive || action.RequiresApproval {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type PlanState string

const (
	PlanPlanned   PlanState = "planned"
	PlanApproved  PlanState = "approved"
	PlanExecuting PlanState = "executing"
	PlanCompleted PlanState = "completed"
	PlanBlocked   PlanState = "blocked"
	PlanPartial   PlanState = "partial"
	PlanAmbiguous PlanState = "ambiguous"
)

type Plan struct {
	ID                    string        `json:"id"`
	IdempotencyKey        string        `json:"idempotency_key"`
	InputDigest           string        `json:"input_digest"`
	FilesystemID          string        `json:"filesystem_id"`
	PolicyID              string        `json:"policy_id"`
	PolicyGeneration      uint64        `json:"policy_generation"`
	PolicyDigest          string        `json:"policy_digest"`
	ObservationID         string        `json:"observation_id"`
	ObservationGeneration uint64        `json:"observation_generation"`
	ObservationDigest     string        `json:"observation_digest"`
	Level                 PressureLevel `json:"level"`
	Reasons               []ReasonCode  `json:"reasons"`
	Actions               []PlanAction  `json:"actions"`
	ProjectedUsableBytes  uint64        `json:"projected_usable_bytes"`
	ProjectedUsableInodes uint64        `json:"projected_usable_inodes"`
	RequiresApproval      bool          `json:"requires_approval"`
	RequiresStepUp        bool          `json:"requires_step_up"`
	State                 PlanState     `json:"state"`
	Generation            uint64        `json:"generation"`
	CreatedAt             time.Time     `json:"created_at"`
	UpdatedAt             time.Time     `json:"updated_at"`
	Digest                string        `json:"digest"`
}

func (plan Plan) Validate() error {
	if !validID(plan.ID) || !validID(plan.IdempotencyKey) || !validDigest(plan.InputDigest) || !validID(plan.FilesystemID) || !validID(plan.PolicyID) || plan.PolicyGeneration == 0 || !validDigest(plan.PolicyDigest) || !validID(plan.ObservationID) || plan.ObservationGeneration == 0 || !validDigest(plan.ObservationDigest) || !plan.Level.Valid() || len(plan.Reasons) == 0 || len(plan.Reasons) > 32 || len(plan.Actions) > 500 || plan.Generation == 0 || plan.CreatedAt.IsZero() || plan.UpdatedAt.Before(plan.CreatedAt) || !validDigest(plan.Digest) {
		return ErrInvalid
	}
	for index, reason := range plan.Reasons {
		if !reason.Valid() || index > 0 && plan.Reasons[index-1] >= reason {
			return ErrInvalid
		}
	}
	approval := false
	for index, action := range plan.Actions {
		if action.Validate() != nil || action.Sequence != uint16(index+1) {
			return ErrInvalid
		}
		approval = approval || action.RequiresApproval
	}
	if plan.RequiresApproval != approval || plan.RequiresStepUp != plan.RequiresApproval || plan.RequiresApproval && plan.Level != PressureEmergency {
		return ErrInvalid
	}
	if len(plan.Actions) == 0 && (plan.Level != PressureNormal || plan.State != PlanCompleted || len(plan.Reasons) != 1 || plan.Reasons[0] != ReasonNoPressure) {
		return ErrInvalid
	}
	switch plan.State {
	case PlanPlanned, PlanApproved, PlanExecuting, PlanCompleted, PlanBlocked, PlanPartial, PlanAmbiguous:
	default:
		return ErrInvalid
	}
	sealed := plan
	sealed.Digest = ""
	digest, err := digestValue(sealed)
	if err != nil || digest != plan.Digest {
		return ErrIntegrity
	}
	return nil
}

func SealPlan(plan Plan) (Plan, error) {
	plan.CreatedAt, plan.UpdatedAt = plan.CreatedAt.UTC(), plan.UpdatedAt.UTC()
	plan.Digest = ""
	digest, err := digestValue(plan)
	if err != nil {
		return Plan{}, err
	}
	plan.Digest = digest
	if err = plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

type Approval struct {
	ID                 string    `json:"id"`
	PlanID             string    `json:"plan_id"`
	PlanDigest         string    `json:"plan_digest"`
	PrincipalID        string    `json:"principal_id"`
	AuthorizationEpoch uint64    `json:"authorization_epoch"`
	StepUpDigest       string    `json:"step_up_digest"`
	ApprovedAt         time.Time `json:"approved_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Generation         uint64    `json:"generation"`
	Digest             string    `json:"digest"`
}

func (approval Approval) Validate() error {
	if !validID(approval.ID) || !validID(approval.PlanID) || !validDigest(approval.PlanDigest) || !validID(approval.PrincipalID) || approval.AuthorizationEpoch == 0 || !validDigest(approval.StepUpDigest) || approval.ApprovedAt.IsZero() || !approval.ExpiresAt.After(approval.ApprovedAt) || approval.ExpiresAt.Sub(approval.ApprovedAt) > 30*time.Minute || approval.Generation == 0 || !validDigest(approval.Digest) {
		return ErrInvalid
	}
	sealed := approval
	sealed.Digest = ""
	digest, err := digestValue(sealed)
	if err != nil || digest != approval.Digest {
		return ErrIntegrity
	}
	return nil
}

func SealApproval(approval Approval) (Approval, error) {
	approval.ApprovedAt, approval.ExpiresAt = approval.ApprovedAt.UTC(), approval.ExpiresAt.UTC()
	approval.Digest = ""
	digest, err := digestValue(approval)
	if err != nil {
		return Approval{}, err
	}
	approval.Digest = digest
	if err = approval.Validate(); err != nil {
		return Approval{}, err
	}
	return approval, nil
}

type ActionOutcome string

const (
	OutcomeApplied   ActionOutcome = "applied"
	OutcomeSkipped   ActionOutcome = "skipped"
	OutcomeFailed    ActionOutcome = "failed"
	OutcomeAmbiguous ActionOutcome = "ambiguous"
)

type ActionReceipt struct {
	ActionID          string        `json:"action_id"`
	Sequence          uint16        `json:"sequence"`
	Outcome           ActionOutcome `json:"outcome"`
	ObservedGeneration uint64       `json:"observed_generation,omitempty"`
	ObservedDigest    string        `json:"observed_digest,omitempty"`
	ReclaimedBytes    uint64        `json:"reclaimed_bytes,omitempty"`
	ReclaimedInodes   uint64        `json:"reclaimed_inodes,omitempty"`
	BackendReceipt    string        `json:"backend_receipt,omitempty"`
	FailureCode       string        `json:"failure_code,omitempty"`
	CompletedAt       time.Time     `json:"completed_at"`
}

type ExecutionReceipt struct {
	ID             string          `json:"id"`
	PlanID         string          `json:"plan_id"`
	PlanDigest     string          `json:"plan_digest"`
	State          PlanState       `json:"state"`
	Actions        []ActionReceipt `json:"actions"`
	NextSequence   uint16          `json:"next_sequence"`
	FailureCode    string          `json:"failure_code,omitempty"`
	Generation     uint64          `json:"generation"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	Digest         string          `json:"digest"`
}

func (receipt ExecutionReceipt) Validate() error {
	if !validID(receipt.ID) || !validID(receipt.PlanID) || !validDigest(receipt.PlanDigest) || receipt.Generation == 0 || receipt.CreatedAt.IsZero() || receipt.UpdatedAt.Before(receipt.CreatedAt) || len(receipt.Actions) > 500 || !validDigest(receipt.Digest) || len(receipt.FailureCode) > 128 || strings.ContainsAny(receipt.FailureCode, "\x00\r\n") {
		return ErrInvalid
	}
	switch receipt.State {
	case PlanExecuting, PlanCompleted, PlanBlocked, PlanPartial, PlanAmbiguous:
	default:
		return ErrInvalid
	}
	for index, action := range receipt.Actions {
		if !validID(action.ActionID) || action.Sequence != uint16(index+1) || action.CompletedAt.IsZero() || len(action.BackendReceipt) > 4096 || strings.ContainsAny(action.BackendReceipt, "\x00\r\n") || len(action.FailureCode) > 128 || strings.ContainsAny(action.FailureCode, "\x00\r\n") {
			return ErrInvalid
		}
		switch action.Outcome {
		case OutcomeApplied, OutcomeSkipped, OutcomeFailed, OutcomeAmbiguous:
		default:
			return ErrInvalid
		}
		if action.ObservedDigest != "" && !validDigest(action.ObservedDigest) {
			return ErrInvalid
		}
		if action.Outcome == OutcomeApplied && action.BackendReceipt == "" || (action.Outcome == OutcomeFailed || action.Outcome == OutcomeAmbiguous) && action.FailureCode == "" {
			return ErrInvalid
		}
	}
	if receipt.State == PlanExecuting && receipt.NextSequence != uint16(len(receipt.Actions)+1) || receipt.State != PlanExecuting && receipt.NextSequence != 0 {
		return ErrInvalid
	}
	sealed := receipt
	sealed.Digest = ""
	digest, err := digestValue(sealed)
	if err != nil || digest != receipt.Digest {
		return ErrIntegrity
	}
	return nil
}

func SealReceipt(receipt ExecutionReceipt) (ExecutionReceipt, error) {
	receipt.CreatedAt, receipt.UpdatedAt = receipt.CreatedAt.UTC(), receipt.UpdatedAt.UTC()
	receipt.Digest = ""
	digest, err := digestValue(receipt)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	receipt.Digest = digest
	if err = receipt.Validate(); err != nil {
		return ExecutionReceipt{}, err
	}
	return receipt, nil
}

func digestValue(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > 16<<20 {
		return "", ErrLimit
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func sortedReasons(reasons map[ReasonCode]struct{}) []ReasonCode {
	result := make([]ReasonCode, 0, len(reasons))
	for reason := range reasons {
		result = append(result, reason)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func addUint64(values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		if math.MaxUint64-total < value {
			return 0, false
		}
		total += value
	}
	return total, true
}

func saturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}

func saturatingSubtract(left, right uint64) uint64 {
	if right >= left {
		return 0
	}
	return left - right
}
