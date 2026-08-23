// Package maintenance owns durable maintenance-window definitions, immutable
// scheduled occurrences, and synchronous admission decisions.
package maintenance

import (
	"context"
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
	ErrInvalid       = errors.New("invalid maintenance resource")
	ErrNotFound      = errors.New("maintenance resource not found")
	ErrConflict      = errors.New("maintenance generation conflict")
	ErrIntegrity     = errors.New("maintenance integrity failure")
	ErrCapacity      = errors.New("maintenance capacity exceeded")
	ErrClockPolicy   = errors.New("maintenance clock-transition policy rejected occurrence")
	ErrAuditRequired = errors.New("maintenance override requires audit sink")
)

const maxGeneration = uint64(1<<63 - 1)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type ScopeKind string

const (
	ScopeTenant   ScopeKind = "tenant"
	ScopeNode     ScopeKind = "node"
	ScopeResource ScopeKind = "resource"
)

type Scope struct {
	Kind         ScopeKind `json:"kind"`
	TenantID     string    `json:"tenant_id"`
	NodeID       string    `json:"node_id,omitempty"`
	ResourceKind string    `json:"resource_kind,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
}

func (scope Scope) Validate() error {
	if !identifierPattern.MatchString(scope.TenantID) {
		return ErrInvalid
	}
	switch scope.Kind {
	case ScopeTenant:
		if scope.NodeID != "" || scope.ResourceKind != "" || scope.ResourceID != "" {
			return ErrInvalid
		}
	case ScopeNode:
		if !identifierPattern.MatchString(scope.NodeID) || scope.ResourceKind != "" || scope.ResourceID != "" {
			return ErrInvalid
		}
	case ScopeResource:
		if scope.NodeID != "" && !identifierPattern.MatchString(scope.NodeID) {
			return ErrInvalid
		}
		if !identifierPattern.MatchString(scope.ResourceKind) || !identifierPattern.MatchString(scope.ResourceID) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (scope Scope) Specificity() uint8 {
	switch scope.Kind {
	case ScopeTenant:
		return 1
	case ScopeNode:
		return 2
	case ScopeResource:
		return 3
	default:
		return 0
	}
}

type Target struct {
	TenantID     string `json:"tenant_id"`
	NodeID       string `json:"node_id,omitempty"`
	ResourceKind string `json:"resource_kind,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
}

func (target Target) Validate() error {
	if !identifierPattern.MatchString(target.TenantID) || target.NodeID != "" && !identifierPattern.MatchString(target.NodeID) {
		return ErrInvalid
	}
	if (target.ResourceKind == "") != (target.ResourceID == "") {
		return ErrInvalid
	}
	if target.ResourceKind != "" && (!identifierPattern.MatchString(target.ResourceKind) || !identifierPattern.MatchString(target.ResourceID)) {
		return ErrInvalid
	}
	return nil
}

func (target Target) Digest() (string, error) {
	if err := target.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(target)
	if err != nil {
		return "", err
	}
	return digestBytes(raw), nil
}

type OperationClass string

const (
	OperationRoutine     OperationClass = "routine"
	OperationDisruptive  OperationClass = "disruptive"
	OperationUpgrade     OperationClass = "upgrade"
	OperationBackup      OperationClass = "backup"
	OperationRestore     OperationClass = "restore"
	OperationCertificate OperationClass = "certificate"
	OperationSecurity    OperationClass = "security"
	OperationRecovery    OperationClass = "recovery"
)

func (class OperationClass) Valid() bool {
	switch class {
	case OperationRoutine, OperationDisruptive, OperationUpgrade, OperationBackup,
		OperationRestore, OperationCertificate, OperationSecurity, OperationRecovery:
		return true
	default:
		return false
	}
}

type WindowEffect string

const (
	EffectAllow WindowEffect = "allow"
	EffectDeny  WindowEffect = "deny"
)

type DrainMode string

const (
	DrainNone     DrainMode = "none"
	DrainGraceful DrainMode = "graceful"
	DrainRequired DrainMode = "required"
)

type DrainPolicy struct {
	Mode         DrainMode     `json:"mode"`
	BeforeStart  time.Duration `json:"before_start"`
	BeforeEnd    time.Duration `json:"before_end"`
}

func (policy DrainPolicy) Validate(maximum time.Duration) error {
	if policy.Mode != DrainNone && policy.Mode != DrainGraceful && policy.Mode != DrainRequired {
		return ErrInvalid
	}
	if policy.BeforeStart < 0 || policy.BeforeEnd < 0 || policy.BeforeStart > maximum || policy.BeforeEnd >= maximum {
		return ErrInvalid
	}
	if policy.Mode == DrainNone && (policy.BeforeStart != 0 || policy.BeforeEnd != 0) {
		return ErrInvalid
	}
	return nil
}

type MissedWindowPolicy string

const (
	MissedSkip  MissedWindowPolicy = "skip"
	MissedDefer MissedWindowPolicy = "defer"
	MissedDeny  MissedWindowPolicy = "deny"
)

type EmergencyOverridePolicy string

const (
	OverrideForbidden     EmergencyOverridePolicy = "forbidden"
	OverrideHighAssurance EmergencyOverridePolicy = "high_assurance"
)

type ScheduleKind string

const (
	ScheduleAbsolute ScheduleKind = "absolute"
	ScheduleWeekly   ScheduleKind = "weekly"
)

type Weekday uint8

const (
	Monday Weekday = iota + 1
	Tuesday
	Wednesday
	Thursday
	Friday
	Saturday
	Sunday
)

func (weekday Weekday) Valid() bool { return weekday >= Monday && weekday <= Sunday }

type FoldPolicy string

const (
	FoldEarlier FoldPolicy = "earlier"
	FoldLater   FoldPolicy = "later"
	FoldReject  FoldPolicy = "reject"
)

type GapPolicy string

const (
	GapSkip      GapPolicy = "skip"
	GapNextValid GapPolicy = "next_valid"
	GapReject    GapPolicy = "reject"
)

type Recurrence struct {
	Weekdays        []Weekday     `json:"weekdays"`
	LocalStartMinute uint16       `json:"local_start_minute"`
	Duration        time.Duration `json:"duration"`
	EffectiveFrom   string        `json:"effective_from"`
	EffectiveUntil  string        `json:"effective_until,omitempty"`
	Fold            FoldPolicy    `json:"fold"`
	Gap             GapPolicy     `json:"gap"`
}

type Schedule struct {
	Kind       ScheduleKind `json:"kind"`
	StartAt    time.Time    `json:"start_at,omitempty"`
	EndAt      time.Time    `json:"end_at,omitempty"`
	Recurrence Recurrence   `json:"recurrence,omitempty"`
}

type Window struct {
	ID                      string                  `json:"id"`
	Scope                   Scope                   `json:"scope"`
	TimeZone                string                  `json:"time_zone"`
	Schedule                Schedule                `json:"schedule"`
	MaximumDuration         time.Duration           `json:"maximum_duration"`
	Effect                  WindowEffect            `json:"effect"`
	OperationClasses        []OperationClass        `json:"operation_classes"`
	Drain                   DrainPolicy             `json:"drain"`
	Missed                  MissedWindowPolicy      `json:"missed"`
	EmergencyOverride       EmergencyOverridePolicy `json:"emergency_override"`
	Enabled                 bool                    `json:"enabled"`
	Generation              uint64                  `json:"generation"`
	CreatedAt               time.Time               `json:"created_at"`
	UpdatedAt               time.Time               `json:"updated_at"`
}

func (window Window) Validate() error {
	if !identifierPattern.MatchString(window.ID) || window.Scope.Validate() != nil || window.Generation == 0 || window.Generation > maxGeneration {
		return ErrInvalid
	}
	if _, err := normalizedLocation(window.TimeZone); err != nil {
		return err
	}
	if window.MaximumDuration < time.Minute || window.MaximumDuration > 7*24*time.Hour || window.Drain.Validate(window.MaximumDuration) != nil {
		return ErrInvalid
	}
	if window.Effect != EffectAllow && window.Effect != EffectDeny || window.Missed != MissedSkip && window.Missed != MissedDefer && window.Missed != MissedDeny || window.EmergencyOverride != OverrideForbidden && window.EmergencyOverride != OverrideHighAssurance {
		return ErrInvalid
	}
	if len(window.OperationClasses) == 0 || len(window.OperationClasses) > 32 {
		return ErrInvalid
	}
	for index, class := range window.OperationClasses {
		if !class.Valid() || index > 0 && window.OperationClasses[index-1] >= class {
			return ErrInvalid
		}
	}
	if !validTimestamp(window.CreatedAt) || !validTimestamp(window.UpdatedAt) || window.UpdatedAt.Before(window.CreatedAt) {
		return ErrInvalid
	}
	if err := validateSchedule(window.Schedule, window.MaximumDuration); err != nil {
		return err
	}
	if window.Drain.BeforeEnd >= scheduleDuration(window.Schedule) && window.Drain.BeforeEnd != 0 {
		return ErrInvalid
	}
	return nil
}

func CanonicalWindow(window Window) (Window, error) {
	window.ID = strings.TrimSpace(window.ID)
	window.TimeZone = strings.TrimSpace(window.TimeZone)
	window.CreatedAt = window.CreatedAt.UTC()
	window.UpdatedAt = window.UpdatedAt.UTC()
	window.Schedule.StartAt = window.Schedule.StartAt.UTC()
	window.Schedule.EndAt = window.Schedule.EndAt.UTC()
	window.OperationClasses = append([]OperationClass(nil), window.OperationClasses...)
	sort.Slice(window.OperationClasses, func(left, right int) bool { return window.OperationClasses[left] < window.OperationClasses[right] })
	window.Schedule.Recurrence.Weekdays = append([]Weekday(nil), window.Schedule.Recurrence.Weekdays...)
	sort.Slice(window.Schedule.Recurrence.Weekdays, func(left, right int) bool {
		return window.Schedule.Recurrence.Weekdays[left] < window.Schedule.Recurrence.Weekdays[right]
	})
	if err := window.Validate(); err != nil {
		return Window{}, err
	}
	return window, nil
}

type Occurrence struct {
	ID               string    `json:"id"`
	WindowID         string    `json:"window_id"`
	WindowGeneration uint64    `json:"window_generation"`
	Scope            Scope     `json:"scope"`
	StartsAt         time.Time `json:"starts_at"`
	EndsAt           time.Time `json:"ends_at"`
	Digest           string    `json:"digest"`
}

func (occurrence Occurrence) Validate() error {
	if !identifierPattern.MatchString(occurrence.ID) || !identifierPattern.MatchString(occurrence.WindowID) || occurrence.WindowGeneration == 0 || occurrence.WindowGeneration > maxGeneration || occurrence.Scope.Validate() != nil {
		return ErrInvalid
	}
	if !validTimestamp(occurrence.StartsAt) || !validTimestamp(occurrence.EndsAt) || !occurrence.EndsAt.After(occurrence.StartsAt) || !validDigest(occurrence.Digest) {
		return ErrInvalid
	}
	return nil
}

type OccurrencePhase string

const (
	PhasePlanned   OccurrencePhase = "planned"
	PhaseDraining  OccurrencePhase = "draining"
	PhaseActive    OccurrencePhase = "active"
	PhaseEnding    OccurrencePhase = "ending"
	PhaseCompleted OccurrencePhase = "completed"
	PhaseMissed    OccurrencePhase = "missed"
)

type AdmissionRequest struct {
	ID               string                 `json:"id"`
	Target           Target                 `json:"target"`
	OperationClass   OperationClass         `json:"operation_class"`
	ExpectedDuration time.Duration          `json:"expected_duration"`
	At               time.Time              `json:"at"`
	Override         *OverrideAuthorization `json:"override,omitempty"`
}

func (request AdmissionRequest) Validate() error {
	if !identifierPattern.MatchString(request.ID) || request.Target.Validate() != nil || !request.OperationClass.Valid() || request.ExpectedDuration < time.Second || request.ExpectedDuration > 7*24*time.Hour || !validTimestamp(request.At) {
		return ErrInvalid
	}
	return nil
}

type AssuranceLevel string

const AssuranceHigh AssuranceLevel = "high_assurance"

type OverrideAuthorization struct {
	ID                  string         `json:"id"`
	Issuer              string         `json:"issuer"`
	Subject             string         `json:"subject"`
	KeyID               string         `json:"key_id"`
	TenantID            string         `json:"tenant_id"`
	TargetDigest        string         `json:"target_digest"`
	OperationClass      OperationClass `json:"operation_class"`
	ReasonCode          string         `json:"reason_code"`
	Assurance           AssuranceLevel `json:"assurance"`
	IssuedAt            time.Time      `json:"issued_at"`
	NotBefore           time.Time      `json:"not_before"`
	ExpiresAt           time.Time      `json:"expires_at"`
	Nonce               string         `json:"nonce"`
	Proof               []byte         `json:"proof"`
	Digest              string         `json:"digest"`
}

func CanonicalOverride(authorization OverrideAuthorization) (OverrideAuthorization, error) {
	authorization.IssuedAt = authorization.IssuedAt.UTC()
	authorization.NotBefore = authorization.NotBefore.UTC()
	authorization.ExpiresAt = authorization.ExpiresAt.UTC()
	provided := authorization.Digest
	authorization.Digest = ""
	if !identifierPattern.MatchString(authorization.ID) || !identifierPattern.MatchString(authorization.Issuer) || !identifierPattern.MatchString(authorization.Subject) || !identifierPattern.MatchString(authorization.KeyID) || !identifierPattern.MatchString(authorization.TenantID) || !identifierPattern.MatchString(authorization.ReasonCode) || !identifierPattern.MatchString(authorization.Nonce) || !validDigest(authorization.TargetDigest) || !authorization.OperationClass.Valid() || authorization.Assurance != AssuranceHigh {
		return OverrideAuthorization{}, ErrInvalid
	}
	if !validTimestamp(authorization.IssuedAt) || !validTimestamp(authorization.NotBefore) || !validTimestamp(authorization.ExpiresAt) || authorization.NotBefore.Before(authorization.IssuedAt) || !authorization.ExpiresAt.After(authorization.NotBefore) || authorization.ExpiresAt.Sub(authorization.NotBefore) > 24*time.Hour || len(authorization.Proof) < 64 || len(authorization.Proof) > 4096 {
		return OverrideAuthorization{}, ErrInvalid
	}
	raw, err := json.Marshal(authorization)
	if err != nil {
		return OverrideAuthorization{}, err
	}
	authorization.Digest = digestBytes(raw)
	if provided != "" && provided != authorization.Digest {
		return OverrideAuthorization{}, ErrIntegrity
	}
	return authorization, nil
}

type DecisionKind string

const (
	DecisionAllow DecisionKind = "allow"
	DecisionDefer DecisionKind = "defer"
	DecisionDeny  DecisionKind = "deny"
)

type Evidence struct {
	WindowID         string          `json:"window_id"`
	WindowGeneration uint64          `json:"window_generation"`
	Specificity      uint8           `json:"specificity"`
	Effect           WindowEffect    `json:"effect"`
	Phase            OccurrencePhase `json:"phase"`
	OccurrenceID     string          `json:"occurrence_id"`
	StartsAt         time.Time       `json:"starts_at"`
	EndsAt           time.Time       `json:"ends_at"`
}

type Decision struct {
	Kind             DecisionKind   `json:"kind"`
	Reason           string         `json:"reason"`
	RequestID        string         `json:"request_id"`
	EvaluatedAt      time.Time      `json:"evaluated_at"`
	Phase            OccurrencePhase `json:"phase,omitempty"`
	WindowID         string         `json:"window_id,omitempty"`
	OccurrenceID     string         `json:"occurrence_id,omitempty"`
	NextEligibleAt   time.Time      `json:"next_eligible_at,omitempty"`
	OverrideID       string         `json:"override_id,omitempty"`
	Evidence         []Evidence     `json:"evidence"`
	EvidenceDigest   string         `json:"evidence_digest"`
}

type OverrideAuditRecord struct {
	ID                  string         `json:"id"`
	AuthorizationID     string         `json:"authorization_id"`
	AuthorizationDigest string         `json:"authorization_digest"`
	RequestID           string         `json:"request_id"`
	TenantID            string         `json:"tenant_id"`
	OperationClass      OperationClass `json:"operation_class"`
	At                  time.Time      `json:"at"`
	PriorDecision       DecisionKind   `json:"prior_decision"`
	PriorReason         string         `json:"prior_reason"`
	EvidenceDigest      string         `json:"evidence_digest"`
	Digest              string         `json:"digest"`
}

type OverrideVerifier interface {
	VerifyMaintenanceOverride(context.Context, OverrideAuthorization) error
}

type AuditSink interface {
	RecordMaintenanceOverride(context.Context, OverrideAuditRecord) error
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
