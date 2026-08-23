package scheduler

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid scheduler resource")
	ErrConflict = errors.New("scheduler resource conflict")
	ErrNotFound = errors.New("scheduler resource not found")
	ErrStale    = errors.New("stale scheduler lease or generation")
)

const (
	MaxReplayOccurrences = uint8(32)
	MaximumTimeout        = 24 * time.Hour
	MaximumJitter         = 24 * time.Hour
)

type ScheduleID string
type OccurrenceID string
type TargetKind string
type ScopeKind string

const (
	ScopeTenant   ScopeKind = "tenant"
	ScopeSite     ScopeKind = "site"
	ScopeNode     ScopeKind = "node"
	ScopeResource ScopeKind = "resource"
)

type Scope struct {
	Kind ScopeKind `json:"kind"`
	Ref  string    `json:"ref"`
}

func (scope Scope) Validate() error {
	if scope.Kind != ScopeTenant && scope.Kind != ScopeSite && scope.Kind != ScopeNode && scope.Kind != ScopeResource || !validToken(scope.Ref, 1, 192) { return ErrInvalid }
	return nil
}

type MissedRunPolicy string

const (
	MissedSkip          MissedRunPolicy = "skip"
	MissedLatest        MissedRunPolicy = "latest"
	MissedBoundedReplay MissedRunPolicy = "bounded_replay"
)

type OverlapPolicy string

const (
	OverlapAllow  OverlapPolicy = "allow"
	OverlapForbid OverlapPolicy = "forbid"
)

type NotificationPolicy struct {
	RouteRef  string `json:"route_ref,omitempty"`
	OnSuccess bool   `json:"on_success"`
	OnFailure bool   `json:"on_failure"`
	OnSkipped bool   `json:"on_skipped"`
}

func (policy NotificationPolicy) Validate() error {
	wanted := policy.OnSuccess || policy.OnFailure || policy.OnSkipped
	if wanted && !validToken(policy.RouteRef, 1, 192) || !wanted && policy.RouteRef != "" { return ErrInvalid }
	return nil
}

type Schedule struct {
	ID                 ScheduleID         `json:"id"`
	TenantID           string             `json:"tenant_id"`
	Scope              Scope              `json:"scope"`
	TargetKind         TargetKind         `json:"target_kind"`
	TargetRef          string             `json:"target_ref"`
	Timezone           string             `json:"timezone"`
	Expression         string             `json:"expression"`
	MissedRunPolicy    MissedRunPolicy    `json:"missed_run_policy"`
	ReplayLimit        uint8              `json:"replay_limit,omitempty"`
	OverlapPolicy      OverlapPolicy      `json:"overlap_policy"`
	Jitter             time.Duration      `json:"jitter"`
	Timeout            time.Duration      `json:"timeout"`
	Priority           int16              `json:"priority"`
	ResourceBudgetRef  string             `json:"resource_budget_ref"`
	NotificationPolicy NotificationPolicy `json:"notification_policy"`
	Enabled            bool               `json:"enabled"`
	NextLogicalTime    time.Time          `json:"next_logical_time"`
	Generation         uint64             `json:"generation"`
}

func (schedule Schedule) Validate() error {
	if !validToken(string(schedule.ID), 3, 128) || !validToken(schedule.TenantID, 1, 128) || schedule.Scope.Validate() != nil || !validToken(string(schedule.TargetKind), 1, 64) || !validToken(schedule.TargetRef, 1, 192) || schedule.Generation == 0 || schedule.Priority < -1000 || schedule.Priority > 1000 || !validToken(schedule.ResourceBudgetRef, 1, 192) || schedule.NotificationPolicy.Validate() != nil { return ErrInvalid }
	if schedule.Scope.Kind == ScopeTenant && schedule.Scope.Ref != schedule.TenantID { return ErrInvalid }
	location, err := time.LoadLocation(schedule.Timezone); if err != nil || schedule.Timezone == "Local" { return ErrInvalid }
	normalized, err := NormalizeExpression(schedule.Expression); if err != nil || normalized != schedule.Expression { return ErrInvalid }
	if schedule.MissedRunPolicy != MissedSkip && schedule.MissedRunPolicy != MissedLatest && schedule.MissedRunPolicy != MissedBoundedReplay { return ErrInvalid }
	if schedule.MissedRunPolicy == MissedBoundedReplay { if schedule.ReplayLimit == 0 || schedule.ReplayLimit > MaxReplayOccurrences { return ErrInvalid } } else if schedule.ReplayLimit != 0 { return ErrInvalid }
	if schedule.OverlapPolicy != OverlapAllow && schedule.OverlapPolicy != OverlapForbid || schedule.Jitter < 0 || schedule.Jitter > MaximumJitter || schedule.Jitter%time.Second != 0 || schedule.Timeout < time.Second || schedule.Timeout > MaximumTimeout || schedule.Timeout%time.Second != 0 || !logicalMinute(schedule.NextLogicalTime) { return ErrInvalid }
	parsed, err := parseCron(schedule.Expression); if err != nil || !parsed.matches(schedule.NextLogicalTime.In(location)) { return ErrInvalid }
	return nil
}

type OccurrenceState string

const (
	OccurrenceAdmitted  OccurrenceState = "admitted"
	OccurrenceLeased    OccurrenceState = "leased"
	OccurrenceRunning   OccurrenceState = "running"
	OccurrenceCompleted OccurrenceState = "completed"
	OccurrenceFailed    OccurrenceState = "failed"
	OccurrenceSkipped   OccurrenceState = "skipped"
)

type Occurrence struct {
	ID                 OccurrenceID    `json:"id"`
	ScheduleID         ScheduleID      `json:"schedule_id"`
	ScheduleGeneration uint64          `json:"schedule_generation"`
	LogicalTime        time.Time       `json:"logical_time"`
	ReadyAt            time.Time       `json:"ready_at"`
	Attempt            uint32          `json:"attempt"`
	Deadline           time.Time       `json:"deadline,omitempty"`
	LeaseToken         string          `json:"lease_token,omitempty"`
	LeaseUntil         time.Time       `json:"lease_until,omitempty"`
	FenceToken         uint64          `json:"fence_token"`
	State              OccurrenceState `json:"state"`
	Receipt            string          `json:"receipt,omitempty"`
	Failure            string          `json:"failure,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

func NewOccurrence(schedule Schedule, logical time.Time, state OccurrenceState, reason string) (Occurrence, error) {
	if schedule.Validate() != nil || !logicalMinute(logical) { return Occurrence{}, ErrInvalid }
	logical = logical.UTC()
	occurrence := Occurrence{
		ID:OccurrenceIDFor(schedule.ID, logical), ScheduleID:schedule.ID, ScheduleGeneration:schedule.Generation,
		LogicalTime:logical, ReadyAt:logical.Add(DeterministicJitter(schedule.ID, logical, schedule.Jitter)),
		State:state, CreatedAt:logical, UpdatedAt:logical,
	}
	if state == OccurrenceSkipped { occurrence.Failure = reason }
	if occurrence.Validate() != nil { return Occurrence{}, ErrInvalid }
	return occurrence, nil
}

func (occurrence Occurrence) Validate() error {
	if occurrence.ID != OccurrenceIDFor(occurrence.ScheduleID, occurrence.LogicalTime) || !validToken(string(occurrence.ScheduleID), 3, 128) || occurrence.ScheduleGeneration == 0 || !logicalMinute(occurrence.LogicalTime) || occurrence.ReadyAt.Before(occurrence.LogicalTime) || occurrence.ReadyAt.Sub(occurrence.LogicalTime) > MaximumJitter || occurrence.Attempt > 1_000_000 || occurrence.UpdatedAt.Before(occurrence.CreatedAt) { return ErrInvalid }
	switch occurrence.State {
	case OccurrenceAdmitted:
		if occurrence.Attempt != 0 || occurrence.FenceToken != 0 || occurrence.LeaseToken != "" || !occurrence.LeaseUntil.IsZero() || !occurrence.Deadline.IsZero() || occurrence.Receipt != "" || occurrence.Failure != "" { return ErrInvalid }
	case OccurrenceLeased, OccurrenceRunning:
		if occurrence.Attempt == 0 || occurrence.FenceToken == 0 || !validToken(occurrence.LeaseToken, 16, 192) || occurrence.LeaseUntil.IsZero() || occurrence.Deadline.IsZero() || occurrence.Receipt != "" || occurrence.Failure != "" { return ErrInvalid }
	case OccurrenceCompleted:
		if occurrence.Attempt == 0 || occurrence.FenceToken == 0 || occurrence.LeaseToken != "" || !occurrence.LeaseUntil.IsZero() || occurrence.Deadline.IsZero() || !validReceipt(occurrence.Receipt) || occurrence.Failure != "" { return ErrInvalid }
	case OccurrenceFailed:
		if occurrence.Attempt == 0 || occurrence.FenceToken == 0 || occurrence.LeaseToken != "" || !occurrence.LeaseUntil.IsZero() || occurrence.Deadline.IsZero() || occurrence.Receipt != "" || !validFailure(occurrence.Failure) { return ErrInvalid }
	case OccurrenceSkipped:
		if occurrence.Attempt != 0 || occurrence.FenceToken != 0 || occurrence.LeaseToken != "" || !occurrence.LeaseUntil.IsZero() || !occurrence.Deadline.IsZero() || occurrence.Receipt != "" || !validFailure(occurrence.Failure) { return ErrInvalid }
	default:
		return ErrInvalid
	}
	return nil
}

func OccurrenceIDFor(scheduleID ScheduleID, logical time.Time) OccurrenceID {
	sum := sha256.Sum256([]byte("cyberpanel:scheduler:occurrence:v1\x00" + string(scheduleID) + "\x00" + logical.UTC().Format(time.RFC3339Nano)))
	return OccurrenceID("occ-" + hex.EncodeToString(sum[:20]))
}

func DeterministicJitter(scheduleID ScheduleID, logical time.Time, bound time.Duration) time.Duration {
	if bound <= 0 { return 0 }
	sum := sha256.Sum256([]byte("cyberpanel:scheduler:jitter:v1\x00" + string(scheduleID) + "\x00" + logical.UTC().Format(time.RFC3339Nano)))
	seconds := uint64(bound/time.Second) + 1
	return time.Duration(binary.BigEndian.Uint64(sum[:8])%seconds) * time.Second
}

func logicalMinute(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC && value.Second() == 0 && value.Nanosecond() == 0 }
func validReceipt(value string) bool { return len(value) >= 8 && len(value) <= 1024 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n") }
func validFailure(value string) bool { return validToken(value, 1, 128) }
func validToken(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || strings.TrimSpace(value) != value { return false }
	for index := range value { character := value[index]; if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == ':' || character == '/' { continue }; return false }
	return true
}
