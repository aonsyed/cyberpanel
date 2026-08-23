// Package alerts owns durable, typed alert rules, evaluation state, and
// immutable firing/recovery events. It does not collect metrics or deliver
// notifications itself.
package alerts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalid   = errors.New("invalid alert resource")
	ErrNotFound  = errors.New("alert resource not found")
	ErrConflict  = errors.New("alert generation conflict")
	ErrStale     = errors.New("stale alert sample")
	ErrScope     = errors.New("alert scope mismatch")
	ErrIntegrity = errors.New("alert integrity failure")
	ErrCapacity  = errors.New("alert evaluation capacity exceeded")
)

const maxGeneration = uint64(1<<63 - 1)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type SignalKind string

const (
	SignalServiceHealth      SignalKind = "service_health"
	SignalDiskPressure       SignalKind = "disk_pressure"
	SignalInodePressure      SignalKind = "inode_pressure"
	SignalQuota              SignalKind = "quota"
	SignalOperationFailure   SignalKind = "operation_failure"
	SignalOperationStall     SignalKind = "operation_stall"
	SignalCertificateExpiry  SignalKind = "certificate_expiry"
	SignalBackupRPO          SignalKind = "backup_rpo"
	SignalBackupRestoreProof SignalKind = "backup_restore_proof"
	SignalMailQueue          SignalKind = "mail_queue"
	SignalSecurityFinding    SignalKind = "security_finding"
	SignalProviderOutage     SignalKind = "provider_outage"
	SignalUpdateFailure      SignalKind = "update_failure"
	SignalReplicationLag     SignalKind = "replication_lag"
	SignalAuditIntegrity     SignalKind = "audit_integrity"
)

func (kind SignalKind) Valid() bool {
	switch kind {
	case SignalServiceHealth, SignalDiskPressure, SignalInodePressure, SignalQuota,
		SignalOperationFailure, SignalOperationStall, SignalCertificateExpiry,
		SignalBackupRPO, SignalBackupRestoreProof, SignalMailQueue,
		SignalSecurityFinding, SignalProviderOutage, SignalUpdateFailure,
		SignalReplicationLag, SignalAuditIntegrity:
		return true
	default:
		return false
	}
}

type Scope struct {
	TenantID    string `json:"tenant_id"`
	ResourceKind string `json:"resource_kind"`
	ResourceID   string `json:"resource_id"`
}

func (scope Scope) Validate() error {
	if !idPattern.MatchString(scope.TenantID) || !idPattern.MatchString(scope.ResourceKind) || !idPattern.MatchString(scope.ResourceID) {
		return ErrInvalid
	}
	return nil
}

type Comparator string

const (
	ComparatorGreaterThan          Comparator = "gt"
	ComparatorGreaterThanOrEqual   Comparator = "gte"
	ComparatorLessThan             Comparator = "lt"
	ComparatorLessThanOrEqual      Comparator = "lte"
	ComparatorEqual                Comparator = "eq"
	ComparatorNotEqual             Comparator = "neq"
)

func (comparator Comparator) Valid() bool {
	switch comparator {
	case ComparatorGreaterThan, ComparatorGreaterThanOrEqual, ComparatorLessThan,
		ComparatorLessThanOrEqual, ComparatorEqual, ComparatorNotEqual:
		return true
	default:
		return false
	}
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

func (severity Severity) Valid() bool {
	return severity == SeverityInfo || severity == SeverityWarning || severity == SeverityError || severity == SeverityCritical
}

type RecoveryPolicy string

const (
	RecoveryAutomatic RecoveryPolicy = "automatic"
	RecoveryManual    RecoveryPolicy = "manual"
)

type Rule struct {
	ID                    string         `json:"id"`
	Kind                  SignalKind     `json:"kind"`
	Scope                 Scope          `json:"scope"`
	Comparator            Comparator     `json:"comparator"`
	Threshold             float64        `json:"threshold"`
	Window                time.Duration  `json:"window"`
	Severity              Severity       `json:"severity"`
	Hysteresis            float64        `json:"hysteresis"`
	ConsecutiveSamples    uint16         `json:"consecutive_samples"`
	Cooldown              time.Duration  `json:"cooldown"`
	Recovery              RecoveryPolicy `json:"recovery"`
	NotificationRouteRefs []string       `json:"notification_route_refs"`
	Enabled               bool           `json:"enabled"`
	Generation            uint64         `json:"generation"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

func (rule Rule) Validate() error {
	if !idPattern.MatchString(rule.ID) || !rule.Kind.Valid() || rule.Scope.Validate() != nil || !rule.Comparator.Valid() || !rule.Severity.Valid() || (rule.Recovery != RecoveryAutomatic && rule.Recovery != RecoveryManual) {
		return ErrInvalid
	}
	if math.IsNaN(rule.Threshold) || math.IsInf(rule.Threshold, 0) || math.IsNaN(rule.Hysteresis) || math.IsInf(rule.Hysteresis, 0) || rule.Hysteresis < 0 {
		return ErrInvalid
	}
	if math.IsInf(rule.Threshold-rule.Hysteresis, 0) || math.IsInf(rule.Threshold+rule.Hysteresis, 0) {
		return ErrInvalid
	}
	if (rule.Comparator == ComparatorEqual || rule.Comparator == ComparatorNotEqual) && rule.Hysteresis != 0 {
		return ErrInvalid
	}
	if rule.Window < time.Second || rule.Window > 30*24*time.Hour || rule.ConsecutiveSamples == 0 || rule.ConsecutiveSamples > 1000 || rule.Cooldown < 0 || rule.Cooldown > 30*24*time.Hour || rule.Generation == 0 || rule.Generation > maxGeneration || rule.UpdatedAt.Before(rule.CreatedAt) {
		return ErrInvalid
	}
	if !validTimestamp(rule.CreatedAt) || !validTimestamp(rule.UpdatedAt) || len(rule.NotificationRouteRefs) > 128 {
		return ErrInvalid
	}
	for index, reference := range rule.NotificationRouteRefs {
		if !idPattern.MatchString(reference) || index > 0 && rule.NotificationRouteRefs[index-1] >= reference {
			return ErrInvalid
		}
	}
	return nil
}

func CanonicalRule(rule Rule) (Rule, error) {
	rule.CreatedAt = rule.CreatedAt.UTC()
	rule.UpdatedAt = rule.UpdatedAt.UTC()
	rule.NotificationRouteRefs = append([]string(nil), rule.NotificationRouteRefs...)
	sort.Strings(rule.NotificationRouteRefs)
	if err := rule.Validate(); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

type SampleStatus string

const (
	SampleKnown   SampleStatus = "known"
	SampleUnknown SampleStatus = "unknown"
)

type Sample struct {
	Kind       SignalKind  `json:"kind"`
	Scope      Scope       `json:"scope"`
	Status     SampleStatus `json:"status"`
	Value      float64     `json:"value,omitempty"`
	SourceID   string      `json:"source_id"`
	ObservedAt time.Time   `json:"observed_at"`
	Digest     string      `json:"digest"`
}

func CanonicalSample(sample Sample) (Sample, error) {
	if !sample.Kind.Valid() || sample.Scope.Validate() != nil || !idPattern.MatchString(sample.SourceID) || !validTimestamp(sample.ObservedAt) || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
		return Sample{}, ErrInvalid
	}
	if sample.Status != SampleKnown && sample.Status != SampleUnknown || sample.Status == SampleUnknown && sample.Value != 0 {
		return Sample{}, ErrInvalid
	}
	provided := sample.Digest
	sample.Digest = ""
	raw, err := json.Marshal(sample)
	if err != nil {
		return Sample{}, err
	}
	sum := sha256.Sum256(raw)
	sample.Digest = hex.EncodeToString(sum[:])
	if provided != "" && provided != sample.Digest {
		return Sample{}, ErrIntegrity
	}
	return sample, nil
}

type Condition string

const (
	ConditionUnknown   Condition = "unknown"
	ConditionHealthy   Condition = "healthy"
	ConditionUnhealthy Condition = "unhealthy"
)

type State struct {
	RuleID             string     `json:"rule_id"`
	RuleGeneration     uint64     `json:"rule_generation"`
	Generation         uint64     `json:"generation"`
	Condition          Condition  `json:"condition"`
	Active             bool       `json:"active"`
	ConsecutiveBad     uint16     `json:"consecutive_bad"`
	ConsecutiveGood    uint16     `json:"consecutive_good"`
	LastStatus         SampleStatus `json:"last_status,omitempty"`
	LastValue          *float64   `json:"last_value,omitempty"`
	LastSampleDigest   string     `json:"last_sample_digest,omitempty"`
	LastObservedAt     time.Time  `json:"last_observed_at,omitempty"`
	LastFiredAt        time.Time  `json:"last_fired_at,omitempty"`
	LastRecoveredAt    time.Time  `json:"last_recovered_at,omitempty"`
	CooldownUntil      time.Time  `json:"cooldown_until,omitempty"`
	NextDueAt          time.Time  `json:"next_due_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (state State) Validate() error {
	if !idPattern.MatchString(state.RuleID) || state.RuleGeneration == 0 || state.RuleGeneration > maxGeneration || state.Generation == 0 || state.Generation > maxGeneration || (state.Condition != ConditionUnknown && state.Condition != ConditionHealthy && state.Condition != ConditionUnhealthy) || !validTimestamp(state.NextDueAt) || !validTimestamp(state.UpdatedAt) {
		return ErrInvalid
	}
	for _, timestamp := range []time.Time{state.LastObservedAt, state.LastFiredAt, state.LastRecoveredAt, state.CooldownUntil} {
		if !timestamp.IsZero() && !validTimestamp(timestamp) {
			return ErrInvalid
		}
	}
	if state.LastStatus != "" && state.LastStatus != SampleKnown && state.LastStatus != SampleUnknown || state.LastStatus == SampleUnknown && state.LastValue != nil || state.LastStatus == SampleKnown && state.LastValue == nil {
		return ErrInvalid
	}
	if state.LastValue != nil && (math.IsNaN(*state.LastValue) || math.IsInf(*state.LastValue, 0)) || state.LastSampleDigest != "" && !validDigest(state.LastSampleDigest) {
		return ErrInvalid
	}
	return nil
}

type EventKind string

const (
	EventFiring   EventKind = "firing"
	EventRecovery EventKind = "recovery"
)

type AlertEvent struct {
	ID                    string      `json:"id"`
	Kind                  EventKind   `json:"kind"`
	RuleID                string      `json:"rule_id"`
	RuleGeneration        uint64      `json:"rule_generation"`
	StateGeneration       uint64      `json:"state_generation"`
	Signal                SignalKind  `json:"signal"`
	Scope                 Scope       `json:"scope"`
	Severity              Severity    `json:"severity"`
	SampleStatus          SampleStatus `json:"sample_status"`
	Value                 *float64    `json:"value,omitempty"`
	SampleDigest          string      `json:"sample_digest"`
	NotificationRouteRefs []string    `json:"notification_route_refs"`
	ObservedAt            time.Time   `json:"observed_at"`
	OccurredAt            time.Time   `json:"occurred_at"`
	Digest                string      `json:"digest"`
}

func (event AlertEvent) Validate() error {
	if !idPattern.MatchString(event.ID) || (event.Kind != EventFiring && event.Kind != EventRecovery) || !idPattern.MatchString(event.RuleID) || event.RuleGeneration == 0 || event.RuleGeneration > maxGeneration || event.StateGeneration == 0 || event.StateGeneration > maxGeneration || !event.Signal.Valid() || event.Scope.Validate() != nil || !event.Severity.Valid() || event.SampleStatus != SampleKnown || event.Value == nil || !validDigest(event.SampleDigest) || !validDigest(event.Digest) || !validTimestamp(event.ObservedAt) || !validTimestamp(event.OccurredAt) {
		return ErrInvalid
	}
	for index, reference := range event.NotificationRouteRefs {
		if !idPattern.MatchString(reference) || index > 0 && event.NotificationRouteRefs[index-1] >= reference {
			return ErrInvalid
		}
	}
	return nil
}

func buildEvent(kind EventKind, rule Rule, state State, sample Sample, now time.Time) (AlertEvent, error) {
	value := sample.Value
	event := AlertEvent{Kind: kind, RuleID: rule.ID, RuleGeneration: rule.Generation, StateGeneration: state.Generation, Signal: rule.Kind, Scope: rule.Scope, Severity: rule.Severity, SampleStatus: sample.Status, Value: &value, SampleDigest: sample.Digest, NotificationRouteRefs: append([]string(nil), rule.NotificationRouteRefs...), ObservedAt: sample.ObservedAt, OccurredAt: now.UTC()}
	idInput := strings.Join([]string{rule.ID, strconv.FormatUint(rule.Generation, 10), string(kind), sample.Digest}, "\x00")
	idSum := sha256.Sum256([]byte(idInput))
	event.ID = "alert_" + hex.EncodeToString(idSum[:24])
	raw, err := json.Marshal(event)
	if err != nil {
		return AlertEvent{}, err
	}
	digest := sha256.Sum256(raw)
	event.Digest = hex.EncodeToString(digest[:])
	return event, event.Validate()
}

func validDigest(value string) bool {
	return len(value) == sha256.Size*2 && strings.Trim(value, "0123456789abcdef") == ""
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validTimestamp(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && time.Unix(0, value.UnixNano()).UTC().Equal(value)
}

type Sink interface {
	Emit(context.Context, AlertEvent) error
}
