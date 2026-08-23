// Package capacity owns bounded historical metrics, evidence-only forecasts,
// and canonical usage evidence. It never owns collectors or resource mutation.
package capacity

import (
	"errors"
	"math"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid              = errors.New("invalid capacity resource")
	ErrNotFound             = errors.New("capacity resource not found")
	ErrConflict             = errors.New("capacity resource conflict")
	ErrStaleSample          = errors.New("capacity sample is not monotonic")
	ErrCardinality          = errors.New("capacity cardinality ceiling reached")
	ErrLimit                = errors.New("capacity operation limit reached")
	ErrIntegrity            = errors.New("capacity evidence integrity failure")
	ErrInsufficientEvidence = errors.New("insufficient capacity evidence")
)

var capacityIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var metricNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

type MetricName string
type Unit string
type Tier string
type MissingReason string

const (
	UnitBytes          Unit = "bytes"
	UnitBytesPerSecond Unit = "bytes_per_second"
	UnitCount          Unit = "count"
	UnitRatio          Unit = "ratio"
	UnitPercent        Unit = "percent"
	UnitSeconds        Unit = "seconds"
	UnitCoreSeconds    Unit = "core_seconds"
	UnitMessages       Unit = "messages"
	UnitOperations     Unit = "operations"
	UnitRequests       Unit = "requests"
)

const (
	TierRaw  Tier = "raw"
	TierHour Tier = "hour"
	TierDay  Tier = "day"
)

const (
	MissingNotCollected       MissingReason = "not_collected"
	MissingCollectorUnavailable MissingReason = "collector_unavailable"
	MissingSourceUnavailable  MissingReason = "source_unavailable"
	MissingCardinalityDropped MissingReason = "cardinality_dropped"
	MissingRetentionGap       MissingReason = "retention_gap"
	MissingMixed              MissingReason = "mixed"
)

type MetricScope struct {
	TenantID    string `json:"tenant_id"`
	ResourceKind string `json:"resource_kind"`
	ResourceID   string `json:"resource_id"`
}

func (scope MetricScope) Validate() error {
	if !capacityIDPattern.MatchString(scope.TenantID) || !metricNamePattern.MatchString(scope.ResourceKind) || !capacityIDPattern.MatchString(scope.ResourceID) {
		return ErrInvalid
	}
	return nil
}

type MetricSample struct {
	Scope          MetricScope   `json:"scope"`
	Metric         MetricName    `json:"metric"`
	Unit           Unit          `json:"unit"`
	SampleInterval time.Duration `json:"sample_interval"`
	ObservedAt     time.Time     `json:"observed_at"`
	Value          float64       `json:"value"`
	Missing        bool          `json:"missing"`
	MissingReason  MissingReason `json:"missing_reason,omitempty"`
}

func (sample MetricSample) Validate() error {
	if sample.Scope.Validate() != nil || !metricNamePattern.MatchString(string(sample.Metric)) || !sample.Unit.Valid() || sample.SampleInterval < time.Second || sample.SampleInterval > time.Hour || time.Hour%sample.SampleInterval != 0 || sample.ObservedAt.IsZero() || sample.ObservedAt.Before(time.Unix(0, 0)) || sample.ObservedAt.After(time.Unix(0, math.MaxInt64)) || sample.Value < 0 || sample.Unit == UnitRatio && sample.Value > 1 || sample.Unit == UnitPercent && sample.Value > 100 || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
		return ErrInvalid
	}
	if sample.Missing {
		if sample.Value != 0 || !sample.MissingReason.Valid() {
			return ErrInvalid
		}
	} else if sample.MissingReason != "" {
		return ErrInvalid
	}
	return nil
}

func (unit Unit) Valid() bool {
	switch unit {
	case UnitBytes, UnitBytesPerSecond, UnitCount, UnitRatio, UnitPercent, UnitSeconds, UnitCoreSeconds, UnitMessages, UnitOperations, UnitRequests:
		return true
	default:
		return false
	}
}

func (reason MissingReason) Valid() bool {
	switch reason {
	case MissingNotCollected, MissingCollectorUnavailable, MissingSourceUnavailable, MissingCardinalityDropped, MissingRetentionGap, MissingMixed:
		return true
	default:
		return false
	}
}

type TierPolicy struct {
	Tier       Tier          `json:"tier"`
	Resolution time.Duration `json:"resolution"`
	RetainFor  time.Duration `json:"retain_for"`
}

type RetentionPolicy struct {
	Raw                   TierPolicy `json:"raw"`
	Hour                  TierPolicy `json:"hour"`
	Day                   TierPolicy `json:"day"`
	MaximumCompactionRows uint32     `json:"maximum_compaction_rows"`
}

func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		Raw: TierPolicy{Tier:TierRaw,RetainFor:7*24*time.Hour},
		Hour: TierPolicy{Tier:TierHour,Resolution:time.Hour,RetainFor:90*24*time.Hour},
		Day: TierPolicy{Tier:TierDay,Resolution:24*time.Hour,RetainFor:3*365*24*time.Hour},
		MaximumCompactionRows:5000,
	}
}

func (policy RetentionPolicy) Validate() error {
	if policy.Raw.Tier != TierRaw || policy.Raw.Resolution != 0 || policy.Raw.RetainFor < time.Hour || policy.Hour.Tier != TierHour || policy.Hour.Resolution != time.Hour || policy.Hour.RetainFor <= policy.Raw.RetainFor || policy.Day.Tier != TierDay || policy.Day.Resolution != 24*time.Hour || policy.Day.RetainFor <= policy.Hour.RetainFor || policy.Day.RetainFor > 10*365*24*time.Hour || policy.MaximumCompactionRows < 3600 || policy.MaximumCompactionRows > 10000 {
		return ErrInvalid
	}
	return nil
}

type MetricPoint struct {
	Scope          MetricScope   `json:"scope"`
	Metric         MetricName    `json:"metric"`
	Unit           Unit          `json:"unit"`
	Tier           Tier          `json:"tier"`
	SampleInterval time.Duration `json:"sample_interval"`
	ObservedAt     time.Time     `json:"observed_at"`
	Minimum        float64       `json:"minimum"`
	Maximum        float64       `json:"maximum"`
	Sum            float64       `json:"sum"`
	Count          uint64        `json:"count"`
	P95            float64       `json:"p95"`
	MissingCount   uint64        `json:"missing_count"`
	MissingReason  MissingReason `json:"missing_reason,omitempty"`
}

func (point MetricPoint) validate() error {
	if point.Scope.Validate() != nil || !metricNamePattern.MatchString(string(point.Metric)) || !point.Unit.Valid() || !point.Tier.Valid() || point.SampleInterval < time.Second || point.SampleInterval > 24*time.Hour || point.ObservedAt.IsZero() || point.Count == 0 && point.MissingCount == 0 || point.Count > 86400 || point.MissingCount > 86400 || point.Count+point.MissingCount > 86400 || math.IsNaN(point.Sum) || math.IsInf(point.Sum, 0) {
		return ErrIntegrity
	}
	if point.Count == 0 {
		if point.Minimum != 0 || point.Maximum != 0 || point.P95 != 0 || !point.MissingReason.Valid() {
			return ErrIntegrity
		}
	} else if point.Minimum < 0 || point.Sum < 0 || point.Unit == UnitRatio && point.Maximum > 1 || point.Unit == UnitPercent && point.Maximum > 100 || math.IsNaN(point.Minimum) || math.IsNaN(point.Maximum) || math.IsNaN(point.P95) || math.IsInf(point.Minimum, 0) || math.IsInf(point.Maximum, 0) || math.IsInf(point.P95, 0) || point.Minimum > point.Maximum || point.P95 < point.Minimum || point.P95 > point.Maximum {
		return ErrIntegrity
	}
	if point.MissingCount > 0 && !point.MissingReason.Valid() || point.MissingCount == 0 && point.MissingReason != "" {
		return ErrIntegrity
	}
	if point.Count > 0 {
		mean := point.Sum / float64(point.Count)
		tolerance := math.Max(1, math.Max(math.Abs(point.Minimum), math.Abs(point.Maximum))) * 1e-12
		if math.IsNaN(mean) || math.IsInf(mean, 0) || mean < point.Minimum-tolerance || mean > point.Maximum+tolerance {
			return ErrIntegrity
		}
	}
	return nil
}

func (tier Tier) Valid() bool {
	switch tier {
	case TierRaw, TierHour, TierDay:
		return true
	default:
		return false
	}
}

type PointQuery struct {
	Scope  MetricScope `json:"scope"`
	Metric MetricName  `json:"metric"`
	Tier   Tier        `json:"tier"`
	From   time.Time   `json:"from"`
	Until  time.Time   `json:"until"`
	Limit  uint16      `json:"limit"`
	Cursor string      `json:"cursor,omitempty"`
}

func (query PointQuery) Validate() error {
	if query.Scope.Validate() != nil || !metricNamePattern.MatchString(string(query.Metric)) || !query.Tier.Valid() || query.From.IsZero() || query.From.Before(time.Unix(0, 0)) || query.Until.After(time.Unix(0, math.MaxInt64)) || !query.Until.After(query.From) || query.Until.Sub(query.From) > 10*365*24*time.Hour || query.Limit == 0 || query.Limit > 1000 || len(query.Cursor) > 2048 || strings.ContainsAny(query.Cursor, "\x00\r\n") {
		return ErrInvalid
	}
	return nil
}

type PointPage struct {
	Points            []MetricPoint `json:"points"`
	NextCursor        string        `json:"next_cursor,omitempty"`
	RawSampleInterval time.Duration `json:"raw_sample_interval"`
	Unit              Unit          `json:"unit"`
}

type CompactionResult struct {
	RawRowsRead     uint32 `json:"raw_rows_read"`
	HourRowsWritten uint32 `json:"hour_rows_written"`
	HourRowsRead    uint32 `json:"hour_rows_read"`
	DayRowsWritten  uint32 `json:"day_rows_written"`
	RowsDeleted     uint32 `json:"rows_deleted"`
	More            bool   `json:"more"`
}
