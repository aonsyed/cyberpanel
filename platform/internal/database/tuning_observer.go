package database

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

const (
	maximumTuningInt64 int64 = 1<<63 - 1
	minimumTuningInt64 int64 = -1 << 63
)

type TuningObservationLimits struct {
	MaximumRows  uint32        `json:"maximum_rows"`
	MaximumBytes uint32        `json:"maximum_bytes"`
	Timeout      time.Duration `json:"timeout"`
}

func DefaultTuningObservationLimits() TuningObservationLimits {
	return TuningObservationLimits{MaximumRows: MaximumSlowQueryDigests + MaximumTuningVariables + 32, MaximumBytes: MaximumTuningSnapshotBytes, Timeout: 15 * time.Second}
}

func (limits TuningObservationLimits) Validate() error {
	if limits.MaximumRows < 1 || limits.MaximumRows > MaximumSlowQueryDigests+MaximumTuningVariables+32 || limits.MaximumBytes < 4096 || limits.MaximumBytes > MaximumTuningSnapshotBytes ||
		limits.Timeout < time.Second || limits.Timeout > MaximumTuningCollectTime {
		return ErrTuningInvalid
	}
	return nil
}

type TuningObservationRequest struct {
	InstanceID               ResourceID              `json:"instance_id"`
	ExpectedServerVersion    MariaDBVersion          `json:"expected_server_version"`
	ExpectedConfigGeneration uint64                  `json:"expected_config_generation"`
	Limits                   TuningObservationLimits `json:"limits"`
}

type TuningObservationSample struct {
	InstanceID       ResourceID     `json:"instance_id"`
	ServerVersion    MariaDBVersion `json:"server_version"`
	ConfigGeneration uint64         `json:"config_generation"`
	WindowStartedAt  time.Time      `json:"window_started_at"`
	CapturedAt       time.Time      `json:"captured_at"`
	RowsRead         uint32         `json:"rows_read"`
	BytesRead        uint32         `json:"bytes_read"`
	Snapshot         TuningSnapshot `json:"snapshot"`
}

// MariaDBTuningObserver is implemented by a narrowly privileged adapter. It
// returns aggregate values and query digests only; no SQL text or row payload
// belongs in this interface.
type MariaDBTuningObserver interface {
	ObserveMariaDBTuning(context.Context, TuningObservationRequest) (TuningObservationSample, error)
}

type TuningCollector struct {
	source MariaDBTuningObserver
	now    func() time.Time
}

func NewTuningCollector(source MariaDBTuningObserver, now func() time.Time) (TuningCollector, error) {
	if source == nil { return TuningCollector{}, ErrTuningInvalid }
	if now == nil { now = time.Now }
	return TuningCollector{source: source, now: now}, nil
}

func (collector TuningCollector) Collect(ctx context.Context, request TuningObservationRequest) (TuningObservation, error) {
	if request.InstanceID.IsZero() || request.ExpectedServerVersion.Major == 0 || request.ExpectedConfigGeneration == 0 || request.Limits.Validate() != nil {
		return TuningObservation{}, ErrTuningInvalid
	}
	if _, err := TuningCapabilitiesFor(request.ExpectedServerVersion); err != nil { return TuningObservation{}, err }
	bounded, cancel := context.WithTimeout(ctx, request.Limits.Timeout)
	defer cancel()
	sample, err := collector.source.ObserveMariaDBTuning(bounded, request)
	if err != nil { return TuningObservation{}, err }
	if bounded.Err() != nil { return TuningObservation{}, bounded.Err() }
	if sample.InstanceID != request.InstanceID || compareVersion(sample.ServerVersion, request.ExpectedServerVersion) != 0 || sample.ConfigGeneration != request.ExpectedConfigGeneration ||
		sample.Snapshot.Server.ConfigGeneration != sample.ConfigGeneration || sample.RowsRead > request.Limits.MaximumRows || sample.BytesRead > request.Limits.MaximumBytes ||
		sample.RowsRead < uint32(len(sample.Snapshot.Server.Variables)+len(sample.Snapshot.SlowQueries)) || sample.BytesRead == 0 {
		return TuningObservation{}, ErrTuningStale
	}
	now := collector.now().UTC()
	if sample.WindowStartedAt.IsZero() || sample.CapturedAt.Before(sample.WindowStartedAt) || sample.CapturedAt.After(now.Add(time.Minute)) { return TuningObservation{}, ErrTuningInvalid }
	observation, err := sealTuningObservation(TuningObservation{InstanceID: sample.InstanceID, ServerVersion: sample.ServerVersion,
		ConfigGeneration: sample.ConfigGeneration, WindowStartedAt: sample.WindowStartedAt.UTC(), CapturedAt: sample.CapturedAt.UTC(), Snapshot: sample.Snapshot})
	if err != nil || observation.Validate() != nil { return TuningObservation{}, ErrTuningInvalid }
	return observation, nil
}

func RecommendTuning(observation TuningObservation, capacity InstanceCapacity, generatedAt time.Time) ([]TuningRecommendation, error) {
	if observation.Validate() != nil || capacity.MemoryBytes < 128<<20 || capacity.StorageBytes == 0 || capacity.MaxConnections == 0 || generatedAt.IsZero() ||
		generatedAt.Before(observation.CapturedAt) || generatedAt.Sub(observation.CapturedAt) > MaximumTuningEvidenceAge || observation.Snapshot.Health == HealthUnavailable || observation.Snapshot.Health == HealthUnknown {
		return nil, ErrTuningStale
	}
	capabilities, err := TuningCapabilitiesFor(observation.ServerVersion)
	if err != nil { return nil, err }
	current := make(map[TuningVariable]TuningValue, len(observation.Snapshot.Server.Variables))
	for _, variable := range observation.Snapshot.Server.Variables { current[variable.Variable] = variable.Value }
	recommendations := make([]TuningRecommendation, 0, 4)
	appendRecommendation := func(recommendation TuningRecommendation) error {
		capability, supported := capabilities.capability(recommendation.Variable)
		if !supported || !containsMode(capability.Modes, recommendation.Mode) { return ErrTuningUnsupported }
		recommendation.ObservationID = observation.ID
		recommendation.ObservationDigest = observation.Digest
		recommendation.GeneratedAt = generatedAt.UTC()
		recommendation.Digest = recommendationDigest(recommendation)
		if recommendation.Validate() != nil { return ErrTuningInvalid }
		recommendations = append(recommendations, recommendation)
		return nil
	}
	buffer, hasBuffer := current[VariableBufferPool]
	readRequests := observation.Snapshot.Status.BufferPoolReadRequests
	physicalReads := observation.Snapshot.Status.BufferPoolReads
	if hasBuffer && readRequests >= 10000 && physicalReads <= readRequests {
		missBasisPoints := physicalReads * 10000 / readRequests
		maximum := capacity.MemoryBytes * 70 / 100
		desired := minUint64(maxUint64(buffer.Uint+buffer.Uint/4, observation.Snapshot.Storage.DatabaseBytes/2), maximum)
		if missBasisPoints >= 100 && desired > buffer.Uint {
			err = appendRecommendation(TuningRecommendation{Variable: VariableBufferPool, Current: buffer, Target: TuningValue{Kind: TuningBytes, Uint: desired}, Mode: ApplicationDynamic,
				Inputs: []MeasuredInput{{Metric: "buffer_pool_read_requests", Value: readRequests, Unit: "count"}, {Metric: "buffer_pool_physical_reads", Value: physicalReads, Unit: "count"}, {Metric: "memory_capacity", Value: capacity.MemoryBytes, Unit: "bytes"}},
				RationaleCode: "buffer_pool_miss_pressure", ConfidenceBasisPoints: confidence(observation.Snapshot.Uncertainty.ServerVariables, observation.Snapshot.Uncertainty.StatusVariables),
				Constraints: []CapacityConstraint{{Name: "memory_ceiling", Available: maximum, Required: desired, Unit: "bytes", Satisfied: desired <= maximum}}})
			if err != nil { return nil, err }
		}
	}
	connections, hasConnections := current[VariableMaxConnections]
	if hasConnections && connections.Uint > 0 && observation.Snapshot.Status.MaxUsedConnections*100 >= connections.Uint*80 {
		desired := minUint64(maxUint64(connections.Uint+connections.Uint/4, observation.Snapshot.Status.MaxUsedConnections+16), uint64(capacity.MaxConnections))
		if desired > connections.Uint {
			err = appendRecommendation(TuningRecommendation{Variable: VariableMaxConnections, Current: connections, Target: TuningValue{Kind: TuningCount, Uint: desired}, Mode: ApplicationDynamic,
				Inputs: []MeasuredInput{{Metric: "max_used_connections", Value: observation.Snapshot.Status.MaxUsedConnections, Unit: "count"}, {Metric: "configured_connections", Value: connections.Uint, Unit: "count"}, {Metric: "capacity_connections", Value: uint64(capacity.MaxConnections), Unit: "count"}},
				RationaleCode: "connection_headroom_low", ConfidenceBasisPoints: confidence(observation.Snapshot.Uncertainty.Connections, observation.Snapshot.Uncertainty.StatusVariables),
				Constraints: []CapacityConstraint{{Name: "connection_capacity", Available: uint64(capacity.MaxConnections), Required: desired, Unit: "count", Satisfied: desired <= uint64(capacity.MaxConnections)}}})
			if err != nil { return nil, err }
		}
	}
	temp, hasTemp := current[VariableTempTable]
	maxHeap, hasHeap := current[VariableMaxHeapTable]
	totalTemp := observation.Snapshot.Status.CreatedTempTables
	diskTemp := observation.Snapshot.Status.CreatedTempDiskTables
	if hasTemp && hasHeap && totalTemp >= 100 && diskTemp <= totalTemp && diskTemp*100 >= totalTemp*20 {
		perConnectionCeiling := capacity.MemoryBytes / maxUint64(uint64(capacity.MaxConnections), 1) / 4
		desired := minUint64(maxUint64(temp.Uint, maxHeap.Uint)*2, perConnectionCeiling)
		if desired > temp.Uint {
			err = appendRecommendation(TuningRecommendation{Variable: VariableTempTable, Current: temp, Target: TuningValue{Kind: TuningBytes, Uint: desired}, Mode: ApplicationDynamic,
				Inputs: []MeasuredInput{{Metric: "created_temp_tables", Value: totalTemp, Unit: "count"}, {Metric: "created_temp_disk_tables", Value: diskTemp, Unit: "count"}, {Metric: "per_connection_memory_ceiling", Value: perConnectionCeiling, Unit: "bytes"}},
				RationaleCode: "temporary_table_disk_pressure", ConfidenceBasisPoints: confidence(observation.Snapshot.Uncertainty.StatusVariables, observation.Snapshot.Uncertainty.Storage),
				Constraints: []CapacityConstraint{{Name: "per_connection_memory", Available: perConnectionCeiling, Required: desired, Unit: "bytes", Satisfied: desired <= perConnectionCeiling}}})
			if err != nil { return nil, err }
		}
	}
	sort.Slice(recommendations, func(left, right int) bool { return recommendations[left].Variable < recommendations[right].Variable })
	return recommendations, nil
}

func confidence(qualities ...EvidenceQuality) uint16 {
	result := uint16(9000)
	for _, quality := range qualities {
		switch quality {
		case EvidenceEstimated:
			if result > 1500 { result -= 1500 }
		case EvidenceUnavailable:
			return 1
		}
	}
	return result
}

type TuningPlanRequest struct {
	PlanID                 ResourceID
	Actor                  TuningActorID
	RecommendationDigests  []string
	MaximumEvidenceAge     time.Duration
	MinimumFreeMemoryBytes uint64
	MinimumFreeDiskBytes   uint64
	MaximumProbeLatency    time.Duration
	MaximumProbeErrorBasisPoints uint16
	MaximumReplicationLag  time.Duration
	MaintenanceWindowRef   ResourceID
	RecoveryPointRef       ResourceID
	IrreversibleFrontier   IrreversibleFrontier
}

func BuildTuningPlan(request TuningPlanRequest, observation TuningObservation, recommendations []TuningRecommendation, capacity InstanceCapacity, createdAt time.Time) (TuningPlan, error) {
	if request.PlanID.IsZero() || !validTuningID(string(request.Actor)) || len(request.RecommendationDigests) == 0 || len(request.RecommendationDigests) > MaximumTuningChanges ||
		!sort.StringsAreSorted(request.RecommendationDigests) || request.MaximumEvidenceAge < time.Second || request.MaximumEvidenceAge > MaximumTuningEvidenceAge ||
		request.MinimumFreeMemoryBytes == 0 || request.MinimumFreeDiskBytes == 0 || request.MaximumProbeLatency < time.Millisecond || request.MaximumProbeLatency > time.Minute || request.MaximumProbeErrorBasisPoints > 10000 ||
		createdAt.IsZero() || createdAt.Before(observation.CapturedAt) || observation.Validate() != nil ||
		capacity.MemoryBytes <= request.MinimumFreeMemoryBytes || capacity.StorageBytes <= request.MinimumFreeDiskBytes {
		return TuningPlan{}, ErrTuningInvalid
	}
	if createdAt.Sub(observation.CapturedAt) > request.MaximumEvidenceAge || observation.Snapshot.Storage.FreeBytes < request.MinimumFreeDiskBytes || observation.Snapshot.Storage.CapacityBytes > capacity.StorageBytes {
		return TuningPlan{}, ErrTuningStale
	}
	selected := make(map[string]TuningRecommendation, len(recommendations))
	observedValues := make(map[TuningVariable]TuningValue, len(observation.Snapshot.Server.Variables))
	for _, variable := range observation.Snapshot.Server.Variables { observedValues[variable.Variable] = variable.Value }
	for _, recommendation := range recommendations {
		current, observed := observedValues[recommendation.Variable]
		if recommendation.Validate() != nil || recommendation.ObservationID != observation.ID || recommendation.ObservationDigest != observation.Digest || !observed || !current.equal(recommendation.Current) {
			return TuningPlan{}, ErrTuningInvalid
		}
		selected[recommendation.Digest] = recommendation
	}
	changes := make([]TuningChange, 0, len(request.RecommendationDigests))
	var memoryImpact, diskImpact int64
	for index, recommendationDigest := range request.RecommendationDigests {
		if !validSHA256(recommendationDigest) || index > 0 && request.RecommendationDigests[index-1] == recommendationDigest { return TuningPlan{}, ErrTuningInvalid }
		recommendation, exists := selected[recommendationDigest]
		if !exists { return TuningPlan{}, ErrTuningInvalid }
		change := TuningChange{Variable: recommendation.Variable, Current: recommendation.Current, Target: recommendation.Target, Mode: recommendation.Mode, RecommendationDigest: recommendation.Digest}
		change.MemoryImpactBytes, change.DiskImpactBytes = estimateImpact(change, observation)
		if addOverflows(memoryImpact, change.MemoryImpactBytes) || addOverflows(diskImpact, change.DiskImpactBytes) { return TuningPlan{}, ErrTuningInvalid }
		memoryImpact += change.MemoryImpactBytes
		diskImpact += change.DiskImpactBytes
		changes = append(changes, change)
	}
	sort.Slice(changes, func(left, right int) bool { return changes[left].Variable < changes[right].Variable })
	if memoryImpact > 0 && uint64(memoryImpact) > capacity.MemoryBytes-request.MinimumFreeMemoryBytes || diskImpact > 0 && uint64(diskImpact) > capacity.StorageBytes-request.MinimumFreeDiskBytes {
		return TuningPlan{}, ErrTuningInvalid
	}
	replication := ReplicationPrecondition{Role: observation.Snapshot.Replication.Role, GTIDSetDigest: observation.Snapshot.Replication.GTIDSetDigest}
	if replication.Role == ReplicationReplica {
		if request.MaximumReplicationLag <= 0 || observation.Snapshot.Replication.LagUpperBound > request.MaximumReplicationLag { return TuningPlan{}, ErrTuningStale }
		replication.MaximumLag = request.MaximumReplicationLag
	} else if request.MaximumReplicationLag != 0 { return TuningPlan{}, ErrTuningInvalid }
	plan := TuningPlan{ID: request.PlanID, InstanceID: observation.InstanceID, Generation: 1, CreatedBy: request.Actor, CreatedAt: createdAt.UTC(),
		Preconditions: TuningPreconditions{ObservationID: observation.ID, ObservationDigest: observation.Digest, EvidenceCapturedAt: observation.CapturedAt,
			MaximumEvidenceAge: request.MaximumEvidenceAge, ServerVersion: observation.ServerVersion, ConfigGeneration: observation.ConfigGeneration,
			MinimumFreeMemoryBytes: request.MinimumFreeMemoryBytes, MinimumFreeDiskBytes: request.MinimumFreeDiskBytes, MaximumProbeLatency: request.MaximumProbeLatency,
			MaximumProbeErrorBasisPoints: request.MaximumProbeErrorBasisPoints, Replication: replication},
		Changes: changes, MemoryImpactBytes: memoryImpact, DiskImpactBytes: diskImpact, MaintenanceWindowRef: request.MaintenanceWindowRef,
		RecoveryPointRef: request.RecoveryPointRef, IrreversibleFrontier: request.IrreversibleFrontier}
	candidate, err := RenderTuningCandidate(plan)
	if err != nil { return TuningPlan{}, err }
	plan.CandidateConfigDigest = candidate.Digest()
	plan.Digest = tuningPlanDigest(plan)
	if plan.Validate() != nil { return TuningPlan{}, ErrTuningInvalid }
	return plan, nil
}

func estimateImpact(change TuningChange, observation TuningObservation) (int64, int64) {
	difference := signedDifference(change.Target.Uint, change.Current.Uint)
	switch change.Variable {
	case VariableBufferPool:
		return difference, 0
	case VariableTempTable, VariableMaxHeapTable:
		connections := uint64(observation.Snapshot.Connections.ConfiguredMaximum)
		return saturatingMultiply(difference, connections), 0
	case VariableMaxConnections:
		return saturatingMultiply(difference, 256<<10), 0
	default:
		return 0, 0
	}
}

func signedDifference(target, current uint64) int64 {
	if target >= current {
		if target-current > uint64(maximumTuningInt64) { return maximumTuningInt64 }
		return int64(target - current)
	}
	if current-target > uint64(maximumTuningInt64) { return minimumTuningInt64 }
	return -int64(current - target)
}

func addOverflows(left, right int64) bool {
	return right > 0 && left > maximumTuningInt64-right || right < 0 && left < minimumTuningInt64-right
}

func saturatingMultiply(value int64, multiplier uint64) int64 {
	if value == 0 || multiplier == 0 { return 0 }
	if value > 0 {
		if multiplier > uint64(maximumTuningInt64)/uint64(value) { return maximumTuningInt64 }
		return value * int64(multiplier)
	}
	magnitude := uint64(-(value + 1)) + 1
	if multiplier > uint64(maximumTuningInt64)/magnitude { return minimumTuningInt64 }
	return value * int64(multiplier)
}

func minUint64(left, right uint64) uint64 { if left < right { return left }; return right }
func maxUint64(left, right uint64) uint64 { if left > right { return left }; return right }

func RecommendationSetDigest(recommendations []TuningRecommendation) (string, error) {
	copyOfRecommendations := append([]TuningRecommendation(nil), recommendations...)
	sort.Slice(copyOfRecommendations, func(left, right int) bool { return copyOfRecommendations[left].Digest < copyOfRecommendations[right].Digest })
	for _, recommendation := range copyOfRecommendations { if recommendation.Validate() != nil { return "", ErrTuningInvalid } }
	encoded, err := json.Marshal(copyOfRecommendations)
	if err != nil { return "", err }
	return tuningDigest(encoded), nil
}
