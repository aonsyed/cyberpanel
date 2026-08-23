package database

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrTuningInvalid     = errors.New("invalid MariaDB tuning evidence or plan")
	ErrTuningStale       = errors.New("MariaDB tuning evidence is stale")
	ErrTuningUnsupported = errors.New("MariaDB tuning is unsupported by this server version")
	ErrTuningConflict    = errors.New("MariaDB tuning generation conflict")
	ErrTuningCompensated = errors.New("MariaDB tuning failed and was compensated")
)

const (
	MaximumTuningSnapshotBytes = 1 << 20
	MaximumTuningVariables     = 128
	MaximumSlowQueryDigests    = 256
	MaximumTuningChanges       = 32
	MaximumTuningEvidenceAge   = 15 * time.Minute
	MaximumTuningCollectTime   = 20 * time.Second
)

type TuningActorID string

func validTuningID(value string) bool {
	if value == "" || len(value) > 128 || !asciiAlphaNumeric(value[0]) || !asciiAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if !asciiAlphaNumeric(value[index]) && value[index] != '-' && value[index] != '_' && value[index] != '.' {
			return false
		}
	}
	return true
}

type TuningValueKind string

const (
	TuningBytes        TuningValueKind = "bytes"
	TuningCount        TuningValueKind = "count"
	TuningMilliseconds TuningValueKind = "milliseconds"
	TuningEnum         TuningValueKind = "enum"
)

type TuningValue struct {
	Kind TuningValueKind `json:"kind"`
	Uint uint64          `json:"uint,omitempty"`
	Enum string          `json:"enum,omitempty"`
}

func (value TuningValue) equal(other TuningValue) bool {
	return value.Kind == other.Kind && value.Uint == other.Uint && value.Enum == other.Enum
}

type TuningVariable string

const (
	VariableBufferPool      TuningVariable = "mysqld.innodb_buffer_pool_size"
	VariableMaxConnections TuningVariable = "mysqld.max_connections"
	VariableTempTable       TuningVariable = "mysqld.tmp_table_size"
	VariableMaxHeapTable    TuningVariable = "mysqld.max_heap_table_size"
	VariableSlowQueryTime   TuningVariable = "mysqld.long_query_time"
	VariableFlushMethod     TuningVariable = "mysqld.innodb_flush_method"
	VariableThreadCache     TuningVariable = "mysqld.thread_cache_size"
)

var tuningVariableOrder = []TuningVariable{
	VariableBufferPool,
	VariableFlushMethod,
	VariableSlowQueryTime,
	VariableMaxConnections,
	VariableMaxHeapTable,
	VariableThreadCache,
	VariableTempTable,
}

func validateTuningValue(variable TuningVariable, value TuningValue) error {
	switch variable {
	case VariableBufferPool:
		if value.Kind != TuningBytes || value.Uint < 64<<20 || value.Uint > 4<<50 || value.Enum != "" { return ErrTuningInvalid }
	case VariableMaxConnections:
		if value.Kind != TuningCount || value.Uint < 1 || value.Uint > 100000 || value.Enum != "" { return ErrTuningInvalid }
	case VariableTempTable, VariableMaxHeapTable:
		if value.Kind != TuningBytes || value.Uint < 1<<20 || value.Uint > 1<<40 || value.Enum != "" { return ErrTuningInvalid }
	case VariableSlowQueryTime:
		if value.Kind != TuningMilliseconds || value.Uint < 1 || value.Uint > uint64((24*time.Hour)/time.Millisecond) || value.Enum != "" { return ErrTuningInvalid }
	case VariableFlushMethod:
		if value.Kind != TuningEnum || value.Uint != 0 || value.Enum != "fsync" && value.Enum != "o_direct" { return ErrTuningInvalid }
	case VariableThreadCache:
		if value.Kind != TuningCount || value.Uint > 16384 || value.Enum != "" { return ErrTuningInvalid }
	default:
		return ErrTuningInvalid
	}
	return nil
}

type ObservedTuningVariable struct {
	Variable TuningVariable `json:"variable"`
	Value    TuningValue    `json:"value"`
	Source   string         `json:"source"`
}

type ServerVariableSnapshot struct {
	ServerIDDigest  string                   `json:"server_id_digest"`
	ConfigGeneration uint64                 `json:"config_generation"`
	Variables       []ObservedTuningVariable `json:"variables"`
}

type StatusVariableSnapshot struct {
	UptimeSeconds          uint64 `json:"uptime_seconds"`
	ThreadsConnected       uint64 `json:"threads_connected"`
	ThreadsRunning         uint64 `json:"threads_running"`
	MaxUsedConnections     uint64 `json:"max_used_connections"`
	AbortedConnects        uint64 `json:"aborted_connects"`
	Questions              uint64 `json:"questions"`
	SlowQueries            uint64 `json:"slow_queries"`
	BufferPoolReadRequests uint64 `json:"buffer_pool_read_requests"`
	BufferPoolReads        uint64 `json:"buffer_pool_reads"`
	CreatedTempTables      uint64 `json:"created_temp_tables"`
	CreatedTempDiskTables  uint64 `json:"created_temp_disk_tables"`
}

type ConnectionSnapshot struct {
	ConfiguredMaximum uint32 `json:"configured_maximum"`
	Current           uint32 `json:"current"`
	Running           uint32 `json:"running"`
	Waiting           uint32 `json:"waiting"`
	LongestSeconds    uint32 `json:"longest_seconds"`
}

type StorageSnapshot struct {
	CapacityBytes        uint64 `json:"capacity_bytes"`
	FreeBytes            uint64 `json:"free_bytes"`
	DatabaseBytes        uint64 `json:"database_bytes"`
	DataBytes            uint64 `json:"data_bytes"`
	IndexBytes           uint64 `json:"index_bytes"`
	LogBytes             uint64 `json:"log_bytes"`
	TemporaryBytes       uint64 `json:"temporary_bytes"`
	FsyncP95Microseconds uint64 `json:"fsync_p95_microseconds"`
}

type ReplicationRole string

const (
	ReplicationStandalone ReplicationRole = "standalone"
	ReplicationPrimary    ReplicationRole = "primary"
	ReplicationReplica    ReplicationRole = "replica"
	ReplicationUnknown    ReplicationRole = "unknown"
)

type ReplicationSnapshot struct {
	Role                  ReplicationRole `json:"role"`
	GTIDSetDigest         string          `json:"gtid_set_digest,omitempty"`
	SourceServerDigest    string          `json:"source_server_digest,omitempty"`
	IOThreadRunning       bool            `json:"io_thread_running"`
	SQLThreadRunning      bool            `json:"sql_thread_running"`
	LagLowerBound         time.Duration   `json:"lag_lower_bound"`
	LagUpperBound         time.Duration   `json:"lag_upper_bound"`
	LagExact              bool            `json:"lag_exact"`
}

type SlowQueryDigest struct {
	StatementDigest string        `json:"statement_digest"`
	SchemaDigest    string        `json:"schema_digest"`
	Executions      uint64        `json:"executions"`
	TotalLatency    time.Duration `json:"total_latency"`
	MaximumLatency  time.Duration `json:"maximum_latency"`
	RowsExamined    uint64        `json:"rows_examined"`
	RowsSent        uint64        `json:"rows_sent"`
}

type EvidenceQuality string

const (
	EvidenceExact       EvidenceQuality = "exact"
	EvidenceEstimated   EvidenceQuality = "estimated"
	EvidenceUnavailable EvidenceQuality = "unavailable"
)

type ObservationUncertainty struct {
	ServerVariables EvidenceQuality `json:"server_variables"`
	StatusVariables EvidenceQuality `json:"status_variables"`
	Connections     EvidenceQuality `json:"connections"`
	Storage         EvidenceQuality `json:"storage"`
	Replication     EvidenceQuality `json:"replication"`
	SlowQueries     EvidenceQuality `json:"slow_queries"`
	ReasonCodes     []string        `json:"reason_codes"`
}

type TuningSnapshot struct {
	Server      ServerVariableSnapshot `json:"server"`
	Status      StatusVariableSnapshot `json:"status"`
	Connections ConnectionSnapshot     `json:"connections"`
	Storage     StorageSnapshot        `json:"storage"`
	Replication ReplicationSnapshot    `json:"replication"`
	SlowQueries []SlowQueryDigest      `json:"slow_query_digests"`
	Health      Health                 `json:"health"`
	Uncertainty ObservationUncertainty `json:"uncertainty"`
}

type TuningObservation struct {
	ID               ResourceID       `json:"id"`
	InstanceID       ResourceID       `json:"instance_id"`
	ServerVersion    MariaDBVersion   `json:"server_version"`
	ConfigGeneration uint64           `json:"config_generation"`
	WindowStartedAt  time.Time        `json:"window_started_at"`
	CapturedAt       time.Time        `json:"captured_at"`
	Snapshot         TuningSnapshot   `json:"snapshot"`
	Digest           string           `json:"digest"`
}

func (observation TuningObservation) Validate() error {
	if observation.ID.IsZero() || observation.InstanceID.IsZero() || observation.ServerVersion.Major == 0 || observation.ConfigGeneration == 0 ||
		observation.WindowStartedAt.IsZero() || observation.CapturedAt.Before(observation.WindowStartedAt) || observation.CapturedAt.Sub(observation.WindowStartedAt) > 24*time.Hour ||
		observation.Snapshot.Server.ConfigGeneration != observation.ConfigGeneration || validateSnapshot(observation.Snapshot) != nil || !validSHA256(observation.Digest) {
		return ErrTuningInvalid
	}
	wanted, err := sealTuningObservation(observation)
	if err != nil || wanted.ID != observation.ID || wanted.Digest != observation.Digest {
		return ErrTuningInvalid
	}
	return nil
}

func sealTuningObservation(observation TuningObservation) (TuningObservation, error) {
	observation.ID = ResourceID{}
	observation.Digest = ""
	encoded, err := json.Marshal(observation)
	if err != nil || len(encoded) > MaximumTuningSnapshotBytes {
		return TuningObservation{}, ErrTuningInvalid
	}
	sum := sha256.Sum256(encoded)
	observation.Digest = hex.EncodeToString(sum[:])
	id, err := NewResourceID("dbobs-" + observation.Digest[:40])
	if err != nil { return TuningObservation{}, err }
	observation.ID = id
	return observation, nil
}

func validateSnapshot(snapshot TuningSnapshot) error {
	if !validSHA256(snapshot.Server.ServerIDDigest) || snapshot.Server.ConfigGeneration == 0 || len(snapshot.Server.Variables) == 0 || len(snapshot.Server.Variables) > MaximumTuningVariables ||
		snapshot.Connections.ConfiguredMaximum == 0 || snapshot.Connections.Current > snapshot.Connections.ConfiguredMaximum || snapshot.Connections.Running > snapshot.Connections.Current || snapshot.Connections.Waiting > snapshot.Connections.Current ||
		snapshot.Storage.CapacityBytes == 0 || snapshot.Storage.FreeBytes > snapshot.Storage.CapacityBytes || snapshot.Storage.DatabaseBytes > snapshot.Storage.CapacityBytes ||
		len(snapshot.SlowQueries) > MaximumSlowQueryDigests || !validHealth(snapshot.Health) || validateUncertainty(snapshot.Uncertainty) != nil {
		return ErrTuningInvalid
	}
	last := TuningVariable("")
	for _, variable := range snapshot.Server.Variables {
		if variable.Variable <= last || validateTuningValue(variable.Variable, variable.Value) != nil || !validReasonCode(variable.Source) {
			return ErrTuningInvalid
		}
		last = variable.Variable
	}
	if validateReplication(snapshot.Replication) != nil { return ErrTuningInvalid }
	lastDigest := ""
	for _, query := range snapshot.SlowQueries {
		if !validSHA256(query.StatementDigest) || !validSHA256(query.SchemaDigest) || query.StatementDigest <= lastDigest || query.Executions == 0 || query.TotalLatency < 0 || query.MaximumLatency < 0 || query.MaximumLatency > query.TotalLatency {
			return ErrTuningInvalid
		}
		lastDigest = query.StatementDigest
	}
	return nil
}

func validHealth(health Health) bool {
	return health == HealthHealthy || health == HealthDegraded || health == HealthUnavailable || health == HealthUnknown
}

func validateReplication(replication ReplicationSnapshot) error {
	switch replication.Role {
	case ReplicationStandalone:
		if replication.GTIDSetDigest != "" || replication.SourceServerDigest != "" || replication.IOThreadRunning || replication.SQLThreadRunning || replication.LagLowerBound != 0 || replication.LagUpperBound != 0 { return ErrTuningInvalid }
	case ReplicationPrimary:
		if replication.GTIDSetDigest != "" && !validSHA256(replication.GTIDSetDigest) || replication.SourceServerDigest != "" || replication.LagLowerBound != 0 || replication.LagUpperBound != 0 { return ErrTuningInvalid }
	case ReplicationReplica:
		if !validSHA256(replication.GTIDSetDigest) || !validSHA256(replication.SourceServerDigest) || replication.LagLowerBound < 0 || replication.LagUpperBound < replication.LagLowerBound || replication.LagUpperBound > 24*time.Hour { return ErrTuningInvalid }
	case ReplicationUnknown:
		if replication.LagLowerBound != 0 || replication.LagUpperBound != 0 { return ErrTuningInvalid }
	default:
		return ErrTuningInvalid
	}
	return nil
}

func validateUncertainty(uncertainty ObservationUncertainty) error {
	qualities := []EvidenceQuality{uncertainty.ServerVariables, uncertainty.StatusVariables, uncertainty.Connections, uncertainty.Storage, uncertainty.Replication, uncertainty.SlowQueries}
	for _, quality := range qualities {
		if quality != EvidenceExact && quality != EvidenceEstimated && quality != EvidenceUnavailable { return ErrTuningInvalid }
	}
	if len(uncertainty.ReasonCodes) > 32 || !sort.StringsAreSorted(uncertainty.ReasonCodes) { return ErrTuningInvalid }
	for index, reason := range uncertainty.ReasonCodes {
		if !validReasonCode(reason) || index > 0 && uncertainty.ReasonCodes[index-1] == reason { return ErrTuningInvalid }
	}
	return nil
}

func validReasonCode(value string) bool {
	if value == "" || len(value) > 96 || value[0] < 'a' || value[0] > 'z' { return false }
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '_' && character != '.' { return false }
			}
		}
	}
	return true
}

type ApplicationMode string

const (
	ApplicationDynamic ApplicationMode = "dynamic"
	ApplicationReload  ApplicationMode = "reload"
	ApplicationRestart ApplicationMode = "restart"
)

type VariableCapability struct {
	Variable     TuningVariable   `json:"variable"`
	Modes        []ApplicationMode `json:"modes"`
	Minimum      TuningValue      `json:"minimum"`
	Maximum      TuningValue      `json:"maximum"`
}

type MariaDBTuningCapabilities struct {
	Version   MariaDBVersion     `json:"version"`
	Variables []VariableCapability `json:"variables"`
}

func TuningCapabilitiesFor(version MariaDBVersion) (MariaDBTuningCapabilities, error) {
	if version.Major != 10 && version.Major != 11 || version.Major == 10 && (version.Minor < 6 || version.Minor > 11) || version.Major == 11 && version.Minor > 8 {
		return MariaDBTuningCapabilities{}, ErrTuningUnsupported
	}
	capabilities := MariaDBTuningCapabilities{Version: version, Variables: []VariableCapability{
		{Variable: VariableBufferPool, Modes: []ApplicationMode{ApplicationDynamic, ApplicationRestart}, Minimum: TuningValue{Kind: TuningBytes, Uint: 64 << 20}, Maximum: TuningValue{Kind: TuningBytes, Uint: 4 << 50}},
		{Variable: VariableFlushMethod, Modes: []ApplicationMode{ApplicationRestart}, Minimum: TuningValue{Kind: TuningEnum, Enum: "fsync"}, Maximum: TuningValue{Kind: TuningEnum, Enum: "o_direct"}},
		{Variable: VariableSlowQueryTime, Modes: []ApplicationMode{ApplicationDynamic, ApplicationRestart}, Minimum: TuningValue{Kind: TuningMilliseconds, Uint: 1}, Maximum: TuningValue{Kind: TuningMilliseconds, Uint: uint64((24*time.Hour)/time.Millisecond)}},
		{Variable: VariableMaxConnections, Modes: []ApplicationMode{ApplicationDynamic, ApplicationRestart}, Minimum: TuningValue{Kind: TuningCount, Uint: 1}, Maximum: TuningValue{Kind: TuningCount, Uint: 100000}},
		{Variable: VariableMaxHeapTable, Modes: []ApplicationMode{ApplicationDynamic, ApplicationRestart}, Minimum: TuningValue{Kind: TuningBytes, Uint: 1 << 20}, Maximum: TuningValue{Kind: TuningBytes, Uint: 1 << 40}},
		{Variable: VariableThreadCache, Modes: []ApplicationMode{ApplicationDynamic, ApplicationRestart}, Minimum: TuningValue{Kind: TuningCount}, Maximum: TuningValue{Kind: TuningCount, Uint: 16384}},
		{Variable: VariableTempTable, Modes: []ApplicationMode{ApplicationDynamic, ApplicationRestart}, Minimum: TuningValue{Kind: TuningBytes, Uint: 1 << 20}, Maximum: TuningValue{Kind: TuningBytes, Uint: 1 << 40}},
	}}
	return capabilities, nil
}

func (capabilities MariaDBTuningCapabilities) capability(variable TuningVariable) (VariableCapability, bool) {
	index := sort.Search(len(capabilities.Variables), func(index int) bool { return capabilities.Variables[index].Variable >= variable })
	if index < len(capabilities.Variables) && capabilities.Variables[index].Variable == variable { return capabilities.Variables[index], true }
	return VariableCapability{}, false
}

type MeasuredInput struct {
	Metric string `json:"metric"`
	Value  uint64 `json:"value"`
	Unit   string `json:"unit"`
}

type CapacityConstraint struct {
	Name       string `json:"name"`
	Available  uint64 `json:"available"`
	Required   uint64 `json:"required"`
	Unit       string `json:"unit"`
	Satisfied  bool   `json:"satisfied"`
}

type TuningRecommendation struct {
	ObservationID     ResourceID           `json:"observation_id"`
	ObservationDigest string               `json:"observation_digest"`
	Variable          TuningVariable       `json:"variable"`
	Current           TuningValue          `json:"current"`
	Target            TuningValue          `json:"target"`
	Mode              ApplicationMode      `json:"mode"`
	Inputs            []MeasuredInput      `json:"measured_inputs"`
	RationaleCode     string               `json:"rationale_code"`
	ConfidenceBasisPoints uint16           `json:"confidence_basis_points"`
	Constraints       []CapacityConstraint `json:"capacity_constraints"`
	GeneratedAt       time.Time            `json:"generated_at"`
	Digest            string               `json:"digest"`
}

func (recommendation TuningRecommendation) Validate() error {
	if recommendation.ObservationID.IsZero() || !validSHA256(recommendation.ObservationDigest) || validateTuningValue(recommendation.Variable, recommendation.Current) != nil ||
		validateTuningValue(recommendation.Variable, recommendation.Target) != nil || recommendation.Current.equal(recommendation.Target) || !validApplicationMode(recommendation.Mode) ||
		len(recommendation.Inputs) == 0 || len(recommendation.Inputs) > 16 || !validReasonCode(recommendation.RationaleCode) || recommendation.ConfidenceBasisPoints == 0 || recommendation.ConfidenceBasisPoints > 10000 ||
		len(recommendation.Constraints) > 16 || recommendation.GeneratedAt.IsZero() || !validSHA256(recommendation.Digest) || recommendationDigest(recommendation) != recommendation.Digest {
		return ErrTuningInvalid
	}
	return nil
}

func recommendationDigest(recommendation TuningRecommendation) string {
	recommendation.Digest = ""
	encoded, _ := json.Marshal(recommendation)
	return tuningDigest(encoded)
}

func validApplicationMode(mode ApplicationMode) bool { return mode == ApplicationDynamic || mode == ApplicationReload || mode == ApplicationRestart }

type TuningChange struct {
	Variable         TuningVariable  `json:"variable"`
	Current          TuningValue     `json:"current"`
	Target           TuningValue     `json:"target"`
	Mode             ApplicationMode `json:"mode"`
	MemoryImpactBytes int64          `json:"memory_impact_bytes"`
	DiskImpactBytes   int64          `json:"disk_impact_bytes"`
	RecommendationDigest string      `json:"recommendation_digest"`
}

type ReplicationPrecondition struct {
	Role              ReplicationRole `json:"role"`
	GTIDSetDigest     string          `json:"gtid_set_digest,omitempty"`
	MaximumLag        time.Duration   `json:"maximum_lag"`
}

type TuningPreconditions struct {
	ObservationID        ResourceID              `json:"observation_id"`
	ObservationDigest    string                  `json:"observation_digest"`
	EvidenceCapturedAt   time.Time               `json:"evidence_captured_at"`
	MaximumEvidenceAge   time.Duration           `json:"maximum_evidence_age"`
	ServerVersion        MariaDBVersion          `json:"server_version"`
	ConfigGeneration     uint64                  `json:"config_generation"`
	MinimumFreeMemoryBytes uint64                `json:"minimum_free_memory_bytes"`
	MinimumFreeDiskBytes uint64                  `json:"minimum_free_disk_bytes"`
	MaximumProbeLatency  time.Duration           `json:"maximum_probe_latency"`
	MaximumProbeErrorBasisPoints uint16           `json:"maximum_probe_error_basis_points"`
	Replication         ReplicationPrecondition `json:"replication"`
}

type IrreversibleFrontier string

const (
	FrontierNone       IrreversibleFrontier = "none"
	FrontierAfterCommit IrreversibleFrontier = "after_commit"
)

type TuningPlan struct {
	ID                    ResourceID          `json:"id"`
	InstanceID            ResourceID          `json:"instance_id"`
	Generation            uint64              `json:"generation"`
	CreatedBy             TuningActorID        `json:"created_by"`
	CreatedAt             time.Time           `json:"created_at"`
	Preconditions         TuningPreconditions `json:"preconditions"`
	Changes               []TuningChange       `json:"changes"`
	MemoryImpactBytes     int64                `json:"memory_impact_bytes"`
	DiskImpactBytes       int64                `json:"disk_impact_bytes"`
	MaintenanceWindowRef  ResourceID           `json:"maintenance_window_ref,omitempty"`
	RecoveryPointRef      ResourceID           `json:"recovery_point_ref,omitempty"`
	CandidateConfigDigest string               `json:"candidate_config_digest"`
	IrreversibleFrontier  IrreversibleFrontier `json:"irreversible_frontier"`
	Digest                string               `json:"digest"`
}

func (plan TuningPlan) Validate() error {
	if plan.ID.IsZero() || plan.InstanceID.IsZero() || plan.Generation != 1 || !validTuningID(string(plan.CreatedBy)) || plan.CreatedAt.IsZero() ||
		validatePreconditions(plan.Preconditions) != nil || len(plan.Changes) == 0 || len(plan.Changes) > MaximumTuningChanges || !validSHA256(plan.CandidateConfigDigest) || !validSHA256(plan.Digest) ||
		plan.IrreversibleFrontier != FrontierNone && plan.IrreversibleFrontier != FrontierAfterCommit {
		return ErrTuningInvalid
	}
	capabilities, err := TuningCapabilitiesFor(plan.Preconditions.ServerVersion)
	if err != nil { return err }
	var memoryImpact, diskImpact int64
	last := TuningVariable("")
	restart := false
	for _, change := range plan.Changes {
		capability, supported := capabilities.capability(change.Variable)
		if !supported || change.Variable <= last || validateChange(change, capability) != nil { return ErrTuningInvalid }
		last = change.Variable
		if addOverflows(memoryImpact, change.MemoryImpactBytes) || addOverflows(diskImpact, change.DiskImpactBytes) { return ErrTuningInvalid }
		memoryImpact += change.MemoryImpactBytes
		diskImpact += change.DiskImpactBytes
		restart = restart || change.Mode == ApplicationRestart || change.Mode == ApplicationReload
	}
	if memoryImpact != plan.MemoryImpactBytes || diskImpact != plan.DiskImpactBytes || restart && (plan.MaintenanceWindowRef.IsZero() || plan.RecoveryPointRef.IsZero()) ||
		!restart && (!plan.MaintenanceWindowRef.IsZero() || !plan.RecoveryPointRef.IsZero()) {
		return ErrTuningInvalid
	}
	candidate, err := RenderTuningCandidate(plan)
	if err != nil || candidate.Digest() != plan.CandidateConfigDigest || tuningPlanDigest(plan) != plan.Digest { return ErrTuningInvalid }
	return nil
}

func validatePreconditions(preconditions TuningPreconditions) error {
	if preconditions.ObservationID.IsZero() || !validSHA256(preconditions.ObservationDigest) || preconditions.EvidenceCapturedAt.IsZero() ||
		preconditions.MaximumEvidenceAge < time.Second || preconditions.MaximumEvidenceAge > MaximumTuningEvidenceAge || preconditions.ServerVersion.Major == 0 || preconditions.ConfigGeneration == 0 ||
		preconditions.MinimumFreeMemoryBytes == 0 || preconditions.MinimumFreeDiskBytes == 0 || preconditions.MaximumProbeLatency < time.Millisecond || preconditions.MaximumProbeLatency > time.Minute ||
		preconditions.MaximumProbeErrorBasisPoints > 10000 || validateReplicationPrecondition(preconditions.Replication) != nil {
		return ErrTuningInvalid
	}
	return nil
}

func validateReplicationPrecondition(precondition ReplicationPrecondition) error {
	if precondition.MaximumLag < 0 || precondition.MaximumLag > time.Hour { return ErrTuningInvalid }
	switch precondition.Role {
	case ReplicationStandalone:
		if precondition.GTIDSetDigest != "" || precondition.MaximumLag != 0 { return ErrTuningInvalid }
	case ReplicationPrimary:
		if precondition.GTIDSetDigest != "" && !validSHA256(precondition.GTIDSetDigest) || precondition.MaximumLag != 0 { return ErrTuningInvalid }
	case ReplicationReplica:
		if !validSHA256(precondition.GTIDSetDigest) || precondition.MaximumLag <= 0 { return ErrTuningInvalid }
	default:
		return ErrTuningInvalid
	}
	return nil
}

func validateChange(change TuningChange, capability VariableCapability) error {
	if validateTuningValue(change.Variable, change.Current) != nil || validateTuningValue(change.Variable, change.Target) != nil || change.Current.equal(change.Target) ||
		!containsMode(capability.Modes, change.Mode) || !validSHA256(change.RecommendationDigest) { return ErrTuningInvalid }
	return nil
}

func containsMode(modes []ApplicationMode, mode ApplicationMode) bool {
	for _, candidate := range modes { if candidate == mode { return true } }
	return false
}

func tuningPlanDigest(plan TuningPlan) string {
	plan.Digest = ""
	encoded, _ := json.Marshal(plan)
	return tuningDigest(encoded)
}

type CandidateTuningConfig struct {
	planID  ResourceID
	digest  string
	content []byte
}

func (candidate CandidateTuningConfig) PlanID() ResourceID { return candidate.planID }
func (candidate CandidateTuningConfig) Digest() string { return candidate.digest }
func (candidate CandidateTuningConfig) Bytes() []byte { return append([]byte(nil), candidate.content...) }

func RenderTuningCandidate(plan TuningPlan) (CandidateTuningConfig, error) {
	if plan.ID.IsZero() || len(plan.Changes) == 0 || len(plan.Changes) > MaximumTuningChanges { return CandidateTuningConfig{}, ErrTuningInvalid }
	var builder strings.Builder
	builder.WriteString("# cyberpanel-mariadb-tuning-v1\n[mysqld]\n")
	last := TuningVariable("")
	for _, change := range plan.Changes {
		if change.Variable <= last || validateTuningValue(change.Variable, change.Target) != nil { return CandidateTuningConfig{}, ErrTuningInvalid }
		last = change.Variable
		name := strings.TrimPrefix(string(change.Variable), "mysqld.")
		if strings.ContainsAny(name, " \t\r\n=#") { return CandidateTuningConfig{}, ErrTuningInvalid }
		builder.WriteString(name)
		builder.WriteString(" = ")
		builder.WriteString(renderTuningValue(change.Variable, change.Target))
		builder.WriteByte('\n')
	}
	content := []byte(builder.String())
	return CandidateTuningConfig{planID: plan.ID, digest: tuningDigest(content), content: content}, nil
}

func renderTuningValue(variable TuningVariable, value TuningValue) string {
	if value.Kind == TuningEnum { return value.Enum }
	if variable == VariableSlowQueryTime {
		seconds := value.Uint / 1000
		milliseconds := value.Uint % 1000
		if milliseconds == 0 { return strconv.FormatUint(seconds, 10) }
		return strings.TrimRight(fmt.Sprintf("%d.%03d", seconds, milliseconds), "0")
	}
	return strconv.FormatUint(value.Uint, 10)
}

type TuningExecutionStatus string

const (
	TuningAccepted    TuningExecutionStatus = "accepted"
	TuningValidated   TuningExecutionStatus = "validated"
	TuningStaged      TuningExecutionStatus = "staged"
	TuningApplying    TuningExecutionStatus = "applying"
	TuningVerifying   TuningExecutionStatus = "verifying"
	TuningCommitted   TuningExecutionStatus = "committed"
	TuningCompensated TuningExecutionStatus = "compensated"
	TuningFailed      TuningExecutionStatus = "failed"
	TuningAmbiguous   TuningExecutionStatus = "ambiguous"
)

type TuningReceipt struct {
	PlanID              ResourceID            `json:"plan_id"`
	PlanDigest          string                `json:"plan_digest"`
	Generation          uint64                `json:"generation"`
	Status              TuningExecutionStatus `json:"status"`
	CandidateConfigDigest string              `json:"candidate_config_digest"`
	ValidationDigest    string                `json:"validation_digest,omitempty"`
	StageDigest         string                `json:"stage_digest,omitempty"`
	StageToken          ResourceID            `json:"stage_token,omitempty"`
	PreviousConfigDigest string               `json:"previous_config_digest,omitempty"`
	PreviousConfigGeneration uint64           `json:"previous_config_generation,omitempty"`
	CandidateConfigGeneration uint64          `json:"candidate_config_generation,omitempty"`
	ConfigCommitDigest  string                `json:"config_commit_digest,omitempty"`
	MariaDBEffectDigest string                `json:"mariadb_effect_digest,omitempty"`
	DeploymentDigest    string                `json:"deployment_digest,omitempty"`
	HealthProbeDigest   string                `json:"health_probe_digest,omitempty"`
	WorkloadProbeDigest string                `json:"workload_probe_digest,omitempty"`
	ReplicationProbeDigest string             `json:"replication_probe_digest,omitempty"`
	CompensationDigest string                 `json:"compensation_digest,omitempty"`
	FailureCode         string                `json:"failure_code,omitempty"`
	MutationPossible    bool                  `json:"mutation_possible"`
	OccurredAt          time.Time             `json:"occurred_at"`
	Digest              string                `json:"digest"`
}

func (receipt TuningReceipt) Validate() error {
	if receipt.PlanID.IsZero() || !validSHA256(receipt.PlanDigest) || receipt.Generation == 0 || !validTuningStatus(receipt.Status) || !validSHA256(receipt.CandidateConfigDigest) ||
		receipt.OccurredAt.IsZero() || !validSHA256(receipt.Digest) || tuningReceiptDigest(receipt) != receipt.Digest || receipt.FailureCode != "" && !validReasonCode(receipt.FailureCode) {
		return ErrTuningInvalid
	}
	digests := []string{receipt.ValidationDigest, receipt.StageDigest, receipt.ConfigCommitDigest, receipt.MariaDBEffectDigest, receipt.DeploymentDigest,
		receipt.HealthProbeDigest, receipt.WorkloadProbeDigest, receipt.ReplicationProbeDigest, receipt.CompensationDigest}
	for _, value := range digests { if value != "" && !validSHA256(value) { return ErrTuningInvalid } }
	staged := !receipt.StageToken.IsZero() || receipt.PreviousConfigDigest != "" || receipt.PreviousConfigGeneration != 0 || receipt.CandidateConfigGeneration != 0
	if staged && (receipt.StageToken.IsZero() || !validSHA256(receipt.PreviousConfigDigest) || receipt.PreviousConfigGeneration == 0 || receipt.CandidateConfigGeneration != receipt.PreviousConfigGeneration+1) { return ErrTuningInvalid }
	if (receipt.Status == TuningStaged || receipt.Status == TuningApplying || receipt.Status == TuningVerifying || receipt.Status == TuningCommitted || receipt.Status == TuningCompensated) && !staged { return ErrTuningInvalid }
	if receipt.Status == TuningAmbiguous && !receipt.MutationPossible { return ErrTuningInvalid }
	return nil
}

func validTuningStatus(status TuningExecutionStatus) bool {
	switch status {
	case TuningAccepted, TuningValidated, TuningStaged, TuningApplying, TuningVerifying, TuningCommitted, TuningCompensated, TuningFailed, TuningAmbiguous:
		return true
	default:
		return false
	}
}

func tuningReceiptDigest(receipt TuningReceipt) string {
	receipt.Digest = ""
	encoded, _ := json.Marshal(receipt)
	return tuningDigest(encoded)
}

func tuningDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func TuningValueString(variable TuningVariable, value TuningValue) (string, error) {
	if validateTuningValue(variable, value) != nil { return "", ErrTuningInvalid }
	return fmt.Sprintf("%s=%s", variable, renderTuningValue(variable, value)), nil
}
