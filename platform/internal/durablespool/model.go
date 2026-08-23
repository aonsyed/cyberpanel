package durablespool

import (
	"context"
	"errors"
	"regexp"
	"time"
)

var (
	ErrInvalid    = errors.New("durable spool: invalid value")
	ErrLimit      = errors.New("durable spool: limit exceeded")
	ErrPressure   = errors.New("durable spool: filesystem pressure")
	ErrConflict   = errors.New("durable spool: conflict")
	ErrNotFound   = errors.New("durable spool: record not found")
	ErrIntegrity  = errors.New("durable spool: integrity failure")
	ErrStaleFence = errors.New("durable spool: stale fence")
)

const (
	SchemaVersion       = "cyberpanel.durable-spool.v1"
	DefaultMaximumLease = 15 * time.Minute
	MaximumLeaseLimit   = 24 * time.Hour
	MaximumLeaseBatch   = 256
	MaximumOwnerBytes   = 128
	MaximumReasonBytes  = 256
	AbsoluteMaximumSpoolBytes = uint64(4 << 30)
	AbsoluteMaximumRecordBytes = uint64(16 << 20)
	AbsoluteMaximumRecords = uint64(1 << 20)
)

var opaqueValuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$`)

type Watermark string

const (
	WatermarkNormal    Watermark = "normal"
	WatermarkWarn      Watermark = "warn"
	WatermarkRestrict  Watermark = "restrict"
	WatermarkEmergency Watermark = "emergency"
)

type CapacityReserve struct {
	Bytes  uint64 `json:"bytes"`
	Inodes uint64 `json:"inodes"`
}

type FilesystemPressure struct {
	BytesTotal    uint64    `json:"bytes_total"`
	BytesFree     uint64    `json:"bytes_free"`
	BytesReserved uint64    `json:"bytes_reserved"`
	InodesTotal   uint64    `json:"inodes_total"`
	InodesFree    uint64    `json:"inodes_free"`
	InodesReserved uint64   `json:"inodes_reserved"`
	ObservedAt    time.Time `json:"observed_at"`
}

func (observation FilesystemPressure) Validate() error {
	if observation.BytesTotal == 0 || observation.InodesTotal == 0 || observation.BytesFree > observation.BytesTotal || observation.BytesReserved > observation.BytesFree || observation.InodesFree > observation.InodesTotal || observation.InodesReserved > observation.InodesFree || observation.ObservedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type WatermarkPolicy struct {
	WarnFreeBasisPoints      uint16          `json:"warn_free_basis_points"`
	RestrictFreeBasisPoints  uint16          `json:"restrict_free_basis_points"`
	EmergencyFreeBasisPoints uint16          `json:"emergency_free_basis_points"`
	AuditReserve             CapacityReserve `json:"audit_reserve"`
	RecoveryReserve          CapacityReserve `json:"recovery_reserve"`
	RollbackReserve          CapacityReserve `json:"rollback_reserve"`
}

type RecordClass string

const (
	ClassTerminalReceipt    RecordClass = "terminal_operation_receipt"
	ClassAuditCheckpoint    RecordClass = "audit_checkpoint_intent"
	ClassSecurityCheckpoint RecordClass = "security_checkpoint_intent"
	ClassOrdinaryEvent      RecordClass = "ordinary_event"
)

func (class RecordClass) valid() bool {
	switch class {
	case ClassTerminalReceipt, ClassAuditCheckpoint, ClassSecurityCheckpoint, ClassOrdinaryEvent:
		return true
	default:
		return false
	}
}

func (class RecordClass) Essential() bool { return class != ClassOrdinaryEvent && class.valid() }

type Priority uint8

const (
	PriorityDisposable Priority = 10
	PriorityEssential  Priority = 100
	PriorityCritical   Priority = 200
)

func priorityFor(class RecordClass) Priority {
	switch class {
	case ClassAuditCheckpoint, ClassSecurityCheckpoint:
		return PriorityCritical
	case ClassTerminalReceipt:
		return PriorityEssential
	case ClassOrdinaryEvent:
		return PriorityDisposable
	default:
		return 0
	}
}

type ClassLimit struct {
	MaximumPayloadBytes uint64 `json:"maximum_payload_bytes"`
	MaximumRecords      uint64 `json:"maximum_records"`
}

type ClassLimits struct {
	TerminalReceipt    ClassLimit `json:"terminal_operation_receipt"`
	AuditCheckpoint    ClassLimit `json:"audit_checkpoint_intent"`
	SecurityCheckpoint ClassLimit `json:"security_checkpoint_intent"`
	OrdinaryEvent      ClassLimit `json:"ordinary_event"`
}

func (limits ClassLimits) For(class RecordClass) ClassLimit {
	switch class {
	case ClassTerminalReceipt:
		return limits.TerminalReceipt
	case ClassAuditCheckpoint:
		return limits.AuditCheckpoint
	case ClassSecurityCheckpoint:
		return limits.SecurityCheckpoint
	case ClassOrdinaryEvent:
		return limits.OrdinaryEvent
	default:
		return ClassLimit{}
	}
}

type Policy struct {
	Watermarks            WatermarkPolicy `json:"watermarks"`
	Classes               ClassLimits     `json:"classes"`
	MaximumPayloadBytes   uint64          `json:"maximum_payload_bytes"`
	MaximumRecords        uint64          `json:"maximum_records"`
	MaximumRecordBytes    uint64          `json:"maximum_record_bytes"`
	EssentialReserveBytes uint64          `json:"essential_reserve_bytes"`
	EssentialReserveCount uint64          `json:"essential_reserve_count"`
	MinimumEssentialBytes uint64          `json:"minimum_essential_bytes"`
	DefaultLease          time.Duration   `json:"default_lease"`
	MaximumLease          time.Duration   `json:"maximum_lease"`
}

func DefaultPolicy() Policy {
	return Policy{
		Watermarks: WatermarkPolicy{
			WarnFreeBasisPoints: 2000, RestrictFreeBasisPoints: 1000, EmergencyFreeBasisPoints: 500,
			AuditReserve: CapacityReserve{Bytes: 128 << 20, Inodes: 2048},
			RecoveryReserve: CapacityReserve{Bytes: 512 << 20, Inodes: 8192},
			RollbackReserve: CapacityReserve{Bytes: 512 << 20, Inodes: 8192},
		},
		Classes: ClassLimits{
			TerminalReceipt: ClassLimit{MaximumPayloadBytes: 16 << 20, MaximumRecords: 2048},
			AuditCheckpoint: ClassLimit{MaximumPayloadBytes: 16 << 20, MaximumRecords: 2048},
			SecurityCheckpoint: ClassLimit{MaximumPayloadBytes: 16 << 20, MaximumRecords: 2048},
			OrdinaryEvent: ClassLimit{MaximumPayloadBytes: 48 << 20, MaximumRecords: 4096},
		},
		MaximumPayloadBytes: 64 << 20, MaximumRecords: 8192, MaximumRecordBytes: 1 << 20,
		EssentialReserveBytes: 16 << 20, EssentialReserveCount: 1024, MinimumEssentialBytes: 1 << 20,
		DefaultLease: time.Minute, MaximumLease: DefaultMaximumLease,
	}
}

type ClassUsage struct {
	PayloadBytes uint64 `json:"payload_bytes"`
	Records      uint64 `json:"records"`
}

type Usage struct {
	TerminalReceipt    ClassUsage `json:"terminal_operation_receipt"`
	AuditCheckpoint    ClassUsage `json:"audit_checkpoint_intent"`
	SecurityCheckpoint ClassUsage `json:"security_checkpoint_intent"`
	OrdinaryEvent      ClassUsage `json:"ordinary_event"`
	TotalPayloadBytes  uint64     `json:"total_payload_bytes"`
	TotalRecords       uint64     `json:"total_records"`
	EvictablePayloadBytes uint64  `json:"evictable_payload_bytes"`
	EvictableRecords   uint64     `json:"evictable_records"`
}

func (usage Usage) For(class RecordClass) ClassUsage {
	switch class {
	case ClassTerminalReceipt:
		return usage.TerminalReceipt
	case ClassAuditCheckpoint:
		return usage.AuditCheckpoint
	case ClassSecurityCheckpoint:
		return usage.SecurityCheckpoint
	case ClassOrdinaryEvent:
		return usage.OrdinaryEvent
	default:
		return ClassUsage{}
	}
}

type AdmissionState struct {
	Watermark                    Watermark `json:"watermark"`
	ReasonCode                   string    `json:"reason_code"`
	EssentialReserveExhausted    bool      `json:"essential_reserve_exhausted"`
	AllowCentralMutations        bool      `json:"allow_central_mutations"`
	AllowOrdinaryEvents          bool      `json:"allow_ordinary_events"`
	AllowEssentialSpool          bool      `json:"allow_essential_spool"`
	AllowLocalRecovery           bool      `json:"allow_local_recovery"`
	AllowLocalAudit              bool      `json:"allow_local_audit"`
	EffectiveFreeBytes           uint64    `json:"effective_free_bytes"`
	EffectiveFreeInodes          uint64    `json:"effective_free_inodes"`
}

type RecordState string

const (
	StateQueued RecordState = "queued"
	StateLeased RecordState = "leased"
)

type RecordID string

func (id RecordID) valid() bool {
	if len(id) != 51 || len(id) < 4 || id[:3] != "ds_" {
		return false
	}
	for _, value := range id[3:] {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return false
		}
	}
	return true
}

type Record struct {
	ID          RecordID   `json:"id"`
	Sequence    uint64     `json:"sequence"`
	Class       RecordClass `json:"class"`
	Priority    Priority   `json:"priority"`
	Disposable  bool       `json:"disposable"`
	PayloadSize uint64     `json:"payload_size"`
	SHA256      string     `json:"sha256"`
	CreatedAt   time.Time  `json:"created_at"`
	AvailableAt time.Time  `json:"available_at"`
	State       RecordState `json:"state"`
	Attempts    uint32     `json:"attempts"`
	Fence       uint64     `json:"fence"`
	LeaseOwner  string     `json:"lease_owner,omitempty"`
	LeaseUntil  time.Time  `json:"lease_until,omitempty"`
	RetryReason string     `json:"retry_reason,omitempty"`
}

type LeasedRecord struct {
	Record  Record `json:"record"`
	Payload []byte `json:"payload"`
}

type AppendRequest struct {
	Class       RecordClass
	Payload     []byte
	Disposable  bool
	AvailableAt time.Time
}

type LeaseRequest struct {
	Owner    string
	Limit    uint16
	Duration time.Duration
}

type AckRequest struct {
	ID    RecordID
	Fence uint64
}

type RetryRequest struct {
	ID          RecordID
	Fence       uint64
	AvailableAt time.Time
	ReasonCode  string
}

type PressureSource interface {
	FilesystemPressure(context.Context) (FilesystemPressure, error)
}

type Spool interface {
	PressureSource
	Admission(context.Context) (AdmissionState, error)
	Append(context.Context, AppendRequest) (Record, error)
	Lease(context.Context, LeaseRequest) ([]LeasedRecord, error)
	Ack(context.Context, AckRequest) error
	Retry(context.Context, RetryRequest) error
	Usage() Usage
	Close() error
}
