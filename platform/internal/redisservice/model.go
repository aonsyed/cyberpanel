package redisservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	MaxInstances       = 100
	MaxConsumers       = 128
	MaxACLUsers        = 32
	MaxDatabases       = 64
	MaxPlanSteps       = 32
	MaxImpacts         = 256
	MaxConfigBytes     = 128 << 10
	MaxRepositoryBytes = 512 << 10
	MaxGeneration      = uint64(1<<63 - 1)
	MaxArtifactBytes   = int64(64 << 30)
)

var (
	ErrInvalid             = errors.New("invalid managed Redis input")
	ErrNotFound            = errors.New("managed Redis record not found")
	ErrConflict            = errors.New("managed Redis compare-and-swap conflict")
	ErrStale               = errors.New("stale managed Redis generation")
	ErrUnsupported         = errors.New("unsupported managed Redis operation")
	ErrUnauthorized        = errors.New("managed Redis operation is not authorized")
	ErrMaintenanceRequired = errors.New("managed Redis maintenance window required")
	ErrConsumersPresent    = errors.New("managed Redis instance has consumers")
	ErrCapacity            = errors.New("managed Redis capacity validation failed")
	ErrAmbiguous           = errors.New("managed Redis runtime state is ambiguous")

	safeIDPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,127}$`)
	instanceIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	aclNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	semanticVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$`)
)

type InstanceID string

type Scope string

const (
	ScopeTenant Scope = "tenant"
	ScopeNode   Scope = "node"
)

type Purpose string

const (
	PurposeCache       Purpose = "cache"
	PurposeSession     Purpose = "session"
	PurposeQueue       Purpose = "queue"
	PurposeRateLimit   Purpose = "rate_limit"
	PurposeObjectCache Purpose = "object_cache"
	PurposeInternal    Purpose = "internal"
)

type SupportTuple struct {
	OSFamily           string `json:"os_family"`
	OSVersion          string `json:"os_version"`
	Architecture       string `json:"architecture"`
	RedisVersion       string `json:"redis_version"`
	PackageChannel     string `json:"package_channel"`
	TLSQualified       bool   `json:"tls_qualified"`
	QualificationDigest string `json:"qualification_digest"`
}

type ListenerMode string

const (
	ListenerUnix     ListenerMode = "unix_socket"
	ListenerLoopback ListenerMode = "loopback"
)

type ListenerPolicy struct {
	Mode            ListenerMode `json:"mode"`
	LoopbackAddress string       `json:"loopback_address,omitempty"`
	Port            uint16       `json:"port,omitempty"`
	SocketMode      uint32       `json:"socket_mode,omitempty"`
	TLS             bool         `json:"tls"`
	TLSServerName   string       `json:"tls_server_name,omitempty"`
	CertificateRef  string       `json:"certificate_ref,omitempty"`
	ClientCARef     string       `json:"client_ca_ref,omitempty"`
}

type SecretRef struct {
	ID      string  `json:"id"`
	Version uint64  `json:"version"`
	Purpose Purpose `json:"purpose"`
	Digest  string  `json:"digest"`
}

type ACLUser struct {
	Name      string    `json:"name"`
	Purpose   Purpose   `json:"purpose"`
	SecretRef SecretRef `json:"secret_ref"`
	Enabled   bool      `json:"enabled"`
}

type Consumer struct {
	ID              string    `json:"id"`
	Kind            string    `json:"kind"`
	Purpose         Purpose   `json:"purpose"`
	ACLUser         string    `json:"acl_user"`
	Database        uint8     `json:"database"`
	Active          bool      `json:"active"`
	Generation      uint64    `json:"generation"`
	EvidenceDigest  string    `json:"evidence_digest"`
}

type ConsumerSnapshot struct {
	InstanceID      InstanceID `json:"instance_id"`
	Generation      uint64     `json:"generation"`
	Complete        bool       `json:"complete"`
	Consumers       []Consumer `json:"consumers"`
	EvidenceDigest  string     `json:"evidence_digest"`
	ObservedAt      time.Time  `json:"observed_at"`
}

type EvictionPolicy string

const (
	EvictionNoEviction   EvictionPolicy = "noeviction"
	EvictionAllKeysLRU   EvictionPolicy = "allkeys-lru"
	EvictionAllKeysLFU   EvictionPolicy = "allkeys-lfu"
	EvictionVolatileLRU  EvictionPolicy = "volatile-lru"
	EvictionVolatileLFU  EvictionPolicy = "volatile-lfu"
	EvictionVolatileTTL  EvictionPolicy = "volatile-ttl"
)

type AOFMode string

const (
	AOFDisabled AOFMode = "disabled"
	AOFEverySec AOFMode = "everysec"
	AOFAlways   AOFMode = "always"
)

type RDBPolicy string

const (
	RDBDisabled RDBPolicy = "disabled"
	RDBBalanced RDBPolicy = "balanced"
	RDBDurable  RDBPolicy = "durable"
)

type PersistencePolicy struct {
	RDB RDBPolicy `json:"rdb"`
	AOF AOFMode   `json:"aof"`
}

type ResourceProfileID string

const (
	ResourceSmall  ResourceProfileID = "small"
	ResourceMedium ResourceProfileID = "medium"
	ResourceLarge  ResourceProfileID = "large"
)

type ResourceProfile struct {
	ID                ResourceProfileID `json:"id"`
	MemoryLimitBytes  uint64            `json:"memory_limit_bytes"`
	CPUQuotaMilli     uint32            `json:"cpu_quota_milli"`
	FileLimit         uint32            `json:"file_limit"`
	IOWeight          uint16            `json:"io_weight"`
}

type BackupFrequency string

const (
	BackupDisabled BackupFrequency = "disabled"
	BackupHourly   BackupFrequency = "hourly"
	BackupDaily    BackupFrequency = "daily"
)

type BackupPolicy struct {
	Frequency       BackupFrequency `json:"frequency"`
	RetentionCount uint16          `json:"retention_count"`
	IncludeAOF     bool            `json:"include_aof"`
}

type LifecycleState string

const (
	LifecycleAbsent    LifecycleState = "absent"
	LifecycleInstalled LifecycleState = "installed"
	LifecycleRunning   LifecycleState = "running"
	LifecycleStopped   LifecycleState = "stopped"
	LifecycleRemoved   LifecycleState = "removed"
)

type HealthState string

const (
	HealthHealthy       HealthState = "healthy"
	HealthDegraded      HealthState = "degraded"
	HealthFailed        HealthState = "failed"
	HealthUnsupported   HealthState = "unsupported"
	HealthIndeterminate HealthState = "indeterminate"
)

type DriftState string

const (
	DriftNone          DriftState = "none"
	DriftPresent       DriftState = "present"
	DriftIndeterminate DriftState = "indeterminate"
)

type InstanceSpec struct {
	ID                InstanceID        `json:"id"`
	NodeID            string            `json:"node_id"`
	TenantID          string            `json:"tenant_id,omitempty"`
	Scope             Scope             `json:"scope"`
	Support           SupportTuple      `json:"support"`
	Purpose           Purpose           `json:"purpose"`
	Listener          ListenerPolicy    `json:"listener"`
	ACLUsers          []ACLUser         `json:"acl_users"`
	MaxMemoryBytes    uint64            `json:"maxmemory_bytes"`
	Eviction          EvictionPolicy    `json:"eviction"`
	Persistence       PersistencePolicy `json:"persistence"`
	Databases         uint8             `json:"databases"`
	ResourceProfile   ResourceProfile   `json:"resource_profile"`
	Backup            BackupPolicy      `json:"backup"`
	Generation        uint64            `json:"generation"`
	ConfigGeneration  uint64            `json:"config_generation"`
	DesiredLifecycle  LifecycleState    `json:"desired_lifecycle"`
	Digest            string            `json:"digest"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

type InstanceObservation struct {
	InstanceID             InstanceID    `json:"instance_id"`
	NodeID                 string        `json:"node_id"`
	Generation             uint64        `json:"generation"`
	ConfigGeneration       uint64        `json:"config_generation"`
	Lifecycle              LifecycleState `json:"lifecycle"`
	Enabled                bool          `json:"enabled"`
	Health                 HealthState   `json:"health"`
	Drift                  DriftState    `json:"drift"`
	ActualVersion          string        `json:"actual_version"`
	ActualConfigDigest     string        `json:"actual_config_digest"`
	ProcessBootID          string        `json:"process_boot_id,omitempty"`
	ProcessID              int64         `json:"process_id,omitempty"`
	ProcessStartTicks      uint64        `json:"process_start_ticks,omitempty"`
	DatasetBytes           uint64        `json:"dataset_bytes"`
	ConnectedClients       uint32        `json:"connected_clients"`
	LastSuccessfulSaveAt   time.Time     `json:"last_successful_save_at,omitempty"`
	EvidenceDigest         string        `json:"evidence_digest"`
	ObservedAt             time.Time     `json:"observed_at"`
}

type PlanAction string

const (
	ActionApply   PlanAction = "apply"
	ActionRemove  PlanAction = "remove"
	ActionBackup  PlanAction = "backup"
	ActionRestore PlanAction = "restore"
)

type StepKind string

const (
	StepQualify       StepKind = "qualify"
	StepInstall       StepKind = "install_package_profile"
	StepRender        StepKind = "render_generation"
	StepStage         StepKind = "stage_generation"
	StepValidate      StepKind = "validate_generation"
	StepSwitchConfig  StepKind = "switch_generation"
	StepActivate      StepKind = "activate"
	StepEnable        StepKind = "enable"
	StepDisable       StepKind = "disable"
	StepReload        StepKind = "reload"
	StepRestart       StepKind = "restart"
	StepProbe         StepKind = "probe"
	StepBackupStream  StepKind = "backup_stream"
	StepRestoreStage  StepKind = "restore_stage"
	StepRestoreVerify StepKind = "restore_verify"
	StepRestoreSwitch StepKind = "restore_switch"
	StepStop          StepKind = "stop"
	StepRemovePackage StepKind = "remove_package_profile"
)

type PlanStep struct {
	Index        int      `json:"index"`
	Kind         StepKind `json:"kind"`
	Irreversible bool     `json:"irreversible"`
	Recovery     string   `json:"recovery,omitempty"`
}

type Impact struct {
	ConsumerID  string `json:"consumer_id,omitempty"`
	Kind        string `json:"kind"`
	Availability string `json:"availability"`
	Reason      string `json:"reason"`
}

type RemapPlan struct {
	ID                    string     `json:"id"`
	SourceInstanceID      InstanceID `json:"source_instance_id"`
	ReplacementInstanceID InstanceID `json:"replacement_instance_id"`
	ConsumerIDs           []string   `json:"consumer_ids"`
	Generation            uint64     `json:"generation"`
	Complete              bool       `json:"complete"`
	Digest                string     `json:"digest"`
}

type RecoveryPlan struct {
	Eligible             bool   `json:"eligible"`
	PriorConfigGeneration uint64 `json:"prior_config_generation"`
	PriorConfigDigest    string `json:"prior_config_digest,omitempty"`
	RecoveryArtifactRef  string `json:"recovery_artifact_ref,omitempty"`
	Reason               string `json:"reason"`
}

type ArtifactKind string

const (
	ArtifactRDB ArtifactKind = "rdb"
	ArtifactAOF ArtifactKind = "aof"
)

type ArtifactDescriptor struct {
	ID               string       `json:"id"`
	GroupID          string       `json:"group_id"`
	InstanceID       InstanceID   `json:"instance_id"`
	Kind             ArtifactKind `json:"kind"`
	RedisVersion     string       `json:"redis_version"`
	ConfigGeneration uint64       `json:"config_generation"`
	SizeBytes        int64        `json:"size_bytes"`
	SHA256           string       `json:"sha256"`
	CreatedAt        time.Time    `json:"created_at"`
}

type LifecyclePlan struct {
	ID                         string            `json:"id"`
	InstanceID                 InstanceID        `json:"instance_id"`
	NodeID                     string            `json:"node_id"`
	Action                     PlanAction        `json:"action"`
	Generation                 uint64            `json:"generation"`
	ExpectedSpecGeneration     uint64            `json:"expected_spec_generation"`
	ExpectedObservedGeneration uint64            `json:"expected_observed_generation"`
	ExpectedConfigGeneration   uint64            `json:"expected_config_generation"`
	TargetSpecDigest           string            `json:"target_spec_digest,omitempty"`
	ConsumerSnapshotGeneration uint64            `json:"consumer_snapshot_generation"`
	ConsumerSnapshotDigest     string            `json:"consumer_snapshot_digest"`
	Artifact                   *ArtifactDescriptor `json:"artifact,omitempty"`
	Remap                      *RemapPlan        `json:"remap,omitempty"`
	Recovery                   RecoveryPlan      `json:"recovery"`
	Steps                      []PlanStep        `json:"steps"`
	Impacts                    []Impact          `json:"impacts"`
	RequiresMaintenance        bool              `json:"requires_maintenance"`
	RequiresStepUp             bool              `json:"requires_step_up"`
	IrreversibleFrontier       int               `json:"irreversible_frontier"`
	Digest                     string            `json:"digest"`
	CreatedAt                  time.Time         `json:"created_at"`
	ExpiresAt                  time.Time         `json:"expires_at"`
}

type StepReceipt struct {
	Index             int         `json:"index"`
	Kind              StepKind    `json:"kind"`
	Outcome           string      `json:"outcome"`
	BeforeDigest      string      `json:"before_digest,omitempty"`
	AfterDigest       string      `json:"after_digest,omitempty"`
	CommandDigest     string      `json:"command_digest,omitempty"`
	OutputDigest      string      `json:"output_digest,omitempty"`
	ArtifactID        string      `json:"artifact_id,omitempty"`
	ObservedVersion   string      `json:"observed_version,omitempty"`
	ConfigDigest      string      `json:"config_digest,omitempty"`
	Compensation      string      `json:"compensation,omitempty"`
	EvidenceDigest    string      `json:"evidence_digest"`
}

type LifecycleReceipt struct {
	ID             string        `json:"id"`
	OperationID    string        `json:"operation_id"`
	PlanID         string        `json:"plan_id"`
	PlanDigest     string        `json:"plan_digest"`
	Outcome        string        `json:"outcome"`
	Steps          []StepReceipt `json:"steps"`
	EvidenceDigest string        `json:"evidence_digest"`
	StartedAt      time.Time     `json:"started_at"`
	CompletedAt    time.Time     `json:"completed_at"`
}

type AuthorizationEvidence struct {
	ActorID             string     `json:"actor_id"`
	DecisionID          string     `json:"decision_id"`
	PlanID              string     `json:"plan_id"`
	PlanDigest          string     `json:"plan_digest"`
	Action              PlanAction `json:"action"`
	MFAAt               time.Time  `json:"mfa_at"`
	PhishingResistantAt time.Time  `json:"phishing_resistant_at"`
	IssuedAt            time.Time  `json:"issued_at"`
	ExpiresAt           time.Time  `json:"expires_at"`
	Digest              string     `json:"digest"`
}

type MaintenanceEvidence struct {
	WindowID  string    `json:"window_id"`
	PlanID    string    `json:"plan_id"`
	PlanDigest string   `json:"plan_digest"`
	NodeID    string    `json:"node_id"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	ApprovedBy string   `json:"approved_by"`
	Digest    string    `json:"digest"`
}

type AuditEvent struct {
	ID             string    `json:"id"`
	OperationID    string    `json:"operation_id"`
	ActorID        string    `json:"actor_id"`
	Kind           string    `json:"kind"`
	Resource       string    `json:"resource"`
	RequestDigest  string    `json:"request_digest"`
	EvidenceDigest string    `json:"evidence_digest"`
	OccurredAt     time.Time `json:"occurred_at"`
}

func validID(value string) bool { return safeIDPattern.MatchString(value) }

func validGeneration(value uint64) bool { return value > 0 && value <= MaxGeneration }

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func digestValue(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: encode evidence: %v", ErrInvalid, err)
	}
	if len(encoded) == 0 || len(encoded) > MaxRepositoryBytes {
		return "", fmt.Errorf("%w: evidence exceeds %d bytes", ErrInvalid, MaxRepositoryBytes)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func parseVersion(version string) (int, int, int, error) {
	matches := semanticVersionRE.FindStringSubmatch(version)
	if matches == nil {
		return 0, 0, 0, fmt.Errorf("%w: Redis version must be exact major.minor.patch", ErrInvalid)
	}
	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])
	return major, minor, patch, nil
}

func validPurpose(purpose Purpose) bool {
	switch purpose {
	case PurposeCache, PurposeSession, PurposeQueue, PurposeRateLimit, PurposeObjectCache, PurposeInternal:
		return true
	default:
		return false
	}
}

func validServerName(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func exactResourceProfile(id ResourceProfileID) (ResourceProfile, bool) {
	switch id {
	case ResourceSmall:
		return ResourceProfile{ID: id, MemoryLimitBytes: 512 << 20, CPUQuotaMilli: 500, FileLimit: 4096, IOWeight: 100}, true
	case ResourceMedium:
		return ResourceProfile{ID: id, MemoryLimitBytes: 2 << 30, CPUQuotaMilli: 1500, FileLimit: 16384, IOWeight: 300}, true
	case ResourceLarge:
		return ResourceProfile{ID: id, MemoryLimitBytes: 8 << 30, CPUQuotaMilli: 4000, FileLimit: 65536, IOWeight: 700}, true
	default:
		return ResourceProfile{}, false
	}
}

func validateSupport(support SupportTuple) error {
	major, _, _, err := parseVersion(support.RedisVersion)
	if err != nil {
		return err
	}
	if major < 7 || major > 8 || support.PackageChannel != "stable" || (support.Architecture != "amd64" && support.Architecture != "arm64") || !validSHA256(support.QualificationDigest) {
		return fmt.Errorf("%w: unqualified Redis support tuple", ErrUnsupported)
	}
	validOS := (support.OSFamily == "ubuntu" && (support.OSVersion == "22.04" || support.OSVersion == "24.04")) || (support.OSFamily == "almalinux" && (support.OSVersion == "8" || support.OSVersion == "9"))
	if !validOS {
		return fmt.Errorf("%w: unsupported Redis operating system tuple", ErrUnsupported)
	}
	return nil
}

func validateListener(listener ListenerPolicy, support SupportTuple) error {
	switch listener.Mode {
	case ListenerUnix:
		if listener.LoopbackAddress != "" || listener.Port != 0 || listener.TLS || listener.TLSServerName != "" || listener.CertificateRef != "" || listener.ClientCARef != "" || (listener.SocketMode != 0o660 && listener.SocketMode != 0o600) {
			return fmt.Errorf("%w: invalid Unix-socket listener policy", ErrInvalid)
		}
	case ListenerLoopback:
		if listener.LoopbackAddress != "127.0.0.1" && listener.LoopbackAddress != "::1" {
			return fmt.Errorf("%w: Redis TCP listener must be loopback-only", ErrInvalid)
		}
		if listener.Port < 1024 || listener.SocketMode != 0 {
			return fmt.Errorf("%w: invalid loopback listener port", ErrInvalid)
		}
		if listener.TLS {
			if !support.TLSQualified || !validID(listener.CertificateRef) || !validID(listener.ClientCARef) || !validServerName(listener.TLSServerName) {
				return fmt.Errorf("%w: unqualified Redis TLS policy", ErrUnsupported)
			}
		} else if listener.TLSServerName != "" || listener.CertificateRef != "" || listener.ClientCARef != "" {
			return fmt.Errorf("%w: TLS references present while TLS is disabled", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: listener mode", ErrInvalid)
	}
	return nil
}

func validatePersistence(purpose Purpose, persistence PersistencePolicy, backup BackupPolicy) error {
	if persistence.RDB != RDBDisabled && persistence.RDB != RDBBalanced && persistence.RDB != RDBDurable {
		return fmt.Errorf("%w: RDB policy", ErrInvalid)
	}
	if persistence.AOF != AOFDisabled && persistence.AOF != AOFEverySec && persistence.AOF != AOFAlways {
		return fmt.Errorf("%w: AOF policy", ErrInvalid)
	}
	if (purpose == PurposeQueue || purpose == PurposeSession || purpose == PurposeInternal) && persistence.RDB == RDBDisabled && persistence.AOF == AOFDisabled {
		return fmt.Errorf("%w: durable purpose requires persistence", ErrInvalid)
	}
	switch backup.Frequency {
	case BackupDisabled:
		if backup.RetentionCount != 0 || backup.IncludeAOF {
			return fmt.Errorf("%w: disabled backup policy has options", ErrInvalid)
		}
	case BackupHourly, BackupDaily:
		if backup.RetentionCount == 0 || backup.RetentionCount > 90 || (persistence.RDB == RDBDisabled && (!backup.IncludeAOF || persistence.AOF == AOFDisabled)) {
			return fmt.Errorf("%w: backup policy lacks persistent source", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: backup frequency", ErrInvalid)
	}
	return nil
}

func ValidateInstanceSpec(spec InstanceSpec) error {
	if !instanceIDPattern.MatchString(string(spec.ID)) || !validID(spec.NodeID) || !validGeneration(spec.Generation) || !validGeneration(spec.ConfigGeneration) || spec.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: incomplete Redis instance identity", ErrInvalid)
	}
	if spec.Scope == ScopeTenant {
		if !validID(spec.TenantID) {
			return fmt.Errorf("%w: tenant scope requires tenant id", ErrInvalid)
		}
	} else if spec.Scope != ScopeNode || spec.TenantID != "" {
		return fmt.Errorf("%w: invalid Redis ownership scope", ErrInvalid)
	}
	if !validPurpose(spec.Purpose) || spec.Databases == 0 || spec.Databases > MaxDatabases || len(spec.ACLUsers) == 0 || len(spec.ACLUsers) > MaxACLUsers {
		return fmt.Errorf("%w: purpose, database, or ACL bounds", ErrInvalid)
	}
	if err := validateSupport(spec.Support); err != nil {
		return err
	}
	if err := validateListener(spec.Listener, spec.Support); err != nil {
		return err
	}
	profile, ok := exactResourceProfile(spec.ResourceProfile.ID)
	if !ok || profile != spec.ResourceProfile {
		return fmt.Errorf("%w: resource profile is not exact", ErrInvalid)
	}
	if spec.MaxMemoryBytes < 16<<20 || spec.MaxMemoryBytes > profile.MemoryLimitBytes-(64<<20) {
		return fmt.Errorf("%w: maxmemory must preserve runtime overhead", ErrCapacity)
	}
	switch spec.Eviction {
	case EvictionNoEviction, EvictionAllKeysLRU, EvictionAllKeysLFU, EvictionVolatileLRU, EvictionVolatileLFU, EvictionVolatileTTL:
	default:
		return fmt.Errorf("%w: eviction policy", ErrInvalid)
	}
	if (spec.Purpose == PurposeCache || spec.Purpose == PurposeObjectCache || spec.Purpose == PurposeRateLimit) && spec.Eviction == EvictionNoEviction {
		return fmt.Errorf("%w: cache purpose requires bounded eviction", ErrCapacity)
	}
	if err := validatePersistence(spec.Purpose, spec.Persistence, spec.Backup); err != nil {
		return err
	}
	seen := make(map[string]bool, len(spec.ACLUsers))
	for _, user := range spec.ACLUsers {
		if !aclNamePattern.MatchString(user.Name) || user.Name == "default" || seen[user.Name] || !user.Enabled || !validPurpose(user.Purpose) || user.Purpose != spec.Purpose {
			return fmt.Errorf("%w: invalid or cross-purpose ACL user", ErrInvalid)
		}
		seen[user.Name] = true
		if !validID(user.SecretRef.ID) || !validGeneration(user.SecretRef.Version) || user.SecretRef.Purpose != user.Purpose || !validSHA256(user.SecretRef.Digest) {
			return fmt.Errorf("%w: ACL secret reference is not purpose-bound", ErrInvalid)
		}
	}
	if spec.DesiredLifecycle != LifecycleInstalled && spec.DesiredLifecycle != LifecycleRunning && spec.DesiredLifecycle != LifecycleStopped && spec.DesiredLifecycle != LifecycleRemoved {
		return fmt.Errorf("%w: desired lifecycle", ErrInvalid)
	}
	return nil
}

func SealInstanceSpec(spec InstanceSpec) (InstanceSpec, error) {
	if err := ValidateInstanceSpec(spec); err != nil {
		return InstanceSpec{}, err
	}
	spec.ACLUsers = append([]ACLUser(nil), spec.ACLUsers...)
	sort.Slice(spec.ACLUsers, func(i, j int) bool { return spec.ACLUsers[i].Name < spec.ACLUsers[j].Name })
	spec.Digest = ""
	digest, err := digestValue(spec)
	if err != nil {
		return InstanceSpec{}, err
	}
	spec.Digest = digest
	return spec, nil
}

func SealConsumerSnapshot(snapshot ConsumerSnapshot) (ConsumerSnapshot, error) {
	if !instanceIDPattern.MatchString(string(snapshot.InstanceID)) || !validGeneration(snapshot.Generation) || !snapshot.Complete || snapshot.ObservedAt.IsZero() || len(snapshot.Consumers) > MaxConsumers {
		return ConsumerSnapshot{}, fmt.Errorf("%w: incomplete consumer snapshot", ErrInvalid)
	}
	seen := make(map[string]bool, len(snapshot.Consumers))
	for _, consumer := range snapshot.Consumers {
		if !validID(consumer.ID) || !validID(consumer.Kind) || !validPurpose(consumer.Purpose) || !aclNamePattern.MatchString(consumer.ACLUser) || consumer.Database >= MaxDatabases || !validGeneration(consumer.Generation) || !validSHA256(consumer.EvidenceDigest) || seen[consumer.ID] {
			return ConsumerSnapshot{}, fmt.Errorf("%w: invalid consumer evidence", ErrInvalid)
		}
		seen[consumer.ID] = true
	}
	snapshot.Consumers = append([]Consumer(nil), snapshot.Consumers...)
	sort.Slice(snapshot.Consumers, func(i, j int) bool { return snapshot.Consumers[i].ID < snapshot.Consumers[j].ID })
	snapshot.EvidenceDigest = ""
	digest, err := digestValue(snapshot)
	if err != nil {
		return ConsumerSnapshot{}, err
	}
	snapshot.EvidenceDigest = digest
	return snapshot, nil
}

func SealObservation(observation InstanceObservation) (InstanceObservation, error) {
	if !instanceIDPattern.MatchString(string(observation.InstanceID)) || !validID(observation.NodeID) || !validGeneration(observation.Generation) || observation.ConfigGeneration > MaxGeneration || observation.ObservedAt.IsZero() {
		return InstanceObservation{}, fmt.Errorf("%w: incomplete Redis observation", ErrInvalid)
	}
	if observation.Lifecycle != LifecycleAbsent && observation.Lifecycle != LifecycleInstalled && observation.Lifecycle != LifecycleRunning && observation.Lifecycle != LifecycleStopped && observation.Lifecycle != LifecycleRemoved {
		return InstanceObservation{}, fmt.Errorf("%w: observed lifecycle", ErrInvalid)
	}
	if observation.Health != HealthHealthy && observation.Health != HealthDegraded && observation.Health != HealthFailed && observation.Health != HealthUnsupported && observation.Health != HealthIndeterminate {
		return InstanceObservation{}, fmt.Errorf("%w: observed health", ErrInvalid)
	}
	if observation.Drift != DriftNone && observation.Drift != DriftPresent && observation.Drift != DriftIndeterminate {
		return InstanceObservation{}, fmt.Errorf("%w: observed drift", ErrInvalid)
	}
	if observation.ActualVersion != "" {
		if _, _, _, err := parseVersion(observation.ActualVersion); err != nil {
			return InstanceObservation{}, err
		}
	}
	if observation.ActualConfigDigest != "" && !validSHA256(observation.ActualConfigDigest) {
		return InstanceObservation{}, fmt.Errorf("%w: observed config digest", ErrInvalid)
	}
	identityFields := 0
	if observation.ProcessBootID != "" {
		identityFields++
	}
	if observation.ProcessID != 0 {
		identityFields++
	}
	if observation.ProcessStartTicks != 0 {
		identityFields++
	}
	if identityFields != 0 && identityFields != 3 {
		return InstanceObservation{}, fmt.Errorf("%w: partial process identity", ErrInvalid)
	}
	observation.EvidenceDigest = ""
	digest, err := digestValue(observation)
	if err != nil {
		return InstanceObservation{}, err
	}
	observation.EvidenceDigest = digest
	return observation, nil
}

func SealRemapPlan(remap RemapPlan) (RemapPlan, error) {
	if !validID(remap.ID) || !instanceIDPattern.MatchString(string(remap.SourceInstanceID)) || !instanceIDPattern.MatchString(string(remap.ReplacementInstanceID)) || remap.SourceInstanceID == remap.ReplacementInstanceID || !validGeneration(remap.Generation) || !remap.Complete || len(remap.ConsumerIDs) > MaxConsumers {
		return RemapPlan{}, fmt.Errorf("%w: incomplete remap plan", ErrInvalid)
	}
	remap.ConsumerIDs = append([]string(nil), remap.ConsumerIDs...)
	sort.Strings(remap.ConsumerIDs)
	for index, id := range remap.ConsumerIDs {
		if !validID(id) || (index > 0 && remap.ConsumerIDs[index-1] == id) {
			return RemapPlan{}, fmt.Errorf("%w: remap consumer set", ErrInvalid)
		}
	}
	remap.Digest = ""
	digest, err := digestValue(remap)
	if err != nil {
		return RemapPlan{}, err
	}
	remap.Digest = digest
	return remap, nil
}

func validateArtifact(artifact ArtifactDescriptor) error {
	if !validID(artifact.ID) || !validID(artifact.GroupID) || !instanceIDPattern.MatchString(string(artifact.InstanceID)) || (artifact.Kind != ArtifactRDB && artifact.Kind != ArtifactAOF) || !validGeneration(artifact.ConfigGeneration) || artifact.SizeBytes <= 0 || artifact.SizeBytes > MaxArtifactBytes || !validSHA256(artifact.SHA256) || artifact.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invalid artifact descriptor", ErrInvalid)
	}
	_, _, _, err := parseVersion(artifact.RedisVersion)
	return err
}

func SealLifecyclePlan(plan LifecyclePlan) (LifecyclePlan, error) {
	if !validID(plan.ID) || !instanceIDPattern.MatchString(string(plan.InstanceID)) || !validID(plan.NodeID) || !validGeneration(plan.Generation) || !validGeneration(plan.ExpectedSpecGeneration) || !validGeneration(plan.ExpectedObservedGeneration) || plan.ExpectedConfigGeneration > MaxGeneration || len(plan.Steps) == 0 || len(plan.Steps) > MaxPlanSteps || len(plan.Impacts) > MaxImpacts || plan.CreatedAt.IsZero() || !plan.ExpiresAt.After(plan.CreatedAt) || plan.ExpiresAt.Sub(plan.CreatedAt) > 30*time.Minute {
		return LifecyclePlan{}, fmt.Errorf("%w: incomplete lifecycle plan", ErrInvalid)
	}
	if plan.Action != ActionApply && plan.Action != ActionRemove && plan.Action != ActionBackup && plan.Action != ActionRestore {
		return LifecyclePlan{}, fmt.Errorf("%w: lifecycle plan action", ErrInvalid)
	}
	if !validSHA256(plan.TargetSpecDigest) || plan.Recovery.Reason == "" || len(plan.Recovery.Reason) > 256 || plan.Recovery.PriorConfigGeneration > MaxGeneration || (plan.Recovery.PriorConfigDigest != "" && !validSHA256(plan.Recovery.PriorConfigDigest)) || (plan.Recovery.RecoveryArtifactRef != "" && !validID(plan.Recovery.RecoveryArtifactRef)) {
		return LifecyclePlan{}, fmt.Errorf("%w: lifecycle recovery or target binding", ErrInvalid)
	}
	if (plan.ConsumerSnapshotGeneration == 0) != (plan.ConsumerSnapshotDigest == "") || (plan.ConsumerSnapshotDigest != "" && !validSHA256(plan.ConsumerSnapshotDigest)) {
		return LifecyclePlan{}, fmt.Errorf("%w: consumer snapshot binding", ErrInvalid)
	}
	frontier := -1
	for index, step := range plan.Steps {
		if step.Index != index || step.Kind == "" || step.Recovery == "" || len(step.Recovery) > 256 {
			return LifecyclePlan{}, fmt.Errorf("%w: non-canonical lifecycle step", ErrInvalid)
		}
		if step.Irreversible && frontier < 0 {
			frontier = index
		}
	}
	impactConsumers := make(map[string]bool, len(plan.Impacts))
	for _, impact := range plan.Impacts {
		if !validID(impact.Kind) || len(impact.Availability) == 0 || len(impact.Availability) > 256 || len(impact.Reason) == 0 || len(impact.Reason) > 256 || (impact.ConsumerID != "" && (!validID(impact.ConsumerID) || impactConsumers[impact.ConsumerID])) {
			return LifecyclePlan{}, fmt.Errorf("%w: bounded plan impact", ErrInvalid)
		}
		if impact.ConsumerID != "" {
			impactConsumers[impact.ConsumerID] = true
		}
	}
	if frontier != plan.IrreversibleFrontier {
		return LifecyclePlan{}, fmt.Errorf("%w: irreversible frontier", ErrInvalid)
	}
	if plan.Artifact != nil {
		if err := validateArtifact(*plan.Artifact); err != nil {
			return LifecyclePlan{}, err
		}
	}
	if plan.Remap != nil {
		sealed, err := SealRemapPlan(*plan.Remap)
		if err != nil || sealed.Digest != plan.Remap.Digest {
			return LifecyclePlan{}, fmt.Errorf("%w: remap plan digest", ErrInvalid)
		}
	}
	if err := validatePlanShape(plan); err != nil {
		return LifecyclePlan{}, err
	}
	plan.Digest = ""
	digest, err := digestValue(plan)
	if err != nil {
		return LifecyclePlan{}, err
	}
	plan.Digest = digest
	return plan, nil
}

func SealStepReceipt(receipt StepReceipt) (StepReceipt, error) {
	if receipt.Index < 0 || receipt.Kind == "" || (receipt.Outcome != "confirmed" && receipt.Outcome != "failed" && receipt.Outcome != "compensated" && receipt.Outcome != "ambiguous") || (receipt.BeforeDigest != "" && !validSHA256(receipt.BeforeDigest)) || (receipt.AfterDigest != "" && !validSHA256(receipt.AfterDigest)) || (receipt.CommandDigest != "" && !validSHA256(receipt.CommandDigest)) || (receipt.OutputDigest != "" && !validSHA256(receipt.OutputDigest)) || (receipt.ConfigDigest != "" && !validSHA256(receipt.ConfigDigest)) || (receipt.ArtifactID != "" && !validID(receipt.ArtifactID)) || len(receipt.Compensation) > 256 {
		return StepReceipt{}, fmt.Errorf("%w: invalid step receipt", ErrInvalid)
	}
	if receipt.ObservedVersion != "" {
		if _, _, _, err := parseVersion(receipt.ObservedVersion); err != nil {
			return StepReceipt{}, err
		}
	}
	receipt.EvidenceDigest = ""
	digest, err := digestValue(receipt)
	if err != nil {
		return StepReceipt{}, err
	}
	receipt.EvidenceDigest = digest
	return receipt, nil
}

func SealLifecycleReceipt(receipt LifecycleReceipt) (LifecycleReceipt, error) {
	if !validID(receipt.ID) || !validID(receipt.OperationID) || !validID(receipt.PlanID) || !validSHA256(receipt.PlanDigest) || len(receipt.Steps) == 0 || len(receipt.Steps) > MaxPlanSteps || receipt.StartedAt.IsZero() || receipt.CompletedAt.Before(receipt.StartedAt) || (receipt.Outcome != "confirmed" && receipt.Outcome != "failed" && receipt.Outcome != "compensated" && receipt.Outcome != "ambiguous") {
		return LifecycleReceipt{}, fmt.Errorf("%w: invalid lifecycle receipt", ErrInvalid)
	}
	for index, step := range receipt.Steps {
		sealed, err := SealStepReceipt(step)
		if err != nil || step.Index != index || sealed.EvidenceDigest != step.EvidenceDigest {
			return LifecycleReceipt{}, fmt.Errorf("%w: step receipt digest", ErrInvalid)
		}
	}
	receipt.EvidenceDigest = ""
	digest, err := digestValue(receipt)
	if err != nil {
		return LifecycleReceipt{}, err
	}
	receipt.EvidenceDigest = digest
	return receipt, nil
}

func SealAuthorization(evidence AuthorizationEvidence) (AuthorizationEvidence, error) {
	if !validID(evidence.ActorID) || !validID(evidence.DecisionID) || !validID(evidence.PlanID) || !validSHA256(evidence.PlanDigest) || (evidence.Action != ActionApply && evidence.Action != ActionRemove && evidence.Action != ActionBackup && evidence.Action != ActionRestore) || evidence.IssuedAt.IsZero() || !evidence.ExpiresAt.After(evidence.IssuedAt) {
		return AuthorizationEvidence{}, fmt.Errorf("%w: incomplete authorization evidence", ErrInvalid)
	}
	evidence.Digest = ""
	digest, err := digestValue(evidence)
	if err != nil {
		return AuthorizationEvidence{}, err
	}
	evidence.Digest = digest
	return evidence, nil
}

func SealMaintenance(evidence MaintenanceEvidence) (MaintenanceEvidence, error) {
	if !validID(evidence.WindowID) || !validID(evidence.PlanID) || !validSHA256(evidence.PlanDigest) || !validID(evidence.NodeID) || !validID(evidence.ApprovedBy) || evidence.StartsAt.IsZero() || !evidence.EndsAt.After(evidence.StartsAt) {
		return MaintenanceEvidence{}, fmt.Errorf("%w: incomplete maintenance evidence", ErrInvalid)
	}
	evidence.Digest = ""
	digest, err := digestValue(evidence)
	if err != nil {
		return MaintenanceEvidence{}, err
	}
	evidence.Digest = digest
	return evidence, nil
}
