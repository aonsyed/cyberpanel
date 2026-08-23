// Package siteops is the privileged, closed site-runtime executor used by the
// unprivileged hosting reconciler. RPC callers identify only a registry-owned
// runtime and desired generation; Unix names, numeric identities, host paths,
// executables, service names, and process arguments never cross this boundary.
package siteops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

const (
	ProtocolVersion uint16 = 1
	MaximumFrameBytes      = 64 << 10
	DefaultSocketPath      = "/run/cyberpanel/panel-execd.sock"
	SitesRootPath          = "/var/lib/cyberpanel/sites"
	QuarantineRootPath     = "/var/lib/cyberpanel/quarantine"
	TombstoneRootPath      = "/var/lib/cyberpanel/tombstones"
	RegistryRootPath       = "/var/lib/cyberpanel/siteops"
	SystemdUnitRootPath    = "/etc/systemd/system"
	RuntimeRootPath        = "/run/cyberpanel/site-runtime"
	HealthRootPath         = "/var/lib/cyberpanel/site-health"
	PHPConfigRootPath      = "/var/lib/cyberpanel/php-config"
	HealthPathToken        = "activation"
	DefaultUIDMinimum      = uint32(200000)
	DefaultUIDMaximum      = uint32(599999)
	DefaultRetention       = 30 * 24 * time.Hour
)

var (
	ErrInvalidRequest    = errors.New("invalid siteops request")
	ErrInvalidResponse   = errors.New("invalid siteops response")
	ErrRegistryConflict  = errors.New("siteops registry conflict")
	ErrFenced            = errors.New("siteops request fenced by a newer generation")
	ErrIdentityExhausted = errors.New("siteops Unix identity range exhausted")
	ErrUnauthorizedPeer  = errors.New("unauthorized siteops peer")
	ErrOperationFailed   = errors.New("siteops operation failed")
	ErrCorruptRegistry   = errors.New("siteops registry is corrupt")
)

type Operation string

const (
	OperationEnsureIdentity    Operation = "ensure_identity"
	OperationEnsureDirectories Operation = "ensure_directories"
	OperationEnsureLSAPIPool   Operation = "ensure_lsapi_pool"
	OperationWriteHealth       Operation = "write_health_attestation"
	OperationSuspend           Operation = "suspend"
	OperationQuarantine        Operation = "quarantine"
	OperationPurge             Operation = "purge"
)

func (operation Operation) valid() bool {
	switch operation {
	case OperationEnsureIdentity, OperationEnsureDirectories, OperationEnsureLSAPIPool,
		OperationWriteHealth, OperationSuspend, OperationQuarantine, OperationPurge:
		return true
	default:
		return false
	}
}

type EngineEdition string

const (
	EditionOpenLiteSpeed        EngineEdition = "openlitespeed"
	EditionLiteSpeedEnterprise  EngineEdition = "litespeed_enterprise"
)

func (edition EngineEdition) valid() bool { return edition == EditionOpenLiteSpeed || edition == EditionLiteSpeedEnterprise }

// Request is the only request accepted by the root executor. RuntimeKey is
// recomputed from TenantID and SiteID, so even these opaque identifiers cannot
// redirect an operation to a different registry record.
type Request struct {
	Version             uint16                  `json:"version"`
	RequestID           string                  `json:"request_id"`
	Operation           Operation               `json:"operation"`
	EffectKey           provisioning.EffectKey  `json:"effect_key"`
	RuntimeKey          provisioning.RuntimeKey `json:"runtime_key"`
	TenantID            string                  `json:"tenant_id"`
	SiteID              string                  `json:"site_id"`
	ProjectionDigest    string                  `json:"projection_digest"`
	Generation          uint64                  `json:"generation"`
	Lifecycle           site.Lifecycle          `json:"lifecycle"`
	PHPProfile          site.PHPProfile         `json:"php_profile"`
	SiteProcessProfile  provisioning.SiteProcessResourceProfile `json:"site_process_profile,omitempty"`
	Withdraw            bool                    `json:"withdraw"`
	AttestationDigest   string                  `json:"attestation_digest,omitempty"`
	IssuedAt            time.Time               `json:"issued_at"`
	Deadline            time.Time               `json:"deadline"`
}

func requestFromSpec(operation Operation, requestID string, spec provisioning.RuntimeSpec, attestation string, now, deadline time.Time) Request {
	scope := spec.Identity().Scope()
	request := Request{
		Version: ProtocolVersion, RequestID: requestID, Operation: operation,
		EffectKey: spec.EffectKey(), RuntimeKey: spec.Identity().Key(), TenantID: scope.TenantID.String(), SiteID: scope.SiteID.String(),
		ProjectionDigest: spec.ProjectionDigest(), Generation: spec.Generation(), Lifecycle: spec.Lifecycle(), PHPProfile: spec.PHPProfile(), Withdraw: spec.Withdraw(),
		AttestationDigest: attestation, IssuedAt: now.UTC(), Deadline: deadline.UTC(),
	}
	if operation == OperationEnsureLSAPIPool { request.SiteProcessProfile = spec.SiteProcessProfile() }
	return request
}

func (request Request) Validate(now time.Time) error {
	if request.Version != ProtocolVersion || !request.Operation.valid() || !validToken(request.RequestID, 16, 128) || request.Generation == 0 || !validDigest(request.ProjectionDigest) {
		return ErrInvalidRequest
	}
	if !validEffectKey(request.EffectKey) || !validRuntimeKey(request.RuntimeKey) || request.RuntimeKey != deriveRuntimeKey(request.TenantID, request.SiteID) {
		return ErrInvalidRequest
	}
	if !validIdentifier(request.TenantID) || !validIdentifier(request.SiteID) || !validLifecycle(request.Lifecycle) || !site.ValidPHPProfile(request.PHPProfile) {
		return ErrInvalidRequest
	}
	withdraw := request.Lifecycle == site.LifecyclePurging || request.Lifecycle == site.LifecycleDeleted
	if request.Withdraw != withdraw || request.IssuedAt.After(now.Add(time.Minute)) || request.IssuedAt.Before(now.Add(-10*time.Minute)) || !request.Deadline.After(now) || request.Deadline.After(now.Add(2*time.Minute)) {
		return ErrInvalidRequest
	}
	if request.Operation == OperationWriteHealth {
		if !validDigest(request.AttestationDigest) { return ErrInvalidRequest }
	} else if request.AttestationDigest != "" {
		return ErrInvalidRequest
	}
	if request.Operation == OperationEnsureLSAPIPool {
		if request.SiteProcessProfile.Generation != request.Generation || request.SiteProcessProfile.Validate() != nil { return ErrInvalidRequest }
	} else if request.SiteProcessProfile != (provisioning.SiteProcessResourceProfile{}) {
		return ErrInvalidRequest
	}
	if request.Operation == OperationPurge && !request.Withdraw { return ErrInvalidRequest }
	return nil
}

func (request Request) Digest() string {
	canonical := request
	canonical.RequestID = ""
	canonical.IssuedAt = time.Time{}
	canonical.Deadline = time.Time{}
	encoded, _ := json.Marshal(canonical)
	return digest("cyberpanel:siteops:request:v1", encoded)
}

func (request Request) IdempotencyKey() string {
	return string(request.EffectKey) + ":" + string(request.Operation)
}

type Response struct {
	Version             uint16                  `json:"version"`
	RequestID           string                  `json:"request_id"`
	Operation           Operation               `json:"operation"`
	EffectKey           provisioning.EffectKey  `json:"effect_key"`
	RuntimeKey          provisioning.RuntimeKey `json:"runtime_key"`
	Generation          uint64                  `json:"generation"`
	Succeeded           bool                    `json:"succeeded"`
	EvidenceDigest      string                  `json:"evidence_digest,omitempty"`
	AttestationDigest   string                  `json:"attestation_digest,omitempty"`
	LifecycleOperation  provisioning.LifecycleOperation `json:"lifecycle_operation,omitempty"`
	LimitBindings       []provisioning.SiteProcessLimitBinding `json:"limit_bindings,omitempty"`
	ErrorCode           string                  `json:"error_code,omitempty"`
	CompletedAt         time.Time               `json:"completed_at"`
}

func (response Response) Validate(request Request, now time.Time) error {
	if response.Version != ProtocolVersion || response.RequestID != request.RequestID || response.Operation != request.Operation || response.EffectKey != request.EffectKey || response.RuntimeKey != request.RuntimeKey || response.Generation != request.Generation || response.CompletedAt.IsZero() || response.CompletedAt.After(now.Add(time.Minute)) {
		return ErrInvalidResponse
	}
	if response.Succeeded {
		if response.ErrorCode != "" || !validDigest(response.EvidenceDigest) { return ErrInvalidResponse }
	} else if response.ErrorCode == "" || response.EvidenceDigest != "" {
		return ErrInvalidResponse
	}
	if request.Operation == OperationWriteHealth && response.Succeeded {
		if response.AttestationDigest != request.AttestationDigest { return ErrInvalidResponse }
	} else if response.AttestationDigest != "" { return ErrInvalidResponse }
	if request.Operation == OperationEnsureLSAPIPool && response.Succeeded {
		if !validLimitBindings(response.LimitBindings, request.SiteProcessProfile) { return ErrInvalidResponse }
	} else if len(response.LimitBindings) != 0 { return ErrInvalidResponse }
	wantedLifecycle := lifecycleOperation(request.Operation)
	if response.Succeeded && wantedLifecycle != "" {
		if response.LifecycleOperation != wantedLifecycle { return ErrInvalidResponse }
	} else if response.LifecycleOperation != "" { return ErrInvalidResponse }
	return nil
}

func validLimitBindings(bindings []provisioning.SiteProcessLimitBinding, profile provisioning.SiteProcessResourceProfile) bool {
	if len(bindings) != 9 || profile.Validate() != nil { return false }
	requested := map[provisioning.SiteProcessLimitDimension]uint64{
		provisioning.SiteProcessCPUQuota: profile.CPUQuotaPerSecondUSec,
		provisioning.SiteProcessCPUWeight: profile.CPUWeight,
		provisioning.SiteProcessMemoryHigh: profile.MemoryHighBytes,
		provisioning.SiteProcessMemoryMax: profile.MemoryMaxBytes,
		provisioning.SiteProcessTasksMax: profile.TasksMax,
		provisioning.SiteProcessIOReadBPS: profile.IOReadBytesPerSecond,
		provisioning.SiteProcessIOWriteBPS: profile.IOWriteBytesPerSecond,
		provisioning.SiteProcessIOReadIOPS: profile.IOReadOperationsPerSec,
		provisioning.SiteProcessIOWriteIOPS: profile.IOWriteOperationsPerSec,
	}
	seen := make(map[provisioning.SiteProcessLimitDimension]struct{}, len(bindings))
	for _, binding := range bindings {
		wanted, exists := requested[binding.Dimension]
		if !exists || binding.Generation != profile.Generation || binding.Scope != "site_processes" || binding.Adapter != "systemd_cgroup_v2" || binding.RequestedValue != wanted || binding.ObservedAt.IsZero() || len(binding.Observation) == 0 || len(binding.Observation) > 128 { return false }
		if _, duplicate := seen[binding.Dimension]; duplicate { return false }; seen[binding.Dimension] = struct{}{}
		if binding.State != provisioning.ResourceLimitEnforced && binding.State != provisioning.ResourceLimitAccountedOnly && binding.State != provisioning.ResourceLimitUnsupported { return false }
		if binding.State == provisioning.ResourceLimitEnforced && (!binding.EffectiveKnown || binding.EffectiveUnlimited || binding.EffectiveValue != wanted) { return false }
		if binding.State == provisioning.ResourceLimitUnsupported && binding.EffectiveKnown { return false }
		isIO := binding.Dimension == provisioning.SiteProcessIOReadBPS || binding.Dimension == provisioning.SiteProcessIOWriteBPS || binding.Dimension == provisioning.SiteProcessIOReadIOPS || binding.Dimension == provisioning.SiteProcessIOWriteIOPS
		if isIO != (binding.Device != "") && binding.EffectiveKnown { return false }
	}
	return len(seen) == len(requested)
}

func lifecycleOperation(operation Operation) provisioning.LifecycleOperation {
	switch operation {
	case OperationSuspend: return provisioning.LifecycleSuspend
	case OperationQuarantine: return provisioning.LifecycleQuarantine
	case OperationPurge: return provisioning.LifecyclePurge
	default: return ""
	}
}

type BindingState string

const (
	BindingAllocated   BindingState = "allocated"
	BindingActive      BindingState = "active"
	BindingSuspended   BindingState = "suspended"
	BindingQuarantined BindingState = "quarantined"
	BindingTombstoned  BindingState = "tombstoned"
	BindingDeleted     BindingState = "deleted"
)

type RuntimeBinding struct {
	RuntimeKey          provisioning.RuntimeKey `json:"runtime_key"`
	TenantID            string                  `json:"tenant_id"`
	SiteID              string                  `json:"site_id"`
	SiteKey             string                  `json:"site_key"`
	Username            string                  `json:"username"`
	UID                 uint32                  `json:"uid"`
	GID                 uint32                  `json:"gid"`
	Fence               uint64                  `json:"fence"`
	State               BindingState            `json:"state"`
	RootGeneration      uint64                  `json:"root_generation"`
	PoolGeneration      uint64                  `json:"pool_generation"`
	InstalledPools      []uint64                `json:"installed_pools,omitempty"`
	QuarantineToken     string                  `json:"quarantine_token,omitempty"`
	QuarantineGeneration uint64                 `json:"quarantine_generation,omitempty"`
	TombstoneToken      string                  `json:"tombstone_token,omitempty"`
	TombstonePurgeAfter time.Time               `json:"tombstone_purge_after,omitempty"`
	CreatedAt           time.Time               `json:"created_at"`
	UpdatedAt           time.Time               `json:"updated_at"`
}

func (binding RuntimeBinding) Validate() error {
	if !validRuntimeKey(binding.RuntimeKey) || binding.RuntimeKey != deriveRuntimeKey(binding.TenantID, binding.SiteID) || binding.SiteKey != deriveSiteKey(binding.TenantID, binding.SiteID) || binding.Username != deriveUsername(binding.SiteKey) || binding.UID < DefaultUIDMinimum || binding.GID != binding.UID || binding.Fence == 0 || binding.CreatedAt.IsZero() || binding.UpdatedAt.IsZero() {
		return ErrCorruptRegistry
	}
	switch binding.State {
	case BindingAllocated, BindingActive, BindingSuspended, BindingQuarantined, BindingTombstoned, BindingDeleted:
	default: return ErrCorruptRegistry
	}
	if binding.State == BindingQuarantined && (binding.QuarantineToken == "" || binding.QuarantineGeneration == 0) { return ErrCorruptRegistry }
	if binding.QuarantineGeneration > binding.Fence || binding.RootGeneration > binding.Fence || binding.PoolGeneration > binding.Fence { return ErrCorruptRegistry }
	previousPool := uint64(0)
	for _, generation := range binding.InstalledPools { if generation == 0 || generation > binding.Fence || generation <= previousPool { return ErrCorruptRegistry }; previousPool = generation }
	if binding.State == BindingTombstoned || binding.State == BindingDeleted { if binding.TombstoneToken == "" || binding.TombstonePurgeAfter.IsZero() { return ErrCorruptRegistry } }
	return nil
}

type OperationState string

const (
	OperationRunning  OperationState = "running"
	OperationComplete OperationState = "complete"
	OperationFailed   OperationState = "failed"
)

type OperationRecord struct {
	Key            string         `json:"key"`
	RuntimeKey     provisioning.RuntimeKey `json:"runtime_key"`
	Operation      Operation      `json:"operation"`
	Generation     uint64         `json:"generation"`
	RequestDigest  string         `json:"request_digest"`
	State          OperationState `json:"state"`
	Attempt        uint32         `json:"attempt"`
	EvidenceDigest string         `json:"evidence_digest,omitempty"`
	ErrorCode      string         `json:"error_code,omitempty"`
	StartedAt      time.Time      `json:"started_at"`
	CompletedAt    time.Time      `json:"completed_at,omitempty"`
}

type Lease struct {
	Binding RuntimeBinding
	Record  OperationRecord
	Cached  bool
}

type Registry interface {
	Begin(Request, time.Time) (Lease, error)
	Complete(Request, RuntimeBinding, string, time.Time) error
	Fail(Request, RuntimeBinding, string, time.Time) error
	Binding(provisioning.RuntimeKey) (RuntimeBinding, bool, error)
	ExpiredTombstones(time.Time, int) ([]RuntimeBinding, error)
	DeleteBinding(provisioning.RuntimeKey, uint64, time.Time) error
}

func deriveRuntimeKey(tenantID, siteID string) provisioning.RuntimeKey {
	sum := sha256.Sum256([]byte("cyberpanel:runtime-identity:v1\x00" + tenantID + "\x00" + siteID))
	return provisioning.RuntimeKey("site-" + hex.EncodeToString(sum[:])[:32])
}

func deriveSiteKey(tenantID, siteID string) string {
	sum := sha256.Sum256([]byte(tenantID + "-" + siteID))
	return "s-" + hex.EncodeToString(sum[:])[:24]
}

func deriveUsername(siteKey string) string { return "cp_" + strings.TrimPrefix(siteKey, "s-") }

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || !alphaNumeric(value[0]) || !alphaNumeric(value[len(value)-1]) { return false }
	for index := range value { character := value[index]; if character > 127 || !(alphaNumeric(character) || character == '-' || character == '_' || character == '.') { return false } }
	return true
}

func alphaNumeric(value byte) bool { return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' }

func validRuntimeKey(key provisioning.RuntimeKey) bool {
	value := string(key); return len(value) == 37 && strings.HasPrefix(value, "site-") && validDigest(strings.Repeat("0", 32)+strings.TrimPrefix(value, "site-"))
}

func validEffectKey(key provisioning.EffectKey) bool {
	value := string(key); return strings.HasPrefix(value, "effect-") && validDigest(strings.TrimPrefix(value, "effect-"))
}

func validDigest(value string) bool { return len(value) == sha256.Size*2 && value == strings.ToLower(value) && strings.Trim(value, "0123456789abcdef") == "" }

func validToken(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum { return false }
	for index := range value { if !alphaNumeric(value[index]) && value[index] != '-' && value[index] != '_' { return false } }
	return true
}

func validLifecycle(value site.Lifecycle) bool {
	switch value {
	case site.LifecycleProvisioning, site.LifecycleActive, site.LifecycleDegraded, site.LifecycleSuspended, site.LifecycleDeleting, site.LifecycleQuarantined, site.LifecyclePurging, site.LifecycleDeleted:
		return true
	default: return false
	}
}

func digest(domain string, parts ...[]byte) string {
	hash := sha256.New(); hash.Write([]byte(domain))
	for _, part := range parts { hash.Write([]byte{0}); hash.Write(part) }
	return hex.EncodeToString(hash.Sum(nil))
}

func bindingEvidence(binding RuntimeBinding) []byte { encoded, _ := json.Marshal(binding); return encoded }

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrFenced): return "fenced"
	case errors.Is(err, ErrRegistryConflict): return "registry_conflict"
	case errors.Is(err, ErrIdentityExhausted): return "identity_exhausted"
	case errors.Is(err, ErrInvalidRequest): return "invalid_request"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled): return "deadline"
	default: return "host_operation"
	}
}

func joinError(code string) error {
	if code == "" { return ErrOperationFailed }
	return fmt.Errorf("%w: %s", ErrOperationFailed, code)
}
