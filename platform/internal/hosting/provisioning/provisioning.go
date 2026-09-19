// Package provisioning turns durable site intent into narrowly typed host
// preparation. It never accepts commands, absolute paths, numeric identities,
// or native web-server configuration from callers.
package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
)

var (
	ErrInvalidRequest       = errors.New("invalid site provisioning request")
	ErrInvalidReceipt       = errors.New("invalid site provisioning receipt")
	ErrIrreversible         = errors.New("purged site provisioning cannot be compensated")
	ErrProvisioningConflict = errors.New("provisioning effect conflicts with durable state")
)

const (
	applicationRoot = "releases/current"
	documentRoot    = "releases/current/public"
	defaultResource = webengine.ResourceRef("resource/profile-default")
	defaultLogs     = webengine.ResourceRef("logs/site-default")
	defaultMaxConns = uint32(8)
)

type EffectKey string
type RuntimeKey string

// RuntimeIdentity is immutable outside this package. Host adapters receive an
// opaque product key and the validated logical scope, never a UID, GID, name,
// or filesystem path chosen by an API caller.
type RuntimeIdentity struct {
	scope service.CommandScope
	key   RuntimeKey
}

func (identity RuntimeIdentity) Scope() service.CommandScope { return identity.scope }
func (identity RuntimeIdentity) Key() RuntimeKey              { return identity.key }

// RuntimeSpec is the closed, immutable input to privileged host adapters.
type RuntimeSpec struct {
	identity         RuntimeIdentity
	effectKey        EffectKey
	projectionDigest string
	generation       uint64
	lifecycle        site.Lifecycle
	withdraw         bool
	phpProfile       site.PHPProfile
}

func (spec RuntimeSpec) Identity() RuntimeIdentity       { return spec.identity }
func (spec RuntimeSpec) EffectKey() EffectKey             { return spec.effectKey }
func (spec RuntimeSpec) ProjectionDigest() string         { return spec.projectionDigest }
func (spec RuntimeSpec) Generation() uint64               { return spec.generation }
func (spec RuntimeSpec) Lifecycle() site.Lifecycle        { return spec.lifecycle }
func (spec RuntimeSpec) Withdraw() bool                    { return spec.withdraw }
func (RuntimeSpec) ApplicationRoot() string                { return applicationRoot }
func (RuntimeSpec) DocumentRoot() string                   { return documentRoot }
func (spec RuntimeSpec) PHPProfileRef() webengine.ResourceRef { return webengine.ResourceRef("php/" + strings.TrimPrefix(string(spec.phpProfile), "php")) }
func (spec RuntimeSpec) PHPProfile() site.PHPProfile       { return spec.phpProfile }
func (RuntimeSpec) ResourceProfileRef() webengine.ResourceRef { return defaultResource }
func (RuntimeSpec) LogPolicyRef() webengine.ResourceRef    { return defaultLogs }
func (RuntimeSpec) MaxConnections() uint32                 { return defaultMaxConns }
func (spec RuntimeSpec) SiteProcessProfile() SiteProcessResourceProfile {
	return DefaultSiteProcessResourceProfile(spec.generation, defaultMaxConns)
}

type SiteProcessResourceProfile struct {
	Generation              uint64 `json:"generation"`
	CPUQuotaPerSecondUSec   uint64 `json:"cpu_quota_per_second_usec"`
	CPUWeight               uint64 `json:"cpu_weight"`
	MemoryHighBytes         uint64 `json:"memory_high_bytes"`
	MemoryMaxBytes          uint64 `json:"memory_max_bytes"`
	TasksMax                uint64 `json:"tasks_max"`
	IOReadBytesPerSecond    uint64 `json:"io_read_bytes_per_second"`
	IOWriteBytesPerSecond   uint64 `json:"io_write_bytes_per_second"`
	IOReadOperationsPerSec  uint64 `json:"io_read_operations_per_second"`
	IOWriteOperationsPerSec uint64 `json:"io_write_operations_per_second"`
}

func DefaultSiteProcessResourceProfile(generation uint64, maxConnections uint32) SiteProcessResourceProfile {
	return SiteProcessResourceProfile{
		Generation: generation, CPUQuotaPerSecondUSec: 1_000_000, CPUWeight: 100,
		MemoryHighBytes: 1536 << 20, MemoryMaxBytes: 2048 << 20,
		TasksMax: uint64(maxConnections)*16 + 32,
		IOReadBytesPerSecond: 50 << 20, IOWriteBytesPerSecond: 25 << 20,
		IOReadOperationsPerSec: 1000, IOWriteOperationsPerSec: 500,
	}
}

func (profile SiteProcessResourceProfile) Validate() error {
	if profile.Generation == 0 || profile.CPUQuotaPerSecondUSec < 1_000 || profile.CPUQuotaPerSecondUSec > 1024*1_000_000 || profile.CPUWeight < 1 || profile.CPUWeight > 10_000 || profile.MemoryHighBytes == 0 || profile.MemoryMaxBytes < profile.MemoryHighBytes || profile.MemoryMaxBytes > 1<<50 || profile.TasksMax == 0 || profile.TasksMax > 1<<20 {
		return ErrInvalidRequest
	}
	for _, value := range []uint64{profile.IOReadBytesPerSecond, profile.IOWriteBytesPerSecond, profile.IOReadOperationsPerSec, profile.IOWriteOperationsPerSec} {
		if value > 1<<50 { return ErrInvalidRequest }
	}
	return nil
}

type SiteProcessLimitDimension string

const (
	SiteProcessCPUQuota  SiteProcessLimitDimension = "cpu_quota"
	SiteProcessCPUWeight SiteProcessLimitDimension = "cpu_weight"
	SiteProcessMemoryHigh SiteProcessLimitDimension = "memory_high"
	SiteProcessMemoryMax SiteProcessLimitDimension = "memory_max"
	SiteProcessTasksMax SiteProcessLimitDimension = "tasks_max"
	SiteProcessIOReadBPS SiteProcessLimitDimension = "io_read_bps"
	SiteProcessIOWriteBPS SiteProcessLimitDimension = "io_write_bps"
	SiteProcessIOReadIOPS SiteProcessLimitDimension = "io_read_iops"
	SiteProcessIOWriteIOPS SiteProcessLimitDimension = "io_write_iops"
)

type ResourceLimitState string

const (
	ResourceLimitEnforced      ResourceLimitState = "enforced"
	ResourceLimitAccountedOnly ResourceLimitState = "accounted_only"
	ResourceLimitUnsupported   ResourceLimitState = "unsupported"
)

type SiteProcessLimitBinding struct {
	Generation         uint64                    `json:"generation"`
	Scope              string                    `json:"scope"`
	Dimension          SiteProcessLimitDimension `json:"dimension"`
	Adapter            string                    `json:"adapter"`
	RequestedValue     uint64                    `json:"requested_value"`
	EffectiveValue     uint64                    `json:"effective_value,omitempty"`
	EffectiveKnown     bool                      `json:"effective_known"`
	EffectiveUnlimited bool                      `json:"effective_unlimited"`
	State              ResourceLimitState        `json:"state"`
	Device             string                    `json:"device,omitempty"`
	Observation        string                    `json:"observation"`
	ObservedAt         time.Time                 `json:"observed_at"`
}

type IdentityReceipt struct {
	EffectKey      EffectKey
	RuntimeKey     RuntimeKey
	Generation     uint64
	EvidenceDigest string
}

type DirectoryReceipt struct {
	EffectKey      EffectKey
	RuntimeKey     RuntimeKey
	Generation     uint64
	EvidenceDigest string
}

type LSAPIPoolReceipt struct {
	EffectKey      EffectKey
	RuntimeKey     RuntimeKey
	Generation     uint64
	EvidenceDigest string
	LimitBindings  []SiteProcessLimitBinding
}

type HealthReceipt struct {
	EffectKey         EffectKey
	RuntimeKey        RuntimeKey
	Generation        uint64
	AttestationDigest string
	EvidenceDigest    string
}

type LifecycleOperation string

const (
	LifecycleSuspend    LifecycleOperation = "suspend"
	LifecycleQuarantine LifecycleOperation = "quarantine"
	LifecyclePurge      LifecycleOperation = "purge"
)

type LifecycleReceipt struct {
	EffectKey      EffectKey
	RuntimeKey     RuntimeKey
	Generation     uint64
	Operation      LifecycleOperation
	EvidenceDigest string
}

// HealthAttestation is constructed only from a canonical native generation
// digest. The executor writes Body verbatim at its product-owned health path.
type HealthAttestation struct{ digest string }

func NewHealthAttestation(nativeGenerationDigest string) (HealthAttestation, error) {
	if !validDigest(nativeGenerationDigest) {
		return HealthAttestation{}, errors.New("health attestation requires a canonical SHA-256 digest")
	}
	return HealthAttestation{digest: nativeGenerationDigest}, nil
}

func (attestation HealthAttestation) Digest() string { return attestation.digest }
func (attestation HealthAttestation) Body() []byte {
	return []byte("panel-health-v1 " + attestation.digest + "\n")
}

// PrivilegedExecutor is the complete host-mutation vocabulary available to
// provisioning. Implementations derive all operating-system identities and
// paths from RuntimeSpec.Identity().Key().
type PrivilegedExecutor interface {
	EnsureIdentity(context.Context, RuntimeSpec) (IdentityReceipt, error)
	EnsureDirectories(context.Context, RuntimeSpec) (DirectoryReceipt, error)
	EnsureLSAPIPool(context.Context, RuntimeSpec) (LSAPIPoolReceipt, error)
	WriteHealthAttestation(context.Context, RuntimeSpec, HealthAttestation) (HealthReceipt, error)
	Suspend(context.Context, RuntimeSpec) (LifecycleReceipt, error)
	Quarantine(context.Context, RuntimeSpec) (LifecycleReceipt, error)
	Purge(context.Context, RuntimeSpec) (LifecycleReceipt, error)
}

type ProvisioningPhase string

const (
	PhasePreparing   ProvisioningPhase = "preparing"
	PhasePrepared    ProvisioningPhase = "prepared"
	PhaseFinalized   ProvisioningPhase = "finalized"
	PhaseCompensated ProvisioningPhase = "compensated"
)

type ProvisioningAction string

const (
	ActionEnsure     ProvisioningAction = "ensure"
	ActionSuspend    ProvisioningAction = "suspend"
	ActionQuarantine ProvisioningAction = "quarantine"
	ActionPurge      ProvisioningAction = "purge"
)

// ProvisioningReceipt is durable progress, not proof that the web engine
// activated the projection. Node reconciliation remains the sole owner of the
// final service.SiteEffectReceipt.
type ProvisioningReceipt struct {
	EffectKey         EffectKey
	Scope             service.CommandScope
	ProjectionDigest  string
	Generation        uint64
	Lifecycle         site.Lifecycle
	Withdraw          bool
	PHPProfile        site.PHPProfile
	RuntimeKey        RuntimeKey
	Phase             ProvisioningPhase
	Action            ProvisioningAction
	Identity          IdentityReceipt
	Directories       DirectoryReceipt
	Pool              LSAPIPoolReceipt
	Health            HealthReceipt
	LifecycleMutation LifecycleReceipt
}

type Journal interface {
	Load(context.Context, EffectKey) (ProvisioningReceipt, bool, error)
	Save(context.Context, ProvisioningReceipt) error
}

type Orchestrator struct {
	executor PrivilegedExecutor
	journal  Journal
}

func New(executor PrivilegedExecutor, journal Journal) (*Orchestrator, error) {
	if nilInterface(executor) || nilInterface(journal) {
		return nil, errors.New("provisioning executor and journal are required")
	}
	return &Orchestrator{executor: executor, journal: journal}, nil
}

// Prepare durably resumes typed host preparation and returns the exact input
// contributed to node-wide composition. Every privileged step is idempotently
// bound to effect, runtime identity, and projection generation.
func (orchestrator *Orchestrator) Prepare(ctx context.Context, request service.SiteEffectRequest) (composer.SiteInput, ProvisioningReceipt, error) {
	if orchestrator == nil || nilInterface(orchestrator.executor) || nilInterface(orchestrator.journal) || nilInterface(ctx) {
		return composer.SiteInput{}, ProvisioningReceipt{}, ErrInvalidRequest
	}
	spec, err := specFromRequest(request)
	if err != nil {
		return composer.SiteInput{}, ProvisioningReceipt{}, err
	}
	receipt, found, err := orchestrator.journal.Load(ctx, spec.EffectKey())
	if err != nil {
		return composer.SiteInput{}, ProvisioningReceipt{}, err
	}
	if found {
		if err := validateProvisioningReceipt(receipt, spec); err != nil {
			return composer.SiteInput{}, ProvisioningReceipt{}, err
		}
		if receipt.Phase == PhaseCompensated {
			return composer.SiteInput{}, receipt, ErrProvisioningConflict
		}
		if receipt.Phase == PhasePrepared || receipt.Phase == PhaseFinalized {
			return composeInput(request, spec), receipt, nil
		}
	} else {
		receipt = newReceipt(spec)
		if err := orchestrator.journal.Save(ctx, receipt); err != nil {
			return composer.SiteInput{}, ProvisioningReceipt{}, err
		}
	}

	if err := orchestrator.resumePrepare(ctx, spec, &receipt); err != nil {
		return composer.SiteInput{}, receipt, err
	}
	receipt.Phase = PhasePrepared
	if err := orchestrator.journal.Save(ctx, receipt); err != nil {
		return composer.SiteInput{}, receipt, err
	}
	return composeInput(request, spec), receipt, nil
}

// Resolve implements catalog.SiteInputResolver without coupling this package
// to the catalog implementation. Durable progress remains addressable by the
// request's EffectID for later finalization or compensation.
func (orchestrator *Orchestrator) Resolve(ctx context.Context, request service.SiteEffectRequest) (composer.SiteInput, error) {
	input, _, err := orchestrator.Prepare(ctx, request)
	return input, err
}

// Finalize writes the digest-bound candidate health attestation after node
// rendering has produced its immutable generation. It does not claim engine
// activation or probe success.
func (orchestrator *Orchestrator) Finalize(ctx context.Context, receipt ProvisioningReceipt, attestation HealthAttestation) (ProvisioningReceipt, error) {
	if orchestrator == nil || nilInterface(orchestrator.executor) || nilInterface(orchestrator.journal) || nilInterface(ctx) {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	spec, err := specFromReceipt(receipt)
	if err != nil || validateProvisioningReceipt(receipt, spec) != nil {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	if receipt.Phase == PhaseCompensated || receipt.Phase == PhasePreparing {
		return receipt, ErrProvisioningConflict
	}
	if receipt.Phase == PhaseFinalized {
		if receipt.Action == ActionPurge || receipt.Health.AttestationDigest == attestation.Digest() {
			return receipt, nil
		}
		return receipt, ErrProvisioningConflict
	}
	if receipt.Action != ActionPurge {
		if !validDigest(attestation.Digest()) {
			return receipt, ErrInvalidReceipt
		}
		health, err := orchestrator.executor.WriteHealthAttestation(ctx, spec, attestation)
		if err != nil {
			return receipt, err
		}
		if !validHealthReceipt(health, spec, attestation) {
			return receipt, ErrInvalidReceipt
		}
		receipt.Health = health
		if err := orchestrator.journal.Save(ctx, receipt); err != nil {
			return receipt, err
		}
	}
	receipt.Phase = PhaseFinalized
	if err := orchestrator.journal.Save(ctx, receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

// Compensate quarantines prepared data when node-wide reconciliation fails.
// Purge is intentionally irreversible.
func (orchestrator *Orchestrator) Compensate(ctx context.Context, receipt ProvisioningReceipt) (ProvisioningReceipt, error) {
	if orchestrator == nil || nilInterface(orchestrator.executor) || nilInterface(orchestrator.journal) || nilInterface(ctx) {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	spec, err := specFromReceipt(receipt)
	if err != nil || validateProvisioningReceipt(receipt, spec) != nil {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	if receipt.Action == ActionPurge {
		if receipt.LifecycleMutation.EvidenceDigest != "" {
			return receipt, ErrIrreversible
		}
		receipt.Phase = PhaseCompensated
		if err := orchestrator.journal.Save(ctx, receipt); err != nil { return receipt, err }
		return receipt, nil
	}
	if receipt.Phase == PhaseCompensated {
		return receipt, nil
	}
	mutation, err := orchestrator.executor.Quarantine(ctx, spec)
	if err != nil {
		return receipt, err
	}
	if !validLifecycleReceipt(mutation, spec, LifecycleQuarantine) {
		return receipt, ErrInvalidReceipt
	}
	receipt.LifecycleMutation = mutation
	receipt.Phase = PhaseCompensated
	if err := orchestrator.journal.Save(ctx, receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

// FinalizeEffect resumes host finalization by durable effect identity after a
// node candidate digest has been rendered. It still does not claim activation.
func (orchestrator *Orchestrator) FinalizeEffect(ctx context.Context, effectID, activationDigest string) (ProvisioningReceipt, error) {
	if orchestrator == nil || nilInterface(orchestrator.journal) || nilInterface(ctx) {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	key := EffectKey(effectID)
	if !validEffectKey(key) {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	receipt, found, err := orchestrator.journal.Load(ctx, key)
	if err != nil {
		return ProvisioningReceipt{}, err
	}
	if !found {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	attestation, err := NewHealthAttestation(activationDigest)
	if err != nil {
		return ProvisioningReceipt{}, err
	}
	return orchestrator.Finalize(ctx, receipt, attestation)
}

// CompensateEffect resumes safe quarantine by durable effect identity.
func (orchestrator *Orchestrator) CompensateEffect(ctx context.Context, effectID string) (ProvisioningReceipt, error) {
	if orchestrator == nil || nilInterface(orchestrator.journal) || nilInterface(ctx) {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	key := EffectKey(effectID)
	if !validEffectKey(key) {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	receipt, found, err := orchestrator.journal.Load(ctx, key)
	if err != nil {
		return ProvisioningReceipt{}, err
	}
	if !found {
		return ProvisioningReceipt{}, ErrInvalidReceipt
	}
	return orchestrator.Compensate(ctx, receipt)
}

// BeforeActivation publishes only the digest-bound health attestation needed
// by the candidate probe. Withdrawals deliberately do no destructive work
// until the node has confirmed that routing no longer references the site.
func (orchestrator *Orchestrator) BeforeActivation(ctx context.Context, effectID, candidateDigest string) error {
	key := EffectKey(effectID)
	if orchestrator == nil || !validEffectKey(key) { return ErrInvalidReceipt }
	receipt, found, err := orchestrator.journal.Load(ctx, key)
	if err != nil { return err }
	if !found { return ErrInvalidReceipt }
	if receipt.Action == ActionPurge { return nil }
	_, err = orchestrator.FinalizeEffect(ctx, effectID, candidateDigest)
	return err
}

// AfterActivation commits host destruction only after the node generation is
// confirmed. Non-withdrawal effects were already finalized before probing.
func (orchestrator *Orchestrator) AfterActivation(ctx context.Context, effectID, candidateDigest string) error {
	key := EffectKey(effectID)
	if orchestrator == nil || !validEffectKey(key) { return ErrInvalidReceipt }
	receipt, found, err := orchestrator.journal.Load(ctx, key)
	if err != nil { return err }
	if !found { return ErrInvalidReceipt }
	if receipt.Action != ActionPurge {
		if receipt.Phase != PhaseFinalized || receipt.Health.AttestationDigest != candidateDigest { return ErrProvisioningConflict }
		return nil
	}
	if receipt.Phase == PhaseFinalized { return nil }
	if receipt.Phase != PhasePrepared { return ErrProvisioningConflict }
	spec, err := specFromReceipt(receipt)
	if err != nil { return err }
	mutation, err := orchestrator.executor.Purge(ctx, spec)
	if err != nil { return err }
	if !validLifecycleReceipt(mutation, spec, LifecyclePurge) { return ErrInvalidReceipt }
	receipt.LifecycleMutation = mutation
	receipt.Phase = PhaseFinalized
	return orchestrator.journal.Save(ctx, receipt)
}

func (orchestrator *Orchestrator) CompensateCandidate(ctx context.Context, effectID string) error {
	_, err := orchestrator.CompensateEffect(ctx, effectID)
	return err
}

func (orchestrator *Orchestrator) resumePrepare(ctx context.Context, spec RuntimeSpec, receipt *ProvisioningReceipt) error {
	switch receipt.Action {
	case ActionPurge:
		// Destruction is a post-activation frontier; Prepare only durably
		// reserves the withdrawal and returns an empty composition input.
		return nil
	case ActionEnsure, ActionSuspend, ActionQuarantine:
	default:
		return ErrInvalidReceipt
	}

	if receipt.Identity.EvidenceDigest == "" {
		value, err := orchestrator.executor.EnsureIdentity(ctx, spec)
		if err != nil {
			return err
		}
		if !validStep(value.EffectKey, value.RuntimeKey, value.Generation, value.EvidenceDigest, spec) {
			return ErrInvalidReceipt
		}
		receipt.Identity = value
		if err := orchestrator.journal.Save(ctx, *receipt); err != nil {
			return err
		}
	}
	if receipt.Directories.EvidenceDigest == "" {
		value, err := orchestrator.executor.EnsureDirectories(ctx, spec)
		if err != nil {
			return err
		}
		if !validStep(value.EffectKey, value.RuntimeKey, value.Generation, value.EvidenceDigest, spec) {
			return ErrInvalidReceipt
		}
		receipt.Directories = value
		if err := orchestrator.journal.Save(ctx, *receipt); err != nil {
			return err
		}
	}
	if receipt.Action != ActionQuarantine && receipt.Pool.EvidenceDigest == "" {
		value, err := orchestrator.executor.EnsureLSAPIPool(ctx, spec)
		if err != nil {
			return err
		}
		if !validStep(value.EffectKey, value.RuntimeKey, value.Generation, value.EvidenceDigest, spec) {
			return ErrInvalidReceipt
		}
		receipt.Pool = value
		if err := orchestrator.journal.Save(ctx, *receipt); err != nil {
			return err
		}
	}
	operation := LifecycleOperation("")
	if receipt.Action == ActionSuspend {
		operation = LifecycleSuspend
	} else if receipt.Action == ActionQuarantine {
		operation = LifecycleQuarantine
	}
	if operation != "" && receipt.LifecycleMutation.EvidenceDigest == "" {
		var value LifecycleReceipt
		var err error
		if operation == LifecycleSuspend {
			value, err = orchestrator.executor.Suspend(ctx, spec)
		} else {
			value, err = orchestrator.executor.Quarantine(ctx, spec)
		}
		if err != nil {
			return err
		}
		if !validLifecycleReceipt(value, spec, operation) {
			return ErrInvalidReceipt
		}
		receipt.LifecycleMutation = value
		if err := orchestrator.journal.Save(ctx, *receipt); err != nil {
			return err
		}
	}
	return nil
}

func specFromRequest(request service.SiteEffectRequest) (RuntimeSpec, error) {
	if !validRequest(request) {
		return RuntimeSpec{}, ErrInvalidRequest
	}
	source := "cyberpanel:runtime-identity:v1\x00" + request.Scope.TenantID.String() + "\x00" + request.Scope.SiteID.String()
	sum := sha256.Sum256([]byte(source))
	return RuntimeSpec{
		identity: RuntimeIdentity{scope: request.Scope, key: RuntimeKey("site-" + hex.EncodeToString(sum[:])[:32])},
		effectKey: EffectKey(request.EffectID), projectionDigest: request.ProjectionDigest,
		generation: request.Projection.Generation, lifecycle: request.Projection.Lifecycle, withdraw: request.Withdraw, phpProfile: request.Projection.PHPProfile,
	}, nil
}

func specFromReceipt(receipt ProvisioningReceipt) (RuntimeSpec, error) {
	if receipt.EffectKey == "" || receipt.Scope.TenantID.String() == "" || receipt.Scope.SiteID.String() == "" || receipt.RuntimeKey == "" || receipt.Generation == 0 || !validDigest(receipt.ProjectionDigest) {
		return RuntimeSpec{}, ErrInvalidReceipt
	}
	return RuntimeSpec{
		identity: RuntimeIdentity{scope: receipt.Scope, key: receipt.RuntimeKey}, effectKey: receipt.EffectKey,
		projectionDigest: receipt.ProjectionDigest, generation: receipt.Generation,
		lifecycle: receipt.Lifecycle, withdraw: receipt.Withdraw, phpProfile: receipt.PHPProfile,
	}, nil
}

func validRequest(request service.SiteEffectRequest) bool {
	if !strings.HasPrefix(request.EffectID, "effect-") || !validDigest(strings.TrimPrefix(request.EffectID, "effect-")) || request.Scope.TenantID.String() == "" || request.Scope.SiteID.String() == "" {
		return false
	}
	if request.Projection.Generation == 0 || !validLifecycle(request.Projection.Lifecycle) || !site.ValidPHPProfile(request.Projection.PHPProfile) || request.ProjectionDigest != digestProjection(request.Projection) {
		return false
	}
	withdraw := request.Projection.Lifecycle == site.LifecyclePurging || request.Projection.Lifecycle == site.LifecycleDeleted
	return request.Withdraw == withdraw
}

func newReceipt(spec RuntimeSpec) ProvisioningReceipt {
	return ProvisioningReceipt{
		EffectKey: spec.EffectKey(), Scope: spec.Identity().Scope(), ProjectionDigest: spec.ProjectionDigest(),
		Generation: spec.Generation(), Lifecycle: spec.Lifecycle(), Withdraw: spec.Withdraw(), PHPProfile: spec.PHPProfile(), RuntimeKey: spec.Identity().Key(),
		Phase: PhasePreparing, Action: actionFor(spec),
	}
}

func actionFor(spec RuntimeSpec) ProvisioningAction {
	if spec.Withdraw() || spec.Lifecycle() == site.LifecyclePurging || spec.Lifecycle() == site.LifecycleDeleted {
		return ActionPurge
	}
	if spec.Lifecycle() == site.LifecycleSuspended {
		return ActionSuspend
	}
	if spec.Lifecycle() == site.LifecycleQuarantined {
		return ActionQuarantine
	}
	return ActionEnsure
}

func composeInput(request service.SiteEffectRequest, spec RuntimeSpec) composer.SiteInput {
	projection := request.Projection
	projection.Bindings = append([]site.DomainBinding(nil), request.Projection.Bindings...)
	return composer.SiteInput{
		Scope: request.Scope, Projection: projection, Withdraw: request.Withdraw,
		ApplicationRoot: applicationRoot, DocumentRoot: documentRoot,
		Indexes: []string{"index.php", "index.html"}, PHPProfileRef: spec.PHPProfileRef(),
		ResourceProfileRef: defaultResource, LogPolicyRef: defaultLogs,
		RootGeneration: spec.Generation(), PoolGeneration: spec.Generation(), MaxConnections: defaultMaxConns,
	}
}

func validateProvisioningReceipt(receipt ProvisioningReceipt, spec RuntimeSpec) error {
	if receipt.EffectKey != spec.EffectKey() || receipt.Scope != spec.Identity().Scope() || receipt.ProjectionDigest != spec.ProjectionDigest() || receipt.Generation != spec.Generation() || receipt.Lifecycle != spec.Lifecycle() || receipt.Withdraw != spec.Withdraw() || receipt.PHPProfile != spec.PHPProfile() || receipt.RuntimeKey != spec.Identity().Key() || receipt.Action != actionFor(spec) {
		return ErrProvisioningConflict
	}
	if receipt.Phase != PhasePreparing && receipt.Phase != PhasePrepared && receipt.Phase != PhaseFinalized && receipt.Phase != PhaseCompensated {
		return ErrInvalidReceipt
	}
	for _, step := range []struct {
		effect EffectKey
		key RuntimeKey
		generation uint64
		evidence string
	}{
		{receipt.Identity.EffectKey, receipt.Identity.RuntimeKey, receipt.Identity.Generation, receipt.Identity.EvidenceDigest},
		{receipt.Directories.EffectKey, receipt.Directories.RuntimeKey, receipt.Directories.Generation, receipt.Directories.EvidenceDigest},
		{receipt.Pool.EffectKey, receipt.Pool.RuntimeKey, receipt.Pool.Generation, receipt.Pool.EvidenceDigest},
	} {
		if step.evidence != "" && !validStep(step.effect, step.key, step.generation, step.evidence, spec) {
			return ErrInvalidReceipt
		}
	}
	if receipt.Pool.EvidenceDigest != "" && !validSiteProcessLimitBindings(receipt.Pool.LimitBindings, spec.SiteProcessProfile()) { return ErrInvalidReceipt }
	if receipt.Health.EvidenceDigest != "" && !validHealthReceipt(receipt.Health, spec, HealthAttestation{digest: receipt.Health.AttestationDigest}) {
		return ErrInvalidReceipt
	}
	if receipt.LifecycleMutation.EvidenceDigest != "" && !validLifecycleReceipt(receipt.LifecycleMutation, spec, receipt.LifecycleMutation.Operation) {
		return ErrInvalidReceipt
	}
	return nil
}

func validSiteProcessLimitBindings(bindings []SiteProcessLimitBinding, profile SiteProcessResourceProfile) bool {
	if len(bindings) != 9 || profile.Validate() != nil { return false }
	requested := map[SiteProcessLimitDimension]uint64{
		SiteProcessCPUQuota:profile.CPUQuotaPerSecondUSec, SiteProcessCPUWeight:profile.CPUWeight,
		SiteProcessMemoryHigh:profile.MemoryHighBytes, SiteProcessMemoryMax:profile.MemoryMaxBytes,
		SiteProcessTasksMax:profile.TasksMax, SiteProcessIOReadBPS:profile.IOReadBytesPerSecond,
		SiteProcessIOWriteBPS:profile.IOWriteBytesPerSecond, SiteProcessIOReadIOPS:profile.IOReadOperationsPerSec,
		SiteProcessIOWriteIOPS:profile.IOWriteOperationsPerSec,
	}
	seen := map[SiteProcessLimitDimension]struct{}{}
	for _, binding := range bindings {
		wanted, ok := requested[binding.Dimension]; if !ok || binding.Generation != profile.Generation || binding.Scope != "site_processes" || binding.Adapter != "systemd_cgroup_v2" || binding.RequestedValue != wanted || binding.ObservedAt.IsZero() || binding.Observation == "" { return false }
		if _, duplicate := seen[binding.Dimension]; duplicate { return false }; seen[binding.Dimension] = struct{}{}
		if binding.State != ResourceLimitEnforced && binding.State != ResourceLimitAccountedOnly && binding.State != ResourceLimitUnsupported { return false }
		if binding.State == ResourceLimitEnforced && (!binding.EffectiveKnown || binding.EffectiveUnlimited || binding.EffectiveValue != wanted) { return false }
		if binding.State == ResourceLimitUnsupported && binding.EffectiveKnown { return false }
	}
	return len(seen) == len(requested)
}

func validStep(effect EffectKey, key RuntimeKey, generation uint64, evidence string, spec RuntimeSpec) bool {
	return effect == spec.EffectKey() && key == spec.Identity().Key() && generation == spec.Generation() && validDigest(evidence)
}

func validHealthReceipt(receipt HealthReceipt, spec RuntimeSpec, attestation HealthAttestation) bool {
	return validStep(receipt.EffectKey, receipt.RuntimeKey, receipt.Generation, receipt.EvidenceDigest, spec) && validDigest(receipt.AttestationDigest) && receipt.AttestationDigest == attestation.Digest()
}

func validLifecycleReceipt(receipt LifecycleReceipt, spec RuntimeSpec, operation LifecycleOperation) bool {
	if operation != LifecycleSuspend && operation != LifecycleQuarantine && operation != LifecyclePurge {
		return false
	}
	return receipt.Operation == operation && validStep(receipt.EffectKey, receipt.RuntimeKey, receipt.Generation, receipt.EvidenceDigest, spec)
}

func validLifecycle(value site.Lifecycle) bool {
	switch value {
	case site.LifecycleProvisioning, site.LifecycleActive, site.LifecycleDegraded, site.LifecycleSuspended,
		site.LifecycleDeleting, site.LifecycleQuarantined, site.LifecyclePurging, site.LifecycleDeleted:
		return true
	default:
		return false
	}
}

func validDigest(value string) bool {
	return len(value) == sha256.Size*2 && strings.Trim(value, "0123456789abcdef") == ""
}

type projectionDigestDTO struct {
	Version int `json:"v"`
	Generation uint64 `json:"generation"`
	Lifecycle site.Lifecycle `json:"lifecycle"`
	PHPProfile site.PHPProfile `json:"php_profile"`
	Bindings []bindingDigestDTO `json:"bindings"`
}

type bindingDigestDTO struct {
	Hostname string `json:"hostname"`
	Kind site.BindingKind `json:"kind"`
	RedirectTarget string `json:"redirect_target,omitempty"`
	RedirectStatus site.RedirectStatus `json:"redirect_status,omitempty"`
}

func digestProjection(projection service.SiteProjection) string {
	bindings := make([]bindingDigestDTO, 0, len(projection.Bindings))
	for _, binding := range projection.Bindings {
		bindings = append(bindings, bindingDigestDTO{Hostname: binding.Hostname.String(), Kind: binding.Kind, RedirectTarget: binding.RedirectTarget.String(), RedirectStatus: binding.RedirectStatus})
	}
	sort.Slice(bindings, func(left, right int) bool {
		if bindings[left].Hostname != bindings[right].Hostname { return bindings[left].Hostname < bindings[right].Hostname }
		return bindings[left].Kind < bindings[right].Kind
	})
	encoded, _ := json.Marshal(projectionDigestDTO{Version: 2, Generation: projection.Generation, Lifecycle: projection.Lifecycle, PHPProfile: projection.PHPProfile, Bindings: bindings})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func nilInterface(value any) bool {
	if value == nil { return true }
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// FileJournal is an unprivileged, atomic receipt journal. Filenames are
// product-derived hashes; callers cannot select a child path.
type FileJournal struct {
	root string
	mu sync.Mutex
}

func NewFileJournal(root string) (*FileJournal, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("journal root must be a clean absolute path")
	}
	if err := os.MkdirAll(root, 0o700); err != nil { return nil, err }
	info, err := os.Lstat(root)
	if err != nil { return nil, err }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return nil, errors.New("journal root must be a real directory") }
	if err := os.Chmod(root, 0o700); err != nil { return nil, err }
	return &FileJournal{root: root}, nil
}

func (journal *FileJournal) Load(ctx context.Context, key EffectKey) (ProvisioningReceipt, bool, error) {
	if journal == nil || nilInterface(ctx) || !validEffectKey(key) { return ProvisioningReceipt{}, false, ErrInvalidReceipt }
	if err := ctx.Err(); err != nil { return ProvisioningReceipt{}, false, err }
	journal.mu.Lock()
	defer journal.mu.Unlock()
	content, err := os.ReadFile(journal.filename(key))
	if errors.Is(err, os.ErrNotExist) { return ProvisioningReceipt{}, false, nil }
	if err != nil { return ProvisioningReceipt{}, false, err }
	var disk diskReceipt
	if err := json.Unmarshal(content, &disk); err != nil { return ProvisioningReceipt{}, false, ErrInvalidReceipt }
	receipt, err := disk.toReceipt()
	if err != nil || receipt.EffectKey != key { return ProvisioningReceipt{}, false, ErrInvalidReceipt }
	return receipt, true, nil
}

func (journal *FileJournal) Save(ctx context.Context, receipt ProvisioningReceipt) error {
	if journal == nil || nilInterface(ctx) || !validEffectKey(receipt.EffectKey) { return ErrInvalidReceipt }
	if err := ctx.Err(); err != nil { return err }
	content, err := json.Marshal(diskFromReceipt(receipt))
	if err != nil { return err }
	journal.mu.Lock()
	defer journal.mu.Unlock()
	temporary, err := os.CreateTemp(journal.root, ".provisioning-*")
	if err != nil { return err }
	name := temporary.Name()
	committed := false
	defer func() { if !committed { _ = os.Remove(name) } }()
	if err = temporary.Chmod(0o600); err == nil { _, err = temporary.Write(content) }
	if err == nil { err = temporary.Sync() }
	if closeErr := temporary.Close(); err == nil { err = closeErr }
	if err == nil { err = os.Rename(name, journal.filename(receipt.EffectKey)) }
	if err != nil { return err }
	directory, err := os.Open(journal.root)
	if err != nil { return err }
	err = directory.Sync()
	closeErr := directory.Close()
	if err == nil { err = closeErr }
	if err != nil { return err }
	committed = true
	return nil
}

func (journal *FileJournal) filename(key EffectKey) string {
	sum := sha256.Sum256([]byte("cyberpanel:provisioning-journal:v1\x00" + string(key)))
	return filepath.Join(journal.root, hex.EncodeToString(sum[:])+".json")
}

func validEffectKey(key EffectKey) bool {
	value := string(key)
	return strings.HasPrefix(value, "effect-") && validDigest(strings.TrimPrefix(value, "effect-"))
}

type diskReceipt struct {
	EffectKey EffectKey `json:"effect_key"`
	TenantID string `json:"tenant_id"`
	SiteID string `json:"site_id"`
	ProjectionDigest string `json:"projection_digest"`
	Generation uint64 `json:"generation"`
	Lifecycle site.Lifecycle `json:"lifecycle"`
	Withdraw bool `json:"withdraw"`
	RuntimeKey RuntimeKey `json:"runtime_key"`
	Phase ProvisioningPhase `json:"phase"`
	Action ProvisioningAction `json:"action"`
	Identity IdentityReceipt `json:"identity"`
	Directories DirectoryReceipt `json:"directories"`
	Pool LSAPIPoolReceipt `json:"pool"`
	Health HealthReceipt `json:"health"`
	LifecycleMutation LifecycleReceipt `json:"lifecycle_mutation"`
}

func diskFromReceipt(receipt ProvisioningReceipt) diskReceipt {
	return diskReceipt{
		EffectKey: receipt.EffectKey, TenantID: receipt.Scope.TenantID.String(), SiteID: receipt.Scope.SiteID.String(),
		ProjectionDigest: receipt.ProjectionDigest, Generation: receipt.Generation, Lifecycle: receipt.Lifecycle,
		Withdraw: receipt.Withdraw, RuntimeKey: receipt.RuntimeKey, Phase: receipt.Phase, Action: receipt.Action,
		Identity: receipt.Identity, Directories: receipt.Directories, Pool: receipt.Pool,
		Health: receipt.Health, LifecycleMutation: receipt.LifecycleMutation,
	}
}

func (disk diskReceipt) toReceipt() (ProvisioningReceipt, error) {
	tenantID, err := site.NewTenantID(disk.TenantID)
	if err != nil { return ProvisioningReceipt{}, err }
	siteID, err := site.NewSiteID(disk.SiteID)
	if err != nil { return ProvisioningReceipt{}, err }
	return ProvisioningReceipt{
		EffectKey: disk.EffectKey, Scope: service.CommandScope{TenantID: tenantID, SiteID: siteID},
		ProjectionDigest: disk.ProjectionDigest, Generation: disk.Generation, Lifecycle: disk.Lifecycle,
		Withdraw: disk.Withdraw, RuntimeKey: disk.RuntimeKey, Phase: disk.Phase, Action: disk.Action,
		Identity: disk.Identity, Directories: disk.Directories, Pool: disk.Pool,
		Health: disk.Health, LifecycleMutation: disk.LifecycleMutation,
	}, nil
}
