package siteops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// Host is implemented only inside the privileged binary. Its methods remain
// closed typed operations; it exposes no generic process runner, host path,
// environment, command, or argument-vector primitive.
type Host interface {
	EnsureIdentity(context.Context, UnixIdentity) error
	DisableIdentity(context.Context, UnixIdentity) error
	DeleteIdentity(context.Context, UnixIdentity) error
	EnsureDirectories(context.Context, UnixIdentity, DirectoryLayout) error
	RestoreQuarantine(context.Context, UnixIdentity, uint64, string) error
	WriteHealth(context.Context, UnixIdentity, uint64, []byte) error
	InstallLSAPI(context.Context, LSAPISpec, []byte) error
	StartLSAPI(context.Context, LSAPISpec) error
	StopLSAPI(context.Context, LSAPISpec) error
	RemoveLSAPI(context.Context, LSAPISpec) error
	ProbeLSAPIResources(context.Context, LSAPISpec) (ProcessResourceObservation, error)
	Quarantine(context.Context, UnixIdentity, uint64, string) error
	Tombstone(context.Context, UnixIdentity, uint64, string, string) error
	DeleteTombstone(context.Context, UnixIdentity, string) error
}

type Config struct {
	Admission rebootcontrol.ExecutionAdmission
	Edition   EngineEdition
	Retention time.Duration
}

type Executor struct {
	admission rebootcontrol.ExecutionAdmission
	registry  Registry
	host      Host
	php       PHPBinaryResolver
	edition   EngineEdition
	retention time.Duration
	locks     keyedLocks
	now       func() time.Time
}

type tombstoneCollectionReceipt struct {
	Runtime       string `json:"runtime"`
	Token         string `json:"token"`
	Fence         uint64 `json:"fence"`
	RequestDigest string `json:"request_digest"`
	DeletedDigest string `json:"deleted_digest"`
}

var _ RequestHandler = (*Executor)(nil)

func NewExecutor(registry Registry, host Host, php PHPBinaryResolver, config Config) (*Executor, error) {
	if nilInterface(registry) || nilInterface(host) || nilInterface(php) || !config.Edition.valid() {
		return nil, errors.New("siteops registry, host, PHP resolver, and engine edition are required")
	}
	if config.Retention == 0 {
		config.Retention = DefaultRetention
	}
	if config.Retention < 24*time.Hour || config.Retention > 365*24*time.Hour {
		return nil, errors.New("siteops tombstone retention must be between one day and one year")
	}
	return &Executor{admission: config.Admission, registry: registry, host: host, php: php, edition: config.Edition, retention: config.Retention}, nil
}

func (executor *Executor) WithClock(clock func() time.Time) *Executor {
	if executor != nil && clock != nil {
		executor.now = clock
	}
	return executor
}
func (executor *Executor) currentTime() time.Time {
	if executor.now != nil {
		return executor.now().UTC()
	}
	return time.Now().UTC()
}

func (executor *Executor) Execute(ctx context.Context, request Request) (Response, error) {
	if executor == nil || nilInterface(executor.registry) || nilInterface(executor.host) || nilInterface(ctx) {
		return Response{}, ErrInvalidRequest
	}
	now := executor.currentTime()
	if err := request.Validate(now); err != nil {
		return Response{}, err
	}
	unlock := executor.locks.lock(string(request.RuntimeKey))
	defer unlock()
	lease, err := executor.registry.Begin(request, now)
	if err != nil {
		return executor.failure(request, err), nil
	}
	if lease.Cached {
		bindings, observeErr := executor.observeLimitBindings(ctx, request, lease.Binding)
		if observeErr != nil {
			return executor.failure(request, observeErr), nil
		}
		return executor.success(request, lease.Record.EvidenceDigest, bindings, now), nil
	}
	binding := lease.Binding
	evidenceDigest, mutation, operationErr := executor.perform(ctx, request, binding)
	if operationErr != nil {
		code := errorCode(operationErr)
		_ = executor.registry.Fail(request, binding, code, executor.currentTime())
		return executor.failure(request, operationErr), nil
	}
	if !validDigest(evidenceDigest) {
		operationErr = ErrCorruptRegistry
		_ = executor.registry.Fail(request, binding, errorCode(operationErr), executor.currentTime())
		return executor.failure(request, operationErr), nil
	}
	bindings, observeErr := executor.observeLimitBindings(ctx, request, mutation)
	if observeErr != nil {
		_ = executor.registry.Fail(request, binding, errorCode(observeErr), executor.currentTime())
		return executor.failure(request, observeErr), nil
	}
	if err = executor.registry.Complete(request, mutation, evidenceDigest, executor.currentTime()); err != nil {
		return executor.failure(request, err), nil
	}
	return executor.success(request, evidenceDigest, bindings, executor.currentTime()), nil
}

func (executor *Executor) perform(ctx context.Context, request Request, binding RuntimeBinding) (string, RuntimeBinding, error) {
	if err := ctx.Err(); err != nil {
		return "", binding, err
	}
	identity, err := identityFromBinding(binding)
	if err != nil {
		return "", binding, err
	}
	switch request.Operation {
	case OperationEnsureIdentity:
		if binding.State == BindingTombstoned || binding.State == BindingDeleted {
			return "", binding, ErrRegistryConflict
		}
		if err = executor.host.EnsureIdentity(ctx, identity); err != nil {
			return "", binding, err
		}
		if binding.State == BindingAllocated || binding.State == BindingSuspended {
			binding.State = BindingActive
		}
		return evidence("identity", string(binding.RuntimeKey), binding.Username, decimal(uint64(binding.UID)), decimal(binding.Fence)), binding, nil
	case OperationEnsureDirectories:
		if binding.State == BindingTombstoned || binding.State == BindingDeleted {
			return "", binding, ErrRegistryConflict
		}
		if binding.State == BindingQuarantined {
			if binding.QuarantineToken == "" {
				return "", binding, ErrCorruptRegistry
			}
			if err = executor.host.RestoreQuarantine(ctx, identity, binding.QuarantineGeneration, binding.QuarantineToken); err != nil {
				return "", binding, err
			}
			binding.QuarantineToken, binding.QuarantineGeneration, binding.State = "", 0, BindingActive
		}
		layout := layoutFor(binding, request.Generation)
		if err = layout.Validate(); err != nil {
			return "", binding, err
		}
		if err = executor.host.EnsureDirectories(ctx, identity, layout); err != nil {
			return "", binding, err
		}
		binding.RootGeneration, binding.State = request.Generation, BindingActive
		return evidence("directories", binding.SiteKey, decimal(request.Generation), decimal(uint64(binding.UID))), binding, nil
	case OperationEnsureLSAPIPool:
		if binding.State != BindingActive && binding.State != BindingSuspended {
			return "", binding, ErrRegistryConflict
		}
		if binding.RootGeneration != request.Generation {
			return "", binding, ErrRegistryConflict
		}
		binary, resolveErr := executor.php.Resolve(request.PHPProfile)
		if resolveErr != nil {
			return "", binding, resolveErr
		}
		spec := poolSpec(binding, request, executor.edition, binary)
		unit, renderErr := spec.RenderSystemdUnit()
		if renderErr != nil {
			return "", binding, renderErr
		}
		if err = executor.host.InstallLSAPI(ctx, spec, unit); err != nil {
			return "", binding, err
		}
		if err = executor.host.StartLSAPI(ctx, spec); err != nil {
			return "", binding, err
		}
		binding.PoolGeneration, binding.State = request.Generation, BindingActive
		binding.InstalledPools = addGeneration(binding.InstalledPools, request.Generation)
		return evidence("lsapi", string(executor.edition), spec.UnitName(), spec.SocketPath(), binary, digest("cyberpanel:siteops:unit:v1", unit)), binding, nil
	case OperationWriteHealth:
		if binding.State != BindingActive && binding.State != BindingSuspended {
			return "", binding, ErrRegistryConflict
		}
		if binding.RootGeneration != request.Generation {
			return "", binding, ErrRegistryConflict
		}
		body := []byte("panel-health-v1 " + request.AttestationDigest + "\n")
		if err = executor.host.WriteHealth(ctx, identity, request.Generation, body); err != nil {
			return "", binding, err
		}
		return evidence("health", binding.SiteKey, decimal(request.Generation), request.AttestationDigest, digest("cyberpanel:siteops:health:v1", body)), binding, nil
	case OperationSuspend:
		if binding.State == BindingTombstoned || binding.State == BindingDeleted || binding.State == BindingQuarantined {
			return "", binding, ErrRegistryConflict
		}
		if binding.PoolGeneration != 0 {
			spec := poolSpec(binding, request, executor.edition, lifecyclePHPBinary)
			spec.Generation, spec.ProcessProfile.Generation = binding.PoolGeneration, binding.PoolGeneration
			if err = executor.host.StopLSAPI(ctx, spec); err != nil {
				return "", binding, err
			}
		}
		if err = executor.host.DisableIdentity(ctx, identity); err != nil {
			return "", binding, err
		}
		binding.State = BindingSuspended
		return evidence("suspend", binding.SiteKey, decimal(request.Generation), decimal(binding.PoolGeneration)), binding, nil
	case OperationQuarantine:
		if binding.State == BindingTombstoned || binding.State == BindingDeleted {
			return "", binding, ErrRegistryConflict
		}
		if binding.State == BindingQuarantined {
			return evidence("quarantine", binding.SiteKey, binding.QuarantineToken, decimal(request.Generation)), binding, nil
		}
		if err = executor.stopGenerationPool(ctx, request, binding, request.Generation); err != nil {
			return "", binding, err
		}
		token := quarantineToken(binding, request.Generation)
		if err = executor.host.Quarantine(ctx, identity, request.Generation, token); err != nil {
			return "", binding, err
		}
		if err = executor.host.DisableIdentity(ctx, identity); err != nil {
			return "", binding, err
		}
		binding.State, binding.QuarantineToken, binding.QuarantineGeneration = BindingQuarantined, token, request.Generation
		return evidence("quarantine", binding.SiteKey, token, decimal(request.Generation)), binding, nil
	case OperationPurge:
		if binding.State == BindingDeleted {
			return "", binding, ErrRegistryConflict
		}
		if binding.State == BindingTombstoned {
			return evidence("purge", binding.SiteKey, binding.TombstoneToken, binding.TombstonePurgeAfter.UTC().Format(time.RFC3339Nano)), binding, nil
		}
		if err = executor.removeAllPools(ctx, request, binding); err != nil {
			return "", binding, err
		}
		token := tombstoneToken(binding, request.Generation)
		quarantineGeneration := binding.QuarantineGeneration
		if quarantineGeneration == 0 {
			quarantineGeneration = request.Generation
		}
		if err = executor.host.Tombstone(ctx, identity, quarantineGeneration, binding.QuarantineToken, token); err != nil {
			return "", binding, err
		}
		if err = executor.host.DisableIdentity(ctx, identity); err != nil {
			return "", binding, err
		}
		binding.State, binding.TombstoneToken, binding.TombstonePurgeAfter, binding.QuarantineToken, binding.QuarantineGeneration = BindingTombstoned, token, executor.currentTime().Add(executor.retention), "", 0
		return evidence("purge", binding.SiteKey, token, binding.TombstonePurgeAfter.UTC().Format(time.RFC3339Nano)), binding, nil
	default:
		return "", binding, ErrInvalidRequest
	}
}

func (executor *Executor) stopGenerationPool(ctx context.Context, request Request, binding RuntimeBinding, generation uint64) error {
	if generation == 0 {
		return nil
	}
	found := false
	for _, installed := range binding.InstalledPools {
		if installed == generation {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	spec := poolSpec(binding, request, executor.edition, lifecyclePHPBinary)
	spec.Generation, spec.ProcessProfile.Generation = generation, generation
	return executor.host.StopLSAPI(ctx, spec)
}

func (executor *Executor) removeAllPools(ctx context.Context, request Request, binding RuntimeBinding) error {
	if len(binding.InstalledPools) == 0 {
		return nil
	}
	spec := poolSpec(binding, request, executor.edition, lifecyclePHPBinary)
	var err error
	for _, generation := range binding.InstalledPools {
		spec.Generation, spec.ProcessProfile.Generation = generation, generation
		if err = executor.host.RemoveLSAPI(ctx, spec); err != nil {
			return err
		}
	}
	return nil
}

func (executor *Executor) CollectExpired(ctx context.Context, limit int) (int, error) {
	if executor == nil || nilInterface(executor.registry) || nilInterface(executor.host) {
		return 0, errors.New("siteops executor is not configured")
	}
	bindings, err := executor.registry.ExpiredTombstones(executor.currentTime(), limit)
	if err != nil {
		return 0, err
	}
	collected := 0
	for _, binding := range bindings {
		if err = ctx.Err(); err != nil {
			return collected, err
		}
		unlock := executor.locks.lock(string(binding.RuntimeKey))
		if executor.admission == nil {
			unlock()
			return collected, rebootcontrol.ErrConflict
		}
		digest := rebootcontrol.ExecutionDigest(binding)
		lease, admissionErr := executor.admission.AdmitExecution(ctx, rebootcontrol.ExecutionBinding{Boundary: "siteops-gc", Method: "collect_tombstone", EffectID: binding.TombstoneToken, RequestDigest: digest, Caller: "panel-execd-gc", Resource: rebootcontrol.ExecutionResource(struct {
			Tenant, Site, Runtime string
			Fence                 uint64
		}{binding.TenantID, binding.SiteID, string(binding.RuntimeKey), binding.Fence})})
		if admissionErr != nil {
			unlock()
			return collected, admissionErr
		}
		if len(lease.Cached) != 0 {
			var receipt tombstoneCollectionReceipt
			deleted, found, loadErr := executor.registry.Binding(binding.RuntimeKey)
			if json.Unmarshal(lease.Cached, &receipt) != nil || loadErr != nil || !found || !validTombstoneCollectionReceipt(binding, deleted, receipt) {
				unlock()
				return collected, rebootcontrol.ErrIntegrity
			}
			unlock()
			collected++
			continue
		}
		identity, identityErr := identityFromBinding(binding)
		if identityErr == nil {
			identityErr = executor.host.DeleteTombstone(ctx, identity, binding.TombstoneToken)
		}
		if identityErr == nil {
			identityErr = executor.host.DeleteIdentity(ctx, identity)
		}
		if identityErr == nil {
			identityErr = executor.registry.DeleteBinding(binding.RuntimeKey, binding.Fence, executor.currentTime())
		}
		var receipt tombstoneCollectionReceipt
		if identityErr == nil {
			deleted, found, loadErr := executor.registry.Binding(binding.RuntimeKey)
			if loadErr != nil || !found {
				identityErr = errors.Join(ErrCorruptRegistry, loadErr)
			} else {
				receipt = tombstoneCollectionReceipt{Runtime: string(binding.RuntimeKey), Token: binding.TombstoneToken, Fence: binding.Fence, RequestDigest: digest, DeletedDigest: rebootcontrol.ExecutionDigest(deleted)}
				if !validTombstoneCollectionReceipt(binding, deleted, receipt) {
					identityErr = ErrCorruptRegistry
				}
			}
		}
		settleErr := rebootcontrol.SettleExecution(executor.admission, lease, identityErr == nil, receipt)
		unlock()
		if identityErr != nil {
			return collected, identityErr
		}
		if settleErr != nil {
			return collected, settleErr
		}
		collected++
	}
	return collected, nil
}

func validTombstoneCollectionReceipt(before, after RuntimeBinding, receipt tombstoneCollectionReceipt) bool {
	return after.State == BindingDeleted && after.RuntimeKey == before.RuntimeKey && after.TenantID == before.TenantID && after.SiteID == before.SiteID && after.SiteKey == before.SiteKey && after.UID == before.UID && after.GID == before.GID && after.Fence == before.Fence && after.TombstoneToken == before.TombstoneToken && receipt.Runtime == string(before.RuntimeKey) && receipt.Token == before.TombstoneToken && receipt.Fence == before.Fence && receipt.RequestDigest == rebootcontrol.ExecutionDigest(before) && receipt.DeletedDigest == rebootcontrol.ExecutionDigest(after)
}

func (executor *Executor) success(request Request, evidence string, bindings []provisioning.SiteProcessLimitBinding, now time.Time) Response {
	return Response{Version: ProtocolVersion, RequestID: request.RequestID, Operation: request.Operation, EffectKey: request.EffectKey, RuntimeKey: request.RuntimeKey, Generation: request.Generation, Succeeded: true, EvidenceDigest: evidence, AttestationDigest: request.AttestationDigest, LifecycleOperation: lifecycleOperation(request.Operation), LimitBindings: bindings, CompletedAt: now.UTC()}
}

func (executor *Executor) failure(request Request, cause error) Response {
	return Response{Version: ProtocolVersion, RequestID: request.RequestID, Operation: request.Operation, EffectKey: request.EffectKey, RuntimeKey: request.RuntimeKey, Generation: request.Generation, Succeeded: false, ErrorCode: errorCode(cause), CompletedAt: executor.currentTime()}
}

func quarantineToken(binding RuntimeBinding, generation uint64) string {
	return binding.SiteKey + "-q-g" + decimal(generation)
}
func tombstoneToken(binding RuntimeBinding, generation uint64) string {
	return binding.SiteKey + "-t-g" + decimal(generation) + "-" + string(binding.RuntimeKey)[5:17]
}

func (executor *Executor) observeLimitBindings(ctx context.Context, request Request, binding RuntimeBinding) ([]provisioning.SiteProcessLimitBinding, error) {
	if request.Operation != OperationEnsureLSAPIPool {
		return nil, nil
	}
	if binding.Fence != request.Generation || binding.RootGeneration != request.Generation || binding.PoolGeneration != request.Generation {
		return nil, ErrFenced
	}
	spec := poolSpec(binding, request, executor.edition, lifecyclePHPBinary)
	observation, err := executor.host.ProbeLSAPIResources(ctx, spec)
	if err != nil {
		return nil, err
	}
	if observation.Generation != request.Generation {
		return nil, ErrFenced
	}
	profile, observedAt := request.SiteProcessProfile, executor.currentTime()
	bindings := []provisioning.SiteProcessLimitBinding{
		limitBinding(profile.Generation, provisioning.SiteProcessCPUQuota, profile.CPUQuotaPerSecondUSec, observation.CPUQuota, observedAt),
		limitBinding(profile.Generation, provisioning.SiteProcessCPUWeight, profile.CPUWeight, observation.CPUWeight, observedAt),
		limitBinding(profile.Generation, provisioning.SiteProcessMemoryHigh, profile.MemoryHighBytes, observation.MemoryHigh, observedAt),
		limitBinding(profile.Generation, provisioning.SiteProcessMemoryMax, profile.MemoryMaxBytes, observation.MemoryMax, observedAt),
		limitBinding(profile.Generation, provisioning.SiteProcessTasksMax, profile.TasksMax, observation.TasksMax, observedAt),
		limitBinding(profile.Generation, provisioning.SiteProcessIOReadBPS, profile.IOReadBytesPerSecond, observation.IOReadBPS, observedAt),
		limitBinding(profile.Generation, provisioning.SiteProcessIOWriteBPS, profile.IOWriteBytesPerSecond, observation.IOWriteBPS, observedAt),
		limitBinding(profile.Generation, provisioning.SiteProcessIOReadIOPS, profile.IOReadOperationsPerSec, observation.IOReadIOPS, observedAt),
		limitBinding(profile.Generation, provisioning.SiteProcessIOWriteIOPS, profile.IOWriteOperationsPerSec, observation.IOWriteIOPS, observedAt),
	}
	return bindings, nil
}

func limitBinding(generation uint64, dimension provisioning.SiteProcessLimitDimension, requested uint64, observed observedProcessLimit, observedAt time.Time) provisioning.SiteProcessLimitBinding {
	binding := provisioning.SiteProcessLimitBinding{Generation: generation, Scope: "site_processes", Dimension: dimension, Adapter: "systemd_cgroup_v2", RequestedValue: requested, EffectiveValue: observed.Value, EffectiveKnown: observed.Known, EffectiveUnlimited: observed.Unlimited, Device: observed.Device, ObservedAt: observedAt}
	switch {
	case !observed.Supported || !observed.Known:
		binding.State, binding.Observation, binding.EffectiveKnown, binding.EffectiveUnlimited, binding.EffectiveValue = provisioning.ResourceLimitUnsupported, "controller_or_device_unavailable", false, false, 0
	case requested == 0:
		binding.State = provisioning.ResourceLimitAccountedOnly
		if observed.Unlimited {
			binding.Observation = "accounting_enabled_unlimited"
		} else {
			binding.Observation = "inherited_limit_observed"
		}
	case !observed.Unlimited && observed.Value == requested:
		binding.State, binding.Observation = provisioning.ResourceLimitEnforced, "exact_live_value"
	default:
		binding.State, binding.Observation = provisioning.ResourceLimitAccountedOnly, "live_value_mismatch"
	}
	return binding
}

func addGeneration(values []uint64, generation uint64) []uint64 {
	set := make(map[uint64]struct{}, len(values)+1)
	for _, value := range values {
		if value != 0 {
			set[value] = struct{}{}
		}
	}
	set[generation] = struct{}{}
	result := make([]uint64, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

type keyedLocks struct {
	mu     sync.Mutex
	values map[string]*keyLock
}
type keyLock struct {
	mu    sync.Mutex
	users int
}

func (locks *keyedLocks) lock(key string) func() {
	locks.mu.Lock()
	if locks.values == nil {
		locks.values = map[string]*keyLock{}
	}
	value := locks.values[key]
	if value == nil {
		value = &keyLock{}
		locks.values[key] = value
	}
	value.users++
	locks.mu.Unlock()
	value.mu.Lock()
	return func() {
		value.mu.Unlock()
		locks.mu.Lock()
		value.users--
		if value.users == 0 {
			delete(locks.values, key)
		}
		locks.mu.Unlock()
	}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func receiptFromResponse(request Request, response Response) (any, error) {
	if !response.Succeeded {
		return nil, joinError(response.ErrorCode)
	}
	switch request.Operation {
	case OperationEnsureIdentity:
		return provisioning.IdentityReceipt{EffectKey: response.EffectKey, RuntimeKey: response.RuntimeKey, Generation: response.Generation, EvidenceDigest: response.EvidenceDigest}, nil
	case OperationEnsureDirectories:
		return provisioning.DirectoryReceipt{EffectKey: response.EffectKey, RuntimeKey: response.RuntimeKey, Generation: response.Generation, EvidenceDigest: response.EvidenceDigest}, nil
	case OperationEnsureLSAPIPool:
		return provisioning.LSAPIPoolReceipt{EffectKey: response.EffectKey, RuntimeKey: response.RuntimeKey, Generation: response.Generation, EvidenceDigest: response.EvidenceDigest, LimitBindings: append([]provisioning.SiteProcessLimitBinding(nil), response.LimitBindings...)}, nil
	case OperationWriteHealth:
		return provisioning.HealthReceipt{EffectKey: response.EffectKey, RuntimeKey: response.RuntimeKey, Generation: response.Generation, AttestationDigest: response.AttestationDigest, EvidenceDigest: response.EvidenceDigest}, nil
	case OperationSuspend, OperationQuarantine, OperationPurge:
		return provisioning.LifecycleReceipt{EffectKey: response.EffectKey, RuntimeKey: response.RuntimeKey, Generation: response.Generation, Operation: response.LifecycleOperation, EvidenceDigest: response.EvidenceDigest}, nil
	default:
		return nil, fmt.Errorf("unsupported siteops receipt")
	}
}
