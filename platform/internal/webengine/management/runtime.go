package management

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

// VerifiedActivator is the privileged desired-state boundary used by the
// production web-engine runtime. The privileged side independently renders
// the request and refuses a digest mismatch before staging native files.
type VerifiedActivator interface {
	ApplyVerified(context.Context, native.RenderRequest, string) (activation.Receipt, error)
}

// Runtime adapts management commands to the canonical catalog and immutable
// activation pipeline. Package acquisition and licensing are deliberately not
// implemented here: those require their own signed-catalog and secret brokers.
type Runtime struct {
	catalog    *catalog.SQLCatalog
	activator  VerifiedActivator
	renderers  map[webengine.Edition]native.Renderer
	lifecycle  *LinuxManagementClient
	activation sync.Mutex
	now        func() time.Time
}

func NewRuntime(catalogValue *catalog.SQLCatalog, activator VerifiedActivator, renderers ...native.Renderer) (*Runtime, error) {
	if catalogValue == nil || nilRuntimeInterface(activator) {
		return nil, ErrInvalid
	}
	byEdition := make(map[webengine.Edition]native.Renderer, len(renderers))
	for _, renderer := range renderers {
		if nilRuntimeInterface(renderer) || renderer.Edition() != webengine.EditionOpenLiteSpeed && renderer.Edition() != webengine.EditionLiteSpeedEnterprise || byEdition[renderer.Edition()] != nil {
			return nil, ErrInvalid
		}
		byEdition[renderer.Edition()] = renderer
	}
	if len(byEdition) != 2 {
		return nil, ErrInvalid
	}
	lifecycle, err := NewLocalLinuxManagementClient()
	if err != nil { return nil, err }
	return &Runtime{catalog: catalogValue, activator: activator, renderers: byEdition, lifecycle: lifecycle, now: time.Now}, nil
}

func (*Runtime) ManagementCapabilities() Capabilities {
	return Capabilities{Inspect: true, Install: true, Convert: false, Upgrade: true, Remove: true, RefreshLicense: true, InstallPHP: true, Tune: true}
}

func DefaultGlobalTuning() GlobalTuning {
	return GlobalTuning{
		WorkerProcesses: 1, MaxConnections: 10_000, MaxTLSConnections: 10_000,
		ConnectionTimeout: 300 * time.Second, KeepAliveTimeout: 5 * time.Second, KeepAliveRequests: 1_000,
		MemoryCacheBytes: 64 << 20, Compression: true, CompressionLevel: 6, Brotli: false, Generation: 1,
	}
}

func DesiredTuning(value GlobalTuning) (webengine.WebEngineTuning, error) {
	return canonicalTuning(value)
}

func ManagementTuning(value webengine.WebEngineTuning) GlobalTuning {
	return GlobalTuning{
		WorkerProcesses: value.WorkerProcesses, MaxConnections: value.MaxConnections, MaxTLSConnections: value.MaxTLSConnections,
		ConnectionTimeout: time.Duration(value.ConnectionTimeoutSeconds) * time.Second,
		KeepAliveTimeout: time.Duration(value.KeepAliveTimeoutSeconds) * time.Second,
		KeepAliveRequests: value.KeepAliveRequests, MemoryCacheBytes: value.MemoryCacheBytes,
		Compression: value.Compression, CompressionLevel: value.CompressionLevel, Brotli: value.Brotli, Generation: value.Generation,
	}
}

func canonicalTuning(value GlobalTuning) (webengine.WebEngineTuning, error) {
	if value.Brotli {
		return webengine.WebEngineTuning{}, ErrUnsupported
	}
	if value.Generation == 0 || value.WorkerProcesses == 0 || value.WorkerProcesses > 1024 ||
		value.MaxConnections == 0 || value.MaxConnections > 10_000_000 || value.MaxTLSConnections == 0 || value.MaxTLSConnections > value.MaxConnections ||
		value.ConnectionTimeout < time.Second || value.ConnectionTimeout > time.Hour || value.ConnectionTimeout%time.Second != 0 ||
		value.KeepAliveTimeout < time.Second || value.KeepAliveTimeout > time.Hour || value.KeepAliveTimeout%time.Second != 0 ||
		value.KeepAliveRequests == 0 || value.KeepAliveRequests > 100_000 ||
		value.MemoryCacheBytes < 1<<20 || value.MemoryCacheBytes > 1<<40 || value.MemoryCacheBytes%(1<<20) != 0 ||
		value.Compression && (value.CompressionLevel == 0 || value.CompressionLevel > 9) ||
		!value.Compression && value.CompressionLevel != 0 {
		return webengine.WebEngineTuning{}, ErrInvalid
	}
	return webengine.WebEngineTuning{
		WorkerProcesses: value.WorkerProcesses, MaxConnections: value.MaxConnections, MaxTLSConnections: value.MaxTLSConnections,
		ConnectionTimeoutSeconds: uint32(value.ConnectionTimeout / time.Second),
		KeepAliveTimeoutSeconds: uint32(value.KeepAliveTimeout / time.Second), KeepAliveRequests: value.KeepAliveRequests,
		MemoryCacheBytes: value.MemoryCacheBytes, Compression: value.Compression, CompressionLevel: value.CompressionLevel,
		Brotli: value.Brotli, Generation: value.Generation,
	}, nil
}

func (runtime *Runtime) Resolve(ctx context.Context, request ArtifactRequest) (ArtifactPlan, error) {
	if runtime == nil || runtime.lifecycle == nil { return ArtifactPlan{}, ErrInvalid }
	return resolveLocalArtifact(ctx, request, false)
}

func (runtime *Runtime) BuildTarget(ctx context.Context, edition webengine.Edition, snapshotGeneration uint64) (native.ConfigGeneration, error) {
	if runtime == nil || runtime.catalog == nil || nilRuntimeInterface(runtime.activator) {
		return native.ConfigGeneration{}, ErrInvalid
	}
	plan, err := runtime.catalog.PlanForEdition(ctx, edition, snapshotGeneration)
	if err != nil {
		return native.ConfigGeneration{}, err
	}
	composed, err := composer.Compose(plan)
	if err != nil {
		return native.ConfigGeneration{}, err
	}
	renderer := runtime.renderers[edition]
	if renderer == nil {
		return native.ConfigGeneration{}, ErrUnsupported
	}
	return renderer.Render(ctx, native.RenderRequest{Desired: composed.Desired, Snapshot: composed.Snapshot})
}

func (runtime *Runtime) Inspect(ctx context.Context, edition webengine.Edition) (Installation, error) {
	if runtime == nil || runtime.catalog == nil || runtime.lifecycle == nil {
		return Installation{}, ErrInvalid
	}
	observed, err := runtime.lifecycle.Inspect(ctx, edition)
	if err != nil { return Installation{}, err }
	state, err := runtime.catalog.NodeState(ctx)
	if err != nil {
		return Installation{}, err
	}
	if edition != state.Configuration.Engine.Edition {
		return Installation{}, ErrNotFound
	}
	observed.ID,observed.Edition,observed.State="node-webengine",edition,StateActive
	observed.Generation,observed.ActiveConfigDigest=state.Configuration.Engine.Tuning.Generation,state.AppliedDigest
	if observed.InstalledAt.IsZero(){observed.InstalledAt=state.UpdatedAt};observed.UpdatedAt=state.UpdatedAt
	return observed, nil
}

func (runtime *Runtime) ApplyGlobalTuning(ctx context.Context, request EffectRequest, tuning GlobalTuning) (EffectReceipt, error) {
	receipt := EffectReceipt{EffectID: request.EffectID, PlanDigest: request.PlanDigest, Generation: tuning.Generation, Fence: request.Fence}
	if runtime == nil || runtime.catalog == nil || nilRuntimeInterface(runtime.activator) || ctx == nil ||
		!validEffectToken(request.EffectID) || request.ExpectedGeneration == 0 || request.Fence != request.ExpectedGeneration+1 ||
		!validSHA256(request.PlanDigest) || request.PlanDigest != digestJSON(tuning) || !validSHA256(request.CommitAuthorizationDigest) ||
		tuning.Generation != request.ExpectedGeneration+1 {
		return receipt, ErrInvalid
	}
	target, err := canonicalTuning(tuning)
	if err != nil {
		return receipt, err
	}
	runtime.activation.Lock()
	defer runtime.activation.Unlock()
	prepared, lookupErr := runtime.catalog.NodeConfigurationChange(ctx, request.EffectID)
	if lookupErr == nil {
		if prepared.Configuration.Engine.Tuning != target || prepared.Configuration.Engine.Edition != prepared.Plan.Engine.Edition {
			return receipt, ErrConflict
		}
	} else if !errors.Is(lookupErr, catalog.ErrChangeMissing) {
		return receipt, mapCatalogError(lookupErr)
	} else {
		state, stateErr := runtime.catalog.NodeState(ctx)
		if stateErr != nil {
			return receipt, stateErr
		}
		if state.Configuration.Engine.Tuning.Generation != request.ExpectedGeneration {
			return receipt, ErrConflict
		}
		if state.Configuration.Engine.Edition == webengine.EditionLiteSpeedEnterprise &&
			target.WorkerProcesses != state.Configuration.Engine.Tuning.WorkerProcesses {
			return receipt, ErrLicense
		}
		next := state.Configuration
		next.Revision++
		next.Engine.Tuning = target
		prepared, err = runtime.catalog.PrepareNodeConfiguration(ctx, request.EffectID, next, state.Configuration.Revision)
		if err != nil {
			return receipt, mapCatalogError(err)
		}
	}
	if prepared.Finalized {
		if !validSHA256(prepared.ActivationDigest) {
			return receipt, ErrAmbiguous
		}
		evidence := prepared.ActivationDigest
		if current, currentErr := runtime.catalog.NodeState(ctx); currentErr == nil && current.Configuration.Engine.Tuning == target && validSHA256(current.AppliedDigest) {
			evidence = current.AppliedDigest
		}
		receipt.Outcome, receipt.EvidenceDigest, receipt.ObservedAt = "confirmed", evidence, runtime.now().UTC()
		return receipt, nil
	}
	composed, err := composer.Compose(prepared.Plan)
	if err != nil {
		_ = runtime.catalog.RejectNodeConfiguration(ctx, prepared)
		return receipt, err
	}
	renderer := runtime.renderers[composed.Desired.Engine.Edition]
	if renderer == nil {
		_ = runtime.catalog.RejectNodeConfiguration(ctx, prepared)
		return receipt, ErrUnsupported
	}
	renderRequest := native.RenderRequest{Desired: composed.Desired, Snapshot: composed.Snapshot}
	generation, err := renderer.Render(ctx, renderRequest)
	if err != nil {
		_ = runtime.catalog.RejectNodeConfiguration(ctx, prepared)
		return receipt, err
	}
	activated, activationErr := runtime.activator.ApplyVerified(ctx, renderRequest, generation.ContentDigest)
	if activated.Status == activation.RolledBack {
		_ = runtime.catalog.RejectNodeConfiguration(ctx, prepared)
		return receipt, errors.Join(ErrAmbiguous, activationErr)
	}
	if activationErr != nil || activated.Status != activation.Applied || !activated.Confirmed || activated.Digest != generation.ContentDigest {
		return receipt, errors.Join(ErrAmbiguous, activationErr)
	}
	if err = runtime.catalog.FinalizeNodeConfiguration(ctx, prepared, activated.Digest); err != nil {
		return receipt, errors.Join(ErrAmbiguous, err)
	}
	receipt.Outcome, receipt.EvidenceDigest, receipt.ObservedAt = "confirmed", activated.Digest, runtime.now().UTC()
	return receipt, nil
}

func (runtime *Runtime) Install(ctx context.Context, request EffectRequest, plan ArtifactPlan) (EffectReceipt, error) {
	if runtime==nil||runtime.lifecycle==nil{return EffectReceipt{},ErrInvalid};return runtime.lifecycle.Install(ctx,request,plan)
}
func (runtime *Runtime) ApplyLicense(ctx context.Context, request EffectRequest, license LicenseRequest) (LicenseStatus, error) {
	if runtime==nil||runtime.lifecycle==nil{return LicenseStatus{},ErrInvalid};return runtime.lifecycle.ApplyLicense(ctx,request,license)
}
func (runtime *Runtime) RefreshLicense(ctx context.Context, request EffectRequest) (LicenseStatus, error) {
	if runtime==nil||runtime.lifecycle==nil{return LicenseStatus{},ErrInvalid};return runtime.lifecycle.RefreshLicense(ctx,request)
}
func (runtime *Runtime) StageGeneration(ctx context.Context, request EffectRequest, generation native.ConfigGeneration) (EffectReceipt, error) {
	input, err := runtime.generationInput(ctx, request, generation)
	if err != nil { return EffectReceipt{}, err }
	var result EffectReceipt
	err = runtime.lifecycle.call(ctx, LinuxManagementStage, input, &result)
	return result, err
}
func (runtime *Runtime) ValidateGeneration(ctx context.Context, request EffectRequest, generation native.ConfigGeneration) (ValidationReceipt, error) {
	input, err := runtime.generationInput(ctx, request, generation)
	if err != nil { return ValidationReceipt{}, err }
	var result ValidationReceipt
	err = runtime.lifecycle.call(ctx, LinuxManagementValidate, input, &result)
	return result, err
}
func (runtime *Runtime) ShadowProbe(ctx context.Context, request EffectRequest, generation native.ConfigGeneration) (ProbeReceipt, error) {
	input, err := runtime.generationInput(ctx, request, generation)
	if err != nil { return ProbeReceipt{}, err }
	var result ProbeReceipt
	err = runtime.lifecycle.call(ctx, LinuxManagementShadow, input, &result)
	return result, err
}
func (runtime *Runtime) SwitchService(ctx context.Context, request SwitchRequest) (SwitchReceipt, error) {
	if runtime == nil || runtime.lifecycle == nil { return SwitchReceipt{}, ErrInvalid }
	var result SwitchReceipt
	err := runtime.lifecycle.call(ctx, LinuxManagementSwitch, request, &result)
	return result, err
}
func (runtime *Runtime) ConfirmService(ctx context.Context, request SwitchReceipt) (ProbeReceipt, error) {
	if runtime == nil || runtime.lifecycle == nil { return ProbeReceipt{}, ErrInvalid }
	var result ProbeReceipt
	err := runtime.lifecycle.call(ctx, LinuxManagementConfirm, request, &result)
	return result, err
}
func (runtime *Runtime) RestoreService(ctx context.Context, request SwitchReceipt) (ProbeReceipt, error) {
	if runtime == nil || runtime.lifecycle == nil { return ProbeReceipt{}, ErrInvalid }
	var result ProbeReceipt
	err := runtime.lifecycle.call(ctx, LinuxManagementRestore, request, &result)
	return result, err
}

func (runtime *Runtime) generationInput(ctx context.Context, request EffectRequest, generation native.ConfigGeneration) (lifecycleGenerationInput, error) {
	if runtime == nil || runtime.catalog == nil || runtime.lifecycle == nil || ctx == nil { return lifecycleGenerationInput{}, ErrInvalid }
	plan, err := runtime.catalog.PlanForEdition(ctx, generation.Edition, generation.SnapshotGeneration)
	if err != nil { return lifecycleGenerationInput{}, err }
	composed, err := composer.Compose(plan)
	if err != nil { return lifecycleGenerationInput{}, err }
	render := native.RenderRequest{Desired: composed.Desired, Snapshot: composed.Snapshot}
	renderer := runtime.renderers[generation.Edition]
	if renderer == nil { return lifecycleGenerationInput{}, ErrInvalid }
	canonical, err := renderer.Render(ctx, render)
	if err != nil || canonical.ContentDigest != generation.ContentDigest { return lifecycleGenerationInput{}, ErrConflict }
	return lifecycleGenerationInput{Request: request, Render: render, ConfigDigest: canonical.ContentDigest}, nil
}

// ProbeCandidate never activates a public route. The broker renders this typed
// candidate independently and executes it only in private Linux namespaces.
func (runtime *Runtime) ProbeCandidate(ctx context.Context, request EffectRequest, render native.RenderRequest) (ProbeReceipt, error) {
	return runtime.probeRender(ctx, request, render, LinuxManagementShadow)
}

// ProbeActive proves the supplied site's PHP/TLS paths on the current live
// listeners. The subset digest and installed master digest are both bound into
// evidence; a subset is not represented as the whole active configuration.
func (runtime *Runtime) ProbeActive(ctx context.Context, request EffectRequest, render native.RenderRequest) (ProbeReceipt, error) {
	return runtime.probeRender(ctx, request, render, LinuxManagementActiveProbe)
}

func (runtime *Runtime) probeRender(ctx context.Context, request EffectRequest, render native.RenderRequest, operation LinuxManagementOperation) (ProbeReceipt, error) {
	if runtime == nil || runtime.lifecycle == nil || ctx == nil { return ProbeReceipt{}, ErrInvalid }
	renderer := runtime.renderers[render.Desired.Engine.Edition]
	if renderer == nil { return ProbeReceipt{}, ErrInvalid }
	generation, err := renderer.Render(ctx, render)
	if err != nil { return ProbeReceipt{}, err }
	input := lifecycleGenerationInput{Request: request, Render: render, ConfigDigest: generation.ContentDigest}
	var result ProbeReceipt
	err = runtime.lifecycle.call(ctx, operation, input, &result)
	return result, err
}
func (runtime *Runtime) Remove(ctx context.Context, request EffectRequest, edition webengine.Edition) (EffectReceipt, error) {
	if runtime==nil||runtime.lifecycle==nil{return EffectReceipt{},ErrInvalid};return runtime.lifecycle.Remove(ctx,request,edition)
}
func (runtime *Runtime) InstallPHP(ctx context.Context, request EffectRequest, plan PHPArtifactPlan) (EffectReceipt, error) {
	if runtime==nil||runtime.lifecycle==nil{return EffectReceipt{},ErrInvalid};return runtime.lifecycle.InstallPHP(ctx,request,plan)
}
func (runtime *Runtime) ApplyPHPProfile(ctx context.Context, request EffectRequest, profile PHPProfile) (EffectReceipt, error) {
	if runtime==nil||runtime.lifecycle==nil{return EffectReceipt{},ErrInvalid};return runtime.lifecycle.ApplyPHPProfile(ctx,request,profile)
}
func (*Runtime) RestartPHPPool(context.Context, EffectRequest, string) (EffectReceipt, error) {
	return EffectReceipt{}, ErrUnsupported
}

func (runtime *Runtime) RollbackPHP(ctx context.Context, request EffectRequest, plan PHPArtifactPlan, previous *PHPProfile) (EffectReceipt, error) {
	if runtime==nil||runtime.lifecycle==nil{return EffectReceipt{},ErrInvalid};return runtime.lifecycle.RollbackPHP(ctx,request,plan,previous)
}

func(runtime *Runtime)Upgrade(ctx context.Context,request EffectRequest,plan ArtifactPlan)(EffectReceipt,error){if runtime==nil||runtime.lifecycle==nil{return EffectReceipt{},ErrInvalid};return runtime.lifecycle.Upgrade(ctx,request,plan)}
func(runtime *Runtime)ConvertEdition(ctx context.Context,request EffectRequest,plan ArtifactPlan,generation native.ConfigGeneration,window time.Duration)(SwitchReceipt,error){if runtime==nil||runtime.lifecycle==nil{return SwitchReceipt{},ErrInvalid};return runtime.lifecycle.ConvertEdition(ctx,request,plan,generation,window)}

func validEffectToken(value string) bool {
	if value == "" || len(value) > 160 {
		return false
	}
	for _, character := range value {
		if character != '-' && character != '_' && character != '.' &&
			(character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func nilRuntimeInterface(value any) bool {
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

func mapCatalogError(err error) error {
	switch {
	case errors.Is(err, catalog.ErrChangeBusy), errors.Is(err, catalog.ErrChangeClosed):
		return errors.Join(ErrConflict, err)
	case errors.Is(err, catalog.ErrChangeMissing):
		return errors.Join(ErrNotFound, err)
	default:
		return err
	}
}

var _ ArtifactCatalog = (*Runtime)(nil)
var _ TargetRenderer = (*Runtime)(nil)
var _ Executor = (*Runtime)(nil)
var _ CapabilityProvider = (*Runtime)(nil)
var _ LifecycleExecutor = (*Runtime)(nil)
