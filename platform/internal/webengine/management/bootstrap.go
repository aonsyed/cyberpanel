package management

import (
	"context"
	"errors"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

// EnsureInitialConfiguration journals the first complete canonical snapshot.
// An existing applied state is never reset or silently adopted here.
func (runtime *Runtime) EnsureInitialConfiguration(ctx context.Context) error {
	if runtime == nil || runtime.catalog == nil || nilRuntimeInterface(runtime.activator) || ctx == nil {
		return ErrInvalid
	}
	runtime.activation.Lock()
	defer runtime.activation.Unlock()
	state, err := runtime.catalog.NodeState(ctx)
	if err != nil {
		return err
	}
	if state.AppliedDigest != "" {
		return nil
	}
	if state.SnapshotGeneration != 0 {
		return ErrConflict
	}
	const effectID = "bootstrap-webengine-v1"
	prepared, err := runtime.catalog.NodeConfigurationChange(ctx, effectID)
	if errors.Is(err, catalog.ErrChangeMissing) {
		next := state.Configuration
		next.Revision++
		next.Engine.Tuning.Generation++
		prepared, err = runtime.catalog.PrepareNodeConfiguration(ctx, effectID, next, state.Configuration.Revision)
	}
	if err != nil {
		return err
	}
	if prepared.Finalized || prepared.Plan.SnapshotGeneration != 1 {
		return ErrConflict
	}
	composed, err := composer.Compose(prepared.Plan)
	if err != nil {
		return err
	}
	renderer := runtime.renderers[composed.Desired.Engine.Edition]
	if renderer == nil {
		return ErrUnsupported
	}
	request := native.RenderRequest{Desired: composed.Desired, Snapshot: composed.Snapshot}
	generation, err := renderer.Render(ctx, request)
	if err != nil {
		return err
	}
	receipt, err := runtime.activator.ApplyVerified(ctx, request, generation.ContentDigest)
	if err != nil || receipt.Status != activation.Applied || !receipt.Confirmed || receipt.Digest != generation.ContentDigest {
		return errors.Join(ErrAmbiguous, err)
	}
	return runtime.catalog.FinalizeNodeConfiguration(ctx, prepared, receipt.Digest)
}
