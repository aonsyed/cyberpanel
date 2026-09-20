package activation

import (
	"context"
	"errors"
)

// BootstrapStore preserves the unadopted vendor master without claiming it
// was a healthy managed generation. Implementations must refuse existing state.
type BootstrapStore interface {
	PrepareBootstrap(context.Context, Receipt) error
	RestoreBootstrap(context.Context, Receipt) error
}

type BootstrapEngine interface {
	CheckStopped(context.Context) error
	ValidateInitial(context.Context) error
	StartInitial(context.Context) error
	StopInitial(context.Context) error
}

// Called only under the ordinary activation/configuration locks, for snapshot
// one with no current receipt. Never fabricates a previous healthy generation.
func (a *Activator) bootstrap(ctx context.Context, candidate Receipt) (Receipt, error) {
	store, ok := a.Store.(BootstrapStore)
	engine, engineOK := a.Engine.(BootstrapEngine)
	if !ok || !engineOK {
		return ambiguousWith(candidate, Receipt{}), errors.New("initial activation is unsupported")
	}
	if err := engine.CheckStopped(ctx); err != nil {
		return ambiguousWith(candidate, Receipt{}), err
	}
	if err := store.PrepareBootstrap(ctx, candidate); err != nil {
		return ambiguousWith(candidate, Receipt{}), err
	}
	err := a.Store.SwapMaster(ctx, candidate)
	if err == nil {
		err = engine.ValidateInitial(ctx)
	}
	if err == nil {
		err = engine.StartInitial(ctx)
	}
	if err == nil {
		err = a.Probe.Check(ctx, candidate)
	}
	if err == nil {
		err = a.Store.Confirm(ctx, candidate)
	}
	if err == nil {
		return applied(candidate, Receipt{}, true, true), nil
	}
	// Do not restore files under a process whose stop could not be proven.
	stopErr := engine.StopInitial(ctx)
	if stopErr != nil {
		return ambiguousWith(candidate, Receipt{}), errors.Join(err, stopErr)
	}
	restoreErr := store.RestoreBootstrap(ctx, candidate)
	return ambiguousWith(candidate, Receipt{}), errors.Join(err, restoreErr)
}
