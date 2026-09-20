package lswsruntime

import (
	"context"
	"errors"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
)

func (engine *Engine) bootstrapRunner() (activation.BootstrapEngine, error) {
	if engine == nil {
		return nil, errors.New("bootstrap engine required")
	}
	runner, ok := engine.runner.(activation.BootstrapEngine)
	if !ok || nilInterface(runner) {
		return nil, errors.New("bootstrap runner unavailable")
	}
	return runner, nil
}
func (engine *Engine) CheckStopped(ctx context.Context) error {
	runner, err := engine.bootstrapRunner()
	if err != nil {
		return err
	}
	return runner.CheckStopped(ctx)
}
func (engine *Engine) ValidateInitial(ctx context.Context) error {
	runner, err := engine.bootstrapRunner()
	if err != nil {
		return err
	}
	return runner.ValidateInitial(ctx)
}
func (engine *Engine) StartInitial(ctx context.Context) error {
	runner, err := engine.bootstrapRunner()
	if err != nil {
		return err
	}
	return runner.StartInitial(ctx)
}
func (engine *Engine) StopInitial(ctx context.Context) error {
	runner, err := engine.bootstrapRunner()
	if err != nil {
		return err
	}
	return runner.StopInitial(ctx)
}
