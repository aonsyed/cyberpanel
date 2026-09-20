//go:build linux

package main

import (
	"context"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

func (admission *startupMutationAdmission) RecoverInitialWebActivation(ctx context.Context, binding rebootcontrol.ExecutionBinding, evidence string) (rebootcontrol.ExecutionLease, error) {
	if admission == nil || admission.delegate == nil {
		return rebootcontrol.ExecutionLease{}, rebootcontrol.ErrConflict
	}
	admission.mu.RLock()
	ready := admission.ready
	admission.mu.RUnlock()
	recovery, ok := admission.delegate.(rebootcontrol.InitialWebActivationRecovery)
	if !ready || !ok {
		return rebootcontrol.ExecutionLease{}, rebootcontrol.ErrConflict
	}
	return recovery.RecoverInitialWebActivation(ctx, binding, evidence)
}

func (admission *startupMutationAdmission) RecoverRestoredWebActivation(ctx context.Context, binding rebootcontrol.ExecutionBinding, evidence string) (rebootcontrol.ExecutionLease, error) {
	if admission == nil || admission.delegate == nil {
		return rebootcontrol.ExecutionLease{}, rebootcontrol.ErrConflict
	}
	admission.mu.RLock()
	ready := admission.ready
	admission.mu.RUnlock()
	recovery, ok := admission.delegate.(rebootcontrol.RestoredWebActivationRecovery)
	if !ready || !ok {
		return rebootcontrol.ExecutionLease{}, rebootcontrol.ErrConflict
	}
	return recovery.RecoverRestoredWebActivation(ctx, binding, evidence)
}
