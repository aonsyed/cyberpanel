//go:build linux

package main

import (
	"context"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

func (admission *startupMutationAdmission) RecoverSiteIdentity(ctx context.Context, binding rebootcontrol.ExecutionBinding, evidence string) (rebootcontrol.ExecutionLease, error) {
	if admission == nil || admission.delegate == nil {
		return rebootcontrol.ExecutionLease{}, rebootcontrol.ErrConflict
	}
	admission.mu.RLock()
	ready := admission.ready
	admission.mu.RUnlock()
	recovery, ok := admission.delegate.(rebootcontrol.SiteIdentityRecovery)
	if !ready || !ok {
		return rebootcontrol.ExecutionLease{}, rebootcontrol.ErrConflict
	}
	return recovery.RecoverSiteIdentity(ctx, binding, evidence)
}
