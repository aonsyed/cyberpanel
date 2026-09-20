package siteops

import (
	"context"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// InitialIdentityRetryEvidence is read-only. It cannot allocate a UID, advance
// a fence, clear an attempt, or authorize another provisioning operation.
func (registry *DurableRegistry) InitialIdentityRetryEvidence(request Request) (string, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	state, err := registry.loadLocked()
	if err != nil {
		return "", err
	}
	if err = registry.validateState(state); err != nil {
		return "", err
	}
	binding, found := state.Bindings[string(request.RuntimeKey)]
	if !found || request.Operation != OperationEnsureIdentity || binding.Fence != request.Generation || binding.TenantID != request.TenantID || binding.SiteID != request.SiteID || binding.RootGeneration != 0 || binding.PoolGeneration != 0 || len(binding.InstalledPools) != 0 {
		return "", ErrRegistryConflict
	}
	record, found := state.Operations[request.IdempotencyKey()]
	if !found || record.RequestDigest != request.Digest() || record.RuntimeKey != request.RuntimeKey || record.Generation != request.Generation || record.Operation != request.Operation {
		return "", ErrRegistryConflict
	}
	failed := binding.State == BindingAllocated && record.State == OperationFailed && record.ErrorCode == "host_operation"
	completed := binding.State == BindingActive && record.State == OperationComplete && validDigest(record.EvidenceDigest)
	if (!failed && !completed) || record.Attempt == 0 || record.CompletedAt.IsZero() {
		return "", ErrRegistryConflict
	}
	return rebootcontrol.ExecutionDigest(struct {
		Binding RuntimeBinding
		Record  OperationRecord
	}{binding, record}), nil
}

func (executor *Executor) InitialIdentityRetryEvidence(ctx context.Context, request Request) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := request.Validate(executor.currentTime()); err != nil {
		return "", err
	}
	registry, ok := executor.registry.(interface{ InitialIdentityRetryEvidence(Request) (string, error) })
	if !ok {
		return "", ErrRegistryConflict
	}
	unlock := executor.locks.lock(string(request.RuntimeKey))
	defer unlock()
	return registry.InitialIdentityRetryEvidence(request)
}

func (server *Server) admitSiteExecution(ctx context.Context, request Request, binding rebootcontrol.ExecutionBinding) (rebootcontrol.ExecutionLease, error) {
	lease, err := server.Admission.AdmitExecution(ctx, binding)
	if err != rebootcontrol.ErrUnproven || request.Operation != OperationEnsureIdentity {
		return lease, err
	}
	observer, ok := server.Handler.(interface {
		InitialIdentityRetryEvidence(context.Context, Request) (string, error)
	})
	if !ok {
		return lease, err
	}
	recovery, ok := server.Admission.(rebootcontrol.SiteIdentityRecovery)
	if !ok {
		return lease, err
	}
	proof, proofErr := observer.InitialIdentityRetryEvidence(ctx, request)
	if proofErr != nil {
		return rebootcontrol.ExecutionLease{}, proofErr
	}
	return recovery.RecoverSiteIdentity(ctx, binding, proof)
}
