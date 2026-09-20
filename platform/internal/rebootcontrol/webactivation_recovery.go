package rebootcontrol

import "context"

type InitialWebActivationRecovery interface {
	RecoverInitialWebActivation(context.Context, ExecutionBinding, string) (ExecutionLease, error)
}

type RestoredWebActivationRecovery interface {
	RecoverRestoredWebActivation(context.Context, ExecutionBinding, string) (ExecutionLease, error)
}

// The broker verifies the exact restored master and live previous-generation
// attestation before requesting a new lease for the same replacement.
func (store *SQLExecutionAdmission) RecoverRestoredWebActivation(ctx context.Context, binding ExecutionBinding, evidence string) (ExecutionLease, error) {
	return store.RecoverInitialWebActivation(ctx, binding, evidence)
}

// Only the trusted activation broker supplies evidence, after observing an
// exact initial attempt, stopped native engine and absent current generation.
// The existing recovery transaction archives the old attempt and preserves
// binding, epoch, drain-gate and lease fencing requirements.
func (store *SQLExecutionAdmission) RecoverInitialWebActivation(ctx context.Context, binding ExecutionBinding, evidence string) (ExecutionLease, error) {
	if binding.Boundary != "webactivation" || binding.Method != "activate" || binding.Caller != "authenticated-panel-core" || binding.Resource != "local:webengine" || binding.Control != nil || !validDigest(evidence) {
		return ExecutionLease{}, ErrInvalid
	}
	return store.admitExecution(ctx, binding, evidence)
}
