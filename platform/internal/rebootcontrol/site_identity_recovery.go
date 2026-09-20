package rebootcontrol

import "context"

type SiteIdentityRecovery interface {
	RecoverSiteIdentity(context.Context, ExecutionBinding, string) (ExecutionLease, error)
}

// Evidence is supplied by the trusted site executor after matching its durable
// initial-identity record. It authorizes an idempotent retry, not a success claim.
func (store *SQLExecutionAdmission) RecoverSiteIdentity(ctx context.Context, binding ExecutionBinding, evidence string) (ExecutionLease, error) {
	if binding.Boundary != "siteops" || binding.Method != "ensure_identity" || binding.Caller != "authenticated-panel-core" || binding.Control != nil || !validDigest(evidence) {
		return ExecutionLease{}, ErrInvalid
	}
	return store.admitExecution(ctx, binding, evidence)
}
