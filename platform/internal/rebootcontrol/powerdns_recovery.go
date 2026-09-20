package rebootcontrol

import "context"

const executionRecoverySchema = `CREATE TABLE IF NOT EXISTS reboot_execution_recoveries(
 effect_id TEXT NOT NULL,attempt_token TEXT NOT NULL,binding_digest TEXT NOT NULL,
 epoch INTEGER NOT NULL,boot_id TEXT NOT NULL,status TEXT NOT NULL,
 admitted_at TEXT NOT NULL,completed_at TEXT NOT NULL,evidence_digest TEXT NOT NULL,
 recovered_at TEXT NOT NULL,PRIMARY KEY(effect_id,attempt_token))`

// RecoverUnappliedPowerDNSStartup is available only to the local startup
// reconciler after it proves the daemon inactive and its managed store empty.
// Evidence is computed by that trusted native observer, never read from an RPC.
// Ordinary admission still refuses every ambiguous effect. Recovery preserves
// the exact binding/epoch and archives the prior attempt in the same transaction.
func (store *SQLExecutionAdmission) RecoverUnappliedPowerDNSStartup(ctx context.Context, binding ExecutionBinding, evidence string) (ExecutionLease, error) {
	if binding.Boundary != "powerdns" || binding.Method != "startup_configuration" || binding.Caller != "panel-execd-startup" || binding.Control != nil || binding.EffectID != binding.RequestDigest || !validDigest(evidence) {
		return ExecutionLease{}, ErrInvalid
	}
	return store.admitExecution(ctx, binding, evidence)
}
