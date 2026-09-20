//go:build linux

package main

import (
	"context"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// Observe only: root must never initialize or repair the core-owned database.
// Missing bootstrap tables are retryable; malformed schema or store ownership
// still fail closed during validation/recovery.
func startupAdmissionSchemaReady(ctx context.Context, raw *rebootcontrol.SQLExecutionAdmission) error {
	if ctx == nil || raw == nil || raw.DB == nil {
		return rebootcontrol.ErrIntegrity
	}
	if raw.ValidateStore != nil {
		if err := raw.ValidateStore(); err != nil {
			return err
		}
	}
	var count int
	err := raw.DB.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('reboot_admission_gate','reboot_execution_effects','reboot_states')`).Scan(&count)
	if err != nil {
		return err
	}
	if count != 3 {
		return rebootcontrol.ErrConflict
	}
	return nil
}
