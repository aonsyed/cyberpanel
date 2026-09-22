package apiserver

import "github.com/aonsyed/cyberpanel/platform/internal/backup"

// ValidateLocalBackupPolicy keeps console creation and low-level policy writes
// inside the same currently supported native capture boundary.
func ValidateLocalBackupPolicy(policy backup.BackupPolicySpec) error {
	return validateBackupPolicySpec(&BackupPolicySpecPayload{Policy: policy})
}
