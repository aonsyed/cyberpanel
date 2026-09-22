package apiserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
)

// Reserve the globally keyed repository ID transactionally before filesystem
// effects. A second tenant cannot bind another tenant's repository directory.
func registerBackupRepository(ctx context.Context, services DomainServices, catalog *backup.BackupCatalog, spec backup.RepositorySpec) error {
	if spec.TenantID == "" || spec.MaximumPartBytes < spec.MinimumPartBytes {
		return backup.ErrInvalidBackup
	}
	if err := validateBackupRepositorySpec(&BackupRepositorySpecPayload{Repository: spec}); err != nil {
		return err
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	tx, err := catalog.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT repository_json FROM backup_repositories_v2 WHERE id=?`, spec.Repository.ID).Scan(&existingRaw)
	if err == nil {
		var prior backup.RepositorySpec
		if json.Unmarshal(existingRaw, &prior) != nil {
			return backup.ErrBackupConflict
		}
		if prior.ObjectFormat == "" {
			prior.ObjectFormat = "plaintext-v1"
		}
		if prior.TenantID != spec.TenantID || prior.EncryptionDomain != spec.EncryptionDomain || prior.ObjectFormat != spec.ObjectFormat || prior.Repository.Kind != spec.Repository.Kind || prior.Repository.Endpoint != spec.Repository.Endpoint {
			return backup.ErrBackupConflict
		}
	} else if err != sql.ErrNoRows {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO backup_repositories_v2(id,tenant_id,repository_json) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET repository_json=excluded.repository_json WHERE backup_repositories_v2.tenant_id=excluded.tenant_id`, spec.Repository.ID, spec.TenantID, raw)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return backup.ErrBackupConflict
	}
	if err = prepareBackupRepository(ctx, services, spec); err != nil {
		return err
	}
	return tx.Commit()
}

func prepareBackupRepository(ctx context.Context, services DomainServices, spec backup.RepositorySpec) error {
	if services.BackupWorkflow == nil {
		return ErrUnavailable
	}
	provider, ok := services.BackupWorkflow.Providers[spec.Repository.Kind].(interface {
		PrepareRepository(context.Context, backup.RepositorySpec) error
	})
	if !ok {
		return ErrUnavailable
	}
	return provider.PrepareRepository(ctx, spec)
}
