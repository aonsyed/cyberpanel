//go:build linux

package providers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/backup"
)

const (
	DefaultLocalRepositoryRoot = "/var/backups/cyberpanel/repositories"
	DefaultCaptureSpoolRoot    = "/var/lib/cyberpanel/backup-spool"
)

// LocalRuntime owns the concrete local provider resources used by panel-core.
// Remote provider kinds remain absent until their credential and transport
// brokers are configured, so the API cannot advertise a provider that would
// only fail after accepting a backup.
type LocalRuntime struct {
	Runtime
	Spool *LocalCaptureSpool
	Local *LocalProvider
}

func NewLocalRuntime(database *sql.DB, now func() time.Time) (*LocalRuntime, error) {
	if database == nil {
		return nil, errors.New("backup runtime database required")
	}
	spool, err := OpenLocalCaptureSpool(DefaultCaptureSpoolRoot)
	if err != nil {
		return nil, err
	}
	local, err := NewLocalProvider(DefaultLocalRepositoryRoot, spool, now)
	if err != nil {
		_ = spool.Close()
		return nil, err
	}
	runtime := NewRuntime(database, ProviderSet{Local: local})
	return &LocalRuntime{Runtime: runtime, Spool: spool, Local: local}, nil
}

// NewLocalRuntimeWithSource keeps capture bytes behind a typed executor
// boundary. The provider receives only content descriptors and a resumable
// reader; it never receives a host path selected by the control process.
func NewLocalRuntimeWithSource(database *sql.DB, source ObjectSource, now func() time.Time) (*LocalRuntime, error) {
	if database == nil || source == nil {
		return nil, errors.New("backup runtime database and object source required")
	}
	local, err := NewLocalProvider(DefaultLocalRepositoryRoot, source, now)
	if err != nil {
		return nil, err
	}
	runtime := NewRuntime(database, ProviderSet{Local: local})
	return &LocalRuntime{Runtime: runtime, Local: local}, nil
}

// ValidateLocalRepositories opens every cataloged local repository through the
// descriptor-safe registry before the API begins accepting backup or restore
// work. The installer protects the service-owned parent; registration creates
// private repository directories there. Legacy root-provisioned roots remain
// readable when their data directories belong to the control service.
func (runtime *LocalRuntime) ValidateLocalRepositories(ctx context.Context) error {
	if runtime == nil || runtime.DB == nil || runtime.Local == nil || runtime.Local.Registry == nil || ctx == nil {
		return errors.New("local backup repository runtime required")
	}
	rows, err := runtime.DB.QueryContext(ctx, `SELECT id,tenant_id,repository_json FROM backup_repositories_v2 ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, tenantID string
		var raw []byte
		if err = rows.Scan(&id, &tenantID, &raw); err != nil {
			return err
		}
		var spec backup.RepositorySpec
		if err = json.Unmarshal(raw, &spec); err != nil {
			return fmt.Errorf("decode backup repository %q: %w", id, err)
		}
		if string(spec.Repository.ID) != id || spec.TenantID != tenantID {
			return fmt.Errorf("backup repository %q catalog scope mismatch: %w", id, ErrInvalid)
		}
		if spec.Repository.Kind != backup.Local {
			continue
		}
		if _, err = runtime.Local.repository(spec); err != nil {
			return fmt.Errorf("open local backup repository %q: %w", id, err)
		}
	}
	return rows.Err()
}

func (runtime *LocalRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	var localErr error
	if runtime.Local != nil {
		localErr = runtime.Local.Close()
	}
	var spoolErr error
	if runtime.Spool != nil {
		spoolErr = runtime.Spool.Close()
	}
	return errors.Join(localErr, spoolErr)
}
