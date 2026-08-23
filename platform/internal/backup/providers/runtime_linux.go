//go:build linux

package providers

import (
	"database/sql"
	"errors"
	"time"
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
