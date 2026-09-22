package apiserver

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/backup"
	_ "modernc.org/sqlite"
)

type registrationProvider struct {
	backup.RepositoryProvider
	calls   int
	failure error
}

func (p *registrationProvider) PrepareRepository(context.Context, backup.RepositorySpec) error {
	p.calls++
	return p.failure
}

func TestBackupRegistrationReservesTenantBeforeFilesystemEffects(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	catalog := &backup.BackupCatalog{DB: db}
	if err = catalog.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	provider := &registrationProvider{}
	services := DomainServices{BackupWorkflow: &backup.BackupCoordinator{Providers: map[backup.ProviderKind]backup.RepositoryProvider{backup.Local: provider}}}
	spec := backup.RepositorySpec{Repository: backup.Repository{ID: "shared", Kind: backup.Local, Endpoint: "file:///var/backups/cyberpanel/repositories/shared", CredentialRef: "local"}, TenantID: "first", FailureDomain: "local", EncryptionDomain: "plaintext", ObjectFormat: "plaintext-v1", MaximumConcurrency: 1}
	if err = registerBackupRepository(ctx, services, catalog, spec); err != nil {
		t.Fatal(err)
	}
	legacy := spec
	legacy.ObjectFormat = ""
	if err = catalog.PutRepository(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	beforeAck := provider.calls
	if err = registerBackupRepository(ctx, services, catalog, legacy); err == nil || provider.calls != beforeAck {
		t.Fatal("implicit plaintext registration accepted")
	}
	if err = registerBackupRepository(ctx, services, catalog, spec); err != nil {
		t.Fatal("explicit legacy plaintext acknowledgement", err)
	}
	spec.TenantID = "second"
	if err = registerBackupRepository(ctx, services, catalog, spec); !errors.Is(err, backup.ErrBackupConflict) {
		t.Fatalf("foreign ownership accepted: %v", err)
	}
	if provider.calls != 2 {
		t.Fatal("foreign tenant caused filesystem effects")
	}
	spec.TenantID = "first"
	if err = registerBackupRepository(ctx, services, catalog, spec); err != nil {
		t.Fatal(err)
	}
	provider.failure = errors.New("unsafe repository root")
	changed := spec
	changed.ObjectFormat = "aes256gcm-v1"
	beforeChange := provider.calls
	if err = registerBackupRepository(ctx, services, catalog, changed); !errors.Is(err, backup.ErrBackupConflict) || provider.calls != beforeChange {
		t.Fatal("repository cryptographic identity changed", err)
	}
	spec.Repository.ID = "failed"
	spec.Repository.Endpoint = "file:///var/backups/cyberpanel/repositories/failed"
	if registerBackupRepository(ctx, services, catalog, spec) == nil {
		t.Fatal("provision failure ignored")
	}
	if _, err = catalog.Repository(ctx, "first", "failed"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("failed registration committed: %v", err)
	}
	before := provider.calls
	spec.Repository.Endpoint = "file:///tmp/invalid"
	if registerBackupRepository(ctx, services, catalog, spec) == nil || provider.calls != before {
		t.Fatal("invalid registration caused filesystem effects")
	}
}
