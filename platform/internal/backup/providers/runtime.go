package providers

import (
	"context"
	"database/sql"
	"errors"

	"github.com/aonsyed/cyberpanel/platform/internal/backup"
)

// Runtime wires the durable backup stores and provider registries without
// hiding component-specific stable-view or restore executors behind a shell.
type Runtime struct{DB *sql.DB;Set ProviderSet;Catalog backup.BackupCatalog;Retention backup.SQLRetentionCatalog;Restores backup.RestoreStore;Uploads SQLUploadJournal;Lifecycle RepositoryLifecycle}
func NewRuntime(database *sql.DB,set ProviderSet)Runtime{return Runtime{DB:database,Set:set,Catalog:backup.BackupCatalog{DB:database},Retention:backup.SQLRetentionCatalog{DB:database},Restores:backup.RestoreStore{DB:database},Uploads:SQLUploadJournal{DB:database},Lifecycle:RepositoryLifecycle{DB:database,Providers:set.Registry(),Probers:set.ProberRegistry()}}}
func (runtime Runtime)Bootstrap(ctx context.Context)error{if runtime.DB==nil{return errors.New("backup runtime database required")};return errors.Join(runtime.Catalog.Bootstrap(ctx),runtime.Retention.Bootstrap(ctx),runtime.Restores.Bootstrap(ctx),runtime.Uploads.Bootstrap(ctx),runtime.Lifecycle.Bootstrap(ctx))}
func (runtime Runtime)BackupCoordinator(snapshots backup.SnapshotProvider,capturer backup.Capturer)backup.BackupCoordinator{return backup.BackupCoordinator{Catalog:runtime.Catalog,Snapshots:snapshots,Capturer:capturer,Providers:runtime.Set.Registry()}}
func (runtime Runtime)RetentionCoordinator(repositories map[backup.RepositoryID]backup.RepositorySpec)backup.RetentionCoordinator{byRepository:=map[backup.RepositoryID]backup.RepositoryProvider{};registry:=runtime.Set.Registry();for id,spec:=range repositories{if provider:=registry[spec.Repository.Kind];provider!=nil{byRepository[id]=provider}};return backup.RetentionCoordinator{Catalog:runtime.Retention,ProviderByRepository:byRepository,Repositories:repositories,ProviderByKind:registry,RepositoryCatalog:runtime.Catalog,Leases:runtime.Catalog}}
func (runtime Runtime)RestoreSource()backup.SQLRestoreSource{return backup.SQLRestoreSource{DB:runtime.DB,Readers:runtime.Set.RestoreRegistry()}}
