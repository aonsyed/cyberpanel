package database

import (
	"context"
	"sync"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// BrokerImportExecution supplies TransferService's catalog/backend for one
// immutable import intent. The job retains its authorized durable source
// export; tenant input is not itself an authorization decision. New invocations
// reconstruct this adapter, while native phase evidence remains executor-owned.
type BrokerImportExecution struct {
	coordinator Coordinator
	executor    TransferImportExecutor
	job         TransferJob
	source      TransferJob
	mu          sync.Mutex
	isolated    *IsolatedTransferDatabase
}

func NewBrokerImportExecution(coordinator Coordinator, job TransferJob) (*BrokerImportExecution, error) {
	if job.ExportSource == nil && job.UploadSource == nil {
		return nil, ErrTransferInvalid
	}
	var source TransferJob
	if job.ExportSource != nil {
		source = *job.ExportSource
	}
	request := TransferImportRequest{Action: "allocate", Job: job, SourceExport: source}
	executor, ok := coordinator.executor.(TransferImportExecutor)
	if !ok || coordinator.repository == nil || request.validate() != nil {
		return nil, ErrTransferInvalid
	}
	return &BrokerImportExecution{coordinator: coordinator, executor: executor, job: job, source: source}, nil
}

func (execution *BrokerImportExecution) request(job TransferJob, action string, isolated *IsolatedTransferDatabase) (TransferImportRequest, error) {
	if execution == nil || job.Validate() != nil || job.Digest != execution.job.Digest {
		return TransferImportRequest{}, ErrUnauthorized
	}
	request := TransferImportRequest{Action: action, Job: job, SourceExport: execution.source, Isolated: isolated}
	if err := request.validate(); err != nil {
		return request, err
	}
	return request, nil
}

func (execution *BrokerImportExecution) LoadTransferDatabase(ctx context.Context, tenant site.TenantID, siteID site.SiteID, id ResourceID) (Database, error) {
	if execution == nil || tenant != execution.job.TenantID || siteID != execution.job.SiteID || id != execution.job.DatabaseID {
		return Database{}, ErrUnauthorized
	}
	envelope, err := execution.coordinator.repository.LoadResource(ctx, KindDatabase, id)
	if err != nil {
		return Database{}, err
	}
	return transferProjectionDatabase(envelope, execution.job)
}

func (execution *BrokerImportExecution) PreviewDatabaseTransfer(ctx context.Context, database Database, direction TransferDirection, selection TransferSelection, source *TransferArtifactDescriptor) (TransferImpactPreview, error) {
	if execution == nil || direction != TransferImport || source == nil || *source != *execution.job.Source || !sameWriterValue(selection, execution.job.Selection) || database.ID != execution.job.DatabaseID || database.Generation != execution.job.DatabaseGeneration || database.TenantID != execution.job.TenantID || database.SiteID != execution.job.SiteID || database.InstanceID != execution.job.InstanceID {
		return TransferImpactPreview{}, ErrUnauthorized
	}
	request, err := execution.request(execution.job, "preview", nil)
	if err != nil {
		return TransferImpactPreview{}, err
	}
	result, err := execution.executor.ExecuteTransferImport(ctx, request)
	if err != nil {
		return TransferImpactPreview{}, err
	}
	if !result.matches(request) {
		return TransferImpactPreview{}, ErrInvalidReceipt
	}
	if execution.job.ConflictPolicy == TransferConflictFail && result.Impact.SchemaObjects != 0 {
		return TransferImpactPreview{}, ErrConflict
	}
	return *result.Impact, nil
}

func (execution *BrokerImportExecution) AllocateIsolatedTransferDatabase(ctx context.Context, job TransferJob, database Database) (IsolatedTransferDatabase, error) {
	if database.ID != job.DatabaseID || database.Generation != job.DatabaseGeneration || database.TenantID != job.TenantID || database.SiteID != job.SiteID || database.InstanceID != job.InstanceID {
		return IsolatedTransferDatabase{}, ErrUnauthorized
	}
	request, err := execution.request(job, "allocate", nil)
	if err != nil {
		return IsolatedTransferDatabase{}, err
	}
	result, err := execution.executor.ExecuteTransferImport(ctx, request)
	if err != nil {
		return IsolatedTransferDatabase{}, err
	}
	if !result.matches(request) {
		return IsolatedTransferDatabase{}, ErrInvalidReceipt
	}
	execution.mu.Lock()
	execution.isolated = &result.Isolated
	execution.mu.Unlock()
	return result.Isolated, nil
}

func (execution *BrokerImportExecution) Import(ctx context.Context, job TransferJob, name SQLIdentifier, checkpoint TransferCheckpoint) (TransferProcessReceipt, error) {
	if execution == nil || checkpoint == nil {
		return TransferProcessReceipt{}, ErrInvalidCommand
	}
	execution.mu.Lock()
	var isolated IsolatedTransferDatabase
	if execution.isolated != nil {
		isolated = *execution.isolated
	}
	execution.mu.Unlock()
	if isolated.Name != name || isolated.Validate(job) != nil {
		return TransferProcessReceipt{}, ErrUnauthorized
	}
	request, err := execution.request(job, "load", &isolated)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	if err = checkpoint(TransferStreamProgress{SafePoint: true}); err != nil {
		return TransferProcessReceipt{}, err
	}
	result, err := execution.executor.ExecuteTransferImport(ctx, request)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	if !result.matches(request) {
		return TransferProcessReceipt{}, ErrInvalidReceipt
	}
	process := *result.Process
	if err = checkpoint(TransferStreamProgress{Bytes: process.BytesProcessed, Rows: process.RowsProcessed, SafePoint: true}); err != nil {
		return process, err
	}
	return process, nil
}

func (*BrokerImportExecution) Export(context.Context, TransferJob, SQLIdentifier, TransferCheckpoint) (TransferProcessReceipt, error) {
	return TransferProcessReceipt{}, ErrInvalidCommand
}

func (execution *BrokerImportExecution) VerifyIsolatedTransferDatabase(ctx context.Context, job TransferJob, isolated IsolatedTransferDatabase) (TransferVerification, error) {
	request, err := execution.request(job, "verify", &isolated)
	if err != nil {
		return TransferVerification{}, err
	}
	result, err := execution.executor.ExecuteTransferImport(ctx, request)
	if err != nil {
		return TransferVerification{}, err
	}
	if !result.matches(request) {
		return TransferVerification{}, ErrInvalidReceipt
	}
	return *result.Verification, nil
}

func (execution *BrokerImportExecution) PromoteIsolatedTransferDatabase(ctx context.Context, job TransferJob, database Database, isolated IsolatedTransferDatabase, point TransferRestorePoint) (TransferPromotion, error) {
	if database.ID != job.DatabaseID || database.Generation != job.DatabaseGeneration || point != (TransferRestorePoint{}) {
		return TransferPromotion{}, ErrUnauthorized
	}
	request, err := execution.request(job, "promote", &isolated)
	if err != nil {
		return TransferPromotion{}, err
	}
	return execution.coordinator.PromoteDatabaseTransfer(ctx, request)
}

func (execution *BrokerImportExecution) DiscardIsolatedTransferDatabase(ctx context.Context, job TransferJob, isolated IsolatedTransferDatabase) error {
	request, err := execution.request(job, "discard", &isolated)
	if err != nil {
		return err
	}
	result, err := execution.executor.ExecuteTransferImport(ctx, request)
	if err != nil {
		return err
	}
	if !result.matches(request) {
		return ErrInvalidReceipt
	}
	return nil
}

var _ TransferDatabaseCatalog = (*BrokerImportExecution)(nil)
var _ TransferBackend = (*BrokerImportExecution)(nil)
