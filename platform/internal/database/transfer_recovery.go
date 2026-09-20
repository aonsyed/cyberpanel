package database

import (
	"context"
	"errors"
	"time"
)

// RecoverDatabaseTransfer is internal; callers must authorize the stored job.
// It consumes executor-owned evidence, never proofs supplied by an API client.
func (coordinator Coordinator) RecoverDatabaseTransfer(ctx context.Context, job TransferJob) (TransferImportResult, error) {
	request := TransferImportRequest{Action: "recover", Job: job}
	if job.ExportSource != nil {
		request.SourceExport = *job.ExportSource
	}
	if ctx == nil || coordinator.repository == nil || request.validate() != nil {
		return TransferImportResult{}, ErrInvalidCommand
	}
	repository, ok := coordinator.repository.(transferPromotionRepository)
	if !ok {
		return TransferImportResult{}, ErrUnavailable
	}
	executor, ok := coordinator.executor.(TransferImportExecutor)
	if !ok {
		return TransferImportResult{}, ErrUnavailable
	}
	envelope, err := coordinator.repository.LoadResource(ctx, KindDatabase, job.DatabaseID)
	if err != nil {
		return TransferImportResult{}, err
	}
	if _, err = transferProjectionDatabase(envelope, job); err != nil {
		return TransferImportResult{}, err
	}
	result, err := executor.ExecuteTransferImport(ctx, request)
	if err != nil {
		return result, err
	}
	if !result.matches(request) {
		return TransferImportResult{}, ErrInvalidReceipt
	}
	if err = repository.RecordTransferPromotion(ctx, job, result.Isolated, *result.Promotion); err != nil {
		return result, errors.Join(ErrAmbiguous, err)
	}
	return result, nil
}

func (execution *BrokerImportExecution) RecoverTransferPromotion(ctx context.Context, job TransferJob) (TransferImportResult, error) {
	if execution == nil || job.Digest != execution.job.Digest {
		return TransferImportResult{}, ErrUnauthorized
	}
	return execution.coordinator.RecoverDatabaseTransfer(ctx, job)
}

type transferRecoveryRepository interface {
	CheckTransferRecovery(context.Context, ResourceID, uint64, time.Time) error
	ReconcileTransferPromotion(context.Context, ResourceID, uint64, TransferImportResult, time.Time) (TransferReceipt, error)
}

func (service TransferService) Recover(ctx context.Context, actor string, id ResourceID, generation uint64) (TransferReceipt, error) {
	state, err := service.repository.LoadTransfer(ctx, id)
	if err != nil {
		return TransferReceipt{}, err
	}
	authority := transferAuthorization(actor, state.Job, AuthorizeTransferRecover)
	if err = service.authorize(ctx, authority); err != nil {
		return TransferReceipt{}, err
	}
	if _, err = service.reauthorizeTransferHistory(ctx, state.Job); err != nil {
		return TransferReceipt{}, err
	}
	if state.Generation != generation {
		return TransferReceipt{}, ErrTransferStale
	}
	if state.Status == TransferCompleted {
		return service.InspectReceipt(ctx, actor, id)
	}
	repository, ok := service.repository.(transferRecoveryRepository)
	if !ok {
		return TransferReceipt{}, ErrUnavailable
	}
	catalog, ok := service.catalog.(interface {
		RecoverTransferPromotion(context.Context, TransferJob) (TransferImportResult, error)
	})
	if !ok {
		return TransferReceipt{}, ErrUnavailable
	}
	if err = repository.CheckTransferRecovery(ctx, id, generation, service.now().UTC()); err != nil {
		return TransferReceipt{}, err
	}
	result, err := catalog.RecoverTransferPromotion(ctx, state.Job)
	if err != nil {
		return TransferReceipt{}, err
	}
	finalize, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	receipt, err := repository.ReconcileTransferPromotion(finalize, id, generation, result, service.now().UTC())
	if err != nil {
		return receipt, err
	}
	if err = service.recordAudit(finalize, authority, "transfer_completed", state.Job.Digest, receipt.Digest, receipt.Generation); err != nil {
		return receipt, err
	}
	return receipt, nil
}
