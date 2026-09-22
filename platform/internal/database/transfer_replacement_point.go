package database

import "context"

func (coordinator Coordinator) PreviewReplacement(ctx context.Context, job TransferJob) (TransferImpactPreview, error) {
	request := TransferImportRequest{Action: "preview", Job: job}
	if job.ExportSource != nil {
		request.SourceExport = *job.ExportSource
	}
	executor, ok := coordinator.executor.(TransferImportExecutor)
	if !ok || request.validate() != nil || job.ConflictPolicy != TransferConflictFail {
		return TransferImpactPreview{}, ErrUnauthorized
	}
	result, err := executor.ExecuteTransferImport(ctx, request)
	if err != nil {
		return TransferImpactPreview{}, err
	}
	if !result.matches(request) {
		return TransferImpactPreview{}, ErrInvalidReceipt
	}
	return *result.Impact, nil
}

// ReplacementPoint uses the existing authenticated import transport. The caller
// must authorize the target and explicit preparation/retirement confirmation.
func (coordinator Coordinator) ReplacementPoint(ctx context.Context, job TransferJob, action string) (TransferRestorePoint, error) {
	request := TransferImportRequest{Action: action, Job: job}
	if job.ExportSource != nil {
		request.SourceExport = *job.ExportSource
	}
	if request.validate() != nil {
		return TransferRestorePoint{}, ErrUnauthorized
	}
	switch action {
	case "replacement-prepare", "replacement-inspect", "replacement-retire", "replacement-abort":
	default:
		return TransferRestorePoint{}, ErrUnauthorized
	}
	executor, ok := coordinator.executor.(TransferImportExecutor)
	if !ok {
		return TransferRestorePoint{}, ErrUnavailable
	}
	result, err := executor.ExecuteTransferImport(ctx, request)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	if !result.matches(request) {
		return TransferRestorePoint{}, ErrInvalidReceipt
	}
	if result.RestorePoint == nil {
		return TransferRestorePoint{}, nil
	}
	return *result.RestorePoint, nil
}
