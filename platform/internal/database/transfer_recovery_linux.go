//go:build linux

package database

import "context"

// Recovery never allocates, loads, renames or drops native SQL resources.
func (executor *LinuxMariaDBExecutor) recoverVerifiedTransferImport(ctx context.Context, request TransferImportRequest) (TransferImportResult, error) {
	result := TransferImportResult{Action: request.Action, JobDigest: request.Job.Digest}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	id, _ := isolatedTransferIdentity(request.Job)
	var record isolatedTransferRecord
	if err := executor.readResource("transfer-imports", id, &record); err != nil {
		return result, err
	}
	var err error
	record, err = executor.loadTransferImport(request.Job, record.Isolated)
	if err != nil {
		return result, err
	}
	if record.Process == nil || !successfulTransferImport(*record.Process, request.Job) || record.Verification == nil || record.Verification.Validate(request.Job, record.Isolated) != nil || record.Promotion == nil || record.Promotion.Validate(request.Job, record.Isolated) != nil {
		return result, ErrAmbiguous
	}
	if record.State == "promotion-verified" {
		_, release, err := executor.beginWriterMutation(ctx)
		if err != nil {
			return result, err
		}
		defer release()
		if _, err = executor.finishVerifiedTransferPromotion(record); err != nil {
			return result, err
		}
	} else if record.State != "promoted" {
		return result, ErrAmbiguous
	}
	result.Isolated, result.Process, result.Verification, result.Promotion = record.Isolated, record.Process, record.Verification, record.Promotion
	return result, nil
}
