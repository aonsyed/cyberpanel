//go:build linux

package database

import (
	"context"
	"errors"
	"os"
)

func (executor *LinuxMariaDBExecutor) ExecuteTransferImport(ctx context.Context, request TransferImportRequest) (TransferImportResult, error) {
	result := TransferImportResult{Action: request.Action, JobDigest: request.Job.Digest}
	if executor == nil || executor.now == nil || ctx == nil || os.Geteuid() != 0 || request.validate() != nil {
		return result, ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if request.Action == "replacement-prepare" || request.Action == "replacement-inspect" || request.Action == "replacement-retire" || request.Action == "replacement-abort" {
		point, err := executor.executeReplacementPoint(ctx, request)
		if err == nil && request.Action != "replacement-abort" {
			result.RestorePoint = &point
		}
		return result, err
	}
	if request.Job.ConflictPolicy == TransferConflictReplace {
		bounded, release, err := executor.replacementTransferContext(ctx, request.Job, request.Action)
		if err != nil {
			return result, err
		}
		defer release()
		ctx = bounded
	}
	if request.Isolated != nil {
		result.Isolated = *request.Isolated
	}
	var err error
	switch request.Action {
	case "recover":
		return executor.recoverVerifiedTransferImport(ctx, request)
	case "preview":
		var impact TransferImpactPreview
		impact, err = executor.previewTransferImport(ctx, request.Job)
		if err == nil {
			result.Impact = &impact
		}
	case "allocate":
		// Validate the stored descriptor before reserving any native resources.
		if _, err = executor.importArtifactStore(ctx, request.Job); err == nil {
			result.Isolated, err = executor.allocateTransferImport(ctx, request.Job)
		}
	case "load":
		var receipt TransferProcessReceipt
		receipt, err = executor.loadBrokerTransferImport(ctx, request)
		if err == nil {
			result.Process = &receipt
		}
	case "verify", "promote":
		// A closed loader alone is not evidence of a successful, verified stream.
		executor.mu.Lock()
		var record isolatedTransferRecord
		record, err = executor.loadTransferImport(request.Job, result.Isolated)
		if err == nil && (record.Process == nil || !successfulTransferImport(*record.Process, request.Job)) {
			err = ErrConflict
		}
		executor.mu.Unlock()
		if err != nil {
			break
		}
		if request.Action == "verify" {
			var proof TransferVerification
			proof, err = executor.verifyTransferImport(ctx, request.Job, result.Isolated)
			if err == nil {
				result.Verification = &proof
			}
		} else {
			var proof TransferPromotion
			if request.Job.ConflictPolicy == TransferConflictReplace {
				proof, err = executor.promoteReplacementTransferImport(ctx, request.Job, result.Isolated, false)
			} else {
				proof, err = executor.promoteEmptyTransferImport(ctx, request.Job, result.Isolated)
			}
			if err == nil {
				result.Promotion = &proof
			}
		}
	case "discard":
		err = executor.discardTransferImport(ctx, request.Job, result.Isolated)
		if errors.Is(err, ErrNotFound) {
			err = nil
		}
	}
	return result, err
}

func (executor *LinuxMariaDBExecutor) importArtifactStore(ctx context.Context, job TransferJob) (*LinuxTransferArtifactStore, error) {
	root := workspaceExportRoot
	if job.UploadSource != nil {
		root = transferUploadRoot
	}
	store, err := NewLinuxTransferArtifactStore(root, MaximumTransferBytes, executor.now)
	if err != nil {
		return nil, err
	}
	reader, err := store.OpenTransferArtifact(ctx, job.Source.Identity)
	if err != nil {
		return nil, err
	}
	descriptor := reader.Descriptor()
	err = reader.Close()
	if err != nil {
		return nil, err
	}
	if descriptor != *job.Source {
		return nil, ErrTransferStale
	}
	return store, nil
}

func (executor *LinuxMariaDBExecutor) loadBrokerTransferImport(ctx context.Context, request TransferImportRequest) (TransferProcessReceipt, error) {
	job, isolated := request.Job, *request.Isolated
	executor.mu.Lock()
	record, err := executor.loadTransferImport(job, isolated)
	if err == nil {
		_, err = executor.transferImportSource(job)
	}
	executor.mu.Unlock()
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	if record.Process != nil && successfulTransferImport(*record.Process, job) && (record.State == "closed" || record.State == "verified") {
		return *record.Process, nil
	}
	if record.State != "allocated" {
		return TransferProcessReceipt{}, ErrAmbiguous
	}
	store, err := executor.importArtifactStore(ctx, job)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	backend, err := NewLinuxTransferBackend(store, isolatedImportConfigs{executor: executor, isolated: isolated}, executor.now)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	receipt, err := backend.Import(ctx, job, isolated.Name, func(TransferStreamProgress) error { return ctx.Err() })
	if err != nil {
		return receipt, err
	}
	if !successfulTransferImport(receipt, job) {
		return receipt, ErrInvalidReceipt
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	record, err = executor.loadTransferImport(job, isolated)
	if err != nil || record.State != "closed" {
		return receipt, ErrAmbiguous
	}
	record.Process = &receipt
	if err = executor.writeResource("transfer-imports", record.Target.ID, record); err != nil {
		return receipt, ErrAmbiguous
	}
	return receipt, nil
}

var _ TransferImportExecutor = (*LinuxMariaDBExecutor)(nil)
