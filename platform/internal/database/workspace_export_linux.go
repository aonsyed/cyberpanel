//go:build linux

package database

import (
	"context"
	"errors"
	"os"
	"syscall"
)

const workspaceExportRoot = mariaDBStateRoot + "/transfers"

type resolvedExportConfig struct {
	descriptor TransferClientConfigDescriptor
}

func (config resolvedExportConfig) TransferClientConfig(context.Context, TransferJob, SQLIdentifier) (TransferClientConfigDescriptor, error) {
	return config.descriptor, nil
}

func (executor *LinuxMariaDBExecutor) ExportWorkspaceDatabase(ctx context.Context, request WorkspaceExportRequest) (TransferProcessReceipt, error) {
	if executor == nil || executor.now == nil || ctx == nil || request.validate(executor.now().UTC()) != nil {
		return TransferProcessReceipt{}, ErrUnauthorized
	}
	bounded, cancel := workspaceContext(ctx, request.Access, executor.now().UTC())
	defer cancel()
	configs, err := NewLinuxWorkspaceExportConfigs(executor, request.Access)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	var database Database
	executor.mu.Lock()
	err = executor.readResource("databases", request.Job.DatabaseID, &database)
	executor.mu.Unlock()
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	config, err := configs.TransferClientConfig(bounded, request.Job, database.Name)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	defer config.Release()
	store, err := NewLinuxTransferArtifactStore(workspaceExportRoot, MaximumTransferBytes, executor.now)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	// A retry must reauthorize before inspecting the previously published result.
	reader, err := store.OpenTransferArtifact(bounded, *request.Job.Destination)
	if err == nil {
		artifact := reader.Descriptor()
		reader.Close()
		// This receipt records completion of recovery, not a guessed original
		// process timestamp. Broker journal replay returns the original receipt.
		receipt := SealTransferProcessReceipt(TransferProcessReceipt{Artifact: &artifact, BytesProcessed: artifact.Bytes, RowsProcessed: artifact.Rows, StderrDigest: transferDigest(nil), CompletedAt: executor.now().UTC()})
		if !request.matches(receipt) {
			return TransferProcessReceipt{}, ErrTransferStale
		}
		return receipt, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return TransferProcessReceipt{}, err
	}
	var disk syscall.Statfs_t
	if err = syscall.Statfs(workspaceExportRoot, &disk); err != nil {
		return TransferProcessReceipt{}, err
	}
	if disk.Bavail*uint64(disk.Bsize) < request.Job.Limits.MaximumBytes+(2<<30) {
		return TransferProcessReceipt{}, ErrTransferLimit
	}
	backend, err := NewLinuxTransferBackend(store, resolvedExportConfig{config}, executor.now)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	return backend.Export(bounded, request.Job, database.Name, func(TransferStreamProgress) error { return bounded.Err() })
}

var _ WorkspaceExportExecutor = (*LinuxMariaDBExecutor)(nil)
