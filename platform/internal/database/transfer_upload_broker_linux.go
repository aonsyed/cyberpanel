//go:build linux

package database

import (
	"context"
	"os"
)

func (executor *LinuxMariaDBExecutor) ExecuteTransferUpload(ctx context.Context, request TransferUploadRequest) (TransferUploadResult, error) {
	result := TransferUploadResult{Action: request.Action, IntentDigest: request.Intent.Digest}
	if executor == nil || executor.now == nil || ctx == nil || os.Geteuid() != 0 || request.Validate() != nil {
		return result, ErrUnauthorized
	}
	executor.mu.Lock()
	var target Database
	err := executor.readResource("databases", request.Intent.DatabaseID, &target)
	if err == nil && (target.Validate() != nil || target.TenantID != request.Intent.TenantID || target.SiteID != request.Intent.SiteID || target.Generation != request.Intent.DatabaseGeneration || !workspaceExportExecutorRecord(target.Metadata)) {
		err = ErrUnauthorized
	}
	if err == nil {
		instance, e := executor.instance(target.InstanceID)
		if e != nil || instance.Placement != PlacementLocal || !workspaceReady(instance.Metadata) {
			err = ErrUnauthorized
		}
	}
	executor.mu.Unlock()
	if err != nil {
		return result, err
	}
	store, err := NewLinuxTransferUploadStore(transferUploadRoot, executor.now)
	if err != nil {
		return result, err
	}
	switch request.Action {
	case "begin":
		result.NextOffset, err = store.Begin(ctx, request.Intent)
	case "chunk":
		result.NextOffset, err = store.Append(ctx, request.Intent, request.Offset, request.Data)
	case "status":
		result.NextOffset, result.Artifact, err = store.Status(ctx, request.Intent)
	case "finish":
		var artifact TransferArtifactDescriptor
		artifact, err = store.Finish(ctx, request.Intent)
		if err == nil {
			result.Artifact = &artifact
			result.NextOffset = artifact.Bytes
		}
	case "discard":
		err = store.Discard(ctx, request.Intent)
	}
	return result, err
}
