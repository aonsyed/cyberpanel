//go:build linux

package database

import (
	"context"
	"io"
)

func (executor *LinuxMariaDBExecutor) ReadWorkspaceExport(ctx context.Context, request WorkspaceExportReadRequest) (WorkspaceExportChunk, error) {
	if executor == nil || executor.now == nil || ctx == nil || request.validate(executor.now().UTC()) != nil {
		return WorkspaceExportChunk{}, ErrUnauthorized
	}
	bounded, cancel := workspaceContext(ctx, request.Export.Access, executor.now().UTC())
	defer cancel()
	// Reauthorize every chunk, including retries and EOF. No secret material is
	// needed to read an authorized artifact, and download bytes are never journaled.
	session, _, _, err := executor.authorizeWorkspaceExport(bounded, request.Export.Access, request.Export.Job)
	if err != nil {
		return WorkspaceExportChunk{}, err
	}
	release, err := executor.acquireWorkspace(session)
	if err != nil {
		return WorkspaceExportChunk{}, err
	}
	defer release()
	// A download is read-only; missing storage must not be initialized here.
	if err = verifyPrivateTransferDirectory(workspaceExportRoot); err != nil {
		return WorkspaceExportChunk{}, err
	}
	store, err := NewLinuxTransferArtifactStore(workspaceExportRoot, MaximumTransferBytes, executor.now)
	if err != nil {
		return WorkspaceExportChunk{}, err
	}
	reader, err := store.OpenTransferArtifact(bounded, request.Artifact.Identity)
	if err != nil {
		return WorkspaceExportChunk{}, err
	}
	defer reader.Close()
	if reader.Descriptor() != request.Artifact {
		return WorkspaceExportChunk{}, ErrTransferStale
	}
	seeker, ok := reader.(io.Seeker)
	if !ok {
		return WorkspaceExportChunk{}, ErrTransferInvalid
	}
	if _, err = seeker.Seek(int64(request.Offset), io.SeekStart); err != nil {
		return WorkspaceExportChunk{}, err
	}
	size := uint64(request.Length)
	if remaining := request.Artifact.Bytes - request.Offset; remaining < size {
		size = remaining
	}
	data := make([]byte, int(size))
	if _, err = io.ReadFull(reader, data); err != nil {
		return WorkspaceExportChunk{}, err
	}
	if err = bounded.Err(); err != nil {
		return WorkspaceExportChunk{}, err
	}
	return WorkspaceExportChunk{Artifact: request.Artifact, Offset: request.Offset, Data: data, EOF: request.Offset+size == request.Artifact.Bytes, Digest: transferDigest(data)}, nil
}

var _ WorkspaceExportReader = (*LinuxMariaDBExecutor)(nil)
