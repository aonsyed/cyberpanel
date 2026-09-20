package database

import (
	"context"
	"time"
)

const MaximumExportChunkBytes = 256 << 10

type WorkspaceExportReadRequest struct {
	Export   WorkspaceExportRequest     `json:"export"`
	Artifact TransferArtifactDescriptor `json:"artifact"`
	Offset   uint64                     `json:"offset"`
	Length   uint32                     `json:"length"`
}

type WorkspaceExportChunk struct {
	Artifact TransferArtifactDescriptor `json:"artifact"`
	Offset   uint64                     `json:"offset"`
	Data     []byte                     `json:"data"`
	EOF      bool                       `json:"eof"`
	Digest   string                     `json:"digest"`
}

type WorkspaceExportReader interface {
	ReadWorkspaceExport(context.Context, WorkspaceExportReadRequest) (WorkspaceExportChunk, error)
}

func (request WorkspaceExportReadRequest) validate(now time.Time) error {
	a, j := request.Artifact, request.Export.Job
	if request.Export.validate(now) != nil || a.Validate() != nil || !now.Before(a.ExpiresAt) || a.Identity != *j.Destination || a.Format != j.Format || a.Compression != j.Compression || a.Bytes > j.Limits.MaximumBytes || a.Rows > j.Limits.MaximumRows || !a.ExpiresAt.Equal(j.Retention.RetainUntil) || request.Offset > a.Bytes || request.Length == 0 || request.Length > MaximumExportChunkBytes {
		return ErrInvalidCommand
	}
	return nil
}

func (chunk WorkspaceExportChunk) matches(request WorkspaceExportReadRequest) bool {
	if request.Offset > request.Artifact.Bytes || request.Length == 0 || request.Length > MaximumExportChunkBytes {
		return false
	}
	remaining := request.Artifact.Bytes - request.Offset
	expected := uint64(request.Length)
	if remaining < expected {
		expected = remaining
	}
	return chunk.Artifact == request.Artifact && chunk.Offset == request.Offset && uint64(len(chunk.Data)) == expected && chunk.EOF == (expected == remaining) && chunk.Digest == transferDigest(chunk.Data)
}

func (client *BrokerClient) ReadWorkspaceExport(ctx context.Context, value WorkspaceExportReadRequest) (WorkspaceExportChunk, error) {
	if client == nil || client.transport == nil || ctx == nil || value.validate(client.now().UTC()) != nil {
		return WorkspaceExportChunk{}, ErrInvalidCommand
	}
	bounded, cancel := workspaceContext(ctx, value.Export.Access, client.now().UTC())
	defer cancel()
	request, err := client.requestWithMaximum(bounded, BrokerWorkspaceExportRead, 2*time.Minute)
	if err != nil {
		return WorkspaceExportChunk{}, err
	}
	request.WorkspaceExportRead = &value
	if err = request.validate(client.now().UTC()); err != nil {
		return WorkspaceExportChunk{}, err
	}
	response, err := client.transport.RoundTrip(bounded, request)
	if err != nil {
		return WorkspaceExportChunk{}, err
	}
	if err = response.validate(request); err != nil {
		return WorkspaceExportChunk{}, err
	}
	if response.FailureCode != "" {
		return WorkspaceExportChunk{}, brokerFailure(response.FailureCode)
	}
	return *response.ExportChunk, nil
}
