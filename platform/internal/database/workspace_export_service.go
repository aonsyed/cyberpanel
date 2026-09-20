package database

import (
	"context"
	"time"
)

type WorkspaceExportOptions struct {
	Compression TransferCompression `json:"compression"`
	Selection   TransferSelection   `json:"selection"`
}

type WorkspaceExportService interface {
	PrepareWorkspaceExport(context.Context, WorkspaceCall, string, string, WorkspaceExportOptions) (TransferJob, error)
	RunWorkspaceExport(context.Context, WorkspaceCall, string, TransferJob) (TransferProcessReceipt, error)
	DownloadWorkspaceExport(context.Context, WorkspaceCall, string, TransferJob, TransferArtifactDescriptor, uint64, uint32) (WorkspaceExportChunk, error)
}

func (coordinator Coordinator) PrepareWorkspaceExport(ctx context.Context, call WorkspaceCall, actor, command string, options WorkspaceExportOptions) (TransferJob, error) {
	if !validTransferIdentifier(actor) || !validTransferIdentifier(command) || options.Selection.Validate() != nil || !validTransferCompression(options.Compression) {
		return TransferJob{}, ErrInvalidCommand
	}
	access, err := coordinator.authorizeWorkspace(ctx, call)
	if err != nil {
		return TransferJob{}, err
	}
	executor, ok := coordinator.executor.(WorkspaceExecutor)
	if !ok {
		return TransferJob{}, ErrUnavailable
	}
	bounded, cancel := workspaceContext(ctx, access, coordinator.clock.Now().UTC())
	defer cancel()
	metadata, err := executor.BrowseWorkspaceMetadata(bounded, access)
	if err != nil {
		return TransferJob{}, err
	}
	if metadata.Truncated {
		return TransferJob{}, ErrTransferLimit
	}
	selected := map[string]bool{}
	for _, table := range options.Selection.Tables {
		selected[table.String()] = false
	}
	now := coordinator.clock.Now().UTC()
	preview := TransferImpactPreview{DatabaseID: access.DatabaseID, DatabaseGeneration: access.DatabaseGeneration, CapturedAt: now}
	for _, entry := range metadata.Entries {
		if entry.Kind != WorkspaceMetadataTable && entry.Kind != WorkspaceMetadataView {
			continue
		}
		if len(selected) != 0 {
			if _, ok := selected[entry.ObjectName]; !ok {
				continue
			}
			selected[entry.ObjectName] = true
		}
		preview.SchemaObjects++
		if options.Selection.Data {
			if entry.RowEstimate > MaximumTransferRows-preview.Rows || entry.DataBytes > MaximumTransferBytes-preview.Bytes {
				return TransferJob{}, ErrTransferLimit
			}
			preview.Rows += entry.RowEstimate
			preview.Bytes += entry.DataBytes
		}
	}
	for _, found := range selected {
		if !found {
			return TransferJob{}, ErrNotFound
		}
	}
	if preview.Rows > uint64(access.Limits.MaxRows) || preview.Bytes > access.Limits.MaxResultBytes {
		return TransferJob{}, ErrTransferLimit
	}
	envelope, err := coordinator.repository.LoadResource(ctx, KindDatabase, access.DatabaseID)
	if err != nil {
		return TransferJob{}, err
	}
	resource, err := DecodeResource(envelope)
	if err != nil {
		return TransferJob{}, err
	}
	db, ok := resource.(*Database)
	if !ok || db.Generation != access.DatabaseGeneration || db.TenantID != call.TenantID || db.SiteID != call.SiteID {
		return TransferJob{}, ErrConflict
	}
	id, _ := NewResourceID("export-" + transferDigest([]byte(call.TenantID.String()+":"+command)))
	job := TransferJob{ID: id, IdempotencyKey: command, TenantID: call.TenantID, SiteID: call.SiteID, DatabaseID: access.DatabaseID, DatabaseGeneration: access.DatabaseGeneration, InstanceID: db.InstanceID, Direction: TransferExport, Format: TransferFormatSQL, Compression: options.Compression, Selection: options.Selection, Limits: TransferLimits{MaximumBytes: access.Limits.MaxResultBytes, MaximumRows: uint64(access.Limits.MaxRows), MaximumDuration: access.Limits.StatementTimeout}, Impact: SealTransferImpactPreview(preview), ConflictPolicy: TransferConflictFail, Retention: TransferRetention{RetainUntil: access.ExpiresAt}, CreatedBy: actor, CreatedAt: now}
	artifact := WorkspaceExportArtifact(job)
	job.Destination = &artifact
	return SealTransferJob(job)
}

func (coordinator Coordinator) workspaceExportRequest(ctx context.Context, call WorkspaceCall, actor string, job TransferJob) (WorkspaceExportRequest, error) {
	access, err := coordinator.authorizeWorkspace(ctx, call)
	if err != nil {
		return WorkspaceExportRequest{}, err
	}
	now := coordinator.clock.Now().UTC()
	request := WorkspaceExportRequest{Access: access, Job: job}
	if actor != job.CreatedBy || job.CreatedAt.After(now.Add(time.Minute)) || now.Sub(job.CreatedAt) > 15*time.Minute || request.validate(now) != nil {
		return WorkspaceExportRequest{}, ErrUnauthorized
	}
	return request, nil
}

func (coordinator Coordinator) RunWorkspaceExport(ctx context.Context, call WorkspaceCall, actor string, job TransferJob) (TransferProcessReceipt, error) {
	request, err := coordinator.workspaceExportRequest(ctx, call, actor, job)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	executor, ok := coordinator.executor.(WorkspaceExportExecutor)
	if !ok {
		return TransferProcessReceipt{}, ErrUnavailable
	}
	return executor.ExportWorkspaceDatabase(ctx, request)
}

func (coordinator Coordinator) DownloadWorkspaceExport(ctx context.Context, call WorkspaceCall, actor string, job TransferJob, artifact TransferArtifactDescriptor, offset uint64, length uint32) (WorkspaceExportChunk, error) {
	request, err := coordinator.workspaceExportRequest(ctx, call, actor, job)
	if err != nil {
		return WorkspaceExportChunk{}, err
	}
	executor, ok := coordinator.executor.(WorkspaceExportReader)
	if !ok {
		return WorkspaceExportChunk{}, ErrUnavailable
	}
	read := WorkspaceExportReadRequest{Export: request, Artifact: artifact, Offset: offset, Length: length}
	if err = read.validate(coordinator.clock.Now().UTC()); err != nil {
		return WorkspaceExportChunk{}, err
	}
	return executor.ReadWorkspaceExport(ctx, read)
}

var _ WorkspaceExportService = Coordinator{}
