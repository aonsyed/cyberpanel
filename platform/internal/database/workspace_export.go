package database

import (
	"context"
	"encoding/json"
	"time"
)

type WorkspaceExportRequest struct {
	Access WorkspaceAccess `json:"access"`
	Job    TransferJob     `json:"job"`
}

type WorkspaceExportExecutor interface {
	ExportWorkspaceDatabase(context.Context, WorkspaceExportRequest) (TransferProcessReceipt, error)
}

// WorkspaceExportArtifact binds storage to the complete export specification,
// excluding its self-referential destination and digest. Call before SealTransferJob.
func WorkspaceExportArtifact(job TransferJob) TransferArtifactIdentity {
	job.Destination = nil
	job.Digest = ""
	raw, _ := json.Marshal(job)
	store, _ := NewResourceID("workspace-export")
	id, _ := NewResourceID("export-" + transferDigest(raw))
	return TransferArtifactIdentity{StoreID: store, ArtifactID: id, Generation: 1}
}

func (request WorkspaceExportRequest) validate(now time.Time) error {
	a, j := request.Access, request.Job
	if a.validate(now) != nil || j.Validate() != nil || j.Direction != TransferExport || j.Destination == nil || *j.Destination != WorkspaceExportArtifact(j) || j.TenantID != a.TenantID || j.SiteID != a.SiteID || j.DatabaseID != a.DatabaseID || j.DatabaseGeneration != a.DatabaseGeneration || j.Limits.MaximumBytes > a.Limits.MaxResultBytes || j.Limits.MaximumRows > uint64(a.Limits.MaxRows) || j.Limits.MaximumDuration > a.Limits.StatementTimeout {
		return ErrUnauthorized
	}
	return nil
}

func (request WorkspaceExportRequest) matches(receipt TransferProcessReceipt) bool {
	job := request.Job
	artifact := receipt.Artifact
	return receipt.Validate(job) == nil && receipt.ExitCode == 0 && !receipt.Partial && artifact != nil && job.Destination != nil && artifact.Identity == *job.Destination && artifact.Format == job.Format && artifact.Compression == job.Compression && artifact.Bytes == receipt.BytesProcessed && artifact.Rows == receipt.RowsProcessed && artifact.ExpiresAt.Equal(job.Retention.RetainUntil)
}

func (client *BrokerClient) ExportWorkspaceDatabase(ctx context.Context, value WorkspaceExportRequest) (TransferProcessReceipt, error) {
	if client == nil || client.transport == nil || ctx == nil || value.validate(client.now().UTC()) != nil {
		return TransferProcessReceipt{}, ErrInvalidCommand
	}
	bounded, cancel := workspaceContext(ctx, value.Access, client.now().UTC())
	defer cancel()
	request, err := client.requestWithMaximum(bounded, BrokerWorkspaceExport, 2*time.Minute)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	request.WorkspaceExport = &value
	if err = request.validate(client.now().UTC()); err != nil {
		return TransferProcessReceipt{}, err
	}
	response, err := client.transport.RoundTrip(bounded, request)
	if err != nil {
		return TransferProcessReceipt{}, err
	}
	if err = response.validate(request); err != nil {
		return TransferProcessReceipt{}, err
	}
	if response.FailureCode != "" {
		return TransferProcessReceipt{}, brokerFailure(response.FailureCode)
	}
	return *response.Export, nil
}
