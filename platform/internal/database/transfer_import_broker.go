package database

import (
	"context"
	"time"
)

// TransferImportRequest is an authenticated core-to-executor command, not a
// tenant API. Core must authorize transfer execution before using this surface.
// SourceExport binds the artifact to its originating tenant/site; an artifact
// descriptor alone is not authority to read private executor storage.
type TransferImportRequest struct {
	Action       string                    `json:"action"`
	Job          TransferJob               `json:"job"`
	SourceExport TransferJob               `json:"source_export"`
	Isolated     *IsolatedTransferDatabase `json:"isolated,omitempty"`
}

type TransferImportResult struct {
	Action       string                   `json:"action"`
	JobDigest    string                   `json:"job_digest"`
	Isolated     IsolatedTransferDatabase `json:"isolated"`
	Process      *TransferProcessReceipt  `json:"process,omitempty"`
	Verification *TransferVerification    `json:"verification,omitempty"`
	Promotion    *TransferPromotion       `json:"promotion,omitempty"`
}

type TransferImportExecutor interface {
	ExecuteTransferImport(context.Context, TransferImportRequest) (TransferImportResult, error)
}

func (request TransferImportRequest) validate() error {
	j, source := request.Job, request.SourceExport
	if j.Validate() != nil || j.Direction != TransferImport || j.ConflictPolicy != TransferConflictFail || j.Source == nil || source.Validate() != nil || source.Direction != TransferExport || source.Destination == nil || *source.Destination != WorkspaceExportArtifact(source) || j.Source.Identity != *source.Destination || j.TenantID != source.TenantID || j.SiteID != source.SiteID || j.Format != source.Format || j.Compression != source.Compression || !j.Source.ExpiresAt.Equal(source.Retention.RetainUntil) {
		return ErrUnauthorized
	}
	switch request.Action {
	case "allocate":
		if request.Isolated != nil {
			return ErrInvalidCommand
		}
	case "load", "verify", "promote", "discard":
		if request.Isolated == nil || request.Isolated.Validate(j) != nil {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func (result TransferImportResult) matches(request TransferImportRequest) bool {
	if result.Action != request.Action || result.JobDigest != request.Job.Digest || result.Isolated.Validate(request.Job) != nil || request.Isolated != nil && result.Isolated != *request.Isolated {
		return false
	}
	switch request.Action {
	case "allocate", "discard":
		return result.Process == nil && result.Verification == nil && result.Promotion == nil
	case "load":
		return result.Process != nil && successfulTransferImport(*result.Process, request.Job) && result.Verification == nil && result.Promotion == nil
	case "verify":
		return result.Process == nil && result.Verification != nil && result.Verification.Validate(request.Job, result.Isolated) == nil && result.Promotion == nil
	case "promote":
		return result.Process == nil && result.Verification == nil && result.Promotion != nil && result.Promotion.Validate(request.Job, result.Isolated) == nil
	}
	return false
}

func successfulTransferImport(receipt TransferProcessReceipt, job TransferJob) bool {
	return receipt.Validate(job) == nil && receipt.ExitCode == 0 && !receipt.Partial && receipt.InputVerified && job.Source != nil && receipt.BytesProcessed == job.Source.Bytes
}

func (client *BrokerClient) ExecuteTransferImport(ctx context.Context, value TransferImportRequest) (TransferImportResult, error) {
	if client == nil || client.transport == nil || ctx == nil || value.validate() != nil {
		return TransferImportResult{}, ErrInvalidCommand
	}
	request, err := client.requestWithMaximum(ctx, BrokerTransferImport, 2*time.Minute)
	if err != nil {
		return TransferImportResult{}, err
	}
	request.TransferImport = &value
	if err = request.validate(client.now().UTC()); err != nil {
		return TransferImportResult{}, err
	}
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil {
		return TransferImportResult{}, err
	}
	if err = response.validate(request); err != nil {
		return TransferImportResult{}, err
	}
	if response.FailureCode != "" {
		return TransferImportResult{}, brokerFailure(response.FailureCode)
	}
	return *response.TransferImport, nil
}
