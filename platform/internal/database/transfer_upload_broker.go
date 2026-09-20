package database

import (
	"context"
	"time"
)

type TransferUploadRequest struct {
	Action string               `json:"action"`
	Intent TransferUploadIntent `json:"intent"`
	Offset uint64               `json:"offset,omitempty"`
	Data   []byte               `json:"data,omitempty"`
}

type TransferUploadResult struct {
	Action       string                      `json:"action"`
	IntentDigest string                      `json:"intent_digest"`
	NextOffset   uint64                      `json:"next_offset"`
	Artifact     *TransferArtifactDescriptor `json:"artifact,omitempty"`
}

type TransferUploadExecutor interface {
	ExecuteTransferUpload(context.Context, TransferUploadRequest) (TransferUploadResult, error)
}

func (r TransferUploadRequest) Validate() error {
	if r.Intent.Validate() != nil {
		return ErrInvalidCommand
	}
	if r.Action == "chunk" {
		if len(r.Data) == 0 || len(r.Data) > MaximumTransferUploadChunk || r.Offset > r.Intent.Bytes || uint64(len(r.Data)) > r.Intent.Bytes-r.Offset {
			return ErrInvalidCommand
		}
		return nil
	}
	if r.Offset != 0 || len(r.Data) != 0 {
		return ErrInvalidCommand
	}
	switch r.Action {
	case "begin", "status", "finish", "discard":
		return nil
	}
	return ErrInvalidCommand
}

func (r TransferUploadResult) matches(request TransferUploadRequest) bool {
	if request.Validate() != nil || r.Action != request.Action || r.IntentDigest != request.Intent.Digest || r.NextOffset > request.Intent.Bytes {
		return false
	}
	if r.Artifact != nil && (!request.Intent.matchesArtifact(*r.Artifact) || r.NextOffset != request.Intent.Bytes) {
		return false
	}
	switch request.Action {
	case "finish":
		return r.Artifact != nil
	case "chunk":
		return r.Artifact == nil && r.NextOffset >= request.Offset+uint64(len(request.Data))
	case "discard":
		return r.Artifact == nil && r.NextOffset == 0
	default:
		return true
	}
}

func (client *BrokerClient) ExecuteTransferUpload(ctx context.Context, value TransferUploadRequest) (TransferUploadResult, error) {
	if client == nil || client.transport == nil || ctx == nil || value.Validate() != nil {
		return TransferUploadResult{}, ErrInvalidCommand
	}
	request, err := client.requestWithMaximum(ctx, BrokerTransferUpload, time.Minute)
	if err != nil {
		return TransferUploadResult{}, err
	}
	request.TransferUpload = &value
	if err = request.validate(client.now().UTC()); err != nil {
		return TransferUploadResult{}, err
	}
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil {
		return TransferUploadResult{}, err
	}
	if err = response.validate(request); err != nil {
		return TransferUploadResult{}, err
	}
	if response.FailureCode != "" {
		return TransferUploadResult{}, brokerFailure(response.FailureCode)
	}
	return *response.TransferUpload, nil
}

// The API supplies an already authorized intent. Native execution rechecks the
// destination record; bytes never pass through a shell or an executable argument.
func (coordinator Coordinator) ExecuteTransferUpload(ctx context.Context, request TransferUploadRequest) (TransferUploadResult, error) {
	executor, ok := coordinator.executor.(TransferUploadExecutor)
	if !ok || request.Validate() != nil {
		return TransferUploadResult{}, ErrInvalidCommand
	}
	return executor.ExecuteTransferUpload(ctx, request)
}
