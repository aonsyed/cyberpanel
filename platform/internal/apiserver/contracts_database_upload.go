package apiserver

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type DatabaseUploadBeginPayload struct {
	DatabaseID  database.ResourceID          `json:"database_id"`
	Compression database.TransferCompression `json:"compression"`
	Bytes       uint64                       `json:"bytes"`
	Digest      string                       `json:"digest"`
}
type DatabaseUploadPayload struct {
	Intent database.TransferUploadIntent `json:"intent"`
	Offset uint64                        `json:"offset,omitempty"`
	Data   []byte                        `json:"data,omitempty"`
}
type DatabaseUploadBeginResult struct {
	Intent database.TransferUploadIntent `json:"intent"`
	State  database.TransferUploadResult `json:"state"`
}
type DatabaseUploadService interface {
	BeginDatabaseUpload(context.Context, Invocation, DatabaseUploadBeginPayload) (DatabaseUploadBeginResult, error)
	ExecuteDatabaseUpload(context.Context, Invocation, database.TransferUploadRequest) (database.TransferUploadResult, error)
}

func registerDatabaseUploadContracts(registry *Registry) error {
	for _, action := range []string{"begin", "chunk", "status", "finish", "discard"} {
		op := Operation{Name: "database.upload." + action, Mutating: action != "status", Auth: AuthRequired, Permission: identity.MustPermission("database:manage"), Assurance: identity.AssuranceMFA, ResolveScope: siteScope, MaximumBodyBytes: 512 << 10, MaximumResponseBytes: 64 << 10}
		if action == "begin" {
			op.NewPayload = func() any { return &DatabaseUploadBeginPayload{} }
			op.ValidatePayload = func(value any) error {
				p := value.(*DatabaseUploadBeginPayload)
				digest, err := hex.DecodeString(p.Digest)
				if p.DatabaseID.IsZero() || p.Bytes == 0 || p.Bytes > database.MaximumTransferUploadBytes || (p.Compression != database.TransferCompressionNone && p.Compression != database.TransferCompressionGzip) || err != nil || len(digest) != 32 {
					return ErrInvalidRequest
				}
				return nil
			}
		} else {
			op.NewPayload = func() any { return &DatabaseUploadPayload{} }
			op.ValidatePayload = func(value any) error {
				p := value.(*DatabaseUploadPayload)
				if (database.TransferUploadRequest{Action: action, Intent: p.Intent, Offset: p.Offset, Data: p.Data}).Validate() != nil {
					return ErrInvalidRequest
				}
				return nil
			}
		}
		if err := register(registry, op); err != nil {
			return err
		}
	}
	return nil
}

func bindDatabaseUploadContracts(registry *Registry, services DomainServices) error {
	service, ok := services.DatabaseTransfers.(DatabaseUploadService)
	if !ok {
		return nil
	}
	if err := registry.Bind("database.upload.begin", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		result, err := service.BeginDatabaseUpload(ctx, inv, *value.(*DatabaseUploadBeginPayload))
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusCreated, Value: result, Generation: result.Intent.DatabaseGeneration}, nil
	}); err != nil {
		return err
	}
	for _, action := range []string{"chunk", "status", "finish", "discard"} {
		if err := registry.Bind("database.upload."+action, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			p := value.(*DatabaseUploadPayload)
			result, err := service.ExecuteDatabaseUpload(ctx, inv, database.TransferUploadRequest{Action: action, Intent: p.Intent, Offset: p.Offset, Data: p.Data})
			if err != nil {
				return OperationResult{}, databaseExportError(err)
			}
			return OperationResult{Status: http.StatusOK, Value: result, Generation: p.Intent.DatabaseGeneration}, nil
		}); err != nil {
			return err
		}
	}
	return nil
}
