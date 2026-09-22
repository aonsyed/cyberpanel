package apiserver

import (
	"context"
	"net/http"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type DatabaseImportPreparePayload struct {
	Replacement  bool                                `json:"replacement,omitempty"`
	DatabaseID   database.ResourceID                 `json:"database_id"`
	SourceExport *database.TransferJob               `json:"source_export,omitempty"`
	UploadSource *database.TransferUploadIntent      `json:"upload_source,omitempty"`
	Artifact     database.TransferArtifactDescriptor `json:"artifact"`
}
type DatabaseImportRunPayload struct {
	Job database.TransferJob `json:"job"`
}
type DatabaseImportInspectPayload struct {
	JobID database.ResourceID `json:"job_id"`
}

func registerDatabaseImportContracts(registry *Registry) error {
	if err := registerDatabaseReplacementContracts(registry); err != nil {
		return err
	}
	if err := registerDatabaseUploadContracts(registry); err != nil {
		return err
	}
	for _, op := range []Operation{
		{Name: "database.import.prepare", NewPayload: func() any { return &DatabaseImportPreparePayload{} }, ValidatePayload: func(v any) error {
			p := v.(*DatabaseImportPreparePayload)
			if p.DatabaseID.IsZero() || p.Artifact.Validate() != nil || (p.SourceExport == nil) == (p.UploadSource == nil) || p.SourceExport != nil && (p.SourceExport.Validate() != nil || p.SourceExport.Direction != database.TransferExport) || p.UploadSource != nil && p.UploadSource.Validate() != nil {
				return ErrInvalidRequest
			}
			return nil
		}},
		{Name: "database.import.run", Mutating: true, NewPayload: func() any { return &DatabaseImportRunPayload{} }, ValidatePayload: func(v any) error {
			p := v.(*DatabaseImportRunPayload)
			if p.Job.Validate() != nil || p.Job.Direction != database.TransferImport || (p.Job.ExportSource == nil && p.Job.UploadSource == nil) || p.Job.ConflictPolicy != database.TransferConflictFail {
				return ErrInvalidRequest
			}
			return nil
		}},
		{Name: "database.import.inspect", NewPayload: func() any { return &DatabaseImportInspectPayload{} }, ValidatePayload: func(v any) error {
			if v.(*DatabaseImportInspectPayload).JobID.IsZero() {
				return ErrInvalidRequest
			}
			return nil
		}},
		{Name: "database.import.cancel", Mutating: true, NewPayload: func() any { return &DatabaseImportInspectPayload{} }, ValidatePayload: func(v any) error {
			if v.(*DatabaseImportInspectPayload).JobID.IsZero() {
				return ErrInvalidRequest
			}
			return nil
		}},
		{Name: "database.import.recover", Mutating: true, NewPayload: func() any { return &DatabaseImportInspectPayload{} }, ValidatePayload: func(v any) error {
			if v.(*DatabaseImportInspectPayload).JobID.IsZero() {
				return ErrInvalidRequest
			}
			return nil
		}},
	} {
		op.Auth = AuthRequired
		op.Permission = identity.MustPermission("database:manage")
		op.Assurance = identity.AssuranceMFA
		op.ResolveScope = siteScope
		op.MaximumBodyBytes = 1 << 20
		op.MaximumResponseBytes = 1 << 20
		if err := register(registry, op); err != nil {
			return err
		}
	}
	return nil
}

func bindDatabaseImportContracts(registry *Registry, services DomainServices) error {
	if err := bindDatabaseReplacementContracts(registry, services); err != nil {
		return err
	}
	if err := bindDatabaseUploadContracts(registry, services); err != nil {
		return err
	}
	service := services.DatabaseTransfers
	if service == nil {
		return nil
	}
	if err := registry.Bind("database.import.prepare", func(ctx context.Context, inv Invocation, v any) (OperationResult, error) {
		job, err := service.PrepareDatabaseImport(ctx, inv, *v.(*DatabaseImportPreparePayload))
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: job, Generation: job.DatabaseGeneration}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("database.import.run", func(ctx context.Context, inv Invocation, v any) (OperationResult, error) {
		receipt, err := service.RunDatabaseImport(ctx, inv, v.(*DatabaseImportRunPayload).Job)
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: receipt, Generation: receipt.Generation}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("database.import.cancel", func(ctx context.Context, inv Invocation, v any) (OperationResult, error) {
		state, err := service.CancelDatabaseImport(ctx, inv, v.(*DatabaseImportInspectPayload).JobID)
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: state, Generation: state.Generation}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("database.import.recover", func(ctx context.Context, inv Invocation, v any) (OperationResult, error) {
		receipt, err := service.RecoverDatabaseImport(ctx, inv, v.(*DatabaseImportInspectPayload).JobID)
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: receipt, Generation: receipt.Generation}, nil
	}); err != nil {
		return err
	}
	return registry.Bind("database.import.inspect", func(ctx context.Context, inv Invocation, v any) (OperationResult, error) {
		state, err := service.InspectDatabaseImport(ctx, inv, v.(*DatabaseImportInspectPayload).JobID)
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: state, Generation: state.Generation}, nil
	})
}
