package apiserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type DatabaseExportPreparePayload struct {
	SessionID database.ResourceID             `json:"session_id"`
	Options   database.WorkspaceExportOptions `json:"options"`
}
type DatabaseExportPayload struct {
	SessionID database.ResourceID  `json:"session_id"`
	Job       database.TransferJob `json:"job"`
}
type DatabaseExportDownloadPayload struct {
	SessionID database.ResourceID                 `json:"session_id"`
	Job       database.TransferJob                `json:"job"`
	Artifact  database.TransferArtifactDescriptor `json:"artifact"`
	Offset    uint64                              `json:"offset"`
	Length    uint32                              `json:"length"`
}

func registerDatabaseExportContracts(registry *Registry) error {
	operations := []Operation{
		{Name: "database.workspace.export_prepare", NewPayload: func() any { return &DatabaseExportPreparePayload{} }, ValidatePayload: func(value any) error {
			p := value.(*DatabaseExportPreparePayload)
			if p.SessionID.IsZero() || p.Options.Selection.Validate() != nil || p.Options.Compression != database.TransferCompressionNone && p.Options.Compression != database.TransferCompressionGzip {
				return ErrInvalidRequest
			}
			return nil
		}},
		{Name: "database.workspace.export", Mutating: true, NewPayload: func() any { return &DatabaseExportPayload{} }, ValidatePayload: func(value any) error {
			p := value.(*DatabaseExportPayload)
			if p.SessionID.IsZero() || p.Job.Validate() != nil || p.Job.Direction != database.TransferExport {
				return ErrInvalidRequest
			}
			return nil
		}},
		{Name: "database.workspace.export_download", NewPayload: func() any { return &DatabaseExportDownloadPayload{} }, ValidatePayload: func(value any) error {
			p := value.(*DatabaseExportDownloadPayload)
			if p.SessionID.IsZero() || p.Job.Validate() != nil || p.Job.Direction != database.TransferExport || p.Artifact.Validate() != nil || p.Offset > p.Artifact.Bytes || p.Length == 0 || p.Length > database.MaximumExportChunkBytes {
				return ErrInvalidRequest
			}
			return nil
		}},
	}
	for _, operation := range operations {
		operation.Permission = identity.MustPermission("database:console")
		operation.Assurance = identity.AssuranceMFA
		operation.Auth = AuthRequired
		operation.ResolveScope = siteScope
		operation.MaximumBodyBytes = 1 << 20
		operation.MaximumResponseBytes = 1 << 20
		if err := register(registry, operation); err != nil {
			return err
		}
	}
	return nil
}

func databaseExportCall(inv Invocation, session database.ResourceID) (database.WorkspaceCall, error) {
	tenant, err := site.NewTenantID(inv.Request.TenantID)
	if err != nil {
		return database.WorkspaceCall{}, ErrInvalidRequest
	}
	siteID, err := site.NewSiteID(inv.Request.ResourceID)
	if err != nil || session.IsZero() || inv.Request.ExpectedGeneration == 0 || inv.Actor.PrincipalID.String() == "" {
		return database.WorkspaceCall{}, ErrInvalidRequest
	}
	return database.WorkspaceCall{TenantID: tenant, SiteID: siteID, SessionID: session, SessionGeneration: inv.Request.ExpectedGeneration}, nil
}

func databaseExportError(err error) error {
	if errors.Is(err, database.ErrTransferInvalid) || errors.Is(err, database.ErrTransferLimit) {
		return ErrInvalidRequest
	}
	if errors.Is(err, database.ErrTransferStale) {
		return ErrConflict
	}
	return mapDomainError(err)
}

func bindDatabaseExportContracts(registry *Registry, services DomainServices) error {
	service, ok := services.Database.(database.WorkspaceExportService)
	if !ok {
		return nil
	}
	if err := registry.Bind("database.workspace.export_prepare", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		p := value.(*DatabaseExportPreparePayload)
		call, err := databaseExportCall(inv, p.SessionID)
		if err != nil {
			return OperationResult{}, err
		}
		job, err := service.PrepareWorkspaceExport(ctx, call, inv.Actor.PrincipalID.String(), commandID(inv), p.Options)
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: job, Generation: call.SessionGeneration}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("database.workspace.export", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		p := value.(*DatabaseExportPayload)
		call, err := databaseExportCall(inv, p.SessionID)
		if err != nil {
			return OperationResult{}, err
		}
		receipt, err := service.RunWorkspaceExport(ctx, call, inv.Actor.PrincipalID.String(), p.Job)
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusCreated, Value: receipt, Generation: call.SessionGeneration}, nil
	}); err != nil {
		return err
	}
	return registry.Bind("database.workspace.export_download", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		p := value.(*DatabaseExportDownloadPayload)
		call, err := databaseExportCall(inv, p.SessionID)
		if err != nil {
			return OperationResult{}, err
		}
		chunk, err := service.DownloadWorkspaceExport(ctx, call, inv.Actor.PrincipalID.String(), p.Job, p.Artifact, p.Offset, p.Length)
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: chunk, Generation: call.SessionGeneration, Headers: map[string]string{"Cache-Control": "no-store"}}, nil
	})
}
