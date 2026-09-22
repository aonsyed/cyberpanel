package apiserver

import (
	"context"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"net/http"
)

// Approval names the exact destructive intent, not a generic yes/no flag.
type DatabaseReplacementApproval struct {
	DatabaseID      database.ResourceID `json:"database_id"`
	DatabaseName    string              `json:"database_name"`
	Generation      uint64              `json:"generation"`
	JobDigest       string              `json:"job_digest"`
	RestorePointRef database.ResourceID `json:"restore_point_ref"`
	Action          string              `json:"action"`
}
type DatabaseReplacementPayload struct {
	Job      database.TransferJob        `json:"job"`
	Approval DatabaseReplacementApproval `json:"approval"`
}
type databaseReplacementService interface {
	RunDatabaseReplacement(context.Context, Invocation, DatabaseReplacementPayload) (database.TransferReceipt, error)
	RetireDatabaseReplacement(context.Context, Invocation, DatabaseReplacementPayload) (database.TransferRestorePoint, error)
	AbortDatabaseReplacement(context.Context, Invocation, DatabaseReplacementPayload) error
}

func registerDatabaseReplacementContracts(registry *Registry) error {
	for _, name := range []string{"database.import.replace.run", "database.import.replace.abort", "database.import.restore_point.retire"} {
		op := Operation{Name: name, Mutating: true, Auth: AuthRequired, Permission: identity.MustPermission("database:manage"), Assurance: identity.AssuranceMFA, ResolveScope: siteScope, MaximumBodyBytes: 1 << 20, MaximumResponseBytes: 1 << 20, NewPayload: func() any { return &DatabaseReplacementPayload{} }, ValidatePayload: func(v any) error {
			p := v.(*DatabaseReplacementPayload)
			if p.Job.Validate() != nil || p.Job.Direction != database.TransferImport || p.Job.ExportSource == nil || p.Job.UploadSource != nil || p.Approval.DatabaseID != p.Job.DatabaseID || p.Approval.Generation != p.Job.DatabaseGeneration || p.Approval.JobDigest != p.Job.Digest || p.Approval.DatabaseName == "" || p.Approval.RestorePointRef.IsZero() {
				return ErrInvalidRequest
			}
			return nil
		}}
		if err := register(registry, op); err != nil {
			return err
		}
	}
	return nil
}
func bindDatabaseReplacementContracts(registry *Registry, services DomainServices) error {
	service, ok := services.DatabaseTransfers.(databaseReplacementService)
	if !ok {
		return nil
	}
	if err := registry.Bind("database.import.replace.abort", func(ctx context.Context, inv Invocation, v any) (OperationResult, error) {
		if err := service.AbortDatabaseReplacement(ctx, inv, *v.(*DatabaseReplacementPayload)); err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: map[string]bool{"released": true}, Generation: inv.Request.ExpectedGeneration}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("database.import.replace.run", func(ctx context.Context, inv Invocation, v any) (OperationResult, error) {
		r, err := service.RunDatabaseReplacement(ctx, inv, *v.(*DatabaseReplacementPayload))
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: r, Generation: r.Generation}, nil
	}); err != nil {
		return err
	}
	return registry.Bind("database.import.restore_point.retire", func(ctx context.Context, inv Invocation, v any) (OperationResult, error) {
		p, err := service.RetireDatabaseReplacement(ctx, inv, *v.(*DatabaseReplacementPayload))
		if err != nil {
			return OperationResult{}, databaseExportError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: p, Generation: inv.Request.ExpectedGeneration}, nil
	})
}
