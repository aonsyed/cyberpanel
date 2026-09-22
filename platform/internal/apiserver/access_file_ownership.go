package apiserver

import (
	"context"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// The authorization scope comes from the request. Bind that scope to the
// authoritative hosting aggregate before reaching the site-ID-only executor.
// Upload/download/trash IDs are payload fields; ResourceID remains the site.
func bindAccessFileOwnership(registry *Registry, hosting HostingQueryService) error {
	for _, name := range registry.Names() {
		if name != "access.file.trash" && !strings.HasPrefix(name, "access.files.") && !strings.HasPrefix(name, "access.upload.") && !strings.HasPrefix(name, "access.download.") && !strings.HasPrefix(name, "access.trash.") && !strings.HasPrefix(name, "access.archive.") {
			continue
		}
		operation, _ := registry.Lookup(name)
		if operation.Handler == nil {
			continue
		}
		handler := operation.Handler
		if err := registry.Bind(name, func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			if hosting == nil {
				return OperationResult{}, ErrUnavailable
			}
			tenant, err := site.NewTenantID(inv.Request.TenantID)
			if err != nil {
				return OperationResult{}, ErrInvalidRequest
			}
			id, err := site.NewSiteID(inv.Request.ResourceID)
			if err != nil {
				return OperationResult{}, ErrInvalidRequest
			}
			aggregate, err := hosting.Load(ctx, tenant, id)
			if err != nil {
				return OperationResult{}, mapHostingError(err)
			}
			if aggregate.TenantID() != tenant || aggregate.ID() != id {
				return OperationResult{}, ErrNotFound
			}
			return handler(ctx, inv, value)
		}); err != nil {
			return err
		}
	}
	return nil
}
