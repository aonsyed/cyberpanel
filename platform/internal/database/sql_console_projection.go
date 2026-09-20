package database

import (
	"context"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// ListDatabasePrincipals returns only principals with a ready grant on this
// database. Close the cursor before loading resources: the control DB may use
// a single connection.
func (repository *SQLRepository) ListDatabasePrincipals(ctx context.Context, tenant site.TenantID, databaseID ResourceID) ([]DatabasePrincipal, error) {
	if repository == nil || repository.db == nil || tenant.String() == "" || databaseID.IsZero() {
		return nil, ErrInvalidResource
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT DISTINCT json_extract(spec_json,'$.principal_id') FROM panel_database_resources WHERE kind=? AND tenant_id=? AND parent_id=? AND json_extract(status_json,'$.lifecycle')='ready' AND json_extract(status_json,'$.reconciliation')='in_sync' ORDER BY 1 LIMIT 1001`, string(KindGrantSet), tenant.String(), databaseID.String())
	if err != nil {
		return nil, err
	}
	var ids []ResourceID
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		id, err := NewResourceID(raw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) > 1000 {
		return nil, ErrConflict
	}
	values := make([]DatabasePrincipal, 0, len(ids))
	for _, id := range ids {
		envelope, err := repository.LoadResource(ctx, KindPrincipal, id)
		if err != nil {
			return nil, err
		}
		resource, err := DecodeResource(envelope)
		if err != nil {
			return nil, err
		}
		principal, ok := resource.(*DatabasePrincipal)
		if !ok || principal.TenantID != tenant {
			return nil, ErrUnauthorized
		}
		if principal.Disabled || !workspaceReady(principal.Metadata) {
			continue
		}
		values = append(values, *principal)
	}
	return values, nil
}
