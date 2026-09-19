//go:build linux

package database

import (
	"context"
	"strings"
)

// ApplicationConnection contains only the selected endpoint and its public
// trust anchor. Administrator passwords and private keys are never exported.
type ApplicationConnection struct {
	InstanceID              ResourceID
	DatabaseName            string
	PrincipalName           string
	Endpoint                Endpoint
	TLS                     TLSMode
	CertificateAuthorityPEM []byte
}

func (executor *LinuxMariaDBExecutor) ApplicationConnection(ctx context.Context, id ResourceID, tenantID, siteID string) (ApplicationConnection, error) {
	if executor == nil || ctx == nil || id.IsZero() || !strings.HasPrefix(id.String(), "appdb-") || tenantID == "" || siteID == "" {
		return ApplicationConnection{}, ErrInvalidResource
	}
	if executor.secrets == nil {
		return ApplicationConnection{}, ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return ApplicationConnection{}, err
	}
	// Effects mutate these resources under the same lock. Do not join a
	// database and principal observed on opposite sides of a local mutation.
	executor.mu.Lock()
	defer executor.mu.Unlock()
	var db Database
	if err := executor.readResource("databases", id, &db); err != nil {
		return ApplicationConnection{}, err
	}
	if db.Validate() != nil || !applicationConnectionActive(db.Status) || db.ID != id || db.TenantID.String() != tenantID || db.SiteID.String() != siteID {
		return ApplicationConnection{}, ErrUnauthorized
	}
	principalID, err := NewResourceID("appuser-" + strings.TrimPrefix(id.String(), "appdb-"))
	if err != nil {
		return ApplicationConnection{}, err
	}
	var principal DatabasePrincipal
	if err := executor.readResource("principals", principalID, &principal); err != nil {
		return ApplicationConnection{}, err
	}
	if principal.Validate() != nil || principal.Disabled || !applicationConnectionActive(principal.Status) || principal.ID != principalID || principal.InstanceID != db.InstanceID || principal.TenantID != db.TenantID || principal.SiteID != db.SiteID {
		return ApplicationConnection{}, ErrUnauthorized
	}
	instance, err := executor.instance(db.InstanceID)
	if err != nil {
		return ApplicationConnection{}, err
	}
	if !applicationConnectionActive(instance.Status) {
		return ApplicationConnection{}, ErrUnauthorized
	}
	connection := ApplicationConnection{InstanceID: instance.ID, DatabaseName: db.Name.String(), PrincipalName: principal.Name.String()}
	if instance.Placement == PlacementLocal {
		return connection, nil
	}
	if instance.Placement != PlacementExternal || instance.External == nil || instance.External.ServerName != instance.External.Endpoint.Host {
		return ApplicationConnection{}, ErrInvalidResource
	}
	connection.Endpoint, connection.TLS = instance.External.Endpoint, instance.External.RequiredTLS
	connection.CertificateAuthorityPEM, err = executor.secrets.PinnedCertificateAuthority(ctx, instance.External.PinnedCASecretRef, instance.External.CredentialAudience)
	if err != nil {
		return ApplicationConnection{}, err
	}
	return connection, nil
}

func applicationConnectionActive(status ResourceStatus) bool {
	switch status.Lifecycle {
	case LifecycleProvisioning, LifecycleReady, LifecycleUpdating:
		return true
	default:
		return false
	}
}
