//go:build linux

package apps

import (
	"context"
	"encoding/json"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

func (runtime *LinuxApplicationRuntime) recoveredInstallationManifest(ctx context.Context, installation ApplicationInstallation) (linuxApplicationReleaseManifest, error) {
	manifest, err := runtime.loadActiveApplicationManifest(installation.ID)
	if err != nil {
		return manifest, err
	}
	if err := validateRecoveredManifest(manifest, installation); err != nil {
		return manifest, err
	}
	if runtime.DatabaseConnections == nil {
		return manifest, ErrPolicyDenied
	}
	id, err := database.NewResourceID(string(manifest.Database.ID))
	if err != nil {
		return manifest, err
	}
	connection, err := runtime.DatabaseConnections.ApplicationConnection(ctx, id, string(installation.TenantID), string(installation.SiteID))
	if err != nil {
		return manifest, err
	}
	defer wipeLinuxApplicationBytes(connection.CertificateAuthorityPEM)
	if err := validateRecoveredConnection(manifest.Database, connection); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func validateRecoveredConnection(binding DatabaseBinding, connection database.ApplicationConnection) error {
	if connection.InstanceID.String() != string(binding.InstanceID) || connection.DatabaseName != binding.DatabaseName || connection.PrincipalName != binding.PrincipalName {
		return ErrPolicyDenied
	}
	return nil
}

func validateRecoveredManifest(manifest linuxApplicationReleaseManifest, installation ApplicationInstallation) error {
	if manifest.Validate() != nil || manifest.InstallationID != installation.ID || manifest.TenantID != installation.TenantID || manifest.SiteID != installation.SiteID || manifest.DefinitionID != installation.DefinitionID || manifest.Kind != installation.Kind || manifest.RecipeDigest != installation.Recipe.RecipeDigest || manifest.ProductVersion != installation.Recipe.ProductVersion || manifest.RuntimeID != installation.RuntimeID {
		return ErrPolicyDenied
	}
	return nil
}

func (provider *LinuxApplicationRecoveryProvider) RecoverInstallationOwnership(ctx context.Context, installation ApplicationInstallation, snapshot RecoveryPointID) (DatabaseBindingID, []SecretRef, ReleaseID, error) {
	leases, ok := provider.Store.(interface {
		recoveredInstallationSecrets(context.Context, ApplicationInstallation) ([]SecretRef, error)
	})
	if !ok || provider.Client == nil {
		return "", nil, "", ErrRecoveryRequired
	}
	request := removalRecoveryRequest(installation)
	var output applicationRecoveryOutput
	if err := provider.Client.call(ctx, applicationRecoveryCreate, installation.SiteID, applicationRecoveryInput{request, installation}, &output); err != nil {
		return "", nil, "", err
	}
	if output.ID != snapshot || output.Ownership == nil {
		return "", nil, "", ErrIntegrity
	}
	manifest := *output.Ownership
	if err := validateRecoveredManifest(manifest, installation); err != nil {
		return "", nil, "", err
	}
	release, err := provider.Store.LoadRelease(ctx, manifest.ReleaseID)
	if err != nil {
		return "", nil, "", err
	}
	if release.InstallationID != installation.ID || release.RecipeDigest != manifest.RecipeDigest || release.ContentDigest != linuxApplicationDigest(mustLinuxApplicationJSON(manifest.Artifact.Digest)) || release.ProductVersion != manifest.ProductVersion {
		return "", nil, "", ErrPolicyDenied
	}
	refs, err := leases.recoveredInstallationSecrets(ctx, installation)
	return manifest.Database.ID, refs, manifest.ReleaseID, err
}

func (repository SQLRepository) recoveredInstallationSecrets(ctx context.Context, installation ApplicationInstallation) ([]SecretRef, error) {
	rows, err := repository.DB.QueryContext(ctx, `SELECT metadata_json FROM app_secret_leases WHERE installation_id=? ORDER BY secret_id`, installation.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []SecretRef
	configuration := false
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var lease ApplicationSecretLease
		if json.Unmarshal(payload, &lease) != nil || lease.Validate() != nil || lease.InstallationID != installation.ID || lease.Metadata.OwnerTenantID != ApplicationTenantOwnerID(string(installation.TenantID)) {
			return nil, ErrPolicyDenied
		}
		audience := lease.Metadata.Audience
		resource, kind := ApplicationAudienceID(string(installation.ID)), "application_installation"
		if lease.Purpose == "administrator" {
			resource, kind = ApplicationAudienceID(string(installation.SiteID)), "hosting_site"
		} else if lease.Purpose != "configuration" && lease.Purpose != "database_tls" {
			return nil, ErrPolicyDenied
		}
		if audience.ResourceID != resource || audience.ResourceKind != kind || audience.AdapterID != ApplicationSecretAdapterID || audience.AdapterVersion != ApplicationSecretAdapterVersion || audience.Account != "site-application" || audience.Origin != "local://panel-execd/applications" || audience.ResourceGeneration != 1 || len(audience.Operations) != 1 || audience.Operations[0] != secrets.OperationAuthenticate || lease.Metadata.Purpose != secrets.PurposeAuthentication {
			return nil, ErrPolicyDenied
		}
		if lease.Purpose == "configuration" {
			configuration = true
		}
		refs = append(refs, SecretRef(lease.Metadata.ID.String()))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !configuration {
		return nil, ErrRecoveryRequired
	}
	return refs, nil
}
