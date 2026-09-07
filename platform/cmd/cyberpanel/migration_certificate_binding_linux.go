//go:build linux

package main

import (
	"context"
	"errors"
	"sync"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	webcatalog "github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/controller"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

type migrationCertificateSiteBinding struct {
	target *migrationCertificateTarget
	catalog *webcatalog.SQLCatalog
	activator controller.VerifiedActivator
	mu sync.Mutex
}

// Install after constructing the certificate target and before registering its
// handler. It reuses the node's ordinary catalog and privileged renderer; no
// migration-selected path, engine, listener address or config text is accepted.
func bindMigrationCertificateSiteTLS(target *migrationCertificateTarget, catalog *webcatalog.SQLCatalog, activator controller.VerifiedActivator) error {
	if target == nil || catalog == nil || activator == nil || target.binding != nil { return migration.ErrInvalid }
	target.binding = &migrationCertificateSiteBinding{target: target, catalog: catalog, activator: activator}
	return nil
}

func (binding *migrationCertificateSiteBinding) scope(ctx context.Context, intent migration.ImportIntent, tenant, key string, generation uint64, names []string) (service.CommandScope, migrationCertificateAdmission, error) {
	admission, err := binding.target.admit(ctx, intent, false)
	if err != nil { return service.CommandScope{}, admission, err }
	if tenant != admission.scope.TenantID || key != admission.resource || generation != 1 || len(names) != 1 || names[0] != admission.value.Names[0] { return service.CommandScope{}, admission, migration.ErrBlocked }
	current, err := binding.target.secrets.repository.Migration(ctx, intent.MigrationID)
	if err != nil { return service.CommandScope{}, admission, err }
	manifest, err := binding.target.secrets.repository.Manifest(ctx, current.ManifestRoot)
	if err != nil { return service.CommandScope{}, admission, err }
	plan, err := binding.target.secrets.repository.Plan(ctx, current.PlanDigest)
	if err != nil { return service.CommandScope{}, admission, err }
	var source, mapped migration.ID
	for _, value := range manifest.Sites { if value.PrimaryHostname == names[0] { if source != "" { return service.CommandScope{}, admission, migration.ErrBlocked }; source = value.SourceID } }
	for _, item := range plan.Mappings {
		if item.SourceID == source && item.SourceKind == string(migration.ImportSite) {
			if mapped != "" || item.Disposition != migration.DispositionCreate || !item.TargetID.Valid() { return service.CommandScope{}, admission, migration.ErrBlocked }; mapped = item.TargetID
		}
	}
	if source == "" || mapped == "" { return service.CommandScope{}, admission, migration.ErrBlocked }
	tenantID, err := site.NewTenantID(tenant); if err != nil { return service.CommandScope{}, admission, err }
	siteID, err := site.NewSiteID(mapped.String()); if err != nil { return service.CommandScope{}, admission, err }
	return service.CommandScope{TenantID: tenantID, SiteID: siteID}, admission, nil
}

func migrationSiteTLS(scope service.CommandScope, key string) composer.TLSInput {
	return composer.TLSInput{OwnerScope: scope, PolicyRef: webengine.ResourceRef("tls/"+key), MaterialKey: native.MaterialKey(key), Generation: 1}
}

func (binding *migrationCertificateSiteBinding) Activate(ctx context.Context, intent migration.ImportIntent, tenant, key string, generation uint64, names []string) (string, error) {
	binding.mu.Lock(); defer binding.mu.Unlock()
	scope, _, err := binding.scope(ctx, intent, tenant, key, generation, names)
	if err != nil { return "", err }
	if err := binding.target.fence(ctx, intent); err != nil { return "", err }
	effect := "tls_"+key
	prepared, err := binding.catalog.PrepareSiteTLS(ctx, effect, scope, names[0], migrationSiteTLS(scope, key))
	if err != nil { return "", err }
	if prepared.Finalized { return binding.Observe(ctx, intent, tenant, key, generation, names) }
	composed, err := composer.Compose(prepared.Plan)
	if err != nil { _ = binding.catalog.Reject(ctx, prepared.Token, effect); return "", err }
	var renderer native.Renderer
	switch composed.Desired.Engine.Edition {
	case webengine.EditionOpenLiteSpeed: renderer = ols.New()
	case webengine.EditionLiteSpeedEnterprise: renderer = enterprise.New()
	default: _ = binding.catalog.Reject(ctx, prepared.Token, effect); return "", migration.ErrBlocked
	}
	request := native.RenderRequest{Desired: composed.Desired, Snapshot: composed.Snapshot}
	rendered, err := renderer.Render(ctx, request)
	if err != nil { _ = binding.catalog.Reject(ctx, prepared.Token, effect); return "", err }
	// Recheck immediately before the privileged activation; an expired fence
	// leaves a recoverable pending catalog intent rather than enabling traffic.
	if err := binding.target.fence(ctx, intent); err != nil { return "", err }
	receipt, err := binding.activator.ApplyVerified(ctx, request, rendered.ContentDigest)
	if err != nil || receipt.Status != activation.Applied || !receipt.Confirmed || receipt.Digest != rendered.ContentDigest {
		if receipt.Status == activation.RolledBack { _ = binding.catalog.Reject(ctx, prepared.Token, effect) }
		return "", errors.Join(migration.ErrBlocked, err)
	}
	if err := binding.target.fence(ctx, intent); err != nil { return "", err }
	if err := binding.catalog.Finalize(ctx, prepared.Token, receipt.Digest); err != nil { return "", err }
	return binding.Observe(ctx, intent, tenant, key, generation, names)
}

func (binding *migrationCertificateSiteBinding) Observe(ctx context.Context, intent migration.ImportIntent, tenant, key string, generation uint64, names []string) (string, error) {
	scope, admission, err := binding.scope(ctx, intent, tenant, key, generation, names)
	if err != nil { return "", err }
	actual, nodeGeneration, nodeDigest, err := binding.catalog.SiteTLS(ctx, scope, names[0])
	if err != nil || actual != migrationSiteTLS(scope, key) { return "", errors.Join(migration.ErrConflict, err) }
	if err := migrationCertificateSNI(ctx, names[0], admission.fingerprint); err != nil { return "", err }
	digest, _, err := migrationSecretDigest(struct { Scope service.CommandScope; Material composer.TLSInput; NodeGeneration uint64; NodeDigest, Leaf string }{scope, actual, nodeGeneration, nodeDigest, admission.fingerprint})
	return digest, err
}

var _ migrationCertificateBinding = (*migrationCertificateSiteBinding)(nil)
