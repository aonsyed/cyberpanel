package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/controller"
)

type PreparedSiteTLS struct {
	controller.PreparedPlan
	Finalized bool
}

// PrepareSiteTLS replaces only an absent TLS binding on an existing owned
// site. The ordinary webengine_changes journal provides cross-process single
// writer exclusion, immutable replay and the existing Finalize/Reject path.
func (catalog *SQLCatalog) PrepareSiteTLS(ctx context.Context, effect string, scope service.CommandScope, hostname string, material composer.TLSInput) (PreparedSiteTLS, error) {
	if catalog == nil || catalog.db == nil || len(effect) < 8 || len(effect) > 128 || scope.TenantID.String() == "" || scope.SiteID.String() == "" || material.OwnerScope != scope || material.Generation != 1 || material.PolicyRef == "" || material.MaterialKey == "" { return PreparedSiteTLS{}, ErrChangeClosed }
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return PreparedSiteTLS{}, err }; defer tx.Rollback()
	if existing, found, err := loadExistingChange(ctx, tx, effect); err != nil { return PreparedSiteTLS{}, err } else if found {
		if existing.status != "pending" && existing.status != "finalized" { return PreparedSiteTLS{}, ErrChangeClosed }
		matched := 0
		for _, input := range existing.plan.Sites {
			if input.Scope != scope { continue }; matched++
			if !tlsHostnameOwned(input, hostname) || len(input.TLS) != 1 || input.TLS[0] != material { return PreparedSiteTLS{}, ErrChangeClosed }
		}
		if matched != 1 { return PreparedSiteTLS{}, ErrChangeClosed }
		return PreparedSiteTLS{PreparedPlan: controller.PreparedPlan{Token: existing.token, Plan: existing.plan}, Finalized: existing.status == "finalized"}, tx.Commit()
	}
	var pending string
	err = tx.QueryRowContext(ctx, `SELECT effect_id FROM webengine_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_proxy_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_access_changes WHERE status='pending' UNION ALL SELECT effect_id FROM webengine_node_changes WHERE status='pending' LIMIT 1`).Scan(&pending)
	if err == nil { return PreparedSiteTLS{}, ErrChangeBusy }; if !errors.Is(err, sql.ErrNoRows) { return PreparedSiteTLS{}, err }
	input, err := loadTLSSite(ctx, tx, scope)
	if err != nil { return PreparedSiteTLS{}, err }
	if !tlsHostnameOwned(input, hostname) || len(input.TLS) != 0 { return PreparedSiteTLS{}, ErrChangeClosed }
	input.TLS = []composer.TLSInput{material}
	configuration, generation, err := loadConfiguration(ctx, tx)
	if err != nil { return PreparedSiteTLS{}, err }
	values, err := loadSiteInputs(ctx, tx, scope, input)
	if err != nil { return PreparedSiteTLS{}, err }
	routes, err := loadProxyRoutes(ctx, tx, composer.ProxyRouteInput{}, true)
	if err != nil { return PreparedSiteTLS{}, err }
	policies, err := loadAccessPolicies(ctx, tx, "", true)
	if err != nil { return PreparedSiteTLS{}, err }
	plan := composer.Plan{Engine: configuration.Engine, SnapshotGeneration: generation+1, Sites: values, DefaultTLS: configuration.DefaultTLS, ProxyRoutes: routes, AccessPolicies: policies}
	if _, err := composer.Compose(plan); err != nil { return PreparedSiteTLS{}, err }
	token, err := controller.NewChangeToken(changeToken(effect))
	if err != nil { return PreparedSiteTLS{}, err }
	planRaw, err := json.Marshal(plan); if err != nil { return PreparedSiteTLS{}, err }
	inputRaw, err := json.Marshal(input); if err != nil { return PreparedSiteTLS{}, err }
	_, err = tx.ExecContext(ctx, `INSERT INTO webengine_changes(change_token,effect_id,tenant_id,site_id,status,plan_json,proposed_input_json,withdraw,activation_digest,created_at) VALUES(?,?,?,?,'pending',?,?,0,'',?)`, token.String(), effect, scope.TenantID.String(), scope.SiteID.String(), planRaw, inputRaw, catalog.clock().UTC())
	if err != nil { return PreparedSiteTLS{}, err }
	if err := tx.Commit(); err != nil { return PreparedSiteTLS{}, err }
	return PreparedSiteTLS{PreparedPlan: controller.PreparedPlan{Token: token, Plan: plan}}, nil
}

// SiteTLS reports the current catalog generation, not an old effect receipt.
// Callers still need a real endpoint leaf probe before claiming serving TLS.
func (catalog *SQLCatalog) SiteTLS(ctx context.Context, scope service.CommandScope, hostname string) (composer.TLSInput, uint64, string, error) {
	if catalog == nil || catalog.db == nil { return composer.TLSInput{}, 0, "", ErrChangeClosed }
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil { return composer.TLSInput{}, 0, "", err }; defer tx.Rollback()
	input, err := loadTLSSite(ctx, tx, scope)
	if err != nil { return composer.TLSInput{}, 0, "", err }
	if !tlsHostnameOwned(input, hostname) || len(input.TLS) != 1 || input.TLS[0].OwnerScope != scope { return composer.TLSInput{}, 0, "", ErrChangeClosed }
	var generation uint64; var digest string
	err = tx.QueryRowContext(ctx, `SELECT snapshot_generation,applied_digest FROM webengine_node_config WHERE singleton_id=1`).Scan(&generation,&digest)
	if err != nil || generation == 0 || !validDigest(digest) { return composer.TLSInput{}, 0, "", ErrChangeClosed }
	return input.TLS[0], generation, digest, tx.Commit()
}

func loadTLSSite(ctx context.Context, tx *sql.Tx, scope service.CommandScope) (composer.SiteInput, error) {
	var raw []byte; var input composer.SiteInput
	if err := tx.QueryRowContext(ctx, `SELECT input_json FROM webengine_site_inputs WHERE tenant_id=? AND site_id=?`, scope.TenantID.String(), scope.SiteID.String()).Scan(&raw); err != nil { return input, err }
	if json.Unmarshal(raw, &input) != nil || input.Scope != scope { return input, ErrChangeClosed }
	return input, nil
}

func tlsHostnameOwned(input composer.SiteInput, hostname string) bool {
	if input.Withdraw || input.Projection.Lifecycle == site.LifecyclePurging || input.Projection.Lifecycle == site.LifecycleDeleted || hostname == "" { return false }
	matched := false
	for _, binding := range input.Projection.Bindings {
		if binding.Kind == site.BindingPreview { continue }
		if binding.Hostname.String() != hostname || binding.Kind != site.BindingPrimary || matched { return false }; matched = true
	}
	return matched
}

// Provisioning resolves roots and pools, not certificate authority. Preserve
// the existing TLS binding across ordinary lifecycle generations; refuse name
// expansion until the certificate authority explicitly covers those names.
func preserveOwnedSiteTLS(ctx context.Context, tx *sql.Tx, input *composer.SiteInput) error {
	if input.Withdraw { return nil }
	previous, err := loadTLSSite(ctx, tx, input.Scope)
	if errors.Is(err, sql.ErrNoRows) { return nil }; if err != nil { return err }
	if len(previous.TLS) == 0 { return nil }
	if len(previous.TLS) != 1 || previous.TLS[0].OwnerScope != input.Scope { return ErrChangeClosed }
	if len(input.TLS) != 0 && !reflect.DeepEqual(input.TLS, previous.TLS) { return ErrChangeClosed }
	names := func(value composer.SiteInput) map[string]bool {
		result := make(map[string]bool)
		for _, binding := range value.Projection.Bindings { if binding.Kind != site.BindingPreview { result[binding.Hostname.String()] = true } }
		return result
	}
	if !reflect.DeepEqual(names(*input), names(previous)) { return ErrChangeClosed }
	input.TLS = append([]composer.TLSInput(nil), previous.TLS...)
	return nil
}
