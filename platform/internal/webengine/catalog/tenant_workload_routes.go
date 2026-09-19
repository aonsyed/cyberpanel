package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
)

// ProvisioningSiteHandoff is the exact catalog reservation that may be
// converted into one same-owner workload route. The projection remains in the
// catalog until the new proxy generation has been observed live.
type ProvisioningSiteHandoff struct {
	Scope                   service.CommandScope
	Hostname                webengine.Hostname
	ListenerRef             webengine.ResourceRef
	ListenerPort            uint16
	ProjectionGeneration    uint64
	ProjectionDigest        string
	ConfigurationGeneration uint64
	ConfigurationDigest     string
}

func (catalog *SQLCatalog) ProvisioningSiteHandoff(ctx context.Context, scope service.CommandScope, hostname string, listenerRef webengine.ResourceRef) (ProvisioningSiteHandoff, error) {
	var handoff ProvisioningSiteHandoff
	parsed, err := webengine.ParseHostname(hostname)
	if catalog == nil || catalog.db == nil || ctx == nil || err != nil || scope.TenantID.String() == "" || scope.SiteID.String() == "" || listenerRef == "" {
		return handoff, ErrChangeClosed
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return handoff, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT projection_generation,projection_digest,input_json FROM webengine_site_inputs WHERE tenant_id=? AND site_id=?`, scope.TenantID.String(), scope.SiteID.String()).Scan(&handoff.ProjectionGeneration, &handoff.ProjectionDigest, &raw)
	if err != nil {
		return ProvisioningSiteHandoff{}, err
	}
	var input composer.SiteInput
	if json.Unmarshal(raw, &input) != nil || input.Scope != scope || input.Withdraw || input.Projection.Generation != handoff.ProjectionGeneration || input.Projection.Lifecycle != site.LifecycleProvisioning || projectionDigestFromInput(input) != handoff.ProjectionDigest || len(input.Projection.Bindings) != 1 || input.Projection.Bindings[0].Kind != site.BindingPrimary || input.Projection.Bindings[0].Hostname.String() != parsed.String() || !validDigest(handoff.ProjectionDigest) {
		return ProvisioningSiteHandoff{}, ErrChangeClosed
	}
	var policies int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM webengine_access_policies WHERE tenant_id=? AND site_id=?`, scope.TenantID.String(), scope.SiteID.String()).Scan(&policies); err != nil || policies != 0 {
		return ProvisioningSiteHandoff{}, errors.Join(ErrChangeClosed, err)
	}
	var configurationRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT snapshot_generation,applied_digest,config_json FROM webengine_node_config WHERE singleton_id=1`).Scan(&handoff.ConfigurationGeneration, &handoff.ConfigurationDigest, &configurationRaw); err != nil {
		return ProvisioningSiteHandoff{}, err
	}
	var configuration NodeConfiguration
	if json.Unmarshal(configurationRaw, &configuration) != nil || handoff.ConfigurationGeneration == 0 || !validDigest(handoff.ConfigurationDigest) {
		return ProvisioningSiteHandoff{}, ErrChangeClosed
	}
	matched := 0
	for _, listener := range configuration.Engine.Listeners {
		if listener.Ref != listenerRef {
			continue
		}
		matched++
		if listener.TLSMode != webengine.TLSModeClear || listener.Port == 0 || len(listener.Protocols) != 1 || listener.Protocols[0] != webengine.ProtocolHTTP1 {
			return ProvisioningSiteHandoff{}, ErrChangeClosed
		}
		handoff.ListenerPort = listener.Port
	}
	if matched != 1 {
		return ProvisioningSiteHandoff{}, ErrChangeClosed
	}
	handoff.Scope = scope
	handoff.Hostname = parsed
	handoff.ListenerRef = listenerRef
	return handoff, tx.Commit()
}

// ProxyRouteState is the current catalog binding and the node-wide generation
// that was last confirmed by the privileged activation broker.
type ProxyRouteState struct {
	Route              composer.ProxyRouteInput
	SnapshotGeneration uint64
	AppliedDigest      string
}

type tenantWorkloadRouteHandoff struct {
	tenantID, siteID        string
	projectionGeneration    uint64
	projectionDigest        string
	configurationGeneration uint64
	configurationDigest     string
}

func loadTenantWorkloadRouteHandoff(ctx context.Context, tx *sql.Tx, effectID string, route composer.ProxyRouteInput) (*tenantWorkloadRouteHandoff, error) {
	if route.Ref == "" {
		return nil, nil
	}
	var handoff tenantWorkloadRouteHandoff
	var routeRef, storedEffect, hostname, listenerRef, endpoint, state string
	var generation uint64
	err := tx.QueryRowContext(ctx, `SELECT tenant_id,site_id,route_ref,activation_effect_id,hostname,listener_ref,generation,target_endpoint,site_projection_generation,site_projection_digest,site_configuration_generation,site_configuration_digest,state FROM webengine_tenant_workload_routes_v1 WHERE route_ref=?`, route.Ref).Scan(
		&handoff.tenantID, &handoff.siteID, &routeRef, &storedEffect, &hostname, &listenerRef, &generation, &endpoint, &handoff.projectionGeneration, &handoff.projectionDigest, &handoff.configurationGeneration, &handoff.configurationDigest, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	target, parseErr := netip.ParseAddrPort(endpoint)
	if parseErr != nil || routeRef != string(route.Ref) || storedEffect != effectID || hostname != route.Hostname.String() || listenerRef != string(route.ListenerRef) || generation != route.Generation || target.Addr() != netip.MustParseAddr("127.0.0.1") || target.Port() != route.UpstreamPort || handoff.projectionGeneration == 0 || !validDigest(handoff.projectionDigest) || handoff.configurationGeneration == 0 || !validDigest(handoff.configurationDigest) || state == "discarded" {
		return nil, ErrChangeClosed
	}
	return &handoff, nil
}

func (catalog *SQLCatalog) ProxyRouteState(ctx context.Context, routeRef webengine.ResourceRef) (ProxyRouteState, error) {
	var state ProxyRouteState
	if catalog == nil || catalog.db == nil || ctx == nil || routeRef == "" {
		return state, ErrChangeMissing
	}
	tx, err := catalog.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return state, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT input_json FROM webengine_proxy_routes WHERE route_ref=?`, routeRef).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return state, ErrChangeMissing
	}
	if err != nil || json.Unmarshal(raw, &state.Route) != nil || state.Route.Ref != routeRef || state.Route.Generation == 0 {
		return ProxyRouteState{}, errors.Join(ErrChangeClosed, err)
	}
	err = tx.QueryRowContext(ctx, `SELECT snapshot_generation,applied_digest FROM webengine_node_config WHERE singleton_id=1`).Scan(&state.SnapshotGeneration, &state.AppliedDigest)
	if err != nil || state.SnapshotGeneration == 0 || !validDigest(state.AppliedDigest) {
		return ProxyRouteState{}, errors.Join(ErrChangeClosed, err)
	}
	return state, tx.Commit()
}

// guardTenantWorkloadRouteTx prevents an ordinary proxy request from claiming
// a hostname/listener pair held by the durable tenant route authority. The one
// matching authority-owned route is admitted only with its canonical effect
// and exact immutable route ref, hostname, listener, generation, and endpoint.
func guardTenantWorkloadRouteTx(ctx context.Context, tx *sql.Tx, effectID string, route composer.ProxyRouteInput, withdraw bool) error {
	var routeRef, activationEffectID, hostname, listenerRef, endpoint, state string
	var generation uint64
	err := tx.QueryRowContext(ctx, `SELECT route_ref,activation_effect_id,hostname,listener_ref,generation,target_endpoint,state FROM webengine_tenant_workload_routes_v1 WHERE route_ref=? OR (hostname=? AND listener_ref=? AND state<>'discarded')`, route.Ref, route.Hostname.String(), route.ListenerRef).Scan(&routeRef, &activationEffectID, &hostname, &listenerRef, &generation, &endpoint, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if withdraw || state == "discarded" {
		return ErrChangeClosed
	}
	switch state {
	case "reserved", "activating", "ambiguous", "active":
	default:
		return ErrChangeClosed
	}
	target, parseErr := netip.ParseAddrPort(endpoint)
	if parseErr != nil || routeRef != string(route.Ref) || activationEffectID != effectID || hostname != route.Hostname.String() || listenerRef != string(route.ListenerRef) || generation != route.Generation || target.Addr() != netip.MustParseAddr("127.0.0.1") || target.Port() != route.UpstreamPort {
		return ErrChangeClosed
	}
	return nil
}

// guardTenantWorkloadSiteTx prevents an ordinary site generation from racing
// a reserved workload route for the same normalized hostname. A site route and
// reverse-proxy route cannot both own that public name safely.
func guardTenantWorkloadSiteTx(ctx context.Context, tx *sql.Tx, input composer.SiteInput) error {
	for _, binding := range input.Projection.Bindings {
		var reserved int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM webengine_tenant_workload_routes_v1 WHERE hostname=? AND state<>'discarded'`, binding.Hostname.String()).Scan(&reserved); err != nil {
			return err
		}
		if reserved != 0 {
			return ErrChangeClosed
		}
	}
	return nil
}
