package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
)

// ProxyRouteState is the current catalog binding and the node-wide generation
// that was last confirmed by the privileged activation broker.
type ProxyRouteState struct {
	Route              composer.ProxyRouteInput
	SnapshotGeneration uint64
	AppliedDigest      string
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
