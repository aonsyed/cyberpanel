package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

// lookupHAIntent recovers the central ID of one previously submitted HA intent.
// It never queues work. The authenticated operator's tenant, an explicit grant,
// and the original stable request digest all constrain the durable lookup.
func (api *OperatorAPI) lookupHAIntent(writer http.ResponseWriter, request *http.Request, operator Operator) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(request.URL.RawQuery) > 2048 || len(query) != 5 || !emptyOperatorBody(request) {
		api.reject(writer, request, operator, "intent.inspect", "intent", "lookup", ErrInvalid)
		return
	}
	for _, name := range []string{"tenant_id", "node_id", "grant_id", "idempotency_key", "request_digest"} {
		if len(query[name]) != 1 || query.Get(name) == "" {
			api.reject(writer, request, operator, "intent.inspect", "intent", "lookup", ErrInvalid)
			return
		}
	}
	node, grant := federation.ID(query.Get("node_id")), federation.ID(query.Get("grant_id"))
	if query.Get("tenant_id") != operator.TenantID || !node.Valid() || !grant.Valid() || api.authority.authorizePermission(request.Context(), operator, "intent.inspect") != nil || api.authority.authorizePermission(request.Context(), operator, "grant.inspect") != nil {
		api.reject(writer, request, operator, "intent.inspect", "node", node.String(), ErrForbidden)
		return
	}
	if !api.admit(writer, request, operator, "intent.inspect", "node", node.String()) { return }
	intent, err := api.store.LookupHAIntent(request.Context(), operator.TenantID, node, grant, query.Get("idempotency_key"), query.Get("request_digest"))
	api.complete(writer, request, operator, "intent.inspect", "node", node.String(), intent, err)
}

func (s *Store) LookupHAIntent(ctx context.Context, tenant string, node, grant federation.ID, idempotency, requestDigest string) (federation.Intent, error) {
	if s == nil || s.db == nil || ctx == nil || !federation.ID(tenant).Valid() || !node.Valid() || !grant.Valid() || idempotency == "" || len(idempotency) > 256 || strings.ContainsAny(idempotency, "\x00\r\n\t ") || !validSHA256(requestDigest) { return federation.Intent{}, ErrInvalid }
	// Grant ownership is checked even for expired/revoked grants: observation
	// does not grant fresh execution authority and must survive a revoke.
	record, err := s.InspectMutationGrant(ctx, grant)
	if err != nil { return federation.Intent{}, err }
	if record.OwnerTenantID.String() != tenant || record.NodeID != node { return federation.Intent{}, ErrForbidden }
	// The SQLite control store already persists the canonical signed intent.
	// Use that durable value, not a second mutable reconciliation ledger.
	rows, err := s.db.QueryContext(ctx, `SELECT intent_json FROM fleet_intents
	 WHERE owner_tenant_id=? AND node_id=?
	 AND json_extract(intent_json,'$.TenantID')=?
	 AND json_extract(intent_json,'$.GrantID')=?
	 AND json_extract(intent_json,'$.IdempotencyKey')=? LIMIT 2`, tenant, node, tenant, grant, idempotency)
	if err != nil { return federation.Intent{}, err }
	defer rows.Close()
	var found federation.Intent
	count := 0
	for rows.Next() {
		count++
		if count > 1 { return federation.Intent{}, ErrConflict }
		var raw []byte
		if err = rows.Scan(&raw); err != nil { return federation.Intent{}, err }
		if json.Unmarshal(raw, &found) != nil || found.TenantID != tenant || found.NodeID != node || found.GrantID != grant || found.IdempotencyKey != idempotency || found.PeerID != record.PeerID { return federation.Intent{}, ErrConflict }
		digest, digestErr := ha.FederatedHAApprovalPlanDigest(found, tenant, grant)
		if digestErr != nil || digest != requestDigest || len(found.Approvals) != 1 || found.Approvals[0].PlanDigest != requestDigest || found.Approvals[0].PolicyVersion != ha.FederatedHAApprovalPolicyVersion || found.Validate(found.IssuedAt) != nil { return federation.Intent{}, ErrConflict }
	}
	if err = rows.Err(); err != nil { return federation.Intent{}, err }
	if count == 0 { return federation.Intent{}, ErrNotFound }
	return found, nil
}
