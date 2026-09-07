package controlplane

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

// All authenticated requests in this namespace, including malformed/unsupported
// operations, use the existing operator audit admission/completion boundary.
func (api *OperatorAPI) projections(writer http.ResponseWriter, request *http.Request, operator Operator, segments []string) {
	permission := "projection.list"
	if len(segments) > 2 { permission = "projection.inspect" }
	target := "projection_inventory"
	if request.Method != http.MethodGet {
		if err := api.audit.Append(request.Context(), operator, permission, "projection", target, "rejected", "method_not_allowed"); err != nil { writeOperatorFailure(writer, err); return }
		writer.Header().Set("Allow", http.MethodGet)
		writeOperatorError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if len(segments) != 2 && len(segments) != 5 {
		api.reject(writer, request, operator, permission, "projection", target, ErrNotFound)
		return
	}
	if !emptyOperatorBody(request) {
		api.reject(writer, request, operator, permission, "projection", target, ErrInvalid)
		return
	}
	if err := api.authority.authorizePermission(request.Context(), operator, permission); err != nil {
		api.reject(writer, request, operator, permission, "projection", target, err)
		return
	}
	if len(segments) == 5 {
		node, kind, resource := segments[2], segments[3], segments[4]
		if request.URL.RawQuery != "" || request.URL.ForceQuery || !federation.ID(node).Valid() || !projectionResourceKindAllowed(kind) || !validProjectionResourceID(resource) {
			api.reject(writer, request, operator, permission, "projection", target, ErrInvalid)
			return
		}
		target = "projection_"+digest([]byte(strings.Join([]string{operator.TenantID,node,kind,resource}, "\x00")))[:48]
		if !api.admit(writer, request, operator, permission, "projection", target) { return }
		value, err := api.store.ResourceProjection(request.Context(), operator.TenantID, node, kind, resource)
		api.complete(writer, request, operator, permission, "projection", target, value, err)
		return
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || request.URL.ForceQuery {
		api.reject(writer, request, operator, permission, "projection", target, ErrInvalid)
		return
	}
	for key, values := range query {
		if key != "limit" && key != "cursor" && key != "node" && key != "kind" || len(values) != 1 || values[0] == "" {
			api.reject(writer, request, operator, permission, "projection", target, ErrInvalid)
			return
		}
	}
	limit := uint64(20)
	if raw := query.Get("limit"); raw != "" {
		limit, err = strconv.ParseUint(raw, 10, 32)
		if err != nil || limit < 1 || limit > 100 || strconv.FormatUint(limit, 10) != raw {
			api.reject(writer, request, operator, permission, "projection", target, ErrInvalid)
			return
		}
	}
	node, kind, cursor := query.Get("node"), query.Get("kind"), query.Get("cursor")
	if node != "" && !federation.ID(node).Valid() || kind != "" && !projectionResourceKindAllowed(kind) {
		api.reject(writer, request, operator, permission, "projection", target, ErrInvalid)
		return
	}
	if _, err = decodeProjectionCursor(cursor, operator.TenantID, node, kind); err != nil {
		api.reject(writer, request, operator, permission, "projection", target, err)
		return
	}
	// Audit identifies the exact tenant/filter/page scope by digest, never by
	// recording potentially sensitive resource/status contents or raw cursors.
	target = "projection_page_"+digest([]byte(operator.TenantID+"\x00"+query.Encode()))[:48]
	if !api.admit(writer, request, operator, permission, "projection", target) { return }
	page, err := api.store.ProjectionInventory(request.Context(), operator.TenantID, node, kind, cursor, uint32(limit))
	api.complete(writer, request, operator, permission, "projection", target, page, err)
}
