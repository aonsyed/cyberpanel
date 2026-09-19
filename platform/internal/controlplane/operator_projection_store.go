package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const projectionReadMaximumPayload = 256 << 10

type ProjectionInventoryState struct {
	NodeID federation.ID `json:"node_id"`
	NodeState NodeState `json:"node_state"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	ProjectionSequence uint64 `json:"projection_sequence"`
	SnapshotGeneration uint64 `json:"snapshot_generation"`
	SnapshotReceiptGeneration uint64 `json:"snapshot_receipt_generation"`
	SnapshotWatermark uint64 `json:"snapshot_watermark"`
	SnapshotPending bool `json:"snapshot_pending"`
	TransportSnapshotComplete bool `json:"transport_snapshot_complete"`
	BaselineGeneration *uint64 `json:"baseline_generation"`
	BaselineComplete bool `json:"baseline_complete"`
	Authoritative bool `json:"authoritative"`
	InventoryState string `json:"inventory_state"`
	BaselineReason string `json:"baseline_reason"`
}

type ResourceProjectionRecord struct {
	NodeID federation.ID `json:"node_id"`
	TenantID string `json:"tenant_id"`
	ResourceKind string `json:"resource_kind"`
	ResourceID string `json:"resource_id"`
	Generation uint64 `json:"generation"`
	EventSequence uint64 `json:"event_sequence"`
	Digest string `json:"digest"`
	ObservedAt time.Time `json:"observed_at"`
	Stale bool `json:"stale"`
	Freshness string `json:"freshness"`
	Operation string `json:"operation,omitempty"`
	Status json.RawMessage `json:"status"`
	StatusAvailable bool `json:"status_available"`
	StatusSanitized bool `json:"status_sanitized"`
	NodeInventory ProjectionInventoryState `json:"node_inventory"`
}

type ProjectionInventoryPage struct {
	Rows []ResourceProjectionRecord `json:"rows"`
	NextCursor string `json:"next_cursor,omitempty"`
	PageComplete bool `json:"page_complete"`
	Consistency string `json:"consistency"`
	Node *ProjectionInventoryState `json:"node,omitempty"`
	InventoryAuthoritative bool `json:"inventory_authoritative"`
	InventoryComplete bool `json:"inventory_complete"`
}

type projectionCursor struct {
	Version uint32 `json:"v"`
	Tenant string `json:"t"`
	NodeFilter string `json:"n"`
	KindFilter string `json:"k"`
	LastNode string `json:"ln"`
	LastKind string `json:"lk"`
	LastResource string `json:"lr"`
}

func projectionResourceKindAllowed(kind string) bool {
	for _, allowed := range federation.NodeProjectionResourceKinds() { if kind == allowed { return true } }
	return false
}

func validProjectionResourceID(value string) bool {
	return value != "" && safeProjectionText(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "/\\\x00\r\n") && value != "." && value != ".."
}

func decodeProjectionCursor(encoded, tenant, node, kind string) (projectionCursor, error) {
	var cursor projectionCursor
	if encoded == "" { return cursor, nil }
	if len(encoded) > 2048 { return cursor, ErrInvalid }
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded { return cursor, ErrInvalid }
	decoder := json.NewDecoder(bytes.NewReader(raw)); decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || decoder.Decode(&struct{}{}) != io.EOF || cursor.Version != 1 || cursor.Tenant != tenant || cursor.NodeFilter != node || cursor.KindFilter != kind || !federation.ID(cursor.LastNode).Valid() || !projectionResourceKindAllowed(cursor.LastKind) || !validProjectionResourceID(cursor.LastResource) || node != "" && cursor.LastNode != node || kind != "" && cursor.LastKind != kind { return projectionCursor{}, ErrInvalid }
	canonical, err := json.Marshal(cursor)
	if err != nil || !bytes.Equal(raw, canonical) { return projectionCursor{}, ErrInvalid }
	return cursor, nil
}

// The cursor is an opaque canonical seek tuple, not an authorization token.
// Tenant and filter binding are checked again on every request; all SQL also
// binds both the node owner and persisted projection tenant independently.
func encodeProjectionCursor(tenant, node, kind string, last ResourceProjectionRecord) string {
	raw, _ := json.Marshal(projectionCursor{1, tenant, node, kind, last.NodeID.String(), last.ResourceKind, last.ResourceID})
	return base64.RawURLEncoding.EncodeToString(raw)
}

const projectionInventoryColumns = `n.id,n.state,n.authority_epoch,n.projection_sequence,n.snapshot_generation,COALESCE(r.generation,0),COALESCE(r.watermark,0),COALESCE(s.state='receiving',false)`
const projectionInventoryJoins = ` LEFT JOIN fleet_projection_snapshot_receipts_v1 r ON r.node_id=n.id LEFT JOIN fleet_projection_snapshots_v1 s ON s.node_id=n.id `
const projectionRecordColumns = `p.node_id,p.tenant_id,p.resource_kind,p.resource_id,p.generation,p.event_sequence,p.digest,p.observed_at,p.stale,CASE WHEN octet_length(p.status_json)<=262144 THEN p.status_json ELSE NULL END,`

func finishProjectionTransport(value *ProjectionInventoryState) {
	value.TransportSnapshotComplete = !value.SnapshotPending && value.SnapshotGeneration > 0 && value.SnapshotReceiptGeneration == value.SnapshotGeneration && value.SnapshotWatermark <= value.ProjectionSequence
}

func applyProjectionBaseline(value *ProjectionInventoryState, baseline ProjectionBaselineStatus) {
	finishProjectionTransport(value)
	value.BaselineGeneration = nil
	value.BaselineComplete = false
	value.Authoritative = false
	value.InventoryState = "baseline_incomplete"
	value.BaselineReason = baseline.Reason
	if baseline.NodeID != value.NodeID || baseline.AuthorityEpoch != value.AuthorityEpoch || baseline.SnapshotGeneration != value.SnapshotGeneration {
		value.BaselineReason = "baseline_scope_mismatch"
		return
	}
	if !baseline.ObservedAt.IsZero() {
		generation := baseline.SnapshotGeneration
		value.BaselineGeneration = &generation
	}
	if !baseline.Authoritative {
		if value.BaselineReason == "" {
			value.BaselineReason = "baseline_not_authoritative"
		}
		return
	}
	value.BaselineComplete = true
	value.Authoritative = true
	value.InventoryState = "authoritative"
	value.BaselineReason = "authoritative"
}

func projectionInventoryForNode(ctx context.Context, tx *authorityTx, tenant, node string) (ProjectionInventoryState, error) {
	var value ProjectionInventoryState
	err := tx.QueryRowContext(ctx, `SELECT `+projectionInventoryColumns+` FROM fleet_nodes n `+projectionInventoryJoins+` WHERE n.owner_tenant_id=? AND n.id=?`, tenant, node).Scan(&value.NodeID,&value.NodeState,&value.AuthorityEpoch,&value.ProjectionSequence,&value.SnapshotGeneration,&value.SnapshotReceiptGeneration,&value.SnapshotWatermark,&value.SnapshotPending)
	if errors.Is(err, sql.ErrNoRows) { return value, ErrNotFound }
	if err != nil { return value, err }
	baseline, err := projectionBaselineStatusTx(ctx, tx, federation.ID(tenant), value.NodeID)
	if err != nil { return value, err }
	applyProjectionBaseline(&value, baseline)
	return value, nil
}

type projectionRowScanner interface { Scan(...any) error }

func scanResourceProjection(scanner projectionRowScanner) (ResourceProjectionRecord, error) {
	var value ResourceProjectionRecord
	var raw []byte
	var stale int
	node := &value.NodeInventory
	if err := scanner.Scan(&value.NodeID,&value.TenantID,&value.ResourceKind,&value.ResourceID,&value.Generation,&value.EventSequence,&value.Digest,&value.ObservedAt,&stale,&raw,&node.NodeID,&node.NodeState,&node.AuthorityEpoch,&node.ProjectionSequence,&node.SnapshotGeneration,&node.SnapshotReceiptGeneration,&node.SnapshotWatermark,&node.SnapshotPending); err != nil { return value, err }
	finishProjectionTransport(node)
	value.Status = json.RawMessage(`{}`)
	value.StatusSanitized = true
	value.Stale = stale != 0 || node.NodeState != NodeOnline || node.SnapshotPending || value.EventSequence == 0 || value.EventSequence > node.ProjectionSequence
	value.StatusAvailable = sanitizeProjectionStatus(&value, raw)
	if !value.StatusAvailable { value.Stale = true }
	value.Freshness = "live"
	if value.Stale { value.Freshness = "stale" }
	return value, nil
}

func (s *Store) ProjectionInventory(ctx context.Context, tenant, node, kind, encodedCursor string, limit uint32) (ProjectionInventoryPage, error) {
	page := ProjectionInventoryPage{Rows: []ResourceProjectionRecord{}, Consistency: "live_keyset_pages_not_a_frozen_inventory"}
	if s == nil || ctx == nil || !federation.ID(tenant).Valid() || limit < 1 || limit > 100 || node != "" && !federation.ID(node).Valid() || kind != "" && !projectionResourceKindAllowed(kind) { return page, ErrInvalid }
	cursor, err := decodeProjectionCursor(encodedCursor, tenant, node, kind)
	if err != nil { return page, err }
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil { return page, err }; defer tx.Rollback()
	if node != "" {
		state, stateErr := projectionInventoryForNode(ctx, tx, tenant, node)
		if stateErr != nil { return page, stateErr }
		page.Node = &state
	}
	kinds := federation.NodeProjectionResourceKinds()
	if len(kinds) == 0 { return page, ErrForbidden }
	query := `SELECT `+projectionRecordColumns+projectionInventoryColumns+` FROM fleet_projections p JOIN fleet_nodes n ON n.id=p.node_id `+projectionInventoryJoins+` WHERE p.tenant_id=? AND n.owner_tenant_id=? AND p.resource_kind IN (`+strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",")+`)`
	args := []any{tenant, tenant}
	for _, allowed := range kinds { args = append(args, allowed) }
	if node != "" { query += ` AND p.node_id=?`; args = append(args, node) }
	if kind != "" { query += ` AND p.resource_kind=?`; args = append(args, kind) }
	if encodedCursor != "" { query += ` AND (p.node_id COLLATE "C",p.resource_kind COLLATE "C",p.resource_id COLLATE "C")>(? COLLATE "C",? COLLATE "C",? COLLATE "C")`; args = append(args, cursor.LastNode, cursor.LastKind, cursor.LastResource) }
	query += ` ORDER BY p.node_id COLLATE "C",p.resource_kind COLLATE "C",p.resource_id COLLATE "C" LIMIT ?`
	args = append(args, limit+1)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil { return page, err }
	for rows.Next() {
		value, scanErr := scanResourceProjection(rows)
		if scanErr != nil { _ = rows.Close(); return page, scanErr }
		page.Rows = append(page.Rows, value)
	}
	err = rows.Err(); _ = rows.Close()
	if err != nil { return page, err }
	page.PageComplete = len(page.Rows) <= int(limit)
	if !page.PageComplete {
		page.Rows = page.Rows[:limit]
		page.NextCursor = encodeProjectionCursor(tenant, node, kind, page.Rows[len(page.Rows)-1])
	}
	if page.Node != nil {
		for index := range page.Rows {
			page.Rows[index].NodeInventory = *page.Node
		}
		page.InventoryAuthoritative = page.Node.Authoritative
		page.InventoryComplete = page.Node.BaselineComplete
	} else {
		// The keyset page is capped at 100 rows, so baseline evaluation is also
		// capped at 100 distinct nodes rather than growing per stored row.
		baselines := make(map[federation.ID]ProjectionBaselineStatus, len(page.Rows))
		for index := range page.Rows {
			nodeID := page.Rows[index].NodeID
			baseline, exists := baselines[nodeID]
			if !exists {
				baseline, err = projectionBaselineStatusTx(ctx, tx, federation.ID(tenant), nodeID)
				if err != nil { return page, err }
				baselines[nodeID] = baseline
			}
			applyProjectionBaseline(&page.Rows[index].NodeInventory, baseline)
		}
		// Unfiltered pages can omit nodes with no rows and are not frozen across
		// cursors, so they never claim tenant-wide inventory completeness.
		page.InventoryAuthoritative = false
		page.InventoryComplete = false
	}
	return page, tx.Commit()
}

func (s *Store) ResourceProjection(ctx context.Context, tenant, node, kind, resource string) (ResourceProjectionRecord, error) {
	var value ResourceProjectionRecord
	if s == nil || ctx == nil || !federation.ID(tenant).Valid() || !federation.ID(node).Valid() || !projectionResourceKindAllowed(kind) || !validProjectionResourceID(resource) { return value, ErrInvalid }
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil { return value, err }; defer tx.Rollback()
	query := `SELECT `+projectionRecordColumns+projectionInventoryColumns+` FROM fleet_projections p JOIN fleet_nodes n ON n.id=p.node_id `+projectionInventoryJoins+` WHERE p.tenant_id=? AND n.owner_tenant_id=? AND p.node_id=? AND p.resource_kind=? AND p.resource_id=? LIMIT 1`
	value, err = scanResourceProjection(tx.QueryRowContext(ctx, query, tenant, tenant, node, kind, resource))
	if errors.Is(err, sql.ErrNoRows) { return value, ErrNotFound }
	if err != nil { return value, err }
	baseline, err := projectionBaselineStatusTx(ctx, tx, federation.ID(tenant), value.NodeID)
	if err != nil { return value, err }
	applyProjectionBaseline(&value.NodeInventory, baseline)
	return value, tx.Commit()
}

// Only bounded scalar/identifier summary fields are exposed. Nested specs,
// credentials, references, paths, provider data, errors, logs and arbitrary
// payload fields never pass through this read surface. Digests still refer to
// original node observation bytes, not this lossy presentation JSON.
var projectionSummaryFields = strings.Fields("schema name hostname kind state lifecycle desiredLifecycle observedLifecycle siteLifecycle health reconciliation phase tier storageMode productVersion phpProfile role dnssecPhase install enable active config drift messageCode siteId projectId parentId policyId definitionId generation sourceGeneration observedGeneration policyGeneration authzEpoch serial dnssecGeneration domainCount transferPeerCount repositoryCount requiredCopies copyCount verifiedCopies failedCopies prunedCopies restartCount attempt configGeneration renewBeforeNanos providerBound enabled mustStaple reuseKey dependenciesReady expectedListenersOwned internallyHealthy externallyFunctional desiredGenerationObserved needDaemonReload proofDigest specDigest observedDigest recipeDigest manifestDigest definitionDigest evidenceDigest createdAt updatedAt observedAt statusUpdatedAt notBefore notAfter names components requiredComponents")

func sanitizeProjectionStatus(value *ResourceProjectionRecord, raw []byte) bool {
	if len(raw) == 0 || len(raw) > projectionReadMaximumPayload || !validSHA256(value.Digest) || digest(raw) != value.Digest { return false }
	var payload struct {
		Schema string `json:"schema"`
		Operation string `json:"operation"`
		NodeID federation.ID `json:"nodeId"`
		AuthorityEpoch uint64 `json:"authorityEpoch"`
		TenantID string `json:"tenantId"`
		ResourceKind string `json:"resourceKind"`
		ResourceID string `json:"resourceId"`
		Generation uint64 `json:"generation"`
		ProjectionDigest string `json:"projectionDigest"`
		Status json.RawMessage `json:"status"`
	}
	if json.Unmarshal(raw, &payload) != nil || payload.Schema != "cyberpanel.federation.resource-projection.v1" || payload.NodeID != value.NodeID || payload.TenantID != value.TenantID || payload.ResourceKind != value.ResourceKind || payload.ResourceID != value.ResourceID || payload.Generation != value.Generation || payload.AuthorityEpoch != value.NodeInventory.AuthorityEpoch { return false }
	if payload.Operation == "tombstone" {
		if len(payload.Status) != 0 || payload.ProjectionDigest != digest([]byte("null")) { return false }
		value.Operation = payload.Operation
		return true
	}
	if payload.Operation != "upsert" || len(payload.Status) == 0 || payload.ProjectionDigest != digest(payload.Status) { return false }
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload.Status, &fields) != nil || fields == nil { return false }
	var schema string
	if json.Unmarshal(fields["schema"], &schema) != nil || schema != "cyberpanel.resource-summary.v1" { return false }
	safe := make(map[string]json.RawMessage)
	for _, key := range projectionSummaryFields {
		encoded, exists := fields[key]
		if !exists || len(encoded) > 8192 { continue }
		var text string
		var number uint64
		var flag bool
		var texts []string
		if bytes.Equal(encoded, []byte("null")) { continue }
		if json.Unmarshal(encoded, &text) == nil {
			if !safeProjectionText(text) { continue }
		} else if json.Unmarshal(encoded, &number) == nil {
		} else if json.Unmarshal(encoded, &flag) == nil {
		} else if json.Unmarshal(encoded, &texts) == nil && len(texts) <= 32 {
			valid := true; for _, entry := range texts { if !safeProjectionText(entry) { valid = false; break } }; if !valid { continue }
		} else { continue }
		safe[key] = encoded
	}
	encoded, err := json.Marshal(safe)
	if err != nil || len(encoded) > 16<<10 { return false }
	value.Operation = payload.Operation
	value.Status = encoded
	return true
}

func safeProjectionText(value string) bool {
	if len(value) > 256 || !utf8.ValidString(value) { return false }
	for _, character := range value { if character < 32 || character == 127 { return false } }
	return true
}
