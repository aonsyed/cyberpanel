package federation

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	ProjectionMaximumRows        = 10000
	ProjectionMaximumSourceBytes = 32 << 20
	ProjectionMaximumEvents      = ProjectionMaximumRows + 1
	ProjectionMaximumEventBytes  = 36 << 20
	ProjectionMaximumSpoolRows   = 20000
	ProjectionMaximumSpoolBytes  = 64 << 20
	projectionMaximumStatusBytes = 192 << 10
	projectionMaximumGeneration  = uint64(1<<63 - 1)
)

const projectionPublisherSchema = `
CREATE TABLE IF NOT EXISTS federation_projection_publisher_v1(
 singleton_id INTEGER PRIMARY KEY,node_id TEXT NOT NULL,authority_epoch BIGINT NOT NULL,
 scan_watermark BIGINT NOT NULL,baseline_complete INTEGER NOT NULL,manifest_digest TEXT NOT NULL,
 resource_count BIGINT NOT NULL,updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS federation_projection_ledger_v1(
 resource_kind TEXT NOT NULL,resource_id TEXT NOT NULL,tenant_id TEXT NOT NULL,
 source_generation BIGINT NOT NULL,published_generation BIGINT NOT NULL,
 status_digest TEXT NOT NULL,state TEXT NOT NULL,authority_epoch BIGINT NOT NULL,
 source_watermark BIGINT NOT NULL,updated_at TIMESTAMP NOT NULL,
 PRIMARY KEY(resource_kind,resource_id)
);
`

var ErrProjectionBackpressure = errors.New("federation: projection spool backpressure")

const (
	ProjectionUpsertEventKind           = "federation.projection.upsert.v1"
	ProjectionTombstoneEventKind        = "federation.projection.tombstone.v1"
	ProjectionBaselineCompleteEventKind = "federation.projection.baseline.complete.v1"
)

type ProjectionExclusion struct {
	ResourceKind string `json:"resourceKind"`
	Reason       string `json:"reason"`
}

type ProjectionCoverageManifest struct {
	SchemaVersion uint32                `json:"schemaVersion"`
	Included      []string              `json:"included"`
	Excluded      []ProjectionExclusion `json:"excluded"`
}

// NodeProjectionResourceKinds is the closed resource allowlist shared by the
// node producer and central read models. Callers receive their own slice.
func NodeProjectionResourceKinds() []string {
	return []string{
		"application.installation", "backup.policy", "backup.recovery_status",
		"certificate.policy", "certificate.status", "container.workload",
		"database.database", "database.instance", "database.principal", "dns.zone",
		"host.operation_status", "host.service_status", "hosting.domain", "hosting.site",
		"identity.tenant", "mail.alias", "mail.domain", "mail.mailbox",
	}
}

func nodeProjectionExclusionKinds() map[string]struct{} {
	return map[string]struct{}{
		"application.secret_and_content": {}, "backup.content_and_provider": {},
		"certificate.secret_and_challenge": {}, "container.secret_and_runtime": {},
		"database.secret_and_access": {}, "dns.record_and_key_material": {},
		"host.raw_and_audit": {}, "identity.principal_and_credential": {},
		"mail.content_and_credential": {},
	}
}

func NodeProjectionCoverage(serviceStatus bool) ProjectionCoverageManifest {
	included := NodeProjectionResourceKinds()
	if !serviceStatus {
		for index, kind := range included {
			if kind == "host.service_status" {
				included = append(included[:index], included[index+1:]...)
				break
			}
		}
	}
	excluded := []ProjectionExclusion{
		{ResourceKind: "application.secret_and_content", Reason: "filesystem roots, runtime IDs, database and secret bindings, releases, recipes, autologin grants, scans, and findings are excluded"},
		{ResourceKind: "backup.content_and_provider", Reason: "repository and provider configuration, credentials, read tokens, manifests, object paths, upload journals, holds, and restore internals are excluded"},
		{ResourceKind: "certificate.secret_and_challenge", Reason: "ACME accounts, provider references, order URLs, authorizations, challenges, errors, PEM bodies, and private key references are excluded"},
		{ResourceKind: "container.secret_and_runtime", Reason: "registry credentials, raw workload specs, images, environment, arguments, mounts, runtime IDs, logs, and exec grants are excluded"},
		{ResourceKind: "database.secret_and_access", Reason: "resource specs, credential references, grants, network policies, tuning data, upgrades, and workspace sessions are excluded"},
		{ResourceKind: "dns.record_and_key_material", Reason: "record values, provider configuration, transfer addresses, TSIG references, DNSSEC keys, DS records, and proof details are excluded"},
		{ResourceKind: "host.raw_and_audit", Reason: "resource specs, physical keys, service units, process identity, paths, receipts, audit entries, file content, and terminal data are excluded"},
		{ResourceKind: "identity.principal_and_credential", Reason: "principals, memberships, roles, invitations, sessions, API credentials, recovery material, support grants, and authenticators are excluded"},
		{ResourceKind: "mail.content_and_credential", Reason: "messages, attachments, drafts, queue content, campaigns, sieve scripts, pipe references, DKIM keys, relay configuration, and credentials are excluded"},
	}
	if !serviceStatus {
		excluded = append(excluded, ProjectionExclusion{ResourceKind: "host.service_status", Reason: "the optional local service observation schema is not installed on this host"})
	}
	return ProjectionCoverageManifest{SchemaVersion: 1, Included: included, Excluded: excluded}
}

type ProjectionResource struct {
	TenantID      string
	ResourceKind  string
	ResourceID    string
	Generation    uint64
	SanitizedJSON json.RawMessage
}

type ProjectionScan struct {
	Coverage  ProjectionCoverageManifest
	Resources []ProjectionResource
}

// ProjectionSource reads only from the transaction supplied by Store. This is
// deliberately narrower than *sql.DB: every domain in a complete baseline is
// therefore observed through one stable SQLite view.
type ProjectionSource interface {
	ScanProjection(context.Context, *sql.Tx) (ProjectionScan, error)
}

type ProjectionPublishResult struct {
	SourceWatermark uint64
	ManifestDigest  string
	Resources       uint64
	Upserts         uint64
	Tombstones      uint64
	Baseline        bool
}

type projectionLedgerEntry struct {
	tenantID            string
	sourceGeneration    uint64
	publishedGeneration uint64
	statusDigest        string
	state               string
	authorityEpoch      uint64
}

type ProjectionResourcePayload struct {
	Schema           string          `json:"schema"`
	Operation        string          `json:"operation"`
	NodeID           ID              `json:"nodeId"`
	AuthorityEpoch   uint64          `json:"authorityEpoch"`
	SourceWatermark  uint64          `json:"sourceWatermark"`
	TenantID         string          `json:"tenantId"`
	ResourceKind     string          `json:"resourceKind"`
	ResourceID       string          `json:"resourceId"`
	Generation       uint64          `json:"generation"`
	SourceGeneration uint64          `json:"sourceGeneration"`
	ProjectionDigest string          `json:"projectionDigest"`
	PreviousDigest   string          `json:"previousDigest,omitempty"`
	Status           json.RawMessage `json:"status,omitempty"`
}

type ProjectionBaselineAttestation struct {
	Schema          string                     `json:"schema"`
	NodeID          ID                         `json:"nodeId"`
	AuthorityEpoch  uint64                     `json:"authorityEpoch"`
	SourceWatermark uint64                     `json:"sourceWatermark"`
	ManifestDigest  string                     `json:"manifestDigest"`
	ResourceCount   uint64                     `json:"resourceCount"`
	TombstoneCount  uint64                     `json:"tombstoneCount"`
	Coverage        ProjectionCoverageManifest `json:"coverage"`
}

type ProjectionManifestEntry struct {
	TenantID         string `json:"tenantId"`
	ResourceKind     string `json:"resourceKind"`
	ResourceID       string `json:"resourceId"`
	SourceGeneration uint64 `json:"sourceGeneration"`
	ProjectionDigest string `json:"projectionDigest"`
}

type ProjectionBaselineEvidence struct {
	EventID       ID              `json:"eventId"`
	EventSequence uint64          `json:"eventSequence"`
	Payload       json.RawMessage `json:"payload"`
	PayloadDigest string          `json:"payloadDigest"`
}

func NormalizeProjectionCoverage(value ProjectionCoverageManifest) (ProjectionCoverageManifest, error) {
	value, _, err := normalizeProjectionCoverage(value)
	return value, err
}

func ProjectionManifestDigest(coverage ProjectionCoverageManifest, entries []ProjectionManifestEntry) (string, error) {
	coverage, included, err := normalizeProjectionCoverage(coverage)
	if err != nil {
		return "", err
	}
	entries = append([]ProjectionManifestEntry(nil), entries...)
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].ResourceKind == entries[right].ResourceKind {
			return entries[left].ResourceID < entries[right].ResourceID
		}
		return entries[left].ResourceKind < entries[right].ResourceKind
	})
	for index, entry := range entries {
		if !validProjectionPart(entry.ResourceKind, 256) || !validProjectionPart(entry.ResourceID, 256) || entry.TenantID != "" && !validProjectionPart(entry.TenantID, 256) || entry.SourceGeneration > projectionMaximumGeneration || !validSHA256Digest(entry.ProjectionDigest) {
			return "", ErrInvalid
		}
		if _, ok := included[entry.ResourceKind]; !ok {
			return "", ErrInvalid
		}
		if index > 0 && entries[index-1].ResourceKind == entry.ResourceKind && entries[index-1].ResourceID == entry.ResourceID {
			return "", ErrInvalid
		}
	}
	encoded, err := json.Marshal(struct {
		Coverage  ProjectionCoverageManifest `json:"coverage"`
		Resources []ProjectionManifestEntry  `json:"resources"`
	}{coverage, entries})
	if err != nil {
		return "", err
	}
	return digest(encoded), nil
}

func DecodeProjectionResourcePayload(raw json.RawMessage) (ProjectionResourcePayload, error) {
	var value ProjectionResourcePayload
	if len(raw) == 0 || len(raw) > SnapshotMaximumChunkBytes/2 || decodeProjectionJSON(raw, &value) != nil {
		return value, ErrInvalid
	}
	canonical, err := canonicalJSON(raw)
	if err != nil || !bytes.Equal(canonical, raw) || value.Schema != "cyberpanel.federation.resource-projection.v1" || value.Operation != "upsert" && value.Operation != "tombstone" || !value.NodeID.Valid() || value.AuthorityEpoch == 0 || value.SourceWatermark == 0 || value.SourceWatermark > projectionMaximumGeneration || !validProjectionPart(value.ResourceKind, 256) || !validProjectionPart(value.ResourceID, 256) || value.TenantID != "" && !validProjectionPart(value.TenantID, 256) || value.Generation == 0 || value.Generation > projectionMaximumGeneration || value.SourceGeneration > projectionMaximumGeneration || !validSHA256Digest(value.ProjectionDigest) {
		return value, ErrInvalid
	}
	if value.Operation == "upsert" {
		status, statusErr := canonicalJSON(value.Status)
		if statusErr != nil || !bytes.Equal(status, value.Status) || len(status) == 0 || len(status) > projectionMaximumStatusBytes || digest(status) != value.ProjectionDigest || value.PreviousDigest != "" {
			return value, ErrInvalid
		}
	} else if len(value.Status) != 0 || value.ProjectionDigest != digest([]byte("null")) || !validSHA256Digest(value.PreviousDigest) {
		return value, ErrInvalid
	}
	return value, nil
}

func DecodeProjectionBaselinePayload(raw json.RawMessage) (ProjectionBaselineAttestation, error) {
	var value ProjectionBaselineAttestation
	if len(raw) == 0 || len(raw) > SnapshotMaximumChunkBytes/2 || decodeProjectionJSON(raw, &value) != nil {
		return value, ErrInvalid
	}
	canonical, err := canonicalJSON(raw)
	if err != nil || !bytes.Equal(canonical, raw) || value.Schema != "cyberpanel.federation.projection-baseline.v1" || !value.NodeID.Valid() || value.AuthorityEpoch == 0 || value.SourceWatermark == 0 || value.SourceWatermark > projectionMaximumGeneration || value.ResourceCount > ProjectionMaximumRows || value.TombstoneCount > 100000 || !validSHA256Digest(value.ManifestDigest) {
		return value, ErrInvalid
	}
	value.Coverage, err = NormalizeProjectionCoverage(value.Coverage)
	if err != nil {
		return value, err
	}
	normalized, err := json.Marshal(value)
	if err == nil {
		normalized, err = canonicalJSON(normalized)
	}
	if err != nil || !bytes.Equal(normalized, raw) {
		return value, ErrInvalid
	}
	return value, nil
}

func ProjectionBaselineEvidenceFromEvent(event NodeEvent) (ProjectionBaselineEvidence, ProjectionBaselineAttestation, error) {
	var evidence ProjectionBaselineEvidence
	if event.Kind != ProjectionBaselineCompleteEventKind || event.Sequence == 0 || event.ResourceKind != "" || event.ResourceID != "" || event.TenantID != "" || event.Generation == 0 || event.PayloadDigest != digest(event.Payload) {
		return evidence, ProjectionBaselineAttestation{}, ErrInvalid
	}
	attestation, err := DecodeProjectionBaselinePayload(event.Payload)
	if err != nil || event.NodeID != attestation.NodeID || event.Generation != attestation.SourceWatermark {
		return evidence, attestation, ErrInvalid
	}
	evidence = ProjectionBaselineEvidence{EventID: event.ID, EventSequence: event.Sequence, Payload: append(json.RawMessage(nil), event.Payload...), PayloadDigest: event.PayloadDigest}
	if err = evidence.Validate(event.NodeID, attestation.AuthorityEpoch, event.Sequence); err != nil {
		return ProjectionBaselineEvidence{}, attestation, err
	}
	return evidence, attestation, nil
}

func (evidence ProjectionBaselineEvidence) Validate(node ID, epoch, watermark uint64) error {
	if !evidence.EventID.Valid() || evidence.EventSequence == 0 || evidence.EventSequence > watermark || evidence.PayloadDigest != digest(evidence.Payload) {
		return ErrInvalid
	}
	attestation, err := DecodeProjectionBaselinePayload(evidence.Payload)
	if err != nil || attestation.NodeID != node || attestation.AuthorityEpoch != epoch {
		return ErrInvalid
	}
	identifier := digest([]byte(fmt.Sprintf("cyberpanel-federation-projection-event-v1\x00%s\x00%d\x00\x00\x00\x00%d\x00%s", node, epoch, attestation.SourceWatermark, evidence.PayloadDigest)))
	if evidence.EventID != ID("projection_"+identifier[:48]) {
		return ErrInvalid
	}
	return nil
}

func ValidateProjectionBaselineState(attestation ProjectionBaselineAttestation, markerSequence uint64, rows []SnapshotProjection) error {
	coverage, included, err := normalizeProjectionCoverage(attestation.Coverage)
	if err != nil || coverage.SchemaVersion != attestation.Coverage.SchemaVersion || markerSequence == 0 || len(rows) > 100000 {
		return ErrInvalid
	}
	entries := make([]ProjectionManifestEntry, 0, attestation.ResourceCount)
	var tombstones uint64
	seen := make(map[string]struct{})
	for _, row := range rows {
		if _, covered := included[row.ResourceKind]; !covered {
			continue
		}
		payload, payloadErr := DecodeProjectionResourcePayload(row.Payload)
		if payloadErr != nil || payload.NodeID != attestation.NodeID || payload.AuthorityEpoch != attestation.AuthorityEpoch || payload.SourceWatermark > attestation.SourceWatermark || payload.TenantID != row.TenantID || payload.ResourceKind != row.ResourceKind || payload.ResourceID != row.ResourceID || payload.Generation != row.Generation || row.EventSequence == 0 || row.EventSequence >= markerSequence || row.PayloadDigest != digest(row.Payload) {
			return ErrInvalid
		}
		key := row.ResourceKind + "\x00" + row.ResourceID
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalid
		}
		seen[key] = struct{}{}
		if payload.Operation == "tombstone" {
			tombstones++
			continue
		}
		entries = append(entries, ProjectionManifestEntry{TenantID: payload.TenantID, ResourceKind: payload.ResourceKind, ResourceID: payload.ResourceID, SourceGeneration: payload.SourceGeneration, ProjectionDigest: payload.ProjectionDigest})
	}
	manifestDigest, err := ProjectionManifestDigest(coverage, entries)
	if err != nil || uint64(len(entries)) != attestation.ResourceCount || tombstones != attestation.TombstoneCount || manifestDigest != attestation.ManifestDigest {
		return ErrInvalid
	}
	return nil
}

func decodeProjectionJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func validSHA256Digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func (s *Store) PublishProjection(ctx context.Context, source ProjectionSource) (ProjectionPublishResult, error) {
	var result ProjectionPublishResult
	if s == nil || s.db == nil || ctx == nil || source == nil {
		return result, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var node, peer ID
	var epoch uint64
	if err = tx.QueryRowContext(ctx, `SELECT node_id,active_peer_id,authority_epoch FROM federation_state WHERE singleton_id=1`).Scan(&node, &peer, &epoch); err != nil {
		return result, err
	}
	if !node.Valid() || epoch == 0 || !peer.Valid() {
		return result, ErrOffline
	}
	now := s.clock().UTC()
	if _, err = tx.ExecContext(ctx, `INSERT INTO federation_projection_publisher_v1(singleton_id,node_id,authority_epoch,scan_watermark,baseline_complete,manifest_digest,resource_count,updated_at)
VALUES(1,?,?,1,0,'',0,?) ON CONFLICT(singleton_id) DO UPDATE SET
 node_id=excluded.node_id,authority_epoch=excluded.authority_epoch,
 scan_watermark=federation_projection_publisher_v1.scan_watermark+1,
 baseline_complete=CASE WHEN federation_projection_publisher_v1.node_id=excluded.node_id AND federation_projection_publisher_v1.authority_epoch=excluded.authority_epoch THEN federation_projection_publisher_v1.baseline_complete ELSE 0 END,
 manifest_digest=CASE WHEN federation_projection_publisher_v1.node_id=excluded.node_id AND federation_projection_publisher_v1.authority_epoch=excluded.authority_epoch THEN federation_projection_publisher_v1.manifest_digest ELSE '' END,
 resource_count=CASE WHEN federation_projection_publisher_v1.node_id=excluded.node_id AND federation_projection_publisher_v1.authority_epoch=excluded.authority_epoch THEN federation_projection_publisher_v1.resource_count ELSE 0 END,
 updated_at=excluded.updated_at`, node, epoch, now); err != nil {
		return result, err
	}
	if err = s.bootstrapProjectionSourceTx(ctx, tx); err != nil {
		return result, err
	}
	var baselineComplete, sourceComplete int
	var previousManifest string
	if err = tx.QueryRowContext(ctx, `SELECT p.scan_watermark,p.baseline_complete,p.manifest_digest,s.complete FROM federation_projection_publisher_v1 p JOIN federation_projection_source_v1 s ON s.singleton_id=1 WHERE p.singleton_id=1`).Scan(&result.SourceWatermark, &baselineComplete, &previousManifest, &sourceComplete); err != nil {
		return result, err
	}
	scan, err := source.ScanProjection(ctx, tx)
	if err != nil {
		return result, err
	}
	coverage, included, err := normalizeProjectionCoverage(scan.Coverage)
	if err != nil {
		return result, err
	}
	resources, manifestRows, sourceBytes, err := normalizeProjectionResources(scan.Resources, included)
	if err != nil {
		return result, err
	}
	if len(resources) > ProjectionMaximumRows || sourceBytes > ProjectionMaximumSourceBytes {
		return result, ErrProjectionBackpressure
	}
	result.ManifestDigest, err = ProjectionManifestDigest(coverage, manifestRows)
	if err != nil {
		return result, err
	}
	result.Resources = uint64(len(resources))
	result.Baseline = baselineComplete != 1 || sourceComplete != 1
	ledger, err := loadProjectionLedger(ctx, tx)
	if err != nil {
		return result, err
	}
	seen := make(map[string]struct{}, len(resources))
	events := make([]NodeEvent, 0, len(resources)+1)
	ledgerUpdates := make([]struct {
		resource ProjectionResource
		entry    projectionLedgerEntry
	}, 0, len(resources))
	for _, resource := range resources {
		key := projectionLedgerKey(resource.ResourceKind, resource.ResourceID)
		seen[key] = struct{}{}
		statusDigest := digest(resource.SanitizedJSON)
		previous, exists := ledger[key]
		unchanged := exists && previous.state == "upsert" && previous.tenantID == resource.TenantID && previous.sourceGeneration == resource.Generation && previous.statusDigest == statusDigest && previous.authorityEpoch == epoch
		if unchanged {
			continue
		}
		published := resource.Generation
		if published == 0 {
			published = 1
		}
		if exists && published <= previous.publishedGeneration {
			if previous.publishedGeneration >= projectionMaximumGeneration {
				return result, ErrInvalid
			}
			published = previous.publishedGeneration + 1
		}
		payload := ProjectionResourcePayload{Schema: "cyberpanel.federation.resource-projection.v1", Operation: "upsert", NodeID: node, AuthorityEpoch: epoch, SourceWatermark: result.SourceWatermark, TenantID: resource.TenantID, ResourceKind: resource.ResourceKind, ResourceID: resource.ResourceID, Generation: published, SourceGeneration: resource.Generation, ProjectionDigest: statusDigest, Status: resource.SanitizedJSON}
		event, eventErr := newProjectionEvent(node, epoch, resource.TenantID, resource.ResourceKind, resource.ResourceID, published, ProjectionUpsertEventKind, payload, now)
		if eventErr != nil {
			return result, eventErr
		}
		events = append(events, event)
		result.Upserts++
		ledgerUpdates = append(ledgerUpdates, struct {
			resource ProjectionResource
			entry    projectionLedgerEntry
		}{resource, projectionLedgerEntry{resource.TenantID, resource.Generation, published, statusDigest, "upsert", epoch}})
	}
	ledgerKeys := make([]string, 0, len(ledger))
	for key := range ledger {
		ledgerKeys = append(ledgerKeys, key)
	}
	sort.Strings(ledgerKeys)
	pendingTombstones := false
	for _, key := range ledgerKeys {
		previous := ledger[key]
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) != 2 {
			return result, ErrInvalid
		}
		if _, covered := included[parts[0]]; !covered {
			continue
		}
		if _, present := seen[key]; present || previous.state == "tombstone" && previous.authorityEpoch == epoch {
			continue
		}
		if len(events) >= ProjectionMaximumEvents {
			pendingTombstones = true
			break
		}
		if previous.publishedGeneration >= projectionMaximumGeneration {
			return result, ErrInvalid
		}
		published := previous.publishedGeneration + 1
		payload := ProjectionResourcePayload{Schema: "cyberpanel.federation.resource-projection.v1", Operation: "tombstone", NodeID: node, AuthorityEpoch: epoch, SourceWatermark: result.SourceWatermark, TenantID: previous.tenantID, ResourceKind: parts[0], ResourceID: parts[1], Generation: published, SourceGeneration: previous.sourceGeneration, ProjectionDigest: digest([]byte("null")), PreviousDigest: previous.statusDigest}
		event, eventErr := newProjectionEvent(node, epoch, previous.tenantID, parts[0], parts[1], published, ProjectionTombstoneEventKind, payload, now)
		if eventErr != nil {
			return result, eventErr
		}
		events = append(events, event)
		result.Tombstones++
		ledgerUpdates = append(ledgerUpdates, struct {
			resource ProjectionResource
			entry    projectionLedgerEntry
		}{ProjectionResource{TenantID: previous.tenantID, ResourceKind: parts[0], ResourceID: parts[1], Generation: previous.sourceGeneration}, projectionLedgerEntry{previous.tenantID, previous.sourceGeneration, published, digest([]byte("null")), "tombstone", epoch}})
	}
	sort.Slice(events, func(left, right int) bool {
		if events[left].ResourceKind == events[right].ResourceKind {
			return events[left].ResourceID < events[right].ResourceID
		}
		return events[left].ResourceKind < events[right].ResourceKind
	})
	projectedLedger := make(map[string]projectionLedgerEntry, len(ledger)+len(ledgerUpdates))
	for key, entry := range ledger {
		projectedLedger[key] = entry
	}
	for _, update := range ledgerUpdates {
		projectedLedger[projectionLedgerKey(update.resource.ResourceKind, update.resource.ResourceID)] = update.entry
	}
	var tombstoneCount uint64
	for key, entry := range projectedLedger {
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) == 2 && entry.authorityEpoch == epoch && entry.state == "tombstone" {
			if _, covered := included[parts[0]]; covered {
				tombstoneCount++
			}
		}
	}
	baselineFinished := !pendingTombstones
	markerCurrent := false
	var markerSequence uint64
	var markerJSON []byte
	if markerErr := tx.QueryRowContext(ctx, `SELECT sequence,payload_json FROM federation_events WHERE kind=? ORDER BY sequence DESC LIMIT 1`, ProjectionBaselineCompleteEventKind).Scan(&markerSequence, &markerJSON); markerErr == nil {
		var markerEvent NodeEvent
		if json.Unmarshal(markerJSON, &markerEvent) == nil {
			markerEvent.Sequence = markerSequence
			_, previous, evidenceErr := ProjectionBaselineEvidenceFromEvent(markerEvent)
			markerCurrent = evidenceErr == nil && previous.NodeID == node && previous.AuthorityEpoch == epoch && previous.ManifestDigest == result.ManifestDigest && previous.ResourceCount == result.Resources && previous.TombstoneCount == tombstoneCount
		}
	} else if !errors.Is(markerErr, sql.ErrNoRows) {
		return result, markerErr
	}
	markerNeeded := result.Baseline || previousManifest != result.ManifestDigest || !markerCurrent
	if markerNeeded && baselineFinished {
		if len(events) >= ProjectionMaximumEvents {
			baselineFinished = false
		} else {
			marker := ProjectionBaselineAttestation{Schema: "cyberpanel.federation.projection-baseline.v1", NodeID: node, AuthorityEpoch: epoch, SourceWatermark: result.SourceWatermark, ManifestDigest: result.ManifestDigest, ResourceCount: result.Resources, TombstoneCount: tombstoneCount, Coverage: coverage}
			event, markerErr := newProjectionEvent(node, epoch, "", "", "", result.SourceWatermark, ProjectionBaselineCompleteEventKind, marker, now)
			if markerErr != nil {
				return result, markerErr
			}
			events = append(events, event)
		}
	}
	eventBytes := 0
	for _, event := range events {
		encoded, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return result, marshalErr
		}
		eventBytes += len(encoded)
	}
	if len(events) > ProjectionMaximumEvents || eventBytes > ProjectionMaximumEventBytes {
		return result, ErrProjectionBackpressure
	}
	var pendingRows, pendingBytes uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(payload_bytes),0) FROM federation_events WHERE acked_at IS NULL`).Scan(&pendingRows, &pendingBytes); err != nil {
		return result, err
	}
	if pendingRows+uint64(len(events)) > ProjectionMaximumSpoolRows || pendingBytes+uint64(eventBytes) > ProjectionMaximumSpoolBytes {
		return result, ErrProjectionBackpressure
	}
	for _, event := range events {
		if _, err = s.enqueueEventTx(ctx, tx, event); err != nil {
			return result, err
		}
	}
	for _, update := range ledgerUpdates {
		if _, err = tx.ExecContext(ctx, `INSERT INTO federation_projection_ledger_v1(resource_kind,resource_id,tenant_id,source_generation,published_generation,status_digest,state,authority_epoch,source_watermark,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(resource_kind,resource_id) DO UPDATE SET tenant_id=excluded.tenant_id,source_generation=excluded.source_generation,published_generation=excluded.published_generation,status_digest=excluded.status_digest,state=excluded.state,authority_epoch=excluded.authority_epoch,source_watermark=excluded.source_watermark,updated_at=excluded.updated_at`, update.resource.ResourceKind, update.resource.ResourceID, update.entry.tenantID, update.entry.sourceGeneration, update.entry.publishedGeneration, update.entry.statusDigest, update.entry.state, update.entry.authorityEpoch, result.SourceWatermark, now); err != nil {
			return result, err
		}
	}
	complete := 0
	if baselineFinished {
		complete = 1
	}
	if _, err = tx.ExecContext(ctx, `UPDATE federation_projection_source_v1 SET complete=? WHERE singleton_id=1`, complete); err != nil {
		return result, err
	}
	publisherReady := 0
	if baselineFinished {
		publisherReady = 1
	}
	publisherUpdate, err := tx.ExecContext(ctx, `UPDATE federation_projection_publisher_v1 SET baseline_complete=?,manifest_digest=?,resource_count=?,updated_at=? WHERE singleton_id=1 AND node_id=? AND authority_epoch=? AND scan_watermark=?`, publisherReady, result.ManifestDigest, result.Resources, now, node, epoch, result.SourceWatermark)
	if err != nil {
		return result, err
	}
	if affected, affectedErr := publisherUpdate.RowsAffected(); affectedErr != nil || affected != 1 {
		return result, errors.Join(ErrStale, affectedErr)
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Store) ProjectionBaselineReady(ctx context.Context, node ID, epoch uint64) (bool, error) {
	if s == nil || s.db == nil || ctx == nil || !node.Valid() || epoch == 0 {
		return false, ErrInvalid
	}
	var ready, sourceComplete int
	err := s.db.QueryRowContext(ctx, `SELECT p.baseline_complete,s.complete FROM federation_projection_publisher_v1 p JOIN federation_projection_source_v1 s ON s.singleton_id=1 WHERE p.singleton_id=1 AND p.node_id=? AND p.authority_epoch=?`, node, epoch).Scan(&ready, &sourceComplete)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return ready == 1 && sourceComplete == 1, err
}

func projectionBaselineReadyTx(ctx context.Context, tx *sql.Tx, node ID, epoch uint64) (bool, error) {
	var ready, sourceComplete int
	err := tx.QueryRowContext(ctx, `SELECT p.baseline_complete,s.complete FROM federation_projection_publisher_v1 p JOIN federation_projection_source_v1 s ON s.singleton_id=1 WHERE p.singleton_id=1 AND p.node_id=? AND p.authority_epoch=?`, node, epoch).Scan(&ready, &sourceComplete)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return ready == 1 && sourceComplete == 1, err
}

func normalizeProjectionCoverage(value ProjectionCoverageManifest) (ProjectionCoverageManifest, map[string]struct{}, error) {
	value.Included = append([]string(nil), value.Included...)
	value.Excluded = append([]ProjectionExclusion(nil), value.Excluded...)
	sort.Strings(value.Included)
	sort.Slice(value.Excluded, func(left, right int) bool {
		return value.Excluded[left].ResourceKind < value.Excluded[right].ResourceKind
	})
	if value.SchemaVersion != 1 || len(value.Included) == 0 || len(value.Included) > 128 || len(value.Excluded) > 256 {
		return value, nil, ErrInvalid
	}
	allowlist := make(map[string]struct{}, len(NodeProjectionResourceKinds()))
	for _, kind := range NodeProjectionResourceKinds() {
		allowlist[kind] = struct{}{}
	}
	included := make(map[string]struct{}, len(value.Included))
	for _, kind := range value.Included {
		if !validProjectionPart(kind, 256) {
			return value, nil, ErrInvalid
		}
		if _, allowed := allowlist[kind]; !allowed {
			return value, nil, ErrInvalid
		}
		if _, exists := included[kind]; exists {
			return value, nil, ErrInvalid
		}
		included[kind] = struct{}{}
	}
	exclusionKinds := nodeProjectionExclusionKinds()
	accounted := make(map[string]struct{}, len(included))
	for kind := range included {
		accounted[kind] = struct{}{}
	}
	for index, exclusion := range value.Excluded {
		if !validProjectionPart(exclusion.ResourceKind, 256) || strings.TrimSpace(exclusion.Reason) == "" || len(exclusion.Reason) > 512 || strings.ContainsAny(exclusion.Reason, "\x00\r\n") || index > 0 && value.Excluded[index-1].ResourceKind == exclusion.ResourceKind {
			return value, nil, ErrInvalid
		}
		_, allowedKind := allowlist[exclusion.ResourceKind]
		_, allowedCategory := exclusionKinds[exclusion.ResourceKind]
		if !allowedKind && !allowedCategory {
			return value, nil, ErrInvalid
		}
		if _, duplicate := accounted[exclusion.ResourceKind]; duplicate {
			return value, nil, ErrInvalid
		}
		if allowedKind {
			accounted[exclusion.ResourceKind] = struct{}{}
		}
	}
	if len(accounted) != len(allowlist) {
		return value, nil, ErrInvalid
	}
	return value, included, nil
}

func normalizeProjectionResources(values []ProjectionResource, included map[string]struct{}) ([]ProjectionResource, []ProjectionManifestEntry, int, error) {
	resources := append([]ProjectionResource(nil), values...)
	sort.Slice(resources, func(left, right int) bool {
		if resources[left].ResourceKind == resources[right].ResourceKind {
			return resources[left].ResourceID < resources[right].ResourceID
		}
		return resources[left].ResourceKind < resources[right].ResourceKind
	})
	manifest := make([]ProjectionManifestEntry, 0, len(resources))
	bytesUsed := 0
	for index := range resources {
		resource := &resources[index]
		if !validProjectionPart(resource.ResourceKind, 256) || !validProjectionPart(resource.ResourceID, 256) || resource.TenantID != "" && !validProjectionPart(resource.TenantID, 256) || resource.Generation > projectionMaximumGeneration {
			return nil, nil, 0, ErrInvalid
		}
		if _, covered := included[resource.ResourceKind]; !covered {
			return nil, nil, 0, ErrInvalid
		}
		if index > 0 && resources[index-1].ResourceKind == resource.ResourceKind && resources[index-1].ResourceID == resource.ResourceID {
			return nil, nil, 0, ErrConflict
		}
		canonical, err := canonicalJSON(resource.SanitizedJSON)
		if err != nil || len(canonical) == 0 || len(canonical) > projectionMaximumStatusBytes {
			return nil, nil, 0, ErrInvalid
		}
		resource.SanitizedJSON = canonical
		bytesUsed += len(canonical)
		manifest = append(manifest, ProjectionManifestEntry{resource.TenantID, resource.ResourceKind, resource.ResourceID, resource.Generation, digest(canonical)})
	}
	return resources, manifest, bytesUsed, nil
}

func loadProjectionLedger(ctx context.Context, tx *sql.Tx) (map[string]projectionLedgerEntry, error) {
	rows, err := tx.QueryContext(ctx, `SELECT resource_kind,resource_id,tenant_id,source_generation,published_generation,status_digest,state,authority_epoch FROM federation_projection_ledger_v1 ORDER BY resource_kind,resource_id LIMIT 100001`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ledger := make(map[string]projectionLedgerEntry)
	for rows.Next() {
		var kind, id string
		var entry projectionLedgerEntry
		if err = rows.Scan(&kind, &id, &entry.tenantID, &entry.sourceGeneration, &entry.publishedGeneration, &entry.statusDigest, &entry.state, &entry.authorityEpoch); err != nil {
			return nil, err
		}
		if len(ledger) >= 100000 || !validProjectionPart(kind, 256) || !validProjectionPart(id, 256) || entry.tenantID != "" && !validProjectionPart(entry.tenantID, 256) || entry.sourceGeneration > projectionMaximumGeneration || entry.publishedGeneration == 0 || entry.publishedGeneration > projectionMaximumGeneration || len(entry.statusDigest) != 64 || entry.state != "upsert" && entry.state != "tombstone" || entry.authorityEpoch == 0 {
			return nil, ErrInvalid
		}
		ledger[projectionLedgerKey(kind, id)] = entry
	}
	return ledger, rows.Err()
}

func newProjectionEvent(node ID, epoch uint64, tenant, kind, id string, generation uint64, eventKind string, value any, occurredAt time.Time) (NodeEvent, error) {
	var event NodeEvent
	payload, err := json.Marshal(value)
	if err != nil {
		return event, err
	}
	payload, err = canonicalJSON(payload)
	if err != nil || len(payload) == 0 || len(payload) > SnapshotMaximumChunkBytes/2 {
		return event, ErrInvalid
	}
	payloadDigest := digest(payload)
	identifier := digest([]byte(fmt.Sprintf("cyberpanel-federation-projection-event-v1\x00%s\x00%d\x00%s\x00%s\x00%s\x00%d\x00%s", node, epoch, tenant, kind, id, generation, payloadDigest)))
	eventID, err := NewID("projection_" + identifier[:48])
	if err != nil {
		return event, err
	}
	return NodeEvent{ID: eventID, NodeID: node, Priority: PriorityState, Kind: eventKind, TenantID: tenant, ResourceID: id, ResourceKind: kind, Generation: generation, Payload: payload, PayloadDigest: payloadDigest, OccurredAt: occurredAt.UTC()}, nil
}

func validProjectionPart(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func projectionLedgerKey(kind, id string) string { return kind + "\x00" + id }
