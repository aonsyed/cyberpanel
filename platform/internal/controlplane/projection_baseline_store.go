package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const projectionBaselineSchema = `
CREATE TABLE IF NOT EXISTS fleet_projection_baselines_v1(
 node_id TEXT NOT NULL REFERENCES fleet_nodes(id) DEFERRABLE INITIALLY DEFERRED,
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),snapshot_generation BIGINT NOT NULL CHECK(snapshot_generation>=0),event_sequence BIGINT NOT NULL CHECK(event_sequence>=0),
 source_watermark BIGINT NOT NULL CHECK(source_watermark>=0),manifest_digest TEXT NOT NULL,resource_count BIGINT NOT NULL CHECK(resource_count>=0),tombstone_count BIGINT NOT NULL CHECK(tombstone_count>=0),
 coverage_json BYTEA NOT NULL,attestation_json BYTEA NOT NULL,evidence_source TEXT NOT NULL,signature_key_id TEXT NOT NULL,
 signature_digest TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL,observed_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(node_id,authority_epoch,snapshot_generation,event_sequence)
);
CREATE INDEX IF NOT EXISTS fleet_projection_baselines_current_v1 ON fleet_projection_baselines_v1(node_id,authority_epoch,snapshot_generation,state,event_sequence DESC);
`

type ProjectionBaselineStatus struct {
	NodeID             federation.ID                         `json:"node_id"`
	AuthorityEpoch     uint64                                `json:"authority_epoch"`
	SnapshotGeneration uint64                                `json:"snapshot_generation"`
	EventSequence      uint64                                `json:"event_sequence"`
	SourceWatermark    uint64                                `json:"source_watermark"`
	ManifestDigest     string                                `json:"manifest_digest"`
	ResourceCount      uint64                                `json:"resource_count"`
	TombstoneCount     uint64                                `json:"tombstone_count"`
	Coverage           federation.ProjectionCoverageManifest `json:"coverage"`
	EvidenceSource     string                                `json:"evidence_source"`
	Authoritative      bool                                  `json:"authoritative"`
	Reason             string                                `json:"reason"`
	ObservedAt         time.Time                             `json:"observed_at"`
}

func (s *Store) ProjectionBaselineStatus(ctx context.Context, tenantID, nodeID federation.ID) (ProjectionBaselineStatus, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || !nodeID.Valid() {
		return ProjectionBaselineStatus{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return ProjectionBaselineStatus{}, err
	}
	defer tx.Rollback()
	status, err := projectionBaselineStatusTx(ctx, tx, tenantID, nodeID)
	if err != nil {
		return status, err
	}
	return status, tx.Commit()
}

// projectionBaselineStatusTx lets operator reads evaluate ownership, node
// lifecycle, projection rows, and baseline evidence in the same read snapshot.
func projectionBaselineStatusTx(ctx context.Context, tx *authorityTx, tenantID, nodeID federation.ID) (ProjectionBaselineStatus, error) {
	status := ProjectionBaselineStatus{NodeID: nodeID, Reason: "baseline_missing"}
	if ctx == nil || tx == nil || !tenantID.Valid() || !nodeID.Valid() {
		return status, ErrInvalid
	}
	node, err := loadNodeTx(ctx, tx, nodeID)
	if err != nil {
		return status, err
	}
	if node.OwnerTenantID != tenantID {
		return status, ErrNotFound
	}
	status.AuthorityEpoch = node.AuthorityEpoch
	status.SnapshotGeneration = node.SnapshotGeneration
	var receiving int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM fleet_projection_snapshots_v1 WHERE node_id=? AND state='receiving'`, nodeID).Scan(&receiving); err != nil {
		return status, err
	}
	var coverageJSON, attestationJSON []byte
	var state, storedReason, signatureKeyID, signatureDigest string
	err = tx.QueryRowContext(ctx, `SELECT event_sequence,source_watermark,manifest_digest,resource_count,tombstone_count,coverage_json,attestation_json,evidence_source,signature_key_id,signature_digest,state,reason,observed_at FROM fleet_projection_baselines_v1 WHERE node_id=? AND authority_epoch=? AND snapshot_generation=? ORDER BY event_sequence DESC LIMIT 1`, nodeID, node.AuthorityEpoch, node.SnapshotGeneration).Scan(&status.EventSequence, &status.SourceWatermark, &status.ManifestDigest, &status.ResourceCount, &status.TombstoneCount, &coverageJSON, &attestationJSON, &status.EvidenceSource, &signatureKeyID, &signatureDigest, &state, &storedReason, &status.ObservedAt)
	if errors.Is(err, sql.ErrNoRows) {
		if node.State == NodeRevoking || node.State == NodeRevoked {
			status.Reason = "node_revoked"
		} else if receiving != 0 {
			status.Reason = "snapshot_in_progress"
		} else if node.State == NodeDegraded {
			status.Reason = "event_sequence_gap"
		} else {
			var historical int
			if countErr := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM fleet_projection_baselines_v1 WHERE node_id=?`, nodeID).Scan(&historical); countErr != nil {
				return status, countErr
			}
			if historical != 0 {
				status.Reason = "epoch_or_generation_changed"
			}
		}
		return status, nil
	}
	if err != nil {
		return status, err
	}
	if json.Unmarshal(coverageJSON, &status.Coverage) != nil || len(attestationJSON) == 0 || signatureKeyID == "" || !validSHA256(signatureDigest) {
		status.Reason = "attestation_corrupt"
		return status, nil
	}
	normalizedCoverage, coverageErr := federation.NormalizeProjectionCoverage(status.Coverage)
	attestation, attestationErr := federation.DecodeProjectionBaselinePayload(attestationJSON)
	if coverageErr != nil || attestationErr != nil || attestation.NodeID != nodeID || attestation.AuthorityEpoch != node.AuthorityEpoch || attestation.SourceWatermark != status.SourceWatermark || attestation.ManifestDigest != status.ManifestDigest || attestation.ResourceCount != status.ResourceCount || attestation.TombstoneCount != status.TombstoneCount || !sameProjectionCoverage(normalizedCoverage, attestation.Coverage) {
		status.Reason = "attestation_corrupt"
		return status, nil
	}
	status.Coverage = normalizedCoverage
	if node.State == NodeRevoking || node.State == NodeRevoked {
		status.Reason = "node_revoked"
		return status, nil
	}
	if receiving != 0 {
		status.Reason = "snapshot_in_progress"
		return status, nil
	}
	if node.State == NodeDegraded {
		status.Reason = "event_sequence_gap"
		if state != "accepted" && storedReason != "" {
			status.Reason = storedReason
		}
		return status, nil
	}
	if node.State != NodeOnline {
		status.Reason = "node_not_online"
		return status, nil
	}
	if state != "accepted" {
		status.Reason = storedReason
		if status.Reason == "" {
			status.Reason = "attestation_invalidated"
		}
		return status, nil
	}
	var maximumEventSequence, maximumSourceWatermark uint64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(event_sequence),0),COALESCE(MAX(source_watermark),0) FROM fleet_projection_baselines_v1 WHERE node_id=? AND authority_epoch=?`, nodeID, node.AuthorityEpoch).Scan(&maximumEventSequence, &maximumSourceWatermark); err != nil {
		return status, err
	}
	if status.EventSequence < maximumEventSequence || status.SourceWatermark < maximumSourceWatermark {
		status.Reason = "sequence_regression"
		return status, nil
	}
	if status.EventSequence > node.ProjectionSequence {
		status.Reason = "sequence_regression"
		return status, nil
	}
	rows, stale, err := projectionBaselineRowsTx(ctx, tx, nodeID)
	if err != nil {
		return status, err
	}
	if stale {
		status.Reason = "projection_stale"
		return status, nil
	}
	if federation.ValidateProjectionBaselineState(attestation, status.EventSequence, rows) != nil {
		status.Reason = "manifest_or_count_mismatch"
		return status, nil
	}
	if status.EvidenceSource == "snapshot" {
		var receiptGeneration, receiptWatermark uint64
		receiptErr := tx.QueryRowContext(ctx, `SELECT generation,watermark FROM fleet_projection_snapshot_receipts_v1 WHERE node_id=?`, nodeID).Scan(&receiptGeneration, &receiptWatermark)
		if receiptErr != nil || receiptGeneration != status.SnapshotGeneration || receiptWatermark < status.EventSequence {
			status.Reason = "snapshot_evidence_missing"
			return status, nil
		}
	} else if status.EvidenceSource != "event" {
		status.Reason = "attestation_corrupt"
		return status, nil
	}
	status.Authoritative = true
	status.Reason = "authoritative"
	return status, nil
}

func (s *Store) applyAuthenticatedEvents(ctx context.Context, nodeID federation.ID, events []federation.NodeEvent) (EventApplyResult, error) {
	if s == nil || s.db == nil || ctx == nil || !nodeID.Valid() || len(events) == 0 {
		return EventApplyResult{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EventApplyResult{}, err
	}
	defer tx.Rollback()
	node, err := loadNodeTx(ctx, tx, nodeID)
	if err != nil {
		return EventApplyResult{}, err
	}
	var pendingSnapshot []byte
	snapshotErr := tx.QueryRowContext(ctx, `SELECT request_json FROM fleet_projection_snapshots_v1 WHERE node_id=? AND state='receiving'`, nodeID).Scan(&pendingSnapshot)
	if snapshotErr == nil {
		var request federation.ProjectionSnapshotRequest
		if json.Unmarshal(pendingSnapshot, &request) != nil {
			return EventApplyResult{}, ErrConflict
		}
		if request.AuthorityEpoch == node.AuthorityEpoch {
			return EventApplyResult{AckThrough: node.ProjectionSequence, ExpectedSequence: request.ExpectedSequence, ReceivedSequence: request.ReceivedSequence, SnapshotGeneration: node.SnapshotGeneration, Resync: true}, tx.Commit()
		}
	} else if !errors.Is(snapshotErr, sql.ErrNoRows) {
		return EventApplyResult{}, snapshotErr
	}
	cursor := node.ProjectionSequence
	expected := cursor + 1
	for _, event := range events {
		if event.Sequence <= cursor {
			var storedRaw []byte
			if err = tx.QueryRowContext(ctx, `SELECT event_json FROM fleet_events WHERE node_id=? AND sequence=?`, nodeID, event.Sequence).Scan(&storedRaw); errors.Is(err, sql.ErrNoRows) {
				var snapshotWatermark uint64
				if snapshotErr = tx.QueryRowContext(ctx, `SELECT watermark FROM fleet_projection_snapshot_receipts_v1 WHERE node_id=?`, nodeID).Scan(&snapshotWatermark); snapshotErr == nil && event.Sequence <= snapshotWatermark {
					continue
				}
				return EventApplyResult{}, ErrConflict
			}
			if err != nil {
				return EventApplyResult{}, err
			}
			var stored federation.NodeEvent
			if json.Unmarshal(storedRaw, &stored) != nil || !sameNodeEvent(stored, event) {
				return EventApplyResult{}, ErrConflict
			}
			continue
		}
		if event.Sequence != expected {
			now := s.clock().UTC()
			if err = invalidateProjectionBaselinesTx(ctx, tx, nodeID, "event_sequence_gap", now); err != nil {
				return EventApplyResult{}, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE fleet_projections SET stale=1 WHERE node_id=?`, nodeID); err != nil {
				return EventApplyResult{}, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE fleet_nodes SET state='degraded',last_seen_at=?,updated_at=? WHERE id=? AND state NOT IN ('revoking','revoked')`, now, now, nodeID); err != nil {
				return EventApplyResult{}, err
			}
			if err = tx.Commit(); err != nil {
				return EventApplyResult{}, err
			}
			return EventApplyResult{AckThrough: cursor, ExpectedSequence: expected, ReceivedSequence: event.Sequence, SnapshotGeneration: node.SnapshotGeneration, Resync: true}, nil
		}
		expected++
	}
	last := cursor
	for _, event := range events {
		if event.Sequence <= cursor {
			last = event.Sequence
			continue
		}
		isBaseline, err := validateAuthenticatedProjectionEvent(node, event)
		if err != nil {
			return EventApplyResult{}, err
		}
		if isNodeProjectionResourceKind(event.ResourceKind) {
			if err = invalidateProjectionBaselinesTx(ctx, tx, nodeID, "projection_changed", s.clock().UTC()); err != nil {
				return EventApplyResult{}, err
			}
		}
		raw, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return EventApplyResult{}, marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_events VALUES(?,?,?,?,?)`, nodeID, event.Sequence, event.ID, raw, event.OccurredAt); err != nil {
			return EventApplyResult{}, err
		}
		if event.ResourceKind != "" && event.ResourceID != "" {
			_, err = tx.ExecContext(ctx, `INSERT INTO fleet_projections VALUES(?,?,?,?,?,?,?,?,?,0) ON CONFLICT(node_id,resource_kind,resource_id) DO UPDATE SET tenant_id=excluded.tenant_id,generation=excluded.generation,status_json=excluded.status_json,digest=excluded.digest,observed_at=excluded.observed_at,event_sequence=excluded.event_sequence,stale=0 WHERE fleet_projections.generation<=excluded.generation`, nodeID, event.TenantID, event.ResourceKind, event.ResourceID, event.Generation, event.Payload, event.PayloadDigest, event.OccurredAt, event.Sequence)
			if err != nil {
				return EventApplyResult{}, err
			}
		}
		if isBaseline {
			if err = s.acceptProjectionBaselineEventTx(ctx, tx, node, event); err != nil {
				return EventApplyResult{}, err
			}
		}
		last = event.Sequence
	}
	if last > cursor {
		node.ProjectionSequence = last
	}
	now := s.clock().UTC()
	if node.State == NodeDegraded {
		if _, err = tx.ExecContext(ctx, `UPDATE fleet_projections SET stale=1 WHERE node_id=?`, nodeID); err != nil {
			return EventApplyResult{}, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_nodes SET projection_sequence=?,last_seen_at=?,updated_at=? WHERE id=?`, node.ProjectionSequence, now, now, nodeID); err != nil {
		return EventApplyResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return EventApplyResult{}, err
	}
	return EventApplyResult{AckThrough: events[len(events)-1].Sequence, ExpectedSequence: node.ProjectionSequence + 1, SnapshotGeneration: node.SnapshotGeneration}, nil
}

func validateAuthenticatedProjectionEvent(node Node, event federation.NodeEvent) (bool, error) {
	if event.Kind == federation.ProjectionBaselineCompleteEventKind {
		_, attestation, err := federation.ProjectionBaselineEvidenceFromEvent(event)
		if err != nil || attestation.NodeID != node.ID || attestation.AuthorityEpoch != node.AuthorityEpoch {
			return false, ErrInvalid
		}
		return true, nil
	}
	projectionKind := isNodeProjectionResourceKind(event.ResourceKind)
	if event.Kind == federation.ProjectionUpsertEventKind || event.Kind == federation.ProjectionTombstoneEventKind || projectionKind {
		if !projectionKind {
			return false, ErrInvalid
		}
		payload, err := federation.DecodeProjectionResourcePayload(event.Payload)
		if err != nil || payload.NodeID != node.ID || payload.AuthorityEpoch != node.AuthorityEpoch || payload.TenantID != event.TenantID || payload.ResourceKind != event.ResourceKind || payload.ResourceID != event.ResourceID || payload.Generation != event.Generation || payload.Operation == "upsert" && event.Kind != federation.ProjectionUpsertEventKind || payload.Operation == "tombstone" && event.Kind != federation.ProjectionTombstoneEventKind {
			return false, ErrInvalid
		}
	}
	return false, nil
}

func (s *Store) acceptProjectionBaselineEventTx(ctx context.Context, tx *authorityTx, node Node, event federation.NodeEvent) error {
	evidence, attestation, err := federation.ProjectionBaselineEvidenceFromEvent(event)
	if err != nil || attestation.NodeID != node.ID || attestation.AuthorityEpoch != node.AuthorityEpoch {
		return ErrInvalid
	}
	rows, stale, err := projectionBaselineRowsTx(ctx, tx, node.ID)
	if err != nil {
		return err
	}
	if stale || federation.ValidateProjectionBaselineState(attestation, evidence.EventSequence, rows) != nil {
		return ErrConflict
	}
	return persistProjectionBaselineTx(ctx, tx, node, node.SnapshotGeneration, evidence, attestation, "event", event.SignatureKeyID, digest(event.Signature), s.clock().UTC())
}

func persistProjectionBaselineTx(ctx context.Context, tx *authorityTx, node Node, generation uint64, evidence federation.ProjectionBaselineEvidence, attestation federation.ProjectionBaselineAttestation, source, keyID, signatureDigest string, now time.Time) error {
	validGeneration := source == "event" && generation == node.SnapshotGeneration || source == "snapshot" && node.SnapshotGeneration < 1<<63-1 && generation == node.SnapshotGeneration+1
	if !validGeneration || evidence.Validate(node.ID, node.AuthorityEpoch, evidence.EventSequence) != nil || source != "event" && source != "snapshot" || keyID == "" || !validSHA256(signatureDigest) || now.IsZero() {
		return ErrInvalid
	}
	coverageJSON, err := json.Marshal(attestation.Coverage)
	if err != nil {
		return err
	}
	now = now.UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_projection_baselines_v1 SET state='invalidated',reason='superseded',updated_at=? WHERE node_id=? AND state='accepted'`, now, node.ID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO fleet_projection_baselines_v1(node_id,authority_epoch,snapshot_generation,event_sequence,source_watermark,manifest_digest,resource_count,tombstone_count,coverage_json,attestation_json,evidence_source,signature_key_id,signature_digest,state,reason,observed_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'accepted','authoritative',?,?) ON CONFLICT(node_id,authority_epoch,snapshot_generation,event_sequence) DO NOTHING`, node.ID, node.AuthorityEpoch, generation, evidence.EventSequence, attestation.SourceWatermark, attestation.ManifestDigest, attestation.ResourceCount, attestation.TombstoneCount, coverageJSON, evidence.Payload, source, keyID, signatureDigest, now, now)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted != 1 {
		return ErrConflict
	}
	return nil
}

func invalidateProjectionBaselinesTx(ctx context.Context, tx *authorityTx, nodeID federation.ID, reason string, now time.Time) error {
	if !nodeID.Valid() || strings.TrimSpace(reason) == "" || len(reason) > 128 {
		return ErrInvalid
	}
	_, err := tx.ExecContext(ctx, `UPDATE fleet_projection_baselines_v1 SET state='invalidated',reason=?,updated_at=? WHERE node_id=? AND state='accepted'`, reason, now.UTC(), nodeID)
	return err
}

func (s *Store) InvalidateProjectionBaseline(ctx context.Context, nodeID federation.ID, reason string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = invalidateProjectionBaselinesTx(ctx, tx, nodeID, reason, s.clock().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) rejectProjectionEvidence(ctx context.Context, nodeID federation.ID, reason string) error {
	if s == nil || s.db == nil || ctx == nil || !nodeID.Valid() {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.clock().UTC()
	if err = invalidateProjectionBaselinesTx(ctx, tx, nodeID, reason, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_projections SET stale=1 WHERE node_id=?`, nodeID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE fleet_nodes SET state=CASE WHEN state IN ('revoking','revoked') THEN state ELSE 'degraded' END,last_seen_at=?,updated_at=? WHERE id=?`, now, now, nodeID)
	if err != nil {
		return err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return errors.Join(ErrNotFound, rowsErr)
	}
	return tx.Commit()
}

func projectionBaselineRowsTx(ctx context.Context, tx *authorityTx, nodeID federation.ID) ([]federation.SnapshotProjection, bool, error) {
	kinds := federation.NodeProjectionResourceKinds()
	arguments := make([]any, 0, len(kinds)+2)
	arguments = append(arguments, nodeID)
	for _, kind := range kinds {
		arguments = append(arguments, kind)
	}
	arguments = append(arguments, 100001)
	query := `SELECT tenant_id,resource_kind,resource_id,generation,status_json,digest,observed_at,event_sequence,stale FROM fleet_projections WHERE node_id=? AND resource_kind IN (` + strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",") + `) ORDER BY resource_kind,resource_id LIMIT ?`
	rows, err := tx.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	values := make([]federation.SnapshotProjection, 0)
	stale := false
	bytesUsed := 0
	for rows.Next() {
		var row federation.SnapshotProjection
		var rowStale bool
		if err = rows.Scan(&row.TenantID, &row.ResourceKind, &row.ResourceID, &row.Generation, &row.Payload, &row.PayloadDigest, &row.ObservedAt, &row.EventSequence, &rowStale); err != nil {
			return nil, false, err
		}
		bytesUsed += len(row.Payload)
		if len(values) >= 100000 || bytesUsed > federation.ProjectionMaximumSpoolBytes {
			return nil, false, ErrInvalid
		}
		values = append(values, row)
		stale = stale || rowStale
	}
	return values, stale, rows.Err()
}

func isNodeProjectionResourceKind(kind string) bool {
	for _, allowed := range federation.NodeProjectionResourceKinds() {
		if kind == allowed {
			return true
		}
	}
	return false
}

func sameProjectionCoverage(left, right federation.ProjectionCoverageManifest) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}
