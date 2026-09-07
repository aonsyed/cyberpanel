package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const lifecycleSchema = `
CREATE TABLE IF NOT EXISTS fleet_node_lifecycle(
 node_id TEXT PRIMARY KEY,
 generation BIGINT NOT NULL CHECK(generation>0),
 updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_lifecycle_operations(
 tenant_id TEXT NOT NULL,
 operation TEXT NOT NULL,
 idempotency_key TEXT NOT NULL,
 node_id TEXT NOT NULL,
 request_digest TEXT NOT NULL,
 expected_generation BIGINT NOT NULL CHECK(expected_generation>0),
 result_generation BIGINT NOT NULL CHECK(result_generation>0),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 state TEXT NOT NULL,
 issued_at TIMESTAMPTZ NOT NULL,
 response_json BYTEA NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(tenant_id,operation,idempotency_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS fleet_lifecycle_node_generation
 ON fleet_lifecycle_operations(node_id,operation,result_generation) WHERE state IN ('reserved','applied');
CREATE TABLE IF NOT EXISTS fleet_lifecycle_evidence(
 sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 event_id TEXT NOT NULL UNIQUE,
 occurred_at TIMESTAMPTZ NOT NULL,
 tenant_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 operation TEXT NOT NULL,
 generation BIGINT NOT NULL CHECK(generation>0),
 authority_epoch BIGINT NOT NULL CHECK(authority_epoch>0),
 request_digest TEXT NOT NULL,
 previous_fingerprint TEXT NOT NULL,
 current_fingerprint TEXT NOT NULL,
 detail_digest TEXT NOT NULL,
 previous_digest TEXT NOT NULL UNIQUE,
 event_digest TEXT NOT NULL UNIQUE
);
`

const (
	lifecycleRotate = "node_certificate_rotate"
	lifecycleDetach = "node_detach"
)

func init() {
	operatorPermissions["node.certificate.rotate"] = struct{}{}
	operatorPermissions["node.detach"] = struct{}{}
}

type NodeCertificateRotationRequest struct {
	NodeID                 federation.ID
	TenantID               federation.ID
	ExpectedGeneration     uint64
	ExpectedAuthorityEpoch uint64
	IdempotencyKey         string
	SigningPublicKey       []byte
	PreviousCertificateFingerprint string
}

type NodeCertificateRotationReservation struct {
	RequestDigest    string
	IssuedAt         time.Time
	ResultGeneration uint64
	Result           *NodeCertificateRotationResult
}

type NodeCertificateRotationResult = federation.NodeCertificateRotationResult

type NodeDetachRequest struct {
	NodeID                 federation.ID
	TenantID               federation.ID
	ExpectedGeneration     uint64
	ExpectedAuthorityEpoch uint64
	IdempotencyKey         string
	Reason                 string
}

type NodeDetachResult struct {
	NodeID                 federation.ID `json:"node_id"`
	Generation             uint64        `json:"generation"`
	AuthorityEpoch         uint64        `json:"authority_epoch"`
	State                  NodeState     `json:"state"`
	RevocationSigningKeyID string        `json:"revocation_signing_key_id"`
	DetachRequestedAt      time.Time     `json:"detach_requested_at"`
}

func (request NodeCertificateRotationRequest) validate() error {
	if !validSHA256(request.PreviousCertificateFingerprint) {
		return ErrInvalid
	}
	if !request.NodeID.Valid() || !request.TenantID.Valid() || request.ExpectedGeneration == 0 || request.ExpectedGeneration >= 1<<63-1 || request.ExpectedAuthorityEpoch == 0 || request.ExpectedAuthorityEpoch >= 1<<63-1 || !validLifecycleIdempotency(request.IdempotencyKey) || len(request.SigningPublicKey) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	return nil
}

func (request NodeCertificateRotationRequest) requestDigest() string {
	encoded, _ := json.Marshal(struct {
		Domain, NodeID, TenantID, IdempotencyKey, PreviousCertificateFingerprint string
		ExpectedGeneration, ExpectedAuthorityEpoch uint64
		SigningPublicKey []byte
	}{"cyberpanel-node-certificate-rotation-v1", request.NodeID.String(), request.TenantID.String(), request.IdempotencyKey, request.PreviousCertificateFingerprint, request.ExpectedGeneration, request.ExpectedAuthorityEpoch, request.SigningPublicKey})
	return digest(encoded)
}

func (request NodeDetachRequest) validate() error {
	if !request.NodeID.Valid() || !request.TenantID.Valid() || request.ExpectedGeneration == 0 || request.ExpectedGeneration >= 1<<63-1 || request.ExpectedAuthorityEpoch == 0 || request.ExpectedAuthorityEpoch >= 1<<63-1 || !validLifecycleIdempotency(request.IdempotencyKey) || request.Reason == "" || len(request.Reason) > 512 || strings.ContainsAny(request.Reason, "\x00\r\n") {
		return ErrInvalid
	}
	return nil
}

func (request NodeDetachRequest) requestDigest() string {
	encoded, _ := json.Marshal(struct {
		Domain, NodeID, TenantID, IdempotencyKey, Reason string
		ExpectedGeneration, ExpectedAuthorityEpoch uint64
	}{"cyberpanel-node-detach-v1", request.NodeID.String(), request.TenantID.String(), request.IdempotencyKey, request.Reason, request.ExpectedGeneration, request.ExpectedAuthorityEpoch})
	return digest(encoded)
}

func validLifecycleIdempotency(value string) bool {
	return value != "" && len(value) <= 256 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func (s *Store) NodeLifecycleGeneration(ctx context.Context, nodeID federation.ID) (uint64, error) {
	if s == nil || s.db == nil || ctx == nil || !nodeID.Valid() {
		return 0, ErrInvalid
	}
	var generation uint64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT generation FROM fleet_node_lifecycle WHERE node_id=fleet_nodes.id),1) FROM fleet_nodes WHERE id=?`, nodeID).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return generation, err
}

func (s *Store) BootstrapLifecycle(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, lifecycleSchema); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_node_lifecycle(node_id,generation,updated_at) SELECT id,1,? FROM fleet_nodes WHERE true ON CONFLICT(node_id) DO NOTHING`, s.clock().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReserveNodeCertificateRotation(ctx context.Context, request NodeCertificateRotationRequest) (NodeCertificateRotationReservation, error) {
	var reservation NodeCertificateRotationReservation
	if s == nil || s.db == nil || ctx == nil || request.validate() != nil {
		return reservation, ErrInvalid
	}
	requestDigest := request.requestDigest()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return reservation, err
	}
	defer tx.Rollback()
	var storedDigest, state string
	var responseJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT request_digest,state,result_generation,issued_at,response_json FROM fleet_lifecycle_operations WHERE tenant_id=? AND operation=? AND idempotency_key=?`, request.TenantID, lifecycleRotate, request.IdempotencyKey).Scan(&storedDigest, &state, &reservation.ResultGeneration, &reservation.IssuedAt, &responseJSON)
	if err == nil {
		if subtle.ConstantTimeCompare([]byte(storedDigest), []byte(requestDigest)) != 1 || state != "reserved" && state != "applied" {
			return reservation, ErrConflict
		}
		reservation.RequestDigest = requestDigest
		if state == "applied" {
			var result NodeCertificateRotationResult
			if json.Unmarshal(responseJSON, &result) != nil {
				return reservation, ErrConflict
			}
			reservation.Result = &result
		}
		return reservation, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return reservation, err
	}
	node, err := loadNodeTx(ctx, tx, request.NodeID)
	if err != nil {
		return reservation, err
	}
	if node.CertificateFingerprint != request.PreviousCertificateFingerprint {
		return reservation, ErrStale
	}
	if node.OwnerTenantID != request.TenantID || node.AuthorityEpoch != request.ExpectedAuthorityEpoch || node.State == NodeRevoked || node.State == NodeRevoking {
		return reservation, ErrForbidden
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_node_lifecycle(node_id,generation,updated_at) VALUES(?,1,?) ON CONFLICT(node_id) DO NOTHING`, node.ID, s.clock().UTC()); err != nil {
		return reservation, err
	}
	var generation uint64
	if err = tx.QueryRowContext(ctx, `SELECT generation FROM fleet_node_lifecycle WHERE node_id=?`, node.ID).Scan(&generation); err != nil {
		return reservation, err
	}
	if generation != request.ExpectedGeneration {
		return reservation, ErrStale
	}
	// A reserved operation has no published certificate or committed effect.
	// A new idempotency key may supersede it; completion checks its state again.
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_lifecycle_operations SET state='cancelled',updated_at=? WHERE node_id=? AND operation=? AND state='reserved' AND expected_generation=?`, s.clock().UTC(), node.ID, lifecycleRotate, generation); err != nil {
		return reservation, err
	}
	reservation = NodeCertificateRotationReservation{RequestDigest: requestDigest, IssuedAt: s.clock().UTC(), ResultGeneration: generation + 1}
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_lifecycle_operations(tenant_id,operation,idempotency_key,node_id,request_digest,expected_generation,result_generation,authority_epoch,state,issued_at,response_json,updated_at) VALUES(?,?,?,?,?,?,?,?,? ,?,'',?)`, request.TenantID, lifecycleRotate, request.IdempotencyKey, request.NodeID, requestDigest, generation, reservation.ResultGeneration, request.ExpectedAuthorityEpoch, "reserved", reservation.IssuedAt, reservation.IssuedAt); err != nil {
		return NodeCertificateRotationReservation{}, err
	}
	return reservation, tx.Commit()
}

func (s *Store) CompleteNodeCertificateRotation(ctx context.Context, request NodeCertificateRotationRequest, reservation NodeCertificateRotationReservation, issued IssuedEnrollmentCertificate, result NodeCertificateRotationResult) (NodeCertificateRotationResult, error) {
	if result.PreviousCertificateFingerprint != request.PreviousCertificateFingerprint || result.RequestDigest != reservation.RequestDigest || result.IdempotencyKey != request.IdempotencyKey || !bytes.Equal(result.SigningPublicKey, request.SigningPublicKey) || len(result.Signature) != ed25519.SignatureSize {
		return NodeCertificateRotationResult{}, ErrInvalid
	}
	if s == nil || s.db == nil || ctx == nil || request.validate() != nil || reservation.RequestDigest != request.requestDigest() || reservation.ResultGeneration != request.ExpectedGeneration+1 || !validSHA256(issued.Fingerprint) || result.NodeID != request.NodeID || result.Generation != reservation.ResultGeneration || result.AuthorityEpoch != request.ExpectedAuthorityEpoch || result.CertificateFingerprint != issued.Fingerprint || result.EvidenceKeyID != "fedcert_"+issued.Fingerprint[:48] || !result.CertificateExpiresAt.Equal(issued.ExpiresAt) || !bytes.Equal(result.NodeCertificate, issued.PEM) {
		return NodeCertificateRotationResult{}, ErrInvalid
	}
	responseJSON, err := json.Marshal(result)
	if err != nil || len(responseJSON) > operatorMaximumResponseBytes {
		return NodeCertificateRotationResult{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return NodeCertificateRotationResult{}, err
	}
	defer tx.Rollback()
	var storedDigest, state string
	var storedResponse []byte
	var storedIssuedAt time.Time
	var storedGeneration uint64
	err = tx.QueryRowContext(ctx, `SELECT request_digest,state,response_json,issued_at,result_generation FROM fleet_lifecycle_operations WHERE tenant_id=? AND operation=? AND idempotency_key=?`, request.TenantID, lifecycleRotate, request.IdempotencyKey).Scan(&storedDigest, &state, &storedResponse, &storedIssuedAt, &storedGeneration)
	if err != nil || subtle.ConstantTimeCompare([]byte(storedDigest), []byte(reservation.RequestDigest)) != 1 {
		return NodeCertificateRotationResult{}, firstLifecycleError(err)
	}
	if state == "applied" {
		var existing NodeCertificateRotationResult
		if json.Unmarshal(storedResponse, &existing) != nil {
			return existing, ErrConflict
		}
		return existing, tx.Commit()
	}
	if state != "reserved" || !storedIssuedAt.Equal(reservation.IssuedAt) || storedGeneration != reservation.ResultGeneration || issued.NotBefore.After(s.clock().UTC()) || !issued.ExpiresAt.After(s.clock().UTC()) {
		return NodeCertificateRotationResult{}, ErrStale
	}
	node, err := loadNodeTx(ctx, tx, request.NodeID)
	if err != nil {
		return NodeCertificateRotationResult{}, err
	}
	if node.CertificateFingerprint != request.PreviousCertificateFingerprint {
		return NodeCertificateRotationResult{}, ErrStale
	}
	if node.OwnerTenantID != request.TenantID || node.AuthorityEpoch != request.ExpectedAuthorityEpoch || node.State == NodeRevoked || node.State == NodeRevoking {
		return NodeCertificateRotationResult{}, ErrForbidden
	}
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_node_evidence_keys SET state='historical',updated_at=? WHERE node_id=? AND state='current'`, reservation.IssuedAt, node.ID); err != nil {
		return NodeCertificateRotationResult{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_node_evidence_keys(node_id,key_id,state,public_key,not_before,expires_at,created_at,updated_at) VALUES(?,?,'current',?,?,?,?,?)`, node.ID, result.EvidenceKeyID, request.SigningPublicKey, issued.NotBefore, issued.ExpiresAt, reservation.IssuedAt, reservation.IssuedAt); err != nil {
		return NodeCertificateRotationResult{}, err
	}
	now := s.clock().UTC()
	update, err := tx.ExecContext(ctx, `UPDATE fleet_nodes SET state='enrolling',certificate_fingerprint=?,updated_at=? WHERE id=? AND owner_tenant_id=? AND authority_epoch=? AND certificate_fingerprint=? AND state NOT IN ('revoking','revoked')`, issued.Fingerprint, now, node.ID, request.TenantID, request.ExpectedAuthorityEpoch, node.CertificateFingerprint)
	if err != nil {
		return NodeCertificateRotationResult{}, err
	}
	if affected, rowsErr := update.RowsAffected(); rowsErr != nil || affected != 1 {
		return NodeCertificateRotationResult{}, ErrStale
	}
	update, err = tx.ExecContext(ctx, `UPDATE fleet_node_lifecycle SET generation=?,updated_at=? WHERE node_id=? AND generation=?`, result.Generation, now, node.ID, request.ExpectedGeneration)
	if err != nil {
		return NodeCertificateRotationResult{}, err
	}
	if affected, rowsErr := update.RowsAffected(); rowsErr != nil || affected != 1 {
		return NodeCertificateRotationResult{}, ErrStale
	}
	update, err = tx.ExecContext(ctx, `UPDATE fleet_lifecycle_operations SET state='applied',response_json=?,updated_at=? WHERE tenant_id=? AND operation=? AND idempotency_key=? AND state='reserved'`, responseJSON, now, request.TenantID, lifecycleRotate, request.IdempotencyKey)
	if err != nil {
		return NodeCertificateRotationResult{}, err
	}
	if affected, rowsErr := update.RowsAffected(); rowsErr != nil || affected != 1 {
		return NodeCertificateRotationResult{}, ErrConflict
	}
	if err = s.appendLifecycleEvidenceTx(ctx, tx, request.TenantID, node.ID, lifecycleRotate, result.Generation, node.AuthorityEpoch, reservation.RequestDigest, node.CertificateFingerprint, issued.Fingerprint, result.EvidenceKeyID); err != nil {
		return NodeCertificateRotationResult{}, err
	}
	return result, tx.Commit()
}

func (s *Store) DetachNode(ctx context.Context, request NodeDetachRequest, revocation federation.Revocation) (NodeDetachResult, error) {
	var detached NodeDetachResult
	if s == nil || s.db == nil || ctx == nil || request.validate() != nil || revocation.NodeID != request.NodeID || !revocation.PeerID.Valid() || revocation.NewAuthorityEpoch != request.ExpectedAuthorityEpoch+1 || revocation.Reason != request.Reason || revocation.IssuedAt.IsZero() || revocation.SigningKeyID == "" || len(revocation.SigningKeyID) > 256 || len(revocation.Signature) != ed25519.SignatureSize {
		return detached, ErrInvalid
	}
	requestDigest := request.requestDigest()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return detached, err
	}
	defer tx.Rollback()
	var storedDigest, state string
	var responseJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT request_digest,state,response_json FROM fleet_lifecycle_operations WHERE tenant_id=? AND operation=? AND idempotency_key=?`, request.TenantID, lifecycleDetach, request.IdempotencyKey).Scan(&storedDigest, &state, &responseJSON)
	if err == nil {
		if subtle.ConstantTimeCompare([]byte(storedDigest), []byte(requestDigest)) != 1 || state != "applied" || json.Unmarshal(responseJSON, &detached) != nil {
			return detached, ErrConflict
		}
		return detached, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return detached, err
	}
	node, err := loadNodeTx(ctx, tx, request.NodeID)
	if err != nil {
		return detached, err
	}
	if node.OwnerTenantID != request.TenantID || node.AuthorityEpoch != request.ExpectedAuthorityEpoch || node.State == NodeRevoked || node.State == NodeRevoking {
		return detached, ErrForbidden
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_node_lifecycle(node_id,generation,updated_at) VALUES(?,1,?) ON CONFLICT(node_id) DO NOTHING`, node.ID, s.clock().UTC()); err != nil {
		return detached, err
	}
	var generation uint64
	if err = tx.QueryRowContext(ctx, `SELECT generation FROM fleet_node_lifecycle WHERE node_id=?`, node.ID).Scan(&generation); err != nil {
		return detached, err
	}
	if generation != request.ExpectedGeneration {
		return detached, ErrStale
	}
	now := s.clock().UTC()
	detached = NodeDetachResult{NodeID: node.ID, Generation: generation + 1, AuthorityEpoch: revocation.NewAuthorityEpoch, State: NodeRevoking, RevocationSigningKeyID: revocation.SigningKeyID, DetachRequestedAt: now}
	responseJSON, err = json.Marshal(detached)
	if err != nil {
		return NodeDetachResult{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_lifecycle_operations(tenant_id,operation,idempotency_key,node_id,request_digest,expected_generation,result_generation,authority_epoch,state,issued_at,response_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, request.TenantID, lifecycleDetach, request.IdempotencyKey, node.ID, requestDigest, generation, detached.Generation, detached.AuthorityEpoch, "applied", now, responseJSON, now); err != nil {
		return NodeDetachResult{}, err
	}
	revocationJSON, err := json.Marshal(revocation)
	if err != nil {
		return NodeDetachResult{}, err
	}
	update, err := tx.ExecContext(ctx, `UPDATE fleet_nodes SET state='revoking',authority_epoch=?,updated_at=? WHERE id=? AND owner_tenant_id=? AND authority_epoch=? AND state NOT IN ('revoking','revoked')`, detached.AuthorityEpoch, now, node.ID, request.TenantID, request.ExpectedAuthorityEpoch)
	if err != nil {
		return NodeDetachResult{}, err
	}
	if affected, rowsErr := update.RowsAffected(); rowsErr != nil || affected != 1 {
		return NodeDetachResult{}, ErrStale
	}
	statements := []struct{ query string; arguments []any }{
		{`UPDATE fleet_node_lifecycle SET generation=?,updated_at=? WHERE node_id=? AND generation=?`, []any{detached.Generation, now, node.ID, generation}},
		{`UPDATE fleet_grants SET state='revoked',updated_at=? WHERE node_id=? AND state='active'`, []any{now, node.ID}},
		{`UPDATE fleet_intents SET status='rejected',updated_at=? WHERE node_id=? AND status IN ('queued','sent','accepted','running','ambiguous')`, []any{now, node.ID}},
		{`UPDATE fleet_node_evidence_keys SET state='revoked',updated_at=? WHERE node_id=? AND state IN ('current','historical')`, []any{now, node.ID}},
		{`UPDATE fleet_enrollment_tokens SET state='revoked',completed_at=? WHERE node_id=? AND state IN ('pending','consumed')`, []any{now, node.ID}},
		{`UPDATE fleet_lifecycle_operations SET state='cancelled',updated_at=? WHERE node_id=? AND state='reserved'`, []any{now, node.ID}},
		{`UPDATE fleet_projections SET stale=1 WHERE node_id=?`, []any{node.ID}},
		{`UPDATE fleet_encrypted_secrets SET consumed_at=? WHERE target_node_id=? AND consumed_at IS NULL`, []any{now, node.ID}},
	}
	for index, statement := range statements {
		result, execErr := tx.ExecContext(ctx, statement.query, statement.arguments...)
		if execErr != nil {
			return NodeDetachResult{}, execErr
		}
		if index == 0 {
			if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
				return NodeDetachResult{}, ErrStale
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_revocations(node_id,authority_epoch,status,revocation_json,created_at,updated_at) VALUES(?,?,'queued',?,?,?)`, node.ID, detached.AuthorityEpoch, revocationJSON, now, now); err != nil {
			return NodeDetachResult{}, err
	}
	if err = s.appendLifecycleEvidenceTx(ctx, tx, request.TenantID, node.ID, lifecycleDetach, detached.Generation, detached.AuthorityEpoch, requestDigest, node.CertificateFingerprint, node.CertificateFingerprint, revocation.SigningKeyID+"\x00"+request.Reason); err != nil {
		return NodeDetachResult{}, err
	}
	return detached, tx.Commit()
}

func (s *Store) appendLifecycleEvidenceTx(ctx context.Context, tx *authorityTx, tenant, node federation.ID, operation string, generation, authorityEpoch uint64, requestDigest, previousFingerprint, currentFingerprint, detail string) error {
	previous := strings.Repeat("0", 64)
	err := tx.QueryRowContext(ctx, `SELECT event_digest FROM fleet_lifecycle_evidence ORDER BY sequence DESC LIMIT 1`).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	now := s.clock().UTC()
	canonical, err := json.Marshal(struct {
		Domain, TenantID, NodeID, Operation, RequestDigest, PreviousFingerprint, CurrentFingerprint, DetailDigest, PreviousDigest string
		Generation, AuthorityEpoch uint64
		OccurredAt time.Time
	}{"cyberpanel-central-lifecycle-evidence-v1", tenant.String(), node.String(), operation, requestDigest, previousFingerprint, currentFingerprint, digest([]byte(detail)), previous, generation, authorityEpoch, now})
	if err != nil {
		return err
	}
	eventDigest := digest(canonical)
	_, err = tx.ExecContext(ctx, `INSERT INTO fleet_lifecycle_evidence(event_id,occurred_at,tenant_id,node_id,operation,generation,authority_epoch,request_digest,previous_fingerprint,current_fingerprint,detail_digest,previous_digest,event_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, "life_"+eventDigest[:48], now, tenant, node, operation, generation, authorityEpoch, requestDigest, previousFingerprint, currentFingerprint, digest([]byte(detail)), previous, eventDigest)
	return err
}

func firstLifecycleError(err error) error {
	if err != nil {
		return err
	}
	return ErrConflict
}
