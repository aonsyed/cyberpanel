package controlplane

import (
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

const enrollmentSchema = `
CREATE TABLE IF NOT EXISTS fleet_enrollment_tokens(
 id TEXT PRIMARY KEY,
 token_digest TEXT NOT NULL UNIQUE,
 node_id TEXT NOT NULL,
 tenant_id TEXT NOT NULL,
 peer_id TEXT NOT NULL,
 ca_fingerprint TEXT NOT NULL,
 capability_digest TEXT NOT NULL,
 authority_epoch BIGINT NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 enrollment_json TEXT NOT NULL,
 state TEXT NOT NULL,
 request_digest TEXT NOT NULL,
 certificate_fingerprint TEXT NOT NULL,
 provisioned_at TIMESTAMP NOT NULL,
 consumed_at TIMESTAMP,
 completed_at TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS fleet_enrollment_node_pending
 ON fleet_enrollment_tokens(node_id) WHERE state='pending';
CREATE INDEX IF NOT EXISTS fleet_enrollment_token_state
 ON fleet_enrollment_tokens(state,expires_at);
CREATE TABLE IF NOT EXISTS fleet_enrollment_audit(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 event_id TEXT NOT NULL UNIQUE,
 occurred_at TIMESTAMP NOT NULL,
 token_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 tenant_id TEXT NOT NULL,
 peer_id TEXT NOT NULL,
 outcome TEXT NOT NULL,
 request_digest TEXT NOT NULL,
 detail_digest TEXT NOT NULL,
 previous_digest TEXT NOT NULL,
 event_digest TEXT NOT NULL UNIQUE
);
`

type ProvisionedEnrollmentToken struct {
	ID               federation.ID        `json:"id"`
	TokenDigest      string               `json:"token_digest"`
	NodeID           federation.ID        `json:"node_id"`
	TenantID         federation.ID        `json:"tenant_id"`
	PeerID           federation.ID        `json:"peer_id"`
	CAFingerprint    string               `json:"ca_fingerprint"`
	CapabilityDigest string               `json:"capability_digest"`
	AuthorityEpoch   uint64               `json:"authority_epoch"`
	ExpiresAt        time.Time            `json:"expires_at"`
	Enrollment       ProvisionedEnrollment `json:"enrollment"`
}

type EnrollmentAttempt struct {
	TokenID          federation.ID
	TokenDigest      string
	NodeID           federation.ID
	PeerID           federation.ID
	CAFingerprint    string
	CapabilityDigest string
	SigningPublicKey []byte
	HPKEPublicKey    []byte
}

func (token ProvisionedEnrollmentToken) validate(now time.Time, peer federation.ID, caFingerprint string) error {
	node := token.Enrollment.Node
	grant := token.Enrollment.Grant
	capabilities := node.Capabilities
	if !token.ID.Valid() || !token.NodeID.Valid() || !token.TenantID.Valid() || token.PeerID != peer || token.CAFingerprint != caFingerprint || !validSHA256(token.TokenDigest) || !validSHA256(token.CAFingerprint) || !validSHA256(token.CapabilityDigest) || token.AuthorityEpoch == 0 || token.ExpiresAt.IsZero() || !token.ExpiresAt.After(now) || token.ExpiresAt.After(now.Add(65*time.Minute)) {
		return ErrInvalid
	}
	if node.ID != token.NodeID || node.OwnerTenantID != token.TenantID || node.AuthorityEpoch != token.AuthorityEpoch || node.CertificateFingerprint != "" || node.State != "" && node.State != NodeEnrolling && node.State != NodeOffline || strings.TrimSpace(node.Name) == "" || node.Name != strings.TrimSpace(node.Name) || len(node.Name) > 256 || len(token.Enrollment.EvidenceKeys) != 0 {
		return ErrInvalid
	}
	if capabilities.NodeID != token.NodeID || capabilities.AuthorityEpoch != token.AuthorityEpoch || capabilities.Digest != token.CapabilityDigest || capabilities.CanonicalDigest() != token.CapabilityDigest {
		return ErrForbidden
	}
	if grant.Validate(now) != nil || grant.NodeID != token.NodeID || grant.PeerID != token.PeerID || grant.AuthorityEpoch != token.AuthorityEpoch || !grant.ExpiresAt.After(token.ExpiresAt) {
		return ErrForbidden
	}
	return nil
}

func (attempt EnrollmentAttempt) validate() error {
	if !attempt.TokenID.Valid() || !attempt.NodeID.Valid() || !attempt.PeerID.Valid() || !validSHA256(attempt.TokenDigest) || !validSHA256(attempt.CAFingerprint) || !validSHA256(attempt.CapabilityDigest) || len(attempt.SigningPublicKey) != ed25519.PublicKeySize || len(attempt.HPKEPublicKey) != 32 {
		return ErrInvalid
	}
	return nil
}

func (attempt EnrollmentAttempt) requestDigest() string {
	encoded, _ := json.Marshal(struct {
		Domain, TokenID, TokenDigest, NodeID, PeerID, CAFingerprint, CapabilityDigest string
		SigningPublicKey, HPKEPublicKey                                            []byte
	}{"cyberpanel-central-enrollment-request-v1", attempt.TokenID.String(), attempt.TokenDigest, attempt.NodeID.String(), attempt.PeerID.String(), attempt.CAFingerprint, attempt.CapabilityDigest, attempt.SigningPublicKey, attempt.HPKEPublicKey})
	return digest(encoded)
}

func (s *Store) BootstrapEnrollment(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, enrollmentSchema)
	return err
}

func (s *Store) ProvisionEnrollmentTokens(ctx context.Context, tokens []ProvisionedEnrollmentToken, peer federation.ID, caFingerprint string) error {
	if s == nil || s.db == nil || ctx == nil || len(tokens) == 0 || len(tokens) > 10000 || !peer.Valid() || !validSHA256(caFingerprint) {
		return ErrInvalid
	}
	now := s.clock().UTC()
	identifiers := make(map[federation.ID]struct{}, len(tokens))
	digests := make(map[string]struct{}, len(tokens))
	nodes := make(map[federation.ID]struct{}, len(tokens))
	activeTokens := make([]ProvisionedEnrollmentToken, 0, len(tokens))
	for _, token := range tokens {
		if !token.ExpiresAt.After(now) {
			continue
		}
		if err := token.validate(now, peer, caFingerprint); err != nil {
			return err
		}
		if _, found := identifiers[token.ID]; found {
			return ErrConflict
		}
		if _, found := digests[token.TokenDigest]; found {
			return ErrConflict
		}
		if _, found := nodes[token.NodeID]; found {
			return ErrConflict
		}
		identifiers[token.ID] = struct{}{}
		digests[token.TokenDigest] = struct{}{}
		nodes[token.NodeID] = struct{}{}
		activeTokens = append(activeTokens, token)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_enrollment_tokens SET state='expired',completed_at=? WHERE state='pending' AND expires_at<=?`, now, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_enrollment_tokens SET state='staged',provisioned_at=? WHERE state='pending'`, now); err != nil {
		return err
	}
	for _, token := range activeTokens {
		enrollmentJSON, marshalErr := json.Marshal(token.Enrollment)
		if marshalErr != nil {
			return marshalErr
		}
		result, execErr := tx.ExecContext(ctx, `INSERT INTO fleet_enrollment_tokens(id,token_digest,node_id,tenant_id,peer_id,ca_fingerprint,capability_digest,authority_epoch,expires_at,enrollment_json,state,request_digest,certificate_fingerprint,provisioned_at,consumed_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,'pending','','',?,NULL,NULL) ON CONFLICT(id) DO UPDATE SET state=CASE WHEN fleet_enrollment_tokens.state='staged' THEN 'pending' ELSE fleet_enrollment_tokens.state END,provisioned_at=excluded.provisioned_at WHERE fleet_enrollment_tokens.token_digest=excluded.token_digest AND fleet_enrollment_tokens.node_id=excluded.node_id AND fleet_enrollment_tokens.tenant_id=excluded.tenant_id AND fleet_enrollment_tokens.peer_id=excluded.peer_id AND fleet_enrollment_tokens.ca_fingerprint=excluded.ca_fingerprint AND fleet_enrollment_tokens.capability_digest=excluded.capability_digest AND fleet_enrollment_tokens.authority_epoch=excluded.authority_epoch AND fleet_enrollment_tokens.expires_at=excluded.expires_at AND fleet_enrollment_tokens.enrollment_json=excluded.enrollment_json AND fleet_enrollment_tokens.state IN ('staged','pending','consumed','issued','failed')`, token.ID, token.TokenDigest, token.NodeID, token.TenantID, token.PeerID, token.CAFingerprint, token.CapabilityDigest, token.AuthorityEpoch, token.ExpiresAt.UTC(), enrollmentJSON, now)
		if execErr != nil {
			return execErr
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
			return ErrStale
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE fleet_enrollment_tokens SET state='revoked',completed_at=? WHERE state='staged'`, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConsumeEnrollmentToken(ctx context.Context, attempt EnrollmentAttempt) (ProvisionedEnrollment, error) {
	var enrollment ProvisionedEnrollment
	if s == nil || s.db == nil || ctx == nil || attempt.validate() != nil {
		return enrollment, ErrInvalid
	}
	requestDigest := attempt.requestDigest()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return enrollment, err
	}
	defer tx.Rollback()
	var stored ProvisionedEnrollmentToken
	var enrollmentJSON []byte
	var state string
	err = tx.QueryRowContext(ctx, `SELECT id,token_digest,node_id,tenant_id,peer_id,ca_fingerprint,capability_digest,authority_epoch,expires_at,enrollment_json,state FROM fleet_enrollment_tokens WHERE id=?`, attempt.TokenID).Scan(&stored.ID, &stored.TokenDigest, &stored.NodeID, &stored.TenantID, &stored.PeerID, &stored.CAFingerprint, &stored.CapabilityDigest, &stored.AuthorityEpoch, &stored.ExpiresAt, &enrollmentJSON, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return enrollment, ErrForbidden
	}
	if err != nil {
		return enrollment, err
	}
	reject := func(outcome string, cause error) (ProvisionedEnrollment, error) {
		if auditErr := s.appendEnrollmentAuditTx(ctx, tx, stored, outcome, requestDigest, cause.Error()); auditErr != nil {
			return enrollment, auditErr
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return enrollment, commitErr
		}
		return enrollment, cause
	}
	if state != "pending" {
		if state == "consumed" || state == "issued" || state == "failed" {
			return reject("replay", federation.ErrReplay)
		}
		if state == "expired" {
			return reject("expired", federation.ErrExpired)
		}
		return reject("revoked", ErrForbidden)
	}
	now := s.clock().UTC()
	if !now.Before(stored.ExpiresAt) {
		if _, err = tx.ExecContext(ctx, `UPDATE fleet_enrollment_tokens SET state='expired',completed_at=? WHERE id=? AND state='pending'`, now, stored.ID); err != nil {
			return enrollment, err
		}
		return reject("expired", federation.ErrExpired)
	}
	bindingsMatch := subtle.ConstantTimeCompare([]byte(stored.TokenDigest), []byte(attempt.TokenDigest)) == 1 && stored.NodeID == attempt.NodeID && stored.PeerID == attempt.PeerID && subtle.ConstantTimeCompare([]byte(stored.CAFingerprint), []byte(attempt.CAFingerprint)) == 1 && subtle.ConstantTimeCompare([]byte(stored.CapabilityDigest), []byte(attempt.CapabilityDigest)) == 1
	if !bindingsMatch {
		return reject("binding_rejected", ErrForbidden)
	}
	if err = json.Unmarshal(enrollmentJSON, &enrollment); err != nil {
		return ProvisionedEnrollment{}, err
	}
	stored.Enrollment = enrollment
	if err = stored.validate(now, attempt.PeerID, attempt.CAFingerprint); err != nil {
		return ProvisionedEnrollment{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE fleet_enrollment_tokens SET state='consumed',request_digest=?,consumed_at=? WHERE id=? AND state='pending'`, requestDigest, now, stored.ID)
	if err != nil {
		return ProvisionedEnrollment{}, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return reject("replay", federation.ErrReplay)
	}
	if err = s.appendEnrollmentAuditTx(ctx, tx, stored, "consumed", requestDigest, "token consumed before certificate issuance"); err != nil {
		return ProvisionedEnrollment{}, err
	}
	if err = tx.Commit(); err != nil {
		return ProvisionedEnrollment{}, err
	}
	return enrollment, nil
}

func (s *Store) RecordEnrollmentResult(ctx context.Context, tokenID federation.ID, outcome, certificateFingerprint string) error {
	validOutcome := outcome == "issued" || outcome == "issuance_failed" || outcome == "persistence_failed"
	if s == nil || s.db == nil || ctx == nil || !tokenID.Valid() || !validOutcome || outcome == "issued" && !validSHA256(certificateFingerprint) || outcome != "issued" && certificateFingerprint != "" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var token ProvisionedEnrollmentToken
	var state, requestDigest string
	err = tx.QueryRowContext(ctx, `SELECT id,node_id,tenant_id,peer_id,state,request_digest FROM fleet_enrollment_tokens WHERE id=?`, tokenID).Scan(&token.ID, &token.NodeID, &token.TenantID, &token.PeerID, &state, &requestDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if state != "consumed" {
		return ErrConflict
	}
	completedState := "failed"
	if outcome == "issued" {
		completedState = "issued"
	}
	now := s.clock().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE fleet_enrollment_tokens SET state=?,certificate_fingerprint=?,completed_at=? WHERE id=? AND state='consumed'`, completedState, certificateFingerprint, now, tokenID)
	if err != nil {
		return err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return ErrStale
	}
	if err = s.appendEnrollmentAuditTx(ctx, tx, token, outcome, requestDigest, certificateFingerprint); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) appendEnrollmentAuditTx(ctx context.Context, tx *sql.Tx, token ProvisionedEnrollmentToken, outcome, requestDigest, detail string) error {
	previous := strings.Repeat("0", 64)
	err := tx.QueryRowContext(ctx, `SELECT event_digest FROM fleet_enrollment_audit ORDER BY sequence DESC LIMIT 1`).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	now := s.clock().UTC()
	canonical, err := json.Marshal(struct {
		Domain, TokenID, NodeID, TenantID, PeerID, Outcome, RequestDigest, DetailDigest, PreviousDigest string
		OccurredAt                                                                                  time.Time
	}{"cyberpanel-central-enrollment-audit-v1", token.ID.String(), token.NodeID.String(), token.TenantID.String(), token.PeerID.String(), outcome, requestDigest, digest([]byte(detail)), previous, now})
	if err != nil {
		return err
	}
	eventDigest := digest(canonical)
	eventID := "enroll_" + eventDigest[:48]
	_, err = tx.ExecContext(ctx, `INSERT INTO fleet_enrollment_audit(event_id,occurred_at,token_id,node_id,tenant_id,peer_id,outcome,request_digest,detail_digest,previous_digest,event_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, eventID, now, token.ID, token.NodeID, token.TenantID, token.PeerID, outcome, requestDigest, digest([]byte(detail)), previous, eventDigest)
	return err
}
