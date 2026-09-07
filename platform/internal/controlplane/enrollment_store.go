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
CREATE TABLE IF NOT EXISTS fleet_enrollment_results(
 token_id TEXT PRIMARY KEY,
 request_digest TEXT NOT NULL UNIQUE,
 hpke_public_key BLOB NOT NULL,
 response_json BLOB NOT NULL,
 certificate_fingerprint TEXT NOT NULL UNIQUE,
 created_at TIMESTAMP NOT NULL
);
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

type EnrollmentConsumption struct {
	Enrollment     ProvisionedEnrollment
	RequestDigest  string
	ConsumedAt     time.Time
	IssuedResponse json.RawMessage
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
		result, execErr := tx.ExecContext(ctx, `INSERT INTO fleet_enrollment_tokens(id,token_digest,node_id,tenant_id,peer_id,ca_fingerprint,capability_digest,authority_epoch,expires_at,enrollment_json,state,request_digest,certificate_fingerprint,provisioned_at,consumed_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,'pending','','',?,NULL,NULL) ON CONFLICT(id) DO UPDATE SET state=CASE WHEN fleet_enrollment_tokens.state='staged' THEN 'pending' ELSE fleet_enrollment_tokens.state END,provisioned_at=excluded.provisioned_at WHERE fleet_enrollment_tokens.token_digest=excluded.token_digest AND fleet_enrollment_tokens.node_id=excluded.node_id AND fleet_enrollment_tokens.tenant_id=excluded.tenant_id AND fleet_enrollment_tokens.peer_id=excluded.peer_id AND fleet_enrollment_tokens.ca_fingerprint=excluded.ca_fingerprint AND fleet_enrollment_tokens.capability_digest=excluded.capability_digest AND fleet_enrollment_tokens.authority_epoch=excluded.authority_epoch AND fleet_enrollment_tokens.expires_at=excluded.expires_at AND fleet_enrollment_tokens.enrollment_json=excluded.enrollment_json AND fleet_enrollment_tokens.state IN ('staged','pending','consumed','issued','failed','revoked')`, token.ID, token.TokenDigest, token.NodeID, token.TenantID, token.PeerID, token.CAFingerprint, token.CapabilityDigest, token.AuthorityEpoch, token.ExpiresAt.UTC(), enrollmentJSON, now)
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

func (s *Store) ConsumeEnrollmentToken(ctx context.Context, attempt EnrollmentAttempt) (EnrollmentConsumption, error) {
	var consumption EnrollmentConsumption
	if s == nil || s.db == nil || ctx == nil || attempt.validate() != nil {
		return consumption, ErrInvalid
	}
	requestDigest := attempt.requestDigest()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return consumption, err
	}
	defer tx.Rollback()
	var stored ProvisionedEnrollmentToken
	var enrollmentJSON []byte
	var state, storedRequestDigest string
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT id,token_digest,node_id,tenant_id,peer_id,ca_fingerprint,capability_digest,authority_epoch,expires_at,enrollment_json,state,request_digest,consumed_at FROM fleet_enrollment_tokens WHERE id=?`, attempt.TokenID).Scan(&stored.ID, &stored.TokenDigest, &stored.NodeID, &stored.TenantID, &stored.PeerID, &stored.CAFingerprint, &stored.CapabilityDigest, &stored.AuthorityEpoch, &stored.ExpiresAt, &enrollmentJSON, &state, &storedRequestDigest, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return consumption, ErrForbidden
	}
	if err != nil {
		return consumption, err
	}
	reject := func(outcome string, cause error) (EnrollmentConsumption, error) {
		if auditErr := s.appendEnrollmentAuditTx(ctx, tx, stored, outcome, requestDigest, cause.Error()); auditErr != nil {
			return consumption, auditErr
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return consumption, commitErr
		}
		return consumption, cause
	}
	if state != "pending" && state != "consumed" && state != "issued" {
		if state == "expired" {
			return reject("expired", federation.ErrExpired)
		}
		if state == "failed" {
			return reject("unrecoverable_replay", federation.ErrReplay)
		}
		return reject("revoked", ErrForbidden)
	}
	if state == "consumed" || state == "issued" {
		if !consumedAt.Valid || subtle.ConstantTimeCompare([]byte(storedRequestDigest), []byte(requestDigest)) != 1 {
			return reject("changed_replay", federation.ErrReplay)
		}
		if err = json.Unmarshal(enrollmentJSON, &consumption.Enrollment); err != nil {
			return EnrollmentConsumption{}, err
		}
		consumption.RequestDigest = requestDigest
		consumption.ConsumedAt = consumedAt.Time.UTC()
		outcome := "issuance_resumed"
		detail := "exact consumed request resumed"
		if state == "issued" {
			var hpkePublicKey, responseJSON []byte
			if err = tx.QueryRowContext(ctx, `SELECT hpke_public_key,response_json FROM fleet_enrollment_results WHERE token_id=? AND request_digest=?`, stored.ID, requestDigest).Scan(&hpkePublicKey, &responseJSON); err != nil {
				return EnrollmentConsumption{}, err
			}
			if subtle.ConstantTimeCompare(hpkePublicKey, attempt.HPKEPublicKey) != 1 {
				return reject("changed_replay", federation.ErrReplay)
			}
			consumption.IssuedResponse = append(json.RawMessage(nil), responseJSON...)
			outcome = "response_replayed"
			detail = "exact issued response replayed"
		}
		if err = s.appendEnrollmentAuditTx(ctx, tx, stored, outcome, requestDigest, detail); err != nil {
			return EnrollmentConsumption{}, err
		}
		if err = tx.Commit(); err != nil {
			return EnrollmentConsumption{}, err
		}
		return consumption, nil
	}
	now := s.clock().UTC()
	if !now.Before(stored.ExpiresAt) {
		if _, err = tx.ExecContext(ctx, `UPDATE fleet_enrollment_tokens SET state='expired',completed_at=? WHERE id=? AND state='pending'`, now, stored.ID); err != nil {
			return consumption, err
		}
		return reject("expired", federation.ErrExpired)
	}
	bindingsMatch := subtle.ConstantTimeCompare([]byte(stored.TokenDigest), []byte(attempt.TokenDigest)) == 1 && stored.NodeID == attempt.NodeID && stored.PeerID == attempt.PeerID && subtle.ConstantTimeCompare([]byte(stored.CAFingerprint), []byte(attempt.CAFingerprint)) == 1 && subtle.ConstantTimeCompare([]byte(stored.CapabilityDigest), []byte(attempt.CapabilityDigest)) == 1
	if !bindingsMatch {
		return reject("binding_rejected", ErrForbidden)
	}
	if err = json.Unmarshal(enrollmentJSON, &consumption.Enrollment); err != nil {
		return EnrollmentConsumption{}, err
	}
	stored.Enrollment = consumption.Enrollment
	if err = stored.validate(now, attempt.PeerID, attempt.CAFingerprint); err != nil {
		return EnrollmentConsumption{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE fleet_enrollment_tokens SET state='consumed',request_digest=?,consumed_at=? WHERE id=? AND state='pending'`, requestDigest, now, stored.ID)
	if err != nil {
		return EnrollmentConsumption{}, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return reject("replay", federation.ErrReplay)
	}
	if err = s.appendEnrollmentAuditTx(ctx, tx, stored, "consumed", requestDigest, "token consumed before certificate issuance"); err != nil {
		return EnrollmentConsumption{}, err
	}
	if err = tx.Commit(); err != nil {
		return EnrollmentConsumption{}, err
	}
	consumption.RequestDigest = requestDigest
	consumption.ConsumedAt = now
	return consumption, nil
}

func (s *Store) CompleteEnrollment(ctx context.Context, attempt EnrollmentAttempt, enrollment ProvisionedEnrollment, responseJSON []byte) ([]byte, error) {
	if s == nil || s.db == nil || ctx == nil || attempt.validate() != nil || len(responseJSON) == 0 || len(responseJSON) > enrollmentMaximumResponseBytes || !json.Valid(responseJSON) || !validSHA256(enrollment.Node.CertificateFingerprint) {
		return nil, ErrInvalid
	}
	tokenID, requestDigest := attempt.TokenID, attempt.requestDigest()
	certificateFingerprint := enrollment.Node.CertificateFingerprint
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var token ProvisionedEnrollmentToken
	var state, storedRequestDigest string
	err = tx.QueryRowContext(ctx, `SELECT id,node_id,tenant_id,peer_id,authority_epoch,state,request_digest FROM fleet_enrollment_tokens WHERE id=?`, tokenID).Scan(&token.ID, &token.NodeID, &token.TenantID, &token.PeerID, &token.AuthorityEpoch, &state, &storedRequestDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(storedRequestDigest), []byte(requestDigest)) != 1 || token.NodeID != enrollment.Node.ID || token.TenantID != enrollment.Node.OwnerTenantID || token.AuthorityEpoch != enrollment.Node.AuthorityEpoch || token.PeerID != enrollment.Grant.PeerID {
		return nil, ErrConflict
	}
	if state == "issued" {
		var storedResponse, storedHPKE []byte
		if err = tx.QueryRowContext(ctx, `SELECT response_json,hpke_public_key FROM fleet_enrollment_results WHERE token_id=? AND request_digest=?`, tokenID, requestDigest).Scan(&storedResponse, &storedHPKE); err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(storedHPKE, attempt.HPKEPublicKey) != 1 {
			return nil, ErrConflict
		}
		return storedResponse, tx.Commit()
	}
	if state != "consumed" {
		return nil, ErrConflict
	}
	existing, lookupErr := loadNodeTx(ctx, tx, token.NodeID)
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return nil, lookupErr
	}
	if lookupErr == nil && (existing.State == NodeRevoked || existing.State == NodeRevoking || existing.CertificateFingerprint != certificateFingerprint || existing.AuthorityEpoch != token.AuthorityEpoch) {
		return nil, ErrStale
	}
	if err = s.provisionEnrollmentTx(ctx, tx, enrollment); err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	if _, err = tx.ExecContext(ctx, `INSERT INTO fleet_enrollment_results(token_id,request_digest,hpke_public_key,response_json,certificate_fingerprint,created_at) VALUES(?,?,?,?,?,?)`, tokenID, requestDigest, attempt.HPKEPublicKey, responseJSON, certificateFingerprint, now); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE fleet_enrollment_tokens SET state='issued',certificate_fingerprint=?,completed_at=? WHERE id=? AND state='consumed' AND request_digest=?`, certificateFingerprint, now, tokenID, requestDigest)
	if err != nil {
		return nil, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return nil, ErrStale
	}
	if err = s.appendEnrollmentAuditTx(ctx, tx, token, "issued", requestDigest, certificateFingerprint); err != nil {
		return nil, err
	}
	return responseJSON, tx.Commit()
}

func (s *Store) RecordEnrollmentFailure(ctx context.Context, tokenID federation.ID, outcome string) error {
	if s == nil || s.db == nil || ctx == nil || !tokenID.Valid() || outcome != "issuance_failed" && outcome != "persistence_failed" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var token ProvisionedEnrollmentToken
	var requestDigest, state string
	if err = tx.QueryRowContext(ctx, `SELECT id,node_id,tenant_id,peer_id,request_digest,state FROM fleet_enrollment_tokens WHERE id=?`, tokenID).Scan(&token.ID, &token.NodeID, &token.TenantID, &token.PeerID, &requestDigest, &state); err != nil {
		return err
	}
	if state != "consumed" || !validSHA256(requestDigest) {
		return ErrConflict
	}
	if err = s.appendEnrollmentAuditTx(ctx, tx, token, outcome, requestDigest, outcome); err != nil {
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
