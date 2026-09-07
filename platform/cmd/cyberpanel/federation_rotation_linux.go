//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const federationRotationSchema = `
CREATE TABLE IF NOT EXISTS federation_certificate_rotations_v1(
 idempotency_key TEXT PRIMARY KEY,
 node_id TEXT NOT NULL,
 peer_id TEXT NOT NULL,
 expected_generation BIGINT NOT NULL,
 authority_epoch BIGINT NOT NULL,
 previous_certificate_ref TEXT NOT NULL,
 previous_fingerprint TEXT NOT NULL,
 signing_key_ref TEXT NOT NULL,
 signing_public_key BLOB NOT NULL,
 request_json BLOB NOT NULL,
 state TEXT NOT NULL,
 response_json BLOB NOT NULL,
 created_at TIMESTAMP NOT NULL,
 updated_at TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS federation_certificate_rotation_pending_v1
 ON federation_certificate_rotations_v1(peer_id) WHERE state='prepared';
`

type federationRotationRequest struct {
	ExpectedGeneration uint64 `json:"expected_generation"`
	ExpectedAuthorityEpoch uint64 `json:"expected_authority_epoch"`
	IdempotencyKey string `json:"idempotency_key"`
	SigningPublicKey []byte `json:"signing_public_key"`
	PreviousCertificateFingerprint string `json:"previous_certificate_fingerprint_sha256"`
}

// The local owner prepares a public request, posts it to the central operator
// /v1/nodes/{node}/certificate/rotate endpoint, then pipes its signed response
// to apply. Central operator credentials never enter control.db or the broker.
func runFederationCertificateCLI(arguments []string) error {
	if len(arguments) == 0 || arguments[0] != "prepare" && arguments[0] != "apply" {
		return errors.New("usage: cyberpanel federation-certificate prepare|apply --id KEY [--generation CENTRAL_GENERATION]; apply reads the signed rotation response from stdin")
	}
	if os.Geteuid() == 0 {
		return errors.New("run the certificate command as the panel-core account, not root")
	}
	flags := flag.NewFlagSet("federation-certificate "+arguments[0], flag.ContinueOnError)
	id := flags.String("id", "", "durable rotation idempotency key")
	generation := flags.Uint64("generation", 0, "generation from central node inspection (prepare only)")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *id == "" || len(*id) > 256 || *id != strings.TrimSpace(*id) || strings.ContainsAny(*id, "\x00\r\n") {
		return federation.ErrInvalid
	}
	configuration, err := loadCoreConfiguration(coreConfigPath)
	if err != nil {
		return err
	}
	info, err := os.Lstat(configuration.DatabasePath)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return federation.ErrForbidden
	}
	db, err := openControlDatabase(configuration)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	materials, _, err := newFederationEnrollmentMaterials(ctx, db, time.Now)
	if err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, federationRotationSchema); err != nil {
		return err
	}
	if arguments[0] == "prepare" {
		request, prepareErr := prepareFederationRotation(ctx, materials, *id, *generation)
		if prepareErr != nil {
			return prepareErr
		}
		_, err = fmt.Fprintln(os.Stdout, string(request))
		return err
	}
	if *generation != 0 {
		return federation.ErrInvalid
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, federationEnrollmentMaximumResponse+1))
	if err != nil || len(body) == 0 || len(body) > federationEnrollmentMaximumResponse {
		return federation.ErrInvalid
	}
	result, err := applyFederationRotation(ctx, materials, *id, body)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		State string `json:"state"`
		NodeID federation.ID `json:"node_id"`
		CertificateRef string `json:"certificate_ref"`
		Generation uint64 `json:"generation"`
	}{"applied", result.NodeID, result.EvidenceKeyID, result.Generation})
}

func prepareFederationRotation(ctx context.Context, materials *federationEnrollmentMaterials, id string, generation uint64) ([]byte, error) {
	if generation == 0 || generation >= 1<<63-1 {
		return nil, federation.ErrInvalid
	}
	tx, err := materials.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var priorRequest []byte
	var priorGeneration uint64
	err = tx.QueryRowContext(ctx, `SELECT request_json,expected_generation FROM federation_certificate_rotations_v1 WHERE idempotency_key=?`, id).Scan(&priorRequest, &priorGeneration)
	if err == nil {
		if priorGeneration != generation {
			return nil, federation.ErrReplay
		}
		return priorRequest, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var node, peer federation.ID
	var epoch uint64
	var previousRef, previousFingerprint, caFingerprint, hpkeRef string
	err = tx.QueryRowContext(ctx, `SELECT s.node_id,s.authority_epoch,p.id,p.node_certificate_ref,p.ca_fingerprint,p.hpke_key_ref,c.leaf_fingerprint_sha256 FROM federation_state s JOIN federation_peers p ON p.id=s.active_peer_id JOIN federation_node_certificates_v1 c ON c.certificate_ref=p.node_certificate_ref AND c.node_id=s.node_id WHERE s.singleton_id=1 AND p.state='active'`).Scan(&node, &epoch, &peer, &previousRef, &caFingerprint, &hpkeRef, &previousFingerprint)
	if err != nil {
		return nil, err
	}
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM federation_certificate_rotations_v1 WHERE peer_id=? AND state='prepared'`, peer).Scan(&pending); err != nil {
		return nil, err
	}
	if pending != 0 {
		return nil, federation.ErrConflict
	}
	if err = materials.begin(node, caFingerprint); err != nil {
		return nil, err
	}
	defer materials.finish(node)
	publicKey, keyRef, err := materials.CreateSigningIdentity(ctx, node)
	if err != nil {
		return nil, err
	}
	// The protected key is committed before the public request is returned. A
	// crash before this transaction commits cannot have published that request;
	// it can leave only an unreachable broker key, never a replaced identity.
	request := federationRotationRequest{generation, epoch, id, publicKey, previousFingerprint}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	now := materials.now().UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO federation_certificate_rotations_v1(idempotency_key,node_id,peer_id,expected_generation,authority_epoch,previous_certificate_ref,previous_fingerprint,signing_key_ref,signing_public_key,request_json,state,response_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'prepared','',?,?)`, id, node, peer, generation, epoch, previousRef, previousFingerprint, keyRef, publicKey, encoded, now, now)
	if err != nil {
		return nil, err
	}
	return encoded, tx.Commit()
}

func applyFederationRotation(ctx context.Context, materials *federationEnrollmentMaterials, id string, body []byte) (federation.NodeCertificateRotationResult, error) {
	var result federation.NodeCertificateRotationResult
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || result.IdempotencyKey != id {
		return result, federation.ErrInvalid
	}
	canonical, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	tx, err := materials.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var node, peer federation.ID
	var generation, epoch uint64
	var previousRef, previousFingerprint, keyRef, state string
	var publicKey, savedResponse []byte
	err = tx.QueryRowContext(ctx, `SELECT node_id,peer_id,expected_generation,authority_epoch,previous_certificate_ref,previous_fingerprint,signing_key_ref,signing_public_key,state,response_json FROM federation_certificate_rotations_v1 WHERE idempotency_key=?`, id).Scan(&node, &peer, &generation, &epoch, &previousRef, &previousFingerprint, &keyRef, &publicKey, &state, &savedResponse)
	if err != nil {
		return result, err
	}
	if state == "applied" {
		if !bytes.Equal(savedResponse, canonical) {
			return result, federation.ErrReplay
		}
		return result, tx.Commit()
	}
	if state != "prepared" || result.NodeID != node || result.PeerID != peer || result.Generation != generation+1 || result.AuthorityEpoch != epoch || result.PreviousCertificateFingerprint != previousFingerprint || !bytes.Equal(publicKey, result.SigningPublicKey) || !validFederationEnrollmentDigest(result.RequestDigest) || len(result.Signature) != ed25519.SignatureSize {
		return result, federation.ErrForbidden
	}
	var activeRef, caFingerprint string
	var activeEpoch uint64
	err = tx.QueryRowContext(ctx, `SELECT p.node_certificate_ref,p.ca_fingerprint,s.authority_epoch FROM federation_state s JOIN federation_peers p ON p.id=s.active_peer_id WHERE s.singleton_id=1 AND s.node_id=? AND p.id=? AND p.state='active'`, node, peer).Scan(&activeRef, &caFingerprint, &activeEpoch)
	if err != nil || activeRef != previousRef || activeEpoch != epoch {
		return result, federation.ErrStale
	}
	chain, certificatePEM, err := parseFederationNodeCertificate(result.NodeCertificate)
	if err != nil {
		return result, err
	}
	now := materials.now().UTC()
	leaf := chain[0]
	fingerprint := sha256.Sum256(leaf.Raw)
	actualFingerprint := hex.EncodeToString(fingerprint[:])
	leafPublic, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(leafPublic, publicKey) || result.CertificateFingerprint != actualFingerprint || result.EvidenceKeyID != "fedcert_"+actualFingerprint[:48] || !result.CertificateExpiresAt.Equal(leaf.NotAfter.UTC()) || !leaf.NotAfter.After(now) || leaf.NotAfter.Sub(leaf.NotBefore) > federationEnrollmentMaximumCertificateTTL+5*time.Minute || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "urn:cyberpanel:federation:node:"+node.String() {
		return result, federation.ErrForbidden
	}
	if err = verifyFederationCertificateChain(chain, "", caFingerprint, now, x509.ExtKeyUsageClientAuth); err != nil {
		return result, err
	}
	verified := false
	for _, certificate := range chain[1:] {
		anchorFingerprint := sha256.Sum256(certificate.Raw)
		anchorPublic, valid := certificate.PublicKey.(ed25519.PublicKey)
		if valid && certificate.IsCA && hex.EncodeToString(anchorFingerprint[:]) == caFingerprint && ed25519.Verify(anchorPublic, result.SigStructure(), result.Signature) {
			verified = true
		}
	}
	if !verified {
		return result, federation.ErrForbidden
	}
	if err = verifyStagedFederationSigningKey(ctx, keyRef, node, publicKey); err != nil {
		return result, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO federation_node_certificates_v1(certificate_ref,node_id,signing_key_ref,leaf_fingerprint_sha256,certificate_pem,not_before,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`, result.EvidenceKeyID, node, keyRef, actualFingerprint, certificatePEM, leaf.NotBefore.UTC(), leaf.NotAfter.UTC(), now)
	if err != nil {
		return result, err
	}
	update, err := tx.ExecContext(ctx, `UPDATE federation_peers SET node_certificate_ref=?,updated_at=? WHERE id=? AND state='active' AND node_certificate_ref=?`, result.EvidenceKeyID, now, peer, previousRef)
	if err != nil {
		return result, err
	}
	if affected, rowsErr := update.RowsAffected(); rowsErr != nil || affected != 1 {
		return result, federation.ErrStale
	}
	_, err = tx.ExecContext(ctx, `UPDATE federation_certificate_rotations_v1 SET state='applied',response_json=?,updated_at=? WHERE idempotency_key=? AND state='prepared'`, canonical, now, id)
	if err != nil {
		return result, err
	}
	payload, _ := json.Marshal(map[string]any{"peer_id": peer, "previous_certificate_fingerprint_sha256": previousFingerprint, "certificate_fingerprint_sha256": actualFingerprint, "generation": result.Generation})
	payloadDigest := sha256.Sum256(payload)
	event := federation.NodeEvent{ID: federation.ID("rotation_"+actualFingerprint[:48]), NodeID: node, Priority: federation.PrioritySecurity, Kind: "federation.node.certificate.rotated", Generation: result.Generation, Payload: payload, PayloadDigest: hex.EncodeToString(payloadDigest[:]), OccurredAt: now}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return result, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO federation_events(id,priority,kind,payload_json,payload_bytes,occurred_at) VALUES(?,?,?,?,?,?)`, event.ID, event.Priority, event.Kind, eventJSON, len(eventJSON), now)
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func verifyStagedFederationSigningKey(ctx context.Context, keyRef string, node federation.ID, publicKey []byte) error {
	reference, err := decodeFederationProtectedKeyReference(keyRef)
	if err != nil || reference.Audience.ResourceID.String() != node.String() || reference.Audience.Account != "node-signing" {
		return federation.ErrForbidden
	}
	client, err := secrets.NewLocalMaterialClient()
	if err != nil {
		return err
	}
	material, err := client.Read(ctx, secrets.MaterialRequest{SecretID: reference.ID, OwnerTenantID: reference.OwnerTenantID, Purpose: secrets.PurposeFederation, Operation: secrets.OperationSign, AdapterID: reference.Audience.AdapterID, AdapterVersion: reference.Audience.AdapterVersion, ResourceID: reference.Audience.ResourceID})
	if err != nil {
		return err
	}
	defer wipeFederationEnrollmentBytes(material.Material)
	if material.SecretID != reference.ID || material.SecretVersion != reference.Version || material.BindingDigest != reference.ExpectedBindingDigest {
		return federation.ErrForbidden
	}
	parsed, err := x509.ParsePKCS8PrivateKey(material.Material)
	if err != nil {
		return federation.ErrForbidden
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return federation.ErrForbidden
	}
	defer wipeFederationEnrollmentBytes(private)
	if len(private) != ed25519.PrivateKeySize || subtle.ConstantTimeCompare(private.Public().(ed25519.PublicKey), publicKey) != 1 {
		return federation.ErrForbidden
	}
	return nil
}
