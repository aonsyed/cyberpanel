//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
	"github.com/aonsyed/cyberpanel/platform/internal/federation"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const (
	federationEnrollmentProtocolVersion    uint32 = 1
	federationEnrollmentMaximumRequest            = 32 << 10
	federationEnrollmentMaximumResponse           = 256 << 10
	federationEnrollmentMaximumCertificate        = 128 << 10
	federationEnrollmentMaximumChain              = 8
	federationEnrollmentMaximumSigningKeys        = 16
	federationEnrollmentMaximumCertificateTTL     = 24 * time.Hour
	federationEnrollmentKeyReferencePrefix         = "federation-key-v1."
)

const federationNodeCertificateSchema = `
CREATE TABLE IF NOT EXISTS federation_node_certificates_v1(
 certificate_ref TEXT PRIMARY KEY,
 node_id TEXT NOT NULL,
 signing_key_ref TEXT NOT NULL,
 leaf_fingerprint_sha256 TEXT NOT NULL UNIQUE,
 certificate_pem BLOB NOT NULL,
 not_before TIMESTAMP NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS federation_node_certificates_node_created_v1
 ON federation_node_certificates_v1(node_id,created_at);
`

type federationEnrollmentMaterialState struct {
	caFingerprint  string
	signingPublic  []byte
	signingRef     string
	hpkeRef        string
	certificateRef string
}

type federationProtectedKeyReference struct {
	ID                    secrets.ID              `json:"id"`
	OwnerTenantID         secrets.ID              `json:"owner_tenant_id"`
	Audience              secrets.AudienceBinding `json:"audience"`
	Version               uint64                  `json:"version"`
	ExpectedBindingDigest string                  `json:"expected_binding_digest"`
}

// federationEnrollmentMaterials is the integration boundary shared by the
// existing federation NodeKeyStore and CertificateStore contracts. Private
// bytes cross only the local secret-management socket; control.db stores
// public certificate material and opaque protected-key references.
type federationEnrollmentMaterials struct {
	db                    *sql.DB
	management            *secrets.ManagementClient
	consumerReleaseDigest string
	now                   func() time.Time
	mutex                 sync.Mutex
	pending               map[federation.ID]*federationEnrollmentMaterialState
}

func newFederationEnrollmentMaterials(ctx context.Context, db *sql.DB, now func() time.Time) (*federationEnrollmentMaterials, string, error) {
	if ctx == nil || db == nil {
		return nil, "", federation.ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	management, err := secrets.NewLocalManagementClient()
	if err != nil {
		return nil, "", err
	}
	releaseDigest, err := certificates.CurrentExecutableDigest()
	if err != nil {
		return nil, "", err
	}
	materials := &federationEnrollmentMaterials{db: db, management: management, consumerReleaseDigest: releaseDigest, now: now, pending: map[federation.ID]*federationEnrollmentMaterialState{}}
	if _, err = db.ExecContext(ctx, federationNodeCertificateSchema); err != nil {
		return nil, "", err
	}
	return materials, releaseDigest, nil
}

func (materials *federationEnrollmentMaterials) begin(node federation.ID, caFingerprint string) error {
	if materials == nil || materials.db == nil || materials.management == nil || !node.Valid() || !validFederationEnrollmentDigest(caFingerprint) {
		return federation.ErrInvalid
	}
	materials.mutex.Lock()
	defer materials.mutex.Unlock()
	if _, exists := materials.pending[node]; exists {
		return federation.ErrConflict
	}
	materials.pending[node] = &federationEnrollmentMaterialState{caFingerprint: strings.ToLower(caFingerprint)}
	return nil
}

func (materials *federationEnrollmentMaterials) finish(node federation.ID) {
	if materials == nil {
		return
	}
	materials.mutex.Lock()
	delete(materials.pending, node)
	materials.mutex.Unlock()
}

func (materials *federationEnrollmentMaterials) cleanup(ctx context.Context, node federation.ID) error {
	if materials == nil || ctx == nil {
		return federation.ErrInvalid
	}
	materials.mutex.Lock()
	state := materials.pending[node]
	delete(materials.pending, node)
	materials.mutex.Unlock()
	if state == nil {
		return nil
	}
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var failures []error
	if state.certificateRef != "" {
		if _, err := materials.db.ExecContext(cleanupContext, `DELETE FROM federation_node_certificates_v1 WHERE certificate_ref=? AND node_id=?`, state.certificateRef, node); err != nil {
			failures = append(failures, err)
		}
	}
	for _, reference := range []string{state.signingRef, state.hpkeRef} {
		if reference == "" {
			continue
		}
		if err := materials.revoke(cleanupContext, reference); err != nil && !errors.Is(err, secrets.ErrRevoked) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (materials *federationEnrollmentMaterials) CreateSigningIdentity(ctx context.Context, node federation.ID) ([]byte, string, error) {
	if materials == nil || ctx == nil || !node.Valid() {
		return nil, "", federation.ErrInvalid
	}
	materials.mutex.Lock()
	defer materials.mutex.Unlock()
	state := materials.pending[node]
	if state == nil || state.signingRef != "" {
		return nil, "", federation.ErrConflict
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	defer wipeFederationEnrollmentBytes(privateKey)
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, "", err
	}
	defer wipeFederationEnrollmentBytes(encoded)
	reference, err := materials.storeKey(ctx, node, "node-signing", []secrets.Operation{secrets.OperationSign}, encoded)
	if err != nil {
		return nil, "", err
	}
	state.signingPublic = append([]byte(nil), publicKey...)
	state.signingRef = reference
	return append([]byte(nil), publicKey...), reference, nil
}

func (materials *federationEnrollmentMaterials) CreateHPKEIdentity(ctx context.Context, node federation.ID) ([]byte, string, error) {
	if materials == nil || ctx == nil || !node.Valid() {
		return nil, "", federation.ErrInvalid
	}
	materials.mutex.Lock()
	defer materials.mutex.Unlock()
	state := materials.pending[node]
	if state == nil || state.signingRef == "" || state.hpkeRef != "" {
		return nil, "", federation.ErrConflict
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, "", err
	}
	defer wipeFederationEnrollmentBytes(encoded)
	reference, err := materials.storeKey(ctx, node, "node-hpke", []secrets.Operation{secrets.OperationDecrypt}, encoded)
	if err != nil {
		return nil, "", err
	}
	state.hpkeRef = reference
	return append([]byte(nil), privateKey.PublicKey().Bytes()...), reference, nil
}

func (materials *federationEnrollmentMaterials) Destroy(ctx context.Context, reference string) error {
	if materials == nil || ctx == nil {
		return federation.ErrInvalid
	}
	return materials.revoke(ctx, reference)
}

func (materials *federationEnrollmentMaterials) StoreNodeCertificate(ctx context.Context, node federation.ID, certificatePEM []byte, expiresAt time.Time) (string, error) {
	if materials == nil || ctx == nil || !node.Valid() || expiresAt.IsZero() {
		return "", federation.ErrInvalid
	}
	materials.mutex.Lock()
	defer materials.mutex.Unlock()
	state := materials.pending[node]
	if state == nil || state.signingRef == "" || state.hpkeRef == "" || len(state.signingPublic) != ed25519.PublicKeySize || state.certificateRef != "" {
		return "", federation.ErrConflict
	}
	chain, canonicalPEM, err := parseFederationNodeCertificate(certificatePEM)
	if err != nil {
		return "", err
	}
	now := materials.now().UTC()
	leaf := chain[0]
	if !expiresAt.Equal(leaf.NotAfter.UTC()) || !expiresAt.After(now) || expiresAt.After(now.Add(federationEnrollmentMaximumCertificateTTL)) || leaf.NotBefore.After(now) || leaf.NotAfter.Sub(leaf.NotBefore) > federationEnrollmentMaximumCertificateTTL+5*time.Minute || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !certificateAllowsClientAuthentication(leaf) {
		return "", federation.ErrForbidden
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || subtle.ConstantTimeCompare(publicKey, state.signingPublic) != 1 {
		return "", federation.ErrForbidden
	}
	if err = verifyFederationCertificateChain(chain, "", state.caFingerprint, now, x509.ExtKeyUsageClientAuth); err != nil {
		return "", err
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	reference := "fedcert_" + hex.EncodeToString(fingerprint[:])[:48]
	if _, err = materials.db.ExecContext(ctx, `INSERT INTO federation_node_certificates_v1(certificate_ref,node_id,signing_key_ref,leaf_fingerprint_sha256,certificate_pem,not_before,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`, reference, node, state.signingRef, hex.EncodeToString(fingerprint[:]), canonicalPEM, leaf.NotBefore.UTC(), leaf.NotAfter.UTC(), now); err != nil {
		return "", err
	}
	state.certificateRef = reference
	return reference, nil
}

func (materials *federationEnrollmentMaterials) storeKey(ctx context.Context, node federation.ID, account string, operations []secrets.Operation, encoded []byte) (string, error) {
	identifier, err := newFederationProtectedKeyID(account)
	if err != nil {
		return "", err
	}
	resourceID, err := secrets.NewID(node.String())
	if err != nil {
		return "", err
	}
	audience := secrets.AudienceBinding{
		AdapterID: "cyberpanel.federation", AdapterVersion: "1", Account: account,
		Origin: "local://panel-core/federation", ResourceKind: "federation_node_identity",
		ResourceID: resourceID, ResourceGeneration: 1, Operations: operations,
		ConsumerReleaseDigest: materials.consumerReleaseDigest,
	}
	metadata, err := materials.management.Put(ctx, secrets.PutRequest{ID: identifier, OwnerTenantID: secrets.ID("installation"), Purpose: secrets.PurposeFederation, Audience: audience, Plaintext: encoded})
	if err != nil {
		return "", err
	}
	return encodeFederationProtectedKeyReference(federationProtectedKeyReference{ID: metadata.ID, OwnerTenantID: metadata.OwnerTenantID, Audience: metadata.Audience, Version: metadata.Version, ExpectedBindingDigest: metadata.BindingDigest})
}

func (materials *federationEnrollmentMaterials) revoke(ctx context.Context, encodedReference string) error {
	reference, err := decodeFederationProtectedKeyReference(encodedReference)
	if err != nil {
		return err
	}
	_, err = materials.management.Revoke(ctx, secrets.RevokeRequest{ID: reference.ID, OwnerTenantID: reference.OwnerTenantID, Purpose: secrets.PurposeFederation, Audience: reference.Audience, ExpectedVersion: reference.Version, ExpectedBindingDigest: reference.ExpectedBindingDigest})
	return err
}

func newFederationProtectedKeyID(account string) (secrets.ID, error) {
	random := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}
	prefix := "fedsign_"
	if account == "node-hpke" {
		prefix = "fedhpke_"
	}
	return secrets.NewID(prefix + hex.EncodeToString(random))
}

func encodeFederationProtectedKeyReference(reference federationProtectedKeyReference) (string, error) {
	if validateFederationProtectedKeyReference(reference) != nil {
		return "", federation.ErrInvalid
	}
	encoded, err := json.Marshal(reference)
	if err != nil {
		return "", err
	}
	return federationEnrollmentKeyReferencePrefix + base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeFederationProtectedKeyReference(value string) (federationProtectedKeyReference, error) {
	var reference federationProtectedKeyReference
	if !strings.HasPrefix(value, federationEnrollmentKeyReferencePrefix) || len(value) > 4096 {
		return reference, federation.ErrInvalid
	}
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, federationEnrollmentKeyReferencePrefix))
	if err != nil || len(encoded) == 0 || len(encoded) > 2048 {
		return reference, federation.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&reference); err != nil || decoder.Decode(&struct{}{}) != io.EOF || validateFederationProtectedKeyReference(reference) != nil {
		return federationProtectedKeyReference{}, federation.ErrInvalid
	}
	return reference, nil
}

func validateFederationProtectedKeyReference(reference federationProtectedKeyReference) error {
	signingAccount := reference.Audience.Account == "node-signing" && len(reference.Audience.Operations) == 1 && reference.Audience.Operations[0] == secrets.OperationSign
	hpkeAccount := reference.Audience.Account == "node-hpke" && len(reference.Audience.Operations) == 1 && reference.Audience.Operations[0] == secrets.OperationDecrypt
	accountValid := signingAccount || hpkeAccount
	if !reference.ID.Valid() || reference.OwnerTenantID.String() != "installation" || reference.Audience.Validate() != nil || reference.Audience.AdapterID != "cyberpanel.federation" || reference.Audience.AdapterVersion != "1" || reference.Audience.Origin != "local://panel-core/federation" || reference.Audience.ResourceKind != "federation_node_identity" || reference.Audience.ResourceGeneration != 1 || !validFederationEnrollmentDigest(reference.Audience.ConsumerReleaseDigest) || !accountValid || reference.Version == 0 || !validFederationEnrollmentDigest(reference.ExpectedBindingDigest) {
		return federation.ErrInvalid
	}
	return nil
}

type federationEnrollmentHTTPExchange struct {
	endpoint      string
	peer          federation.ID
	caFingerprint string
	now           func() time.Time
}

func newFederationEnrollmentHTTPExchange(endpoint string, peer federation.ID, caFingerprint string, now func() time.Time) (*federationEnrollmentHTTPExchange, error) {
	normalized, err := normalizedFederationEndpoint(endpoint)
	if err != nil || normalized != endpoint || !peer.Valid() || !validFederationEnrollmentDigest(caFingerprint) {
		return nil, federation.ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &federationEnrollmentHTTPExchange{endpoint: endpoint, peer: peer, caFingerprint: strings.ToLower(caFingerprint), now: now}, nil
}

func (exchange *federationEnrollmentHTTPExchange) Enroll(ctx context.Context, request federation.EnrollmentRequest) (federation.EnrollmentResponse, error) {
	if exchange == nil || ctx == nil || !request.TokenID.Valid() || !request.NodeID.Valid() || len(request.Token) < 32 || len(request.Token) > 4096 || len(request.SigningPublicKey) != ed25519.PublicKeySize || len(request.HPKEPublicKey) != 32 || !validFederationEnrollmentDigest(request.CapabilityDigest) || subtle.ConstantTimeCompare([]byte(strings.ToLower(request.CAFingerprint)), []byte(exchange.caFingerprint)) != 1 {
		return federation.EnrollmentResponse{}, federation.ErrInvalid
	}
	payload := struct {
		ProtocolVersion   uint32        `json:"protocol_version"`
		TokenID          federation.ID `json:"token_id"`
		Token            []byte        `json:"token"`
		NodeID           federation.ID `json:"node_id"`
		PeerID           federation.ID `json:"peer_id"`
		SigningPublicKey []byte        `json:"signing_public_key"`
		HPKEPublicKey    []byte        `json:"hpke_public_key"`
		CapabilityDigest string        `json:"capability_digest"`
		CAFingerprint    string        `json:"ca_fingerprint"`
	}{
		ProtocolVersion: federationEnrollmentProtocolVersion,
		TokenID: request.TokenID, Token: request.Token, NodeID: request.NodeID, PeerID: exchange.peer,
		SigningPublicKey: request.SigningPublicKey, HPKEPublicKey: request.HPKEPublicKey,
		CapabilityDigest: request.CapabilityDigest, CAFingerprint: exchange.caFingerprint,
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) == 0 || len(encoded) > federationEnrollmentMaximumRequest {
		wipeFederationEnrollmentBytes(encoded)
		return federation.EnrollmentResponse{}, federation.ErrInvalid
	}
	defer wipeFederationEnrollmentBytes(encoded)
	parsedEndpoint, err := url.Parse(exchange.endpoint)
	if err != nil {
		return federation.EnrollmentResponse{}, federation.ErrInvalid
	}
	transport, err := newFederationPinnedEnrollmentTransport(parsedEndpoint, exchange.caFingerprint, exchange.now)
	if err != nil {
		return federation.EnrollmentResponse{}, err
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, exchange.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return federation.EnrollmentResponse{}, err
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(httpRequest)
	if err != nil {
		return federation.EnrollmentResponse{}, errors.Join(federation.ErrOffline, err)
	}
	defer response.Body.Close()
	if response.ContentLength > federationEnrollmentMaximumResponse {
		return federation.EnrollmentResponse{}, federation.ErrInvalid
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, federationEnrollmentMaximumResponse+1))
	if readErr != nil || len(body) > federationEnrollmentMaximumResponse {
		return federation.EnrollmentResponse{}, federation.ErrInvalid
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return federation.EnrollmentResponse{}, federationEnrollmentStatusError(response.StatusCode)
	}
	contentType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || contentType != "application/json" {
		return federation.EnrollmentResponse{}, federation.ErrInvalid
	}
	var result struct {
		ProtocolVersion       uint32            `json:"protocol_version"`
		NodeID                federation.ID     `json:"node_id"`
		PeerID                federation.ID     `json:"peer_id"`
		PeerSigningKeys      map[string]federation.SigningKeyTrust `json:"peer_signing_keys"`
		NodeCertificate      []byte            `json:"node_certificate"`
		CertificateExpiresAt time.Time         `json:"certificate_expires_at"`
		AuthorityEpoch       uint64            `json:"authority_epoch"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return federation.EnrollmentResponse{}, federation.ErrInvalid
	}
	now := exchange.now().UTC()
	if result.ProtocolVersion != federationEnrollmentProtocolVersion || result.NodeID != request.NodeID || result.PeerID != exchange.peer || result.AuthorityEpoch == 0 || len(result.PeerSigningKeys) == 0 || len(result.PeerSigningKeys) > federationEnrollmentMaximumSigningKeys || len(result.NodeCertificate) == 0 || len(result.NodeCertificate) > federationEnrollmentMaximumCertificate || result.CertificateExpiresAt.IsZero() || !result.CertificateExpiresAt.After(now) || result.CertificateExpiresAt.After(now.Add(federationEnrollmentMaximumCertificateTTL)) {
		return federation.EnrollmentResponse{}, federation.ErrForbidden
	}
	for identifier, key := range result.PeerSigningKeys {
		if _, keyErr := federation.NewID(identifier); keyErr != nil || key.ID != identifier || key.Validate() != nil {
			return federation.EnrollmentResponse{}, federation.ErrForbidden
		}
	}
	return federation.EnrollmentResponse{PeerID: result.PeerID, PeerSigningKeys: result.PeerSigningKeys, NodeCertificate: result.NodeCertificate, CertificateExpiresAt: result.CertificateExpiresAt, AuthorityEpoch: result.AuthorityEpoch}, nil
}

func newFederationPinnedEnrollmentTransport(endpoint *url.URL, fingerprint string, now func() time.Time) (*http.Transport, error) {
	if endpoint == nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || !validFederationEnrollmentDigest(fingerprint) || now == nil {
		return nil, federation.ErrInvalid
	}
	serverName := endpoint.Hostname()
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		// Enrollment bootstraps a private central CA from its independently
		// verified fingerprint, so normal roots are replaced by the pinned CA
		// and the complete server chain is verified below.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyFederationCertificateChain(state.PeerCertificates, serverName, fingerprint, now().UTC(), x509.ExtKeyUsageServerAuth)
		},
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		DisableCompression: true, DisableKeepAlives: true,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 32 << 10,
		TLSClientConfig: tlsConfig,
	}, nil
}

func parseFederationNodeCertificate(content []byte) ([]*x509.Certificate, []byte, error) {
	if len(content) == 0 || len(content) > federationEnrollmentMaximumCertificate {
		return nil, nil, federation.ErrInvalid
	}
	remaining := content
	chain := make([]*x509.Certificate, 0, 3)
	canonical := make([]byte, 0, len(content))
	for len(bytes.TrimSpace(remaining)) != 0 {
		remaining = bytes.TrimSpace(remaining)
		if len(chain) >= federationEnrollmentMaximumChain {
			return nil, nil, federation.ErrInvalid
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, nil, federation.ErrInvalid
		}
		block, next := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(next) >= len(remaining) {
			return nil, nil, federation.ErrInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, federation.ErrInvalid
		}
		chain = append(chain, certificate)
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
		remaining = next
	}
	if len(chain) < 2 {
		return nil, nil, federation.ErrInvalid
	}
	return chain, canonical, nil
}

func verifyFederationCertificateChain(chain []*x509.Certificate, serverName, fingerprint string, now time.Time, usage x509.ExtKeyUsage) error {
	if len(chain) < 2 || !validFederationEnrollmentDigest(fingerprint) || now.IsZero() {
		return federation.ErrForbidden
	}
	expected, err := hex.DecodeString(fingerprint)
	if err != nil {
		return federation.ErrForbidden
	}
	var anchor *x509.Certificate
	for _, certificate := range chain[1:] {
		digest := sha256.Sum256(certificate.Raw)
		if certificate.IsCA && subtle.ConstantTimeCompare(digest[:], expected) == 1 {
			anchor = certificate
			break
		}
	}
	if anchor == nil {
		return federation.ErrForbidden
	}
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		if certificate != anchor {
			intermediates.AddCert(certificate)
		}
	}
	_, err = chain[0].Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
	if err != nil {
		return federation.ErrForbidden
	}
	return nil
}

func certificateAllowsClientAuthentication(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func federationEnrollmentStatusError(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return federation.ErrForbidden
	case status == http.StatusConflict:
		return federation.ErrConflict
	case status == http.StatusGone:
		return federation.ErrExpired
	case status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500:
		return federation.ErrOffline
	default:
		return federation.ErrInvalid
	}
}

func validFederationEnrollmentDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func wipeFederationEnrollmentBytes(values ...[]byte) {
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
	}
}

var _ federation.NodeKeyStore = (*federationEnrollmentMaterials)(nil)
var _ federation.CertificateStore = (*federationEnrollmentMaterials)(nil)
var _ federation.EnrollmentExchange = (*federationEnrollmentHTTPExchange)(nil)
