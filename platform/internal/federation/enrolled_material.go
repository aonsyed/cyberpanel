package federation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
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
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const enrolledKeyReferencePrefix = "federation-key-v1."

type FederationSecretMaterial interface {
	Read(context.Context, secrets.MaterialRequest) (secrets.MaterialResponse, error)
}

type EnrolledMaterialLoader struct {
	Store    *Store
	Material FederationSecretMaterial
	Now      func() time.Time
}

type NodeEvidenceSigner interface {
	ReceiptSigner
	EventSigner
}

type EnrolledRunnerMaterial struct {
	NodeID    ID
	PeerID    ID
	Endpoint  string
	Connector Connector
	Signer    NodeEvidenceSigner
	store     *Store
}

func (loader EnrolledMaterialLoader) Load(ctx context.Context, peerID ID) (*EnrolledRunnerMaterial, error) {
	if ctx == nil || loader.Store == nil || loader.Store.db == nil || loader.Material == nil || !peerID.Valid() {
		return nil, ErrInvalid
	}
	now := time.Now().UTC()
	if loader.Now != nil {
		now = loader.Now().UTC()
	}
	nodeID, _, activePeer, err := loader.Store.State(ctx)
	if err != nil {
		return nil, err
	}
	peer, err := loader.Store.Peer(ctx, peerID)
	if err != nil {
		return nil, err
	}
	if activePeer != peerID || peer.State != "active" || !validSHA256Value(peer.CAFingerprint) || peer.NodeCertificateRef == "" {
		return nil, ErrForbidden
	}
	endpoint, err := loadEnrolledEndpoint(ctx, loader.Store.db, nodeID, peer)
	if err != nil {
		return nil, err
	}
	parsed, address, err := enrolledRunnerEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	certificate, roots, keyReference, keyID, err := loadEnrolledCertificate(ctx, loader.Store.db, nodeID, peer, now)
	if err != nil {
		return nil, err
	}
	reference, err := decodeEnrolledKeyReference(keyReference, nodeID)
	if err != nil {
		return nil, err
	}
	publicKey, ok := certificate.Leaf.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrForbidden
	}
	signer := &protectedNodeSigner{material: loader.Material, reference: reference, publicKey: append(ed25519.PublicKey(nil), publicKey...), keyID: keyID}
	privateKey, err := signer.privateKey(ctx)
	if err != nil {
		return nil, err
	}
	wipeFederationMaterial(privateKey)
	certificate.PrivateKey = signer
	serverName := parsed.Hostname()
	tlsConfiguration := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, Certificates: []tls.Certificate{certificate}}
	tlsConfiguration.VerifyConnection = func(state tls.ConnectionState) error {
		if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.ServerName != serverName || len(state.PeerCertificates) == 0 || !chainEndsAtFingerprint(state.VerifiedChains, peer.CAFingerprint) {
			return ErrForbidden
		}
		return nil
	}
	connector := &TLSConnector{Address: address, ServerName: serverName, TLSConfig: tlsConfiguration, Dialer: net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}, MaxFrame: MaxFrameBytes}
	return &EnrolledRunnerMaterial{NodeID: nodeID, PeerID: peerID, Endpoint: endpoint, Connector: connector, Signer: signer, store: loader.Store}, nil
}

func (material *EnrolledRunnerMaterial) NewAgent(schemas SchemaRegistry, authority AuthorityVerifier, policy LocalPolicy, gateway CommandGateway) (*Agent, error) {
	if material == nil || material.store == nil || material.Signer == nil {
		return nil, ErrInvalid
	}
	return NewAgent(material.store, schemas, authority, policy, gateway, material.Signer)
}

func (material *EnrolledRunnerMaterial) NewRunner(agent *Agent, capabilities func(context.Context) (CapabilitySet, error)) (*OutboundRunner, error) {
	if material == nil || material.store == nil || material.Connector == nil || material.Signer == nil || agent == nil || agent.store != material.store || capabilities == nil {
		return nil, ErrInvalid
	}
	core := &Runner{Agent: agent, Store: material.store, Connector: material.Connector, Capabilities: capabilities}
	return NewOutboundRunner(core, material.PeerID, material.Signer)
}

type enrolledProtectedKeyReference struct {
	ID                    secrets.ID              `json:"id"`
	OwnerTenantID         secrets.ID              `json:"owner_tenant_id"`
	Audience              secrets.AudienceBinding `json:"audience"`
	Version               uint64                  `json:"version"`
	ExpectedBindingDigest string                  `json:"expected_binding_digest"`
}

type protectedNodeSigner struct {
	material  FederationSecretMaterial
	reference enrolledProtectedKeyReference
	publicKey ed25519.PublicKey
	keyID     string
}

func (signer *protectedNodeSigner) Public() crypto.PublicKey {
	if signer == nil {
		return ed25519.PublicKey(nil)
	}
	return append(ed25519.PublicKey(nil), signer.publicKey...)
}

func (signer *protectedNodeSigner) Sign(_ io.Reader, message []byte, options crypto.SignerOpts) ([]byte, error) {
	if options == nil || options.HashFunc() != crypto.Hash(0) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return signer.sign(ctx, signer.keyID, message)
}

func (signer *protectedNodeSigner) ReceiptKeyID(ctx context.Context) (string, error) {
	return signer.key(ctx)
}

func (signer *protectedNodeSigner) SignReceipt(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	return signer.sign(ctx, keyID, message)
}

func (signer *protectedNodeSigner) EventKeyID(ctx context.Context) (string, error) {
	return signer.key(ctx)
}

func (signer *protectedNodeSigner) SignEvent(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	return signer.sign(ctx, keyID, message)
}

func (signer *protectedNodeSigner) key(ctx context.Context) (string, error) {
	if signer == nil || ctx == nil || signer.keyID == "" {
		return "", ErrInvalid
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
		return signer.keyID, nil
	}
}

func (signer *protectedNodeSigner) sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	if signer == nil || ctx == nil || keyID == "" || len(message) == 0 || len(message) > MaxFrameBytes || subtle.ConstantTimeCompare([]byte(keyID), []byte(signer.keyID)) != 1 {
		return nil, ErrInvalid
	}
	privateKey, err := signer.privateKey(ctx)
	if err != nil {
		return nil, err
	}
	defer wipeFederationMaterial(privateKey)
	return ed25519.Sign(privateKey, message), nil
}

func (signer *protectedNodeSigner) privateKey(ctx context.Context) (ed25519.PrivateKey, error) {
	if signer == nil || signer.material == nil || ctx == nil {
		return nil, ErrInvalid
	}
	reference := signer.reference
	response, err := signer.material.Read(ctx, secrets.MaterialRequest{SecretID: reference.ID, OwnerTenantID: reference.OwnerTenantID, Purpose: secrets.PurposeFederation, Operation: secrets.OperationSign, AdapterID: reference.Audience.AdapterID, AdapterVersion: reference.Audience.AdapterVersion, ResourceID: reference.Audience.ResourceID})
	if err != nil {
		return nil, errors.Join(ErrForbidden, err)
	}
	defer wipeFederationMaterial(response.Material)
	if response.SecretID != reference.ID || response.SecretVersion != reference.Version || subtle.ConstantTimeCompare([]byte(response.BindingDigest), []byte(reference.ExpectedBindingDigest)) != 1 || len(response.Material) == 0 || len(response.Material) > 1<<20 {
		return nil, ErrForbidden
	}
	parsed, err := x509.ParsePKCS8PrivateKey(response.Material)
	if err != nil {
		return nil, ErrForbidden
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize || subtle.ConstantTimeCompare(privateKey.Public().(ed25519.PublicKey), signer.publicKey) != 1 {
		wipeParsedFederationKey(parsed)
		return nil, ErrForbidden
	}
	result := append(ed25519.PrivateKey(nil), privateKey...)
	wipeParsedFederationKey(parsed)
	return result, nil
}

func enrolledRunnerEndpoint(endpoint string) (*url.URL, string, error) {
	trimmed := strings.TrimSpace(endpoint)
	parsed, err := url.Parse(trimmed)
	if err != nil || trimmed != endpoint || parsed.String() != endpoint || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, "", ErrInvalid
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return nil, "", ErrInvalid
	}
	return parsed, net.JoinHostPort(parsed.Hostname(), port), nil
}

func loadEnrolledEndpoint(ctx context.Context, db *sql.DB, nodeID ID, peer Peer) (string, error) {
	var raw []byte
	var consumedAt time.Time
	err := db.QueryRowContext(ctx, `SELECT token_json,consumed_at FROM federation_enrollment_tokens WHERE node_id=? AND peer_id=? AND state='consumed' ORDER BY consumed_at DESC,id DESC LIMIT 1`, nodeID, peer.ID).Scan(&raw, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	var token EnrollmentToken
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&token); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !token.ID.Valid() || token.NodeID != nodeID || token.PeerID != peer.ID || !validSHA256Value(token.TokenDigest) || !validSHA256Value(token.CAFingerprint) || subtle.ConstantTimeCompare([]byte(token.CAFingerprint), []byte(peer.CAFingerprint)) != 1 || consumedAt.IsZero() || token.ExpiresAt.IsZero() || !consumedAt.Before(token.ExpiresAt) {
		return "", ErrForbidden
	}
	if _, _, err = enrolledRunnerEndpoint(token.Endpoint); err != nil {
		return "", err
	}
	return token.Endpoint, nil
}

func loadEnrolledCertificate(ctx context.Context, db *sql.DB, nodeID ID, peer Peer, now time.Time) (tls.Certificate, *x509.CertPool, string, string, error) {
	var certificatePEM []byte
	var signingKeyReference, leafFingerprint string
	var notBefore, expiresAt time.Time
	err := db.QueryRowContext(ctx, `SELECT signing_key_ref,leaf_fingerprint_sha256,certificate_pem,not_before,expires_at FROM federation_node_certificates_v1 WHERE certificate_ref=? AND node_id=?`, peer.NodeCertificateRef, nodeID).Scan(&signingKeyReference, &leafFingerprint, &certificatePEM, &notBefore, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return tls.Certificate{}, nil, "", "", ErrNotFound
	}
	if err != nil {
		return tls.Certificate{}, nil, "", "", err
	}
	chain, err := parseEnrolledCertificateChain(certificatePEM)
	if err != nil {
		return tls.Certificate{}, nil, "", "", err
	}
	leaf := chain[0]
	leafSum := sha256.Sum256(leaf.Raw)
	actualFingerprint := hex.EncodeToString(leafSum[:])
	if !validSHA256Value(leafFingerprint) || subtle.ConstantTimeCompare([]byte(actualFingerprint), []byte(leafFingerprint)) != 1 || peer.NodeCertificateRef != "fedcert_"+actualFingerprint[:48] || !notBefore.UTC().Equal(leaf.NotBefore.UTC()) || !expiresAt.UTC().Equal(leaf.NotAfter.UTC()) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return tls.Certificate{}, nil, "", "", ErrForbidden
	}
	anchor := pinnedCertificateAuthority(chain[1:], peer.CAFingerprint)
	if anchor == nil {
		return tls.Certificate{}, nil, "", "", ErrForbidden
	}
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		if certificate != anchor {
			intermediates.AddCert(certificate)
		}
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return tls.Certificate{}, nil, "", "", ErrForbidden
	}
	encodedChain := make([][]byte, len(chain))
	for index, certificate := range chain {
		encodedChain[index] = append([]byte(nil), certificate.Raw...)
	}
	return tls.Certificate{Certificate: encodedChain, Leaf: leaf}, roots, signingKeyReference, peer.NodeCertificateRef, nil
}

func parseEnrolledCertificateChain(content []byte) ([]*x509.Certificate, error) {
	if len(content) == 0 || len(content) > 128<<10 {
		return nil, ErrInvalid
	}
	remaining := content
	chain := make([]*x509.Certificate, 0, 3)
	for len(bytes.TrimSpace(remaining)) != 0 {
		remaining = bytes.TrimSpace(remaining)
		if len(chain) >= 8 || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrInvalid
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) >= len(remaining) {
			return nil, ErrInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalid
		}
		chain = append(chain, certificate)
		remaining = rest
	}
	if len(chain) < 2 {
		return nil, ErrInvalid
	}
	return chain, nil
}

func decodeEnrolledKeyReference(value string, nodeID ID) (enrolledProtectedKeyReference, error) {
	var reference enrolledProtectedKeyReference
	if !strings.HasPrefix(value, enrolledKeyReferencePrefix) || len(value) > 4096 {
		return reference, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, enrolledKeyReferencePrefix))
	if err != nil || len(raw) == 0 || len(raw) > 2048 {
		return reference, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&reference); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return enrolledProtectedKeyReference{}, ErrInvalid
	}
	resourceID, resourceErr := secrets.NewID(nodeID.String())
	validAudience := reference.Audience.Validate() == nil && reference.Audience.AdapterID == "cyberpanel.federation" && reference.Audience.AdapterVersion == "1" && reference.Audience.Account == "node-signing" && reference.Audience.Origin == "local://panel-core/federation" && reference.Audience.ResourceKind == "federation_node_identity" && reference.Audience.ResourceID == resourceID && reference.Audience.ResourceGeneration == 1 && len(reference.Audience.Operations) == 1 && reference.Audience.Operations[0] == secrets.OperationSign && validSHA256Value(reference.Audience.ConsumerReleaseDigest)
	if resourceErr != nil || !reference.ID.Valid() || reference.OwnerTenantID.String() != "installation" || reference.Version == 0 || !validSHA256Value(reference.ExpectedBindingDigest) || !validAudience {
		return enrolledProtectedKeyReference{}, ErrForbidden
	}
	return reference, nil
}

func pinnedCertificateAuthority(chain []*x509.Certificate, fingerprint string) *x509.Certificate {
	if !validSHA256Value(fingerprint) {
		return nil
	}
	expected, _ := hex.DecodeString(fingerprint)
	for _, certificate := range chain {
		sum := sha256.Sum256(certificate.Raw)
		if certificate.IsCA && subtle.ConstantTimeCompare(sum[:], expected) == 1 {
			return certificate
		}
	}
	return nil
}

func chainEndsAtFingerprint(chains [][]*x509.Certificate, fingerprint string) bool {
	if !validSHA256Value(fingerprint) {
		return false
	}
	expected, _ := hex.DecodeString(fingerprint)
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		sum := sha256.Sum256(chain[len(chain)-1].Raw)
		if subtle.ConstantTimeCompare(sum[:], expected) == 1 {
			return true
		}
	}
	return false
}

func validSHA256Value(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func wipeParsedFederationKey(value any) {
	if key, ok := value.(ed25519.PrivateKey); ok {
		wipeFederationMaterial(key)
	}
}

func wipeFederationMaterial(values ...[]byte) {
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
	}
}

var _ crypto.Signer = (*protectedNodeSigner)(nil)
var _ NodeEvidenceSigner = (*protectedNodeSigner)(nil)
