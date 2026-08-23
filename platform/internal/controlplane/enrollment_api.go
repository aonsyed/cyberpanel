package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

const (
	enrollmentHTTPPath              = "/v1/federation/enroll"
	enrollmentProtocolVersion       = uint32(1)
	enrollmentMaximumRequestBytes   = int64(32 << 10)
	enrollmentMaximumResponseBytes  = 256 << 10
	enrollmentMaximumCertificatePEM = 128 << 10
)

type IssuedEnrollmentCertificate struct {
	PEM         []byte
	Fingerprint string
	NotBefore   time.Time
	ExpiresAt   time.Time
}

type EnrollmentIssuer struct {
	ca                *x509.Certificate
	caPEM             []byte
	privateKey        ed25519.PrivateKey
	peer              federation.ID
	peerSigningKeys   map[string][]byte
	certificateTTL    time.Duration
	clock             func() time.Time
}

func NewEnrollmentIssuer(caPEM, privateKey []byte, expectedFingerprint string, peer federation.ID, peerSigningKeys map[string][]byte, certificateTTL time.Duration) (*EnrollmentIssuer, error) {
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || len(privateKey) != ed25519.PrivateKeySize || !validSHA256(expectedFingerprint) || !peer.Valid() || len(peerSigningKeys) == 0 || len(peerSigningKeys) > 16 || certificateTTL < 5*time.Minute || certificateTTL > 23*time.Hour {
		return nil, ErrInvalid
	}
	now := time.Now().UTC()
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return nil, ErrForbidden
	}
	fingerprint := sha256.Sum256(ca.Raw)
	expected, _ := hex.DecodeString(expectedFingerprint)
	caPublic, ok := ca.PublicKey.(ed25519.PublicKey)
	keyPublic, keyOK := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(fingerprint[:], expected) != 1 || !ok || !keyOK || subtle.ConstantTimeCompare(caPublic, keyPublic) != 1 {
		return nil, ErrForbidden
	}
	publicKeys := make(map[string][]byte, len(peerSigningKeys))
	for id, key := range peerSigningKeys {
		if _, keyErr := federation.NewID(id); keyErr != nil || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		publicKeys[id] = append([]byte(nil), key...)
	}
	return &EnrollmentIssuer{ca: ca, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), privateKey: append(ed25519.PrivateKey(nil), privateKey...), peer: peer, peerSigningKeys: publicKeys, certificateTTL: certificateTTL, clock: time.Now}, nil
}

func (issuer *EnrollmentIssuer) Close() {
	if issuer != nil {
		clear(issuer.privateKey)
	}
}

func (issuer *EnrollmentIssuer) PublicSigningKeys() map[string][]byte {
	keys := make(map[string][]byte, len(issuer.peerSigningKeys))
	for id, key := range issuer.peerSigningKeys {
		keys[id] = append([]byte(nil), key...)
	}
	return keys
}

func (issuer *EnrollmentIssuer) Issue(node federation.ID, signingPublicKey []byte) (IssuedEnrollmentCertificate, error) {
	var issued IssuedEnrollmentCertificate
	if issuer == nil || issuer.ca == nil || !node.Valid() || len(signingPublicKey) != ed25519.PublicKeySize || len(issuer.privateKey) != ed25519.PrivateKeySize {
		return issued, ErrInvalid
	}
	now := issuer.clock().UTC()
	expiresAt := now.Add(issuer.certificateTTL)
	if issuer.ca.NotAfter.Before(expiresAt) {
		expiresAt = issuer.ca.NotAfter.UTC()
	}
	if !expiresAt.After(now.Add(5 * time.Minute)) {
		return issued, ErrForbidden
	}
	serialBytes := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, serialBytes); err != nil {
		return issued, err
	}
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		return issued, ErrConflict
	}
	identity, err := url.Parse("urn:cyberpanel:federation:node:" + node.String())
	if err != nil {
		return issued, ErrInvalid
	}
	keyDigest := sha256.Sum256(signingPublicKey)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{CommonName: "cyberpanel-federation-node:" + node.String(), Organization: []string{"CyberPanel federation"}},
		NotBefore: now.Add(-time.Minute), NotAfter: expiresAt,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: false, URIs: []*url.URL{identity}, SubjectKeyId: append([]byte(nil), keyDigest[:20]...), AuthorityKeyId: append([]byte(nil), issuer.ca.SubjectKeyId...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.ca, ed25519.PublicKey(signingPublicKey), issuer.privateKey)
	if err != nil {
		return issued, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !allowsCertificateUsage(leaf, x509.ExtKeyUsageClientAuth) || len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity.String() {
		return issued, ErrForbidden
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer.ca)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return issued, ErrForbidden
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), issuer.caPEM...)
	if len(certificatePEM) == 0 || len(certificatePEM) > enrollmentMaximumCertificatePEM {
		return issued, ErrInvalid
	}
	return IssuedEnrollmentCertificate{PEM: certificatePEM, Fingerprint: hex.EncodeToString(fingerprint[:]), NotBefore: leaf.NotBefore.UTC(), ExpiresAt: leaf.NotAfter.UTC()}, nil
}

type EnrollmentAPI struct {
	store  *Store
	issuer *EnrollmentIssuer
}

func NewEnrollmentAPI(store *Store, issuer *EnrollmentIssuer) (*EnrollmentAPI, error) {
	if store == nil || store.db == nil || issuer == nil || issuer.ca == nil {
		return nil, ErrInvalid
	}
	return &EnrollmentAPI{store: store, issuer: issuer}, nil
}

func (api *EnrollmentAPI) Handler() http.Handler { return http.HandlerFunc(api.serveHTTP) }

func (api *EnrollmentAPI) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.Path != enrollmentHTTPPath || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		writeEnrollmentError(writer, http.StatusNotFound, "operation_not_found")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeEnrollmentError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 || request.Header.Get("Authorization") != "" {
		writeEnrollmentError(writer, http.StatusForbidden, "transport_rejected")
		return
	}
	var payload struct {
		ProtocolVersion   uint32        `json:"protocol_version"`
		TokenID          federation.ID `json:"token_id"`
		Token            []byte        `json:"token"`
		NodeID           federation.ID `json:"node_id"`
		PeerID           federation.ID `json:"peer_id"`
		SigningPublicKey []byte        `json:"signing_public_key"`
		HPKEPublicKey    []byte        `json:"hpke_public_key"`
		CapabilityDigest string        `json:"capability_digest"`
		CAFingerprint    string        `json:"ca_fingerprint"`
	}
	if err := decodeEnrollmentRequest(request, &payload); err != nil || payload.ProtocolVersion != enrollmentProtocolVersion || len(payload.Token) < 32 || len(payload.Token) > 4096 {
		clear(payload.Token)
		writeEnrollmentError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	defer clear(payload.Token)
	tokenDigest := sha256.Sum256(payload.Token)
	attempt := EnrollmentAttempt{TokenID: payload.TokenID, TokenDigest: hex.EncodeToString(tokenDigest[:]), NodeID: payload.NodeID, PeerID: payload.PeerID, CAFingerprint: payload.CAFingerprint, CapabilityDigest: payload.CapabilityDigest, SigningPublicKey: payload.SigningPublicKey, HPKEPublicKey: payload.HPKEPublicKey}
	enrollment, err := api.store.ConsumeEnrollmentToken(request.Context(), attempt)
	if err != nil {
		writeEnrollmentFailure(writer, err)
		return
	}
	issued, err := api.issuer.Issue(payload.NodeID, payload.SigningPublicKey)
	if err != nil {
		_ = api.store.RecordEnrollmentResult(request.Context(), payload.TokenID, "issuance_failed", "")
		writeEnrollmentFailure(writer, err)
		return
	}
	enrollment.Node.CertificateFingerprint = issued.Fingerprint
	enrollment.Node.State = NodeEnrolling
	enrollment.EvidenceKeys = []NodeEvidenceKey{{KeyID: "fedcert_" + issued.Fingerprint[:48], PublicKey: append([]byte(nil), payload.SigningPublicKey...), State: "current", NotBefore: issued.NotBefore, ExpiresAt: issued.ExpiresAt}}
	if err = api.store.ProvisionEnrollment(request.Context(), enrollment); err != nil {
		_ = api.store.RecordEnrollmentResult(request.Context(), payload.TokenID, "persistence_failed", "")
		writeEnrollmentFailure(writer, err)
		return
	}
	if err = api.store.RecordEnrollmentResult(request.Context(), payload.TokenID, "issued", issued.Fingerprint); err != nil {
		writeEnrollmentFailure(writer, err)
		return
	}
	writeEnrollmentJSON(writer, http.StatusCreated, struct {
		ProtocolVersion       uint32            `json:"protocol_version"`
		NodeID                federation.ID     `json:"node_id"`
		PeerID                federation.ID     `json:"peer_id"`
		PeerSigningKeys       map[string][]byte `json:"peer_signing_keys"`
		NodeCertificate       []byte            `json:"node_certificate"`
		CertificateExpiresAt time.Time         `json:"certificate_expires_at"`
		AuthorityEpoch       uint64            `json:"authority_epoch"`
	}{enrollmentProtocolVersion, payload.NodeID, api.issuer.peer, api.issuer.PublicSigningKeys(), issued.PEM, issued.ExpiresAt, enrollment.Node.AuthorityEpoch})
}

func decodeEnrollmentRequest(request *http.Request, target any) error {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 || request.ContentLength <= 0 || request.ContentLength > enrollmentMaximumRequestBytes || len(request.TransferEncoding) != 0 {
		return ErrInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, enrollmentMaximumRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func writeEnrollmentJSON(writer http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > enrollmentMaximumResponseBytes {
		writeEnrollmentError(writer, http.StatusInternalServerError, "response_unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func writeEnrollmentError(writer http.ResponseWriter, status int, code string) {
	encoded, _ := json.Marshal(struct{ Code string `json:"code"` }{code})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func writeEnrollmentFailure(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		writeEnrollmentError(writer, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrForbidden):
		writeEnrollmentError(writer, http.StatusForbidden, "forbidden")
	case errors.Is(err, federation.ErrExpired):
		writeEnrollmentError(writer, http.StatusGone, "expired")
	case errors.Is(err, federation.ErrReplay), errors.Is(err, ErrConflict), errors.Is(err, ErrStale):
		writeEnrollmentError(writer, http.StatusConflict, "replay_or_conflict")
	case errors.Is(err, context.DeadlineExceeded):
		writeEnrollmentError(writer, http.StatusGatewayTimeout, "deadline_exceeded")
	default:
		writeEnrollmentError(writer, http.StatusInternalServerError, "internal_error")
	}
}

type EnrollmentServer struct {
	API                *EnrollmentAPI
	TLSConfig          *tls.Config
	MaximumConnections uint32
	ShutdownTimeout    time.Duration
}

func NewEnrollmentServer(api *EnrollmentAPI, tlsConfig *tls.Config, maximumConnections uint32, shutdownTimeout time.Duration) (*EnrollmentServer, error) {
	if api == nil || tlsConfig == nil || maximumConnections == 0 || maximumConnections > 4096 || shutdownTimeout < time.Second || shutdownTimeout > 2*time.Minute {
		return nil, ErrInvalid
	}
	configured := tlsConfig.Clone()
	configured.MinVersion = tls.VersionTLS13
	configured.MaxVersion = tls.VersionTLS13
	configured.ClientAuth = tls.NoClientCert
	configured.ClientCAs = nil
	configured.VerifyConnection = nil
	configured.SessionTicketsDisabled = true
	if validateEnrollmentServerIdentity(configured, api.issuer.ca, api.issuer.clock().UTC()) != nil {
		return nil, ErrForbidden
	}
	return &EnrollmentServer{API: api, TLSConfig: configured, MaximumConnections: maximumConnections, ShutdownTimeout: shutdownTimeout}, nil
}

func validateEnrollmentServerIdentity(config *tls.Config, ca *x509.Certificate, now time.Time) error {
	if config == nil || ca == nil || len(config.Certificates) != 1 || len(config.Certificates[0].Certificate) < 2 {
		return ErrInvalid
	}
	leaf, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil || leaf.IsCA || !allowsCertificateUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return ErrForbidden
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	intermediates := x509.NewCertPool()
	foundAnchor := false
	for _, raw := range config.Certificates[0].Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return ErrInvalid
		}
		if bytes.Equal(certificate.Raw, ca.Raw) {
			foundAnchor = true
		} else {
			intermediates.AddCert(certificate)
		}
	}
	if !foundAnchor {
		return ErrForbidden
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func allowsCertificateUsage(certificate *x509.Certificate, wanted x509.ExtKeyUsage) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == wanted {
			return true
		}
	}
	return false
}

func (server *EnrollmentServer) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || ctx == nil || listener == nil {
		return ErrInvalid
	}
	bounded := &operatorBoundedListener{Listener: listener, semaphore: make(chan struct{}, server.MaximumConnections)}
	httpServer := &http.Server{Handler: server.API.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: server.TLSConfig.Clone()}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- httpServer.ServeTLS(bounded, "", "") }()
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), server.ShutdownTimeout)
		defer cancel()
		shutdownErr := httpServer.Shutdown(shutdownContext)
		if shutdownErr != nil {
			_ = httpServer.Close()
		}
		serveErr := <-serveErrors
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			return errors.Join(shutdownErr, serveErr)
		}
		return shutdownErr
	}
}
