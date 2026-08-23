package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/federation"
)

type Endpoint struct {
	service          *Service
	HandshakeTimeout time.Duration
	HelloTimeout     time.Duration
	ReceiveTimeout   time.Duration
	SendEvery        time.Duration
	MaxFrame         uint32
}

func NewEndpoint(service *Service) (*Endpoint, error) {
	if service == nil || service.store == nil || service.receiptVerifier == nil || service.eventVerifier == nil || !service.peerID.Valid() {
		return nil, ErrInvalid
	}
	return &Endpoint{service: service, HandshakeTimeout: 15 * time.Second, HelloTimeout: 15 * time.Second, ReceiveTimeout: 45 * time.Second, SendEvery: 500 * time.Millisecond, MaxFrame: federation.MaxFrameBytes}, nil
}

func (endpoint *Endpoint) ServeTLS(ctx context.Context, connection *tls.Conn) error {
	if endpoint == nil || endpoint.service == nil || ctx == nil || connection == nil {
		return ErrInvalid
	}
	defer connection.Close()
	timeout := endpoint.HandshakeTimeout
	if timeout <= 0 || timeout > time.Minute {
		timeout = 15 * time.Second
	}
	handshakeContext, cancel := context.WithTimeout(ctx, timeout)
	err := connection.HandshakeContext(handshakeContext)
	cancel()
	if err != nil {
		return err
	}
	session, err := federation.NewFramedSession(connection, endpoint.MaxFrame)
	if err != nil {
		return err
	}
	bound, err := endpoint.bind(connection.ConnectionState(), session)
	if err != nil {
		return err
	}
	return bound.Run(ctx)
}

func (endpoint *Endpoint) bind(state tls.ConnectionState, session federation.Session) (*NodeSession, error) {
	if endpoint == nil || endpoint.service == nil || endpoint.service.store == nil || endpoint.service.receiptVerifier == nil || endpoint.service.eventVerifier == nil || session == nil {
		return nil, ErrInvalid
	}
	fingerprint, err := verifiedClientCertificateFingerprint(state, endpoint.service.clock().UTC())
	if err != nil {
		return nil, err
	}
	return &NodeSession{service: endpoint.service, store: endpoint.service.store, session: session, certificateFingerprint: fingerprint, sendEvery: endpoint.SendEvery, helloTimeout: endpoint.HelloTimeout, receiveTimeout: endpoint.ReceiveTimeout}, nil
}

func verifiedClientCertificateFingerprint(state tls.ConnectionState, now time.Time) ([sha256.Size]byte, error) {
	var fingerprint [sha256.Size]byte
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return fingerprint, ErrForbidden
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fingerprint, ErrForbidden
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		return fingerprint, ErrForbidden
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			clientAuth = true
			break
		}
	}
	if !clientAuth {
		return fingerprint, ErrForbidden
	}
	verified := false
	for _, chain := range state.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && chain[0].Equal(leaf) {
			verified = true
			break
		}
	}
	if !verified {
		return fingerprint, ErrForbidden
	}
	return sha256.Sum256(leaf.Raw), nil
}

func certificateFingerprintMatches(stored string, presented [sha256.Size]byte) bool {
	if len(stored) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(stored)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(decoded, presented[:]) == 1
}
