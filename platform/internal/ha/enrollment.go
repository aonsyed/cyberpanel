package ha

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const enrollmentAudience = "cyberpanel-fleet-enrollment-v1"

// EnrollmentClaims is the closed, central-signed description of a node that
// a local owner is admitting to the fleet. The certificate itself is carried
// by SignedEnrollmentToken; the separately entered SHA-256 fingerprint pins
// that exact certificate before any claim is accepted.
type EnrollmentClaims struct {
	SchemaVersion uint32       `json:"schema_version"`
	Audience      string       `json:"audience"`
	TokenID       string       `json:"token_id"`
	Group         NodeGroup    `json:"group"`
	Node          NodeMember   `json:"node"`
	IssuedAt      time.Time    `json:"issued_at"`
	ExpiresAt     time.Time    `json:"expires_at"`
}

type SignedEnrollmentToken struct {
	Claims         EnrollmentClaims `json:"claims"`
	CertificateDER string           `json:"certificate_der"`
	Signature      string           `json:"signature"`
}

type VerifiedEnrollment struct {
	TokenID    string
	TokenDigest string
	Group      NodeGroup
	Node       NodeMember
}

type EnrollmentVerifier struct{ Now func() time.Time }

func (verifier EnrollmentVerifier) Verify(raw []byte, expectedFingerprint string) (VerifiedEnrollment, error) {
	var result VerifiedEnrollment
	if len(raw) < 32 || len(raw) > 4096 {
		return result, ErrInvalid
	}
	encoded := strings.TrimSpace(string(raw))
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(payload) == 0 || len(payload) > 16<<10 {
		return result, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var token SignedEnrollmentToken
	if err = decoder.Decode(&token); err != nil {
		return result, ErrInvalid
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return result, ErrInvalid
	}
	certificateDER, err := decodeEnrollmentBase64(token.CertificateDER)
	if err != nil || len(certificateDER) == 0 || len(certificateDER) > 8<<10 {
		return result, ErrInvalid
	}
	fingerprint := sha256.Sum256(certificateDER)
	wanted := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(expectedFingerprint)), "sha256:")
	if len(wanted) != sha256.Size*2 || hex.EncodeToString(fingerprint[:]) != wanted {
		return result, ErrForbidden
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return result, ErrInvalid
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize || certificate.IsCA || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return result, ErrUnsupported
	}
	signature, err := decodeEnrollmentBase64(token.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return result, ErrForbidden
	}
	claimsPayload, err := json.Marshal(token.Claims)
	if err != nil || !ed25519.Verify(publicKey, enrollmentSignatureStructure(claimsPayload), signature) {
		return result, ErrForbidden
	}
	now := time.Now().UTC()
	if verifier.Now != nil {
		now = verifier.Now().UTC()
	}
	claims := token.Claims
	if claims.SchemaVersion != 1 || claims.Audience != enrollmentAudience || !validID(claims.TokenID) || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || claims.ExpiresAt.Sub(claims.IssuedAt) <= 0 || claims.ExpiresAt.Sub(claims.IssuedAt) > time.Hour || now.Before(claims.IssuedAt.Add(-time.Minute)) || !now.Before(claims.ExpiresAt) || now.Before(certificate.NotBefore.Add(-time.Minute)) || !now.Before(certificate.NotAfter) || claims.IssuedAt.Before(certificate.NotBefore.Add(-time.Minute)) || claims.ExpiresAt.After(certificate.NotAfter) {
		return result, ErrExpired
	}
	group := claims.Group
	group.State = "active"
	group.Generation = 1
	group.CreatedAt = now
	group.UpdatedAt = now
	if err = group.Validate(); err != nil {
		return result, err
	}
	node := claims.Node
	if node.GroupID != group.ID || node.ID == "" || len(node.Roles) == 0 {
		return result, ErrInvalid
	}
	node.State = NodeReady
	node.Generation = 1
	node.JoinedAt = now
	node.UpdatedAt = now
	node.Capabilities.ObservedAt = now
	if err = node.Validate(); err != nil {
		return result, err
	}
	tokenDigest := sha256.Sum256([]byte(encoded))
	return VerifiedEnrollment{TokenID:claims.TokenID, TokenDigest:hex.EncodeToString(tokenDigest[:]), Group:group, Node:node}, nil
}

func enrollmentSignatureStructure(claims []byte) []byte {
	value := make([]byte, 0, len(enrollmentAudience)+1+len(claims))
	value = append(value, enrollmentAudience...)
	value = append(value, 0)
	return append(value, claims...)
}

func decodeEnrollmentBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
