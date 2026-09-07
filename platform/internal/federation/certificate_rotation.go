package federation

import (
	"encoding/json"
	"time"
)

// NodeCertificateRotationResult is signed by the pinned enrollment CA, not
// by a newly introduced central authority or a transport-only identity.
type NodeCertificateRotationResult struct {
	NodeID ID `json:"node_id"`
	PeerID ID `json:"peer_id"`
	Generation uint64 `json:"generation"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestDigest string `json:"request_digest"`
	PreviousCertificateFingerprint string `json:"previous_certificate_fingerprint_sha256"`
	SigningPublicKey []byte `json:"signing_public_key"`
	EvidenceKeyID string `json:"evidence_key_id"`
	CertificateFingerprint string `json:"certificate_fingerprint_sha256"`
	NodeCertificate []byte `json:"node_certificate"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
	Signature []byte `json:"signature"`
}

func (result NodeCertificateRotationResult) SigStructure() []byte {
	result.Signature = nil
	encoded, _ := json.Marshal(struct {
		Domain string `json:"domain"`
		Result NodeCertificateRotationResult `json:"result"`
	}{"cyberpanel-node-certificate-rotation-result-v1", result})
	return encoded
}
