package extensions

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"
)

const maximumReleaseDocumentBytes = 4 << 20

// TrustKey is panel-owned trust metadata. Key material is public only and is
// copied when a verifier is constructed so callers cannot alter the trust set.
type TrustKey struct {
	ID        string
	Publisher string
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	RevokedAt *time.Time
}

// TrustVerifier verifies release signatures against a fixed trust set and a
// fixed panel contract version.
type TrustVerifier struct {
	keys     map[string]TrustKey
	contract ContractVersion
	now      func() time.Time
}

func NewTrustVerifier(keys []TrustKey, contract ContractVersion, now func() time.Time) (*TrustVerifier, error) {
	if !contract.Valid() {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	verifier := &TrustVerifier{keys: make(map[string]TrustKey, len(keys)), contract: contract, now: now}
	for _, key := range keys {
		if !namePattern.MatchString(key.ID) || !namePattern.MatchString(key.Publisher) || len(key.PublicKey) != ed25519.PublicKeySize ||
			key.NotBefore.IsZero() || key.NotAfter.IsZero() || !key.NotAfter.After(key.NotBefore) ||
			key.RevokedAt != nil && key.RevokedAt.Before(key.NotBefore) {
			return nil, ErrInvalid
		}
		if _, exists := verifier.keys[key.ID]; exists {
			return nil, ErrConflict
		}
		key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
		if key.RevokedAt != nil {
			revokedAt := *key.RevokedAt
			key.RevokedAt = &revokedAt
		}
		verifier.keys[key.ID] = key
	}
	return verifier, nil
}

// Verify rejects malformed, unsigned, untrusted, revoked, deprecated, and
// contract-incompatible releases. A signature binds the canonical release
// digest, which itself binds the complete manifest and artifact metadata.
func (verifier *TrustVerifier) Verify(ctx context.Context, release ExtensionRelease) error {
	if verifier == nil {
		return ErrUntrusted
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := release.Validate(); err != nil {
		return err
	}
	if verifier.contract.Compare(release.Manifest.MinimumContract) < 0 || verifier.contract.Compare(release.Manifest.MaximumContract) > 0 {
		return ErrIncompatible
	}
	now := verifier.now().UTC()
	if release.DeprecatedAt != nil && !now.Before(release.DeprecatedAt.UTC()) {
		return ErrUntrusted
	}
	key, ok := verifier.keys[release.SigningKeyID]
	if !ok || key.Publisher != release.Manifest.Publisher || release.PublishedAt.Before(key.NotBefore) || release.PublishedAt.After(key.NotAfter) ||
		key.RevokedAt != nil && !now.Before(*key.RevokedAt) {
		return ErrUntrusted
	}
	signature, err := decodeSignature(release.Signature)
	if err != nil || !ed25519.Verify(key.PublicKey, ReleaseSigningPayload(release), signature) {
		return ErrUntrusted
	}
	return nil
}

// ReleaseSigningPayload is intentionally small and domain-separated. The
// validated digest covers all release and manifest metadata except signature.
func ReleaseSigningPayload(release ExtensionRelease) []byte {
	return []byte("cyberpanel.extension.release.v1\x00" + release.Digest)
}

func decodeSignature(encoded string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		decoded, err := encoding.DecodeString(encoded)
		if err == nil && len(decoded) == ed25519.SignatureSize {
			return decoded, nil
		}
	}
	return nil, ErrUntrusted
}

// DecodeRelease accepts one strict JSON document and rejects unknown fields or
// appended content before any trust decision is made.
func DecodeRelease(document []byte) (ExtensionRelease, error) {
	if len(document) == 0 || len(document) > maximumReleaseDocumentBytes {
		return ExtensionRelease{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var release ExtensionRelease
	if err := decoder.Decode(&release); err != nil {
		return ExtensionRelease{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ExtensionRelease{}, ErrInvalid
	}
	if err := release.Validate(); err != nil {
		return ExtensionRelease{}, err
	}
	return release, nil
}

func digestExtensionManifest(manifest ExtensionManifest) string {
	manifest.Digest = ""
	return digestJSON(manifest)
}

func CanonicalManifestDigest(manifest ExtensionManifest) string {
	return digestExtensionManifest(manifest)
}

func digestExtensionRelease(release ExtensionRelease) string {
	release.Digest = ""
	release.Signature = ""
	return digestJSON(release)
}

func CanonicalReleaseDigest(release ExtensionRelease) string {
	return digestExtensionRelease(release)
}

func digestCapabilityApproval(approval CapabilityApproval) string {
	approval.Digest = ""
	return digestJSON(approval)
}

func CanonicalCapabilityApprovalDigest(approval CapabilityApproval) string {
	return digestCapabilityApproval(approval)
}
