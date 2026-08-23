package productupdate

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"time"
)

const manifestSignatureDomain = "cyberpanel-product-manifest-v1\n"
const rotationSignatureDomain = "cyberpanel-product-key-rotation-v1\n"

type TrustRoot struct {
	KeyID     string
	Epoch     uint64
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	Revoked   bool
}

type TrustPolicy struct {
	Roots            []TrustRoot
	Threshold        uint16
	CurrentEpoch     uint64
	MaximumClockSkew time.Duration
	MaximumLifetime  time.Duration
	MaximumBytes     int64
}

type Verifier struct {
	policy TrustPolicy
	keys   map[uint64]map[string]TrustRoot
}

func NewVerifier(policy TrustPolicy) (*Verifier, error) {
	if policy.Threshold == 0 || policy.CurrentEpoch == 0 || policy.CurrentEpoch >= maxGeneration || policy.MaximumClockSkew < 0 ||
		policy.MaximumClockSkew > 10*time.Minute || policy.MaximumLifetime <= 0 ||
		policy.MaximumLifetime > 366*24*time.Hour || policy.MaximumBytes <= 0 || policy.MaximumBytes > 16<<20 || len(policy.Roots) == 0 || len(policy.Roots) > 128 {
		return nil, ErrInvalid
	}
	verifier := &Verifier{policy: policy, keys: make(map[uint64]map[string]TrustRoot)}
	for _, root := range policy.Roots {
		if !identifierPattern.MatchString(root.KeyID) || root.Epoch == 0 || len(root.PublicKey) != ed25519.PublicKeySize ||
			!validTime(root.NotBefore) || !validTime(root.NotAfter) || !root.NotAfter.After(root.NotBefore) {
			return nil, ErrInvalid
		}
		if root.Epoch != policy.CurrentEpoch && root.Epoch != policy.CurrentEpoch+1 { return nil, ErrInvalid }
		if verifier.keys[root.Epoch] == nil { verifier.keys[root.Epoch] = make(map[string]TrustRoot) }
		if _, exists := verifier.keys[root.Epoch][root.KeyID]; exists { return nil, ErrInvalid }
		root.PublicKey = append(ed25519.PublicKey(nil), root.PublicKey...)
		root.NotBefore, root.NotAfter = root.NotBefore.UTC(), root.NotAfter.UTC()
		verifier.keys[root.Epoch][root.KeyID] = root
	}
	if activeRootCount(verifier.keys[policy.CurrentEpoch]) < int(policy.Threshold) { return nil, ErrInvalid }
	return verifier, nil
}

func activeRootCount(roots map[string]TrustRoot) int {
	count := 0
	for _, root := range roots { if !root.Revoked { count++ } }
	return count
}

func (verifier *Verifier) Verify(manifest ReleaseManifest, inventory InstalledInventory, now time.Time, acceptedSequence uint64, acceptedDigest string) (ReleaseManifest, InstalledInventory, error) {
	if verifier == nil || !validTime(now) || acceptedDigest != "" && !validDigest(acceptedDigest) ||
		acceptedSequence == 0 && acceptedDigest != "" || acceptedSequence != 0 && acceptedDigest == "" { return ReleaseManifest{}, InstalledInventory{}, ErrInvalid }
	canonicalManifest, err := CanonicalManifest(manifest)
	if err != nil { return ReleaseManifest{}, InstalledInventory{}, err }
	canonicalInventory, err := CanonicalInventory(inventory)
	if err != nil { return ReleaseManifest{}, InstalledInventory{}, err }
	now = now.UTC()
	if err := verifier.verifyAuthenticity(canonicalManifest, now); err != nil { return ReleaseManifest{}, InstalledInventory{}, err }
	if canonicalManifest.Platform != canonicalInventory.Platform { return ReleaseManifest{}, InstalledInventory{}, ErrIncompatible }
	if canonicalManifest.SchemaCompatibility.Validate() != nil || canonicalInventory.SchemaVersion < canonicalManifest.SchemaCompatibility.Minimum ||
		canonicalInventory.SchemaVersion > canonicalManifest.SchemaCompatibility.Maximum || !canonicalManifest.RuntimeCompatibility.Includes(canonicalInventory.Runtime) ||
		!containsAll(canonicalInventory.Capabilities, canonicalManifest.RequiredCapabilities) {
		return ReleaseManifest{}, InstalledInventory{}, ErrIncompatible
	}
	if canonicalManifest.Sequence < acceptedSequence || canonicalManifest.Sequence == acceptedSequence && canonicalManifest.Digest != acceptedDigest {
		return ReleaseManifest{}, InstalledInventory{}, ErrConflict
	}
	return canonicalManifest, canonicalInventory, nil
}

func (verifier *Verifier) verifyAuthenticity(manifest ReleaseManifest, now time.Time) error {
	if verifier == nil || !validTime(now) { return ErrInvalid }
	manifest, err := CanonicalManifest(manifest)
	if err != nil { return err }
	raw, err := json.Marshal(manifest)
	if err != nil || int64(len(raw)) > verifier.policy.MaximumBytes { return ErrCapacity }
	now = now.UTC()
	if now.Add(verifier.policy.MaximumClockSkew).Before(manifest.IssuedAt) { return ErrInvalid }
	if !now.Add(-verifier.policy.MaximumClockSkew).Before(manifest.ExpiresAt) { return ErrExpired }
	if manifest.ExpiresAt.Sub(manifest.IssuedAt) > verifier.policy.MaximumLifetime { return ErrInvalid }
	if manifest.SignerEpoch != verifier.policy.CurrentEpoch && manifest.SignerEpoch != verifier.policy.CurrentEpoch+1 { return ErrUnauthorized }
	if manifest.SignatureThreshold < verifier.policy.Threshold { return ErrUnauthorized }
	if manifest.SignerEpoch == verifier.policy.CurrentEpoch {
		if manifest.Rotation != nil { return ErrInvalid }
	} else if err := verifier.verifyRotation(manifest.Rotation, now); err != nil { return err }
	return verifier.verifyThreshold(manifest.SignerEpoch, manifest.Signatures, int(manifest.SignatureThreshold),
		[]byte(manifestSignatureDomain+manifest.Digest), now)
}

func (verifier *Verifier) verifyRotation(proof *RotationProof, now time.Time) error {
	if proof == nil || proof.FromEpoch != verifier.policy.CurrentEpoch || proof.ToEpoch != verifier.policy.CurrentEpoch+1 ||
		len(proof.NewKeyIDs) == 0 || len(proof.NewKeyIDs) > 128 { return ErrUnauthorized }
	proof.NewKeyIDs = append([]string(nil), proof.NewKeyIDs...)
	sort.Strings(proof.NewKeyIDs)
	newRoots := verifier.keys[proof.ToEpoch]
	expected := make([]string, 0, len(newRoots))
	for keyID, root := range newRoots { if !root.Revoked { expected = append(expected, keyID) } }
	sort.Strings(expected)
	if len(expected) < int(verifier.policy.Threshold) || len(expected) != len(proof.NewKeyIDs) { return ErrUnauthorized }
	for index, keyID := range proof.NewKeyIDs {
		if !identifierPattern.MatchString(keyID) || expected[index] != keyID || index > 0 && proof.NewKeyIDs[index-1] == keyID { return ErrUnauthorized }
	}
	payload := struct {
		FromEpoch uint64   `json:"from_epoch"`
		ToEpoch   uint64   `json:"to_epoch"`
		NewKeyIDs []string `json:"new_key_ids"`
	}{proof.FromEpoch, proof.ToEpoch, proof.NewKeyIDs}
	digest, err := digestJSON(payload)
	if err != nil || proof.Digest != digest { return ErrIntegrity }
	return verifier.verifyThreshold(proof.FromEpoch, proof.Signatures, int(verifier.policy.Threshold),
		[]byte(rotationSignatureDomain+digest), now)
}

func (verifier *Verifier) verifyThreshold(epoch uint64, signatures []ManifestSignature, threshold int, message []byte, now time.Time) error {
	if threshold <= 0 || len(signatures) < threshold || len(signatures) > 128 { return ErrUnauthorized }
	roots := verifier.keys[epoch]
	seen := make(map[string]struct{}, len(signatures))
	valid := 0
	for _, signature := range signatures {
		if signature.Epoch != epoch || len(signature.Value) != ed25519.SignatureSize { return ErrUnauthorized }
		if _, duplicate := seen[signature.KeyID]; duplicate { return ErrUnauthorized }
		seen[signature.KeyID] = struct{}{}
		root, found := roots[signature.KeyID]
		if !found || root.Revoked || now.Before(root.NotBefore) || !now.Before(root.NotAfter) { continue }
		if ed25519.Verify(root.PublicKey, message, signature.Value) { valid++ }
	}
	if valid < threshold { return ErrUnauthorized }
	return nil
}

func containsAll(have, required []string) bool {
	index := 0
	for _, capability := range required {
		for index < len(have) && have[index] < capability { index++ }
		if index == len(have) || have[index] != capability { return false }
	}
	return true
}
