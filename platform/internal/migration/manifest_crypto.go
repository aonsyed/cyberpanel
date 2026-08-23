package migration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const manifestSignatureDomain = "cyberpanel-migration-manifest-v1"

// ManifestTrustPolicy is immutable process configuration. Extractor keys are
// explicitly pinned by ID; a source manifest cannot add or rotate its own
// trust root.
type ManifestTrustPolicy struct {
	TargetInstallationID string
	SchemaHashes         map[string]struct{}
	Keys                 map[string]ed25519.PublicKey
	MaximumManifestBytes int
	MaximumChunks        int
	MaximumResources     int
}

type SignedManifestVerifier struct{ policy ManifestTrustPolicy }

func NewSignedManifestVerifier(policy ManifestTrustPolicy) (*SignedManifestVerifier, error) {
	if strings.TrimSpace(policy.TargetInstallationID) == "" || len(policy.SchemaHashes) == 0 || len(policy.Keys) == 0 {
		return nil, ErrInvalid
	}
	if policy.MaximumManifestBytes == 0 {
		policy.MaximumManifestBytes = 32 << 20
	}
	if policy.MaximumChunks == 0 {
		policy.MaximumChunks = 1_000_000
	}
	if policy.MaximumResources == 0 {
		policy.MaximumResources = 100_000
	}
	if policy.MaximumManifestBytes < 4096 || policy.MaximumChunks < 1 || policy.MaximumResources < 1 {
		return nil, ErrInvalid
	}
	keys := make(map[string]ed25519.PublicKey, len(policy.Keys))
	for id, key := range policy.Keys {
		if !validSigningKeyID(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	hashes := make(map[string]struct{}, len(policy.SchemaHashes))
	for digest := range policy.SchemaHashes {
		if !isDigest(digest) {
			return nil, ErrInvalid
		}
		hashes[digest] = struct{}{}
	}
	policy.Keys, policy.SchemaHashes = keys, hashes
	return &SignedManifestVerifier{policy: policy}, nil
}

func (v *SignedManifestVerifier) Verify(ctx context.Context, manifest Manifest) error {
	if v == nil || ctx == nil {
		return ErrInvalid
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := manifest.Validate(); err != nil || manifest.TargetInstallationID != v.policy.TargetInstallationID {
		return ErrInvalid
	}
	if _, trusted := v.policy.SchemaHashes[manifest.SchemaHash]; !trusted {
		return errors.Join(ErrBlocked, fmt.Errorf("untrusted migration schema %s", manifest.SchemaHash))
	}
	key, trusted := v.policy.Keys[manifest.SigningKeyID]
	if !trusted {
		return errors.Join(ErrBlocked, fmt.Errorf("untrusted migration signing key %s", manifest.SigningKeyID))
	}
	if len(manifest.Chunks) > v.policy.MaximumChunks || resourceCount(manifest) > v.policy.MaximumResources {
		return ErrCapacity
	}
	canonical, err := canonicalManifest(manifest)
	if err != nil || len(canonical) > v.policy.MaximumManifestBytes {
		return ErrCapacity
	}
	root, err := ComputeManifestRoot(manifest)
	if err != nil || subtle.ConstantTimeCompare([]byte(root), []byte(manifest.MerkleRoot)) != 1 {
		return errors.Join(ErrInvalid, errors.New("manifest merkle root mismatch"))
	}
	message := manifestSignatureMessage(manifest.SchemaHash, manifest.MerkleRoot, manifest.TargetInstallationID, manifest.SourceInstallationID, manifest.SourceGeneration)
	if !ed25519.Verify(key, message, manifest.Signature) {
		return errors.Join(ErrInvalid, errors.New("manifest signature rejected"))
	}
	return nil
}

// SignManifest is used by the separately deployed extractor. The target
// runtime only needs Verify; signing keys never enter panel-core.
func SignManifest(manifest Manifest, keyID string, privateKey ed25519.PrivateKey) (Manifest, error) {
	if !validSigningKeyID(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, ErrInvalid
	}
	manifest.SigningKeyID = keyID
	manifest.Signature = nil
	manifest.MerkleRoot = strings.Repeat("0", 64)
	root, err := ComputeManifestRoot(manifest)
	if err != nil {
		return Manifest{}, err
	}
	manifest.MerkleRoot = root
	manifest.Signature = ed25519.Sign(privateKey, manifestSignatureMessage(manifest.SchemaHash, root, manifest.TargetInstallationID, manifest.SourceInstallationID, manifest.SourceGeneration))
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func ComputeManifestRoot(manifest Manifest) (string, error) {
	clone := manifest
	clone.Signature = nil
	clone.MerkleRoot = ""
	normalizeManifest(&clone)
	raw, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	leaves := make([][32]byte, 0, len(clone.Chunks)+len(clone.Secrets)+1)
	leaves = append(leaves, sha256.Sum256(append([]byte("manifest\x00"), raw...)))
	for _, chunk := range clone.Chunks {
		encoded, err := json.Marshal(chunk)
		if err != nil {
			return "", err
		}
		leaves = append(leaves, sha256.Sum256(append([]byte("chunk\x00"), encoded...)))
	}
	for _, secret := range clone.Secrets {
		encoded, err := json.Marshal(secret)
		if err != nil {
			return "", err
		}
		leaves = append(leaves, sha256.Sum256(append([]byte("secret\x00"), encoded...)))
	}
	sort.Slice(leaves, func(i, j int) bool { return bytes.Compare(leaves[i][:], leaves[j][:]) < 0 })
	for len(leaves) > 1 {
		next := make([][32]byte, 0, (len(leaves)+1)/2)
		for index := 0; index < len(leaves); index += 2 {
			right := index + 1
			if right >= len(leaves) {
				right = index
			}
			input := make([]byte, 0, len("node\x00")+64)
			input = append(input, []byte("node\x00")...)
			input = append(input, leaves[index][:]...)
			input = append(input, leaves[right][:]...)
			next = append(next, sha256.Sum256(input))
		}
		leaves = next
	}
	return hex.EncodeToString(leaves[0][:]), nil
}

func canonicalManifest(manifest Manifest) ([]byte, error) {
	normalizeManifest(&manifest)
	return json.Marshal(manifest)
}

func normalizeManifest(manifest *Manifest) {
	manifest.Chunks = canonicalChunks(manifest.Chunks)
	sort.Slice(manifest.Sites, func(i, j int) bool { return manifest.Sites[i].SourceID < manifest.Sites[j].SourceID })
	sort.Slice(manifest.Databases, func(i, j int) bool { return manifest.Databases[i].SourceID < manifest.Databases[j].SourceID })
	sort.Slice(manifest.DNSZones, func(i, j int) bool { return manifest.DNSZones[i].SourceID < manifest.DNSZones[j].SourceID })
	sort.Slice(manifest.MailDomains, func(i, j int) bool { return manifest.MailDomains[i].SourceID < manifest.MailDomains[j].SourceID })
	sort.Slice(manifest.Certificates, func(i, j int) bool { return manifest.Certificates[i].SourceID < manifest.Certificates[j].SourceID })
	sort.Slice(manifest.Credentials, func(i, j int) bool { return manifest.Credentials[i].SourceID < manifest.Credentials[j].SourceID })
	sort.Slice(manifest.Schedules, func(i, j int) bool { return manifest.Schedules[i].SourceID < manifest.Schedules[j].SourceID })
	sort.Slice(manifest.Repositories, func(i, j int) bool { return manifest.Repositories[i].SourceID < manifest.Repositories[j].SourceID })
	sort.Slice(manifest.Containers, func(i, j int) bool { return manifest.Containers[i].SourceID < manifest.Containers[j].SourceID })
	sort.Slice(manifest.BackupPolicies, func(i, j int) bool { return manifest.BackupPolicies[i].SourceID < manifest.BackupPolicies[j].SourceID })
	sort.Slice(manifest.Secrets, func(i, j int) bool {
		if manifest.Secrets[i].SecretID == manifest.Secrets[j].SecretID {
			return manifest.Secrets[i].Version < manifest.Secrets[j].Version
		}
		return manifest.Secrets[i].SecretID < manifest.Secrets[j].SecretID
	})
	for index := range manifest.Sites {
		sort.Strings(manifest.Sites[index].Aliases)
		sort.Strings(manifest.Sites[index].Redirects)
		sort.Strings(manifest.Sites[index].Children)
		sort.Slice(manifest.Sites[index].Content, func(i, j int) bool { return manifest.Sites[index].Content[i].Digest < manifest.Sites[index].Content[j].Digest })
	}
}

func manifestSignatureMessage(schemaHash, root, targetInstallation, sourceInstallation string, generation uint64) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%d", manifestSignatureDomain, schemaHash, root, targetInstallation, sourceInstallation, generation))
}

func resourceCount(manifest Manifest) int {
	count := len(manifest.Sites) + len(manifest.Databases) + len(manifest.DNSZones) + len(manifest.MailDomains) + len(manifest.Certificates) + len(manifest.Credentials) + len(manifest.Schedules) + len(manifest.Repositories) + len(manifest.Containers) + len(manifest.BackupPolicies)
	for _, domain := range manifest.MailDomains {
		count += len(domain.Mailboxes)
	}
	return count
}

func isDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validSigningKeyID(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' && character != ':' && character != '.' {
			return false
		}
	}
	return true
}
