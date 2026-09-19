package noderelease

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	BundleManifestPath = "release.json"
	maximumSpecBytes   = 16 << 20
)

type SourceArtifact struct {
	ID          string           `json:"id"`
	Kind        ArtifactKind     `json:"kind"`
	Source      string           `json:"source"`
	Destination string           `json:"destination,omitempty"`
	UID         uint32           `json:"uid"`
	GID         uint32           `json:"gid"`
	Mode        string           `json:"mode"`
	Package     *PackageMetadata `json:"package,omitempty"`
}

type BuildSpec struct {
	SchemaVersion  uint16           `json:"schema_version"`
	SigningKeyID   string           `json:"signing_key_id"`
	ReleaseID      string           `json:"release_id"`
	Sequence       uint64           `json:"sequence"`
	ProductVersion Version          `json:"product_version"`
	ProductSchema  uint64           `json:"product_schema"`
	Target         Target           `json:"target"`
	FreshInstall   bool             `json:"fresh_install"`
	UpgradeSource  VersionRange     `json:"upgrade_source"`
	SourceSchema   SchemaRange      `json:"source_schema"`
	Artifacts      []SourceArtifact `json:"artifacts"`
	InstallOrder   []string         `json:"install_order"`
	Services       []ServiceProbe   `json:"services"`
	Rollback       RollbackMetadata `json:"rollback"`
	IssuedAt       time.Time        `json:"issued_at"`
	ExpiresAt      time.Time        `json:"expires_at"`
}

type BundleReceipt struct {
	BundlePath     string `json:"bundle_path"`
	BundleSHA256   string `json:"bundle_sha256"`
	ManifestDigest string `json:"manifest_digest"`
	ReleaseID      string `json:"release_id"`
	Target         Target `json:"target"`
	ArtifactCount  int    `json:"artifact_count"`
	ArtifactBytes  int64  `json:"artifact_bytes"`
}

type TrustedKey struct {
	ID              string
	PublicKey       ed25519.PublicKey
	NotBefore       time.Time
	NotAfter        time.Time
	MinimumSequence uint64
	MaximumSequence uint64
}

type TrustStore struct {
	Keys map[string]TrustedKey
}

type trustedKeyDocument struct {
	SchemaVersion   uint16    `json:"schema_version"`
	KeyID           string    `json:"key_id"`
	PublicKey       string    `json:"public_key"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	MinimumSequence uint64    `json:"minimum_sequence"`
	MaximumSequence uint64    `json:"maximum_sequence"`
}

func ReadBuildSpec(path string) (BuildSpec, error) {
	payload, err := readBoundedRegular(path, maximumSpecBytes, false)
	if err != nil {
		return BuildSpec{}, fmt.Errorf("read node release source spec %s: %w", path, err)
	}
	var spec BuildSpec
	if err = decodeStrictJSON(payload, &spec); err != nil {
		return BuildSpec{}, fmt.Errorf("decode node release source spec %s: %w", path, err)
	}
	return spec, nil
}

func AssembleBundle(spec BuildSpec, sourceRoot, privateKeyPath, outputPath string) (BundleReceipt, error) {
	root, err := canonicalDirectory(sourceRoot)
	if err != nil {
		return BundleReceipt{}, fmt.Errorf("open node release source tree %s: %w", sourceRoot, err)
	}
	if !filepath.IsAbs(outputPath) || filepath.Clean(outputPath) != outputPath || filepath.Ext(outputPath) != ".tar" {
		return BundleReceipt{}, fmt.Errorf("%w: output must be an absolute .tar path", ErrInvalid)
	}
	outputRoot, err := canonicalDirectory(filepath.Dir(outputPath))
	if err != nil {
		return BundleReceipt{}, fmt.Errorf("open node release output directory %s: %w", filepath.Dir(outputPath), err)
	}
	if !filepath.IsAbs(privateKeyPath) || filepath.Clean(privateKeyPath) != privateKeyPath || pathBelow(privateKeyPath, root) ||
		outputRoot == root || pathBelow(outputRoot, root) {
		return BundleReceipt{}, fmt.Errorf("%w: signing key and output must be outside the release source tree", ErrInvalid)
	}
	if _, err = os.Lstat(outputPath); err == nil {
		return BundleReceipt{}, fmt.Errorf("%w: release output already exists: %s", ErrConflict, outputPath)
	} else if !os.IsNotExist(err) {
		return BundleReceipt{}, err
	}
	if spec.SchemaVersion != ManifestSchema || !identifier.MatchString(spec.SigningKeyID) || len(spec.Artifacts) == 0 {
		return BundleReceipt{}, ErrInvalid
	}
	sources := make(map[string]string, len(spec.Artifacts))
	artifacts := make([]Artifact, 0, len(spec.Artifacts))
	var artifactBytes int64
	for _, input := range spec.Artifacts {
		if !identifier.MatchString(input.ID) || sources[input.ID] != "" || forbiddenSourcePath(input.Source) {
			return BundleReceipt{}, ErrInvalid
		}
		source, err := canonicalSource(root, input.Source)
		if err != nil {
			return BundleReceipt{}, fmt.Errorf("open source artifact %s (%s): %w", input.ID, input.Source, err)
		}
		digest, size, err := digestFile(source)
		if err != nil {
			return BundleReceipt{}, fmt.Errorf("digest source artifact %s (%s): %w", input.ID, input.Source, err)
		}
		if artifactBytes > 16<<30-size {
			return BundleReceipt{}, ErrInvalid
		}
		artifactBytes += size
		artifact := Artifact{ID: input.ID, Kind: input.Kind, SHA256: digest, Size: size, Destination: input.Destination,
			UID: input.UID, GID: input.GID, Mode: input.Mode, Package: input.Package}
		if err = artifact.validate(spec.Target); err != nil {
			return BundleReceipt{}, fmt.Errorf("validate source artifact %s (%s): %w", input.ID, input.Source, err)
		}
		if input.Kind == ArtifactConfig || input.Kind == ArtifactUnit {
			if err = rejectPackagedAuthority(source, size); err != nil {
				return BundleReceipt{}, fmt.Errorf("reject secret or host identity in source artifact %s (%s): %w", input.ID, input.Source, err)
			}
		}
		sources[input.ID] = source
		artifacts = append(artifacts, artifact)
	}
	manifest, err := CanonicalManifest(Manifest{SchemaVersion: spec.SchemaVersion, ReleaseID: spec.ReleaseID,
		Sequence: spec.Sequence, ProductVersion: spec.ProductVersion, ProductSchema: spec.ProductSchema, Target: spec.Target,
		FreshInstall: spec.FreshInstall, UpgradeSource: spec.UpgradeSource, SourceSchema: spec.SourceSchema, Artifacts: artifacts,
		InstallOrder: spec.InstallOrder, Services: spec.Services, Rollback: spec.Rollback, IssuedAt: spec.IssuedAt, ExpiresAt: spec.ExpiresAt})
	if err != nil {
		return BundleReceipt{}, fmt.Errorf("compile signed node release manifest: %w", err)
	}
	privateKey, err := readPrivateKey(privateKeyPath)
	if err != nil {
		return BundleReceipt{}, fmt.Errorf("read Ed25519 node release signing key %s: %w", privateKeyPath, err)
	}
	signedBytes, err := manifest.SignedBytes()
	if err != nil {
		return BundleReceipt{}, err
	}
	signature := ed25519.Sign(privateKey, signedBytes)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !ed25519.Verify(publicKey, signedBytes, signature) {
		return BundleReceipt{}, fmt.Errorf("%w: Ed25519 signing key failed self-verification", ErrIntegrity)
	}
	envelope := SignedManifest{Manifest: manifest, KeyID: spec.SigningKeyID,
		Signature: base64.RawStdEncoding.EncodeToString(signature)}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return BundleReceipt{}, err
	}
	envelopeBytes = append(envelopeBytes, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(outputPath), ".node-release-*.tar")
	if err != nil {
		return BundleReceipt{}, err
	}
	temporaryPath := temporary.Name()
	complete := false
	defer func() {
		_ = temporary.Close()
		if !complete {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0600); err != nil {
		return BundleReceipt{}, err
	}
	bundleHash := sha256.New()
	archive := tar.NewWriter(io.MultiWriter(temporary, bundleHash))
	if err = writeTarBytes(archive, BundleManifestPath, envelopeBytes, spec.IssuedAt); err != nil {
		return BundleReceipt{}, err
	}
	for _, id := range manifest.InstallOrder {
		artifact, _ := manifest.Artifact(id)
		if err = writeTarSource(archive, artifact, sources[id], spec.IssuedAt); err != nil {
			return BundleReceipt{}, fmt.Errorf("archive source artifact %s: %w", id, err)
		}
	}
	if err = archive.Close(); err != nil {
		return BundleReceipt{}, err
	}
	if err = temporary.Sync(); err != nil {
		return BundleReceipt{}, err
	}
	if err = temporary.Close(); err != nil {
		return BundleReceipt{}, err
	}
	if err = os.Link(temporaryPath, outputPath); err != nil {
		return BundleReceipt{}, err
	}
	if err = os.Remove(temporaryPath); err != nil {
		cleanupErr := os.Remove(outputPath)
		return BundleReceipt{}, errors.Join(err, cleanupErr)
	}
	if err = syncDirectory(filepath.Dir(outputPath)); err != nil {
		return BundleReceipt{}, err
	}
	complete = true
	return BundleReceipt{BundlePath: outputPath, BundleSHA256: hex.EncodeToString(bundleHash.Sum(nil)),
		ManifestDigest: manifest.ManifestDigest, ReleaseID: manifest.ReleaseID, Target: manifest.Target,
		ArtifactCount: len(manifest.Artifacts), ArtifactBytes: artifactBytes}, nil
}

func forbiddenSourcePath(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(lower)
	if strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx") ||
		strings.HasSuffix(base, ".kdb") || base == "machine-id" || base == "hostname" || strings.HasPrefix(base, "ssh_host_") {
		return true
	}
	return strings.Contains(lower, "/credentials/") || strings.Contains(lower, "/host-identity/")
}

func LoadTrustStore(directory string) (TrustStore, error) {
	if directory != "/etc/cyberpanel/node-release/trust.d" {
		return TrustStore{}, fmt.Errorf("%w: trust path must be /etc/cyberpanel/node-release/trust.d", ErrInvalid)
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return TrustStore{}, errors.Join(ErrIntegrity, err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return TrustStore{}, err
	}
	if err = requireRootOwned(info, 0755, true); err != nil {
		return TrustStore{}, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return TrustStore{}, err
	}
	store := TrustStore{Keys: make(map[string]TrustedKey)}
	publicKeys := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		payload, err := readRootOwnedFile(path, 1<<20, 0644)
		if err != nil {
			return TrustStore{}, fmt.Errorf("read node release trust document %s: %w", path, err)
		}
		var document trustedKeyDocument
		if decodeStrictJSON(payload, &document) != nil || document.SchemaVersion != ManifestSchema ||
			!identifier.MatchString(document.KeyID) || !canonicalTime(document.NotBefore) || !canonicalTime(document.NotAfter) ||
			!document.NotAfter.After(document.NotBefore) || document.MinimumSequence == 0 ||
			document.MaximumSequence < document.MinimumSequence {
			return TrustStore{}, fmt.Errorf("%w: invalid node release trust document %s", ErrIntegrity, path)
		}
		raw, decodeErr := hex.DecodeString(document.PublicKey)
		if decodeErr != nil || len(raw) != ed25519.PublicKeySize || document.PublicKey != strings.ToLower(document.PublicKey) {
			return TrustStore{}, fmt.Errorf("%w: invalid Ed25519 public key in %s", ErrIntegrity, path)
		}
		if _, exists := store.Keys[document.KeyID]; exists {
			return TrustStore{}, fmt.Errorf("%w: duplicate node release key %s", ErrConflict, document.KeyID)
		}
		if existingID, exists := publicKeys[document.PublicKey]; exists {
			return TrustStore{}, fmt.Errorf("%w: Ed25519 public key is assigned to both %s and %s", ErrConflict, existingID, document.KeyID)
		}
		publicKeys[document.PublicKey] = document.KeyID
		store.Keys[document.KeyID] = TrustedKey{ID: document.KeyID, PublicKey: ed25519.PublicKey(raw),
			NotBefore: document.NotBefore, NotAfter: document.NotAfter, MinimumSequence: document.MinimumSequence,
			MaximumSequence: document.MaximumSequence}
	}
	if len(store.Keys) == 0 {
		return TrustStore{}, ErrNotFound
	}
	return store, nil
}

func (store TrustStore) Verify(envelope SignedManifest, now time.Time) (Manifest, error) {
	if !identifier.MatchString(envelope.KeyID) || envelope.Signature == "" || now.IsZero() {
		return Manifest{}, ErrUntrusted
	}
	manifest, key, err := store.verifySignature(envelope)
	if err != nil {
		return Manifest{}, err
	}
	now = now.UTC()
	if now.Before(manifest.IssuedAt) || !now.Before(manifest.ExpiresAt) || now.Before(key.NotBefore) || !now.Before(key.NotAfter) {
		return Manifest{}, ErrExpired
	}
	return manifest, nil
}

func (store TrustStore) VerifyRetained(envelope SignedManifest) (Manifest, error) {
	manifest, _, err := store.verifySignature(envelope)
	return manifest, err
}

func (store TrustStore) verifySignature(envelope SignedManifest) (Manifest, TrustedKey, error) {
	if !identifier.MatchString(envelope.KeyID) || envelope.Signature == "" {
		return Manifest{}, TrustedKey{}, ErrUntrusted
	}
	original, err := json.Marshal(envelope.Manifest)
	if err != nil {
		return Manifest{}, TrustedKey{}, err
	}
	manifest, err := CanonicalManifest(envelope.Manifest)
	if err != nil {
		return Manifest{}, TrustedKey{}, err
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(original, canonical) {
		return Manifest{}, TrustedKey{}, ErrIntegrity
	}
	key, exists := store.Keys[envelope.KeyID]
	if !exists || len(key.PublicKey) != ed25519.PublicKeySize || manifest.Sequence < key.MinimumSequence ||
		manifest.Sequence > key.MaximumSequence || manifest.IssuedAt.Before(key.NotBefore) || manifest.ExpiresAt.After(key.NotAfter) {
		return Manifest{}, TrustedKey{}, ErrUntrusted
	}
	signature, err := base64.RawStdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Manifest{}, TrustedKey{}, ErrUntrusted
	}
	payload, err := manifest.SignedBytes()
	if err != nil || !ed25519.Verify(key.PublicKey, payload, signature) {
		return Manifest{}, TrustedKey{}, ErrUntrusted
	}
	return manifest, key, nil
}

func decodeStrictJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func canonicalDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(ErrInvalid, err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.Join(ErrInvalid, err)
	}
	return path, nil
}

func canonicalSource(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", ErrInvalid
	}
	path := filepath.Join(root, relative)
	if !pathBelow(path, root) {
		return "", ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 4<<30 {
		return "", errors.Join(ErrInvalid, err)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Nlink != 1 {
		return "", ErrIntegrity
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.Join(ErrInvalid, err)
	}
	return path, nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.Join(ErrInvalid, err)
	}
	payload, err := readBoundedRegular(path, 1024, true)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Nlink != 1 {
		return nil, ErrIntegrity
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(payload)))
	if err != nil {
		return nil, ErrInvalid
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, ErrInvalid
	}
}

func readBoundedRegular(path string, maximum int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maximum {
		return nil, ErrInvalid
	}
	if private && before.Mode().Perm()&0077 != 0 {
		return nil, ErrIntegrity
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrIntegrity
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return nil, errors.Join(ErrInvalid, err)
	}
	return payload, nil
}

func readRootOwnedFile(path string, maximum int64, maximumMode os.FileMode) ([]byte, error) {
	payload, err := readBoundedRegular(path, maximum, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err = requireRootOwned(info, maximumMode, false); err != nil {
		return nil, err
	}
	return payload, nil
}

func requireRootOwned(info os.FileInfo, maximumMode os.FileMode, directory bool) error {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || metadata.Gid != 0 || !directory && metadata.Nlink != 1 || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&^maximumMode != 0 || info.Mode().Perm()&0022 != 0 || directory != info.IsDir() {
		return ErrIntegrity
	}
	return nil
}

func digestFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func rejectPackagedAuthority(path string, size int64) error {
	if size > 16<<20 {
		return ErrInvalid
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(payload))
	for _, marker := range []string{
		"begin openssh private key", "begin private key", "begin rsa private key", "begin ec private key",
		"\"private_key\"", "password=", "\"password\"", "secret=", "\"secret\"", "token=", "\"token\"",
		"/etc/machine-id", "ssh_host_", "machine_id", "node_id", "host_identity",
	} {
		if strings.Contains(lower, marker) {
			return ErrIntegrity
		}
	}
	return nil
}

func writeTarBytes(archive *tar.Writer, name string, payload []byte, timestamp time.Time) error {
	header := &tar.Header{Name: name, Mode: 0600, Size: int64(len(payload)), ModTime: timestamp,
		AccessTime: timestamp, ChangeTime: timestamp, Uid: 0, Gid: 0, Uname: "root", Gname: "root", Format: tar.FormatPAX}
	if err := archive.WriteHeader(header); err != nil {
		return err
	}
	_, err := archive.Write(payload)
	return err
}

func writeTarSource(archive *tar.Writer, artifact Artifact, source string, timestamp time.Time) error {
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()
	header := &tar.Header{Name: artifact.PayloadPath(), Mode: 0600, Size: artifact.Size, ModTime: timestamp,
		AccessTime: timestamp, ChangeTime: timestamp, Uid: 0, Gid: 0, Uname: "root", Gname: "root", Format: tar.FormatPAX}
	if err = archive.WriteHeader(header); err != nil {
		return err
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(archive, hasher), io.LimitReader(file, artifact.Size+1))
	if err != nil || written != artifact.Size || hex.EncodeToString(hasher.Sum(nil)) != artifact.SHA256 {
		return errors.Join(ErrIntegrity, err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
