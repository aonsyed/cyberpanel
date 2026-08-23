//go:build linux

package cpanel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanel"
)

const (
	archiveRuntimeVersion             = "cpanel-archive-migrator/v1"
	defaultArchiveRuntimeSeconds      = uint64(6 * 60 * 60)
	maximumArchiveRuntimeSeconds      = uint64(24 * 60 * 60)
	defaultMaximumArtifactBytes       = uint64(256 << 30)
	maximumRuntimeArtifactBytes       = uint64(2 << 40)
	defaultMaximumArchiveEntries      = uint64(2_000_000)
	maximumRuntimeArchiveEntries      = uint64(5_000_000)
	defaultMaximumArchiveExpanded     = uint64(1 << 40)
	maximumRuntimeArchiveExpanded     = uint64(2 << 40)
	defaultMaximumArchiveMetadata     = uint64(64 << 20)
	maximumRuntimeArchiveMetadata     = uint64(256 << 20)
	maximumRuntimeManifestBytes       = int64(32 << 20)
	maximumArchiveRuntimeConfigBytes = int64(1 << 20)
)

// ArchiveRuntimeConfig is deliberately local-only. It contains archive and
// key paths, but no endpoint, username, password, token, or remote command.
type ArchiveRuntimeConfig struct {
	MigrationID                       migration.ID         `json:"migration_id"`
	SourceInstallationID             string               `json:"source_installation_id"`
	Accounts                         map[string]string    `json:"accounts"`
	PlanDirectory                    string               `json:"plan_directory"`
	OutputDirectory                  string               `json:"output_directory"`
	ApprovalKeys                     map[string]string    `json:"approval_keys"`
	AllowedTargetInstallationIDs     []string             `json:"allowed_target_installation_ids"`
	MaximumPlanLifetimeSeconds       uint64               `json:"maximum_plan_lifetime_seconds"`
	ManifestSigningKeyID             string               `json:"manifest_signing_key_id"`
	ManifestSigningPrivateKeyPath    string               `json:"manifest_signing_private_key_path"`
	TargetSealingKeyID               string               `json:"target_sealing_key_id"`
	TargetSealingPublicKey           string               `json:"target_sealing_public_key"`
	ArchiveGateAuthenticationKeyPath string               `json:"archive_gate_authentication_key_path"`
	MaximumRuntimeSeconds            uint64               `json:"maximum_runtime_seconds"`
	Limits                           ArchiveRuntimeLimits `json:"limits"`
}

type ArchiveRuntimeLimits struct {
	MaximumEntries       uint64 `json:"maximum_entries"`
	MaximumExpandedBytes uint64 `json:"maximum_expanded_bytes"`
	MaximumMetadataBytes uint64 `json:"maximum_metadata_bytes"`
	MaximumArtifactBytes uint64 `json:"maximum_artifact_bytes"`
	MaximumChunkBytes    uint64 `json:"maximum_chunk_bytes"`
}

// ArchiveRuntimeResult points at the immutable artifact set and carries the
// signed canonical source model. Secret material appears only as envelopes.
type ArchiveRuntimeResult struct {
	Manifest              migration.Manifest `json:"manifest"`
	ManifestPath          string             `json:"manifest_path"`
	ChunkDirectory        string             `json:"chunk_directory"`
	ArchiveEvidenceDigest string             `json:"archive_evidence_digest"`
	ArchiveLeaseExpiresAt time.Time          `json:"archive_lease_expires_at"`
}

func LoadArchiveRuntimeConfig(path string) (ArchiveRuntimeConfig, error) {
	var config ArchiveRuntimeConfig
	raw, err := readArchiveRuntimeFile(path, maximumArchiveRuntimeConfigBytes, false)
	if err != nil {
		return config, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil {
		return ArchiveRuntimeConfig{}, errors.Join(ErrInvalid, err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ArchiveRuntimeConfig{}, ErrInvalid
	}
	return normalizeArchiveRuntimeConfig(config)
}

// RunArchive consumes only archives named in a signed local plan. The caller
// must install a kernel policy that denies AF_INET and AF_INET6 socket creation;
// the runtime checks that policy before touching an archive.
func RunArchive(ctx context.Context, config ArchiveRuntimeConfig) (result ArchiveRuntimeResult, err error) {
	if ctx == nil {
		return result, ErrInvalid
	}
	if os.Geteuid() == 0 {
		return result, errors.Join(ErrDenied, errors.New("cPanel archive migration refuses to run as root"))
	}
	if err = requireNetworklessArchiveRuntime(); err != nil {
		return result, err
	}
	config, err = normalizeArchiveRuntimeConfig(config)
	if err != nil {
		return result, err
	}
	runContext, cancel := context.WithTimeout(ctx, time.Duration(config.MaximumRuntimeSeconds)*time.Second)
	defer cancel()

	if err = validatePrivateArchiveDirectory(config.PlanDirectory); err != nil {
		return result, fmt.Errorf("validate plan directory: %w", err)
	}
	plans, err := OpenFilePlanStore(config.PlanDirectory)
	if err != nil {
		return result, err
	}
	defer joinArchiveClose(&err, plans.Close)
	approved, err := plans.ApprovedPlan(runContext, config.MigrationID)
	if err != nil {
		return result, err
	}
	approvalKeys, err := archiveApprovalKeys(config.ApprovalKeys)
	if err != nil {
		return result, err
	}
	allowedTargets := make(map[string]struct{}, len(config.AllowedTargetInstallationIDs))
	for _, target := range config.AllowedTargetInstallationIDs {
		allowedTargets[target] = struct{}{}
	}
	planVerifier, err := NewLocalApprovalVerifier(LocalApprovalPolicy{
		SourceInstallationID: config.SourceInstallationID,
		Keys:                 approvalKeys,
		MaximumLifetime:      time.Duration(config.MaximumPlanLifetimeSeconds) * time.Second,
		AllowedTargets:       allowedTargets,
		AllowedSchemaHashes:  map[string]struct{}{CanonicalManifestSchemaHash(): {}},
	})
	if err != nil {
		return result, err
	}
	if err = planVerifier.VerifyApprovedPlan(runContext, approved, time.Now().UTC()); err != nil {
		return result, err
	}
	if approved.Plan.MigrationID != config.MigrationID || approved.Plan.SourceInstallationID != config.SourceInstallationID {
		return result, ErrDenied
	}
	approvalDigest, err := archiveApprovedPlanDigest(approved)
	if err != nil {
		return result, err
	}

	outputRoot, err := openPrivateArchiveRoot(config.OutputDirectory)
	if err != nil {
		return result, fmt.Errorf("open output directory: %w", err)
	}
	defer joinArchiveClose(&err, outputRoot.Close)
	chunkDirectory, err := ensurePrivateArchiveChild(outputRoot, config.OutputDirectory, "chunks")
	if err != nil {
		return result, err
	}
	artifactDirectory, err := os.MkdirTemp(config.OutputDirectory, ".cpanel-artifacts-")
	if err != nil {
		return result, err
	}
	defer func() {
		if cleanupErr := removeArchiveTemporaryDirectory(config.OutputDirectory, artifactDirectory); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()
	if err = validatePrivateArchiveDirectory(artifactDirectory); err != nil {
		return result, err
	}

	artifacts, err := cyberpanel.OpenMaterializedCatalog(artifactDirectory, nil, config.Limits.MaximumArtifactBytes)
	if err != nil {
		return result, err
	}
	defer joinArchiveClose(&err, artifacts.Close)
	chunks, err := migration.OpenChunkStore(chunkDirectory, config.Limits.MaximumChunkBytes)
	if err != nil {
		return result, err
	}
	defer joinArchiveClose(&err, chunks.Close)
	source, err := NewArchiveSource(ArchiveSourceConfig{
		InstallationID: config.SourceInstallationID,
		Accounts:       config.Accounts,
		Artifacts:      artifacts,
		Limits: ArchiveLimits{
			MaximumEntries:       config.Limits.MaximumEntries,
			MaximumExpandedBytes: config.Limits.MaximumExpandedBytes,
			MaximumMetadataBytes: config.Limits.MaximumMetadataBytes,
		},
	})
	if err != nil {
		return result, err
	}
	defer joinArchiveClose(&err, source.Close)

	gateKey, err := readArchiveRuntimeHexKey(config.ArchiveGateAuthenticationKeyPath, 32)
	if err != nil {
		return result, err
	}
	defer wipe(gateKey)
	gate, err := NewArchiveGate(ArchiveGateConfig{
		Source:            source,
		AuthenticationKey: gateKey,
		LeaseDuration:     time.Duration(config.MaximumRuntimeSeconds) * time.Second,
	})
	if err != nil {
		return result, err
	}
	defer joinArchiveClose(&err, gate.Close)

	signingKeyBytes, err := readArchiveRuntimeHexKey(config.ManifestSigningPrivateKeyPath, ed25519.PrivateKeySize)
	if err != nil {
		return result, err
	}
	defer wipe(signingKeyBytes)
	signingKey := ed25519.PrivateKey(signingKeyBytes)
	targetPublicKey, err := decodeArchiveRuntimeHex(config.TargetSealingPublicKey, 32)
	if err != nil {
		return result, err
	}
	sealer, err := NewX25519Sealer(config.TargetSealingKeyID, targetPublicKey)
	if err != nil {
		return result, err
	}
	extractor, err := NewExtractor(ExtractorConfig{
		PlanStore:        plans,
		PlanVerifier:     planVerifier,
		Collector:        source,
		Artifacts:        source,
		Secrets:          source,
		Sealer:           sealer,
		Chunks:           chunks,
		SigningKeyID:     config.ManifestSigningKeyID,
		SigningKey:       signingKey,
		ExtractorVersion: archiveRuntimeVersion,
	})
	if err != nil {
		return result, err
	}
	defer joinArchiveClose(&err, extractor.Close)

	gateBindingDigest := approved.Plan.TargetPlanDigest
	if gateBindingDigest == "" {
		// Inventory precedes target planning, so its immutable-read lease binds
		// to the signed source approval until a target plan digest exists.
		gateBindingDigest = approvalDigest
	}
	lease, err := gate.Freeze(runContext, GateScope{
		MigrationID:         config.MigrationID,
		SourceInstallationID: config.SourceInstallationID,
		SiteSourceIDs:       append([]string(nil), approved.Plan.SiteSourceIDs...),
		Mode:                approved.Plan.QuiesceMode,
		ExpectedFence:       1,
		TargetPlanDigest:    gateBindingDigest,
		ApprovalDigest:      approvalDigest,
	})
	if err != nil {
		return result, err
	}
	manifest, err := extractor.Discover(runContext, config.MigrationID)
	if err != nil {
		return result, err
	}
	if manifest.Source != migration.SourceCPanel || manifest.SourceInstallationID != config.SourceInstallationID || manifest.TargetInstallationID != approved.Plan.TargetInstallationID || manifest.MigrationID != config.MigrationID || manifest.SchemaHash != CanonicalManifestSchemaHash() {
		return result, migration.ErrInvalid
	}
	if err = planVerifier.VerifyApprovedPlan(runContext, approved, time.Now().UTC()); err != nil {
		return result, err
	}
	if err = gate.Verify(runContext, ComponentAction{
		MigrationID:     config.MigrationID,
		SiteSourceIDs:   append([]string(nil), approved.Plan.SiteSourceIDs...),
		SourceGeneration: manifest.SourceGeneration,
		ExpectedFence:   1,
		FenceDigest:     manifest.MerkleRoot,
		Token:           lease.Token,
	}); err != nil {
		return result, err
	}
	publicKey := append(ed25519.PublicKey(nil), signingKey.Public().(ed25519.PublicKey)...)
	manifestVerifier, err := migration.NewSignedManifestVerifier(migration.ManifestTrustPolicy{
		TargetInstallationID: manifest.TargetInstallationID,
		SchemaHashes:         map[string]struct{}{CanonicalManifestSchemaHash(): {}},
		Keys:                 map[string]ed25519.PublicKey{config.ManifestSigningKeyID: publicKey},
	})
	if err != nil {
		return result, err
	}
	if err = manifestVerifier.Verify(runContext, manifest); err != nil {
		return result, err
	}
	manifestPath, err := writeArchiveManifest(outputRoot, config.OutputDirectory, manifest)
	if err != nil {
		return result, err
	}
	return ArchiveRuntimeResult{
		Manifest:              manifest,
		ManifestPath:          manifestPath,
		ChunkDirectory:        chunkDirectory,
		ArchiveEvidenceDigest: lease.EvidenceDigest,
		ArchiveLeaseExpiresAt: lease.ExpiresAt.UTC(),
	}, nil
}

func normalizeArchiveRuntimeConfig(config ArchiveRuntimeConfig) (ArchiveRuntimeConfig, error) {
	if !config.MigrationID.Valid() || !boundedArchiveRuntimeText(config.SourceInstallationID, 256) || len(config.Accounts) == 0 || len(config.Accounts) > 1000 || len(config.ApprovalKeys) == 0 || len(config.ApprovalKeys) > 64 || len(config.AllowedTargetInstallationIDs) == 0 || len(config.AllowedTargetInstallationIDs) > 64 || !boundedArchiveRuntimeText(config.ManifestSigningKeyID, 128) || !boundedArchiveRuntimeText(config.TargetSealingKeyID, 128) {
		return ArchiveRuntimeConfig{}, ErrInvalid
	}
	for _, path := range []string{config.PlanDirectory, config.OutputDirectory, config.ManifestSigningPrivateKeyPath, config.ArchiveGateAuthenticationKeyPath} {
		if !canonicalArchiveRuntimePath(path) {
			return ArchiveRuntimeConfig{}, ErrInvalid
		}
	}
	for accountID, path := range config.Accounts {
		if !validAccountID(accountID) || !canonicalArchiveRuntimePath(path) {
			return ArchiveRuntimeConfig{}, ErrInvalid
		}
	}
	seenTargets := map[string]struct{}{}
	for _, target := range config.AllowedTargetInstallationIDs {
		if !boundedArchiveRuntimeText(target, 256) {
			return ArchiveRuntimeConfig{}, ErrInvalid
		}
		if _, duplicate := seenTargets[target]; duplicate {
			return ArchiveRuntimeConfig{}, ErrInvalid
		}
		seenTargets[target] = struct{}{}
	}
	if config.MaximumPlanLifetimeSeconds == 0 {
		config.MaximumPlanLifetimeSeconds = 24 * 60 * 60
	}
	if config.MaximumPlanLifetimeSeconds < 60 || config.MaximumPlanLifetimeSeconds > 30*24*60*60 {
		return ArchiveRuntimeConfig{}, ErrInvalid
	}
	if config.MaximumRuntimeSeconds == 0 {
		config.MaximumRuntimeSeconds = defaultArchiveRuntimeSeconds
	}
	if config.MaximumRuntimeSeconds < 60 || config.MaximumRuntimeSeconds > maximumArchiveRuntimeSeconds {
		return ArchiveRuntimeConfig{}, ErrInvalid
	}
	if config.Limits.MaximumEntries == 0 {
		config.Limits.MaximumEntries = defaultMaximumArchiveEntries
	}
	if config.Limits.MaximumExpandedBytes == 0 {
		config.Limits.MaximumExpandedBytes = defaultMaximumArchiveExpanded
	}
	if config.Limits.MaximumMetadataBytes == 0 {
		config.Limits.MaximumMetadataBytes = defaultMaximumArchiveMetadata
	}
	if config.Limits.MaximumArtifactBytes == 0 {
		config.Limits.MaximumArtifactBytes = defaultMaximumArtifactBytes
	}
	if config.Limits.MaximumChunkBytes == 0 {
		config.Limits.MaximumChunkBytes = defaultMaximumArtifactBytes
	}
	if config.Limits.MaximumEntries > maximumRuntimeArchiveEntries || config.Limits.MaximumExpandedBytes < 1<<20 || config.Limits.MaximumExpandedBytes > maximumRuntimeArchiveExpanded || config.Limits.MaximumMetadataBytes < 1<<20 || config.Limits.MaximumMetadataBytes > maximumRuntimeArchiveMetadata || config.Limits.MaximumArtifactBytes < 1<<20 || config.Limits.MaximumArtifactBytes > maximumRuntimeArtifactBytes || config.Limits.MaximumChunkBytes < 1<<20 || config.Limits.MaximumChunkBytes > maximumRuntimeArtifactBytes {
		return ArchiveRuntimeConfig{}, ErrInvalid
	}
	if _, err := archiveApprovalKeys(config.ApprovalKeys); err != nil {
		return ArchiveRuntimeConfig{}, err
	}
	if _, err := decodeArchiveRuntimeHex(config.TargetSealingPublicKey, 32); err != nil {
		return ArchiveRuntimeConfig{}, err
	}
	return config, nil
}

func archiveApprovalKeys(encoded map[string]string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for keyID, value := range encoded {
		if !boundedArchiveRuntimeText(keyID, 128) {
			return nil, ErrInvalid
		}
		raw, err := decodeArchiveRuntimeHex(value, ed25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		keys[keyID] = ed25519.PublicKey(raw)
	}
	return keys, nil
}

func archiveApprovedPlanDigest(approved ApprovedPlan) (string, error) {
	approved.Signature = nil
	approved.Plan.SiteSourceIDs = append([]string(nil), approved.Plan.SiteSourceIDs...)
	sort.Strings(approved.Plan.SiteSourceIDs)
	raw, err := json.Marshal(approved)
	if err != nil {
		return "", err
	}
	message := append([]byte("cyberpanel-source-plan-v1\x00"), raw...)
	sum := sha256.Sum256(message)
	return hex.EncodeToString(sum[:]), nil
}

func requireNetworklessArchiveRuntime() error {
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		descriptor, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err == nil {
			_ = syscall.Close(descriptor)
			return errors.Join(ErrDenied, errors.New("cPanel archive migration requires AF_INET and AF_INET6 to be denied by the process sandbox"))
		}
		if !errors.Is(err, syscall.EAFNOSUPPORT) && !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
			return errors.Join(ErrDenied, err)
		}
	}
	return nil
}

func openPrivateArchiveRoot(path string) (*os.Root, error) {
	if err := validatePrivateArchiveDirectory(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = root.Close()
		return nil, ErrArchiveChanged
	}
	return root, nil
}

func validatePrivateArchiveDirectory(path string) error {
	if !canonicalArchiveRuntimePath(path) {
		return ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || !archiveRuntimeOwner(info, false) {
		return ErrDenied
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return ErrDenied
	}
	return nil
}

func ensurePrivateArchiveChild(root *os.Root, rootPath, name string) (string, error) {
	if root == nil || name == "" || filepath.Base(name) != name {
		return "", ErrInvalid
	}
	if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := root.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || !archiveRuntimeOwner(info, false) {
		return "", errors.Join(ErrDenied, err)
	}
	return filepath.Join(rootPath, name), nil
}

func removeArchiveTemporaryDirectory(rootPath, temporary string) error {
	prefix := filepath.Join(rootPath, ".cpanel-artifacts-")
	if temporary == "" || !strings.HasPrefix(temporary, prefix) || filepath.Dir(temporary) != rootPath {
		return ErrDenied
	}
	return os.RemoveAll(temporary)
}

func writeArchiveManifest(root *os.Root, rootPath string, manifest migration.Manifest) (string, error) {
	if root == nil || !manifest.MigrationID.Valid() {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(manifest)
	if err != nil || int64(len(raw)) > maximumRuntimeManifestBytes {
		return "", errors.Join(migration.ErrCapacity, err)
	}
	raw = append(raw, '\n')
	name := manifest.MigrationID.String() + ".manifest.json"
	if same, verifyErr := verifyArchiveManifestFile(root, name, raw); verifyErr != nil || same {
		if same {
			return filepath.Join(rootPath, name), nil
		}
		if !errors.Is(verifyErr, os.ErrNotExist) {
			return "", verifyErr
		}
	}
	randomValue := make([]byte, 16)
	if _, err = rand.Read(randomValue); err != nil {
		return "", err
	}
	temporary := ".manifest-" + hex.EncodeToString(randomValue)
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	keep := true
	defer func() {
		_ = file.Close()
		if keep {
			_ = root.Remove(temporary)
		}
	}()
	if err = writeArchiveRuntimeBytes(file, raw); err != nil {
		return "", err
	}
	if err = file.Sync(); err != nil {
		return "", err
	}
	if err = file.Chmod(0o400); err != nil {
		return "", err
	}
	if err = file.Close(); err != nil {
		return "", err
	}
	if err = root.Link(temporary, name); err != nil {
		if same, verifyErr := verifyArchiveManifestFile(root, name, raw); verifyErr != nil || !same {
			return "", errors.Join(err, verifyErr, migration.ErrConflict)
		}
	}
	if err = root.Remove(temporary); err != nil {
		return "", err
	}
	keep = false
	directory, err := os.Open(rootPath)
	if err != nil {
		return "", err
	}
	err = errors.Join(directory.Sync(), directory.Close())
	if err != nil {
		return "", err
	}
	return filepath.Join(rootPath, name), nil
}

func verifyArchiveManifestFile(root *os.Root, name string, expected []byte) (bool, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return false, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 || before.Size() != int64(len(expected)) {
		return false, migration.ErrConflict
	}
	file, err := root.Open(name)
	if err != nil {
		return false, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return false, errors.Join(ErrArchiveChanged, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumRuntimeManifestBytes+2))
	if err != nil {
		return false, err
	}
	final, err := file.Stat()
	if err != nil || !sameFileSnapshot(after, final) {
		return false, errors.Join(ErrArchiveChanged, err)
	}
	return bytes.Equal(raw, expected), nil
}

func writeArchiveRuntimeBytes(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
		value = value[count:]
	}
	return nil
}

func readArchiveRuntimeHexKey(path string, size int) ([]byte, error) {
	raw, err := readArchiveRuntimeFile(path, int64(size*2+2), true)
	if err != nil {
		return nil, err
	}
	return decodeArchiveRuntimeHex(string(raw), size)
}

func decodeArchiveRuntimeHex(value string, size int) ([]byte, error) {
	value = strings.TrimSpace(value)
	if size < 1 || len(value) != size*2 {
		return nil, ErrInvalid
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != size {
		return nil, ErrInvalid
	}
	return raw, nil
}

func readArchiveRuntimeFile(path string, maximum int64, private bool) ([]byte, error) {
	if !canonicalArchiveRuntimePath(path) || maximum < 1 {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximum || before.Mode().Perm()&0o022 != 0 || private && before.Mode().Perm()&0o077 != 0 || !archiveRuntimeOwner(before, true) {
		return nil, ErrDenied
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !sameFileSnapshot(before, after) {
		return nil, errors.Join(ErrArchiveChanged, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum || int64(len(raw)) != after.Size() {
		return nil, errors.Join(ErrInvalid, err)
	}
	final, err := file.Stat()
	if err != nil || !sameFileSnapshot(after, final) {
		return nil, errors.Join(ErrArchiveChanged, err)
	}
	return raw, nil
}

func archiveRuntimeOwner(info os.FileInfo, allowRoot bool) bool {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	owner := int(metadata.Uid)
	return owner == os.Geteuid() || allowRoot && owner == 0
}

func canonicalArchiveRuntimePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func boundedArchiveRuntimeText(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func joinArchiveClose(target *error, close func() error) {
	if target != nil && close != nil {
		*target = errors.Join(*target, close())
	}
}
