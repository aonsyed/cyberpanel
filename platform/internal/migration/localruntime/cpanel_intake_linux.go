//go:build linux

package localruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
)

const (
	DefaultCPanelIntakePath     = "/var/lib/cyberpanel/migration/cpanel-intake"
	DefaultCPanelQuarantinePath = "/var/lib/cyberpanel/migration/cpanel-quarantine"
	maximumCPanelManifestBytes  = int64(32<<20) + 1
	defaultCPanelBundleBytes    = uint64(2 << 40)
)

// CPanelAdmission is the result of accepting an already-canonical bundle.
// Archive parsing remains entirely inside the disposable migrator.
type CPanelAdmission struct {
	Manifest       migration.Manifest
	SourceEndpoint string
}

type cPanelIntake struct {
	intakePath     string
	quarantinePath string
	maximumBytes   uint64
	verifier       migration.ManifestVerifier
	clock          func() time.Time
	mu             sync.Mutex
}

type cPanelAdmissionReceipt struct {
	Version          uint32       `json:"version"`
	TenantID         string       `json:"tenant_id"`
	MigrationID      migration.ID `json:"migration_id"`
	ManifestRoot     string       `json:"manifest_root"`
	SourcePathDigest string       `json:"source_path_digest"`
	AdmittedAt       time.Time    `json:"admitted_at"`
}

type verifiedCPanelBundle struct {
	manifest migration.Manifest
	path     string
	identity os.FileInfo
}

func newCPanelIntake(intakePath, quarantinePath string, maximumBytes uint64, verifier migration.ManifestVerifier) (*cPanelIntake, error) {
	if verifier == nil || !canonicalLocalPath(intakePath) || !canonicalLocalPath(quarantinePath) || intakePath == quarantinePath {
		return nil, migration.ErrInvalid
	}
	if maximumBytes == 0 {
		maximumBytes = defaultCPanelBundleBytes
	}
	if maximumBytes < 1<<20 || maximumBytes > defaultCPanelBundleBytes {
		return nil, migration.ErrInvalid
	}
	if err := ensurePrivateDirectory(intakePath); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(quarantinePath); err != nil {
		return nil, err
	}
	intakeInfo, err := os.Lstat(intakePath)
	if err != nil {
		return nil, err
	}
	quarantineInfo, err := os.Lstat(quarantinePath)
	if err != nil || !sameFilesystem(intakeInfo, quarantineInfo) {
		return nil, errors.Join(migration.ErrBlocked, err)
	}
	return &cPanelIntake{intakePath: intakePath, quarantinePath: quarantinePath, maximumBytes: maximumBytes, verifier: verifier, clock: time.Now}, nil
}

func (intake *cPanelIntake) Available() bool {
	return intake != nil && intake.verifier != nil && intake.validateRoots() == nil
}

func (intake *cPanelIntake) Ready() bool {
	if !intake.Available() {
		return false
	}
	verifier, configured := intake.verifier.(configuredManifestVerifier)
	if !configured {
		return true
	}
	policy, err := loadTrustPolicy(verifier.path)
	if err != nil {
		return false
	}
	_, err = migration.NewSignedManifestVerifier(policy)
	return err == nil
}

func (intake *cPanelIntake) Admit(ctx context.Context, tenantID, endpoint string) (CPanelAdmission, error) {
	if !intake.Ready() || ctx == nil || !runtimeScopeText(tenantID, 128) {
		return CPanelAdmission{}, migration.ErrInvalid
	}
	bundlePath, err := intake.intakeBundlePath(endpoint)
	if err != nil {
		return CPanelAdmission{}, err
	}
	verified, err := intake.verifyBundle(ctx, bundlePath)
	if err != nil {
		return CPanelAdmission{}, err
	}
	receipt := cPanelAdmissionReceipt{
		Version:          1,
		TenantID:         tenantID,
		MigrationID:      verified.manifest.MigrationID,
		ManifestRoot:     verified.manifest.MerkleRoot,
		SourcePathDigest: digestLocalPath(bundlePath),
		AdmittedAt:       intake.clock().UTC(),
	}
	claimPath := filepath.Join(intake.quarantinePath, receipt.ManifestRoot)
	quarantinedPath := filepath.Join(claimPath, "bundle")

	intake.mu.Lock()
	defer intake.mu.Unlock()
	select {
	case <-ctx.Done():
		return CPanelAdmission{}, ctx.Err()
	default:
	}
	if err = os.Mkdir(claimPath, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return intake.resumeCPanelAdmission(ctx, receipt, verified)
		}
		return CPanelAdmission{}, err
	}
	moved := false
	defer func() {
		if !moved {
			_ = os.Remove(filepath.Join(claimPath, "admission.json"))
			_ = os.Remove(claimPath)
		}
	}()
	if err = writeCPanelReceipt(claimPath, receipt); err != nil {
		return CPanelAdmission{}, err
	}
	current, err := os.Lstat(bundlePath)
	if err != nil || !sameOwnedDirectory(verified.identity, current) {
		return CPanelAdmission{}, errors.Join(migration.ErrConflict, err)
	}
	if err = os.Rename(bundlePath, quarantinedPath); err != nil {
		return CPanelAdmission{}, err
	}
	moved = true
	if err = errors.Join(syncLocalDirectory(intake.intakePath), syncLocalDirectory(claimPath), syncLocalDirectory(intake.quarantinePath)); err != nil {
		return CPanelAdmission{}, err
	}
	quarantined, err := intake.verifyBundle(ctx, quarantinedPath)
	if err != nil {
		return CPanelAdmission{}, err
	}
	if quarantined.manifest.MigrationID != receipt.MigrationID || quarantined.manifest.MerkleRoot != receipt.ManifestRoot || !os.SameFile(verified.identity, quarantined.identity) {
		return CPanelAdmission{}, migration.ErrConflict
	}
	return CPanelAdmission{Manifest: quarantined.manifest, SourceEndpoint: localFileEndpoint(quarantinedPath)}, nil
}

func (intake *cPanelIntake) resumeCPanelAdmission(ctx context.Context, expected cPanelAdmissionReceipt, source verifiedCPanelBundle) (CPanelAdmission, error) {
	claimPath := filepath.Join(intake.quarantinePath, expected.ManifestRoot)
	claimInfo, err := os.Lstat(claimPath)
	if err != nil || !ownedDirectory(claimInfo) {
		return CPanelAdmission{}, errors.Join(migration.ErrConflict, err)
	}
	resolved, err := filepath.EvalSymlinks(claimPath)
	if err != nil || resolved != claimPath {
		return CPanelAdmission{}, errors.Join(migration.ErrConflict, err)
	}
	receipt, err := readCPanelReceipt(filepath.Join(claimPath, "admission.json"))
	if err != nil || receipt.Version != expected.Version || receipt.TenantID != expected.TenantID || receipt.MigrationID != expected.MigrationID || receipt.ManifestRoot != expected.ManifestRoot || receipt.SourcePathDigest != expected.SourcePathDigest || receipt.AdmittedAt.IsZero() {
		return CPanelAdmission{}, errors.Join(migration.ErrConflict, err)
	}
	quarantinedPath := filepath.Join(claimPath, "bundle")
	quarantined, err := intake.verifyBundle(ctx, quarantinedPath)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		current, statErr := os.Lstat(source.path)
		if statErr != nil || !sameOwnedDirectory(source.identity, current) {
			return CPanelAdmission{}, errors.Join(migration.ErrConflict, statErr)
		}
		if err = os.Rename(source.path, quarantinedPath); err != nil {
			return CPanelAdmission{}, err
		}
		if err = errors.Join(syncLocalDirectory(intake.intakePath), syncLocalDirectory(claimPath), syncLocalDirectory(intake.quarantinePath)); err != nil {
			return CPanelAdmission{}, err
		}
		quarantined, err = intake.verifyBundle(ctx, quarantinedPath)
	}
	if err != nil || quarantined.manifest.MigrationID != expected.MigrationID || quarantined.manifest.MerkleRoot != expected.ManifestRoot {
		return CPanelAdmission{}, errors.Join(migration.ErrConflict, err)
	}
	return CPanelAdmission{Manifest: quarantined.manifest, SourceEndpoint: localFileEndpoint(quarantinedPath)}, nil
}

func (intake *cPanelIntake) Discover(ctx context.Context, scope migration.RuntimeScope) (migration.Manifest, error) {
	bundle, err := intake.quarantinedBundle(ctx, scope)
	if err != nil {
		return migration.Manifest{}, err
	}
	return bundle.manifest, nil
}

func (intake *cPanelIntake) OpenChunk(ctx context.Context, scope migration.RuntimeScope, digest string, offset, length uint64) ([]byte, error) {
	bundle, err := intake.quarantinedBundle(ctx, scope)
	if err != nil {
		return nil, err
	}
	var descriptor migration.Chunk
	found := false
	for _, candidate := range bundle.manifest.Chunks {
		if candidate.Digest == digest {
			descriptor, found = candidate, true
			break
		}
	}
	if !found || length == 0 || offset > descriptor.Size || length > descriptor.Size-offset {
		return nil, migration.ErrInvalid
	}
	chunks, err := migration.OpenChunkStore(filepath.Join(bundle.path, "chunks"), intake.maximumBytes)
	if err != nil {
		return nil, err
	}
	defer chunks.Close()
	return chunks.ReadRange(ctx, digest, offset, length)
}

func (intake *cPanelIntake) Generation(ctx context.Context, scope migration.RuntimeScope) (uint64, error) {
	manifest, err := intake.Discover(ctx, scope)
	if err != nil {
		return 0, err
	}
	return manifest.SourceGeneration, nil
}

func (intake *cPanelIntake) OwnsEndpoint(endpoint string) bool {
	if !intake.Available() {
		return false
	}
	path, err := parseLocalFileEndpoint(endpoint)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(intake.quarantinePath, path)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	return len(parts) == 2 && isLocalDigest(parts[0]) && parts[1] == "bundle"
}

func (intake *cPanelIntake) validateRoots() error {
	if intake == nil || !canonicalLocalPath(intake.intakePath) || !canonicalLocalPath(intake.quarantinePath) || intake.intakePath == intake.quarantinePath {
		return migration.ErrInvalid
	}
	intakeInfo, err := os.Lstat(intake.intakePath)
	if err != nil || !ownedDirectory(intakeInfo) {
		return errors.Join(migration.ErrBlocked, err)
	}
	quarantineInfo, err := os.Lstat(intake.quarantinePath)
	if err != nil || !ownedDirectory(quarantineInfo) || !sameFilesystem(intakeInfo, quarantineInfo) {
		return errors.Join(migration.ErrBlocked, err)
	}
	for _, path := range []string{intake.intakePath, intake.quarantinePath} {
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil || resolved != path {
			return errors.Join(migration.ErrBlocked, resolveErr)
		}
	}
	return nil
}

func (intake *cPanelIntake) quarantinedBundle(ctx context.Context, scope migration.RuntimeScope) (verifiedCPanelBundle, error) {
	if !intake.Available() || ctx == nil || !scope.MigrationID.Valid() || !runtimeScopeText(scope.TenantID, 128) || !intake.OwnsEndpoint(scope.SourceEndpoint) {
		return verifiedCPanelBundle{}, migration.ErrInvalid
	}
	bundlePath, err := parseLocalFileEndpoint(scope.SourceEndpoint)
	if err != nil {
		return verifiedCPanelBundle{}, err
	}
	claimPath := filepath.Dir(bundlePath)
	receipt, err := readCPanelReceipt(filepath.Join(claimPath, "admission.json"))
	if err != nil {
		return verifiedCPanelBundle{}, err
	}
	if receipt.Version != 1 || receipt.TenantID != scope.TenantID || receipt.MigrationID != scope.MigrationID || receipt.ManifestRoot != filepath.Base(claimPath) || !isLocalDigest(receipt.ManifestRoot) || !isLocalDigest(receipt.SourcePathDigest) || receipt.AdmittedAt.IsZero() {
		return verifiedCPanelBundle{}, migration.ErrConflict
	}
	claimInfo, err := os.Lstat(claimPath)
	if err != nil || !ownedDirectory(claimInfo) {
		return verifiedCPanelBundle{}, errors.Join(migration.ErrBlocked, err)
	}
	resolved, err := filepath.EvalSymlinks(claimPath)
	if err != nil || resolved != claimPath {
		return verifiedCPanelBundle{}, errors.Join(migration.ErrBlocked, err)
	}
	bundle, err := intake.verifyBundle(ctx, bundlePath)
	if err != nil {
		return verifiedCPanelBundle{}, err
	}
	if bundle.manifest.MigrationID != scope.MigrationID || bundle.manifest.MerkleRoot != receipt.ManifestRoot {
		return verifiedCPanelBundle{}, migration.ErrConflict
	}
	return bundle, nil
}

func (intake *cPanelIntake) intakeBundlePath(endpoint string) (string, error) {
	path, err := parseLocalFileEndpoint(endpoint)
	if err != nil || filepath.Dir(path) != intake.intakePath || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return "", migration.ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.Join(migration.ErrBlocked, err)
	}
	return path, nil
}

func (intake *cPanelIntake) verifyBundle(ctx context.Context, path string) (verifiedCPanelBundle, error) {
	if ctx == nil || !canonicalLocalPath(path) {
		return verifiedCPanelBundle{}, migration.ErrInvalid
	}
	identity, err := os.Lstat(path)
	if err != nil || !ownedDirectory(identity) {
		return verifiedCPanelBundle{}, errors.Join(migration.ErrBlocked, err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return verifiedCPanelBundle{}, errors.Join(migration.ErrBlocked, err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return verifiedCPanelBundle{}, err
	}
	manifestName := ""
	for _, entry := range entries {
		if entry.Name() == "chunks" && entry.IsDir() {
			continue
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".manifest.json") && manifestName == "" {
			manifestName = entry.Name()
			continue
		}
		return verifiedCPanelBundle{}, migration.ErrInvalid
	}
	if manifestName == "" || len(entries) != 2 {
		return verifiedCPanelBundle{}, migration.ErrInvalid
	}
	manifestPath := filepath.Join(path, manifestName)
	raw, _, err := readOwnedLocalFile(manifestPath, maximumCPanelManifestBytes)
	if err != nil {
		return verifiedCPanelBundle{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest migration.Manifest
	if err = decoder.Decode(&manifest); err != nil {
		return verifiedCPanelBundle{}, migration.ErrInvalid
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return verifiedCPanelBundle{}, migration.ErrInvalid
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return verifiedCPanelBundle{}, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return verifiedCPanelBundle{}, migration.ErrInvalid
	}
	if manifest.Source != migration.SourceCPanel || manifestName != manifest.MigrationID.String()+".manifest.json" {
		return verifiedCPanelBundle{}, migration.ErrInvalid
	}
	if err = intake.verifier.Verify(ctx, manifest); err != nil {
		return verifiedCPanelBundle{}, err
	}
	if err = intake.auditBundleTree(ctx, path, manifest); err != nil {
		return verifiedCPanelBundle{}, err
	}
	total := uint64(0)
	chunks, err := migration.OpenChunkStore(filepath.Join(path, "chunks"), intake.maximumBytes)
	if err != nil {
		return verifiedCPanelBundle{}, err
	}
	for _, descriptor := range manifest.Chunks {
		if descriptor.Size == 0 || descriptor.Size > intake.maximumBytes-total {
			err = migration.ErrCapacity
			break
		}
		total += descriptor.Size
		if err = chunks.Verify(ctx, descriptor); err != nil {
			break
		}
	}
	err = errors.Join(err, chunks.Close())
	if err != nil {
		return verifiedCPanelBundle{}, err
	}
	if err = intake.auditBundleTree(ctx, path, manifest); err != nil {
		return verifiedCPanelBundle{}, err
	}
	finalRaw, _, err := readOwnedLocalFile(manifestPath, maximumCPanelManifestBytes)
	if err != nil || !bytes.Equal(raw, finalRaw) {
		return verifiedCPanelBundle{}, errors.Join(migration.ErrConflict, err)
	}
	current, err := os.Lstat(path)
	if err != nil || !sameOwnedDirectory(identity, current) {
		return verifiedCPanelBundle{}, errors.Join(migration.ErrConflict, err)
	}
	return verifiedCPanelBundle{manifest: manifest, path: path, identity: identity}, nil
}

func (intake *cPanelIntake) auditBundleTree(ctx context.Context, root string, manifest migration.Manifest) error {
	expected := map[string]bool{
		".": true,
		manifest.MigrationID.String() + ".manifest.json": false,
		"chunks": true,
		filepath.Join("chunks", "sha256"): true,
	}
	for _, descriptor := range manifest.Chunks {
		prefix := filepath.Join("chunks", "sha256", descriptor.Digest[:2])
		expected[prefix] = true
		expected[filepath.Join(prefix, descriptor.Digest)] = false
	}
	seen := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || strings.HasPrefix(filepath.ToSlash(relative), "../") {
			return migration.ErrInvalid
		}
		directory, allowed := expected[relative]
		if !allowed {
			return migration.ErrInvalid
		}
		info, err := entry.Info()
		if err != nil || directory && !ownedDirectory(info) || !directory && !ownedImmutableFile(info) {
			return errors.Join(migration.ErrBlocked, err)
		}
		seen[relative] = struct{}{}
		return nil
	})
	if err != nil || len(seen) != len(expected) {
		return errors.Join(migration.ErrInvalid, err)
	}
	return nil
}

func writeCPanelReceipt(claimPath string, receipt cPanelAdmissionReceipt) error {
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := filepath.Join(claimPath, "admission.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err = writeLocalBytes(file, raw); err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = file.Chmod(0o400)
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	return syncLocalDirectory(claimPath)
}

func readCPanelReceipt(path string) (cPanelAdmissionReceipt, error) {
	var receipt cPanelAdmissionReceipt
	raw, _, err := readOwnedLocalFile(path, 16<<10)
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&receipt); err != nil {
		return cPanelAdmissionReceipt{}, migration.ErrInvalid
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return cPanelAdmissionReceipt{}, migration.ErrInvalid
	}
	return receipt, nil
}

func readOwnedLocalFile(path string, maximum int64) ([]byte, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || maximum < 1 || !ownedImmutableFile(before) || before.Size() < 1 || before.Size() > maximum {
		return nil, nil, errors.Join(migration.ErrBlocked, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !ownedImmutableFile(after) {
		return nil, nil, errors.Join(migration.ErrConflict, err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != after.Size() || int64(len(raw)) > maximum {
		return nil, nil, errors.Join(migration.ErrInvalid, err)
	}
	final, err := file.Stat()
	if err != nil || !sameOwnedFile(after, final) {
		return nil, nil, errors.Join(migration.ErrConflict, err)
	}
	return raw, final, nil
}

func ownedDirectory(info os.FileInfo) bool {
	metadata, ok := localStat(info)
	return ok && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700 && int(metadata.Uid) == os.Geteuid()
}

func ownedImmutableFile(info os.FileInfo) bool {
	metadata, ok := localStat(info)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o400 && metadata.Nlink == 1 && int(metadata.Uid) == os.Geteuid()
}

func sameOwnedDirectory(left, right os.FileInfo) bool {
	return ownedDirectory(left) && ownedDirectory(right) && os.SameFile(left, right) && left.ModTime() == right.ModTime()
}

func sameOwnedFile(left, right os.FileInfo) bool {
	return ownedImmutableFile(left) && ownedImmutableFile(right) && os.SameFile(left, right) && left.Size() == right.Size() && left.ModTime() == right.ModTime()
}

func sameFilesystem(left, right os.FileInfo) bool {
	leftStat, leftOK := localStat(left)
	rightStat, rightOK := localStat(right)
	return leftOK && rightOK && leftStat.Dev == rightStat.Dev
}

func localStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	return metadata, ok
}

func parseLocalFileEndpoint(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", migration.ErrInvalid
	}
	path := parsed.Path
	if !canonicalLocalPath(path) || localFileEndpoint(path) != endpoint {
		return "", migration.ErrInvalid
	}
	return path, nil
}

func localFileEndpoint(path string) string {
	return (&url.URL{Scheme: "file", Path: path}).String()
}

func canonicalLocalPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func digestLocalPath(path string) string {
	sum := sha256.Sum256([]byte("cpanel-local-intake-path-v1\x00" + path))
	return hex.EncodeToString(sum[:])
}

func isLocalDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func writeLocalBytes(writer io.Writer, value []byte) error {
	for len(value) != 0 {
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

func syncLocalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
