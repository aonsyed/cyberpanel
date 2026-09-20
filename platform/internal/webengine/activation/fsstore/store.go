// Package fsstore persists sealed native configurations beneath an engine
// configuration root. Every managed access is relative to an os.Root.
package fsstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

const (
	stateDir             = ".panel-state"
	maxStateBytes        = 8 << 20
	maxArtifactBytes     = 16 << 20
	maxGenerationBytes   = 256 << 20
	maxGenerationEntries = 12_288
)

type Store struct {
	root     *os.Root
	rootPath string
	edition  webengine.Edition
	master   string
	vhost    string
}

type manifest struct {
	ContentAddressedVHosts bool               `json:"content_addressed_vhosts,omitempty"`
	Edition                webengine.Edition  `json:"edition"`
	Digest                 string             `json:"digest"`
	DesiredDigest          string             `json:"desired_digest"`
	Snapshot               uint64             `json:"snapshot"`
	Artifacts              []manifestArtifact `json:"artifacts"`
}

type manifestArtifact struct {
	Role   native.ArtifactRole `json:"role"`
	Key    native.ArtifactKey  `json:"key"`
	Path   string              `json:"path"`
	Size   int64               `json:"size"`
	SHA256 string              `json:"sha256"`
}

func New(root string, edition webengine.Edition) (*Store, error) {
	if edition != webengine.EditionOpenLiteSpeed && edition != webengine.EditionLiteSpeedEnterprise {
		return nil, errors.New("unsupported web engine edition")
	}
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("configuration root must be absolute and canonical")
	}
	before, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateDirectory(before); err != nil {
		return nil, fmt.Errorf("configuration root: %w", err)
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil || real != root {
		return nil, errors.New("configuration root must not contain symlinks")
	}

	openedRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	rootFile, err := openedRoot.Open(".")
	if err != nil {
		openedRoot.Close()
		return nil, err
	}
	opened, statErr := rootFile.Stat()
	closeErr := rootFile.Close()
	if statErr != nil || closeErr != nil {
		openedRoot.Close()
		if statErr != nil {
			return nil, statErr
		}
		return nil, closeErr
	}
	if err := validatePrivateDirectory(opened); err != nil || !os.SameFile(before, opened) {
		openedRoot.Close()
		return nil, errors.New("configuration root changed while opening")
	}

	master, vhost := "httpd_config.conf", "vhost.conf"
	if edition == webengine.EditionLiteSpeedEnterprise {
		master, vhost = "httpd_config.xml", "vhconf.xml"
	}
	if info, err := openedRoot.Lstat(master); err == nil {
		if err := validatePrivateRegular(info); err != nil {
			openedRoot.Close()
			return nil, fmt.Errorf("live master: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		openedRoot.Close()
		return nil, err
	}
	return &Store{root: openedRoot, rootPath: root, edition: edition, master: master, vhost: vhost}, nil
}

// GenerationPath returns only a fully reverified, sealed master. Callers must
// not accept a filesystem destination from an unprivileged request.
func (s *Store) GenerationPath(ctx context.Context, receipt activation.Receipt) (string, error) {
	if ctx == nil {
		return "", errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	sealed, _, err := s.resolve(receipt, true)
	if err != nil {
		return "", err
	}
	name, err := s.artifactPath(sealed, native.ArtifactServer, "engine", "")
	if err != nil {
		return "", err
	}
	return filepath.Join(s.rootPath, name), nil
}

func (s *Store) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
}

func (s *Store) Stage(ctx context.Context, generation native.ConfigGeneration) (activation.Receipt, error) {
	if err := ctx.Err(); err != nil {
		return activation.Receipt{}, err
	}
	if s == nil || s.root == nil || generation.Edition != s.edition {
		return activation.Receipt{}, errors.New("generation edition does not match store")
	}
	rebuilt, err := native.NewCompleteGeneration(
		generation.Edition,
		generation.DesiredDigest,
		generation.SnapshotGeneration,
		generation.Artifacts,
	)
	if err != nil || rebuilt.Kind != generation.Kind || rebuilt.ContentDigest != generation.ContentDigest {
		return activation.Receipt{}, errors.New("generation digest does not match content")
	}
	if len(rebuilt.Artifacts) == 0 || len(rebuilt.Artifacts) > maxGenerationEntries {
		return activation.Receipt{}, errors.New("generation artifact count is outside policy")
	}

	sealed := manifest{
		ContentAddressedVHosts: true,
		Edition:                rebuilt.Edition,
		Digest:                 rebuilt.ContentDigest,
		DesiredDigest:          rebuilt.DesiredDigest,
		Snapshot:               rebuilt.SnapshotGeneration,
		Artifacts:              make([]manifestArtifact, 0, len(rebuilt.Artifacts)),
	}
	var total int64
	for _, artifact := range rebuilt.Artifacts {
		if err := ctx.Err(); err != nil {
			return activation.Receipt{}, err
		}
		size := int64(len(artifact.Content))
		total += size
		if size <= 0 || size > maxArtifactBytes || total > maxGenerationBytes {
			return activation.Receipt{}, errors.New("generation artifact bytes are outside policy")
		}
		digest := sha256.Sum256(artifact.Content)
		name, err := s.artifactPath(sealed, artifact.Role, artifact.Key, hex.EncodeToString(digest[:]))
		if err != nil {
			return activation.Receipt{}, err
		}
		if err := s.writeExact(name, artifact.Content); err != nil {
			return activation.Receipt{}, err
		}
		sealed.Artifacts = append(sealed.Artifacts, manifestArtifact{
			Role:   artifact.Role,
			Key:    artifact.Key,
			Path:   name,
			Size:   size,
			SHA256: hex.EncodeToString(digest[:]),
		})
	}

	encoded, err := json.Marshal(sealed)
	if err != nil {
		return activation.Receipt{}, err
	}
	if len(encoded) > maxStateBytes {
		return activation.Receipt{}, errors.New("generation manifest exceeds policy")
	}
	if err := s.writeExact(path.Join(stateDir, "generations", rebuilt.ContentDigest), encoded); err != nil {
		return activation.Receipt{}, err
	}
	return activation.Receipt{Edition: s.edition, Digest: rebuilt.ContentDigest}, nil
}

func (s *Store) SwapMaster(ctx context.Context, receipt activation.Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sealed, master, err := s.resolve(receipt, false)
	if err != nil {
		return err
	}
	if sealed.Digest != receipt.Digest {
		return errors.New("generation receipt changed while resolving")
	}
	return s.replace(s.master, master)
}

func (s *Store) RestoreMaster(ctx context.Context, receipt activation.Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, master, err := s.resolve(receipt, true)
	if err != nil {
		return err
	}
	return s.replace(s.master, master)
}

func (s *Store) Confirm(ctx context.Context, receipt activation.Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sealed, master, err := s.resolve(receipt, false)
	if err != nil {
		return err
	}
	if err := s.verifyLiveMaster(master); err != nil {
		return err
	}
	current := activation.Receipt{
		Edition:   sealed.Edition,
		Digest:    sealed.Digest,
		Status:    activation.Applied,
		Confirmed: true,
	}
	encoded, err := json.Marshal(current)
	if err != nil {
		return err
	}
	return s.replace(path.Join(stateDir, "current"), encoded)
}

func (s *Store) Current(ctx context.Context) (activation.Receipt, error) {
	if err := ctx.Err(); err != nil {
		return activation.Receipt{}, err
	}
	if s == nil || s.root == nil {
		return activation.Receipt{}, errors.New("store is required")
	}
	encoded, err := s.readManagedFile(path.Join(stateDir, "current"), maxStateBytes)
	if err != nil {
		return activation.Receipt{}, err
	}
	var receipt activation.Receipt
	if err := parseCanonicalJSON(encoded, &receipt); err != nil || !s.validCurrentReceipt(receipt) {
		return activation.Receipt{}, errors.New("invalid current state")
	}
	_, master, err := s.resolve(receipt, true)
	if err != nil {
		return activation.Receipt{}, err
	}
	if err := s.verifyLiveMaster(master); err != nil {
		return activation.Receipt{}, err
	}
	return receipt, nil
}

func (s *Store) resolve(receipt activation.Receipt, allowCurrent bool) (manifest, []byte, error) {
	if s == nil || s.root == nil || (!s.validStagedReceipt(receipt) && !(allowCurrent && s.validCurrentReceipt(receipt))) {
		return manifest{}, nil, errors.New("unrecognized receipt")
	}
	encoded, err := s.readManagedFile(path.Join(stateDir, "generations", receipt.Digest), maxStateBytes)
	if err != nil {
		return manifest{}, nil, err
	}
	var sealed manifest
	if err := parseCanonicalJSON(encoded, &sealed); err != nil {
		return manifest{}, nil, errors.New("invalid generation manifest")
	}
	if sealed.Edition != s.edition || sealed.Digest != receipt.Digest || sealed.Snapshot == 0 ||
		!validDigest(sealed.Digest) || !validDigest(sealed.DesiredDigest) {
		return manifest{}, nil, errors.New("invalid generation manifest")
	}
	master, err := s.verifyManifest(sealed)
	if err != nil {
		return manifest{}, nil, err
	}
	return sealed, master, nil
}

func (s *Store) verifyManifest(sealed manifest) ([]byte, error) {
	if len(sealed.Artifacts) == 0 || len(sealed.Artifacts) > maxGenerationEntries {
		return nil, errors.New("invalid generation manifest artifact count")
	}
	artifacts := make([]native.Artifact, 0, len(sealed.Artifacts))
	var master []byte
	var total int64
	for index, entry := range sealed.Artifacts {
		if entry.Size <= 0 || entry.Size > maxArtifactBytes || !validDigest(entry.SHA256) {
			return nil, errors.New("invalid generation manifest artifact")
		}
		total += entry.Size
		if total > maxGenerationBytes {
			return nil, errors.New("generation exceeds total byte policy")
		}
		expectedPath, err := s.artifactPath(sealed, entry.Role, entry.Key, entry.SHA256)
		if err != nil || entry.Path != expectedPath {
			return nil, errors.New("generation manifest contains an unsafe artifact path")
		}
		content, err := s.readManagedFile(entry.Path, maxArtifactBytes)
		if err != nil {
			return nil, err
		}
		if int64(len(content)) != entry.Size {
			return nil, errors.New("generation artifact size does not match manifest")
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != entry.SHA256 {
			return nil, errors.New("generation artifact digest does not match manifest")
		}
		artifact := native.Artifact{Role: entry.Role, Key: entry.Key, Mode: 0o600, Content: content}
		artifacts = append(artifacts, artifact)
		if entry.Role == native.ArtifactServer {
			if master != nil || entry.Key != native.ArtifactKey("engine") {
				return nil, errors.New("generation manifest has an invalid master")
			}
			master = append([]byte(nil), content...)
		}
		if index > 0 {
			previous := sealed.Artifacts[index-1]
			if previous.Role > entry.Role || (previous.Role == entry.Role && previous.Key >= entry.Key) {
				return nil, errors.New("generation manifest artifacts are not canonical")
			}
		}
	}
	if master == nil {
		return nil, errors.New("generation manifest has no master")
	}
	rebuilt, err := native.NewCompleteGeneration(
		sealed.Edition,
		sealed.DesiredDigest,
		sealed.Snapshot,
		artifacts,
	)
	if err != nil || rebuilt.ContentDigest != sealed.Digest {
		return nil, errors.New("generation manifest does not seal its artifacts")
	}
	return master, nil
}

func (s *Store) artifactPath(sealed manifest, role native.ArtifactRole, key native.ArtifactKey, contentDigest string) (string, error) {
	if !safeArtifactKey(key) || sealed.Snapshot == 0 || !validDigest(sealed.Digest) {
		return "", errors.New("unsafe generation artifact identity")
	}
	switch role {
	case native.ArtifactServer:
		if key != native.ArtifactKey("engine") {
			return "", errors.New("unknown server artifact")
		}
		return path.Join(".panel-generations", fmt.Sprintf("g%d", sealed.Snapshot), sealed.Digest, s.master), nil
	case native.ArtifactVirtualHost:
		if sealed.ContentAddressedVHosts {
			if !validDigest(contentDigest) {
				return "", errors.New("invalid vhost content digest")
			}
			return path.Join("vhosts", ".panel-generations", fmt.Sprintf("g%d", sealed.Snapshot), string(key), contentDigest, s.vhost), nil
		}
		return path.Join("vhosts", ".panel-generations", fmt.Sprintf("g%d", sealed.Snapshot), string(key), s.vhost), nil
	case native.ArtifactCredentialVerifier:
		return path.Join("vhosts", ".panel-generations", fmt.Sprintf("g%d", sealed.Snapshot), "access", string(key)+".users"), nil
	default:
		return "", errors.New("unknown generation artifact role")
	}
}

func (s *Store) validStagedReceipt(receipt activation.Receipt) bool {
	return receipt.Edition == s.edition && validDigest(receipt.Digest) && receipt.Status == "" &&
		receipt.CandidateDigest == "" && receipt.PreviousDigest == "" &&
		!receipt.ReloadRequested && !receipt.CandidateProbed && !receipt.Confirmed &&
		!receipt.RollbackRestored && !receipt.RollbackReloaded && !receipt.PreviousProbed
}

func (s *Store) validCurrentReceipt(receipt activation.Receipt) bool {
	return receipt.Edition == s.edition && validDigest(receipt.Digest) &&
		receipt.Status == activation.Applied && receipt.Confirmed &&
		receipt.CandidateDigest == "" && receipt.PreviousDigest == "" &&
		!receipt.ReloadRequested && !receipt.CandidateProbed &&
		!receipt.RollbackRestored && !receipt.RollbackReloaded && !receipt.PreviousProbed
}

func (s *Store) verifyLiveMaster(expected []byte) error {
	live, err := s.readManagedFile(s.master, maxArtifactBytes)
	if err != nil || !bytes.Equal(live, expected) {
		return errors.New("live master does not match sealed generation")
	}
	return nil
}

func (s *Store) writeExact(name string, data []byte) error {
	if err := validateManagedName(name); err != nil {
		return err
	}
	if err := s.ensurePrivateDirectory(path.Dir(name)); err != nil {
		return err
	}
	info, err := s.root.Lstat(name)
	if err == nil {
		if err := validatePrivateRegular(info); err != nil {
			return fmt.Errorf("existing managed file: %w", err)
		}
		old, err := s.readManagedFile(name, maxArtifactBytes)
		if err != nil {
			return err
		}
		if !bytes.Equal(old, data) {
			return errors.New("immutable generation conflicts")
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return s.syncDirectory(path.Dir(name))
}

func (s *Store) replace(name string, data []byte) error {
	if err := validateManagedName(name); err != nil {
		return err
	}
	directory := path.Dir(name)
	if err := s.ensurePrivateDirectory(directory); err != nil {
		return err
	}
	if info, err := s.root.Lstat(name); err == nil {
		if err := validatePrivateRegular(info); err != nil {
			return fmt.Errorf("managed replacement target: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	temporary := path.Join(directory, ".tmp-"+path.Base(name))
	if _, err := s.root.Lstat(temporary); err == nil {
		return errors.New("protocol-owned crash residue")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := s.writeTemporary(temporary, data); err != nil {
		return err
	}
	if err := s.root.Rename(temporary, name); err != nil {
		return err
	}
	if err := s.syncDirectory(directory); err != nil {
		return err
	}
	published, err := s.readManagedFile(name, maxArtifactBytes)
	if err != nil || !bytes.Equal(published, data) {
		return errors.New("published managed file could not be verified")
	}
	return nil
}

func (s *Store) writeTemporary(name string, data []byte) error {
	file, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (s *Store) readManagedFile(name string, limit int64) ([]byte, error) {
	if err := validateManagedName(name); err != nil {
		return nil, err
	}
	before, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateRegular(before); err != nil {
		return nil, err
	}
	if before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("managed file exceeds byte policy")
	}
	file, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := validatePrivateRegular(opened); err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("managed file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("managed file exceeds byte policy")
	}
	after, err := s.root.Lstat(name)
	if err != nil || !os.SameFile(opened, after) {
		return nil, errors.New("managed file changed while reading")
	}
	return data, nil
}

func (s *Store) ensurePrivateDirectory(name string) error {
	if name == "." {
		info, err := s.root.Lstat(".")
		if err != nil {
			return err
		}
		return validatePrivateDirectory(info)
	}
	if err := validateManagedName(name); err != nil {
		return err
	}
	current := ""
	for _, component := range strings.Split(name, "/") {
		parent := "."
		if current != "" {
			parent = current
		}
		current = path.Join(current, component)
		info, err := s.root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err := s.root.Mkdir(current, 0o700); err != nil {
				return err
			}
			if err := s.syncDirectory(parent); err != nil {
				return err
			}
			info, err = s.root.Lstat(current)
		}
		if err != nil {
			return err
		}
		if err := validatePrivateDirectory(info); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) syncDirectory(name string) error {
	directory, err := s.root.Open(name)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return err
	}
	return directory.Close()
}

func parseCanonicalJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("JSON has trailing data")
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return errors.New("JSON is not canonical")
	}
	return nil
}

func validateManagedName(name string) error {
	if name == "" || name == "." || !fs.ValidPath(name) || path.Clean(name) != name {
		return errors.New("unsafe managed path")
	}
	return nil
}

func validatePrivateDirectory(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("directory must be real and mode 0700")
	}
	return nil
}

func validatePrivateRegular(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("file must be regular and mode 0600")
	}
	return nil
}

func validDigest(digest string) bool {
	return len(digest) == 64 && strings.Trim(digest, "0123456789abcdef") == ""
}

func safeArtifactKey(key native.ArtifactKey) bool {
	value := string(key)
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}
