//go:build linux

package noderelease

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	StateRoot       = "/var/lib/cyberpanel/node-release"
	JournalRoot     = StateRoot + "/journal"
	StagingRoot     = StateRoot + "/staging"
	ReleaseRoot     = "/opt/cyberpanel/node-releases"
	ActiveRelease   = "/opt/cyberpanel/node-current"
	TrustRoot       = "/etc/cyberpanel/node-release/trust.d"
	FrontierPath    = StateRoot + "/admission-frontier.json"
	installedPath   = StateRoot + "/installed.json"
	installerLock   = StateRoot + "/lock"
	operationDomain = "cyberpanel-node-release-operation-v1\n"
	effectDomain    = "cyberpanel-node-release-effect-v1\n"
)

type InstalledRelease struct {
	ReleaseID      string         `json:"release_id"`
	ManifestDigest string         `json:"manifest_digest"`
	Sequence       uint64         `json:"sequence"`
	ProductVersion Version        `json:"product_version"`
	ProductSchema  uint64         `json:"product_schema"`
	Target         Target         `json:"target"`
	ReleasePath    string         `json:"release_path"`
	Destinations   []string       `json:"destinations"`
	Packages       []string       `json:"packages"`
	Services       []ServiceProbe `json:"services"`
}

type InstalledState struct {
	SchemaVersion   uint16            `json:"schema_version"`
	Target          Target            `json:"target"`
	HighestSequence uint64            `json:"highest_sequence"`
	Active          InstalledRelease  `json:"active"`
	Previous        *InstalledRelease `json:"previous,omitempty"`
	Generation      uint64            `json:"generation"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type AdmissionFrontier struct {
	SchemaVersion   uint16    `json:"schema_version"`
	Target          Target    `json:"target"`
	HighestSequence uint64    `json:"highest_sequence"`
	ManifestDigest  string    `json:"manifest_digest"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type EffectRecord struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Resource       string    `json:"resource"`
	State          string    `json:"state"`
	EvidenceDigest string    `json:"evidence_digest,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at,omitempty"`
}

type Journal struct {
	SchemaVersion  uint16            `json:"schema_version"`
	OperationID    string            `json:"operation_id"`
	ManifestDigest string            `json:"manifest_digest"`
	State          string            `json:"state"`
	Candidate      InstalledRelease  `json:"candidate"`
	Previous       *InstalledRelease `json:"previous,omitempty"`
	Effects        []EffectRecord    `json:"effects"`
	Failure        string            `json:"failure,omitempty"`
	Generation     uint64            `json:"generation"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	CompletedAt    time.Time         `json:"completed_at,omitempty"`
}

type InstallReceipt struct {
	OperationID    string    `json:"operation_id"`
	ManifestDigest string    `json:"manifest_digest"`
	ReleaseID      string    `json:"release_id"`
	Sequence       uint64    `json:"sequence"`
	State          string    `json:"state"`
	ActivePath     string    `json:"active_path"`
	ReleasePath    string    `json:"release_path"`
	CompletedAt    time.Time `json:"completed_at"`
	ReceiptDigest  string    `json:"receipt_digest"`
}

type Status struct {
	Frontier  *AdmissionFrontier `json:"frontier,omitempty"`
	Installed *InstalledState    `json:"installed,omitempty"`
	Journals  []Journal          `json:"journals"`
}

type Installer struct {
	Now func() time.Time
}

func (installer Installer) now() time.Time {
	if installer.Now != nil {
		return installer.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func NewInstaller() (*Installer, error) {
	if os.Geteuid() != 0 || os.Getuid() != 0 {
		return nil, fmt.Errorf("%w: panel-node-install must run as real and effective root", ErrUnsupported)
	}
	if err := ensureNodeStateParent(filepath.Dir(StateRoot)); err != nil { return nil, err }
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{{StateRoot, 0700}, {JournalRoot, 0700}, {StagingRoot, 0700}, {ReleaseRoot, 0755}} {
		if err := ensureRootDirectory(entry.path, entry.mode); err != nil {
			return nil, err
		}
	}
	return &Installer{}, nil
}

// The parent is shared with non-root control-plane services. Only the node
// installer's own state subtree is private. Repair the old root-only parent
// mode without changing any private child or accepting unsafe ownership.
func ensureNodeStateParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path { return ErrInvalid }
	if err := validateRootOwnedAncestors(filepath.Dir(path)); err != nil { return err }
	if err := os.Mkdir(path, 0755); err != nil && !os.IsExist(err) { return err }
	info, err := os.Lstat(path)
	metadata, ok := entryMetadata(info)
	if err != nil || !ok || metadata.Uid != 0 || metadata.Gid != 0 || !info.IsDir() || (info.Mode().Perm() != 0700 && info.Mode().Perm() != 0755) { return ErrIntegrity }
	if info.Mode().Perm() == 0700 { return os.Chmod(path, 0755) }
	return nil
}

func (installer *Installer) Apply(ctx context.Context, bundlePath string) (InstallReceipt, error) {
	if installer == nil || ctx == nil {
		return InstallReceipt{}, ErrInvalid
	}
	var receipt InstallReceipt
	err := installer.withLock(func() error {
		if _, err := installer.reconcileLocked(ctx, ""); err != nil {
			return err
		}
		trust, err := LoadTrustStore(TrustRoot)
		if err != nil {
			return fmt.Errorf("load offline node release trust from %s: %w", TrustRoot, err)
		}
		target, err := probeTarget()
		if err != nil {
			return err
		}
		staged, envelope, err := installer.stageBundle(ctx, bundlePath, trust, target)
		if err != nil {
			return err
		}
		manifest := envelope.Manifest
		state, stateErr := loadInstalledState()
		if stateErr != nil && !errors.Is(stateErr, ErrNotFound) {
			return stateErr
		}
		if stateErr == nil && state.Active.ManifestDigest == manifest.ManifestDigest {
			if err = admitFrontier(manifest, installer.now()); err != nil {
				return err
			}
			activeDigest, activeErr := observeActiveRelease()
			if activeErr != nil || activeDigest != manifest.ManifestDigest || verifyReleaseTree(state.Active.ReleasePath, manifest) != nil {
				return fmt.Errorf("%w: installed state does not match the active immutable release", ErrRecovery)
			}
			operation := operationID(manifest.ManifestDigest)
			completedAt := state.UpdatedAt
			committed, journalErr := loadJournal(operation)
			if journalErr == nil {
				if committed.State != "committed" || digestJSON(committed.Candidate) != digestJSON(state.Active) {
					return fmt.Errorf("%w: installed state conflicts with operation journal %s", ErrRecovery, journalPath(operation))
				}
				completedAt = committed.CompletedAt
			} else if !errors.Is(journalErr, ErrNotFound) {
				return journalErr
			}
			receipt = receiptFor(operation, state.Active, "committed", completedAt)
			return nil
		}
		if err = admitManifest(manifest, state, stateErr); err != nil {
			return err
		}
		if err = admitFrontier(manifest, installer.now()); err != nil {
			return err
		}
		operation := operationID(manifest.ManifestDigest)
		journal, journalErr := loadJournal(operation)
		if journalErr == nil {
			if journal.ManifestDigest != manifest.ManifestDigest {
				return ErrConflict
			}
			if journal.State == "committed" || journal.State == "rolled_back" {
				receipt = receiptFor(journal.OperationID, journal.Candidate, journal.State, journal.CompletedAt)
				if journal.State == "rolled_back" {
					return ErrRollback
				}
				return nil
			}
		} else if !errors.Is(journalErr, ErrNotFound) {
			return journalErr
		} else {
			candidate, err := installer.materializeRelease(staged, envelope)
			if err != nil {
				return err
			}
			journal = Journal{SchemaVersion: ManifestSchema, OperationID: operation, ManifestDigest: manifest.ManifestDigest,
				State: "staged", Candidate: candidate, Generation: 1, CreatedAt: installer.now(), UpdatedAt: installer.now()}
			if stateErr == nil {
				previous := state.Active
				journal.Previous = &previous
			}
			if err = saveJournal(journal); err != nil {
				return err
			}
		}
		receipt, err = installer.resumeLocked(ctx, &journal, trust)
		return err
	})
	return receipt, err
}

func (installer *Installer) Reconcile(ctx context.Context) ([]InstallReceipt, error) {
	if installer == nil || ctx == nil {
		return nil, ErrInvalid
	}
	var receipts []InstallReceipt
	err := installer.withLock(func() error {
		var err error
		receipts, err = installer.reconcileLocked(ctx, "")
		return err
	})
	return receipts, err
}

func (installer *Installer) InspectStatus() (Status, error) {
	if installer == nil {
		return Status{}, ErrInvalid
	}
	var status Status
	err := installer.withLock(func() error {
		frontier, frontierErr := loadAdmissionFrontier()
		if frontierErr == nil {
			status.Frontier = &frontier
		} else if !errors.Is(frontierErr, ErrNotFound) {
			return frontierErr
		}
		state, err := loadInstalledState()
		if err == nil {
			status.Installed = &state
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		status.Journals, err = loadJournals()
		return err
	})
	return status, err
}

func (installer *Installer) withLock(action func() error) error {
	file, err := os.OpenFile(installerLock, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return action()
}

func operationID(manifestDigest string) string {
	sum := sha256.Sum256([]byte(operationDomain + manifestDigest))
	return "install-" + hex.EncodeToString(sum[:])
}

func effectID(manifestDigest, kind, resource string) string {
	sum := sha256.Sum256([]byte(effectDomain + manifestDigest + "\n" + kind + "\n" + resource))
	return hex.EncodeToString(sum[:])
}

func receiptFor(operation string, release InstalledRelease, state string, completed time.Time) InstallReceipt {
	receipt := InstallReceipt{OperationID: operation, ManifestDigest: release.ManifestDigest, ReleaseID: release.ReleaseID,
		Sequence: release.Sequence, State: state, ActivePath: ActiveRelease, ReleasePath: release.ReleasePath, CompletedAt: completed}
	receipt.ReceiptDigest = digestJSON(receipt)
	return receipt
}

func admitManifest(manifest Manifest, state InstalledState, stateErr error) error {
	if manifest.Target.Validate() != nil {
		return ErrUnsupported
	}
	if errors.Is(stateErr, ErrNotFound) {
		if !manifest.FreshInstall {
			return fmt.Errorf("%w: release does not authorize a fresh node install", ErrRollback)
		}
		return nil
	}
	if stateErr != nil || state.Target.Key() != manifest.Target.Key() || state.Active.Target.Key() != manifest.Target.Key() {
		return ErrUnsupported
	}
	if manifest.Sequence <= state.HighestSequence || manifest.ProductVersion.Compare(state.Active.ProductVersion) < 0 ||
		manifest.ProductSchema < state.Active.ProductSchema ||
		!manifest.UpgradeSource.Includes(state.Active.ProductVersion) || !manifest.SourceSchema.Includes(state.Active.ProductSchema) {
		return fmt.Errorf("%w: installed source is %s schema %d at sequence frontier %d", ErrRollback,
			state.Active.ProductVersion.String(), state.Active.ProductSchema, state.HighestSequence)
	}
	return nil
}

func releaseFromManifest(manifest Manifest) InstalledRelease {
	destinations := make([]string, 0, len(manifest.Artifacts))
	packages := make([]string, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind == ArtifactPackage {
			packages = append(packages, artifact.ID)
		} else {
			destinations = append(destinations, artifact.Destination)
		}
	}
	sort.Strings(destinations)
	sort.Strings(packages)
	return InstalledRelease{ReleaseID: manifest.ReleaseID, ManifestDigest: manifest.ManifestDigest, Sequence: manifest.Sequence,
		ProductVersion: manifest.ProductVersion, ProductSchema: manifest.ProductSchema, Target: manifest.Target,
		ReleasePath: filepath.Join(ReleaseRoot, manifest.ManifestDigest), Destinations: destinations, Packages: packages,
		Services: append([]ServiceProbe(nil), manifest.Services...)}
}

func digestJSON(value any) string {
	payload, _ := json.Marshal(value)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (installer *Installer) stageBundle(ctx context.Context, bundlePath string, trust TrustStore, target Target) (string, SignedManifest, error) {
	if !filepath.IsAbs(bundlePath) || filepath.Clean(bundlePath) != bundlePath {
		return "", SignedManifest{}, fmt.Errorf("%w: bundle must be an absolute canonical path", ErrInvalid)
	}
	info, err := os.Lstat(bundlePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 16<<30 {
		return "", SignedManifest{}, errors.Join(ErrInvalid, err)
	}
	if err = requireRootOwned(info, 0644, false); err != nil {
		return "", SignedManifest{}, fmt.Errorf("offline bundle must be root-owned, singly linked, regular, and not writable by group/other: %w", err)
	}
	file, err := os.Open(bundlePath)
	if err != nil {
		return "", SignedManifest{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", SignedManifest{}, ErrIntegrity
	}
	archive := tar.NewReader(file)
	header, err := archive.Next()
	if err != nil || header.Name != BundleManifestPath || !regularTarHeader(header) || header.Size <= 0 || header.Size > maximumSpecBytes {
		return "", SignedManifest{}, errors.Join(ErrIntegrity, err)
	}
	envelopeRaw, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
	if err != nil || int64(len(envelopeRaw)) != header.Size {
		return "", SignedManifest{}, errors.Join(ErrIntegrity, err)
	}
	var envelope SignedManifest
	if err = decodeStrictJSON(envelopeRaw, &envelope); err != nil {
		return "", SignedManifest{}, fmt.Errorf("decode signed node release manifest at %s in %s: %w", BundleManifestPath, bundlePath, err)
	}
	manifest, err := trust.Verify(envelope, installer.now())
	if err != nil {
		return "", SignedManifest{}, fmt.Errorf("verify signed node release manifest at %s in %s: %w", BundleManifestPath, bundlePath, err)
	}
	if manifest.Target.Key() != target.Key() {
		return "", SignedManifest{}, fmt.Errorf("%w: bundle target %s does not match host %s", ErrUnsupported, manifest.Target.Key(), target.Key())
	}
	envelope.Manifest = manifest
	temporary, err := os.MkdirTemp(StagingRoot, ".incoming-")
	if err != nil {
		return "", SignedManifest{}, err
	}
	if err = os.Chmod(temporary, 0700); err != nil {
		_ = os.RemoveAll(temporary)
		return "", SignedManifest{}, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err = writeDurableFile(filepath.Join(temporary, BundleManifestPath), envelopeRaw, 0600, 0, 0); err != nil {
		return "", SignedManifest{}, err
	}
	payloadRoot := filepath.Join(temporary, "payload")
	if err = ensureRootDirectory(payloadRoot, 0700); err != nil {
		return "", SignedManifest{}, err
	}
	for _, id := range manifest.InstallOrder {
		artifact, exists := manifest.Artifact(id)
		if !exists {
			return "", SignedManifest{}, ErrIntegrity
		}
		header, err = archive.Next()
		if err != nil || header.Name != artifact.PayloadPath() || !regularTarHeader(header) || header.Size != artifact.Size {
			return "", SignedManifest{}, fmt.Errorf("%w: expected release member %s", ErrIntegrity, artifact.PayloadPath())
		}
		targetPath := filepath.Join(payloadRoot, artifact.ID)
		output, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return "", SignedManifest{}, err
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(output, hasher), io.LimitReader(archive, artifact.Size+1))
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != artifact.Size ||
			hex.EncodeToString(hasher.Sum(nil)) != artifact.SHA256 {
			return "", SignedManifest{}, errors.Join(ErrIntegrity, copyErr, syncErr, closeErr)
		}
	}
	if extra, nextErr := archive.Next(); nextErr != io.EOF || extra != nil {
		return "", SignedManifest{}, ErrIntegrity
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind == ArtifactPackage {
			if err = verifyPackageMetadata(ctx, filepath.Join(payloadRoot, artifact.ID), artifact, manifest.Target); err != nil {
				return "", SignedManifest{}, fmt.Errorf("verify offline package %s: %w", artifact.ID, err)
			}
		}
	}
	final := filepath.Join(StagingRoot, manifest.ManifestDigest)
	if _, err = os.Lstat(final); err == nil {
		if verifyStagedRelease(final, envelope) != nil {
			return "", SignedManifest{}, ErrConflict
		}
		_ = os.RemoveAll(temporary)
		complete = true
		return final, envelope, nil
	} else if !os.IsNotExist(err) {
		return "", SignedManifest{}, err
	}
	if err = syncDirectory(payloadRoot); err != nil {
		return "", SignedManifest{}, err
	}
	if err = syncDirectory(temporary); err != nil {
		return "", SignedManifest{}, err
	}
	if err = os.Rename(temporary, final); err != nil {
		return "", SignedManifest{}, err
	}
	if err = syncDirectory(StagingRoot); err != nil {
		return "", SignedManifest{}, err
	}
	complete = true
	return final, envelope, nil
}

func regularTarHeader(header *tar.Header) bool {
	return header != nil && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) && header.Mode == 0600 &&
		header.Uid == 0 && header.Gid == 0 && !filepath.IsAbs(header.Name) && filepath.Clean(header.Name) == header.Name
}

func verifyStagedRelease(root string, envelope SignedManifest) error {
	manifest := envelope.Manifest
	expected := map[string]bool{BundleManifestPath: true}
	for _, artifact := range manifest.Artifacts {
		expected[filepath.Join("payload", artifact.ID)] = true
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, relativeErr := filepath.Rel(root, path)
		metadata, ok := entryMetadata(info)
		if relativeErr != nil || !ok || metadata.Uid != 0 || metadata.Gid != 0 || info.Mode()&os.ModeSymlink != 0 {
			return ErrIntegrity
		}
		if info.IsDir() {
			if (relative != "." && relative != "payload") || info.Mode().Perm() != 0700 {
				return ErrIntegrity
			}
			return nil
		}
		if !info.Mode().IsRegular() || !expected[relative] || info.Mode().Perm() != 0600 || metadata.Nlink != 1 {
			return ErrIntegrity
		}
		return nil
	})
	if err != nil {
		return err
	}
	payload, err := os.ReadFile(filepath.Join(root, BundleManifestPath))
	if err != nil {
		return err
	}
	var stored SignedManifest
	if decodeStrictJSON(payload, &stored) != nil {
		return ErrIntegrity
	}
	storedCanonical, storedErr := json.Marshal(stored)
	expectedCanonical, expectedErr := json.Marshal(envelope)
	if stored.KeyID != envelope.KeyID || stored.Signature != envelope.Signature ||
		stored.Manifest.ManifestDigest != manifest.ManifestDigest || storedErr != nil || expectedErr != nil ||
		!bytes.Equal(storedCanonical, expectedCanonical) {
		return ErrIntegrity
	}
	for _, artifact := range manifest.Artifacts {
		path := filepath.Join(root, "payload", artifact.ID)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() != artifact.Size {
			return ErrIntegrity
		}
		digest, size, err := digestFile(path)
		if err != nil || digest != artifact.SHA256 || size != artifact.Size {
			return ErrIntegrity
		}
	}
	return nil
}

func (installer *Installer) materializeRelease(staged string, envelope SignedManifest) (InstalledRelease, error) {
	manifest := envelope.Manifest
	release := releaseFromManifest(manifest)
	if err := verifyReleaseTree(release.ReleasePath, manifest); err == nil {
		return release, nil
	} else if !errors.Is(err, ErrNotFound) {
		return InstalledRelease{}, err
	}
	temporary := filepath.Join(ReleaseRoot, ".candidate-"+manifest.ManifestDigest)
	if _, err := os.Lstat(temporary); err == nil {
		return InstalledRelease{}, ErrConflict
	} else if !os.IsNotExist(err) {
		return InstalledRelease{}, err
	}
	if err := os.Mkdir(temporary, 0700); err != nil {
		return InstalledRelease{}, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(temporary)
		}
	}()
	envelopeRaw, err := os.ReadFile(filepath.Join(staged, BundleManifestPath))
	if err != nil {
		return InstalledRelease{}, err
	}
	if err = writeDurableFile(filepath.Join(temporary, BundleManifestPath), envelopeRaw, 0600, 0, 0); err != nil {
		return InstalledRelease{}, err
	}
	for _, id := range manifest.InstallOrder {
		artifact, _ := manifest.Artifact(id)
		source := filepath.Join(staged, "payload", artifact.ID)
		destination := filepath.Join(temporary, "packages", artifact.ID)
		if artifact.Kind != ArtifactPackage {
			destination = filepath.Join(temporary, "root", strings.TrimPrefix(artifact.Destination, "/"))
		}
		if err = copyReleaseFile(source, destination, artifact); err != nil {
			return InstalledRelease{}, fmt.Errorf("materialize release artifact %s: %w", artifact.ID, err)
		}
	}
	if err = chmodReleaseDirectories(temporary); err != nil {
		return InstalledRelease{}, err
	}
	if err = syncReleaseTree(temporary); err != nil {
		return InstalledRelease{}, err
	}
	if err = os.Rename(temporary, release.ReleasePath); err != nil {
		return InstalledRelease{}, err
	}
	if err = syncDirectory(ReleaseRoot); err != nil {
		return InstalledRelease{}, err
	}
	complete = true
	if err = verifyReleaseTree(release.ReleasePath, manifest); err != nil {
		return InstalledRelease{}, err
	}
	return release, nil
}

func verifyReleaseTree(root string, manifest Manifest) error {
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	rootMetadata, rootMetadataOK := entryMetadata(info)
	if err != nil || !rootMetadataOK || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0755 ||
		rootMetadata.Uid != 0 || rootMetadata.Gid != 0 {
		return ErrIntegrity
	}
	expectedFiles := map[string]bool{BundleManifestPath: true}
	expectedDirectories := map[string]bool{".": true}
	for _, artifact := range manifest.Artifacts {
		relative := filepath.Join("packages", artifact.ID)
		if artifact.Kind != ArtifactPackage {
			relative = filepath.Join("root", strings.TrimPrefix(artifact.Destination, "/"))
		}
		expectedFiles[relative] = true
		for parent := filepath.Dir(relative); parent != "."; parent = filepath.Dir(parent) {
			expectedDirectories[parent] = true
		}
	}
	if err = filepath.Walk(root, func(path string, entry os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, relativeErr := filepath.Rel(root, path)
		if relativeErr != nil || entry.Mode()&os.ModeSymlink != 0 {
			return ErrIntegrity
		}
		metadata, ok := entryMetadata(entry)
		if !ok || metadata.Uid != 0 || metadata.Gid != 0 {
			return ErrIntegrity
		}
		if entry.IsDir() {
			if !expectedDirectories[relative] || entry.Mode().Perm() != 0755 {
				return ErrIntegrity
			}
			return nil
		}
		if !entry.Mode().IsRegular() || !expectedFiles[relative] || metadata.Nlink != 1 {
			return ErrIntegrity
		}
		return nil
	}); err != nil {
		return err
	}
	manifestInfo, err := os.Lstat(filepath.Join(root, BundleManifestPath))
	manifestMetadata, manifestMetadataOK := entryMetadata(manifestInfo)
	if err != nil || !manifestMetadataOK || manifestInfo.Mode().Perm() != 0600 || manifestMetadata.Uid != 0 ||
		manifestMetadata.Gid != 0 || manifestMetadata.Nlink != 1 {
		return ErrIntegrity
	}
	payload, err := os.ReadFile(filepath.Join(root, BundleManifestPath))
	if err != nil {
		return err
	}
	var envelope SignedManifest
	if decodeStrictJSON(payload, &envelope) != nil || envelope.Manifest.ManifestDigest != manifest.ManifestDigest {
		return ErrIntegrity
	}
	canonical, err := CanonicalManifest(envelope.Manifest)
	if err != nil || canonical.ManifestDigest != manifest.ManifestDigest {
		return ErrIntegrity
	}
	for _, artifact := range manifest.Artifacts {
		path := filepath.Join(root, "packages", artifact.ID)
		if artifact.Kind != ArtifactPackage {
			path = filepath.Join(root, "root", strings.TrimPrefix(artifact.Destination, "/"))
		}
		entry, err := os.Lstat(path)
		mode, _ := artifact.FileMode()
		metadata, ok := entryMetadata(entry)
		if err != nil || !ok || !entry.Mode().IsRegular() || entry.Mode()&os.ModeSymlink != 0 ||
			entry.Mode().Perm() != os.FileMode(mode) || metadata.Uid != artifact.UID || metadata.Gid != artifact.GID || entry.Size() != artifact.Size {
			return ErrIntegrity
		}
		digest, size, err := digestFile(path)
		if err != nil || digest != artifact.SHA256 || size != artifact.Size {
			return ErrIntegrity
		}
	}
	return nil
}

func copyReleaseFile(source, destination string, artifact Artifact) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	mode, err := artifact.FileMode()
	if err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, os.FileMode(mode))
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hasher), io.LimitReader(input, artifact.Size+1))
	chownErr := output.Chown(int(artifact.UID), int(artifact.GID))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || chownErr != nil || syncErr != nil || closeErr != nil || written != artifact.Size ||
		hex.EncodeToString(hasher.Sum(nil)) != artifact.SHA256 {
		return errors.Join(ErrIntegrity, copyErr, chownErr, syncErr, closeErr)
	}
	return nil
}

func chmodReleaseDirectories(root string) error {
	var directories []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, path := range directories {
		if err = os.Chown(path, 0, 0); err != nil {
			return err
		}
		if err = os.Chmod(path, 0755); err != nil {
			return err
		}
	}
	return nil
}

func syncReleaseTree(root string) error {
	var directories []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, path := range directories {
		if err = syncDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func entryMetadata(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	return metadata, ok
}

func (installer *Installer) resumeLocked(ctx context.Context, journal *Journal, trust TrustStore) (InstallReceipt, error) {
	if journal == nil || journal.SchemaVersion != ManifestSchema || journal.OperationID != operationID(journal.ManifestDigest) ||
		journal.Candidate.ManifestDigest != journal.ManifestDigest {
		return InstallReceipt{}, ErrIntegrity
	}
	if journal.State == "committed" || journal.State == "rolled_back" {
		receipt := receiptFor(journal.OperationID, journal.Candidate, journal.State, journal.CompletedAt)
		if journal.State == "rolled_back" {
			return receipt, ErrRollback
		}
		return receipt, nil
	}
	initialState := journal.State
	activeDigest, activeErr := observeActiveRelease()
	if installed, installedErr := loadInstalledState(); installedErr == nil &&
		digestJSON(installed.Active) == digestJSON(journal.Candidate) &&
		installedPreviousMatchesJournal(installed.Previous, journal.Previous) &&
		activeErr == nil && activeDigest == journal.ManifestDigest {
		if _, _, err := loadRetainedEnvelopeWithoutTime(journal.Candidate, trust); err != nil {
			return installer.markRecovery(journal, "committed_release_integrity_failed")
		}
		journal.State = "committed"
		journal.Failure = ""
		journal.CompletedAt = installer.now()
		if err := updateJournal(journal, installer.now()); err != nil {
			return InstallReceipt{}, err
		}
		return receiptFor(journal.OperationID, journal.Candidate, journal.State, journal.CompletedAt), nil
	}
	envelope, manifest, err := loadRetainedEnvelope(journal.Candidate, trust, installer.now())
	if err != nil {
		return installer.recoverVerificationFailure(ctx, journal, trust, err)
	}
	_ = envelope
	previousDigest := ""
	if journal.Previous != nil {
		previousDigest = journal.Previous.ManifestDigest
	}
	switch journal.State {
	case "staged", "installing_packages", "linking":
		if journal.Previous != nil && (activeErr != nil || activeDigest != previousDigest) ||
			journal.Previous == nil && !errors.Is(activeErr, ErrNotFound) {
			return installer.markRecovery(journal, "active_release_conflict")
		}
	case "activation_prepared", "activated", "probing":
		if activeErr == nil && activeDigest == journal.ManifestDigest {
			journal.State = "activated"
			if initialState == "activated" || initialState == "probing" {
				resetEffects(journal, "service_probe")
			}
			if err = updateJournal(journal, installer.now()); err != nil {
				return InstallReceipt{}, err
			}
		} else if journal.Previous != nil && activeErr == nil && activeDigest == previousDigest ||
			journal.Previous == nil && errors.Is(activeErr, ErrNotFound) {
			journal.State = "linking"
			if err = updateJournal(journal, installer.now()); err != nil {
				return InstallReceipt{}, err
			}
		} else {
			return installer.markRecovery(journal, "activation_observation_ambiguous")
		}
	case "rolling_back":
		return installer.rollbackLocked(ctx, journal, trust, ErrRecovery)
	case "recovery_required":
		return InstallReceipt{}, ErrRecovery
	default:
		return installer.markRecovery(journal, "unknown_journal_state")
	}
	if journal.State != "activated" {
		if err = validateManagedDestinations(manifest); err != nil {
			return InstallReceipt{}, err
		}
		journal.State = "installing_packages"
		if err = updateJournal(journal, installer.now()); err != nil {
			return InstallReceipt{}, err
		}
		for _, id := range manifest.InstallOrder {
			artifact, _ := manifest.Artifact(id)
			if artifact.Kind != ArtifactPackage {
				continue
			}
			execute, err := beginEffect(journal, "install_package", artifact.ID, installer.now())
			if err != nil {
				return InstallReceipt{}, err
			}
			if !execute {
				observed, observeErr := installedPackageEvidence(ctx, artifact)
				recorded, recordErr := completedEffectEvidence(journal, "install_package", artifact.ID)
				if observeErr == nil && recordErr == nil && observed == recorded {
					continue
				}
				if ctx.Err() != nil {
					return InstallReceipt{}, ctx.Err()
				}
				if err = restartEffect(journal, "install_package", artifact.ID, installer.now()); err != nil {
					return InstallReceipt{}, err
				}
			}
			path := filepath.Join(journal.Candidate.ReleasePath, "packages", artifact.ID)
			evidence, installErr := installOfflinePackage(ctx, path, artifact, manifest.Target)
			if installErr != nil {
				return installer.handlePreActivationFailure(ctx, journal, trust, installErr)
			}
			if err = completeEffect(journal, "install_package", artifact.ID, evidence, installer.now()); err != nil {
				return InstallReceipt{}, err
			}
		}
		journal.State = "linking"
		if err = updateJournal(journal, installer.now()); err != nil {
			return InstallReceipt{}, err
		}
		for _, id := range manifest.InstallOrder {
			artifact, _ := manifest.Artifact(id)
			if artifact.Kind == ArtifactPackage {
				continue
			}
			execute, err := beginEffect(journal, "managed_link", artifact.ID, installer.now())
			if err != nil {
				return InstallReceipt{}, err
			}
			if err = ensureManagedLink(artifact.Destination); err != nil {
				return installer.handlePreActivationFailure(ctx, journal, trust, err)
			}
			if execute {
				if err = completeEffect(journal, "managed_link", artifact.ID, digestJSON(struct {
					Destination string `json:"destination"`
					Target      string `json:"target"`
				}{artifact.Destination, managedLinkTarget(artifact.Destination)}), installer.now()); err != nil {
					return InstallReceipt{}, err
				}
			}
		}
		execute, err := beginEffect(journal, "activate", manifest.ReleaseID, installer.now())
		if err != nil {
			return InstallReceipt{}, err
		}
		journal.State = "activation_prepared"
		if err = updateJournal(journal, installer.now()); err != nil {
			return InstallReceipt{}, err
		}
		// Retire units while their files still resolve through the old active
		// generation. After the switch a removed unit becomes a dangling link.
		if journal.Previous != nil {
			if err = retireRemovedServices(ctx, journal.Previous.Services, journal.Candidate.Services); err != nil {
				return installer.rollbackLocked(ctx, journal, trust, err)
			}
		}
		if err = switchActiveRelease(journal.Candidate.ReleasePath); err != nil {
			return installer.rollbackLocked(ctx, journal, trust, err)
		}
		if execute {
			if err = completeEffect(journal, "activate", manifest.ReleaseID, digestJSON(struct {
				Active string `json:"active"`
				Digest string `json:"digest"`
			}{ActiveRelease, manifest.ManifestDigest}), installer.now()); err != nil {
				return InstallReceipt{}, err
			}
		}
		journal.State = "activated"
		if err = updateJournal(journal, installer.now()); err != nil {
			return InstallReceipt{}, err
		}
	}
	journal.State = "probing"
	if err = updateJournal(journal, installer.now()); err != nil {
		return InstallReceipt{}, err
	}
	if journal.Previous != nil {
		if err = cleanupManagedLinks(journal.Previous.Destinations, journal.Candidate.Destinations); err != nil {
			return installer.rollbackLocked(ctx, journal, trust, err)
		}
	}
	if _, err = runSystemctl(ctx, "daemon-reload"); err != nil {
		return installer.rollbackLocked(ctx, journal, trust, err)
	}
	for _, service := range manifest.Services {
		execute, err := beginEffect(journal, "service_probe", service.Unit, installer.now())
		if err != nil {
			return InstallReceipt{}, err
		}
		if !execute {
			continue
		}
		evidence, probeErr := activateAndProbeService(ctx, service)
		if probeErr != nil {
			return installer.rollbackLocked(ctx, journal, trust, probeErr)
		}
		if err = completeEffect(journal, "service_probe", service.Unit, evidence, installer.now()); err != nil {
			return InstallReceipt{}, err
		}
	}
	activeDigest, err = observeActiveRelease()
	if err != nil || activeDigest != manifest.ManifestDigest {
		return installer.rollbackLocked(ctx, journal, trust, errors.Join(ErrIntegrity, err))
	}
	current, stateErr := loadInstalledState()
	next := InstalledState{SchemaVersion: ManifestSchema, Target: manifest.Target, HighestSequence: manifest.Sequence,
		Active: journal.Candidate, Generation: 1, UpdatedAt: installer.now()}
	if stateErr == nil {
		if current.Active.ManifestDigest != previousDigest || current.HighestSequence >= manifest.Sequence {
			return installer.rollbackLocked(ctx, journal, trust, ErrConflict)
		}
		previous := current.Active
		next.Previous = &previous
		next.Generation = current.Generation + 1
	} else if !errors.Is(stateErr, ErrNotFound) {
		return installer.rollbackLocked(ctx, journal, trust, stateErr)
	}
	if err = saveInstalledState(next); err != nil {
		return installer.rollbackLocked(ctx, journal, trust, err)
	}
	journal.State = "committed"
	journal.Failure = ""
	journal.CompletedAt = installer.now()
	if err = updateJournal(journal, installer.now()); err != nil {
		return InstallReceipt{}, err
	}
	return receiptFor(journal.OperationID, journal.Candidate, journal.State, journal.CompletedAt), nil
}

func (installer *Installer) handlePreActivationFailure(ctx context.Context, journal *Journal, trust TrustStore, cause error) (InstallReceipt, error) {
	if journal.Previous == nil {
		journal.State = "staged"
		journal.Failure = "pre_activation_effect_failed"
		if err := updateJournal(journal, installer.now()); err != nil {
			return InstallReceipt{}, errors.Join(cause, err)
		}
		return InstallReceipt{}, cause
	}
	if err := restorePackages(ctx, *journal.Previous, trust); err != nil {
		return installer.markRecovery(journal, "previous_package_restore_failed")
	}
	for index := range journal.Effects {
		if journal.Effects[index].Kind == "install_package" {
			journal.Effects[index].State = "started"
			journal.Effects[index].EvidenceDigest = ""
			journal.Effects[index].CompletedAt = time.Time{}
		}
	}
	journal.State = "staged"
	journal.Failure = "pre_activation_effect_failed"
	if err := updateJournal(journal, installer.now()); err != nil {
		return InstallReceipt{}, errors.Join(cause, err)
	}
	return InstallReceipt{}, cause
}

func installedPreviousMatchesJournal(installed, journal *InstalledRelease) bool {
	if installed == nil || journal == nil {
		return installed == nil && journal == nil
	}
	return digestJSON(*installed) == digestJSON(*journal)
}

func (installer *Installer) rollbackLocked(ctx context.Context, journal *Journal, trust TrustStore, cause error) (InstallReceipt, error) {
	journal.State = "rolling_back"
	journal.Failure = "candidate_activation_failed"
	if err := updateJournal(journal, installer.now()); err != nil {
		return InstallReceipt{}, errors.Join(cause, err)
	}
	for _, service := range journal.Candidate.Services {
		if err := stopService(ctx, service.Unit); err != nil {
			return installer.markRecovery(journal, "candidate_service_stop_failed")
		}
	}
	if journal.Previous == nil {
		if err := retireRemovedServices(ctx, journal.Candidate.Services, nil); err != nil {
			return installer.markRecovery(journal, "fresh_install_service_disable_failed")
		}
		active, err := observeActiveRelease()
		if err == nil && active == journal.ManifestDigest {
			if err = removeActiveRelease(); err != nil {
				return installer.markRecovery(journal, "fresh_install_deactivation_failed")
			}
		} else if err != nil && !errors.Is(err, ErrNotFound) || err == nil && active != journal.ManifestDigest {
			return installer.markRecovery(journal, "fresh_install_activation_ambiguous")
		}
		if err = cleanupManagedLinks(journal.Candidate.Destinations, nil); err != nil {
			return installer.markRecovery(journal, "fresh_install_link_cleanup_failed")
		}
		if _, err = runSystemctl(ctx, "daemon-reload"); err != nil {
			return installer.markRecovery(journal, "fresh_install_systemd_reload_failed")
		}
	} else {
		previousEnvelope, previousManifest, err := loadRetainedEnvelopeWithoutTime(*journal.Previous, trust)
		if err != nil {
			return installer.markRecovery(journal, "previous_release_integrity_failed")
		}
		_ = previousEnvelope
		if err = restorePackagesWithManifest(ctx, *journal.Previous, previousManifest); err != nil {
			return installer.markRecovery(journal, "previous_package_restore_failed")
		}
		if err = ensureManagedLinks(journal.Previous.Destinations); err != nil {
			return installer.markRecovery(journal, "previous_link_restore_failed")
		}
		if err = retireRemovedServices(ctx, journal.Candidate.Services, journal.Previous.Services); err != nil {
			return installer.markRecovery(journal, "candidate_service_disable_failed")
		}
		if err = switchActiveRelease(journal.Previous.ReleasePath); err != nil {
			return installer.markRecovery(journal, "previous_release_activation_failed")
		}
		if err = cleanupManagedLinks(journal.Candidate.Destinations, journal.Previous.Destinations); err != nil {
			return installer.markRecovery(journal, "candidate_link_cleanup_failed")
		}
		if _, err = runSystemctl(ctx, "daemon-reload"); err != nil {
			return installer.markRecovery(journal, "previous_systemd_reload_failed")
		}
		for _, service := range previousManifest.Services {
			if _, err = activateAndProbeService(ctx, service); err != nil {
				return installer.markRecovery(journal, "previous_service_probe_failed")
			}
		}
		active, err := observeActiveRelease()
		if err != nil || active != journal.Previous.ManifestDigest {
			return installer.markRecovery(journal, "previous_release_observation_failed")
		}
	}
	journal.State = "rolled_back"
	journal.CompletedAt = installer.now()
	if err := updateJournal(journal, installer.now()); err != nil {
		return InstallReceipt{}, errors.Join(cause, err)
	}
	receipt := receiptFor(journal.OperationID, journal.Candidate, journal.State, journal.CompletedAt)
	return receipt, cause
}

func (installer *Installer) recoverVerificationFailure(ctx context.Context, journal *Journal, trust TrustStore, cause error) (InstallReceipt, error) {
	switch journal.State {
	case "activation_prepared", "activated", "probing", "rolling_back":
		return installer.rollbackLocked(ctx, journal, trust, cause)
	default:
		active, activeErr := observeActiveRelease()
		if journal.Previous != nil && (activeErr != nil || active != journal.Previous.ManifestDigest) ||
			journal.Previous == nil && !errors.Is(activeErr, ErrNotFound) {
			return installer.markRecovery(journal, "pre_activation_position_ambiguous")
		}
		if journal.Previous != nil {
			if err := restorePackages(ctx, *journal.Previous, trust); err != nil {
				return installer.markRecovery(journal, "expired_candidate_package_restore_failed")
			}
		}
		var retained []string
		if journal.Previous != nil {
			retained = journal.Previous.Destinations
		}
		if err := cleanupManagedLinks(journal.Candidate.Destinations, retained); err != nil {
			return installer.markRecovery(journal, "expired_candidate_link_cleanup_failed")
		}
		journal.State = "rolled_back"
		journal.Failure = "candidate_verification_expired_or_failed"
		journal.CompletedAt = installer.now()
		if err := updateJournal(journal, installer.now()); err != nil {
			return InstallReceipt{}, errors.Join(cause, err)
		}
		return receiptFor(journal.OperationID, journal.Candidate, journal.State, journal.CompletedAt), cause
	}
}

func (installer *Installer) markRecovery(journal *Journal, reason string) (InstallReceipt, error) {
	journal.State = "recovery_required"
	journal.Failure = reason
	recoveryErr := fmt.Errorf("%w: operation %s: %s; inspect %s", ErrRecovery, journal.OperationID, reason, journalPath(journal.OperationID))
	if err := updateJournal(journal, installer.now()); err != nil {
		return InstallReceipt{}, errors.Join(recoveryErr, fmt.Errorf("persist recovery state: %w", err))
	}
	return InstallReceipt{}, recoveryErr
}

func beginEffect(journal *Journal, kind, resource string, now time.Time) (bool, error) {
	id := effectID(journal.ManifestDigest, kind, resource)
	for _, effect := range journal.Effects {
		if effect.ID != id {
			continue
		}
		if effect.Kind != kind || effect.Resource != resource {
			return false, ErrIntegrity
		}
		return effect.State != "completed", nil
	}
	journal.Effects = append(journal.Effects, EffectRecord{ID: id, Kind: kind, Resource: resource, State: "started", StartedAt: now})
	if err := updateJournal(journal, now); err != nil {
		return false, err
	}
	return true, nil
}

func resetEffects(journal *Journal, kind string) {
	for index := range journal.Effects {
		if journal.Effects[index].Kind != kind {
			continue
		}
		journal.Effects[index].State = "started"
		journal.Effects[index].EvidenceDigest = ""
		journal.Effects[index].CompletedAt = time.Time{}
	}
}

func completedEffectEvidence(journal *Journal, kind, resource string) (string, error) {
	id := effectID(journal.ManifestDigest, kind, resource)
	for _, effect := range journal.Effects {
		if effect.ID == id && effect.Kind == kind && effect.Resource == resource && effect.State == "completed" && validDigest(effect.EvidenceDigest) {
			return effect.EvidenceDigest, nil
		}
	}
	return "", ErrIntegrity
}

func restartEffect(journal *Journal, kind, resource string, now time.Time) error {
	id := effectID(journal.ManifestDigest, kind, resource)
	for index := range journal.Effects {
		effect := &journal.Effects[index]
		if effect.ID != id {
			continue
		}
		if effect.Kind != kind || effect.Resource != resource {
			return ErrIntegrity
		}
		effect.State = "started"
		effect.EvidenceDigest = ""
		effect.StartedAt = now
		effect.CompletedAt = time.Time{}
		return updateJournal(journal, now)
	}
	return ErrNotFound
}

func completeEffect(journal *Journal, kind, resource, evidence string, now time.Time) error {
	if !validDigest(evidence) {
		return ErrIntegrity
	}
	id := effectID(journal.ManifestDigest, kind, resource)
	for index := range journal.Effects {
		effect := &journal.Effects[index]
		if effect.ID == id {
			if effect.Kind != kind || effect.Resource != resource {
				return ErrIntegrity
			}
			effect.State = "completed"
			effect.EvidenceDigest = evidence
			effect.CompletedAt = now
			return updateJournal(journal, now)
		}
	}
	return ErrNotFound
}

func (installer *Installer) reconcileLocked(ctx context.Context, except string) ([]InstallReceipt, error) {
	journals, err := loadJournals()
	if err != nil {
		return nil, err
	}
	var trust TrustStore
	trustLoaded := false
	receipts := make([]InstallReceipt, 0, len(journals))
	for index := range journals {
		journal := journals[index]
		if journal.OperationID == except || journal.State == "committed" || journal.State == "rolled_back" {
			continue
		}
		if !trustLoaded {
			trust, err = LoadTrustStore(TrustRoot)
			if err != nil {
				return receipts, err
			}
			trustLoaded = true
		}
		receipt, reconcileErr := installer.resumeLocked(ctx, &journal, trust)
		if reconcileErr != nil {
			return receipts, reconcileErr
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func journalPath(operation string) string {
	return filepath.Join(JournalRoot, operation+".json")
}

func loadJournal(operation string) (Journal, error) {
	if !identifier.MatchString(operation) {
		return Journal{}, ErrInvalid
	}
	payload, err := readRootOwnedFile(journalPath(operation), 8<<20, 0600)
	if os.IsNotExist(err) {
		return Journal{}, ErrNotFound
	}
	if err != nil {
		return Journal{}, err
	}
	var journal Journal
	if decodeStrictJSON(payload, &journal) != nil || validateJournal(journal) != nil {
		return Journal{}, ErrIntegrity
	}
	return journal, nil
}

func loadJournals() ([]Journal, error) {
	entries, err := os.ReadDir(JournalRoot)
	if err != nil {
		return nil, err
	}
	journals := make([]Journal, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		operation := strings.TrimSuffix(entry.Name(), ".json")
		journal, err := loadJournal(operation)
		if err != nil {
			return nil, err
		}
		journals = append(journals, journal)
	}
	sort.Slice(journals, func(i, j int) bool {
		if journals[i].CreatedAt.Equal(journals[j].CreatedAt) {
			return journals[i].OperationID < journals[j].OperationID
		}
		return journals[i].CreatedAt.Before(journals[j].CreatedAt)
	})
	return journals, nil
}

func saveJournal(journal Journal) error {
	if validateJournal(journal) != nil {
		return ErrIntegrity
	}
	payload, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return writeDurableFile(journalPath(journal.OperationID), payload, 0600, 0, 0)
}

func updateJournal(journal *Journal, now time.Time) error {
	if journal == nil || journal.Generation == ^uint64(0) {
		return ErrInvalid
	}
	journal.Generation++
	journal.UpdatedAt = now
	return saveJournal(*journal)
}

func validateJournal(journal Journal) error {
	if journal.SchemaVersion != ManifestSchema || !identifier.MatchString(journal.OperationID) || !validDigest(journal.ManifestDigest) ||
		journal.OperationID != operationID(journal.ManifestDigest) || journal.Candidate.ManifestDigest != journal.ManifestDigest ||
		validateInstalledRelease(journal.Candidate) != nil || journal.Generation == 0 || !canonicalTime(journal.CreatedAt) ||
		!canonicalTime(journal.UpdatedAt) || journal.UpdatedAt.Before(journal.CreatedAt) || len(journal.Effects) > 8192 {
		return ErrIntegrity
	}
	if journal.Previous != nil {
		if validateInstalledRelease(*journal.Previous) != nil || journal.Previous.Target.Key() != journal.Candidate.Target.Key() ||
			journal.Previous.Sequence >= journal.Candidate.Sequence {
			return ErrIntegrity
		}
	}
	switch journal.State {
	case "staged", "installing_packages", "linking", "activation_prepared", "activated", "probing", "rolling_back", "committed", "rolled_back", "recovery_required":
	default:
		return ErrIntegrity
	}
	if (journal.State == "committed" || journal.State == "rolled_back") != !journal.CompletedAt.IsZero() ||
		!journal.CompletedAt.IsZero() && (!canonicalTime(journal.CompletedAt) || journal.CompletedAt.Before(journal.CreatedAt)) {
		return ErrIntegrity
	}
	seen := make(map[string]bool, len(journal.Effects))
	for _, effect := range journal.Effects {
		if !validDigest(effect.ID) || seen[effect.ID] || effect.ID != effectID(journal.ManifestDigest, effect.Kind, effect.Resource) ||
			!identifier.MatchString(effect.Kind) || (!identifier.MatchString(effect.Resource) && !unitName.MatchString(effect.Resource)) ||
			!canonicalTime(effect.StartedAt) || effect.StartedAt.Before(journal.CreatedAt) {
			return ErrIntegrity
		}
		seen[effect.ID] = true
		if effect.State == "completed" {
			if !validDigest(effect.EvidenceDigest) || !canonicalTime(effect.CompletedAt) || effect.CompletedAt.Before(effect.StartedAt) {
				return ErrIntegrity
			}
		} else if effect.State != "started" || effect.EvidenceDigest != "" || !effect.CompletedAt.IsZero() {
			return ErrIntegrity
		}
	}
	return nil
}

func admitFrontier(manifest Manifest, now time.Time) error {
	frontier, err := loadAdmissionFrontier()
	if errors.Is(err, ErrNotFound) {
		return saveAdmissionFrontier(AdmissionFrontier{SchemaVersion: ManifestSchema, Target: manifest.Target,
			HighestSequence: manifest.Sequence, ManifestDigest: manifest.ManifestDigest, UpdatedAt: now})
	}
	if err != nil {
		return err
	}
	if frontier.Target.Key() != manifest.Target.Key() {
		return ErrUnsupported
	}
	if frontier.HighestSequence == manifest.Sequence && frontier.ManifestDigest == manifest.ManifestDigest {
		return nil
	}
	if manifest.Sequence <= frontier.HighestSequence {
		return fmt.Errorf("%w: release sequence %d is not above durable admission frontier %d", ErrRollback,
			manifest.Sequence, frontier.HighestSequence)
	}
	return saveAdmissionFrontier(AdmissionFrontier{SchemaVersion: ManifestSchema, Target: manifest.Target,
		HighestSequence: manifest.Sequence, ManifestDigest: manifest.ManifestDigest, UpdatedAt: now})
}

func loadAdmissionFrontier() (AdmissionFrontier, error) {
	payload, err := readRootOwnedFile(FrontierPath, 1<<20, 0600)
	if os.IsNotExist(err) {
		return AdmissionFrontier{}, ErrNotFound
	}
	if err != nil {
		return AdmissionFrontier{}, err
	}
	var frontier AdmissionFrontier
	if decodeStrictJSON(payload, &frontier) != nil || validateAdmissionFrontier(frontier) != nil {
		return AdmissionFrontier{}, ErrIntegrity
	}
	return frontier, nil
}

func saveAdmissionFrontier(frontier AdmissionFrontier) error {
	if validateAdmissionFrontier(frontier) != nil {
		return ErrIntegrity
	}
	payload, err := json.Marshal(frontier)
	if err != nil {
		return err
	}
	return writeDurableFile(FrontierPath, payload, 0600, 0, 0)
}

func validateAdmissionFrontier(frontier AdmissionFrontier) error {
	if frontier.SchemaVersion != ManifestSchema || frontier.Target.Validate() != nil || frontier.HighestSequence == 0 ||
		!validDigest(frontier.ManifestDigest) || !canonicalTime(frontier.UpdatedAt) {
		return ErrIntegrity
	}
	return nil
}

func loadInstalledState() (InstalledState, error) {
	payload, err := readRootOwnedFile(installedPath, 8<<20, 0600)
	if os.IsNotExist(err) {
		return InstalledState{}, ErrNotFound
	}
	if err != nil {
		return InstalledState{}, err
	}
	var state InstalledState
	if decodeStrictJSON(payload, &state) != nil || validateInstalledState(state) != nil {
		return InstalledState{}, ErrIntegrity
	}
	return state, nil
}

func saveInstalledState(state InstalledState) error {
	if validateInstalledState(state) != nil {
		return ErrIntegrity
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeDurableFile(installedPath, payload, 0600, 0, 0)
}

func validateInstalledState(state InstalledState) error {
	if state.SchemaVersion != ManifestSchema || state.Target.Validate() != nil || validateInstalledRelease(state.Active) != nil ||
		state.Target.Key() != state.Active.Target.Key() || state.HighestSequence != state.Active.Sequence || state.Generation == 0 ||
		!canonicalTime(state.UpdatedAt) {
		return ErrIntegrity
	}
	if state.Previous != nil && (validateInstalledRelease(*state.Previous) != nil || state.Previous.Target.Key() != state.Target.Key() ||
		state.Previous.Sequence >= state.Active.Sequence || state.Previous.ManifestDigest == state.Active.ManifestDigest) {
		return ErrIntegrity
	}
	return nil
}

func validateInstalledRelease(release InstalledRelease) error {
	if !identifier.MatchString(release.ReleaseID) || !validDigest(release.ManifestDigest) || release.Sequence == 0 ||
		release.ProductVersion.zero() || release.ProductSchema == 0 || release.Target.Validate() != nil ||
		release.ReleasePath != filepath.Join(ReleaseRoot, release.ManifestDigest) || len(release.Destinations) == 0 ||
		len(release.Packages) == 0 || len(release.Services) == 0 {
		return ErrIntegrity
	}
	for index, destination := range release.Destinations {
		if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || index > 0 && release.Destinations[index-1] >= destination {
			return ErrIntegrity
		}
	}
	for index, id := range release.Packages {
		if !identifier.MatchString(id) || index > 0 && release.Packages[index-1] >= id {
			return ErrIntegrity
		}
	}
	for index, service := range release.Services {
		if service.validate() != nil || index > 0 && release.Services[index-1].Unit >= service.Unit {
			return ErrIntegrity
		}
	}
	return nil
}

func loadRetainedEnvelope(release InstalledRelease, trust TrustStore, now time.Time) (SignedManifest, Manifest, error) {
	payload, err := readRootOwnedFile(filepath.Join(release.ReleasePath, BundleManifestPath), maximumSpecBytes, 0600)
	if err != nil {
		return SignedManifest{}, Manifest{}, err
	}
	var envelope SignedManifest
	if decodeStrictJSON(payload, &envelope) != nil {
		return SignedManifest{}, Manifest{}, ErrIntegrity
	}
	manifest, err := trust.Verify(envelope, now)
	if err != nil || manifest.ManifestDigest != release.ManifestDigest || manifest.ReleaseID != release.ReleaseID ||
		manifest.Sequence != release.Sequence || manifest.Target.Key() != release.Target.Key() {
		return SignedManifest{}, Manifest{}, errors.Join(ErrIntegrity, err)
	}
	if err = verifyReleaseTree(release.ReleasePath, manifest); err != nil {
		return SignedManifest{}, Manifest{}, err
	}
	envelope.Manifest = manifest
	return envelope, manifest, nil
}

func loadRetainedEnvelopeWithoutTime(release InstalledRelease, trust TrustStore) (SignedManifest, Manifest, error) {
	payload, err := readRootOwnedFile(filepath.Join(release.ReleasePath, BundleManifestPath), maximumSpecBytes, 0600)
	if err != nil {
		return SignedManifest{}, Manifest{}, err
	}
	var envelope SignedManifest
	if decodeStrictJSON(payload, &envelope) != nil {
		return SignedManifest{}, Manifest{}, ErrIntegrity
	}
	manifest, err := trust.VerifyRetained(envelope)
	if err != nil || manifest.ManifestDigest != release.ManifestDigest || manifest.ReleaseID != release.ReleaseID ||
		manifest.Sequence != release.Sequence || manifest.Target.Key() != release.Target.Key() {
		return SignedManifest{}, Manifest{}, errors.Join(ErrIntegrity, err)
	}
	if err = verifyReleaseTree(release.ReleasePath, manifest); err != nil {
		return SignedManifest{}, Manifest{}, err
	}
	envelope.Manifest = manifest
	return envelope, manifest, nil
}

func writeDurableFile(path string, payload []byte, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	complete := false
	defer func() {
		_ = temporary.Close()
		if !complete {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(mode); err != nil {
		return err
	}
	if err = temporary.Chown(uid, gid); err != nil {
		return err
	}
	if _, err = temporary.Write(payload); err != nil {
		return err
	}
	if err = temporary.Sync(); err != nil {
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return err
	}
	if err = syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	complete = true
	return nil
}

func ensureRootDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	if err := validateRootOwnedAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return errors.Join(ErrIntegrity, err)
	}
	metadata, ok := entryMetadata(info)
	if !ok || metadata.Uid != 0 || metadata.Gid != 0 {
		return ErrIntegrity
	}
	return nil
}

func probeTarget() (Target, error) {
	payload, err := os.ReadFile("/etc/os-release")
	if err != nil || len(payload) == 0 || len(payload) > 64<<10 {
		return Target{}, errors.Join(ErrUnsupported, err)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return Target{}, ErrUnsupported
		}
		value := strings.Trim(parts[1], "\"")
		values[parts[0]] = value
	}
	target := Target{}
	switch values["ID"] {
	case "ubuntu":
		target.Distribution, target.Release, target.Codename = DistributionUbuntu, values["VERSION_ID"], values["VERSION_CODENAME"]
	case "almalinux":
		target.Distribution, target.Release, target.Codename = DistributionAlma, strings.SplitN(values["VERSION_ID"], ".", 2)[0], "el9"
	default:
		return Target{}, ErrUnsupported
	}
	switch runtime.GOARCH {
	case "amd64":
		target.Architecture = ArchitectureAMD64
	case "arm64":
		target.Architecture = ArchitectureARM64
	default:
		return Target{}, ErrUnsupported
	}
	if err = target.Validate(); err != nil {
		return Target{}, err
	}
	return target, nil
}

func verifyPackageMetadata(ctx context.Context, path string, artifact Artifact, target Target) error {
	if artifact.Package == nil || artifact.Package.validate(target) != nil {
		return ErrInvalid
	}
	name, version, architecture, err := packageFields(ctx, path, artifact.Package.Manager, true, artifact.Package.Name)
	if err != nil || name != artifact.Package.Name || version != artifact.Package.Version || architecture != artifact.Package.Architecture {
		return errors.Join(ErrIntegrity, err)
	}
	if err = verifyPackageInventory(ctx, path, artifact.Package.Manager); err != nil {
		return err
	}
	return nil
}

func verifyPackageInventory(ctx context.Context, path string, manager PackageManager) error {
	var output string
	var err error
	if manager == PackageDPKG {
		output, err = runFixed(ctx, "/usr/bin/dpkg-deb", "--contents", path)
	} else {
		output, err = runFixed(ctx, "/usr/bin/rpm", "-qpl", path)
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		member := strings.TrimSpace(line)
		if manager == PackageDPKG {
			position := strings.LastIndex(member, " ./")
			if position < 0 {
				return ErrIntegrity
			}
			member = member[position+2:]
		} else if !strings.HasPrefix(member, "/") {
			return ErrIntegrity
		}
		member = strings.SplitN(member, " -> ", 2)[0]
		rawMember := "/" + strings.TrimPrefix(filepath.ToSlash(member), "/")
		rawMember = strings.TrimSuffix(rawMember, "/")
		if rawMember == "" {
			rawMember = "/"
		}
		member = filepath.Clean(rawMember)
		if member != rawMember || strings.ContainsRune(member, '\x00') {
			return ErrIntegrity
		}
		if forbiddenPackageMember(member) && !privateCertificateDirectoryInventory(line, manager) {
			return fmt.Errorf("%w: OS package contains protected host path %s", ErrIntegrity, member)
		}
	}
	return nil
}

// Debian's ssl-cert ships this empty 0700 directory, not private material.
// Do not generalize the exception to files, symlinks, descendants or RPM's
// path-only inventory, which cannot establish type/ownership/mode.
func privateCertificateDirectoryInventory(line string, manager PackageManager) bool {
	fields := strings.Fields(line)
	return manager == PackageDPKG && len(fields) == 6 && fields[0] == "drwx------" && fields[1] == "root/root" && fields[2] == "0" && fields[5] == "./etc/ssl/private/"
}

func forbiddenPackageMember(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, prefix := range []string{
		"/etc/cyberpanel/node-release", "/etc/cyberpanel/secrets", "/etc/cyberpanel/credentials",
		"/etc/cyberpanel/node-identity", "/etc/cyberpanel/host-identity", "/etc/cyberpanel/identity",
		"/var/lib/cyberpanel/node-release", "/var/lib/cyberpanel/node-identity",
		"/opt/cyberpanel/node-releases", "/opt/cyberpanel/node-current",
		"/usr/local/sbin/panel-node-install", "/etc/systemd/system/panel-node-release-reconcile.service",
		"/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostname", "/etc/machine-info",
		"/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group", "/etc/subuid", "/etc/subgid",
		"/etc/ssl/private", "/root", "/home", "/var/lib/systemd/random-seed", "/var/lib/cloud/instance",
	} {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			return true
		}
	}
	for _, prefix := range []string{"/etc/ssh/ssh_host_", "/etc/hostname.", "/etc/machine-id."} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func packageFields(ctx context.Context, path string, manager PackageManager, archive bool, name string) (string, string, string, error) {
	if manager == PackageDPKG {
		if archive {
			packageName, err := runFixed(ctx, "/usr/bin/dpkg-deb", "--field", path, "Package")
			if err != nil {
				return "", "", "", err
			}
			version, err := runFixed(ctx, "/usr/bin/dpkg-deb", "--field", path, "Version")
			if err != nil {
				return "", "", "", err
			}
			architecture, err := runFixed(ctx, "/usr/bin/dpkg-deb", "--field", path, "Architecture")
			return strings.TrimSpace(packageName), strings.TrimSpace(version), strings.TrimSpace(architecture), err
		}
		output, err := runFixed(ctx, "/usr/bin/dpkg-query", "--show", "--showformat=${Package}\\n${Version}\\n${Architecture}\\n", name)
		if err != nil {
			return "", "", "", err
		}
		fields := strings.Split(strings.TrimSpace(output), "\n")
		if len(fields) != 3 {
			return "", "", "", ErrIntegrity
		}
		return fields[0], fields[1], fields[2], nil
	}
	format := "%{NAME}\\n%{VERSION}-%{RELEASE}\\n%{ARCH}\\n"
	arguments := []string{"-q", "--qf", format, name}
	if archive {
		arguments = []string{"-qp", "--qf", format, path}
	}
	output, err := runFixed(ctx, "/usr/bin/rpm", arguments...)
	if err != nil {
		return "", "", "", err
	}
	fields := strings.Split(strings.TrimSpace(output), "\n")
	if len(fields) != 3 {
		return "", "", "", ErrIntegrity
	}
	return fields[0], fields[1], fields[2], nil
}

func installOfflinePackage(ctx context.Context, path string, artifact Artifact, target Target) (string, error) {
	if err := verifyPackageMetadata(ctx, path, artifact, target); err != nil {
		return "", err
	}
	var err error
	if artifact.Package.Manager == PackageDPKG {
		_, err = runOfflineFixed(ctx, "/usr/bin/dpkg", "--force-downgrade", "--install", path)
	} else {
		_, err = runOfflineFixed(ctx, "/usr/bin/rpm", "-U", "--replacepkgs", "--oldpackage", path)
	}
	if err != nil {
		return "", err
	}
	return installedPackageEvidence(ctx, artifact)
}

func installedPackageEvidence(ctx context.Context, artifact Artifact) (string, error) {
	if artifact.Package == nil {
		return "", ErrInvalid
	}
	name, version, architecture, err := packageFields(ctx, "", artifact.Package.Manager, false, artifact.Package.Name)
	if err != nil || name != artifact.Package.Name || version != artifact.Package.Version || architecture != artifact.Package.Architecture {
		return "", errors.Join(ErrIntegrity, err)
	}
	return digestJSON(struct {
		Name         string `json:"name"`
		Version      string `json:"version"`
		Architecture string `json:"architecture"`
	}{name, version, architecture}), nil
}

func restorePackages(ctx context.Context, release InstalledRelease, trust TrustStore) error {
	_, manifest, err := loadRetainedEnvelopeWithoutTime(release, trust)
	if err != nil {
		return err
	}
	return restorePackagesWithManifest(ctx, release, manifest)
}

func restorePackagesWithManifest(ctx context.Context, release InstalledRelease, manifest Manifest) error {
	for _, id := range manifest.InstallOrder {
		artifact, _ := manifest.Artifact(id)
		if artifact.Kind != ArtifactPackage {
			continue
		}
		if _, err := installOfflinePackage(ctx, filepath.Join(release.ReleasePath, "packages", artifact.ID), artifact, manifest.Target); err != nil {
			return err
		}
	}
	return nil
}

func runFixed(ctx context.Context, path string, arguments ...string) (string, error) {
	return runFixedMode(ctx, path, false, arguments...)
}

func runOfflineFixed(ctx context.Context, path string, arguments ...string) (string, error) {
	return runFixedMode(ctx, path, true, arguments...)
}

func runFixedMode(ctx context.Context, path string, isolateNetwork bool, arguments ...string) (string, error) {
	allowed := map[string]bool{
		"/usr/bin/dpkg-deb":   true,
		"/usr/bin/dpkg":       true,
		"/usr/bin/dpkg-query": true,
		"/usr/bin/rpm":        true,
		"/usr/bin/systemctl":  true,
	}
	if !allowed[path] {
		return "", ErrUnsupported
	}
	info, err := os.Lstat(path)
	metadata, ok := entryMetadata(info)
	if err != nil || !ok || metadata.Uid != 0 || metadata.Gid != 0 || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return "", errors.Join(ErrIntegrity, err)
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "SYSTEMD_PAGER="}
	if isolateNetwork {
		command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	}
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = &output
	err = command.Run()
	if output.exceeded {
		return output.String(), fmt.Errorf("%w: %s output exceeded the 16 MiB limit", ErrIntegrity, filepath.Base(path))
	}
	if err != nil {
		return output.String(), fmt.Errorf("%s failed: %w: %s", filepath.Base(path), err, commandDiagnostic(output.String()))
	}
	return output.String(), nil
}

type boundedOutput struct {
	buffer   bytes.Buffer
	exceeded bool
}

func (output *boundedOutput) Write(payload []byte) (int, error) {
	const maximum = 16 << 20
	if output.buffer.Len()+len(payload) > maximum {
		remaining := maximum - output.buffer.Len()
		if remaining > 0 {
			_, _ = output.buffer.Write(payload[:remaining])
		}
		output.exceeded = true
		return remaining, ErrIntegrity
	}
	return output.buffer.Write(payload)
}

func (output *boundedOutput) String() string {
	return output.buffer.String()
}

func commandDiagnostic(output string) string {
	const maximum = 4 << 10
	output = strings.TrimSpace(output)
	if len(output) <= maximum {
		return output
	}
	return output[:maximum] + "...[truncated]"
}

func managedLinkTarget(destination string) string {
	return filepath.Join(ActiveRelease, "root", strings.TrimPrefix(destination, "/"))
}

func validateManagedDestinations(manifest Manifest) error {
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind == ArtifactPackage {
			continue
		}
		if err := validateManagedDestination(artifact.Destination); err != nil {
			return fmt.Errorf("managed destination %s: %w", artifact.Destination, err)
		}
	}
	return nil
}

func validateManagedDestination(destination string) error {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return ErrInvalid
	}
	if err := validateRootOwnedAncestors(filepath.Dir(destination)); err != nil {
		return err
	}
	info, err := os.Lstat(destination)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return errors.Join(ErrConflict, err)
	}
	metadata, ok := entryMetadata(info)
	if !ok || metadata.Uid != 0 || metadata.Gid != 0 {
		return ErrIntegrity
	}
	target, err := os.Readlink(destination)
	if err != nil || target != managedLinkTarget(destination) {
		return errors.Join(ErrConflict, err)
	}
	return nil
}

func validateRootOwnedAncestors(path string) error {
	current := path
	for {
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			parent := filepath.Dir(current)
			if parent == current {
				return ErrIntegrity
			}
			current = parent
			continue
		}
		metadata, ok := entryMetadata(info)
		if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || metadata.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.Join(ErrIntegrity, err)
		}
		return nil
	}
}

func ensureManagedLink(destination string) error {
	if err := validateManagedDestination(destination); err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if err := ensureRootParents(filepath.Dir(destination)); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(destination), ".node-release-link-"+filepath.Base(destination))
	if err := os.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(managedLinkTarget(destination), temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func ensureManagedLinks(destinations []string) error {
	for _, destination := range destinations {
		if err := ensureManagedLink(destination); err != nil {
			return err
		}
	}
	return nil
}

func ensureRootParents(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	current := path
	for current != "/" {
		info, err := os.Lstat(current)
		metadata, ok := entryMetadata(info)
		if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || metadata.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.Join(ErrIntegrity, err)
		}
		current = filepath.Dir(current)
	}
	return nil
}

func observeActiveRelease() (string, error) {
	info, err := os.Lstat(ActiveRelease)
	if os.IsNotExist(err) {
		return "", ErrNotFound
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", errors.Join(ErrIntegrity, err)
	}
	metadata, ok := entryMetadata(info)
	if !ok || metadata.Uid != 0 || metadata.Gid != 0 {
		return "", ErrIntegrity
	}
	target, err := os.Readlink(ActiveRelease)
	if err != nil || !filepath.IsAbs(target) || filepath.Dir(target) != ReleaseRoot || !validDigest(filepath.Base(target)) {
		return "", errors.Join(ErrIntegrity, err)
	}
	root, err := filepath.EvalSymlinks(target)
	if err != nil || root != target {
		return "", errors.Join(ErrIntegrity, err)
	}
	return filepath.Base(target), nil
}

func switchActiveRelease(releasePath string) error {
	if !filepath.IsAbs(releasePath) || filepath.Dir(releasePath) != ReleaseRoot || !validDigest(filepath.Base(releasePath)) {
		return ErrInvalid
	}
	info, err := os.Lstat(releasePath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrIntegrity, err)
	}
	if digest, observeErr := observeActiveRelease(); observeErr == nil && digest == filepath.Base(releasePath) {
		return nil
	} else if observeErr != nil && !errors.Is(observeErr, ErrNotFound) {
		return observeErr
	}
	if err = ensureRootParents(filepath.Dir(ActiveRelease)); err != nil {
		return err
	}
	temporary := ActiveRelease + ".new"
	if err = os.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err = os.Symlink(releasePath, temporary); err != nil {
		return err
	}
	if err = os.Rename(temporary, ActiveRelease); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(filepath.Dir(ActiveRelease))
}

func removeActiveRelease() error {
	info, err := os.Lstat(ActiveRelease)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return errors.Join(ErrIntegrity, err)
	}
	if err = os.Remove(ActiveRelease); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(ActiveRelease))
}

func cleanupManagedLinks(candidate, retained []string) error {
	keep := make(map[string]bool, len(retained))
	for _, destination := range retained {
		keep[destination] = true
	}
	for _, destination := range candidate {
		if keep[destination] {
			continue
		}
		info, err := os.Lstat(destination)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return errors.Join(ErrIntegrity, err)
		}
		metadata, ok := entryMetadata(info)
		if !ok || metadata.Uid != 0 || metadata.Gid != 0 {
			return ErrIntegrity
		}
		target, err := os.Readlink(destination)
		if err != nil || target != managedLinkTarget(destination) {
			return errors.Join(ErrIntegrity, err)
		}
		if err = os.Remove(destination); err != nil {
			return err
		}
		if err = syncDirectory(filepath.Dir(destination)); err != nil {
			return err
		}
	}
	return nil
}

func runSystemctl(ctx context.Context, action string, unit ...string) (string, error) {
	switch action {
	case "daemon-reload":
		if len(unit) != 0 {
			return "", ErrInvalid
		}
	case "enable", "disable", "restart", "stop", "is-active", "show":
		if len(unit) != 1 || !unitName.MatchString(unit[0]) {
			return "", ErrInvalid
		}
	default:
		return "", ErrUnsupported
	}
	arguments := []string{action}
	if action == "show" {
		arguments = []string{"show", "--property=ActiveState", "--property=SubState", "--property=ActiveEnterTimestampMonotonic", "--property=ExecMainPID"}
	}
	arguments = append(arguments, unit...)
	return runFixed(ctx, "/usr/bin/systemctl", arguments...)
}

func activateAndProbeService(ctx context.Context, probe ServiceProbe) (string, error) {
	if probe.validate() != nil {
		return "", ErrInvalid
	}
	if _, err := runSystemctl(ctx, "enable", probe.Unit); err != nil {
		return "", err
	}
	beforeOutput, _ := runSystemctl(ctx, "show", probe.Unit)
	before := parseSystemdProperties(beforeOutput)
	beforeStarted, _ := strconv.ParseUint(before["ActiveEnterTimestampMonotonic"], 10, 64)
	if _, err := runSystemctl(ctx, "restart", probe.Unit); err != nil {
		return "", err
	}
	deadline := time.Now().Add(time.Duration(probe.TimeoutSeconds) * time.Second)
	stableWindow := time.Duration(probe.TimeoutSeconds) * time.Second / 2
	if stableWindow > 2*time.Second { stableWindow = 2*time.Second }
	var last string
	var stableSince time.Time
	var stableStarted uint64
	for {
		active, activeErr := runSystemctl(ctx, "is-active", probe.Unit)
		last = strings.TrimSpace(active)
		if activeErr == nil && last == "active" {
			show, showErr := runSystemctl(ctx, "show", probe.Unit)
			if showErr != nil {
				return "", showErr
			}
			properties := parseSystemdProperties(show)
			started, parseErr := strconv.ParseUint(properties["ActiveEnterTimestampMonotonic"], 10, 64)
			if parseErr != nil || properties["ActiveState"] != "active" || started == 0 || started <= beforeStarted {
				return "", ErrIntegrity
			}
			if stableStarted != started {
				stableStarted, stableSince = started, time.Now()
			}
			// Type=simple becomes active before application initialization.
			// Require the same activation to survive multiple observations;
			// an auto-restart must not count as continuous readiness.
			if time.Since(stableSince) >= stableWindow {
			return digestJSON(struct {
				Unit       string            `json:"unit"`
				Properties map[string]string `json:"properties"`
			}{probe.Unit, properties}), nil
			}
		} else {
			stableStarted, stableSince = 0, time.Time{}
		}
		if !time.Now().Before(deadline) {
			return "", fmt.Errorf("%w: %s did not become freshly active (%s)", ErrRecovery, probe.Unit, last)
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
}

func retireRemovedServices(ctx context.Context, existing, retained []ServiceProbe) error {
	keep := make(map[string]bool, len(retained))
	for _, service := range retained {
		keep[service.Unit] = true
	}
	for _, service := range existing {
		if keep[service.Unit] {
			continue
		}
		if err := stopService(ctx, service.Unit); err != nil {
			return err
		}
		if _, err := runSystemctl(ctx, "disable", service.Unit); err != nil {
			return err
		}
	}
	return nil
}

func stopService(ctx context.Context, unit string) error {
	if _, err := runSystemctl(ctx, "stop", unit); err == nil {
		return nil
	} else {
		state, stateErr := runSystemctl(ctx, "is-active", unit)
		switch strings.TrimSpace(state) {
		case "inactive", "failed", "unknown":
			return nil
		default:
			return errors.Join(err, stateErr)
		}
	}
}

func parseSystemdProperties(output string) map[string]string {
	properties := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			properties[parts[0]] = parts[1]
		}
	}
	return properties
}
