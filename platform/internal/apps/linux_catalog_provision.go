//go:build linux

package apps

import (
	"bytes"
	"context"
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
)

const (
	linuxApplicationCatalogSchemaVersion = 1
	linuxApplicationCatalogManifestName  = "manifest.json"
	linuxApplicationCatalogMaximumKeys   = 64
	linuxApplicationCatalogMaximumItems  = 512
)

// LinuxApplicationCatalogKey binds a release-provided public key to the
// catalog epochs for which it is authoritative.
type LinuxApplicationCatalogKey struct {
	ID           string `json:"id"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	MinimumEpoch uint64 `json:"minimum_epoch"`
	MaximumEpoch uint64 `json:"maximum_epoch"`
}

// LinuxApplicationCatalogRecipe describes one signed recipe envelope. The
// digest covers the envelope; RecipeReference.RecipeDigest covers its
// canonical signed payload independently.
type LinuxApplicationCatalogRecipe struct {
	ID     RecipeID `json:"id"`
	SHA256 string   `json:"sha256"`
	Size   int64    `json:"size"`
}

// LinuxApplicationCatalogArtifact describes one release-local artifact. Its
// filename is always <sha256>.tar.gz and no URL is consulted while installing.
type LinuxApplicationCatalogArtifact struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// LinuxApplicationCatalogManifest is shipped inside the already verified
// panel release. ContentDigest binds the complete ordered catalog inventory.
type LinuxApplicationCatalogManifest struct {
	SchemaVersion uint32                            `json:"schema_version"`
	CatalogID     string                            `json:"catalog_id"`
	Sequence      uint64                            `json:"sequence"`
	MinimumEpoch  uint64                            `json:"minimum_epoch"`
	ReleaseID     string                            `json:"release_id"`
	CreatedAt     time.Time                         `json:"created_at"`
	Keys          []LinuxApplicationCatalogKey      `json:"keys"`
	Recipes       []LinuxApplicationCatalogRecipe   `json:"recipes"`
	Artifacts     []LinuxApplicationCatalogArtifact `json:"artifacts"`
	ContentDigest string                            `json:"content_digest"`
}

// Digest computes the manifest inventory digest used by the release builder
// and by the host provisioner.
func (manifest LinuxApplicationCatalogManifest) Digest() (string, error) {
	manifest.ContentDigest = ""
	payload, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func (manifest LinuxApplicationCatalogManifest) Validate(now time.Time) error {
	if manifest.SchemaVersion != linuxApplicationCatalogSchemaVersion || !validID(manifest.CatalogID) || !validID(manifest.ReleaseID) || manifest.Sequence == 0 || manifest.MinimumEpoch == 0 || manifest.CreatedAt.IsZero() || manifest.CreatedAt.After(now.Add(5*time.Minute)) || !validDigest(manifest.ContentDigest) {
		return ErrRecipeUntrusted
	}
	if len(manifest.Keys) == 0 || len(manifest.Keys) > linuxApplicationCatalogMaximumKeys || len(manifest.Recipes) == 0 || len(manifest.Recipes) > linuxApplicationCatalogMaximumItems || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > linuxApplicationCatalogMaximumItems {
		return ErrRecipeUntrusted
	}
	for index, key := range manifest.Keys {
		if !validID(key.ID) || !validDigest(key.SHA256) || key.Size <= 0 || key.Size > 4096 || key.MinimumEpoch < manifest.MinimumEpoch || key.MaximumEpoch < key.MinimumEpoch || index > 0 && manifest.Keys[index-1].ID >= key.ID {
			return ErrRecipeUntrusted
		}
	}
	for index, recipe := range manifest.Recipes {
		if !validID(string(recipe.ID)) || !validDigest(recipe.SHA256) || recipe.Size <= 0 || recipe.Size > 4<<20 || index > 0 && manifest.Recipes[index-1].ID >= recipe.ID {
			return ErrRecipeUntrusted
		}
	}
	for index, artifact := range manifest.Artifacts {
		if !validDigest(artifact.SHA256) || artifact.Size <= 0 || artifact.Size > 16<<30 || index > 0 && manifest.Artifacts[index-1].SHA256 >= artifact.SHA256 {
			return ErrRecipeUntrusted
		}
	}
	digest, err := manifest.Digest()
	if err != nil || digest != manifest.ContentDigest {
		return ErrRecipeUntrusted
	}
	return nil
}

type LinuxApplicationCatalogProvisionRequest struct {
	SourceRoot      string
	DestinationRoot string
	ReleaseID       string
	Now             func() time.Time
}

type LinuxApplicationCatalogProvisionReceipt struct {
	CatalogID            string `json:"catalog_id"`
	Sequence             uint64 `json:"sequence"`
	ReleaseID            string `json:"release_id"`
	ManifestDigest       string `json:"manifest_digest"`
	CandidateGeneration  string `json:"candidate_generation"`
	PreviousGeneration   string `json:"previous_generation,omitempty"`
	PreviousManifestHash string `json:"previous_manifest_digest,omitempty"`
	RollbackManifest     string `json:"rollback_manifest"`
}

type linuxApplicationCatalogRollback struct {
	Version                uint32    `json:"version"`
	ReleaseID              string    `json:"release_id"`
	CandidateGeneration    string    `json:"candidate_generation"`
	CandidateManifestHash  string    `json:"candidate_manifest_digest"`
	PreviousGeneration     string    `json:"previous_generation,omitempty"`
	PreviousManifestHash   string    `json:"previous_manifest_digest,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
}

func ProvisionLinuxApplicationCatalog(ctx context.Context, request LinuxApplicationCatalogProvisionRequest) (LinuxApplicationCatalogProvisionReceipt, error) {
	var receipt LinuxApplicationCatalogProvisionReceipt
	if ctx == nil || os.Geteuid() != 0 || !validID(request.ReleaseID) {
		return receipt, ErrPolicyDenied
	}
	source := filepath.Clean(request.SourceRoot)
	destination := filepath.Clean(request.DestinationRoot)
	if request.DestinationRoot == "" {
		destination = DefaultApplicationCatalogRoot
	}
	if !validCatalogAbsolutePath(source) || !validCatalogAbsolutePath(destination) || source == destination {
		return receipt, ErrInvalid
	}
	now := time.Now().UTC()
	if request.Now != nil {
		now = request.Now().UTC()
	}
	if err := validateCatalogAncestorChain(source); err != nil {
		return receipt, err
	}
	sourceManifest, err := loadLinuxApplicationCatalogManifest(source, now, false)
	if err != nil {
		return receipt, err
	}
	if sourceManifest.ReleaseID != request.ReleaseID {
		return receipt, ErrConflict
	}
	if err = validateLinuxApplicationCatalogGeneration(ctx, source, sourceManifest, now, false); err != nil {
		return receipt, err
	}

	parent := filepath.Dir(destination)
	if err = ensureRootCatalogDirectory(parent, 0755); err != nil {
		return receipt, err
	}
	generationRoot := destination + ".generations"
	rollbackRoot := destination + ".rollbacks"
	if err = ensureRootCatalogDirectory(generationRoot, 0755); err != nil {
		return receipt, err
	}
	if err = ensureRootCatalogDirectory(rollbackRoot, 0700); err != nil {
		return receipt, err
	}
	lock, err := openCatalogLock(destination + ".lock")
	if err != nil {
		return receipt, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return receipt, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	var previousRoot string
	var previousManifest LinuxApplicationCatalogManifest
	previousRoot, previousManifest, err = linuxApplicationCatalogSnapshot(destination, now)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return receipt, err
	}
	if err == nil {
		if previousManifest.CatalogID != sourceManifest.CatalogID {
			return receipt, ErrConflict
		}
		if previousManifest.Sequence > sourceManifest.Sequence {
			return receipt, ErrStaleGeneration
		}
		if previousManifest.Sequence == sourceManifest.Sequence && previousManifest.ContentDigest != sourceManifest.ContentDigest {
			return receipt, ErrConflict
		}
	}

	generationName := linuxApplicationCatalogGenerationName(sourceManifest)
	candidate := filepath.Join(generationRoot, generationName)
	if _, statErr := os.Lstat(candidate); errors.Is(statErr, os.ErrNotExist) {
		if err = stageLinuxApplicationCatalogGeneration(ctx, source, candidate, generationRoot, sourceManifest, now); err != nil {
			return receipt, err
		}
	} else if statErr != nil {
		return receipt, statErr
	} else {
		candidateManifest, loadErr := loadLinuxApplicationCatalogManifest(candidate, now, true)
		if loadErr != nil || !sameLinuxApplicationCatalogManifest(candidateManifest, sourceManifest) {
			return receipt, errors.Join(ErrConflict, loadErr)
		}
		if err = validateLinuxApplicationCatalogGeneration(ctx, candidate, candidateManifest, now, true); err != nil {
			return receipt, err
		}
	}
	rollbackPath := filepath.Join(rollbackRoot, request.ReleaseID+".json")
	if previousRoot == candidate {
		rollback, rollbackErr := readLinuxApplicationCatalogRollback(rollbackPath)
		if rollbackErr != nil || rollback.CandidateGeneration != generationName || rollback.CandidateManifestHash != sourceManifest.ContentDigest {
			return receipt, errors.Join(ErrConflict, rollbackErr)
		}
		previous := ""
		if rollback.PreviousGeneration != "" {
			previous = filepath.Join(generationRoot, rollback.PreviousGeneration)
		}
		return LinuxApplicationCatalogProvisionReceipt{
			CatalogID: sourceManifest.CatalogID, Sequence: sourceManifest.Sequence, ReleaseID: request.ReleaseID,
			ManifestDigest: sourceManifest.ContentDigest, CandidateGeneration: candidate,
			PreviousGeneration: previous, PreviousManifestHash: rollback.PreviousManifestHash, RollbackManifest: rollbackPath,
		}, nil
	}

	previousName := ""
	previousDigest := ""
	if previousRoot != "" {
		previousName = filepath.Base(previousRoot)
		previousDigest = previousManifest.ContentDigest
	}
	rollback := linuxApplicationCatalogRollback{
		Version: linuxApplicationCatalogSchemaVersion, ReleaseID: request.ReleaseID,
		CandidateGeneration: generationName, CandidateManifestHash: sourceManifest.ContentDigest,
		PreviousGeneration: previousName, PreviousManifestHash: previousDigest, CreatedAt: now,
	}
	if err = writeLinuxApplicationCatalogRollback(rollbackPath, rollback); err != nil {
		return receipt, err
	}
	if previousRoot != candidate {
		if err = switchLinuxApplicationCatalog(destination, candidate); err != nil {
			return receipt, err
		}
	}
	activeRoot, activeManifest, verifyErr := linuxApplicationCatalogSnapshot(destination, now)
	if verifyErr != nil || activeRoot != candidate || !sameLinuxApplicationCatalogManifest(activeManifest, sourceManifest) {
		rollbackErr := restoreLinuxApplicationCatalogLink(destination, generationRoot, rollback, now)
		return receipt, errors.Join(ErrIntegrity, verifyErr, rollbackErr)
	}
	receipt = LinuxApplicationCatalogProvisionReceipt{
		CatalogID: sourceManifest.CatalogID, Sequence: sourceManifest.Sequence, ReleaseID: request.ReleaseID,
		ManifestDigest: sourceManifest.ContentDigest, CandidateGeneration: candidate,
		PreviousGeneration: previousRoot, PreviousManifestHash: previousDigest, RollbackManifest: rollbackPath,
	}
	return receipt, nil
}

func RollbackLinuxApplicationCatalog(ctx context.Context, root, releaseID string, now time.Time) error {
	if ctx == nil || os.Geteuid() != 0 || !validID(releaseID) {
		return ErrPolicyDenied
	}
	if root == "" {
		root = DefaultApplicationCatalogRoot
	}
	root = filepath.Clean(root)
	if !validCatalogAbsolutePath(root) {
		return ErrInvalid
	}
	lock, err := openCatalogLock(root + ".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	rollback, err := readLinuxApplicationCatalogRollback(filepath.Join(root+".rollbacks", releaseID+".json"))
	if err != nil {
		return err
	}
	if rollback.ReleaseID != releaseID {
		return ErrConflict
	}
	return restoreLinuxApplicationCatalogLink(root, root+".generations", rollback, now.UTC())
}

func ValidateLinuxApplicationCatalog(ctx context.Context, root string, now time.Time) (LinuxApplicationCatalogManifest, error) {
	if ctx == nil {
		return LinuxApplicationCatalogManifest{}, ErrInvalid
	}
	if root == "" {
		root = DefaultApplicationCatalogRoot
	}
	resolved, manifest, err := linuxApplicationCatalogSnapshot(filepath.Clean(root), now.UTC())
	if err != nil {
		return LinuxApplicationCatalogManifest{}, err
	}
	if err = validateLinuxApplicationCatalogGeneration(ctx, resolved, manifest, now.UTC(), true); err != nil {
		return LinuxApplicationCatalogManifest{}, err
	}
	return manifest, nil
}

func linuxApplicationCatalogSnapshot(root string, now time.Time) (string, LinuxApplicationCatalogManifest, error) {
	resolved, linked, err := resolveLinuxApplicationCatalogRoot(root)
	if err != nil {
		return "", LinuxApplicationCatalogManifest{}, err
	}
	manifest, err := loadLinuxApplicationCatalogManifest(resolved, now, linked)
	if err != nil {
		return "", LinuxApplicationCatalogManifest{}, err
	}
	if linked && filepath.Base(resolved) != linuxApplicationCatalogGenerationName(manifest) {
		return "", LinuxApplicationCatalogManifest{}, ErrRecipeUntrusted
	}
	return resolved, manifest, nil
}

func resolveLinuxApplicationCatalogRoot(root string) (string, bool, error) {
	if !validCatalogAbsolutePath(root) {
		return "", false, ErrInvalid
	}
	if err := validateCatalogAncestorChain(filepath.Dir(root)); err != nil {
		return "", false, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", false, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		if err = validateRootCatalogDirectoryInfo(info, false); err != nil {
			return "", false, err
		}
		return root, false, nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return "", false, ErrRecipeUntrusted
	}
	target, err := os.Readlink(root)
	if err != nil {
		return "", false, err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(root), target)
	}
	target = filepath.Clean(target)
	generationRoot := root + ".generations"
	if target == generationRoot || !strings.HasPrefix(target, generationRoot+string(os.PathSeparator)) || filepath.Dir(target) != generationRoot {
		return "", false, ErrRecipeUntrusted
	}
	if err = validateCatalogAncestorChain(target); err != nil {
		return "", false, err
	}
	targetInfo, err := os.Lstat(target)
	if err != nil || validateRootCatalogDirectoryInfo(targetInfo, true) != nil {
		return "", false, ErrRecipeUntrusted
	}
	return target, true, nil
}

func loadLinuxApplicationCatalogManifest(root string, now time.Time, immutable bool) (LinuxApplicationCatalogManifest, error) {
	var manifest LinuxApplicationCatalogManifest
	for _, directory := range []string{root, filepath.Join(root, "keys"), filepath.Join(root, "recipes"), filepath.Join(root, "artifacts")} {
		info, err := os.Lstat(directory)
		if err != nil || validateRootCatalogDirectoryInfo(info, immutable) != nil {
			return manifest, ErrRecipeUntrusted
		}
	}
	payload, err := readRootCatalogFile(filepath.Join(root, linuxApplicationCatalogManifestName), 4<<20, immutable)
	if err != nil {
		return manifest, err
	}
	if err = decodeLinuxApplicationCatalogJSON(payload, &manifest); err != nil || manifest.Validate(now) != nil {
		return LinuxApplicationCatalogManifest{}, ErrRecipeUntrusted
	}
	return manifest, nil
}

func validateLinuxApplicationCatalogGeneration(ctx context.Context, root string, manifest LinuxApplicationCatalogManifest, now time.Time, immutable bool) error {
	loaded, err := loadLinuxApplicationCatalogManifest(root, now, immutable)
	if err != nil || !sameLinuxApplicationCatalogManifest(loaded, manifest) {
		return errors.Join(ErrRecipeUntrusted, err)
	}
	keyFiles := make(map[string]string, len(manifest.Keys))
	for _, key := range manifest.Keys {
		keyFiles[key.ID+".pub"] = key.SHA256
		payload, readErr := readRootCatalogFile(filepath.Join(root, "keys", key.ID+".pub"), key.Size, immutable)
		if readErr != nil || int64(len(payload)) != key.Size || linuxApplicationCatalogDigest(payload) != key.SHA256 {
			return ErrRecipeUntrusted
		}
	}
	recipeFiles := make(map[string]string, len(manifest.Recipes))
	authority := &LinuxRecipeCatalogAuthority{Root: root}
	referencedArtifacts := make(map[string]int64, len(manifest.Artifacts))
	for _, recipe := range manifest.Recipes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		recipeFiles[string(recipe.ID)+".json"] = recipe.SHA256
		document, fetchErr := authority.fetchRecipeFrom(root, manifest, recipe.ID, immutable)
		if fetchErr != nil || document.Reference.CatalogEpoch < manifest.MinimumEpoch || authority.verifyRecipeFrom(root, manifest, document.Reference.SigningKeyID, document.Reference.CatalogEpoch, document.CanonicalPayload, document.Signature, immutable) != nil {
			return ErrRecipeUntrusted
		}
		if linuxApplicationCatalogDigest(document.CanonicalPayload) != document.Reference.RecipeDigest {
			return ErrRecipeUntrusted
		}
		var definition ApplicationDefinition
		if decodeLinuxApplicationCatalogJSON(document.CanonicalPayload, &definition) != nil || definition.Validate(now) != nil || !sameLinuxApplicationCatalogRecipeReference(definition.Recipe, document.Reference) {
			return ErrRecipeUntrusted
		}
		artifact, found := catalogManifestArtifact(manifest, definition.Artifact.Digest)
		if !found || artifact.Size != definition.Artifact.Size {
			return ErrRecipeUntrusted
		}
		if size, exists := referencedArtifacts[definition.Artifact.Digest]; exists && size != definition.Artifact.Size {
			return ErrRecipeUntrusted
		}
		referencedArtifacts[definition.Artifact.Digest] = definition.Artifact.Size
	}
	artifactFiles := make(map[string]string, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if referencedArtifacts[artifact.SHA256] != artifact.Size {
			return ErrRecipeUntrusted
		}
		name := artifact.SHA256 + ".tar.gz"
		artifactFiles[name] = artifact.SHA256
		path := filepath.Join(root, "artifacts", name)
		info, statErr := os.Lstat(path)
		if statErr != nil || validateRootCatalogFileInfo(info, artifact.Size, immutable) != nil {
			return ErrRecipeUntrusted
		}
		digest, digestErr := digestLinuxApplicationFile(path, uint64(artifact.Size))
		if digestErr != nil || digest != artifact.SHA256 || validatePinnedApplicationArchive(path) != nil {
			return ErrRecipeUntrusted
		}
	}
	if err = validateLinuxApplicationCatalogDirectory(filepath.Join(root, "keys"), keyFiles); err != nil {
		return err
	}
	if err = validateLinuxApplicationCatalogDirectory(filepath.Join(root, "recipes"), recipeFiles); err != nil {
		return err
	}
	if err = validateLinuxApplicationCatalogDirectory(filepath.Join(root, "artifacts"), artifactFiles); err != nil {
		return err
	}
	rootEntries, err := os.ReadDir(root)
	if err != nil || len(rootEntries) != 4 {
		return ErrRecipeUntrusted
	}
	expectedRoot := map[string]bool{"keys": true, "recipes": true, "artifacts": true, linuxApplicationCatalogManifestName: true}
	for _, entry := range rootEntries {
		if !expectedRoot[entry.Name()] || entry.Type()&os.ModeSymlink != 0 {
			return ErrRecipeUntrusted
		}
	}
	return nil
}

func stageLinuxApplicationCatalogGeneration(ctx context.Context, source, candidate, generationRoot string, manifest LinuxApplicationCatalogManifest, now time.Time) (err error) {
	suffix, err := randomLinuxApplicationCatalogSuffix()
	if err != nil {
		return err
	}
	stage := filepath.Join(generationRoot, ".staging-"+suffix)
	if err = os.Mkdir(stage, 0700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(stage)
		}
	}()
	for _, directory := range []string{"keys", "recipes", "artifacts"} {
		if err = os.Mkdir(filepath.Join(stage, directory), 0700); err != nil {
			return err
		}
	}
	for _, key := range manifest.Keys {
		if err = copyLinuxApplicationCatalogFile(ctx, filepath.Join(source, "keys", key.ID+".pub"), filepath.Join(stage, "keys", key.ID+".pub"), key.Size, key.SHA256); err != nil {
			return err
		}
	}
	for _, recipe := range manifest.Recipes {
		if err = copyLinuxApplicationCatalogFile(ctx, filepath.Join(source, "recipes", string(recipe.ID)+".json"), filepath.Join(stage, "recipes", string(recipe.ID)+".json"), recipe.Size, recipe.SHA256); err != nil {
			return err
		}
	}
	for _, artifact := range manifest.Artifacts {
		name := artifact.SHA256 + ".tar.gz"
		if err = copyLinuxApplicationCatalogFile(ctx, filepath.Join(source, "artifacts", name), filepath.Join(stage, "artifacts", name), artifact.Size, artifact.SHA256); err != nil {
			return err
		}
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err = writeNewRootCatalogFile(filepath.Join(stage, linuxApplicationCatalogManifestName), manifestPayload, 0444); err != nil {
		return err
	}
	for _, directory := range []string{"keys", "recipes", "artifacts"} {
		if err = syncAndSealLinuxApplicationCatalogDirectory(filepath.Join(stage, directory)); err != nil {
			return err
		}
	}
	if err = syncAndSealLinuxApplicationCatalogDirectory(stage); err != nil {
		return err
	}
	if err = validateLinuxApplicationCatalogGeneration(ctx, stage, manifest, now, true); err != nil {
		return err
	}
	if err = os.Rename(stage, candidate); err != nil {
		return err
	}
	return syncLinuxApplicationCatalogDirectory(generationRoot)
}

func copyLinuxApplicationCatalogFile(ctx context.Context, source, target string, expectedSize int64, expectedDigest string) error {
	input, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || validateRootCatalogFileInfo(info, expectedSize, false) != nil {
		return ErrRecipeUntrusted
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0400)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	buffer := make([]byte, 256<<10)
	var written int64
	for written < expectedSize {
		select {
		case <-ctx.Done():
			output.Close()
			return ctx.Err()
		default:
		}
		limit := int64(len(buffer))
		if remaining := expectedSize - written; remaining < limit {
			limit = remaining
		}
		count, readErr := input.Read(buffer[:limit])
		if count > 0 {
			if _, err = hasher.Write(buffer[:count]); err == nil {
				_, err = output.Write(buffer[:count])
			}
			if err != nil {
				output.Close()
				return err
			}
			written += int64(count)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			output.Close()
			return readErr
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	extra := make([]byte, 1)
	extraCount, extraErr := input.Read(extra)
	if written != expectedSize || extraCount != 0 || extraErr != nil && !errors.Is(extraErr, io.EOF) || hex.EncodeToString(hasher.Sum(nil)) != expectedDigest {
		output.Close()
		return ErrRecipeUntrusted
	}
	if err = output.Sync(); err == nil {
		err = output.Chown(0, 0)
	}
	if err == nil {
		err = output.Chmod(0444)
	}
	closeErr := output.Close()
	return errors.Join(err, closeErr)
}

func switchLinuxApplicationCatalog(root, candidate string) error {
	if filepath.Dir(candidate) != root+".generations" {
		return ErrPolicyDenied
	}
	if info, err := os.Lstat(root); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return ErrConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	suffix, err := randomLinuxApplicationCatalogSuffix()
	if err != nil {
		return err
	}
	temporary := root + ".new-" + suffix
	if err = os.Symlink(candidate, temporary); err != nil {
		return err
	}
	if err = os.Lchown(temporary, 0, 0); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err = os.Rename(temporary, root); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncLinuxApplicationCatalogDirectory(filepath.Dir(root))
}

func restoreLinuxApplicationCatalogLink(root, generationRoot string, rollback linuxApplicationCatalogRollback, now time.Time) error {
	candidate := filepath.Join(generationRoot, rollback.CandidateGeneration)
	if filepath.Dir(candidate) != generationRoot || !validDigest(rollback.CandidateManifestHash) {
		return ErrRecipeUntrusted
	}
	candidateManifest, err := loadLinuxApplicationCatalogManifest(candidate, now, true)
	if err != nil || candidateManifest.ContentDigest != rollback.CandidateManifestHash {
		return ErrRecipeUntrusted
	}
	active, _, activeErr := linuxApplicationCatalogSnapshot(root, now)
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return activeErr
	}
	if rollback.PreviousGeneration == "" {
		if errors.Is(activeErr, os.ErrNotExist) {
			return nil
		}
		if active != candidate {
			return ErrConflict
		}
		if err = os.Remove(root); err != nil {
			return err
		}
		return syncLinuxApplicationCatalogDirectory(filepath.Dir(root))
	}
	previous := filepath.Join(generationRoot, rollback.PreviousGeneration)
	if filepath.Dir(previous) != generationRoot || !validDigest(rollback.PreviousManifestHash) {
		return ErrRecipeUntrusted
	}
	previousManifest, err := loadLinuxApplicationCatalogManifest(previous, now, true)
	if err != nil || previousManifest.ContentDigest != rollback.PreviousManifestHash {
		return ErrRecipeUntrusted
	}
	if activeErr == nil && active == previous {
		return nil
	}
	if activeErr != nil || active != candidate {
		return ErrConflict
	}
	return switchLinuxApplicationCatalog(root, previous)
}

func writeLinuxApplicationCatalogRollback(path string, rollback linuxApplicationCatalogRollback) error {
	if rollback.Version != linuxApplicationCatalogSchemaVersion || !validID(rollback.ReleaseID) || !validCatalogGenerationName(rollback.CandidateGeneration) || !validDigest(rollback.CandidateManifestHash) || rollback.CreatedAt.IsZero() || rollback.PreviousGeneration == "" && rollback.PreviousManifestHash != "" || rollback.PreviousGeneration != "" && (!validCatalogGenerationName(rollback.PreviousGeneration) || !validDigest(rollback.PreviousManifestHash)) {
		return ErrInvalid
	}
	payload, err := json.Marshal(rollback)
	if err != nil {
		return err
	}
	if existing, readErr := readRootCatalogFile(path, 1<<20, false); readErr == nil {
		var prior linuxApplicationCatalogRollback
		if decodeLinuxApplicationCatalogJSON(existing, &prior) != nil || !sameLinuxApplicationCatalogRollback(prior, rollback) {
			return ErrConflict
		}
		return nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	return writeNewRootCatalogFile(path, payload, 0600)
}

func readLinuxApplicationCatalogRollback(path string) (linuxApplicationCatalogRollback, error) {
	var rollback linuxApplicationCatalogRollback
	payload, err := readRootCatalogFile(path, 1<<20, false)
	if err != nil {
		return rollback, err
	}
	if decodeLinuxApplicationCatalogJSON(payload, &rollback) != nil || rollback.Version != linuxApplicationCatalogSchemaVersion || !validID(rollback.ReleaseID) || !validCatalogGenerationName(rollback.CandidateGeneration) || !validDigest(rollback.CandidateManifestHash) || rollback.CreatedAt.IsZero() || rollback.PreviousGeneration == "" && rollback.PreviousManifestHash != "" || rollback.PreviousGeneration != "" && (!validCatalogGenerationName(rollback.PreviousGeneration) || !validDigest(rollback.PreviousManifestHash)) {
		return linuxApplicationCatalogRollback{}, ErrRecipeUntrusted
	}
	return rollback, nil
}

func readRootCatalogFile(path string, maximum int64, immutable bool) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > maximum || validateRootCatalogFileInfo(info, info.Size(), immutable) != nil {
		return nil, ErrRecipeUntrusted
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) != info.Size() {
		return nil, ErrRecipeUntrusted
	}
	return payload, nil
}

func writeNewRootCatalogFile(path string, payload []byte, mode os.FileMode) error {
	if len(payload) == 0 || mode != 0444 && mode != 0600 {
		return ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(payload)
	syncErr := file.Sync()
	chownErr := file.Chown(0, 0)
	chmodErr := file.Chmod(mode)
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, chownErr, chmodErr, closeErr); err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncLinuxApplicationCatalogDirectory(filepath.Dir(path))
}

func validateRootCatalogDirectoryInfo(info os.FileInfo, immutable bool) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || immutable && info.Mode().Perm() != 0555 {
		return ErrRecipeUntrusted
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return ErrRecipeUntrusted
	}
	return nil
}

func validateRootCatalogFileInfo(info os.FileInfo, size int64, immutable bool) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != size || info.Mode().Perm()&0022 != 0 || immutable && info.Mode().Perm() != 0444 {
		return ErrRecipeUntrusted
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return ErrRecipeUntrusted
	}
	return nil
}

func ensureRootCatalogDirectory(path string, mode os.FileMode) error {
	if !validCatalogAbsolutePath(path) || mode.Perm()&0022 != 0 {
		return ErrInvalid
	}
	current := string(os.PathSeparator)
	parts := strings.Split(strings.TrimPrefix(path, string(os.PathSeparator)), string(os.PathSeparator))
	for index, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			createMode := os.FileMode(0755)
			if index == len(parts)-1 {
				createMode = mode
			}
			if err = os.Mkdir(current, createMode); err != nil {
				return err
			}
			if err = os.Chown(current, 0, 0); err != nil {
				return err
			}
			continue
		}
		if err != nil || validateRootCatalogDirectoryInfo(info, false) != nil {
			return ErrRecipeUntrusted
		}
	}
	return os.Chmod(path, mode)
}

func validateCatalogAncestorChain(path string) error {
	if !validCatalogAbsolutePath(path) {
		return ErrInvalid
	}
	current := string(os.PathSeparator)
	for _, part := range strings.Split(strings.TrimPrefix(path, string(os.PathSeparator)), string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || validateRootCatalogDirectoryInfo(info, false) != nil {
			return ErrRecipeUntrusted
		}
	}
	return nil
}

func validateLinuxApplicationCatalogDirectory(path string, expected map[string]string) error {
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != len(expected) {
		return ErrRecipeUntrusted
	}
	for _, entry := range entries {
		if _, found := expected[entry.Name()]; !found || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrRecipeUntrusted
		}
	}
	return nil
}

func syncAndSealLinuxApplicationCatalogDirectory(path string) error {
	if err := syncLinuxApplicationCatalogDirectory(path); err != nil {
		return err
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return os.Chmod(path, 0555)
}

func syncLinuxApplicationCatalogDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func openCatalogLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	if statErr != nil || validateRootCatalogFileInfo(info, info.Size(), false) != nil || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, ErrRecipeUntrusted
	}
	return file, nil
}

func decodeLinuxApplicationCatalogJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrRecipeUntrusted
	}
	return nil
}

func linuxApplicationCatalogGenerationName(manifest LinuxApplicationCatalogManifest) string {
	return fmt.Sprintf("g%020d-%s", manifest.Sequence, manifest.ContentDigest[:24])
}

func validCatalogGenerationName(value string) bool {
	return len(value) == len("g00000000000000000000-")+24 && strings.HasPrefix(value, "g") && strings.IndexByte(value, '/') < 0
}

func sameLinuxApplicationCatalogManifest(left, right LinuxApplicationCatalogManifest) bool {
	leftPayload, leftErr := json.Marshal(left)
	rightPayload, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftPayload, rightPayload)
}

func sameLinuxApplicationCatalogRecipeReference(left, right RecipeReference) bool {
	leftPayload, leftErr := json.Marshal(left)
	rightPayload, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftPayload, rightPayload)
}

func sameLinuxApplicationCatalogRollback(left, right linuxApplicationCatalogRollback) bool {
	return left.Version == right.Version && left.ReleaseID == right.ReleaseID && left.CandidateGeneration == right.CandidateGeneration && left.CandidateManifestHash == right.CandidateManifestHash && left.PreviousGeneration == right.PreviousGeneration && left.PreviousManifestHash == right.PreviousManifestHash
}

func linuxApplicationCatalogDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func randomLinuxApplicationCatalogSuffix() (string, error) {
	value := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func validCatalogAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != string(os.PathSeparator) && len(value) <= 4096
}

func catalogManifestKey(manifest LinuxApplicationCatalogManifest, id string, epoch uint64) (LinuxApplicationCatalogKey, bool) {
	index := sort.Search(len(manifest.Keys), func(index int) bool { return manifest.Keys[index].ID >= id })
	if index >= len(manifest.Keys) || manifest.Keys[index].ID != id || epoch < manifest.Keys[index].MinimumEpoch || epoch > manifest.Keys[index].MaximumEpoch {
		return LinuxApplicationCatalogKey{}, false
	}
	return manifest.Keys[index], true
}

func catalogManifestRecipe(manifest LinuxApplicationCatalogManifest, id RecipeID) (LinuxApplicationCatalogRecipe, bool) {
	index := sort.Search(len(manifest.Recipes), func(index int) bool { return manifest.Recipes[index].ID >= id })
	if index >= len(manifest.Recipes) || manifest.Recipes[index].ID != id {
		return LinuxApplicationCatalogRecipe{}, false
	}
	return manifest.Recipes[index], true
}

func catalogManifestArtifact(manifest LinuxApplicationCatalogManifest, digest string) (LinuxApplicationCatalogArtifact, bool) {
	index := sort.Search(len(manifest.Artifacts), func(index int) bool { return manifest.Artifacts[index].SHA256 >= digest })
	if index >= len(manifest.Artifacts) || manifest.Artifacts[index].SHA256 != digest {
		return LinuxApplicationCatalogArtifact{}, false
	}
	return manifest.Artifacts[index], true
}
