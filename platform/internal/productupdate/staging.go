package productupdate

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type ArtifactSource interface {
	OpenArtifact(context.Context, string, string) (io.ReadCloser, error)
}

type StagingLimits struct {
	MaximumArtifactBytes int64
	MaximumTotalBytes    int64
	MaximumExtractedBytes int64
	MaximumFileBytes     int64
	MaximumFiles         int
	MaximumPathBytes     int
}

const (
	hardMaximumArtifactBytes  = int64(4 << 30)
	hardMaximumTotalBytes     = int64(16 << 30)
	hardMaximumExtractedBytes = int64(32 << 30)
)

type Stager struct {
	root   string
	limits StagingLimits
}

type StagedArtifact struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

type ReleaseRoot struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Path   string `json:"-"`
}

type StagedRelease struct {
	ManifestID    string           `json:"manifest_id"`
	ManifestDigest string          `json:"manifest_digest"`
	Root          ReleaseRoot      `json:"root"`
	Artifacts     []StagedArtifact `json:"artifacts"`
	FileCount     int              `json:"file_count"`
	ExtractedBytes int64           `json:"extracted_bytes"`
	EvidenceDigest string          `json:"evidence_digest"`
}

type stagedFile struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

func NewStager(root string, limits StagingLimits) (*Stager, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || limits.MaximumArtifactBytes <= 0 ||
		limits.MaximumArtifactBytes > hardMaximumArtifactBytes || limits.MaximumTotalBytes < limits.MaximumArtifactBytes ||
		limits.MaximumTotalBytes > hardMaximumTotalBytes || limits.MaximumExtractedBytes <= 0 || limits.MaximumExtractedBytes > hardMaximumExtractedBytes ||
		limits.MaximumFileBytes <= 0 || limits.MaximumFileBytes > limits.MaximumExtractedBytes ||
		limits.MaximumFiles <= 0 || limits.MaximumFiles > 1000000 || limits.MaximumPathBytes < 16 || limits.MaximumPathBytes > 4096 {
		return nil, ErrInvalid
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return nil, ErrInvalid }
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root { return nil, ErrInvalid }
	return &Stager{root: root, limits: limits}, nil
}

func (stager *Stager) resolve(rootID, digest string) (ReleaseRoot, error) {
	if stager == nil || !identifierPattern.MatchString(rootID) || !validDigest(digest) { return ReleaseRoot{}, ErrInvalid }
	path := filepath.Join(stager.root, "releases", rootID)
	if !withinRoot(stager.root, path) { return ReleaseRoot{}, ErrIntegrity }
	release, found, err := loadStagedRelease(path)
	if err != nil { return ReleaseRoot{}, err }
	if !found { return ReleaseRoot{}, ErrNotFound }
	if release.Root.ID != rootID || release.Root.Digest != digest { return ReleaseRoot{}, ErrIntegrity }
	if err := stager.verifyStagedRelease(path, release); err != nil { return ReleaseRoot{}, err }
	return release.Root, nil
}

func (stager *Stager) stage(ctx context.Context, manifest ReleaseManifest, source ArtifactSource) (release StagedRelease, err error) {
	if stager == nil || source == nil { return StagedRelease{}, ErrInvalid }
	manifest, err = CanonicalManifest(manifest)
	if err != nil { return StagedRelease{}, err }
	releasesRoot := filepath.Join(stager.root, "releases")
	if err = ensureFixedDirectory(stager.root, releasesRoot); err != nil { return StagedRelease{}, err }
	finalID := "release-" + manifest.Digest[:32]
	finalPath := filepath.Join(releasesRoot, finalID)
	if existing, found, loadErr := loadStagedRelease(finalPath); loadErr != nil {
		return StagedRelease{}, loadErr
	} else if found {
		if existing.ManifestDigest != manifest.Digest || existing.Root.Digest != manifest.ReleaseRootDigest { return StagedRelease{}, ErrIntegrity }
		if verifyErr := stager.verifyStagedRelease(finalPath, existing); verifyErr != nil { return StagedRelease{}, verifyErr }
		return existing, nil
	}
	temporary, err := os.MkdirTemp(releasesRoot, ".stage-")
	if err != nil { return StagedRelease{}, err }
	defer func() { if err != nil { _ = removeTemporary(releasesRoot, temporary) } }()
	artifactsRoot, contentRoot := filepath.Join(temporary, "artifacts"), filepath.Join(temporary, "content")
	if err = os.Mkdir(artifactsRoot, 0700); err != nil { return StagedRelease{}, err }
	if err = os.Mkdir(contentRoot, 0700); err != nil { return StagedRelease{}, err }
	release = StagedRelease{ManifestID: manifest.ID, ManifestDigest: manifest.Digest,
		Root: ReleaseRoot{ID: finalID, Digest: manifest.ReleaseRootDigest, Path: finalPath}}
	var stagedTotal int64
	for _, artifact := range manifest.Artifacts {
		if artifact.Size > stager.limits.MaximumArtifactBytes || artifact.Size > stager.limits.MaximumTotalBytes-stagedTotal { return StagedRelease{}, ErrCapacity }
		staged, stageErr := stager.streamArtifact(ctx, source, manifest.ID, artifact, artifactsRoot)
		if stageErr != nil { return StagedRelease{}, stageErr }
		release.Artifacts = append(release.Artifacts, staged)
		stagedTotal += artifact.Size
	}
	seen := make(map[string]string)
	files := make([]stagedFile, 0)
	for _, artifact := range manifest.Artifacts {
		archivePath := filepath.Join(artifactsRoot, artifact.ID+".tar")
		if err = stager.extractTar(ctx, archivePath, contentRoot, seen, &files, &release.ExtractedBytes); err != nil {
			return StagedRelease{}, err
		}
	}
	if len(files) == 0 { return StagedRelease{}, ErrInvalid }
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	rootDigest, digestErr := digestJSON(files)
	if digestErr != nil || rootDigest != manifest.ReleaseRootDigest { return StagedRelease{}, ErrIntegrity }
	release.FileCount = len(files)
	release.EvidenceDigest, err = digestJSON(struct {
		ManifestDigest string           `json:"manifest_digest"`
		RootDigest     string           `json:"root_digest"`
		Artifacts      []StagedArtifact `json:"artifacts"`
		FileCount      int              `json:"file_count"`
		ExtractedBytes int64            `json:"extracted_bytes"`
	}{manifest.Digest, rootDigest, release.Artifacts, release.FileCount, release.ExtractedBytes})
	if err != nil { return StagedRelease{}, err }
	marker, err := json.Marshal(release)
	if err != nil { return StagedRelease{}, err }
	markerPath := filepath.Join(temporary, "release.json")
	if err = writeExact(markerPath, marker, 0400); err != nil { return StagedRelease{}, err }
	if err = makeImmutable(temporary); err != nil { return StagedRelease{}, err }
	if err = os.Rename(temporary, finalPath); err != nil {
		if existing, found, loadErr := loadStagedRelease(finalPath); loadErr == nil && found && existing.ManifestDigest == manifest.Digest && existing.Root.Digest == rootDigest {
			if verifyErr := stager.verifyStagedRelease(finalPath, existing); verifyErr != nil { return StagedRelease{}, verifyErr }
			if cleanupErr := removeTemporary(releasesRoot, temporary); cleanupErr != nil { return StagedRelease{}, cleanupErr }
			return existing, nil
		}
		return StagedRelease{}, err
	}
	if err = syncDirectory(releasesRoot); err != nil { return StagedRelease{}, err }
	return release, nil
}

func (stager *Stager) streamArtifact(ctx context.Context, source ArtifactSource, manifestID string, artifact Artifact, root string) (StagedArtifact, error) {
	reader, err := source.OpenArtifact(ctx, manifestID, artifact.ID)
	if err != nil { return StagedArtifact{}, err }
	if reader == nil { return StagedArtifact{}, ErrInvalid }
	closed := false
	defer func() { if !closed { _ = reader.Close() } }()
	file, err := os.OpenFile(filepath.Join(root, artifact.ID+".tar"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil { return StagedArtifact{}, err }
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(&contextReader{ctx: ctx, reader: reader}, artifact.Size+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	sourceCloseErr := reader.Close()
	closed = true
	if copyErr != nil { return StagedArtifact{}, copyErr }
	if syncErr != nil { return StagedArtifact{}, syncErr }
	if closeErr != nil { return StagedArtifact{}, closeErr }
	if sourceCloseErr != nil { return StagedArtifact{}, ErrIntegrity }
	if written != artifact.Size || hex.EncodeToString(hash.Sum(nil)) != artifact.Digest { return StagedArtifact{}, ErrIntegrity }
	return StagedArtifact{artifact.ID, artifact.Digest, artifact.Size}, nil
}

func (stager *Stager) extractTar(ctx context.Context, archivePath, contentRoot string, seen map[string]string, files *[]stagedFile, total *int64) error {
	archive, err := os.Open(archivePath)
	if err != nil { return err }
	defer archive.Close()
	reader := tar.NewReader(&contextReader{ctx: ctx, reader: archive})
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) { return nil }
		if nextErr != nil { return nextErr }
		name, valid := canonicalArchivePath(header.Name, stager.limits.MaximumPathBytes)
		if !valid || header.Mode&07000 != 0 { return ErrUnsafeArchive }
		if !registerArchivePath(seen, name) { return ErrUnsafeArchive }
		target := filepath.Join(contentRoot, filepath.FromSlash(name))
		if !withinRoot(contentRoot, target) { return ErrUnsafeArchive }
		switch header.Typeflag {
		case tar.TypeDir:
			if err := secureMkdirAll(contentRoot, target); err != nil { return err }
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > stager.limits.MaximumFileBytes || header.Size > stager.limits.MaximumExtractedBytes-*total || len(*files) >= stager.limits.MaximumFiles {
				return ErrCapacity
			}
			if err := secureMkdirAll(contentRoot, filepath.Dir(target)); err != nil { return err }
			mode := os.FileMode(header.Mode) & 0777
			if mode&0400 == 0 { return ErrUnsafeArchive }
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil { return err }
			hash := sha256.New()
			written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, header.Size+1))
			syncErr := file.Sync()
			closeErr := file.Close()
			if copyErr != nil { return copyErr }
			if syncErr != nil { return syncErr }
			if closeErr != nil { return closeErr }
			if written != header.Size { return ErrIntegrity }
			*total += written
			*files = append(*files, stagedFile{name, uint32(mode & 0555), written, hex.EncodeToString(hash.Sum(nil))})
		default:
			return ErrUnsafeArchive
		}
	}
}

func registerArchivePath(seen map[string]string, name string) bool {
	parts := strings.Split(name, "/")
	for index := 1; index < len(parts); index++ {
		prefix := strings.Join(parts[:index], "/")
		folded := strings.ToLower(prefix)
		if prior, exists := seen[folded]; exists && prior != prefix { return false }
		if _, exists := seen[folded]; !exists { seen[folded] = prefix }
	}
	folded := strings.ToLower(name)
	if _, exists := seen[folded]; exists { return false }
	seen[folded] = name
	return true
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	select { case <-reader.ctx.Done(): return 0, reader.ctx.Err(); default: }
	return reader.reader.Read(buffer)
}

func canonicalArchivePath(name string, maximum int) (string, bool) {
	if name == "" || len(name) > maximum || strings.ContainsRune(name, 0) || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", false
	}
	trimmed := strings.TrimSuffix(name, "/")
	clean := path.Clean(trimmed)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != trimmed { return "", false }
	for _, part := range strings.Split(clean, "/") {
		if part == "" || part == "." || part == ".." { return "", false }
		for index := 0; index < len(part); index++ { if part[index] < 0x21 || part[index] > 0x7e { return "", false } }
	}
	return clean, true
}

func ensureFixedDirectory(root, directory string) error {
	if !withinRoot(root, directory) { return ErrInvalid }
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(directory, 0700); err != nil { return err }
		return syncDirectory(root)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return ErrIntegrity }
	return nil
}

func secureMkdirAll(root, target string) error {
	if !withinRoot(root, target) { return ErrUnsafeArchive }
	relative, err := filepath.Rel(root, target)
	if err != nil { return err }
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "." || component == "" { continue }
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			if err := os.Mkdir(current, 0755); err != nil { return err }
			continue
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return ErrUnsafeArchive }
	}
	return nil
}

func withinRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func writeExact(path string, raw []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil { return err }
	if _, err = file.Write(raw); err == nil { err = file.Sync() }
	if closeErr := file.Close(); err == nil { err = closeErr }
	return err
}

func makeImmutable(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil { return err }
		if info.Mode()&os.ModeSymlink != 0 { return ErrUnsafeArchive }
		if info.IsDir() { return os.Chmod(path, 0555) }
		return os.Chmod(path, info.Mode().Perm()&0555)
	})
}

func loadStagedRelease(path string) (StagedRelease, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) { return StagedRelease{}, false, nil }
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return StagedRelease{}, false, ErrIntegrity }
	markerPath := filepath.Join(path, "release.json")
	markerInfo, err := os.Lstat(markerPath)
	if err != nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 || markerInfo.Size() > 1<<20 { return StagedRelease{}, false, ErrIntegrity }
	raw, err := os.ReadFile(markerPath)
	if err != nil || len(raw) > 1<<20 { return StagedRelease{}, false, ErrIntegrity }
	var release StagedRelease
	if json.Unmarshal(raw, &release) != nil || !identifierPattern.MatchString(release.ManifestID) || !validDigest(release.ManifestDigest) ||
		!identifierPattern.MatchString(release.Root.ID) || !validDigest(release.Root.Digest) || !validDigest(release.EvidenceDigest) { return StagedRelease{}, false, ErrIntegrity }
	release.Root.Path = path
	return release, true, nil
}

func (stager *Stager) verifyStagedRelease(root string, release StagedRelease) error {
	if release.FileCount <= 0 || release.FileCount > stager.limits.MaximumFiles || release.ExtractedBytes < 0 ||
		release.ExtractedBytes > stager.limits.MaximumExtractedBytes || len(release.Artifacts) == 0 || len(release.Artifacts) > 256 {
		return ErrIntegrity
	}
	evidence, err := digestJSON(struct {
		ManifestDigest string           `json:"manifest_digest"`
		RootDigest     string           `json:"root_digest"`
		Artifacts      []StagedArtifact `json:"artifacts"`
		FileCount      int              `json:"file_count"`
		ExtractedBytes int64            `json:"extracted_bytes"`
	}{release.ManifestDigest, release.Root.Digest, release.Artifacts, release.FileCount, release.ExtractedBytes})
	if err != nil || evidence != release.EvidenceDigest { return ErrIntegrity }
	artifactsRoot := filepath.Join(root, "artifacts")
	artifactsInfo, err := os.Lstat(artifactsRoot)
	if err != nil || !artifactsInfo.IsDir() || artifactsInfo.Mode()&os.ModeSymlink != 0 { return ErrIntegrity }
	entries, err := os.ReadDir(artifactsRoot)
	if err != nil || len(entries) != len(release.Artifacts) { return ErrIntegrity }
	var stagedTotal int64
	for index, artifact := range release.Artifacts {
		if !identifierPattern.MatchString(artifact.ID) || !validDigest(artifact.Digest) || artifact.Size <= 0 ||
			artifact.Size > stager.limits.MaximumArtifactBytes || artifact.Size > stager.limits.MaximumTotalBytes-stagedTotal ||
			index > 0 && release.Artifacts[index-1].ID >= artifact.ID { return ErrIntegrity }
		filePath := filepath.Join(artifactsRoot, artifact.ID+".tar")
		info, err := os.Lstat(filePath)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != artifact.Size { return ErrIntegrity }
		digest, size, err := hashFile(filePath, artifact.Size)
		if err != nil || size != artifact.Size || digest != artifact.Digest { return ErrIntegrity }
		stagedTotal += size
	}
	contentRoot := filepath.Join(root, "content")
	info, err := os.Lstat(contentRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return ErrIntegrity }
	files := make([]stagedFile, 0, release.FileCount)
	seen := make(map[string]struct{}, release.FileCount)
	var extracted int64
	err = filepath.Walk(contentRoot, func(filePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil { return walkErr }
		if filePath == contentRoot { return nil }
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() { return ErrIntegrity }
		relative, err := filepath.Rel(contentRoot, filePath)
		if err != nil { return err }
		name := filepath.ToSlash(relative)
		if canonical, valid := canonicalArchivePath(name, stager.limits.MaximumPathBytes); !valid || canonical != name { return ErrIntegrity }
		if !registerVerifiedPath(seen, name) { return ErrIntegrity }
		if info.IsDir() { return nil }
		if len(files) >= stager.limits.MaximumFiles || info.Size() < 0 || info.Size() > stager.limits.MaximumFileBytes ||
			info.Size() > stager.limits.MaximumExtractedBytes-extracted { return ErrCapacity }
		digest, size, err := hashFile(filePath, info.Size())
		if err != nil { return err }
		files = append(files, stagedFile{name, uint32(info.Mode().Perm()), size, digest})
		extracted += size
		return nil
	})
	if err != nil || len(files) != release.FileCount || extracted != release.ExtractedBytes { return ErrIntegrity }
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	digest, err := digestJSON(files)
	if err != nil || digest != release.Root.Digest { return ErrIntegrity }
	return nil
}

func registerVerifiedPath(seen map[string]struct{}, name string) bool {
	folded := strings.ToLower(name)
	if _, exists := seen[folded]; exists { return false }
	seen[folded] = struct{}{}
	return true
}

func hashFile(path string, maximum int64) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil { return "", 0, err }
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || size > maximum { if err != nil { return "", 0, err }; return "", 0, ErrCapacity }
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func removeTemporary(root, target string) error {
	if filepath.Dir(target) != root || !strings.HasPrefix(filepath.Base(target), ".stage-") { return ErrInvalid }
	if err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if errors.Is(err, os.ErrNotExist) { return nil }
		if err != nil { return err }
		if info.Mode()&os.ModeSymlink != 0 { return ErrIntegrity }
		if info.IsDir() { return os.Chmod(path, 0700) }
		return os.Chmod(path, 0600)
	}); err != nil && !errors.Is(err, os.ErrNotExist) { return err }
	return os.RemoveAll(target)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil { return err }
	defer directory.Close()
	return directory.Sync()
}
