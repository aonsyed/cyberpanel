package images

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// AdmitRequest binds one locked image to its protected content-addressed cache
// location and to the closed qemu-img verifier.
type AdmitRequest struct {
	Image       Image
	SourcePath  string
	CacheRoot   string
	QEMUImgPath string
	Runner      Runner
}

// AdmitAndVerify copies locked bytes into the protected cache without replacing
// an existing object, then verifies only that admitted, read-only object.
func AdmitAndVerify(ctx context.Context, request AdmitRequest) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("admit image: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("admit image: %w", err)
	}
	if request.Runner == nil {
		return "", fmt.Errorf("admit image: runner is nil")
	}
	if err := request.Image.validate("image"); err != nil {
		return "", fmt.Errorf("admit image lock record: %w", err)
	}
	if err := validateVerificationPath("source image path", request.SourcePath, ""); err != nil {
		return "", err
	}
	if err := validateVerificationPath("cache root", request.CacheRoot, ""); err != nil {
		return "", err
	}
	if err := validateVerificationPath("qemu-img path", request.QEMUImgPath, "qemu-img"); err != nil {
		return "", err
	}

	admittedPath, digestDirectory, exists, err := prepareProtectedCache(request)
	if err != nil {
		return "", err
	}
	if exists {
		initialInfo, inspectErr := os.Lstat(admittedPath)
		if inspectErr != nil {
			return "", fmt.Errorf("inspect admitted image before verification: %w", inspectErr)
		}
		if err = Verify(ctx, request.Image, admittedPath, request.QEMUImgPath, request.Runner); err != nil {
			return "", err
		}
		if err = observeProtectedImage(admittedPath, digestDirectory, initialInfo); err != nil {
			return "", err
		}
		return admittedPath, nil
	}

	admittedInfo, err := admitSource(ctx, request, admittedPath, digestDirectory)
	if err != nil {
		return "", err
	}
	if err = Verify(ctx, request.Image, admittedPath, request.QEMUImgPath, request.Runner); err != nil {
		cleanupErr := cleanupCreatedImage(admittedPath, digestDirectory, admittedInfo)
		return "", errors.Join(err, cleanupErr)
	}
	if err = observeProtectedImage(admittedPath, digestDirectory, admittedInfo); err != nil {
		cleanupErr := cleanupCreatedImage(admittedPath, digestDirectory, admittedInfo)
		return "", errors.Join(err, cleanupErr)
	}
	return admittedPath, nil
}

func prepareProtectedCache(request AdmitRequest) (string, string, bool, error) {
	rootInfo, err := os.Lstat(request.CacheRoot)
	if err != nil {
		return "", "", false, fmt.Errorf("inspect cache root: %w", err)
	}
	if err = requireProtectedDirectory("cache root", rootInfo, 0o700); err != nil {
		return "", "", false, err
	}

	relativePath := filepath.FromSlash(request.Image.RuntimePath)
	if filepath.IsAbs(relativePath) || filepath.Clean(relativePath) != relativePath {
		return "", "", false, fmt.Errorf("image runtime path must be canonical and relative")
	}
	directoryParts := strings.Split(filepath.Dir(relativePath), string(os.PathSeparator))
	if len(directoryParts) < 2 {
		return "", "", false, fmt.Errorf("image runtime path has no protected digest directory")
	}

	current := request.CacheRoot
	for _, part := range directoryParts[:len(directoryParts)-1] {
		if part == "" || part == "." || part == ".." {
			return "", "", false, fmt.Errorf("image runtime path has an unsafe directory component")
		}
		current = filepath.Join(current, part)
		if err = ensureProtectedDirectory(current, 0o700); err != nil {
			return "", "", false, err
		}
	}

	digestPart := directoryParts[len(directoryParts)-1]
	if digestPart == "" || digestPart == "." || digestPart == ".." {
		return "", "", false, fmt.Errorf("image runtime path has an unsafe digest directory")
	}
	digestDirectory := filepath.Join(current, digestPart)
	digestInfo, err := os.Lstat(digestDirectory)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(digestDirectory, 0o700); err != nil {
			return "", "", false, fmt.Errorf("create image digest directory: %w", err)
		}
		digestInfo, err = os.Lstat(digestDirectory)
	}
	if err != nil {
		return "", "", false, fmt.Errorf("inspect image digest directory: %w", err)
	}
	if !digestInfo.IsDir() {
		return "", "", false, fmt.Errorf("image digest directory must be a directory without symlinks")
	}
	if err = requireProtectedOwner("image digest directory", digestInfo); err != nil {
		return "", "", false, err
	}

	admittedPath := filepath.Join(request.CacheRoot, relativePath)
	admittedInfo, err := os.Lstat(admittedPath)
	if errors.Is(err, os.ErrNotExist) {
		if digestInfo.Mode().Perm() != 0o700 {
			return "", "", false, fmt.Errorf("empty image digest directory must have mode 0700")
		}
		return admittedPath, digestDirectory, false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("inspect admitted image: %w", err)
	}
	if digestInfo.Mode().Perm() != 0o500 {
		return "", "", false, fmt.Errorf("published image digest directory must have mode 0500")
	}
	if err = requireProtectedImage(admittedInfo); err != nil {
		return "", "", false, err
	}
	return admittedPath, digestDirectory, true, nil
}

func ensureProtectedDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create protected cache directory %q: %w", path, err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect protected cache directory %q: %w", path, err)
	}
	return requireProtectedDirectory("protected cache directory", info, mode)
}

func requireProtectedDirectory(name string, info os.FileInfo, mode os.FileMode) error {
	if info == nil || !info.IsDir() {
		return fmt.Errorf("%s must be a directory without symlinks", name)
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("%s must have mode %04o", name, mode.Perm())
	}
	return requireProtectedOwner(name, info)
}

func requireProtectedImage(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() {
		return fmt.Errorf("admitted image must be a regular file without symlinks")
	}
	if info.Mode().Perm() != 0o400 {
		return fmt.Errorf("admitted image must have mode 0400")
	}
	return requireProtectedOwner("admitted image", info)
}

func requireProtectedOwner(name string, info os.FileInfo) error {
	if info == nil {
		return fmt.Errorf("%s ownership cannot be inspected", name)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("%s ownership cannot be verified", name)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s must be owned by the current uid", name)
	}
	return nil
}

func admitSource(ctx context.Context, request AdmitRequest, admittedPath, digestDirectory string) (admittedInfo os.FileInfo, err error) {
	sourcePathInfo, err := os.Lstat(request.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("inspect source image: %w", err)
	}
	if !sourcePathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("source image must be a regular file without symlinks")
	}
	if sourcePathInfo.Size() < 0 || sourcePathInfo.Size() > MaxImageBytes {
		return nil, fmt.Errorf("source image exceeds hashing size limit of %d bytes", MaxImageBytes)
	}
	source, err := os.Open(request.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("open source image: %w", err)
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened source image: %w", err)
	}
	if !sourceInfo.Mode().IsRegular() || !os.SameFile(sourcePathInfo, sourceInfo) {
		return nil, imageChanged(request.SourcePath, "path no longer identifies the opened regular file", nil)
	}

	temporary, err := os.CreateTemp(digestDirectory, ".admit-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary admitted image: %w", err)
	}
	temporaryPath := temporary.Name()
	temporaryOpen := true
	defer func() {
		var cleanupErr error
		if temporaryOpen {
			cleanupErr = temporary.Close()
		}
		if temporaryPath != "" {
			cleanupErr = errors.Join(cleanupErr, os.Remove(temporaryPath))
		}
		if err != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()

	hasher := sha256.New()
	written, err := copyImage(ctx, source, temporary, hasher)
	if err != nil {
		return nil, err
	}
	if written != sourceInfo.Size() {
		return nil, imageChanged(request.SourcePath, "size changed while admitting", nil)
	}
	if err = requireUnchangedImage(request.SourcePath, source, sourceInfo); err != nil {
		return nil, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if digest != request.Image.SHA256 {
		return nil, fmt.Errorf("image SHA256 %s does not match locked SHA256 %s", digest, request.Image.SHA256)
	}
	if err = preflightQCOW2Header(temporary, written); err != nil {
		return nil, err
	}
	if err = temporary.Sync(); err != nil {
		return nil, fmt.Errorf("sync temporary admitted image: %w", err)
	}
	if err = temporary.Chmod(0o400); err != nil {
		return nil, fmt.Errorf("protect temporary admitted image: %w", err)
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect temporary admitted image: %w", err)
	}
	if err = temporary.Close(); err != nil {
		temporaryOpen = false
		return nil, fmt.Errorf("close temporary admitted image: %w", err)
	}
	temporaryOpen = false

	if err = os.Link(temporaryPath, admittedPath); err != nil {
		return nil, fmt.Errorf("publish admitted image without replacement: %w", err)
	}
	if err = os.Remove(temporaryPath); err != nil {
		cleanupErr := os.Remove(admittedPath)
		return nil, errors.Join(fmt.Errorf("remove temporary admitted image: %w", err), cleanupErr)
	}
	temporaryPath = ""
	if err = os.Chmod(digestDirectory, 0o500); err != nil {
		cleanupErr := os.Remove(admittedPath)
		return nil, errors.Join(fmt.Errorf("protect image digest directory: %w", err), cleanupErr)
	}

	admittedInfo, err = os.Lstat(admittedPath)
	if err != nil {
		cleanupErr := cleanupCreatedImage(admittedPath, digestDirectory, temporaryInfo)
		return nil, errors.Join(fmt.Errorf("inspect published admitted image: %w", err), cleanupErr)
	}
	if !os.SameFile(temporaryInfo, admittedInfo) {
		cleanupErr := cleanupCreatedImage(admittedPath, digestDirectory, temporaryInfo)
		return nil, errors.Join(fmt.Errorf("published admitted image identity changed"), cleanupErr)
	}
	if err = requireProtectedImage(admittedInfo); err != nil {
		cleanupErr := cleanupCreatedImage(admittedPath, digestDirectory, temporaryInfo)
		return nil, errors.Join(err, cleanupErr)
	}
	return admittedInfo, nil
}

func copyImage(ctx context.Context, source, destination *os.File, hasher io.Writer) (int64, error) {
	buffer := make([]byte, 128<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("admit image: %w", err)
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			total += int64(count)
			if total > MaxImageBytes {
				return total, fmt.Errorf("source image exceeds hashing size limit of %d bytes", MaxImageBytes)
			}
			written, err := destination.Write(buffer[:count])
			if err != nil {
				return total, fmt.Errorf("write temporary admitted image: %w", err)
			}
			if written != count {
				return total, fmt.Errorf("write temporary admitted image: %w", io.ErrShortWrite)
			}
			if _, err := hasher.Write(buffer[:count]); err != nil {
				return total, fmt.Errorf("hash admitted image: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return total, fmt.Errorf("read source image: %w", readErr)
		}
	}
	if err := ctx.Err(); err != nil {
		return total, fmt.Errorf("admit image: %w", err)
	}
	return total, nil
}

func observeProtectedImage(admittedPath, digestDirectory string, expected os.FileInfo) error {
	directoryInfo, err := os.Lstat(digestDirectory)
	if err != nil {
		return fmt.Errorf("inspect image digest directory after verification: %w", err)
	}
	if err = requireProtectedDirectory("published image digest directory", directoryInfo, 0o500); err != nil {
		return err
	}
	current, err := os.Lstat(admittedPath)
	if err != nil {
		return fmt.Errorf("inspect admitted image after verification: %w", err)
	}
	if expected == nil || !os.SameFile(expected, current) {
		return imageChanged(admittedPath, "published object identity differs", nil)
	}
	return requireProtectedImage(current)
}

func cleanupCreatedImage(admittedPath, digestDirectory string, expected os.FileInfo) error {
	current, err := os.Lstat(admittedPath)
	if errors.Is(err, os.ErrNotExist) {
		return os.Chmod(digestDirectory, 0o700)
	}
	if err != nil {
		return fmt.Errorf("inspect failed admitted image cleanup: %w", err)
	}
	if expected == nil || !os.SameFile(expected, current) {
		return fmt.Errorf("refuse to remove a replaced admitted image")
	}
	if err = os.Chmod(digestDirectory, 0o700); err != nil {
		return fmt.Errorf("unlock image digest directory for cleanup: %w", err)
	}
	if err = os.Remove(admittedPath); err != nil {
		return fmt.Errorf("remove failed admitted image: %w", err)
	}
	return nil
}
