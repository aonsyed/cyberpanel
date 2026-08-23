//go:build linux

package supportbundle

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const LinuxArtifactRoot = "/var/lib/cyberpanel/support-bundles"

type LinuxArtifactStore struct {
	rootFD int
	device uint64
	ready  bool
	mu     sync.Mutex
}

func NewLinuxArtifactStore() (*LinuxArtifactStore, error) {
	parent := filepath.Dir(LinuxArtifactRoot)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0002 != 0 {
		return nil, ErrIntegrity
	}
	info, err := os.Lstat(LinuxArtifactRoot)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(LinuxArtifactRoot, 0700); err != nil {
			return nil, err
		}
		info, err = os.Lstat(LinuxArtifactRoot)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, ErrIntegrity
	}
	fd, err := syscall.Open(LinuxArtifactRoot, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || stat.Mode&0777 != 0700 || stat.Uid != 0 {
		syscall.Close(fd)
		return nil, ErrIntegrity
	}
	return &LinuxArtifactStore{rootFD: fd, device: uint64(stat.Dev), ready: true}, nil
}

func (store *LinuxArtifactStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.ready { return nil }
	err := syscall.Close(store.rootFD)
	store.rootFD, store.ready = -1, false
	return err
}

func artifactID(digest string) (ArtifactID, error) {
	if !validSHA256(digest) {
		return "", ErrIntegrity
	}
	id := ArtifactID("sb_" + digest[:48])
	return id, id.Validate()
}

func validateBundle(bundle Bundle) error {
	if bundle.Manifest.Schema != SchemaVersion || len(bundle.Content) == 0 || len(bundle.Content) > AbsoluteMaximumCompressedBytes || !validSHA256(bundle.ArchiveSHA256) || !validSHA256(bundle.Manifest.BundleDigest) || bundle.Manifest.CreatedAt.IsZero() || !bundle.Manifest.ExpiresAt.After(bundle.Manifest.CreatedAt) || bundle.Manifest.ExpiresAt.After(bundle.Manifest.CreatedAt.Add(AbsoluteMaximumExpiry)) || !validSignature(Signature{KeyID: bundle.Manifest.SignerKeyID, Value: bundle.Manifest.Signature}) {
		return ErrInvalid
	}
	digest := sha256.Sum256(bundle.Content)
	if hex.EncodeToString(digest[:]) != bundle.ArchiveSHA256 || len(bundle.Content) < 2 || bundle.Content[0] != 0x1f || bundle.Content[1] != 0x8b {
		return ErrIntegrity
	}
	return nil
}

func randomArtifactLeaf(prefix string) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]) + ".tmp", nil
}

func artifactReceiptFor(bundle Bundle, id ArtifactID) ArtifactReceipt {
	return ArtifactReceipt{ID: id, ArchiveSHA256: bundle.ArchiveSHA256, BundleDigest: bundle.Manifest.BundleDigest, Bytes: int64(len(bundle.Content)), CreatedAt: bundle.Manifest.CreatedAt, ExpiresAt: bundle.Manifest.ExpiresAt}
}

func (store *LinuxArtifactStore) existing(ctx context.Context, leaf string, bundle Bundle, id ArtifactID) (ArtifactReceipt, bool, error) {
	fd, err := syscall.Openat(store.rootFD, leaf, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return ArtifactReceipt{}, false, nil
	}
	if err != nil {
		return ArtifactReceipt{}, false, ErrIntegrity
	}
	defer syscall.Close(fd)
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&0777 != 0600 || stat.Nlink != 1 || uint64(stat.Dev) != store.device || stat.Size != int64(len(bundle.Content)) {
		return ArtifactReceipt{}, false, ErrConflict
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			return ArtifactReceipt{}, false, err
		}
		count, readErr := syscall.Read(fd, buffer)
		if count > 0 {
			_, _ = hash.Write(buffer[:count])
		}
		if errors.Is(readErr, io.EOF) || count == 0 {
			break
		}
		if readErr != nil {
			return ArtifactReceipt{}, false, readErr
		}
	}
	if hex.EncodeToString(hash.Sum(nil)) != bundle.ArchiveSHA256 {
		return ArtifactReceipt{}, false, ErrConflict
	}
	return artifactReceiptFor(bundle, id), true, nil
}

func (store *LinuxArtifactStore) StoreSupportBundle(ctx context.Context, bundle Bundle) (ArtifactReceipt, error) {
	if store == nil || ctx == nil {
		return ArtifactReceipt{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.ready { return ArtifactReceipt{}, ErrInvalid }
	if err := validateBundle(bundle); err != nil {
		return ArtifactReceipt{}, err
	}
	id, err := artifactID(bundle.ArchiveSHA256)
	if err != nil {
		return ArtifactReceipt{}, err
	}
	target := string(id) + ".tar.gz"
	if receipt, exists, inspectErr := store.existing(ctx, target, bundle, id); inspectErr != nil || exists {
		return receipt, inspectErr
	}
	temporary, err := randomArtifactLeaf("." + string(id) + "-")
	if err != nil {
		return ArtifactReceipt{}, err
	}
	fd, err := syscall.Openat(store.rootFD, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return ArtifactReceipt{}, err
	}
	committed := false
	defer func() {
		_ = syscall.Close(fd)
		if !committed {
			_ = syscall.Unlinkat(store.rootFD, temporary)
		}
	}()
	written := 0
	for written < len(bundle.Content) {
		if err = ctx.Err(); err != nil {
			return ArtifactReceipt{}, err
		}
		count, writeErr := syscall.Write(fd, bundle.Content[written:])
		if writeErr != nil {
			return ArtifactReceipt{}, writeErr
		}
		if count == 0 {
			return ArtifactReceipt{}, io.ErrShortWrite
		}
		written += count
	}
	if err = syscall.Fchmod(fd, 0600); err == nil {
		err = syscall.Fsync(fd)
	}
	var stat syscall.Stat_t
	if err == nil {
		err = syscall.Fstat(fd, &stat)
	}
	if err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&0777 != 0600 || stat.Nlink != 1 || uint64(stat.Dev) != store.device || stat.Size != int64(len(bundle.Content)) {
		return ArtifactReceipt{}, errors.Join(ErrIntegrity, err)
	}
	if err = syscall.Close(fd); err != nil {
		fd = -1
		return ArtifactReceipt{}, err
	}
	fd = -1
	if _, exists, inspectErr := store.existing(ctx, target, bundle, id); inspectErr != nil || exists {
		return ArtifactReceipt{}, errors.Join(ErrConflict, inspectErr)
	}
	if err = syscall.Renameat(store.rootFD, temporary, store.rootFD, target); err != nil {
		return ArtifactReceipt{}, err
	}
	committed = true
	if err = syscall.Fsync(store.rootFD); err != nil {
		return ArtifactReceipt{}, err
	}
	return artifactReceiptFor(bundle, id), nil
}

var _ ArtifactStore = (*LinuxArtifactStore)(nil)
