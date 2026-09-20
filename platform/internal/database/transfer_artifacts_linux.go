//go:build linux

package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// LinuxTransferArtifactStore is private executor storage. Callers must authorize
// the job before supplying its artifact identity; filesystem paths never cross
// the broker boundary. The configured bound also applies to future upload users.
type LinuxTransferArtifactStore struct {
	root    string
	maximum uint64
	now     func() time.Time
}

type transferArtifactMetadata struct {
	Schema     uint32                     `json:"schema"`
	Descriptor TransferArtifactDescriptor `json:"descriptor"`
	Retention  TransferRetention          `json:"retention"`
}

func NewLinuxTransferArtifactStore(root string, maximum uint64, now func() time.Time) (*LinuxTransferArtifactStore, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || maximum < 1024 || maximum > MaximumTransferBytes {
		return nil, ErrTransferInvalid
	}
	// Every ancestor must be root-controlled, not just the final leaf. Never
	// traverse an administrator-supplied symlink into a tenant-writable directory.
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err = os.Mkdir(current, 0700); err != nil {
				return nil, err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return nil, ErrUnauthorized
		}
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0700 {
		return nil, ErrUnauthorized
	}
	if now == nil {
		now = time.Now
	}
	return &LinuxTransferArtifactStore{root: root, maximum: maximum, now: now}, nil
}

func (store *LinuxTransferArtifactStore) artifactPath(identity TransferArtifactIdentity) (string, error) {
	if store == nil || identity.Validate() != nil {
		return "", ErrTransferInvalid
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	return filepath.Join(store.root, transferDigest(raw)), nil
}

func (store *LinuxTransferArtifactStore) BeginTransferArtifact(ctx context.Context, identity TransferArtifactIdentity, format TransferFormat, compression TransferCompression, retention TransferRetention) (TransferArtifactWriter, error) {
	if ctx == nil {
		return nil, ErrTransferInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := store.artifactPath(identity)
	if err != nil {
		return nil, err
	}
	now := store.now().UTC()
	if format != TransferFormatSQL || !validTransferCompression(compression) || retention.Validate(now) != nil || !retention.RetainUntil.After(now) {
		return nil, ErrTransferInvalid
	}
	if _, err = os.Lstat(target); err == nil {
		return nil, ErrConflict
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err = verifyPrivateTransferDirectory(store.root); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(store.root, ".incoming-")
	if err != nil {
		return nil, err
	}
	lease, err := os.OpenFile(staging, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err == nil {
		err = syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		if lease != nil {
			_ = lease.Close()
		}
		_ = os.RemoveAll(staging)
		return nil, err
	}
	metadata := transferArtifactMetadata{Schema: 1, Descriptor: TransferArtifactDescriptor{Identity: identity, Format: format, Compression: compression, CreatedAt: now, ExpiresAt: retention.RetainUntil.UTC()}, Retention: retention}
	raw, err := json.Marshal(metadata)
	if err == nil {
		err = atomicRootFile(filepath.Join(staging, "descriptor.json"), raw, 0600)
	}
	if err != nil {
		_ = lease.Close()
		_ = os.RemoveAll(staging)
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(staging, "payload"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		_ = lease.Close()
		_ = os.RemoveAll(staging)
		return nil, err
	}
	return &transferArtifactFileWriter{store: store, ctx: ctx, file: file, lease: lease, staging: staging, target: target, hash: sha256.New(), metadata: metadata}, nil
}

func (store *LinuxTransferArtifactStore) OpenTransferArtifact(ctx context.Context, identity TransferArtifactIdentity) (TransferArtifactReader, error) {
	if ctx == nil {
		return nil, ErrTransferInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory, err := store.artifactPath(identity)
	if err != nil {
		return nil, err
	}
	if err = verifyPrivateTransferDirectory(store.root); err != nil {
		return nil, err
	}
	if err = verifyPrivateTransferDirectory(directory); err != nil {
		return nil, err
	}
	meta, err := openTransferArtifactFile(filepath.Join(directory, "descriptor.json"))
	if err != nil {
		return nil, err
	}
	defer meta.Close()
	metaInfo, err := meta.Stat()
	if err != nil || metaInfo.Size() > 65536 {
		return nil, ErrTransferInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(meta, 65537))
	decoder.DisallowUnknownFields()
	var metadata transferArtifactMetadata
	if decoder.Decode(&metadata) != nil || decoder.Decode(&struct{}{}) != io.EOF || metadata.Schema != 1 || metadata.Descriptor.Validate() != nil || metadata.Descriptor.Identity != identity || metadata.Descriptor.Bytes > store.maximum || metadata.Retention.Validate(metadata.Descriptor.CreatedAt) != nil || !metadata.Descriptor.ExpiresAt.Equal(metadata.Retention.RetainUntil) || !store.now().Before(metadata.Descriptor.ExpiresAt) {
		return nil, ErrTransferInvalid
	}
	file, err := openTransferArtifactFile(filepath.Join(directory, "payload"))
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || uint64(info.Size()) != metadata.Descriptor.Bytes {
		file.Close()
		return nil, ErrTransferInvalid
	}
	return &transferArtifactFileReader{File: file, descriptor: metadata.Descriptor}, nil
}

func verifyPrivateTransferDirectory(path string) error {
	if err := verifyRootDirectory(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0700 {
		return ErrUnauthorized
	}
	return nil
}

func openTransferArtifactFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, ErrUnauthorized
	}
	return file, nil
}

type transferArtifactFileReader struct {
	*os.File
	descriptor TransferArtifactDescriptor
}

func (reader *transferArtifactFileReader) Descriptor() TransferArtifactDescriptor {
	return reader.descriptor
}

type transferArtifactFileWriter struct {
	mu                         sync.Mutex
	store                      *LinuxTransferArtifactStore
	ctx                        context.Context
	file                       *os.File
	lease                      *os.File // retained across Close until Commit/Abort; process exit releases it
	staging, target            string
	hash                       hash.Hash
	bytes                      uint64
	metadata                   transferArtifactMetadata
	closed, aborted, published bool
	closeErr                   error
}

func (writer *transferArtifactFileWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed || writer.aborted {
		return 0, os.ErrClosed
	}
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	if uint64(len(data)) > writer.store.maximum-writer.bytes {
		return 0, ErrTransferLimit
	}
	n, err := writer.file.Write(data)
	_, _ = writer.hash.Write(data[:n])
	writer.bytes += uint64(n)
	return n, err
}

func (writer *transferArtifactFileWriter) closeLocked() error {
	if !writer.closed {
		writer.closed = true
		writer.closeErr = errors.Join(writer.file.Sync(), writer.file.Close())
	}
	return writer.closeErr
}
func (writer *transferArtifactFileWriter) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.closeLocked()
}

func (writer *transferArtifactFileWriter) Commit(ctx context.Context, digest string, size, rows uint64) (TransferArtifactDescriptor, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if ctx == nil || writer.aborted || !validSHA256(digest) || size == 0 || size != writer.bytes || digest != hex.EncodeToString(writer.hash.Sum(nil)) || rows > MaximumTransferRows {
		return TransferArtifactDescriptor{}, ErrTransferInvalid
	}
	if err := ctx.Err(); err != nil {
		return TransferArtifactDescriptor{}, err
	}
	if err := writer.closeLocked(); err != nil {
		return TransferArtifactDescriptor{}, err
	}
	if writer.published {
		if writer.metadata.Descriptor.Rows != rows {
			return TransferArtifactDescriptor{}, ErrConflict
		}
		return writer.metadata.Descriptor, syncTransferDirectory(writer.store.root)
	}
	if !writer.store.now().Before(writer.metadata.Descriptor.ExpiresAt) {
		return TransferArtifactDescriptor{}, ErrTransferInvalid
	}
	writer.metadata.Descriptor.Digest, writer.metadata.Descriptor.Bytes, writer.metadata.Descriptor.Rows = digest, size, rows
	if writer.metadata.Descriptor.Validate() != nil {
		return TransferArtifactDescriptor{}, ErrTransferInvalid
	}
	raw, err := json.Marshal(writer.metadata)
	if err != nil {
		return TransferArtifactDescriptor{}, err
	}
	if err = atomicRootFile(filepath.Join(writer.staging, "descriptor.json"), raw, 0600); err != nil {
		return TransferArtifactDescriptor{}, err
	}
	if err = syncTransferDirectory(writer.staging); err != nil {
		return TransferArtifactDescriptor{}, err
	}
	// A published generation is a non-empty directory, so concurrent rename
	// cannot replace it. Losers retain their private staging for Abort cleanup.
	if err = os.Rename(writer.staging, writer.target); err != nil {
		return TransferArtifactDescriptor{}, errors.Join(ErrConflict, err)
	}
	writer.published = true
	_ = writer.lease.Close()
	if err = syncTransferDirectory(writer.store.root); err != nil {
		return TransferArtifactDescriptor{}, err
	}
	return writer.metadata.Descriptor, nil
}

func (writer *transferArtifactFileWriter) Abort(ctx context.Context) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.published || writer.aborted {
		return nil
	}
	writer.aborted = true
	closeErr := writer.closeLocked()
	removeErr := os.RemoveAll(writer.staging)
	return errors.Join(closeErr, removeErr, writer.lease.Close(), syncTransferDirectory(writer.store.root))
}

func syncTransferDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

var _ TransferArtifactStore = (*LinuxTransferArtifactStore)(nil)
