//go:build linux

package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// LinuxTransferUploadStore holds resumable uploads in executor-private storage.
// No caller-supplied filesystem paths or SQL are executed by this store.
type LinuxTransferUploadStore struct{ artifacts *LinuxTransferArtifactStore }

const transferUploadRoot = mariaDBStateRoot + "/transfer-uploads"

func NewLinuxTransferUploadStore(root string, now func() time.Time) (*LinuxTransferUploadStore, error) {
	store, err := NewLinuxTransferArtifactStore(root, MaximumTransferUploadBytes, now)
	if err != nil {
		return nil, err
	}
	return &LinuxTransferUploadStore{artifacts: store}, nil
}

func (store *LinuxTransferUploadStore) locked(ctx context.Context, intent TransferUploadIntent, operation func(string) error) error {
	if store == nil || store.artifacts == nil || ctx == nil || intent.Validate() != nil {
		return ErrTransferInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !store.artifacts.now().Before(intent.ExpiresAt) || store.artifacts.now().Before(intent.CreatedAt) {
		return ErrTransferStale
	}
	return store.withLock(ctx, func() error { return operation(filepath.Join(store.artifacts.root, ".upload-"+intent.Digest)) })
}

func (store *LinuxTransferUploadStore) withLock(ctx context.Context, operation func() error) error {
	if store == nil || store.artifacts == nil || ctx == nil {
		return ErrTransferInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyPrivateTransferDirectory(store.artifacts.root); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(store.artifacts.root, ".upload-lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return ErrUnauthorized
	}
	// Do not block an executor worker on another upload; a busy client retries.
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return ErrConflict
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return operation()
}

func (store *LinuxTransferUploadStore) Begin(ctx context.Context, intent TransferUploadIntent) (offset uint64, err error) {
	err = store.locked(ctx, intent, func(directory string) error {
		if existing, e := store.artifacts.OpenTransferArtifact(ctx, intent.ArtifactIdentity()); e == nil {
			descriptor := existing.Descriptor()
			e = existing.Close()
			if e != nil {
				return e
			}
			if !intent.matchesArtifact(descriptor) {
				return ErrConflict
			}
			offset = intent.Bytes
			return store.removePending(directory, intent)
		} else if !os.IsNotExist(e) {
			return e
		}
		if _, e := os.Lstat(directory); e == nil {
			file, e := store.open(directory, intent, false)
			if e != nil {
				return e
			}
			defer file.Close()
			info, e := file.Stat()
			if e != nil {
				return e
			}
			offset = uint64(info.Size())
			return nil
		} else if !os.IsNotExist(e) {
			return e
		}
		var space syscall.Statfs_t
		if e := syscall.Statfs(store.artifacts.root, &space); e != nil {
			return e
		}
		if uint64(space.Bavail)*uint64(space.Bsize) < (2<<30)+2*intent.Bytes {
			return ErrTransferLimit
		}
		entries, e := os.ReadDir(store.artifacts.root)
		if e != nil {
			return e
		}
		pending, scoped := 0, 0
		for _, entry := range entries {
			if len(entry.Name()) > 8 && entry.Name()[:8] == ".upload-" && validSHA256(entry.Name()[8:]) {
				staleDirectory := filepath.Join(store.artifacts.root, entry.Name())
				if e = verifyPrivateTransferDirectory(staleDirectory); e != nil {
					return e
				}
				meta, readErr := openTransferArtifactFile(filepath.Join(staleDirectory, "intent.json"))
				if readErr != nil {
					return readErr
				}
				decoder := json.NewDecoder(io.LimitReader(meta, 8193))
				decoder.DisallowUnknownFields()
				var previous TransferUploadIntent
				decodeErr := decoder.Decode(&previous)
				endErr := decoder.Decode(&struct{}{})
				closeErr := meta.Close()
				if decodeErr != nil || endErr != io.EOF || closeErr != nil || previous.Validate() != nil || entry.Name() != ".upload-"+previous.Digest {
					return ErrUnauthorized
				}
				if !store.artifacts.now().Before(previous.ExpiresAt) {
					if e = store.removePending(staleDirectory, previous); e != nil {
						return e
					}
					continue
				}
				pending++
				if previous.TenantID == intent.TenantID {
					scoped++
				}
			}
		}
		if pending >= 32 || scoped >= 4 {
			return ErrTransferLimit
		}
		if e = os.Mkdir(directory, 0700); e != nil {
			return e
		}
		committed := false
		defer func() {
			if !committed {
				_ = os.RemoveAll(directory)
			}
		}()
		raw, _ := json.Marshal(intent)
		if e = atomicRootFile(filepath.Join(directory, "intent.json"), raw, 0600); e != nil {
			return e
		}
		file, e := os.OpenFile(filepath.Join(directory, "payload"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return e
		}
		if e = errors.Join(file.Sync(), file.Close()); e != nil {
			return e
		}
		if e = syncTransferDirectory(directory); e != nil {
			return e
		}
		if e = syncTransferDirectory(store.artifacts.root); e != nil {
			return e
		}
		committed = true
		return nil
	})
	return
}

func (store *LinuxTransferUploadStore) Status(ctx context.Context, intent TransferUploadIntent) (offset uint64, artifact *TransferArtifactDescriptor, err error) {
	err = store.locked(ctx, intent, func(directory string) error {
		reader, e := store.artifacts.OpenTransferArtifact(ctx, intent.ArtifactIdentity())
		if e == nil {
			descriptor := reader.Descriptor()
			e = reader.Close()
			if e != nil {
				return e
			}
			if !intent.matchesArtifact(descriptor) {
				return ErrConflict
			}
			artifact = &descriptor
			offset = descriptor.Bytes
			return nil
		}
		if !os.IsNotExist(e) {
			return e
		}
		file, e := store.open(directory, intent, false)
		if e != nil {
			return e
		}
		defer file.Close()
		info, e := file.Stat()
		if e != nil {
			return e
		}
		offset = uint64(info.Size())
		return nil
	})
	return
}

func (store *LinuxTransferUploadStore) open(directory string, intent TransferUploadIntent, writable bool) (*os.File, error) {
	if err := verifyPrivateTransferDirectory(directory); err != nil {
		return nil, err
	}
	meta, err := openTransferArtifactFile(filepath.Join(directory, "intent.json"))
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(io.LimitReader(meta, 8193))
	decoder.DisallowUnknownFields()
	var recorded TransferUploadIntent
	decodeErr := decoder.Decode(&recorded)
	endErr := decoder.Decode(&struct{}{})
	closeErr := meta.Close()
	if decodeErr != nil || endErr != io.EOF || closeErr != nil || recorded.Validate() != nil || recorded.Digest != intent.Digest {
		return nil, ErrUnauthorized
	}
	flags := os.O_RDONLY
	if writable {
		flags = os.O_RDWR
	}
	file, err := os.OpenFile(filepath.Join(directory, "payload"), flags|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 || uint64(info.Size()) > intent.Bytes {
		file.Close()
		return nil, ErrUnauthorized
	}
	return file, nil
}

func (store *LinuxTransferUploadStore) Append(ctx context.Context, intent TransferUploadIntent, offset uint64, data []byte) (next uint64, err error) {
	if len(data) == 0 || len(data) > MaximumTransferUploadChunk || offset > intent.Bytes || uint64(len(data)) > intent.Bytes-offset {
		return 0, ErrTransferLimit
	}
	err = store.locked(ctx, intent, func(directory string) error {
		file, e := store.open(directory, intent, true)
		if e != nil {
			return e
		}
		defer file.Close()
		info, e := file.Stat()
		if e != nil {
			return e
		}
		next = uint64(info.Size())
		if offset < next {
			if uint64(len(data)) > next-offset {
				return ErrAmbiguous
			}
			previous := make([]byte, len(data))
			if _, e = file.ReadAt(previous, int64(offset)); e != nil {
				return e
			}
			if !bytes.Equal(previous, data) {
				return ErrConflict
			}
			return file.Sync()
		}
		if offset != next {
			return ErrConflict
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		var space syscall.Statfs_t
		if e = syscall.Statfs(store.artifacts.root, &space); e != nil {
			return e
		}
		if uint64(space.Bavail)*uint64(space.Bsize) < (2<<30)+uint64(len(data)) {
			return ErrTransferLimit
		}
		if _, e = file.WriteAt(data, int64(offset)); e != nil {
			return e
		}
		if e = file.Sync(); e != nil {
			return e
		}
		next += uint64(len(data))
		return nil
	})
	return
}

func (store *LinuxTransferUploadStore) Finish(ctx context.Context, intent TransferUploadIntent) (artifact TransferArtifactDescriptor, err error) {
	err = store.locked(ctx, intent, func(directory string) error {
		if existing, e := store.artifacts.OpenTransferArtifact(ctx, intent.ArtifactIdentity()); e == nil {
			artifact = existing.Descriptor()
			e = existing.Close()
			if e != nil {
				return e
			}
			if !intent.matchesArtifact(artifact) {
				return ErrConflict
			}
			return store.removePending(directory, intent)
		} else if !os.IsNotExist(e) {
			return e
		}
		file, e := store.open(directory, intent, false)
		if e != nil {
			return e
		}
		defer file.Close()
		info, e := file.Stat()
		if e != nil {
			return e
		}
		if uint64(info.Size()) != intent.Bytes {
			return ErrConflict
		}
		var space syscall.Statfs_t
		if e = syscall.Statfs(store.artifacts.root, &space); e != nil {
			return e
		}
		if uint64(space.Bavail)*uint64(space.Bsize) < (2<<30)+intent.Bytes {
			return ErrTransferLimit
		}
		writer, e := store.artifacts.BeginTransferArtifact(ctx, intent.ArtifactIdentity(), TransferFormatSQL, intent.Compression, TransferRetention{RetainUntil: intent.ExpiresAt})
		if e != nil {
			return e
		}
		defer writer.Abort(context.Background())
		hash := sha256.New()
		n, e := io.Copy(io.MultiWriter(writer, hash), io.LimitReader(file, int64(intent.Bytes)+1))
		if e != nil {
			return e
		}
		if uint64(n) != intent.Bytes || hex.EncodeToString(hash.Sum(nil)) != intent.PayloadDigest {
			return ErrTransferInvalid
		}
		// Uploaded SQL has no trusted row count. Import provenance distinguishes
		// it from exports; native verification must measure rows after loading.
		artifact, e = writer.Commit(ctx, intent.PayloadDigest, intent.Bytes, 0)
		if e != nil {
			return e
		}
		if !intent.matchesArtifact(artifact) {
			return ErrInvalidReceipt
		}
		return store.removePending(directory, intent)
	})
	return
}

// Discard only removes unfinished bytes; a published artifact retains its
// immutable identity and follows artifact retention instead.
func (store *LinuxTransferUploadStore) Discard(ctx context.Context, intent TransferUploadIntent) error {
	return store.locked(ctx, intent, func(directory string) error { return store.removePending(directory, intent) })
}

func (store *LinuxTransferUploadStore) removePending(directory string, intent TransferUploadIntent) error {
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return nil
	}
	file, err := store.open(directory, intent, false)
	if err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "intent.json" && entry.Name() != "payload" {
			return ErrUnauthorized
		}
	}
	if err = os.RemoveAll(directory); err != nil {
		return err
	}
	return syncTransferDirectory(store.artifacts.root)
}
