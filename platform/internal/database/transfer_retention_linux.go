//go:build linux

package database

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CollectExpired removes validated, root-owned expired published artifacts and
// abandoned incoming artifacts. Live writers, unknown files, invalid records
// and legal holds are preserved.
// Renaming first makes interrupted removal distinguishable from corrupt storage.
func (store *LinuxTransferArtifactStore) CollectExpired(ctx context.Context, maximum int) (int, error) {
	if store == nil || ctx == nil || maximum < 1 || maximum > 1024 {
		return 0, ErrTransferInvalid
	}
	if err := verifyPrivateTransferDirectory(store.root); err != nil {
		return 0, err
	}
	root, err := os.Open(store.root)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	collected := 0
	var failures error
	for collected < maximum {
		if err := ctx.Err(); err != nil {
			return collected, errors.Join(failures, err)
		}
		entries, err := root.ReadDir(128)
		if err != nil && err != io.EOF {
			return collected, errors.Join(failures, err)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return collected, errors.Join(failures, err)
			}
			name := entry.Name()
			var removed bool
			var collectErr error
			if strings.HasPrefix(name, ".incoming-") || strings.HasPrefix(name, ".abandoned-") {
				removed, collectErr = store.collectAbandonedIncoming(name)
			} else {
				digest := strings.TrimPrefix(name, ".expired-")
				if !validSHA256(digest) {
					continue
				}
				removed, collectErr = store.collectExpiredArtifact(name, digest)
			}
			// Preserve the first failure without accumulating an unbounded error
			// tree when many damaged records require administrator attention.
			if failures == nil {
				failures = collectErr
			}
			if removed {
				collected++
			}
			if collected == maximum {
				break
			}
		}
		if err == io.EOF {
			break
		}
	}
	return collected, failures
}

func (store *LinuxTransferArtifactStore) collectExpiredArtifact(name, digest string) (bool, error) {
	directory := filepath.Join(store.root, name)
	if err := verifyPrivateTransferDirectory(directory); err != nil {
		return false, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, err
	}
	tombstone := name == ".expired-"+digest
	if tombstone && len(entries) == 0 {
		if err := os.Remove(directory); err != nil {
			return false, err
		}
		return true, syncTransferDirectory(store.root)
	}
	for _, entry := range entries {
		if entry.Name() != "descriptor.json" && entry.Name() != "payload" {
			return false, ErrTransferInvalid
		}
	}
	meta, err := openTransferArtifactFile(filepath.Join(directory, "descriptor.json"))
	if err != nil {
		return false, err
	}
	decoder := json.NewDecoder(io.LimitReader(meta, 65537))
	decoder.DisallowUnknownFields()
	var metadata transferArtifactMetadata
	info, statErr := meta.Stat()
	decodeErr := decoder.Decode(&metadata)
	endErr := decoder.Decode(&struct{}{})
	meta.Close()
	if statErr != nil || info.Size() > 65536 || decodeErr != nil || endErr != io.EOF || metadata.Schema != 1 || metadata.Descriptor.Validate() != nil || metadata.Retention.Validate(metadata.Descriptor.CreatedAt) != nil || !metadata.Descriptor.ExpiresAt.Equal(metadata.Retention.RetainUntil) {
		return false, ErrTransferInvalid
	}
	expected, err := store.artifactPath(metadata.Descriptor.Identity)
	if err != nil || filepath.Base(expected) != digest {
		return false, ErrTransferInvalid
	}
	if metadata.Retention.LegalHold || store.now().Before(metadata.Retention.RetainUntil) {
		return false, nil
	}
	payload, err := openTransferArtifactFile(filepath.Join(directory, "payload"))
	if err != nil && !(tombstone && os.IsNotExist(err)) {
		return false, err
	}
	if err == nil {
		info, statErr := payload.Stat()
		payload.Close()
		if statErr != nil || uint64(info.Size()) != metadata.Descriptor.Bytes {
			return false, ErrTransferInvalid
		}
	}
	if !tombstone {
		target := filepath.Join(store.root, ".expired-"+digest)
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			return false, ErrConflict
		}
		if err := os.Rename(directory, target); err != nil {
			return false, err
		}
		directory = target
		if err := syncTransferDirectory(store.root); err != nil {
			return false, err
		}
	}
	// Never recursively remove: unexpected contents must survive for inspection.
	if err := os.Remove(filepath.Join(directory, "payload")); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := syncTransferDirectory(directory); err != nil {
		return false, err
	}
	if err := os.Remove(filepath.Join(directory, "descriptor.json")); err != nil {
		return false, err
	}
	if err := syncTransferDirectory(directory); err != nil {
		return false, err
	}
	if err := os.Remove(directory); err != nil {
		return false, err
	}
	return true, syncTransferDirectory(store.root)
}

// CollectExpiredWorkspaceExports is daemon-owned maintenance, never a broker
// operation. Absence is normal before the first export; do not initialize stores.
func (executor *LinuxMariaDBExecutor) CollectExpiredWorkspaceExports(ctx context.Context, maximum int) (int, error) {
	if executor == nil || ctx == nil {
		return 0, ErrTransferInvalid
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if _, err := os.Lstat(workspaceExportRoot); os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	store, err := NewLinuxTransferArtifactStore(workspaceExportRoot, MaximumTransferBytes, executor.now)
	if err != nil {
		return 0, err
	}
	return store.CollectExpired(ctx, maximum)
}
