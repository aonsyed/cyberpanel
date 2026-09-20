//go:build linux

package database

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (store *LinuxTransferUploadStore) CollectExpired(ctx context.Context, maximum int) (count int, err error) {
	if maximum < 1 || maximum > 1000 {
		return 0, ErrTransferInvalid
	}
	err = store.withLock(ctx, func() error {
		entries, e := os.ReadDir(store.artifacts.root)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if e = ctx.Err(); e != nil {
				return e
			}
			if count == maximum {
				return nil
			}
			digest := strings.TrimPrefix(entry.Name(), ".upload-")
			if digest == entry.Name() || !validSHA256(digest) {
				continue
			}
			directory := filepath.Join(store.artifacts.root, entry.Name())
			if e = verifyPrivateTransferDirectory(directory); e != nil {
				return e
			}
			meta, e := openTransferArtifactFile(filepath.Join(directory, "intent.json"))
			if e != nil {
				return e
			}
			decoder := json.NewDecoder(io.LimitReader(meta, 8193))
			decoder.DisallowUnknownFields()
			var intent TransferUploadIntent
			decodeErr := decoder.Decode(&intent)
			endErr := decoder.Decode(&struct{}{})
			closeErr := meta.Close()
			if decodeErr != nil || endErr != io.EOF || closeErr != nil || intent.Validate() != nil || intent.Digest != digest {
				return ErrUnauthorized
			}
			if store.artifacts.now().Before(intent.ExpiresAt) {
				continue
			}
			if e = store.removePending(directory, intent); e != nil {
				return e
			}
			count++
		}
		if count < maximum {
			published, e := store.artifacts.CollectExpired(ctx, maximum-count)
			count += published
			return e
		}
		return nil
	})
	return
}

// Daemon maintenance does not create an unused upload store or expose cleanup
// authority to API clients. Pending and published expired bytes are collected.
func (executor *LinuxMariaDBExecutor) CollectExpiredUploads(ctx context.Context, maximum int) (int, error) {
	if executor == nil || executor.now == nil || ctx == nil {
		return 0, ErrTransferInvalid
	}
	if _, err := os.Lstat(transferUploadRoot); os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	store, err := NewLinuxTransferUploadStore(transferUploadRoot, executor.now)
	if err != nil {
		return 0, err
	}
	return store.CollectExpired(ctx, maximum)
}
