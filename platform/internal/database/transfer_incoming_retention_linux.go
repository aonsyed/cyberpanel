//go:build linux

package database

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A process-lifetime directory flock distinguishes crashed writers from slow
// ones. Age alone never authorizes deletion of an active transfer.
func (store *LinuxTransferArtifactStore) collectAbandonedIncoming(name string) (bool, error) {
	tombstone := strings.HasPrefix(name, ".abandoned-")
	suffix := strings.TrimPrefix(strings.TrimPrefix(name, ".incoming-"), ".abandoned-")
	if suffix == "" || strings.Trim(suffix, "0123456789") != "" {
		return false, nil
	}
	directory := filepath.Join(store.root, name)
	if err := verifyPrivateTransferDirectory(directory); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	lease, err := os.OpenFile(directory, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer lease.Close()
	if err := syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return false, nil
		}
		return false, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if tombstone && len(entries) == 0 {
		if err := os.Remove(directory); err != nil {
			return false, err
		}
		return true, syncTransferDirectory(store.root)
	}
	for _, entry := range entries {
		if entry.Name() != "payload" && entry.Name() != "descriptor.json" {
			return false, ErrTransferInvalid
		}
	}
	meta, err := openTransferArtifactFile(filepath.Join(directory, "descriptor.json"))
	if err != nil {
		// Old pre-metadata writers and interrupted initialization are not enough
		// evidence to delete. Preserve them for administrator inspection.
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	decoder := json.NewDecoder(io.LimitReader(meta, 65537))
	decoder.DisallowUnknownFields()
	var metadata transferArtifactMetadata
	info, statErr := meta.Stat()
	decodeErr := decoder.Decode(&metadata)
	endErr := decoder.Decode(&struct{}{})
	closeErr := meta.Close()
	d := metadata.Descriptor
	if statErr != nil || info.Size() > 65536 || decodeErr != nil || endErr != io.EOF || closeErr != nil || metadata.Schema != 1 || d.Identity.Validate() != nil || d.Format != TransferFormatSQL || !validTransferCompression(d.Compression) || d.CreatedAt.IsZero() || !d.ExpiresAt.After(d.CreatedAt) || !d.ExpiresAt.Equal(metadata.Retention.RetainUntil) || metadata.Retention.Validate(d.CreatedAt) != nil {
		return false, ErrTransferInvalid
	}
	if (d.Digest != "" || d.Bytes != 0 || d.Rows != 0) && d.Validate() != nil {
		return false, ErrTransferInvalid
	}
	if metadata.Retention.LegalHold || store.now().Before(d.ExpiresAt) {
		return false, nil
	}
	payload, err := openTransferArtifactFile(filepath.Join(directory, "payload"))
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err == nil {
		info, statErr := payload.Stat()
		payload.Close()
		if statErr != nil || info.Size() < 0 || uint64(info.Size()) > store.maximum {
			return false, ErrTransferInvalid
		}
	}
	if !tombstone {
		target := filepath.Join(store.root, ".abandoned-"+suffix)
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
	// Explicit names only: never recursively delete an inspected candidate.
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
