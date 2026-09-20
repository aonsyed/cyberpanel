//go:build linux

package webactivation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// Keep the full prior receipt, not just its evidence digest. Separate immutable
// files keep the live journal format readable by the previous release.
func (journal *Journal) archiveAttempt(record journalRecord) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	name := "recovery-" + rebootcontrol.ExecutionDigest(record) + ".json"
	file, err := journal.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := journal.root.Lstat(name)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(len(encoded)) {
			return ErrInvalidResponse
		}
		old, readErr := journal.root.ReadFile(name)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(old, encoded) {
			return ErrInvalidResponse
		}
		return nil
	}
	if err != nil {
		return err
	}
	n, writeErr := file.Write(encoded)
	if writeErr == nil && n != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	dir, err := journal.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
