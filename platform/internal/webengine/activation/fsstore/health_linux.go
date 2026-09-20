//go:build linux

package fsstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

// NewWithHealth is the production store. Root owns the proof tree; workers can
// read proofs but cannot change them. New remains config-only for parser tools.
func NewWithHealth(configRoot string, edition webengine.Edition, healthRoot string) (*Store, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(healthRoot) || filepath.Clean(healthRoot) != healthRoot {
		return nil, errors.New("root-owned absolute health directory required")
	}
	for name := healthRoot; ; name = filepath.Dir(name) {
		info, err := os.Lstat(name)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("unsafe health directory ancestry")
		}
		if name == filepath.Dir(name) {
			break
		}
	}
	store, err := New(configRoot, edition)
	if err != nil {
		return nil, err
	}
	store.health, err = os.OpenRoot(healthRoot)
	if err != nil {
		store.Close()
		return nil, err
	}
	store.healthWriter = store.writeHealth
	return store, nil
}

func (s *Store) writeHealth(ctx context.Context, candidate manifest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, currentErr := s.Current(ctx)
	initial := errors.Is(currentErr, fs.ErrNotExist)
	if currentErr != nil && !initial {
		return currentErr
	}
	if !initial && current.Digest != candidate.Digest {
		previous, _, err := s.resolve(current, true)
		if err != nil {
			return err
		}
		if candidate.Snapshot <= previous.Snapshot {
			return errors.New("new activation must advance the confirmed web snapshot")
		}
	}
	if initial && candidate.Snapshot != 1 {
		return errors.New("initial health proof requires snapshot one")
	}
	name := "g" + strconv.FormatUint(candidate.Snapshot, 10)
	if err := s.health.Mkdir(name, 0755); err == nil {
		if err := s.health.Chmod(name, 0755); err != nil {
			return err
		}
		parent, err := s.health.Open(".")
		if err != nil {
			return err
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if err := errors.Join(syncErr, closeErr); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := s.health.Lstat(name)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm() != 0755 {
		return errors.New("unsafe health generation directory")
	}
	directory, err := s.health.OpenRoot(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	body := []byte("panel-health-v1 " + candidate.Digest + "\n")
	file, err := directory.OpenFile("activation", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		info, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			return statErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0444 || stat.Uid != 0 || stat.Nlink != 1 || info.Size() > 128 {
			file.Close()
			return errors.New("unsafe health proof file")
		}
		previous, readErr := io.ReadAll(io.LimitReader(file, 129))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		if bytes.Equal(previous, body) {
			return nil
		}
		// Bootstrap's stopped-engine guard permits replacing a failed initial
		// candidate. Never overwrite a confirmed generation's proof.
		if !initial {
			return errors.New("health proof conflicts with sealed generation")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".activation-" + hex.EncodeToString(nonce[:])
	file, err = directory.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0444)
	if err != nil {
		return err
	}
	defer directory.Remove(temporary)
	if err := file.Chmod(0444); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := directory.Rename(temporary, "activation"); err != nil {
		return err
	}
	parent, err := directory.Open(".")
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
