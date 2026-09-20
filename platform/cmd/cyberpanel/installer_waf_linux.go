//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/operations"
)

func reconcileInitialWAF() error {
	if os.Geteuid() != 0 {
		return errors.New("WAF bootstrap requires root installer")
	}
	if err := trustedDNSAncestors("/usr/local/lsws/conf"); err != nil {
		return err
	}
	const directory = "/usr/local/lsws/conf/modsec"
	if err := ensureOwnedDirectory(directory, 0700, 0, 0); err != nil {
		return err
	}
	uid, gid, err := lookupIdentity("cyberpanel-web")
	if err != nil {
		return err
	}
	// Root-owned parent prevents the worker replacing the runtime directories.
	const state = "/var/lib/cyberpanel-waf"
	if err := trustedDNSAncestors(filepath.Dir(state)); err != nil {
		return err
	}
	if err := ensureOwnedDirectory(state, 0711, 0, 0); err != nil {
		return err
	}
	for _, path := range []string{state + "/tmp", state + "/data"} {
		if err := ensureOwnedDirectory(path, 0700, uid, gid); err != nil {
			return err
		}
	}
	return provisionInitialWAFFile(directory+"/cyberpanel.conf", operations.VerifyInitialWAFAssets)
}

func provisionInitialWAFFile(path string, verifyAssets func() error) error {
	if err := trustedDNSAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	baseline := operations.InitialWAFConfiguration()
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || info.Mode().Perm() != 0600 || info.Size() > 64<<20 {
			return errors.New("unsafe existing WAF policy")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Equal(data, baseline) {
			return verifyAssets()
		}
		// Later managed generations belong to the executor, not installer replay.
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := verifyAssets(); err != nil {
		return err
	}
	_, err := ensureOwnedFile(path, 0600, 0, 0, baseline)
	return err
}
