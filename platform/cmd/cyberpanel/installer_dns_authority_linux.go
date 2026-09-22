//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/aonsyed/cyberpanel/platform/internal/dns"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const managedPowerDNSConfig = dns.PowerDNSConfigurationRoot + "/current/pdns/pdns.conf"

// Adoption is installer-only and limited to the pristine package conffile.
// Operator edits are never treated as disposable defaults.
func reconcileDNSAuthority() error {
	if os.Geteuid() != 0 {
		return errors.New("DNS adoption requires root installer")
	}
	found := false
	for _, path := range []string{"/etc/powerdns/pdns.conf", "/etc/pdns/pdns.conf"} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		found = true
		if err = trustedDNSAncestors(filepath.Dir(path)); err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, readErr := os.Readlink(path)
			metadata, ok := info.Sys().(*syscall.Stat_t)
			if readErr != nil || !ok || metadata.Uid != 0 || target != managedPowerDNSConfig {
				return errors.New("unmanaged DNS configuration link")
			}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		state, stateErr := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "pdns.service").Output()
		cancel()
		if stateErr == nil || strings.TrimSpace(string(state)) != "inactive" {
			return errors.New("stop PowerDNS before adopting its package configuration")
		}
		ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
		var command *exec.Cmd
		if path == "/etc/powerdns/pdns.conf" {
			command = exec.CommandContext(ctx, "/usr/bin/dpkg-query", "-W", "-f=${Conffiles}\n", "pdns-server")
		} else {
			command = exec.CommandContext(ctx, "/usr/bin/rpm", "-q", "--dump", "pdns")
		}
		output, queryErr := command.Output()
		cancel()
		if queryErr != nil || len(output) > 1<<20 {
			return errors.New("cannot verify PowerDNS package configuration")
		}
		digest := ""
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != path {
				continue
			}
			if digest != "" {
				return errors.New("duplicate package configuration record")
			}
			if path == "/etc/powerdns/pdns.conf" {
				if len(fields) != 2 {
					return errors.New("obsolete or invalid PowerDNS conffile")
				}
				digest = fields[1]
			} else {
				if len(fields) < 10 || fields[7] != "1" {
					return errors.New("invalid RPM configuration record")
				}
				digest = fields[3]
			}
		}
		if err = adoptPristineDNSConfig(path, managedPowerDNSConfig, digest); err != nil {
			return err
		}
	}
	if found {
		if err := reconcileDefaultResolved(); err != nil {
			return err
		}
		return installPowerDNSCredentialUnit()
	}
	return nil
}

const powerDNSCredentialUnit = `[Service]
# Copy only the active config into the daemon's private credential mount.
LoadCredential=pdns.conf:/var/lib/cyberpanel/powerdns/current/pdns/pdns.conf
ExecStart=
ExecStart=/usr/sbin/pdns_server --guardian=no --daemon=no --disable-syslog --log-timestamp=no --write-pid=no --config-dir=/run/credentials/pdns.service
`

// A completed configuration receipt is not a daemon-start receipt for a new
// boot. Pull the native service in before executor recovery probes it. Wants
// deliberately permits first installation without an active generation: the
// existing executor activation then materializes and starts PowerDNS.
const powerDNSStartupUnit = `[Unit]
Wants=pdns.service
After=pdns.service
`

func installPowerDNSCredentialUnit() error {
	const directory = "/etc/systemd/system/pdns.service.d"
	if err := trustedDNSAncestors(filepath.Dir(directory)); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := trustedDNSAncestors(directory); err != nil {
		return err
	}
	path := filepath.Join(directory, "50-cyberpanel-credentials.conf")
	if _, err := ensureOwnedFile(path, 0644, 0, 0, []byte(powerDNSCredentialUnit)); err != nil {
		return err
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != powerDNSCredentialUnit {
		return errors.New("PowerDNS credential unit differs from managed definition")
	}
	const startupDirectory = "/etc/systemd/system/panel-execd.service.d"
	if err := os.Mkdir(startupDirectory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := trustedDNSAncestors(startupDirectory); err != nil {
		return err
	}
	startupPath := filepath.Join(startupDirectory, "50-cyberpanel-powerdns.conf")
	if _, err := ensureOwnedFile(startupPath, 0644, 0, 0, []byte(powerDNSStartupUnit)); err != nil {
		return err
	}
	content, err = os.ReadFile(startupPath)
	if err != nil || string(content) != powerDNSStartupUnit {
		return errors.New("PowerDNS startup unit differs from managed definition")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload").Run()
}

func trustedDNSAncestors(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe DNS configuration ancestor")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func adoptPristineDNSConfig(path, target, packageDigest string) error {
	if err := trustedDNSAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || metadata.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
		return errors.New("unsafe native DNS configuration")
	}
	content, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(content) > 1<<20 {
		return errors.New("cannot read native DNS configuration")
	}
	defer wipeBytes(content)
	sha := sha256.Sum256(content)
	shaText := hex.EncodeToString(sha[:])
	// MD5 here compares dpkg's local conffile record, not release signatures.
	md := md5.Sum(content)
	if packageDigest != shaText && packageDigest != hex.EncodeToString(md[:]) {
		return errors.New("PowerDNS configuration differs from installed package; refusing adoption")
	}
	backup := path + ".cyberpanel-vendor-" + shaText
	if _, err = ensureOwnedFile(backup, 0600, 0, 0, content); err != nil {
		return err
	}
	backupContent, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	matched := bytes.Equal(backupContent, content)
	wipeBytes(backupContent)
	if !matched {
		return errors.New("PowerDNS vendor backup does not match")
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		return errors.New("PowerDNS configuration changed during adoption")
	}
	temporary := path + ".cyberpanel-adopt"
	if err = os.Symlink(target, temporary); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		linkInfo, statErr := os.Lstat(temporary)
		linkTarget, readErr := os.Readlink(temporary)
		if statErr != nil || readErr != nil || linkInfo.Sys().(*syscall.Stat_t).Uid != 0 || linkTarget != target {
			return errors.New("unsafe DNS adoption staging link")
		}
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
