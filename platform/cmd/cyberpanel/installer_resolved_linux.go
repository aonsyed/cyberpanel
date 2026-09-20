//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const resolvedHandoff = "[Resolve]\nDNSStubListener=no\n"

// Only the distribution's default stub setup is adopted. The resolver continues
// tracking DHCP upstreams; no static public resolver or authoritative recursion
// is substituted. Custom settings need an explicit operator migration.
func reconcileDefaultResolved() error {
	const resolver = "/etc/resolv.conf"
	const upstream = "/run/systemd/resolve/resolv.conf"
	const backup = "/etc/resolv.conf.cyberpanel-stub-backup"
	const directory = "/etc/systemd/resolved.conf.d"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	state, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "systemd-resolved.service").Output()
	if err != nil {
		if strings.TrimSpace(string(state)) == "inactive" {
			return nil
		}
		return errors.New("cannot determine systemd-resolved state")
	}
	if err := trustedDNSAncestors("/etc"); err != nil {
		return err
	}
	info, err := os.Lstat(resolver)
	if err != nil {
		return err
	}
	target, err := os.Readlink(resolver)
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || metadata.Uid != 0 || (target != "../run/systemd/resolve/stub-resolv.conf" && target != "/run/systemd/resolve/stub-resolv.conf" && target != upstream) {
		return errors.New("refusing to replace custom resolver configuration")
	}
	configuration, err := exec.CommandContext(ctx, "/usr/bin/systemd-analyze", "cat-config", "systemd/resolved.conf").Output()
	if err != nil || !defaultResolvedConfiguration(string(configuration)) {
		return errors.New("refusing to alter custom systemd-resolved settings")
	}
	contents, err := os.ReadFile(upstream)
	if err != nil {
		return err
	}
	hasUpstream := false
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" {
			if strings.HasPrefix(fields[1], "127.") || fields[1] == "::1" {
				return errors.New("resolved upstream points to local DNS")
			}
			hasUpstream = true
		}
	}
	if !hasUpstream {
		return errors.New("resolved has no upstream nameserver")
	}
	if target == upstream {
		// An already-direct custom resolver is not evidence of our adoption.
		content, err := os.ReadFile(backup)
		if err != nil || (string(content) != "../run/systemd/resolve/stub-resolv.conf" && string(content) != "/run/systemd/resolve/stub-resolv.conf") {
			return errors.New("missing resolver handoff backup")
		}
		target = string(content)
	}
	if _, err := ensureOwnedFile(backup, 0600, 0, 0, []byte(target)); err != nil {
		return err
	}
	saved, err := os.ReadFile(backup)
	if err != nil || string(saved) != target {
		return errors.New("resolver backup mismatch")
	}
	if err := trustedDNSAncestors(filepath.Dir(directory)); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := trustedDNSAncestors(directory); err != nil {
		return err
	}
	path := directory + "/50-cyberpanel-authoritative.conf"
	if _, err := ensureOwnedFile(path, 0644, 0, 0, []byte(resolvedHandoff)); err != nil {
		return err
	}
	installed, err := os.ReadFile(path)
	if err != nil || string(installed) != resolvedHandoff {
		return errors.New("resolver drop-in mismatch")
	}
	// Switch clients to the live upstream file before stopping the stub.
	temporary := resolver + ".cyberpanel-adopt"
	if err := os.Symlink(upstream, temporary); err != nil {
		return err
	}
	current, err := os.Lstat(resolver)
	if err != nil || !os.SameFile(info, current) {
		_ = os.Remove(temporary)
		return errors.New("resolver changed during adoption")
	}
	if err := os.Rename(temporary, resolver); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	dir, err := os.Open("/etc")
	if err != nil {
		return err
	}
	err = dir.Sync()
	_ = dir.Close()
	if err != nil {
		return err
	}
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", "systemd-resolved.service").Run()
}

func defaultResolvedConfiguration(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || line == "[Resolve]" || line == "DNSStubListener=no" {
			continue
		}
		return false
	}
	return true
}
