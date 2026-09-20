//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/install"
)

const webWorkerUnit = `[Service]
# The panel, not the vendor WebAdmin, owns immutable configuration generations.
ReadOnlyPaths=/usr/local/lsws/conf /etc
CapabilityBoundingSet=~CAP_SYS_ADMIN
KillMode=control-group
`

func reconcileWebWorker() error {
	if os.Geteuid() != 0 {
		return errors.New("web worker provisioning requires root installer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := install.NewLinuxHost().EnsureIdentity(ctx, install.IdentityWebWorker); err != nil {
		return err
	}
	account, err := user.Lookup(string(install.IdentityWebWorker))
	if err != nil {
		return err
	}
	group, err := user.LookupGroup(string(install.IdentityWebWorker))
	if err != nil {
		return err
	}
	if account.Uid == "0" || group.Gid == "0" || account.Gid != group.Gid || account.HomeDir != "/var/lib/cyberpanel-web" {
		return errors.New("web worker identity conflicts with isolated service account")
	}
	// lshttpd.service is the canonical unit; lsws/openlitespeed are aliases.
	const directory = "/etc/systemd/system/lshttpd.service.d"
	if err := trustedDNSAncestors(filepath.Dir(directory)); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := trustedDNSAncestors(directory); err != nil {
		return err
	}
	const path = directory + "/50-cyberpanel-authority.conf"
	if _, err := ensureOwnedFile(path, 0644, 0, 0, []byte(webWorkerUnit)); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != webWorkerUnit {
		return errors.New("web service authority differs from managed definition")
	}
	if err := provisionSystemWebContent(); err != nil {
		return err
	}
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload").Run()
}

func provisionSystemWebContent() error {
	// Fixed panel-owned static roots, not tenant identities or uploaded content.
	for _, directory := range []string{"/var/lib/cyberpanel/sites", "/var/lib/cyberpanel/site-health"} {
		if err := trustedDNSAncestors(filepath.Dir(directory)); err != nil {
			return err
		}
		if err := ensureOwnedDirectory(directory, 0711, 0, 0); err != nil {
			return err
		}
	}
	for _, directory := range []string{
		"/var/lib/cyberpanel/sites/system-default",
		"/var/lib/cyberpanel/sites/system-default/roots",
		"/var/lib/cyberpanel/sites/system-default/roots/g1",
		"/usr/local/lsws/panel", "/usr/local/lsws/panel/system",
		"/usr/local/lsws/panel/system/maintenance", "/usr/local/lsws/panel/system/suspended",
		"/var/lib/cyberpanel/site-health/system-default",
		"/var/lib/cyberpanel/site-health/system-default/g1",
	} {
		if err := trustedDNSAncestors(filepath.Dir(directory)); err != nil {
			return err
		}
		if err := ensureOwnedDirectory(directory, 0755, 0, 0); err != nil {
			return err
		}
	}
	for _, state := range []string{"maintenance", "suspended"} {
		path := "/usr/local/lsws/panel/system/" + state + "/index.html"
		content := []byte("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Site unavailable</title><h1>Site unavailable</h1><p>This site is currently " + state + ".</p></html>\n")
		if _, err := ensureOwnedFile(path, 0644, 0, 0, content); err != nil {
			return err
		}
		existing, err := os.ReadFile(path)
		if err != nil || string(existing) != string(content) {
			return errors.New("system web content differs from managed definition")
		}
	}
	return nil
}
