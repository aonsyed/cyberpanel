//go:build linux

package dns

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

// No startup activation can have persisted in an empty store with no current
// generation. Require the fixed daemon inactive as well. Any staged generation
// or live service needs deeper reconciliation and is deliberately not retried.
func (host *LinuxPowerDNSHost) unappliedStartupEvidence(ctx context.Context, snapshotDigest string) (string, error) {
	if host == nil || ctx == nil || !powerDNSSHA256(snapshotDigest) {
		return "", ErrPowerDNSAmbiguous
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.Store == nil || host.Store.Root != PowerDNSConfigurationRoot {
		return "", ErrPowerDNSAmbiguous
	}
	if err := observePowerDNSBinding(host.profile.configuration); err != nil {
		return "", err
	}
	current, err := host.Store.Current()
	if err != nil || current != "" {
		return "", ErrPowerDNSAmbiguous
	}
	for _, name := range []string{"generations", "staging"} {
		path := filepath.Join(PowerDNSConfigurationRoot, name)
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return "", ErrPowerDNSAmbiguous
		}
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			return "", ErrPowerDNSAmbiguous
		}
	}
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := runPowerDNSProcess(probe, host.profile.systemctl, "is-active", host.profile.unit)
	var exit *exec.ExitError
	if probe.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 3 || strings.TrimSpace(string(output)) != "inactive" {
		return "", ErrPowerDNSAmbiguous
	}
	return digestPowerDNSEvidence("unapplied-startup-v1", snapshotDigest, host.profile.configuration.link, host.profile.configuration.target, "empty-generations", "empty-staging", "inactive", host.now().Format(time.RFC3339Nano)), nil
}
