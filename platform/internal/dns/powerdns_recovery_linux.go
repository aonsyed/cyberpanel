//go:build linux

package dns

import (
	"context"
	"errors"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Recovery requires no active generation and an inactive daemon. A retained
// immutable SQLite generation is allowed only when its verified artifacts match
// the exact requested rendering. Partial staging, other generations and live
// services remain ambiguous and are never silently retried.
func (host *LinuxPowerDNSHost) unappliedStartupEvidence(ctx context.Context, snapshot PowerDNSConfigSnapshot) (string, error) {
	if host == nil || ctx == nil || snapshot.Validate(host.ControlDatabaseFingerprint) != nil {
		return "", ErrPowerDNSAmbiguous
	}
	snapshotDigest := rebootcontrol.ExecutionDigest(snapshot)
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
	retained := "empty-generations"
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
		if err != nil {
			return "", ErrPowerDNSAmbiguous
		}
		if len(entries) == 0 {
			continue
		}
		if name != "generations" || len(entries) != 1 || snapshot.Database.Backend != PowerDNSBackendSQLite {
			return "", ErrPowerDNSAmbiguous
		}
		generation, err := renderPowerDNSGeneration(snapshot, nil, host.Ownership, host.profile, host.ControlDatabaseFingerprint)
		if err != nil {
			return "", err
		}
		defer clearPowerDNSArtifacts(generation.Artifacts)
		if entries[0].Name() != generation.ID {
			return "", ErrPowerDNSAmbiguous
		}
		manifest, err := host.Store.Verify(generation.ID, generation.StorageDigest)
		if err != nil || len(manifest.Artifacts) != len(generation.Artifacts) {
			return "", ErrPowerDNSAmbiguous
		}
		for _, wanted := range generation.Artifacts {
			matched := false
			for _, actual := range manifest.Artifacts {
				if actual.Path == wanted.Path && actual.Mode == wanted.Mode && actual.GID == wanted.GID && actual.SHA256 == wanted.SHA256 && actual.Size == uint64(len(wanted.Content)) {
					matched = true
					break
				}
			}
			if !matched {
				return "", ErrPowerDNSAmbiguous
			}
		}
		retained = generation.ID + ":" + generation.StorageDigest
	}
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := runPowerDNSProcess(probe, host.profile.systemctl, "is-active", host.profile.unit)
	var exit *exec.ExitError
	if probe.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 3 || strings.TrimSpace(string(output)) != "inactive" {
		return "", ErrPowerDNSAmbiguous
	}
	return digestPowerDNSEvidence("unapplied-startup-v2", snapshotDigest, host.profile.configuration.link, host.profile.configuration.target, retained, "empty-staging", "inactive", host.now().Format(time.RFC3339Nano)), nil
}
