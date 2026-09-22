//go:build linux

package siteops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// ReconcilePoolDependencies upgrades only enabled, current, canonical managed
// pools. It never starts a service: restore freezes must survive executor boot.
func (host *LinuxHost) ReconcilePoolDependencies(ctx context.Context, registry *DurableRegistry, admission rebootcontrol.ExecutionAdmission) error {
	if ctx == nil || registry == nil || admission == nil {
		return ErrInvalidRequest
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	state, err := registry.loadLocked()
	if err != nil {
		return err
	}
	if err = registry.validateState(state); err != nil {
		return err
	}
	keys := make([]string, 0, len(state.Bindings))
	for key := range state.Bindings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		binding := state.Bindings[key]
		// EnsureLSAPIPool requires the same root generation before committing
		// PoolGeneration; a mismatch here is an unfinished provisioning transition.
		if binding.State != BindingActive || binding.PoolGeneration == 0 || binding.RootGeneration != binding.PoolGeneration {
			continue
		}
		name := LSAPISpec{SiteKey: binding.SiteKey, Generation: binding.PoolGeneration}.UnitName()
		content, readErr := readPoolUnit(host.unitFD, name)
		if errors.Is(readErr, syscall.ENOENT) {
			continue
		}
		if readErr != nil {
			return readErr
		}
		next, recognized := poolDependencyUpgrade(binding, content)
		if !recognized {
			continue
		}
		enabled, enabledErr := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-enabled", name).Output()
		if enabledErr != nil || strings.TrimSpace(string(enabled)) != "enabled" {
			continue
		}
		digest := rebootcontrol.ExecutionDigest(struct {
			Binding RuntimeBinding
			Unit    string
		}{binding, string(next)})
		lease, admitErr := admission.AdmitExecution(ctx, rebootcontrol.ExecutionBinding{Boundary: "siteops-pool-dependencies", Method: "engine_start_membership", EffectID: name + "-" + digest[:16], RequestDigest: digest, Caller: "panel-execd-startup", Resource: rebootcontrol.ExecutionResource(binding)})
		if admitErr != nil {
			return admitErr
		}
		if len(lease.Cached) != 0 {
			target, linkErr := os.Readlink(filepath.Join(SystemdUnitRootPath, "lsws.service.wants", name))
			if !bytes.Equal(content, next) || linkErr != nil || target != filepath.Join(SystemdUnitRootPath, name) {
				return ErrRegistryConflict
			}
			continue
		}
		applyErr := func() error {
			if !bytes.Equal(content, next) {
				if err := atomicWriteAt(host.unitFD, name, next, 0644, 0, 0); err != nil {
					return err
				}
			}
			// enable refreshes dependency links but deliberately omits --now.
			if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload").Run(); err != nil {
				return err
			}
			return exec.CommandContext(ctx, "/usr/bin/systemctl", "enable", name).Run()
		}()
		settleErr := rebootcontrol.SettleExecution(admission, lease, applyErr == nil, struct{ Digest string }{digest})
		if err = errors.Join(applyErr, settleErr); err != nil {
			return err
		}
	}
	return nil
}

func readPoolUnit(directory int, name string) ([]byte, error) {
	var parent syscall.Stat_t
	if err := syscall.Fstat(directory, &parent); err != nil {
		return nil, err
	}
	if parent.Uid != 0 || parent.Gid != 0 || parent.Mode&0022 != 0 {
		return nil, ErrRegistryConflict
	}
	fd, err := syscall.Openat(directory, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0022 != 0 || stat.Size > 64<<10 {
		return nil, ErrRegistryConflict
	}
	return io.ReadAll(io.LimitReader(file, 64<<10))
}

// Existing provisioning emits the fixed eight-child resource profile. Only an
// exact old/new canonical rendering is migrated; custom units remain untouched.
func poolDependencyUpgrade(binding RuntimeBinding, content []byte) ([]byte, bool) {
	for _, edition := range []EngineEdition{EditionOpenLiteSpeed, EditionLiteSpeedEnterprise} {
		for _, version := range []string{"81", "82", "83", "84"} {
			spec := LSAPISpec{Edition: edition, SiteKey: binding.SiteKey, Username: binding.Username, UID: binding.UID, GID: binding.GID, Generation: binding.PoolGeneration, MaxConnections: 8, PHPBinary: "/usr/local/lsws/lsphp" + version + "/bin/lsphp", ProcessProfile: provisioning.DefaultSiteProcessResourceProfile(binding.PoolGeneration, 8)}
			next, err := spec.RenderSystemdUnit()
			if err != nil {
				return nil, false
			}
			old := bytes.Replace(next, []byte("WantedBy=multi-user.target lsws.service\n"), []byte("WantedBy=multi-user.target\n"), 1)
			if bytes.Equal(content, old) || bytes.Equal(content, next) {
				return next, true
			}
		}
	}
	return nil, false
}
