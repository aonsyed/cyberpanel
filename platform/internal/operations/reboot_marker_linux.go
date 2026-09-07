//go:build linux

package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

const rebootMarkerDirectory = "/var/lib/cyberpanel/reboot-control"
const rebootMarkerFile = rebootMarkerDirectory + "/recovery.marker"
const legacyRebootMarkerFile = "/var/lib/cyberpanel/control/reboot-control.marker"

// All marker operations, including dispatch validation, hold this directory
// lock. Parent ownership checks prevent panel-core from replacing the directory.
func lockRebootMarkerDirectory(ctx context.Context) (*os.File, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 { return nil, ErrInvalidEffect }
	for _, path := range []string{"/", "/var", "/var/lib", "/var/lib/cyberpanel"} {
		info, err := os.Lstat(path); if err != nil { return nil, err }
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 { return nil, ErrInvalidEffect }
	}
	// Never silently discard a marker left by the old panel-core implementation.
	if _, err := os.Lstat(legacyRebootMarkerFile); !errors.Is(err, os.ErrNotExist) { return nil, ErrCompensationFailed }
	if err := os.Mkdir(rebootMarkerDirectory, 0700); err != nil && !errors.Is(err, os.ErrExist) { return nil, err }
	fd, err := syscall.Open(rebootMarkerDirectory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil { return nil, err }
	directory := os.NewFile(uintptr(fd), rebootMarkerDirectory)
	info, err := directory.Stat()
	if err != nil { directory.Close(); return nil, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0700 { directory.Close(); return nil, ErrInvalidEffect }
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil { directory.Close(); return nil, err }
	// Sync the parent as well, so first-time directory creation is durable.
	parent, err := os.Open("/var/lib/cyberpanel")
	if err != nil { directory.Close(); return nil, err }
	err = parent.Sync(); closeErr := parent.Close(); if err == nil { err = closeErr }
	if err != nil { directory.Close(); return nil, err }
	return directory, nil
}

func readRebootMarker() (*rebootcontrol.RecoveryMarker, error) {
	file, err := os.OpenFile(rebootMarkerFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) { return nil, nil }
	if err != nil { return nil, err }
	defer file.Close()
	info, err := file.Stat(); if err != nil { return nil, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 64<<10 { return nil, ErrInvalidEffect }
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil { return nil, err }; if len(raw) > 64<<10 { return nil, ErrInvalidEffect }
	decoder := json.NewDecoder(bytes.NewReader(raw)); decoder.DisallowUnknownFields()
	var marker rebootcontrol.RecoveryMarker
	if decoder.Decode(&marker) != nil || decoder.Decode(&struct{}{}) != io.EOF || marker.Validate() != nil || marker.NodeID != "local" { return nil, ErrInvalidEffect }
	canonical, err := json.Marshal(marker)
	if err != nil || !bytes.Equal(raw, canonical) { return nil, ErrInvalidEffect }
	return &marker, nil
}

// This deliberately bypasses the generic effect journal: a cached probe could
// conceal a new marker and a cached arm could claim a deleted marker is armed.
// The fsynced marker itself is the authority. Any failed mutation is ambiguous
// and is never sent through generic compensation/rollback.
func (executor *LinuxOperationsExecutor) observeRebootMarker(ctx context.Context, request EffectRequest) (EffectReceipt, error) {
	receipt := EffectReceipt{EffectID: request.EffectID, RequestDigest: request.RequestDigest, CompletedAt: executor.clock.Now().UTC()}
	result, err := applyRebootMarker(ctx, request)
	if err != nil {
		receipt.Outcome = EffectAmbiguous
		receipt.FailureCode = "reboot_marker_unproven"
		return receipt, errors.Join(ErrCompensationFailed, err)
	}
	receipt.Outcome = EffectConfirmed
	receipt.MutationObserved = effectIsMutation(request.Kind)
	receipt.Result = EffectResult{RebootMarker: &result}
	receipt.ProofDigest = effectProof(request, linuxEffectResult{Result: receipt.Result})
	return receipt, nil
}

func applyRebootMarker(ctx context.Context, request EffectRequest) (RebootMarkerResult, error) {
	directory, err := lockRebootMarkerDirectory(ctx); if err != nil { return RebootMarkerResult{}, err }
	defer directory.Close()
	marker, err := readRebootMarker(); if err != nil { return RebootMarkerResult{}, err }
	if err = ctx.Err(); err != nil { return RebootMarkerResult{}, err }
	switch request.Kind {
	case EffectRebootMarkerProbe:
		if marker == nil { return RebootMarkerResult{}, nil }
		return RebootMarkerResult{Present: true, Marker: marker, ExactDigest: marker.Digest}, nil
	case EffectRebootMarkerArm:
		wanted := request.RebootMarker.Marker
		boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil { return RebootMarkerResult{}, err }
		if strings.TrimSpace(string(boot)) != wanted.SourceBootID { return RebootMarkerResult{}, ErrInvalidEffect }
		if marker != nil {
			if marker.Digest != wanted.Digest { return RebootMarkerResult{}, ErrInvalidEffect }
			if err = directory.Sync(); err != nil { return RebootMarkerResult{}, err }
			return RebootMarkerResult{Present: true, Committed: true, Marker: marker, ExactDigest: marker.Digest}, nil
		}
		raw, err := json.Marshal(wanted); if err != nil { return RebootMarkerResult{}, err }
		file, err := os.CreateTemp(rebootMarkerDirectory, ".arm-")
		if err != nil { return RebootMarkerResult{}, err }
		temporary := file.Name(); defer os.Remove(temporary)
		// Set exact permissions even when the executor has a restrictive umask.
		if err = file.Chmod(0600); err == nil { err = file.Chown(0, 0) }
		if err == nil { var count int; count, err = file.Write(raw); if err == nil && count != len(raw) { err = io.ErrShortWrite } }
		if err == nil { err = file.Sync() }
		closeErr := file.Close(); if err == nil { err = closeErr }; if err != nil { return RebootMarkerResult{}, err }
		// link publishes atomically without overwriting another marker.
		if err = os.Link(temporary, rebootMarkerFile); err != nil { return RebootMarkerResult{}, err }
		if err = os.Remove(temporary); err != nil { return RebootMarkerResult{}, err }
		if err = directory.Sync(); err != nil { return RebootMarkerResult{}, err }
		return RebootMarkerResult{Present: true, Committed: true, Marker: wanted, ExactDigest: wanted.Digest}, nil
	case EffectRebootMarkerClear:
		if marker == nil || marker.Digest != request.RebootMarker.ExactDigest { return RebootMarkerResult{}, ErrInvalidEffect }
		if err = os.Remove(rebootMarkerFile); err != nil { return RebootMarkerResult{}, err }
		if err = directory.Sync(); err != nil { return RebootMarkerResult{}, err }
		return RebootMarkerResult{Cleared: true, ExactDigest: marker.Digest}, nil
	default: return RebootMarkerResult{}, ErrInvalidEffect
	}
}

func (executor *LinuxOperationsExecutor) dispatchMarkedReboot(ctx context.Context, request EffectRequest) (linuxEffectResult, error) {
	directory, err := lockRebootMarkerDirectory(ctx); if err != nil { return linuxEffectResult{}, err }; defer directory.Close()
	marker, err := readRebootMarker(); if err != nil { return linuxEffectResult{}, err }
	effect := request.ControlledReboot
	if marker == nil || marker.Digest != effect.MarkerDigest || marker.PlanID != effect.PlanID.String() || marker.PlanDigest != effect.PlanDigest || marker.Fence != effect.Fence || marker.SourceBootID != effect.SourceBootID.String() || !executor.clock.Now().UTC().Before(effect.DispatchBy) { return linuxEffectResult{}, ErrInvalidEffect }
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); if err != nil { return linuxEffectResult{}, err }
	if strings.TrimSpace(string(boot)) != marker.SourceBootID { return linuxEffectResult{}, ErrInvalidEffect }
	if err = directory.Sync(); err != nil { return linuxEffectResult{}, err }
	_, err = executor.runner.Run(ctx, "/usr/bin/systemctl", "reboot", "--no-block")
	if err != nil { err = errors.Join(ErrCompensationFailed, err) }
	return linuxEffectResult{MutationObserved: true, ExecutionEvidenceDigest: request.RequestDigest}, err
}
