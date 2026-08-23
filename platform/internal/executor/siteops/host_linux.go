//go:build linux

package siteops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type LinuxHost struct {
	sitesFD      int
	quarantineFD int
	tombstoneFD  int
	unitFD       int
	healthFD     int
	phpConfigFD  int
}

var _ Host = (*LinuxHost)(nil)

func NewLinuxHost() (*LinuxHost, error) {
	for _, directory := range []struct { path string; mode os.FileMode }{
		{"/var/lib/cyberpanel", 0755}, {SitesRootPath, 0711}, {QuarantineRootPath, 0700}, {TombstoneRootPath, 0700},
		{"/run/cyberpanel", 0711}, {RuntimeRootPath, 0711}, {HealthRootPath, 0711}, {PHPConfigRootPath, 0711},
	} { if err := secureAbsoluteDirectory(directory.path, directory.mode); err != nil { return nil, err } }
	if info, err := os.Lstat(SystemdUnitRootPath); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { if err != nil { return nil, err }; return nil, errors.New("systemd unit root is not a real directory") }
	values := make([]int, 0, 6)
	for _, path := range []string{SitesRootPath, QuarantineRootPath, TombstoneRootPath, SystemdUnitRootPath, HealthRootPath, PHPConfigRootPath} { fd, err := openDirectory(path); if err != nil { for _, value := range values { syscall.Close(value) }; return nil, err }; values = append(values, fd) }
	return &LinuxHost{sitesFD: values[0], quarantineFD: values[1], tombstoneFD: values[2], unitFD: values[3], healthFD: values[4], phpConfigFD: values[5]}, nil
}

func (host *LinuxHost) Close() error {
	if host == nil { return nil }; var result error
	for _, pointer := range []*int{&host.sitesFD, &host.quarantineFD, &host.tombstoneFD, &host.unitFD, &host.healthFD, &host.phpConfigFD} { if *pointer >= 0 { if err := syscall.Close(*pointer); result == nil { result = err }; *pointer = -1 } }
	return result
}

func (host *LinuxHost) EnsureIdentity(ctx context.Context, identity UnixIdentity) error {
	if err := validateUnixIdentity(identity); err != nil { return err }
	group, groupErr := user.LookupGroup(identity.Username)
	if groupErr != nil {
		if err := runAdministrative(ctx, processCreateGroup, identity, LSAPISpec{}); err != nil { group, groupErr = user.LookupGroup(identity.Username); if groupErr != nil { return err } }
	}
	if group == nil { group, groupErr = user.LookupGroup(identity.Username) }
	if groupErr != nil || group.Gid != strconv.FormatUint(uint64(identity.GID), 10) { return errors.New("Unix group does not match registry allocation") }
	account, accountErr := user.Lookup(identity.Username)
	if accountErr != nil {
		if err := runAdministrative(ctx, processCreateUser, identity, LSAPISpec{}); err != nil { account, accountErr = user.Lookup(identity.Username); if accountErr != nil { return err } }
	}
	if account == nil { account, accountErr = user.Lookup(identity.Username) }
	if accountErr != nil || account.Uid != strconv.FormatUint(uint64(identity.UID), 10) || account.Gid != strconv.FormatUint(uint64(identity.GID), 10) || account.HomeDir != SitesRootPath+"/"+identity.SiteKey { return errors.New("Unix user does not match registry allocation") }
	if err := verifyLocalIdentity(identity); err != nil { return err }
	return runAdministrative(ctx, processEnableUser, identity, LSAPISpec{})
}

func (host *LinuxHost) DisableIdentity(ctx context.Context, identity UnixIdentity) error {
	if err := validateUnixIdentity(identity); err != nil { return err }
	if _, err := user.Lookup(identity.Username); err != nil { return nil }
	return runAdministrative(ctx, processDisableUser, identity, LSAPISpec{})
}

func (host *LinuxHost) DeleteIdentity(ctx context.Context, identity UnixIdentity) error {
	if err := validateUnixIdentity(identity); err != nil { return err }
	if _, err := user.Lookup(identity.Username); err == nil { if err = runAdministrative(ctx, processDeleteUser, identity, LSAPISpec{}); err != nil { return err } }
	if _, err := user.LookupGroup(identity.Username); err == nil { if err = runAdministrative(ctx, processDeleteGroup, identity, LSAPISpec{}); err != nil { return err } }
	return nil
}

func validateUnixIdentity(identity UnixIdentity) error {
	if !validRuntimeKey(identity.RuntimeKey) || identity.SiteKey == "" || identity.Username != deriveUsername(identity.SiteKey) || identity.UID < DefaultUIDMinimum || identity.GID != identity.UID { return invalidSpec("Unix identity") }
	return nil
}

func LinuxUIDAvailable(uid uint32) (bool, error) {
	if uid < 1000 { return false, nil }
	numeric := strconv.FormatUint(uint64(uid), 10)
	_, err := user.LookupId(numeric); if err == nil { return false, nil }
	if _, unknown := err.(user.UnknownUserIdError); !unknown { return false, err }
	_, err = user.LookupGroupId(numeric); if err == nil { return false, nil }
	if _, unknown := err.(user.UnknownGroupIdError); unknown { return true, nil }
	return false, err
}

func (host *LinuxHost) EnsureDirectories(ctx context.Context, identity UnixIdentity, layout DirectoryLayout) error {
	if err := ctx.Err(); err != nil { return err }; if err := validateUnixIdentity(identity); err != nil { return err }; if err := layout.Validate(); err != nil { return err }; if layout.SiteKey != identity.SiteKey { return ErrRegistryConflict }
	for _, definition := range layout.Definitions { if err := ctx.Err(); err != nil { return err }; if err := ensureDirectoryPath(host.sitesFD, definition, identity.UID, identity.GID); err != nil { return err } }
	return syscall.Fsync(host.sitesFD)
}

func (host *LinuxHost) RestoreQuarantine(ctx context.Context, identity UnixIdentity, generation uint64, token string) error {
	if err := ctx.Err(); err != nil { return err }; if err := validateUnixIdentity(identity); err != nil || generation == 0 || !validToken(token, 8, 128) { return invalidSpec("quarantine restore") }
	source, err := directoryExistsAt(host.quarantineFD, token); if err != nil { return err }
	roots, err := descendDirectory(host.sitesFD, identity.SiteKey, "roots"); if err != nil { return err }; defer syscall.Close(roots)
	leaf := "g"+strconv.FormatUint(generation, 10); target, err := directoryExistsAt(roots, leaf); if err != nil { return err }
	if !source && target { return nil }; if !source || target { return ErrRegistryConflict }
	return renameBetween(host.quarantineFD, token, roots, leaf)
}

func (host *LinuxHost) WriteHealth(ctx context.Context, identity UnixIdentity, generation uint64, body []byte) error {
	if err := ctx.Err(); err != nil { return err }; if err := validateUnixIdentity(identity); err != nil || generation == 0 || len(body) != len("panel-health-v1 ")+64+1 || !bytes.HasPrefix(body, []byte("panel-health-v1 ")) || body[len(body)-1] != '\n' { return invalidSpec("health attestation") }
	for _, definition := range []DirectoryDefinition{
		{Components: []string{identity.SiteKey}, Mode: 0711, Owner: OwnerRoot},
		{Components: []string{identity.SiteKey, "g"+strconv.FormatUint(generation, 10)}, Mode: 0755, Owner: OwnerRoot},
	} { if err := ensureDirectoryPath(host.healthFD, definition, identity.UID, identity.GID); err != nil { return err } }
	directory, err := descendDirectory(host.healthFD, identity.SiteKey, "g"+strconv.FormatUint(generation, 10))
	if err != nil { return err }; defer syscall.Close(directory)
	return atomicWriteAt(directory, HealthPathToken, body, 0444, 0, 0)
}

func (host *LinuxHost) InstallLSAPI(ctx context.Context, spec LSAPISpec, content []byte) error {
	if err := ctx.Err(); err != nil { return err }; expected, err := spec.RenderSystemdUnit(); if err != nil { return err }; if !bytes.Equal(expected, content) { return errors.New("LSAPI unit differs from canonical rendering") }
	phpINI, err := spec.RenderPHPINI(); if err != nil { return err }
	for _, definition := range []DirectoryDefinition{
		{Components: []string{spec.SiteKey}, Mode: 0711, Owner: OwnerRoot},
		{Components: []string{spec.SiteKey, "g"+strconv.FormatUint(spec.Generation, 10)}, Mode: 0750, Owner: OwnerRootSiteGroup},
	} { if err = ensureDirectoryPath(host.phpConfigFD, definition, spec.UID, spec.GID); err != nil { return err } }
	configDirectory, err := descendDirectory(host.phpConfigFD, spec.SiteKey, "g"+strconv.FormatUint(spec.Generation, 10)); if err != nil { return err }
	writeErr := atomicWriteAt(configDirectory, "99-panel-runtime.ini", phpINI, 0440, 0, int(spec.GID)); closeErr := syscall.Close(configDirectory)
	if writeErr != nil { return writeErr }; if closeErr != nil { return closeErr }
	if err = atomicWriteAt(host.unitFD, spec.UnitName(), content, 0644, 0, 0); err != nil { return err }
	return runAdministrative(ctx, processDaemonReload, UnixIdentity{}, spec)
}

func (host *LinuxHost) StartLSAPI(ctx context.Context, spec LSAPISpec) error { if err := spec.Validate(); err != nil { return err }; return runAdministrative(ctx, processStartUnit, UnixIdentity{}, spec) }
func (host *LinuxHost) StopLSAPI(ctx context.Context, spec LSAPISpec) error {
	if err := spec.Validate(); err != nil { return err }
	err := runAdministrative(ctx, processStopUnit, UnixIdentity{}, spec); if err == nil { return nil }
	exists, existenceErr := regularExistsAt(host.unitFD, spec.UnitName()); if existenceErr != nil { return existenceErr }; if !exists { return nil }
	return err
}

func (host *LinuxHost) RemoveLSAPI(ctx context.Context, spec LSAPISpec) error {
	if err := spec.Validate(); err != nil { return err }
	if err := host.StopLSAPI(ctx, spec); err != nil { return err }
	if err := unlinkAt(host.unitFD, spec.UnitName(), 0); err != nil && !errors.Is(err, syscall.ENOENT) { return err }
	if err := syscall.Fsync(host.unitFD); err != nil { return err }
	return runAdministrative(ctx, processDaemonReload, UnixIdentity{}, spec)
}

func (host *LinuxHost) ProbeLSAPIResources(ctx context.Context, spec LSAPISpec) (ProcessResourceObservation, error) {
	if err := ctx.Err(); err != nil { return ProcessResourceObservation{}, err }
	if err := spec.Validate(); err != nil { return ProcessResourceObservation{}, err }
	observation := ProcessResourceObservation{Generation: spec.Generation}
	controlGroup, ok := liveControlGroup(ctx, spec.UnitName())
	if !ok { return observation, nil }
	root := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(controlGroup, "/"))
	observation.CPUQuota = readCPUQuota(filepath.Join(root, "cpu.max"))
	observation.CPUWeight = readScalarLimit(filepath.Join(root, "cpu.weight"))
	observation.MemoryHigh = readScalarLimit(filepath.Join(root, "memory.high"))
	observation.MemoryMax = readScalarLimit(filepath.Join(root, "memory.max"))
	observation.TasksMax = readScalarLimit(filepath.Join(root, "pids.max"))
	device, deviceOK := generationDevice(spec.GenerationRoot())
	if deviceOK {
		observation.IOReadBPS, observation.IOWriteBPS, observation.IOReadIOPS, observation.IOWriteIOPS = readIOMax(filepath.Join(root, "io.max"), device)
	}
	return observation, nil
}

func liveControlGroup(ctx context.Context, unit string) (string, bool) {
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", unit, "--property=ControlGroup", "--value", "--no-pager")
	command.Stdin = nil; output := &boundedOutput{limit: 4096}; command.Stdout, command.Stderr = output, output
	if command.Run() != nil { return "", false }
	value := strings.TrimSpace(output.String())
	if value == "" || len(value) > 1024 || value[0] != '/' || strings.Contains(value, "..") { return "", false }
	for index := range value { character := value[index]; if !alphaNumeric(character) && character != '/' && character != '-' && character != '_' && character != '.' { return "", false } }
	return value, true
}

func readCPUQuota(path string) observedProcessLimit {
	content, err := os.ReadFile(path); if err != nil { return observedProcessLimit{} }
	fields := strings.Fields(string(content)); if len(fields) != 2 { return observedProcessLimit{} }
	period, err := strconv.ParseUint(fields[1], 10, 64); if err != nil || period == 0 { return observedProcessLimit{} }
	if fields[0] == "max" { return observedProcessLimit{Supported:true, Known:true, Unlimited:true} }
	quota, err := strconv.ParseUint(fields[0], 10, 64); if err != nil || quota == 0 || quota/period > ^uint64(0)/1_000_000 { return observedProcessLimit{} }
	value := quota/period*1_000_000 + quota%period*1_000_000/period
	return observedProcessLimit{Supported:true, Known:true, Value:value}
}

func readScalarLimit(path string) observedProcessLimit {
	content, err := os.ReadFile(path); if err != nil { return observedProcessLimit{} }
	value := strings.TrimSpace(string(content)); if value == "max" { return observedProcessLimit{Supported:true, Known:true, Unlimited:true} }
	parsed, err := strconv.ParseUint(value, 10, 64); if err != nil { return observedProcessLimit{} }
	return observedProcessLimit{Supported:true, Known:true, Value:parsed}
}

func generationDevice(path string) (string, bool) {
	info, err := os.Stat(path); if err != nil { return "", false }
	metadata, ok := info.Sys().(*syscall.Stat_t); if !ok { return "", false }
	device := uint64(metadata.Dev); major := device>>8&0xfff | device>>32&^uint64(0xfff); minor := device&0xff | device>>12&^uint64(0xff)
	if major == 0 { return "", false }
	return strconv.FormatUint(major, 10)+":"+strconv.FormatUint(minor, 10), true
}

func readIOMax(path, device string) (observedProcessLimit, observedProcessLimit, observedProcessLimit, observedProcessLimit) {
	content, err := os.ReadFile(path); if err != nil { return observedProcessLimit{}, observedProcessLimit{}, observedProcessLimit{}, observedProcessLimit{} }
	readBPS := observedProcessLimit{Supported:true, Known:true, Unlimited:true, Device:device}
	writeBPS, readIOPS, writeIOPS := readBPS, readBPS, readBPS
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line); if len(fields) == 0 || fields[0] != device { continue }
		for _, field := range fields[1:] {
			name, value, found := strings.Cut(field, "="); if !found { continue }
			limit := observedProcessLimit{Supported:true, Known:true, Device:device}
			if value == "max" { limit.Unlimited = true } else { parsed, parseErr := strconv.ParseUint(value, 10, 64); if parseErr != nil { continue }; limit.Value = parsed }
			switch name { case "rbps": readBPS = limit; case "wbps": writeBPS = limit; case "riops": readIOPS = limit; case "wiops": writeIOPS = limit }
		}
		break
	}
	return readBPS, writeBPS, readIOPS, writeIOPS
}

func (host *LinuxHost) Quarantine(ctx context.Context, identity UnixIdentity, generation uint64, token string) error {
	if err := ctx.Err(); err != nil { return err }; if err := validateUnixIdentity(identity); err != nil || generation == 0 || !validToken(token, 8, 128) { return invalidSpec("quarantine") }
	roots, err := descendDirectory(host.sitesFD, identity.SiteKey, "roots"); if err != nil { return err }; defer syscall.Close(roots)
	leaf := "g"+strconv.FormatUint(generation, 10); source, err := directoryExistsAt(roots, leaf); if err != nil { return err }; target, err := directoryExistsAt(host.quarantineFD, token); if err != nil { return err }
	if !source && target { return nil }; if !source || target { return ErrRegistryConflict }
	return renameBetween(roots, leaf, host.quarantineFD, token)
}

func (host *LinuxHost) Tombstone(ctx context.Context, identity UnixIdentity, generation uint64, quarantineToken, tombstoneToken string) error {
	if err := ctx.Err(); err != nil { return err }; if err := validateUnixIdentity(identity); err != nil || generation == 0 || !validToken(tombstoneToken, 8, 128) || quarantineToken != "" && !validToken(quarantineToken, 8, 128) { return invalidSpec("tombstone") }
	target, err := directoryExistsAt(host.tombstoneFD, tombstoneToken); if err != nil { return err }
	if !target {
		source, sourceErr := directoryExistsAt(host.sitesFD, identity.SiteKey); if sourceErr != nil { return sourceErr }
		if source { if err = renameBetween(host.sitesFD, identity.SiteKey, host.tombstoneFD, tombstoneToken); err != nil { return err } } else {
			definition := DirectoryDefinition{Components: []string{tombstoneToken}, Mode: 0700, Owner: OwnerRoot}; if err = ensureDirectoryPath(host.tombstoneFD, definition, identity.UID, identity.GID); err != nil { return err }
			definition = DirectoryDefinition{Components: []string{tombstoneToken, "roots"}, Mode: 0700, Owner: OwnerRoot}; if err = ensureDirectoryPath(host.tombstoneFD, definition, identity.UID, identity.GID); err != nil { return err }
		}
	}
	if quarantineToken != "" {
		source, sourceErr := directoryExistsAt(host.quarantineFD, quarantineToken); if sourceErr != nil { return sourceErr }
		if source {
			roots, rootsErr := descendDirectory(host.tombstoneFD, tombstoneToken, "roots"); if rootsErr != nil { return rootsErr }; defer syscall.Close(roots)
			leaf := "g"+strconv.FormatUint(generation, 10); destination, destinationErr := directoryExistsAt(roots, leaf); if destinationErr != nil { return destinationErr }
			if destination { return ErrRegistryConflict }; if err = renameBetween(host.quarantineFD, quarantineToken, roots, leaf); err != nil { return err }
		}
	}
	if err = removeTreeAt(host.healthFD, identity.SiteKey); err != nil { return err }
	if err = removeTreeAt(host.phpConfigFD, identity.SiteKey); err != nil { return err }
	return nil
}

func (host *LinuxHost) DeleteTombstone(ctx context.Context, identity UnixIdentity, token string) error {
	if err := ctx.Err(); err != nil { return err }; if err := validateUnixIdentity(identity); err != nil || !validToken(token, 8, 128) { return invalidSpec("tombstone deletion") }
	return removeTreeAt(host.tombstoneFD, token)
}

type processOperation uint8
const (
	processCreateGroup processOperation = iota + 1
	processCreateUser
	processEnableUser
	processDisableUser
	processDeleteUser
	processDeleteGroup
	processDaemonReload
	processStartUnit
	processStopUnit
)

func runAdministrative(ctx context.Context, operation processOperation, identity UnixIdentity, spec LSAPISpec) error {
	var executable string; var arguments []string
	switch operation {
	case processCreateGroup:
		executable, arguments = "/usr/sbin/groupadd", []string{"--gid", strconv.FormatUint(uint64(identity.GID), 10), identity.Username}
	case processCreateUser:
		executable, arguments = "/usr/sbin/useradd", []string{"--uid", strconv.FormatUint(uint64(identity.UID), 10), "--gid", identity.Username, "--home-dir", SitesRootPath + "/" + identity.SiteKey, "--no-create-home", "--shell", "/usr/sbin/nologin", "--no-user-group", identity.Username}
	case processEnableUser:
		executable, arguments = "/usr/sbin/usermod", []string{"--expiredate", "-1", identity.Username}
	case processDisableUser:
		executable, arguments = "/usr/sbin/usermod", []string{"--expiredate", "1", identity.Username}
	case processDeleteUser:
		executable, arguments = "/usr/sbin/userdel", []string{identity.Username}
	case processDeleteGroup:
		executable, arguments = "/usr/sbin/groupdel", []string{identity.Username}
	case processDaemonReload:
		executable, arguments = "/usr/bin/systemctl", []string{"daemon-reload"}
	case processStartUnit:
		executable, arguments = "/usr/bin/systemctl", []string{"enable", "--now", spec.UnitName()}
	case processStopUnit:
		executable, arguments = "/usr/bin/systemctl", []string{"disable", "--now", spec.UnitName()}
	default: return errors.New("unsupported administrative operation")
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdin = nil; output := &boundedOutput{limit: 8192}; command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		text := strings.TrimSpace(output.String()); if len(text) > 512 { text = text[:512] }
		if text == "" { return fmt.Errorf("administrative operation %d failed: %w", operation, err) }
		return fmt.Errorf("administrative operation %d failed: %w: %s", operation, err, text)
	}
	return nil
}

type boundedOutput struct { buffer bytes.Buffer; limit int; overflow bool }
func (output *boundedOutput) Write(value []byte) (int, error) { original := len(value); remaining := output.limit-output.buffer.Len(); if remaining > 0 { if len(value) > remaining { value = value[:remaining]; output.overflow = true }; _, _ = output.buffer.Write(value) } else { output.overflow = true }; return original, nil }
func (output *boundedOutput) String() string { value := output.buffer.String(); if output.overflow { value += " [truncated]" }; return value }

func verifyLocalIdentity(identity UnixIdentity) error {
	passwd, err := readTrustedAccountFile("/etc/passwd"); if err != nil { return err }
	wantedUID, wantedGID := strconv.FormatUint(uint64(identity.UID), 10), strconv.FormatUint(uint64(identity.GID), 10)
	matchedUser := false
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":"); if len(fields) != 7 || fields[0] != identity.Username { continue }
		if fields[2] != wantedUID || fields[3] != wantedGID || fields[5] != SitesRootPath+"/"+identity.SiteKey || fields[6] != "/usr/sbin/nologin" && fields[6] != "/sbin/nologin" { return errors.New("local Unix user differs from registry binding") }
		matchedUser = true; break
	}
	if !matchedUser { return errors.New("registry Unix user is not local") }
	groups, err := readTrustedAccountFile("/etc/group"); if err != nil { return err }
	for _, line := range strings.Split(string(groups), "\n") { fields := strings.Split(line, ":"); if len(fields) == 4 && fields[0] == identity.Username { if fields[2] != wantedGID { return errors.New("local Unix group differs from registry binding") }; return nil } }
	return errors.New("registry Unix group is not local")
}

func readTrustedAccountFile(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0); if err != nil { return nil, err }
	file := os.NewFile(uintptr(fd), path); defer file.Close()
	info, err := file.Stat(); if err != nil { return nil, err }; metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > 4<<20 { return nil, errors.New("unsafe local account database") }
	content, err := io.ReadAll(io.LimitReader(file, 4<<20+1)); if err != nil || len(content) > 4<<20 { if err != nil { return nil, err }; return nil, errors.New("local account database exceeds limit") }
	return content, nil
}
