//go:build linux

package siteops

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const atRemovedDir = 0x200

func secureAbsoluteDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || mode.Perm()&0002 != 0 { return errors.New("invalid trusted directory") }
	current := string(os.PathSeparator)
	for _, component := range strings.Split(strings.TrimPrefix(path, string(os.PathSeparator)), string(os.PathSeparator)) {
		if !validPathComponent(component) { return errors.New("invalid trusted directory component") }
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) { if err = os.Mkdir(current, mode); err != nil && !errors.Is(err, os.ErrExist) { return err }; info, err = os.Lstat(current) }
		if err != nil { return err }
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return fmt.Errorf("trusted directory %s is not a real directory", current) }
	}
	return os.Chmod(path, mode)
}

func openDirectory(path string) (int, error) { return syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) }

func openDirectoryAt(parent int, leaf string) (int, error) {
	if !validPathComponent(leaf) { return -1, errors.New("unsafe directory component") }
	return syscall.Openat(parent, leaf, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}

func ensureDirectoryPath(base int, definition DirectoryDefinition, uid, gid uint32) error {
	current, err := syscall.Dup(base); if err != nil { return err }
	for index, component := range definition.Components {
		next, openErr := openDirectoryAt(current, component)
		if errors.Is(openErr, syscall.ENOENT) {
			creationMode := uint32(0750); if index == len(definition.Components)-1 { creationMode = definition.Mode }
			if mkdirErr := syscall.Mkdirat(current, component, creationMode); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) { syscall.Close(current); return mkdirErr }
			next, openErr = openDirectoryAt(current, component)
		}
		if openErr != nil { syscall.Close(current); return openErr }
		if index == len(definition.Components)-1 {
			ownerUID, ownerGID := 0, 0; if definition.Owner == OwnerSite { ownerUID, ownerGID = int(uid), int(gid) } else if definition.Owner == OwnerRootSiteGroup { ownerGID = int(gid) }
			if err = syscall.Fchown(next, ownerUID, ownerGID); err == nil { err = syscall.Fchmod(next, definition.Mode) }
			if err != nil { syscall.Close(next); syscall.Close(current); return err }
		}
		syscall.Close(current); current = next
	}
	err = syscall.Fsync(current); closeErr := syscall.Close(current); if err == nil { err = closeErr }; return err
}

func descendDirectory(base int, components ...string) (int, error) {
	current, err := syscall.Dup(base); if err != nil { return -1, err }
	for _, component := range components {
		next, openErr := openDirectoryAt(current, component); syscall.Close(current)
		if openErr != nil { return -1, openErr }; current = next
	}
	return current, nil
}

func atomicWriteAt(directory int, leaf string, content []byte, mode uint32, uid, gid int) error {
	if !validPathComponent(leaf) || len(content) == 0 || len(content) > 64<<20 || mode&0002 != 0 { return errors.New("invalid atomic write") }
	temporary, err := randomLeaf(".panel-write-"); if err != nil { return err }
	fd, err := syscall.Openat(directory, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil { return err }
	committed := false
	defer func() { syscall.Close(fd); if !committed { _ = unlinkAt(directory, temporary, 0) } }()
	if err = syscall.Fchown(fd, uid, gid); err == nil { err = syscall.Fchmod(fd, mode) }
	if err == nil {
		written := 0
		for written < len(content) { count, writeErr := syscall.Write(fd, content[written:]); if writeErr != nil { err = writeErr; break }; if count == 0 { err = io.ErrShortWrite; break }; written += count }
	}
	if err == nil { err = syscall.Fsync(fd) }
	if err == nil { err = syscall.Renameat(directory, temporary, directory, leaf) }
	if err == nil { err = syscall.Fsync(directory) }
	if err != nil { return err }; committed = true; return nil
}

func randomLeaf(prefix string) (string, error) { var value [12]byte; if _, err := io.ReadFull(rand.Reader, value[:]); err != nil { return "", err }; return prefix + hex.EncodeToString(value[:]), nil }

func renameBetween(sourceDirectory int, source string, targetDirectory int, target string) error {
	if !validPathComponent(source) || !validPathComponent(target) { return errors.New("invalid rename component") }
	err := syscall.Renameat(sourceDirectory, source, targetDirectory, target)
	if err == nil { if syncErr := syscall.Fsync(sourceDirectory); syncErr != nil { return syncErr }; if sourceDirectory != targetDirectory { return syscall.Fsync(targetDirectory) } }
	return err
}

func directoryExistsAt(parent int, leaf string) (bool, error) {
	fd, err := openDirectoryAt(parent, leaf); if err == nil { syscall.Close(fd); return true, nil }; if errors.Is(err, syscall.ENOENT) { return false, nil }; return false, err
}

func regularExistsAt(parent int, leaf string) (bool, error) {
	if !validPathComponent(leaf) { return false, errors.New("unsafe file component") }
	fd, err := syscall.Openat(parent, leaf, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) { return false, nil }; if err != nil { return false, err }; defer syscall.Close(fd)
	var metadata syscall.Stat_t; if err = syscall.Fstat(fd, &metadata); err != nil { return false, err }
	return metadata.Mode&syscall.S_IFMT == syscall.S_IFREG, nil
}

func removeTreeAt(parent int, leaf string) error {
	fd, err := openDirectoryAt(parent, leaf); if errors.Is(err, syscall.ENOENT) { return nil }; if err != nil { return err }
	mount, err := fdMountID(fd); if err != nil { syscall.Close(fd); return err }
	if err = removeDirectoryContents(fd, mount); err != nil { syscall.Close(fd); return err }; syscall.Close(fd)
	if err = unlinkAt(parent, leaf, atRemovedDir); err != nil && !errors.Is(err, syscall.ENOENT) { return err }
	return syscall.Fsync(parent)
}

func removeDirectoryContents(directory int, mount uint64) error {
	duplicate, err := syscall.Dup(directory); if err != nil { return err }
	file := os.NewFile(uintptr(duplicate), "siteops-delete")
	for {
		names, readErr := file.Readdirnames(128)
		for _, name := range names {
			if !validPathComponent(name) { file.Close(); return errors.New("unsafe tombstone child") }
			child, openErr := openDirectoryAt(directory, name)
			if openErr == nil {
				childMount, mountErr := fdMountID(child); if mountErr != nil { syscall.Close(child); file.Close(); return mountErr }; if childMount != mount { syscall.Close(child); file.Close(); return errors.New("refusing to cross a mount while deleting a tombstone") }
				if err = removeDirectoryContents(child, mount); err == nil { err = unlinkAt(directory, name, atRemovedDir) }; syscall.Close(child)
			} else if errors.Is(openErr, syscall.ENOTDIR) || errors.Is(openErr, syscall.ELOOP) {
				err = unlinkAt(directory, name, 0)
			} else if errors.Is(openErr, syscall.ENOENT) { err = nil } else { err = openErr }
			if err != nil { file.Close(); return err }
		}
		if errors.Is(readErr, io.EOF) { break }; if readErr != nil { file.Close(); return readErr }
	}
	if err = file.Close(); err != nil { return err }
	return syscall.Fsync(directory)
}

func fdMountID(fd int) (uint64, error) {
	content, err := os.ReadFile("/proc/self/fdinfo/"+strconv.Itoa(fd)); if err != nil { return 0, err }; if len(content) > 8192 { return 0, errors.New("descriptor metadata exceeds limit") }
	for _, line := range strings.Split(string(content), "\n") { if strings.HasPrefix(line, "mnt_id:") { value := strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")); parsed, parseErr := strconv.ParseUint(value, 10, 64); if parseErr != nil || parsed == 0 { return 0, errors.New("invalid descriptor mount identity") }; return parsed, nil } }
	return 0, errors.New("descriptor mount identity is unavailable")
}

func unlinkAt(directory int, path string, flags int) error {
	if !validPathComponent(path) { return errors.New("unsafe unlink component") }
	pointer, err := syscall.BytePtrFromString(path); if err != nil { return err }
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(directory), uintptr(unsafe.Pointer(pointer)), uintptr(flags))
	if errno != 0 { return errno }
	return nil
}

type LinuxStateBackend struct{ rootFD int }

var _ StateBackend = (*LinuxStateBackend)(nil)

func NewLinuxStateBackend() (*LinuxStateBackend, error) {
	if err := secureAbsoluteDirectory(RegistryRootPath, 0700); err != nil { return nil, err }
	fd, err := openDirectory(RegistryRootPath); if err != nil { return nil, err }
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil { syscall.Close(fd); return nil, errors.New("another panel-execd owns the siteops registry") }
	return &LinuxStateBackend{rootFD: fd}, nil
}

func (backend *LinuxStateBackend) Close() error { if backend == nil || backend.rootFD < 0 { return nil }; _ = syscall.Flock(backend.rootFD, syscall.LOCK_UN); err := syscall.Close(backend.rootFD); backend.rootFD = -1; return err }

func (backend *LinuxStateBackend) Load() ([]byte, bool, error) {
	if backend == nil || backend.rootFD < 0 { return nil, false, errors.New("siteops state backend is closed") }
	fd, err := syscall.Openat(backend.rootFD, "registry.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) { return nil, false, nil }; if err != nil { return nil, false, err }
	file := os.NewFile(uintptr(fd), "registry.json"); defer file.Close()
	info, err := file.Stat(); if err != nil { return nil, false, err }; metadata, ok := info.Sys().(*syscall.Stat_t); if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || metadata.Uid != 0 || metadata.Gid != 0 || info.Size() < 1 || info.Size() > 64<<20 { return nil, false, ErrCorruptRegistry }
	content, err := io.ReadAll(io.LimitReader(file, 64<<20+1)); if err != nil { return nil, false, err }; if int64(len(content)) != info.Size() { return nil, false, ErrCorruptRegistry }
	return content, true, nil
}

func (backend *LinuxStateBackend) Store(content []byte) error {
	if backend == nil || backend.rootFD < 0 || len(content) == 0 || len(content) > 64<<20 { return errors.New("invalid siteops state write") }
	return atomicWriteAt(backend.rootFD, "registry.json", content, 0600, 0, 0)
}
