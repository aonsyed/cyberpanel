//go:build linux

package main

import (
	"encoding/binary"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// systemd's per-service credentials use a named-user ACL. Its mask appears
// as group read permission even though the owning group has no access.
// Ordinary secret files must never inherit this exception.
func privateSystemdCredential(file *os.File) bool {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0440 {
		return false
	}
	var metadata unix.Stat_t
	if unix.Fstat(int(file.Fd()), &metadata) != nil || metadata.Uid != 0 || metadata.Gid != 0 || metadata.Nlink != 1 {
		return false
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&unix.ST_RDONLY == 0 {
		return false
	}
	if !credentialACL(int(file.Fd()), uint32(os.Geteuid()), 4) {
		return false
	}
	parent, err := unix.Open(filepath.Dir(file.Name()), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(parent)
	if unix.Fstat(parent, &metadata) != nil || metadata.Uid != 0 || metadata.Gid != 0 || metadata.Mode&0777 != 0550 {
		return false
	}
	return credentialACL(parent, uint32(os.Geteuid()), 5)
}

func credentialACL(fd int, uid uint32, permission uint16) bool {
	if uid == 0 {
		return false
	}
	var data [256]byte
	n, err := unix.Fgetxattr(fd, "system.posix_acl_access", data[:])
	if err != nil || n != 44 || binary.LittleEndian.Uint32(data[:4]) != 2 {
		return false
	}
	seen := uint16(0)
	for offset := 4; offset < n; offset += 8 {
		tag := binary.LittleEndian.Uint16(data[offset:])
		perm := binary.LittleEndian.Uint16(data[offset+2:])
		id := binary.LittleEndian.Uint32(data[offset+4:])
		if seen&tag != 0 {
			return false
		}
		seen |= tag
		switch tag {
		case 1, 16: // owner and mask
			if perm != permission || id != ^uint32(0) {
				return false
			}
		case 2: // exactly the service account; no other named users
			if perm != permission || id != uid {
				return false
			}
		case 4, 32: // owning group and everyone else
			if perm != 0 || id != ^uint32(0) {
				return false
			}
		default:
			return false
		}
	}
	return seen == 55
}
