//go:build linux

package apps

import (
	"bytes"
	"encoding/binary"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// A sibling staging tree does not inherit the public directory's reader ACL.
// Preserve only the provisioned public-reader policy, before extracting files;
// never copy this policy onto the release directory or its private siblings.
func preserveCertifiedPublicAccess(current, stage linuxApplicationScope) error {
	if filepath.Base(current.root) != "public" || filepath.Base(filepath.Dir(current.root)) != "current" {
		return nil
	}
	account, err := user.Lookup("cyberpanel-web")
	if err != nil {
		return err
	}
	webUID, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || webUID == 0 || uint32(webUID) == current.binding.UID {
		return ErrPolicyDenied
	}
	open := func(path string) (int, error) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err
		}
		var stat unix.Stat_t
		if err = unix.Fstat(fd, &stat); err != nil || stat.Uid != current.binding.UID || stat.Gid != current.binding.GID || stat.Mode&0777 != 0750 {
			unix.Close(fd)
			return -1, ErrPolicyDenied
		}
		return fd, nil
	}
	source, err := open(current.root)
	if err != nil {
		return err
	}
	defer unix.Close(source)
	var policy []byte
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		var value [44]byte
		n, err := unix.Fgetxattr(source, name, value[:])
		if err != nil {
			return err
		}
		if n != len(value) || !validCertifiedPublicACL(value[:], uint32(webUID)) {
			return ErrPolicyDenied
		}
		if policy != nil && !bytes.Equal(policy, value[:]) {
			return ErrPolicyDenied
		}
		policy = append([]byte(nil), value[:]...)
	}
	target, err := open(stage.root)
	if err != nil {
		return err
	}
	defer unix.Close(target)
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		if err := unix.Fsetxattr(target, name, policy, 0); err != nil {
			return err
		}
	}
	return unix.Fsync(target)
}

func validCertifiedPublicACL(value []byte, webUID uint32) bool {
	if len(value) != 44 || binary.LittleEndian.Uint32(value) != 2 {
		return false
	}
	entries := [][3]uint32{{1, 7, ^uint32(0)}, {2, 5, webUID}, {4, 5, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 0, ^uint32(0)}}
	for i, entry := range entries {
		part := value[4+i*8:]
		if uint32(binary.LittleEndian.Uint16(part)) != entry[0] || uint32(binary.LittleEndian.Uint16(part[2:])) != entry[1] || binary.LittleEndian.Uint32(part[4:]) != entry[2] {
			return false
		}
	}
	return true
}
