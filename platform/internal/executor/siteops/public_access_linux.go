//go:build linux

package siteops

import (
	"context"
	"encoding/binary"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func webWorkerUID() (uint32, error) {
	account, err := user.Lookup("cyberpanel-web")
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || id == 0 || id >= uint64(DefaultUIDMinimum) {
		return 0, ErrInvalidRequest
	}
	return uint32(id), nil
}

func lookupSiteSocketUser(uid uint32) (string, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	return account.Username, nil
}

// Named-user access never puts site processes in a shared web-server group.
// The ACL mask preserves site-group permissions; unrelated users get no access.
func webWorkerACL(mode, uid, permission uint32) []byte {
	entries := [][3]uint32{{1, (mode >> 6) & 7, ^uint32(0)}, {2, permission, uid}, {4, (mode >> 3) & 7, ^uint32(0)}, {16, ((mode >> 3) & 7) | permission, ^uint32(0)}, {32, mode & 7, ^uint32(0)}}
	data := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(data, 2)
	for i, e := range entries {
		offset := 4 + i*8
		binary.LittleEndian.PutUint16(data[offset:], uint16(e[0]))
		binary.LittleEndian.PutUint16(data[offset+2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(data[offset+4:], e[2])
	}
	return data
}

func (host *LinuxHost) grantPublicDirectoryAccess(ctx context.Context, identity UnixIdentity, layout DirectoryLayout) error {
	uid, err := webWorkerUID()
	if err != nil {
		return err
	}
	for _, definition := range layout.Definitions {
		if err = ctx.Err(); err != nil {
			return err
		}
		if len(definition.Components) < 3 {
			continue
		}
		suffix := strings.Join(definition.Components[3:], "/")
		public := suffix == "releases/current/public" || suffix == "shared/uploads"
		if !public && suffix != "" && suffix != "releases" && suffix != "releases/current" && suffix != "shared" {
			continue
		}
		fd, err := descendDirectory(host.sitesFD, definition.Components...)
		if err != nil {
			return err
		}
		err = grantPublicDirectoryFD(fd, identity, uid, public)
		closeErr := unix.Close(fd)
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func grantPublicDirectoryFD(fd int, identity UnixIdentity, webUID uint32, public bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != identity.UID) || st.Gid != identity.GID || st.Mode&0007 != 0 {
		return ErrRegistryConflict
	}
	permission := uint32(1)
	if public {
		permission = 5
	}
	acl := webWorkerACL(st.Mode&0777, webUID, permission)
	if err := unix.Fsetxattr(fd, "system.posix_acl_access", acl, 0); err != nil {
		return err
	}
	if public {
		if err := unix.Fsetxattr(fd, "system.posix_acl_default", acl, 0); err != nil {
			return err
		}
	}
	return unix.Fsync(fd)
}
