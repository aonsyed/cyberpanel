//go:build linux

package siteops

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// GrantRestoredPublicAccess rebinds public-reader ACLs discarded by portable
// archives. The caller supplies an open, no-follow restored release directory.
// Only release traversal and public descendants are granted; never private data.
func GrantRestoredPublicAccess(releaseFD int, siteUID, siteGID uint32) error {
	if siteUID < 1000 || siteGID != siteUID {
		return ErrInvalidRequest
	}
	webUID, err := webWorkerUID()
	if err != nil {
		return err
	}
	identity := UnixIdentity{UID: siteUID, GID: siteGID}
	if err = grantPublicDirectoryFD(releaseFD, identity, webUID, false); err != nil {
		return err
	}
	public, err := unix.Openat(releaseFD, "public", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(public)
	return grantRestoredPublicTree(public, identity, webUID)
}

func grantRestoredPublicTree(fd int, identity UnixIdentity, webUID uint32) error {
	if err := grantPublicDirectoryFD(fd, identity, webUID, true); err != nil {
		return err
	}
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(duplicate), "restored-public")
	entries, err := file.ReadDir(-1)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, entry := range entries {
		var stat unix.Stat_t
		if err = unix.Fstatat(fd, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			continue
		}
		child, openErr := unix.Openat(fd, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return openErr
		}
		if err = unix.Fstat(child, &stat); err == nil {
			if stat.Uid != identity.UID || stat.Gid != identity.GID {
				err = ErrRegistryConflict
			} else if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
				err = grantRestoredPublicTree(child, identity, webUID)
			} else if stat.Mode&unix.S_IFMT == unix.S_IFREG {
				err = unix.Fsetxattr(child, "system.posix_acl_access", webWorkerACL(stat.Mode&0777, webUID, 4), 0)
				if err == nil {
					err = unix.Fsync(child)
				}
			} else {
				err = ErrInvalidRequest
			}
		}
		closeErr = unix.Close(child)
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
