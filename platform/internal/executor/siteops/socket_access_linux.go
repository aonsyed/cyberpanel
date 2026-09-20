//go:build linux

package siteops

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// GrantLSAPIWebAccess runs as the site account after every pool start. It can
// grant access only to that account's fixed socket, never an arbitrary path.
func GrantLSAPIWebAccess(ctx context.Context, siteKey, generation string) error {
	if !validToken(siteKey, 3, 64) || len(siteKey) < 3 || siteKey[:2] != "s-" {
		return ErrInvalidRequest
	}
	gen, err := strconv.ParseUint(generation, 10, 64)
	if err != nil || gen == 0 || strconv.FormatUint(gen, 10) != generation {
		return ErrInvalidRequest
	}
	owner, err := userIdentityForSocket(siteKey)
	if err != nil {
		return err
	}
	webUID, err := webWorkerUID()
	if err != nil {
		return err
	}
	root, err := unix.Open(RuntimeRootPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	fd, err := descendDirectory(root, siteKey, "php", "pool-"+siteKey)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for {
		err = grantWebSocketAt(fd, "g"+generation+".sock", owner, webUID)
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func userIdentityForSocket(siteKey string) (uint32, error) {
	uid := uint32(os.Geteuid())
	if uid < DefaultUIDMinimum || uid > DefaultUIDMaximum {
		return 0, ErrInvalidRequest
	}
	account, err := lookupSiteSocketUser(uid)
	if err != nil || account != deriveUsername(siteKey) {
		return 0, ErrInvalidRequest
	}
	return uid, nil
}

func grantWebSocketAt(fd int, leaf string, owner, webUID uint32) error {
	var directory, socket unix.Stat_t
	if err := unix.Fstat(fd, &directory); err != nil {
		return err
	}
	if directory.Uid != owner || directory.Mode&0027 != 0 {
		return ErrRegistryConflict
	}
	if err := unix.Fstatat(fd, leaf, &socket, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if socket.Uid != owner || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Nlink != 1 || socket.Mode&0007 != 0 {
		return ErrRegistryConflict
	}
	if err := unix.Fsetxattr(fd, "system.posix_acl_access", webWorkerACL(directory.Mode&0777, webUID, 1), 0); err != nil {
		return err
	}
	return unix.Lsetxattr("/proc/self/fd/"+strconv.Itoa(fd)+"/"+leaf, "system.posix_acl_access", webWorkerACL(socket.Mode&0777, webUID, 6), 0)
}
