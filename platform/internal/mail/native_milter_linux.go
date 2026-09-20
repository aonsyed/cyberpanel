//go:build linux

package mail

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// PrepareNativeMilterAccess runs as a fixed service ExecStartPost helper. It
// grants Postfix socket access without adding it to a signing-key/config group.
func PrepareNativeMilterAccess(service string) error {
	if os.Geteuid() != 0 {
		return ErrInvalidCommand
	}
	var directory, socket, account string
	switch service {
	case "opendkim":
		directory, socket, account = "/run/opendkim", "/run/opendkim/opendkim.sock", "opendkim"
	case "rspamd":
		directory, socket, account = "/run/rspamd", "/run/rspamd/milter.sock", "_rspamd"
	default:
		return ErrInvalidCommand
	}
	owner, err := user.Lookup(account)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(owner.Uid, 10, 32)
	if err != nil || uid == 0 {
		return ErrInvalidCommand
	}
	postfix, err := user.Lookup("postfix")
	if err != nil {
		return err
	}
	postfixUID, err := strconv.ParseUint(postfix.Uid, 10, 32)
	if err != nil || postfixUID == 0 {
		return ErrInvalidCommand
	}
	for _, path := range []string{"/", "/run"} {
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return err
		}
		if stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0022 != 0 {
			return ErrInvalidCommand
		}
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		err = grantMilterSocket(directory, socket, uint32(uid), uint32(postfixUID))
		if err == nil || !errors.Is(err, unix.ENOENT) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func grantMilterSocket(directory, socket string, owner, postfix uint32) error {
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var dir, endpoint unix.Stat_t
	if err := unix.Fstat(fd, &dir); err != nil {
		return err
	}
	if dir.Uid != owner || dir.Mode&0022 != 0 {
		return ErrInvalidCommand
	}
	if err := unix.Lstat(socket, &endpoint); err != nil {
		return err
	}
	if endpoint.Uid != owner || endpoint.Mode&unix.S_IFMT != unix.S_IFSOCK || endpoint.Nlink != 1 || endpoint.Mode&0007 != 0 {
		return ErrInvalidCommand
	}
	dirACL, err := mailReadACL(dir.Mode&0777, []uint32{postfix}, 1)
	if err != nil {
		return err
	}
	socketACL, err := mailReadACL(endpoint.Mode&0777, []uint32{postfix}, 6)
	if err != nil {
		return err
	}
	if err := unix.Fsetxattr(fd, "system.posix_acl_access", dirACL, 0); err != nil {
		return err
	}
	// Do not follow a final symlink swapped by the daemon. The daemon owns the
	// endpoint directory, but cannot replace that directory under root-owned /run.
	return unix.Lsetxattr(socket, "system.posix_acl_access", socketACL, 0)
}
