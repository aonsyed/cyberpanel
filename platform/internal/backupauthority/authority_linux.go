//go:build linux

package backupauthority

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

var ErrInvalidBackup = errors.New("invalid local backup authority")

// ReconcileLocalRepositoryAuthority is the root installer's fixed, idempotent
// backup boundary. It does not initialize databases, claims, apps or services.
func ReconcileLocalRepositoryAuthority() ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, ErrInvalidBackup
	}
	account, err := user.Lookup("cyberpanel")
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid <= 0 {
		return nil, ErrInvalidBackup
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid <= 0 {
		return nil, ErrInvalidBackup
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, segment := range []string{"var", "backups"} {
		if segment == "backups" {
			if err := syscall.Mkdirat(fd, segment, 0755); err != nil && !errors.Is(err, syscall.EEXIST) {
				syscall.Close(fd)
				return nil, err
			}
		}
		next, openErr := syscall.Openat(fd, segment, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		var stat syscall.Stat_t
		if syscall.Fstat(next, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 {
			syscall.Close(next)
			return nil, ErrInvalidBackup
		}
		fd = next
	}
	defer syscall.Close(fd)
	parent, err := reconcileBackupAuthorityChild(fd, "cyberpanel", 0, gid, 0750)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(parent)
	repositories, err := reconcileBackupAuthorityChild(parent, "repositories", uid, gid, 0700)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(repositories)
	return []string{"/var/backups/cyberpanel", "/var/backups/cyberpanel/repositories"}, nil
}

func reconcileBackupAuthorityChild(parent int, name string, uid, gid int, mode uint32) (int, error) {
	if err := syscall.Mkdirat(parent, name, 0700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return -1, err
	}
	fd, err := syscall.Openat(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Uid != 0 && stat.Uid != uint32(uid) || stat.Gid != 0 && stat.Gid != uint32(gid) || stat.Mode&0022 != 0 {
		syscall.Close(fd)
		return -1, ErrInvalidBackup
	}
	if err = syscall.Fchown(fd, uid, gid); err == nil {
		err = syscall.Fchmod(fd, mode)
	}
	if err == nil {
		err = syscall.Fsync(parent)
	}
	if err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}
