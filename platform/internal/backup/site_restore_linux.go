//go:build linux

package backup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"golang.org/x/sys/unix"
)

// Keep current a real directory: native vhosts deliberately forbid symlink
// document roots. Both identities are journaled before this atomic exchange.
func switchLinuxBackupCurrent(target, current, previousIdentity, candidateIdentity string) error {
	if filepath.Dir(target) != filepath.Dir(current) || target == current || previousIdentity == "" || candidateIdentity == "" || previousIdentity == candidateIdentity {
		return ErrInvalidBackup
	}
	live, err := linuxBackupReleaseIdentity(current, false)
	if err != nil {
		return err
	}
	retained, err := linuxBackupReleaseIdentity(target, false)
	if err != nil {
		return err
	}
	if live == candidateIdentity && retained == previousIdentity {
		if _, err = linuxBackupReleaseIdentity(current, true); err != nil {
			return err
		}
		return syncLinuxBackupReleaseParent(current)
	}
	if live != previousIdentity || retained != candidateIdentity {
		return ErrBackupConflict
	}
	if _, err = linuxBackupReleaseIdentity(target, true); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, target, unix.AT_FDCWD, current, unix.RENAME_EXCHANGE); err != nil {
		return err
	}
	return syncLinuxBackupReleaseParent(current)
}

func linuxBackupReleaseIdentity(path string, directoryOnly bool) (string, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return "", err
	}
	kind := stat.Mode & unix.S_IFMT
	if kind != unix.S_IFDIR && (directoryOnly || kind != unix.S_IFLNK) {
		return "", ErrInvalidBackup
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}

func syncLinuxBackupReleaseParent(current string) error {
	fd, err := unix.Open(filepath.Dir(current), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	return errors.Join(unix.Fsync(fd), unix.Close(fd))
}

// Archives deliberately discard source numeric owners. Rebind extracted site
// content to the resolved target identity before it becomes the live release;
// keeping root ownership leaves private files unreadable to the application.
func extractLinuxBackupSiteTar(archive, target string, binding LinuxBackupSiteBinding) error {
	if binding.UID < 1000 || binding.GID != binding.UID {
		return ErrInvalidBackup
	}
	if err := extractLinuxBackupTar(archive, target); err != nil {
		return err
	}
	for _, component := range []string{"release", "private"} {
		root := filepath.Join(target, component)
		info, err := os.Lstat(root)
		if os.IsNotExist(err) && component == "private" {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidBackup
		}
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			// Never follow an archived symlink while assigning target ownership.
			return os.Lchown(path, int(binding.UID), int(binding.GID))
		}); err != nil {
			return err
		}
	}
	fd, err := unix.Open(filepath.Join(target, "release"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return siteops.GrantRestoredPublicAccess(fd, binding.UID, binding.GID)
}
