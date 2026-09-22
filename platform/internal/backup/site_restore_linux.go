//go:build linux

package backup

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Freshly provisioned sites have a real current directory. Exchange it with the
// prepared symlink atomically, retaining the old directory at the staging name.
// A failed exchange leaves current untouched; never delete the old content.
func switchLinuxBackupCurrent(target, prepared, current string) error {
	if filepath.Dir(target) != filepath.Dir(current) || filepath.Dir(prepared) != filepath.Dir(current) || target == current || prepared == current {
		return ErrInvalidBackup
	}
	if info, err := os.Lstat(target); err != nil || !info.IsDir() {
		return ErrInvalidBackup
	}
	if link, err := os.Readlink(current); err == nil && link == filepath.Base(target) {
		// Exchange completed before a crash. A retained directory is expected;
		// do not remove it or exchange it back into the live position.
		info, err := os.Lstat(prepared)
		if os.IsNotExist(err) || err == nil && info.IsDir() {
			return syncLinuxBackupReleaseParent(current)
		}
		return ErrInvalidBackup
	}
	if link, err := os.Readlink(prepared); err == nil {
		if link != filepath.Base(target) {
			return ErrInvalidBackup
		}
	} else if os.IsNotExist(err) {
		if err = os.Symlink(filepath.Base(target), prepared); err != nil {
			return err
		}
	} else {
		return err
	}
	info, err := os.Lstat(current)
	if err != nil {
		return err
	}
	if info.IsDir() {
		err = unix.Renameat2(unix.AT_FDCWD, prepared, unix.AT_FDCWD, current, unix.RENAME_EXCHANGE)
	} else if info.Mode()&os.ModeSymlink != 0 {
		err = os.Rename(prepared, current)
	} else {
		return ErrInvalidBackup
	}
	if err != nil {
		return err
	}
	return syncLinuxBackupReleaseParent(current)
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
	return nil
}
