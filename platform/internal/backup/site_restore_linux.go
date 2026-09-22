//go:build linux

package backup

import (
	"io/fs"
	"os"
	"path/filepath"
)

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
