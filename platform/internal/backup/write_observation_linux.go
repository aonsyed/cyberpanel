//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Observe the bound databases, not optional server-wide InnoDB counters (which
// do not account for every supported engine). This is state-change evidence,
// not proof that no write occurred and was subsequently reversed.
func linuxBackupScopedDatabaseFingerprint(ctx context.Context, binding LinuxBackupSiteBinding) (string, error) {
	names, err := linuxBackupDatabaseNames(binding)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	if len(names) == 0 {
		return hex.EncodeToString(hash.Sum(nil)), nil
	}
	arguments := []string{"--protocol=socket", "--socket=/run/mysqld/mysqld.sock", "--user=root", "--single-transaction", "--quick", "--skip-comments", "--skip-dump-date", "--order-by-primary", "--skip-extended-insert", "--routines", "--events", "--triggers", "--hex-blob", "--databases"}
	arguments = append(arguments, names...)
	command := exec.CommandContext(ctx, "/usr/bin/mariadb-dump", arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/root"}
	command.Stdout = hash
	stderr := &linuxBackupLimitedBuffer{maximum: 1 << 20}
	command.Stderr = stderr
	if err = command.Run(); err != nil {
		return "", fmt.Errorf("scoped database observation failed: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func linuxBackupTreeFingerprint(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidBackup
	}
	hash := sha256.New()
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrInvalidBackup
		}
		fmt.Fprintf(hash, "%s\x00%d\x00%d\x00%d\x00%d\x00%d\x00", filepath.ToSlash(relative), info.Mode(), stat.Uid, stat.Gid, info.Size(), info.ModTime().UnixNano())
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_, err = io.WriteString(hash, target+"\x00")
			return err
		case info.IsDir():
			return nil
		case info.Mode().IsRegular():
			file, err := openLinuxBackupRegular(path)
			if err != nil {
				return err
			}
			opened, err := file.Stat()
			if err != nil || !os.SameFile(info, opened) {
				file.Close()
				return errors.Join(ErrBackupConflict, err)
			}
			content := sha256.New()
			_, readErr := io.Copy(content, file)
			after, statErr := file.Stat()
			closeErr := file.Close()
			if err = errors.Join(readErr, statErr, closeErr); err != nil {
				return err
			}
			if opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
				return ErrBackupConflict
			}
			_, err = hash.Write(content.Sum(nil))
			return err
		default:
			return ErrInvalidBackup
		}
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
