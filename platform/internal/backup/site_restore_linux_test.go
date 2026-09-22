//go:build linux

package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentDirectoryExchangeRetainsPreviousAndReplays(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current")
	target := filepath.Join(root, "restore-one")
	for _, path := range []string{current, target} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(current, "old"), []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	previous, _ := linuxBackupReleaseIdentity(current, false)
	candidate, _ := linuxBackupReleaseIdentity(target, true)
	for i := 0; i < 2; i++ {
		if err := switchLinuxBackupCurrent(target, current, previous, candidate); err != nil {
			t.Fatal(err)
		}
	}
	if value, err := os.ReadFile(filepath.Join(target, "old")); err != nil || string(value) != "previous" {
		t.Fatalf("retained previous: %q %v", value, err)
	}
	if info, err := os.Lstat(current); err != nil || !info.IsDir() {
		t.Fatalf("current must remain a real directory: %v", err)
	}
	// Rollback publication preserves the real-directory boundary too.
	rollback := filepath.Join(root, "rollback-one")
	if err := os.Mkdir(rollback, 0700); err != nil {
		t.Fatal(err)
	}
	rollbackIdentity, _ := linuxBackupReleaseIdentity(rollback, true)
	if err := switchLinuxBackupCurrent(rollback, current, candidate, rollbackIdentity); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "old")); err != nil {
		t.Fatal("rollback removed retained original", err)
	}
}

func TestCurrentExchangeRejectsUnknownPreparedDirectory(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current")
	target := filepath.Join(root, "restored")
	for _, path := range []string{current, target} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := switchLinuxBackupCurrent(target, current, "unknown-old", "unknown-new"); err == nil {
		t.Fatal("unknown directory accepted")
	}
	if info, err := os.Lstat(current); err != nil || !info.IsDir() {
		t.Fatal("current changed")
	}
}

func TestCurrentExchangeMigratesLegacySymlink(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current")
	old := filepath.Join(root, "old")
	target := filepath.Join(root, "restored")
	for _, p := range []string{old, target} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("old", current); err != nil {
		t.Fatal(err)
	}
	previous, _ := linuxBackupReleaseIdentity(current, false)
	candidate, _ := linuxBackupReleaseIdentity(target, true)
	for i := 0; i < 2; i++ {
		if err := switchLinuxBackupCurrent(target, current, previous, candidate); err != nil {
			t.Fatal(err)
		}
	}
	if info, err := os.Lstat(current); err != nil || !info.IsDir() {
		t.Fatal("legacy symlink not replaced by directory", err)
	}
	if link, err := os.Readlink(target); err != nil || link != "old" {
		t.Fatal("legacy symlink not retained", err)
	}
}
