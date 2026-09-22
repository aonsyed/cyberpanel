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
	prepared := filepath.Join(root, ".current-one")
	for _, path := range []string{current, target} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(current, "old"), []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := switchLinuxBackupCurrent(target, prepared, current); err != nil {
			t.Fatal(err)
		}
	}
	if value, err := os.ReadFile(filepath.Join(prepared, "old")); err != nil || string(value) != "previous" {
		t.Fatalf("retained previous: %q %v", value, err)
	}
	if link, err := os.Readlink(current); err != nil || link != "restore-one" {
		t.Fatalf("current: %q %v", link, err)
	}
	// Rollback publication uses the same boundary but starts from a symlink.
	rollback := filepath.Join(root, "rollback-one")
	if err := os.Mkdir(rollback, 0700); err != nil {
		t.Fatal(err)
	}
	if err := switchLinuxBackupCurrent(rollback, filepath.Join(root, ".rollback"), current); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(prepared, "old")); err != nil {
		t.Fatal("rollback removed retained original", err)
	}
}

func TestCurrentExchangeRejectsUnknownPreparedDirectory(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current")
	target := filepath.Join(root, "restored")
	prepared := filepath.Join(root, ".prepared")
	for _, path := range []string{current, target, prepared} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := switchLinuxBackupCurrent(target, prepared, current); err == nil {
		t.Fatal("unknown directory accepted")
	}
	if info, err := os.Lstat(current); err != nil || !info.IsDir() {
		t.Fatal("current changed")
	}
}
