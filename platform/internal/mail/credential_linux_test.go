//go:build linux

package mail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCoreMailCredentialPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := loadCoreMailCredential(path)
	if err != nil || len(key) != 32 {
		t.Fatal("owner-only fixture rejected", err)
	}
	wipeMailBytes(key)
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCoreMailCredential(path); err == nil {
		t.Fatal("accepted ordinary group-readable secret")
	}
	if _, err := LoadMailSessionCredential(path); err == nil {
		t.Fatal("accepted arbitrary session credential path")
	}
	if _, err := LoadCampaignUnsubscribeCredential(path); err == nil {
		t.Fatal("accepted arbitrary campaign credential path")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 31, 33} {
		if err := os.WriteFile(path, make([]byte, size), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCoreMailCredential(path); err == nil {
			t.Fatalf("accepted %d-byte key", size)
		}
	}
	if err := os.WriteFile(path, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCoreMailCredential(link); err == nil {
		t.Fatal("accepted symlink credential")
	}
}

func TestActualCoreMailCredentials(t *testing.T) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		t.Skip("requires QEMU systemd credential unit")
	}
	for _, name := range []string{"webmail-session.key", "marketing-unsubscribe.key"} {
		key, err := loadCoreMailCredential(filepath.Join(dir, name))
		if err != nil || len(key) != 32 {
			t.Fatalf("%s: %v", name, err)
		}
		wipeMailBytes(key)
	}
}
