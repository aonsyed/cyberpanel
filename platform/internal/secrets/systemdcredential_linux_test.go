//go:build linux

package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestActualSystemdCredentialACL(t *testing.T) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		t.Skip("requires QEMU systemd credential unit")
	}
	f, err := os.Open(filepath.Join(dir, "audit-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !PrivateSystemdCredential(f) {
		t.Fatal("rejected actual private credential")
	}
	if credentialACL(int(f.Fd()), uint32(os.Geteuid())+1, 4) {
		t.Fatal("accepted wrong UID")
	}
	if credentialACL(int(f.Fd()), uint32(os.Geteuid()), 6) {
		t.Fatal("accepted wrong permissions")
	}
}
