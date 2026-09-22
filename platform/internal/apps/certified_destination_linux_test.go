//go:build linux

package apps

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCertifiedInstallAcceptsServedPublicRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "current", "public")
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	if err := validateCertifiedInstallDestination(linuxApplicationScope{root: root}); err != nil {
		t.Fatalf("provisioned public directory rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "configuration.php"), []byte("existing application"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateCertifiedInstallDestination(linuxApplicationScope{root: root}); !errors.Is(err, ErrConflict) {
		t.Fatalf("existing application could be overwritten: %v", err)
	}
}

func TestCertifiedInstallRejectsUnrelatedDestination(t *testing.T) {
	for _, relative := range []string{"other/public", "current/private", "current/public/nested"} {
		root := filepath.Join(t.TempDir(), relative)
		if err := os.MkdirAll(root, 0750); err != nil {
			t.Fatal(err)
		}
		if err := validateCertifiedInstallDestination(linuxApplicationScope{root: root}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unrelated root %s admitted: %v", relative, err)
		}
	}
}
