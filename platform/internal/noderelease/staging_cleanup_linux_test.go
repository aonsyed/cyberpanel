//go:build linux

package noderelease

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompletedStagingCleanupIsScopedAndReplaySafe(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("QEMU root-owned installer fixture")
	}
	for _, variant := range []string{"valid", "wrong-digest", "target-symlink", "root-symlink", "writable-root", "invalid-id"} {
		t.Run(variant, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "staging")
			digest := strings.Repeat("a", 64)
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, digest)
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			retained := filepath.Join(base, "retained-package")
			if err := os.WriteFile(retained, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			manifestDigest := digest
			if variant == "wrong-digest" {
				manifestDigest = strings.Repeat("b", 64)
			}
			raw, _ := json.Marshal(SignedManifest{Manifest: Manifest{ManifestDigest: manifestDigest}})
			if err := os.WriteFile(filepath.Join(target, BundleManifestPath), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(retained, filepath.Join(target, "external-link")); err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "target-symlink":
				if err := os.Rename(target, target+"-keep"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target+"-keep", target); err != nil {
					t.Fatal(err)
				}
			case "root-symlink":
				if err := os.Rename(root, root+"-keep"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(root+"-keep", root); err != nil {
					t.Fatal(err)
				}
			case "writable-root":
				if err := os.Chmod(root, 0777); err != nil {
					t.Fatal(err)
				}
			case "invalid-id":
				digest = ".."
			}
			err := cleanupCompletedStaging(root, digest)
			if variant == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = os.Lstat(target); !os.IsNotExist(err) {
					t.Fatal("duplicate staging retained")
				}
				if err = cleanupCompletedStaging(root, digest); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe cleanup accepted")
			}
			if raw, err := os.ReadFile(retained); err != nil || string(raw) != "keep" {
				t.Fatal("retained package changed")
			}
		})
	}
}
