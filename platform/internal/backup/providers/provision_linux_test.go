//go:build linux

package providers

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLocalRepositoryProvisioning(t *testing.T) {
	root := t.TempDir()
	parent, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(parent)
	for n := 0; n < 2; n++ {
		if err := provisionLocalRepositoryAt(parent, "valid"); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".staging", "blobs", "points"} {
		info, err := os.Stat(filepath.Join(root, "valid", name))
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("repository data directory: %v %v", info, err)
		}
	}
	if provisionLocalRepositoryAt(parent, "../escape") == nil {
		t.Fatal("traversal accepted")
	}
	if err := os.Symlink(filepath.Join(root, "valid"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if provisionLocalRepositoryAt(parent, "link") == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(filepath.Join(root, "valid"), 0777); err != nil {
		t.Fatal(err)
	}
	if provisionLocalRepositoryAt(parent, "valid") == nil {
		t.Fatal("unsafe mode accepted")
	}
	if err := os.Chmod(filepath.Join(root, "valid"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "valid", "blobs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(root, "valid", "blobs")); err != nil {
		t.Fatal(err)
	}
	if provisionLocalRepositoryAt(parent, "valid") == nil {
		t.Fatal("symlink data directory accepted")
	}
}
