//go:build linux

package management

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogFileTrustBoundary(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "catalog.json")
	if err := os.WriteFile(path, []byte("catalog"), 0644); err != nil {
		t.Fatal(err)
	}
	if got, err := readCatalogFile(path, 7, os.Geteuid() == 0); err != nil || string(got) != "catalog" {
		t.Fatalf("regular catalog: %q %v", got, err)
	}
	if _, err := readCatalogFile(path, 6, true); err == nil {
		t.Fatal("oversized catalog accepted")
	}
	link := filepath.Join(root, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readCatalogFile(link, 7, true); err == nil {
		t.Fatal("arbitrary link accepted")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readCatalogFile(path, 7, true); err == nil {
		t.Fatal("writable catalog accepted")
	}
}
