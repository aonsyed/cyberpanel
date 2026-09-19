//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialFileOwnershipBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, make([]byte, 32), 0400); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Geteuid())
	if _, err := readProtectedFileOwnedBy(path, 32, 0400, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedFileOwnedBy(path, 32, 0400, owner+1); err == nil {
		t.Fatal("accepted another account's credential")
	}
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedFileOwnedBy(path, 32, 0400, owner); err == nil {
		t.Fatal("accepted group-readable credential")
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedFileOwnedBy(link, 32, 0400, owner); err == nil {
		t.Fatal("accepted credential symlink")
	}
}
