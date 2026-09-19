//go:build linux

package noderelease

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSharedStateParentKeepsPrivateChildren(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned installer fixture; run in QEMU as root")
	}
	root := filepath.Join(t.TempDir(), "cyberpanel")
	child := filepath.Join(root, "node-release")
	if err := os.MkdirAll(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ensureNodeStateParent(root); err != nil {
		t.Fatal(err)
	}
	parentInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	childInfo, err := os.Stat(child)
	if err != nil {
		t.Fatal(err)
	}
	if parentInfo.Mode().Perm() != 0755 || childInfo.Mode().Perm() != 0700 {
		t.Fatal("incorrect shared/private modes")
	}
	if err := ensureNodeStateParent(root); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if err := ensureNodeStateParent(root); err == nil {
		t.Fatal("accepted writable state parent")
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	link := root + "-link"
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureNodeStateParent(link); err == nil {
		t.Fatal("accepted symlink state parent")
	}
}
