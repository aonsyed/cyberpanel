//go:build linux

package siteops

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPublicDirectoryACLAllowsWebButNotOtherTenants(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root QEMU guest")
	}
	webUID, err := webWorkerUID()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/var/tmp", "panel-public-acl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	fd, err := openDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	_, _, lease := identityRetryFixture(t)
	identity, err := identityFromBinding(lease.Binding)
	if err != nil {
		t.Fatal(err)
	}
	host := &LinuxHost{sitesFD: fd}
	layout := layoutFor(lease.Binding, 1)
	if err = host.EnsureDirectories(context.Background(), identity, layout); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, identity.SiteKey, "roots", "g1")
	public := filepath.Join(base, "releases", "current", "public", "index.php")
	private := filepath.Join(base, "private", "secret")
	for _, path := range []string{public, private} {
		if err = os.WriteFile(path, []byte("fixture"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	check := func(uid uint32, path string, want bool) {
		t.Helper()
		cmd := exec.Command("/usr/bin/test", "-r", path)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		if got := cmd.Run() == nil; got != want {
			t.Fatalf("uid=%d read=%t want=%t path=%s", uid, got, want, path)
		}
	}
	check(webUID, public, true)
	check(webUID, private, false)
	check(DefaultUIDMaximum, public, false)
	check(DefaultUIDMaximum, private, false)
	if err = host.EnsureDirectories(context.Background(), identity, layout); err != nil {
		t.Fatal(err)
	}
	check(webUID, public, true)
}
