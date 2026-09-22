//go:build linux

package apps

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"golang.org/x/sys/unix"
)

func TestUpdateShadowPreservesServedRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated QEMU filesystem fixture requires root")
	}
	site, err := os.MkdirTemp(linuxApplicationSitesRoot, "s-qemu-update-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(site) })
	binding := LinuxApplicationSiteBinding{SiteKey: filepath.Base(site), Generation: 1, UID: 1000, GID: 1000}
	releases := filepath.Join(site, "roots", "g1", "releases")
	token := applicationShadowToken("app-test", "release-test")
	shadow := filepath.Join(releases, ".app-"+token)
	for _, path := range []string{filepath.Join(releases, "current", "public"), filepath.Join(shadow, "public"), filepath.Join(shadow, "private")} {
		if err := os.MkdirAll(path, 0750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(shadow, "public", "configuration.php"), []byte("owned configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	runtime := &LinuxApplicationRuntime{}
	for _, relative := range []string{".", "public"} {
		result, err := runtime.shadowScope(linuxApplicationScope{binding: binding, root: filepath.Join(releases, "current", relative)}, token)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(shadow, relative); result.root != want {
			t.Fatalf("served root = %s; want %s", result.root, want)
		}
	}
	if _, err := runtime.shadowScope(linuxApplicationScope{binding: binding, root: filepath.Join(releases, "foreign", "public")}, token); err == nil {
		t.Fatal("unrelated root accepted")
	}
	if err := os.Symlink(filepath.Join(shadow, "public"), filepath.Join(shadow, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.shadowScope(linuxApplicationScope{binding: binding, root: filepath.Join(releases, "current", "linked")}, token); err == nil {
		t.Fatal("symlink candidate accepted")
	}
	current := filepath.Join(releases, "current")
	public := filepath.Join(current, "public")
	for _, path := range []string{current, public, shadow, filepath.Join(shadow, "public")} {
		if err := os.Chown(path, 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := unix.Open(current, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = siteops.GrantRestoredPublicAccess(fd, 1000, 1000)
	unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(shadow, "public.next")
	if err := ensureSiteOwnedDirectory(stage, binding); err != nil {
		t.Fatal(err)
	}
	if err := preserveCertifiedPublicAccess(linuxApplicationScope{binding: binding, root: public}, linuxApplicationScope{binding: binding, root: stage}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "index.php"), []byte("candidate"), 0640); err != nil {
		t.Fatal(err)
	}
	if n, err := unix.Getxattr(filepath.Join(stage, "index.php"), "system.posix_acl_access", nil); err != nil || n != 44 {
		t.Fatalf("candidate did not inherit public ACL: %d %v", n, err)
	}
	if _, err := unix.Getxattr(filepath.Join(shadow, "private"), "system.posix_acl_access", nil); err != unix.ENODATA {
		t.Fatalf("private sibling policy changed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(public, "configuration.php"), []byte("original ownership configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	runtime.Resolver = LinuxApplicationSiteResolverFunc(func(context.Context, SiteID) (LinuxApplicationSiteBinding, error) { return binding, nil })
	ctx := context.Background()
	if err := runtime.ActivateReleaseRoute(ctx, "site-test", "app-test", "release-test", token); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RestoreReleaseRoute(ctx, "site-test", "app-test", "release-old"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RemoveShadowRoute(ctx, "site-test", "app-test", "release-test"); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(filepath.Join(public, "configuration.php")); err != nil || string(value) != "original ownership configuration" {
		t.Fatalf("rollback lost original configuration: %v", err)
	}
	if _, err := os.Lstat(shadow); !os.IsNotExist(err) {
		t.Fatalf("failed candidate retained: %v", err)
	}
}
