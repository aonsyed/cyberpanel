//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// Exercise the real upgrade hook body inside a child-only disposable chroot,
// not the installed host's authority directories or claim token.
func TestBackupRepositoryAuthorityUpgrade(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for isolated native ownership regression")
	}
	if root := os.Getenv("CYBERPANEL_BACKUP_UPGRADE_TEST_ROOT"); root != "" {
		uid, gid, err := lookupIdentity("cyberpanel")
		if err != nil {
			t.Fatal(err)
		}
		if err = syscall.Chroot(root); err != nil {
			t.Fatal(err)
		}
		if err = os.Chdir("/"); err != nil {
			t.Fatal(err)
		}
		for attempt := 0; attempt < 2; attempt++ {
			if err = os.Chown("/var/backups/cyberpanel/repositories", 0, gid); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod("/var/backups/cyberpanel/repositories", 0750); err != nil {
				t.Fatal(err)
			}
			if _, err = migrateAuthority(); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat("/var/backups/cyberpanel/repositories")
			if err != nil {
				t.Fatal(err)
			}
			stat := info.Sys().(*syscall.Stat_t)
			if stat.Uid != uint32(uid) || stat.Gid != uint32(gid) || info.Mode().Perm() != 0700 {
				t.Fatalf("upgrade left wrong owner/mode: %d:%d %o", stat.Uid, stat.Gid, info.Mode().Perm())
			}
		}
		if data, err := os.ReadFile("/var/lib/cyberpanel/control/recovery/claim.token"); err != nil || string(data) != "preserve-claim" {
			t.Fatalf("upgrade changed claim token: %v", err)
		}
		return
	}
	uid, gid, err := lookupIdentity("cyberpanel")
	if err != nil {
		t.Skip("requires installed service identity")
	}
	root := t.TempDir()
	for _, dir := range []string{"etc", "var/backups/cyberpanel/repositories", "var/lib/cyberpanel/control/recovery"} {
		if err = os.MkdirAll(filepath.Join(root, dir), 0750); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"etc/passwd": fmt.Sprintf("cyberpanel:x:%d:%d::/nonexistent:/usr/sbin/nologin\n", uid, gid), "etc/group": fmt.Sprintf("cyberpanel:x:%d:\n", gid), "var/lib/cyberpanel/control/control.db": "", "var/lib/cyberpanel/control/recovery/claim.token": "preserve-claim"}
	for path, content := range files {
		if err = os.WriteFile(filepath.Join(root, path), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Chown(filepath.Join(root, "var/lib/cyberpanel/control/control.db"), uid, gid); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestBackupRepositoryAuthorityUpgrade$", "-test.v")
	command.Env = append(os.Environ(), "CYBERPANEL_BACKUP_UPGRADE_TEST_ROOT="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("upgrade regression: %v\n%s", err, output)
	}
}
