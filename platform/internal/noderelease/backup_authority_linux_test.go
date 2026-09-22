//go:build linux

package noderelease

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestNodeReleaseCoreBackupAuthority(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU sandbox required")
	}
	account, err := user.Lookup("cyberpanel")
	if err != nil {
		t.Skip("installed service identity required")
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if root := os.Getenv("CYBERPANEL_NODE_BACKUP_TEST_ROOT"); root != "" {
		if err = syscall.Chroot(root); err != nil {
			t.Fatal(err)
		}
		if err = os.Chdir("/"); err != nil {
			t.Fatal(err)
		}
		const path = "/var/backups/cyberpanel/repositories"
		if err = prepareServiceAuthority("panel-authd.service"); err != nil {
			t.Fatal(err)
		}
		for attempt := 0; attempt < 2; attempt++ {
			if err = prepareServiceAuthority("panel-core.service"); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			stat := info.Sys().(*syscall.Stat_t)
			if stat.Uid != uint32(uid) || stat.Gid != uint32(gid) || info.Mode().Perm() != 0700 {
				t.Fatalf("actual core boundary left %d:%d %o", stat.Uid, stat.Gid, info.Mode().Perm())
			}
		}
		if err = os.Chown(path, 65533, 65533); err != nil {
			t.Fatal(err)
		}
		if prepareServiceAuthority("panel-core.service") == nil {
			t.Fatal("foreign owner accepted")
		}
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink("/outside", path); err != nil {
			t.Fatal(err)
		}
		if prepareServiceAuthority("panel-core.service") == nil {
			t.Fatal("symlink accepted")
		}
		info, err := os.Stat("/outside")
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatal("symlink target changed")
		}
		return
	}
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing-%t", existing), func(t *testing.T) {
			root := t.TempDir()
			for _, path := range []string{"etc", "var", "outside"} {
				if err := os.MkdirAll(filepath.Join(root, path), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if existing {
				if err := os.MkdirAll(filepath.Join(root, "var/backups/cyberpanel/repositories"), 0750); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(fmt.Sprintf("cyberpanel:x:%d:%d::/nonexistent:/usr/sbin/nologin\n", uid, gid)), 0600); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestNodeReleaseCoreBackupAuthority$", "-test.v")
			command.Env = append(os.Environ(), "CYBERPANEL_NODE_BACKUP_TEST_ROOT="+root)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("node-release authority boundary: %v\n%s", err, output)
			}
		})
	}
}
