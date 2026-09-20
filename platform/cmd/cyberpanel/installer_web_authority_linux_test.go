package main

import (
	"crypto/sha256"
	"os"
	"syscall"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation/fsstore"
)

func TestQEMUWebEngineAuthority(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_WEB_BOOTSTRAP") != "1" {
		t.Skip("root QEMU installed OLS bootstrap")
	}
	const master = "/usr/local/lsws/conf/httpd_config.conf"
	before, err := os.ReadFile(master)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = reconcileWebEngineAuthority(); err != nil {
			t.Fatal(err)
		}
		for path, mode := range map[string]os.FileMode{"/usr/local/lsws/conf": 0700, "/usr/local/lsws/conf/vhosts": 0700, master: 0600} {
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			stat := info.Sys().(*syscall.Stat_t)
			if stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != mode {
				t.Fatalf("unsafe metadata: %s", path)
			}
		}
	}
	after, err := os.ReadFile(master)
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("bootstrap changed configuration content")
	}
	if _, err = fsstore.New("/usr/local/lsws/conf", webengine.EditionOpenLiteSpeed); err != nil {
		t.Fatal(err)
	}
}
