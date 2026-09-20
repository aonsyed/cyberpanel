//go:build linux

package mail

import (
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
)

func TestQEMUMailNativeConfigAccess(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_ACCESS") != "1" {
		t.Skip("explicit QEMU native mail access")
	}
	entries, err := os.ReadDir(filepath.Join(MailConfigurationRoot, "generations"))
	if err != nil || len(entries) == 0 {
		t.Fatal("retained generation required", err)
	}
	root := filepath.Join(MailConfigurationRoot, "generations", entries[0].Name())
	store, err := daemoncfg.OpenStore(MailConfigurationRoot, MailConfigurationRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var ownership MailOwnership
	for name, target := range map[string]*uint32{"postfix": &ownership.PostfixGID, "dovecot": &ownership.DovecotGID, "_rspamd": &ownership.RspamdGID, "opendkim": &ownership.OpenDKIMGID, "redis": &ownership.RedisGID, "clamav": &ownership.ClamAVGID} {
		group, err := user.LookupGroup(name)
		if err != nil {
			t.Fatal(err)
		}
		gid, err := strconv.ParseUint(group.Gid, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		*target = uint32(gid)
	}
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Manifest daemoncfg.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	host := &LinuxMailHost{Store: store, Ownership: ownership}
	for i := 0; i < 2; i++ {
		if err := host.prepareNativeConfigAccess(entries[0].Name(), envelope.Manifest.Digest); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Verify(entries[0].Name(), envelope.Manifest.Digest); err != nil {
		t.Fatal("generation integrity after access grant", err)
	}
	for _, item := range []struct{ user, path string }{{"postfix", "postfix/main.cf"}, {"dovecot", "dovecot/oauth2.conf"}, {"_rspamd", "rspamd/redis.conf"}, {"opendkim", "opendkim/KeyTable"}, {"redis", "redis/redis.conf"}, {"clamav", "clamav/clamd.conf"}} {
		if err := exec.Command("/usr/sbin/runuser", "-u", item.user, "--", "/usr/bin/test", "-r", filepath.Join(root, item.path)).Run(); err != nil {
			t.Fatalf("%s cannot read own %s: %v", item.user, item.path, err)
		}
		if err := exec.Command("/usr/sbin/runuser", "-u", item.user, "--", "/usr/bin/test", "-r", MailConfigurationRoot).Run(); err == nil {
			t.Fatal("native service can list authority root", item.user)
		}
		other := "postfix/main.cf"
		if item.user == "postfix" {
			other = "opendkim/KeyTable"
		}
		if err := exec.Command("/usr/sbin/runuser", "-u", item.user, "--", "/usr/bin/test", "-r", filepath.Join(root, other)).Run(); err == nil {
			t.Fatal("native service can read another role", item.user, other)
		}
		for _, path := range []string{MailConfigurationRoot, filepath.Join(root, filepath.Dir(item.path)), filepath.Join(root, item.path)} {
			if err := exec.Command("/usr/sbin/runuser", "-u", item.user, "--", "/usr/bin/test", "-w", path).Run(); err == nil {
				t.Fatal("native service can mutate authority", item.user, path)
			}
		}
	}
	for _, path := range []string{filepath.Join(root, "opendkim/KeyTable"), "/var/lib/cyberpanel/control/control.db", "/var/lib/cyberpanel/mail/tls/default/private.key"} {
		if err := exec.Command("/usr/sbin/runuser", "-u", "_rspamd", "--", "/usr/bin/test", "-r", path).Run(); err == nil {
			t.Fatal("Rspamd can read unrelated private state", path)
		}
	}
	if err := exec.Command("/usr/sbin/runuser", "-u", "postfix", "--", "/usr/bin/test", "-r", "/var/lib/cyberpanel/mail/tls/default/private.key").Run(); err != nil {
		t.Fatal("Postfix cannot read its fallback TLS key", err)
	}
}

func TestMailNativeACLRejectsUnsafeState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("QEMU root fixtures with TMPDIR=/root")
	}
	for _, variant := range []string{"writeable directory", "different ACL", "symlink", "hardlinked file", "writeable ancestor"} {
		t.Run(variant, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "authority")
			directory := variant != "hardlinked file"
			mode := uint32(0750)
			permission := uint32(1)
			if directory {
				if err := os.Mkdir(path, 0750); err != nil {
					t.Fatal(err)
				}
			} else {
				mode = 0440
				permission = 4
				if err := os.WriteFile(path, []byte("fixture"), 0440); err != nil {
					t.Fatal(err)
				}
			}
			switch variant {
			case "writeable directory":
				if err := os.Chmod(path, 0770); err != nil {
					t.Fatal(err)
				}
			case "different ACL":
				if err := grantMailReadAccess(path, mode, []uint32{1234}, permission, true); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := filepath.Join(parent, "link")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "hardlinked file":
				if err := os.Link(path, filepath.Join(parent, "second")); err != nil {
					t.Fatal(err)
				}
			case "writeable ancestor":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if err := grantMailReadAccess(path, mode, []uint32{1235}, permission, directory); err == nil {
				t.Fatal("accepted unsafe ACL target")
			}
		})
	}
}
