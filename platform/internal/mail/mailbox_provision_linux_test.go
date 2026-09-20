//go:build linux

package mail

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
)

func TestQEMUOrdinaryMailboxDirectory(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_MAPS") != "1" {
		t.Skip("requires root inside QEMU")
	}
	if os.Geteuid() != 0 {
		t.Fatal("QEMU root required")
	}
	rootPath := t.TempDir()
	root, err := syscall.Open(rootPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(root)
	runtime := sha256.Sum256([]byte("cyberpanel:runtime-identity:v1\x00tenant\x00site"))
	site := sha256.Sum256([]byte("tenant-site"))
	key := hex.EncodeToString(site[:])[:24]
	binding := siteops.RuntimeBinding{RuntimeKey: provisioning.RuntimeKey("site-" + hex.EncodeToString(runtime[:])[:32]), TenantID: "tenant", SiteID: "site", SiteKey: "s-" + key, Username: "cp_" + key, UID: 250001, GID: 250001, Fence: 1, State: siteops.BindingActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := binding.Validate(); err != nil {
		t.Fatal(err)
	}
	const domain = "qemu-mailbox.example.invalid"
	if err := ensureOrdinaryMaildir(root, domain, "owner", binding); err != nil {
		t.Fatal("provision", err)
	}
	for _, name := range []string{"owner", "owner/Maildir", "owner/Maildir/cur", "owner/Maildir/new", "owner/Maildir/tmp"} {
		info, err := os.Stat(filepath.Join(rootPath, "mailboxes", domain, name))
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != binding.UID || stat.Gid != binding.GID || info.Mode().Perm() != 0700 {
			t.Fatal("mailbox ownership/mode", name)
		}
	}
	sentinel := filepath.Join(rootPath, "mailboxes", domain, "owner/Maildir/new/retained")
	if err := os.WriteFile(sentinel, []byte("existing message"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureOrdinaryMaildir(root, domain, "owner", binding); err != nil {
		t.Fatal("replay", err)
	}
	if value, err := os.ReadFile(sentinel); err != nil || string(value) != "existing message" {
		t.Fatal("replay changed existing mail")
	}
	other := binding
	other.UID++
	other.GID++
	if err := ensureOrdinaryMaildir(root, domain, "owner", other); err == nil {
		t.Fatal("different site owner adopted existing mail")
	}
	suspended := binding
	suspended.State = siteops.BindingSuspended
	if err := ensureOrdinaryMaildir(root, domain, "blocked", suspended); err == nil {
		t.Fatal("suspended site provisioned")
	}
	for _, local := range []string{"../escape", "bad/name", "bad\nname"} {
		if err := ensureOrdinaryMaildir(root, domain, local, binding); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
	outside := t.TempDir()
	link := filepath.Join(rootPath, "mailboxes", domain, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureOrdinaryMaildir(root, domain, "linked", binding); err == nil {
		t.Fatal("symlink followed")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatal("escaped mailbox root")
	}
}
