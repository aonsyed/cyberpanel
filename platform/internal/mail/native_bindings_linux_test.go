//go:build linux

package mail

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestQEMUNativeMailBindings(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_BINDINGS") != "1" {
		t.Skip("explicit native mail binding reconciliation in QEMU")
	}
	if err := ReconcileNativeMailBindings(context.Background(), MailUbuntuNoble); err != nil {
		t.Fatal("installer binding reconciliation", err)
	}
	profile, err := profileForMail(MailUbuntuNoble)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range profile.bindings {
		if err := ensureMailBinding(binding); err != nil {
			t.Fatalf("binding %s: %v", binding.link, err)
		}
	}
}

func TestQEMUMailRedisNativeUnit(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_REDIS") != "1" {
		t.Skip("explicit native mail Redis QEMU qualification")
	}
	const unit = "redis-server@cyberpanel-mail.service"
	if out, err := exec.Command("/usr/bin/systemctl", "is-active", unit).Output(); err == nil || strings.TrimSpace(string(out)) != "inactive" {
		t.Fatal("mail Redis must be inactive")
	}
	config := filepath.Join(t.TempDir(), "redis.conf")
	if err := os.WriteFile(config, renderMailRedis(), 0600); err != nil {
		t.Fatal(err)
	}
	const directory = "/run/systemd/system/redis-server@cyberpanel-mail.service.d"
	if err := os.Mkdir(directory, 0755); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	const override = directory + "/90-qemu-credential.conf"
	f, err := os.OpenFile(override, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("[Service]\nLoadCredential=\nLoadCredential=redis.conf:" + config + "\n")
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	defer func() {
		if out, err := exec.Command("/usr/bin/systemctl", "stop", unit).CombinedOutput(); err != nil {
			t.Errorf("stop Redis: %v %s", err, out)
		}
		if err := os.Remove(override); err != nil {
			t.Error(err)
		}
		if out, err := exec.Command("/usr/bin/systemctl", "daemon-reload").CombinedOutput(); err != nil {
			t.Errorf("reload: %v %s", err, out)
		}
	}()
	for _, args := range [][]string{{"daemon-reload"}, {"start", unit}} {
		if out, err := exec.Command("/usr/bin/systemctl", args...).CombinedOutput(); err != nil {
			t.Fatalf("native Redis unit: %v %s", err, out)
		}
	}
	for _, user := range []string{"redis", "_rspamd"} {
		out, err := exec.Command("/usr/sbin/runuser", "-u", user, "--", "/usr/bin/redis-cli", "-s", "/run/cyberpanel-mail-redis/redis.sock", "PING").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "PONG" {
			t.Fatalf("mail Redis PING as %s: %v %s", user, err, out)
		}
	}
	if err := exec.Command("/usr/sbin/runuser", "-u", "_rspamd", "--", "/usr/bin/test", "-r", config).Run(); err == nil {
		t.Fatal("Rspamd can read private config")
	}
	if err := exec.Command("/usr/sbin/runuser", "-u", "redis", "--", "/usr/bin/test", "-w", "/etc/cyberpanel/mail").Run(); err == nil {
		t.Fatal("Redis can write managed config directory")
	}
}
