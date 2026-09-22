//go:build linux

package mail

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDovecotVacationUsesExistingLoopbackSubmission(t *testing.T) {
	content := renderDovecot(ConfigSnapshot{Postmaster: "postmaster@qemu.invalid"})
	if !bytes.Contains(content, []byte("submission_host = 127.0.0.1:25\n")) {
		t.Fatal("vacation would fall back to sendmail under mailbox UID")
	}
	if os.Getenv("CYBERPANEL_QEMU_MAIL_CONFIG") != "1" {
		return
	}
	path := filepath.Join(t.TempDir(), "dovecot.conf")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("/usr/bin/doveconf", "-c", path, "-h", "submission_host").Output()
	if err != nil || strings.TrimSpace(string(output)) != "127.0.0.1:25" {
		t.Fatalf("native submission setting: %q %v", output, err)
	}
}

func TestQEMUDovecotRenderedConfiguration(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_CONFIG") != "1" {
		t.Skip("requires native QEMU Dovecot and test certificate")
	}
	content := renderDovecot(ConfigSnapshot{Postmaster: "postmaster@qemu.invalid"})
	// Exercise the real installer-provisioned mail fallback paths and required TLS.
	path := filepath.Join(t.TempDir(), "dovecot.conf")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/doveconf", "-c", path, "-n")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("native Dovecot parser: %v: %s", err, stderr.String())
	}
}

func TestQEMUDovecotMailboxQuota(t *testing.T) {
	address := os.Getenv("CYBERPANEL_QEMU_MAILBOX")
	if address == "" {
		t.Skip("requires an enrolled disposable mailbox in QEMU")
	}
	if ValidateAddress(Address(address)) != nil {
		t.Fatal("invalid fixture mailbox")
	}
	content := renderDovecot(ConfigSnapshot{Postmaster: "postmaster@qemu.invalid"})
	content = bytes.ReplaceAll(content, []byte("/run/cyberpanel/mail/dovecot-users"), []byte("/var/lib/cyberpanel/mail/current/dovecot/users"))
	path := filepath.Join(t.TempDir(), "dovecot.conf")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("/usr/bin/doveadm", "-c", path, "-o", "mail_plugins=quota", "quota", "get", "-u", address).CombinedOutput()
	if err != nil {
		t.Fatalf("native mailbox quota initialization: %v: %s", err, output)
	}
	if !bytes.Contains(output, []byte("STORAGE")) {
		t.Fatalf("missing native storage quota: %s", output)
	}
}

func TestQEMUMailNativeConfigValidators(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_CONFIG") != "1" {
		t.Skip("requires native QEMU mail validators")
	}
	profile, err := profileForMail(MailUbuntuNoble)
	if err != nil {
		t.Fatal(err)
	}
	host := &LinuxMailHost{profile: profile}
	for _, invalid := range []bool{false, true} {
		directory := t.TempDir()
		redis := renderMailRedis()
		clam := renderClamAV(ConfigSnapshot{})
		if invalid {
			redis = append(redis, []byte("not-a-redis-option yes\n")...)
			clam = append(clam, []byte("NotAClamAVOption yes\n")...)
		}
		redisPath := filepath.Join(directory, "redis.conf")
		if err := os.WriteFile(redisPath, redis, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "clamd.conf"), clam, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = host.validateRedisConfig(context.Background(), redisPath)
		if (err != nil) != invalid {
			t.Fatalf("Redis invalid=%v: %v", invalid, err)
		}
		_, err = validateClamAVConfig(context.Background(), directory)
		if (err != nil) != invalid {
			t.Fatalf("ClamAV invalid=%v: %v", invalid, err)
		}
	}
}

func TestQEMUOpenDKIMRenderedConfiguration(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_CONFIG") != "1" {
		t.Skip("requires native QEMU OpenDKIM")
	}
	directory := t.TempDir()
	content := bytes.ReplaceAll(renderOpenDKIM(), []byte("/var/lib/cyberpanel/mail/current/opendkim"), []byte(directory))
	for name, data := range map[string][]byte{"opendkim.conf": content, "KeyTable": {}, "SigningTable": {}, "TrustedHosts": renderOpenDKIMTrustedHosts()} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0640); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("/usr/sbin/opendkim", "-n", "-x", filepath.Join(directory, "opendkim.conf"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native OpenDKIM parser: %v: %s", err, output)
	}
}

func TestQEMUOpenDKIMNativeUnit(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_OPENDKIM") != "1" {
		t.Skip("requires QEMU native OpenDKIM stopped for isolated startup")
	}
	state, err := exec.Command("/usr/bin/systemctl", "show", "opendkim", "-p", "ActiveState", "--value").Output()
	if err != nil || (string(state) != "inactive\n" && string(state) != "failed\n") {
		t.Fatal("OpenDKIM must be stopped", err)
	}
	directory, err := os.MkdirTemp("/run", "cyberpanel-opendkim-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	content := bytes.ReplaceAll(renderOpenDKIM(), []byte("/var/lib/cyberpanel/mail/current/opendkim"), []byte(directory))
	for name, data := range map[string][]byte{"opendkim.conf": content, "KeyTable": {}, "SigningTable": {}, "TrustedHosts": renderOpenDKIMTrustedHosts()} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	const dropdir = "/run/systemd/system/opendkim.service.d"
	const override = dropdir + "/90-qemu-mail.conf"
	if err := os.MkdirAll(dropdir, 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(override, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = exec.Command("/usr/bin/systemctl", "stop", "opendkim").Run()
		_ = os.Remove(override)
		_ = exec.Command("/usr/bin/systemctl", "daemon-reload").Run()
	}()
	_, err = f.WriteString("[Service]\nExecStart=\nExecStart=/usr/sbin/opendkim -x " + directory + "/opendkim.conf\nTimeoutStartSec=5s\n")
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	if err := exec.Command("/usr/bin/systemctl", "daemon-reload").Run(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "start", "opendkim").CombinedOutput(); err != nil {
		t.Fatalf("native OpenDKIM unit startup: %v %s", err, output)
	}
	if err := exec.Command("/usr/bin/systemctl", "is-active", "--quiet", "opendkim").Run(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat("/run/opendkim/opendkim.sock"); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("native milter socket missing", err)
	}
	if data, err := os.ReadFile("/run/opendkim/opendkim.pid"); err != nil || len(bytes.TrimSpace(data)) == 0 {
		t.Fatal("native PID file missing", err)
	}
}
