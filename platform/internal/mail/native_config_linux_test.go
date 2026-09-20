//go:build linux

package mail

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

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
