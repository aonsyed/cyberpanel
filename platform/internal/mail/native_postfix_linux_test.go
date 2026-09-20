//go:build linux

package mail

import (
	"crypto/tls"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestQEMUPostfixRenderedSMTP(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_SMTP") != "1" {
		t.Skip("explicit QEMU native Postfix stop/start qualification")
	}
	const proxy = "/etc/rspamd/override.d/worker-proxy.inc"
	proxyFile, err := os.OpenFile(proxy, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal("isolated Rspamd override must be absent", err)
	}
	defer func() {
		_ = os.Remove(proxy)
		_ = exec.Command("/usr/bin/systemctl", "restart", "rspamd").Run()
	}()
	_, writeErr := proxyFile.Write(renderRspamdMilter())
	closeErr := proxyFile.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
	if output, err := exec.Command("/usr/bin/systemctl", "restart", "rspamd").CombinedOutput(); err != nil {
		t.Fatalf("native Rspamd: %v %s", err, output)
	}
	for _, service := range []string{"opendkim", "rspamd"} {
		if err := PrepareNativeMilterAccess(service); err != nil {
			t.Fatal(service, err)
		}
		if err := PrepareNativeMilterAccess(service); err != nil {
			t.Fatal("access replay", service, err)
		}
	}
	for _, socket := range []string{"/run/opendkim/opendkim.sock", "/run/rspamd/milter.sock"} {
		if err := exec.Command("/usr/sbin/runuser", "-u", "postfix", "--", "/usr/bin/test", "-w", socket).Run(); err != nil {
			t.Fatal("Postfix socket access", socket, err)
		}
		if err := exec.Command("/usr/sbin/runuser", "-u", "nobody", "--", "/usr/bin/test", "-w", socket).Run(); err == nil {
			t.Fatal("unprivileged milter access", socket)
		}
	}
	if err := exec.Command("/usr/sbin/runuser", "-u", "postfix", "--", "/usr/bin/test", "-r", "/var/lib/cyberpanel/mail/current/opendkim/KeyTable").Run(); err == nil {
		t.Fatal("Postfix acquired signing configuration access")
	}
	directory, err := os.MkdirTemp("/run", "cyberpanel-postfix-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	main, err := os.ReadFile("/var/lib/cyberpanel/mail/current/postfix/main.cf")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"main.cf": main, "master.cf": renderPostfixMaster()} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.Command("/usr/bin/systemctl", "stop", "postfix", "postfix@-").CombinedOutput(); err != nil {
		t.Fatalf("stop native Postfix: %v %s", err, output)
	}
	defer func() {
		_ = exec.Command("/usr/sbin/postfix", "-c", directory, "stop").Run()
		if output, err := exec.Command("/usr/bin/systemctl", "start", "postfix").CombinedOutput(); err != nil {
			t.Errorf("restore installed Postfix: %v %s", err, output)
		}
	}()
	if output, err := exec.Command("/usr/sbin/postfix", "-c", directory, "start").CombinedOutput(); err != nil {
		t.Fatalf("start rendered Postfix: %v %s", err, output)
	}
	assertNativeSMTP(t)
}

func TestQEMUInstalledSMTP(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_INSTALLED_SMTP") != "1" {
		t.Skip("requires installed native mail services")
	}
	for _, service := range []string{"postfix", "dovecot", "rspamd", "opendkim", "clamav-daemon", "redis-server@cyberpanel-mail"} {
		if err := exec.Command("/usr/bin/systemctl", "is-active", "--quiet", service).Run(); err != nil {
			t.Fatal(service, err)
		}
	}
	assertNativeSMTP(t)
}

func assertNativeSMTP(t *testing.T) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	// The installer intentionally supplies an untrusted bootstrap certificate.
	connection, err := tls.DialWithDialer(dialer, "tcp", "127.0.0.1:465", &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal("native SMTP TLS handshake", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := smtp.NewClient(connection, "qemu.invalid")
	if err != nil {
		t.Fatal("native SMTP banner", err)
	}
	defer client.Close()
	if err := client.Hello("qemu.invalid"); err != nil {
		t.Fatal("native SMTP EHLO", err)
	}
	if err := client.Quit(); err != nil {
		t.Fatal("native SMTP QUIT", err)
	}
	for _, address := range []string{"127.0.0.1:25", "127.0.0.1:587"} {
		connection, err := dialer.Dial("tcp", address)
		if err != nil {
			t.Fatal(address, err)
		}
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		client, err := smtp.NewClient(connection, "qemu.invalid")
		if err != nil {
			connection.Close()
			t.Fatal(address, err)
		}
		if err := client.Hello("qemu.invalid"); err != nil {
			client.Close()
			t.Fatal(address, err)
		}
		if offered, _ := client.Extension("AUTH"); offered {
			client.Close()
			t.Fatal("plaintext AUTH advertised", address)
		}
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}); err != nil {
			client.Close()
			t.Fatal("STARTTLS", address, err)
		}
		if offered, _ := client.Extension("AUTH"); !offered {
			client.Close()
			t.Fatal("TLS AUTH unavailable", address)
		}
		if err := client.Quit(); err != nil {
			client.Close()
			t.Fatal(address, err)
		}
	}
}
