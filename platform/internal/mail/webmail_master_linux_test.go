//go:build linux

package mail

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWebmailMasterPassdbArtifact(t *testing.T) {
	secret := bytes.Repeat([]byte("x"), 64)
	item := webmailMasterPassdbArtifact(secret, 123)
	want := sha256.Sum256(secret)
	if item.Path != "dovecot/webmail-master" || item.Mode != 0440 || item.GID != 123 {
		t.Fatal("master verifier must use the root-owned Dovecot-only generation boundary")
	}
	if string(item.Content) != webmailMasterUser+":{SHA256}"+base64.StdEncoding.EncodeToString(want[:])+"\n" || bytes.Contains(item.Content, secret) {
		t.Fatal("native passwd-file must contain only the master verifier")
	}
	config := renderDovecot(ConfigSnapshot{})
	if !bytes.Contains(config, []byte("args = /var/lib/cyberpanel/mail/current/dovecot/webmail-master\n")) || bytes.Contains(config, []byte("/etc/cyberpanel/secrets")) {
		t.Fatal("Dovecot must not traverse the root secret tree")
	}
}

func TestQEMUWebmailMasterAuthentication(t *testing.T) {
	fixture := os.Getenv("CYBERPANEL_QEMU_WEBMAIL_ACCOUNT")
	if fixture == "" {
		t.Skip("requires guest-only disposable mailbox credentials and root")
	}
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeMailBytes(raw)
	var account struct{ Address, Password string }
	if json.Unmarshal(raw, &account) != nil || ValidateAddress(Address(account.Address)) != nil {
		t.Fatal("invalid guest fixture")
	}
	master, err := loadWebmailMaster()
	if err != nil {
		t.Fatal(err)
	}
	defer wipeMailBytes(master)
	group, err := user.LookupGroup("dovecot")
	if err != nil {
		t.Fatal(err)
	}
	gid, _ := strconv.Atoi(group.Gid)
	root, err := os.MkdirTemp("/run", "cyberpanel-webmail-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	artifact := webmailMasterPassdbArtifact(master, uint32(gid))
	verifierPath := filepath.Join(root, "webmail-master")
	if err := os.WriteFile(verifierPath, artifact.Content, os.FileMode(artifact.Mode)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(verifierPath, 0, gid); err != nil {
		t.Fatal(err)
	}
	config := string(renderDovecot(ConfigSnapshot{Postmaster: "postmaster@qemu.invalid"}))
	config = strings.NewReplacer("protocols = imap lmtp sieve", "protocols = imap", "listen = *, ::", "listen = 127.0.0.1", "/var/lib/cyberpanel/mail/current/dovecot/webmail-master", verifierPath, "/run/cyberpanel/mail/dovecot-users", "/var/lib/cyberpanel/mail/current/dovecot/users", "/var/spool/postfix/private/", root+"/", "/run/dovecot/cyberpanel-managesieve", root+"/managesieve").Replace(config)
	config += "\nbase_dir = " + root + "/run\nservice imap-login {\n inet_listener imap {\n port = 0\n }\n inet_listener imaps {\n port = 19993\n }\n}\n"
	configPath := filepath.Join(root, "dovecot.conf")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	process := exec.Command("/usr/sbin/dovecot", "-F", "-c", configPath)
	var log bytes.Buffer
	process.Stderr = &log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	for attempt := 0; attempt < 50; attempt++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:19993", 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if attempt == 49 {
			t.Fatal("isolated Dovecot did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, check := range []struct {
		name, login, password string
		allowed               bool
	}{
		{"master", account.Address + "*" + webmailMasterUser, string(master), true},
		{"wrong master", account.Address + "*" + webmailMasterUser, "intentionally-wrong", false},
		{"ordinary", account.Address, account.Password, true},
		{"wrong ordinary", account.Address, "intentionally-wrong", false},
	} {
		t.Run(check.name, func(t *testing.T) {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", "127.0.0.1:19993", &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // QEMU bootstrap certificate only.
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			client := &localIMAPClient{connection: conn, reader: bufio.NewReader(conn), writer: bufio.NewWriter(conn)}
			if _, err := client.reader.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			_, err = client.command("LOGIN " + imapQuote(check.login) + " " + imapQuote(check.password))
			if (err == nil) != check.allowed {
				t.Fatalf("authentication allowed=%v expected=%v", err == nil, check.allowed)
			}
			if check.allowed {
				if _, err := client.command("SELECT INBOX"); err != nil {
					t.Fatal("authenticated INBOX selection failed")
				}
			}
		})
	}
}
