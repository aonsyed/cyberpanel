//go:build linux

package mail

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestQEMUMailboxArgonPassword(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_MAPS") != "1" {
		t.Skip("requires native QEMU Dovecot")
	}
	// Synthetic public fixture only; never use real account secrets in argv.
	const password = "qemu-public-password-fixture"
	salt := []byte("0123456789abcdef")
	hashed, err := HashMailboxPassword([]byte(password), salt)
	if err != nil || ValidateMailboxPasswordHash(hashed) != nil {
		t.Fatal("password hash", err)
	}
	replay, err := HashMailboxPassword([]byte(password), salt)
	if err != nil || !bytes.Equal(hashed, replay) {
		t.Fatal("enrollment retry changed hash")
	}
	for _, candidate := range []string{password, "qemu-wrong-password-fixture"} {
		command := exec.Command("/usr/bin/doveadm", "pw", "-t", string(hashed), "-p", candidate)
		if err := command.Run(); (err == nil) != (candidate == password) {
			t.Fatal("native Dovecot password verification mismatch")
		}
	}
	for _, invalid := range []string{strings.Replace(string(hashed), "m=65536", "m=8", 1), string(hashed) + "$extra", strings.TrimSuffix(string(hashed), string(hashed[len(hashed)-1]))} {
		if ValidateMailboxPasswordHash([]byte(invalid)) == nil {
			t.Fatal("invalid password hash accepted")
		}
	}
	if _, err := HashMailboxPassword([]byte("short"), salt); err == nil {
		t.Fatal("short password accepted")
	}
}
