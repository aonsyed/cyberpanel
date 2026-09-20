//go:build linux

package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQEMUMailPackageDefaults(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_ADOPTION") != "1" {
		t.Skip("explicit QEMU native mail defaults")
	}
	for _, path := range []string{"/etc/postfix/main.cf", "/etc/postfix/master.cf", "/etc/dovecot/dovecot.conf", "/etc/opendkim.conf", "/etc/clamav/clamd.conf"} {
		data, err := readRootMailDefault(path)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := pristineUbuntuMailDigest(path, data)
		sum := md5.Sum(data)
		if err != nil || digest != hex.EncodeToString(sum[:]) {
			t.Fatalf("default verification %s: %v", path, err)
		}
		if path == "/etc/postfix/main.cf" {
			hostname, err := os.Hostname()
			if err != nil {
				t.Fatal(err)
			}
			for _, modified := range []string{string(data) + "\nrelayhost=\n", string(data) + "\nunknown=value\n", strings.Replace(string(data), "relayhost = ", "relayhost = custom.example", 1)} {
				if defaultUbuntuPostfixMain(modified, hostname) {
					t.Fatal("accepted edited Postfix default")
				}
			}
		}
	}
}

func TestQEMUMailPackageAdoption(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_APPLY") != "1" {
		t.Skip("explicit QEMU native mail adoption")
	}
	for i := 0; i < 2; i++ {
		if err := reconcileMailAuthority(); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/etc/postfix/main.cf", "/etc/postfix/master.cf", "/etc/dovecot/dovecot.conf", "/etc/opendkim.conf", "/etc/clamav/clamd.conf"} {
		link, err := os.Readlink(path)
		if err != nil || !strings.HasPrefix(link, "/var/lib/cyberpanel/mail/current/") {
			t.Fatal("missing managed mail link", path, err)
		}
		backups, err := filepath.Glob(path + ".cyberpanel-vendor-*")
		if err != nil || len(backups) != 1 {
			t.Fatal("missing unique original mail backup", path, err)
		}
		data, err := readRootMailDefault(backups[0])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if backups[0] != path+".cyberpanel-vendor-"+hex.EncodeToString(sum[:]) {
			t.Fatal("backup bytes differ", path)
		}
		digest, err := pristineUbuntuMailDigest(path, data)
		md := md5.Sum(data)
		if err != nil || digest != hex.EncodeToString(md[:]) {
			t.Fatal("backup is not verified package default", path, err)
		}
		info, err := os.Stat(backups[0])
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("backup privacy", err)
		}
	}
}
