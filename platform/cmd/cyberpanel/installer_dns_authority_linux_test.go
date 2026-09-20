//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestQEMUPowerDNSCredentialUnit(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_PDNS_ACCESS") != "1" {
		t.Skip("explicit QEMU credential unit installation")
	}
	for i := 0; i < 2; i++ {
		if err := installPowerDNSCredentialUnit(); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile("/etc/systemd/system/pdns.service.d/50-cyberpanel-credentials.conf")
	if err != nil || string(content) != powerDNSCredentialUnit {
		t.Fatal("credential unit mismatch", err)
	}
	if out, err := exec.Command("/usr/bin/systemd-analyze", "verify", "pdns.service").CombinedOutput(); err != nil {
		t.Fatalf("unit verification: %v: %s", err, out)
	}
}

func TestPristineDNSConfigAdoption(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("QEMU root fixture, TMPDIR=/root")
	}
	for _, variant := range []string{"valid", "modified", "unsafe mode", "wrong backup", "foreign staging link"} {
		t.Run(variant, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pdns.conf")
			content := []byte("# package default\n")
			if err := os.WriteFile(path, content, 0640); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(content)
			digest := hex.EncodeToString(sum[:])
			backup := path + ".cyberpanel-vendor-" + digest
			if variant == "modified" {
				digest = "unknown"
			}
			if variant == "unsafe mode" {
				if err := os.Chmod(path, 0660); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "wrong backup" {
				if err := os.WriteFile(backup, []byte("wrong"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "foreign staging link" {
				if err := os.Symlink("/wrong", path+".cyberpanel-adopt"); err != nil {
					t.Fatal(err)
				}
			}
			err := adoptPristineDNSConfig(path, managedPowerDNSConfig, digest)
			if variant != "valid" {
				if err == nil {
					t.Fatal("accepted unsafe adoption")
				}
				got, readErr := os.ReadFile(path)
				if readErr != nil || !bytes.Equal(got, content) {
					t.Fatal("changed original on failure", readErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			link, err := os.Readlink(path)
			if err != nil || link != managedPowerDNSConfig {
				t.Fatal(link, err)
			}
			got, err := os.ReadFile(backup)
			if err != nil || !bytes.Equal(got, content) {
				t.Fatal("backup mismatch", err)
			}
			info, err := os.Stat(backup)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("backup permissions", err)
			}
		})
	}
}

func TestQEMUPowerDNSPackageAdoption(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_DNS_ADOPTION") != "1" {
		t.Skip("explicit actual native QEMU config adoption")
	}
	const path = "/etc/powerdns/pdns.conf"
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(before)
	for i := 0; i < 2; i++ {
		if err := reconcileDNSAuthority(); err != nil {
			t.Fatal(err)
		}
	}
	link, err := os.Readlink(path)
	if err != nil || link != managedPowerDNSConfig {
		t.Fatal(link, err)
	}
	backup, err := os.ReadFile(path + ".cyberpanel-vendor-" + hex.EncodeToString(sum[:]))
	if err != nil || !bytes.Equal(backup, before) {
		t.Fatal("native backup mismatch", err)
	}
}
