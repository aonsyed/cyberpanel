//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCoreOrdinaryGroupReadableSecretRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCoreFile(path, 64, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if _, err := readCoreFile(path, 64, true); err == nil {
		t.Fatal("accepted group-readable ordinary secret")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if privateSystemdCredential(f) {
		t.Fatal("accepted ordinary file as systemd credential")
	}
}

func TestActualSystemdCredential(t *testing.T) {
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" {
		t.Skip("requires real QEMU systemd LoadCredential unit")
	}
	f, err := os.Open(filepath.Join(directory, "audit-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !privateSystemdCredential(f) {
		t.Fatal("rejected actual private systemd credential")
	}
	if credentialACL(int(f.Fd()), uint32(os.Geteuid())+1, 4) {
		t.Fatal("accepted credential ACL for another account")
	}
	if credentialACL(int(f.Fd()), uint32(os.Geteuid()), 6) {
		t.Fatal("accepted unexpected credential permissions")
	}
}
