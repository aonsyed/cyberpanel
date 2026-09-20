//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/operations"
)

func TestInitialWAFProvisionPreservesManagedPolicy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU installer check")
	}
	path := filepath.Join(t.TempDir(), "cyberpanel.conf")
	checks := 0
	verify := func() error { checks++; return nil }
	for i := 0; i < 2; i++ {
		if err := provisionInitialWAFFile(path, verify); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, operations.InitialWAFConfiguration()) || checks != 2 {
		t.Fatal("bootstrap not verified/replayed", err)
	}
	managed := []byte("# Later executor-owned policy\nSecRuleEngine On\n")
	if err := os.WriteFile(path, managed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := provisionInitialWAFFile(path, verify); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(content, managed) || checks != 2 {
		t.Fatal("installer replaced managed policy", err)
	}
}

func TestInitialWAFProvisionFailsClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU installer check")
	}
	path := filepath.Join(t.TempDir(), "cyberpanel.conf")
	if err := provisionInitialWAFFile(path, func() error { return errors.New("bad assets") }); err == nil {
		t.Fatal("unverified assets accepted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("policy written before verification")
	}
	target := filepath.Join(filepath.Dir(path), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := provisionInitialWAFFile(path, func() error { return nil }); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, path); err != nil {
		t.Fatal(err)
	}
	if err := provisionInitialWAFFile(path, func() error { return nil }); err == nil {
		t.Fatal("hardlink accepted")
	}
}
