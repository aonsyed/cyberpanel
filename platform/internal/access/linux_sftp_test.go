//go:build linux

package access

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestSFTPJailDirectoryIgnoresExecutorUmask(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned native directory fixture")
	}
	previous := syscall.Umask(0027)
	defer syscall.Umask(previous)
	path := filepath.Join(t.TempDir(), "jail")
	if err := sftpDirectory(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("managed jail root blocks SFTP principal traversal: %04o", info.Mode().Perm())
	}
	if err = os.Chmod(path, 0750); err != nil {
		t.Fatal(err)
	}
	if err = sftpDirectory(path); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("existing umask-affected jail not repaired: %v", err)
	}
}

func TestSFTPReloadSupportedUnitSelection(t *testing.T) {
	for _, test := range []struct {
		name              string
		primary, fallback error
		want              []string
		failed            bool
	}{
		{name: "sshd", want: []string{"sshd.service"}},
		{name: "ssh fallback", primary: errors.New("sshd unavailable"), want: []string{"sshd.service", "ssh.service"}},
		{name: "both fail", primary: errors.New("sshd unavailable"), fallback: errors.New("ssh unavailable"), want: []string{"sshd.service", "ssh.service"}, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var called []string
			err := reloadSFTPUnit(func(unit string) error {
				called = append(called, unit)
				if unit == "sshd.service" {
					return test.primary
				}
				return test.fallback
			})
			if !reflect.DeepEqual(called, test.want) || (err != nil) != test.failed {
				t.Fatalf("calls=%v error=%v", called, err)
			}
		})
	}
}
