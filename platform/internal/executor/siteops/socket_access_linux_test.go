//go:build linux

package siteops

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWebSocketACLRejectsOtherTenantAndSymlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root QEMU")
	}
	webUID, err := webWorkerUID()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/var/tmp", "panel-socket-acl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	pool := filepath.Join(root, "pool")
	if err = os.Mkdir(pool, 0750); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(pool, int(DefaultUIDMinimum), int(DefaultUIDMinimum)); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(pool, "g1.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.Chown(socket, int(DefaultUIDMinimum), int(DefaultUIDMinimum)); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(socket, 0750); err != nil {
		t.Fatal(err)
	}
	fd, err := openDirectory(pool)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err = grantWebSocketAt(fd, "g1.sock", DefaultUIDMinimum, webUID); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		uid     uint32
		allowed bool
	}{{webUID, true}, {DefaultUIDMaximum, false}} {
		cmd := exec.Command("/usr/bin/test", "-w", socket)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.uid, Gid: c.uid}}
		if got := cmd.Run() == nil; got != c.allowed {
			t.Fatalf("uid=%d socket-write=%t", c.uid, got)
		}
	}
	if err = grantWebSocketAt(fd, "g1.sock", DefaultUIDMaximum, webUID); err == nil {
		t.Fatal("wrong owner accepted")
	}
	if err = os.Symlink("g1.sock", filepath.Join(pool, "g2.sock")); err != nil {
		t.Fatal(err)
	}
	if err = grantWebSocketAt(fd, "g2.sock", DefaultUIDMinimum, webUID); err == nil {
		t.Fatal("symlink accepted")
	}
}
