//go:build linux

package secrets

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestManagementPeerUsesKernelUIDAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manage.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	policy, err := NewLinuxManagementPeerAuthorizer(uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := policy.Authorize(connection)
	if err != nil || peer.UID != uint32(os.Geteuid()) || peer.PID != uint32(os.Getpid()) {
		t.Fatalf("peer credentials: %+v %v", peer, err)
	}
	denied, _ := NewLinuxManagementPeerAuthorizer(uint32(os.Geteuid()) + 1)
	if _, err := denied.Authorize(connection); err == nil {
		t.Fatal("accepted UID outside allowlist")
	}
	if peer.ExecutableDigest != "" || peer.ProcessStart != 0 {
		t.Fatal("management peer must not claim verified material-consumer identity")
	}
}
