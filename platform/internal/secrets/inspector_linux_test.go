//go:build linux

package secrets

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMaterialInspectorDescriptorBoundary(t *testing.T) {
	directory := t.TempDir()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "helper.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go ServeMaterialInspector(listener, uint32(os.Geteuid()))
	peerListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "peer.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer peerListener.Close()
	peer, err := net.DialUnix("unix", nil, peerListener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	accepted, err := peerListener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	descriptor, err := accepted.File()
	if err != nil {
		t.Fatal(err)
	}
	defer descriptor.Close()
	regular, err := os.Create(filepath.Join(directory, "not-a-socket"))
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	for _, test := range []struct {
		name   string
		fds    []int
		denied bool
	}{
		{"connected socket", []int{int(descriptor.Fd())}, false},
		{"missing descriptor", nil, true},
		{"regular file", []int{int(regular.Fd())}, true},
		{"multiple descriptors", []int{int(descriptor.Fd()), int(descriptor.Fd())}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			helper, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer helper.Close()
			helper.SetDeadline(time.Now().Add(5 * time.Second))
			var rights []byte
			if len(test.fds) > 0 {
				rights = syscall.UnixRights(test.fds...)
			}
			if _, _, err = helper.WriteMsgUnix([]byte{1}, rights, nil); err != nil {
				t.Fatal(err)
			}
			var response inspectorResponse
			if err = readMaterialFrame(helper, &response); err != nil {
				t.Fatal(err)
			}
			if response.Denied != test.denied {
				t.Fatalf("unexpected inspection: %+v", response)
			}
			if !test.denied {
				digest, err := linuxExecutableDigest(uint32(os.Getpid()))
				if err != nil || response.Peer.UID != uint32(os.Geteuid()) || response.Peer.PID != uint32(os.Getpid()) || response.Peer.ExecutableDigest != digest {
					t.Fatalf("wrong kernel peer: %+v %v", response, err)
				}
			}
		})
	}
}

func TestQEMUInspectorCrossUserSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root inside QEMU")
	}
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("QEMU python fixture unavailable")
	}
	directory, err := os.MkdirTemp("/tmp", "cp-inspector-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err = os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "peer.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.Chmod(listener.Addr().String(), 0666); err != nil {
		t.Fatal(err)
	}
	child := exec.Command("/usr/bin/python3", "-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.recv(1)", listener.Addr().String())
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	listener.SetDeadline(time.Now().Add(5 * time.Second))
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	helperListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "helper.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer helperListener.Close()
	go ServeMaterialInspector(helperListener, 0)
	helper, err := net.DialUnix("unix", nil, helperListener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	helper.SetDeadline(time.Now().Add(5 * time.Second))
	descriptor, err := connection.File()
	if err != nil {
		t.Fatal(err)
	}
	defer descriptor.Close()
	if _, _, err = helper.WriteMsgUnix([]byte{1}, syscall.UnixRights(int(descriptor.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	var response inspectorResponse
	if err = readMaterialFrame(helper, &response); err != nil {
		t.Fatal(err)
	}
	if response.Denied || response.Peer.UID != 65534 || response.Peer.PID != uint32(child.Process.Pid) || response.Peer.ProcessStart == 0 {
		t.Fatalf("cross-user identity unavailable: %+v", response)
	}
}

func TestMaterialInspectorRejectsOtherCaller(t *testing.T) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "helper.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go ServeMaterialInspector(listener, uint32(os.Geteuid())+1)
	connection, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(time.Second))
	_, _ = connection.Write([]byte{1})
	var response inspectorResponse
	if err := readMaterialFrame(connection, &response); err == nil {
		t.Fatal("non-broker caller received inspection response")
	}
}
