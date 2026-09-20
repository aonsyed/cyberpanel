package noderelease

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestQEMUOfflinePackageNetwork(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_NODE_RELEASE") != "1" {
		t.Skip("root QEMU network namespace check")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	before, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		err = runInOfflineNetwork(func() error {
			interfaces, err := net.Interfaces()
			if err != nil {
				return err
			}
			if len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp == 0 {
				return fmt.Errorf("need active private loopback only: %+v", interfaces)
			}
			fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				return err
			}
			defer syscall.Close(fd)
			if err = syscall.Connect(fd, &syscall.SockaddrInet4{Port: 443, Addr: [4]byte{192, 0, 2, 1}}); !errors.Is(err, syscall.ENETUNREACH) {
				return fmt.Errorf("external route must be absent: %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		after, err := os.Readlink("/proc/thread-self/ns/net")
		if err != nil || after != before {
			t.Fatalf("parent namespace changed: %s -> %s, %v", before, after, err)
		}
	}
}
