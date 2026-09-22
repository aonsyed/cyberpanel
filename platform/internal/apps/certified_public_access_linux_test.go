//go:build linux

package apps

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
	"golang.org/x/sys/unix"
)

func TestCertifiedPublicACLRejectsBroaderOrUnrelatedPolicy(t *testing.T) {
	value := make([]byte, 44)
	binary.LittleEndian.PutUint32(value, 2)
	for i, entry := range [][3]uint32{{1, 7, ^uint32(0)}, {2, 5, 988}, {4, 5, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		part := value[4+i*8:]
		binary.LittleEndian.PutUint16(part, uint16(entry[0]))
		binary.LittleEndian.PutUint16(part[2:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(part[4:], entry[2])
	}
	if !validCertifiedPublicACL(value, 988) {
		t.Fatal("provisioned public-reader policy rejected")
	}
	for _, test := range []struct {
		name        string
		offset      int
		replacement byte
	}{
		{"version", 0, 3}, {"web-write", 14, 7}, {"other-read", 38, 4}, {"named-principal", 16, 1}, {"group-write", 22, 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := append([]byte(nil), value...)
			bad[test.offset] = test.replacement
			if validCertifiedPublicACL(bad, 988) {
				t.Fatal("untrusted policy accepted")
			}
		})
	}
	if validCertifiedPublicACL(value[:36], 988) || validCertifiedPublicACL(append(value, 0), 988) || validCertifiedPublicACL(value, 989) {
		t.Fatal("malformed or unrelated policy accepted")
	}
}

func TestEmptyLegacyPublicACLRecoveryIsScoped(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("QEMU root required for isolated ownership fixture")
	}
	for _, variant := range []string{"empty-managed", "nonempty", "foreign", "symlink", "widened"} {
		t.Run(variant, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "current")
			public := filepath.Join(root, "public")
			stage := filepath.Join(root, ".app-install-test")
			for _, path := range []string{root, public, stage} {
				if err := os.Mkdir(path, 0750); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(path, 1000, 1000); err != nil {
					t.Fatal(err)
				}
			}
			fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			if err != nil {
				t.Fatal(err)
			}
			err = siteops.GrantRestoredPublicAccess(fd, 1000, 1000)
			unix.Close(fd)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
				if err := unix.Removexattr(public, name); err != nil {
					t.Fatal(err)
				}
			}
			private := filepath.Join(root, "private")
			if err := os.WriteFile(private, []byte("private"), 0600); err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "nonempty":
				if err := os.WriteFile(filepath.Join(public, "owned"), []byte("data"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err := os.Chown(public, 1001, 1001); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(public); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(stage, public); err != nil {
					t.Fatal(err)
				}
			case "widened":
				if err := os.Chmod(public, 0755); err != nil {
					t.Fatal(err)
				}
			}
			binding := LinuxApplicationSiteBinding{UID: 1000, GID: 1000}
			err = preserveCertifiedPublicAccess(linuxApplicationScope{root: public, binding: binding}, linuxApplicationScope{root: stage, binding: binding})
			if variant == "empty-managed" {
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
					if n, err := unix.Getxattr(stage, name, nil); err != nil || n != 44 {
						t.Fatalf("stage policy missing: %d %v", n, err)
					}
				}
			} else if err == nil {
				t.Fatal("unsafe legacy public root accepted")
			}
			if _, err := unix.Getxattr(private, "system.posix_acl_access", nil); err != unix.ENODATA {
				t.Fatal("private permissions changed")
			}
		})
	}
}
