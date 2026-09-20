package containers

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestQEMUContainerPolicyPersistentProvisionAndReplay(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_CONTAINER_RUNTIME") != "1" {
		t.Skip("QEMU root/AppArmor fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	name, policy := RootlessAppArmorPolicy()
	path := filepath.Join("/etc/apparmor.d", name)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Skip("preserve existing managed policy file")
	}
	if rootlessContainerProfileReady() == nil {
		t.Skip("preserve existing loaded profile")
	}
	cleanupPath := filepath.Join(t.TempDir(), "policy")
	if err := os.WriteFile(cleanupPath, policy, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if rootlessContainerProfileReady() == nil {
			if output, err := exec.Command("/usr/sbin/apparmor_parser", "-R", cleanupPath).CombinedOutput(); err != nil {
				t.Errorf("remove fixture profile: %v: %s", err, output)
			}
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
	})
	installed, err := ProvisionRootlessContainerPolicy(context.Background())
	if err != nil || installed != path {
		t.Fatalf("provision: %s: %v", installed, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, policy) {
		t.Fatal("persisted policy differs from executable")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm() != 0644 {
		t.Fatal("policy not root-owned 0644")
	}
	inode := stat.Ino
	// A surviving disk file/receipt must not suppress restoration of kernel state.
	if output, err := exec.Command("/usr/sbin/apparmor_parser", "-R", path).CombinedOutput(); err != nil {
		t.Fatalf("unload fixture: %v: %s", err, output)
	}
	if rootlessContainerProfileReady() == nil {
		t.Fatal("profile remained loaded")
	}
	if _, err := ProvisionRootlessContainerPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(path)
	if err != nil || info.Sys().(*syscall.Stat_t).Ino != inode {
		t.Fatal("replay rewrote immutable generation")
	}
	if err := rootlessContainerProfileReady(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte(nil), policy...), []byte("# altered\n")...), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ProvisionRootlessContainerPolicy(context.Background()); !errors.Is(err, ErrPolicy) {
		t.Fatal("altered generation accepted")
	}
	if err := os.WriteFile(path, policy, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := ProvisionRootlessContainerPolicy(context.Background()); !errors.Is(err, ErrPolicy) {
		t.Fatal("writable generation accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cleanupPath, path); err != nil {
		t.Fatal(err)
	}
	if _, err := ProvisionRootlessContainerPolicy(context.Background()); !errors.Is(err, ErrPolicy) {
		t.Fatal("symlink generation accepted")
	}
}
