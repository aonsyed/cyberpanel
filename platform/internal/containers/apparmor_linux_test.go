package containers

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestContainerAppArmorRequiresExactEnforcingGeneration(t *testing.T) {
	name, _ := RootlessAppArmorPolicy()
	for _, entry := range []struct {
		content string
		valid   bool
	}{
		{name + " (enforce)\n", true}, {name + " (complain)\n", false}, {name + " (unconfined)\n", false}, {name + "-other (enforce)\n", false}, {"other (enforce)\n", false}, {name + " (enforce)\n" + name + " (complain)\n", false},
	} {
		if loadedEnforcingContainerProfile(strings.NewReader(entry.content), name) != entry.valid {
			t.Errorf("incorrect verdict for %q", entry.content)
		}
	}
}

func loadQEMUContainerPolicy(t *testing.T) {
	t.Helper()
	if rootlessContainerProfileReady() == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := (NativeLinuxContainerCommandRunner{}).Run(ctx, LinuxContainerInvocation{Path: "/usr/bin/podman", Arguments: []string{"info", "--format", "json"}, UID: 1000, GID: 1000, OutputLimit: 2 << 20})
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("missing profile did not reject native launch: %v", err)
	}
	_, policy := RootlessAppArmorPolicy()
	path := filepath.Join(t.TempDir(), "container.apparmor")
	if err := os.WriteFile(path, policy, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/sbin/apparmor_parser", "-a", path).CombinedOutput(); err != nil {
		t.Fatalf("load profile: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if output, err := exec.Command("/usr/sbin/apparmor_parser", "-R", path).CombinedOutput(); err != nil {
			t.Errorf("unload profile: %v: %s", err, output)
		}
	})
	if err := rootlessContainerProfileReady(); err != nil {
		t.Fatal(err)
	}
}

func TestQEMUContainerInheritedPolicyEnforcement(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_CONTAINER_RUNTIME") != "1" {
		t.Skip("QEMU AppArmor and pinned n8n image required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root QEMU fixture required")
	}
	loadQEMUContainerPolicy(t)
	account, err := user.Lookup("harness")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(account.HomeDir, "qemu-container-policy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"allowed", "denied"} {
		if err = os.WriteFile(filepath.Join(root, name), []byte(name+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	profile, _ := RootlessAppArmorPolicy()
	script := `set -eu
test "$(cat /proc/self/attr/current)" = "` + profile + ` (enforce)"
test "$(cat /probe-allowed)" = allowed
if cat /etc/cyberpanel/mac-probe; then exit 41; fi
if echo 'changeprofile unconfined' > /proc/self/attr/current; then exit 42; fi
test "$(cat /proc/self/attr/current)" = "` + profile + ` (enforce)"
echo policy-enforcement-passed`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	invocation := LinuxContainerInvocation{Path: "/usr/bin/podman", UID: uint32(uid), GID: uint32(gid), Directory: account.HomeDir, OutputLimit: 2 << 20, Environment: []string{"HOME=" + account.HomeDir, "XDG_RUNTIME_DIR=/run/user/" + account.Uid}, Arguments: []string{"run", "--rm", "--name", "qemu-policy-enforcement", "--pull=never", "--network=none", "--user=1000:1000", "--cap-drop=all", "--security-opt=no-new-privileges", "--read-only", "--memory=256m", "--pids-limit=64", "--volume", filepath.Join(root, "allowed") + ":/probe-allowed:ro", "--volume", filepath.Join(root, "denied") + ":/etc/cyberpanel/mac-probe:ro", "--entrypoint", "/bin/sh", "docker.io/n8nio/n8n@sha256:24b5c803a1465c524dbe65adb082f00740610d1077d3061063f47a6bb5fe5bba", "-c", script}}
	output, code, err := (NativeLinuxContainerCommandRunner{}).Run(ctx, invocation)
	if err != nil || code != 0 || !strings.Contains(string(output), "policy-enforcement-passed") {
		t.Fatalf("enforcement: code=%d err=%v output=%s", code, err, output)
	}
}
