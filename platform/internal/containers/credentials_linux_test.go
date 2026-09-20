package containers

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNativeContainerCommandDropsSupervisorGroups(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("run as root in QEMU to exercise credential dropping")
	}
	inherited, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(inherited) == 0 {
		t.Fatal("QEMU supervisor must have a supplementary group for this regression")
	}
	for _, gid := range []uint32{1000, 1001} {
		t.Run(strconv.FormatUint(uint64(gid), 10), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Executes the exact process-construction boundary used after the runner's
			// Podman/Skopeo allowlist. No arbitrary executable is admitted by Run.
			command := nativeLinuxContainerCommand(ctx, LinuxContainerInvocation{Path: "/usr/bin/id", Arguments: []string{"-G"}, UID: 1000, GID: gid})
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("credential probe: %v: %s", err, output)
			}
			expected := strconv.FormatUint(uint64(gid), 10)
			if strings.TrimSpace(string(output)) != expected {
				t.Fatalf("supervisor groups leaked: got %q, want only %s (parent %v)", strings.TrimSpace(string(output)), expected, inherited)
			}
		})
	}
}

func TestNativeContainerRunnerRejectsProbeExecutable(t *testing.T) {
	if _, _, err := (NativeLinuxContainerCommandRunner{}).Run(context.Background(), LinuxContainerInvocation{Path: "/usr/bin/id", OutputLimit: 1024}); err == nil {
		t.Fatal("process-boundary probe widened the runtime executable allowlist")
	}
}

func TestQEMUContainerRunnerUsesRootlessPodman(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_CONTAINER_RUNTIME") != "1" {
		t.Skip("installed QEMU Podman required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("run as root in QEMU")
	}
	account, err := user.Lookup("harness")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Fatal("invalid harness UID")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		t.Fatal("invalid harness GID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, code, err := (NativeLinuxContainerCommandRunner{}).Run(ctx, LinuxContainerInvocation{
		Path: "/usr/bin/podman", Arguments: []string{"info", "--format", "json"}, UID: uint32(uid), GID: uint32(gid), Directory: account.HomeDir, OutputLimit: 2 << 20,
		Environment: []string{"HOME=" + account.HomeDir, "XDG_RUNTIME_DIR=/run/user/" + account.Uid},
	})
	if err != nil || code != 0 {
		t.Fatalf("native rootless invocation: code=%d err=%v output=%s", code, err, output)
	}
	var info struct {
		Host struct {
			Security struct {
				Rootless bool `json:"rootless"`
			} `json:"security"`
		} `json:"host"`
	}
	if err := json.Unmarshal(output, &info); err != nil {
		t.Fatal(err)
	}
	if !info.Host.Security.Rootless {
		t.Fatal("native invocation did not run rootlessly")
	}
}
