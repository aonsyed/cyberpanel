//go:build linux

package mail

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestQEMUExecutorOpenat2(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_OPENAT2_HELPER") == "1" {
		fd, err := openMailProductRoot()
		if err != nil {
			t.Fatal(err)
		}
		syscall.Close(fd)
		return
	}
	if os.Getenv("CYBERPANEL_QEMU_MAIL_SANDBOX") != "1" {
		t.Skip("requires QEMU systemd")
	}
	unit, err := os.ReadFile("../../packaging/systemd/panel-execd.service")
	if err != nil {
		t.Fatal(err)
	}
	var restriction string
	for _, line := range strings.Split(string(unit), "\n") {
		if strings.HasPrefix(line, "RestrictSUIDSGID=") {
			restriction = line
		}
	}
	if restriction == "" {
		t.Fatal("missing explicit executor SUID/SGID policy")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := func(property string) ([]byte, error) {
		return exec.Command("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "-p", property, "--setenv=CYBERPANEL_QEMU_OPENAT2_HELPER=1", executable, "-test.run=^TestQEMUExecutorOpenat2$").CombinedOutput()
	}
	if output, err := probe("RestrictSUIDSGID=true"); err == nil || !strings.Contains(string(output), "function not implemented") {
		t.Fatalf("negative control did not reproduce blocked openat2: %v %s", err, output)
	}
	if output, err := probe(restriction); err != nil {
		t.Fatalf("executor policy prevents confined filesystem access: %v %s", err, output)
	}
}

func TestQEMUPostfixExecutorAddressFamilies(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_MAIL_SANDBOX") != "1" {
		t.Skip("requires QEMU systemd and retained native mail generation")
	}
	unit, err := os.ReadFile("../../packaging/systemd/panel-execd.service")
	if err != nil {
		t.Fatal(err)
	}
	var families string
	for _, line := range strings.Split(string(unit), "\n") {
		if strings.HasPrefix(line, "RestrictAddressFamilies=") {
			families = line
		}
	}
	if families == "" {
		t.Fatal("missing executor address-family restriction")
	}
	entries, err := os.ReadDir(filepath.Join(MailConfigurationRoot, "generations"))
	if err != nil || len(entries) == 0 {
		t.Fatal("retained generation required", err)
	}
	config := filepath.Join(MailConfigurationRoot, "generations", entries[0].Name(), "postfix")
	probe := func(property string) ([]byte, error) {
		return exec.Command("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "-p", property, "/usr/sbin/postfix", "-c", config, "check").CombinedOutput()
	}
	output, err := probe("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6")
	if err == nil || !strings.Contains(string(output), "getifaddrs: Address family not supported") {
		t.Fatalf("negative control did not reproduce interface enumeration failure: %v %s", err, output)
	}
	if output, err := probe(families); err != nil {
		t.Fatalf("Postfix rejected executor address families: %v %s", err, output)
	}
	// Exercise the real unit's security properties together: User=root with
	// its mount sandbox can lose SETUID even when it remains in the bounding set.
	args := []string{"--quiet", "--wait", "--pipe", "--collect"}
	for _, line := range strings.Split(string(unit), "\n") {
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "User", "Group", "NoNewPrivileges", "PrivateTmp", "PrivateDevices", "ProtectSystem", "ProtectHome", "BindPaths", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock", "LockPersonality", "RestrictSUIDSGID", "RestrictRealtime", "RestrictNamespaces", "SystemCallArchitectures", "RestrictAddressFamilies", "CapabilityBoundingSet", "AmbientCapabilities":
			args = append(args, "-p", line)
		}
	}
	args = append(args, "/usr/sbin/postfix", "-c", config, "check")
	if output, err := exec.Command("/usr/bin/systemd-run", args...).CombinedOutput(); err != nil {
		t.Fatalf("Postfix rejected executor security sandbox: %v %s", err, output)
	}
}
