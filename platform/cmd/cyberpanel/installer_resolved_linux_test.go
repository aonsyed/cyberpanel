//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDefaultResolvedConfiguration(t *testing.T) {
	for _, content := range []string{"# vendor defaults\n[Resolve]\n", resolvedHandoff} {
		if !defaultResolvedConfiguration(content) {
			t.Fatal("rejected default config")
		}
	}
	for _, content := range []string{"[Resolve]\nDNS=1.1.1.1", "[Resolve]\nDNSStubListener=yes", "[Resolve]\nDNSStubListenerExtra=127.0.0.54", "[Other]"} {
		if defaultResolvedConfiguration(content) {
			t.Fatal("accepted custom config", content)
		}
	}
}

func TestQEMUDefaultResolvedHandoff(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_RESOLVED_HANDOFF") != "1" {
		t.Skip("explicit QEMU resolver handoff")
	}
	for i := 0; i < 2; i++ {
		if err := reconcileDefaultResolved(); err != nil {
			t.Fatal(err)
		}
		link, err := os.Readlink("/etc/resolv.conf")
		if err != nil || link != "/run/systemd/resolve/resolv.conf" {
			t.Fatal("resolver target", link, err)
		}
		if out, err := exec.Command("/usr/bin/getent", "ahostsv4", "archive.ubuntu.com").CombinedOutput(); err != nil || len(out) == 0 {
			t.Fatalf("outbound DNS: %v: %s", err, out)
		}
		for _, protocol := range []string{"-lnup", "-lntp"} {
			out, err := exec.Command("/usr/bin/ss", protocol, "sport = :53").CombinedOutput()
			if err != nil || strings.Contains(string(out), "systemd-resolve") {
				t.Fatalf("stub still owns DNS port: %v: %s", err, out)
			}
		}
	}
}
