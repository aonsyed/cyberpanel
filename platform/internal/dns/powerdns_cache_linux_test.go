//go:build linux

package dns

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/daemoncfg"
)

func TestPowerDNSCachePurgeRejectsNonZoneTargets(t *testing.T) {
	host := &LinuxPowerDNSHost{}
	for _, name := range []string{"", "@", "*", "example.invalid$", "--help", "example.invalid\n"} {
		if _, err := host.RediscoverZone(context.Background(), DNSName{value: name}); err == nil {
			t.Fatalf("accepted unsafe cache target %q", name)
		}
	}
}

func TestQEMUPowerDNSZoneCachePurge(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_DNS_CACHE") != "1" {
		t.Skip("scoped native purge of the retained DNS UI fixture")
	}
	store, err := daemoncfg.OpenStore(PowerDNSConfigurationRoot, PowerDNSConfigurationRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	profile, err := profileForPowerDNS(PowerDNSUbuntuNoble)
	if err != nil {
		t.Fatal(err)
	}
	host := &LinuxPowerDNSHost{Store: store, profile: profile}
	zone, _ := ParseName("qemu-dns-20260922.invalid")
	receipt, err := host.RediscoverZone(context.Background(), zone)
	if err != nil || !receipt.Success || !receipt.Healthy || !powerDNSSHA256(receipt.EvidenceDigest) {
		t.Fatal("native scoped purge", err)
	}
	for kind, expected := range map[string]string{"A": "192.0.2.23", "TXT": "\"dns-second\""} {
		out, err := exec.Command("/usr/bin/dig", "@127.0.0.1", zone.String(), kind, "+short", "+norecurse").Output()
		if err != nil || strings.TrimSpace(string(out)) != expected {
			t.Fatalf("%s authoritative answer %q: %v", kind, out, err)
		}
	}
}
