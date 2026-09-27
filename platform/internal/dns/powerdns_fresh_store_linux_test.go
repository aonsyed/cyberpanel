//go:build linux

package dns

import (
 "os"
 "testing"
)

// The fresh-store normalization runs against the fixed store root; it is
// only safe to exercise on a host where no authority exists yet (the clean
// install drill guest before the first apply).
func TestQEMIFreshPowerDNSStoreRootNormalization(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_PDNS_FRESH") != "1" {
		t.Skip("requires a host with no PowerDNS authority yet")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root QEMU required")
	}
	if _, err := os.Lstat(LocalPowerDNSDatabasePath); err == nil {
		t.Skip("authority already exists on this host")
	}
	directory := "/var/lib/cyberpanel/powerdns"
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.MkdirAll(directory, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0750); err != nil {
		t.Fatal(err)
	}
	if err := normalizeFreshPowerDNSStoreRoot(directory); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("fresh 0750 root not normalized: %04o %v", info.Mode().Perm(), err)
	}
	// With a database present the root is never rewritten.
	if err = os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(LocalPowerDNSDatabasePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	t.Cleanup(func() { _ = os.Remove(LocalPowerDNSDatabasePath) })
	if err = normalizeFreshPowerDNSStoreRoot(directory); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(directory)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("existing authority root was rewritten: %04o %v", info.Mode().Perm(), err)
	}
}
