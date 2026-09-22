//go:build linux

package dns

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestQEMUPowerDNSDNSSECNativeExports(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_DNSSEC") != "1" {
		t.Skip("isolated installed PowerDNS command qualification")
	}
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(powerDNSSQLiteSchema); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "pdns.conf"), []byte("launch=gsqlite3\ngsqlite3-database="+filepath.Join(dir, "authority.db")+"\ngsqlite3-dnssec=yes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.Command("/usr/bin/pdnsutil", append([]string{"--config-dir=" + dir}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", args[0], err, out)
		}
		return out
	}
	const zone = "isolated-dnssec.invalid"
	run("create-zone", zone)
	out := run("add-zone-key", zone, "ksk", "active", "published", "ECDSAP256SHA256")
	id, err := parsePowerDNSKeyID(out)
	if err != nil {
		t.Fatalf("key ID: %v output=%q", err, out)
	}
	out = run("export-zone-dnskey", zone, id)
	public, tag, err := parsePowerDNSDNSKEY(out)
	if err != nil {
		t.Fatalf("DNSKEY: %v output=%q", err, out)
	}
	// A second key makes selection from the zone-wide native export material.
	run("add-zone-key", zone, "ksk", "active", "published", "ECDSAP256SHA256")
	out = run("export-zone-ds", zone)
	name, _ := ParseName(zone)
	ds, err := powerDNSDSForKey(out, name, DNSSECKeyDescriptor{PublicDNSKEY: public, KeyTag: tag})
	if err != nil {
		t.Fatalf("DS: %v output=%q", err, out)
	}
	if ds.KeyTag != tag {
		t.Fatalf("DS tag=%d DNSKEY tag=%d", ds.KeyTag, tag)
	}
	wrong := []byte(fmt.Sprintf("%s IN DS %d %d 2 %s\n", zone, tag, ds.Algorithm, strings.Repeat("0", 64)))
	if _, err = powerDNSDSForKey(wrong, name, DNSSECKeyDescriptor{PublicDNSKEY: public, KeyTag: tag}); err == nil {
		t.Fatal("accepted colliding tag with wrong digest")
	}
	if selected, err := powerDNSDSForKey(append(wrong, out...), name, DNSSECKeyDescriptor{PublicDNSKEY: public, KeyTag: tag}); err != nil || selected.Digest != ds.Digest {
		t.Fatal("exact public key digest selection", err)
	}
	run("disable-dnssec", zone)
	var count int
	if err = db.QueryRow("SELECT count(*) FROM cryptokeys").Scan(&count); err != nil || count != 0 {
		t.Fatalf("disable keys=%d err=%v", count, err)
	}
}
