//go:build linux

package dns

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type unusedNativeTSIGResolver struct{}

func (unusedNativeTSIGResolver) ResolvePowerDNSTSIGSecret(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("no TSIG material requested by access test")
}

func TestPowerDNSNativeAccessRejectsUnsafeFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("QEMU root fixture")
	}
	uid, err := powerDNSNativeUID()
	if err != nil {
		t.Skip("native pdns account required")
	}
	path := filepath.Join(t.TempDir(), "authority.db")
	if err = os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = powerDNSNativeAccessFile(path, uid, false, true); err != nil {
		t.Fatal(err)
	}
	if err = powerDNSNativeAccessFile(path, uid, false, false); err != nil {
		t.Fatal(err)
	}
	if err = powerDNSNativeAccessFile(path, uid+1, false, false); err == nil {
		t.Fatal("accepted another service UID")
	}
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err = powerDNSNativeAccessFile(path, uid, false, true); err == nil {
		t.Fatal("accepted world-writable database")
	}
	if err = os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if err = powerDNSNativeAccessFile(path+".link", uid, false, true); err == nil {
		t.Fatal("accepted symlink database")
	}
}

func TestQEMUPowerDNSNativeDatabaseAccess(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_PDNS_ACCESS") != "1" {
		t.Skip("explicit QEMU native database access qualification")
	}
	if err := preparePowerDNSNativeDatabaseAccess(); err != nil {
		t.Fatal(err)
	}
	if err := validatePowerDNSNativeDatabaseFiles(); err != nil {
		t.Fatal(err)
	}
	database, _, err := OpenLocalSQLitePowerDNSAuthority(context.Background(), unusedNativeTSIGResolver{})
	if err != nil {
		t.Fatal("reopen authority without revoking native ACL", err)
	}
	defer database.Close()
	// Execute a real SQLite write transaction as the daemon UID; roll it back
	// so this probe does not create an authoritative DNS zone.
	php := `$d=new PDO("sqlite:/var/lib/cyberpanel/powerdns/authority.db"); $d->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION); $d->exec("BEGIN IMMEDIATE"); $d->exec("INSERT INTO domains(name,type) VALUES ('qemu-acl-probe.invalid','NATIVE')"); $d->exec("ROLLBACK");`
	if out, err := exec.Command("/usr/sbin/runuser", "-u", "pdns", "--", "/usr/local/lsws/lsphp83/bin/php", "-r", php).CombinedOutput(); err != nil {
		t.Fatalf("native SQLite transaction: %v: %s", err, out)
	}
	for _, check := range []string{"test ! -w /var/lib/cyberpanel/powerdns", "test ! -r /var/lib/cyberpanel/control/control.db", "test ! -r /var/lib/cyberpanel/powerdns/generations"} {
		if out, err := exec.Command("/usr/sbin/runuser", "-u", "pdns", "--", "/bin/sh", "-c", check).CombinedOutput(); err != nil {
			t.Fatalf("isolation check: %v: %s", err, out)
		}
	}
}
