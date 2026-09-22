//go:build linux

package database

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

func replacementFixtureDatabase(name string) Database {
	id, _ := NewResourceID(name)
	tenant, _ := site.NewTenantID("replacement-tenant")
	siteID, _ := site.NewSiteID("replacement-site")
	instance, _ := NewResourceID("replacement-instance")
	native, _ := ParseSQLIdentifier(name)
	charset, _ := ParseSQLIdentifier("utf8mb4")
	collation, _ := ParseSQLIdentifier("utf8mb4_unicode_ci")
	return Database{Metadata: Metadata{ID: id, TenantID: tenant, SiteID: siteID, Generation: 1,
		Status: ResourceStatus{Lifecycle: LifecycleReady, Health: HealthHealthy, Reconciliation: ReconciliationInSync}},
		InstanceID: instance, Name: native, Charset: charset, Collation: collation, QuotaBytes: 1 << 20}
}

func TestTransferReplacementRenameSQL(t *testing.T) {
	live, staged, restore := replacementFixtureDatabase("live"), replacementFixtureDatabase("staged"), replacementFixtureDatabase("restore")
	statement, err := transferReplacementRenameSQL(live, staged, restore, []string{"same", "old`only"}, []string{"same", "new"})
	want := "RENAME TABLE `live`.`same` TO `restore`.`same`, `live`.`old``only` TO `restore`.`old``only`, `staged`.`same` TO `live`.`same`, `staged`.`new` TO `live`.`new`;\n"
	if err != nil || statement != want {
		t.Fatalf("statement = %q, %v", statement, err)
	}
	for _, mutate := range []func(*Database, *Database, *Database){
		func(l, s, r *Database) { r.Name = l.Name },
		func(l, s, r *Database) { r.ID = s.ID },
		func(l, s, r *Database) { s.InstanceID, _ = NewResourceID("other") },
		func(l, s, r *Database) { r.TenantID, _ = site.NewTenantID("other") },
		func(l, s, r *Database) { r.SiteID, _ = site.NewSiteID("other") },
	} {
		l, s, r := live, staged, restore
		mutate(&l, &s, &r)
		if _, err := transferReplacementRenameSQL(l, s, r, []string{"same"}, []string{"same"}); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
	for _, names := range [][]string{nil, {"same", "same"}, {""}, {"nul\x00"}, make([]string, MaximumTransferTables+1)} {
		if _, err := transferReplacementRenameSQL(live, staged, restore, names, []string{"same"}); err == nil {
			t.Fatal("invalid old tables accepted")
		}
		if _, err := transferReplacementRenameSQL(live, staged, restore, []string{"same"}, names); err == nil {
			t.Fatal("invalid new tables accepted")
		}
	}
}

// This tests the internal SQL primitive, not the still-disabled replacement API.
// Native metadata locks prevent the atomic move from bypassing an active writer;
// application admission fencing/journaling must still surround production use.
func TestQEMUTransferReplacementAtomicMove(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_TRANSFER") != "1" {
		t.Skip("requires disposable QEMU MariaDB")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root inside QEMU")
	}
	for _, engine := range []string{"InnoDB", "MyISAM", "Aria"} {
		t.Run(engine, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			random := make([]byte, 8)
			if _, err := rand.Read(random); err != nil {
				t.Fatal(err)
			}
			prefix := "qemu_replace_" + hex.EncodeToString(random)
			live, staged, restore := replacementFixtureDatabase(prefix+"_live"), replacementFixtureDatabase(prefix+"_stage"), replacementFixtureDatabase(prefix+"_restore")
			args := []string{"--no-defaults", "--protocol=socket", "--socket=" + mariaDBSocket, "--user=root", "--batch", "--skip-column-names", "--unbuffered"}
			query := func(statement string) (string, error) {
				cmd := exec.CommandContext(ctx, mariaDBClientBinary, args...)
				cmd.Stdin = strings.NewReader(statement)
				out, err := cmd.CombinedOutput()
				return strings.TrimSpace(string(out)), err
			}
			must := func(statement string) string {
				t.Helper()
				out, err := query(statement)
				if err != nil {
					t.Fatalf("native SQL: %v: %s", err, out)
				}
				return out
			}
			versionText := must("SELECT @@version;")
			version, err := parseMariaDBVersion(versionText)
			if err != nil || !strings.Contains(versionText, "MariaDB") || compareVersion(version, MariaDBVersion{Major: 10, Minor: 6, Patch: 1}) < 0 {
				t.Fatalf("atomic rename requires MariaDB >=10.6.1: %q", versionText)
			}
			for _, db := range []Database{live, staged, restore} {
				must("CREATE DATABASE " + quotedIdentifier(db.Name) + ";")
				t.Cleanup(func() {
					cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
					defer stop()
					cmd := exec.CommandContext(cleanup, mariaDBClientBinary, args...)
					cmd.Stdin = strings.NewReader("DROP DATABASE IF EXISTS " + quotedIdentifier(db.Name) + ";")
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Errorf("cleanup: %v: %s", err, out)
					}
				})
			}
			for i, db := range []Database{live, staged} {
				value := "original"
				if i == 1 {
					value = "replacement"
				}
				must("CREATE TABLE " + quotedIdentifier(db.Name) + ".sample(body VARCHAR(30)) ENGINE=" + engine + "; INSERT INTO " + quotedIdentifier(db.Name) + ".sample VALUES ('" + value + "');")
			}
			check := func(db Database, value string) {
				t.Helper()
				if got := must("SELECT body FROM " + quotedIdentifier(db.Name) + ".sample;"); got != value {
					t.Fatalf("%s = %q, want %q", db.Name.String(), got, value)
				}
			}
			statement, err := transferReplacementRenameSQL(live, staged, restore, []string{"sample"}, []string{"sample", "missing"})
			if err != nil {
				t.Fatal(err)
			}
			if out, err := query(statement); err == nil {
				t.Fatalf("missing source accepted: %s", out)
			}
			check(live, "original")
			check(staged, "replacement")
			statement, err = transferReplacementRenameSQL(live, staged, restore, []string{"sample"}, []string{"sample"})
			if err != nil {
				t.Fatal(err)
			}
			writer := exec.CommandContext(ctx, mariaDBClientBinary, args...)
			input, err := writer.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := writer.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = input.Close(); _ = writer.Wait() }()
			if _, err := io.WriteString(input, "LOCK TABLES "+quotedIdentifier(live.Name)+".sample WRITE; SELECT 'locked';\n"); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(output)
			if line, err := reader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "locked" {
				t.Fatalf("writer lock: %q, %v", line, err)
			}
			if out, err := query("SET lock_wait_timeout=1; " + statement); err == nil || !strings.Contains(out, "1205") {
				t.Fatalf("rename bypassed writer lock or failed unexpectedly: %v: %s", err, out)
			}
			if _, err := io.WriteString(input, "UNLOCK TABLES; SELECT 'released';\n"); err != nil {
				t.Fatal(err)
			}
			if line, err := reader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "released" {
				t.Fatalf("writer release: %q, %v", line, err)
			}
			check(live, "original")
			check(staged, "replacement")
			// Same-session LOCK TABLES + RENAME is not a supported writer fence:
			// the native probe returned ERROR 1192 on all three engines. Keep this
			// primitive disconnected from production admission until fenced.
			if out, err := query("LOCK TABLES " + quotedIdentifier(live.Name) + ".sample WRITE, " + quotedIdentifier(staged.Name) + ".sample WRITE; " + statement); err == nil || !strings.Contains(out, "1192") {
				t.Fatalf("native lock behavior changed; requalify replacement fencing: %v: %s", err, out)
			}
			check(live, "original")
			check(staged, "replacement")
			must(statement)
			check(live, "replacement")
			check(restore, "original")
			rollback, err := transferReplacementRenameSQL(live, restore, staged, []string{"sample"}, []string{"sample"})
			if err != nil {
				t.Fatal(err)
			}
			must(rollback)
			check(live, "original")
			check(staged, "replacement")
		})
	}
}
