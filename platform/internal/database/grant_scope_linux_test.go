//go:build linux

package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQEMUGrantDatabaseNameIsLiteral(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_TRANSFER") != "1" {
		t.Skip("requires disposable QEMU MariaDB")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root inside QEMU")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	defer wipeBytes(seed)
	suffix := hex.EncodeToString(seed[:8])
	name, _ := ParseSQLIdentifier("qg_scope_" + suffix)
	neighbor, _ := ParseSQLIdentifier("qgxscopex" + suffix)
	user, _ := ParseSQLIdentifier("qg" + suffix)
	password := hex.EncodeToString(seed)
	root := func(ctx context.Context, query string) (string, error) {
		cmd := exec.CommandContext(ctx, mariaDBClientBinary, "--no-defaults", "--protocol=socket", "--socket="+mariaDBSocket, "--user=root", "--batch", "--skip-column-names")
		cmd.Stdin = strings.NewReader(query)
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	count, err := root(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('"+name.String()+"','"+neighbor.String()+"'); SELECT COUNT(*) FROM mysql.user WHERE User='"+user.String()+"';")
	if err != nil || count != "0\n0" {
		t.Fatal("fixture names already present or unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := root(cleanup, "DROP USER IF EXISTS '"+user.String()+"'@'localhost'; DROP DATABASE IF EXISTS `"+name.String()+"`; DROP DATABASE IF EXISTS `"+neighbor.String()+"`;"); err != nil {
			t.Error("grant fixture cleanup failed")
		}
	}()
	_, err = root(ctx, "CREATE DATABASE `"+name.String()+"`; CREATE DATABASE `"+neighbor.String()+"`; CREATE TABLE `"+name.String()+"`.probe(id INT); INSERT INTO `"+name.String()+"`.probe VALUES(7); CREATE TABLE `"+neighbor.String()+"`.probe(id INT); INSERT INTO `"+neighbor.String()+"`.probe VALUES(9); CREATE USER '"+user.String()+"'@'localhost' IDENTIFIED BY '"+password+"';")
	if err != nil {
		t.Fatal("fixture creation failed")
	}
	// Seed the old broad grant too: replacement must remove it, not merely
	// add a second literal grant while retaining the wildcard authority.
	if _, err := root(ctx, "GRANT SELECT,INSERT ON `"+name.String()+"`.* TO '"+user.String()+"'@'localhost';"); err != nil {
		t.Fatal("legacy grant fixture failed")
	}
	statement, err := grantStatements(grantMutation{Database: Database{Name: name}, Principal: DatabasePrincipal{Name: user, HostScope: HostScopeLoopback}, GrantSet: GrantSet{Grants: []Grant{{Scope: GrantScopeDatabase, Privileges: []Privilege{PrivilegeSelect, PrivilegeInsert}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = root(ctx, statement); err != nil {
		t.Fatal("native grants failed")
	}
	path := filepath.Join(t.TempDir(), "client.cnf")
	config := []byte("[client]\nuser=" + user.String() + "\npassword=" + password + "\n")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	wipeBytes(config)
	query := func(statement string) (string, error) {
		cmd := exec.CommandContext(ctx, mariaDBClientBinary, "--defaults-file="+path, "--protocol=socket", "--socket="+mariaDBSocket, "--batch", "--skip-column-names")
		cmd.Stdin = strings.NewReader(statement)
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	if got, err := query("SELECT id FROM `" + name.String() + "`.probe;"); err != nil || got != "7" {
		t.Fatal("intended database denied", err)
	}
	for _, statement := range []string{"SELECT id FROM `" + neighbor.String() + "`.probe;", "INSERT INTO `" + neighbor.String() + "`.probe VALUES(10);"} {
		if _, err := query(statement); err == nil {
			t.Error("database underscore grant escaped exact scope")
		}
	}
}
