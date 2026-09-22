//go:build linux

package database

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQEMUTransferScopedWriterFence(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_TRANSFER") != "1" {
		t.Skip("requires disposable QEMU accounts")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires QEMU root")
	}
	for _, mode := range []string{"drained", "interrupted", "previously_locked", "shared_account", "independent_writer", "definer_writer", "definer_view", "credential_drift"} {
		t.Run(mode, func(t *testing.T) { testQEMUTransferScopedWriterFence(t, mode) })
	}
}

func testQEMUTransferScopedWriterFence(t *testing.T, mode string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	seed := make([]byte, 8)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	name := "qf_" + hex.EncodeToString(seed)
	grantPattern := strings.ReplaceAll(name, "_", "\\_")
	id := func(s string) ResourceID {
		result, err := NewResourceID(s)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	db := replacementFixtureDatabase(name)
	db.InstanceID = id("mariadb-local")
	p := DatabasePrincipal{Metadata: db.Metadata, InstanceID: db.InstanceID, Name: db.Name, HostScope: HostScopeLoopback}
	p.ID = id(name + "-principal")
	p.CredentialSecretRef, _ = NewSecretRef(name + "-secret")
	g := GrantSet{Metadata: db.Metadata, InstanceID: db.InstanceID, DatabaseID: db.ID, PrincipalID: p.ID, Grants: []Grant{{Scope: GrantScopeDatabase, Privileges: []Privilege{PrivilegeSelect, PrivilegeInsert}}}}
	g.ID = id(name + "-grants")
	rootArgs := []string{"--no-defaults", "--protocol=socket", "--socket=" + mariaDBSocket, "--user=root", "--batch", "--skip-column-names", "--unbuffered"}
	query := func(statement string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, mariaDBClientBinary, rootArgs...)
		cmd.Stdin = strings.NewReader(statement)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("native fixture: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	query("CREATE DATABASE `" + name + "`; CREATE TABLE `" + name + "`.sample(id INT); INSERT INTO `" + name + "`.sample VALUES(77); CREATE USER '" + name + "'@'localhost' IDENTIFIED BY 'fixture-only-password'; GRANT SELECT,INSERT ON `" + grantPattern + "`.* TO '" + name + "'@'localhost';")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		cmd := exec.CommandContext(cleanup, mariaDBClientBinary, rootArgs...)
		cmd.Stdin = strings.NewReader("DROP USER IF EXISTS '" + name + "'@'localhost','" + name + "x'@'localhost'; DROP DATABASE IF EXISTS `" + name + "`; DROP DATABASE IF EXISTS `" + name + "x`;")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("cleanup: %v: %s", err, out)
		}
	})
	executor := &LinuxMariaDBExecutor{now: time.Now}
	if err := executor.initializeRoots(); err != nil {
		t.Fatal(err)
	}
	for kind, value := range map[string]Resource{"databases": db, "principals": p, "grants": g} {
		if err := executor.writeResource(kind, value.Meta().ID, value); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := executor.removeResource(kind, value.Meta().ID); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(func() {
		if err := executor.removeResource("transfer-fences", db.ID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Error(err)
		}
		if err := os.Remove(filepath.Join(mariaDBStateRoot, "transfer-fences", db.ID.String()+".lock")); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
	})
	config := filepath.Join(t.TempDir(), "client.cnf")
	if err := os.WriteFile(config, []byte("[client]\nuser="+name+"\npassword=fixture-only-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	clientArgs := []string{"--defaults-file=" + config, "--protocol=socket", "--socket=" + mariaDBSocket, "--batch", "--skip-column-names", "--unbuffered"}
	canWrite := func() bool {
		cmd := exec.CommandContext(ctx, mariaDBClientBinary, clientArgs...)
		cmd.Stdin = strings.NewReader("INSERT INTO `" + name + "`.sample VALUES(88);")
		return cmd.Run() == nil
	}
	if mode == "previously_locked" {
		query("ALTER USER '" + name + "'@'localhost' ACCOUNT LOCK;")
	}
	if mode == "shared_account" {
		query("CREATE DATABASE `" + name + "x`; GRANT SELECT,INSERT ON `" + grantPattern + "x`.* TO '" + name + "'@'localhost';")
	}
	if mode == "independent_writer" {
		query("CREATE USER '" + name + "x'@'localhost' IDENTIFIED BY 'fixture-only-password'; GRANT INSERT ON `" + grantPattern + "`.* TO '" + name + "x'@'localhost';")
	}
	if mode == "definer_writer" {
		query("CREATE DATABASE `" + name + "x`; CREATE PROCEDURE `" + name + "x`.write_target() SQL SECURITY DEFINER INSERT INTO `" + name + "`.sample VALUES(99);")
	}
	if mode == "definer_view" {
		query("CREATE DATABASE `" + name + "x`; CREATE SQL SECURITY DEFINER VIEW `" + name + "x`.write_target AS SELECT id FROM `" + name + "`.sample;")
	}
	if mode == "shared_account" || mode == "independent_writer" || mode == "definer_writer" || mode == "definer_view" {
		if record, err := executor.acquireTransferWriterFence(ctx, db, id(name+"-fence"), []ResourceID{g.ID}, time.Second); err == nil || record.State == "held" {
			t.Fatal("unscoped writer accepted", err)
		}
		if !canWrite() {
			t.Fatal("rejected fence changed original access")
		}
		return
	}
	var writer *exec.Cmd
	var input io.WriteCloser
	var sessionReader *bufio.Reader
	if mode == "drained" || mode == "interrupted" {
		writer = exec.CommandContext(ctx, mariaDBClientBinary, clientArgs...)
		var err error
		input, err = writer.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := writer.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err = writer.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = input.Close(); _ = writer.Wait() }()
		if _, err = io.WriteString(input, "SELECT 'connected';\n"); err != nil {
			t.Fatal(err)
		}
		sessionReader = bufio.NewReader(output)
		if line, err := sessionReader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "connected" {
			t.Fatal("fixture connection", err)
		}
	}
	type outcome struct {
		record transferWriterFence
		err    error
	}
	result := make(chan outcome, 1)
	drain := 4 * time.Second
	if mode == "interrupted" {
		drain = 150 * time.Millisecond
	}
	go func() {
		r, e := executor.acquireTransferWriterFence(ctx, db, id(name+"-fence"), []ResourceID{g.ID}, drain)
		result <- outcome{r, e}
	}()
	if writer != nil {
		for query("SELECT COALESCE(JSON_VALUE(Priv,'$.account_locked'),0) FROM mysql.global_priv WHERE User='"+name+"' AND Host='localhost';") != "1" {
			select {
			case got := <-result:
				t.Fatalf("acquisition before lock: %s, %v", got.record.State, got.err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		if canWrite() {
			t.Fatal("new writer admitted while acquiring")
		}
		if mode == "drained" {
			if _, err := io.WriteString(input, "INSERT INTO `"+name+"`.sample VALUES(66); SELECT 'written';\n"); err != nil {
				t.Fatal(err)
			}
			if line, err := sessionReader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "written" {
				t.Fatal("existing writer did not retain its session", err)
			}
			other := &LinuxMariaDBExecutor{now: time.Now}
			if _, err := other.acquireTransferWriterFence(ctx, db, id(name+"-other"), []ResourceID{g.ID}, time.Second); !errors.Is(err, ErrConflict) {
				t.Fatal("concurrent acquisition not fenced", err)
			}
			select {
			case got := <-result:
				t.Fatalf("held before existing session drained: %+v", got)
			default:
			}
			_ = input.Close()
			_ = writer.Wait()
		}
	}
	got := <-result
	if mode == "interrupted" {
		if got.err == nil || got.record.State != "acquiring" {
			t.Fatal("interruption published held fence", got.err)
		}
	} else if got.err != nil || got.record.State != "held" {
		t.Fatal("acquisition", got.record.State, got.err)
	}
	if canWrite() {
		t.Fatal("new writer admitted while held")
	}
	if got.record.Accounts[0].Grants == "" {
		t.Fatal("missing original grants")
	}
	if mode == "credential_drift" {
		query("ALTER USER '" + name + "'@'localhost' IDENTIFIED BY 'changed-fixture-password';")
	}
	// Reconstruct the executor. No in-memory lock/account state is reused.
	recovered := &LinuxMariaDBExecutor{now: time.Now}
	if _, err := recovered.acquireTransferWriterFence(ctx, db, id(name+"-other"), []ResourceID{g.ID}, time.Second); !errors.Is(err, ErrConflict) {
		t.Fatal("unreconciled journal reused", err)
	}
	err := recovered.releaseTransferWriterFence(ctx, db.ID, id(name+"-fence"))
	if mode == "credential_drift" {
		if !errors.Is(err, ErrAmbiguous) {
			t.Fatal("changed principal unlocked", err)
		}
		if query("SELECT COALESCE(JSON_VALUE(Priv,'$.account_locked'),0) FROM mysql.global_priv WHERE User='"+name+"' AND Host='localhost';") != "1" {
			t.Fatal("credential drift released admission")
		}
		return
	}
	if err != nil {
		t.Fatal("reconstructed release", err)
	}
	if canWrite() == (mode == "previously_locked") {
		t.Fatal("original admission state not restored")
	}
	var journal transferWriterFence
	if err = recovered.readResource("transfer-fences", db.ID, &journal); err != nil || journal.State != "released" {
		t.Fatal("release not durable", err)
	}
	if err = recovered.releaseTransferWriterFence(ctx, db.ID, id(name+"-fence")); err != nil {
		t.Fatal("release replay", err)
	}
	if mode == "drained" {
		if _, err = recovered.acquireTransferWriterFence(ctx, db, id(name+"-next"), []ResourceID{g.ID}, time.Second); err != nil {
			t.Fatal("next fence lifecycle", err)
		}
		if err = recovered.releaseTransferWriterFence(ctx, db.ID, id(name+"-fence")); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("old token released newer fence", err)
		}
		if canWrite() {
			t.Fatal("old token opened admission")
		}
		if err = recovered.releaseTransferWriterFence(ctx, db.ID, id(name+"-next")); err != nil {
			t.Fatal("next release", err)
		}
	}
	if query("SELECT COUNT(*) FROM `"+name+"`.sample WHERE id=77;") != "1" {
		t.Fatal("original rows changed")
	}
	if mode == "drained" && query("SELECT COUNT(*) FROM `"+name+"`.sample WHERE id=66;") != "1" {
		t.Fatal("in-flight writer data lost")
	}
}
