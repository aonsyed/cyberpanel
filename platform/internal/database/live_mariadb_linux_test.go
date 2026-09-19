//go:build linux

package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// Database create/drop uses root Unix-socket authentication, not secret material.
// An unexpected secret request must fail rather than silently obtain credentials.
type liveDatabaseNoSecrets struct{ LinuxMariaDBSecretSource }

func TestQEMULiveMariaDBCreateReplayDelete(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_MARIADB") != "1" {
		t.Skip("requires disposable QEMU MariaDB guest")
	}
	if os.Geteuid() != 0 {
		t.Fatal("live executor requires root inside QEMU")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	instance, err := DefaultLocalInstance()
	if err != nil {
		t.Fatal(err)
	}
	distribution, err := DetectLinuxMariaDBDistribution()
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewLinuxMariaDBExecutor(liveDatabaseNoSecrets{}, distribution, []DatabaseInstance{instance})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "control.db")
	open := func() (*sql.DB, *SQLRepository) {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { db.Close() })
		repository, err := NewSQLRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
		return db, repository
	}
	handle, repository := open()
	if err := repository.EnsureBootstrapResources(ctx, instance); err != nil {
		t.Fatal(err)
	}
	token := fmt.Sprintf("%x", time.Now().UnixNano())
	id, _ := NewResourceID("qemu-live-" + token)
	name, _ := ParseSQLIdentifier("cp_qemu_" + token)
	tenant, _ := site.NewTenantID("qemu-live-tenant")
	siteID, _ := site.NewSiteID("qemu-live-site")
	charset, _ := ParseSQLIdentifier("utf8mb4")
	collation, _ := ParseSQLIdentifier("utf8mb4_unicode_ci")
	resource := Database{Metadata: Metadata{ID: id, TenantID: tenant, SiteID: siteID, Generation: 1, Status: instance.Status}, InstanceID: instance.ID, Name: name, Charset: charset, Collation: collation, QuotaBytes: 1 << 20}
	header := CommandHeader{CommandID: "qemu-create-" + token, TenantID: tenant, Actor: Actor{TenantID: tenant, Capability: CapabilityTenantManage}}
	create := CreateDatabase{Header: header, Database: resource}
	probe := func() string {
		t.Helper()
		command := exec.CommandContext(ctx, "/usr/bin/mariadb", "--no-defaults", "--protocol=socket", "--socket="+mariaDBSocket, "--user=root", "--batch", "--skip-column-names")
		command.Stdin = strings.NewReader("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + name.String() + "';")
		output, err := command.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(output))
	}
	if probe() != "" {
		t.Fatal("fixture database already exists; refusing to modify it")
	}
	coordinator := NewCoordinator(repository, executor, persistenceClock{})
	created, err := coordinator.Handle(ctx, create)
	if err != nil || created.Status != OperationApplied {
		t.Fatalf("create status=%s: %v", created.Status, err)
	}
	if probe() != name.String() {
		t.Fatal("applied receipt without actual MariaDB database")
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	_, repository = open()
	coordinator = NewCoordinator(repository, executor, persistenceClock{})
	replayed, err := coordinator.Handle(ctx, create)
	if err != nil || replayed.Status != OperationApplied || replayed.Effect.ProofDigest != created.Effect.ProofDigest {
		t.Fatalf("replay status=%s: %v", replayed.Status, err)
	}
	header.CommandID = "qemu-delete-" + token
	approval, _ := NewResourceID("qemu-disposable-fixture-" + token)
	remove := DeleteDatabase{Header: header, DatabaseID: id, ExpectedGeneration: 1, WaiveRecovery: true, ApprovalRef: approval}
	deleted, err := coordinator.Handle(ctx, remove)
	if err != nil || deleted.Status != OperationApplied {
		t.Fatalf("delete status=%s: %v; fixture %s retained for diagnosis", deleted.Status, err, name.String())
	}
	if probe() != "" {
		t.Fatal("applied delete receipt but database remains")
	}
	if receipt, err := coordinator.Handle(ctx, remove); err != nil || receipt.Status != OperationApplied {
		t.Fatalf("delete replay status=%s: %v", receipt.Status, err)
	}
	t.Log("real MariaDB create, SQLite reopen/replay, delete and delete replay verified; no secret-delivery claim")
}
