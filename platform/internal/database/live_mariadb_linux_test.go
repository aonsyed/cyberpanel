//go:build linux

package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// In-memory fixture replaces only secret delivery, never MariaDB execution.
type liveDatabaseSecrets struct {
	LinuxMariaDBSecretSource
	password []byte
	ref      SecretRef
}

func (source liveDatabaseSecrets) PrincipalPassword(_ context.Context, ref SecretRef, _ ResourceID, _, _ string) ([]byte, error) {
	if ref != source.ref {
		return nil, ErrUnauthorized
	}
	return append([]byte(nil), source.password...), nil
}

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
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	password := []byte(hex.EncodeToString(random))
	wipeBytes(random)
	defer wipeBytes(password)
	secretRef, _ := NewSecretRef("qemu-live-password")
	fixtureSecrets := &liveDatabaseSecrets{password: password, ref: secretRef}
	executor, err := NewLinuxMariaDBExecutor(fixtureSecrets, distribution, []DatabaseInstance{instance})
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
	principalID, _ := NewResourceID("qemu-user-" + token)
	principal := DatabasePrincipal{Metadata: resource.Metadata, InstanceID: instance.ID, Name: name, HostScope: HostScopeLoopback, CredentialSecretRef: secretRef}
	principal.ID = principalID
	header.CommandID = "qemu-principal-" + token
	if receipt, err := coordinator.Handle(ctx, CreatePrincipal{Header: header, Principal: principal}); err != nil || receipt.Status != OperationApplied {
		t.Fatalf("principal status=%s: %v", receipt.Status, err)
	}
	grantID, _ := NewResourceID("qemu-grants-" + token)
	grants := GrantSet{Metadata: resource.Metadata, InstanceID: instance.ID, DatabaseID: id, PrincipalID: principalID, Grants: []Grant{{Scope: GrantScopeDatabase, Privileges: []Privilege{PrivilegeSelect, PrivilegeCreate, PrivilegeInsert}}}}
	grants.ID = grantID
	header.CommandID = "qemu-grants-" + token
	if receipt, err := coordinator.Handle(ctx, ReplaceGrantSet{Header: header, GrantSet: grants}); err != nil || receipt.Status != OperationApplied {
		t.Fatalf("grants status=%s: %v", receipt.Status, err)
	}
	clientConfig := filepath.Join(t.TempDir(), "client.cnf")
	login := func(credential []byte, query string) (string, error) {
		t.Helper()
		config := []byte("[client]\nuser=" + name.String() + "\npassword=\"" + string(credential) + "\"\n")
		defer wipeBytes(config)
		if err := os.WriteFile(clientConfig, config, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "/usr/bin/mariadb", "--defaults-file="+clientConfig, "--protocol=socket", "--socket="+mariaDBSocket, "--batch", "--skip-column-names")
		command.Stdin = strings.NewReader(query)
		output, err := command.CombinedOutput()
		return strings.TrimSpace(string(output)), err
	}
	if output, err := login(password, "USE "+name.String()+"; CREATE TABLE probe (id INT); INSERT INTO probe VALUES (7); SELECT id FROM probe;"); err != nil || output != "7" {
		t.Fatalf("managed principal access: %v, output=%q", err, output)
	}
	if output, err := login([]byte("incorrect-fixture-password"), "SELECT 1;"); err == nil || !strings.Contains(output, "ERROR 1045") {
		t.Fatalf("wrong password was not rejected as authentication failure: %v", err)
	}
	if output, err := login(password, "SELECT User FROM mysql.user;"); err == nil || !(strings.Contains(output, "ERROR 1142") || strings.Contains(output, "ERROR 1044")) {
		t.Fatalf("principal escaped database grants: %v", err)
	}
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	rotatedPassword := []byte(hex.EncodeToString(random))
	wipeBytes(random)
	defer wipeBytes(rotatedPassword)
	rotatedRef, _ := NewSecretRef("qemu-live-rotated-password")
	fixtureSecrets.password, fixtureSecrets.ref = rotatedPassword, rotatedRef
	header.CommandID = "qemu-rotate-principal-" + token
	if receipt, err := coordinator.Handle(ctx, RotatePrincipalPassword{Header: header, PrincipalID: principalID, ExpectedGeneration: 1, NewSecretRef: rotatedRef}); err != nil || receipt.Status != OperationApplied {
		t.Fatalf("password rotation status=%s: %v", receipt.Status, err)
	}
	if output, err := login(password, "SELECT 1;"); err == nil || !strings.Contains(output, "ERROR 1045") {
		t.Fatalf("old password remains valid: %v", err)
	}
	if output, err := login(rotatedPassword, "USE "+name.String()+"; SELECT id FROM probe;"); err != nil || output != "7" {
		t.Fatalf("rotated password access: %v", err)
	}
	header.CommandID = "qemu-drop-principal-" + token
	if receipt, err := coordinator.Handle(ctx, DeletePrincipal{Header: header, PrincipalID: principalID, ExpectedGeneration: 2}); err != nil || receipt.Status != OperationApplied {
		t.Fatalf("principal removal status=%s: %v", receipt.Status, err)
	}
	if output, err := login(rotatedPassword, "SELECT 1;"); err == nil || !(strings.Contains(output, "ERROR 1045") || strings.Contains(output, "ERROR 1698")) {
		t.Fatalf("removed principal authentication result: %v, output=%q", err, output)
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
	t.Log("real MariaDB create/replay, principal login, scoped grants, wrong-password rejection, account removal and database deletion verified; no secret-delivery claim")
}
