//go:build linux

package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQEMUTransferReplacementLifecycle(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_TRANSFER") != "1" {
		t.Skip("requires disposable native QEMU fixtures")
	}
	for _, phase := range []string{"success", "recover_before", "recover_after", "recover_released", "rollback_after", "unknown_layout", "unreconciled_fence"} {
		t.Run(phase, func(t *testing.T) { testQEMUTransferReplacementLifecycle(t, phase) })
	}
}

func testQEMUTransferReplacementLifecycle(t *testing.T, phase string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seed := make([]byte, 8)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	name := "qr" + hex.EncodeToString(seed)
	id := func(s string) ResourceID {
		v, e := NewResourceID(s)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	live := replacementFixtureDatabase(name)
	live.InstanceID = id("mariadb-local")
	live.Status.ObservedGeneration = 1
	p := DatabasePrincipal{Metadata: live.Metadata, InstanceID: live.InstanceID, Name: live.Name, HostScope: HostScopeLoopback}
	p.ID = id(name + "-principal")
	p.CredentialSecretRef, _ = NewSecretRef(name + "-secret")
	g := GrantSet{Metadata: live.Metadata, InstanceID: live.InstanceID, DatabaseID: live.ID, PrincipalID: p.ID, Grants: []Grant{{Scope: GrantScopeDatabase, Privileges: []Privilege{PrivilegeSelect, PrivilegeInsert}}}}
	g.ID = id(name + "-grants")
	args := []string{"--no-defaults", "--protocol=socket", "--socket=" + mariaDBSocket, "--user=root", "--batch", "--skip-column-names"}
	query := func(statement string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, mariaDBClientBinary, args...)
		cmd.Stdin = strings.NewReader(statement)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("native fixture: %v: %s", e, out)
		}
		return strings.TrimSpace(string(out))
	}
	query("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE TABLE `" + name + "`.sample(id INT PRIMARY KEY,body TEXT,raw_bytes BLOB) ENGINE=InnoDB; INSERT INTO `" + name + "`.sample VALUES(77,'original',X'00FF'); CREATE USER '" + name + "'@'localhost' IDENTIFIED BY 'fixture-password'; GRANT SELECT,INSERT ON `" + name + "`.* TO '" + name + "'@'localhost';")
	executor := &LinuxMariaDBExecutor{now: time.Now}
	if e := executor.initializeRoots(); e != nil {
		t.Fatal(e)
	}
	for kind, value := range map[string]Resource{"databases": live, "principals": p, "grants": g} {
		if e := executor.writeResource(kind, value.Meta().ID, value); e != nil {
			t.Fatal(e)
		}
	}
	var isolated IsolatedTransferDatabase
	var restore Database
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		script := "DROP USER IF EXISTS '" + name + "'@'localhost'; DROP DATABASE IF EXISTS `" + name + "`;"
		if !isolated.Name.IsZero() {
			script += "DROP DATABASE IF EXISTS " + quotedIdentifier(isolated.Name) + ";"
		}
		if !restore.Name.IsZero() {
			script += "DROP DATABASE IF EXISTS " + quotedIdentifier(restore.Name) + ";"
		}
		cmd := exec.CommandContext(cleanup, mariaDBClientBinary, args...)
		cmd.Stdin = strings.NewReader(script)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Errorf("cleanup: %v: %s", e, out)
		}
		for kind, key := range map[string]ResourceID{"databases": live.ID, "principals": p.ID, "grants": g.ID, "transfer-fences": live.ID} {
			if e := executor.removeResource(kind, key); e != nil {
				t.Error(e)
			}
		}
		if !isolated.Token.IsZero() {
			if e := executor.removeResource("transfer-imports", isolated.Token); e != nil {
				t.Error(e)
			}
		}
		if e := os.Remove(filepath.Join(mariaDBStateRoot, "transfer-fences", live.ID.String()+".lock")); e != nil && !os.IsNotExist(e) {
			t.Error(e)
		}
	})
	limits := TransferLimits{MaximumBytes: 1 << 20, MaximumRows: 100, MaximumDuration: time.Minute}
	point, e := executor.prepareReplacementRestorePoint(ctx, live, id(name+"-restore"), []ResourceID{g.ID}, limits)
	if e != nil {
		t.Fatal("restore point", e)
	}
	var fence transferWriterFence
	if e = executor.readResource("transfer-fences", live.ID, &fence); e != nil {
		t.Fatal(e)
	}
	restore = fence.Restore.Database
	if query("SELECT COUNT(*) FROM `"+name+"`.sample;") != "1" {
		t.Fatal("preparation changed original")
	}
	// Reconstructed management executor must honor the persisted native fence.
	reconstructed := &LinuxMariaDBExecutor{now: time.Now}
	instance, e := reconstructed.instance(live.InstanceID)
	if e != nil {
		t.Fatal(e)
	}
	connection, closeC, e := reconstructed.connection(ctx, instance)
	if e != nil {
		t.Fatal(e)
	}
	defer closeC()
	for statement, value := range map[mariaDBStatement]any{sqlDropDatabase: live, sqlDropPrincipal: p, sqlRotatePrincipal: principalMutation{Principal: p, Password: []byte("changed-fixture-password")}, sqlReplaceGrants: grantMutation{Database: live, Principal: p, GrantSet: g}} {
		if _, e = connection.query(ctx, statement, value); !errors.Is(e, ErrConflict) {
			t.Fatal("management bypassed fence", statement, e)
		}
	}
	now := time.Now().UTC()
	export := TransferJob{ID: id(name + "-export"), IdempotencyKey: name + "-export", TenantID: live.TenantID, SiteID: live.SiteID, DatabaseID: live.ID, DatabaseGeneration: 1, InstanceID: live.InstanceID, Direction: TransferExport, Format: TransferFormatSQL, Compression: TransferCompressionNone, Selection: TransferSelection{Schema: true, Data: true}, Limits: limits, ConflictPolicy: TransferConflictFail, Retention: TransferRetention{RetainUntil: now.Add(time.Hour)}, CreatedBy: "owner", CreatedAt: now, Impact: SealTransferImpactPreview(TransferImpactPreview{DatabaseID: live.ID, DatabaseGeneration: 1, Rows: 1, Bytes: 512, SchemaObjects: 1, CapturedAt: now})}
	artifact := WorkspaceExportArtifact(export)
	export.Destination = &artifact
	export, e = SealTransferJob(export)
	if e != nil {
		t.Fatal(e)
	}
	store, e := NewLinuxTransferArtifactStore(workspaceExportRoot, 1<<20, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	writer, e := store.BeginTransferArtifact(ctx, artifact, export.Format, export.Compression, export.Retention)
	if e != nil {
		t.Fatal(e)
	}
	data := []byte(transferSQLMagic + "CREATE TABLE `sample` (id INT PRIMARY KEY,body TEXT,raw_bytes BLOB) ENGINE=InnoDB; INSERT INTO `sample` VALUES(88,'replacement',X'112200'),(99,NULL,NULL);\n")
	if _, e = writer.Write(data); e != nil {
		t.Fatal(e)
	}
	descriptor, e := writer.Commit(ctx, transferDigest(data), uint64(len(data)), 2)
	if e != nil {
		t.Fatal(e)
	}
	artifactPath, _ := store.artifactPath(artifact)
	t.Cleanup(func() {
		if e := os.RemoveAll(artifactPath); e != nil {
			t.Error(e)
		}
	})
	job := export
	job.ID = id(name + "-import")
	job.IdempotencyKey = name + "-import"
	job.Direction = TransferImport
	job.Destination = nil
	job.Source = &descriptor
	job.ExportSource = &export
	job.ConflictPolicy = TransferConflictReplace
	job.RestorePointRef = point.Reference
	job.RestorePointDigest = point.ProofDigest
	job.RestorePointCreatedAt = point.CreatedAt
	job, e = SealTransferJob(job)
	if e != nil {
		t.Fatal(e)
	}
	request := TransferImportRequest{Action: "allocate", Job: job, SourceExport: export}
	if e = request.validate(); e != nil {
		t.Fatal("request validation", e)
	}
	if _, e = executor.transferImportSource(job); e != nil {
		t.Fatal("source authorization", e)
	}
	_, releaseContext, e := executor.replacementTransferContext(ctx, job, "allocate")
	if e != nil {
		t.Fatal("replacement context", e)
	}
	releaseContext()
	allocated, e := executor.ExecuteTransferImport(ctx, request)
	if e != nil {
		t.Fatal("allocate", e)
	}
	isolated = allocated.Isolated
	request.Isolated = &isolated
	for _, action := range []string{"load", "verify"} {
		request.Action = action
		if _, e = executor.ExecuteTransferImport(ctx, request); e != nil {
			t.Fatal(action, e)
		}
	}
	var record isolatedTransferRecord
	if e = executor.readResource("transfer-imports", isolated.Token, &record); e != nil {
		t.Fatal(e)
	}
	if phase == "recover_released" {
		request.Action = "promote"
		if _, e = executor.ExecuteTransferImport(ctx, request); e != nil {
			t.Fatal(e)
		}
		if e = executor.readResource("transfer-imports", isolated.Token, &record); e != nil {
			t.Fatal(e)
		}
		// Persist the boundary after native verification/release, before metadata
		// projection. No native contents or account state are changed here.
		record.State = "promotion-verified"
		if e = executor.writeResource("transfer-imports", isolated.Token, record); e != nil {
			t.Fatal(e)
		}
		if e = executor.writeResource("databases", live.ID, live); e != nil {
			t.Fatal(e)
		}
	}
	if phase != "success" && phase != "recover_released" {
		record.Replacement = &transferReplacementPlan{Restore: *fence.Restore, Before: live, Tables: []string{"sample"}}
		record.State = "replacement-moving"
		if e = executor.writeResource("transfer-imports", isolated.Token, record); e != nil {
			t.Fatal(e)
		}
		if e = executor.releaseTransferWriterFence(ctx, live.ID, point.Reference); !errors.Is(e, ErrAmbiguous) {
			t.Fatal("released unresolved native placement", e)
		}
		if phase == "recover_after" || phase == "rollback_after" {
			swap, e := transferReplacementRenameSQL(live, record.Target, restore, []string{"sample"}, []string{"sample"})
			if e != nil {
				t.Fatal(e)
			}
			query(swap)
		}
		if phase == "rollback_after" {
			record.State = "replacement-restoring"
			if e = executor.writeResource("transfer-imports", isolated.Token, record); e != nil {
				t.Fatal(e)
			}
		}
		if phase == "unknown_layout" {
			query("CREATE TABLE " + quotedIdentifier(restore.Name) + ".unplanned(id INT);")
		}
		if phase == "unreconciled_fence" {
			if e = executor.readResource("transfer-fences", live.ID, &fence); e != nil {
				t.Fatal(e)
			}
			fence.State = "acquiring"
			if e = executor.writeResource("transfer-fences", live.ID, fence); e != nil {
				t.Fatal(e)
			}
			if _, e = connection.query(ctx, sqlReplaceGrants, grantMutation{Database: live, Principal: p, GrantSet: g}); !errors.Is(e, ErrConflict) {
				t.Fatal("management bypassed acquiring fence", e)
			}
		}
	}
	controlPath := filepath.Join(t.TempDir(), "control.db")
	open := func() (*sql.DB, *SQLRepository) {
		db, e := sql.Open("sqlite", controlPath)
		if e != nil {
			t.Fatal(e)
		}
		db.SetMaxOpenConns(1)
		repository, e := NewSQLRepository(db)
		if e != nil {
			t.Fatal(e)
		}
		if e = repository.Bootstrap(ctx); e != nil {
			t.Fatal(e)
		}
		return db, repository
	}
	control, repository := open()
	if e = repository.EnsureBootstrapResources(ctx, live); e != nil {
		t.Fatal(e)
	}
	if e = control.Close(); e != nil {
		t.Fatal(e)
	}
	control, repository = open()
	defer control.Close()
	coordinator := NewCoordinator(repository, reconstructed, SystemClock{})
	request.Action = "promote"
	if phase == "success" {
		_, e = coordinator.PromoteDatabaseTransfer(ctx, request)
	} else {
		_, e = coordinator.RecoverDatabaseTransfer(ctx, job)
	}
	failed := phase == "unknown_layout" || phase == "unreconciled_fence"
	if failed {
		if e == nil {
			t.Fatal("unsafe recovery accepted")
		}
	} else if phase == "rollback_after" {
		if !errors.Is(e, ErrTransferCancelled) {
			t.Fatal("rollback recovery", e)
		}
	} else if e != nil {
		t.Fatal("promotion/recovery", e)
	}
	read := func(db Database) string {
		return query("SELECT CONCAT(id,':',COALESCE(body,'NULL'),':',COALESCE(HEX(raw_bytes),'NULL')) FROM " + quotedIdentifier(db.Name) + ".sample ORDER BY id;")
	}
	if failed || phase == "rollback_after" {
		if got := read(live); got != "77:original:00FF" {
			t.Fatal("original changed", got)
		}
		if got := read(record.Target); got != "88:replacement:112200\n99:NULL:NULL" {
			t.Fatal("candidate lost", got)
		}
		var generation int
		if e = control.QueryRowContext(ctx, "SELECT generation FROM panel_database_resources WHERE resource_id=?", live.ID.String()).Scan(&generation); e != nil || generation != 1 {
			t.Fatal("failed/rolled-back replacement published", generation, e)
		}
		if failed {
			if e = executor.readResource("transfer-fences", live.ID, &fence); e != nil || fence.State == "released" {
				t.Fatal("failed recovery released writers", e)
			}
		}
		if phase == "rollback_after" {
			if _, e = coordinator.RecoverDatabaseTransfer(ctx, job); !errors.Is(e, ErrTransferCancelled) {
				t.Fatal("rollback replay", e)
			}
		}
		return
	}
	if got := read(live); got != "88:replacement:112200\n99:NULL:NULL" {
		t.Fatal("new data differs", got)
	}
	if got := read(restore); got != "77:original:00FF" {
		t.Fatal("retained original differs", got)
	}
	if e = executor.readResource("transfer-fences", live.ID, &fence); e != nil || fence.State != "released" {
		t.Fatal("completed replacement did not restore admission", e)
	}
	if _, e = coordinator.PromoteDatabaseTransfer(ctx, request); e != nil {
		t.Fatal("coordinator receipt replay", e)
	}
	if _, e = executor.acquireTransferWriterFence(ctx, live, id(name+"-next"), []ResourceID{g.ID}, time.Second); !errors.Is(e, ErrConflict) {
		t.Fatal("retained recovery anchor overwritten", e)
	}
}
