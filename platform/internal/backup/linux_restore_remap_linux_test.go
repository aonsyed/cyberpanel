//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const linuxBackupRemapFixtureDump = `-- MySQL dump 10.19
--
-- Host: localhost    Database: fixture_src
-- ------------------------------------------------------
/*!40103 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40000 DROP DATABASE IF EXISTS ` + "`fixture_src`" + `*/;
CREATE DATABASE /*!32312 IF NOT EXISTS*/ ` + "`fixture_src`" + ` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;
USE ` + "`fixture_src`" + `;
/*!40101 SET @saved_cs_client = @@character_set_client */;
DROP TABLE IF EXISTS ` + "`probe`" + `;
CREATE TABLE ` + "`probe`" + ` (id INT PRIMARY KEY, note TEXT);
INSERT INTO ` + "`probe`" + ` VALUES (1,'references fixture_src by string only');
-- Dump completed
`

func writeLinuxBackupRemapFixture(t *testing.T, body string) string {
	t.Helper()
	root := linuxBackupRemapTestRoot(t)
	path := filepath.Join(root, "dump.sql")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// linuxBackupRemapTestRoot returns a private scratch directory matching the
// runtime's own 0700 root-owned directory boundary.
func linuxBackupRemapTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLinuxBackupDumpDatabasesParsesDatabaseStatements(t *testing.T) {
	names, err := linuxBackupDumpDatabases(writeLinuxBackupRemapFixture(t, linuxBackupRemapFixtureDump))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "fixture_src" {
		t.Fatalf("names: %v", names)
	}
}

func TestLinuxBackupRemapRewritesDatabaseStatementsOnly(t *testing.T) {
	dump := writeLinuxBackupRemapFixture(t, linuxBackupRemapFixtureDump)
	target := filepath.Join(linuxBackupRemapTestRoot(t), "remapped.sql")
	remap := map[string]string{"fixture_src": "fixture_dst"}
	if err := rewriteLinuxBackupDump(dump, target, remap); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, statement := range []string{"DROP DATABASE IF EXISTS `fixture_dst`", "CREATE DATABASE /*!32312 IF NOT EXISTS*/ `fixture_dst`", "USE `fixture_dst`"} {
		if !strings.Contains(text, statement) {
			t.Fatalf("rewritten dump missing %q", statement)
		}
	}
	if !strings.Contains(text, "CREATE TABLE `probe`") {
		t.Fatal("table identifiers must survive untouched")
	}
	if strings.Contains(text, "`fixture_src`") {
		t.Fatal("source name survived outside comments")
	}
	if !strings.Contains(text, "'references fixture_src by string only'") {
		t.Fatal("string literal must not be rewritten")
	}
}

func TestLinuxBackupRemapFailsClosedOnQualifiedBodyReference(t *testing.T) {
	dangerous := strings.Replace(linuxBackupRemapFixtureDump,
		"INSERT INTO `probe` VALUES (1,'references fixture_src by string only');",
		"INSERT INTO `fixture_src`.`probe` VALUES (1,'qualified');", 1)
	dump := writeLinuxBackupRemapFixture(t, dangerous)
	target := filepath.Join(linuxBackupRemapTestRoot(t), "remapped.sql")
	if err := rewriteLinuxBackupDump(dump, target, map[string]string{"fixture_src": "fixture_dst"}); err == nil {
		t.Fatal("qualified body reference must fail closed")
	}
	if _, statErr := os.Lstat(target); statErr == nil {
		t.Fatal("failed rewrite must not leave an artifact")
	}
}

func TestLinuxBackupRemappedDatabaseNameIsDeterministicAndUnique(t *testing.T) {
	first, err := linuxBackupRemappedDatabaseName("fixture_src", "site-target")
	if err != nil {
		t.Fatal(err)
	}
	second, err := linuxBackupRemappedDatabaseName("fixture_src", "site-target")
	if err != nil || first != second {
		t.Fatalf("naming not deterministic: %q %q %v", first, second, err)
	}
	otherScope, err := linuxBackupRemappedDatabaseName("fixture_src", "site-other")
	if err != nil || strings.EqualFold(otherScope, first) {
		t.Fatalf("naming must differ per destination scope: %q %q %v", first, otherScope, err)
	}
	if strings.EqualFold(first, "fixture_src") {
		t.Fatal("remapped name must never equal the source name")
	}
	long := strings.Repeat("a", 80)
	capped, err := linuxBackupRemappedDatabaseName(long, "site-target")
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) > 64 {
		t.Fatalf("remapped name exceeds the MariaDB limit: %d", len(capped))
	}
}

func TestLinuxBackupRemapPlanRejectsClaimedNames(t *testing.T) {
	remap, err := linuxBackupDatabaseRemapPlan([]string{"fixture_a", "fixture_b"}, "site-target", map[string]bool{"mysql": true}, map[string]bool{})
	if err != nil || len(remap) != 2 {
		t.Fatalf("clean plan: %v %v", remap, err)
	}
	first := remap["fixture_a"]
	if strings.EqualFold(first, remap["fixture_b"]) {
		t.Fatal("distinct sources must map to distinct targets")
	}
	if _, err = linuxBackupDatabaseRemapPlan([]string{"fixture_a"}, "site-target", map[string]bool{strings.ToLower(first): true}, map[string]bool{}); err == nil {
		t.Fatal("physically claimed target name must fail closed")
	}
	if _, err = linuxBackupDatabaseRemapPlan([]string{"fixture_a"}, "site-target", map[string]bool{}, map[string]bool{strings.ToLower(first): true}); err == nil {
		t.Fatal("registry-claimed target name must fail closed")
	}
}

func TestNativeCrossScopeDatabaseRemapRestore(t *testing.T) {
	if os.Getenv("CYBERPANEL_NATIVE_BACKUP_TEST") != "1" {
		t.Skip("requires QEMU MariaDB")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root QEMU fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id := fmt.Sprintf("restore_xscope_%d", time.Now().UnixNano())
	sourceSite, targetSite := id+"_site_a", id+"_site_b"
	sourceDatabase := id + "_src"
	mariadb := func(sql string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, "/usr/bin/mariadb", "--protocol=socket", "--user=root", "--skip-column-names", "--batch", "--execute="+sql).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture mariadb: %v: %s", err, output)
		}
		return string(output)
	}
	mariadb("CREATE DATABASE `" + sourceDatabase + "`; CREATE TABLE `" + sourceDatabase + "`.proof (id INT PRIMARY KEY, note TEXT); INSERT INTO `" + sourceDatabase + "`.proof VALUES (1,'cross scope drill')")
	registryRecords := []string{
		filepath.Join(linuxBackupDatabaseStateRoot, "dbsrc-"+id+".json"),
		filepath.Join(linuxBackupDatabaseStateRoot, "dbtgt-"+id+".json"),
	}
	sourceRecord := fmt.Sprintf(`{"id":"dbsrc-%s","tenant_id":%q,"site_id":%q,"generation":1,"status":{"lifecycle":"provisioning","health":"unknown","reconciliation":"pending"},"instance_id":"mariadb-local","name":%q,"charset":"utf8mb4","collation":"utf8mb4_unicode_ci","quota_bytes":10485760}`, id, id, sourceSite, sourceDatabase)
	targetRecord := fmt.Sprintf(`{"id":"dbtgt-%s","tenant_id":%q,"site_id":%q,"generation":1,"status":{"lifecycle":"provisioning","health":"unknown","reconciliation":"pending"},"instance_id":"mariadb-local","name":%q,"charset":"utf8mb4","collation":"utf8mb4_unicode_ci","quota_bytes":10485760}`, id, id, targetSite, id+"_existing")
	for record, body := range map[string]string{registryRecords[0]: sourceRecord, registryRecords[1]: targetRecord} {
		if err := os.WriteFile(record, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = exec.Command("/usr/bin/mariadb", "--protocol=socket", "--user=root", "--execute=DROP DATABASE IF EXISTS `"+sourceDatabase+"`").CombinedOutput()
		for _, record := range registryRecords {
			_ = os.Remove(record)
		}
	})
	hostRoot := linuxBackupRemapTestRoot(t)
	host := &LinuxBackupHost{Root: hostRoot, Now: time.Now, Resolver: LinuxBackupSiteResolverFunc(func(context.Context, string, string) (LinuxBackupSiteBinding, error) {
		return LinuxBackupSiteBinding{SiteKey: id + "_key_b", SiteID: targetSite, TenantID: id, Generation: 1, UID: 1000, GID: 1000}, nil
	})}
	sourceBinding := LinuxBackupSiteBinding{SiteKey: id + "_key_a", SiteID: sourceSite, TenantID: id, Generation: 1, UID: 1000, GID: 1000}
	dump := filepath.Join(linuxBackupRemapTestRoot(t), "capture.sql")
	if err := host.captureDatabase(ctx, sourceBinding, dump); err != nil {
		t.Fatal(err)
	}
	plan := RestorePlanSpec{ID: RestoreID(id), TenantID: id, SourceScope: sourceSite, TargetScope: targetSite, CollisionPolicy: CollisionReplaceBlueGreen, SecretPolicy: SecretResetRequired, ComponentMapping: map[ComponentKind]string{ComponentDatabase: targetSite}}
	state := linuxRestoreState{RecoveryVersion: 1, PlanDigest: nativeRestorePlanDigest(plan), PlanID: plan.ID, TenantID: plan.TenantID, TargetScope: plan.TargetScope, ScratchID: "scratch", Watermark: 1}
	remap, err := host.crossScopeDatabaseRemap(ctx, plan, &state, dump)
	if err != nil {
		t.Fatal(err)
	}
	if len(remap) != 1 || remap[sourceDatabase] == "" || strings.EqualFold(remap[sourceDatabase], sourceDatabase) {
		t.Fatalf("remap: %v", remap)
	}
	restored := remap[sourceDatabase]
	if strings.EqualFold(restored, id+"_existing") {
		t.Fatal("remapped name collides with an existing target-scope database")
	}
	if err = host.importDatabase(ctx, dump, remap); err != nil {
		t.Fatal(err)
	}
	if row := mariadb("SELECT note FROM `" + restored + "`.proof WHERE id=1"); strings.TrimSpace(row) != "cross scope drill" {
		t.Fatalf("restored row missing: %q", row)
	}
	if row := mariadb("SELECT note FROM `" + sourceDatabase + "`.proof WHERE id=1"); strings.TrimSpace(row) != "cross scope drill" {
		t.Fatalf("source database was mutated: %q", row)
	}
	if err = host.registerRestoredDatabases(ctx, plan, LinuxBackupSiteBinding{SiteKey: id + "_key_b", SiteID: targetSite, TenantID: id, Generation: 1, UID: 1000, GID: 1000}, remap, &state); err != nil {
		t.Fatal(err)
	}
	names, err := linuxBackupDatabaseNames(LinuxBackupSiteBinding{SiteKey: id + "_key_b", SiteID: targetSite, TenantID: id})
	if err != nil {
		t.Fatal(err)
	}
	ownsRestored, ownsSource := false, false
	for _, name := range names {
		if name == restored {
			ownsRestored = true
		}
		if name == sourceDatabase {
			ownsSource = true
		}
	}
	if !ownsRestored || ownsSource {
		t.Fatalf("target scope must own the restored database only: %v", names)
	}
	// Retry reuses the persisted mapping instead of allocating a second name.
	again, err := host.crossScopeDatabaseRemap(ctx, plan, &state, dump)
	if err != nil || len(again) != 1 || again[sourceDatabase] != restored {
		t.Fatalf("remap retry: %v %v", again, err)
	}
	if err = host.dropRestoredDatabases(ctx, &state); err != nil {
		t.Fatal(err)
	}
	if databases := mariadb("SHOW DATABASES"); strings.Contains(databases, restored) {
		t.Fatal("rollback left the remapped database behind")
	}
	for _, record := range state.RestoredDatabaseRecords {
		if _, statErr := os.Lstat(record); statErr == nil {
			t.Fatalf("rollback left registry record %s behind", record)
		}
	}
	if row := mariadb("SELECT note FROM `" + sourceDatabase + "`.proof WHERE id=1"); strings.TrimSpace(row) != "cross scope drill" {
		t.Fatalf("source database damaged by rollback: %q", row)
	}
}

func TestNativeCrossScopeDatabasePromoteRemapsAndPersists(t *testing.T) {
	if os.Getenv("CYBERPANEL_NATIVE_BACKUP_TEST") != "1" {
		t.Skip("requires QEMU MariaDB")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root QEMU fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id := fmt.Sprintf("restore_promote_%d", time.Now().UnixNano())
	sourceSite, targetSite := id+"_site_a", id+"_site_b"
	sourceDatabase := id + "_src"
	mariadb := func(sql string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, "/usr/bin/mariadb", "--protocol=socket", "--user=root", "--skip-column-names", "--batch", "--execute="+sql).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture mariadb: %v: %s", err, output)
		}
		return string(output)
	}
	mariadb("CREATE DATABASE `" + sourceDatabase + "`; CREATE TABLE `" + sourceDatabase + "`.proof (id INT PRIMARY KEY, note TEXT); INSERT INTO `" + sourceDatabase + "`.proof VALUES (1,'promoted drill')")
	mariadb("CREATE DATABASE `" + id + "_existing`")
	sourceRecord := filepath.Join(linuxBackupDatabaseStateRoot, "dbsrc-"+id+".json")
	targetRecord := filepath.Join(linuxBackupDatabaseStateRoot, "dbtgt-"+id+".json")
	if err := os.WriteFile(sourceRecord, []byte(fmt.Sprintf(`{"id":"dbsrc-%s","tenant_id":%q,"site_id":%q,"generation":1,"status":{"lifecycle":"provisioning","health":"unknown","reconciliation":"pending"},"instance_id":"mariadb-local","name":%q,"charset":"utf8mb4","collation":"utf8mb4_unicode_ci","quota_bytes":10485760}`, id, id, sourceSite, sourceDatabase)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetRecord, []byte(fmt.Sprintf(`{"id":"dbtgt-%s","tenant_id":%q,"site_id":%q,"generation":1,"status":{"lifecycle":"provisioning","health":"unknown","reconciliation":"pending"},"instance_id":"mariadb-local","name":%q,"charset":"utf8mb4","collation":"utf8mb4_unicode_ci","quota_bytes":10485760}`, id, id, targetSite, id+"_existing")), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = exec.Command("/usr/bin/mariadb", "--protocol=socket", "--user=root", "--execute=DROP DATABASE IF EXISTS `"+sourceDatabase+"`;DROP DATABASE IF EXISTS `"+id+"_existing`").CombinedOutput()
		_ = os.Remove(sourceRecord)
		_ = os.Remove(targetRecord)
	})
	hostRoot := linuxBackupRemapTestRoot(t)
	host := &LinuxBackupHost{Root: hostRoot, Now: time.Now, Resolver: LinuxBackupSiteResolverFunc(func(context.Context, string, string) (LinuxBackupSiteBinding, error) {
		return LinuxBackupSiteBinding{SiteKey: id + "_key_b", SiteID: targetSite, TenantID: id, Generation: 1, UID: 1000, GID: 1000}, nil
	})}
	dump := filepath.Join(linuxBackupRemapTestRoot(t), "capture.sql")
	if err := host.captureDatabase(ctx, LinuxBackupSiteBinding{SiteKey: id + "_key_a", SiteID: sourceSite, TenantID: id, Generation: 1, UID: 1000, GID: 1000}, dump); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	artifact := ArtifactManifest{ID: ArtifactID(linuxBackupID("artifact", id, string(ComponentDatabase), hex.EncodeToString(digest[:]))), Component: ComponentDatabase, ObjectCount: 1, Bytes: uint64(len(raw)), RootDigest: func() string { rootHash := sha256.New(); rootHash.Write([]byte("site/database.sql")); rootHash.Write([]byte{0}); rootHash.Write([]byte(hex.EncodeToString(digest[:]))); rootHash.Write([]byte{0}); return hex.EncodeToString(rootHash.Sum(nil)) }(), Tool: "mariadb-dump-v1", SchemaVersion: 1, SourceGeneration: 1, Consistency: ConsistencyFuzzy, Objects: []ObjectDescriptor{{Key: "site/database.sql", Digest: hex.EncodeToString(digest[:]), Size: uint64(len(raw))}}}
	manifest := RecoveryPointManifest{RecoveryPointID: RecoveryPointID(id + "_point"), PolicyID: "policy", TenantID: id, Scope: sourceSite, WriteFrontier: 1, SourceGeneration: 1, CreatedAt: time.Now().UTC(), Artifacts: []ArtifactManifest{artifact}, RequiredComponents: []ComponentKind{ComponentDatabase}}
	manifest.ManifestDigest, err = RecoveryPointDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	plan := RestorePlanSpec{ID: RestoreID(id), IdempotencyKey: id, TenantID: id, RecoveryPointID: manifest.RecoveryPointID, SourceScope: sourceSite, TargetScope: targetSite, CollisionPolicy: CollisionReplaceBlueGreen, SecretPolicy: SecretResetRequired, ComponentMapping: map[ComponentKind]string{ComponentDatabase: targetSite}, RequiredFreeBytes: 1 << 20, Generation: 1}
	root := host.restoreRoot(plan)
	componentRoot := filepath.Join(root, "scratch", string(ComponentDatabase))
	for _, directory := range []string{root, componentRoot} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(componentRoot, "object-0"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeLinuxBackupJSON(filepath.Join(componentRoot, "artifact.json"), artifact); err != nil {
		t.Fatal(err)
	}
	if err := writeLinuxBackupJSON(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	state := linuxRestoreState{RecoveryVersion: 1, PlanDigest: nativeRestorePlanDigest(plan), PlanID: plan.ID, TenantID: plan.TenantID, TargetScope: plan.TargetScope, ScratchID: "scratch", Watermark: 1, Frozen: true}
	if err := writeLinuxBackupJSON(filepath.Join(root, "state.json"), state); err != nil {
		t.Fatal(err)
	}
	if _, err = host.Promote(ctx, plan, "scratch", id); err != nil {
		t.Fatalf("cross-scope promote: %v", err)
	}
	var persisted linuxRestoreState
	if err = readLinuxBackupJSON(filepath.Join(root, "state.json"), &persisted); err != nil {
		t.Fatal(err)
	}
	if !persisted.Promoted || len(persisted.DatabaseRemap) != 1 || len(persisted.RestoredDatabaseRecords) != 1 {
		t.Fatalf("promote state: remap=%v records=%v promoted=%v", persisted.DatabaseRemap, persisted.RestoredDatabaseRecords, persisted.Promoted)
	}
	restored := persisted.DatabaseRemap[sourceDatabase]
	if restored == "" || strings.EqualFold(restored, sourceDatabase) {
		t.Fatalf("remap: %v", persisted.DatabaseRemap)
	}
	if row := mariadb("SELECT note FROM `" + restored + "`.proof WHERE id=1"); strings.TrimSpace(row) != "promoted drill" {
		t.Fatalf("promoted row missing: %q", row)
	}
	if row := mariadb("SELECT note FROM `" + sourceDatabase + "`.proof WHERE id=1"); strings.TrimSpace(row) != "promoted drill" {
		t.Fatalf("source database mutated by promote: %q", row)
	}
	// A completed promote is terminal at the host boundary; retries reconcile
	// through the coordinator, not by re-promoting the same scratch.
	if _, err = host.Promote(ctx, plan, "scratch", id); err == nil {
		t.Fatal("re-promotion of a completed scratch must conflict")
	}
	if err = host.dropRestoredDatabases(ctx, &persisted); err != nil {
		t.Fatal(err)
	}
	if databases := mariadb("SHOW DATABASES"); strings.Contains(databases, restored) {
		t.Fatal("cleanup left the remapped database behind")
	}
	for _, record := range persisted.RestoredDatabaseRecords {
		_ = os.Remove(record)
	}
}
