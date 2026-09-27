//go:build linux

package database

import (
 "context"
 "crypto/rand"
 "encoding/hex"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// INVOKER routines now travel inside the SQL artifact and survive the full
// export → upload/import → verification → promotion pipeline. Triggers and
// events remain explicitly unsupported and must fail closed.
func TestQEMUTransferNativeRoutines(t *testing.T) {
 if os.Getenv("CYBERPANEL_QEMU_LIVE_TRANSFER_OBJECTS") != "1" {
  t.Skip("requires disposable QEMU MariaDB program-object qualification")
 }
 if os.Geteuid() != 0 {
  t.Fatal("requires root inside QEMU")
 }
 ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
 defer cancel()
 random := make([]byte, 8)
 if _, err := rand.Read(random); err != nil {
  t.Fatal(err)
 }
 prefix := "qemu_routine_" + hex.EncodeToString(random)
 source, _ := ParseSQLIdentifier(prefix + "_src")
 target, _ := ParseSQLIdentifier(prefix + "_dst")
 query := func(ctx context.Context, statement string) (string, error) {
  cmd := exec.CommandContext(ctx, mariaDBClientBinary, "--protocol=socket", "--socket="+mariaDBSocket, "--user=root", "--batch", "--skip-column-names")
  cmd.Stdin = strings.NewReader(statement)
  out, err := cmd.Output()
  return strings.TrimSpace(string(out)), err
 }
 defer func() {
  cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
  defer cancel()
  if _, err := query(cleanup, "DROP DATABASE IF EXISTS `"+source.String()+"`; DROP DATABASE IF EXISTS `"+target.String()+"`;"); err != nil {
   t.Error("fixture cleanup failed")
  }
  if remaining, err := query(cleanup, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE '"+prefix+"%';"); err != nil || remaining != "0" {
   t.Error("routine fixture schemas remain", remaining, err)
  }
 }()
 if _, err := query(ctx, "CREATE DATABASE `"+source.String()+"`; CREATE DATABASE `"+target.String()+"`; CREATE TABLE `"+source.String()+"`.sample(id INT PRIMARY KEY, body TEXT) ENGINE=InnoDB; INSERT INTO `"+source.String()+"`.sample VALUES(1,'routine round trip');"); err != nil {
  t.Fatal("fixture setup failed", err)
 }
 if _, err := query(ctx, "CREATE PROCEDURE `"+source.String()+"`.sample_procedure() SQL SECURITY INVOKER SELECT body FROM `"+source.String()+"`.sample WHERE id=1;"); err != nil {
  t.Fatal("procedure fixture", err)
 }
 if _, err := query(ctx, "CREATE FUNCTION `"+source.String()+"`.sample_function() RETURNS INT DETERMINISTIC SQL SECURITY INVOKER RETURN 7;"); err != nil {
  t.Fatal("function fixture", err)
 }
 if err := ensureRootDirectory(strings.TrimSuffix(transferConfigDirectory, "/"), 0700); err != nil {
  t.Fatal(err)
 }
 configDir, err := os.MkdirTemp(transferConfigDirectory, "routine-")
 if err != nil {
  t.Fatal(err)
 }
 defer os.RemoveAll(configDir)
 configPath := filepath.Join(configDir, "client.cnf")
 importUser := "qemu_rimp_" + hex.EncodeToString(random)
 passwordBytes := make([]byte, 32)
 if _, err = rand.Read(passwordBytes); err != nil {
  t.Fatal(err)
 }
 defer wipeBytes(passwordBytes)
 password := hex.EncodeToString(passwordBytes)
 // The production isolated resolver grants CREATE ROUTINE to the scoped
 // loader; the direct-import fixture mirrors that grant exactly.
 if _, err = query(ctx, "CREATE USER '"+importUser+"'@'localhost' IDENTIFIED BY '"+password+"'; GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,CREATE VIEW,ALTER,INDEX,DROP,LOCK TABLES,CREATE ROUTINE ON `"+target.String()+"`.* TO '"+importUser+"'@'localhost';"); err != nil {
  t.Fatal("scoped import account setup failed", err)
 }
 t.Cleanup(func() {
  cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
  defer cancel()
  if _, err := query(cleanup, "DROP USER IF EXISTS '"+importUser+"'@'localhost';"); err != nil {
   t.Error("import account cleanup failed")
  }
 })
 if err = os.WriteFile(configPath, []byte("[client]\nuser="+importUser+"\npassword="+password+"\nlocal-infile=0\n"), 0600); err != nil {
  t.Fatal(err)
 }
 store, err := NewLinuxTransferArtifactStore(workspaceExportRoot, 1<<20, time.Now)
 if err != nil {
  t.Fatal(err)
 }
 id := func(value string) ResourceID {
  result, err := NewResourceID(value)
  if err != nil {
   t.Fatal(err)
  }
  return result
 }
 tenant, _ := site.NewTenantID("qemu-routine-tenant")
 siteID, _ := site.NewSiteID("qemu-routine-site")
 backend, err := NewLinuxTransferBackend(store, liveTransferConfigs{configPath, id("routine-token")}, time.Now)
 if err != nil {
  t.Fatal(err)
 }
 now := time.Now().UTC()
 job := TransferJob{ID: id("routine-job"), IdempotencyKey: "routine", TenantID: tenant, SiteID: siteID, DatabaseID: id(prefix + "-database"), DatabaseGeneration: 1, InstanceID: id("mariadb-local"), Direction: TransferExport, Format: TransferFormatSQL, Compression: TransferCompressionNone, Selection: TransferSelection{Schema: true, Data: true}, Limits: TransferLimits{MaximumBytes: 1 << 20, MaximumRows: 100, MaximumDuration: time.Minute}, ConflictPolicy: TransferConflictFail, Retention: TransferRetention{RetainUntil: now.Add(time.Hour)}, CreatedBy: "fixture-user", CreatedAt: now}
 job.Impact = SealTransferImpactPreview(TransferImpactPreview{DatabaseID: job.DatabaseID, DatabaseGeneration: 1, SchemaObjects: 3, Rows: 1, Bytes: 2048, CapturedAt: now})
 artifact := WorkspaceExportArtifact(job)
 job.Destination = &artifact
 if job, err = SealTransferJob(job); err != nil {
  t.Fatal(err)
 }
 exportConfigs := liveWorkspaceExportFixture(t, ctx, prefix, job, source, query)
 exportClient := liveExportBroker(t, ctx, exportConfigs.executor)
 coordinator := NewCoordinator(liveExportRepository{executor: exportConfigs.executor}, exportClient, liveExportClock{})
 call := WorkspaceCall{TenantID: tenant, SiteID: siteID, SessionID: exportConfigs.access.SessionID, SessionGeneration: exportConfigs.access.SessionGeneration}
 prepared, err := coordinator.PrepareWorkspaceExport(ctx, call, "fixture-user", "routine-prepare", WorkspaceExportOptions{Compression: TransferCompressionNone, Selection: TransferSelection{Schema: true, Data: true}})
 if err != nil {
  t.Fatal("routine export preview rejected", err)
 }
 for _, unsupported := range []struct{ name, create, drop string }{
  {"trigger", "CREATE TRIGGER `" + source.String() + "`.sample_insert BEFORE INSERT ON `" + source.String() + "`.sample FOR EACH ROW SET NEW.body=CONCAT('trigger:',NEW.body)", "DROP TRIGGER `" + source.String() + "`.sample_insert"},
  {"event", "CREATE EVENT `" + source.String() + "`.sample_event ON SCHEDULE EVERY 1 DAY DISABLE DO SET @fixture_event=1", "DROP EVENT `" + source.String() + "`.sample_event"},
  {"view_combination", "CREATE SQL SECURITY INVOKER VIEW `" + source.String() + "`.`routine_view` AS SELECT id FROM `" + source.String() + "`.sample", "DROP VIEW `" + source.String() + "`.`routine_view`"},
 } {
  if _, err = query(ctx, unsupported.create+";"); err != nil {
   t.Fatal(unsupported.name, err)
  }
  _, previewErr := coordinator.PrepareWorkspaceExport(ctx, call, "fixture-user", "unsupported-"+unsupported.name, WorkspaceExportOptions{Compression: TransferCompressionNone, Selection: TransferSelection{Schema: true, Data: true}})
  if !errors.Is(previewErr, ErrTransferUnsupportedObjects) {
   t.Fatal("unsupported object accepted in preview", unsupported.name, previewErr)
  }
  if _, err = query(ctx, unsupported.drop+";"); err != nil {
   t.Fatal(unsupported.name, err)
  }
 }
 // A rejected preview must not strand the single-slot workspace credential.
 if _, err = coordinator.PrepareWorkspaceExport(ctx, call, "fixture-user", "routine-prepare-after-rejections", WorkspaceExportOptions{Compression: TransferCompressionNone, Selection: TransferSelection{Schema: true, Data: true}}); err != nil {
  t.Fatal("workspace slot stranded by rejected previews", err)
 }
 job = prepared
 job.Destination = nil
 artifact = WorkspaceExportArtifact(job)
 job.Destination = &artifact
 if job, err = SealTransferJob(job); err != nil {
  t.Fatal(err)
 }
 artifactPath, err := store.artifactPath(artifact)
 if err != nil {
  t.Fatal(err)
 }
 t.Cleanup(func() {
  if err := os.RemoveAll(artifactPath); err != nil {
   t.Error("artifact cleanup", err)
  }
 })
 receipt, err := coordinator.RunWorkspaceExport(ctx, call, "fixture-user", job)
 if err != nil {
  t.Fatalf("routine export failed: %v (exit %d)", err, receipt.ExitCode)
 }
 var raw []byte
 read := WorkspaceExportReadRequest{Export: WorkspaceExportRequest{Access: exportConfigs.access, Job: job}, Artifact: *receipt.Artifact, Length: MaximumExportChunkBytes}
 for {
  chunk, err := exportClient.ReadWorkspaceExport(ctx, read)
  if err != nil {
   t.Fatal("routine artifact download", err)
  }
  raw = append(raw, chunk.Data...)
  read.Offset += uint64(len(chunk.Data))
  if chunk.EOF {
   break
  }
 }
 if !strings.Contains(string(raw), transferRoutineMarker) {
  t.Fatal("published artifact lacks routine marker")
 }
 exportJob := job
 job.Direction, job.Source, job.Destination = TransferImport, receipt.Artifact, nil
 if job, err = SealTransferJob(job); err != nil {
  t.Fatal(err)
 }
 importReceipt, err := backend.Import(ctx, job, target, func(TransferStreamProgress) error { return nil })
 if err != nil {
  t.Fatalf("routine import failed: %v (exit %d, stderr %d bytes)", err, importReceipt.ExitCode, importReceipt.StderrBytes)
 }
 if !importReceipt.InputVerified || importReceipt.Partial {
  t.Fatal("unverified routine import")
 }
 verifyRoutineDestination(t, ctx, query, target.String(), "1")
 verifyRoutineNativePromotion(t, ctx, exportConfigs.executor, store, backend, exportJob, job, query, prefix, tenant, siteID, id)
}

func verifyRoutineDestination(t *testing.T, ctx context.Context, query func(context.Context, string) (string, error), schema string, expectedRows string) {
 t.Helper()
 rows, err := query(ctx, "SELECT COUNT(*) FROM `"+schema+"`.sample;")
 if err != nil || rows != expectedRows {
  t.Fatal("routine destination rows differ", rows, expectedRows, err)
 }
 body, err := query(ctx, "CALL `"+schema+"`.sample_procedure();")
 if err != nil || body != "routine round trip" {
  t.Fatal("promoted procedure differs", body, err)
 }
 value, err := query(ctx, "SELECT `"+schema+"`.sample_function();")
 if err != nil || value != "7" {
  t.Fatal("promoted function differs", value, err)
 }
 security, err := query(ctx, "SELECT security_type FROM mysql.proc WHERE db='"+schema+"' AND name IN ('sample_procedure','sample_function') ORDER BY name;")
 if err != nil || security != "INVOKER\nINVOKER" {
  t.Fatal("promoted routines are not INVOKER", security, err)
 }
}

func verifyRoutineNativePromotion(t *testing.T, ctx context.Context, executor *LinuxMariaDBExecutor, store *LinuxTransferArtifactStore, backend *LinuxTransferBackend, sourceExport TransferJob, job TransferJob, query func(context.Context, string) (string, error), prefix string, tenant site.TenantID, siteID site.SiteID, id func(string) ResourceID) {
 t.Helper()
 live, err := executor.transferImportSource(job)
 if err != nil {
  t.Fatal(err)
 }
 live.ID = id("routine-promotion-" + prefix)
 live.Name, _ = ParseSQLIdentifier("cprtn" + job.Digest[:24])
 live.Generation = 1
 job.ID = id("routine-promotion-job-" + prefix)
 job.DatabaseID = live.ID
 job.Impact.DatabaseID = live.ID
 job.Impact = SealTransferImpactPreview(job.Impact)
 if job, err = SealTransferJob(job); err != nil {
  t.Fatal(err)
 }
 if _, err = query(ctx, "CREATE DATABASE `"+live.Name.String()+"` CHARACTER SET "+live.Charset.String()+" COLLATE "+live.Collation.String()+";"); err != nil {
  t.Fatal(err)
 }
 if err = executor.writeResource("databases", live.ID, live); err != nil {
  t.Fatal(err)
 }
 var isolated IsolatedTransferDatabase
 t.Cleanup(func() {
  cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
  defer cancel()
  if !isolated.Token.IsZero() {
   if _, err := query(cleanup, "DROP DATABASE IF EXISTS `"+isolated.Name.String()+"`;"); err != nil {
    t.Error(err)
   }
   if err := executor.removeResource("transfer-imports", isolated.Token); err != nil {
    t.Error(err)
   }
  }
  if _, err := query(cleanup, "DROP DATABASE IF EXISTS `"+live.Name.String()+"`;"); err != nil {
   t.Error(err)
  }
  if err := executor.removeResource("databases", live.ID); err != nil {
   t.Error(err)
  }
 })
 client := liveExportBroker(t, ctx, executor)
 request := TransferImportRequest{Action: "allocate", Job: job, SourceExport: sourceExport}
 allocated, err := client.ExecuteTransferImport(ctx, request)
 if err != nil {
  t.Fatal("routine staging allocation", err)
 }
 isolated = allocated.Isolated
 request.Isolated, request.Action = &isolated, "load"
 if _, err = client.ExecuteTransferImport(ctx, request); err != nil {
  t.Fatal("routine staging load", err)
 }
 if staged, err := query(ctx, "SELECT COUNT(*) FROM mysql.proc WHERE db='"+isolated.Name.String()+"';"); err != nil || staged != "2" {
  t.Fatal("staging lacks recreated routines", staged, err)
 }
 request.Action = "verify"
 if _, err = client.ExecuteTransferImport(ctx, request); err != nil {
  t.Fatal("routine staging verification", err)
 }
 request.Action = "promote"
 if _, err = client.ExecuteTransferImport(ctx, request); err != nil {
  t.Fatal("routine promotion", err)
 }
 verifyRoutineDestination(t, ctx, query, live.Name.String(), "1")
 if remaining, err := query(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+isolated.Name.String()+"';"); err != nil || remaining != "0" {
  t.Fatal("promotion retained staging schema", remaining, err)
 }
 t.Log("routine promotion recreated INVOKER routines in destination and dropped staging")
}
