//go:build linux

package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

// Import uses a target-only native account with fixture credential provisioning.
// Export uses the production session-bound config resolver and a native
// SELECT/SHOW VIEW account; secret delivery remains a fixture. All SQL
// subprocesses and artifacts are real; import provisioning is not production.
type liveTransferConfigs struct {
	path  string
	token ResourceID
}

func (config liveTransferConfigs) TransferClientConfig(_ context.Context, job TransferJob, name SQLIdentifier) (TransferClientConfigDescriptor, error) {
	return TransferClientConfigDescriptor{Path: config.path, Token: config.token, Database: name, Direction: job.Direction, ReadOnly: job.Direction == TransferExport, Release: func() error { return nil }}, nil
}

func TestTransferAtomicRenameEngineBoundary(t *testing.T) {
	for _, engine := range []string{"InnoDB", "MyISAM", "Aria"} {
		if !atomicTransferRenameEngine(engine) {
			t.Fatal("supported engine rejected", engine)
		}
	}
	for _, engine := range []string{"", "MEMORY", "CSV", "FEDERATED", "CONNECT", "SPIDER", "unknown"} {
		if atomicTransferRenameEngine(engine) {
			t.Fatal("unqualified engine accepted", engine)
		}
	}
}

func TestQEMUTransferNativeRoundTrip(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_TRANSFER") != "1" {
		t.Skip("requires disposable QEMU MariaDB")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root inside QEMU")
	}
	for _, engine := range []string{"InnoDB", "MyISAM", "Aria"} {
		t.Run(engine, func(t *testing.T) { testQEMUTransferNativeRoundTrip(t, engine) })
	}
}

func testQEMUTransferNativeRoundTrip(t *testing.T, engine string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	prefix := "qemu_transfer_" + hex.EncodeToString(random)
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
			t.Error("fixture database cleanup failed")
		}
	}()
	if _, err := query(ctx, "CREATE DATABASE `"+source.String()+"`; CREATE DATABASE `"+target.String()+"`; CREATE TABLE `"+source.String()+"`.sample(id INT PRIMARY KEY, body TEXT, raw_bytes BLOB) ENGINE="+engine+"; INSERT INTO `"+source.String()+"`.sample VALUES(1,'transfer round trip',X'0001FF'),(2,NULL,NULL);"); err != nil {
		t.Fatal("fixture setup failed", err)
	}
	if err := ensureRootDirectory(strings.TrimSuffix(transferConfigDirectory, "/"), 0700); err != nil {
		t.Fatal(err)
	}
	configDir, err := os.MkdirTemp(transferConfigDirectory, "fixture-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(configDir)
	configPath := filepath.Join(configDir, "client.cnf")
	importUser := "qemu_imp_" + hex.EncodeToString(random)
	passwordBytes := make([]byte, 32)
	if _, err = rand.Read(passwordBytes); err != nil {
		t.Fatal(err)
	}
	defer wipeBytes(passwordBytes)
	password := hex.EncodeToString(passwordBytes)
	if _, err = query(ctx, "CREATE USER '"+importUser+"'@'localhost' IDENTIFIED BY '"+password+"'; GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,CREATE VIEW,ALTER,INDEX,DROP,LOCK TABLES ON `"+target.String()+"`.* TO '"+importUser+"'@'localhost';"); err != nil {
		t.Fatal("scoped import account setup failed")
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
	for _, forbidden := range []string{"SELECT * FROM mysql.user;", "CREATE TABLE `" + source.String() + "`.import_escape(id INT);"} {
		command := exec.CommandContext(ctx, mariaDBClientBinary, "--defaults-file="+configPath, "--protocol=socket", "--socket="+mariaDBSocket, "--batch")
		command.Stdin = strings.NewReader(forbidden)
		if command.Run() == nil {
			t.Fatal("import account escaped target database")
		}
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
	backend, err := NewLinuxTransferBackend(store, liveTransferConfigs{configPath, id("fixture-token")}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := site.NewTenantID("qemu-transfer-tenant")
	siteID, _ := site.NewSiteID("qemu-transfer-site")
	for _, compression := range []TransferCompression{TransferCompressionNone, TransferCompressionGzip} {
		t.Run(string(compression), func(t *testing.T) {
			now := time.Now().UTC()
			artifact := TransferArtifactIdentity{StoreID: id("fixture-store"), ArtifactID: id("fixture-" + string(compression)), Generation: 1}
			job := TransferJob{ID: id("job-" + string(compression)), IdempotencyKey: "fixture-" + string(compression), TenantID: tenant, SiteID: siteID, DatabaseID: id(prefix + "-database"), DatabaseGeneration: 1, InstanceID: id("mariadb-local"), Direction: TransferExport, Format: TransferFormatSQL, Compression: compression, Destination: &artifact, Selection: TransferSelection{Schema: true, Data: true}, Limits: TransferLimits{MaximumBytes: 1 << 20, MaximumRows: 100, MaximumDuration: time.Minute}, ConflictPolicy: TransferConflictFail, Retention: TransferRetention{RetainUntil: now.Add(time.Hour)}, CreatedBy: "fixture-user", CreatedAt: now}
			job.Impact = SealTransferImpactPreview(TransferImpactPreview{DatabaseID: job.DatabaseID, DatabaseGeneration: 1, SchemaObjects: 1, Rows: 2, Bytes: 1024, CapturedAt: now})
			artifact = WorkspaceExportArtifact(job)
			job.Destination = &artifact
			artifactPath, err := store.artifactPath(artifact)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(artifactPath); err != nil {
					t.Error("export artifact cleanup", err)
				}
			})
			job, err = SealTransferJob(job)
			if err != nil {
				t.Fatal(err)
			}
			exportConfigs := liveWorkspaceExportFixture(t, ctx, prefix, job, source, query)
			exportClient := liveExportBroker(t, ctx, exportConfigs.executor)
			coordinator := NewCoordinator(liveExportRepository{executor: exportConfigs.executor}, exportClient, liveExportClock{})
			call := WorkspaceCall{TenantID: tenant, SiteID: siteID, SessionID: exportConfigs.access.SessionID, SessionGeneration: exportConfigs.access.SessionGeneration}
			job, err = coordinator.PrepareWorkspaceExport(ctx, call, "fixture-user", "prepare-"+string(compression), WorkspaceExportOptions{Compression: compression, Selection: TransferSelection{Schema: true, Data: true}})
			if err != nil {
				t.Fatal("prepare export", err)
			}
			// Deliberately stale native preview estimate: receipts must count the
			// two actual dumped rows, never repeat this estimate as fact.
			job.Impact.Rows = 0
			job.Impact = SealTransferImpactPreview(job.Impact)
			actualArtifact := WorkspaceExportArtifact(job)
			job.Destination = &actualArtifact
			job, err = SealTransferJob(job)
			if err != nil {
				t.Fatal(err)
			}
			preparedPath, err := store.artifactPath(*job.Destination)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(preparedPath); err != nil {
					t.Error(err)
				}
			})
			request := WorkspaceExportRequest{Access: exportConfigs.access, Job: job}
			if _, err = coordinator.RunWorkspaceExport(ctx, call, "different-actor", job); err == nil {
				t.Fatal("different actor accepted")
			}
			receipt, err := coordinator.RunWorkspaceExport(ctx, call, "fixture-user", job)
			if err != nil {
				t.Fatalf("native export: %v (exit %d)", err, receipt.ExitCode)
			}
			if receipt.RowsProcessed != 2 || receipt.Artifact.Rows != 2 {
				t.Fatal("export trusted preview row estimate")
			}
			limited := job
			limited.Limits.MaximumRows = 1
			limitedArtifact := WorkspaceExportArtifact(limited)
			limited.Destination = &limitedArtifact
			limited, err = SealTransferJob(limited)
			if err != nil {
				t.Fatal(err)
			}
			limitedReceipt, limitErr := exportConfigs.executor.ExportWorkspaceDatabase(ctx, WorkspaceExportRequest{Access: exportConfigs.access, Job: limited})
			if !errors.Is(limitErr, ErrTransferLimit) || limitedReceipt.Artifact != nil {
				t.Fatal("native export row limit", limitErr)
			}
			limitedPath, _ := store.artifactPath(limitedArtifact)
			if _, err := os.Lstat(limitedPath); !os.IsNotExist(err) {
				t.Fatal("over-limit artifact published")
			}
			replay, err := exportClient.ExportWorkspaceDatabase(ctx, request)
			if err != nil || replay.Digest != receipt.Digest {
				t.Fatal("broker export replay differs", err)
			}
			directReplay, err := exportConfigs.executor.ExportWorkspaceDatabase(ctx, request)
			if err != nil || directReplay.Artifact == nil || *directReplay.Artifact != *receipt.Artifact {
				t.Fatal("executor publication replay differs", err)
			}
			frame, err := exportClient.request(ctx, BrokerWorkspaceExport)
			if err != nil {
				t.Fatal(err)
			}
			frame.WorkspaceExport = &request
			if err = frame.validate(time.Now()); err != nil {
				t.Fatal(err)
			}
			frame.Workspace = &WorkspaceBrokerRequest{Access: request.Access}
			if frame.validate(time.Now()) == nil {
				t.Fatal("mixed broker operation accepted")
			}
			frame.Workspace = nil
			response := BrokerResponse{Version: frame.Version, RequestID: frame.RequestID, Operation: frame.Operation, Export: &receipt}
			if response.validate(frame) != nil {
				t.Fatal("valid export receipt rejected")
			}
			wrongReceipt := receipt
			wrongArtifact := *receipt.Artifact
			wrongArtifact.Identity.Generation++
			wrongReceipt.Artifact = &wrongArtifact
			wrongReceipt = SealTransferProcessReceipt(wrongReceipt)
			response.Export = &wrongReceipt
			if response.validate(frame) == nil {
				t.Fatal("different artifact accepted")
			}
			wrongRequest := request
			wrongJob := request.Job
			wrongDestination := *wrongJob.Destination
			wrongDestination.Generation++
			wrongJob.Destination = &wrongDestination
			wrongJob, err = SealTransferJob(wrongJob)
			if err != nil {
				t.Fatal(err)
			}
			wrongRequest.Job = wrongJob
			if _, err = exportClient.ExportWorkspaceDatabase(ctx, wrongRequest); err == nil {
				t.Fatal("caller-selected artifact destination accepted")
			}
			verifyLiveExportDownload(t, ctx, exportClient, exportConfigs.executor, request, *receipt.Artifact)
			if _, err = coordinator.DownloadWorkspaceExport(ctx, call, "fixture-user", job, *receipt.Artifact, 0, 97); err != nil {
				t.Fatal("coordinator download", err)
			}
			job.Direction, job.Source, job.Destination = TransferImport, receipt.Artifact, nil
			job, err = SealTransferJob(job)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = query(ctx, "DROP TABLE IF EXISTS `"+target.String()+"`.sample;"); err != nil {
				t.Fatal(err)
			}
			receipt, err = backend.Import(ctx, job, target, func(TransferStreamProgress) error { return nil })
			if err != nil {
				t.Fatalf("native import: %v (exit %d, stderr bytes %d)", err, receipt.ExitCode, receipt.StderrBytes)
			}
			if !receipt.InputVerified || receipt.Partial {
				t.Fatal("unverified import")
			}
			got, err := query(ctx, "SELECT CONCAT(id,':',COALESCE(body,'NULL'),':',COALESCE(HEX(raw_bytes),'NULL')) FROM `"+target.String()+"`.sample ORDER BY id;")
			if err != nil || got != "1:transfer round trip:0001FF\n2:NULL:NULL" {
				t.Fatalf("round trip contents differ: %q %v", got, err)
			}
			verifyOrdinaryNativeImports(t, ctx, store, backend, job, target, query, exportConfigs.executor)
			verifyIsolatedNativeImport(t, ctx, exportConfigs.executor, store, job, query)
			verifyEmptyNativePromotion(t, ctx, exportConfigs.executor, exportClient, request.Job, job, query, engine)
			verifyServiceNativeImport(t, ctx, exportConfigs.executor, exportClient, request.Job, job, query)
			verifyServiceNativeImport(t, ctx, exportConfigs.executor, exportClient, request.Job, job, query, true)
		})
	}
}

func verifyEmptyNativePromotion(t *testing.T, ctx context.Context, executor *LinuxMariaDBExecutor, client *BrokerClient, sourceExport TransferJob, job TransferJob, query func(context.Context, string) (string, error), engine string) {
	t.Helper()
	live, err := executor.transferImportSource(job)
	if err != nil {
		t.Fatal(err)
	}
	live.ID, _ = NewResourceID("promotion-" + job.ID.String())
	live.Name, _ = ParseSQLIdentifier("cpprom" + job.Digest[:24])
	job.ID, _ = NewResourceID("promotion-job-" + job.ID.String())
	job.DatabaseID = live.ID
	job.Impact.DatabaseID = live.ID
	job.Impact = SealTransferImpactPreview(job.Impact)
	job, err = SealTransferJob(job)
	if err != nil {
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
		if _, err := query(cleanup, "DROP DATABASE `"+live.Name.String()+"`;"); err != nil {
			t.Error(err)
		}
		if err := executor.removeResource("databases", live.ID); err != nil {
			t.Error(err)
		}
	})
	request := TransferImportRequest{Action: "allocate", Job: job, SourceExport: sourceExport}
	checkTransferImportProtocol(t, request)
	// A descriptor is not trusted merely because it names an owned export.
	wrong := request
	changedSource := *job.Source
	changedSource.Digest = transferDigest([]byte("not-the-stored-export"))
	wrong.Job.Source = &changedSource
	wrong.Job, err = SealTransferJob(wrong.Job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = executor.ExecuteTransferImport(ctx, wrong); !errors.Is(err, ErrTransferStale) {
		t.Fatal("altered source descriptor accepted", err)
	}
	wrongID, _ := isolatedTransferIdentity(wrong.Job)
	var absent isolatedTransferRecord
	if err = executor.readResource("transfer-imports", wrongID, &absent); !errors.Is(err, ErrNotFound) {
		t.Fatal("invalid source allocated native resources", err)
	}

	discardRequest := request
	discardRequest.Job.ID, _ = NewResourceID("discard-" + job.ID.String())
	discardRequest.Job, err = SealTransferJob(discardRequest.Job)
	if err != nil {
		t.Fatal(err)
	}
	discardTarget, err := client.ExecuteTransferImport(ctx, discardRequest)
	if err != nil {
		t.Fatal("discard fixture allocation", err)
	}
	discardRequest.Action, discardRequest.Isolated = "discard", &discardTarget.Isolated
	if _, err = client.ExecuteTransferImport(ctx, discardRequest); err != nil {
		t.Fatal("broker discard", err)
	}
	if _, err = client.ExecuteTransferImport(ctx, discardRequest); err != nil {
		t.Fatal("broker discard replay", err)
	}
	if err = executor.readResource("transfer-imports", discardTarget.Isolated.Token, &absent); !errors.Is(err, ErrNotFound) {
		t.Fatal("discard retained protected record", err)
	}
	if value, err := query(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+discardTarget.Isolated.Name.String()+"';"); err != nil || value != "0" {
		t.Fatal("discard retained native schema", err)
	}

	allocated, err := client.ExecuteTransferImport(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	isolated = allocated.Isolated
	responseRequest := BrokerRequest{Version: DatabaseBrokerProtocolVersion, RequestID: "req-0123456789abcdef0123456789abcdef", Operation: BrokerTransferImport, TransferImport: &request}
	response := BrokerResponse{Version: responseRequest.Version, RequestID: responseRequest.RequestID, Operation: responseRequest.Operation, TransferImport: &allocated}
	if err = response.validate(responseRequest); err != nil {
		t.Fatal("valid allocation response", err)
	}
	for _, change := range []func(*BrokerResponse){
		func(r *BrokerResponse) { r.FailureCode = "conflict" },
		func(r *BrokerResponse) { r.Export = &TransferProcessReceipt{} },
		func(r *BrokerResponse) {
			result := *r.TransferImport
			result.JobDigest = transferDigest([]byte("other-job"))
			r.TransferImport = &result
		},
		func(r *BrokerResponse) {
			result := *r.TransferImport
			result.Process = &TransferProcessReceipt{}
			r.TransferImport = &result
		},
	} {
		invalid := response
		change(&invalid)
		if invalid.validate(responseRequest) == nil {
			t.Fatal("mismatched import response accepted")
		}
	}
	request.Isolated = &isolated
	request.Action = "verify"
	if _, err = client.ExecuteTransferImport(ctx, request); err == nil {
		t.Fatal("unloaded import verified")
	}
	request.Action = "load"
	loaded, err := client.ExecuteTransferImport(ctx, request)
	if err != nil {
		t.Fatal("broker import load", err)
	}
	reloaded, err := client.ExecuteTransferImport(ctx, request)
	if err != nil || loaded.Process.Digest != reloaded.Process.Digest {
		t.Fatal("journal import replay", err)
	}
	direct, err := executor.ExecuteTransferImport(ctx, request)
	if err != nil || direct.Process.Digest != loaded.Process.Digest {
		t.Fatal("durable import replay", err)
	}
	request.Action = "verify"
	if _, err = client.ExecuteTransferImport(ctx, request); err != nil {
		t.Fatal("broker import verify", err)
	}
	if _, err = query(ctx, "CREATE TABLE `"+live.Name.String()+"`.existing(id INT); INSERT INTO `"+live.Name.String()+"`.existing VALUES(77);"); err != nil {
		t.Fatal(err)
	}
	denied, err := executor.promoteEmptyTransferImport(ctx, job, isolated)
	if !errors.Is(err, ErrConflict) || !denied.SourcePreserved || denied.Promoted {
		t.Fatal("nonempty destination accepted", err)
	}
	value, err := query(ctx, "SELECT id FROM `"+live.Name.String()+"`.existing;")
	if err != nil || value != "77" {
		t.Fatal("existing data changed", err)
	}
	if _, err = query(ctx, "DROP TABLE `"+live.Name.String()+"`.existing;"); err != nil {
		t.Fatal(err)
	}
	request.Action = "promote"
	controlPath := filepath.Join(t.TempDir(), "import-control.db")
	openControl := func() (*sql.DB, *SQLRepository) {
		t.Helper()
		control, err := sql.Open("sqlite", controlPath)
		if err != nil {
			t.Fatal(err)
		}
		control.SetMaxOpenConns(1)
		t.Cleanup(func() { control.Close() })
		repository, err := NewSQLRepository(control)
		if err != nil {
			t.Fatal(err)
		}
		if err = repository.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
		return control, repository
	}
	control, repository := openControl()
	coreLive := live
	coreLive.Status = readyStatus(coreLive.Generation)
	if err = repository.EnsureBootstrapResources(ctx, coreLive); err != nil {
		t.Fatal(err)
	}
	coordinator := NewCoordinator(repository, client, SystemClock{})
	// Fail after the resource UPDATE, while inserting its receipt: both changes
	// must roll back together, while the native promotion remains durable.
	if _, err = control.ExecContext(ctx, `CREATE TRIGGER reject_import_projection BEFORE INSERT ON panel_database_transfer_promotions BEGIN SELECT RAISE(ABORT,'injected projection failure'); END`); err != nil {
		t.Fatal(err)
	}
	failedProjection, err := coordinator.PromoteDatabaseTransfer(ctx, request)
	if !errors.Is(err, ErrAmbiguous) || failedProjection.Validate(job, isolated) != nil {
		t.Fatal("projection failure lost native receipt", err)
	}
	var coreGeneration, receipts int
	if err = control.QueryRowContext(ctx, `SELECT generation FROM panel_database_resources WHERE kind=? AND resource_id=?`, string(KindDatabase), live.ID.String()).Scan(&coreGeneration); err != nil || coreGeneration != 1 {
		t.Fatal("failed projection changed core generation", err)
	}
	if err = control.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_database_transfer_promotions`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("failed projection published receipt", err)
	}
	if _, err = control.ExecContext(ctx, `DROP TRIGGER reject_import_projection`); err != nil {
		t.Fatal(err)
	}
	promoted, err := coordinator.PromoteDatabaseTransfer(ctx, request)
	if err != nil || promoted != failedProjection {
		t.Fatal("projection recovery changed native receipt", err)
	}
	envelope, err := repository.LoadResource(ctx, KindDatabase, live.ID)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := transferProjectionDatabase(envelope, job)
	if err != nil || projected.Generation != 2 || projected.Name != live.Name || projected.Status.ObservedGeneration != 2 || projected.Status.ProofDigest != promoted.ProofDigest {
		t.Fatal("core promotion projection mismatch", err)
	}
	if err = control.Close(); err != nil {
		t.Fatal(err)
	}
	control, repository = openControl()
	// A persisted panel receipt must replay without another executor call.
	coordinator = NewCoordinator(repository, noTransferReplayExecutor{}, SystemClock{})
	coreReplay, err := coordinator.PromoteDatabaseTransfer(ctx, request)
	if err != nil || coreReplay != promoted {
		t.Fatal("core promotion replay after reopen", err)
	}
	if err = control.QueryRowContext(ctx, `SELECT COUNT(*) FROM panel_database_transfer_promotions`).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatal("duplicate promotion record", err)
	}
	wrongPromotion := promoted
	wrongPromotion.TargetGeneration++
	if err = repository.RecordTransferPromotion(ctx, job, isolated, wrongPromotion); err == nil {
		t.Fatal("wrong promotion generation accepted")
	}
	wrongPromotion = promoted
	wrongPromotion.ProofDigest = transferDigest([]byte("not-the-original-proof"))
	if err = repository.RecordTransferPromotion(ctx, job, isolated, wrongPromotion); err == nil {
		t.Fatal("conflicting promotion receipt accepted")
	}
	value, err = query(ctx, "SELECT CONCAT(id,':',COALESCE(body,'NULL'),':',COALESCE(HEX(raw_bytes),'NULL')) FROM `"+live.Name.String()+"`.sample ORDER BY id;")
	if err != nil || value != "1:transfer round trip:0001FF\n2:NULL:NULL" {
		t.Fatal("promoted data differs", err)
	}
	if got, err := query(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA='"+live.Name.String()+"' AND TABLE_NAME='sample';"); err != nil || got != engine {
		t.Fatal("promotion changed the native storage engine", got, err)
	}
	replayed, err := executor.promoteEmptyTransferImport(ctx, job, isolated)
	if err != nil || replayed != promoted {
		t.Fatal("promotion replay differs", err)
	}
	brokerReplay, err := client.ExecuteTransferImport(ctx, request)
	if err != nil || brokerReplay.Promotion == nil || *brokerReplay.Promotion != promoted {
		t.Fatal("broker promotion replay differs", err)
	}
	var updated Database
	if err = executor.readResource("databases", live.ID, &updated); err != nil || updated.Generation != 2 || updated.Name != live.Name {
		t.Fatal("promotion generation/name", err)
	}
	value, err = query(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+isolated.Name.String()+"';")
	if err != nil || value != "0" {
		t.Fatal("empty isolated schema retained", err)
	}
	// Simulate interruption on either side of native metadata persistence. The
	// isolated schema is already gone, so a repeated RENAME would fail here.
	committed, err := executor.loadTransferImport(job, isolated)
	if err != nil || committed.PromotionCommit == nil {
		t.Fatal("missing durable native commit", err)
	}
	for _, phase := range []string{"before-metadata", "after-metadata", "metadata-drift", "missing-proof", "unverified-move"} {
		recovering := committed
		recovering.State = "promotion-verified"
		current := committed.PromotionCommit.After
		if phase == "before-metadata" {
			current = committed.PromotionCommit.Before
		}
		if phase == "metadata-drift" {
			current.QuotaBytes++
		}
		if phase == "missing-proof" {
			recovering.Promotion = nil
		}
		if phase == "unverified-move" {
			recovering.State = "promoting"
		}
		if err = executor.writeResource("databases", live.ID, current); err != nil {
			t.Fatal(err)
		}
		if err = executor.writeResource("transfer-imports", isolated.Token, recovering); err != nil {
			t.Fatal(err)
		}
		recovered, recoverErr := executor.ExecuteTransferImport(ctx, request)
		if phase == "metadata-drift" || phase == "missing-proof" || phase == "unverified-move" {
			if !errors.Is(recoverErr, ErrAmbiguous) {
				t.Fatal("unproven recovery accepted", phase, recoverErr)
			}
			var unchanged Database
			if err = executor.readResource("databases", live.ID, &unchanged); err != nil || unchanged != current {
				t.Fatal("recovery overwrote drift", err)
			}
		} else if recoverErr != nil || recovered.Promotion == nil || *recovered.Promotion != promoted {
			t.Fatal("verified promotion recovery failed", phase, recoverErr)
		} else {
			var finalized Database
			if err = executor.readResource("databases", live.ID, &finalized); err != nil || finalized != committed.PromotionCommit.After {
				t.Fatal("promotion metadata not finalized", phase, err)
			}
			finalRecord, err := executor.loadTransferImport(job, isolated)
			if err != nil || finalRecord.State != "promoted" || finalRecord.Promotion == nil || *finalRecord.Promotion != promoted {
				t.Fatal("promotion receipt not finalized", phase, err)
			}
		}
	}
	if err = executor.writeResource("databases", live.ID, committed.PromotionCommit.After); err != nil {
		t.Fatal(err)
	}
	if err = executor.writeResource("transfer-imports", isolated.Token, committed); err != nil {
		t.Fatal(err)
	}
	value, err = query(ctx, "SELECT COUNT(*) FROM `"+live.Name.String()+"`.sample;")
	if err != nil || value != "2" {
		t.Fatal("recovery changed native rows", err)
	}
}

type noTransferReplayExecutor struct{ MariaDBExecutor }

func (noTransferReplayExecutor) ExecuteTransferImport(context.Context, TransferImportRequest) (TransferImportResult, error) {
	return TransferImportResult{}, errors.New("unexpected native replay")
}

func checkTransferImportProtocol(t *testing.T, request TransferImportRequest) {
	t.Helper()
	if err := request.validate(); err != nil {
		t.Fatal("valid import rejected", err)
	}
	otherTenant, _ := site.NewTenantID("other-import-tenant")
	otherSite, _ := site.NewSiteID("other-import-site")
	for _, change := range []func(*TransferImportRequest){
		func(r *TransferImportRequest) {
			r.SourceExport.TenantID = otherTenant
			r.SourceExport, _ = SealTransferJob(r.SourceExport)
		},
		func(r *TransferImportRequest) {
			r.SourceExport.SiteID = otherSite
			r.SourceExport, _ = SealTransferJob(r.SourceExport)
		},
		func(r *TransferImportRequest) {
			r.SourceExport.CreatedBy = "different-owner"
			r.SourceExport, _ = SealTransferJob(r.SourceExport)
		},
		func(r *TransferImportRequest) { r.Action = "sql" },
		func(r *TransferImportRequest) { r.Action = "load" },
	} {
		wrong := request
		change(&wrong)
		if wrong.validate() == nil {
			t.Fatal("forged import authority accepted")
		}
	}
	frame := BrokerRequest{Version: DatabaseBrokerProtocolVersion, RequestID: "req-0123456789abcdef0123456789abcdef", Operation: BrokerTransferImport, Deadline: time.Now().Add(time.Minute), TransferImport: &request}
	if err := frame.validate(time.Now()); err != nil {
		t.Fatal("import broker frame", err)
	}
	frame.WorkspaceExport = &WorkspaceExportRequest{}
	if frame.validate(time.Now()) == nil {
		t.Fatal("mixed import/export frame accepted")
	}
	frame.WorkspaceExport = nil
	frame.Operation = BrokerWorkspaceExport
	if frame.validate(time.Now()) == nil {
		t.Fatal("import payload on export accepted")
	}
}

func verifyIsolatedNativeImport(t *testing.T, ctx context.Context, executor *LinuxMariaDBExecutor, store *LinuxTransferArtifactStore, job TransferJob, query func(context.Context, string) (string, error)) {
	t.Helper()
	isolated, err := executor.allocateTransferImport(ctx, job)
	if err != nil {
		t.Fatal("allocate isolated import", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := executor.discardTransferImport(cleanup, job, isolated); err != nil && !errors.Is(err, ErrNotFound) {
			t.Error("discard isolated import", err)
		}
	})
	replay, err := executor.allocateTransferImport(ctx, job)
	if err != nil || replay != isolated {
		t.Fatal("allocation replay", err)
	}
	configs := isolatedImportConfigs{executor: executor, isolated: isolated}
	wrong := isolated
	wrong.Name, _ = ParseSQLIdentifier("mysql")
	if _, err := (isolatedImportConfigs{executor: executor, isolated: wrong}).TransferClientConfig(ctx, job, wrong.Name); err == nil {
		t.Fatal("caller-selected import database accepted")
	}
	config, err := configs.TransferClientConfig(ctx, job, isolated.Name)
	if err != nil {
		t.Fatal("isolated import credentials", err)
	}
	defer config.Release()
	if _, err := configs.TransferClientConfig(ctx, job, isolated.Name); err == nil {
		t.Fatal("duplicate loader accepted")
	}
	if err := executor.discardTransferImport(ctx, job, isolated); !errors.Is(err, ErrConflict) {
		t.Fatal("active import could be discarded", err)
	}
	if _, err := executor.verifyTransferImport(ctx, job, isolated); !errors.Is(err, ErrConflict) {
		t.Fatal("active loader verified", err)
	}
	source, err := executor.transferImportSource(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{"SELECT * FROM mysql.user;", "CREATE TABLE `" + source.Name.String() + "`.import_escape(id INT);"} {
		cmd := exec.CommandContext(ctx, mariaDBClientBinary, "--defaults-file="+config.Path, "--protocol=socket", "--socket="+mariaDBSocket, "--batch")
		cmd.Stdin = strings.NewReader(statement)
		if cmd.Run() == nil {
			t.Fatal("isolated loader escaped scope")
		}
	}
	backend, err := NewLinuxTransferBackend(store, resolvedExportConfig{descriptor: config}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Import(ctx, job, isolated.Name, func(TransferStreamProgress) error { return nil })
	if err != nil || receipt.Partial || !receipt.InputVerified {
		t.Fatal("native isolated import", err)
	}
	if _, err := os.Lstat(config.Path); !os.IsNotExist(err) {
		t.Fatal("import credential retained", err)
	}
	accountCount, err := query(ctx, "SELECT COUNT(*) FROM mysql.user WHERE User='cpmig_"+strings.TrimPrefix(config.Token.String(), "migloader-")+"';")
	if err != nil || accountCount != "0" {
		t.Fatal("native loader retained", err)
	}
	got, err := query(ctx, "SELECT CONCAT(id,':',COALESCE(body,'NULL'),':',COALESCE(HEX(raw_bytes),'NULL')) FROM `"+isolated.Name.String()+"`.sample ORDER BY id;")
	if err != nil || got != "1:transfer round trip:0001FF\n2:NULL:NULL" {
		t.Fatal("isolated import contents differ", err)
	}
	verification, err := executor.verifyTransferImport(ctx, job, isolated)
	if err != nil || verification.Validate(job, isolated) != nil || verification.RowCount != 2 || verification.Bytes == 0 {
		t.Fatal("native isolated verification", err)
	}
	stored, err := executor.loadTransferImport(job, isolated)
	if err != nil || stored.State != "verified" || stored.Verification == nil || stored.Verification.Digest != verification.Digest {
		t.Fatal("verification not persisted", err)
	}
	if _, err = query(ctx, "RENAME TABLE `"+isolated.Name.String()+"`.sample TO `"+isolated.Name.String()+"`.`qemu``quoted`;"); err != nil {
		t.Fatal(err)
	}
	quotedVerification, err := executor.verifyTransferImport(ctx, job, isolated)
	if err != nil || quotedVerification.RowCount != 2 || quotedVerification.SchemaDigest == verification.SchemaDigest {
		t.Fatal("quoted table verification", err)
	}
	if _, err = query(ctx, "INSERT INTO `"+isolated.Name.String()+"`.`qemu``quoted` VALUES(3,'unexpected',NULL);"); err != nil {
		t.Fatal(err)
	}
	if _, err = executor.verifyTransferImport(ctx, job, isolated); err == nil {
		t.Fatal("changed row count verified")
	}
	stored, err = executor.loadTransferImport(job, isolated)
	if err != nil || stored.State != "closed" || stored.Verification != nil {
		t.Fatal("stale verification retained", err)
	}
	if err = executor.discardTransferImport(ctx, job, isolated); err != nil {
		t.Fatal("discard", err)
	}
	count, err := query(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+isolated.Name.String()+"';")
	if err != nil || count != "0" {
		t.Fatal("isolated database retained", err)
	}
}

func verifyOrdinaryNativeImports(t *testing.T, ctx context.Context, store *LinuxTransferArtifactStore, backend *LinuxTransferBackend, job TransferJob, target SQLIdentifier, query func(context.Context, string) (string, error), executor *LinuxMariaDBExecutor) {
	t.Helper()
	reader, err := store.OpenTransferArtifact(ctx, job.Source.Identity)
	if err != nil {
		t.Fatal(err)
	}
	var input io.Reader = reader
	if job.Compression == TransferCompressionGzip {
		compressed, err := gzip.NewReader(reader)
		if err != nil {
			reader.Close()
			t.Fatal(err)
		}
		defer compressed.Close()
		input = compressed
	}
	raw, err := io.ReadAll(io.LimitReader(input, 1<<20))
	reader.Close()
	if err != nil || !bytes.HasPrefix(raw, []byte(transferSQLMagic)) {
		t.Fatal("invalid native dump fixture", err)
	}
	raw = bytes.TrimPrefix(raw, []byte(transferSQLMagic))
	for index, form := range []string{"ordinary", "utf8-bom", "insert-ignore", "replace", "view-load"} {
		t.Run(form, func(t *testing.T) {
			plain := append([]byte(nil), raw...)
			if form == "utf8-bom" {
				plain = append([]byte{0xef, 0xbb, 0xbf}, plain...)
			}
			if form == "insert-ignore" {
				plain = append(plain, []byte("\nINSERT IGNORE INTO `sample` VALUES (1,'must not overwrite',X'AA');\n")...)
			}
			if form == "replace" {
				plain = append(plain, []byte("\nREPLACE INTO `sample` VALUES (2,'replacement',NULL);\n")...)
			}
			if form == "view-load" {
				plain = append(plain, []byte("\n/*!50001 CREATE ALGORITHM=UNDEFINED */ /*!50013 DEFINER=`root`@`localhost` SQL SECURITY DEFINER */ /*!50001 VIEW `sample_view` AS SELECT id,body FROM sample */;\n")...)
			}
			data := plain
			if job.Compression == TransferCompressionGzip {
				var buffer bytes.Buffer
				compressed := gzip.NewWriter(&buffer)
				if _, err := compressed.Write(plain); err != nil {
					t.Fatal(err)
				}
				if err := compressed.Close(); err != nil {
					t.Fatal(err)
				}
				data = buffer.Bytes()
			}
			identity := job.Source.Identity
			identity.Generation += 10 + uint64(index)
			writer, err := store.BeginTransferArtifact(ctx, identity, job.Format, job.Compression, job.Retention)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Abort(context.Background())
			path, _ := store.artifactPath(identity)
			t.Cleanup(func() {
				for _, name := range []string{"payload", "descriptor.json"} {
					if err := os.Remove(filepath.Join(path, name)); err != nil && !os.IsNotExist(err) {
						t.Error(err)
					}
				}
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					t.Error(err)
				}
			})
			if _, err = writer.Write(data); err != nil {
				t.Fatal(err)
			}
			descriptor, err := writer.Commit(ctx, transferDigest(data), uint64(len(data)), job.Source.Rows)
			if err != nil {
				t.Fatal(err)
			}
			variant := job
			variant.Source = &descriptor
			variant, err = SealTransferJob(variant)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = query(ctx, "DROP TABLE IF EXISTS `"+target.String()+"`.sample;"); err != nil {
				t.Fatal(err)
			}
			receipt, err := backend.Import(ctx, variant, target, func(TransferStreamProgress) error { return nil })
			if err != nil || receipt.Partial || !receipt.InputVerified {
				t.Fatalf("ordinary native import: %v", err)
			}
			got, err := query(ctx, "SELECT CONCAT(id,':',COALESCE(body,'NULL'),':',COALESCE(HEX(raw_bytes),'NULL')) FROM `"+target.String()+"`.sample ORDER BY id;")
			expected := "1:transfer round trip:0001FF\n2:NULL:NULL"
			if form == "replace" {
				expected = "1:transfer round trip:0001FF\n2:replacement:NULL"
			}
			if err != nil || got != expected {
				t.Fatal("ordinary import contents differ", err)
			}
			if form == "view-load" {
				got, err := query(ctx, "SELECT SECURITY_TYPE FROM information_schema.VIEWS WHERE TABLE_SCHEMA='"+target.String()+"' AND TABLE_NAME='sample_view';")
				if err != nil || got != "INVOKER" {
					t.Fatal("dump definer security survived rewrite", got, err)
				}
				got, err = query(ctx, "SELECT COUNT(*) FROM `"+target.String()+"`.sample_view;")
				if err != nil || got != "2" {
					t.Fatal("loaded native view cannot read its tables", err)
				}
				var resource Database
				if err := executor.readResource("databases", job.DatabaseID, &resource); err != nil {
					t.Fatal(err)
				}
				resource.Name = target
				instance, err := executor.instance(job.InstanceID)
				if err != nil {
					t.Fatal(err)
				}
				connection, cleanup, err := executor.connection(ctx, instance)
				if err != nil {
					t.Fatal(err)
				}
				defer cleanup()
				view, err := executor.observeTransferView(ctx, connection, isolatedTransferTable{Database: resource, Table: "sample_view"})
				if err != nil || len(view.Columns) != 2 || view.Columns[0] != "id" || view.Columns[1] != "body" || !strings.Contains(view.Definition, "SQL SECURITY INVOKER") || strings.Contains(view.Definition, "`"+target.String()+"`.") {
					t.Fatal("native view capture", err)
				}
				isolated := IsolatedTransferDatabase{Token: job.ID, InstanceID: job.InstanceID, Name: target, SourceDatabaseID: job.DatabaseID, SourceGeneration: job.DatabaseGeneration, CreatedAt: time.Now().UTC()}
				verified, err := executor.observeTransferDatabase(ctx, connection, variant, isolated, resource)
				if err != nil || verified.RowCount != 2 {
					t.Fatal("view verification must not double count table rows", err)
				}
				if _, err = query(ctx, "DROP VIEW `"+target.String()+"`.sample_view;"); err != nil {
					t.Fatal(err)
				}
				withoutView, err := executor.observeTransferDatabase(ctx, connection, variant, isolated, resource)
				if err != nil || withoutView.SchemaDigest == verified.SchemaDigest {
					t.Fatal("view absent from schema verification", err)
				}
			}
		})
	}
}

type liveExportClock struct{}

func (liveExportClock) Now() time.Time { return time.Now() }

// Read-only domain repository fixture joins the same real protected resources
// used by the root broker. SQL domain persistence is qualified separately.
type liveExportRepository struct {
	Repository
	executor *LinuxMariaDBExecutor
}

func (repository liveExportRepository) LoadResource(ctx context.Context, kind ResourceKind, id ResourceID) (ResourceEnvelope, error) {
	var resource Resource
	var directory string
	switch kind {
	case KindConsoleSession:
		resource = &DatabaseWorkspaceSession{}
		directory = "sessions"
	case KindDatabase:
		resource = &Database{}
		directory = "databases"
	case KindPrincipal:
		resource = &DatabasePrincipal{}
		directory = "principals"
	default:
		return ResourceEnvelope{}, ErrInvalidResource
	}
	if err := repository.executor.readResource(directory, id, resource); err != nil {
		return ResourceEnvelope{}, err
	}
	// The coordinator stores the confirmed projection separately from the
	// executor's applied input record. Match that distinction in this fixture.
	meta := resource.Meta()
	if meta.Status.Lifecycle == LifecycleProvisioning && meta.Status.Reconciliation == ReconciliationPending {
		setResourceStatus(resource, ResourceStatus{Lifecycle: LifecycleReady, Health: HealthHealthy, Reconciliation: ReconciliationInSync, ObservedGeneration: meta.Generation})
	}
	return EncodeResource(resource)
}

// This private QEMU socket uses a fixture peer authorizer. Framing, dispatch,
// SQL reboot admission, protected-resource checks and MariaDB execution are real.
type liveExportPeer struct{}

func (liveExportPeer) Authorize(net.Conn) error { return nil }

type liveExportDialer struct{ path string }

func (d liveExportDialer) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", d.path)
}

func liveExportBroker(t *testing.T, ctx context.Context, executor *LinuxMariaDBExecutor) *BrokerClient {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "admission.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	repo, err := rebootcontrol.NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = rebootcontrol.NewAdmissionGate(ctx, db, "qemu-export-boot", time.Now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &DatabaseBrokerServer{Authorizer: liveExportPeer{}, Executor: executor, Admission: &rebootcontrol.SQLExecutionAdmission{DB: db, BootID: "qemu-export-boot"}}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { listener.Close(); <-done })
	client, err := NewBrokerClient(FramedDatabaseBrokerTransport{Dialer: liveExportDialer{path}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var count int
		if err := db.QueryRow("SELECT count(*) FROM reboot_execution_effects WHERE method='workspace_export_read'").Scan(&count); err != nil || count != 0 {
			t.Error("download bytes must not enter mutation journal", count, err)
		}
		if err := db.QueryRow("SELECT count(*) FROM reboot_execution_effects WHERE method='transfer_import' AND status!='completed'").Scan(&count); err != nil || count != 0 {
			t.Error("import execution left unsettled journal entries", count, err)
		}
	})
	return client
}

func verifyLiveExportDownload(t *testing.T, ctx context.Context, client *BrokerClient, executor *LinuxMariaDBExecutor, export WorkspaceExportRequest, artifact TransferArtifactDescriptor) {
	t.Helper()
	request := WorkspaceExportReadRequest{Export: export, Artifact: artifact, Length: 97}
	var downloaded []byte
	for {
		chunk, err := client.ReadWorkspaceExport(ctx, request)
		if err != nil {
			t.Fatal("download", err)
		}
		if !chunk.matches(request) {
			t.Fatal("invalid download response")
		}
		downloaded = append(downloaded, chunk.Data...)
		request.Offset += uint64(len(chunk.Data))
		if chunk.EOF {
			break
		}
	}
	if uint64(len(downloaded)) != artifact.Bytes || transferDigest(downloaded) != artifact.Digest {
		t.Fatal("download differs from exported bytes")
	}
	chunk, err := client.ReadWorkspaceExport(ctx, request)
	if err != nil || !chunk.EOF || len(chunk.Data) != 0 {
		t.Fatal("EOF range", err)
	}
	request.Offset = 0
	for _, variant := range []string{"offset", "length", "digest", "expiry"} {
		bad := request
		switch variant {
		case "offset":
			bad.Offset = artifact.Bytes + 1
		case "length":
			bad.Length = MaximumExportChunkBytes + 1
		case "digest":
			bad.Artifact.Digest = strings.Repeat("0", 64)
		case "expiry":
			bad.Export.Access.ExpiresAt = time.Now().Add(-time.Second)
		}
		if _, err := client.ReadWorkspaceExport(ctx, bad); err == nil {
			t.Fatal("invalid download accepted", variant)
		}
	}
	var session DatabaseWorkspaceSession
	if err = executor.readResource("sessions", export.Access.SessionID, &session); err != nil {
		t.Fatal(err)
	}
	old := session
	session.Status.Lifecycle = LifecycleDeleted
	if err = executor.writeResource("sessions", session.ID, session); err != nil {
		t.Fatal(err)
	}
	defer executor.writeResource("sessions", old.ID, old)
	if _, err = client.ReadWorkspaceExport(ctx, request); err == nil {
		t.Fatal("revoked session can still download")
	}
}

// Only the secret delivery is in-memory. The export configuration resolver,
// protected resource reads, native account authentication and grants are real.
func liveWorkspaceExportFixture(t *testing.T, ctx context.Context, prefix string, job TransferJob, name SQLIdentifier, query func(context.Context, string) (string, error)) *LinuxWorkspaceExportConfigs {
	t.Helper()
	id := func(value string) ResourceID {
		result, err := NewResourceID(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	password := []byte(hex.EncodeToString(random))
	wipeBytes(random)
	t.Cleanup(func() { wipeBytes(password) })
	user, _ := ParseSQLIdentifier(prefix)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := query(cleanup, "DROP USER IF EXISTS '"+user.String()+"'@'localhost';"); err != nil {
			t.Error("export account cleanup", err)
		}
	})
	if _, err := query(ctx, "CREATE USER '"+user.String()+"'@'localhost' IDENTIFIED VIA mysql_native_password USING '"+nativePasswordHash(password)+"'; GRANT SELECT, SHOW VIEW ON `"+name.String()+"`.* TO '"+user.String()+"'@'localhost';"); err != nil {
		t.Fatal("export account setup", err)
	}
	secretRef, _ := NewSecretRef(prefix)
	executor := &LinuxMariaDBExecutor{secrets: liveDatabaseSecrets{password: password, ref: secretRef}, now: time.Now}
	if err := executor.initializeRoots(); err != nil {
		t.Fatal(err)
	}
	instance, err := executor.instance(job.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{ID: job.DatabaseID, TenantID: job.TenantID, SiteID: job.SiteID, Generation: job.DatabaseGeneration, Status: instance.Status}
	metadata.Status = ResourceStatus{Lifecycle: LifecycleProvisioning, Health: HealthUnknown, Reconciliation: ReconciliationPending}
	charset, _ := ParseSQLIdentifier("utf8mb4")
	collation, _ := ParseSQLIdentifier("utf8mb4_unicode_ci")
	db := Database{Metadata: metadata, InstanceID: job.InstanceID, Name: name, Charset: charset, Collation: collation, QuotaBytes: 1 << 20}
	principal := DatabasePrincipal{Metadata: metadata, InstanceID: job.InstanceID, Name: user, HostScope: HostScopeLoopback, CredentialSecretRef: secretRef}
	principal.ID = id(prefix + "-principal")
	session := DatabaseWorkspaceSession{Metadata: metadata, DatabaseID: db.ID, PrincipalID: principal.ID, SessionSecretRef: secretRef, ExpiresAt: time.Now().UTC().Add(time.Minute), Limits: SessionLimits{StatementTimeout: time.Minute, MaxRows: 100, MaxResultBytes: 1 << 20, MaxConnections: 1}}
	session.ID = id(prefix + "-session")
	for kind, resource := range map[string]Resource{"databases": db, "principals": principal, "sessions": session} {
		if err := resource.Validate(); err != nil {
			t.Fatal(kind, err)
		}
		if err := executor.writeResource(kind, resource.Meta().ID, resource); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := executor.removeResource(kind, resource.Meta().ID); err != nil {
				t.Error("fixture resource cleanup", err)
			}
		})
	}
	access := WorkspaceAccess{TenantID: job.TenantID, SiteID: job.SiteID, SessionID: session.ID, SessionGeneration: session.Generation, DatabaseID: db.ID, DatabaseGeneration: db.Generation, PrincipalID: principal.ID, PrincipalGeneration: principal.Generation, ExpiresAt: session.ExpiresAt, Limits: session.Limits}
	configs, err := NewLinuxWorkspaceExportConfigs(executor, access)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := configs.TransferClientConfig(ctx, job, name)
	if err != nil {
		t.Fatal(err)
	}
	client := func(sql string) error {
		cmd := exec.CommandContext(ctx, mariaDBClientBinary, "--defaults-file="+descriptor.Path, "--protocol=socket", "--socket="+mariaDBSocket)
		cmd.Stdin = strings.NewReader(sql)
		return cmd.Run()
	}
	if err := client("SELECT User FROM mysql.user;"); err == nil {
		t.Fatal("export account has cross-database access")
	}
	if err := client("CREATE TABLE `" + name.String() + "`.forbidden(id INT);"); err == nil {
		t.Fatal("export account can mutate source")
	}
	if _, err := configs.TransferClientConfig(ctx, job, name); err == nil {
		t.Fatal("connection limit bypassed")
	}
	if err := descriptor.Release(); err != nil {
		t.Fatal(err)
	}
	if err := descriptor.Release(); err != nil {
		t.Fatal("release replay", err)
	}
	if _, err := os.Lstat(descriptor.Path); !os.IsNotExist(err) {
		t.Fatal("credential file leaked")
	}
	for _, variant := range []string{"tenant", "database-generation", "principal-generation", "expiry", "limits"} {
		wrong := *configs
		switch variant {
		case "tenant":
			wrong.access.TenantID, _ = site.NewTenantID("other-transfer-tenant")
		case "database-generation":
			wrong.access.DatabaseGeneration++
		case "principal-generation":
			wrong.access.PrincipalGeneration++
		case "expiry":
			wrong.access.ExpiresAt = time.Now().Add(-time.Second)
		case "limits":
			wrong.access.Limits.MaxResultBytes = 1024
		}
		if d, err := wrong.TransferClientConfig(ctx, job, name); err == nil {
			d.Release()
			t.Fatal(variant, "was accepted")
		}
	}
	principal.Disabled = true
	if err := executor.writeResource("principals", principal.ID, principal); err != nil {
		t.Fatal(err)
	}
	if d, err := configs.TransferClientConfig(ctx, job, name); err == nil {
		d.Release()
		t.Fatal("disabled principal accepted")
	}
	principal.Disabled = false
	if err := executor.writeResource("principals", principal.ID, principal); err != nil {
		t.Fatal(err)
	}
	wrongName, _ := ParseSQLIdentifier("mysql")
	if _, err := configs.TransferClientConfig(ctx, job, wrongName); err == nil {
		t.Fatal("different database accepted")
	}
	return configs
}
