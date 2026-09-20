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

func TestQEMUTransferNativeRoundTrip(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_TRANSFER") != "1" {
		t.Skip("requires disposable QEMU MariaDB")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root inside QEMU")
	}
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
	if _, err := query(ctx, "CREATE DATABASE `"+source.String()+"`; CREATE DATABASE `"+target.String()+"`; CREATE TABLE `"+source.String()+"`.sample(id INT PRIMARY KEY, body TEXT, raw_bytes BLOB); INSERT INTO `"+source.String()+"`.sample VALUES(1,'transfer round trip',X'0001FF'),(2,NULL,NULL);"); err != nil {
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
	if _, err = query(ctx, "CREATE USER '"+importUser+"'@'localhost' IDENTIFIED BY '"+password+"'; GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,ALTER,INDEX,DROP,LOCK TABLES ON `"+target.String()+"`.* TO '"+importUser+"'@'localhost';"); err != nil {
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
			verifyOrdinaryNativeImports(t, ctx, store, backend, job, target, query)
			verifyIsolatedNativeImport(t, ctx, exportConfigs.executor, store, job, query)
		})
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
	if err = executor.discardTransferImport(ctx, job, isolated); err != nil {
		t.Fatal("discard", err)
	}
	count, err := query(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+isolated.Name.String()+"';")
	if err != nil || count != "0" {
		t.Fatal("isolated database retained", err)
	}
}

func verifyOrdinaryNativeImports(t *testing.T, ctx context.Context, store *LinuxTransferArtifactStore, backend *LinuxTransferBackend, job TransferJob, target SQLIdentifier, query func(context.Context, string) (string, error)) {
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
	for _, bom := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "utf8-bom"}[bom], func(t *testing.T) {
			plain := append([]byte(nil), raw...)
			if bom {
				plain = append([]byte{0xef, 0xbb, 0xbf}, plain...)
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
			identity.Generation += 10
			if bom {
				identity.Generation++
			}
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
			if err != nil || got != "1:transfer round trip:0001FF\n2:NULL:NULL" {
				t.Fatal("ordinary import contents differ", err)
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
