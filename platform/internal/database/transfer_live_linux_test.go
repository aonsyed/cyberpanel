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

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// Import still uses a root fixture. Export uses the production session-bound
// config resolver and a native SELECT/SHOW VIEW account; only secret delivery
// for that account is a fixture. All SQL subprocesses and artifacts are real.
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
	if err = os.WriteFile(configPath, []byte("[client]\nuser=root\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := NewLinuxTransferArtifactStore(filepath.Join(t.TempDir(), "artifacts"), 1<<20, time.Now)
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
			job, err = SealTransferJob(job)
			if err != nil {
				t.Fatal(err)
			}
			exportConfigs := liveWorkspaceExportFixture(t, ctx, prefix, job, source, query)
			exportBackend, err := NewLinuxTransferBackend(store, exportConfigs, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := exportBackend.Export(ctx, job, source, func(TransferStreamProgress) error { return nil })
			if err != nil {
				t.Fatalf("native export: %v (exit %d)", err, receipt.ExitCode)
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
		})
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
	metadata.Status.ObservedGeneration = metadata.Generation
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
