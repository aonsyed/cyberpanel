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

// Only client configuration is a fixture. Both dump/import subprocesses and
// the artifact store are real; this does not qualify least-privilege provisioning.
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
			job := TransferJob{ID: id("job-" + string(compression)), IdempotencyKey: "fixture-" + string(compression), TenantID: tenant, SiteID: siteID, DatabaseID: id("fixture-database"), DatabaseGeneration: 1, InstanceID: id("mariadb-local"), Direction: TransferExport, Format: TransferFormatSQL, Compression: compression, Destination: &artifact, Selection: TransferSelection{Schema: true, Data: true}, Limits: TransferLimits{MaximumBytes: 1 << 20, MaximumRows: 100, MaximumDuration: time.Minute}, ConflictPolicy: TransferConflictFail, Retention: TransferRetention{RetainUntil: now.Add(time.Hour)}, CreatedBy: "fixture-user", CreatedAt: now}
			job.Impact = SealTransferImpactPreview(TransferImpactPreview{DatabaseID: job.DatabaseID, DatabaseGeneration: 1, SchemaObjects: 1, Rows: 2, Bytes: 1024, CapturedAt: now})
			job, err = SealTransferJob(job)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := backend.Export(ctx, job, source, func(TransferStreamProgress) error { return nil })
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
