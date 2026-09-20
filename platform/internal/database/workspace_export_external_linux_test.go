//go:build linux

package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

type externalExportSecrets struct{ *liveTLSSecrets }

func (source externalExportSecrets) PrincipalPassword(context.Context, SecretRef, ResourceID, string, string) ([]byte, error) {
	return append([]byte(nil), source.password...), nil
}

// Runs inside the existing disposable TLS server fixture, never the host.
func liveExternalWorkspaceExport(t *testing.T, ctx context.Context, instance DatabaseInstance, secrets *liveTLSSecrets, rootQuery func(string) ([]byte, error)) {
	t.Helper()
	if _, err := rootQuery("CREATE DATABASE qemu_export; CREATE TABLE qemu_export.sample(id INT, body TEXT); INSERT INTO qemu_export.sample VALUES(1,'external export'); GRANT SELECT,SHOW VIEW ON qemu_export.* TO 'qemu_tls'@'127.0.0.1';"); err != nil {
		t.Fatal(err)
	}
	id := func(s string) ResourceID {
		value, err := NewResourceID(s)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	tenant, _ := site.NewTenantID("qemu-external-export")
	siteID, _ := site.NewSiteID("qemu-external-export")
	ready := ResourceStatus{Lifecycle: LifecycleReady, Health: HealthHealthy, Reconciliation: ReconciliationInSync, ObservedGeneration: 1}
	instance.Status = ready
	executor := &LinuxMariaDBExecutor{secrets: externalExportSecrets{secrets}, now: time.Now}
	if err := executor.initializeRoots(); err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{ID: id("qemu-external-export-db"), TenantID: tenant, SiteID: siteID, Generation: 1, Status: ready}
	name, _ := ParseSQLIdentifier("qemu_export")
	charset, _ := ParseSQLIdentifier("utf8mb4")
	collation, _ := ParseSQLIdentifier("utf8mb4_unicode_ci")
	db := Database{Metadata: metadata, InstanceID: instance.ID, Name: name, Charset: charset, Collation: collation, QuotaBytes: 1 << 20}
	user, _ := ParseSQLIdentifier("qemu_tls")
	ref, _ := NewSecretRef("qemu-external-export-secret")
	principal := DatabasePrincipal{Metadata: metadata, InstanceID: instance.ID, Name: user, HostScope: HostScopeLoopback, CredentialSecretRef: ref}
	principal.ID = id("qemu-external-export-principal")
	session := DatabaseWorkspaceSession{Metadata: metadata, DatabaseID: db.ID, PrincipalID: principal.ID, SessionSecretRef: ref, ExpiresAt: time.Now().UTC().Add(time.Minute), Limits: SessionLimits{StatementTimeout: time.Minute, MaxRows: 100, MaxResultBytes: 1 << 20, MaxConnections: 1}}
	session.ID = id("qemu-external-export-session")
	for kind, resource := range map[string]Resource{"instances": instance, "databases": db, "principals": principal, "sessions": session} {
		if err := resource.Validate(); err != nil {
			t.Fatal(kind, err)
		}
		if err := executor.writeResource(kind, resource.Meta().ID, resource); err != nil {
			t.Fatal(err)
		}
		defer executor.removeResource(kind, resource.Meta().ID)
	}
	access := WorkspaceAccess{TenantID: tenant, SiteID: siteID, SessionID: session.ID, SessionGeneration: 1, DatabaseID: db.ID, DatabaseGeneration: 1, PrincipalID: principal.ID, PrincipalGeneration: 1, ExpiresAt: session.ExpiresAt, Limits: session.Limits}
	client := liveExportBroker(t, ctx, executor)
	coordinator := NewCoordinator(liveExportRepository{executor: executor}, client, liveExportClock{})
	call := WorkspaceCall{TenantID: tenant, SiteID: siteID, SessionID: session.ID, SessionGeneration: 1}
	store, err := NewLinuxTransferArtifactStore(workspaceExportRoot, 1<<20, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ca := append([]byte(nil), secrets.ca...)
	defer func() { secrets.ca = ca }()
	for _, variant := range []string{"valid", "gzip", "wrong-ca", "wrong-name", "wrong-tenant"} {
		t.Run("external-export-"+variant, func(t *testing.T) {
			secrets.ca = ca
			target := instance
			external := *instance.External
			target.External = &external
			if variant == "wrong-ca" {
				secrets.ca, _, _, _, _ = liveTLSCertificate(t)
			}
			if variant == "wrong-name" {
				external.Endpoint.Host, external.ServerName = "localhost", "localhost"
			}
			if err := executor.writeResource("instances", target.ID, target); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			job := TransferJob{ID: id("qemu-export-" + variant), IdempotencyKey: variant, TenantID: tenant, SiteID: siteID, DatabaseID: db.ID, DatabaseGeneration: 1, InstanceID: instance.ID, Direction: TransferExport, Format: TransferFormatSQL, Compression: TransferCompressionNone, Selection: TransferSelection{Schema: true, Data: true}, Limits: TransferLimits{MaximumBytes: 1 << 20, MaximumRows: 100, MaximumDuration: time.Minute}, ConflictPolicy: TransferConflictFail, Retention: TransferRetention{RetainUntil: now.Add(time.Hour)}, CreatedBy: "qemu-owner", CreatedAt: now}
			job.Impact = SealTransferImpactPreview(TransferImpactPreview{DatabaseID: db.ID, DatabaseGeneration: 1, SchemaObjects: 1, Rows: 1, Bytes: 1024, CapturedAt: now})
			if variant == "gzip" {
				job.Compression = TransferCompressionGzip
			}
			artifact := WorkspaceExportArtifact(job)
			job.Destination = &artifact
			job, err = SealTransferJob(job)
			if err != nil {
				t.Fatal(err)
			}
			if variant == "valid" || variant == "gzip" {
				job, err = coordinator.PrepareWorkspaceExport(ctx, call, "qemu-owner", "external-"+variant, WorkspaceExportOptions{Compression: job.Compression, Selection: job.Selection})
				if err != nil {
					t.Fatal("external export preparation through broker", err)
				}
				artifact = *job.Destination
				if _, err := coordinator.RunWorkspaceExport(ctx, call, "other-actor", job); err == nil {
					t.Fatal("different export actor accepted")
				}
			}
			path, err := store.artifactPath(artifact)
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(path)
			request := WorkspaceExportRequest{Access: access, Job: job}
			if err := request.validate(time.Now().UTC()); err != nil {
				t.Fatal("fixture request", err)
			}
			if _, _, _, err := executor.authorizeWorkspaceExport(ctx, access, job); err != nil {
				t.Fatal("fixture resource authorization", err)
			}
			if variant == "wrong-tenant" {
				request.Access.TenantID, _ = site.NewTenantID("other-tenant")
			}
			var receipt TransferProcessReceipt
			if variant == "valid" || variant == "gzip" {
				receipt, err = coordinator.RunWorkspaceExport(ctx, call, "qemu-owner", job)
			} else {
				receipt, err = executor.ExportWorkspaceDatabase(ctx, request)
			}
			if variant != "valid" && variant != "gzip" {
				if err == nil {
					t.Fatal("unauthorized export succeeded")
				}
				if variant != "wrong-tenant" && receipt.ExitCode == 0 {
					t.Fatal("TLS refusal did not reach native dump")
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("failed export published artifact")
				}
				return
			}
			if err != nil || receipt.RowsProcessed != 1 {
				t.Fatalf("external export: %v, rows %d", err, receipt.RowsProcessed)
			}
			reader, err := store.OpenTransferArtifact(ctx, artifact)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			chunkRequest := WorkspaceExportReadRequest{Export: request, Artifact: *receipt.Artifact, Length: MaximumExportChunkBytes}
			chunk, err := coordinator.DownloadWorkspaceExport(ctx, call, "qemu-owner", job, *receipt.Artifact, 0, MaximumExportChunkBytes)
			if err != nil || !chunk.matches(chunkRequest) || !bytes.Equal(chunk.Data, payload) {
				t.Fatal("external export download mismatch", err)
			}
			chunkRequest.Export.Access.TenantID, _ = site.NewTenantID("other-tenant")
			if _, err := executor.ReadWorkspaceExport(ctx, chunkRequest); err == nil {
				t.Fatal("cross-tenant export download accepted")
			}
			wrongCall := call
			wrongCall.SessionGeneration++
			if _, err := coordinator.DownloadWorkspaceExport(ctx, wrongCall, "qemu-owner", job, *receipt.Artifact, 0, MaximumExportChunkBytes); err == nil {
				t.Fatal("stale session downloaded external artifact")
			}
			if variant == "gzip" {
				compressed, err := gzip.NewReader(bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				payload, err = io.ReadAll(compressed)
				compressed.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err != nil || !strings.Contains(string(payload), "external export") {
				t.Fatal("missing native row", err)
			}
		})
	}
}
