//go:build linux

package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func verifyServiceNativeImport(t *testing.T, ctx context.Context, executor *LinuxMariaDBExecutor, client *BrokerClient, sourceExport, job TransferJob, query func(context.Context, string) (string, error)) {
	t.Helper()
	live, err := executor.transferImportSource(job)
	if err != nil {
		t.Fatal(err)
	}
	live.ID, _ = NewResourceID("service-" + job.ID.String())
	live.Name, _ = ParseSQLIdentifier("cpsvc" + job.Digest[:24])
	job.ID, _ = NewResourceID("service-job-" + job.ID.String())
	job.IdempotencyKey = "service-" + job.IdempotencyKey
	job.DatabaseID = live.ID
	job.CreatedBy = "owner"
	job.ExportSource = &sourceExport
	job.CreatedAt = time.Now().UTC()
	job.Impact = SealTransferImpactPreview(TransferImpactPreview{DatabaseID: live.ID, DatabaseGeneration: 1, CapturedAt: job.CreatedAt.Add(-time.Second)})
	job, err = SealTransferJob(job)
	if err != nil {
		t.Fatal(err)
	}
	isolatedID, isolatedName := isolatedTransferIdentity(job)
	if _, err = query(ctx, "CREATE DATABASE `"+live.Name.String()+"` CHARACTER SET "+live.Charset.String()+" COLLATE "+live.Collation.String()+";"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := query(cleanup, "DROP DATABASE IF EXISTS `"+live.Name.String()+"`; DROP DATABASE IF EXISTS `"+isolatedName.String()+"`;"); err != nil {
			t.Error(err)
		}
		if err := executor.removeResource("databases", live.ID); err != nil {
			t.Error(err)
		}
		if err := executor.removeResource("transfer-imports", isolatedID); err != nil {
			t.Error(err)
		}
	})
	if err = executor.writeResource("databases", live.ID, live); err != nil {
		t.Fatal(err)
	}
	control, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "service-control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetMaxOpenConns(1)
	repository, err := NewSQLRepository(control)
	if err != nil {
		t.Fatal(err)
	}
	if err = repository.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	coreLive := live
	coreLive.Status = readyStatus(1)
	if err = repository.EnsureBootstrapResources(ctx, coreLive); err != nil {
		t.Fatal(err)
	}
	execution, err := NewBrokerImportExecution(NewCoordinator(repository, client, SystemClock{}), job)
	if err != nil {
		t.Fatal(err)
	}
	unbound := job
	unbound.ExportSource = nil
	unbound, err = SealTransferJob(unbound)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewBrokerImportExecution(NewCoordinator(repository, client, SystemClock{}), unbound); err == nil {
		t.Fatal("worker accepted missing durable source binding")
	}
	for _, nested := range []bool{false, true} {
		changed := job
		changedSource := sourceExport
		if nested {
			changedSource.ExportSource = &sourceExport
		} else {
			changedSource.CreatedBy = "different-source-owner"
		}
		changedSource.Digest = transferJobDigest(changedSource)
		changed.ExportSource = &changedSource
		if _, err = SealTransferJob(changed); err == nil {
			t.Fatal("changed or nested source export accepted")
		}
	}
	transfers, err := NewSQLiteTransferRepository(control)
	if err != nil {
		t.Fatal(err)
	}
	if err = transfers.BootstrapTransfers(ctx); err != nil {
		t.Fatal(err)
	}
	// Authorization and audit delivery remain fixtures; all execution adapters,
	// job/projection persistence, socket transport and native SQL are real.
	service := TransferService{repository: transfers, catalog: execution, backend: execution, authorizer: transferHistoryPolicy{}, audit: transferHistoryPolicy{}, now: time.Now}
	if _, err = service.Create(ctx, "intruder", job, nil); err == nil {
		t.Fatal("unauthorized import admitted")
	}
	if _, err = query(ctx, "CREATE TABLE `"+live.Name.String()+"`.existing(id INT); INSERT INTO `"+live.Name.String()+"`.existing VALUES(77);"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Create(ctx, "owner", job, nil); err == nil {
		t.Fatal("nonempty destination admitted")
	}
	if value, err := query(ctx, "SELECT id FROM `"+live.Name.String()+"`.existing;"); err != nil || value != "77" {
		t.Fatal("preview modified live data", err)
	}
	if _, err = query(ctx, "DROP TABLE `"+live.Name.String()+"`.existing;"); err != nil {
		t.Fatal(err)
	}
	state, err := service.Create(ctx, "owner", job, nil)
	if err != nil {
		t.Fatal("create service import", err)
	}
	if _, err = service.Create(ctx, "owner", job, nil); err != nil {
		t.Fatal("create replay", err)
	}
	// Reconstruct execution solely from the durable job, not the caller's
	// original source-export variable or an in-memory authority map.
	loaded, err := transfers.LoadTransfer(ctx, job.ID)
	if err != nil || loaded.Job.ExportSource == nil || loaded.Job.ExportSource.Digest != sourceExport.Digest {
		t.Fatal("source binding not persisted", err)
	}
	execution, err = NewBrokerImportExecution(NewCoordinator(repository, client, SystemClock{}), loaded.Job)
	if err != nil {
		t.Fatal("reconstruct persisted import", err)
	}
	service.catalog, service.backend = execution, execution
	if _, err = service.Run(ctx, "intruder", "worker", job.ID, state.Generation, time.Minute); err == nil {
		t.Fatal("unauthorized import executed")
	}
	receipt, err := service.Run(ctx, "owner", "worker", job.ID, state.Generation, time.Minute)
	if err != nil || receipt.Status != TransferCompleted || receipt.Validate(job) != nil {
		t.Fatal("service native import", receipt.Status, err)
	}
	if value, err := query(ctx, "SELECT CONCAT(id,':',COALESCE(body,'NULL'),':',COALESCE(HEX(raw_bytes),'NULL')) FROM `"+live.Name.String()+"`.sample ORDER BY id;"); err != nil || value != "1:transfer round trip:0001FF\n2:NULL:NULL" {
		t.Fatal("service imported data mismatch", err)
	}
	current, err := service.Inspect(ctx, "owner", job.ID)
	if err != nil || current.Status != TransferCompleted {
		t.Fatal("completed import job unreadable", err)
	}
	stored, err := service.InspectReceipt(ctx, "owner", job.ID)
	if err != nil || stored.Digest != receipt.Digest {
		t.Fatal("completed import receipt unreadable", err)
	}
	projected, err := execution.LoadTransferDatabase(ctx, job.TenantID, job.SiteID, job.DatabaseID)
	if err != nil || projected.Generation != 2 || !workspaceReady(projected.Metadata) || projected.Status.ProofDigest != receipt.PromotionDigest {
		t.Fatal("service did not project promotion", err)
	}
	if _, err = service.Run(ctx, "owner", "worker", job.ID, current.Generation, time.Minute); err == nil {
		t.Fatal("completed import ran twice")
	}
}

func TestTransferImpactFreshnessAndContent(t *testing.T) {
	now := time.Now().UTC()
	id, _ := NewResourceID("preview-db")
	expected := SealTransferImpactPreview(TransferImpactPreview{DatabaseID: id, DatabaseGeneration: 1, SchemaObjects: 1, Rows: 2, Bytes: 512, CapturedAt: now.Add(-time.Minute)})
	fresh := expected
	fresh.CapturedAt = now
	fresh = SealTransferImpactPreview(fresh)
	if !sameTransferImpact(fresh, expected, now) {
		t.Fatal("fresh identical observation rejected")
	}
	for _, change := range []func(*TransferImpactPreview){
		func(p *TransferImpactPreview) { p.Rows++ }, func(p *TransferImpactPreview) { p.Bytes++ }, func(p *TransferImpactPreview) { p.SchemaObjects++ }, func(p *TransferImpactPreview) { p.DatabaseGeneration++ }, func(p *TransferImpactPreview) { p.CapturedAt = now.Add(-16 * time.Minute) }, func(p *TransferImpactPreview) { p.CapturedAt = now.Add(2 * time.Minute) },
	} {
		changed := fresh
		change(&changed)
		changed = SealTransferImpactPreview(changed)
		if sameTransferImpact(changed, expected, now) {
			t.Fatal("changed or stale observation accepted")
		}
	}
}
