package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

type transferHistoryCatalog struct {
	TransferDatabaseCatalog
	current Database
}

func (c *transferHistoryCatalog) LoadTransferDatabase(context.Context, site.TenantID, site.SiteID, ResourceID) (Database, error) {
	return c.current, nil
}

type transferHistoryPolicy struct{}

func (transferHistoryPolicy) AuthorizeDatabaseTransfer(_ context.Context, r TransferAuthorizationRequest) error {
	if r.Actor != "owner" {
		return ErrUnauthorized
	}
	return r.Validate()
}
func (transferHistoryPolicy) RecordDatabaseTransfer(_ context.Context, r TransferAuditRecord) error {
	return r.Validate()
}

// Real SQLite jobs/leases/receipts; native execution is not part of this read
// authorization test. The catalog projection and authentication policy are fixtures.
func TestTransferHistorySurvivesPromotionGeneration(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	id := func(value string) ResourceID {
		result, err := NewResourceID(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	tenant, _ := site.NewTenantID("history-tenant")
	siteID, _ := site.NewSiteID("history-site")
	name, _ := ParseSQLIdentifier("historydb")
	charset, _ := ParseSQLIdentifier("utf8mb4")
	collation, _ := ParseSQLIdentifier("utf8mb4_unicode_ci")
	db := Database{Metadata: Metadata{ID: id("history-db"), TenantID: tenant, SiteID: siteID, Generation: 1, Status: ResourceStatus{Lifecycle: LifecycleReady, Health: HealthHealthy, Reconciliation: ReconciliationInSync, ObservedGeneration: 1}}, InstanceID: id("mariadb-local"), Name: name, Charset: charset, Collation: collation, QuotaBytes: 1 << 20}
	artifact := TransferArtifactDescriptor{Identity: TransferArtifactIdentity{StoreID: id("history-store"), ArtifactID: id("history-artifact"), Generation: 1}, Format: TransferFormatSQL, Compression: TransferCompressionNone, Bytes: 1, Rows: 1, Digest: transferDigest([]byte("fixture")), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	job, err := SealTransferJob(TransferJob{ID: id("history-job"), IdempotencyKey: "history-create", TenantID: tenant, SiteID: siteID, DatabaseID: db.ID, DatabaseGeneration: 1, InstanceID: db.InstanceID, Direction: TransferImport, Format: TransferFormatSQL, Compression: TransferCompressionNone, Source: &artifact, Selection: TransferSelection{Schema: true, Data: true}, Limits: TransferLimits{MaximumBytes: 1 << 20, MaximumRows: 100, MaximumDuration: time.Minute}, ConflictPolicy: TransferConflictFail, Retention: TransferRetention{RetainUntil: now.Add(time.Hour)}, Impact: SealTransferImpactPreview(TransferImpactPreview{DatabaseID: db.ID, DatabaseGeneration: 1, Rows: 1, Bytes: 1, CapturedAt: now}), CreatedBy: "owner", CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := OpenSQLiteTransferRepository(filepath.Join(t.TempDir(), "transfers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err = repository.BootstrapTransfers(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := repository.CreateTransfer(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := repository.ClaimTransfer(ctx, job.ID, "worker", state.Generation, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	process := SealTransferProcessReceipt(TransferProcessReceipt{ExitCode: 0, BytesProcessed: 1, RowsProcessed: 1, StderrDigest: transferDigest(nil), InputVerified: true, CompletedAt: now})
	receipt := SealTransferReceipt(TransferReceipt{JobID: job.ID, JobDigest: job.Digest, Attempt: lease.Attempt, Generation: lease.Generation + 1, Status: TransferCompleted, ResumeClass: TransferResumeNotSafe, Process: &process, VerificationDigest: transferDigest([]byte("verified")), PromotionDigest: transferDigest([]byte("promoted")), SourcePreserved: true, MutationPossible: true, OccurredAt: now})
	if err = repository.CompleteTransfer(ctx, lease, receipt); err != nil {
		t.Fatal(err)
	}
	catalog := &transferHistoryCatalog{current: db}
	catalog.current.Generation = 2
	catalog.current.Status.ObservedGeneration = 2
	service := TransferService{repository: repository, catalog: catalog, authorizer: transferHistoryPolicy{}, audit: transferHistoryPolicy{}, now: func() time.Time { return now }}
	if got, err := service.Inspect(ctx, "owner", job.ID); err != nil || got.Status != TransferCompleted {
		t.Fatal("completed job unreadable after promotion", err)
	}
	if got, err := service.InspectReceipt(ctx, "owner", job.ID); err != nil || got.Digest != receipt.Digest {
		t.Fatal("completed receipt unreadable after promotion", err)
	}
	if _, err := service.reauthorizeDatabase(ctx, job); err == nil {
		t.Fatal("old generation executable")
	}
	if _, err := service.Run(ctx, "owner", "worker", job.ID, receipt.Generation, time.Minute); err == nil {
		t.Fatal("old generation run accepted")
	}
	if err := service.Cancel(ctx, "owner", job.ID, receipt.Generation); err == nil {
		t.Fatal("old generation cancellation accepted")
	}
	if _, err := service.InspectReceipt(ctx, "intruder", job.ID); err == nil {
		t.Fatal("unauthorized history reader accepted")
	}
	for _, variant := range []string{"tenant", "site", "instance", "generation", "unhealthy"} {
		catalog.current = db
		catalog.current.Generation = 2
		switch variant {
		case "tenant":
			catalog.current.TenantID, _ = site.NewTenantID("different-tenant")
		case "site":
			catalog.current.SiteID, _ = site.NewSiteID("different-site")
		case "instance":
			catalog.current.InstanceID = id("different-instance")
		case "generation":
			catalog.current.Generation = 0
		case "unhealthy":
			catalog.current.Status.Health = HealthUnknown
		}
		if _, err := service.Inspect(ctx, "owner", job.ID); err == nil {
			t.Fatal("invalid history scope accepted", variant)
		}
		if _, err := service.InspectReceipt(ctx, "owner", job.ID); err == nil {
			t.Fatal("invalid receipt scope accepted", variant)
		}
	}
}
