package database

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// Native effects are controlled at the catalog/backend seam in this test;
// jobs, leases, phase checkpoints and terminal receipts use real SQLite.
type promotionFailureCatalog struct {
	TransferDatabaseCatalog
	database     Database
	isolated     IsolatedTransferDatabase
	verification TransferVerification
	promotion    TransferPromotion
	err          error
	discarded    int
	cancel       context.CancelFunc
}

func (c *promotionFailureCatalog) LoadTransferDatabase(context.Context, site.TenantID, site.SiteID, ResourceID) (Database, error) {
	return c.database, nil
}
func (c *promotionFailureCatalog) AllocateIsolatedTransferDatabase(context.Context, TransferJob, Database) (IsolatedTransferDatabase, error) {
	return c.isolated, nil
}
func (c *promotionFailureCatalog) VerifyIsolatedTransferDatabase(context.Context, TransferJob, IsolatedTransferDatabase) (TransferVerification, error) {
	return c.verification, nil
}
func (c *promotionFailureCatalog) PromoteIsolatedTransferDatabase(context.Context, TransferJob, Database, IsolatedTransferDatabase, TransferRestorePoint) (TransferPromotion, error) {
	if c.cancel != nil {
		c.cancel()
	}
	return c.promotion, c.err
}
func (c *promotionFailureCatalog) DiscardIsolatedTransferDatabase(context.Context, TransferJob, IsolatedTransferDatabase) error {
	c.discarded++
	return nil
}

type promotionFailureBackend struct {
	TransferBackend
	process TransferProcessReceipt
}

type promotionOutcomeAudit struct {
	t        *testing.T
	terminal bool
}

func (audit *promotionOutcomeAudit) RecordDatabaseTransfer(ctx context.Context, record TransferAuditRecord) error {
	if record.Outcome == "transfer_completed" || record.Outcome == "transfer_ambiguous" || record.Outcome == "transfer_failed" || record.Outcome == "transfer_cancelled" {
		audit.terminal = true
		deadline, ok := ctx.Deadline()
		if ctx.Err() != nil || !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
			audit.t.Fatal("terminal audit must have a live bounded context")
		}
	}
	return record.Validate()
}

func (b promotionFailureBackend) Import(_ context.Context, _ TransferJob, _ SQLIdentifier, checkpoint TransferCheckpoint) (TransferProcessReceipt, error) {
	if err := checkpoint(TransferStreamProgress{Bytes: b.process.BytesProcessed, Rows: b.process.RowsProcessed, SafePoint: true}); err != nil {
		return TransferProcessReceipt{}, err
	}
	return b.process, nil
}

func TestTransferServicePreservesUncertainPromotion(t *testing.T) {
	for _, test := range []struct {
		name                string
		err                 error
		promoted, preserved bool
		status              TransferStatus
		discarded           int
	}{
		{"native_success_projection_failure", errors.Join(ErrAmbiguous, errors.New("projection failed")), true, true, TransferAmbiguous, 0},
		{"ambiguous_preserved_source", ErrAmbiguous, false, true, TransferAmbiguous, 0},
		{"reported_promotion_with_error", errors.New("response unavailable"), true, true, TransferAmbiguous, 0},
		{"source_not_proven_preserved", ErrUnavailable, false, false, TransferAmbiguous, 0},
		{"definite_pre_promotion_conflict", ErrConflict, false, true, TransferFailed, 1},
		{"success", nil, true, true, TransferCompleted, 0},
		{"disconnect_after_promotion", nil, true, true, TransferCompleted, 0},
		{"disconnect_uncertain_promotion", ErrAmbiguous, false, false, TransferAmbiguous, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := time.Now().UTC()
			id := func(raw string) ResourceID {
				value, err := NewResourceID(raw)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			identifier := func(raw string) SQLIdentifier {
				value, err := ParseSQLIdentifier(raw)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			tenant, _ := site.NewTenantID("promotion-tenant")
			siteID, _ := site.NewSiteID("promotion-site")
			database := Database{Metadata: Metadata{ID: id("promotion-db"), TenantID: tenant, SiteID: siteID, Generation: 1, Status: readyStatus(1)}, InstanceID: id("mariadb-local"), Name: identifier("promotiondb"), Charset: identifier("utf8mb4"), Collation: identifier("utf8mb4_unicode_ci"), QuotaBytes: 1 << 20}
			artifact := TransferArtifactDescriptor{Identity: TransferArtifactIdentity{StoreID: id("export-store"), ArtifactID: id("export-artifact"), Generation: 1}, Format: TransferFormatSQL, Compression: TransferCompressionNone, Bytes: 1, Rows: 1, Digest: transferDigest([]byte("source")), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			job, err := SealTransferJob(TransferJob{ID: id("promotion-job"), IdempotencyKey: "promotion-create", TenantID: tenant, SiteID: siteID, DatabaseID: database.ID, DatabaseGeneration: 1, InstanceID: database.InstanceID, Direction: TransferImport, Format: artifact.Format, Compression: artifact.Compression, Source: &artifact, Selection: TransferSelection{Schema: true, Data: true}, Limits: TransferLimits{MaximumBytes: 1 << 20, MaximumRows: 100, MaximumDuration: time.Minute}, ConflictPolicy: TransferConflictFail, Retention: TransferRetention{RetainUntil: now.Add(time.Hour)}, Impact: SealTransferImpactPreview(TransferImpactPreview{DatabaseID: database.ID, DatabaseGeneration: 1, Rows: 1, Bytes: 1, CapturedAt: now}), CreatedBy: "owner", CreatedAt: now})
			if err != nil {
				t.Fatal(err)
			}
			isolated := IsolatedTransferDatabase{Token: id("isolated-token"), InstanceID: database.InstanceID, Name: identifier("isolateddb"), SourceDatabaseID: database.ID, SourceGeneration: 1, CreatedAt: now}
			verification := TransferVerification{IsolatedToken: isolated.Token, SchemaDigest: transferDigest([]byte("schema")), RowCount: 1, Bytes: 1, IntegrityDigest: transferDigest([]byte("integrity")), Health: HealthHealthy, VerifiedAt: now}
			verification.Digest = transferVerificationDigest(verification)
			promotion := TransferPromotion{JobID: job.ID, IsolatedToken: isolated.Token, SourceDatabaseID: database.ID, SourceGeneration: 1, TargetGeneration: 2, SourcePreserved: test.preserved, Promoted: test.promoted, ProofDigest: transferDigest([]byte("native-proof")), CompletedAt: now}
			process := SealTransferProcessReceipt(TransferProcessReceipt{BytesProcessed: 1, RowsProcessed: 1, StderrDigest: transferDigest(nil), InputVerified: true, CompletedAt: now})
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
			catalog := &promotionFailureCatalog{database: database, isolated: isolated, verification: verification, promotion: promotion, err: test.err}
			if test.name == "disconnect_after_promotion" || test.name == "disconnect_uncertain_promotion" {
				catalog.cancel = cancel
			}
			audit := &promotionOutcomeAudit{t: t}
			service := TransferService{repository: repository, catalog: catalog, backend: promotionFailureBackend{process: process}, authorizer: transferHistoryPolicy{}, audit: audit, now: time.Now}
			receipt, err := service.Run(ctx, "owner", "worker", job.ID, state.Generation, time.Minute)
			if receipt.Status != test.status || catalog.discarded != test.discarded {
				t.Fatalf("status=%s discard=%d error=%v; want status=%s discard=%d", receipt.Status, catalog.discarded, err, test.status, test.discarded)
			}
			if test.status == TransferAmbiguous && (!errors.Is(err, ErrAmbiguous) || receipt.ResumeClass != TransferResumeNotSafe || !receipt.MutationPossible || receipt.PromotionDigest != promotion.ProofDigest || receipt.VerificationDigest != verification.Digest) {
				t.Fatal("uncertain promotion lost its recovery evidence", err)
			}
			stored, loadErr := repository.LatestTransferReceipt(context.Background(), job.ID)
			if loadErr != nil || stored.Digest != receipt.Digest {
				t.Fatal("promotion outcome not durable", loadErr)
			}
			if !audit.terminal {
				t.Fatal("terminal outcome not audited")
			}
			if test.status == TransferAmbiguous {
				current, err := repository.LoadTransfer(context.Background(), job.ID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = repository.ClaimTransfer(context.Background(), job.ID, "another-worker", current.Generation, time.Now().UTC(), time.Minute); err == nil {
					t.Fatal("ambiguous promotion could restart import")
				}
			}
		})
	}
}
