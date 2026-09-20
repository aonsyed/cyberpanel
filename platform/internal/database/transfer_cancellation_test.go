package database

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

func cancellationJob(t *testing.T) TransferJob {
	t.Helper()
	now := time.Now().UTC()
	id := func(raw string) ResourceID {
		value, err := NewResourceID(raw)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	tenant, _ := site.NewTenantID("cancel-tenant")
	siteID, _ := site.NewSiteID("cancel-site")
	artifact := TransferArtifactDescriptor{Identity: TransferArtifactIdentity{StoreID: id("cancel-store"), ArtifactID: id("cancel-artifact"), Generation: 1}, Format: TransferFormatSQL, Compression: TransferCompressionNone, Bytes: 1, Rows: 1, Digest: transferDigest([]byte("fixture")), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	job, err := SealTransferJob(TransferJob{ID: id("cancel-job"), IdempotencyKey: "cancel-create", TenantID: tenant, SiteID: siteID, DatabaseID: id("cancel-db"), DatabaseGeneration: 1, InstanceID: id("mariadb-local"), Direction: TransferImport, Source: &artifact, Format: TransferFormatSQL, Compression: TransferCompressionNone, Selection: TransferSelection{Schema: true, Data: true}, Limits: TransferLimits{MaximumBytes: 1 << 20, MaximumRows: 100, MaximumDuration: time.Minute}, ConflictPolicy: TransferConflictFail, Retention: TransferRetention{RetainUntil: now.Add(time.Hour)}, Impact: SealTransferImpactPreview(TransferImpactPreview{DatabaseID: id("cancel-db"), DatabaseGeneration: 1, CapturedAt: now}), CreatedBy: "owner", CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func TestQueuedTransferCancellationIsTerminal(t *testing.T) {
	ctx := context.Background()
	repository, err := OpenSQLiteTransferRepository(filepath.Join(t.TempDir(), "transfer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err = repository.BootstrapTransfers(ctx); err != nil {
		t.Fatal(err)
	}
	job := cancellationJob(t)
	state, err := repository.CreateTransfer(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if err = repository.RequestTransferCancellation(ctx, job.ID, state.Generation+1, time.Now().UTC()); !errors.Is(err, ErrTransferStale) {
		t.Fatal("stale cancellation accepted", err)
	}
	if err = repository.RequestTransferCancellation(ctx, job.ID, state.Generation, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	after, err := repository.LoadTransfer(ctx, job.ID)
	if err != nil || after.Status != TransferCancelled || !after.CancellationRequested || after.Generation != state.Generation+1 || after.Progress.Phase != TransferPhaseTerminal {
		t.Fatalf("queued cancellation did not terminate: status=%s generation=%d err=%v", after.Status, after.Generation, err)
	}
	receipt, err := repository.LatestTransferReceipt(ctx, job.ID)
	if err != nil || receipt.Validate(job) != nil || receipt.Status != TransferCancelled || receipt.Process != nil || receipt.MutationPossible || !receipt.SourcePreserved || receipt.Generation != after.Generation {
		t.Fatal("missing safe cancellation receipt", err)
	}
	if _, err = repository.ClaimTransfer(ctx, job.ID, "worker", after.Generation, time.Now().UTC(), time.Minute); !errors.Is(err, ErrTransferStale) {
		t.Fatal("cancelled job executable", err)
	}
}

func TestTransferCancellationAtomicityAndRunningSafePoint(t *testing.T) {
	for _, mode := range []string{"receipt_failure", "running"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			repository, err := OpenSQLiteTransferRepository(filepath.Join(t.TempDir(), "transfer.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer repository.Close()
			if err = repository.BootstrapTransfers(ctx); err != nil {
				t.Fatal(err)
			}
			job := cancellationJob(t)
			state, err := repository.CreateTransfer(ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "receipt_failure" {
				if _, err = repository.db.ExecContext(ctx, `CREATE TRIGGER fail_receipt BEFORE INSERT ON database_transfer_receipts_v1 BEGIN SELECT RAISE(ABORT, 'fixture receipt failure'); END`); err != nil {
					t.Fatal(err)
				}
				if err = repository.RequestTransferCancellation(ctx, job.ID, state.Generation, time.Now().UTC()); err == nil {
					t.Fatal("receipt failure ignored")
				}
				after, err := repository.LoadTransfer(ctx, job.ID)
				if err != nil || after.Status != TransferQueued || after.CancellationRequested || after.Generation != state.Generation || after.Progress.Digest != state.Progress.Digest {
					t.Fatal("partial cancellation persisted", err)
				}
				return
			}
			lease, err := repository.ClaimTransfer(ctx, job.ID, "worker", state.Generation, time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if err = repository.RequestTransferCancellation(ctx, job.ID, lease.Generation, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			after, err := repository.LoadTransfer(ctx, job.ID)
			if err != nil || after.Status != TransferRunning || !after.CancellationRequested || after.Generation != lease.Generation {
				t.Fatal("running cancellation finalized prematurely", err)
			}
			progress := SealTransferProgress(TransferProgress{JobID: job.ID, Generation: lease.Generation + 1, Phase: TransferPhaseStreaming, SafePoint: false, UpdatedAt: time.Now().UTC()})
			lease, err = repository.CheckpointTransfer(ctx, lease, progress)
			if err != nil {
				t.Fatal("unsafe checkpoint interrupted", err)
			}
			progress.Generation, progress.SafePoint, progress.UpdatedAt = lease.Generation+1, true, time.Now().UTC()
			progress = SealTransferProgress(progress)
			if _, err = repository.CheckpointTransfer(ctx, lease, progress); !errors.Is(err, ErrTransferCancelled) {
				t.Fatal("safe checkpoint ignored cancellation", err)
			}
		})
	}
}
