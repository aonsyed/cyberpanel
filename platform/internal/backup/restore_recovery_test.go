package backup

import (
	"context"
	"database/sql"
	"errors"
	_ "modernc.org/sqlite"
	"testing"
	"time"
)

type recoveryHealthFixture struct {
	RestoreTarget
	RestoreSafety
	proof                                    RestoreRecoveryProof
	failHealth, writeDuringHealth            bool
	healthCalls, restores, promotedUnfreezes int
}

func (f *recoveryHealthFixture) ReconcileRestore(context.Context, RestorePlanSpec, RestoreReceipt) (RestoreRecoveryProof, error) {
	return f.proof, nil
}
func (f *recoveryHealthFixture) VerifyPromotedHealth(context.Context, RestorePlanSpec, string, string) (string, error) {
	f.healthCalls++
	if f.writeDuringHealth {
		now := time.Now()
		f.proof.FirstWriteAt = &now
		f.proof.Watermark++
	}
	if f.failHealth {
		return "", errors.New("failed promoted health")
	}
	f.proof.HealthDigest = restorePlanDigest([]byte("health"))
	return f.proof.HealthDigest, nil
}
func (f *recoveryHealthFixture) RestorePrevious(context.Context, RestorePlanSpec, string, string) error {
	f.restores++
	f.proof.Phase = RestoreRolledBack
	return nil
}
func (f *recoveryHealthFixture) UnfreezeTargetWrites(_ context.Context, _ RestorePlanSpec, generation, _ string) error {
	if generation == "target" {
		f.promotedUnfreezes++
	}
	f.proof.Frozen = false
	return nil
}
func (f *recoveryHealthFixture) Quarantine(context.Context, RestorePlanSpec, string, string) error {
	return nil
}

func TestRecoveryPreservesPromotedHealthGate(t *testing.T) {
	for _, scenario := range []string{"lost-promotion-failed-health", "failed-health-after-write", "unfrozen-without-health", "unfrozen-with-health", "frozen-success"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			db, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			store := RestoreStore{DB: db}
			if err = store.Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			plan := RestorePlanSpec{ID: "restore", IdempotencyKey: "restore", TenantID: "tenant", RecoveryPointID: "point", SourceScope: "site", TargetScope: "site", ComponentMapping: map[ComponentKind]string{ComponentFiles: "site"}, CollisionPolicy: CollisionReplaceBlueGreen, SecretPolicy: SecretResetRequired, RequiredFreeBytes: 1, Generation: 1}
			receipt, _, err := store.Admit(ctx, plan)
			if err != nil {
				t.Fatal(err)
			}
			receipt.ManifestDigest = restorePlanDigest([]byte("manifest"))
			receipt.ScratchID = "scratch"
			receipt.PreviousGeneration = "previous"
			receipt.SafetySnapshotID = "safety"
			receipt.RollbackFrontier = 1
			for _, phase := range []RestorePhase{RestoreValidating, RestoreStaging, RestoreProbing, RestoreCutoverReady, RestorePromoting, RestoreAmbiguous} {
				receipt.Phase = phase
				if err = store.Save(ctx, &receipt); err != nil {
					t.Fatal(err)
				}
			}
			f := &recoveryHealthFixture{proof: RestoreRecoveryProof{Phase: RestoreActive, TargetGeneration: "target", Watermark: 1, Frozen: true, Digest: restorePlanDigest([]byte("proof"))}}
			switch scenario {
			case "lost-promotion-failed-health":
				f.failHealth = true
			case "failed-health-after-write":
				f.failHealth = true
				f.writeDuringHealth = true
			case "unfrozen-without-health":
				f.proof.Frozen = false
			case "unfrozen-with-health":
				f.proof.Frozen = false
				f.proof.HealthDigest = restorePlanDigest([]byte("health"))
			}
			coordinator := RestoreCoordinator{Store: store, Target: f, Safety: f}
			result, err := coordinator.recoverCompleted(ctx, plan, receipt)
			switch scenario {
			case "lost-promotion-failed-health":
				if err == nil || result.Phase != RestoreRolledBack || f.healthCalls != 1 || f.restores != 1 || f.promotedUnfreezes != 0 {
					t.Fatalf("health failure bypassed: %+v calls=%+v err=%v", result, f, err)
				}
			case "failed-health-after-write":
				if err == nil || result.Phase != RestoreFailForward || f.restores != 0 || f.promotedUnfreezes != 0 {
					t.Fatal("write frontier lost", result, err)
				}
			case "unfrozen-without-health":
				if err == nil || result.Phase == RestoreActive || f.promotedUnfreezes != 0 {
					t.Fatal("unproven health accepted", result, err)
				}
			default:
				if err != nil || result.Phase != RestoreActive {
					t.Fatal("proven health recovery failed", result, err)
				}
			}
		})
	}
}
