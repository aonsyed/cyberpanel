package cyberpanel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	_ "modernc.org/sqlite"
)

// A source-local filesystem write gate, not a source-panel/service emulator.
// The real coordinated quiescer and SQL fence journal own its typed lease.
type fileGate struct {
	path, token string
	scope       GateScope
	failThaw    bool
}

func (g *fileGate) Freeze(ctx context.Context, s GateScope) (ComponentLease, error) {
	if err := ctx.Err(); err != nil {
		return ComponentLease{}, err
	}
	g.scope = s
	g.token = "owned-source-token"
	if err := os.WriteFile(g.path, []byte(g.token), 0600); err != nil {
		return ComponentLease{}, err
	}
	return ComponentLease{Token: g.token, EvidenceDigest: strings.Repeat("e", 64), ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (g *fileGate) Verify(ctx context.Context, a ComponentAction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.MigrationID != g.scope.MigrationID || a.ExpectedFence != g.scope.ExpectedFence || a.Token != g.token || !sameStringSequence(a.SiteSourceIDs, g.scope.SiteSourceIDs) {
		return ErrDenied
	}
	return nil
}
func (g *fileGate) Thaw(ctx context.Context, a ComponentAction) error {
	if err := g.Verify(ctx, a); err != nil {
		return err
	}
	if g.failThaw {
		return errors.New("fixture source thaw unavailable")
	}
	err := os.Remove(g.path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func (g *fileGate) Rollback(ctx context.Context, a ComponentAction) error { return g.Thaw(ctx, a) }
func (g *fileGate) Commit(ctx context.Context, a ComponentAction) error {
	return errors.New("unexpected source commit")
}

type fixedGeneration struct{}

func (fixedGeneration) Generation(context.Context, migration.ID) (uint64, error) { return 7, nil }

type noDelta struct{}

func (noDelta) BuildFinalDelta(context.Context, migration.SourceFence, migration.Manifest) (migration.Manifest, error) {
	return migration.Manifest{}, errors.New("unexpected final delta")
}

type cancelAfterBegin struct {
	*SQLFenceController
	cancel context.CancelFunc
}

func (c cancelAfterBegin) BeginQuiesce(ctx context.Context, r QuiesceRequest) (QuiesceObservation, error) {
	v, err := c.SQLFenceController.BeginQuiesce(ctx, r)
	if err == nil {
		c.cancel()
	}
	return v, err
}

func cutoverFixture(t *testing.T) (*sql.DB, *SQLFenceController, *Cutover, *fileGate, migration.Plan) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	gate := &fileGate{path: filepath.Join(root, "source-frozen")}
	q, err := NewCoordinatedQuiescer([]NamedComponentGate{{Name: "files", Gate: gate}}, fixedGeneration{})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewSQLFenceController(db, q)
	if err != nil {
		t.Fatal(err)
	}
	if err = controller.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	id := migration.ID("migration-fixture")
	plan := migration.Plan{ID: "plan-fixture", MigrationID: id, ManifestRoot: strings.Repeat("b", 64), DryRunDigest: strings.Repeat("a", 64), ApprovedAt: &now, QuiesceMode: "write_fence", CutoverMethod: "dns", RollbackWindow: time.Minute}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := SignApprovedPlan(SourcePlan{MigrationID: id, SourceInstallationID: "source-one", TargetInstallationID: "target-one", SchemaHash: CanonicalManifestSchemaHash(), SiteSourceIDs: []string{"site-one"}, Selection: ResourceSelection{Sites: true}, TargetPlanDigest: plan.DryRunDigest, QuiesceMode: "write_fence", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Nonce: "fixture-approval-nonce"}, now, "local-key", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(approved)
	if err = os.WriteFile(filepath.Join(root, id.String()+".json"), raw, 0400); err != nil {
		t.Fatal(err)
	}
	plans, err := OpenFilePlanStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plans.Close() })
	verifier, err := NewLocalApprovalVerifier(LocalApprovalPolicy{SourceInstallationID: "source-one", Keys: map[string]ed25519.PublicKey{"local-key": pub}, AllowedTargets: map[string]struct{}{"target-one": {}}, AllowedSchemaHashes: map[string]struct{}{CanonicalManifestSchemaHash(): {}}})
	if err != nil {
		t.Fatal(err)
	}
	cutover, err := NewCutover(plans, verifier, controller, noDelta{})
	if err != nil {
		t.Fatal(err)
	}
	return db, controller, cutover, gate, plan
}

func TestCanceledBindReleasesOwnedSourceFence(t *testing.T) {
	db, controller, cutover, gate, plan := cutoverFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cutover.controller = cancelAfterBegin{controller, cancel}
	if _, err := cutover.Quiesce(ctx, plan.MigrationID, plan, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
	if _, err := os.Stat(gate.path); !os.IsNotExist(err) {
		t.Fatal("canceled bind leaked owned source fence", err)
	}
	var state string
	if err := db.QueryRow("SELECT state FROM migration_source_fences").Scan(&state); err != nil || state != "aborted" {
		t.Fatal("abort not durable", state, err)
	}
	cutover.controller = controller
	if _, err := cutover.Quiesce(context.Background(), plan.MigrationID, plan, 1); err == nil {
		t.Fatal("reused aborted fence")
	}
	fence, err := cutover.Quiesce(context.Background(), plan.MigrationID, plan, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"migration", "generation", "fence"} {
		wrong := fence
		switch change {
		case "migration":
			wrong.MigrationID = "other-migration"
		case "generation":
			wrong.Generation++
		case "fence":
			wrong.Fence++
		}
		if err = cutover.RollbackSource(context.Background(), wrong); err == nil {
			t.Fatal("foreign/stale fence released source", change)
		}
	}
	if err = cutover.RollbackSource(context.Background(), fence); err != nil {
		t.Fatal(err)
	}
	if err = cutover.RollbackSource(context.Background(), fence); err != nil {
		t.Fatal("rollback replay", err)
	}
}

type rollbackTarget struct {
	migration.TargetImporter
	path           string
	failDeactivate bool
	cancel         context.CancelFunc
}

func (t *rollbackTarget) VerifyActive(context.Context, migration.Migration, migration.Plan, migration.ActivationReceipt) (migration.Verification, error) {
	if t.cancel != nil {
		t.cancel()
	}
	return migration.Verification{}, errors.New("fixture target health failed")
}
func (t *rollbackTarget) Deactivate(ctx context.Context, _ migration.ActivationReceipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.failDeactivate {
		return errors.New("fixture target deactivate unavailable")
	}
	err := os.Remove(t.path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

type unusedSource struct{ migration.SourceReader }
type unusedVerifier struct{ migration.ManifestVerifier }

func TestCutoverRollbackConfirmsBothSidesBeforeTerminal(t *testing.T) {
	for _, failure := range []string{"canceled", "target", "source"} {
		t.Run(failure, func(t *testing.T) {
			db, _, cutover, gate, plan := cutoverFixture(t)
			ctx := context.Background()
			repo, err := migration.NewSQLRepository(db)
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			manifest, err := migration.SignManifest(migration.Manifest{SchemaVersion: 1, MigrationID: plan.MigrationID, Source: migration.SourceCyberPanel, SourceInstallationID: "source-one", TargetInstallationID: "target-one", SourceGeneration: 7, CreatedAt: now, SchemaHash: CanonicalManifestSchemaHash()}, "fixture-key", key)
			if err != nil {
				t.Fatal(err)
			}
			plan.ManifestRoot = manifest.MerkleRoot
			if err = repo.PutManifest(ctx, manifest); err != nil {
				t.Fatal(err)
			}
			if err = repo.PutPlan(ctx, plan); err != nil {
				t.Fatal(err)
			}
			if err = repo.Create(ctx, migration.Migration{ID: plan.MigrationID, Source: migration.SourceCyberPanel, Phase: migration.PhaseCreated, AttemptID: "attempt-one", Fence: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			phases := []migration.Phase{migration.PhaseCreated, migration.PhaseDiscovering, migration.PhaseInventoried, migration.PhasePlanned, migration.PhaseReady, migration.PhaseBaseSync, migration.PhaseQuiescing, migration.PhaseFinalSync, migration.PhaseCutoverReady, migration.PhaseCutoverCommitting, migration.PhaseVerifying}
			for i := 1; i < len(phases); i++ {
				checkpoint := plan.DryRunDigest
				if phases[i] == migration.PhaseInventoried {
					checkpoint = manifest.MerkleRoot
				}
				if _, err = repo.Transition(ctx, plan.MigrationID, phases[i-1], phases[i], checkpoint, 7); err != nil {
					t.Fatal(err)
				}
			}
			fence, err := cutover.Quiesce(ctx, plan.MigrationID, plan, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.PutReceipt(ctx, plan.MigrationID, "source_fence", fence); err != nil {
				t.Fatal(err)
			}
			activation := migration.ActivationReceipt{MigrationID: plan.MigrationID, TargetGeneration: 1, EvidenceDigest: strings.Repeat("c", 64), ActivatedAt: now}
			if err = repo.PutReceipt(ctx, plan.MigrationID, "activation", activation); err != nil {
				t.Fatal(err)
			}
			target := &rollbackTarget{path: filepath.Join(t.TempDir(), "target-active"), failDeactivate: failure == "target"}
			if err = os.WriteFile(target.path, []byte("active"), 0600); err != nil {
				t.Fatal(err)
			}
			gate.failThaw = failure == "source"
			runctx, cancel := context.WithCancel(ctx)
			defer cancel()
			if failure == "canceled" {
				target.cancel = cancel
			}
			orchestrator, err := migration.NewOrchestrator(repo, unusedVerifier{}, unusedSource{}, cutover, target)
			if err != nil {
				t.Fatal(err)
			}
			result, runErr := orchestrator.Cutover(runctx, plan.MigrationID)
			if runErr == nil {
				t.Fatal("health failure discarded")
			}
			stored, err := repo.Migration(ctx, plan.MigrationID)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "canceled" {
				if stored.Phase != migration.PhaseRolledBack {
					t.Fatalf("canceled cleanup did not rollback: %s %v", stored.Phase, runErr)
				}
			} else {
				if stored.Phase != migration.PhaseRollingBack || result.Phase == migration.PhaseRolledBack {
					t.Fatalf("unconfirmed rollback claimed terminal: %s %s %v", stored.Phase, result.Phase, runErr)
				}
				if _, err = os.Stat(gate.path); err != nil {
					t.Fatal("source unfenced despite failed compensation", err)
				}
				target.failDeactivate = false
				gate.failThaw = false
				stale := fence
				stale.Generation++
				if err = repo.PutReceipt(ctx, plan.MigrationID, "source_fence", stale); err != nil {
					t.Fatal(err)
				}
				if _, err = orchestrator.Cutover(ctx, plan.MigrationID); !errors.Is(err, migration.ErrConflict) {
					t.Fatal("stale source generation accepted", err)
				}
				if _, err = os.Stat(gate.path); err != nil {
					t.Fatal("stale retry thawed source", err)
				}
				if err = repo.PutReceipt(ctx, plan.MigrationID, "source_fence", fence); err != nil {
					t.Fatal(err)
				}
				result, err = orchestrator.Cutover(ctx, plan.MigrationID)
				if err != nil || result.Phase != migration.PhaseRolledBack {
					t.Fatal("same-plan rollback retry failed", result.Phase, err)
				}
			}
			for _, path := range []string{gate.path, target.path} {
				if _, err = os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("compensation not complete", path, err)
				}
			}
			var sourceState string
			if err = db.QueryRow("SELECT state FROM migration_source_fences").Scan(&sourceState); err != nil || sourceState != "rolled_back" {
				t.Fatal("source journal", sourceState, err)
			}
			replayed, err := orchestrator.Cutover(ctx, plan.MigrationID)
			if err != nil || replayed.Phase != migration.PhaseRolledBack {
				t.Fatal("terminal rollback replay", replayed.Phase, err)
			}
			scopes, err := migration.NewRuntimeScopeStore(db)
			if err != nil {
				t.Fatal(err)
			}
			if err = scopes.Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = scopes.Create(ctx, migration.RuntimeScope{MigrationID: plan.MigrationID, TenantID: "tenant-one", SourceEndpoint: "source-one", Generation: 1, LastCommandID: "command-one", UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if _, err = scopes.Claim(ctx, "tenant-other", plan.MigrationID, 1, "command-other"); err == nil {
				t.Fatal("foreign tenant claimed retry")
			}
			if _, err = scopes.Claim(ctx, "tenant-one", plan.MigrationID, 1, "command-two"); err != nil {
				t.Fatal(err)
			}
			if _, err = scopes.Claim(ctx, "tenant-one", plan.MigrationID, 1, "command-three"); err == nil {
				t.Fatal("stale generation claimed retry")
			}
		})
	}
}
