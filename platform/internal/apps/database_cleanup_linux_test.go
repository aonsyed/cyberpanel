//go:build linux

package apps

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	_ "modernc.org/sqlite"
)

type cleanupRepository struct {
	database.Repository
	resources map[database.ResourceKind]database.ResourceEnvelope
}

func (repo cleanupRepository) LoadResource(_ context.Context, kind database.ResourceKind, id database.ResourceID) (database.ResourceEnvelope, error) {
	envelope, found := repo.resources[kind]
	if !found || envelope.Metadata.ID != id {
		return database.ResourceEnvelope{}, database.ErrNotFound
	}
	return envelope, nil
}

type cleanupCommands struct {
	statuses []database.OperationStatus
	calls    int
}

func (repo cleanupRepository) LookupOperation(context.Context, database.OperationScope, string) (database.OperationReceipt, bool, error) {
	return database.OperationReceipt{}, false, nil
}

func (commands *cleanupCommands) Handle(context.Context, database.Command) (database.OperationReceipt, error) {
	status := commands.statuses[commands.calls]
	commands.calls++
	return database.OperationReceipt{Status: status}, nil
}

func TestDatabaseCleanupRequiresAppliedReceipts(t *testing.T) {
	resourceID := func(value string) database.ResourceID {
		id, err := database.NewResourceID(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	identifier := func(value string) database.SQLIdentifier {
		id, err := database.ParseSQLIdentifier(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	tenant, _ := site.NewTenantID("tenant-1")
	siteID, _ := site.NewSiteID("site-1")
	secret, _ := database.NewSecretRef("secret-1")
	metadata := database.Metadata{ID: resourceID("appdb-test"), TenantID: tenant, SiteID: siteID, Generation: 1, Status: database.ResourceStatus{Lifecycle: database.LifecycleReady, Health: database.HealthHealthy, Reconciliation: database.ReconciliationInSync}}
	db := database.Database{Metadata: metadata, InstanceID: resourceID("mariadb-local"), Name: identifier("cp_test"), Charset: identifier("utf8mb4"), Collation: identifier("utf8mb4_unicode_ci"), QuotaBytes: 1024}
	metadata.ID = resourceID("appuser-test")
	principal := database.DatabasePrincipal{Metadata: metadata, InstanceID: db.InstanceID, Name: db.Name, HostScope: database.HostScopeLoopback, CredentialSecretRef: secret}
	repo := cleanupRepository{resources: make(map[database.ResourceKind]database.ResourceEnvelope)}
	for _, resource := range []database.Resource{db, principal} {
		envelope, err := database.EncodeResource(resource)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.DecodeResource(envelope); err != nil {
			t.Fatalf("stored %s cannot round-trip: %v", resource.Kind(), err)
		}
		repo.resources[resource.Kind()] = envelope
	}
	for _, status := range []database.OperationStatus{database.OperationApplied, database.OperationAccepted, database.OperationRejected, database.OperationCompensated, database.OperationAmbiguous} {
		for _, stage := range []string{"principal", "database"} {
			t.Run(stage+"/"+string(status), func(t *testing.T) {
				commands := &cleanupCommands{statuses: []database.OperationStatus{database.OperationApplied, database.OperationApplied}}
				index := 0
				if stage == "database" {
					index = 1
				}
				commands.statuses[index] = status
				provisioner := ApplicationDatabaseProvisioner{Commands: commands, Repository: repo}
				err := provisioner.RevokeApplicationDatabase(context.Background(), "appdb-test")
				if status == database.OperationApplied {
					if err != nil || commands.calls != 2 {
						t.Fatalf("successful cleanup: calls=%d error=%v", commands.calls, err)
					}
				} else if !errors.Is(err, database.ErrInvalidReceipt) || commands.calls != index+1 {
					t.Fatalf("non-applied cleanup acknowledged: calls=%d error=%v", commands.calls, err)
				}
			})
		}
	}
	for _, interrupted := range []bool{false, true} {
		t.Run("durable retry after reopen/interrupted="+strconv.FormatBool(interrupted), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.db")
			open := func() (*sql.DB, *database.SQLRepository) {
				t.Helper()
				handle, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				handle.SetMaxOpenConns(1)
				t.Cleanup(func() { handle.Close() })
				repository, err := database.NewSQLRepository(handle)
				if err != nil {
					t.Fatal(err)
				}
				if err := repository.Bootstrap(context.Background()); err != nil {
					t.Fatal(err)
				}
				return handle, repository
			}
			handle, repository := open()
			instance, err := database.DefaultLocalInstance()
			if err != nil {
				t.Fatal(err)
			}
			if err := repository.EnsureBootstrapResources(context.Background(), instance, db, principal); err != nil {
				t.Fatal(err)
			}
			effects := &cleanupEffects{interrupt: interrupted}
			coordinator := database.NewCoordinator(repository, effects, cleanupClock{})
			provisioner := ApplicationDatabaseProvisioner{Repository: repository, Commands: coordinator}
			firstErr := provisioner.RevokeApplicationDatabase(context.Background(), "appdb-test")
			if interrupted {
				if !errors.Is(firstErr, database.ErrUnavailable) {
					t.Fatalf("interruption: %v", firstErr)
				}
			} else if firstErr != nil {
				t.Fatal(firstErr)
			}
			if err := handle.Close(); err != nil {
				t.Fatal(err)
			}
			_, repository = open()
			provisioner.Repository = repository
			provisioner.Commands = database.NewCoordinator(repository, effects, cleanupClock{})
			if err := provisioner.RevokeApplicationDatabase(context.Background(), "appdb-test"); err != nil {
				t.Fatalf("retry: %v", err)
			}
			wantCalls := 2
			if interrupted {
				wantCalls++
			}
			if effects.calls != wantCalls {
				t.Fatalf("unexpected effect attempts: %d, want %d", effects.calls, wantCalls)
			}
			if err := provisioner.RevokeApplicationDatabase(context.Background(), "appdb-test"); err != nil {
				t.Fatalf("terminal replay: %v", err)
			}
			if effects.calls != wantCalls {
				t.Fatalf("terminal replay repeated effects: %d", effects.calls)
			}
			for _, resource := range []database.Resource{db, principal} {
				stored, err := repository.LoadResource(context.Background(), resource.Kind(), resource.Meta().ID)
				if err != nil {
					t.Fatal(err)
				}
				if stored.Metadata.Status.Lifecycle != database.LifecycleDeleted || stored.Metadata.Status.ObservedGeneration != stored.Metadata.Generation {
					t.Fatalf("cleanup not observed: %+v", stored.Metadata.Status)
				}
			}
		})
	}
}

type cleanupClock struct{}

func (cleanupClock) Now() time.Time { return time.Now().UTC() }

// Only the MariaDB effect is controlled; commands and persistence are real.
type cleanupEffects struct {
	calls     int
	interrupt bool
}

func (effects *cleanupEffects) ObserveOrApply(_ context.Context, request database.EffectRequest) (database.EffectReceipt, error) {
	effects.calls++
	if effects.interrupt && effects.calls == 1 {
		return database.EffectReceipt{EffectID: request.EffectID, RequestDigest: request.RequestDigest, Outcome: database.EffectAmbiguous}, database.ErrUnavailable
	}
	return database.EffectReceipt{EffectID: request.EffectID, RequestDigest: request.RequestDigest, Outcome: database.EffectConfirmed, ProofDigest: strings.Repeat("a", 64), MutationObserved: true}, nil
}
func (*cleanupEffects) Compensate(context.Context, database.CompensationRequest) (database.CompensationReceipt, error) {
	return database.CompensationReceipt{}, errors.New("unexpected compensation")
}
