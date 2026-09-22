package apps

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSQLRecoveryRemovalAdmissionPreservesAuditAndSingleMutator(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	repo := SQLRepository{DB: db}
	if err := repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	original := Operation{CommandID: "install-recovery", Kind: "install", TenantID: "tenant-1", SiteID: "site-1", InstallationID: "app-1", RequestDigest: strings.Repeat("a", 64), State: OperationRecoveryRequired, Stage: "health", Failure: "application integrity check failed", CreatedAt: now, UpdatedAt: now}
	if _, created, err := repo.AdmitOperation(ctx, original); err != nil || !created {
		t.Fatal(err)
	}
	// Simulate the installed pre-fix index, then exercise its atomic migration.
	if _, err := db.ExecContext(ctx, `DROP INDEX app_operations_active_installation; CREATE UNIQUE INDEX app_operations_active_installation ON app_operations(installation_id) WHERE installation_id IS NOT NULL AND state IN ('admitted','executing','compensating','recovery_required')`); err != nil {
		t.Fatal(err)
	}
	if err := repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"foreign-tenant", "foreign-site", "update"} {
		candidate := original
		candidate.CommandID = CommandID(variant)
		candidate.Kind = "remove"
		candidate.State = OperationAdmitted
		candidate.Stage = "admitted"
		switch variant {
		case "foreign-tenant":
			candidate.TenantID = "tenant-other"
		case "foreign-site":
			candidate.SiteID = "site-other"
		case "update":
			candidate.Kind = "update"
		}
		if _, created, err := repo.AdmitOperation(ctx, candidate); err == nil || created {
			t.Fatalf("unsafe %s admitted", variant)
		}
	}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, id := range []CommandID{"remove-one", "remove-two"} {
		wg.Add(1)
		go func(id CommandID) {
			defer wg.Done()
			candidate := original
			candidate.CommandID = id
			candidate.Kind = "remove"
			candidate.State = OperationAdmitted
			candidate.Stage = "admitted"
			_, created, err := repo.AdmitOperation(ctx, candidate)
			results <- created && err == nil
		}(id)
	}
	wg.Wait()
	close(results)
	admitted := 0
	for created := range results {
		if created {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("want exactly one removal mutator, got %d", admitted)
	}
	stored, err := repo.LoadOperation(ctx, original.CommandID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != OperationRecoveryRequired || stored.Stage != "health" || stored.Failure != original.Failure {
		t.Fatal("original recovery audit changed")
	}
	var active int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_operations WHERE installation_id='app-1' AND state IN ('admitted','executing','compensating')`).Scan(&active); err != nil || active != 1 {
		t.Fatalf("active mutation invariant: %d %v", active, err)
	}
}
