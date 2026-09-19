package apps

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type cloneRecordExecutor struct {
	cloneFailureExecutor
	inspect func(CloneExecution)
	success bool
}

func (executor cloneRecordExecutor) CreateClone(ctx context.Context, execution CloneExecution) (ExecutionReceipt, error) {
	executor.inspect(execution)
	if executor.success {
		return (cloneFailureExecutor{stage: "probe"}).CreateClone(ctx, execution)
	}
	return executor.cloneFailureExecutor.CreateClone(ctx, execution)
}

func (executor cloneRecordExecutor) ProbeClone(ctx context.Context, execution CloneExecution) (HealthObservation, ExecutionReceipt, error) {
	receipt, err := (cloneFailureExecutor{stage: "probe"}).CreateClone(ctx, execution)
	receipt.Operation = "probe_clone"
	return HealthObservation{State: HealthHealthy}, receipt, err
}

func TestCloneRecoveryRecordSurvivesReopen(t *testing.T) {
	for _, success := range []bool{false, true} {
		name := "recovery"
		if success {
			name = "committed"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "clone.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repo := SQLRepository{DB: db}
			if err := repo.Bootstrap(context.Background()); err != nil {
				t.Fatal(err)
			}
			request := cloneRequestFixture(time.Now().UTC())
			request.AccessPolicyID = "tenant-test/policy-test"
			request.TargetDatabaseClientIdentityRef = SecretRef(ApplicationManagedSecretID("database_tls", request.TargetInstallationID).String())
			if err := repo.CreateInstallation(context.Background(), request.Source); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("partial clone execution canceled")
			executor := cloneRecordExecutor{success: success, cloneFailureExecutor: cloneFailureExecutor{cause: cause, cancel: cancel}, inspect: func(execution CloneExecution) {
				record, err := repo.LoadInstallation(context.Background(), request.TargetInstallationID)
				if err != nil || record.State != InstallationInstalling || record.DatabaseBindingID != execution.TargetDatabase.ID {
					t.Errorf("resources untracked before executor: %+v, %v", record, err)
				}
			}}
			coordinator := StagingCoordinator{Store: repo, Snapshots: cloneFailureSnapshots{}, Databases: &compensationDatabase{}, Executor: executor}
			_, _, err = coordinator.CreateClone(ctx, request, SiteExecutionScope{SiteID: request.Source.SiteID}, SiteExecutionScope{SiteID: request.TargetSiteID, SiteUID: request.TargetSiteUID})
			if success && err != nil || !success && (!errors.Is(err, cause) || !errors.Is(err, ErrRecoveryRequired)) {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repo = SQLRepository{DB: db}
			record, err := repo.LoadInstallation(context.Background(), request.TargetInstallationID)
			if err != nil {
				t.Fatal(err)
			}
			wantState, wantOperation := InstallationRecovery, OperationRecoveryRequired
			if success {
				wantState, wantOperation = InstallationActive, OperationCommitted
			}
			if record.State != wantState || record.Generation != 2 || record.DatabaseBindingID != "appdb-1" || record.SiteID != request.TargetSiteID {
				t.Fatalf("missing recovery identity: %+v", record)
			}
			found := false
			for _, ref := range record.SecretRefs {
				found = found || ref == request.TargetDatabaseClientIdentityRef
			}
			if !found {
				t.Fatal("target client identity not retained")
			}
			operation, err := repo.LoadOperation(context.Background(), request.CommandID)
			if err != nil || operation.State != wantOperation {
				t.Fatalf("missing recovery operation: %+v, %v", operation, err)
			}
			coordinator.Store = repo
			_, _, err = coordinator.CreateClone(context.Background(), request, SiteExecutionScope{SiteID: request.Source.SiteID}, SiteExecutionScope{SiteID: request.TargetSiteID, SiteUID: request.TargetSiteUID})
			if success && err != nil || !success && !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("wrong replay outcome: %v", err)
			}
		})
	}
}
