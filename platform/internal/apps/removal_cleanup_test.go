package apps

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type removalCleanupStore struct {
	ApplicationStore
	installation ApplicationInstallation
	operation    Operation
}

func (store *removalCleanupStore) LoadInstallation(context.Context, InstallationID) (ApplicationInstallation, error) {
	return store.installation, nil
}
func (store *removalCleanupStore) AdmitOperation(_ context.Context, operation Operation) (Operation, bool, error) {
	return operation, true, nil
}
func (store *removalCleanupStore) UpdateInstallation(ctx context.Context, installation ApplicationInstallation, _ uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.installation = installation
	return nil
}
func (store *removalCleanupStore) UpdateOperation(ctx context.Context, operation Operation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.operation = operation
	return nil
}

type removalCleanupRecovery struct{ RecoveryPointProvider }

func (removalCleanupRecovery) CreateRecoveryPoint(context.Context, RecoveryRequest) (RecoveryPointID, uint64, error) {
	return "recovery-test", 1, nil
}

type removalCleanupExecutor struct {
	SiteApplicationExecutor
	cancel context.CancelFunc
}

func (executor removalCleanupExecutor) Remove(_ context.Context, execution RemovalExecution) (ExecutionReceipt, error) {
	if executor.cancel != nil {
		executor.cancel()
	}
	return ExecutionReceipt{Operation: "remove", SiteID: execution.Scope.SiteID, SiteUID: execution.Scope.SiteUID, InstallationID: execution.Installation, InputDigest: strings.Repeat("a", 64), OutputDigest: strings.Repeat("b", 64), Attestation: "fixture", CompletedAt: time.Now().UTC()}, nil
}

type removalCleanupSecrets struct {
	compensationSecrets
	failure error
}

func (secrets *removalCleanupSecrets) RevokeApplicationSecret(ctx context.Context, ref SecretRef) error {
	if err := secrets.compensationSecrets.RevokeApplicationSecret(ctx, ref); err != nil {
		return err
	}
	return secrets.failure
}

func TestApplicationPurgeRequiresResourceRevocation(t *testing.T) {
	for _, test := range []struct {
		name                                   string
		databaseFailure, secretFailure, cancel bool
	}{
		{"success", false, false, false},
		{"database failure", true, false, false},
		{"secret failure", false, true, false},
		{"canceled after file removal", false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("resource revocation unavailable")
			store := &removalCleanupStore{installation: ApplicationInstallation{ID: "app-test", TenantID: "tenant-test", SiteID: "site-test", SiteUID: 1001, State: InstallationActive, Generation: 1, DatabaseBindingID: "appdb-test", SecretRefs: []SecretRef{"config-test", "client-identity-test"}}}
			database := &compensationDatabase{}
			secrets := &removalCleanupSecrets{}
			if test.databaseFailure {
				database.failure = failure
			}
			if test.secretFailure {
				secrets.failure = failure
			}
			executor := removalCleanupExecutor{}
			if test.cancel {
				executor.cancel = cancel
			}
			coordinator := LifecycleCoordinator{Store: store, Executor: executor, Recovery: removalCleanupRecovery{}, Databases: database, Secrets: secrets}
			_, err := coordinator.Remove(ctx, RemovalRequest{CommandID: "remove-test", InstallationID: "app-test", ExpectedGeneration: 1, Disposition: RemovalPurge, SiteGeneration: 1, IsolationProfile: "application-runtime"})
			if len(database.revoked) != 1 || len(secrets.revoked) != 2 {
				t.Fatalf("cleanup omitted resources: db=%v secrets=%v", database.revoked, secrets.revoked)
			}
			if test.databaseFailure || test.secretFailure {
				if !errors.Is(err, failure) || !errors.Is(err, ErrRecoveryRequired) || store.operation.State != OperationRecoveryRequired || store.operation.Stage != "revoke_resources" || store.installation.State == InstallationRemoved {
					t.Fatalf("cleanup failure reported as successful removal: %v, %s, %s", err, store.operation.State, store.installation.State)
				}
			} else if err != nil || store.operation.State != OperationCommitted || store.installation.State != InstallationRemoved {
				t.Fatalf("purge did not finish: %v", err)
			}
		})
	}
}

func TestLifecycleRecoveryPreservesJournalFailure(t *testing.T) {
	cause := errors.New("cleanup failure")
	journalFailure := errors.New("journal unavailable")
	store := &compensationJournal{failState: OperationRecoveryRequired, failure: journalFailure}
	err := (LifecycleCoordinator{Store: store}).recovery(context.Background(), Operation{CommandID: "remove-test"}, "revoke_resources", cause)
	if !errors.Is(err, cause) || !errors.Is(err, journalFailure) || !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("recovery failure hidden: %v", err)
	}
}
