package apps

import (
	"context"
	"errors"
	"testing"
)

type strandedInstallStore struct {
	removalCleanupStore
	history []Operation
}

func (store *strandedInstallStore) ListOperations(context.Context, InstallationID, uint16, string) ([]Operation, string, error) {
	return store.history, "", nil
}

type requiredInstallRecovery struct {
	RecoveryPointProvider
	called  bool
	failure error
}

func (recovery *requiredInstallRecovery) CreateRecoveryPoint(context.Context, RecoveryRequest) (RecoveryPointID, uint64, error) {
	recovery.called = true
	return "recovery-retained", 1, recovery.failure
}

func (recovery *requiredInstallRecovery) RecoverInstallationOwnership(_ context.Context, installation ApplicationInstallation, snapshot RecoveryPointID) (DatabaseBindingID, []SecretRef, ReleaseID, error) {
	if !recovery.called || recovery.failure != nil || snapshot != "recovery-retained" || installation.State != InstallationInstalling {
		return "", nil, "", ErrRecoveryRequired
	}
	return "appdb-test", []SecretRef{"admin-test", "config-test"}, "release-test", nil
}

func TestInstallHealthFailurePreservesResourcesAndAllowsExplicitRemoval(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		store := &strandedInstallStore{removalCleanupStore: removalCleanupStore{installation: ApplicationInstallation{ID: "app-test", TenantID: "tenant-test", SiteID: "site-test", SiteUID: 1001, State: InstallationInstalling, Generation: 2, DatabaseBindingID: "appdb-test", SecretRefs: []SecretRef{"admin-test", "config-test"}}}}
		operation := Operation{Kind: "install", InstallationID: "app-test", TenantID: "tenant-test", SiteID: "site-test", State: OperationExecuting}
		if err := (ApplicationService{Store: store}).failRecovery(context.Background(), operation, "health", ErrIntegrity); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatal(err)
		}
		if store.installation.State != InstallationRecovery || store.installation.DatabaseBindingID != "appdb-test" || len(store.installation.SecretRefs) != 2 || store.operation.State != OperationRecoveryRequired {
			t.Fatal("recovery lost installation or resources")
		}
		store.history = []Operation{store.operation}
		if legacy {
			store.installation.State = InstallationInstalling
			store.installation.DatabaseBindingID = ""
			store.installation.SecretRefs = []SecretRef{"admin-test"}
		}
		database := &compensationDatabase{}
		secrets := &removalCleanupSecrets{}
		recovery := &requiredInstallRecovery{}
		coordinator := LifecycleCoordinator{Store: store, Recovery: recovery, Executor: removalCleanupExecutor{}, Databases: database, Secrets: secrets}
		_, err := coordinator.Remove(context.Background(), RemovalRequest{CommandID: "remove-test", InstallationID: "app-test", ExpectedGeneration: store.installation.Generation, Disposition: RemovalPurge, SiteGeneration: 1, IsolationProfile: "application-runtime"})
		if err != nil || !recovery.called || store.installation.State != InstallationRemoved || len(database.revoked) != 1 || len(secrets.revoked) != 2 {
			t.Fatalf("explicit recovered removal: %v", err)
		}
	}
}

func TestStrandedInstallRemovalRequiresRecoveryHistoryAndSnapshot(t *testing.T) {
	for _, variant := range []string{"executing", "unrelated", "snapshot-failed", "missing"} {
		t.Run(variant, func(t *testing.T) {
			store := &strandedInstallStore{removalCleanupStore: removalCleanupStore{installation: ApplicationInstallation{ID: "app-test", TenantID: "tenant-test", SiteID: "site-test", State: InstallationInstalling, Generation: 2, DatabaseBindingID: "appdb-test"}}, history: []Operation{{Kind: "install", InstallationID: "app-test", TenantID: "tenant-test", SiteID: "site-test", State: OperationRecoveryRequired, Stage: "health"}}}
			recovery := &requiredInstallRecovery{}
			switch variant {
			case "executing":
				store.history[0].State = OperationExecuting
			case "unrelated":
				store.history[0].TenantID = "other"
			case "snapshot-failed":
				recovery.failure = ErrIntegrity
			case "missing":
				store.history = nil
			}
			database := &compensationDatabase{}
			coordinator := LifecycleCoordinator{Store: store, Recovery: recovery, Databases: database}
			_, err := coordinator.Remove(context.Background(), RemovalRequest{CommandID: "remove-test", InstallationID: "app-test", ExpectedGeneration: 2, Disposition: RemovalPurge, SiteGeneration: 1})
			if err == nil || store.installation.State != InstallationInstalling || len(database.revoked) != 0 {
				t.Fatal("unsafe recovery removal accepted")
			}
		})
	}
}
