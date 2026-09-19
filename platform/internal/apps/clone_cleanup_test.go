package apps

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type cloneFailureStore struct {
	installFailureStore
	StagingStore
	source ApplicationInstallation
}

func (store *cloneFailureStore) LoadInstallation(context.Context, InstallationID) (ApplicationInstallation, error) {
	return store.source, nil
}

type cloneFailureSnapshots struct{ SnapshotProvider }

func (cloneFailureSnapshots) CreateApplicationSnapshot(context.Context, SnapshotRequest) (Snapshot, error) {
	return Snapshot{ID: "snapshot-test"}, nil
}
func (cloneFailureSnapshots) VerifyApplicationSnapshot(context.Context, SnapshotID) error { return nil }
func (cloneFailureSnapshots) ReleaseApplicationSnapshot(context.Context, SnapshotID) error {
	return nil
}

type cloneFailureExecutor struct {
	StagingExecutor
	cancel context.CancelFunc
	cause  error
	stage  string
}

func (executor cloneFailureExecutor) CreateClone(_ context.Context, execution CloneExecution) (ExecutionReceipt, error) {
	if executor.cancel != nil {
		executor.cancel()
	}
	if executor.stage == "clone_receipt" {
		return ExecutionReceipt{}, nil
	}
	if executor.stage == "probe" || executor.stage == "probe_receipt" {
		return ExecutionReceipt{Operation: "create_clone", SiteID: execution.TargetScope.SiteID, SiteUID: execution.TargetScope.SiteUID, InstallationID: execution.TargetInstallationID, InputDigest: strings.Repeat("a", 64), OutputDigest: strings.Repeat("b", 64), Attestation: "fixture", CompletedAt: time.Now()}, nil
	}
	return ExecutionReceipt{}, executor.cause
}

func (executor cloneFailureExecutor) ProbeClone(context.Context, CloneExecution) (HealthObservation, ExecutionReceipt, error) {
	if executor.stage == "probe_receipt" {
		return HealthObservation{State: HealthHealthy}, ExecutionReceipt{}, nil
	}
	return HealthObservation{}, ExecutionReceipt{}, executor.cause
}

func TestClonePartialFailureRequiresRecovery(t *testing.T) {
	for _, name := range []string{"partial-files", "database-cleanup-failure", "canceled-request", "journal-failure", "clone_receipt", "probe", "probe_receipt"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			request := cloneRequestFixture(now)
			cause := errors.New("clone failed after writing target files")
			if name == "clone_receipt" || name == "probe_receipt" {
				cause = ErrIntegrity
			}
			cleanupFailure := errors.New("database revocation failed")
			journalFailure := errors.New("journal unavailable")
			store := &cloneFailureStore{source: request.Source}
			database := &compensationDatabase{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			executor := cloneFailureExecutor{cause: cause, stage: name}
			if name == "canceled-request" {
				executor.cancel = cancel
			}
			if name == "database-cleanup-failure" {
				database.failure = cleanupFailure
			}
			if name == "journal-failure" {
				store.failState = OperationRecoveryRequired
				store.failure = journalFailure
			}
			coordinator := StagingCoordinator{Store: store, Snapshots: cloneFailureSnapshots{}, Databases: database, Executor: executor}
			_, _, err := coordinator.CreateClone(ctx, request, SiteExecutionScope{SiteID: request.Source.SiteID}, SiteExecutionScope{SiteID: request.TargetSiteID, SiteUID: request.TargetSiteUID})
			if !errors.Is(err, cause) || !errors.Is(err, ErrRecoveryRequired) {
				t.Errorf("unsafe terminal outcome: %v", err)
			}
			if len(database.revoked) != 1 {
				t.Errorf("database cleanup not attempted: %v", database.revoked)
			}
			if name == "database-cleanup-failure" && !errors.Is(err, cleanupFailure) {
				t.Errorf("cleanup failure lost: %v", err)
			}
			if name == "journal-failure" && !errors.Is(err, journalFailure) {
				t.Errorf("journal failure lost: %v", err)
			}
			if len(store.writes) == 0 || store.writes[len(store.writes)-1] != OperationRecoveryRequired {
				t.Errorf("wrong journal state: %v", store.writes)
			}
			if store.deadline.IsZero() {
				t.Error("cleanup journal context is unbounded")
			}
		})
	}
}
