package apps

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestFailureJournalSurvivesCanceledRequest(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		name := "failed"
		if recovery {
			name = "recovery_required"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := SQLRepository{DB: db}
			if err := repository.Bootstrap(context.Background()); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			operation := Operation{CommandID: "install-1", Kind: "install", TenantID: "tenant-1", SiteID: "site-1", RequestDigest: strings.Repeat("a", 64), State: OperationExecuting, Stage: "install", CreatedAt: now, UpdatedAt: now}
			if _, _, err := repository.AdmitOperation(context.Background(), operation); err != nil {
				t.Fatal(err)
			}
			service := ApplicationService{Store: repository}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			fail := service.fail
			want := OperationFailed
			if recovery {
				fail = service.failRecovery
				want = OperationRecoveryRequired
			}
			err = fail(ctx, operation, "interrupted", context.Canceled)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cause: %v", err)
			}
			if errors.Is(err, ErrRecoveryRequired) != recovery {
				t.Fatalf("wrong recovery outcome: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			stored, err := (SQLRepository{DB: db}).LoadOperation(context.Background(), operation.CommandID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.State != want || stored.Stage != "interrupted" || stored.Failure != context.Canceled.Error() {
				t.Fatalf("failure not durable after reopen: %+v", stored)
			}
		})
	}
}

func TestFailureJournalPreservesWriteError(t *testing.T) {
	failure := errors.New("journal write failed")
	cause := errors.New("catalog failed")
	service := ApplicationService{Store: failingTerminalJournal{failure: failure}}
	err := service.fail(context.Background(), Operation{CommandID: "install-1"}, "catalog", cause)
	if !errors.Is(err, cause) || !errors.Is(err, failure) || !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("lost durable failure: %v", err)
	}
}

type failingTerminalJournal struct {
	ApplicationStore
	failure error
}

func (journal failingTerminalJournal) UpdateOperation(context.Context, Operation) error {
	return journal.failure
}
