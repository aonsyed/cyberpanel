//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"testing"
	"time"
)

func TestStartupWaitsForCoreAdmissionSchema(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	raw := &rebootcontrol.SQLExecutionAdmission{DB: db, BootID: "boot-test"}
	for i := 0; i < 2; i++ {
		if err := startupAdmissionSchemaReady(ctx, raw); !errors.Is(err, rebootcontrol.ErrConflict) {
			t.Fatalf("missing schema: %v", err)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("executor created schema", count, err)
	}
	repo, err := rebootcontrol.NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err := startupAdmissionSchemaReady(ctx, raw); !errors.Is(err, rebootcontrol.ErrConflict) {
		t.Fatalf("partial schema: %v", err)
	}
	if _, err = rebootcontrol.NewAdmissionGate(ctx, db, raw.BootID, time.Now); err != nil {
		t.Fatal(err)
	}
	if err := startupAdmissionSchemaReady(ctx, raw); err != nil {
		t.Fatal(err)
	}
	admission := &startupMutationAdmission{delegate: raw}
	if _, err := admission.AdmitExecution(ctx, rebootcontrol.ExecutionBinding{}); !errors.Is(err, rebootcontrol.ErrConflict) {
		t.Fatalf("schema availability opened admission before recovery: %v", err)
	}
	raw.ValidateStore = func() error { return rebootcontrol.ErrIntegrity }
	if err := startupAdmissionSchemaReady(ctx, raw); !errors.Is(err, rebootcontrol.ErrIntegrity) {
		t.Fatal("ignored invalid store", err)
	}
}
