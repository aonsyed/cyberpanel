package rebootcontrol

import (
	"context"
	"database/sql"
	"errors"
	_ "modernc.org/sqlite"
	"testing"
	"time"
)

func TestUnappliedPowerDNSRecoveryPreservesAttempt(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	repo, err := NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = NewAdmissionGate(ctx, db, "boot-one", time.Now); err != nil {
		t.Fatal(err)
	}
	store := &SQLExecutionAdmission{DB: db, BootID: "boot-one"}
	if _, err = db.Exec(`UPDATE reboot_admission_gate SET epoch=1,plan_id='plan-one',fence=1,boot_id='boot-one'`); err != nil {
		t.Fatal(err)
	}
	digest := ExecutionDigest("snapshot")
	binding := ExecutionBinding{Boundary: "powerdns", Method: "startup_configuration", Caller: "panel-execd-startup", EffectID: digest, RequestDigest: digest, Resource: "local"}
	proof := ExecutionDigest("native-empty-store-proof")
	if _, err = store.RecoverUnappliedPowerDNSStartup(ctx, binding, proof); !errors.Is(err, ErrUnproven) {
		t.Fatalf("missing effect: %v", err)
	}
	first, err := store.AdmitExecution(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.RecoverUnappliedPowerDNSStartup(ctx, binding, proof); !errors.Is(err, ErrUnproven) {
		t.Fatalf("active effect: %v", err)
	}
	if err = store.FinishExecution(ctx, first, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AdmitExecution(ctx, binding); !errors.Is(err, ErrUnproven) {
		t.Fatal("ordinary admission replayed ambiguity", err)
	}
	wrong := binding
	wrong.Resource = "other"
	if _, err = store.RecoverUnappliedPowerDNSStartup(ctx, wrong, proof); !errors.Is(err, ErrIntegrity) {
		t.Fatal("changed binding", err)
	}
	wrong = binding
	wrong.Boundary = "mail"
	if _, err = store.RecoverUnappliedPowerDNSStartup(ctx, wrong, proof); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong boundary", err)
	}
	if _, err = db.Exec(`UPDATE reboot_admission_gate SET epoch=2,closed=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RecoverUnappliedPowerDNSStartup(ctx, binding, proof); err == nil {
		t.Fatal("recovered across changed epoch")
	}
	if _, err = db.Exec(`UPDATE reboot_admission_gate SET epoch=1,closed=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RecoverUnappliedPowerDNSStartup(ctx, binding, proof); !errors.Is(err, ErrConflict) {
		t.Fatal("recovered through closed gate", err)
	}
	if _, err = db.Exec(`UPDATE reboot_admission_gate SET closed=0`); err != nil {
		t.Fatal(err)
	}
	second, err := store.RecoverUnappliedPowerDNSStartup(ctx, binding, proof)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.Epoch != second.Epoch || first.Token == second.Token {
		t.Fatal("recovery identity/fencing mismatch")
	}
	var oldToken, oldStatus, evidence string
	if err = db.QueryRow(`SELECT attempt_token,status,evidence_digest FROM reboot_execution_recoveries WHERE effect_id=?`, first.ID).Scan(&oldToken, &oldStatus, &evidence); err != nil || oldToken != first.Token || oldStatus != "ambiguous" || evidence != proof {
		t.Fatal("prior attempt not retained", err)
	}
	if err = store.FinishExecution(ctx, first, true, []byte(`{"ok":true}`)); err == nil {
		t.Fatal("stale lease settled recovered attempt")
	}
	if err = store.FinishExecution(ctx, second, true, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	replay, err := store.AdmitExecution(ctx, binding)
	if err != nil || len(replay.Cached) == 0 {
		t.Fatal("terminal receipt not replayable", err)
	}
}
