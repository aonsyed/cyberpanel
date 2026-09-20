package webactivation

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	_ "modernc.org/sqlite"
)

type recoveryObserver struct {
	err   error
	calls int
}

func (*recoveryObserver) Execute(context.Context, Request) (Response, error) {
	return Response{}, ErrInvalidRequest
}
func (o *recoveryObserver) InitialRecoveryEvidence(context.Context, Request) (string, error) {
	o.calls++
	return rebootcontrol.ExecutionDigest("stopped-without-current"), o.err
}

func TestInitialRecoveryAdmissionArchivesAttemptAndPreservesFencing(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	repo, err := rebootcontrol.NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := rebootcontrol.NewAdmissionGate(ctx, db, "boot-one", time.Now); err != nil {
		t.Fatal(err)
	}
	admission := &rebootcontrol.SQLExecutionAdmission{DB: db, BootID: "boot-one"}
	observer := &recoveryObserver{}
	server := &Server{Admission: admission, Handler: observer}
	request := Request{}
	request.Render.Snapshot.Generation = 1
	binding := rebootcontrol.ExecutionBinding{Boundary: "webactivation", Method: "activate", EffectID: "first-web", RequestDigest: request.Digest(), Caller: "authenticated-panel-core", Resource: "local:webengine"}
	first, err := server.admitActivation(ctx, request, binding)
	if err != nil || observer.calls != 0 {
		t.Fatalf("first admission: %v", err)
	}
	if _, err := server.admitActivation(ctx, request, binding); !errors.Is(err, rebootcontrol.ErrUnproven) {
		t.Fatalf("active attempt replayed: %v", err)
	}
	if err := admission.FinishExecution(ctx, first, false, nil); err != nil {
		t.Fatal(err)
	}
	observer.err = ErrOutcomeUnknown
	if _, err := server.admitActivation(ctx, request, binding); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unproven native state admitted: %v", err)
	}
	observer.err = nil
	later := request
	later.Render.Snapshot.Generation = 2
	if _, err := server.admitActivation(ctx, later, binding); !errors.Is(err, rebootcontrol.ErrUnproven) {
		t.Fatal("later snapshot recovered", err)
	}
	if _, err := db.Exec(`UPDATE reboot_admission_gate SET epoch=1,closed=1,plan_id='plan-one',fence=1,boot_id='boot-one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := server.admitActivation(ctx, request, binding); err == nil {
		t.Fatal("recovered across changed epoch")
	}
	if _, err := db.Exec(`UPDATE reboot_admission_gate SET epoch=0,closed=0,plan_id='',fence=0,boot_id=''`); err != nil {
		t.Fatal(err)
	}
	second, err := server.admitActivation(ctx, request, binding)
	if err != nil || first.ID != second.ID || first.Token == second.Token {
		t.Fatalf("recovery lease: %v", err)
	}
	var token, status, evidence string
	if err := db.QueryRow(`SELECT attempt_token,status,evidence_digest FROM reboot_execution_recoveries WHERE effect_id=?`, first.ID).Scan(&token, &status, &evidence); err != nil || token != first.Token || status != "ambiguous" || evidence != rebootcontrol.ExecutionDigest("stopped-without-current") {
		t.Fatal("attempt evidence lost", err)
	}
	if err := admission.FinishExecution(ctx, first, true, []byte(`{"ok":true}`)); err == nil {
		t.Fatal("stale lease accepted")
	}
	if err := admission.FinishExecution(ctx, second, true, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	observer.calls = 0
	if replay, err := server.admitActivation(ctx, request, binding); err != nil || len(replay.Cached) == 0 || observer.calls != 0 {
		t.Fatal("terminal outcome replayed effects", err)
	}
}
