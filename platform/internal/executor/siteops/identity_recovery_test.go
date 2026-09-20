package siteops

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	_ "modernc.org/sqlite"
)

type recoveryBackend struct{ data []byte }

func (b *recoveryBackend) Load() ([]byte, bool, error) { return b.data, b.data != nil, nil }
func (b *recoveryBackend) Store(data []byte) error     { b.data = append([]byte(nil), data...); return nil }

func identityRetryFixture(t *testing.T) (*DurableRegistry, Request, Lease) {
	t.Helper()
	r, err := NewDurableRegistry(&recoveryBackend{}, DefaultUIDMinimum, DefaultUIDMaximum)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	q := Request{Version: ProtocolVersion, RequestID: "request-1234567890", Operation: OperationEnsureIdentity, EffectKey: provisioning.EffectKey("effect-" + strings.Repeat("a", 64)), RuntimeKey: deriveRuntimeKey("tenant-one", "site-one"), TenantID: "tenant-one", SiteID: "site-one", ProjectionDigest: strings.Repeat("b", 64), Generation: 1, Lifecycle: site.LifecycleProvisioning, PHPProfile: site.PHPProfile83, IssuedAt: now, Deadline: now.Add(time.Minute)}
	if err = q.Validate(now); err != nil {
		t.Fatal(err)
	}
	l, err := r.Begin(q, now)
	if err != nil {
		t.Fatal(err)
	}
	return r, q, l
}

func TestInitialIdentityEvidenceRejectsUnsafeRetry(t *testing.T) {
	for _, mode := range []string{"running", "wrong-digest", "new-fence", "wrong-operation", "wrong-error", "root-exists", "suspended"} {
		t.Run(mode, func(t *testing.T) {
			r, q, l := identityRetryFixture(t)
			code := "host_operation"
			if mode == "wrong-error" {
				code = "registry_conflict"
			}
			if mode == "root-exists" {
				l.Binding.RootGeneration = 1
			}
			if mode == "suspended" {
				l.Binding.State = BindingSuspended
			}
			if mode != "running" {
				if err := r.Fail(q, l.Binding, code, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "wrong-digest":
				q.PHPProfile = site.PHPProfile82
			case "new-fence":
				q.Generation++
			case "wrong-operation":
				q.Operation = OperationEnsureDirectories
			}
			if _, err := r.InitialIdentityRetryEvidence(q); err == nil {
				t.Fatal("unsafe retry accepted")
			}
		})
	}
}

func TestInitialIdentityRecoveryPreservesAdmissionAttempt(t *testing.T) {
	ctx := context.Background()
	r, q, l := identityRetryFixture(t)
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
	if err = repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = rebootcontrol.NewAdmissionGate(ctx, db, "boot-one", time.Now); err != nil {
		t.Fatal(err)
	}
	admission := &rebootcontrol.SQLExecutionAdmission{DB: db, BootID: "boot-one"}
	server := &Server{Admission: admission, Handler: &Executor{registry: r}}
	binding := rebootcontrol.ExecutionBinding{Boundary: "siteops", Method: string(q.Operation), EffectID: string(q.EffectKey), RequestDigest: q.Digest(), Caller: "authenticated-panel-core", Resource: string(q.RuntimeKey)}
	first, err := server.admitSiteExecution(ctx, q, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Fail(q, l.Binding, "host_operation", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = server.admitSiteExecution(ctx, q, binding); !errors.Is(err, rebootcontrol.ErrUnproven) {
		t.Fatalf("active admission: %v", err)
	}
	if err = admission.FinishExecution(ctx, first, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE reboot_admission_gate SET closed=1,epoch=1,plan_id='plan-one',fence=1,boot_id='boot-one'`); err != nil {
		t.Fatal(err)
	}
	if _, err = server.admitSiteExecution(ctx, q, binding); err == nil {
		t.Fatal("crossed changed epoch")
	}
	if _, err = db.Exec(`UPDATE reboot_admission_gate SET closed=0,epoch=0,plan_id='',fence=0,boot_id=''`); err != nil {
		t.Fatal(err)
	}
	second, err := server.admitSiteExecution(ctx, q, binding)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.Token == first.Token {
		t.Fatal("lost fencing")
	}
	var oldToken, status, proof string
	if err = db.QueryRow(`SELECT attempt_token,status,evidence_digest FROM reboot_execution_recoveries WHERE effect_id=?`, first.ID).Scan(&oldToken, &status, &proof); err != nil || oldToken != first.Token || status != "ambiguous" || !validDigest(proof) {
		t.Fatal("lost old attempt", err)
	}
	if err = admission.FinishExecution(ctx, first, true, []byte(`{"ok":true}`)); err == nil {
		t.Fatal("stale lease accepted")
	}
	if err = admission.FinishExecution(ctx, second, true, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if cached, err := server.admitSiteExecution(ctx, q, binding); err != nil || len(cached.Cached) == 0 {
		t.Fatal("terminal replay", err)
	}
}
