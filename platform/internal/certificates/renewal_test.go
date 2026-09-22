package certificates

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// These interface fixtures exercise durable renewal orchestration, not ACME
// transport or public trust. No CA, DNS provider, or native service is contacted.
type renewalACME struct {
	fail     string
	cancel   context.CancelFunc
	orders   int
	material CertificateMaterial
}

func (a *renewalACME) EnsureAccount(ctx context.Context, _ AccountSpec, _ string) (string, error) {
	if a.fail == "cancel" {
		a.cancel()
		return "", ctx.Err()
	}
	return "https://ca.invalid/account", nil
}
func (a *renewalACME) NewOrder(_ context.Context, _ AccountSpec, p CertificatePolicy, _ string) (RemoteOrder, error) {
	a.orders++
	if a.fail == "order" {
		return RemoteOrder{}, errors.New("order unavailable")
	}
	return RemoteOrder{URL: "https://ca.invalid/order", FinalizeURL: "https://ca.invalid/finalize", Authorizations: []Authorization{{Name: p.Names[0], URL: "https://ca.invalid/auth", Challenge: Challenge{ID: "challenge", Kind: HTTP01, Name: p.Names[0]}}}}, nil
}
func (*renewalACME) AcceptChallenge(context.Context, AccountSpec, RemoteOrder, Authorization, string) error {
	return nil
}
func (*renewalACME) PollAuthorization(_ context.Context, _ AccountSpec, a Authorization) (Authorization, error) {
	a.Status = "valid"
	return a, nil
}
func (*renewalACME) FinalizeOrder(_ context.Context, _ AccountSpec, o RemoteOrder, _ CSRMaterial, _ string) (RemoteOrder, error) {
	return o, nil
}
func (a *renewalACME) DownloadCertificate(context.Context, AccountSpec, RemoteOrder) (CertificateMaterial, error) {
	return a.material, nil
}
func (*renewalACME) RevokeCertificate(context.Context, AccountSpec, CertificateMaterial, string) error {
	return nil
}

type renewalSigner struct{}

func (renewalSigner) CreateCSR(context.Context, CSRRequest) (CSRMaterial, error) {
	return CSRMaterial{DER: []byte("fixture"), PrivateKeyRef: "tenant_a/key", PublicKeyDigest: "fixture"}, nil
}

type renewalValidator struct{}

func (renewalValidator) Validate(context.Context, CertificateMaterial, CertificatePolicy) error {
	return nil
}

type renewalPresenter struct{}

func (renewalPresenter) PresentHTTP01(context.Context, Challenge) error { return nil }
func (renewalPresenter) RemoveHTTP01(context.Context, Challenge) error  { return nil }

type renewalTarget struct {
	live       map[string]string
	fail       string
	cancel     context.CancelFunc
	staged     []string
	restoreErr error
}

func (r *renewalTarget) StageCertificate(ctx context.Context, consumer string, m CertificateMaterial, _ string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	r.staged = append(r.staged, consumer)
	if r.fail == "stage" {
		return "", "", errors.New("stage failed")
	}
	return r.live[consumer], string(m.ID), nil
}
func (r *renewalTarget) ActivateCertificate(ctx context.Context, consumer, candidate, _ string) (string, error) {
	r.live[consumer] = candidate
	if r.fail == "activate" {
		return "", errors.New("activation failed")
	}
	return candidate, nil
}
func (r *renewalTarget) ProbeCertificate(ctx context.Context, _ string, m CertificateMaterial) (string, error) {
	if r.fail == "cancel" {
		r.cancel()
		return "", ctx.Err()
	}
	if r.fail == "probe" {
		return "", errors.New("probe failed")
	}
	return m.FingerprintSHA256, nil
}
func (r *renewalTarget) RestoreCertificate(ctx context.Context, consumer, previous, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > 30*time.Second {
		return errors.New("unbounded restore context")
	}
	if r.restoreErr != nil {
		return r.restoreErr
	}
	r.live[consumer] = previous
	return nil
}

func renewalFixture(t *testing.T) (*RenewalCoordinator, *renewalACME, *renewalTarget, *time.Time) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "renewal.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(8)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	store := IssuanceStore{DB: db}
	repo := Repository{DB: db}
	if err = store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	policy := CertificatePolicy{ID: "policy_a", TenantID: "tenant_a", AccountID: "account_a", Names: []string{"a.example.invalid"}, PreferredChallenge: HTTP01, KeyAlgorithm: "ecdsa-p256", RenewBefore: 30 * 24 * time.Hour, Generation: 1}
	account := AccountSpec{ID: "account_a", TenantID: "tenant_a", Directory: IssuerDirectory{Kind: IssuerPrivateACME, ProductionURL: "https://ca.invalid/directory", StagingURL: "https://ca.invalid/staging", PinnedOrigin: "https://ca.invalid"}, Contact: []string{"mailto:owner@example.invalid"}, AccountKeyRef: "account-key", AcceptedTermsAt: now}
	if err = store.PutAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	if err = store.PutPolicy(ctx, policy, 0); err != nil {
		t.Fatal(err)
	}
	old := CertificateMaterial{ID: "old_a", IssuanceID: "original_a", Names: policy.Names, NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: now.Add(24 * time.Hour), FingerprintSHA256: "old-fingerprint"}
	issuance := Issuance{ID: old.IssuanceID, TenantID: policy.TenantID, PolicyID: policy.ID, PolicyGeneration: 1, IdempotencyKey: "original-key", Phase: IssuanceIssued, Certificate: old, CreatedAt: now, UpdatedAt: now}
	if _, _, err = store.Admit(ctx, issuance); err != nil {
		t.Fatal(err)
	}
	if err = store.Save(ctx, issuance); err != nil {
		t.Fatal(err)
	}
	for consumer, id := range map[string]CertificateID{"site/tenant_a": "old_a", "site/tenant_b": "old_b"} {
		if err = repo.Deploy(ctx, Deployment{ID: DeploymentID("initial_" + string(id)), Consumer: consumer, Generation: id, ImmutablePath: "/fixture/" + string(id), DeployedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	acme := &renewalACME{material: CertificateMaterial{ID: "new_a", Names: policy.Names, NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour), FingerprintSHA256: "new-fingerprint"}}
	target := &renewalTarget{live: map[string]string{"site/tenant_a": "old_a", "site/tenant_b": "old_b"}}
	issuanceCoordinator := &IssuanceCoordinator{Store: store, ACME: acme, Signer: renewalSigner{}, Validator: renewalValidator{}, HTTP: renewalPresenter{}, Now: func() time.Time { return now }}
	c := &RenewalCoordinator{Store: store, Deployments: repo, Issuance: issuanceCoordinator, Deployment: &DeploymentCoordinator{Store: repo, Target: target}, Now: func() time.Time { return now }}
	if err = c.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	return c, acme, target, &now
}

func TestRenewalConcurrentClaimAndExpiredToken(t *testing.T) {
	c, _, _, now := renewalFixture(t)
	ctx := context.Background()
	due, err := c.due(ctx, 1)
	if err != nil || len(due) != 1 {
		t.Fatal("due", len(due), err)
	}
	r, err := c.admit(ctx, due[0])
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		r       Renewal
		token   string
		claimed bool
		err     error
	}
	results := make(chan result, 8)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, token, ok, err := c.claim(ctx, r, false)
			results <- result{r, token, ok, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	var first result
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.claimed {
			winners++
			first = result
		}
	}
	if winners != 1 {
		t.Fatalf("claim winners=%d", winners)
	}
	*now = now.Add(renewalLease + time.Second)
	second, token, ok, err := c.claim(ctx, r, false)
	if err != nil || !ok || second.Attempt != 2 {
		t.Fatal("reclaim", ok, second.Attempt, err)
	}
	if err = c.complete(ctx, first.r, first.token, "wrong"); !errors.Is(err, ErrCertificateConflict) {
		t.Fatal("expired token accepted", err)
	}
	if err = c.complete(ctx, second, token, "new_a"); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalFailurePreservesBindingAndRetries(t *testing.T) {
	for _, failure := range []string{"issuance_order", "issuance_cancel", "deployment_stage", "deployment_activate", "deployment_probe", "deployment_cancel"} {
		t.Run(failure, func(t *testing.T) {
			c, acme, target, now := renewalFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			acme.cancel = cancel
			target.cancel = cancel
			switch failure {
			case "issuance_order":
				acme.fail = "order"
			case "issuance_cancel":
				acme.fail = "cancel"
			case "deployment_stage":
				target.fail = "stage"
			case "deployment_activate":
				target.fail = "activate"
			case "deployment_probe":
				target.fail = "probe"
			case "deployment_cancel":
				target.fail = "cancel"
			}
			if count, err := c.RunOnce(ctx, 1); err == nil || count != 1 {
				t.Fatal("failure not observed", count, err)
			} else if ctx.Err() != nil && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation cause lost", err)
			}
			if target.live["site/tenant_a"] != "old_a" || target.live["site/tenant_b"] != "old_b" {
				t.Fatalf("working certificate changed after failure: %v", target.live)
			}
			current, err := c.Deployments.CurrentDeployment(context.Background(), "site/tenant_a")
			if err != nil || current.Generation != "old_a" {
				t.Fatal("durable binding changed", current, err)
			}
			id := renewalEffectID("renewal", "tenant_a", "policy_a", "1", "old_a")
			r, token, err := c.load(context.Background(), id)
			if err != nil || r.State != RenewalDegraded || token != "" {
				t.Fatalf("failure not retryable: state=%s tokenPresent=%t err=%v", r.State, token != "", err)
			}
			if due, err := c.due(context.Background(), 1); err != nil || len(due) != 0 {
				t.Fatal("retry bypassed backoff", len(due), err)
			}
			acme.fail = ""
			target.fail = ""
			*now = r.NextAttemptAt.Add(time.Second)
			orders := acme.orders
			if count, err := c.RunOnce(context.Background(), 1); err != nil || count != 1 {
				t.Fatal("retry", count, err)
			}
			if target.live["site/tenant_a"] != "new_a" || target.live["site/tenant_b"] != "old_b" {
				t.Fatal("retry crossed binding", target.live)
			}
			r, _, err = c.load(context.Background(), id)
			if err != nil || r.State != RenewalComplete || r.ReplacementID != "new_a" || r.Attempt != 2 {
				t.Fatal("completion", r, err)
			}
			if failure[:10] == "deployment" && acme.orders != orders {
				t.Fatal("deployment retry reissued certificate")
			}
			for _, consumer := range target.staged {
				if consumer != "site/tenant_a" {
					t.Fatal("foreign consumer staged", consumer)
				}
			}
			if _, err = c.Store.Material(context.Background(), "tenant_b", "new_a"); !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("foreign material access", err)
			}
		})
	}
}

func TestRenewalRestoreFailureIsNotHidden(t *testing.T) {
	c, _, target, _ := renewalFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target.fail = "cancel"
	target.cancel = cancel
	target.restoreErr = errors.New("native restore failed")
	_, err := c.RunOnce(ctx, 1)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, target.restoreErr) {
		t.Fatal("cleanup or causal error suppressed", err)
	}
	if target.live["site/tenant_a"] != "new_a" {
		t.Fatal("fixture did not exercise failed restore")
	}
	r, _, err := c.load(context.Background(), renewalEffectID("renewal", "tenant_a", "policy_a", "1", "old_a"))
	if err != nil || r.State != RenewalDegraded || r.ReplacementID != "" {
		t.Fatal("failed restore marked complete", r, err)
	}
	current, err := c.Deployments.CurrentDeployment(context.Background(), "site/tenant_a")
	if err != nil || current.Generation != "old_a" {
		t.Fatal("failed deployment committed", current, err)
	}
}
