package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

type tenantDatabaseAudit struct {
	db   *sql.DB
	fail bool
}

func (a *tenantDatabaseAudit) Record(ctx context.Context, event AuditEvent) error {
	if a.fail {
		return errors.New("audit unavailable")
	}
	_, err := a.db.ExecContext(ctx, "INSERT INTO test_audit_events(action,outcome) VALUES(?,?)", event.Action, event.Outcome)
	return err
}

func TestClaimedOwnerCreatesManagedCustomer(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "CREATE TABLE test_audit_events(action TEXT, outcome TEXT)"); err != nil {
		t.Fatal(err)
	}
	audit := &tenantDatabaseAudit{db: db}
	service, err := NewService(store, &claimVerifier{}, audit)
	if err != nil {
		t.Fatal(err)
	}
	quota := ResourceQuota{Sites: 2, Domains: 4, DiskBytes: 2 << 30, Inodes: 40000, MemoryBytes: 1 << 29, PIDs: 128, PHPConcurrency: 4}
	principal, err := service.ClaimInstallation(ctx, InstallationClaim{
		PrincipalID: "owner", TenantID: "installation", MembershipID: "owner_member", RoleID: "owner_role",
		BindingID: "owner_binding", PlanID: "owner_plan", Username: "owner", Email: "owner@example.invalid",
		DisplayName: "Owner", Password: []byte("qemu-only-test-password"), Quota: quota,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialID, _ := derivedID("cred", principal.ID.String()+"\x00password")
	credential, err := store.Credential(ctx, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	session, _, _, err := service.issueSession(ctx, principal, credential, AssurancePhishingResistant, netip.MustParseAddr("127.0.0.1"), "test-agent", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	actor := ActorContext{PrincipalID: principal.ID, SessionID: session.ID, CredentialID: credentialID, AuthzEpoch: principal.AuthzEpoch, Assurance: session.Assurance}
	apiCredential := credential
	apiCredential.ID, apiCredential.VerifierRef, apiCredential.Kind = "test_api_key", "test_api_verifier", CredentialAPIKey
	apiCredential.Scopes = []Permission{"site:read"}
	if err = store.Apply(ctx, Mutation{Credential: &apiCredential}); err != nil {
		t.Fatal(err)
	}
	command := CreateManagedTenantCommand{
		CommandID: "create_customer", Actor: actor, TenantID: "customer", ParentTenantID: "installation",
		ManagerPrincipalID: principal.ID, ManagerMembershipID: "customer_member", ManagerBindingID: "customer_binding",
		DelegationID: "customer_delegation", Kind: TenantCustomer, Name: "QEMU customer", PlanReferenceID: "owner_plan",
		Permissions:       []Permission{"site:create", "site:read", "site:manage", "identity:manage"},
		Selectors:         []Scope{{Kind: ScopeTenant, TenantID: "customer"}},
		Quota:             ResourceQuota{Sites: 1, Domains: 2, DiskBytes: 1 << 30, Inodes: 20000, MemoryBytes: 1 << 28, PIDs: 64, PHPConcurrency: 2},
		OwnershipContacts: []ID{principal.ID},
	}
	audit.fail = true
	if _, err = service.CreateManagedTenant(ctx, command); err == nil {
		t.Fatal("creation ignored audit failure")
	}
	if _, err = store.Tenant(ctx, command.TenantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant persisted despite audit failure: %v", err)
	}
	audit.fail = false
	overQuota := command
	overQuota.Quota.Sites = quota.Sites + 1
	if _, err = service.CreateManagedTenant(ctx, overQuota); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota enforcement: %v", err)
	}
	if _, err = store.Tenant(ctx, command.TenantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected tenant persisted: %v", err)
	}
	created, err := service.CreateManagedTenant(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "customer" || created.LifecycleState != TenantLifecycleActive {
		t.Fatalf("unexpected tenant: %s/%s", created.ID, created.LifecycleState)
	}
	stored, err := store.ManagedTenant(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ManagerPrincipalID != principal.ID || stored.Revision != 1 {
		t.Fatal("tenant ownership or revision not persisted")
	}
	updatedPrincipal, err := store.Principal(ctx, principal.ID)
	if err != nil {
		t.Fatal(err)
	}
	updatedCredential, err := store.Credential(ctx, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedCredential.AuthzEpoch != updatedPrincipal.AuthzEpoch {
		t.Fatal("manager's reusable credential became stale after role assignment")
	}
	staleAPI, err := store.Credential(ctx, apiCredential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if staleAPI.AuthzEpoch != principal.AuthzEpoch {
		t.Fatal("API key authority was silently refreshed")
	}
	if err = service.validateActor(ctx, actor, AssurancePassword); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old session survived authority change: %v", err)
	}
}
