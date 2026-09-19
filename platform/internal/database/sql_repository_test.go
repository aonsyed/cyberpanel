package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	_ "modernc.org/sqlite"
)

type persistenceClock struct{}

func (persistenceClock) Now() time.Time { return time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC) }

// The SQL repository is real; MariaDB effects are controlled at their boundary.
// This test does not qualify a running MariaDB server.
type persistenceEffects struct{ calls int }

func (executor *persistenceEffects) ObserveOrApply(_ context.Context, request EffectRequest) (EffectReceipt, error) {
	executor.calls++
	return EffectReceipt{EffectID: request.EffectID, RequestDigest: request.RequestDigest,
		Outcome: EffectConfirmed, ProofDigest: strings.Repeat("a", 64), MutationObserved: true}, nil
}
func (*persistenceEffects) Compensate(context.Context, CompensationRequest) (CompensationReceipt, error) {
	return CompensationReceipt{}, errors.New("unexpected compensation")
}

func TestSQLCoordinatorResourcesAndReplayAfterReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	open := func() (*sql.DB, *SQLRepository) {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { db.Close() })
		repository, err := NewSQLRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
		return db, repository
	}
	db, repository := open()
	instance, err := DefaultLocalInstance()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := DefaultLocalNetworkPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.EnsureBootstrapResources(ctx, instance, policy); err != nil {
		t.Fatal(err)
	}
	tenant, err := site.NewTenantID("tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	id := func(raw string) ResourceID {
		value, err := NewResourceID(raw)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	identifier := func(raw string) SQLIdentifier {
		value, err := ParseSQLIdentifier(raw)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	siteID, err := site.NewSiteID("site-1")
	if err != nil {
		t.Fatal(err)
	}
	metadata := func(raw string) Metadata {
		return Metadata{ID: id(raw), TenantID: tenant, SiteID: siteID, Generation: 1, Status: instance.Status}
	}
	header := func(raw string) CommandHeader {
		return CommandHeader{CommandID: raw, TenantID: tenant, Actor: Actor{TenantID: tenant, Capability: CapabilityTenantManage}}
	}
	secret, err := NewSecretRef("principal-credential")
	if err != nil {
		t.Fatal(err)
	}
	create := CreateDatabase{Header: header("create-db"), Database: Database{Metadata: metadata("database-1"), InstanceID: instance.ID, Name: identifier("tenant_database"), Charset: identifier("utf8mb4"), Collation: identifier("utf8mb4_unicode_ci"), QuotaBytes: 1 << 20}}
	principal := CreatePrincipal{Header: header("create-principal"), Principal: DatabasePrincipal{Metadata: metadata("principal-1"), InstanceID: instance.ID, Name: identifier("tenant_user"), HostScope: HostScopeLoopback, CredentialSecretRef: secret}}
	grants := ReplaceGrantSet{Header: header("replace-grants"), GrantSet: GrantSet{Metadata: metadata("grants-1"), InstanceID: instance.ID, DatabaseID: create.Database.ID, PrincipalID: principal.Principal.ID, Grants: []Grant{{Scope: GrantScopeDatabase, Privileges: []Privilege{PrivilegeSelect, PrivilegeInsert}}}}}
	commands := []Command{create, principal, grants}
	effects := &persistenceEffects{}
	coordinator := NewCoordinator(repository, effects, persistenceClock{})
	for _, command := range commands {
		receipt, err := coordinator.Handle(ctx, command)
		if err != nil || receipt.Status != OperationApplied {
			t.Fatalf("%s: status=%s error=%v", command.commandKind(), receipt.Status, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, repository = open()
	coordinator = NewCoordinator(repository, effects, persistenceClock{})
	for _, command := range commands {
		receipt, err := coordinator.Handle(ctx, command)
		if err != nil || receipt.Status != OperationApplied {
			t.Fatalf("replay %s: status=%s error=%v", command.commandKind(), receipt.Status, err)
		}
		envelope, err := repository.LoadResource(ctx, command.commandScope().Kind, command.commandScope().ID)
		if err != nil {
			t.Fatal(err)
		}
		resource, err := DecodeResource(envelope)
		if err != nil || resource.Validate() != nil {
			t.Fatalf("stored %s: %v", command.commandKind(), err)
		}
		if envelope.Metadata.Status.ObservedGeneration != 1 || envelope.Metadata.Status.ProofDigest != strings.Repeat("a", 64) {
			t.Fatalf("lost observation: %+v", envelope.Metadata.Status)
		}
	}
	if effects.calls != len(commands) {
		t.Fatalf("replay repeated effects: %d", effects.calls)
	}
	create.Database.QuotaBytes++
	if _, err := coordinator.Handle(ctx, create); !errors.Is(err, ErrIdempotency) {
		t.Fatalf("changed replay: %v", err)
	}
	otherTenant, _ := site.NewTenantID("tenant-2")
	rows, _, total, err := repository.ListDatabases(ctx, otherTenant, "", 100)
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("tenant isolation: rows=%d total=%d err=%v", len(rows), total, err)
	}
}
