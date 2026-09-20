//go:build linux

package main

import (
	"context"
	"database/sql"
	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"path/filepath"
	"testing"
	"time"
)

type consoleCoordinator struct {
	calls   int
	session database.DatabaseWorkspaceSession
}

func (coordinator *consoleCoordinator) Handle(_ context.Context, command database.Command) (database.OperationReceipt, error) {
	coordinator.calls++
	coordinator.session = command.(database.OpenConsoleSession).Session
	return database.OperationReceipt{Status: database.OperationApplied}, nil
}

func TestManagedConsoleBindsDatabasePrincipalAndTenant(t *testing.T) {
	for _, change := range []string{"none", "tenant", "site", "instance", "disabled", "no-grant", "generation"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "control.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			repository, err := database.NewSQLRepository(db)
			if err != nil {
				t.Fatal(err)
			}
			if err := repository.Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			rid := func(raw string) database.ResourceID {
				value, err := database.NewResourceID(raw)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			tenant, _ := site.NewTenantID("console-tenant")
			siteID, _ := site.NewSiteID("console-site")
			meta := func(id string) database.Metadata {
				return database.Metadata{ID: rid(id), TenantID: tenant, SiteID: siteID, Generation: 1, Status: database.ResourceStatus{Lifecycle: database.LifecycleReady, Health: database.HealthHealthy, Reconciliation: database.ReconciliationInSync, ObservedGeneration: 1}}
			}
			name, _ := database.ParseSQLIdentifier("console_db")
			charset, _ := database.ParseSQLIdentifier("utf8mb4")
			collation, _ := database.ParseSQLIdentifier("utf8mb4_unicode_ci")
			secret, _ := database.NewSecretRef("console-secret")
			managed := database.Database{Metadata: meta("console-db"), InstanceID: rid("instance-a"), Name: name, Charset: charset, Collation: collation, QuotaBytes: 1 << 20}
			principal := database.DatabasePrincipal{Metadata: meta("console-principal"), InstanceID: managed.InstanceID, Name: name, HostScope: database.HostScopeLoopback, CredentialSecretRef: secret}
			call := apiserver.EdgeCall{CommandID: "console-command", TenantID: tenant.String(), ResourceID: managed.ID.String(), ExpectedGeneration: 1}
			switch change {
			case "tenant":
				call.TenantID = "other-tenant"
			case "site":
				principal.SiteID, _ = site.NewSiteID("other-site")
			case "instance":
				principal.InstanceID = rid("instance-b")
			case "disabled":
				principal.Disabled = true
			case "generation":
				call.ExpectedGeneration = 2
			}
			resources := []database.Resource{managed, principal}
			if change != "no-grant" {
				resources = append(resources, database.GrantSet{Metadata: meta("console-grant"), InstanceID: managed.InstanceID, DatabaseID: managed.ID, PrincipalID: principal.ID, Grants: []database.Grant{{Scope: database.GrantScopeDatabase, Privileges: []database.Privilege{database.PrivilegeSelect}}}})
			}
			if err := repository.EnsureBootstrapResources(ctx, resources...); err != nil {
				t.Fatal(err)
			}
			coordinator := &consoleCoordinator{}
			edge := &databaseEdge{repository: repository, coordinator: coordinator}
			result, err := edge.IssueDatabaseConsole(ctx, call, apiserver.DatabaseConsoleIssuePayload{PrincipalID: principal.ID.String()})
			if change != "none" {
				if err == nil || coordinator.calls != 0 {
					t.Fatalf("unsafe console admitted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if coordinator.calls != 1 || result.ID == "" || result.SiteID != siteID.String() || result.Generation != 1 || coordinator.session.SessionSecretRef != secret || coordinator.session.DatabaseID != managed.ID || coordinator.session.PrincipalID != principal.ID || coordinator.session.Limits.MaxConnections != 1 {
				t.Fatal("session not derived from validated managed resources")
			}
			// A retry must return the original expiry/session, not extend its lifetime.
			stored := coordinator.session
			stored.Status = meta("unused").Status
			if err := repository.EnsureBootstrapResources(ctx, stored); err != nil {
				t.Fatal(err)
			}
			replay, err := edge.IssueDatabaseConsole(ctx, call, apiserver.DatabaseConsoleIssuePayload{PrincipalID: principal.ID.String()})
			if err != nil || replay != result || coordinator.calls != 1 {
				t.Fatal("console replay changed session or expiry", err)
			}
		})
	}
}
