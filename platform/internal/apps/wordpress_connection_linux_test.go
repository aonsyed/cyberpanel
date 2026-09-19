//go:build linux

package apps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
)

type applicationConnectionFixture struct {
	connection database.ApplicationConnection
}

func (fixture applicationConnectionFixture) ApplicationConnection(context.Context, database.ResourceID, string, string) (database.ApplicationConnection, error) {
	return fixture.connection, nil
}

func TestWordPressConnectionMatchesProtectedBinding(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "wp-content"), 0700); err != nil {
		t.Fatal(err)
	}
	instance, _ := database.NewResourceID("mariadb-local")
	connection := database.ApplicationConnection{InstanceID: instance, DatabaseName: "app_database", PrincipalName: "app_principal"}
	runtime := &LinuxApplicationRuntime{DatabaseConnections: applicationConnectionFixture{connection}}
	scope := linuxApplicationScope{root: root, binding: LinuxApplicationSiteBinding{SiteKey: "s-wordpress-test", Generation: 1, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}}
	owner := SiteExecutionScope{TenantID: "tenant-test", SiteID: "site-test"}
	binding := DatabaseBinding{ID: "appdb-test", InstanceID: "mariadb-local", Placement: "local", DatabaseName: "app_database", PrincipalName: "app_principal", EndpointRef: "local-mariadb"}
	if err := runtime.configureWordPressDatabaseTLS(context.Background(), scope, owner, "installation-test", binding); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DatabaseBinding){
		func(b *DatabaseBinding) { b.InstanceID = "other-instance" },
		func(b *DatabaseBinding) { b.DatabaseName = "other_database" },
		func(b *DatabaseBinding) { b.PrincipalName = "other_principal" },
		func(b *DatabaseBinding) { b.Placement = "external" },
		func(b *DatabaseBinding) { b.EndpointRef = "other.example.test:3306" },
	} {
		changed := binding
		change(&changed)
		if err := runtime.configureWordPressDatabaseTLS(context.Background(), scope, owner, "installation-test", changed); !errors.Is(err, ErrPolicyDenied) {
			t.Fatalf("unbound application connection accepted: %v", err)
		}
	}
}
