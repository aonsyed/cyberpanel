//go:build linux

package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

type applicationConnectionSecrets struct {
	t        *testing.T
	ref      SecretRef
	audience ResourceID
	calls    int
	err      error
}

func (source *applicationConnectionSecrets) PinnedCertificateAuthority(_ context.Context, ref SecretRef, audience ResourceID) ([]byte, error) {
	source.calls++
	if ref != source.ref || audience != source.audience {
		source.t.Fatal("application CA lease changed authority")
	}
	if source.err != nil {
		return nil, source.err
	}
	return []byte("public CA fixture"), nil
}
func (source *applicationConnectionSecrets) ExternalAdministrator(context.Context, SecretRef, ResourceID, ResourceID) (MariaDBAdministrator, error) {
	source.t.Fatal("application resolver requested an administrator credential")
	return MariaDBAdministrator{}, ErrUnauthorized
}
func (source *applicationConnectionSecrets) PrincipalPassword(context.Context, SecretRef, ResourceID, string, string) ([]byte, error) {
	source.t.Fatal("connection metadata resolver requested a principal password")
	return nil, ErrUnauthorized
}
func (source *applicationConnectionSecrets) LocalServerTLS(context.Context, ResourceID, ResourceID, TLSMode) (MariaDBServerTLS, error) {
	source.t.Fatal("application resolver requested a server private key")
	return MariaDBServerTLS{}, ErrUnauthorized
}

func TestQEMUApplicationConnectionAuthority(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_MARIADB") != "1" {
		t.Skip("requires disposable QEMU protected database state")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root inside QEMU")
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(random)
	id, _ := NewResourceID("appdb-" + token)
	principalID, _ := NewResourceID("appuser-" + token)
	instance, err := DefaultLocalInstance()
	if err != nil {
		t.Fatal(err)
	}
	instance.ID, _ = NewResourceID("qemu-app-connection-" + token)
	ref, _ := NewSecretRef("qemu-application-ca-" + token)
	source := &applicationConnectionSecrets{t: t, ref: ref, audience: instance.ID}
	distribution, err := DetectLinuxMariaDBDistribution()
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewLinuxMariaDBExecutor(source, distribution, nil)
	if err != nil {
		t.Fatal(err)
	}
	for kind, target := range map[string]ResourceID{"databases": id, "principals": principalID, "instances": instance.ID} {
		kind, target := kind, target
		t.Cleanup(func() {
			if err := executor.removeResource(kind, target); err != nil && !errors.Is(err, ErrNotFound) {
				t.Error(err)
			}
		})
	}
	tenant, _ := site.NewTenantID("qemu-app-tenant")
	siteID, _ := site.NewSiteID("qemu-app-site")
	name, _ := ParseSQLIdentifier("qemu_app_database")
	username, _ := ParseSQLIdentifier("qemu_app_principal")
	charset, _ := ParseSQLIdentifier("utf8mb4")
	collation, _ := ParseSQLIdentifier("utf8mb4_unicode_ci")
	db := Database{Metadata: Metadata{ID: id, TenantID: tenant, SiteID: siteID, Generation: 1, Status: instance.Status}, InstanceID: instance.ID, Name: name, Charset: charset, Collation: collation, QuotaBytes: 1 << 20}
	principal := DatabasePrincipal{Metadata: db.Metadata, InstanceID: instance.ID, Name: username, HostScope: HostScopeLoopback, CredentialSecretRef: ref}
	principal.ID = principalID
	store := func(db Database, principal DatabasePrincipal, instance DatabaseInstance) {
		t.Helper()
		if err := executor.writeResource("databases", id, db); err != nil {
			t.Fatal(err)
		}
		if err := executor.writeResource("principals", principalID, principal); err != nil {
			t.Fatal(err)
		}
		if err := executor.writeResource("instances", instance.ID, instance); err != nil {
			t.Fatal(err)
		}
	}
	resolve := func() (ApplicationConnection, error) {
		return executor.ApplicationConnection(context.Background(), id, tenant.String(), siteID.String())
	}
	store(db, principal, instance)
	connection, err := resolve()
	if err != nil || connection.DatabaseName != name.String() || connection.PrincipalName != username.String() || connection.Endpoint.Host != "" || source.calls != 0 {
		t.Fatalf("local profile: %+v, %v", connection, err)
	}
	instance.Placement, instance.LocalServiceRef = PlacementExternal, ResourceID{}
	instance.External = &ExternalInstance{Endpoint: Endpoint{Host: "db.example.test", Port: 3307}, ServerName: "db.example.test", PinnedCASecretRef: ref, AdminSecretRef: ref, CredentialAudience: instance.ID, RequiredTLS: TLSMutual}
	store(db, principal, instance)
	connection, err = resolve()
	if err != nil || connection.Endpoint != instance.External.Endpoint || connection.TLS != TLSMutual || string(connection.CertificateAuthorityPEM) != "public CA fixture" || source.calls != 1 {
		t.Fatalf("external public profile: %+v, %v", connection, err)
	}
	t.Run("cross owner requests never lease CA", func(t *testing.T) {
		before := source.calls
		if _, err := executor.ApplicationConnection(context.Background(), id, "other-tenant", siteID.String()); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("cross-tenant metadata exposed")
		}
		if _, err := executor.ApplicationConnection(context.Background(), id, tenant.String(), "other-site"); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("cross-site metadata exposed")
		}
		if source.calls != before {
			t.Fatal("unauthorized request reached broker")
		}
	})
	for _, test := range []struct {
		name   string
		mutate func(*Database, *DatabasePrincipal, *DatabaseInstance)
	}{
		{"principal tenant", func(_ *Database, p *DatabasePrincipal, _ *DatabaseInstance) {
			p.TenantID, _ = site.NewTenantID("other-tenant")
		}},
		{"principal site", func(_ *Database, p *DatabasePrincipal, _ *DatabaseInstance) {
			p.SiteID, _ = site.NewSiteID("other-site")
		}},
		{"principal instance", func(_ *Database, p *DatabasePrincipal, _ *DatabaseInstance) {
			p.InstanceID, _ = NewResourceID("other-instance")
		}},
		{"database record identity", func(d *Database, _ *DatabasePrincipal, _ *DatabaseInstance) {
			d.ID, _ = NewResourceID("other-database")
		}},
		{"principal disabled", func(_ *Database, p *DatabasePrincipal, _ *DatabaseInstance) { p.Disabled = true }},
		{"database quarantined", func(d *Database, _ *DatabasePrincipal, _ *DatabaseInstance) {
			d.Status.Lifecycle = LifecycleQuarantined
		}},
		{"principal deleting", func(_ *Database, p *DatabasePrincipal, _ *DatabaseInstance) { p.Status.Lifecycle = LifecycleDeleting }},
		{"instance deleted", func(_ *Database, _ *DatabasePrincipal, i *DatabaseInstance) { i.Status.Lifecycle = LifecycleDeleted }},
		{"endpoint name mismatch", func(_ *Database, _ *DatabasePrincipal, i *DatabaseInstance) {
			i.External.ServerName = "other.example.test"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, p, i := db, principal, instance
			external := *instance.External
			i.External = &external
			test.mutate(&d, &p, &i)
			store(d, p, i)
			before := source.calls
			if _, err := resolve(); err == nil {
				t.Fatal("invalid application authority accepted")
			}
			if source.calls != before {
				t.Fatal("rejected authority still requested CA material")
			}
		})
	}
	store(db, principal, instance)
	source.err = ErrUnauthorized
	if connection, err := resolve(); !errors.Is(err, ErrUnauthorized) || connection.Endpoint.Host != "" {
		t.Fatal("CA failure returned a usable external profile")
	}
}
