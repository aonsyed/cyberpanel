//go:build linux

package apps

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

func TestRecoveredManifestRejectsUnrelatedOwnership(t *testing.T) {
	manifest := canonicalManifestFixture()
	manifest.CanonicalURL = "http://example.invalid"
	installation := ApplicationInstallation{ID: manifest.InstallationID, TenantID: manifest.TenantID, SiteID: manifest.SiteID, DefinitionID: manifest.DefinitionID, Kind: manifest.Kind, RuntimeID: manifest.RuntimeID, Recipe: RecipeReference{RecipeDigest: manifest.RecipeDigest, ProductVersion: manifest.ProductVersion}}
	if err := validateRecoveredManifest(manifest, installation); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*linuxApplicationReleaseManifest){
		func(m *linuxApplicationReleaseManifest) { m.InstallationID = "other" }, func(m *linuxApplicationReleaseManifest) { m.TenantID = "other" }, func(m *linuxApplicationReleaseManifest) { m.SiteID = "other" }, func(m *linuxApplicationReleaseManifest) { m.RecipeDigest = strings.Repeat("b", 64) }, func(m *linuxApplicationReleaseManifest) { m.RuntimeID = "php82" },
	} {
		bad := manifest
		change(&bad)
		if !errors.Is(validateRecoveredManifest(bad, installation), ErrPolicyDenied) {
			t.Fatal("unrelated manifest accepted")
		}
	}
}

func TestRecoverySecretReferencesRequireExactOwnership(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := SQLRepository{DB: db}
	ctx := context.Background()
	if err := repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	installation := ApplicationInstallation{ID: "recover-app", TenantID: "recover-tenant", SiteID: "recover-site"}
	digest := strings.Repeat("a", 64)
	now := time.Now().UTC()
	issuer := ApplicationSecretIssuer{ReleaseDigest: digest}
	lease := ApplicationSecretLease{InstallationID: installation.ID, Purpose: "configuration", UpdatedAt: now, Metadata: secrets.Metadata{ID: ApplicationManagedSecretID("configuration", installation.ID), OwnerTenantID: ApplicationTenantOwnerID(string(installation.TenantID)), Purpose: secrets.PurposeAuthentication, Version: 1, KeyEpoch: 1, State: secrets.StateActive, Audience: issuer.applicationAudience(installation.SiteID, installation.ID, "configuration"), Algorithm: "AES-256-GCM", WrappedDEKDigest: digest, CiphertextDigest: digest, BindingDigest: digest, CreatedAt: now}}
	if err := repo.SaveApplicationSecretLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	refs, err := repo.recoveredInstallationSecrets(ctx, installation)
	if err != nil || len(refs) != 1 || refs[0] != SecretRef(lease.Metadata.ID.String()) {
		t.Fatalf("recovery references: %v", err)
	}
	other := installation
	other.TenantID = "other-tenant"
	if _, err := repo.recoveredInstallationSecrets(ctx, other); !errors.Is(err, ErrPolicyDenied) {
		t.Fatal("foreign tenant references accepted")
	}
	lease.Metadata.Audience.ResourceID = ApplicationAudienceID("other-app")
	lease.Metadata.Version++
	if err := repo.SaveApplicationSecretLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.recoveredInstallationSecrets(ctx, installation); !errors.Is(err, ErrPolicyDenied) {
		t.Fatal("foreign application audience accepted")
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM app_secret_leases WHERE installation_id=?", installation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.recoveredInstallationSecrets(ctx, installation); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatal("missing configuration lease accepted")
	}
}

func TestRecoveredConnectionRejectsDatabaseAndPrincipalMismatch(t *testing.T) {
	binding := canonicalManifestFixture().Database
	id, _ := database.NewResourceID(string(binding.InstanceID))
	connection := database.ApplicationConnection{InstanceID: id, DatabaseName: binding.DatabaseName, PrincipalName: binding.PrincipalName}
	if err := validateRecoveredConnection(binding, connection); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*database.ApplicationConnection){func(c *database.ApplicationConnection) { c.DatabaseName = "other" }, func(c *database.ApplicationConnection) { c.PrincipalName = "other" }, func(c *database.ApplicationConnection) { c.InstanceID, _ = database.NewResourceID("other-instance") }} {
		bad := connection
		change(&bad)
		if !errors.Is(validateRecoveredConnection(binding, bad), ErrPolicyDenied) {
			t.Fatal("unowned database binding accepted")
		}
	}
}

func TestRemovalRecoveryRequestIsStable(t *testing.T) {
	i := ApplicationInstallation{ID: "app-test", TenantID: "tenant-test", SiteID: "site-test"}
	r := removalRecoveryRequest(i)
	if r.InstallationID != i.ID || r.TenantID != i.TenantID || r.SiteID != i.SiteID || r.Purpose != "application_removal" || r.Consistency != "application_consistent" || !r.Required {
		t.Fatal("removal ownership request drifted")
	}
}

func TestQEMURetainedJoomlaOwnershipReadOnly(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_RECOVERY_OWNERSHIP") != "1" {
		t.Skip("retained QEMU recovery fixture required")
	}
	db, err := sql.Open("sqlite", "file:/var/lib/cyberpanel/control/control.db?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := SQLRepository{DB: db}
	ctx := context.Background()
	installation, err := repo.LoadInstallation(ctx, "app-6c8623f3dfca4f0a2c9b79dd8a7e980873d76c87b00f95c1")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := (&LinuxApplicationRuntime{}).loadActiveApplicationManifest(installation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRecoveredManifest(manifest, installation); err != nil {
		t.Fatal(err)
	}
	release, err := repo.LoadRelease(ctx, manifest.ReleaseID)
	if err != nil || release.InstallationID != installation.ID || release.ContentDigest != linuxApplicationDigest(mustLinuxApplicationJSON(manifest.Artifact.Digest)) {
		t.Fatalf("durable release mismatch: %v", err)
	}
	refs, err := repo.recoveredInstallationSecrets(ctx, installation)
	if err != nil || len(refs) != 2 {
		t.Fatalf("retained secret ownership mismatch: %v", err)
	}
}
