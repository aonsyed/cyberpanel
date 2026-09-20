package apps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWordPressInstallRejectsUnpinnedArchiveWithoutNetwork(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root in QEMU required for site execution")
	}
	if err := os.MkdirAll(linuxApplicationSitesRoot, 0755); err != nil {
		t.Fatal(err)
	}
	site, err := os.MkdirTemp(linuxApplicationSitesRoot, "s-qemu-offline-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(site); err != nil {
			t.Error(err)
		}
	})
	root := filepath.Join(site, "roots", "g1", "releases", "current")
	if err := os.Chmod(site, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	binding := LinuxApplicationSiteBinding{SiteKey: filepath.Base(site), UID: 1000, GID: 1000, Generation: 1}
	runtime := &LinuxApplicationRuntime{Resolver: LinuxApplicationSiteResolverFunc(func(context.Context, SiteID) (LinuxApplicationSiteBinding, error) { return binding, nil }), Tar: "/usr/bin/false"}
	now := time.Now().UTC()
	digest := strings.Repeat("f", 64)
	reference := RecipeReference{ID: "offline-recipe", DefinitionID: "wordpress", ProductVersion: "7.1", RecipeDigest: digest, Signature: "test", SigningKeyID: "offline-key", CatalogEpoch: 1, PublishedAt: now.Add(-time.Hour)}
	execution := InstallExecution{
		Scope:        SiteExecutionScope{TenantID: "offline-tenant", SiteID: "offline-site", SiteUID: 1000, IsolationProfile: "application-runtime", ResourceGeneration: 1},
		Installation: "offline-install", ReleaseID: "offline-release", RuntimeID: "php83", CanonicalURL: "https://offline.example.invalid", Locale: "en_US", Timezone: "UTC", Title: "Offline",
		Definition:    DefinitionFromContract(CertifiedProductContracts()[ApplicationWordPress], reference, ArtifactReference{URL: "https://unreachable.example.invalid/wordpress.tar.gz", Digest: digest, Size: 1}, digest),
		Database:      DatabaseBinding{ID: "offline-db", InstanceID: "mariadb-local", Placement: "local", Engine: "mariadb", DatabaseName: "offline_db", PrincipalName: "offline_user", EndpointRef: "local-mariadb", PasswordRef: "offline-password"},
		Administrator: AdministratorBootstrap{Username: "administrator", Email: "admin@example.invalid", DisplayName: "Administrator", PasswordRef: "offline-admin"},
	}
	if err := execution.Validate(now); err != nil {
		t.Fatal(err)
	}
	if err := applicationManifestFromInstall(execution).Validate(); err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Install(context.Background(), execution)
	if !errors.Is(err, ErrRecipeUnavailable) && !errors.Is(err, ErrRecipeUntrusted) {
		t.Fatalf("expected catalog rejection before curl/tar/secrets, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".cyberpanel-wordpress.tar.gz")); !os.IsNotExist(err) {
		t.Fatal("created online download staging file")
	}
}
