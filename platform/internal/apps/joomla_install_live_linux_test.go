package apps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This exercises real Joomla and MariaDB through the complete production install
// runtime. It does not claim panel API, HTTP serving or administrator login proof.
func TestQEMURealJoomlaInstallation(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_INSTALL_JOOMLA") != "1" {
		t.Skip("QEMU real archive, PHP and MariaDB required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("run fixture as root inside QEMU")
	}
	account, err := user.Lookup("harness")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	site, err := os.MkdirTemp(linuxApplicationSitesRoot, "s-qemu-joomla-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(site); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(site, 0755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(site, "roots", "g1", "releases", "current", "public")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	binding := LinuxApplicationSiteBinding{SiteKey: filepath.Base(site), UID: uint32(uid), GID: uint32(gid), Generation: 1}
	runtime := &LinuxApplicationRuntime{Tar: "/usr/bin/tar"}
	artifact := ArtifactReference{URL: "https://127.0.0.1:19443/af8baac671deb19649f38236f53428d501b69e39e39ac5e23f3010c9623b6320.tar.gz", Digest: "af8baac671deb19649f38236f53428d501b69e39e39ac5e23f3010c9623b6320", Size: 28938128}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	name := "qj" + hex.EncodeToString(random[:8])
	password := hex.EncodeToString(random[8:]) + "Az!9"
	defer wipeLinuxApplicationBytes(random)
	sql := func(input string) ([]byte, error) {
		queryCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		command := exec.CommandContext(queryCtx, "/usr/bin/mariadb", "--protocol=socket", "--batch", "--skip-column-names")
		command.Stdin = strings.NewReader(input)
		output, err := command.CombinedOutput()
		return []byte(strings.ReplaceAll(string(output), password, "[REDACTED]")), err
	}
	t.Cleanup(func() {
		if _, err := sql("DROP DATABASE IF EXISTS " + name + "; DROP USER IF EXISTS '" + name + "'@'localhost';"); err != nil {
			t.Errorf("fixture database cleanup: %v", err)
		}
	})
	if output, err := sql("CREATE DATABASE " + name + " CHARACTER SET utf8mb4; CREATE USER '" + name + "'@'localhost' IDENTIFIED BY '" + password + "'; GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,ALTER,INDEX,DROP,CREATE TEMPORARY TABLES,EXECUTE,CREATE VIEW,SHOW VIEW,TRIGGER,EVENT ON " + name + ".* TO '" + name + "'@'localhost';"); err != nil {
		t.Fatalf("fixture database: %v: %s", err, output)
	}
	input := filepath.Join(root, ".cyberpanel-bootstrap.json")
	runtime.Resolver = LinuxApplicationSiteResolverFunc(func(context.Context, SiteID) (LinuxApplicationSiteBinding, error) { return binding, nil })
	runtime.Secrets = qemuJoomlaSecret(password)
	now := time.Now().UTC()
	reference := RecipeReference{ID: "qemu-joomla", DefinitionID: "joomla", ProductVersion: "6.1.3", RecipeDigest: artifact.Digest, Signature: "fixture", SigningKeyID: "qemu", CatalogEpoch: 1, PublishedAt: now.Add(-time.Hour)}
	public, _ := ParseRelativePath("public")
	execution := InstallExecution{
		Scope:        SiteExecutionScope{TenantID: "qemu-tenant", SiteID: "qemu-site", SiteUID: SiteUID(uid), Root: public, IsolationProfile: "application-runtime", ResourceGeneration: 1},
		Installation: InstallationID(name), ReleaseID: ReleaseID(name), RuntimeID: "php83", CanonicalURL: "http://qemu.example.invalid", Locale: "en_US", Timezone: "UTC", Title: "QEMU Joomla",
		Definition:    DefinitionFromContract(CertifiedProductContracts()[ApplicationJoomla], reference, artifact, artifact.Digest),
		Database:      DatabaseBinding{ID: DatabaseBindingID(name), InstanceID: "mariadb-local", Placement: "local", Engine: "mariadb", DatabaseName: name, PrincipalName: name, EndpointRef: "local-mariadb", PasswordRef: "qemu-password"},
		Administrator: AdministratorBootstrap{Username: "qemuadmin", Email: "qemu@example.invalid", DisplayName: "QEMU Administrator", PasswordRef: "qemu-admin"},
	}
	t.Cleanup(func() {
		directory, err := applicationManifestDirectory(execution.Installation)
		if err == nil {
			err = os.RemoveAll(directory)
		}
		if err != nil {
			t.Error(err)
		}
	})
	if _, err := runtime.Install(ctx, execution); err != nil {
		t.Fatalf("real production install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "configuration.php")); err != nil {
		t.Fatal("installer did not create configuration")
	}
	if _, err := os.Stat(input); !os.IsNotExist(err) {
		t.Fatal("argument bootstrap input was not consumed")
	}
	if _, err := os.Stat(filepath.Join(root, "installation")); !os.IsNotExist(err) {
		t.Fatal("installation directory remains after activation")
	}
	if manifest, err := runtime.loadActiveApplicationManifest(execution.Installation); err != nil || manifest.ReleaseID != execution.ReleaseID {
		t.Fatalf("installed release not active: %v", err)
	}
	prefix := "cp" + linuxApplicationDigest([]byte(execution.Installation))[:8] + "_"
	output, err := sql("SELECT COUNT(*) FROM " + name + "." + prefix + "users WHERE username='qemuadmin';")
	if err != nil || strings.TrimSpace(string(output)) != "1" {
		t.Fatalf("administrator not installed: %v: %s", err, output)
	}
}

type qemuJoomlaSecret string

func (secret qemuJoomlaSecret) ApplicationSecret(context.Context, SecretRef, TenantID, SiteID, InstallationID, string) ([]byte, error) {
	return []byte(secret), nil
}
