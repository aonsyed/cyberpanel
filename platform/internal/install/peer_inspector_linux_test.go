package install

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPeerInspectorInstallerMappings(t *testing.T) {
	if got := executablePath(ExecutablePeerInspector); got != "/usr/local/libexec/cyberpanel/panel-peer-inspectd" {
		t.Fatalf("executable: %s", got)
	}
	if got := managedPath(PathPeerInspectorService); got != "/etc/systemd/system/panel-peer-inspectd.service" {
		t.Fatalf("unit path: %s", got)
	}
	for _, distribution := range []Distribution{DistributionUbuntu, DistributionAlma} {
		if got, err := nativeService(distribution, ServicePeerInspector); err != nil || got != "panel-peer-inspectd.service" {
			t.Fatalf("%s service: %s %v", distribution, got, err)
		}
	}
	if err := (ServiceSpec{ID: ServicePeerInspector, Health: HealthServiceActive, Required: true, StartupTimeout: 30 * time.Second}).Validate(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile("../../packaging/systemd/panel-peer-inspectd.service")
	if err != nil {
		t.Fatal(err)
	}
	file := ManagedFile{PathID: PathPeerInspectorService, Content: string(content), ContentDigest: digestText(string(content)), Owner: IdentityRoot, Group: IdentityRoot, Mode: 0644}
	if err := file.Validate(); err != nil {
		t.Fatal(err)
	}
	file.Owner = IdentitySecrets
	if err := file.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted non-root service owner: %v", err)
	}
}

func TestExecutorCatalogRequiresPeerInspector(t *testing.T) {
	component := ComponentDefinition{Artifact: &Artifact{Format: ArtifactTarGzip, Executable: true}}
	for id := range closedExecutablePaths {
		if id != ExecutablePeerInspector {
			component.Artifact.Members = append(component.Artifact.Members, ArtifactMember{PathID: id, SHA256: strings.Repeat("a", 64)})
		}
	}
	for _, id := range []PackageID{PackageTar, PackageUnzip, PackageZip, PackageGit, PackageRsync, PackageCurl, PackageOpenSSHClient, PackageOpenSSHServer, PackageFindutils, PackageCoreutils, PackageShadowUtils, PackageMariaDBClient, PackageMariaDBBackup, PackageChromium, PackageUtilLinux, PackageIPRoute, PackageNodeJS, PackagePython3} {
		component.Packages = append(component.Packages, PackageSelection{ID: id})
	}
	if err := validateExecutorCatalog(component); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), string(ExecutablePeerInspector)) {
		t.Fatalf("accepted missing helper: %v", err)
	}
	member := ArtifactMember{PathID: ExecutablePeerInspector, SHA256: strings.Repeat("a", 64)}
	if err := member.Validate(); err != nil {
		t.Fatal(err)
	}
	component.Artifact.Members = append(component.Artifact.Members, member)
	if err := validateExecutorCatalog(component); err != nil {
		t.Fatal(err)
	}
}
