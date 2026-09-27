//go:build linux

package noderelease

import (
 "context"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

// The dependency-closure admission is a clean-host precondition: a bundle
// package declaring a dependency that neither the system nor the bundle
// satisfies (directly or through Provides) must fail BEFORE the native
// transaction mutates anything. Panel-owned fixture packages only.
func TestQEMUOfflineDependencyClosure(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_PACKAGE_REPLAY") != "1" {
		t.Skip("explicit root QEMU package-manager fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root QEMU required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "packages"), 0755); err != nil {
		t.Fatal(err)
	}
	target := Target{Distribution: DistributionUbuntu, Release: "24.04", Codename: "noble", Architecture: ArchitectureARM64}
	const prefix = "cyberpanel-qemu-closure-"
	var installed []string
	defer func() {
		for _, name := range installed {
			output, err := exec.Command("/usr/bin/dpkg", "--purge", name).CombinedOutput()
			if err != nil && !strings.Contains(string(output), "is not installed") {
				t.Errorf("fixture cleanup %s: %v %s", name, err, output)
			}
		}
	}()
	build := func(name, version, depends, provides string) Artifact {
		stage := filepath.Join(root, "stage-"+name)
		if err := os.MkdirAll(filepath.Join(stage, "DEBIAN"), 0755); err != nil {
			t.Fatal(err)
		}
		control := "Package: " + name + "\nVersion: " + version + "\nArchitecture: all\nMaintainer: QEMU fixture <test@example.invalid>\nDescription: disposable closure fixture\n"
		if depends != "" {
			control += "Depends: " + depends + "\n"
		}
		if provides != "" {
			control += "Provides: " + provides + "\n"
		}
		if err := os.WriteFile(filepath.Join(stage, "DEBIAN/control"), []byte(control), 0644); err != nil {
			t.Fatal(err)
		}
		artifact := Artifact{ID: name, Kind: ArtifactPackage, Package: &PackageMetadata{Manager: PackageDPKG, Name: name, Version: version, Architecture: "all"}}
		output, err := exec.CommandContext(ctx, "/usr/bin/dpkg-deb", "--root-owner-group", "--build", stage, filepath.Join(root, "packages", artifact.ID)).CombinedOutput()
		if err != nil {
			t.Fatalf("build fixture %s: %v %s", name, err, output)
		}
		return artifact
	}
	missingDependent := build(prefix+"dependent", "1.0", "definitely-missing-qemu-closure-fixture", "")
	err := verifyOfflineDependencyClosure(ctx, root, []Artifact{missingDependent}, target)
	var missing *OfflineDependencyError
	if !errors.As(err, &missing) || !strings.Contains(err.Error(), "definitely-missing-qemu-closure-fixture") {
		t.Fatalf("missing dependency accepted: %v", err)
	}
	// The same admission runs inside the native phase: nothing may install.
	if _, installErr := installOfflinePackages(ctx, root, []Artifact{missingDependent}, target); installErr == nil {
		t.Fatal("native phase installed a package with unsatisfied dependency")
		installed = append(installed, prefix+"dependent")
	}
	if queryErr := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "-W", prefix+"dependent").Run(); queryErr == nil {
		t.Fatal("rejected dependency left an installed package behind")
	}
	bundleSatisfied := []Artifact{
		build(prefix+"child", "1.0", prefix+"base", ""),
		build(prefix+"base", "1.0", "", ""),
	}
	if err = verifyOfflineDependencyClosure(ctx, root, bundleSatisfied, target); err != nil {
		t.Fatalf("bundle-satisfied dependency rejected: %v", err)
	}
	virtual := []Artifact{
		build(prefix+"virtual-user", "1.0", "qemu-virtual-closure-fixture", ""),
		build(prefix+"virtual-provider", "1.0", "", "qemu-virtual-closure-fixture"),
	}
	if err = verifyOfflineDependencyClosure(ctx, root, virtual, target); err != nil {
		t.Fatalf("provided virtual dependency rejected: %v", err)
	}
	installed = append(installed, prefix+"child", prefix+"base", prefix+"virtual-user", prefix+"virtual-provider")
	if _, err = installOfflinePackages(ctx, root, bundleSatisfied, target); err != nil {
		t.Fatalf("closure-satisfied install failed: %v", err)
	}
	if _, err = installOfflinePackages(ctx, root, virtual, target); err != nil {
		t.Fatalf("virtual-satisfied install failed: %v", err)
	}
}

func TestDependencyNameParsing(t *testing.T) {
	if got := dependencyName("libzip4t64 (>= 1.7.0)"); got != "libzip4t64" {
		t.Fatal("version constraint not stripped:", got)
	}
	if got := dependencyName("php-common [amd64]"); got != "php-common" {
		t.Fatal("architecture qualifier not stripped:", got)
	}
	if got := dependencyName("php-cli:any"); got != "php-cli" {
		t.Fatal("multiarch suffix not stripped:", got)
	}
	group := splitDependencyGroup("php-cli | php8.3-cli (>= 8.0)")
	if len(group) != 2 || group[0] != "php-cli" || group[1] != "php8.3-cli" {
		t.Fatal("alternatives parsed wrong:", group)
	}
}
