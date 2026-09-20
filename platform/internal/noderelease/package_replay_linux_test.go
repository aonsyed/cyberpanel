//go:build linux

package noderelease

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A tiny panel-owned fixture package, not a vendor build. Its postinst counter
// proves whether the real installer re-runs native maintenance on an unchanged
// installed package. Every generated file/package is removed on exit.
func TestQEMUOfflinePackageReplayDoesNotReinstallConfiguredPackages(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_PACKAGE_REPLAY") != "1" {
		t.Skip("explicit root QEMU package-manager fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root QEMU required")
	}
	const name = "cyberpanel-qemu-package-replay"
	const counter = "/var/lib/cyberpanel-qemu-package-replay.count"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "-W", name).Output(); err == nil {
		t.Fatal("fixture package already exists; refusing to touch it")
	}
	if _, err := os.Lstat(counter); !os.IsNotExist(err) {
		t.Fatal("fixture counter already exists; refusing to touch it")
	}
	defer func() {
		output, err := exec.Command("/usr/bin/dpkg", "--purge", name).CombinedOutput()
		if err != nil {
			t.Errorf("fixture package cleanup: %v %s", err, output)
		}
		if err := os.Remove(counter); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
	}()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "packages"), 0755); err != nil {
		t.Fatal(err)
	}
	target := Target{Distribution: DistributionUbuntu, Release: "24.04", Codename: "noble", Architecture: ArchitectureARM64}
	build := func(version string) Artifact {
		stage := filepath.Join(root, "stage-"+version)
		for _, directory := range []string{"DEBIAN", "usr/share/" + name} {
			if err := os.MkdirAll(filepath.Join(stage, directory), 0755); err != nil {
				t.Fatal(err)
			}
		}
		control := "Package: " + name + "\nVersion: " + version + "\nArchitecture: all\nMaintainer: QEMU fixture <test@example.invalid>\nDescription: disposable panel installer replay fixture\n"
		if err := os.WriteFile(filepath.Join(stage, "DEBIAN/control"), []byte(control), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage, "DEBIAN/postinst"), []byte("#!/bin/sh\nset -eu\nprintf 'configured\\n' >> "+counter+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage, "usr/share/"+name+"/sentinel"), []byte(version), 0644); err != nil {
			t.Fatal(err)
		}
		artifact := Artifact{ID: "fixture-" + version, Kind: ArtifactPackage, Package: &PackageMetadata{Manager: PackageDPKG, Name: name, Version: version, Architecture: "all"}}
		output, err := exec.CommandContext(ctx, "/usr/bin/dpkg-deb", "--root-owner-group", "--build", stage, filepath.Join(root, "packages", artifact.ID)).CombinedOutput()
		if err != nil {
			t.Fatalf("build text-only fixture: %v %s", err, output)
		}
		return artifact
	}
	first, second := build("1.0"), build("2.0")
	expect := func(want int) {
		data, err := os.ReadFile(counter)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(string(data), "configured\n"); got != want {
			t.Fatalf("maintainer script ran %d times, want %d", got, want)
		}
	}
	apply := func(artifact Artifact) {
		evidence, err := installOfflinePackages(ctx, root, []Artifact{artifact}, target)
		if err != nil {
			t.Fatal(err)
		}
		if evidence[artifact.ID] == "" {
			t.Fatal("missing installed evidence")
		}
	}
	apply(first)
	expect(1)
	apply(first)
	expect(1)
	apply(second)
	expect(2)
	apply(first)
	expect(3)
	if output, err := exec.CommandContext(ctx, "/usr/bin/dpkg", "--unpack", filepath.Join(root, "packages", first.ID)).CombinedOutput(); err != nil {
		t.Fatalf("partial fixture: %v %s", err, output)
	}
	if _, err := installedPackageEvidence(ctx, first); err == nil {
		t.Fatal("unconfigured package incorrectly complete")
	}
	apply(first)
	expect(4)
	invalid := first
	metadata := *first.Package
	metadata.Version = "3.0"
	invalid.Package = &metadata
	if _, err := installOfflinePackages(ctx, root, []Artifact{second, invalid}, target); err == nil {
		t.Fatal("invalid package metadata accepted")
	}
	expect(4)
	if _, err := installedPackageEvidence(ctx, first); err != nil {
		t.Fatal("valid package was changed before all inputs verified", err)
	}
}
