package noderelease

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestQEMUUnconfiguredPackageHasNoCompletionEvidence(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_NODE_RELEASE") != "1" {
		t.Skip("QEMU partial LSPHP installation fixture")
	}
	ctx := context.Background()
	status, err := runFixed(ctx, "/usr/bin/dpkg-query", "--show", "--showformat=${db:Status-Status}", "lsphp83-opcache")
	if err != nil || strings.TrimSpace(status) == "installed" {
		t.Skip("partial package fixture no longer present")
	}
	name, version, arch, err := packageFields(ctx, "", PackageDPKG, false, "lsphp83-opcache")
	if err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{Package: &PackageMetadata{Manager: PackageDPKG, Name: name, Version: version, Architecture: arch}}
	if _, err = installedPackageEvidence(ctx, artifact); err == nil {
		t.Fatal("unconfigured package was credited as installed")
	}
}
