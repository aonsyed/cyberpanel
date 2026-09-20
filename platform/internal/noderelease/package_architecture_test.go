package noderelease

import "testing"

func TestNativePackageArchitectureAdmission(t *testing.T) {
	for _, target := range []Target{
		{DistributionUbuntu, "24.04", "noble", ArchitectureAMD64},
		{DistributionUbuntu, "24.04", "noble", ArchitectureARM64},
		{DistributionAlma, "9", "el9", ArchitectureAMD64},
		{DistributionAlma, "9", "el9", ArchitectureARM64},
	} {
		manager, native, independent := PackageDPKG, string(target.Architecture), "all"
		if target.Distribution == DistributionAlma {
			manager, independent = PackageRPM, "noarch"
			native = "aarch64"
			if target.Architecture == ArchitectureAMD64 {
				native = "x86_64"
			}
		}
		for _, arch := range []string{"amd64", "arm64", "x86_64", "aarch64", "all", "noarch", "any", ""} {
			for _, candidateManager := range []PackageManager{PackageDPKG, PackageRPM} {
				metadata := PackageMetadata{Manager: candidateManager, Name: "native-data", Version: "1.0-1", Architecture: arch}
				want := candidateManager == manager && (arch == native || arch == independent)
				if err := metadata.validate(target); (err == nil) != want {
					t.Errorf("target=%s manager=%s arch=%q: err=%v, want admission=%v", target.Key(), candidateManager, arch, err, want)
				}
			}
		}
	}
}
