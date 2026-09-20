package management

import (
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

func TestArtifactPlanNativePackageVersion(t *testing.T) {
	for _, version := range []string{"1.9.2-1+noble", "1:1.9.2-1+noble", "1.9.2~rc1-1", "1.9.2-1.el9"} {
		t.Run(version, func(t *testing.T) {
			plan := ArtifactPlan{Edition: webengine.EditionOpenLiteSpeed, Version: version,
				ArtifactDigest: strings.Repeat("a", 64), RepositorySnapshotDigest: strings.Repeat("b", 64),
				Packages:         []PackageArtifact{{Name: "openlitespeed", Version: version, Digest: strings.Repeat("c", 64), RepositoryID: "native"}},
				ServiceProfileID: "systemd-lsws-v1", NativeConfigFormat: "ols-text-v1"}
			if err := validateArtifactPlan(plan); err != nil {
				t.Fatalf("native version rejected: %v", err)
			}
		})
	}
}

func TestLifecycleVersionRejectsUnsafeInput(t *testing.T) {
	for _, version := range []string{"", "../1", "1..2", "1/2", "1\\2", "1 2", "1\n2", "1;id", "$(id)", "1\x002", "１.2", strings.Repeat("1", 129)} {
		if safeLifecycleVersion(version) {
			t.Errorf("accepted unsafe version %q", version)
		}
	}
	for _, token := range []string{"pkg+suffix", "key:epoch", "repo~candidate"} {
		if safeLifecycleToken(token) {
			t.Errorf("version grammar leaked into tokens: %q", token)
		}
	}
}
