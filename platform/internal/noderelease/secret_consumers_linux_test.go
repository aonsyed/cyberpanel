//go:build linux

package noderelease

import (
	"strings"
	"testing"
)

func TestConsumerReleaseMovesMatchSignedRoles(t *testing.T) {
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	old := Manifest{Artifacts: []Artifact{{Kind: ArtifactBinary, Destination: "/usr/local/libexec/cyberpanel/panel-execd", SHA256: a}, {Kind: ArtifactPackage, Destination: "/ignored", SHA256: c}}}
	next := Manifest{Artifacts: []Artifact{{Kind: ArtifactBinary, Destination: "/usr/local/libexec/cyberpanel/panel-execd", SHA256: b}, {Kind: ArtifactBinary, Destination: "/different-role", SHA256: c}}}
	moves, err := consumerReleaseMoves([]Manifest{old, old}, next)
	if err != nil || len(moves) != 1 || moves[0].From != a || moves[0].To != b {
		t.Fatalf("role mapping: %+v %v", moves, err)
	}
	moves, err = consumerReleaseMoves([]Manifest{old}, old)
	if err != nil || len(moves) != 0 {
		t.Fatalf("unchanged binary: %+v %v", moves, err)
	}
	old.Artifacts = append(old.Artifacts, Artifact{Kind: ArtifactBinary, Destination: "/different-role", SHA256: a})
	if _, err = consumerReleaseMoves([]Manifest{old}, next); err == nil {
		t.Fatal("one old executable gained two replacement identities")
	}
}
