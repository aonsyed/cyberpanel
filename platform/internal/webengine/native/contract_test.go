package native

import (
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

func TestNewCompleteGenerationBindsSnapshotGeneration(t *testing.T) {
	artifacts := []Artifact{{Role: ArtifactServer, Key: "engine", Mode: 0o600, Content: []byte("master")}}
	if _, err := NewCompleteGeneration(webengine.EditionOpenLiteSpeed, strings.Repeat("d", 64), 0, artifacts); err == nil {
		t.Fatal("NewCompleteGeneration accepted zero snapshot generation")
	}
	first, err := NewCompleteGeneration(webengine.EditionOpenLiteSpeed, strings.Repeat("d", 64), 7, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCompleteGeneration(webengine.EditionOpenLiteSpeed, strings.Repeat("d", 64), 8, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if first.SnapshotGeneration != 7 {
		t.Fatalf("SnapshotGeneration = %d, want 7", first.SnapshotGeneration)
	}
	if first.ContentDigest == second.ContentDigest {
		t.Fatal("ContentDigest did not bind snapshot generation")
	}
}
