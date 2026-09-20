//go:build linux

package fsstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

func TestHealthProofSnapshotsPreserveRollbackAndRejectReuse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU health ownership check")
	}
	root, health := privateRoot(t), t.TempDir()
	if err := os.Chmod(health, 0755); err != nil {
		t.Fatal(err)
	}
	writePrivateFile(t, filepath.Join(root, "httpd_config.conf"), "vendor")
	s, err := NewWithHealth(root, webengine.EditionOpenLiteSpeed, health)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	first, err := s.Stage(ctx, testGeneration(t, webengine.EditionOpenLiteSpeed, 1, "first", "first-vhost"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwapMaster(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(ctx, first); err != nil {
		t.Fatal(err)
	}
	firstProof := filepath.Join(health, "g1", "activation")
	check := func(path, digest string) {
		t.Helper()
		body, err := os.ReadFile(path)
		if err != nil || string(body) != "panel-health-v1 "+digest+"\n" {
			t.Fatalf("proof: %q %v", body, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0444 {
			t.Fatal("proof is not read-only")
		}
	}
	check(firstProof, first.Digest)
	second, err := s.Stage(ctx, testGeneration(t, webengine.EditionOpenLiteSpeed, 2, "second", "second-vhost"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwapMaster(ctx, second); err != nil {
		t.Fatal(err)
	}
	check(firstProof, first.Digest)
	check(filepath.Join(health, "g2", "activation"), second.Digest)
	if err := s.RestoreMaster(ctx, first); err != nil {
		t.Fatal(err)
	}
	conflict, err := s.Stage(ctx, testGeneration(t, webengine.EditionOpenLiteSpeed, 1, "conflict", "other-vhost"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwapMaster(ctx, conflict); err == nil {
		t.Fatal("confirmed snapshot reused")
	}
	check(firstProof, first.Digest)
	for _, mode := range []os.FileMode{0644, 0666} {
		if err := os.Chmod(firstProof, mode); err != nil {
			t.Fatal(err)
		}
		if err := s.SwapMaster(ctx, first); err == nil {
			t.Fatal("unsafe proof mode accepted")
		}
	}
	if err := os.Remove(firstProof); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(health, "g2", "activation"), firstProof); err != nil {
		t.Fatal(err)
	}
	if err := s.SwapMaster(ctx, first); err == nil {
		t.Fatal("symlink proof accepted")
	}
}
