//go:build linux

package webactivation

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Exercise the same isolated observer dispatch when the QEMU native checks
// re-execute this test binary instead of the installed executor binary.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == StoppedProofMode {
		if RunStoppedProof() != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStoppedProofUsesKernelExecutableIdentity(t *testing.T) {
	if err := requireExecutableStopped(context.Background(), "/proc/self/exe"); err == nil {
		t.Fatal("running test executable accepted as stopped")
	}
	path := filepath.Join(t.TempDir(), "not-running")
	if err := os.WriteFile(path, []byte("not an executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireExecutableStopped(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := requireExecutableStopped(ctx, path); err == nil {
		t.Fatal("cancelled observation accepted")
	}
}
