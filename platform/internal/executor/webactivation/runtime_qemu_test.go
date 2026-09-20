//go:build linux

package webactivation

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation/fsstore"
)

// Explicit native parser check of an already sealed initial candidate. It
// never starts the daemon and restores the original master even on failure.
func TestQEMUInitialWebParser(t *testing.T) {
	digest := os.Getenv("CYBERPANEL_QEMU_WEB_CANDIDATE")
	if digest == "" {
		t.Skip("QEMU root, stopped OLS and sealed initial candidate required")
	}
	if os.Geteuid() != 0 || !validDigest(digest) {
		t.Fatal("invalid QEMU parser test inputs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := (FixedRunner{}).CheckStopped(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := fsstore.New("/usr/local/lsws/conf", webengine.EditionOpenLiteSpeed)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	candidate := activation.Receipt{Edition: webengine.EditionOpenLiteSpeed, Digest: digest}
	if err := store.PrepareBootstrap(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.RestoreBootstrap(context.Background(), candidate); err != nil {
			t.Error(err)
		}
	}()
	if err := store.SwapMaster(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(ctx, "/usr/local/lsws/bin/lshttpd", "-t").CombinedOutput()
	if err != nil {
		t.Fatalf("native parser: %v\n%s", err, output)
	}
}
