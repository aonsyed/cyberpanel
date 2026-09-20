//go:build linux

package webactivation

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation/fsstore"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
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
	store, err := fsstore.NewWithHealth("/usr/local/lsws/conf", webengine.EditionOpenLiteSpeed, "/var/lib/cyberpanel/site-health/activation")
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
	if err := (FixedRunner{}).ValidateInitial(ctx); err != nil {
		t.Fatalf("native parser: %v", err)
	}
}

// Render the real pending bootstrap plan, but bind its sealed master only in
// the parser's private read-only namespace. No live master/checkpoint is changed.
func TestQEMURenderedInitialWebParser(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_RENDER_WEB") != "1" {
		t.Skip("root QEMU with pending bootstrap plan required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := (FixedRunner{}).CheckStopped(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:/var/lib/cyberpanel/control/control.db?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT plan_json FROM webengine_node_changes WHERE effect_id='bootstrap-webengine-v1' AND status='pending'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plan composer.Plan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	composed, err := composer.Compose(plan)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := ols.New().Render(ctx, native.RenderRequest{Desired: composed.Desired, Snapshot: composed.Snapshot})
	if err != nil {
		t.Fatal(err)
	}
	store, err := fsstore.New("/usr/local/lsws/conf", webengine.EditionOpenLiteSpeed)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	candidate, err := store.Stage(ctx, generation)
	if err != nil {
		t.Fatal(err)
	}
	master, err := store.GenerationPath(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	output, parseErr := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
		"--property=ReadOnlyPaths=/usr/local/lsws/conf /etc", "--property=CapabilityBoundingSet=~CAP_SYS_ADMIN",
		"--property=RuntimeMaxSec=20s", "--property=TimeoutStopSec=5s",
		"--property=BindReadOnlyPaths="+master+":/usr/local/lsws/conf/httpd_config.conf",
		"/usr/local/lsws/bin/lshttpd", "-t").CombinedOutput()
	// The real parser must not rewrite sealed artifacts or their metadata.
	if _, err := store.GenerationPath(ctx, candidate); err != nil {
		t.Fatalf("native parser changed immutable generation: %v", err)
	}
	if parseErr != nil {
		if len(output) > 4096 {
			output = output[len(output)-4096:]
		}
		t.Fatalf("native parser: %v\n%s", parseErr, output)
	}
	t.Logf("native parser accepted %s", candidate.Digest)
	if os.Getenv("CYBERPANEL_QEMU_WAF_HTTP") == "1" {
		defer func() {
			if _, err := store.GenerationPath(context.Background(), candidate); err != nil {
				t.Errorf("HTTP fixture changed immutable generation: %v", err)
			}
			if err := (FixedRunner{}).CheckStopped(context.Background()); err != nil {
				t.Errorf("HTTP fixture left a running native server: %v", err)
			}
		}()
		runQEMUWAFHTTP(t, master, candidate.Digest)
	}
}
