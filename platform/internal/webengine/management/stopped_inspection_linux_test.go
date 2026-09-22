//go:build linux

package management

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

// Read-only regression against the installer-owned artifacts. The caller must
// already have the engine stopped; this test never starts/stops any service.
func TestQEMUStoppedInstalledEngineInspection(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_STOPPED_ENGINE") != "1" {
		t.Skip("requires installed stopped QEMU engine")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root artifact inspection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", lifecycleService).Run() == nil {
		t.Fatal("fixture must already be stopped")
	}
	host := &LinuxLifecycleHost{now: time.Now}
	if err := host.load(); err != nil {
		t.Fatal(err)
	}
	installed, err := host.inspectState(ctx, webengine.EditionOpenLiteSpeed, false)
	if err != nil || installed.Edition != webengine.EditionOpenLiteSpeed || !validSHA256(installed.ArtifactDigest) || !validSHA256(installed.ActiveConfigDigest) {
		t.Fatal("valid stopped installation blocks startup", err)
	}
	if _, err = host.inspect(ctx, webengine.EditionOpenLiteSpeed); err == nil {
		t.Fatal("operational health accepted stopped engine")
	}
	if _, err = host.inspectState(ctx, webengine.Edition("invalid"), false); err == nil {
		t.Fatal("invalid installation accepted")
	}
	if err = verifyLifecycleInstallation(ctx, ArtifactPlan{}); err == nil {
		t.Fatal("untrusted artifact plan accepted")
	}
	t.Log("stopped installed engine identity/config verified; operational health and invalid plan remain denied")
}
