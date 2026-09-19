package noderelease

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAbsentReleaseStatePreservesNotExist(t *testing.T) {
	_, err := readRootOwnedFile(filepath.Join(t.TempDir(), "installed.json"), 1<<20, 0600)
	if !os.IsNotExist(err) {
		t.Fatalf("fresh-install state must remain distinguishable from corrupt state: %v", err)
	}
}

func TestPackagedPanelServiceExecutablesAreReleaseDestinations(t *testing.T) {
	units, err := filepath.Glob("../../packaging/systemd/panel-*.service")
	if err != nil || len(units) == 0 {
		t.Fatalf("packaged units unavailable: %v", err)
	}
	for _, unit := range units {
		if filepath.Base(unit) == "panel-node-release-reconcile.service" {
			continue
		} // Bootstrap is deliberately outside the active generation.
		payload, err := os.ReadFile(unit)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, line := range strings.Split(string(payload), "\n") {
			if !strings.HasPrefix(line, "ExecStart=") {
				continue
			}
			fields := strings.Fields(strings.TrimPrefix(line, "ExecStart="))
			if len(fields) == 0 {
				t.Fatalf("empty ExecStart in %s", unit)
			}
			found = true
			if !allowedDestination(ArtifactBinary, fields[0]) || forbiddenReleasePath(fields[0]) {
				t.Errorf("%s executable cannot be installed by a signed release: %s", filepath.Base(unit), fields[0])
			}
		}
		if !found {
			t.Errorf("no executable in %s", unit)
		}
	}
}

func TestBinaryDestinationBoundary(t *testing.T) {
	for _, path := range []string{"/usr/lib/cyberpanel/bin/cyberpanel", "/usr/lib/cyberpanel/bin/paneld", "/usr/local/libexec/cyberpanel/panel-authd"} {
		if !allowedDestination(ArtifactBinary, path) {
			t.Errorf("rejected packaged executable: %s", path)
		}
	}
	for _, path := range []string{"/usr/lib/cyberpanel/bin", "/usr/lib/cyberpanel/bin-evil/paneld", "/usr/lib/cyberpanel/bin/../paneld", "/usr/lib/other/paneld", "/etc/cyberpanel/paneld"} {
		if allowedDestination(ArtifactBinary, path) {
			t.Errorf("accepted out-of-scope executable: %s", path)
		}
	}
}
