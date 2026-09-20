//go:build linux

package management

import (
	"os"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

func TestQEMUInstalledReleaseEdition(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_WEB_EDITION") != "1" {
		t.Skip("requires signed QEMU node release")
	}
	info, err := os.Lstat(lifecycleEditionPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("installer-managed edition link required", err)
	}
	edition, err := readLifecycleEdition()
	if err != nil || edition != webengine.EditionOpenLiteSpeed {
		t.Fatal("installed OpenLiteSpeed edition unavailable", edition, err)
	}
}
