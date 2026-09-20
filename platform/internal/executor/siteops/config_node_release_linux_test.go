package siteops

import (
	"os"
	"testing"
)

func TestQEMULoadInstalledEngineEdition(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_NODE_RELEASE") != "1" {
		t.Skip("installed QEMU node release required")
	}
	info, err := os.Lstat(engineEditionPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected real signed installer config link: %v", err)
	}
	edition, err := LoadEngineEdition()
	if err != nil || edition != EditionOpenLiteSpeed {
		t.Fatalf("installed edition=%q, err=%v", edition, err)
	}
}
