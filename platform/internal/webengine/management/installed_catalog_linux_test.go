//go:build linux

package management

import (
	"context"
	"os"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

func TestQEMUInstalledEngineCatalog(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_ENGINE_CATALOG") != "1" {
		t.Skip("requires signed QEMU engine catalog and native package cache")
	}
	info, err := os.Lstat(localArtifactCatalogPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("installer-managed catalog link required", err)
	}
	ctx := context.Background()
	plan, err := resolveLocalArtifact(ctx, ArtifactRequest{Edition: webengine.EditionOpenLiteSpeed, Channel: ChannelStable, Version: "1.9.2-1+noble"}, true)
	if err != nil {
		t.Fatal("signed catalog resolution", err)
	}
	channel, paths, err := authorizeLifecyclePlan(ctx, plan)
	if err != nil || channel != ChannelStable || len(paths) != 1 {
		t.Fatal("native package authorization", channel, paths, err)
	}
	if err := installedLifecyclePlan(ctx, plan); err != nil {
		t.Fatal("installed native package", err)
	}
}
