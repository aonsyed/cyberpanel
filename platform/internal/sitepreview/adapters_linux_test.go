//go:build linux

package sitepreview

import (
	"os"
	"testing"
)

func TestHelperRejectsUnregisteredPaths(t *testing.T) {
	for _, path := range []string{"", "/bin/sh", DefaultLinuxRouteHelper + ".old", "/usr/libexec/../libexec/cyberpanel-sitepreview-route"} {
		if _, err := resolveRootHelper(path); err == nil {
			t.Fatalf("accepted unregistered helper %q", path)
		}
	}
}

func TestQEMUInstalledPreviewHelpers(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_INSTALLED_PREVIEW") != "1" {
		t.Skip("requires the installed signed QEMU release")
	}
	for _, path := range []string{DefaultLinuxRouteHelper, DefaultLinuxChromiumHelper} {
		resolved, err := resolveRootHelper(path)
		if err != nil {
			t.Fatalf("resolve %s: %v", path, err)
		}
		if resolved == path {
			t.Fatalf("fixture must exercise managed release link: %s", path)
		}
	}
	if _, err := NewLinuxRouteRuntime("", ""); err != nil {
		t.Fatalf("installed route runtime: %v", err)
	}
	if _, err := NewLinuxChromeNamespace(""); err != nil {
		t.Fatalf("installed chromium namespace: %v", err)
	}
}
