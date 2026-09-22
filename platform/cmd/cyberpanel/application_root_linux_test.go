//go:build linux

package main

import (
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
)

func TestApplicationServedRootMatchesProvisioning(t *testing.T) {
	spec := provisioning.RuntimeSpec{}
	root, err := applicationServedRoot(spec.ApplicationRoot(), spec.DocumentRoot())
	if err != nil || root.String() != "public" {
		t.Fatalf("installed application is outside the served public root: %q, %v", root.String(), err)
	}
	for _, pair := range [][2]string{
		{"releases/current", "releases/other/public"},
		{"releases/current", "releases/currently/public"},
		{"releases/current", "releases/current/../private"},
		{"releases/current", "/etc/public"},
		{"releases/current", "releases/current//public"},
		{"", "public"},
		{"../current", "../current/public"},
	} {
		if root, err := applicationServedRoot(pair[0], pair[1]); err == nil {
			t.Errorf("accepted invalid/unrelated document root %q: %q", pair, root.String())
		}
	}
}
