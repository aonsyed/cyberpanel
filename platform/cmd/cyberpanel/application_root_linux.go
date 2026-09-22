//go:build linux

package main

import (
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/apps"
)

// Application scopes are relative to the release root, while HTTP serves the
// provisioner's document root. Never install into a sibling or parent tree.
func applicationServedRoot(applicationRoot, documentRoot string) (apps.RelativePath, error) {
	if _, err := apps.ParseRelativePath(applicationRoot); err != nil || applicationRoot == "" {
		return apps.RelativePath{}, apps.ErrInvalid
	}
	if _, err := apps.ParseRelativePath(documentRoot); err != nil {
		return apps.RelativePath{}, apps.ErrInvalid
	}
	if documentRoot == applicationRoot {
		return apps.ParseRelativePath("")
	}
	if !strings.HasPrefix(documentRoot, applicationRoot+"/") {
		return apps.RelativePath{}, apps.ErrPolicyDenied
	}
	return apps.ParseRelativePath(strings.TrimPrefix(documentRoot, applicationRoot+"/"))
}
