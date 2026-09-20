package main

import (
	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/noderelease"
)

func loadInstalledUI(root string, maximumBytes int64) (*apiserver.StaticUI, error) {
	resolved, err := noderelease.ResolveUIRoot(root)
	if err != nil {
		return nil, err
	}
	return apiserver.LoadStaticUI(resolved, maximumBytes)
}
