//go:build linux

package siteops

import (
	"errors"
	"os"
	"strings"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/noderelease"
)

const engineEditionPath = "/etc/cyberpanel/engine.edition"

// LoadEngineEdition reads the installer-owned node edition. The API and local
// RPC cannot select an engine edition per operation.
func LoadEngineEdition() (EngineEdition, error) {
	path, err := noderelease.ResolveConfigPath(engineEditionPath); if err != nil { return "", err }
	info, err := os.Lstat(path); if err != nil { return "", err }
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > 128 { return "", errors.New("engine edition file has unsafe metadata") }
	content, err := os.ReadFile(path); if err != nil { return "", err }
	edition := EngineEdition(strings.TrimSpace(string(content))); if !edition.valid() { return "", errors.New("engine edition file is invalid") }
	return edition, nil
}
