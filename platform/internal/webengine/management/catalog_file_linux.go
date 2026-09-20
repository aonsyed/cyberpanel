//go:build linux

package management

import (
	"io"
	"os"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/noderelease"
)

// Pin only installer-managed links; never follow arbitrary catalog/key links.
// Catalog signatures remain independently verified by the caller.
func readCatalogFile(path string, limit int64, requireRoot bool) ([]byte, error) {
	resolved, err := noderelease.ResolveConfigPath(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !safeLocalCatalogFile(info, limit, requireRoot) {
		return nil, ErrInvalid
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) != info.Size() {
		return nil, ErrInvalid
	}
	return content, nil
}
