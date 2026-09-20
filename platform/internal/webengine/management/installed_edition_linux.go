//go:build linux

package management

import (
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/noderelease"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

func readLifecycleEdition() (webengine.Edition, error) {
	// Accept only the installer's exact root-owned immutable-release link,
	// not arbitrary symlinks. Pin the resolved generation before opening.
	path, err := noderelease.ResolveConfigPath(lifecycleEditionPath)
	if err != nil {
		return "", ErrNotFound
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", ErrNotFound
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !rootOwnedFile(info) || info.Size() <= 0 || info.Size() > 128 {
		return "", ErrNotFound
	}
	content, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return "", err
	}
	if int64(len(content)) != info.Size() {
		return "", ErrInvalid
	}
	edition := webengine.Edition(strings.TrimSpace(string(content)))
	if edition != webengine.EditionOpenLiteSpeed && edition != webengine.EditionLiteSpeedEnterprise {
		return "", ErrInvalid
	}
	return edition, nil
}
