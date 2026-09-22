//go:build linux

package providers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/backup"
)

// PrepareRepository runs as panel-core, only below its installer-owned private
// repository parent. It does not accept a caller-selected host path.
func (provider *LocalProvider) PrepareRepository(ctx context.Context, spec backup.RepositorySpec) error {
	if ctx == nil || ctx.Err() != nil || provider.Registry == nil || validateSpec(spec, backup.Local) != nil || !safeID(string(spec.Repository.ID)) || spec.Repository.Endpoint != "file://"+filepath.Join(DefaultLocalRepositoryRoot, string(spec.Repository.ID)) {
		return ErrInvalid
	}
	parent, err := openLocalRepositoryTree(DefaultLocalRepositoryRoot)
	if err != nil {
		return err
	}
	defer syscall.Close(parent)
	var stat syscall.Stat_t
	if syscall.Fstat(parent, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0700 {
		return ErrInvalid
	}
	return provisionLocalRepositoryAt(parent, string(spec.Repository.ID))
}

func provisionLocalRepositoryAt(parent int, id string) error {
	if !safeID(id) {
		return ErrInvalid
	}
	if err := syscall.Mkdirat(parent, id, 0700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	fd, err := syscall.Openat(parent, id, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Mode&07777 != 0700 {
		return ErrInvalid
	}
	repository := LocalRepository{rootFD: fd}
	for _, name := range []string{".staging", "blobs", "points"} {
		dir, err := repository.openDir(name, true)
		if err != nil {
			return err
		}
		err = validateRepositoryDataDirectory(dir)
		syscall.Close(dir)
		if err != nil {
			return err
		}
	}
	return syscall.Fsync(parent)
}

// Root-owned ancestors stay mandatory until the fixed service data boundary.
// Only that parent and its direct repository child may belong to panel-core.
func openLocalRepositoryTree(absolute string) (int, error) {
	base := DefaultLocalRepositoryRoot
	if absolute != base && (filepath.Dir(absolute) != base || !safeID(filepath.Base(absolute))) {
		return -1, ErrInvalid
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	path := ""
	for _, segment := range strings.Split(strings.TrimPrefix(absolute, "/"), "/") {
		path += "/" + segment
		next, err := syscall.Openat(fd, segment, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				return -1, ErrNotFound
			}
			return -1, err
		}
		var stat syscall.Stat_t
		if err = syscall.Fstat(next, &stat); err != nil {
			syscall.Close(next)
			return -1, err
		}
		ownerOK := stat.Uid == 0
		if path == base || filepath.Dir(path) == base {
			ownerOK = ownerOK || stat.Uid == uint32(os.Geteuid())
		}
		if !ownerOK || stat.Mode&0022 != 0 {
			syscall.Close(next)
			return -1, ErrInvalid
		}
		if path == base && stat.Uid != 0 && (stat.Gid != uint32(os.Getegid()) || stat.Mode&07777 != 0700) {
			syscall.Close(next)
			return -1, ErrInvalid
		}
		privateServiceRoot := stat.Uid == uint32(os.Geteuid()) && stat.Mode&07777 == 0700
		legacyRootOwned := stat.Uid == 0 && stat.Mode&07777 == 0750
		if path == absolute && absolute != base && (stat.Gid != uint32(os.Getegid()) || !privateServiceRoot && !legacyRootOwned) {
			syscall.Close(next)
			return -1, ErrInvalid
		}
		fd = next
	}
	return fd, nil
}
