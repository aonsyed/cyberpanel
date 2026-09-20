//go:build linux

package noderelease

import (
	"os"
	"path/filepath"
	"strings"
)

// ResolveConfigPath pins an installer-managed non-secret config to its current
// immutable generation. Callers must still apply their regular-file ownership,
// mode, size and decoding checks. Arbitrary symlinks and credential paths are
// not accepted. This relies on the installer's root-owned activation boundary;
// it does not admit releases or replace signature verification at installation.
func ResolveConfigPath(path string) (string, error) {
	return resolveConfigPath(path, "/etc/cyberpanel", ActiveRelease, ReleaseRoot)
}

// ResolveUIRoot selects one immutable generation via its managed index. The
// static loader still rejects symlinks within that generation. Never walk the
// public per-file links, which could otherwise cross an activation boundary.
func ResolveUIRoot(path string) (string, error) {
	if path != "/usr/lib/cyberpanel/ui" {
		return "", ErrInvalid
	}
	index, err := resolveConfigPath(filepath.Join(path, "index.html"), path, ActiveRelease, ReleaseRoot)
	if err != nil {
		return "", err
	}
	root := filepath.Dir(index)
	if err := configAncestors(root); err != nil {
		return "", err
	}
	return root, nil
}

func resolveConfigPath(path, configRoot, active, releases string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	if !pathBelow(path, configRoot) || forbiddenReleasePath(path) {
		return "", ErrIntegrity
	}
	if err := configAncestors(filepath.Dir(path)); err != nil {
		return "", err
	}
	if err := configAncestors(filepath.Dir(active)); err != nil {
		return "", err
	}
	for _, link := range []string{path, active} {
		info, err := os.Lstat(link)
		metadata, ok := entryMetadata(info)
		if err != nil || !ok || metadata.Uid != 0 || metadata.Gid != 0 || info.Mode()&os.ModeSymlink == 0 {
			return "", ErrIntegrity
		}
	}
	target, err := os.Readlink(path)
	if err != nil || target != filepath.Join(active, "root", strings.TrimPrefix(path, "/")) {
		return "", ErrIntegrity
	}
	generation, err := os.Readlink(active)
	if err != nil || filepath.Dir(generation) != releases || !validDigest(filepath.Base(generation)) {
		return "", ErrIntegrity
	}
	resolved := filepath.Join(generation, "root", strings.TrimPrefix(path, "/"))
	if err := configAncestors(filepath.Dir(resolved)); err != nil {
		return "", err
	}
	info, err = os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", ErrIntegrity
	}
	if err := requireRootOwned(info, 0644, false); err != nil {
		return "", err
	}
	return resolved, nil
}

// Check every component, not just the immediate parent: a root-owned file in
// an attacker-writable ancestor is not a trusted configuration boundary.
func configAncestors(path string) error {
	for {
		info, err := os.Lstat(path)
		metadata, ok := entryMetadata(info)
		if err != nil || !ok || metadata.Uid != 0 || metadata.Gid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return ErrIntegrity
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
