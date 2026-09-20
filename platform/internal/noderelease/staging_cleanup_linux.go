//go:build linux

package noderelease

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
)

// cleanupCompletedStaging removes a named extraction after Apply no longer
// needs it, after durable completion, or after verifying the retained release.
// Retained release trees and their rollback packages are never removed here.
func cleanupCompletedStaging(root, digest string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || !validDigest(digest) {
		return ErrInvalid
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
		return ErrIntegrity
	}
	target := filepath.Join(root, digest)
	info, err = os.Lstat(target)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
		return ErrIntegrity
	}
	raw, err := readRootOwnedFile(filepath.Join(target, BundleManifestPath), maximumSpecBytes, 0600)
	if err != nil {
		return err
	}
	var envelope SignedManifest
	if decodeStrictJSON(raw, &envelope) != nil || envelope.Manifest.ManifestDigest != digest {
		return ErrIntegrity
	}
	if err = os.RemoveAll(target); err != nil {
		return err
	}
	return syncDirectory(root)
}

// PruneInstalledStaging handles installations made before automatic cleanup.
// It verifies both materialized releases before removing either duplicate.
func (installer *Installer) PruneInstalledStaging(ctx context.Context) error {
	if installer == nil || ctx == nil {
		return ErrInvalid
	}
	return installer.withLock(func() error {
		state, err := loadInstalledState()
		if err != nil {
			return err
		}
		trust, err := LoadTrustStore(TrustRoot)
		if err != nil {
			return err
		}
		releases := []InstalledRelease{state.Active}
		if state.Previous != nil {
			releases = append(releases, *state.Previous)
		}
		for _, release := range releases {
			if _, _, err = loadRetainedEnvelopeWithoutTime(release, trust); err != nil {
				return err
			}
		}
		for _, release := range releases {
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = cleanupCompletedStaging(StagingRoot, release.ManifestDigest); err != nil {
				return err
			}
		}
		return nil
	})
}
