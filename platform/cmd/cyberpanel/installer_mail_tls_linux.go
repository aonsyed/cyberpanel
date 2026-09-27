//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/certificates"
)

// A fresh node needs a local fallback identity before any tenant certificate
// exists. It is deliberately self-signed, not a publicly trusted mail identity,
// and has its own key instead of sharing the web-engine fallback private key.
func bootstrapDefaultMailCertificate() error {
	if _, err := bootstrapDefaultCertificate("mail", "default"); err != nil {
		return err
	}
	if err := certificates.PublishLocalMailIdentity(""); err != nil {
		return err
	}
	// A clean host has no mail store yet; the first generation belongs to the
	// running panel, but the fixed store root is installer-owned.
	if err := trustedDNSAncestors("/var/lib/cyberpanel"); err != nil {
		return err
	}
	if err := ensureOwnedDirectory("/var/lib/cyberpanel/mail", 0750, 0, 0); err != nil {
		return err
	}
	const parent = "/var/lib/cyberpanel/mail/tls"
	if err := trustedDNSAncestors("/var/lib/cyberpanel/mail"); err != nil {
		return err
	}
	if err := ensureOwnedDirectory(parent, 0750, 0, 0); err != nil {
		return err
	}
	const path = parent + "/default"
	const target = "/var/lib/cyberpanel/certificates/consumers/mail/default/current"
	info, err := os.Lstat(path)
	if err == nil {
		link, linkErr := os.Readlink(path)
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if linkErr != nil || !ok || metadata.Uid != 0 || link != target {
			return errors.New("unmanaged mail fallback certificate binding")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return installDefaultCertificateLink(path, target)
}
