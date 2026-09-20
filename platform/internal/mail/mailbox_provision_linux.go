//go:build linux

package mail

import (
	"syscall"

	"github.com/aonsyed/cyberpanel/platform/internal/executor/siteops"
)

// Called only after the site's live registry binding and mailbox credential
// have been verified. Replays accept exact ownership; they never chown existing
// customer data or follow symlinks. Empty directories may survive failed config
// activation, but no authentication is published until generation activation.
func ensureOrdinaryMaildir(root int, domain, local string, identity siteops.RuntimeBinding) error {
	if !validHostname(domain) || !validLocalPart(local) || identity.Validate() != nil || identity.State != siteops.BindingActive || identity.UID < 200000 || identity.UID > 599999 {
		return ErrUnauthorized
	}
	mailboxes, err := ensureMailDirectory(root, "mailboxes", 0, 0, 0755)
	if err != nil {
		return err
	}
	defer syscall.Close(mailboxes)
	domainFD, err := ensureMailDirectory(mailboxes, domain, 0, 0, 0711)
	if err != nil {
		return err
	}
	defer syscall.Close(domainFD)
	home, err := ensureMailDirectory(domainFD, local, identity.UID, identity.GID, 0700)
	if err != nil {
		return err
	}
	defer syscall.Close(home)
	maildir, err := ensureMailDirectory(home, "Maildir", identity.UID, identity.GID, 0700)
	if err != nil {
		return err
	}
	defer syscall.Close(maildir)
	for _, name := range []string{"cur", "new", "tmp"} {
		fd, err := ensureMailDirectory(maildir, name, identity.UID, identity.GID, 0700)
		if err != nil {
			return err
		}
		syscall.Close(fd)
	}
	return nil
}
