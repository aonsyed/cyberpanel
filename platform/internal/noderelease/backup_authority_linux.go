//go:build linux

package noderelease

import "github.com/aonsyed/cyberpanel/platform/internal/backupauthority"

// This installer does not execute the legacy authority hooks. Reconcile the
// fixed local repository parent before core activation, including probe replay.
// No release-selected path or executable is accepted here.
func prepareServiceAuthority(unit string) error {
	if unit != "panel-core.service" {
		return nil
	}
	_, err := backupauthority.ReconcileLocalRepositoryAuthority()
	return err
}
