package apps

import "context"

type installationOwnershipRecovery interface {
	RecoverInstallationOwnership(context.Context, ApplicationInstallation, RecoveryPointID) (DatabaseBindingID, []SecretRef, ReleaseID, error)
}

func removalRecoveryRequest(installation ApplicationInstallation) RecoveryRequest {
	return RecoveryRequest{TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, Purpose: "application_removal", Consistency: "application_consistent", Required: true}
}

func (coordinator LifecycleCoordinator) recoverStrandedInstall(ctx context.Context, installation *ApplicationInstallation, snapshot RecoveryPointID) error {
	operations, next, err := coordinator.Store.ListOperations(ctx, installation.ID, 100, "")
	if err != nil {
		return err
	}
	// Ambiguous histories require explicit recovery, never an inferred removal.
	if next != "" {
		return ErrRecoveryRequired
	}
	matched := false
	for _, operation := range operations {
		if operation.Kind != "install" {
			continue
		}
		if operation.InstallationID != installation.ID || operation.TenantID != installation.TenantID || operation.SiteID != installation.SiteID || operation.State != OperationRecoveryRequired || operation.Stage != "health" {
			return ErrRecoveryRequired
		}
		matched = true
	}
	if !matched {
		return ErrRecoveryRequired
	}
	if installation.DatabaseBindingID == "" {
		provider, ok := coordinator.Recovery.(installationOwnershipRecovery)
		if !ok {
			return ErrRecoveryRequired
		}
		database, refs, release, err := provider.RecoverInstallationOwnership(ctx, *installation, snapshot)
		if err != nil {
			return err
		}
		if database == "" || len(refs) == 0 || release == "" {
			return ErrIntegrity
		}
		installation.DatabaseBindingID, installation.SecretRefs, installation.ActiveReleaseID = database, refs, release
	}
	previous := installation.Generation
	if err := installation.Transition(InstallationRecovery, coordinator.now()); err != nil {
		return err
	}
	return coordinator.Store.UpdateInstallation(ctx, *installation, previous)
}
