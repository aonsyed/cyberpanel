package apps

import (
	"context"
	"fmt"
	"time"
)

type WordPressMutationRequest struct {
	CommandID          CommandID `json:"command_id"`
	InstallationID     InstallationID `json:"installation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Action             WordPressComponentAction `json:"action"`
	Kind               ComponentKind `json:"kind"`
	Name               string `json:"name"`
	ExpectedVersion    string `json:"expected_version,omitempty"`
	ExpectedDigest     string `json:"expected_digest,omitempty"`
	Release            *ComponentRelease `json:"release,omitempty"`
	Force              bool `json:"force"`
	NetworkWide        bool `json:"network_wide"`
	SiteGeneration     uint64 `json:"site_generation"`
	IsolationProfile   string `json:"isolation_profile"`
}

type WordPressManager struct {
	Store      ApplicationStore
	Executor   WordPressExecutor
	Recovery   RecoveryPointProvider
	Now        func() time.Time
}

func (manager WordPressManager) now() time.Time {
	if manager.Now != nil { return manager.Now().UTC() }
	return time.Now().UTC()
}

func (manager WordPressManager) MutateComponent(ctx context.Context, request WordPressMutationRequest) (ComponentInventory, error) {
	if manager.Store == nil || manager.Executor == nil || manager.Recovery == nil { return ComponentInventory{}, ErrInvalid }
	installation, err := manager.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return ComponentInventory{}, err }
	if installation.Kind != ApplicationWordPress || installation.Generation != request.ExpectedGeneration || installation.State != InstallationActive && installation.State != InstallationDegraded { return ComponentInventory{}, ErrConflict }
	digest, err := requestDigest(request)
	if err != nil { return ComponentInventory{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "wordpress_component", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: manager.now(), UpdatedAt: manager.now()}
	operation, created, err := manager.Store.AdmitOperation(ctx, operation)
	if err != nil { return ComponentInventory{}, err }
	if !created {
		if operation.State == OperationCommitted { return manager.Store.LoadInventory(ctx, installation.ID) }
		return ComponentInventory{}, ErrConflict
	}
	recoveryPoint, _, err := manager.Recovery.CreateRecoveryPoint(ctx, RecoveryRequest{TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, Purpose: "wordpress_component_" + string(request.Action), Consistency: "application_consistent", Required: request.Action == WordPressUpdateComponent || request.Action == WordPressDeleteComponent || request.Action == WordPressReinstallCore})
	if err != nil { return ComponentInventory{}, manager.fail(ctx, operation, "recovery_point", err) }
	if err := manager.Recovery.VerifyRecoveryPoint(ctx, recoveryPoint); err != nil { return ComponentInventory{}, manager.fail(ctx, operation, "verify_recovery_point", err) }
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	mutation := ComponentMutation{Scope: scope, InstallationID: installation.ID, Action: request.Action, Kind: request.Kind, Name: request.Name, ExpectedVersion: request.ExpectedVersion, ExpectedDigest: request.ExpectedDigest, Release: request.Release, Force: request.Force, NetworkWide: request.NetworkWide, RecoveryPointID: recoveryPoint}
	if err := mutation.Validate(); err != nil { return ComponentInventory{}, manager.fail(ctx, operation, "validate", err) }
	operation.State, operation.Stage, operation.UpdatedAt = OperationExecuting, "execute", manager.now()
	if err := manager.Store.UpdateOperation(ctx, operation); err != nil { return ComponentInventory{}, err }
	inventory, receipt, err := manager.Executor.MutateComponent(ctx, mutation)
	if err != nil { return ComponentInventory{}, manager.fail(ctx, operation, "execute", err) }
	if err := receipt.Validate("wordpress_component", scope, installation.ID); err != nil { return ComponentInventory{}, manager.recovery(ctx, operation, "executor_receipt", err) }
	if err := inventory.Validate(); err != nil { return ComponentInventory{}, manager.recovery(ctx, operation, "inventory", err) }
	if err := manager.Store.SaveInventory(ctx, inventory); err != nil { return ComponentInventory{}, manager.recovery(ctx, operation, "persist_inventory", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, manager.now()
	if err := manager.Store.UpdateOperation(ctx, operation); err != nil { return ComponentInventory{}, err }
	return inventory, nil
}

type WordPressSettingsRequest struct {
	CommandID          CommandID `json:"command_id"`
	InstallationID     InstallationID `json:"installation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Settings           WordPressSettings `json:"settings"`
	SiteGeneration     uint64 `json:"site_generation"`
	IsolationProfile   string `json:"isolation_profile"`
}

func (manager WordPressManager) UpdateSettings(ctx context.Context, request WordPressSettingsRequest) (WordPressSettings, error) {
	if err := request.Settings.Validate(); err != nil { return WordPressSettings{}, err }
	installation, err := manager.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return WordPressSettings{}, err }
	if installation.Kind != ApplicationWordPress || installation.Generation != request.ExpectedGeneration { return WordPressSettings{}, ErrConflict }
	currentGeneration := uint64(0)
	current, loadErr := manager.Store.LoadWordPressSettings(ctx, installation.ID)
	if loadErr == nil { currentGeneration = current.Generation } else if loadErr != ErrNotFound { return WordPressSettings{}, loadErr }
	if request.Settings.Generation != currentGeneration+1 { return WordPressSettings{}, ErrStaleGeneration }
	digest, err := requestDigest(request)
	if err != nil { return WordPressSettings{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "wordpress_settings", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: manager.now(), UpdatedAt: manager.now()}
	operation, created, err := manager.Store.AdmitOperation(ctx, operation)
	if err != nil { return WordPressSettings{}, err }
	if !created {
		if operation.State == OperationCommitted { return manager.Store.LoadWordPressSettings(ctx, installation.ID) }
		return WordPressSettings{}, ErrConflict
	}
	recoveryPoint, _, err := manager.Recovery.CreateRecoveryPoint(ctx, RecoveryRequest{TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, Purpose: "wordpress_settings", Consistency: "application_consistent", Required: true})
	if err != nil { return WordPressSettings{}, manager.fail(ctx, operation, "recovery_point", err) }
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	settings, receipt, err := manager.Executor.ApplySettings(ctx, WordPressSettingsMutation{Scope: scope, InstallationID: installation.ID, ExpectedGeneration: currentGeneration, Settings: request.Settings, RecoveryPointID: recoveryPoint})
	if err != nil { return WordPressSettings{}, manager.fail(ctx, operation, "execute", err) }
	if err := receipt.Validate("wordpress_settings", scope, installation.ID); err != nil { return WordPressSettings{}, manager.recovery(ctx, operation, "receipt", err) }
	if err := manager.Store.SaveWordPressSettings(ctx, installation.ID, settings, currentGeneration); err != nil { return WordPressSettings{}, manager.recovery(ctx, operation, "persist", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, manager.now()
	if err := manager.Store.UpdateOperation(ctx, operation); err != nil { return WordPressSettings{}, err }
	return settings, nil
}

type LSCacheRequest struct {
	CommandID        CommandID `json:"command_id"`
	InstallationID   InstallationID `json:"installation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Policy           LSCachePolicy `json:"policy"`
	SiteGeneration   uint64 `json:"site_generation"`
	IsolationProfile string `json:"isolation_profile"`
}

func (manager WordPressManager) ConfigureLSCache(ctx context.Context, request LSCacheRequest) (LSCachePolicy, error) {
	if err := request.Policy.Validate(); err != nil { return LSCachePolicy{}, err }
	installation, err := manager.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return LSCachePolicy{}, err }
	if installation.Kind != ApplicationWordPress || installation.Generation != request.ExpectedGeneration || request.Policy.InstallationID != installation.ID { return LSCachePolicy{}, ErrConflict }
	currentGeneration := uint64(0)
	current, loadErr := manager.Store.LoadLSCachePolicy(ctx, installation.ID)
	if loadErr == nil { currentGeneration = current.Generation } else if loadErr != ErrNotFound { return LSCachePolicy{}, loadErr }
	if request.Policy.Generation != currentGeneration+1 { return LSCachePolicy{}, ErrStaleGeneration }
	digest, err := requestDigest(request)
	if err != nil { return LSCachePolicy{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "lscache_configure", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: manager.now(), UpdatedAt: manager.now()}
	operation, created, err := manager.Store.AdmitOperation(ctx, operation)
	if err != nil { return LSCachePolicy{}, err }
	if !created {
		if operation.State == OperationCommitted { return manager.Store.LoadLSCachePolicy(ctx, installation.ID) }
		return LSCachePolicy{}, ErrConflict
	}
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	policy, receipt, err := manager.Executor.ConfigureLSCache(ctx, CacheMutation{Scope: scope, InstallationID: installation.ID, Policy: &request.Policy})
	if err != nil { return LSCachePolicy{}, manager.fail(ctx, operation, "execute", err) }
	if err := receipt.Validate("lscache_configure", scope, installation.ID); err != nil { return LSCachePolicy{}, manager.fail(ctx, operation, "receipt", err) }
	if err := manager.Store.SaveLSCachePolicy(ctx, policy, currentGeneration); err != nil { return LSCachePolicy{}, manager.recovery(ctx, operation, "persist", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, manager.now()
	if err := manager.Store.UpdateOperation(ctx, operation); err != nil { return LSCachePolicy{}, err }
	return policy, nil
}

type LSCachePurgeRequest struct {
	CommandID CommandID `json:"command_id"`
	InstallationID InstallationID `json:"installation_id"`
	PurgeScope CachePurgeScope `json:"purge_scope"`
	Values []string `json:"values,omitempty"`
	SiteGeneration uint64 `json:"site_generation"`
	IsolationProfile string `json:"isolation_profile"`
}

func (manager WordPressManager) PurgeLSCache(ctx context.Context, request LSCachePurgeRequest) error {
	installation, err := manager.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return err }
	if installation.Kind != ApplicationWordPress || request.PurgeScope != PurgeAll && len(request.Values) == 0 { return ErrInvalid }
	digest, err := requestDigest(request)
	if err != nil { return err }
	operation := Operation{CommandID: request.CommandID, Kind: "lscache_purge", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: manager.now(), UpdatedAt: manager.now()}
	operation, created, err := manager.Store.AdmitOperation(ctx, operation)
	if err != nil { return err }
	if !created { if operation.State == OperationCommitted { return nil }; return ErrConflict }
	scope := SiteExecutionScope{TenantID: installation.TenantID, SiteID: installation.SiteID, SiteUID: installation.SiteUID, Root: installation.Root, IsolationProfile: request.IsolationProfile, ResourceGeneration: request.SiteGeneration}
	receipt, err := manager.Executor.PurgeLSCache(ctx, CacheMutation{Scope: scope, InstallationID: installation.ID, PurgeScope: request.PurgeScope, PurgeValues: request.Values})
	if err != nil { return manager.fail(ctx, operation, "execute", err) }
	if err := receipt.Validate("lscache_purge", scope, installation.ID); err != nil { return manager.fail(ctx, operation, "receipt", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, manager.now()
	return manager.Store.UpdateOperation(ctx, operation)
}

func (manager WordPressManager) fail(ctx context.Context, operation Operation, stage string, cause error) error {
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, stage, cause.Error(), manager.now()
	_ = manager.Store.UpdateOperation(ctx, operation)
	return cause
}

func (manager WordPressManager) recovery(ctx context.Context, operation Operation, stage string, cause error) error {
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationRecoveryRequired, stage, cause.Error(), manager.now()
	_ = manager.Store.UpdateOperation(ctx, operation)
	return fmt.Errorf("%w: %v", ErrRecoveryRequired, cause)
}
