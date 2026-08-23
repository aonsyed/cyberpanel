package apps

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (binding AccessProtectionBinding) Validate() error {
	if err := requireID("installation", string(binding.InstallationID)); err != nil { return err }
	if !validWebAccessPolicyID(binding.PolicyID) || binding.Generation == 0 || len(binding.Route) > 2048 || strings.IndexByte(binding.Route, 0) >= 0 || !strings.HasPrefix(binding.Route, "/") {
		return fmt.Errorf("%w: application access protection", ErrInvalid)
	}
	return nil
}

func validWebAccessPolicyID(value string) bool {
	if len(value) < 3 || len(value) > 255 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") { return false }
	segments:=strings.Split(value,"/");if len(segments)<2{return false}
	for _,segment:=range segments{if !idPattern.MatchString(segment){return false}}
	return true
}

type AccessProtectionRequest struct {
	CommandID          CommandID `json:"command_id"`
	InstallationID     InstallationID `json:"installation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Binding            AccessProtectionBinding `json:"binding"`
}

// WebAccessPolicyPort bridges the application domain to the engine-neutral
// access-policy service. Credential verifiers remain owned by that service;
// the application subsystem stores only a policy binding and never plaintext.
type WebAccessPolicyPort interface {
	BindApplicationPolicy(context.Context, TenantID, SiteID, InstallationID, string, string) error
	EnableApplicationPolicy(context.Context, string) error
	DisableApplicationPolicy(context.Context, string) error
	RevokeApplicationPolicy(context.Context, string) error
}

type AccessProtectionStore interface {
	SaveAccessProtection(context.Context, AccessProtectionBinding, uint64) error
	LoadAccessProtection(context.Context, InstallationID) (AccessProtectionBinding, error)
}

type AccessProtectionService struct {
	Store interface { ApplicationStore; AccessProtectionStore }
	Policies WebAccessPolicyPort
	Now func() time.Time
}

func (service AccessProtectionService) now() time.Time {
	if service.Now != nil { return service.Now().UTC() }
	return time.Now().UTC()
}

func (service AccessProtectionService) Configure(ctx context.Context, request AccessProtectionRequest) (AccessProtectionBinding, error) {
	if service.Store == nil || service.Policies == nil { return AccessProtectionBinding{}, ErrInvalid }
	if err := request.Binding.Validate(); err != nil { return AccessProtectionBinding{}, err }
	installation, err := service.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return AccessProtectionBinding{}, err }
	if installation.Generation != request.ExpectedGeneration || request.Binding.InstallationID != installation.ID { return AccessProtectionBinding{}, ErrStaleGeneration }
	digest, err := requestDigest(request)
	if err != nil { return AccessProtectionBinding{}, err }
	operation := Operation{CommandID: request.CommandID, Kind: "application_access_protection", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: service.now(), UpdatedAt: service.now()}
	operation, created, err := service.Store.AdmitOperation(ctx, operation)
	if err != nil { return AccessProtectionBinding{}, err }
	if !created {
		if operation.State == OperationCommitted { return service.Store.LoadAccessProtection(ctx, installation.ID) }
		return AccessProtectionBinding{}, ErrConflict
	}
	currentGeneration := uint64(0)
	current, loadErr := service.Store.LoadAccessProtection(ctx, installation.ID)
	if loadErr == nil { currentGeneration = current.Generation }
	if request.Binding.Generation != currentGeneration+1 { return AccessProtectionBinding{}, ErrStaleGeneration }
	if currentGeneration == 0 {
		if err := service.Policies.BindApplicationPolicy(ctx, installation.TenantID, installation.SiteID, installation.ID, request.Binding.PolicyID, request.Binding.Route); err != nil { return AccessProtectionBinding{}, service.fail(ctx, operation, "bind", err) }
	}
	if request.Binding.Enabled { err = service.Policies.EnableApplicationPolicy(ctx, request.Binding.PolicyID) } else { err = service.Policies.DisableApplicationPolicy(ctx, request.Binding.PolicyID) }
	if err != nil { return AccessProtectionBinding{}, service.fail(ctx, operation, "configure", err) }
	if err := service.Store.SaveAccessProtection(ctx, request.Binding, currentGeneration); err != nil { return AccessProtectionBinding{}, service.recovery(ctx, operation, "persist", err) }
	resultDigest, err := requestDigest(request.Binding)
	if err != nil { return AccessProtectionBinding{}, err }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", resultDigest, service.now()
	if err := service.Store.UpdateOperation(ctx, operation); err != nil { return AccessProtectionBinding{}, err }
	return request.Binding, nil
}

func (service AccessProtectionService) Revoke(ctx context.Context, commandID CommandID, installationID InstallationID) error {
	installation, err := service.Store.LoadInstallation(ctx, installationID)
	if err != nil { return err }
	binding, err := service.Store.LoadAccessProtection(ctx, installationID)
	if err != nil { return err }
	digest, err := requestDigest(struct{ CommandID CommandID; InstallationID InstallationID; Generation uint64 }{commandID, installationID, binding.Generation})
	if err != nil { return err }
	operation := Operation{CommandID: commandID, Kind: "application_access_revoke", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: service.now(), UpdatedAt: service.now()}
	operation, created, err := service.Store.AdmitOperation(ctx, operation)
	if err != nil { return err }
	if !created { if operation.State == OperationCommitted { return nil }; return ErrConflict }
	if err := service.Policies.RevokeApplicationPolicy(ctx, binding.PolicyID); err != nil { return service.fail(ctx, operation, "revoke", err) }
	binding.Enabled, binding.Generation = false, binding.Generation+1
	if err := service.Store.SaveAccessProtection(ctx, binding, binding.Generation-1); err != nil { return service.recovery(ctx, operation, "persist", err) }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", digest, service.now()
	return service.Store.UpdateOperation(ctx, operation)
}

func (service AccessProtectionService) fail(ctx context.Context, operation Operation, stage string, cause error) error {
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, stage, cause.Error(), service.now()
	_ = service.Store.UpdateOperation(ctx, operation)
	return cause
}

func (service AccessProtectionService) recovery(ctx context.Context, operation Operation, stage string, cause error) error {
	operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationRecoveryRequired, stage, cause.Error(), service.now()
	_ = service.Store.UpdateOperation(ctx, operation)
	return fmt.Errorf("%w: %v", ErrRecoveryRequired, cause)
}
