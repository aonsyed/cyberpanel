package apiserver

import (
	"context"
	"net/http"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

// PackageMaintenanceProjection is an installation-scoped summary. It exposes
// bounded health and durable evidence, never caller-selectable package names,
// repository locations, native solver input, or command arguments.
type PackageMaintenanceProjection struct {
	ID                       string    `json:"id"`
	Type                     string    `json:"type"`
	NodeID                   string    `json:"node_id"`
	Manager                  string    `json:"manager"`
	RepositoryHealth         string    `json:"repository_health"`
	EnabledRepositories      uint64    `json:"enabled_repositories"`
	VerifiedRepositories     uint64    `json:"verified_repositories"`
	BlockedRepositories      uint64    `json:"blocked_repositories"`
	SecurityUpdatesAvailable uint64    `json:"security_updates_available"`
	SecurityUpdatesBlocked   uint64    `json:"security_updates_blocked"`
	HighestSecurity          string    `json:"highest_security"`
	PackageDatabaseStatus    string    `json:"package_database_status"`
	RebootRequired           bool      `json:"reboot_required"`
	PlannedReboot            string    `json:"planned_reboot,omitempty"`
	InventoryID              string    `json:"inventory_id"`
	InventoryDigest          string    `json:"inventory_digest"`
	PlanID                   string    `json:"plan_id,omitempty"`
	PlanDigest               string    `json:"plan_digest,omitempty"`
	MaintenanceOccurrenceID  string    `json:"maintenance_occurrence_id,omitempty"`
	PlanStatus               string    `json:"plan_status"`
	ApplyStatus              string    `json:"apply_status"`
	OperationID              string    `json:"operation_id,omitempty"`
	OperationState           string    `json:"operation_state,omitempty"`
	OperationOutcome         string    `json:"operation_outcome,omitempty"`
	RollbackStatus           string    `json:"rollback_status"`
	RecoveryStatus           string    `json:"recovery_status"`
	RecoveryKind             string    `json:"recovery_kind,omitempty"`
	RecoveryRequired         bool      `json:"recovery_required"`
	RecoveryEvidence         string    `json:"recovery_evidence,omitempty"`
	RecoveryInstructions     []string  `json:"recovery_instructions,omitempty"`
	SnapshotID               string    `json:"snapshot_id,omitempty"`
	Ambiguous                bool      `json:"ambiguous"`
	Generation               uint64    `json:"generation"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type PackageMaintenancePlanPayload struct {
	ValidForSeconds         uint32 `json:"valid_for_seconds,omitempty"`
	MaintenanceOccurrenceID string `json:"maintenance_occurrence_id"`
}

type PackageMaintenanceApplyPayload struct {
	MaintenanceOccurrenceID string `json:"maintenance_occurrence_id"`
}

type PackageMaintenanceEdgeService interface {
	ListPackageMaintenance(context.Context, EdgeCall, EdgePagePayload) (EdgePage[PackageMaintenanceProjection], error)
	RefreshPackageMaintenance(context.Context, EdgeCall) (EdgeMutation[PackageMaintenanceProjection], error)
	PlanPackageMaintenance(context.Context, EdgeCall, PackageMaintenancePlanPayload) (EdgeMutation[PackageMaintenanceProjection], error)
	ApplyPackageMaintenance(context.Context, EdgeCall, PackageMaintenanceApplyPayload) (EdgeMutation[PackageMaintenanceProjection], error)
}

// PackageMaintenanceEdgeCapabilities prevents a status-only deployment from
// advertising plan or apply before its signed resolver, protected authorizer,
// and privileged executor are all present.
type PackageMaintenanceEdgeCapabilities struct {
	List    bool
	Refresh bool
	Plan    bool
	Apply   bool
}

type PackageMaintenanceEdgeCapabilityProvider interface {
	PackageMaintenanceCapabilities() PackageMaintenanceEdgeCapabilities
}

func registerPackageMaintenanceContracts(registry *Registry) error {
	definitions := []Operation{
		consoleOperation("package_maintenance.status.list", "operations:observe", identity.AssurancePassword, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeInstallationListScope),
		consoleOperation("package_maintenance.refresh", "package:manage", identity.AssuranceMFA, true, func() any { return &EmptyPayload{} }, nil, edgeInstallationCreateScope),
		consoleOperation("package_maintenance.plan", "package:manage", identity.AssuranceMFA, true, func() any { return &PackageMaintenancePlanPayload{} }, validatePackageMaintenancePlan, edgeInstallationExistingMutationScope),
		consoleOperation("package_maintenance.apply", "package:manage", identity.AssurancePhishingResistant, true, func() any { return &PackageMaintenanceApplyPayload{} }, validatePackageMaintenanceApply, edgeInstallationExistingMutationScope),
	}
	for _, definition := range definitions {
		if err := register(registry, definition); err != nil {
			return err
		}
	}
	return nil
}

func validatePackageMaintenancePlan(value any) error {
	payload := value.(*PackageMaintenancePlanPayload)
	if payload.ValidForSeconds == 0 {
		payload.ValidForSeconds = 1800
	}
	if payload.ValidForSeconds < 60 || payload.ValidForSeconds > 86400 || !validEdgeID(payload.MaintenanceOccurrenceID) {
		return invalid("package maintenance plan lifetime")
	}
	return nil
}

func validatePackageMaintenanceApply(value any) error {
	if !validEdgeID(value.(*PackageMaintenanceApplyPayload).MaintenanceOccurrenceID) {
		return invalid("package maintenance occurrence")
	}
	return nil
}

func bindPackageMaintenanceContracts(registry *Registry, services DomainServices) error {
	if services.PackageMaintenance == nil {
		return nil
	}
	capabilities := PackageMaintenanceEdgeCapabilities{List: true, Refresh: true, Plan: true, Apply: true}
	if provider, ok := services.PackageMaintenance.(PackageMaintenanceEdgeCapabilityProvider); ok {
		capabilities = provider.PackageMaintenanceCapabilities()
	}
	if capabilities.List {
		if err := registry.Bind("package_maintenance.status.list", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
			result, err := services.PackageMaintenance.ListPackageMaintenance(ctx, edgeCall(invocation), *value.(*EdgePagePayload))
			if err != nil {
				return OperationResult{}, mapDomainError(err)
			}
			return OperationResult{Status: http.StatusOK, Value: result}, nil
		}); err != nil {
			return err
		}
	}
	if capabilities.Refresh {
		if err := registry.Bind("package_maintenance.refresh", func(ctx context.Context, invocation Invocation, _ any) (OperationResult, error) {
			result, err := services.PackageMaintenance.RefreshPackageMaintenance(ctx, edgeCall(invocation))
			if err != nil {
				return OperationResult{}, mapDomainError(err)
			}
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil {
			return err
		}
	}
	if capabilities.Plan {
		if err := registry.Bind("package_maintenance.plan", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
			result, err := services.PackageMaintenance.PlanPackageMaintenance(ctx, edgeCall(invocation), *value.(*PackageMaintenancePlanPayload))
			if err != nil {
				return OperationResult{}, mapDomainError(err)
			}
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil {
			return err
		}
	}
	if capabilities.Apply {
		if err := registry.Bind("package_maintenance.apply", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
			result, err := services.PackageMaintenance.ApplyPackageMaintenance(ctx, edgeCall(invocation), *value.(*PackageMaintenanceApplyPayload))
			if err != nil {
				return OperationResult{}, mapDomainError(err)
			}
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil {
			return err
		}
	}
	return nil
}
