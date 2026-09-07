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
	RepairID                 string    `json:"repair_id,omitempty"`
	RepairCode               string    `json:"repair_code,omitempty"`
	RepairState              string    `json:"repair_state,omitempty"`
	RepairDigest             string    `json:"repair_digest,omitempty"`
	RebootRequired           bool      `json:"reboot_required"`
	PlannedReboot            string    `json:"planned_reboot,omitempty"`
	InventoryID              string    `json:"inventory_id"`
	InventoryDigest          string    `json:"inventory_digest"`
	PlanID                   string    `json:"plan_id,omitempty"`
	PlanDigest               string    `json:"plan_digest,omitempty"`
	PlannedChanges           []string  `json:"planned_changes,omitempty"`
	PlannedServices          []string  `json:"planned_services,omitempty"`
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

type PackageMaintenancePackageProjection struct {
	SupportedUpdates []PackageMaintenanceUpdateOption `json:"supported_updates"`
	ID string `json:"id"`; Type string `json:"type"`; NodeID string `json:"node_id"`; Manager string `json:"manager"`
	Name string `json:"name"`; Architecture string `json:"architecture"`; InstalledVersion string `json:"installed_version"`; CandidateVersion string `json:"candidate_version,omitempty"`
	PendingSecurity bool `json:"pending_security"`; Security string `json:"security"`; RepositoryID string `json:"repository_id,omitempty"`; RepositoryOrigin string `json:"repository_origin,omitempty"`
	RepositorySuite string `json:"repository_suite,omitempty"`; RepositoryComponent string `json:"repository_component,omitempty"`; RepositoryEnabled bool `json:"repository_enabled"`; RepositoryMetadataRevision string `json:"repository_metadata_revision,omitempty"`; RepositorySignature string `json:"repository_signature,omitempty"`; RepositorySigningKeyID string `json:"repository_signing_key_id,omitempty"`; RepositoryDigest string `json:"repository_digest,omitempty"`
	InstalledProvenanceDigest string `json:"installed_provenance_digest"`; InstalledProvenanceSignature string `json:"installed_provenance_signature"`; InstalledProvenanceSigningKeyID string `json:"installed_provenance_signing_key_id,omitempty"`; InstalledVendor string `json:"installed_vendor,omitempty"`; LocalArtifact bool `json:"local_artifact"`
	CandidateProvenanceDigest string `json:"candidate_provenance_digest,omitempty"`; CandidateProvenanceSignature string `json:"candidate_provenance_signature,omitempty"`
	Held bool `json:"held"`; HoldKind string `json:"hold_kind,omitempty"`; HoldSource string `json:"hold_source,omitempty"`
	HoldOperationID string `json:"hold_operation_id,omitempty"`; HoldOutcome string `json:"hold_outcome,omitempty"`; HoldReceiptDigest string `json:"hold_receipt_digest,omitempty"`
	InventoryID string `json:"inventory_id"`; InventoryDigest string `json:"inventory_digest"`; Generation uint64 `json:"generation"`; UpdatedAt time.Time `json:"updated_at"`
}

type PackageMaintenanceUpdateOption struct { Label string `json:"label"`; Value string `json:"value"` }

type PackageMaintenancePlanPayload struct {
	TransactionReference    string `json:"transaction_reference,omitempty"`
	ValidForSeconds         uint32 `json:"valid_for_seconds,omitempty"`
	MaintenanceOccurrenceID string `json:"maintenance_occurrence_id"`
}

type PackageMaintenanceApplyPayload struct {
	MaintenanceOccurrenceID string `json:"maintenance_occurrence_id"`
}

type PackageMaintenanceEdgeService interface {
	ListPackageMaintenance(context.Context, EdgeCall, EdgePagePayload) (EdgePage[PackageMaintenanceProjection], error)
	ListPackageMaintenancePackages(context.Context, EdgeCall, EdgePagePayload) (EdgePage[PackageMaintenancePackageProjection], error)
	GetPackageMaintenancePackage(context.Context, EdgeCall) (PackageMaintenancePackageProjection, error)
	HoldPackageMaintenancePackage(context.Context, EdgeCall) (EdgeMutation[PackageMaintenancePackageProjection], error)
	UnholdPackageMaintenancePackage(context.Context, EdgeCall) (EdgeMutation[PackageMaintenancePackageProjection], error)
	RefreshPackageMaintenance(context.Context, EdgeCall) (EdgeMutation[PackageMaintenanceProjection], error)
	PlanPackageMaintenance(context.Context, EdgeCall, PackageMaintenancePlanPayload) (EdgeMutation[PackageMaintenanceProjection], error)
	ApplyPackageMaintenance(context.Context, EdgeCall, PackageMaintenanceApplyPayload) (EdgeMutation[PackageMaintenanceProjection], error)
}

type PackageMaintenanceRepairEdge interface {
	PlanPackageRepair(context.Context,EdgeCall,PackageMaintenanceApplyPayload) (EdgeMutation[PackageMaintenanceProjection],error)
	ExecutePackageRepair(context.Context,EdgeCall,PackageMaintenanceApplyPayload) (EdgeMutation[PackageMaintenanceProjection],error)
}

// PackageMaintenanceEdgeCapabilities prevents a status-only deployment from
// advertising plan or apply before its signed resolver, protected authorizer,
// and privileged executor are all present.
type PackageMaintenanceEdgeCapabilities struct {
	List    bool
	Refresh bool
	Plan    bool
	Apply   bool
	Packages bool
	Holds bool
}

type PackageMaintenanceEdgeCapabilityProvider interface {
	PackageMaintenanceCapabilities() PackageMaintenanceEdgeCapabilities
}

func registerPackageMaintenanceContracts(registry *Registry) error {
	definitions := []Operation{
		consoleOperation("package_maintenance.repair.plan", "package:manage", identity.AssuranceMFA, true, func() any { return &PackageMaintenanceApplyPayload{} }, validatePackageMaintenanceApply, edgeInstallationExistingMutationScope),
		consoleOperation("package_maintenance.repair.execute", "package:manage", identity.AssurancePhishingResistant, true, func() any { return &PackageMaintenanceApplyPayload{} }, validatePackageMaintenanceApply, edgeInstallationExistingMutationScope),
		consoleOperation("package_maintenance.status.list", "operations:observe", identity.AssurancePassword, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeInstallationListScope),
		consoleOperation("package_maintenance.package.list", "operations:observe", identity.AssurancePassword, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeInstallationListScope),
		consoleOperation("package_maintenance.package.get", "operations:observe", identity.AssurancePassword, false, func() any { return &EmptyPayload{} }, nil, edgeInstallationResourceReadScope),
		consoleOperation("package_maintenance.package.hold", "package:manage", identity.AssuranceMFA, true, func() any { return &EmptyPayload{} }, nil, edgeInstallationExistingMutationScope),
		consoleOperation("package_maintenance.package.unhold", "package:manage", identity.AssuranceMFA, true, func() any { return &EmptyPayload{} }, nil, edgeInstallationExistingMutationScope),
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
	if payload.TransactionReference != "" && !validEdgeID(payload.TransactionReference) { return invalid("signed package update reference") }
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
	if repairs,ok := services.PackageMaintenance.(PackageMaintenanceRepairEdge); ok {
		if err := registry.Bind("package_maintenance.repair.plan",func(ctx context.Context,invocation Invocation,value any)(OperationResult,error){ result,err := repairs.PlanPackageRepair(ctx,edgeCall(invocation),*value.(*PackageMaintenanceApplyPayload)); if err != nil { return OperationResult{},mapDomainError(err) }; return edgeOperationResult(http.StatusAccepted,result),nil }); err != nil { return err }
		if err := registry.Bind("package_maintenance.repair.execute",func(ctx context.Context,invocation Invocation,value any)(OperationResult,error){ result,err := repairs.ExecutePackageRepair(ctx,edgeCall(invocation),*value.(*PackageMaintenanceApplyPayload)); if err != nil { return OperationResult{},mapDomainError(err) }; return edgeOperationResult(http.StatusAccepted,result),nil }); err != nil { return err }
	}
	capabilities := PackageMaintenanceEdgeCapabilities{List: true, Refresh: true, Plan: true, Apply: true, Packages: true, Holds: true}
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
	if capabilities.Packages {
		if err := registry.Bind("package_maintenance.package.list", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
			result, err := services.PackageMaintenance.ListPackageMaintenancePackages(ctx, edgeCall(invocation), *value.(*EdgePagePayload)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status: http.StatusOK, Value: result}, nil
		}); err != nil { return err }
		if err := registry.Bind("package_maintenance.package.get", func(ctx context.Context, invocation Invocation, _ any) (OperationResult, error) {
			result, err := services.PackageMaintenance.GetPackageMaintenancePackage(ctx, edgeCall(invocation)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status: http.StatusOK, Value: result}, nil
		}); err != nil { return err }
	}
	if capabilities.Holds {
		if err := registry.Bind("package_maintenance.package.hold", func(ctx context.Context, invocation Invocation, _ any) (OperationResult, error) {
			result, err := services.PackageMaintenance.HoldPackageMaintenancePackage(ctx, edgeCall(invocation)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
		if err := registry.Bind("package_maintenance.package.unhold", func(ctx context.Context, invocation Invocation, _ any) (OperationResult, error) {
			result, err := services.PackageMaintenance.UnholdPackageMaintenancePackage(ctx, edgeCall(invocation)); if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
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
