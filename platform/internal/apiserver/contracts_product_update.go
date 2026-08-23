package apiserver

import (
	"context"
	"net/http"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type ProductUpdateProjection struct {
	ID                        string    `json:"id"`
	Type                      string    `json:"type"`
	NodeID                    string    `json:"node_id"`
	CurrentVersion            string    `json:"current_version"`
	CurrentChannel            string    `json:"current_channel"`
	TargetVersion             string    `json:"target_version,omitempty"`
	TargetChannel             string    `json:"target_channel,omitempty"`
	Phase                     string    `json:"phase"`
	CheckStatus               string    `json:"check_status"`
	PlanStatus                string    `json:"plan_status"`
	ApplyStatus               string    `json:"apply_status"`
	RollbackClass             string    `json:"rollback_class,omitempty"`
	RollbackStatus            string    `json:"rollback_status,omitempty"`
	RollbackProven            bool      `json:"rollback_proven"`
	RollbackReleaseID         string    `json:"rollback_release_id,omitempty"`
	IrreversibleStep          string    `json:"irreversible_step,omitempty"`
	IrreversibleSchemaVersion uint64    `json:"irreversible_schema_version,omitempty"`
	RecoveryStatus            string    `json:"recovery_status"`
	RecoveryEvidence          string    `json:"recovery_evidence,omitempty"`
	RecoverySteps             []string  `json:"recovery_steps,omitempty"`
	Reason                    string    `json:"reason,omitempty"`
	Generation                uint64    `json:"generation,omitempty"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type ProductUpdateCheckPayload struct {
	ManifestID string `json:"manifest_id"`
}

type ProductUpdateApplyPayload struct {
	ExpectedDurationSeconds uint32 `json:"expected_duration_seconds,omitempty"`
}

type ProductUpdateEdgeService interface {
	ListProductUpdates(context.Context, EdgeCall, EdgePagePayload) (EdgePage[ProductUpdateProjection], error)
	CheckProductUpdate(context.Context, EdgeCall, ProductUpdateCheckPayload) (EdgeMutation[ProductUpdateProjection], error)
	PlanProductUpdate(context.Context, EdgeCall) (EdgeMutation[ProductUpdateProjection], error)
	ApplyProductUpdate(context.Context, EdgeCall, ProductUpdateApplyPayload) (EdgeMutation[ProductUpdateProjection], error)
}

// ProductUpdateEdgeCapabilities keeps mutation contracts out of the live
// catalog until the concrete runtime has every protected dependency required
// by that stage. In particular, a status-only adapter cannot advertise apply.
type ProductUpdateEdgeCapabilities struct {
	List  bool
	Check bool
	Plan  bool
	Apply bool
}

type ProductUpdateEdgeCapabilityProvider interface {
	ProductUpdateCapabilities() ProductUpdateEdgeCapabilities
}

func registerProductUpdateContracts(registry *Registry) error {
	definitions := []Operation{
		consoleOperation("product_update.status.list", "product_update:observe", identity.AssurancePassword, false, func() any { return &EdgePagePayload{} }, validateEdgePage, edgeInstallationListScope),
		consoleOperation("product_update.check", "product_update:manage", identity.AssuranceMFA, true, func() any { return &ProductUpdateCheckPayload{} }, validateProductUpdateCheck, edgeInstallationCreateScope),
		consoleOperation("product_update.plan", "product_update:manage", identity.AssuranceMFA, true, func() any { return &EmptyPayload{} }, nil, edgeInstallationExistingMutationScope),
		consoleOperation("product_update.apply", "product_update:manage", identity.AssurancePhishingResistant, true, func() any { return &ProductUpdateApplyPayload{} }, validateProductUpdateApply, edgeInstallationExistingMutationScope),
	}
	for _, definition := range definitions {
		if err := register(registry, definition); err != nil { return err }
	}
	return nil
}

func validateProductUpdateCheck(value any) error {
	if !validEdgeID(value.(*ProductUpdateCheckPayload).ManifestID) { return invalid("product update manifest") }
	return nil
}

func validateProductUpdateApply(value any) error {
	payload := value.(*ProductUpdateApplyPayload)
	if payload.ExpectedDurationSeconds == 0 { payload.ExpectedDurationSeconds = 1800 }
	if payload.ExpectedDurationSeconds < 60 || payload.ExpectedDurationSeconds > 86400 { return invalid("product update duration") }
	return nil
}

func bindProductUpdateContracts(registry *Registry, services DomainServices) error {
	if services.ProductUpdates == nil { return nil }
	capabilities := ProductUpdateEdgeCapabilities{List:true, Check:true, Plan:true, Apply:true}
	if provider, ok := services.ProductUpdates.(ProductUpdateEdgeCapabilityProvider); ok { capabilities = provider.ProductUpdateCapabilities() }
	if capabilities.List {
		if err := registry.Bind("product_update.status.list", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ProductUpdates.ListProductUpdates(ctx, edgeCall(inv), *value.(*EdgePagePayload))
			if err != nil { return OperationResult{}, mapDomainError(err) }
			return OperationResult{Status:http.StatusOK, Value:result}, nil
		}); err != nil { return err }
	}
	if capabilities.Check {
		if err := registry.Bind("product_update.check", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ProductUpdates.CheckProductUpdate(ctx, edgeCall(inv), *value.(*ProductUpdateCheckPayload))
			if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
	}
	if capabilities.Plan {
		if err := registry.Bind("product_update.plan", func(ctx context.Context, inv Invocation, _ any) (OperationResult, error) {
			result, err := services.ProductUpdates.PlanProductUpdate(ctx, edgeCall(inv))
			if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
	}
	if capabilities.Apply {
		if err := registry.Bind("product_update.apply", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
			result, err := services.ProductUpdates.ApplyProductUpdate(ctx, edgeCall(inv), *value.(*ProductUpdateApplyPayload))
			if err != nil { return OperationResult{}, mapDomainError(err) }
			return edgeOperationResult(http.StatusAccepted, result), nil
		}); err != nil { return err }
	}
	return nil
}
