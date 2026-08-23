package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/maintenance"
)

type MaintenanceWindowListPayload struct {
	Limit           uint16    `json:"limit,omitempty"`
	Cursor          string    `json:"cursor,omitempty"`
	ProjectionAt    time.Time `json:"projection_at,omitempty"`
	HorizonDays     uint16    `json:"horizon_days,omitempty"`
	OccurrenceLimit uint16    `json:"occurrence_limit,omitempty"`
}

type MaintenanceWindowMutationPayload struct {
	Spec     maintenance.WindowSpec `json:"spec,omitempty"`
	SpecJSON string                 `json:"spec_json,omitempty"`
}

type MaintenanceWindowEdgeService interface {
	ListWindows(context.Context, maintenance.WindowListRequest) (maintenance.WindowProjectionPage, error)
	CreateWindow(context.Context, maintenance.CreateWindowRequest) (maintenance.WindowProjection, error)
	UpdateWindow(context.Context, maintenance.UpdateWindowRequest) (maintenance.WindowProjection, error)
	CancelWindow(context.Context, maintenance.CancelWindowRequest) (maintenance.WindowProjection, error)
}

func registerMaintenanceWindowContracts(registry *Registry) error {
	definitions := []Operation{
		consoleOperation("maintenance_window.list", "operations:observe", identity.AssurancePassword, false, func() any { return &MaintenanceWindowListPayload{} }, validateMaintenanceWindowList, edgeTenantOrInstallationListScope),
		consoleOperation("maintenance_window.create", "operations:manage", identity.AssurancePhishingResistant, true, func() any { return &MaintenanceWindowMutationPayload{} }, validateMaintenanceWindowMutation, edgeTenantOrInstallationCreateScope),
		consoleOperation("maintenance_window.update", "operations:manage", identity.AssurancePhishingResistant, true, func() any { return &MaintenanceWindowMutationPayload{} }, validateMaintenanceWindowMutation, edgeTenantOrInstallationExistingMutationScope),
		consoleOperation("maintenance_window.cancel", "operations:manage", identity.AssurancePhishingResistant, true, func() any { return &EmptyPayload{} }, nil, edgeTenantOrInstallationExistingMutationScope),
	}
	for _, definition := range definitions {
		definition.MaximumBodyBytes = 64 << 10
		if err := register(registry, definition); err != nil {
			return err
		}
	}
	return nil
}

func validateMaintenanceWindowList(value any) error {
	payload := value.(*MaintenanceWindowListPayload)
	if payload.Limit == 0 {
		payload.Limit = 100
	}
	if payload.HorizonDays == 0 {
		payload.HorizonDays = 90
	}
	if payload.OccurrenceLimit == 0 {
		payload.OccurrenceLimit = 16
	}
	if !payload.ProjectionAt.IsZero() {
		payload.ProjectionAt = payload.ProjectionAt.UTC()
	}
	if payload.Limit > 128 || payload.HorizonDays > 366 || payload.OccurrenceLimit > 64 ||
		payload.Cursor != "" && !validEdgeID(payload.Cursor) {
		return invalid("maintenance window projection")
	}
	return nil
}

func validateMaintenanceWindowMutation(value any) error {
	payload := value.(*MaintenanceWindowMutationPayload)
	hasSpec := !reflect.DeepEqual(payload.Spec, maintenance.WindowSpec{})
	payload.SpecJSON = strings.TrimSpace(payload.SpecJSON)
	if hasSpec == (payload.SpecJSON != "") || len(payload.SpecJSON) > 64<<10 {
		return invalid("maintenance window spec")
	}
	if payload.SpecJSON != "" {
		decoder := json.NewDecoder(bytes.NewBufferString(payload.SpecJSON))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&payload.Spec) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return invalid("maintenance window spec")
		}
	}
	canonical, err := maintenance.CanonicalWindowSpec(payload.Spec)
	if err != nil {
		return invalid("maintenance window spec")
	}
	payload.Spec = canonical
	payload.SpecJSON = ""
	return nil
}

func bindMaintenanceWindowContracts(registry *Registry, services DomainServices) error {
	if services.MaintenanceWindows == nil {
		return nil
	}
	if err := registry.Bind("maintenance_window.list", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		payload := value.(*MaintenanceWindowListPayload)
		result, err := services.MaintenanceWindows.ListWindows(ctx, maintenance.WindowListRequest{TenantID: maintenanceWindowTenant(invocation),
			Limit: int(payload.Limit), Cursor: payload.Cursor, At: payload.ProjectionAt,
			Horizon: time.Duration(payload.HorizonDays) * 24 * time.Hour, OccurrenceLimit: int(payload.OccurrenceLimit)})
		if err != nil {
			return OperationResult{}, mapDomainError(err)
		}
		return OperationResult{Status: http.StatusOK, Value: result}, nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("maintenance_window.create", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		result, err := services.MaintenanceWindows.CreateWindow(ctx, maintenance.CreateWindowRequest{TenantID: maintenanceWindowTenant(invocation), CommandID: commandID(invocation), Spec: value.(*MaintenanceWindowMutationPayload).Spec})
		if err != nil {
			return OperationResult{}, mapDomainError(err)
		}
		return edgeOperationResult(http.StatusCreated, maintenanceWindowMutation(commandID(invocation), result)), nil
	}); err != nil {
		return err
	}
	if err := registry.Bind("maintenance_window.update", func(ctx context.Context, invocation Invocation, value any) (OperationResult, error) {
		result, err := services.MaintenanceWindows.UpdateWindow(ctx, maintenance.UpdateWindowRequest{TenantID: maintenanceWindowTenant(invocation), WindowID: invocation.Request.ResourceID,
			ExpectedGeneration: invocation.Request.ExpectedGeneration, Spec: value.(*MaintenanceWindowMutationPayload).Spec})
		if err != nil {
			return OperationResult{}, mapDomainError(err)
		}
		return edgeOperationResult(http.StatusOK, maintenanceWindowMutation(commandID(invocation), result)), nil
	}); err != nil {
		return err
	}
	return registry.Bind("maintenance_window.cancel", func(ctx context.Context, invocation Invocation, _ any) (OperationResult, error) {
		result, err := services.MaintenanceWindows.CancelWindow(ctx, maintenance.CancelWindowRequest{TenantID: maintenanceWindowTenant(invocation), WindowID: invocation.Request.ResourceID,
			ExpectedGeneration: invocation.Request.ExpectedGeneration})
		if err != nil {
			return OperationResult{}, mapDomainError(err)
		}
		return edgeOperationResult(http.StatusOK, maintenanceWindowMutation(commandID(invocation), result)), nil
	})
}

func maintenanceWindowTenant(invocation Invocation) string {
	if invocation.Request.TenantID == "" {
		return maintenance.InstallationTenantID
	}
	return invocation.Request.TenantID
}

func maintenanceWindowMutation(operationID string, resource maintenance.WindowProjection) EdgeMutation[maintenance.WindowProjection] {
	return EdgeMutation[maintenance.WindowProjection]{OperationID: operationID, State: resource.State,
		Generation: resource.Generation, Resource: resource}
}
