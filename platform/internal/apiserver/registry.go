package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type OperationHandler func(context.Context, Invocation, any) (OperationResult, error)
type ScopeResolver func(RequestEnvelope, any) (identity.Scope, error)

type Operation struct {
	Name string
	Permission identity.Permission
	Assurance identity.AssuranceLevel
	Auth AuthMode
	SelfService bool
	Mutating bool
	MaximumBodyBytes int64
	MaximumResponseBytes int64
	NewPayload func() any
	ValidatePayload func(any) error
	ResolveScope ScopeResolver
	Handler OperationHandler
}

func (operation Operation) Validate() error {
	if !operationPattern.MatchString(operation.Name) || operation.NewPayload == nil || operation.ResolveScope == nil { return invalid("operation definition") }
	if operation.Auth != AuthNone && operation.Auth != AuthRequired { return invalid("operation auth mode") }
	if operation.Auth == AuthRequired {
		if operation.SelfService { if operation.Permission!="" { return invalid("self-service operation permission") } } else if _, err := identity.NewPermission(string(operation.Permission)); err != nil { return invalid("operation permission") }
		if operation.Assurance < identity.AssurancePassword || operation.Assurance > identity.AssurancePhishingResistant { return invalid("operation assurance") }
	}
	return nil
}

type Registry struct {
	mutex sync.RWMutex
	operations map[string]Operation
}

func NewRegistry() *Registry { return &Registry{operations: make(map[string]Operation)} }

func (registry *Registry) Register(operation Operation) error {
	if registry == nil { return invalid("operation registry") }
	if err := operation.Validate(); err != nil { return err }
	registry.mutex.Lock(); defer registry.mutex.Unlock()
	if _, exists := registry.operations[operation.Name]; exists { return fmt.Errorf("%w: duplicate operation %s", ErrConflict, operation.Name) }
	registry.operations[operation.Name] = operation
	return nil
}

func (registry *Registry) Bind(name string, handler OperationHandler) error {
	if registry == nil || handler == nil { return invalid("operation handler") }
	registry.mutex.Lock(); defer registry.mutex.Unlock()
	operation, exists := registry.operations[name]
	if !exists { return ErrNotFound }
	operation.Handler = handler
	registry.operations[name] = operation
	return nil
}

func (registry *Registry) Lookup(name string) (Operation, bool) {
	if registry == nil { return Operation{}, false }
	registry.mutex.RLock(); defer registry.mutex.RUnlock()
	operation, exists := registry.operations[name]
	return operation, exists
}

func (registry *Registry) Names() []string {
	registry.mutex.RLock(); defer registry.mutex.RUnlock()
	names := make([]string, 0, len(registry.operations))
	for name := range registry.operations { names = append(names, name) }
	sort.Strings(names)
	return names
}

func (registry *Registry) Canonicalize(request RequestEnvelope) (Operation, any, RequestEnvelope, error) {
	if err := request.Validate(); err != nil { return Operation{}, nil, request, err }
	operation, exists := registry.Lookup(request.Operation)
	if !exists { return Operation{}, nil, request, ErrOperationUnavailable }
	canonical, payload, err := canonicalPayload(request.Payload, operation.NewPayload, operation.ValidatePayload)
	if err != nil { return Operation{}, nil, request, err }
	request.Payload = canonical
	if _, err = operation.ResolveScope(request, payload); err != nil { return Operation{}, nil, request, err }
	return operation, payload, request, nil
}

type operationDescription struct {
	Name string `json:"name"`
	Permission identity.Permission `json:"permission,omitempty"`
	Assurance identity.AssuranceLevel `json:"assurance,omitempty"`
	Auth AuthMode `json:"auth"`
	SelfService bool `json:"self_service,omitempty"`
	Mutating bool `json:"mutating"`
	MaximumBodyBytes int64 `json:"maximum_body_bytes"`
	MaximumResponseBytes int64 `json:"maximum_response_bytes"`
}

func (registry *Registry) Describe() []operationDescription {
	return registry.describe(false)
}

func (registry *Registry) DescribeBound() []operationDescription {
	return registry.describe(true)
}

func (registry *Registry) describe(boundOnly bool) []operationDescription {
	names := registry.Names()
	descriptions := make([]operationDescription, 0, len(names))
	for _, name := range names {
		operation, _ := registry.Lookup(name)
		if boundOnly&&operation.Handler==nil{continue}
		descriptions = append(descriptions, operationDescription{Name: name, Permission: operation.Permission, Assurance: operation.Assurance, Auth: operation.Auth, SelfService:operation.SelfService, Mutating: operation.Mutating, MaximumBodyBytes: effectiveBodyLimit(operation), MaximumResponseBytes: effectiveResponseLimit(operation)})
	}
	return descriptions
}

func effectiveBodyLimit(operation Operation) int64 { if operation.MaximumBodyBytes > 0 && operation.MaximumBodyBytes <= AbsoluteMaximumBodyBytes { return operation.MaximumBodyBytes }; return DefaultMaximumBodyBytes }
func effectiveResponseLimit(operation Operation) int64 { if operation.MaximumResponseBytes > 0 && operation.MaximumResponseBytes <= DefaultMaximumResponseBytes { return operation.MaximumResponseBytes }; return DefaultMaximumResponseBytes }

func installationScope(RequestEnvelope, any) (identity.Scope, error) { return identity.Scope{Kind: identity.ScopeInstallation}, nil }
func tenantScope(request RequestEnvelope, _ any) (identity.Scope, error) {
	tenant, err := identity.NewID(request.TenantID); if err != nil { return identity.Scope{}, invalid("tenant_id") }
	return identity.Scope{Kind: identity.ScopeTenant, TenantID: tenant}, nil
}
func siteScope(request RequestEnvelope, _ any) (identity.Scope, error) {
	tenant, err := identity.NewID(request.TenantID); if err != nil { return identity.Scope{}, invalid("tenant_id") }
	resource, err := identity.NewID(request.ResourceID); if err != nil { return identity.Scope{}, invalid("resource_id") }
	return identity.Scope{Kind: identity.ScopeSite, TenantID: tenant, ResourceID: resource}, nil
}

func rawResult(value any) (json.RawMessage, error) { content, err := json.Marshal(value); return json.RawMessage(content), err }

func statusOrDefault(status int, mutating bool) int {
	if status >= 200 && status <= 299 { return status }
	if mutating { return http.StatusOK }
	return http.StatusOK
}
