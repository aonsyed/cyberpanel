//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
)

type integrationEdgeProfile struct {
	Kind     integrations.ProviderKind
	Purpose  integrations.CredentialPurpose
	Endpoint integrations.EndpointPolicy
}

type integrationEdge struct {
	store    integrations.Store
	bindings *integrations.BindingService
	profiles map[string]integrationEdgeProfile
}

func newIntegrationEdge(store integrations.Store, bindings *integrations.BindingService, profiles map[string]integrationEdgeProfile) (apiserver.IntegrationEdgeService, error) {
	if store == nil || bindings == nil || bindings.Store == nil || bindings.Secrets == nil || len(bindings.Providers) == 0 || len(profiles) == 0 {
		return nil, errors.New("integration edge requires concrete provider adapters")
	}
	copyProfiles := make(map[string]integrationEdgeProfile, len(profiles))
	for name, profile := range profiles {
		name = strings.TrimSpace(name)
		if name == "" || !profile.Kind.Valid() || bindings.Providers[profile.Kind] == nil || profile.Endpoint.Validate() != nil {
			return nil, errors.New("integration edge provider profile is invalid")
		}
		copyProfiles[name] = profile
	}
	return &integrationEdge{store:store, bindings:bindings, profiles:copyProfiles}, nil
}

func (edge *integrationEdge) ListBindings(ctx context.Context, call apiserver.EdgeCall, page apiserver.EdgePagePayload) (apiserver.EdgePage[apiserver.IntegrationProjection], error) {
	if edge == nil || edge.store == nil || ctx == nil || call.TenantID == "" {
		return apiserver.EdgePage[apiserver.IntegrationProjection]{}, integrations.ErrInvalid
	}
	limit := page.Limit
	if limit == 0 {
		limit = 100
	}
	bindings, next, err := edge.store.ListBindings(ctx, integrations.TenantID(call.TenantID), "", limit, page.Cursor)
	if err != nil {
		return apiserver.EdgePage[apiserver.IntegrationProjection]{}, err
	}
	items := make([]apiserver.IntegrationProjection, 0, len(bindings))
	for _, binding := range bindings {
		if binding.TenantID != integrations.TenantID(call.TenantID) {
			return apiserver.EdgePage[apiserver.IntegrationProjection]{}, integrations.ErrIntegrity
		}
		items = append(items, edge.projection(ctx, binding, nil))
	}
	return apiserver.EdgePage[apiserver.IntegrationProjection]{Items:items, NextCursor:next}, nil
}

func (edge *integrationEdge) CreateBinding(ctx context.Context, call apiserver.EdgeCall, payload apiserver.IntegrationCreatePayload, secret []byte) (apiserver.EdgeMutation[apiserver.IntegrationProjection], error) {
	if edge == nil || edge.bindings == nil || ctx == nil || call.CommandID == "" || call.TenantID == "" || len(secret) == 0 {
		wipeIntegrationEdgeSecret(secret)
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, integrations.ErrInvalid
	}
	profile, ok := edge.profiles[payload.Provider]
	if !ok || edge.bindings.Providers[profile.Kind] == nil {
		wipeIntegrationEdgeSecret(secret)
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, integrations.ErrUnsupported
	}
	id := integrations.BindingID(integrationEdgeID(call.TenantID, call.CommandID))
	binding, err := edge.bindings.Enroll(ctx, integrations.BindingRequest{ID:id, TenantID:integrations.TenantID(call.TenantID), Kind:profile.Kind, DisplayName:payload.Name, Purpose:profile.Purpose, Endpoint:profile.Endpoint, Secret:secret})
	if err != nil {
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, err
	}
	projection := edge.projection(ctx, binding, nil)
	return apiserver.EdgeMutation[apiserver.IntegrationProjection]{OperationID:call.CommandID, State:string(binding.State), Generation:binding.Generation, Resource:projection}, nil
}

func (edge *integrationEdge) RotateBinding(ctx context.Context, call apiserver.EdgeCall, _ apiserver.IntegrationRotatePayload, secret []byte) (apiserver.EdgeMutation[apiserver.IntegrationProjection], error) {
	binding, err := edge.scopedBinding(ctx, call)
	if err != nil {
		wipeIntegrationEdgeSecret(secret)
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, err
	}
	if len(secret) == 0 || call.ExpectedGeneration == 0 || binding.Generation != call.ExpectedGeneration {
		wipeIntegrationEdgeSecret(secret)
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, integrations.ErrStaleGeneration
	}
	binding, err = edge.bindings.Rotate(ctx, binding.ID, binding.Generation, binding.SecretVersion, secret)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, err
	}
	projection := edge.projection(ctx, binding, nil)
	return apiserver.EdgeMutation[apiserver.IntegrationProjection]{OperationID:call.CommandID, State:string(binding.State), Generation:binding.Generation, Resource:projection}, nil
}

func (edge *integrationEdge) CheckBinding(ctx context.Context, call apiserver.EdgeCall, _ apiserver.IntegrationHealthPayload) (apiserver.EdgeMutation[apiserver.IntegrationProjection], error) {
	binding, err := edge.scopedBinding(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, err
	}
	if call.ExpectedGeneration != 0 && binding.Generation != call.ExpectedGeneration {
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, integrations.ErrStaleGeneration
	}
	health, err := edge.bindings.ObserveHealth(ctx, binding.ID)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, err
	}
	projection := edge.projection(ctx, binding, &health)
	return apiserver.EdgeMutation[apiserver.IntegrationProjection]{OperationID:call.CommandID, State:string(health.State), Generation:binding.Generation, Resource:projection}, nil
}

func (edge *integrationEdge) DeleteBinding(ctx context.Context, call apiserver.EdgeCall) (apiserver.EdgeMutation[apiserver.IntegrationProjection], error) {
	binding, err := edge.scopedBinding(ctx, call)
	if err != nil {
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, err
	}
	if call.ExpectedGeneration == 0 || binding.Generation != call.ExpectedGeneration {
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, integrations.ErrStaleGeneration
	}
	if err = edge.bindings.Delete(ctx, binding.ID, binding.Generation); err != nil {
		return apiserver.EdgeMutation[apiserver.IntegrationProjection]{}, err
	}
	binding.State = integrations.BindingDeleted
	binding.Generation++
	projection := edge.projection(ctx, binding, nil)
	return apiserver.EdgeMutation[apiserver.IntegrationProjection]{OperationID:call.CommandID, State:string(binding.State), Generation:binding.Generation, Resource:projection}, nil
}

func (edge *integrationEdge) scopedBinding(ctx context.Context, call apiserver.EdgeCall) (integrations.ProviderBinding, error) {
	if edge == nil || edge.store == nil || ctx == nil || call.TenantID == "" || call.ResourceID == "" {
		return integrations.ProviderBinding{}, integrations.ErrInvalid
	}
	binding, err := edge.store.LoadBinding(ctx, integrations.BindingID(call.ResourceID))
	if err != nil {
		return integrations.ProviderBinding{}, err
	}
	if binding.TenantID != integrations.TenantID(call.TenantID) {
		return integrations.ProviderBinding{}, integrations.ErrNotFound
	}
	return binding, nil
}

func (edge *integrationEdge) projection(ctx context.Context, binding integrations.ProviderBinding, observed *integrations.ProviderHealth) apiserver.IntegrationProjection {
	health := "unknown"
	if observed != nil {
		health = string(observed.State)
	} else if value, err := edge.store.LoadHealth(ctx, binding.ID); err == nil && value.CapabilitiesDigest == binding.Capabilities.Digest {
		health = string(value.State)
	}
	provider := string(binding.Kind)
	for name, profile := range edge.profiles {
		if profile.Kind == binding.Kind {
			provider = name
			break
		}
	}
	return apiserver.IntegrationProjection{ID:string(binding.ID), TenantID:string(binding.TenantID), Provider:provider, Name:binding.DisplayName, State:string(binding.State), Health:health, Generation:binding.Generation, UpdatedAt:binding.UpdatedAt}
}

func integrationEdgeID(tenant, command string) string {
	sum := sha256.Sum256([]byte("cyberpanel-integration-binding-v1\x00" + tenant + "\x00" + command))
	return "integration_" + hex.EncodeToString(sum[:])[:48]
}

func wipeIntegrationEdgeSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ apiserver.IntegrationEdgeService = (*integrationEdge)(nil)
