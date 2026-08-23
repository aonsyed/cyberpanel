package siteops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
)

const registryVersion = 1

type registryState struct {
	Version    int                         `json:"version"`
	NextUID    uint32                      `json:"next_uid"`
	Bindings   map[string]RuntimeBinding   `json:"bindings"`
	Operations map[string]OperationRecord  `json:"operations"`
}

type StateBackend interface {
	Load() ([]byte, bool, error)
	Store([]byte) error
}

// DurableRegistry serializes allocation, fencing, idempotency, and receipt
// commits through one atomically replaced state image. panel-execd is the sole
// writer; the backend additionally uses descriptor-relative no-follow I/O.
type DurableRegistry struct {
	backend StateBackend
	minimum uint32
	maximum uint32
	available func(uint32) (bool, error)
	mu      sync.Mutex
}

func NewDurableRegistry(backend StateBackend, minimum, maximum uint32) (*DurableRegistry, error) {
	return NewDurableRegistryWithUIDAvailability(backend, minimum, maximum, nil)
}

func NewDurableRegistryWithUIDAvailability(backend StateBackend, minimum, maximum uint32, available func(uint32) (bool, error)) (*DurableRegistry, error) {
	if backend == nil || minimum < DefaultUIDMinimum || maximum < minimum || maximum-minimum < 1024 || maximum == ^uint32(0) {
		return nil, errors.New("siteops registry backend and UID range are required")
	}
	registry := &DurableRegistry{backend: backend, minimum: minimum, maximum: maximum, available: available}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	state, err := registry.loadLocked()
	if err != nil { return nil, err }
	if err = registry.validateState(state); err != nil { return nil, err }
	if _, found, err := backend.Load(); err != nil { return nil, err } else if !found {
		if err = registry.storeLocked(state); err != nil { return nil, err }
	}
	return registry, nil
}

func (registry *DurableRegistry) loadLocked() (registryState, error) {
	content, found, err := registry.backend.Load()
	if err != nil { return registryState{}, err }
	if !found {
		return registryState{Version: registryVersion, NextUID: registry.minimum, Bindings: map[string]RuntimeBinding{}, Operations: map[string]OperationRecord{}}, nil
	}
	var state registryState
	if len(content) == 0 || len(content) > 64<<20 { return registryState{}, ErrCorruptRegistry }
	decoder := json.NewDecoder(bytes.NewReader(content)); decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF { return registryState{}, ErrCorruptRegistry }
	if state.Bindings == nil || state.Operations == nil { return registryState{}, ErrCorruptRegistry }
	return state, nil
}

func (registry *DurableRegistry) storeLocked(state registryState) error {
	if err := registry.validateState(state); err != nil { return err }
	content, err := json.Marshal(state); if err != nil { return err }
	return registry.backend.Store(content)
}

func (registry *DurableRegistry) validateState(state registryState) error {
	if state.Version != registryVersion || state.NextUID < registry.minimum || state.NextUID > registry.maximum+1 { return ErrCorruptRegistry }
	uids := make(map[uint32]string, len(state.Bindings)); usernames := make(map[string]string, len(state.Bindings))
	for key, binding := range state.Bindings {
		if key != string(binding.RuntimeKey) || binding.UID < registry.minimum || binding.UID > registry.maximum { return ErrCorruptRegistry }
		if err := binding.Validate(); err != nil { return err }
		if owner, exists := uids[binding.UID]; exists && owner != key { return ErrCorruptRegistry }; uids[binding.UID] = key
		if owner, exists := usernames[binding.Username]; exists && owner != key { return ErrCorruptRegistry }; usernames[binding.Username] = key
	}
	for key, operation := range state.Operations {
		if key != operation.Key || operation.Key == "" || !validRuntimeKey(operation.RuntimeKey) || !operation.Operation.valid() || operation.Generation == 0 || !validDigest(operation.RequestDigest) || operation.Attempt == 0 || operation.StartedAt.IsZero() { return ErrCorruptRegistry }
		if operation.State != OperationRunning && operation.State != OperationComplete && operation.State != OperationFailed { return ErrCorruptRegistry }
		if operation.State == OperationComplete && !validDigest(operation.EvidenceDigest) { return ErrCorruptRegistry }
	}
	return nil
}

func (registry *DurableRegistry) Begin(request Request, now time.Time) (Lease, error) {
	registry.mu.Lock(); defer registry.mu.Unlock()
	state, err := registry.loadLocked(); if err != nil { return Lease{}, err }
	binding, found := state.Bindings[string(request.RuntimeKey)]
	if !found {
		if request.Operation != OperationEnsureIdentity && request.Operation != OperationPurge { return Lease{}, ErrRegistryConflict }
		uid, err := registry.allocateUID(&state); if err != nil { return Lease{}, err }
		binding = RuntimeBinding{
			RuntimeKey: request.RuntimeKey, TenantID: request.TenantID, SiteID: request.SiteID,
			SiteKey: deriveSiteKey(request.TenantID, request.SiteID), Username: deriveUsername(deriveSiteKey(request.TenantID, request.SiteID)),
			UID: uid, GID: uid, Fence: request.Generation, State: BindingAllocated, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
		}
		state.Bindings[string(binding.RuntimeKey)] = binding
	} else {
		if binding.TenantID != request.TenantID || binding.SiteID != request.SiteID || binding.RuntimeKey != request.RuntimeKey || binding.State == BindingDeleted { return Lease{}, ErrRegistryConflict }
		if request.Generation < binding.Fence { return Lease{}, ErrFenced }
		if request.Generation > binding.Fence { binding.Fence, binding.UpdatedAt = request.Generation, now.UTC(); state.Bindings[string(binding.RuntimeKey)] = binding }
	}
	key, requestDigest := request.IdempotencyKey(), request.Digest()
	record, exists := state.Operations[key]
	if exists {
		if record.RequestDigest != requestDigest || record.RuntimeKey != request.RuntimeKey || record.Generation != request.Generation || record.Operation != request.Operation { return Lease{}, ErrRegistryConflict }
		if record.State == OperationComplete { return Lease{Binding: binding, Record: record, Cached: true}, nil }
		record.State, record.ErrorCode, record.StartedAt, record.CompletedAt = OperationRunning, "", now.UTC(), time.Time{}
		record.Attempt++
	} else {
		record = OperationRecord{Key: key, RuntimeKey: request.RuntimeKey, Operation: request.Operation, Generation: request.Generation, RequestDigest: requestDigest, State: OperationRunning, Attempt: 1, StartedAt: now.UTC()}
	}
	state.Operations[key] = record
	if err = registry.storeLocked(state); err != nil { return Lease{}, err }
	return Lease{Binding: binding, Record: record}, nil
}

func (registry *DurableRegistry) allocateUID(state *registryState) (uint32, error) {
	// Numeric identities are never reused. PHP session stores and delayed
	// filesystem artifacts can outlive retention; permanent allocation avoids
	// ever handing those residual objects to a different tenant.
	used := make(map[uint32]struct{}, len(state.Bindings)); for _, binding := range state.Bindings { used[binding.UID] = struct{}{} }
	start := state.NextUID
	for candidate := start; candidate <= registry.maximum; candidate++ { if _, exists := used[candidate]; !exists { available, err := registry.uidAvailable(candidate); if err != nil { return 0, err }; if available { state.NextUID = candidate+1; return candidate, nil } } }
	for candidate := registry.minimum; candidate < start; candidate++ { if _, exists := used[candidate]; !exists { available, err := registry.uidAvailable(candidate); if err != nil { return 0, err }; if available { state.NextUID = candidate+1; return candidate, nil } } }
	return 0, ErrIdentityExhausted
}

func (registry *DurableRegistry) uidAvailable(uid uint32) (bool, error) { if registry.available == nil { return true, nil }; return registry.available(uid) }

func (registry *DurableRegistry) Complete(request Request, binding RuntimeBinding, evidence string, now time.Time) error {
	if !validDigest(evidence) { return ErrCorruptRegistry }
	return registry.finish(request, binding, OperationComplete, evidence, "", now)
}

func (registry *DurableRegistry) Fail(request Request, binding RuntimeBinding, code string, now time.Time) error {
	if code == "" || len(code) > 128 { return ErrCorruptRegistry }
	return registry.finish(request, binding, OperationFailed, "", code, now)
}

func (registry *DurableRegistry) finish(request Request, binding RuntimeBinding, operationState OperationState, evidence, code string, now time.Time) error {
	registry.mu.Lock(); defer registry.mu.Unlock()
	state, err := registry.loadLocked(); if err != nil { return err }
	current, found := state.Bindings[string(request.RuntimeKey)]; if !found || current.Fence != request.Generation || binding.Fence != request.Generation || current.TenantID != binding.TenantID || current.SiteID != binding.SiteID { return ErrFenced }
	record, found := state.Operations[request.IdempotencyKey()]; if !found || record.RequestDigest != request.Digest() || record.State != OperationRunning { return ErrRegistryConflict }
	binding.UpdatedAt = now.UTC(); state.Bindings[string(binding.RuntimeKey)] = binding
	record.State, record.EvidenceDigest, record.ErrorCode, record.CompletedAt = operationState, evidence, code, now.UTC(); state.Operations[record.Key] = record
	return registry.storeLocked(state)
}

func (registry *DurableRegistry) Binding(key provisioning.RuntimeKey) (RuntimeBinding, bool, error) {
	registry.mu.Lock(); defer registry.mu.Unlock(); state, err := registry.loadLocked(); if err != nil { return RuntimeBinding{}, false, err }; binding, found := state.Bindings[string(key)]; return binding, found, nil
}

// BindingForSite resolves the active privileged runtime for access adapters.
// Site identifiers are control-plane unique; duplicate live bindings are
// treated as registry corruption rather than choosing an arbitrary tenant.
func (registry *DurableRegistry) BindingForSite(siteID string) (RuntimeBinding, bool, error) {
	if !validIdentifier(siteID) { return RuntimeBinding{}, false, ErrRegistryConflict }
	registry.mu.Lock(); defer registry.mu.Unlock()
	state, err := registry.loadLocked(); if err != nil { return RuntimeBinding{}, false, err }
	var result RuntimeBinding; found := false
	for _, binding := range state.Bindings {
		if binding.SiteID != siteID || binding.State == BindingDeleted || binding.State == BindingTombstoned { continue }
		if found { return RuntimeBinding{}, false, ErrCorruptRegistry }
		result, found = binding, true
	}
	return result, found, nil
}

func (registry *DurableRegistry) ExpiredTombstones(now time.Time, limit int) ([]RuntimeBinding, error) {
	if limit < 1 || limit > 1000 { return nil, fmt.Errorf("invalid tombstone collection limit") }
	registry.mu.Lock(); defer registry.mu.Unlock(); state, err := registry.loadLocked(); if err != nil { return nil, err }
	values := make([]RuntimeBinding, 0, limit)
	for _, binding := range state.Bindings { if binding.State == BindingTombstoned && !binding.TombstonePurgeAfter.IsZero() && !binding.TombstonePurgeAfter.After(now) { values = append(values, binding) } }
	sort.Slice(values, func(left, right int) bool { if values[left].TombstonePurgeAfter.Equal(values[right].TombstonePurgeAfter) { return values[left].RuntimeKey < values[right].RuntimeKey }; return values[left].TombstonePurgeAfter.Before(values[right].TombstonePurgeAfter) })
	if len(values) > limit { values = values[:limit] }
	return values, nil
}

func (registry *DurableRegistry) DeleteBinding(key provisioning.RuntimeKey, fence uint64, now time.Time) error {
	registry.mu.Lock(); defer registry.mu.Unlock(); state, err := registry.loadLocked(); if err != nil { return err }
	binding, found := state.Bindings[string(key)]; if !found { return nil }; if binding.Fence != fence || binding.State != BindingTombstoned { return ErrFenced }
	binding.State, binding.UpdatedAt = BindingDeleted, now.UTC(); state.Bindings[string(key)] = binding
	return registry.storeLocked(state)
}
