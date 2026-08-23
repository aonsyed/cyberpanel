package themes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

type Manager struct {
	store    *Store
	verifier *Verifier
}

func NewManager(store *Store, verifier *Verifier) (*Manager, error) {
	if store == nil || store.root == nil || verifier == nil {
		return nil, ErrInvalid
	}
	return &Manager{store: store, verifier: verifier}, nil
}

func (manager *Manager) Install(ctx context.Context, candidate Package, expectedInventoryGeneration uint64) (Receipt, error) {
	if manager == nil || manager.store == nil || manager.verifier == nil || ctx == nil {
		return Receipt{}, ErrInvalid
	}
	verified, err := manager.verifier.VerifyPackage(ctx, candidate)
	if err != nil {
		return Receipt{}, err
	}
	return manager.store.install(ctx, verified, expectedInventoryGeneration)
}

func (manager *Manager) List(ctx context.Context, limit int, cursor string) (Inventory, error) {
	if manager == nil || manager.store == nil || ctx == nil {
		return Inventory{}, ErrInvalid
	}
	return manager.store.list(ctx, limit, cursor)
}

func (manager *Manager) Inspect(ctx context.Context, themeID, version string) (Inspection, error) {
	if manager == nil || manager.store == nil || manager.verifier == nil || ctx == nil {
		return Inspection{}, ErrInvalid
	}
	inspection, err := manager.store.inspect(ctx, themeID, version)
	if err != nil {
		return Inspection{}, err
	}
	verified, err := manager.verifier.VerifyManifest(ctx, inspection.Theme.Manifest)
	if err != nil || verified.Digest != inspection.Theme.Reference.Digest {
		return Inspection{}, errors.Join(ErrIntegrity, err)
	}
	inspection.Theme.Manifest = verified
	return inspection, nil
}

func (manager *Manager) PreviewReference(ctx context.Context, scope Scope, themeID, version string) (Preview, error) {
	if scope.Validate() != nil {
		return Preview{}, ErrInvalid
	}
	inspection, err := manager.Inspect(ctx, themeID, version)
	if err != nil {
		return Preview{}, err
	}
	return Preview{Scope: scope, Reference: inspection.Theme.Reference, Tokens: inspection.Theme.Manifest.Tokens, Probe: inspection.Probe}, nil
}

func (manager *Manager) Activate(ctx context.Context, scope Scope, reference ThemeReference, expectedScopeGeneration uint64) (Receipt, error) {
	if scope.Validate() != nil || reference.Validate() != nil {
		return Receipt{}, ErrInvalid
	}
	inspection, err := manager.Inspect(ctx, reference.ThemeID, reference.Version)
	if err != nil {
		return Receipt{}, err
	}
	if !sameReference(inspection.Theme.Reference, reference) {
		return Receipt{}, ErrConflict
	}
	return manager.store.activate(ctx, scope, reference, expectedScopeGeneration)
}

func (manager *Manager) Rollback(ctx context.Context, scope Scope, expectedScopeGeneration uint64) (Receipt, error) {
	if manager == nil || manager.store == nil || ctx == nil || scope.Validate() != nil {
		return Receipt{}, ErrInvalid
	}
	state, err := manager.store.snapshot(ctx)
	if err != nil {
		return Receipt{}, err
	}
	index, found := findScope(state.Scopes, scope)
	if !found || state.Scopes[index].Generation != expectedScopeGeneration {
		return Receipt{}, ErrConflict
	}
	activation := state.Scopes[index]
	target := activation.B
	if activation.Active == SlotB {
		target = activation.A
	}
	if target == nil {
		return Receipt{}, ErrNotFound
	}
	inspection, err := manager.Inspect(ctx, target.ThemeID, target.Version)
	if err != nil {
		return Receipt{}, err
	}
	if !sameReference(inspection.Theme.Reference, *target) {
		return Receipt{}, ErrIntegrity
	}
	return manager.store.rollback(ctx, scope, expectedScopeGeneration)
}

func (manager *Manager) Delete(ctx context.Context, themeID, version string, expectedInventoryGeneration uint64) (Receipt, error) {
	if manager == nil || manager.store == nil || ctx == nil {
		return Receipt{}, ErrInvalid
	}
	return manager.store.delete(ctx, themeID, version, expectedInventoryGeneration)
}

// Resolve walks only the caller-supplied, structurally valid authority chain.
// A tenant or reseller activation therefore cannot affect siblings or parents.
func (manager *Manager) Resolve(ctx context.Context, hierarchy ResolutionPath, base BuiltInTheme) (ResolvedBranding, error) {
	if manager == nil || manager.store == nil || manager.verifier == nil || ctx == nil || !base.Valid() {
		return ResolvedBranding{}, ErrInvalid
	}
	scopes, err := hierarchy.Scopes()
	if err != nil {
		return ResolvedBranding{}, err
	}
	state, err := manager.store.snapshot(ctx)
	if err != nil {
		return ResolvedBranding{}, err
	}
	resolved := ResolvedBranding{BaseTheme: base, Fallback: true}
	for index := len(scopes) - 1; index >= 0; index-- {
		stateIndex, found := findScope(state.Scopes, scopes[index])
		if !found {
			continue
		}
		reference := state.Scopes[stateIndex].ActiveReference()
		if reference == nil {
			resolved.Degraded = true
			resolved.Probes = append(resolved.Probes, failedProbe("activation_reference", state.Digest, manager.store.clock()))
			continue
		}
		inspection, inspectErr := manager.Inspect(ctx, reference.ThemeID, reference.Version)
		if inspectErr != nil || !sameReference(inspection.Theme.Reference, *reference) {
			resolved.Degraded = true
			resolved.Probes = append(resolved.Probes, failedProbe("package_integrity", reference.Digest, manager.store.clock()))
			continue
		}
		scope := scopes[index]
		tokens := inspection.Theme.Manifest.Tokens
		resolved.Scope = &scope
		resolved.Reference = cloneReference(reference)
		resolved.Tokens = &tokens
		resolved.Fallback = false
		resolved.Probes = append(resolved.Probes, inspection.Probe)
		return resolved, nil
	}
	now := manager.store.clock().UTC()
	sum := sha256.Sum256([]byte("builtin-theme\x00" + string(base)))
	resolved.Probes = append(resolved.Probes, Probe{Name: "builtin_fallback", Passed: true, Digest: hex.EncodeToString(sum[:]), ObservedAt: now})
	return resolved, nil
}

func failedProbe(name, digest string, now time.Time) Probe {
	if !validDigest(digest) {
		sum := sha256.Sum256([]byte(digest))
		digest = hex.EncodeToString(sum[:])
	}
	return Probe{Name: name, Passed: false, Digest: digest, ObservedAt: now.UTC()}
}
