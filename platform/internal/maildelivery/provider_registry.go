package maildelivery

import (
	"context"
	"sync"
)

// ProviderRegistryV1 is an exact-version resolver. It never falls back from a
// requested adapter version to another implementation.
type ProviderRegistryV1 struct {
	mutex    sync.RWMutex
	adapters map[ProviderAdapterRef]ProviderAdapterV1
}

func NewProviderRegistryV1(adapters ...ProviderAdapterV1) (*ProviderRegistryV1, error) {
	registry := &ProviderRegistryV1{adapters: make(map[ProviderAdapterRef]ProviderAdapterV1, len(adapters))}
	for _, adapter := range adapters {
		if err := registry.Register(adapter); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func NewCyberMailProviderRegistryV1(options CyberMailAdapterV1Options) (*ProviderRegistryV1, error) {
	adapter, err := NewCyberMailAdapterV1(options)
	if err != nil {
		return nil, err
	}
	return NewProviderRegistryV1(adapter)
}

func (registry *ProviderRegistryV1) Register(adapter ProviderAdapterV1) error {
	if registry == nil || adapter == nil {
		return ErrInvalid
	}
	reference := adapter.Reference()
	if reference.Validate() != nil {
		return ErrInvalid
	}
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	if registry.adapters == nil {
		return ErrInvalid
	}
	if _, exists := registry.adapters[reference]; exists {
		return ErrConflict
	}
	registry.adapters[reference] = adapter
	return nil
}

func (registry *ProviderRegistryV1) ResolveMailDeliveryProvider(ctx context.Context, reference ProviderAdapterRef) (ProviderAdapterV1, error) {
	if registry == nil || ctx == nil || reference.Validate() != nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	registry.mutex.RLock()
	adapter := registry.adapters[reference]
	registry.mutex.RUnlock()
	if adapter == nil || adapter.Reference() != reference {
		return nil, ErrNotFound
	}
	return adapter, nil
}

var _ ProviderResolver = (*ProviderRegistryV1)(nil)
