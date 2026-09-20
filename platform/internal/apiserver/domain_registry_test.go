package apiserver

import (
	"context"
	"errors"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type registryIdentityEdge struct{ IdentityEdgeService }

func TestConsoleBindingPreservesManagedTenantHandlers(t *testing.T) {
	registry, err := NewDomainRegistry()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"identity.tenant.list", "identity.tenant.create", "identity.tenant.suspend"}
	for _, name := range names {
		if err := registry.Bind(name, func(context.Context, Invocation, any) (OperationResult, error) {
			return OperationResult{Value: "managed-tenant-handler"}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := bindConsoleEdgeContracts(registry, DomainServices{IdentityEdge: registryIdentityEdge{}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		operation, _ := registry.Lookup(name)
		result, err := operation.Handler(context.Background(), Invocation{}, operation.NewPayload())
		if err != nil || result.Value != "managed-tenant-handler" {
			t.Fatalf("console replaced %s handler: %v", name, err)
		}
	}
}

func TestDomainRegistryHasSingleTenantContract(t *testing.T) {
	registry, err := NewDomainRegistry()
	if err != nil {
		t.Fatal(err)
	}
	create, ok := registry.Lookup("identity.tenant.create")
	if !ok || create.Permission != "tenant:create" || create.Assurance != identity.AssuranceMFA || !create.Mutating {
		t.Fatal("tenant creation lost its permission or MFA requirement")
	}
	if _, ok := create.NewPayload().(*TenantCreatePayload); !ok {
		t.Fatal("tenant creation must use the managed ownership/delegation payload")
	}
	if err := create.ValidatePayload(&TenantCreatePayload{Kind: identity.TenantCustomer, Name: "customer"}); err == nil {
		t.Fatal("tenant creation accepted missing manager and ownership contacts")
	}
	list, ok := registry.Lookup("identity.tenant.list")
	if !ok {
		t.Fatal("tenant list absent")
	}
	if _, ok := list.NewPayload().(*TenantPagePayload); !ok {
		t.Fatal("tenant listing lost managed pagination/search payload")
	}
	if err := registry.Register(create); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate detection weakened: %v", err)
	}
}
