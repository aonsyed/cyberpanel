package composer

import (
	"context"
	"reflect"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

func TestComposeActiveSitesSharesNodeListenersAndProducesRendererReadyTenantState(t *testing.T) {
	plan := composePlan(t, webengine.EditionOpenLiteSpeed, activeSite(t, "acme", "shop", "shop.example.test"), activeSite(t, "globex", "docs", "docs.example.test"))
	result, err := Compose(plan)
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	if findings := webengine.Validate(result.Desired); len(findings) != 0 {
		t.Fatalf("Compose() produced invalid desired state: %#v", findings)
	}
	if got, want := len(result.Desired.Engine.Listeners), 2; got != want {
		t.Fatalf("listeners = %d, want %d", got, want)
	}
	if got, want := len(result.Desired.Applications), 3; got != want { // tenant applications plus system default
		t.Fatalf("applications = %d, want %d", got, want)
	}
	if got, want := len(result.Snapshot.Sites), 3; got != want {
		t.Fatalf("site runtimes = %d, want %d", got, want)
	}
	assertUniqueTenantRefs(t, result)
	for _, renderer := range []native.Renderer{ols.New(), enterprise.New()} {
		request := native.RenderRequest{Desired: result.Desired, Snapshot: result.Snapshot}
		if renderer.Edition() != request.Desired.Engine.Edition {
			request.Desired.Engine.Edition = renderer.Edition()
			if renderer.Edition() == webengine.EditionLiteSpeedEnterprise {
				request.Desired.Engine.EnterpriseLicense = &webengine.EnterpriseLicenseExpectation{ExpectedState: webengine.LicenseTrial}
			}
		}
		if _, err := renderer.Render(context.Background(), request); err != nil {
			t.Fatalf("%s renderer rejected composed state: %v", renderer.Edition(), err)
		}
	}
}

func TestComposeIsDeterministicForReorderedInputsAndDoesNotMutatePlan(t *testing.T) {
	first := activeSite(t, "acme", "shop", "shop.example.test")
	second := activeSite(t, "globex", "docs", "docs.example.test")
	first.Projection.Bindings = append(first.Projection.Bindings, domain(t, "www.shop.example.test", site.BindingAlias))
	plan := composePlan(t, webengine.EditionOpenLiteSpeed, first, second)
	for index := range plan.Engine.Listeners {
		plan.Engine.Listeners[index].Addresses = []string{"127.0.0.1", "::1"}
		plan.Engine.Listeners[index].Protocols = []webengine.Protocol{webengine.ProtocolHTTP1, webengine.ProtocolHTTP2}
	}
	original := clonePlan(plan)

	forward, err := Compose(plan)
	if err != nil {
		t.Fatalf("Compose(forward) error = %v", err)
	}
	if !reflect.DeepEqual(plan, original) {
		t.Fatal("Compose() mutated its plan input")
	}
	plan.Sites[0], plan.Sites[1] = plan.Sites[1], plan.Sites[0]
	for index := range plan.Sites {
		if len(plan.Sites[index].Projection.Bindings) > 1 {
			plan.Sites[index].Projection.Bindings[0], plan.Sites[index].Projection.Bindings[1] = plan.Sites[index].Projection.Bindings[1], plan.Sites[index].Projection.Bindings[0]
			break
		}
	}
	for index := range plan.Engine.Listeners {
		plan.Engine.Listeners[index].Addresses[0], plan.Engine.Listeners[index].Addresses[1] = plan.Engine.Listeners[index].Addresses[1], plan.Engine.Listeners[index].Addresses[0]
		plan.Engine.Listeners[index].Protocols[0], plan.Engine.Listeners[index].Protocols[1] = plan.Engine.Listeners[index].Protocols[1], plan.Engine.Listeners[index].Protocols[0]
	}
	reversed, err := Compose(plan)
	if err != nil {
		t.Fatalf("Compose(reversed) error = %v", err)
	}
	if forward.Digest != reversed.Digest || !reflect.DeepEqual(forward, reversed) {
		t.Fatalf("composition changed when inputs were reordered\nforward=%#v\nreversed=%#v", forward, reversed)
	}
}

func TestComposeMapsLifecycleAndOmitsTerminalOrWithdrawnSites(t *testing.T) {
	inputs := []SiteInput{
		siteWithLifecycle(t, "active", site.LifecycleActive, false),
		siteWithLifecycle(t, "suspended", site.LifecycleSuspended, false),
		siteWithLifecycle(t, "provisioning", site.LifecycleProvisioning, false),
		siteWithLifecycle(t, "degraded", site.LifecycleDegraded, false),
		siteWithLifecycle(t, "deleting", site.LifecycleDeleting, false),
		siteWithLifecycle(t, "quarantined", site.LifecycleQuarantined, false),
		siteWithLifecycle(t, "purging", site.LifecyclePurging, false),
		siteWithLifecycle(t, "deleted", site.LifecycleDeleted, false),
		siteWithLifecycle(t, "withdrawn", site.LifecycleActive, true),
	}
	result, err := Compose(composePlan(t, webengine.EditionOpenLiteSpeed, inputs...))
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	want := map[string]webengine.RoutingState{"active": webengine.RoutingServe, "suspended": webengine.RoutingSuspended, "provisioning": webengine.RoutingMaintenance, "degraded": webengine.RoutingMaintenance, "deleting": webengine.RoutingMaintenance, "quarantined": webengine.RoutingMaintenance}
	got := map[string]webengine.RoutingState{}
	for _, binding := range result.Desired.Bindings {
		for _, hostname := range binding.Hostnames {
			got[hostname.String()] = binding.RoutingState
		}
	}
	for name, routing := range want {
		if got[name+".example.test"] != routing {
			t.Errorf("%s routing = %q, want %q", name, got[name+".example.test"], routing)
		}
	}
	for _, omitted := range []string{"purging", "deleted", "withdrawn"} {
		if _, exists := got[omitted+".example.test"]; exists {
			t.Errorf("%s was composed but must be omitted", omitted)
		}
	}
}

func TestComposeMapsChildAliasPreviewAndRedirectRelationships(t *testing.T) {
	input := activeSite(t, "acme", "store", "store.example.test")
	input.Projection.Bindings = append(input.Projection.Bindings,
		domain(t, "child.store.example.test", site.BindingChild),
		domain(t, "alias.store.example.test", site.BindingAlias),
		domain(t, "preview.store.example.test", site.BindingPreview),
		site.DomainBinding{Hostname: siteHostname(t, "old.store.example.test"), Kind: site.BindingRedirect, RedirectTarget: siteHostname(t, "store.example.test"), RedirectStatus: site.RedirectStatusPermanent301},
	)
	result, err := Compose(composePlan(t, webengine.EditionOpenLiteSpeed, input))
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	got := bindingsByHostname(result.Desired)
	for _, hostname := range []string{"store.example.test", "child.store.example.test", "alias.store.example.test"} {
		if got[hostname].Relationship != webengine.BindingPrimary && got[hostname].Relationship != webengine.BindingAlias {
			t.Errorf("%s relationship = %q", hostname, got[hostname].Relationship)
		}
	}
	if got["preview.store.example.test"].Relationship != webengine.BindingPreview {
		t.Errorf("preview relationship = %q, want preview", got["preview.store.example.test"].Relationship)
	}
	redirect := got["old.store.example.test"]
	if redirect.Relationship != webengine.BindingRedirect || redirect.RedirectTarget.String() != "store.example.test" || redirect.RedirectStatus != webengine.RedirectStatusPermanent301 {
		t.Errorf("redirect = %#v, want redirect to store.example.test with 301", redirect)
	}

	unknown := activeSite(t, "acme", "unknown", "unknown.example.test")
	unknown.Projection.Bindings[0].Kind = site.BindingKind("future_relationship")
	if _, err := Compose(composePlan(t, webengine.EditionOpenLiteSpeed, unknown)); err == nil {
		t.Fatal("Compose() accepted an unknown site binding kind")
	}
}

func TestComposeUsesSystemDefaultAndRequiresOwnedTLSMaterial(t *testing.T) {
	plain := composePlan(t, webengine.EditionOpenLiteSpeed, activeSite(t, "acme", "shop", "shop.example.test"))
	plain.DefaultTLS = nil
	plain.Engine.Listeners = []ListenerInput{{Ref: "listener/http", Addresses: []string{"127.0.0.1"}, Port: 80, TLSMode: webengine.TLSModeClear, Protocols: []webengine.Protocol{webengine.ProtocolHTTP1}}}
	plainResult, err := Compose(plain)
	if err != nil {
		t.Fatalf("Compose(clear) error = %v", err)
	}
	listener := plainResult.Desired.Engine.Listeners[0]
	defaultBinding := bindingByRef(plainResult.Desired, listener.DefaultBindingRef)
	if defaultBinding.ApplicationRef == plainResult.Desired.Applications[1].Ref || defaultBinding.ApplicationRef == plainResult.Desired.Applications[0].Ref && defaultBinding.ApplicationRef != "application/system-default" {
		t.Fatalf("unknown-host default binding falls through to a tenant: %#v", defaultBinding)
	}

	missingDefault := composePlan(t, webengine.EditionOpenLiteSpeed, activeSite(t, "acme", "shop", "shop.example.test"))
	missingDefault.DefaultTLS = nil
	if _, err := Compose(missingDefault); err == nil {
		t.Fatal("Compose(TLS listener without system DefaultTLS) succeeded")
	}

	missingTenant := composePlan(t, webengine.EditionOpenLiteSpeed, activeSite(t, "acme", "shop", "shop.example.test"))
	missingTenant.Sites[0].TLS = nil
	if _, err := Compose(missingTenant); err == nil {
		t.Fatal("Compose(TLS tenant binding without owned TLS material) succeeded")
	}

	owned := composePlan(t, webengine.EditionOpenLiteSpeed, activeSite(t, "acme", "shop", "shop.example.test"))
	const ownedPolicy = webengine.ResourceRef("tls/acme-shop-owned")
	owned.Sites[0].TLS[0].PolicyRef = ownedPolicy
	ownedResult, err := Compose(owned)
	if err != nil {
		t.Fatalf("Compose(owned TLS) error = %v", err)
	}
	tenantBinding := bindingsByHostname(ownedResult.Desired)["shop.example.test"]
	if tenantBinding.TLSPolicyRef != ownedPolicy {
		t.Fatalf("tenant binding TLS policy = %q, want exact input %q", tenantBinding.TLSPolicyRef, ownedPolicy)
	}
	tenantApplication := applicationByRef(ownedResult.Desired, tenantBinding.ApplicationRef)
	material, found := materialByPolicy(ownedResult.Snapshot, ownedPolicy)
	if !found || material.SiteRef != tenantApplication.SiteRef || material.IdentityRef != tenantApplication.IdentityRef {
		t.Fatalf("TLS material is not owned by its tenant application: material=%#v application=%#v", material, tenantApplication)
	}

	additional := clonePlan(owned)
	additional.Sites[0].TLS = append(additional.Sites[0].TLS, TLSInput{PolicyRef: "tls/unsupported-extra", MaterialKey: "unsupported-extra", Generation: 1})
	if _, err := Compose(additional); err == nil {
		t.Fatal("Compose() accepted more than one TLS mapping for a site")
	}

	duplicate := composePlan(t, webengine.EditionOpenLiteSpeed,
		activeSite(t, "acme", "shop", "shop.example.test"),
		activeSite(t, "globex", "docs", "docs.example.test"),
	)
	duplicate.Sites[1].TLS[0].PolicyRef = duplicate.Sites[0].TLS[0].PolicyRef
	if _, err := Compose(duplicate); err == nil {
		t.Fatal("Compose() accepted one TLS policy for two tenant sites")
	}

	crossSite := clonePlan(owned)
	crossSite.Sites[0].TLS[0].PolicyRef = crossSite.DefaultTLS.PolicyRef
	if _, err := Compose(crossSite); err == nil {
		t.Fatal("Compose() accepted the system TLS policy as tenant-owned material")
	}

	foreignOwner := clonePlan(owned)
	foreignTenant, _ := site.NewTenantID("foreign")
	foreignSite, _ := site.NewSiteID("foreign-site")
	foreignOwner.Sites[0].TLS[0].OwnerScope = service.CommandScope{TenantID: foreignTenant, SiteID: foreignSite}
	foreignOwner.Sites[0].TLS[0].PolicyRef = "tls/unique-but-foreign"
	if _, err := Compose(foreignOwner); err == nil {
		t.Fatal("Compose() accepted TLS material owned by another tenant site")
	}

	unsafe := clonePlan(owned)
	unsafe.Sites[0].TLS[0].PolicyRef = "tls/../../outside"
	if _, err := Compose(unsafe); err == nil {
		t.Fatal("Compose() accepted an unsafe tenant TLS policy reference")
	}
}

func composePlan(t *testing.T, edition webengine.Edition, sites ...SiteInput) Plan {
	t.Helper()
	return Plan{Engine: NodeEngine{Edition: edition, Listeners: []ListenerInput{{Ref: "listener/http", Addresses: []string{"127.0.0.1"}, Port: 80, TLSMode: webengine.TLSModeClear, Protocols: []webengine.Protocol{webengine.ProtocolHTTP1}}, {Ref: "listener/https", Addresses: []string{"127.0.0.1"}, Port: 443, TLSMode: webengine.TLSModeTLS, Protocols: []webengine.Protocol{webengine.ProtocolHTTP1, webengine.ProtocolHTTP2}}}}, SnapshotGeneration: 44, Sites: sites, DefaultTLS: &TLSInput{PolicyRef: "tls/system-default", MaterialKey: "system-default", Generation: 1}}
}

func activeSite(t *testing.T, tenant, name, hostname string) SiteInput {
	return siteInput(t, tenant, name, hostname, site.LifecycleActive, false)
}
func siteWithLifecycle(t *testing.T, name string, lifecycle site.Lifecycle, withdraw bool) SiteInput {
	return siteInput(t, "tenant", name, name+".example.test", lifecycle, withdraw)
}
func siteInput(t *testing.T, tenant, name, hostname string, lifecycle site.Lifecycle, withdraw bool) SiteInput {
	t.Helper()
	tenantID, _ := site.NewTenantID(tenant)
	siteID, _ := site.NewSiteID(name)
	scope := service.CommandScope{TenantID: tenantID, SiteID: siteID}
	return SiteInput{Scope: scope, Projection: service.SiteProjection{Generation: 9, Lifecycle: lifecycle, Bindings: []site.DomainBinding{domain(t, hostname, site.BindingPrimary)}}, Withdraw: withdraw, ApplicationRoot: "releases/current", DocumentRoot: "releases/current/public", PHPProfileRef: "php/8.4", ResourceProfileRef: "resource/default", LogPolicyRef: "logs/default", RootGeneration: 3, PoolGeneration: 5, MaxConnections: 12, TLS: []TLSInput{{OwnerScope: scope, PolicyRef: webengine.ResourceRef("tls/" + name), MaterialKey: native.MaterialKey("material-" + name), Generation: 7}}}
}
func domain(t *testing.T, raw string, kind site.BindingKind) site.DomainBinding {
	return site.DomainBinding{Hostname: siteHostname(t, raw), Kind: kind}
}
func siteHostname(t *testing.T, raw string) site.Hostname {
	t.Helper()
	value, err := site.ParseHostname(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func bindingsByHostname(state webengine.DesiredState) map[string]webengine.WebBindingSpec {
	result := map[string]webengine.WebBindingSpec{}
	for _, binding := range state.Bindings {
		for _, hostname := range binding.Hostnames {
			result[hostname.String()] = binding
		}
	}
	return result
}
func bindingByRef(state webengine.DesiredState, ref webengine.ResourceRef) webengine.WebBindingSpec {
	for _, binding := range state.Bindings {
		if binding.Ref == ref {
			return binding
		}
	}
	return webengine.WebBindingSpec{}
}
func applicationByRef(state webengine.DesiredState, ref webengine.ResourceRef) webengine.WebApplicationSpec {
	for _, application := range state.Applications {
		if application.Ref == ref {
			return application
		}
	}
	return webengine.WebApplicationSpec{}
}
func materialByPolicy(snapshot native.RuntimeSnapshot, ref webengine.ResourceRef) (native.TLSMaterial, bool) {
	for _, material := range snapshot.TLSMaterials {
		if material.PolicyRef == ref {
			return material, true
		}
	}
	return native.TLSMaterial{}, false
}
func assertUniqueTenantRefs(t *testing.T, result Result) {
	t.Helper()
	seen := map[webengine.ResourceRef]bool{}
	for _, application := range result.Desired.Applications {
		if seen[application.Ref] {
			t.Fatalf("duplicate application ref %q", application.Ref)
		}
		seen[application.Ref] = true
	}
	for _, runtime := range result.Snapshot.Sites {
		if runtime.SiteRef == "" || runtime.IdentityRef == "" {
			t.Fatalf("incomplete site runtime %#v", runtime)
		}
	}
}
func clonePlan(plan Plan) Plan {
	copy := plan
	copy.Engine = plan.Engine
	copy.Engine.Listeners = make([]ListenerInput, len(plan.Engine.Listeners))
	for index, listener := range plan.Engine.Listeners {
		copy.Engine.Listeners[index] = listener
		copy.Engine.Listeners[index].Addresses = append([]string(nil), listener.Addresses...)
		copy.Engine.Listeners[index].Protocols = append([]webengine.Protocol(nil), listener.Protocols...)
	}
	if plan.DefaultTLS != nil {
		defaultTLS := *plan.DefaultTLS
		copy.DefaultTLS = &defaultTLS
	}
	copy.Sites = make([]SiteInput, len(plan.Sites))
	for index, input := range plan.Sites {
		copy.Sites[index] = input
		copy.Sites[index].Projection.Bindings = append([]site.DomainBinding(nil), input.Projection.Bindings...)
		copy.Sites[index].Indexes = append([]string(nil), input.Indexes...)
		copy.Sites[index].TLS = append([]TLSInput(nil), input.TLS...)
	}
	return copy
}
