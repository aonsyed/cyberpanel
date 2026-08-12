package ols

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

// These are contract-first tests for the OpenLiteSpeed renderer. They require
// a complete replacement generation; an implementation that emits live-file
// edits, shell commands, or partial listener/vhost patches cannot satisfy them.
func TestRenderEmitsDeterministicCompleteNativeTextGeneration(t *testing.T) {
	renderer := New()
	left := renderRequest(t, webengine.EditionOpenLiteSpeed)
	right := reorderedRequest(t, webengine.EditionOpenLiteSpeed)

	leftGeneration, err := renderer.Render(context.Background(), left)
	if err != nil {
		t.Fatalf("Render(left): %v", err)
	}
	rightGeneration, err := renderer.Render(context.Background(), right)
	if err != nil {
		t.Fatalf("Render(right): %v", err)
	}

	if !reflect.DeepEqual(leftGeneration, rightGeneration) {
		t.Fatalf("render is not deterministic\nleft:  %#v\nright: %#v", leftGeneration, rightGeneration)
	}
	if leftGeneration.Edition != webengine.EditionOpenLiteSpeed {
		t.Fatalf("generation edition = %q", leftGeneration.Edition)
	}
	if leftGeneration.Kind != native.GenerationCompleteReplacement {
		t.Fatalf("generation kind = %q, want complete replacement", leftGeneration.Kind)
	}
	if leftGeneration.DesiredDigest == "" || leftGeneration.ContentDigest == "" {
		t.Fatal("complete generation must bind both desired state and rendered bytes")
	}

	wantArtifacts := []string{
		"server:engine",
		"virtual_host:site-a--binding-a",
		"virtual_host:site-b--binding-b",
	}
	if got := artifactIdentities(leftGeneration); !reflect.DeepEqual(got, wantArtifacts) {
		t.Fatalf("artifact identities = %#v, want %#v", got, wantArtifacts)
	}
	for _, artifact := range leftGeneration.Artifacts {
		if artifact.Mode != 0o600 {
			t.Fatalf("artifact %s:%s mode = %#o, want 0600", artifact.Role, artifact.Key, artifact.Mode)
		}
		if len(artifact.Content) == 0 {
			t.Fatalf("artifact %s:%s is empty", artifact.Role, artifact.Key)
		}
	}
}

func TestRenderDerivesUniqueVHostLSAPIAndTLSIdentityPerSite(t *testing.T) {
	generation, err := New().Render(context.Background(), renderRequest(t, webengine.EditionOpenLiteSpeed))
	if err != nil {
		t.Fatalf("Render(): %v", err)
	}

	server := artifactContent(t, generation, native.ArtifactServer, "engine")
	siteA := artifactContent(t, generation, native.ArtifactVirtualHost, "site-a--binding-a")
	siteB := artifactContent(t, generation, native.ArtifactVirtualHost, "site-b--binding-b")

	assertContainsAll(t, server,
		"listener listener-public",
		"address 127.0.0.1:443",
		"listener listener-public-ipv6",
		"address [::1]:443",
		"secure 1",
		"virtualHost vh_site_a_binding_a",
		"configFile $SERVER_ROOT/conf/vhosts/site-a--binding-a/vhost.conf",
		"virtualHost vh_site_b_binding_b",
		"configFile $SERVER_ROOT/conf/vhosts/site-b--binding-b/vhost.conf",
		"map vh_site_a_binding_a site-a.example.test, www.site-a.example.test",
		"map vh_site_b_binding_b site-b.example.test",
	)
	assertContainsAll(t, siteA,
		"docRoot /var/lib/cyberpanel/sites/site-a/roots/g7/releases/current/public",
		"scripthandler",
		"lsapi:pool_site_a_g3",
		"extprocessor pool_site_a_g3",
		"address UDS:///run/cyberpanel/site-runtime/site-a/php/pool-site-a/g3.sock",
		"maxConns 8",
		"autoStart 0",
		"vhssl",
		"keyFile /var/lib/cyberpanel/webengine/generations/g42/tls/cert-site-a/g9/privkey.pem",
		"certFile /var/lib/cyberpanel/webengine/generations/g42/tls/cert-site-a/g9/fullchain.pem",
	)
	assertContainsAll(t, siteB,
		"docRoot /var/lib/cyberpanel/sites/site-b/roots/g13/releases/current/public",
		"lsapi:pool_site_b_g5",
		"address UDS:///run/cyberpanel/site-runtime/site-b/php/pool-site-b/g5.sock",
		"keyFile /var/lib/cyberpanel/webengine/generations/g42/tls/cert-site-b/g11/privkey.pem",
	)
	assertContainsNone(t, siteA,
		"pool_site_b_g5",
		"/site-b/",
		"\n  path ",
		"\n  extUser ",
		"\n  extGroup ",
		"/bin/lsphp",
	)
	assertContainsNone(t, siteB, "pool_site_a_g3", "/site-a/")
}

func TestRenderUsesProductOwnedMaintenanceAndSuspendedRoutesWithoutTenantPHP(t *testing.T) {
	request := renderRequest(t, webengine.EditionOpenLiteSpeed)
	request.Desired.Bindings[0].RoutingState = webengine.RoutingMaintenance
	request.Desired.Bindings[1].RoutingState = webengine.RoutingSuspended

	generation, err := New().Render(context.Background(), request)
	if err != nil {
		t.Fatalf("Render(): %v", err)
	}

	maintenance := artifactContent(t, generation, native.ArtifactVirtualHost, "site-a--binding-a")
	suspended := artifactContent(t, generation, native.ArtifactVirtualHost, "site-b--binding-b")
	assertContainsAll(t, maintenance, "context /", "location $SERVER_ROOT/panel/system/maintenance")
	assertContainsAll(t, suspended, "context /", "location $SERVER_ROOT/panel/system/suspended")
	assertContainsNone(t, maintenance, "lsapi:", "extprocessor", "/site-runtime/site-a/")
	assertContainsNone(t, suspended, "lsapi:", "extprocessor", "/site-runtime/site-b/")
}

func TestCompleteGenerationWithdrawsDeletedBindingEvenIfRuntimeIsStillQuarantined(t *testing.T) {
	request := renderRequest(t, webengine.EditionOpenLiteSpeed)
	request.Desired.Applications = request.Desired.Applications[:1]
	request.Desired.Bindings = request.Desired.Bindings[:1]
	// Site B intentionally remains in the runtime snapshot: quarantined data and
	// runtime registry records must not keep an HTTP route alive.

	generation, err := New().Render(context.Background(), request)
	if err != nil {
		t.Fatalf("Render(): %v", err)
	}
	wantArtifacts := []string{"server:engine", "virtual_host:site-a--binding-a"}
	if got := artifactIdentities(generation); !reflect.DeepEqual(got, wantArtifacts) {
		t.Fatalf("artifact identities = %#v, want %#v", got, wantArtifacts)
	}
	assertContainsNone(t, allContent(generation), "site-b", "binding-b", "site-b.example.test", "pool_site_b")
}

func TestRenderRejectsUnclosedDesiredStateAndRegistryIdentifiers(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*native.RenderRequest)
		want   error
	}{
		{
			name: "native directive in relative document root",
			mutate: func(request *native.RenderRequest) {
				request.Desired.Applications[0].DocumentRoot = "releases/current/public\ninclude /etc/passwd"
			},
			want: native.ErrInvalidDesiredState,
		},
		{
			name: "host path in site key",
			mutate: func(request *native.RenderRequest) {
				request.Snapshot.Sites[0].SiteKey = native.SiteKey("../site-a")
			},
			want: native.ErrInvalidSnapshot,
		},
		{
			name: "dotdot site key",
			mutate: func(request *native.RenderRequest) {
				request.Snapshot.Sites[0].SiteKey = native.SiteKey("..")
			},
			want: native.ErrInvalidSnapshot,
		},
		{
			name: "zoned IPv6 listener",
			mutate: func(request *native.RenderRequest) {
				request.Desired.Engine.Listeners[0].Addresses = []string{"fe80::1%eth0"}
			},
			want: native.ErrInvalidDesiredState,
		},
		{
			name: "shell expression in pool key",
			mutate: func(request *native.RenderRequest) {
				request.Snapshot.LSAPIPools[0].PoolKey = native.PoolKey("pool;$(id)")
			},
			want: native.ErrInvalidSnapshot,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := renderRequest(t, webengine.EditionOpenLiteSpeed)
			test.mutate(&request)
			generation, err := New().Render(context.Background(), request)
			if !errors.Is(err, test.want) {
				t.Fatalf("Render() error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(generation, native.ConfigGeneration{}) {
				t.Fatalf("failed render leaked partial generation: %#v", generation)
			}
		})
	}
}

func TestRenderRejectsCrossSiteOrDanglingTLSMaterial(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*native.RenderRequest)
	}{
		{
			name: "cross-site material",
			mutate: func(request *native.RenderRequest) {
				request.Snapshot.TLSMaterials[0].SiteRef = "site/b"
				request.Snapshot.TLSMaterials[0].IdentityRef = "identity/b"
			},
		},
		{
			name: "clear binding with dangling policy",
			mutate: func(request *native.RenderRequest) {
				request.Desired.Engine.Listeners[0].TLSMode = webengine.TLSModeClear
				request.Desired.Engine.Listeners[0].Protocols = []webengine.Protocol{webengine.ProtocolHTTP1}
				request.Snapshot.TLSMaterials = request.Snapshot.TLSMaterials[1:]
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := renderRequest(t, webengine.EditionOpenLiteSpeed)
			test.mutate(&request)
			generation, err := New().Render(context.Background(), request)
			if !errors.Is(err, native.ErrInvalidSnapshot) {
				t.Fatalf("Render() error = %v, want invalid snapshot", err)
			}
			if !reflect.DeepEqual(generation, native.ConfigGeneration{}) {
				t.Fatalf("invalid TLS ownership returned partial generation: %#v", generation)
			}
		})
	}
}

func TestRenderRequestExposesNoRawNativeShellOrHostPathEscapeHatch(t *testing.T) {
	assertClosedNativeType(t, reflect.TypeOf(native.RenderRequest{}), map[reflect.Type]bool{})
}

func TestRendererRejectsLiteSpeedEnterpriseDesiredState(t *testing.T) {
	generation, err := New().Render(context.Background(), renderRequest(t, webengine.EditionLiteSpeedEnterprise))
	if !errors.Is(err, native.ErrEditionMismatch) {
		t.Fatalf("Render() error = %v, want edition mismatch", err)
	}
	if !reflect.DeepEqual(generation, native.ConfigGeneration{}) {
		t.Fatalf("edition mismatch returned partial generation: %#v", generation)
	}
}

func renderRequest(t *testing.T, edition webengine.Edition) native.RenderRequest {
	t.Helper()
	hostA := mustHostname(t, "site-a.example.test")
	hostAWWW := mustHostname(t, "www.site-a.example.test")
	hostB := mustHostname(t, "site-b.example.test")
	desired := webengine.DesiredState{
		Engine: webengine.WebEngineSpec{
			Edition: edition,
			Listeners: []webengine.Listener{{
				Ref:               "listener/public",
				Addresses:         []string{"127.0.0.1", "::1"},
				Port:              443,
				TLSMode:           webengine.TLSModeTLS,
				Protocols:         []webengine.Protocol{webengine.ProtocolHTTP1, webengine.ProtocolHTTP2, webengine.ProtocolHTTP3},
				DefaultBindingRef: "binding/a",
			}},
		},
		Applications: []webengine.WebApplicationSpec{
			{Ref: "application/a", SiteRef: "site/a", IdentityRef: "identity/a", ApplicationRoot: "releases/current", DocumentRoot: "releases/current/public", Indexes: []string{"index.php", "index.html"}, PHPProfileRef: "php/8.4", ResourceProfileRef: "resource/default", LogPolicyRef: "logs/a"},
			{Ref: "application/b", SiteRef: "site/b", IdentityRef: "identity/b", ApplicationRoot: "releases/current", DocumentRoot: "releases/current/public", Indexes: []string{"index.php", "index.html"}, PHPProfileRef: "php/8.3", ResourceProfileRef: "resource/default", LogPolicyRef: "logs/b"},
		},
		Bindings: []webengine.WebBindingSpec{
			{Ref: "binding/a", ApplicationRef: "application/a", Hostnames: []webengine.Hostname{hostA, hostAWWW}, ListenerRefs: []webengine.ResourceRef{"listener/public"}, TLSPolicyRef: "tls/a", Relationship: webengine.BindingPrimary, RoutingState: webengine.RoutingServe},
			{Ref: "binding/b", ApplicationRef: "application/b", Hostnames: []webengine.Hostname{hostB}, ListenerRefs: []webengine.ResourceRef{"listener/public"}, TLSPolicyRef: "tls/b", Relationship: webengine.BindingPrimary, RoutingState: webengine.RoutingServe},
		},
	}
	if edition == webengine.EditionLiteSpeedEnterprise {
		desired.Engine.EnterpriseLicense = &webengine.EnterpriseLicenseExpectation{ExpectedState: webengine.LicenseActive, SecretRef: "secret/lse-license"}
	}
	return native.RenderRequest{
		Desired: desired,
		Snapshot: native.RuntimeSnapshot{
			Generation: 42,
			Sites: []native.SiteRuntime{
				{SiteRef: "site/a", IdentityRef: "identity/a", SiteKey: "site-a", RootGeneration: 7},
				{SiteRef: "site/b", IdentityRef: "identity/b", SiteKey: "site-b", RootGeneration: 13},
			},
			LSAPIPools: []native.LSAPIPool{
				{SiteRef: "site/a", IdentityRef: "identity/a", PHPProfileRef: "php/8.4", PoolKey: "pool-site-a", Generation: 3, MaxConnections: 8},
				{SiteRef: "site/b", IdentityRef: "identity/b", PHPProfileRef: "php/8.3", PoolKey: "pool-site-b", Generation: 5, MaxConnections: 6},
			},
			TLSMaterials: []native.TLSMaterial{
				{PolicyRef: "tls/a", SiteRef: "site/a", IdentityRef: "identity/a", MaterialKey: "cert-site-a", Generation: 9},
				{PolicyRef: "tls/b", SiteRef: "site/b", IdentityRef: "identity/b", MaterialKey: "cert-site-b", Generation: 11},
			},
		},
	}
}

func reorderedRequest(t *testing.T, edition webengine.Edition) native.RenderRequest {
	t.Helper()
	request := renderRequest(t, edition)
	request.Desired.Engine.Listeners[0].Addresses = []string{"::1", "127.0.0.1"}
	request.Desired.Engine.Listeners[0].Protocols = []webengine.Protocol{webengine.ProtocolHTTP3, webengine.ProtocolHTTP1, webengine.ProtocolHTTP2}
	request.Desired.Bindings[0].Hostnames[0], request.Desired.Bindings[0].Hostnames[1] = request.Desired.Bindings[0].Hostnames[1], request.Desired.Bindings[0].Hostnames[0]
	request.Desired.Applications[0], request.Desired.Applications[1] = request.Desired.Applications[1], request.Desired.Applications[0]
	request.Desired.Bindings[0], request.Desired.Bindings[1] = request.Desired.Bindings[1], request.Desired.Bindings[0]
	request.Snapshot.Sites[0], request.Snapshot.Sites[1] = request.Snapshot.Sites[1], request.Snapshot.Sites[0]
	request.Snapshot.LSAPIPools[0], request.Snapshot.LSAPIPools[1] = request.Snapshot.LSAPIPools[1], request.Snapshot.LSAPIPools[0]
	request.Snapshot.TLSMaterials[0], request.Snapshot.TLSMaterials[1] = request.Snapshot.TLSMaterials[1], request.Snapshot.TLSMaterials[0]
	return request
}

func mustHostname(t *testing.T, raw string) webengine.Hostname {
	t.Helper()
	hostname, err := webengine.ParseHostname(raw)
	if err != nil {
		t.Fatalf("ParseHostname(%q): %v", raw, err)
	}
	return hostname
}

func artifactIdentities(generation native.ConfigGeneration) []string {
	identities := make([]string, 0, len(generation.Artifacts))
	for _, artifact := range generation.Artifacts {
		identities = append(identities, string(artifact.Role)+":"+string(artifact.Key))
	}
	sort.Strings(identities)
	return identities
}

func artifactContent(t *testing.T, generation native.ConfigGeneration, role native.ArtifactRole, key native.ArtifactKey) string {
	t.Helper()
	for _, artifact := range generation.Artifacts {
		if artifact.Role == role && artifact.Key == key {
			return string(artifact.Content)
		}
	}
	t.Fatalf("artifact %s:%s not found in %#v", role, key, artifactIdentities(generation))
	return ""
}

func allContent(generation native.ConfigGeneration) string {
	var combined strings.Builder
	for _, artifact := range generation.Artifacts {
		combined.Write(artifact.Content)
		combined.WriteByte('\n')
	}
	return combined.String()
}

func assertContainsAll(t *testing.T, text string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(text, fragment) {
			t.Fatalf("rendered artifact does not contain %q:\n%s", fragment, text)
		}
	}
}

func assertContainsNone(t *testing.T, text string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if strings.Contains(text, fragment) {
			t.Fatalf("rendered artifact unexpectedly contains %q:\n%s", fragment, text)
		}
	}
}

func assertClosedNativeType(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true
	if typ.PkgPath() != "github.com/aonsyed/cyberpanel/platform/internal/webengine/native" {
		return
	}
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		lower := strings.ToLower(field.Name)
		for _, forbidden := range []string{"raw", "directive", "shell", "command", "argv", "executablepath", "hostpath", "configpath", "includepath"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%s exposes forbidden caller escape-hatch field %q", typ, field.Name)
			}
		}
		assertClosedNativeType(t, field.Type, seen)
	}
}
