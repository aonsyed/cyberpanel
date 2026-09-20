package enterprise

import (
	"context"
	"encoding/xml"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

// Enterprise is deliberately a native sibling renderer. These tests reject
// both Apache-compatible configuration and translation from OLS artifacts.
func TestRenderEmitsDeterministicCompleteNativeXMLGeneration(t *testing.T) {
	renderer := New()
	left := renderRequest(t, webengine.EditionLiteSpeedEnterprise)
	right := reorderedRequest(t, webengine.EditionLiteSpeedEnterprise)

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
	if leftGeneration.Edition != webengine.EditionLiteSpeedEnterprise {
		t.Fatalf("generation edition = %q", leftGeneration.Edition)
	}
	if leftGeneration.Kind != native.GenerationCompleteReplacement {
		t.Fatalf("generation kind = %q, want complete replacement", leftGeneration.Kind)
	}
	if leftGeneration.DesiredDigest == "" || leftGeneration.ContentDigest == "" {
		t.Fatal("complete generation must bind desired state and rendered bytes")
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
		if artifact.Mode != 0o600 || len(artifact.Content) == 0 {
			t.Fatalf("artifact %s:%s mode/content = %#o/%d", artifact.Role, artifact.Key, artifact.Mode, len(artifact.Content))
		}
	}
}

func TestRenderIsolatesNativeWorkerFromPanelAndVendorAdmin(t *testing.T) {
	generation, err := New().Render(context.Background(), renderRequest(t, webengine.EditionLiteSpeedEnterprise))
	if err != nil {
		t.Fatal(err)
	}
	server := artifactContent(t, generation, native.ArtifactServer, "engine")
	for _, directive := range []string{"<user>cyberpanel-web</user>", "<group>cyberpanel-web</group>", "<disableWebAdmin>1</disableWebAdmin>", "<requiredPermissionMask>000</requiredPermissionMask>", "<restrictedPermissionMask>000</restrictedPermissionMask>"} {
		if !strings.Contains(server, directive) {
			t.Fatalf("missing worker isolation directive %q", directive)
		}
	}
}

func TestRenderAssignsUniqueNativeNamesToCollidingListenerRefs(t *testing.T) {
	request := renderRequest(t, webengine.EditionLiteSpeedEnterprise)
	refs := []webengine.ResourceRef{
		"listener/a.b",
		"listener/a-b",
		"listener/a",
		"listener/a-ipv6",
	}
	request.Desired.Engine.Listeners = []webengine.Listener{
		{Ref: refs[0], Addresses: []string{"127.0.0.1"}, Port: 8080, TLSMode: webengine.TLSModeClear, Protocols: []webengine.Protocol{webengine.ProtocolHTTP1}, DefaultBindingRef: "binding/a"},
		{Ref: refs[1], Addresses: []string{"127.0.0.1"}, Port: 8081, TLSMode: webengine.TLSModeClear, Protocols: []webengine.Protocol{webengine.ProtocolHTTP1}, DefaultBindingRef: "binding/a"},
		{Ref: refs[2], Addresses: []string{"::1"}, Port: 8082, TLSMode: webengine.TLSModeClear, Protocols: []webengine.Protocol{webengine.ProtocolHTTP1}, DefaultBindingRef: "binding/a"},
		{Ref: refs[3], Addresses: []string{"127.0.0.1"}, Port: 8083, TLSMode: webengine.TLSModeClear, Protocols: []webengine.Protocol{webengine.ProtocolHTTP1}, DefaultBindingRef: "binding/a"},
	}
	request.Desired.Bindings[0].ListenerRefs = refs
	request.Desired.Bindings[1].ListenerRefs = []webengine.ResourceRef{refs[0]}

	generation, err := New().Render(context.Background(), request)
	if err != nil {
		t.Fatalf("Render(): %v", err)
	}
	server := artifactContent(t, generation, native.ArtifactServer, "engine")
	var document struct {
		ListenerList struct {
			Listeners []struct {
				Name string `xml:"name"`
			} `xml:"listener"`
		} `xml:"listenerList"`
	}
	if err := xml.Unmarshal([]byte(server), &document); err != nil {
		t.Fatalf("rendered server XML is malformed: %v\n%s", err, server)
	}
	names := make([]string, 0, len(document.ListenerList.Listeners))
	for _, listener := range document.ListenerList.Listeners {
		names = append(names, listener.Name)
	}
	if len(names) != len(refs) {
		t.Fatalf("rendered listener names = %#v, want one physical name per ref %#v", names, refs)
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, exists := seen[name]; exists {
			t.Fatalf("rendered listener name %q is not unique: %#v", name, names)
		}
		seen[name] = struct{}{}
	}
}

func TestRenderUsesEnterpriseNativeXMLNotApacheCompatibilityMode(t *testing.T) {
	generation, err := New().Render(context.Background(), renderRequest(t, webengine.EditionLiteSpeedEnterprise))
	if err != nil {
		t.Fatalf("Render(): %v", err)
	}
	server := artifactContent(t, generation, native.ArtifactServer, "engine")
	assertContainsAll(t, server,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
		"<httpServerConfig>",
		"<loadApacheConf>0</loadApacheConf>",
		"<listener>",
		"<name>listener-public</name>",
		"<address>127.0.0.1:443</address>",
		"<name>listener-public-ipv6</name>",
		"<address>[::1]:443</address>",
		"<secure>1</secure>",
		"<name>vh_site_a_binding_a</name>",
		"<configFile>$SERVER_ROOT/conf/vhosts/.panel-generations/g42/site-a--binding-a/vhconf.xml</configFile>",
		"<name>vh_site_b_binding_b</name>",
		"<configFile>$SERVER_ROOT/conf/vhosts/.panel-generations/g42/site-b--binding-b/vhconf.xml</configFile>",
		"<vhost>vh_site_a_binding_a</vhost>",
		"<domain>site-a.example.test, www.site-a.example.test</domain>",
		"<vhost>vh_site_b_binding_b</vhost>",
	)
	assertContainsNone(t, server,
		"<configFile>$SERVER_ROOT/conf/vhosts/site-a--binding-a/vhconf.xml</configFile>",
		"<configFile>$SERVER_ROOT/conf/vhosts/site-b--binding-b/vhconf.xml</configFile>",
	)
	assertContainsNone(t, allContent(generation),
		"<VirtualHost",
		"ServerName ",
		"SuexecUserGroup ",
		"Include /",
		"<apacheConfFile>",
		"<loadApacheConf>1</loadApacheConf>",
		"secret/lse-license",
	)
}

func TestEnterpriseArtifactsRemainWellFormedForValidDoubleHyphenHostname(t *testing.T) {
	request := renderRequest(t, webengine.EditionLiteSpeedEnterprise)
	request.Desired.Bindings[0].Hostnames[0] = mustHostname(t, "site--a.example.test")
	generation, err := New().Render(context.Background(), request)
	if err != nil {
		t.Fatalf("Render(): %v", err)
	}
	for _, artifact := range generation.Artifacts {
		var document any
		if err := xml.Unmarshal(artifact.Content, &document); err != nil {
			t.Fatalf("artifact %s:%s is malformed XML: %v\n%s", artifact.Role, artifact.Key, err, artifact.Content)
		}
	}
}

func TestRenderDerivesUniqueEnterpriseVHostLSAPIAndTLSIdentityPerSite(t *testing.T) {
	generation, err := New().Render(context.Background(), renderRequest(t, webengine.EditionLiteSpeedEnterprise))
	if err != nil {
		t.Fatalf("Render(): %v", err)
	}
	siteA := artifactContent(t, generation, native.ArtifactVirtualHost, "site-a--binding-a")
	siteB := artifactContent(t, generation, native.ArtifactVirtualHost, "site-b--binding-b")

	assertContainsAll(t, siteA,
		"<virtualHostConfig>",
		"<docRoot>/var/lib/cyberpanel/sites/site-a/roots/g7/releases/current/public</docRoot>",
		"<scriptHandler>",
		"<handler>pool_site_a_g3</handler>",
		"<extProcessor>",
		"<type>lsapi</type>",
		"<name>pool_site_a_g3</name>",
		"<address>uds:///run/cyberpanel/site-runtime/site-a/php/pool-site-a/g3.sock</address>",
		"<maxConns>8</maxConns>",
		"<autoStart>0</autoStart>",
		"<vhssl>",
		"<keyFile>/var/lib/cyberpanel/certificates/consumers/webengine/cert-site-a/current/private.key</keyFile>",
		"<certFile>/var/lib/cyberpanel/certificates/consumers/webengine/cert-site-a/current/fullchain.pem</certFile>",
	)
	assertContainsAll(t, siteB,
		"<docRoot>/var/lib/cyberpanel/sites/site-b/roots/g13/releases/current/public</docRoot>",
		"<handler>pool_site_b_g5</handler>",
		"<address>uds:///run/cyberpanel/site-runtime/site-b/php/pool-site-b/g5.sock</address>",
		"<keyFile>/var/lib/cyberpanel/certificates/consumers/webengine/cert-site-b/current/private.key</keyFile>",
	)
	assertContainsNone(t, siteA,
		"pool_site_b_g5",
		"/site-b/",
		"<path>",
		"<extUser>",
		"<extGroup>",
		"/bin/lsphp",
		"/var/lib/cyberpanel/webengine/generations/",
	)
	assertContainsNone(t, siteB, "pool_site_a_g3", "/site-a/", "/var/lib/cyberpanel/webengine/generations/")
}

func TestRenderUsesProductOwnedEnterpriseMaintenanceAndSuspendedRoutes(t *testing.T) {
	request := renderRequest(t, webengine.EditionLiteSpeedEnterprise)
	request.Desired.Bindings[0].RoutingState = webengine.RoutingMaintenance
	request.Desired.Bindings[1].RoutingState = webengine.RoutingSuspended

	generation, err := New().Render(context.Background(), request)
	if err != nil {
		t.Fatalf("Render(): %v", err)
	}
	maintenance := artifactContent(t, generation, native.ArtifactVirtualHost, "site-a--binding-a")
	suspended := artifactContent(t, generation, native.ArtifactVirtualHost, "site-b--binding-b")
	assertContainsAll(t, maintenance, "<context>", "<location>$SERVER_ROOT/panel/system/maintenance</location>")
	assertContainsAll(t, suspended, "<context>", "<location>$SERVER_ROOT/panel/system/suspended</location>")
	assertContainsNone(t, maintenance, "<type>lsapi</type>", "<extProcessor>", "/site-runtime/site-a/")
	assertContainsNone(t, suspended, "<type>lsapi</type>", "<extProcessor>", "/site-runtime/site-b/")
}

func TestCompleteEnterpriseGenerationWithdrawsDeletedBinding(t *testing.T) {
	request := renderRequest(t, webengine.EditionLiteSpeedEnterprise)
	request.Desired.Applications = request.Desired.Applications[:1]
	request.Desired.Bindings = request.Desired.Bindings[:1]
	// The quarantined site's runtime and TLS records deliberately remain.
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

func TestEnterpriseRendererRejectsInvalidClosedInputWithoutPartialOutput(t *testing.T) {
	request := renderRequest(t, webengine.EditionLiteSpeedEnterprise)
	request.Snapshot.TLSMaterials[0].MaterialKey = native.MaterialKey("../../private-key")
	generation, err := New().Render(context.Background(), request)
	if !errors.Is(err, native.ErrInvalidSnapshot) {
		t.Fatalf("Render() error = %v, want invalid snapshot", err)
	}
	if !reflect.DeepEqual(generation, native.ConfigGeneration{}) {
		t.Fatalf("failed render leaked partial generation: %#v", generation)
	}
}

func TestEnterpriseRendererRejectsOpenLiteSpeedDesiredState(t *testing.T) {
	generation, err := New().Render(context.Background(), renderRequest(t, webengine.EditionOpenLiteSpeed))
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
