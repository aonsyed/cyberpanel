package webengine

import (
	"reflect"
	"testing"
)

// These tests are the engine-neutral contract. Native renderer syntax belongs
// behind the OLS and LSE adapters and must not leak into this desired state.
func TestValidateAcceptsMinimalOLSAndLSEDesiredStates(t *testing.T) {
	for _, edition := range []Edition{EditionOpenLiteSpeed, EditionLiteSpeedEnterprise} {
		t.Run(string(edition), func(t *testing.T) {
			state := validDesiredState(edition)
			if edition == EditionLiteSpeedEnterprise {
				state.Engine.EnterpriseLicense = &EnterpriseLicenseExpectation{
					ExpectedState: LicenseActive,
					SecretRef:     ResourceRef("secret/lse-license"),
				}
			}
			if got := Validate(state); len(got) != 0 {
				t.Fatalf("Validate() = %#v, want no findings", got)
			}
		})
	}
}

func TestValidateRejectsClosedEngineProtocolAndTLSValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DesiredState)
		want   Finding
	}{
		{"edition", func(s *DesiredState) { s.Engine.Edition = Edition("apache") }, Finding{"WEBENGINE_EDITION_INVALID", SeverityError, "engine.edition"}},
		{"protocol", func(s *DesiredState) { s.Engine.Listeners[0].Protocols = []Protocol{"h3c"} }, Finding{"WEBENGINE_PROTOCOL_INVALID", SeverityError, "engine.listeners[0].protocols[0]"}},
		{"tls mode", func(s *DesiredState) { s.Engine.Listeners[0].TLSMode = TLSMode("opportunistic") }, Finding{"WEBENGINE_TLS_MODE_INVALID", SeverityError, "engine.listeners[0].tlsMode"}},
		{"http3 requires tls", func(s *DesiredState) {
			s.Engine.Listeners[0].Protocols = []Protocol{ProtocolHTTP3}
			s.Engine.Listeners[0].TLSMode = TLSModeClear
		}, Finding{"WEBENGINE_HTTP3_REQUIRES_TLS", SeverityError, "engine.listeners[0]"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertFinding(t, Validate(mutated(tc.mutate)), tc.want) })
	}
}

func TestValidateRejectsListenerConflictsAndInvalidEndpoints(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DesiredState)
		want   Finding
	}{
		{"duplicate endpoint", func(s *DesiredState) { s.Engine.Listeners = append(s.Engine.Listeners, s.Engine.Listeners[0]) }, Finding{"WEBENGINE_LISTENER_CONFLICT", SeverityError, "engine.listeners[1]"}},
		{"invalid address", func(s *DesiredState) { s.Engine.Listeners[0].Addresses = []string{"not-an-ip"} }, Finding{"WEBENGINE_LISTENER_ADDRESS_INVALID", SeverityError, "engine.listeners[0].addresses[0]"}},
		{"zero port", func(s *DesiredState) { s.Engine.Listeners[0].Port = 0 }, Finding{"WEBENGINE_LISTENER_PORT_INVALID", SeverityError, "engine.listeners[0].port"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertFinding(t, Validate(mutated(tc.mutate)), tc.want) })
	}
}

func TestValidateRejectsTLSBindingWithoutPolicyAndDuplicateHostOnListener(t *testing.T) {
	state := validDesiredState(EditionOpenLiteSpeed)
	state.Bindings[0].TLSPolicyRef = ""
	assertFinding(t, Validate(state), Finding{"WEBENGINE_TLS_POLICY_REQUIRED", SeverityError, "bindings[0].tlsPolicyRef"})

	state = validDesiredState(EditionOpenLiteSpeed)
	duplicate := state.Bindings[0]
	duplicate.Ref = "binding/duplicate"
	state.Bindings = append(state.Bindings, duplicate)
	assertFinding(t, Validate(state), Finding{"WEBENGINE_BINDING_HOST_CONFLICT", SeverityError, "bindings[1].hostnames[0]"})
}

func TestValidateRejectsMissingReferencesAndInvalidBindingState(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DesiredState)
		want   Finding
	}{
		{"missing application", func(s *DesiredState) { s.Bindings[0].ApplicationRef = "application/missing" }, Finding{"WEBENGINE_APPLICATION_REF_MISSING", SeverityError, "bindings[0].applicationRef"}},
		{"missing listener", func(s *DesiredState) { s.Bindings[0].ListenerRefs = []ResourceRef{"listener/missing"} }, Finding{"WEBENGINE_LISTENER_REF_MISSING", SeverityError, "bindings[0].listenerRefs[0]"}},
		{"invalid relationship", func(s *DesiredState) { s.Bindings[0].Relationship = BindingRelationship("mirror") }, Finding{"WEBENGINE_BINDING_RELATIONSHIP_INVALID", SeverityError, "bindings[0].relationship"}},
		{"invalid routing", func(s *DesiredState) { s.Bindings[0].RoutingState = RoutingState("disabled") }, Finding{"WEBENGINE_BINDING_ROUTING_STATE_INVALID", SeverityError, "bindings[0].routingState"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertFinding(t, Validate(mutated(tc.mutate)), tc.want) })
	}
}

func TestValidatePreservesTypedRedirectIntent(t *testing.T) {
	valid := validDesiredState(EditionOpenLiteSpeed)
	valid.Bindings[0].Relationship = BindingRedirect
	valid.Bindings[0].RedirectTarget = mustHostname("target.example.test")
	valid.Bindings[0].RedirectStatus = RedirectStatusPermanent301
	if got := Validate(valid); len(got) != 0 {
		t.Fatalf("Validate(valid redirect) = %#v, want no findings", got)
	}

	cases := []struct {
		name   string
		mutate func(*DesiredState)
		want   Finding
	}{
		{"missing target", func(s *DesiredState) {
			s.Bindings[0].Relationship = BindingRedirect
			s.Bindings[0].RedirectStatus = RedirectStatusPermanent301
		}, Finding{"WEBENGINE_REDIRECT_TARGET_REQUIRED", SeverityError, "bindings[0].redirectTarget"}},
		{"missing status", func(s *DesiredState) {
			s.Bindings[0].Relationship = BindingRedirect
			s.Bindings[0].RedirectTarget = mustHostname("target.example.test")
		}, Finding{"WEBENGINE_REDIRECT_STATUS_INVALID", SeverityError, "bindings[0].redirectStatus"}},
		{"unknown status", func(s *DesiredState) {
			s.Bindings[0].Relationship = BindingRedirect
			s.Bindings[0].RedirectTarget = mustHostname("target.example.test")
			s.Bindings[0].RedirectStatus = RedirectStatus("see_other_303")
		}, Finding{"WEBENGINE_REDIRECT_STATUS_INVALID", SeverityError, "bindings[0].redirectStatus"}},
		{"metadata on primary", func(s *DesiredState) {
			s.Bindings[0].RedirectTarget = mustHostname("target.example.test")
			s.Bindings[0].RedirectStatus = RedirectStatusTemporary302
		}, Finding{"WEBENGINE_REDIRECT_METADATA_FORBIDDEN", SeverityError, "bindings[0].redirectTarget"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertFinding(t, Validate(mutated(tc.mutate)), tc.want) })
	}
}

func TestValidateRejectsUnsafeApplicationPathsAndMissingRequiredReferences(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DesiredState)
		want   Finding
	}{
		{"missing site", func(s *DesiredState) { s.Applications[0].SiteRef = "" }, Finding{"WEBENGINE_SITE_REF_REQUIRED", SeverityError, "applications[0].siteRef"}},
		{"missing identity", func(s *DesiredState) { s.Applications[0].IdentityRef = "" }, Finding{"WEBENGINE_IDENTITY_REF_REQUIRED", SeverityError, "applications[0].identityRef"}},
		{"absolute root", func(s *DesiredState) { s.Applications[0].ApplicationRoot = "/srv/site" }, Finding{"WEBENGINE_APPLICATION_ROOT_INVALID", SeverityError, "applications[0].applicationRoot"}},
		{"traversing root", func(s *DesiredState) { s.Applications[0].ApplicationRoot = "../site" }, Finding{"WEBENGINE_APPLICATION_ROOT_INVALID", SeverityError, "applications[0].applicationRoot"}},
		{"document outside app", func(s *DesiredState) { s.Applications[0].DocumentRoot = "../public" }, Finding{"WEBENGINE_DOCUMENT_ROOT_OUTSIDE_APPLICATION", SeverityError, "applications[0].documentRoot"}},
		{"empty index", func(s *DesiredState) { s.Applications[0].Indexes = []string{""} }, Finding{"WEBENGINE_INDEX_INVALID", SeverityError, "applications[0].indexes[0]"}},
		{"missing php", func(s *DesiredState) { s.Applications[0].PHPProfileRef = "" }, Finding{"WEBENGINE_PHP_PROFILE_REQUIRED", SeverityError, "applications[0].phpProfileRef"}},
		{"missing resource", func(s *DesiredState) { s.Applications[0].ResourceProfileRef = "" }, Finding{"WEBENGINE_RESOURCE_PROFILE_REQUIRED", SeverityError, "applications[0].resourceProfileRef"}},
		{"missing log", func(s *DesiredState) { s.Applications[0].LogPolicyRef = "" }, Finding{"WEBENGINE_LOG_POLICY_REQUIRED", SeverityError, "applications[0].logPolicyRef"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertFinding(t, Validate(mutated(tc.mutate)), tc.want) })
	}
}

func TestValidateRequiresEnterpriseLicenseExpectationAndActiveSecret(t *testing.T) {
	state := validDesiredState(EditionLiteSpeedEnterprise)
	assertFinding(t, Validate(state), Finding{"WEBENGINE_ENTERPRISE_LICENSE_REQUIRED", SeverityError, "engine.enterpriseLicense"})
	state.Engine.EnterpriseLicense = &EnterpriseLicenseExpectation{ExpectedState: LicenseActive}
	assertFinding(t, Validate(state), Finding{"WEBENGINE_ENTERPRISE_LICENSE_SECRET_REQUIRED", SeverityError, "engine.enterpriseLicense.secretRef"})
}

func TestDesiredStateCanonicalDigestIsOrderIndependentAndModelHasNoRawFields(t *testing.T) {
	left := digestOrderFixture(false)
	right := digestOrderFixture(true)
	leftBefore := digestOrderFixture(false)
	rightBefore := digestOrderFixture(true)
	leftDigest, err := left.CanonicalDigest()
	if err != nil {
		t.Fatalf("left CanonicalDigest(): %v", err)
	}
	rightDigest, err := right.CanonicalDigest()
	if err != nil {
		t.Fatalf("right CanonicalDigest(): %v", err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("digest must be canonical: %q != %q", leftDigest, rightDigest)
	}
	if !reflect.DeepEqual(left, leftBefore) || !reflect.DeepEqual(right, rightBefore) {
		t.Fatal("CanonicalDigest mutated desired state")
	}

	reversedIndexes := digestOrderFixture(false)
	reversedIndexes.Applications[0].Indexes = []string{"index.html", "index.php"}
	reversedDigest, err := reversedIndexes.CanonicalDigest()
	if err != nil {
		t.Fatalf("reversed-index CanonicalDigest(): %v", err)
	}
	if leftDigest == reversedDigest {
		t.Fatal("index precedence must affect canonical digest")
	}

	for _, typ := range []reflect.Type{reflect.TypeOf(WebEngineSpec{}), reflect.TypeOf(Listener{}), reflect.TypeOf(WebApplicationSpec{}), reflect.TypeOf(WebBindingSpec{}), reflect.TypeOf(DesiredState{})} {
		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Name
			if name == "RawConfig" || name == "NativeConfig" || name == "Raw" {
				t.Fatalf("%s exposes forbidden raw/native field %q", typ, name)
			}
		}
	}
}

func TestHostnameParsingCanonicalizesAndValidationRejectsInvalidNames(t *testing.T) {
	canonical, err := ParseHostname("EXAMPLE.TEST.")
	if err != nil {
		t.Fatalf("ParseHostname(): %v", err)
	}
	if got := canonical.String(); got != "example.test" {
		t.Fatalf("Hostname.String() = %q, want example.test", got)
	}

	state := validDesiredState(EditionOpenLiteSpeed)
	state.Bindings[0].Hostnames = append(state.Bindings[0].Hostnames, canonical)
	assertFinding(t, Validate(state), Finding{"WEBENGINE_BINDING_HOST_CONFLICT", SeverityError, "bindings[0].hostnames[2]"})

	for _, raw := range []string{"bad host.example", "münich.example"} {
		t.Run(raw, func(t *testing.T) {
			hostname, err := ParseHostname(raw)
			if err == nil {
				t.Fatalf("ParseHostname(%q) succeeded", raw)
			}
			state := validDesiredState(EditionOpenLiteSpeed)
			state.Bindings[0].Hostnames = []Hostname{hostname}
			assertFinding(t, Validate(state), Finding{"WEBENGINE_BINDING_HOSTNAME_INVALID", SeverityError, "bindings[0].hostnames[0]"})
		})
	}
}

func TestValidateRejectsBlankAndDuplicateResourceReferences(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DesiredState)
		want   Finding
	}{
		{"blank listener", func(s *DesiredState) { s.Engine.Listeners[0].Ref = "" }, Finding{"WEBENGINE_LISTENER_REF_REQUIRED", SeverityError, "engine.listeners[0].ref"}},
		{"duplicate listener", func(s *DesiredState) {
			duplicate := s.Engine.Listeners[0]
			duplicate.Port = 8443
			s.Engine.Listeners = append(s.Engine.Listeners, duplicate)
		}, Finding{"WEBENGINE_LISTENER_REF_DUPLICATE", SeverityError, "engine.listeners[1].ref"}},
		{"blank application", func(s *DesiredState) { s.Applications[0].Ref = "" }, Finding{"WEBENGINE_APPLICATION_REF_REQUIRED", SeverityError, "applications[0].ref"}},
		{"duplicate application", func(s *DesiredState) { s.Applications = append(s.Applications, s.Applications[0]) }, Finding{"WEBENGINE_APPLICATION_REF_DUPLICATE", SeverityError, "applications[1].ref"}},
		{"blank binding", func(s *DesiredState) { s.Bindings[0].Ref = "" }, Finding{"WEBENGINE_BINDING_REF_REQUIRED", SeverityError, "bindings[0].ref"}},
		{"duplicate binding", func(s *DesiredState) {
			duplicate := s.Bindings[0]
			duplicate.Hostnames = []Hostname{mustHostname("other.example.test")}
			s.Bindings = append(s.Bindings, duplicate)
		}, Finding{"WEBENGINE_BINDING_REF_DUPLICATE", SeverityError, "bindings[1].ref"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertFinding(t, Validate(mutated(tc.mutate)), tc.want) })
	}
}

func TestValidateRejectsUnsafeResourceReferenceGrammar(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DesiredState)
		path   string
	}{
		{
			name: "whitespace and control characters in listener definition",
			mutate: func(state *DesiredState) {
				state.Engine.Listeners[0].Ref = "listener/public\ninclude"
			},
			path: "engine.listeners[0].ref",
		},
		{
			name: "traversal in site ownership reference",
			mutate: func(state *DesiredState) {
				state.Applications[0].SiteRef = "site/../../other"
			},
			path: "applications[0].siteRef",
		},
		{
			name: "whitespace in execution identity reference",
			mutate: func(state *DesiredState) {
				state.Applications[0].IdentityRef = "identity/site owner"
			},
			path: "applications[0].identityRef",
		},
		{
			name: "absolute listener relationship reference",
			mutate: func(state *DesiredState) {
				state.Bindings[0].ListenerRefs[0] = "/listener/public"
			},
			path: "bindings[0].listenerRefs[0]",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			state := validDesiredState(EditionOpenLiteSpeed)
			test.mutate(&state)
			assertFinding(t, Validate(state), Finding{
				Code:     "WEBENGINE_RESOURCE_REF_INVALID",
				Severity: SeverityError,
				Path:     test.path,
			})
		})
	}
}

func TestValidateRejectsRedirectToItsOwnHostname(t *testing.T) {
	state := validDesiredState(EditionOpenLiteSpeed)
	state.Bindings[0].Hostnames = []Hostname{mustHostname("source.example.test")}
	state.Bindings[0].Relationship = BindingRedirect
	state.Bindings[0].RedirectTarget = mustHostname("source.example.test")
	state.Bindings[0].RedirectStatus = RedirectStatusPermanent301

	assertFinding(t, Validate(state), Finding{
		Code:     "WEBENGINE_REDIRECT_CYCLE",
		Severity: SeverityError,
		Path:     "bindings[0].redirectTarget",
	})
}

func TestValidateRejectsRedirectCycleAcrossBindings(t *testing.T) {
	state := validDesiredState(EditionOpenLiteSpeed)
	state.Bindings[0].Hostnames = []Hostname{mustHostname("a.example.test")}
	state.Bindings[0].Relationship = BindingRedirect
	state.Bindings[0].RedirectTarget = mustHostname("b.example.test")
	state.Bindings[0].RedirectStatus = RedirectStatusPermanent301
	state.Bindings = append(state.Bindings, WebBindingSpec{
		Ref:            "binding/b",
		ApplicationRef: "application/site",
		Hostnames:      []Hostname{mustHostname("b.example.test")},
		RedirectTarget: mustHostname("a.example.test"),
		RedirectStatus: RedirectStatusTemporary302,
		ListenerRefs:   []ResourceRef{"listener/public"},
		TLSPolicyRef:   "tls/example",
		Relationship:   BindingRedirect,
		RoutingState:   RoutingServe,
	})

	assertFinding(t, Validate(state), Finding{
		Code:     "WEBENGINE_REDIRECT_CYCLE",
		Severity: SeverityError,
		Path:     "bindings[1].redirectTarget",
	})
}

func TestValidateTreatsEquivalentIPv6SpellingsAsListenerConflict(t *testing.T) {
	state := validDesiredState(EditionOpenLiteSpeed)
	state.Engine.Listeners[0].Addresses = []string{"::1"}
	state.Engine.Listeners = append(state.Engine.Listeners, Listener{
		Ref:               "listener/equivalent-ipv6",
		Addresses:         []string{"0:0:0:0:0:0:0:1"},
		Port:              443,
		TLSMode:           TLSModeTLS,
		Protocols:         []Protocol{ProtocolHTTP1, ProtocolHTTP2},
		DefaultBindingRef: "binding/main",
	})
	state.Bindings[0].ListenerRefs = append(state.Bindings[0].ListenerRefs, "listener/equivalent-ipv6")

	assertFinding(t, Validate(state), Finding{
		Code:     "WEBENGINE_LISTENER_CONFLICT",
		Severity: SeverityError,
		Path:     "engine.listeners[1]",
	})
}

func TestCanonicalDigestNormalizesEquivalentIPv6Spellings(t *testing.T) {
	compressed := validDesiredState(EditionOpenLiteSpeed)
	compressed.Engine.Listeners[0].Addresses = []string{"::1"}
	expanded := validDesiredState(EditionOpenLiteSpeed)
	expanded.Engine.Listeners[0].Addresses = []string{"0:0:0:0:0:0:0:1"}

	compressedDigest, err := compressed.CanonicalDigest()
	if err != nil {
		t.Fatalf("compressed CanonicalDigest(): %v", err)
	}
	expandedDigest, err := expanded.CanonicalDigest()
	if err != nil {
		t.Fatalf("expanded CanonicalDigest(): %v", err)
	}
	if compressedDigest != expandedDigest {
		t.Fatalf("equivalent IPv6 states produced different digests: %q != %q", compressedDigest, expandedDigest)
	}
}

func TestValidateRequiresBindingTargetsAndConsistentListenerDefault(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DesiredState)
		want   Finding
	}{
		{"hostnames", func(s *DesiredState) { s.Bindings[0].Hostnames = nil }, Finding{"WEBENGINE_BINDING_HOSTNAMES_REQUIRED", SeverityError, "bindings[0].hostnames"}},
		{"listeners", func(s *DesiredState) { s.Bindings[0].ListenerRefs = nil }, Finding{"WEBENGINE_BINDING_LISTENER_REFS_REQUIRED", SeverityError, "bindings[0].listenerRefs"}},
		{"missing default binding", func(s *DesiredState) { s.Engine.Listeners[0].DefaultBindingRef = "binding/missing" }, Finding{"WEBENGINE_DEFAULT_BINDING_REF_MISSING", SeverityError, "engine.listeners[0].defaultBindingRef"}},
		{"default binding targets another listener", func(s *DesiredState) {
			s.Engine.Listeners = append(s.Engine.Listeners, Listener{Ref: "listener/other", Addresses: []string{"127.0.0.1"}, Port: 8443, TLSMode: TLSModeTLS, Protocols: []Protocol{ProtocolHTTP1}, DefaultBindingRef: "binding/main"})
			s.Bindings[0].ListenerRefs = []ResourceRef{"listener/other"}
		}, Finding{"WEBENGINE_DEFAULT_BINDING_LISTENER_MISMATCH", SeverityError, "engine.listeners[0].defaultBindingRef"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertFinding(t, Validate(mutated(tc.mutate)), tc.want) })
	}
}

func validDesiredState(edition Edition) DesiredState {
	return DesiredState{
		Engine:       WebEngineSpec{Edition: edition, Listeners: []Listener{{Ref: "listener/public", Addresses: []string{"127.0.0.1", "::1"}, Port: 443, TLSMode: TLSModeTLS, Protocols: []Protocol{ProtocolHTTP1, ProtocolHTTP2}, DefaultBindingRef: "binding/main"}}},
		Applications: []WebApplicationSpec{{Ref: "application/site", SiteRef: "site/example", IdentityRef: "identity/site", ApplicationRoot: "releases/current", DocumentRoot: "releases/current/public", Indexes: []string{"index.php", "index.html"}, PHPProfileRef: "php/default", ResourceProfileRef: "resource/default", LogPolicyRef: "logs/default"}},
		Bindings:     []WebBindingSpec{{Ref: "binding/main", ApplicationRef: "application/site", Hostnames: []Hostname{mustHostname("example.test"), mustHostname("www.example.test")}, ListenerRefs: []ResourceRef{"listener/public"}, TLSPolicyRef: "tls/example", Relationship: BindingPrimary, RoutingState: RoutingServe}},
	}
}

func digestOrderFixture(reverse bool) DesiredState {
	state := validDesiredState(EditionOpenLiteSpeed)
	state.Engine.Listeners = append(state.Engine.Listeners, Listener{Ref: "listener/other", Addresses: []string{"192.0.2.1"}, Port: 8443, TLSMode: TLSModeTLS, Protocols: []Protocol{ProtocolHTTP1}, DefaultBindingRef: "binding/main"})
	state.Bindings[0].ListenerRefs = []ResourceRef{"listener/public", "listener/other"}
	if reverse {
		state.Engine.Listeners[0].Addresses = []string{"::1", "127.0.0.1"}
		state.Bindings[0].Hostnames = []Hostname{mustHostname("www.example.test"), mustHostname("example.test")}
		state.Bindings[0].ListenerRefs = []ResourceRef{"listener/other", "listener/public"}
	}
	return state
}

func mustHostname(raw string) Hostname {
	hostname, err := ParseHostname(raw)
	if err != nil {
		panic(err)
	}
	return hostname
}

func mutated(mutate func(*DesiredState)) DesiredState {
	state := validDesiredState(EditionOpenLiteSpeed)
	mutate(&state)
	return state
}

func assertFinding(t *testing.T, findings []Finding, want Finding) {
	t.Helper()
	for _, finding := range findings {
		if finding == want {
			return
		}
	}
	t.Fatalf("Validate() findings = %#v, want %#v", findings, want)
}
