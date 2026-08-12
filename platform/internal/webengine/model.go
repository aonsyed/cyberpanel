// Package webengine defines engine-neutral desired state for OpenLiteSpeed and
// LiteSpeed Enterprise. Rendering vendor configuration is deliberately outside
// this package's model contract.
package webengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"path"
	"sort"
	"strings"
)

type Edition string

const (
	EditionOpenLiteSpeed       Edition = "openlitespeed"
	EditionLiteSpeedEnterprise Edition = "litespeed_enterprise"
)

type ResourceRef string

// Hostname is a normalized ASCII fully-qualified domain name. Its
// representation is private so callers cannot bypass ParseHostname.
type Hostname struct{ value string }

func ParseHostname(raw string) (Hostname, error) {
	if raw == "" || strings.HasPrefix(raw, ".") {
		return Hostname{}, errors.New("hostname must be an ASCII FQDN")
	}
	if strings.HasSuffix(raw, ".") {
		raw = raw[:len(raw)-1]
	}
	if raw == "" || len(raw) > 253 || !strings.Contains(raw, ".") {
		return Hostname{}, errors.New("hostname must be an ASCII FQDN")
	}
	for _, label := range strings.Split(raw, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Hostname{}, errors.New("hostname contains an invalid label")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-') {
				return Hostname{}, errors.New("hostname contains a non-ASCII DNS character")
			}
		}
	}
	return Hostname{value: strings.ToLower(raw)}, nil
}

func (hostname Hostname) String() string { return hostname.value }

func (hostname Hostname) MarshalJSON() ([]byte, error) {
	return json.Marshal(hostname.value)
}

type TLSMode string
type Protocol string
type BindingRelationship string
type RedirectStatus string
type RoutingState string
type LicenseState string
type Severity string

const (
	TLSModeClear TLSMode = "clear"
	TLSModeTLS   TLSMode = "tls"

	ProtocolHTTP1 Protocol = "http1"
	ProtocolHTTP2 Protocol = "http2"
	ProtocolHTTP3 Protocol = "http3"

	BindingPrimary  BindingRelationship = "primary"
	BindingAlias    BindingRelationship = "alias"
	BindingRedirect BindingRelationship = "redirect"
	BindingPreview  BindingRelationship = "preview"

	RedirectStatusPermanent301 RedirectStatus = "permanent_301"
	RedirectStatusTemporary302 RedirectStatus = "temporary_302"

	RoutingServe       RoutingState = "serve"
	RoutingMaintenance RoutingState = "maintenance"
	RoutingSuspended   RoutingState = "suspended"

	LicenseActive LicenseState = "active"
	LicenseTrial  LicenseState = "trial"

	SeverityError Severity = "error"
)

// Finding is a stable, machine-consumable validation result.
type Finding struct {
	Code     string
	Severity Severity
	Path     string
}

type EnterpriseLicenseExpectation struct {
	SecretRef     ResourceRef
	ExpectedState LicenseState
}

type Listener struct {
	Ref               ResourceRef
	Addresses         []string
	Port              uint16
	TLSMode           TLSMode
	Protocols         []Protocol
	DefaultBindingRef ResourceRef
}

type WebEngineSpec struct {
	Edition           Edition
	Listeners         []Listener
	EnterpriseLicense *EnterpriseLicenseExpectation
}

type WebApplicationSpec struct {
	Ref                ResourceRef
	SiteRef            ResourceRef
	IdentityRef        ResourceRef
	ApplicationRoot    string
	DocumentRoot       string
	Indexes            []string
	PHPProfileRef      ResourceRef
	ResourceProfileRef ResourceRef
	LogPolicyRef       ResourceRef
}

type WebBindingSpec struct {
	Ref            ResourceRef
	ApplicationRef ResourceRef
	Hostnames      []Hostname
	RedirectTarget Hostname
	RedirectStatus RedirectStatus
	ListenerRefs   []ResourceRef
	TLSPolicyRef   ResourceRef
	Relationship   BindingRelationship
	RoutingState   RoutingState
}

type DesiredState struct {
	Engine       WebEngineSpec
	Applications []WebApplicationSpec
	Bindings     []WebBindingSpec
}

// Validate returns deterministic, stable findings without mutating desired
// state. It validates only canonical model invariants; adapter capability and
// native syntax checks belong to the individual engine adapters.
func Validate(state DesiredState) []Finding {
	var findings []Finding
	add := func(code, fieldPath string) {
		findings = append(findings, Finding{Code: code, Severity: SeverityError, Path: fieldPath})
	}
	validateRef := func(ref ResourceRef, fieldPath string) {
		if ref != "" && !validResourceRef(ref) {
			add("WEBENGINE_RESOURCE_REF_INVALID", fieldPath)
		}
	}

	if state.Engine.Edition != EditionOpenLiteSpeed && state.Engine.Edition != EditionLiteSpeedEnterprise {
		add("WEBENGINE_EDITION_INVALID", "engine.edition")
	}
	if state.Engine.Edition == EditionLiteSpeedEnterprise {
		if state.Engine.EnterpriseLicense == nil {
			add("WEBENGINE_ENTERPRISE_LICENSE_REQUIRED", "engine.enterpriseLicense")
		} else {
			license := state.Engine.EnterpriseLicense
			if license.ExpectedState != LicenseActive && license.ExpectedState != LicenseTrial {
				add("WEBENGINE_ENTERPRISE_LICENSE_STATE_INVALID", "engine.enterpriseLicense.expectedState")
			}
			if license.ExpectedState == LicenseActive && license.SecretRef == "" {
				add("WEBENGINE_ENTERPRISE_LICENSE_SECRET_REQUIRED", "engine.enterpriseLicense.secretRef")
			}
			validateRef(license.SecretRef, "engine.enterpriseLicense.secretRef")
		}
	}

	listeners := make(map[ResourceRef]Listener, len(state.Engine.Listeners))
	listenerIndexes := make(map[ResourceRef]int, len(state.Engine.Listeners))
	endpoints := make(map[string]struct{})
	for listenerIndex, listener := range state.Engine.Listeners {
		listenerPath := "engine.listeners[" + decimal(listenerIndex) + "]"
		if listener.Ref == "" {
			add("WEBENGINE_LISTENER_REF_REQUIRED", listenerPath+".ref")
		} else if !validResourceRef(listener.Ref) {
			add("WEBENGINE_RESOURCE_REF_INVALID", listenerPath+".ref")
		} else if _, exists := listenerIndexes[listener.Ref]; exists {
			add("WEBENGINE_LISTENER_REF_DUPLICATE", listenerPath+".ref")
		} else {
			listenerIndexes[listener.Ref] = listenerIndex
			listeners[listener.Ref] = listener
		}
		validateRef(listener.DefaultBindingRef, listenerPath+".defaultBindingRef")
		if listener.Port == 0 {
			add("WEBENGINE_LISTENER_PORT_INVALID", listenerPath+".port")
		}
		if listener.TLSMode != TLSModeClear && listener.TLSMode != TLSModeTLS {
			add("WEBENGINE_TLS_MODE_INVALID", listenerPath+".tlsMode")
		}
		hasHTTP3 := false
		for protocolIndex, protocol := range listener.Protocols {
			if protocol != ProtocolHTTP1 && protocol != ProtocolHTTP2 && protocol != ProtocolHTTP3 {
				add("WEBENGINE_PROTOCOL_INVALID", listenerPath+".protocols["+decimal(protocolIndex)+"]")
			}
			if protocol == ProtocolHTTP3 {
				hasHTTP3 = true
			}
		}
		if hasHTTP3 && listener.TLSMode != TLSModeTLS {
			add("WEBENGINE_HTTP3_REQUIRES_TLS", listenerPath)
		}
		for addressIndex, address := range listener.Addresses {
			parsedAddress, err := netip.ParseAddr(address)
			if err != nil {
				add("WEBENGINE_LISTENER_ADDRESS_INVALID", listenerPath+".addresses["+decimal(addressIndex)+"]")
				continue
			}
			if parsedAddress.Zone() != "" {
				add("WEBENGINE_LISTENER_ADDRESS_INVALID", listenerPath+".addresses["+decimal(addressIndex)+"]")
				continue
			}
			endpoint := parsedAddress.String() + ":" + decimal(int(listener.Port))
			if _, exists := endpoints[endpoint]; exists {
				add("WEBENGINE_LISTENER_CONFLICT", listenerPath)
			} else {
				endpoints[endpoint] = struct{}{}
			}
		}
	}

	applications := make(map[ResourceRef]struct{}, len(state.Applications))
	for applicationIndex, application := range state.Applications {
		applicationPath := "applications[" + decimal(applicationIndex) + "]"
		if application.Ref == "" {
			add("WEBENGINE_APPLICATION_REF_REQUIRED", applicationPath+".ref")
		} else if !validResourceRef(application.Ref) {
			add("WEBENGINE_RESOURCE_REF_INVALID", applicationPath+".ref")
		} else if _, exists := applications[application.Ref]; exists {
			add("WEBENGINE_APPLICATION_REF_DUPLICATE", applicationPath+".ref")
		} else {
			applications[application.Ref] = struct{}{}
		}
		if application.SiteRef == "" {
			add("WEBENGINE_SITE_REF_REQUIRED", applicationPath+".siteRef")
		}
		validateRef(application.SiteRef, applicationPath+".siteRef")
		if application.IdentityRef == "" {
			add("WEBENGINE_IDENTITY_REF_REQUIRED", applicationPath+".identityRef")
		}
		validateRef(application.IdentityRef, applicationPath+".identityRef")
		if !safeRelative(application.ApplicationRoot) {
			add("WEBENGINE_APPLICATION_ROOT_INVALID", applicationPath+".applicationRoot")
		}
		if !documentInsideApplication(application.ApplicationRoot, application.DocumentRoot) {
			add("WEBENGINE_DOCUMENT_ROOT_OUTSIDE_APPLICATION", applicationPath+".documentRoot")
		}
		for indexIndex, index := range application.Indexes {
			if strings.TrimSpace(index) == "" {
				add("WEBENGINE_INDEX_INVALID", applicationPath+".indexes["+decimal(indexIndex)+"]")
			}
		}
		if application.PHPProfileRef == "" {
			add("WEBENGINE_PHP_PROFILE_REQUIRED", applicationPath+".phpProfileRef")
		}
		validateRef(application.PHPProfileRef, applicationPath+".phpProfileRef")
		if application.ResourceProfileRef == "" {
			add("WEBENGINE_RESOURCE_PROFILE_REQUIRED", applicationPath+".resourceProfileRef")
		}
		validateRef(application.ResourceProfileRef, applicationPath+".resourceProfileRef")
		if application.LogPolicyRef == "" {
			add("WEBENGINE_LOG_POLICY_REQUIRED", applicationPath+".logPolicyRef")
		}
		validateRef(application.LogPolicyRef, applicationPath+".logPolicyRef")
	}

	hostsByListener := make(map[ResourceRef]map[string]struct{})
	bindings := make(map[ResourceRef]WebBindingSpec, len(state.Bindings))
	type redirectEdge struct {
		target       Hostname
		bindingIndex int
	}
	redirectEdges := make(map[Hostname]redirectEdge)
	redirectSources := make([]Hostname, 0)
	for bindingIndex, binding := range state.Bindings {
		bindingPath := "bindings[" + decimal(bindingIndex) + "]"
		if binding.Ref == "" {
			add("WEBENGINE_BINDING_REF_REQUIRED", bindingPath+".ref")
		} else if !validResourceRef(binding.Ref) {
			add("WEBENGINE_RESOURCE_REF_INVALID", bindingPath+".ref")
		} else if _, exists := bindings[binding.Ref]; exists {
			add("WEBENGINE_BINDING_REF_DUPLICATE", bindingPath+".ref")
		} else {
			bindings[binding.Ref] = binding
		}
		validateRef(binding.ApplicationRef, bindingPath+".applicationRef")
		if _, exists := applications[binding.ApplicationRef]; !exists {
			add("WEBENGINE_APPLICATION_REF_MISSING", bindingPath+".applicationRef")
		}
		if len(binding.Hostnames) == 0 {
			add("WEBENGINE_BINDING_HOSTNAMES_REQUIRED", bindingPath+".hostnames")
		}
		for hostnameIndex, hostname := range binding.Hostnames {
			if hostname.String() == "" {
				add("WEBENGINE_BINDING_HOSTNAME_INVALID", bindingPath+".hostnames["+decimal(hostnameIndex)+"]")
			}
		}
		if len(binding.ListenerRefs) == 0 {
			add("WEBENGINE_BINDING_LISTENER_REFS_REQUIRED", bindingPath+".listenerRefs")
		}
		if binding.Relationship != BindingPrimary && binding.Relationship != BindingAlias && binding.Relationship != BindingRedirect && binding.Relationship != BindingPreview {
			add("WEBENGINE_BINDING_RELATIONSHIP_INVALID", bindingPath+".relationship")
		}
		if binding.Relationship == BindingRedirect {
			if binding.RedirectTarget.String() == "" {
				add("WEBENGINE_REDIRECT_TARGET_REQUIRED", bindingPath+".redirectTarget")
			}
			if binding.RedirectStatus != RedirectStatusPermanent301 && binding.RedirectStatus != RedirectStatusTemporary302 {
				add("WEBENGINE_REDIRECT_STATUS_INVALID", bindingPath+".redirectStatus")
			}
			if binding.RedirectTarget.String() != "" {
				for _, hostname := range binding.Hostnames {
					if hostname.String() == "" {
						continue
					}
					if _, exists := redirectEdges[hostname]; !exists {
						redirectEdges[hostname] = redirectEdge{target: binding.RedirectTarget, bindingIndex: bindingIndex}
						redirectSources = append(redirectSources, hostname)
					}
				}
			}
		} else {
			if binding.RedirectTarget.String() != "" {
				add("WEBENGINE_REDIRECT_METADATA_FORBIDDEN", bindingPath+".redirectTarget")
			}
			if binding.RedirectStatus != "" {
				add("WEBENGINE_REDIRECT_METADATA_FORBIDDEN", bindingPath+".redirectStatus")
			}
		}
		if binding.RoutingState != RoutingServe && binding.RoutingState != RoutingMaintenance && binding.RoutingState != RoutingSuspended {
			add("WEBENGINE_BINDING_ROUTING_STATE_INVALID", bindingPath+".routingState")
		}
		for listenerIndex, listenerRef := range binding.ListenerRefs {
			validateRef(listenerRef, bindingPath+".listenerRefs["+decimal(listenerIndex)+"]")
			listener, exists := listeners[listenerRef]
			if !exists {
				add("WEBENGINE_LISTENER_REF_MISSING", bindingPath+".listenerRefs["+decimal(listenerIndex)+"]")
				continue
			}
			if listener.TLSMode == TLSModeTLS && binding.TLSPolicyRef == "" {
				add("WEBENGINE_TLS_POLICY_REQUIRED", bindingPath+".tlsPolicyRef")
			}
			if hostsByListener[listenerRef] == nil {
				hostsByListener[listenerRef] = make(map[string]struct{})
			}
			for hostnameIndex, hostname := range binding.Hostnames {
				canonicalHostname := hostname.String()
				if canonicalHostname == "" {
					continue
				}
				if _, exists := hostsByListener[listenerRef][canonicalHostname]; exists {
					add("WEBENGINE_BINDING_HOST_CONFLICT", bindingPath+".hostnames["+decimal(hostnameIndex)+"]")
				}
				hostsByListener[listenerRef][canonicalHostname] = struct{}{}
			}
		}
		validateRef(binding.TLSPolicyRef, bindingPath+".tlsPolicyRef")
	}

	const (
		redirectVisiting = 1
		redirectVisited  = 2
	)
	redirectMarks := make(map[Hostname]uint8, len(redirectEdges))
	var findRedirectCycle func(Hostname) (int, bool)
	findRedirectCycle = func(source Hostname) (int, bool) {
		if redirectMarks[source] == redirectVisited {
			return 0, false
		}
		redirectMarks[source] = redirectVisiting
		edge, exists := redirectEdges[source]
		if !exists {
			redirectMarks[source] = redirectVisited
			return 0, false
		}
		if redirectMarks[edge.target] == redirectVisiting {
			return edge.bindingIndex, true
		}
		if redirectMarks[edge.target] == 0 {
			if bindingIndex, found := findRedirectCycle(edge.target); found {
				return bindingIndex, true
			}
		}
		redirectMarks[source] = redirectVisited
		return 0, false
	}
	for _, source := range redirectSources {
		if bindingIndex, found := findRedirectCycle(source); found {
			add("WEBENGINE_REDIRECT_CYCLE", "bindings["+decimal(bindingIndex)+"].redirectTarget")
			break
		}
	}
	for listenerIndex, listener := range state.Engine.Listeners {
		listenerPath := "engine.listeners[" + decimal(listenerIndex) + "]"
		binding, exists := bindings[listener.DefaultBindingRef]
		if !exists {
			add("WEBENGINE_DEFAULT_BINDING_REF_MISSING", listenerPath+".defaultBindingRef")
			continue
		}
		if !containsResourceRef(binding.ListenerRefs, listener.Ref) {
			add("WEBENGINE_DEFAULT_BINDING_LISTENER_MISMATCH", listenerPath+".defaultBindingRef")
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].Severity < findings[j].Severity
	})
	return findings
}

// CanonicalDigest returns the SHA-256 of a normalized, JSON-encoded copy of
// desired state. It does not mutate the caller's slices or nested values.
func (state DesiredState) CanonicalDigest() (string, error) {
	canonical := canonicalState(state)
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalState(state DesiredState) DesiredState {
	copy := state
	copy.Engine.Listeners = append([]Listener(nil), state.Engine.Listeners...)
	for listenerIndex := range copy.Engine.Listeners {
		copy.Engine.Listeners[listenerIndex].Addresses = append([]string(nil), state.Engine.Listeners[listenerIndex].Addresses...)
		copy.Engine.Listeners[listenerIndex].Protocols = append([]Protocol(nil), state.Engine.Listeners[listenerIndex].Protocols...)
		for addressIndex, address := range copy.Engine.Listeners[listenerIndex].Addresses {
			if parsedAddress, err := netip.ParseAddr(address); err == nil {
				copy.Engine.Listeners[listenerIndex].Addresses[addressIndex] = parsedAddress.String()
			}
		}
		sort.Strings(copy.Engine.Listeners[listenerIndex].Addresses)
		sort.Slice(copy.Engine.Listeners[listenerIndex].Protocols, func(i, j int) bool {
			return copy.Engine.Listeners[listenerIndex].Protocols[i] < copy.Engine.Listeners[listenerIndex].Protocols[j]
		})
	}
	sort.Slice(copy.Engine.Listeners, func(i, j int) bool { return copy.Engine.Listeners[i].Ref < copy.Engine.Listeners[j].Ref })
	copy.Applications = append([]WebApplicationSpec(nil), state.Applications...)
	for applicationIndex := range copy.Applications {
		copy.Applications[applicationIndex].Indexes = append([]string(nil), state.Applications[applicationIndex].Indexes...)
	}
	sort.Slice(copy.Applications, func(i, j int) bool { return copy.Applications[i].Ref < copy.Applications[j].Ref })
	copy.Bindings = append([]WebBindingSpec(nil), state.Bindings...)
	for bindingIndex := range copy.Bindings {
		copy.Bindings[bindingIndex].Hostnames = append([]Hostname(nil), state.Bindings[bindingIndex].Hostnames...)
		copy.Bindings[bindingIndex].ListenerRefs = append([]ResourceRef(nil), state.Bindings[bindingIndex].ListenerRefs...)
		sort.Slice(copy.Bindings[bindingIndex].Hostnames, func(i, j int) bool {
			return copy.Bindings[bindingIndex].Hostnames[i].String() < copy.Bindings[bindingIndex].Hostnames[j].String()
		})
		sort.Slice(copy.Bindings[bindingIndex].ListenerRefs, func(i, j int) bool {
			return copy.Bindings[bindingIndex].ListenerRefs[i] < copy.Bindings[bindingIndex].ListenerRefs[j]
		})
	}
	sort.Slice(copy.Bindings, func(i, j int) bool { return copy.Bindings[i].Ref < copy.Bindings[j].Ref })
	if state.Engine.EnterpriseLicense != nil {
		license := *state.Engine.EnterpriseLicense
		copy.Engine.EnterpriseLicense = &license
	}
	return copy
}

func containsResourceRef(refs []ResourceRef, target ResourceRef) bool {
	for _, ref := range refs {
		if ref == target {
			return true
		}
	}
	return false
}

func validResourceRef(ref ResourceRef) bool {
	value := string(ref)
	if len(value) < 3 || len(value) > 255 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	segments := strings.Split(value, "/")
	if len(segments) < 2 {
		return false
	}
	for _, segment := range segments {
		if len(segment) == 0 || len(segment) > 128 || !resourceRefAlphaNumeric(segment[0]) || !resourceRefAlphaNumeric(segment[len(segment)-1]) {
			return false
		}
		for _, character := range segment {
			if character > 127 || !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
				return false
			}
		}
	}
	return true
}

func resourceRefAlphaNumeric(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
}

func safeRelative(value string) bool {
	return value != "" && !strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && !strings.HasPrefix(value, "../") && value != ".."
}

func documentInsideApplication(applicationRoot, documentRoot string) bool {
	if !safeRelative(documentRoot) || !safeRelative(applicationRoot) {
		return false
	}
	return documentRoot == applicationRoot || strings.HasPrefix(documentRoot, applicationRoot+"/")
}

func decimal(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte(value%10) + '0'
		value /= 10
	}
	return string(digits[position:])
}
