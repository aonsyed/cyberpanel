// Package composer turns tenant-owned site projections into one node webengine state.
package composer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

type ListenerInput struct {
	Ref       webengine.ResourceRef
	Addresses []string
	Port      uint16
	TLSMode   webengine.TLSMode
	Protocols []webengine.Protocol
}

type NodeEngine struct {
	Edition   webengine.Edition
	Listeners []ListenerInput
}

type TLSInput struct {
	OwnerScope  service.CommandScope
	PolicyRef   webengine.ResourceRef
	MaterialKey native.MaterialKey
	Generation  uint64
}

type SiteInput struct {
	Scope              service.CommandScope
	Projection         service.SiteProjection
	Withdraw           bool
	ApplicationRoot    string
	DocumentRoot       string
	Indexes            []string
	PHPProfileRef      webengine.ResourceRef
	ResourceProfileRef webengine.ResourceRef
	LogPolicyRef       webengine.ResourceRef
	RootGeneration     uint64
	PoolGeneration     uint64
	MaxConnections     uint32
	TLS                []TLSInput
}

type Plan struct {
	Engine             NodeEngine
	SnapshotGeneration uint64
	Sites              []SiteInput
	DefaultTLS         *TLSInput
}

type Result struct {
	Desired  webengine.DesiredState
	Snapshot native.RuntimeSnapshot
	Digest   string
}

func Compose(plan Plan) (Result, error) {
	if plan.SnapshotGeneration == 0 {
		return Result{}, errors.New("snapshot generation is required")
	}
	if plan.Engine.Edition != webengine.EditionOpenLiteSpeed && plan.Engine.Edition != webengine.EditionLiteSpeedEnterprise {
		return Result{}, errors.New("supported engine edition is required")
	}
	listeners := append([]ListenerInput(nil), plan.Engine.Listeners...)
	for i := range listeners {
		listeners[i].Addresses = append([]string(nil), listeners[i].Addresses...)
		listeners[i].Protocols = append([]webengine.Protocol(nil), listeners[i].Protocols...)
		sort.Strings(listeners[i].Addresses)
		sort.Slice(listeners[i].Protocols, func(left, right int) bool {
			return listeners[i].Protocols[left] < listeners[i].Protocols[right]
		})
	}
	sort.Slice(listeners, func(i, j int) bool { return listeners[i].Ref < listeners[j].Ref })
	if len(listeners) == 0 {
		return Result{}, errors.New("at least one listener is required")
	}
	hasTLS := false
	for _, listener := range listeners {
		if listener.TLSMode == webengine.TLSModeTLS {
			hasTLS = true
		}
	}
	if hasTLS && plan.DefaultTLS == nil {
		return Result{}, errors.New("TLS listeners require a system default TLS material")
	}
	if plan.DefaultTLS != nil && plan.DefaultTLS.OwnerScope != (service.CommandScope{}) {
		return Result{}, errors.New("system default TLS material must not have a tenant owner")
	}

	const systemSite = webengine.ResourceRef("site/system-default")
	const systemIdentity = webengine.ResourceRef("identity/system-default")
	const systemApp = webengine.ResourceRef("application/system-default")
	const systemBinding = webengine.ResourceRef("binding/system-default")
	defaultPolicy := webengine.ResourceRef("tls/system-default")
	if plan.DefaultTLS != nil && plan.DefaultTLS.PolicyRef != "" {
		defaultPolicy = plan.DefaultTLS.PolicyRef
	}
	desired := webengine.DesiredState{Engine: webengine.WebEngineSpec{Edition: plan.Engine.Edition}}
	if plan.Engine.Edition == webengine.EditionLiteSpeedEnterprise {
		desired.Engine.EnterpriseLicense = &webengine.EnterpriseLicenseExpectation{ExpectedState: webengine.LicenseTrial}
	}
	snapshot := native.RuntimeSnapshot{Generation: plan.SnapshotGeneration}
	snapshot.Sites = append(snapshot.Sites, native.SiteRuntime{SiteRef: systemSite, IdentityRef: systemIdentity, SiteKey: "system-default", RootGeneration: 1})
	desired.Applications = append(desired.Applications, webengine.WebApplicationSpec{Ref: systemApp, SiteRef: systemSite, IdentityRef: systemIdentity, ApplicationRoot: "system", DocumentRoot: "system/public", Indexes: []string{"index.html"}, PHPProfileRef: "php/system", ResourceProfileRef: "resource/system", LogPolicyRef: "logs/system"})
	listenerRefs := make([]webengine.ResourceRef, len(listeners))
	for i, listener := range listeners {
		listenerRefs[i] = listener.Ref
		desired.Engine.Listeners = append(desired.Engine.Listeners, webengine.Listener{Ref: listener.Ref, Addresses: append([]string(nil), listener.Addresses...), Port: listener.Port, TLSMode: listener.TLSMode, Protocols: append([]webengine.Protocol(nil), listener.Protocols...), DefaultBindingRef: systemBinding})
	}
	systemPolicy := webengine.ResourceRef("")
	if hasTLS {
		systemPolicy = defaultPolicy
	}
	desired.Bindings = append(desired.Bindings, webengine.WebBindingSpec{Ref: systemBinding, ApplicationRef: systemApp, Hostnames: []webengine.Hostname{mustHostname("default.invalid")}, ListenerRefs: append([]webengine.ResourceRef(nil), listenerRefs...), TLSPolicyRef: systemPolicy, Relationship: webengine.BindingPrimary, RoutingState: webengine.RoutingMaintenance})
	if plan.DefaultTLS != nil {
		snapshot.TLSMaterials = append(snapshot.TLSMaterials, native.TLSMaterial{PolicyRef: defaultPolicy, SiteRef: systemSite, IdentityRef: systemIdentity, MaterialKey: plan.DefaultTLS.MaterialKey, Generation: plan.DefaultTLS.Generation})
	}
	usedTLSPolicies := make(map[webengine.ResourceRef]struct{})
	if hasTLS {
		usedTLSPolicies[defaultPolicy] = struct{}{}
	}

	sites := append([]SiteInput(nil), plan.Sites...)
	sort.Slice(sites, func(i, j int) bool { return siteToken(sites[i]) < siteToken(sites[j]) })
	for _, input := range sites {
		if input.Withdraw || input.Projection.Lifecycle == site.LifecyclePurging || input.Projection.Lifecycle == site.LifecycleDeleted {
			continue
		}
		token := siteToken(input)
		siteRef := webengine.ResourceRef("site/" + token)
		identityRef := webengine.ResourceRef("identity/" + token)
		applicationRef := webengine.ResourceRef("application/" + token)
		if input.RootGeneration == 0 || input.PoolGeneration == 0 || input.MaxConnections == 0 {
			return Result{}, fmt.Errorf("site %s has incomplete runtime generations", token)
		}
		snapshot.Sites = append(snapshot.Sites, native.SiteRuntime{SiteRef: siteRef, IdentityRef: identityRef, SiteKey: native.SiteKey(token), RootGeneration: input.RootGeneration})
		desired.Applications = append(desired.Applications, webengine.WebApplicationSpec{Ref: applicationRef, SiteRef: siteRef, IdentityRef: identityRef, ApplicationRoot: input.ApplicationRoot, DocumentRoot: input.DocumentRoot, Indexes: append([]string(nil), input.Indexes...), PHPProfileRef: input.PHPProfileRef, ResourceProfileRef: input.ResourceProfileRef, LogPolicyRef: input.LogPolicyRef})
		snapshot.LSAPIPools = append(snapshot.LSAPIPools, native.LSAPIPool{SiteRef: siteRef, IdentityRef: identityRef, PHPProfileRef: input.PHPProfileRef, PoolKey: native.PoolKey("pool-" + token), Generation: input.PoolGeneration, MaxConnections: input.MaxConnections})
		policy := webengine.ResourceRef("")
		if hasTLS {
			if len(input.TLS) != 1 {
				return Result{}, fmt.Errorf("site %s requires exactly one owned TLS material", token)
			}
			material := input.TLS[0]
			if material.OwnerScope != input.Scope {
				return Result{}, fmt.Errorf("site %s does not own its TLS material", token)
			}
			policy = material.PolicyRef
			if !safeResourceRef(policy) || material.MaterialKey == "" || material.Generation == 0 {
				return Result{}, fmt.Errorf("site %s has invalid TLS material", token)
			}
			if _, exists := usedTLSPolicies[policy]; exists {
				return Result{}, fmt.Errorf("site %s reuses TLS policy %q", token, policy)
			}
			usedTLSPolicies[policy] = struct{}{}
			snapshot.TLSMaterials = append(snapshot.TLSMaterials, native.TLSMaterial{PolicyRef: policy, SiteRef: siteRef, IdentityRef: identityRef, MaterialKey: material.MaterialKey, Generation: material.Generation})
		}
		bindings := append([]site.DomainBinding(nil), input.Projection.Bindings...)
		sort.Slice(bindings, func(i, j int) bool { return bindings[i].Hostname.String() < bindings[j].Hostname.String() })
		for _, binding := range bindings {
			host, err := webengine.ParseHostname(binding.Hostname.String())
			if err != nil {
				return Result{}, err
			}
			ref := webengine.ResourceRef("binding/" + token + "-" + shortHash(binding.Hostname.String()))
			relationship, target, status, err := mapBinding(binding)
			if err != nil {
				return Result{}, err
			}
			desired.Bindings = append(desired.Bindings, webengine.WebBindingSpec{Ref: ref, ApplicationRef: applicationRef, Hostnames: []webengine.Hostname{host}, RedirectTarget: target, RedirectStatus: status, ListenerRefs: append([]webengine.ResourceRef(nil), listenerRefs...), TLSPolicyRef: policy, Relationship: relationship, RoutingState: routing(input.Projection.Lifecycle)})
		}
	}
	if findings := webengine.Validate(desired); len(findings) != 0 {
		return Result{}, fmt.Errorf("composed desired state invalid: %s at %s", findings[0].Code, findings[0].Path)
	}
	request := native.RenderRequest{Desired: desired, Snapshot: snapshot}
	if err := native.ValidateRequest(request, desired.Engine.Edition); err != nil {
		return Result{}, err
	}
	digest, err := resultDigest(desired, snapshot)
	if err != nil {
		return Result{}, err
	}
	return Result{Desired: desired, Snapshot: snapshot, Digest: digest}, nil
}

func routing(l site.Lifecycle) webengine.RoutingState {
	if l == site.LifecycleActive {
		return webengine.RoutingServe
	}
	if l == site.LifecycleSuspended {
		return webengine.RoutingSuspended
	}
	return webengine.RoutingMaintenance
}
func mapBinding(binding site.DomainBinding) (webengine.BindingRelationship, webengine.Hostname, webengine.RedirectStatus, error) {
	switch binding.Kind {
	case site.BindingPrimary, site.BindingChild:
		return webengine.BindingPrimary, webengine.Hostname{}, "", nil
	case site.BindingAlias:
		return webengine.BindingAlias, webengine.Hostname{}, "", nil
	case site.BindingPreview:
		return webengine.BindingPreview, webengine.Hostname{}, "", nil
	case site.BindingRedirect:
		target, err := webengine.ParseHostname(binding.RedirectTarget.String())
		if err != nil {
			return "", webengine.Hostname{}, "", fmt.Errorf("invalid redirect target: %w", err)
		}
		return webengine.BindingRedirect, target, webengine.RedirectStatus(binding.RedirectStatus), nil
	default:
		return "", webengine.Hostname{}, "", fmt.Errorf("unsupported site binding kind %q", binding.Kind)
	}
}

func safeResourceRef(ref webengine.ResourceRef) bool {
	value := string(ref)
	if len(value) < 3 || len(value) > 255 || value[0] == '/' || value[len(value)-1] == '/' {
		return false
	}
	segments := 1
	segmentLength := 0
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '/' {
			if segmentLength == 0 || segmentLength > 128 {
				return false
			}
			segments++
			segmentLength = 0
			continue
		}
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
		if segmentLength == 0 && !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')) {
			return false
		}
		segmentLength++
		if (index+1 == len(value) || value[index+1] == '/') && !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')) {
			return false
		}
	}
	return segments >= 2 && segmentLength > 0 && segmentLength <= 128
}
func mustHostname(raw string) webengine.Hostname {
	hostname, _ := webengine.ParseHostname(raw)
	return hostname
}
func siteToken(input SiteInput) string {
	source := input.Scope.TenantID.String() + "-" + input.Scope.SiteID.String()
	return "s-" + shortHash(source)
}
func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:24]
}
func resultDigest(desired webengine.DesiredState, snapshot native.RuntimeSnapshot) (string, error) {
	desiredDigest, err := desired.CanonicalDigest()
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(append([]byte("cyberpanel:composer:v1:"), []byte(desiredDigest)...), encoded...))
	return hex.EncodeToString(sum[:]), nil
}
