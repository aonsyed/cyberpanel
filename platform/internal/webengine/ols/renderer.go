// Package ols renders complete OpenLiteSpeed native text configurations from
// the engine-neutral desired model.
package ols

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

type Renderer struct{}

func New() *Renderer { return &Renderer{} }

func (*Renderer) Edition() webengine.Edition { return webengine.EditionOpenLiteSpeed }

func (renderer *Renderer) Render(ctx context.Context, request native.RenderRequest) (native.ConfigGeneration, error) {
	if err := ctx.Err(); err != nil {
		return native.ConfigGeneration{}, err
	}
	if err := native.ValidateRequest(request, renderer.Edition()); err != nil {
		return native.ConfigGeneration{}, err
	}

	desiredDigest, err := request.Desired.CanonicalDigest()
	if err != nil {
		return native.ConfigGeneration{}, fmt.Errorf("canonical desired state: %w", err)
	}
	index := newRenderIndex(request)
	bindings := sortedBindings(request.Desired.Bindings)
	if err := validateDerivedIdentities(bindings, index); err != nil {
		return native.ConfigGeneration{}, err
	}

	artifacts := make([]native.Artifact, 0, len(bindings)+1)
	artifacts = append(artifacts, native.Artifact{
		Role:    native.ArtifactServer,
		Key:     "engine",
		Mode:    0o600,
		Content: renderServer(request, index, bindings),
	})
	for _, binding := range bindings {
		application := index.applications[binding.ApplicationRef]
		site := index.sites[application.SiteRef]
		artifacts = append(artifacts, native.Artifact{
			Role:    native.ArtifactVirtualHost,
			Key:     artifactKey(site, binding),
			Mode:    0o600,
			Content: renderVirtualHost(request, index, application, site, binding),
		})
	}

	return native.NewCompleteGeneration(renderer.Edition(), desiredDigest, artifacts)
}

type renderIndex struct {
	applications map[webengine.ResourceRef]webengine.WebApplicationSpec
	bindings     map[webengine.ResourceRef]webengine.WebBindingSpec
	sites        map[webengine.ResourceRef]native.SiteRuntime
	pools        map[string]native.LSAPIPool
	materials    map[webengine.ResourceRef]native.TLSMaterial
}

func newRenderIndex(request native.RenderRequest) renderIndex {
	index := renderIndex{
		applications: make(map[webengine.ResourceRef]webengine.WebApplicationSpec, len(request.Desired.Applications)),
		bindings:     make(map[webengine.ResourceRef]webengine.WebBindingSpec, len(request.Desired.Bindings)),
		sites:        make(map[webengine.ResourceRef]native.SiteRuntime, len(request.Snapshot.Sites)),
		pools:        make(map[string]native.LSAPIPool, len(request.Snapshot.LSAPIPools)),
		materials:    make(map[webengine.ResourceRef]native.TLSMaterial, len(request.Snapshot.TLSMaterials)),
	}
	for _, application := range request.Desired.Applications {
		index.applications[application.Ref] = application
	}
	for _, binding := range request.Desired.Bindings {
		index.bindings[binding.Ref] = binding
	}
	for _, site := range request.Snapshot.Sites {
		index.sites[site.SiteRef] = site
	}
	for _, pool := range request.Snapshot.LSAPIPools {
		index.pools[poolLookup(pool.SiteRef, pool.PHPProfileRef)] = pool
	}
	for _, material := range request.Snapshot.TLSMaterials {
		index.materials[material.PolicyRef] = material
	}
	return index
}

func renderServer(request native.RenderRequest, index renderIndex, bindings []webengine.WebBindingSpec) []byte {
	var output strings.Builder
	output.WriteString("# CyberPanel managed complete OpenLiteSpeed generation\n")
	output.WriteString("serverName cyberpanel-managed\n")
	output.WriteString("showVersionNumber 0\n")
	output.WriteString("autoLoadHtaccess 0\n\n")

	for _, binding := range bindings {
		application := index.applications[binding.ApplicationRef]
		site := index.sites[application.SiteRef]
		output.WriteString("virtualHost ")
		output.WriteString(vhostName(site, binding))
		output.WriteString(" {\n")
		output.WriteString("  vhRoot ")
		output.WriteString(siteRoot(site))
		output.WriteByte('\n')
		output.WriteString("  configFile $SERVER_ROOT/conf/vhosts/")
		output.WriteString(string(artifactKey(site, binding)))
		output.WriteString("/vhost.conf\n")
		output.WriteString("  allowSymbolLink 0\n")
		if servesApplication(binding) {
			output.WriteString("  enableScript 1\n")
		} else {
			output.WriteString("  enableScript 0\n")
		}
		output.WriteString("  restrained 1\n")
		output.WriteString("}\n\n")
	}

	listeners := append([]webengine.Listener(nil), request.Desired.Engine.Listeners...)
	sort.Slice(listeners, func(left, right int) bool { return listeners[left].Ref < listeners[right].Ref })
	listenerNames := nativeListenerNames(listeners)
	for _, listener := range listeners {
		addresses := sortedAddresses(listener.Addresses)
		ipv4Count := 0
		ipv6Count := 0
		for _, address := range addresses {
			parsed := netip.MustParseAddr(address)
			physicalName := listenerName(listener.Ref, parsed.Is6(), &ipv4Count, &ipv6Count, listenerNames)
			output.WriteString("listener ")
			output.WriteString(physicalName)
			output.WriteString(" {\n")
			output.WriteString("  address ")
			output.WriteString(nativeAddress(parsed, listener.Port))
			output.WriteByte('\n')
			if listener.TLSMode == webengine.TLSModeTLS {
				output.WriteString("  secure 1\n")
				defaultBinding := index.bindings[listener.DefaultBindingRef]
				material := index.materials[defaultBinding.TLSPolicyRef]
				keyFile, certFile := tlsFiles(request.Snapshot.Generation, material)
				output.WriteString("  keyFile ")
				output.WriteString(keyFile)
				output.WriteByte('\n')
				output.WriteString("  certFile ")
				output.WriteString(certFile)
				output.WriteString("\n  certChain 1\n")
			} else {
				output.WriteString("  secure 0\n")
			}
			if hasProtocol(listener.Protocols, webengine.ProtocolHTTP2) {
				output.WriteString("  enableSpdy 15\n")
			}
			if hasProtocol(listener.Protocols, webengine.ProtocolHTTP3) {
				output.WriteString("  enableQuic 1\n")
			}
			for _, binding := range bindings {
				if !containsRef(binding.ListenerRefs, listener.Ref) {
					continue
				}
				application := index.applications[binding.ApplicationRef]
				site := index.sites[application.SiteRef]
				output.WriteString("  map ")
				output.WriteString(vhostName(site, binding))
				output.WriteByte(' ')
				output.WriteString(joinHostnames(binding.Hostnames))
				output.WriteByte('\n')
			}
			output.WriteString("}\n\n")
		}
	}
	return []byte(output.String())
}

func renderVirtualHost(request native.RenderRequest, index renderIndex, application webengine.WebApplicationSpec, site native.SiteRuntime, binding webengine.WebBindingSpec) []byte {
	var output strings.Builder
	output.WriteString("# CyberPanel managed OpenLiteSpeed virtual host\n")
	output.WriteString("docRoot ")
	if servesApplication(binding) {
		output.WriteString(siteRoot(site))
		output.WriteByte('/')
		output.WriteString(application.DocumentRoot)
	} else {
		output.WriteString(systemContentRoot(binding))
	}
	output.WriteByte('\n')
	hostnames := sortedHostnames(binding.Hostnames)
	output.WriteString("vhDomain ")
	output.WriteString(hostnames[0])
	output.WriteByte('\n')
	if len(hostnames) > 1 {
		output.WriteString("vhAliases ")
		output.WriteString(strings.Join(hostnames[1:], ", "))
		output.WriteByte('\n')
	}
	output.WriteString("enableGzip 1\n\n")

	output.WriteString("index {\n")
	output.WriteString("  useServer 0\n")
	output.WriteString("  indexFiles ")
	output.WriteString(strings.Join(application.Indexes, ", "))
	output.WriteString("\n  autoIndex 0\n}\n\n")

	if binding.TLSPolicyRef != "" {
		material := index.materials[binding.TLSPolicyRef]
		keyFile, certFile := tlsFiles(request.Snapshot.Generation, material)
		output.WriteString("vhssl {\n")
		output.WriteString("  keyFile ")
		output.WriteString(keyFile)
		output.WriteByte('\n')
		output.WriteString("  certFile ")
		output.WriteString(certFile)
		output.WriteString("\n  certChain 1\n  renegProtection 1\n  sslSessionCache 1\n}\n\n")
	}

	switch {
	case binding.RoutingState == webengine.RoutingMaintenance || binding.RoutingState == webengine.RoutingSuspended:
		output.WriteString("context / {\n")
		output.WriteString("  type static\n")
		output.WriteString("  location ")
		output.WriteString(systemContentRoot(binding))
		output.WriteString("\n  allowBrowse 1\n  addDefaultCharset off\n}\n")
	case binding.Relationship == webengine.BindingRedirect:
		output.WriteString("context / {\n")
		output.WriteString("  type redirect\n")
		output.WriteString("  location https://")
		output.WriteString(binding.RedirectTarget.String())
		output.WriteString("/\n  externalRedirect 1\n  statusCode ")
		output.WriteString(redirectCode(binding.RedirectStatus))
		output.WriteString("\n}\n")
	default:
		pool := index.pools[poolLookup(application.SiteRef, application.PHPProfileRef)]
		poolName := lsapiName(pool)
		output.WriteString("scripthandler {\n")
		output.WriteString("  add lsapi:")
		output.WriteString(poolName)
		output.WriteString(" php\n}\n\n")
		output.WriteString("extprocessor ")
		output.WriteString(poolName)
		output.WriteString(" {\n")
		output.WriteString("  type lsapi\n")
		output.WriteString("  address UDS://")
		output.WriteString(lsapiSocket(site, pool))
		output.WriteByte('\n')
		output.WriteString("  maxConns ")
		output.WriteString(strconv.FormatUint(uint64(pool.MaxConnections), 10))
		output.WriteString("\n  initTimeout 60\n  retryTimeout 0\n  persistConn 1\n  respBuffer 0\n  autoStart 0\n}\n")
	}
	return []byte(output.String())
}

func validateDerivedIdentities(bindings []webengine.WebBindingSpec, index renderIndex) error {
	artifacts := make(map[native.ArtifactKey]struct{}, len(bindings))
	names := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		application := index.applications[binding.ApplicationRef]
		site := index.sites[application.SiteRef]
		key := artifactKey(site, binding)
		name := vhostName(site, binding)
		if _, exists := artifacts[key]; exists {
			return fmt.Errorf("%w: virtual-host artifact identity collision", native.ErrInvalidDesiredState)
		}
		if _, exists := names[name]; exists {
			return fmt.Errorf("%w: virtual-host native name collision", native.ErrInvalidDesiredState)
		}
		artifacts[key] = struct{}{}
		names[name] = struct{}{}
	}
	return nil
}

func sortedBindings(bindings []webengine.WebBindingSpec) []webengine.WebBindingSpec {
	ordered := append([]webengine.WebBindingSpec(nil), bindings...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Ref < ordered[right].Ref })
	return ordered
}

func sortedAddresses(addresses []string) []string {
	ordered := append([]string(nil), addresses...)
	sort.Slice(ordered, func(left, right int) bool {
		leftAddress := netip.MustParseAddr(ordered[left])
		rightAddress := netip.MustParseAddr(ordered[right])
		if leftAddress.Is6() != rightAddress.Is6() {
			return !leftAddress.Is6()
		}
		return leftAddress.Compare(rightAddress) < 0
	})
	return ordered
}

func sortedHostnames(hostnames []webengine.Hostname) []string {
	ordered := make([]string, len(hostnames))
	for index, hostname := range hostnames {
		ordered[index] = hostname.String()
	}
	sort.Strings(ordered)
	return ordered
}

func joinHostnames(hostnames []webengine.Hostname) string {
	return strings.Join(sortedHostnames(hostnames), ", ")
}

const maxNativeListenerNameLength = 63

type physicalListenerIdentity struct {
	ref   webengine.ResourceRef
	ipv6  bool
	index int
}

func nativeListenerNames(listeners []webengine.Listener) map[physicalListenerIdentity]string {
	ordered := append([]webengine.Listener(nil), listeners...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Ref < ordered[right].Ref })

	identities := make([]physicalListenerIdentity, 0)
	candidates := make(map[physicalListenerIdentity]string)
	candidateCounts := make(map[string]int)
	for _, listener := range ordered {
		ipv4Count := 0
		ipv6Count := 0
		for _, address := range sortedAddresses(listener.Addresses) {
			ipv6 := netip.MustParseAddr(address).Is6()
			index := 0
			if ipv6 {
				ipv6Count++
				index = ipv6Count
			} else {
				ipv4Count++
				index = ipv4Count
			}
			identity := physicalListenerIdentity{ref: listener.Ref, ipv6: ipv6, index: index}
			candidate := listenerNameCandidate(identity)
			identities = append(identities, identity)
			candidates[identity] = candidate
			candidateCounts[candidate]++
		}
	}

	names := make(map[physicalListenerIdentity]string, len(identities))
	reserved := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		candidate := candidates[identity]
		if candidateCounts[candidate] == 1 && len(candidate) <= maxNativeListenerNameLength {
			names[identity] = candidate
			reserved[candidate] = struct{}{}
		}
	}

	used := make(map[string]struct{}, len(identities))
	for name := range reserved {
		used[name] = struct{}{}
	}
	for _, identity := range identities {
		if _, exists := names[identity]; exists {
			continue
		}
		for ordinal := 1; ; ordinal++ {
			name := disambiguatedListenerName(candidates[identity], identity, ordinal)
			if _, exists := used[name]; exists {
				continue
			}
			names[identity] = name
			used[name] = struct{}{}
			break
		}
	}
	return names
}

func listenerName(ref webengine.ResourceRef, ipv6 bool, ipv4Count, ipv6Count *int, names map[physicalListenerIdentity]string) string {
	index := 0
	if ipv6 {
		(*ipv6Count)++
		index = *ipv6Count
	} else {
		(*ipv4Count)++
		index = *ipv4Count
	}
	return names[physicalListenerIdentity{ref: ref, ipv6: ipv6, index: index}]
}

func listenerNameCandidate(identity physicalListenerIdentity) string {
	base := hyphenName(string(identity.ref))
	if identity.ipv6 {
		if identity.index == 1 {
			return base + "-ipv6"
		}
		return base + "-ipv6-" + strconv.Itoa(identity.index)
	}
	if identity.index == 1 {
		return base
	}
	return base + "-ipv4-" + strconv.Itoa(identity.index)
}

func disambiguatedListenerName(prefix string, identity physicalListenerIdentity, ordinal int) string {
	family := "ipv4"
	if identity.ipv6 {
		family = "ipv6"
	}
	digest := sha256.Sum256([]byte(string(identity.ref) + "\x00" + family + "\x00" + strconv.Itoa(identity.index)))
	hash := fmt.Sprintf("%x", digest[:12])
	disambiguator := ""
	if ordinal > 1 {
		disambiguator = "-" + strconv.Itoa(ordinal)
	}
	maxPrefixLength := maxNativeListenerNameLength - 1 - len(hash) - len(disambiguator)
	if len(prefix) > maxPrefixLength {
		prefix = prefix[:maxPrefixLength]
	}
	prefix = strings.TrimRight(prefix, "-")
	if prefix == "" {
		prefix = "listener"
	}
	return prefix + "-" + hash + disambiguator
}

func nativeAddress(address netip.Addr, port uint16) string {
	if address.Is6() {
		return "[" + address.String() + "]:" + strconv.Itoa(int(port))
	}
	return address.String() + ":" + strconv.Itoa(int(port))
}

func artifactKey(site native.SiteRuntime, binding webengine.WebBindingSpec) native.ArtifactKey {
	return native.ArtifactKey(string(site.SiteKey) + "--" + hyphenName(string(binding.Ref)))
}

func vhostName(site native.SiteRuntime, binding webengine.WebBindingSpec) string {
	return "vh_" + underscoreName(string(site.SiteKey)) + "_" + underscoreName(string(binding.Ref))
}

func siteRoot(site native.SiteRuntime) string {
	return "/var/lib/cyberpanel/sites/" + string(site.SiteKey) + "/roots/g" + strconv.FormatUint(site.RootGeneration, 10)
}

func lsapiName(pool native.LSAPIPool) string {
	return underscoreName(string(pool.PoolKey)) + "_g" + strconv.FormatUint(pool.Generation, 10)
}

func lsapiSocket(site native.SiteRuntime, pool native.LSAPIPool) string {
	return "/run/cyberpanel/site-runtime/" + string(site.SiteKey) + "/php/" + string(pool.PoolKey) + "/g" + strconv.FormatUint(pool.Generation, 10) + ".sock"
}

func tlsFiles(generation uint64, material native.TLSMaterial) (string, string) {
	base := "/var/lib/cyberpanel/webengine/generations/g" + strconv.FormatUint(generation, 10) + "/tls/" + string(material.MaterialKey) + "/g" + strconv.FormatUint(material.Generation, 10)
	return base + "/privkey.pem", base + "/fullchain.pem"
}

func systemContentRoot(binding webengine.WebBindingSpec) string {
	if binding.RoutingState == webengine.RoutingSuspended {
		return "$SERVER_ROOT/panel/system/suspended"
	}
	return "$SERVER_ROOT/panel/system/maintenance"
}

func servesApplication(binding webengine.WebBindingSpec) bool {
	return binding.RoutingState == webengine.RoutingServe && binding.Relationship != webengine.BindingRedirect
}

func redirectCode(status webengine.RedirectStatus) string {
	if status == webengine.RedirectStatusTemporary302 {
		return "302"
	}
	return "301"
}

func hasProtocol(protocols []webengine.Protocol, target webengine.Protocol) bool {
	for _, protocol := range protocols {
		if protocol == target {
			return true
		}
	}
	return false
}

func containsRef(refs []webengine.ResourceRef, target webengine.ResourceRef) bool {
	for _, ref := range refs {
		if ref == target {
			return true
		}
	}
	return false
}

func poolLookup(siteRef, profileRef webengine.ResourceRef) string {
	return string(siteRef) + "\x00" + string(profileRef)
}

func hyphenName(value string) string {
	return mapName(value, '-')
}

func underscoreName(value string) string {
	return mapName(value, '_')
}

func mapName(value string, separator byte) string {
	var output strings.Builder
	output.Grow(len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			output.WriteByte(character)
		} else {
			output.WriteByte(separator)
		}
	}
	return output.String()
}
