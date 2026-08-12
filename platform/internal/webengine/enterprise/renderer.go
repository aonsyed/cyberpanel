// Package enterprise renders complete LiteSpeed Enterprise native XML
// configurations directly from engine-neutral desired state.
package enterprise

import (
	"context"
	"crypto/sha256"
	"encoding/xml"
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

func (*Renderer) Edition() webengine.Edition { return webengine.EditionLiteSpeedEnterprise }

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
	output.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	output.WriteString("<httpServerConfig>\n")
	writeElement(&output, 1, "serverName", "cyberpanel-managed")
	writeElement(&output, 1, "loadApacheConf", "0")
	writeElement(&output, 1, "autoReloadApacheConf", "0")
	writeElement(&output, 1, "showVersionNumber", "0")
	output.WriteString("  <virtualHostList>\n")
	for _, binding := range bindings {
		application := index.applications[binding.ApplicationRef]
		site := index.sites[application.SiteRef]
		output.WriteString("    <virtualHost>\n")
		writeElement(&output, 3, "name", vhostName(site, binding))
		writeElement(&output, 3, "vhRoot", siteRoot(site))
		writeElement(&output, 3, "configFile", "$SERVER_ROOT/conf/vhosts/"+string(artifactKey(site, binding))+"/vhconf.xml")
		writeElement(&output, 3, "allowSymbolLink", "0")
		if servesApplication(binding) {
			writeElement(&output, 3, "enableScript", "1")
		} else {
			writeElement(&output, 3, "enableScript", "0")
		}
		writeElement(&output, 3, "restrained", "1")
		writeElement(&output, 3, "setUIDMode", "0")
		writeElement(&output, 3, "chrootMode", "0")
		output.WriteString("    </virtualHost>\n")
	}
	output.WriteString("  </virtualHostList>\n")

	output.WriteString("  <listenerList>\n")
	listeners := append([]webengine.Listener(nil), request.Desired.Engine.Listeners...)
	sort.Slice(listeners, func(left, right int) bool { return listeners[left].Ref < listeners[right].Ref })
	listenerNames := nativeListenerNames(listeners)
	for _, listener := range listeners {
		ipv4Count := 0
		ipv6Count := 0
		for _, address := range sortedAddresses(listener.Addresses) {
			parsed := netip.MustParseAddr(address)
			output.WriteString("    <listener>\n")
			writeElement(&output, 3, "name", listenerName(listener.Ref, parsed.Is6(), &ipv4Count, &ipv6Count, listenerNames))
			writeElement(&output, 3, "address", nativeAddress(parsed, listener.Port))
			if listener.TLSMode == webengine.TLSModeTLS {
				writeElement(&output, 3, "secure", "1")
				defaultBinding := index.bindings[listener.DefaultBindingRef]
				material := index.materials[defaultBinding.TLSPolicyRef]
				keyFile, certFile := tlsFiles(request.Snapshot.Generation, material)
				writeElement(&output, 3, "keyFile", keyFile)
				writeElement(&output, 3, "certFile", certFile)
				writeElement(&output, 3, "certChain", "1")
			} else {
				writeElement(&output, 3, "secure", "0")
			}
			if hasProtocol(listener.Protocols, webengine.ProtocolHTTP2) {
				writeElement(&output, 3, "enableSpdy", "15")
			}
			if hasProtocol(listener.Protocols, webengine.ProtocolHTTP3) {
				writeElement(&output, 3, "enableQuic", "1")
			}
			output.WriteString("      <vhostMapList>\n")
			for _, binding := range bindings {
				if !containsRef(binding.ListenerRefs, listener.Ref) {
					continue
				}
				application := index.applications[binding.ApplicationRef]
				site := index.sites[application.SiteRef]
				name := vhostName(site, binding)
				domains := joinHostnames(binding.Hostnames)
				output.WriteString("        <vhostMap>\n")
				writeElement(&output, 5, "vhost", name)
				writeElement(&output, 5, "domain", domains)
				output.WriteString("        </vhostMap>\n")
			}
			output.WriteString("      </vhostMapList>\n")
			output.WriteString("    </listener>\n")
		}
	}
	output.WriteString("  </listenerList>\n")
	output.WriteString("</httpServerConfig>\n")
	return []byte(output.String())
}

func renderVirtualHost(request native.RenderRequest, index renderIndex, application webengine.WebApplicationSpec, site native.SiteRuntime, binding webengine.WebBindingSpec) []byte {
	var output strings.Builder
	output.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	output.WriteString("<virtualHostConfig>\n")
	if servesApplication(binding) {
		writeElement(&output, 1, "docRoot", siteRoot(site)+"/"+application.DocumentRoot)
	} else {
		writeElement(&output, 1, "docRoot", systemContentRoot(binding))
	}
	hostnames := sortedHostnames(binding.Hostnames)
	writeElement(&output, 1, "vhDomain", hostnames[0])
	if len(hostnames) > 1 {
		writeElement(&output, 1, "vhAliases", strings.Join(hostnames[1:], ", "))
	}
	writeElement(&output, 1, "enableGzip", "1")
	output.WriteString("  <index>\n")
	writeElement(&output, 2, "useServer", "0")
	writeElement(&output, 2, "indexFiles", strings.Join(application.Indexes, ", "))
	writeElement(&output, 2, "autoIndex", "0")
	output.WriteString("  </index>\n")

	if binding.TLSPolicyRef != "" {
		material := index.materials[binding.TLSPolicyRef]
		keyFile, certFile := tlsFiles(request.Snapshot.Generation, material)
		output.WriteString("  <vhssl>\n")
		writeElement(&output, 2, "keyFile", keyFile)
		writeElement(&output, 2, "certFile", certFile)
		writeElement(&output, 2, "certChain", "1")
		writeElement(&output, 2, "renegProtection", "1")
		writeElement(&output, 2, "sslSessionCache", "1")
		output.WriteString("  </vhssl>\n")
	}

	switch {
	case binding.RoutingState == webengine.RoutingMaintenance || binding.RoutingState == webengine.RoutingSuspended:
		output.WriteString("  <contextList>\n    <context>\n")
		writeElement(&output, 3, "type", "null")
		writeElement(&output, 3, "uri", "/")
		writeElement(&output, 3, "location", systemContentRoot(binding))
		writeElement(&output, 3, "allowBrowse", "1")
		output.WriteString("    </context>\n  </contextList>\n")
	case binding.Relationship == webengine.BindingRedirect:
		output.WriteString("  <contextList>\n    <context>\n")
		writeElement(&output, 3, "type", "redirect")
		writeElement(&output, 3, "uri", "/")
		writeElement(&output, 3, "location", "https://"+binding.RedirectTarget.String()+"/")
		writeElement(&output, 3, "externalRedirect", "1")
		writeElement(&output, 3, "statusCode", redirectCode(binding.RedirectStatus))
		output.WriteString("    </context>\n  </contextList>\n")
	default:
		pool := index.pools[poolLookup(application.SiteRef, application.PHPProfileRef)]
		poolName := lsapiName(pool)
		output.WriteString("  <scriptHandlerList>\n    <scriptHandler>\n")
		writeElement(&output, 3, "suffix", "php")
		writeElement(&output, 3, "type", "lsapi")
		writeElement(&output, 3, "handler", poolName)
		output.WriteString("    </scriptHandler>\n  </scriptHandlerList>\n")
		output.WriteString("  <extProcessorList>\n    <extProcessor>\n")
		writeElement(&output, 3, "type", "lsapi")
		writeElement(&output, 3, "name", poolName)
		writeElement(&output, 3, "address", "uds://"+lsapiSocket(site, pool))
		writeElement(&output, 3, "maxConns", strconv.FormatUint(uint64(pool.MaxConnections), 10))
		writeElement(&output, 3, "initTimeout", "60")
		writeElement(&output, 3, "retryTimeout", "0")
		writeElement(&output, 3, "persistConn", "1")
		writeElement(&output, 3, "respBuffer", "0")
		writeElement(&output, 3, "autoStart", "0")
		output.WriteString("    </extProcessor>\n  </extProcessorList>\n")
	}
	output.WriteString("</virtualHostConfig>\n")
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

func writeElement(output *strings.Builder, depth int, name, value string) {
	output.WriteString(strings.Repeat("  ", depth))
	output.WriteByte('<')
	output.WriteString(name)
	output.WriteByte('>')
	writeXMLText(output, value)
	output.WriteString("</")
	output.WriteString(name)
	output.WriteString(">\n")
}

func writeXMLText(output *strings.Builder, value string) {
	_ = xml.EscapeText(output, []byte(value))
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

func hyphenName(value string) string { return mapName(value, '-') }

func underscoreName(value string) string { return mapName(value, '_') }

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
