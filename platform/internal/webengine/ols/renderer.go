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

	artifacts := make([]native.Artifact, 0, len(bindings)+len(request.Snapshot.AccessVerifiers)+1)
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
	verifiers := append([]native.AccessVerifier(nil), request.Snapshot.AccessVerifiers...)
	sort.Slice(verifiers, func(i, j int) bool { return verifiers[i].PolicyRef < verifiers[j].PolicyRef })
	for _, verifier := range verifiers {
		artifacts = append(artifacts, native.Artifact{Role: native.ArtifactCredentialVerifier, Key: native.ArtifactKey(verifier.VerifierKey), Mode: 0o600, Content: renderAccessVerifier(verifier)})
	}

	return native.NewCompleteGeneration(renderer.Edition(), desiredDigest, request.Snapshot.Generation, artifacts)
}

type renderIndex struct {
	applications map[webengine.ResourceRef]webengine.WebApplicationSpec
	bindings     map[webengine.ResourceRef]webengine.WebBindingSpec
	sites        map[webengine.ResourceRef]native.SiteRuntime
	pools        map[string]native.LSAPIPool
	materials    map[webengine.ResourceRef]native.TLSMaterial
	policies     map[webengine.ResourceRef][]webengine.WebAccessPolicy
	verifiers    map[webengine.ResourceRef]native.AccessVerifier
}

func newRenderIndex(request native.RenderRequest) renderIndex {
	index := renderIndex{
		applications: make(map[webengine.ResourceRef]webengine.WebApplicationSpec, len(request.Desired.Applications)),
		bindings:     make(map[webengine.ResourceRef]webengine.WebBindingSpec, len(request.Desired.Bindings)),
		sites:        make(map[webengine.ResourceRef]native.SiteRuntime, len(request.Snapshot.Sites)),
		pools:        make(map[string]native.LSAPIPool, len(request.Snapshot.LSAPIPools)),
		materials:    make(map[webengine.ResourceRef]native.TLSMaterial, len(request.Snapshot.TLSMaterials)),
		policies:     make(map[webengine.ResourceRef][]webengine.WebAccessPolicy),
		verifiers:    make(map[webengine.ResourceRef]native.AccessVerifier, len(request.Snapshot.AccessVerifiers)),
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
	for _, policy := range request.Desired.AccessPolicies {
		index.policies[policy.BindingRef] = append(index.policies[policy.BindingRef], policy)
	}
	for bindingRef := range index.policies {
		sort.Slice(index.policies[bindingRef], func(i, j int) bool { return index.policies[bindingRef][i].Route < index.policies[bindingRef][j].Route })
	}
	for _, verifier := range request.Snapshot.AccessVerifiers {
		index.verifiers[verifier.PolicyRef] = verifier
	}
	return index
}

func nativeBool(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func nativeMemorySize(bytes uint64) string {
	return strconv.FormatUint(bytes/(1<<20), 10) + "M"
}

func renderServer(request native.RenderRequest, index renderIndex, bindings []webengine.WebBindingSpec) []byte {
	var output strings.Builder
	tuning := request.Desired.Engine.Tuning
	output.WriteString("# CyberPanel managed complete OpenLiteSpeed generation\n")
	output.WriteString("serverName cyberpanel-managed\n")
	output.WriteString("user cyberpanel-web\ngroup cyberpanel-web\ndisableWebAdmin 1\n")
	output.WriteString("mime $SERVER_ROOT/conf/mime.properties\n")
	// Match CyberPanel's native file-access policy. Unix ownership/modes and
	// per-vhost isolation remain authoritative; do not inherit vendor masks.
	output.WriteString("fileAccessControl {\n  requiredPermissionMask 000\n  restrictedPermissionMask 000\n}\n")
	output.WriteString("errorlog $SERVER_ROOT/logs/error.log {\n  logLevel WARN\n  rollingSize 10M\n  enableStderrLog 1\n}\n")
	output.WriteString("accesslog $SERVER_ROOT/logs/access.log {\n  rollingSize 10M\n  keepDays 30\n  compressArchive 1\n}\n")
	output.WriteString("showVersionNumber 0\n")
	output.WriteString("autoLoadHtaccess 0\n")
	if tuning.Generation != 0 {
		output.WriteString("httpdWorkers ")
		output.WriteString(strconv.FormatUint(uint64(tuning.WorkerProcesses), 10))
		output.WriteString("\n\ntuning {\n  maxConnections ")
		output.WriteString(strconv.FormatUint(uint64(tuning.MaxConnections), 10))
		output.WriteString("\n  maxSSLConnections ")
		output.WriteString(strconv.FormatUint(uint64(tuning.MaxTLSConnections), 10))
		output.WriteString("\n  connTimeout ")
		output.WriteString(strconv.FormatUint(uint64(tuning.ConnectionTimeoutSeconds), 10))
		output.WriteString("\n  maxKeepAliveReq ")
		output.WriteString(strconv.FormatUint(uint64(tuning.KeepAliveRequests), 10))
		output.WriteString("\n  keepAliveTimeout ")
		output.WriteString(strconv.FormatUint(uint64(tuning.KeepAliveTimeoutSeconds), 10))
		output.WriteString("\n  totalInMemCacheSize ")
		output.WriteString(nativeMemorySize(tuning.MemoryCacheBytes))
		output.WriteString("\n  enableGzipCompress ")
		output.WriteString(nativeBool(tuning.Compression))
		output.WriteString("\n  enableDynGzipCompress ")
		output.WriteString(nativeBool(tuning.Compression))
		if tuning.Compression {
			output.WriteString("\n  gzipCompressLevel ")
			output.WriteString(strconv.FormatUint(uint64(tuning.CompressionLevel), 10))
		}
		output.WriteString("\n}\n")
	}
	output.WriteByte('\n')
	output.WriteString("module mod_security {\n")
	output.WriteString("  ls_enabled 1\n")
	output.WriteString("  modsecurity on\n")
	output.WriteString("  modsecurity_rules_file /usr/local/lsws/conf/modsec/cyberpanel.conf\n")
	output.WriteString("}\n\n")

	for _, binding := range bindings {
		application := index.applications[binding.ApplicationRef]
		site := index.sites[application.SiteRef]
		output.WriteString("virtualHost ")
		output.WriteString(vhostName(site, binding))
		output.WriteString(" {\n")
		output.WriteString("  vhRoot ")
		output.WriteString(siteRoot(site))
		output.WriteByte('\n')
		output.WriteString("  configFile $SERVER_ROOT/conf/")
		output.WriteString(native.VirtualHostDirectory(request.Snapshot.Generation, artifactKey(site, binding), renderVirtualHost(request, index, application, site, binding)))
		output.WriteString("/vhost.conf\n")
		output.WriteString("  allowSymbolLink 0\n")
		if servesApplication(binding) {
			output.WriteString("  enableScript 1\n")
		} else {
			output.WriteString("  enableScript 0\n")
			// Product-owned static pages stay root-owned. Explicit execution
			// identity avoids deriving a privileged UID from their document root.
			output.WriteString("  user cyberpanel-web\n  group cyberpanel-web\n")
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
	compression := true
	if request.Desired.Engine.Tuning.Generation != 0 {
		compression = request.Desired.Engine.Tuning.Compression
	}
	output.WriteString("enableGzip ")
	output.WriteString(nativeBool(compression))
	output.WriteString("\n\n")
	if binding.Relationship == webengine.BindingPreview {
		output.WriteString("rewrite {\n  enable 1\n  rules <<<END_preview_rules\nRewriteCond %{HTTPS} !=on\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=308,L,NE]\n")
		if application.ReverseProxy != nil && application.ReverseProxy.HostHeader.String() != "" {
			output.WriteString("RewriteRule ^ - [E=Proxy-Host:")
			output.WriteString(application.ReverseProxy.HostHeader.String())
			output.WriteString("]\n")
		}
		output.WriteString("END_preview_rules\n}\n\n")
	}

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
	policies := index.policies[binding.Ref]
	for _, policy := range policies {
		verifier := index.verifiers[policy.Ref]
		output.WriteString("realm ")
		output.WriteString(accessRealmName(policy.Ref))
		output.WriteString(" {\n  userDB {\n    location ")
		output.WriteString(accessVerifierPath(request.Snapshot.Generation, verifier))
		output.WriteString("\n    maxCacheSize 1024\n    cacheTimeout 60\n  }\n}\n\n")
	}
	output.WriteString("context /.well-known/acme-challenge/ {\n")
	output.WriteString("  type static\n  location /var/lib/cyberpanel/acme/http-01\n  allowBrowse 1\n  autoIndex 0\n  addDefaultCharset off\n  rewrite {\n    enable 0\n  }\n}\n\n")
	output.WriteString("context /.well-known/panel-health/ {\n")
	output.WriteString("  type static\n  location ")
	output.WriteString(native.HealthDocumentRoot(site))
	output.WriteString("\n  allowBrowse 1\n  autoIndex 0\n  addDefaultCharset off\n  rewrite {\n    enable 0\n  }\n}\n\n")

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
	case application.ReverseProxy != nil:
		proxyName := proxyProcessorName(application.Ref)
		output.WriteString("extprocessor ")
		output.WriteString(proxyName)
		output.WriteString(" {\n  type proxy\n  address ")
		output.WriteString(netip.AddrPortFrom(application.ReverseProxy.Address, application.ReverseProxy.Port).String())
		output.WriteString("\n  maxConns 256\n  initTimeout 30\n  retryTimeout 0\n  respBuffer 0\n}\n\ncontext / {\n  type proxy\n  handler ")
		output.WriteString(proxyName)
		output.WriteString("\n  addDefaultCharset off\n")
		if policy, exists := accessPolicyAt(policies, "/"); exists {
			writeAccessDirectives(&output, policy, index.verifiers[policy.Ref])
		}
		output.WriteString("}\n")
		for _, policy := range policies {
			if policy.Route == "/" {
				continue
			}
			output.WriteString("\ncontext ")
			output.WriteString(policy.Route)
			output.WriteString(" {\n  type proxy\n  handler ")
			output.WriteString(proxyName)
			output.WriteByte('\n')
			writeAccessDirectives(&output, policy, index.verifiers[policy.Ref])
			output.WriteString("}\n")
		}
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
		for _, policy := range policies {
			output.WriteString("\ncontext ")
			output.WriteString(policy.Route)
			output.WriteString(" {\n  type null\n  location ")
			output.WriteString(siteRoot(site) + "/" + application.DocumentRoot)
			if policy.Route != "/" {
				output.WriteString(policy.Route)
			}
			output.WriteString("\n  allowBrowse 1\n")
			writeAccessDirectives(&output, policy, index.verifiers[policy.Ref])
			output.WriteString("}\n")
		}
	}
	return []byte(output.String())
}

func renderAccessVerifier(verifier native.AccessVerifier) []byte {
	principals := append([]native.PasswordVerifier(nil), verifier.Principals...)
	sort.Slice(principals, func(i, j int) bool { return principals[i].Username < principals[j].Username })
	var output strings.Builder
	for _, principal := range principals {
		output.WriteString(principal.Username)
		output.WriteByte(':')
		output.WriteString(principal.Digest)
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

func accessRealmName(ref webengine.ResourceRef) string {
	sum := sha256.Sum256([]byte(ref))
	return "panel_" + fmt.Sprintf("%x", sum[:10])
}
func accessVerifierPath(generation uint64, verifier native.AccessVerifier) string {
	return "$SERVER_ROOT/conf/vhosts/.panel-generations/g" + strconv.FormatUint(generation, 10) + "/access/" + string(verifier.VerifierKey) + ".users"
}
func accessPolicyAt(policies []webengine.WebAccessPolicy, route string) (webengine.WebAccessPolicy, bool) {
	for _, policy := range policies {
		if policy.Route == route {
			return policy, true
		}
	}
	return webengine.WebAccessPolicy{}, false
}
func writeAccessDirectives(output *strings.Builder, policy webengine.WebAccessPolicy, verifier native.AccessVerifier) {
	output.WriteString("  realm ")
	output.WriteString(accessRealmName(policy.Ref))
	output.WriteString("\n  authName ")
	output.WriteString(policy.Realm)
	output.WriteString("\n  required user")
	for _, principal := range verifier.Principals {
		output.WriteByte(' ')
		output.WriteString(principal.Username)
	}
	output.WriteByte('\n')
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
	_, _ = generation, material.Generation
	base := "/var/lib/cyberpanel/certificates/consumers/webengine/" + string(material.MaterialKey) + "/current"
	return base + "/private.key", base + "/fullchain.pem"
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

func proxyProcessorName(ref webengine.ResourceRef) string {
	digest := sha256.Sum256([]byte("cyberpanel:webengine-proxy:v1\x00" + string(ref)))
	return "proxy-" + fmt.Sprintf("%x", digest[:10])
}
