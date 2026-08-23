// Package native defines the closed boundary between engine-neutral desired
// state and edition-specific configuration renderers.
package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
)

var (
	ErrEditionMismatch     = errors.New("webengine renderer edition mismatch")
	ErrInvalidDesiredState = errors.New("invalid webengine desired state")
	ErrInvalidSnapshot     = errors.New("invalid webengine runtime snapshot")
	ErrInvalidGeneration   = errors.New("invalid native configuration generation")
)

// Renderer produces one complete, immutable native configuration generation.
// It never mutates live engine files or executes an activation command.
type Renderer interface {
	Edition() webengine.Edition
	Render(context.Context, RenderRequest) (ConfigGeneration, error)
}

// RenderRequest intentionally contains no native text, directive, executable,
// socket path, certificate path, or destination path supplied by its caller.
// Native identities and paths are derived from the registry snapshot below.
type RenderRequest struct {
	Desired  webengine.DesiredState
	Snapshot RuntimeSnapshot
}

// RuntimeSnapshot is the renderer's closed projection of registry-owned
// identities. Generations make every derived path immutable and replay-safe.
type RuntimeSnapshot struct {
	Generation   uint64
	Sites        []SiteRuntime
	LSAPIPools   []LSAPIPool
	TLSMaterials []TLSMaterial
	AccessVerifiers []AccessVerifier
}

type SiteKey string
type PoolKey string
type MaterialKey string
type VerifierKey string

type SiteRuntime struct {
	SiteRef        webengine.ResourceRef
	IdentityRef    webengine.ResourceRef
	SiteKey        SiteKey
	RootGeneration uint64
}

// HealthDocumentRoot is the immutable, root-owned attestation directory for a
// candidate site generation. Tenant-writable content is never used to prove
// engine activation.
func HealthDocumentRoot(site SiteRuntime) string {
	return "/var/lib/cyberpanel/site-health/" + string(site.SiteKey) + "/g" + strconv.FormatUint(site.RootGeneration, 10)
}

type LSAPIPool struct {
	SiteRef        webengine.ResourceRef
	IdentityRef    webengine.ResourceRef
	PHPProfileRef  webengine.ResourceRef
	PoolKey        PoolKey
	Generation     uint64
	MaxConnections uint32
}

type TLSMaterial struct {
	PolicyRef   webengine.ResourceRef
	SiteRef     webengine.ResourceRef
	IdentityRef webengine.ResourceRef
	MaterialKey MaterialKey
	Generation  uint64
}

type PasswordVerifier struct {
	PrincipalRef webengine.ResourceRef
	Username     string
	Digest       string
}

// AccessVerifier contains only one-way password verifiers. It may be sealed in
// durable generation state; plaintext credentials and secret broker references
// must never cross the renderer boundary.
type AccessVerifier struct {
	PolicyRef   webengine.ResourceRef
	BindingRef  webengine.ResourceRef
	SiteRef     webengine.ResourceRef
	IdentityRef webengine.ResourceRef
	VerifierKey VerifierKey
	Generation  uint64
	Principals  []PasswordVerifier
}

type GenerationKind string

const GenerationCompleteReplacement GenerationKind = "complete_replacement"

type ArtifactRole string

const (
	ArtifactServer             ArtifactRole = "server"
	ArtifactVirtualHost        ArtifactRole = "virtual_host"
	ArtifactCredentialVerifier ArtifactRole = "web_access_verifier"
)

type ArtifactKey string

// Artifact is a destination-independent native file. Stage owns the mapping
// from role/key to an edition- and release-qualified filesystem location.
type Artifact struct {
	Role    ArtifactRole
	Key     ArtifactKey
	Mode    fs.FileMode
	Content []byte
}

type ConfigGeneration struct {
	Edition            webengine.Edition
	Kind               GenerationKind
	DesiredDigest      string
	SnapshotGeneration uint64
	ContentDigest      string
	Artifacts          []Artifact
}

// ValidateRequest validates both the canonical model and all registry-owned
// identifiers without modifying either. Edition mismatch is checked first so
// one renderer can never reinterpret the other edition's state.
func ValidateRequest(request RenderRequest, edition webengine.Edition) error {
	if request.Desired.Engine.Edition != edition {
		return fmt.Errorf("%w: renderer=%s desired=%s", ErrEditionMismatch, edition, request.Desired.Engine.Edition)
	}
	if findings := webengine.Validate(request.Desired); len(findings) != 0 {
		return fmt.Errorf("%w: %s at %s", ErrInvalidDesiredState, findings[0].Code, findings[0].Path)
	}
	if err := validateDesiredStrings(request.Desired); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDesiredState, err)
	}
	if err := validateSnapshot(request); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
	}
	return nil
}

// NewCompleteGeneration sorts and copies artifacts, then binds their exact
// bytes and metadata to a domain-separated digest.
func NewCompleteGeneration(edition webengine.Edition, desiredDigest string, snapshotGeneration uint64, artifacts []Artifact) (ConfigGeneration, error) {
	if edition != webengine.EditionOpenLiteSpeed && edition != webengine.EditionLiteSpeedEnterprise {
		return ConfigGeneration{}, fmt.Errorf("%w: unknown edition %q", ErrInvalidGeneration, edition)
	}
	if !validSHA256(desiredDigest) {
		return ConfigGeneration{}, fmt.Errorf("%w: desired digest is not SHA-256", ErrInvalidGeneration)
	}
	if snapshotGeneration == 0 {
		return ConfigGeneration{}, fmt.Errorf("%w: snapshot generation must be non-zero", ErrInvalidGeneration)
	}

	ordered := make([]Artifact, len(artifacts))
	for index, artifact := range artifacts {
		ordered[index] = artifact
		ordered[index].Content = append([]byte(nil), artifact.Content...)
	}
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].Role != ordered[right].Role {
			return ordered[left].Role < ordered[right].Role
		}
		return ordered[left].Key < ordered[right].Key
	})
	if len(ordered) == 0 || ordered[0].Role != ArtifactServer || ordered[0].Key != ArtifactKey("engine") {
		return ConfigGeneration{}, fmt.Errorf("%w: complete generation requires server:engine", ErrInvalidGeneration)
	}
	for index, artifact := range ordered {
		if artifact.Role != ArtifactServer && artifact.Role != ArtifactVirtualHost && artifact.Role != ArtifactCredentialVerifier {
			return ConfigGeneration{}, fmt.Errorf("%w: artifact %d has unknown role", ErrInvalidGeneration, index)
		}
		if !validRegistryKey(string(artifact.Key)) || artifact.Mode != 0o600 || len(artifact.Content) == 0 {
			return ConfigGeneration{}, fmt.Errorf("%w: artifact %d has invalid key, mode, or content", ErrInvalidGeneration, index)
		}
		if index > 0 && artifact.Role == ordered[index-1].Role && artifact.Key == ordered[index-1].Key {
			return ConfigGeneration{}, fmt.Errorf("%w: duplicate artifact %s:%s", ErrInvalidGeneration, artifact.Role, artifact.Key)
		}
	}

	digest := sha256.New()
	writeDigestPart(digest, []byte("cyberpanel:webengine:native-generation:v2"))
	writeDigestPart(digest, []byte(edition))
	writeDigestPart(digest, []byte(GenerationCompleteReplacement))
	writeDigestPart(digest, []byte(desiredDigest))
	var snapshot [8]byte
	binary.BigEndian.PutUint64(snapshot[:], snapshotGeneration)
	writeDigestPart(digest, snapshot[:])
	for _, artifact := range ordered {
		writeDigestPart(digest, []byte(artifact.Role))
		writeDigestPart(digest, []byte(artifact.Key))
		var mode [4]byte
		binary.BigEndian.PutUint32(mode[:], uint32(artifact.Mode.Perm()))
		writeDigestPart(digest, mode[:])
		writeDigestPart(digest, artifact.Content)
	}

	return ConfigGeneration{
		Edition:            edition,
		Kind:               GenerationCompleteReplacement,
		DesiredDigest:      desiredDigest,
		SnapshotGeneration: snapshotGeneration,
		ContentDigest:      hex.EncodeToString(digest.Sum(nil)),
		Artifacts:          ordered,
	}, nil
}

func validateDesiredStrings(desired webengine.DesiredState) error {
	for listenerIndex, listener := range desired.Engine.Listeners {
		if !validResourceRef(listener.Ref) || !validResourceRef(listener.DefaultBindingRef) {
			return fmt.Errorf("listener %d contains an unsafe reference", listenerIndex)
		}
	}
	for applicationIndex, application := range desired.Applications {
		for _, ref := range []webengine.ResourceRef{
			application.Ref,
			application.SiteRef,
			application.IdentityRef,
			application.PHPProfileRef,
			application.ResourceProfileRef,
			application.LogPolicyRef,
		} {
			if !validResourceRef(ref) {
				return fmt.Errorf("application %d contains an unsafe reference", applicationIndex)
			}
		}
		if !validRelativePath(application.ApplicationRoot) || !validRelativePath(application.DocumentRoot) {
			return fmt.Errorf("application %d contains an unsafe relative path", applicationIndex)
		}
		for indexIndex, index := range application.Indexes {
			if !validLeaf(index) {
				return fmt.Errorf("application %d index %d is unsafe", applicationIndex, indexIndex)
			}
		}
	}
	for bindingIndex, binding := range desired.Bindings {
		if !validResourceRef(binding.Ref) || !validResourceRef(binding.ApplicationRef) {
			return fmt.Errorf("binding %d contains an unsafe reference", bindingIndex)
		}
		if binding.TLSPolicyRef != "" && !validResourceRef(binding.TLSPolicyRef) {
			return fmt.Errorf("binding %d contains an unsafe TLS reference", bindingIndex)
		}
		for _, listenerRef := range binding.ListenerRefs {
			if !validResourceRef(listenerRef) {
				return fmt.Errorf("binding %d contains an unsafe listener reference", bindingIndex)
			}
		}
	}
	for policyIndex, policy := range desired.AccessPolicies {
		if !validResourceRef(policy.Ref) || !validResourceRef(policy.BindingRef) {
			return fmt.Errorf("access policy %d contains an unsafe reference", policyIndex)
		}
		for _, principal := range policy.PrincipalRefs {
			if !validResourceRef(principal) {
				return fmt.Errorf("access policy %d contains an unsafe principal reference", policyIndex)
			}
		}
	}
	return nil
}

func validateSnapshot(request RenderRequest) error {
	snapshot := request.Snapshot
	if snapshot.Generation == 0 {
		return errors.New("snapshot generation must be non-zero")
	}

	sites := make(map[webengine.ResourceRef]SiteRuntime, len(snapshot.Sites))
	siteKeys := make(map[SiteKey]struct{}, len(snapshot.Sites))
	identityOwners := make(map[webengine.ResourceRef]webengine.ResourceRef, len(snapshot.Sites))
	for index, site := range snapshot.Sites {
		if !validResourceRef(site.SiteRef) || !validResourceRef(site.IdentityRef) || !validRegistryKey(string(site.SiteKey)) || site.RootGeneration == 0 {
			return fmt.Errorf("site runtime %d is invalid", index)
		}
		if _, exists := sites[site.SiteRef]; exists {
			return fmt.Errorf("site runtime %d duplicates site reference", index)
		}
		if _, exists := siteKeys[site.SiteKey]; exists {
			return fmt.Errorf("site runtime %d duplicates site key", index)
		}
		if owner, exists := identityOwners[site.IdentityRef]; exists && owner != site.SiteRef {
			return fmt.Errorf("site runtime %d shares an identity across sites", index)
		}
		sites[site.SiteRef] = site
		siteKeys[site.SiteKey] = struct{}{}
		identityOwners[site.IdentityRef] = site.SiteRef
	}

	pools := make(map[string]LSAPIPool, len(snapshot.LSAPIPools))
	poolIdentities := make(map[string]struct{}, len(snapshot.LSAPIPools))
	for index, pool := range snapshot.LSAPIPools {
		if !validResourceRef(pool.SiteRef) || !validResourceRef(pool.IdentityRef) || !validResourceRef(pool.PHPProfileRef) || !validRegistryKey(string(pool.PoolKey)) || pool.Generation == 0 || pool.MaxConnections == 0 || pool.MaxConnections > 1_000_000 {
			return fmt.Errorf("LSAPI pool %d is invalid", index)
		}
		site, exists := sites[pool.SiteRef]
		if !exists || site.IdentityRef != pool.IdentityRef {
			return fmt.Errorf("LSAPI pool %d does not belong to its site identity", index)
		}
		lookup := poolLookup(pool.SiteRef, pool.PHPProfileRef)
		if _, exists := pools[lookup]; exists {
			return fmt.Errorf("LSAPI pool %d duplicates site and PHP profile", index)
		}
		identity := string(pool.PoolKey) + "\x00" + uint64Decimal(pool.Generation)
		if _, exists := poolIdentities[identity]; exists {
			return fmt.Errorf("LSAPI pool %d duplicates native identity", index)
		}
		pools[lookup] = pool
		poolIdentities[identity] = struct{}{}
	}

	materials := make(map[webengine.ResourceRef]TLSMaterial, len(snapshot.TLSMaterials))
	materialIdentities := make(map[string]struct{}, len(snapshot.TLSMaterials))
	for index, material := range snapshot.TLSMaterials {
		if !validResourceRef(material.PolicyRef) || !validResourceRef(material.SiteRef) || !validResourceRef(material.IdentityRef) || !validRegistryKey(string(material.MaterialKey)) || material.Generation == 0 {
			return fmt.Errorf("TLS material %d is invalid", index)
		}
		site, exists := sites[material.SiteRef]
		if !exists || site.IdentityRef != material.IdentityRef {
			return fmt.Errorf("TLS material %d does not belong to its site identity", index)
		}
		if _, exists := materials[material.PolicyRef]; exists {
			return fmt.Errorf("TLS material %d duplicates policy reference", index)
		}
		identity := string(material.MaterialKey) + "\x00" + uint64Decimal(material.Generation)
		if _, exists := materialIdentities[identity]; exists {
			return fmt.Errorf("TLS material %d duplicates native identity", index)
		}
		materials[material.PolicyRef] = material
		materialIdentities[identity] = struct{}{}
	}

	verifiers := make(map[webengine.ResourceRef]AccessVerifier, len(snapshot.AccessVerifiers))
	verifierIdentities := make(map[string]struct{}, len(snapshot.AccessVerifiers))
	for index, verifier := range snapshot.AccessVerifiers {
		if !validResourceRef(verifier.PolicyRef) || !validResourceRef(verifier.BindingRef) || !validResourceRef(verifier.SiteRef) || !validResourceRef(verifier.IdentityRef) || !validRegistryKey(string(verifier.VerifierKey)) || verifier.Generation == 0 || len(verifier.Principals) == 0 || len(verifier.Principals) > 128 {
			return fmt.Errorf("access verifier %d is invalid", index)
		}
		site, exists := sites[verifier.SiteRef]
		if !exists || site.IdentityRef != verifier.IdentityRef {
			return fmt.Errorf("access verifier %d does not belong to its site identity", index)
		}
		if _, exists := verifiers[verifier.PolicyRef]; exists {
			return fmt.Errorf("access verifier %d duplicates policy reference", index)
		}
		identity := string(verifier.VerifierKey) + "\x00" + uint64Decimal(verifier.Generation)
		if _, exists := verifierIdentities[identity]; exists {
			return fmt.Errorf("access verifier %d duplicates native identity", index)
		}
		seenPrincipals := make(map[webengine.ResourceRef]struct{}, len(verifier.Principals))
		seenUsernames := make(map[string]struct{}, len(verifier.Principals))
		for principalIndex, principal := range verifier.Principals {
			if !validResourceRef(principal.PrincipalRef) || !validVerifierUsername(principal.Username) || !validBcryptDigest(principal.Digest) {
				return fmt.Errorf("access verifier %d principal %d is invalid", index, principalIndex)
			}
			if _, exists := seenPrincipals[principal.PrincipalRef]; exists {
				return fmt.Errorf("access verifier %d duplicates principal reference", index)
			}
			if _, exists := seenUsernames[principal.Username]; exists {
				return fmt.Errorf("access verifier %d duplicates username", index)
			}
			seenPrincipals[principal.PrincipalRef] = struct{}{}
			seenUsernames[principal.Username] = struct{}{}
		}
		verifiers[verifier.PolicyRef] = verifier
		verifierIdentities[identity] = struct{}{}
	}

	applications := make(map[webengine.ResourceRef]webengine.WebApplicationSpec, len(request.Desired.Applications))
	for index, application := range request.Desired.Applications {
		site, exists := sites[application.SiteRef]
		if !exists || site.IdentityRef != application.IdentityRef {
			return fmt.Errorf("application %d does not resolve to its site identity", index)
		}
		applications[application.Ref] = application
	}
	listeners := make(map[webengine.ResourceRef]webengine.Listener, len(request.Desired.Engine.Listeners))
	for _, listener := range request.Desired.Engine.Listeners {
		listeners[listener.Ref] = listener
	}
	bindings := make(map[webengine.ResourceRef]webengine.WebBindingSpec, len(request.Desired.Bindings))
	for index, binding := range request.Desired.Bindings {
		bindings[binding.Ref] = binding
		application, exists := applications[binding.ApplicationRef]
		if !exists {
			return fmt.Errorf("binding %d does not resolve to an application", index)
		}
		if binding.RoutingState == webengine.RoutingServe && binding.Relationship != webengine.BindingRedirect && application.ReverseProxy==nil {
			if _, exists := pools[poolLookup(application.SiteRef, application.PHPProfileRef)]; !exists {
				return fmt.Errorf("binding %d has no LSAPI pool", index)
			}
		}
		if binding.TLSPolicyRef != "" {
			material, exists := materials[binding.TLSPolicyRef]
			site := sites[application.SiteRef]
			sharedPreviewMaterial := exists && binding.Relationship == webengine.BindingPreview && material.SiteRef == webengine.ResourceRef("site/system-default") && material.IdentityRef == webengine.ResourceRef("identity/system-default")
			if !exists || !sharedPreviewMaterial && (material.SiteRef != application.SiteRef || material.IdentityRef != site.IdentityRef) {
				return fmt.Errorf("binding %d has no owned TLS material", index)
			}
		}
		for _, listenerRef := range binding.ListenerRefs {
			if listener, exists := listeners[listenerRef]; exists && listener.TLSMode == webengine.TLSModeTLS {
				if _, exists := materials[binding.TLSPolicyRef]; !exists {
					return fmt.Errorf("binding %d has no TLS material", index)
				}
			}
		}
	}
	for index, policy := range request.Desired.AccessPolicies {
		if policy.State != webengine.AccessPolicyEnabled {
			if _, exists := verifiers[policy.Ref]; exists {
				return fmt.Errorf("disabled access policy %d has a native verifier", index)
			}
			continue
		}
		binding, exists := bindings[policy.BindingRef]
		if !exists {
			return fmt.Errorf("access policy %d does not resolve to a binding", index)
		}
		application, exists := applications[binding.ApplicationRef]
		if !exists {
			return fmt.Errorf("access policy %d does not resolve to an application", index)
		}
		verifier, exists := verifiers[policy.Ref]
		if !exists || verifier.BindingRef != policy.BindingRef || verifier.SiteRef != application.SiteRef || len(verifier.Principals) != len(policy.PrincipalRefs) {
			return fmt.Errorf("access policy %d has no owned verifier", index)
		}
		for principalIndex, principalRef := range policy.PrincipalRefs {
			if verifier.Principals[principalIndex].PrincipalRef != principalRef {
				return fmt.Errorf("access policy %d principal order does not match verifier", index)
			}
		}
	}
	for policyRef := range verifiers {
		found := false
		for _, policy := range request.Desired.AccessPolicies {
			if policy.Ref == policyRef && policy.State == webengine.AccessPolicyEnabled {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("access verifier has no enabled policy")
		}
	}
	return nil
}

func validVerifierUsername(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '-' || value[0] == '.' {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' || character == '@') {
			return false
		}
	}
	return true
}

func validBcryptDigest(value string) bool {
	if len(value) != 60 || !(strings.HasPrefix(value, "$2a$12$") || strings.HasPrefix(value, "$2b$12$") || strings.HasPrefix(value, "$2y$12$")) {
		return false
	}
	for index := 7; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '/') {
			return false
		}
	}
	return true
}

func validResourceRef(ref webengine.ResourceRef) bool {
	value := string(ref)
	if value == "" || len(value) > 255 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if !validRegistryKey(segment) || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validRegistryKey(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 127 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validRelativePath(value string) bool {
	if value == "" || len(value) > 1024 || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '/' && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validLeaf(value string) bool {
	if value == "" || len(value) > 255 || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func poolLookup(siteRef, profileRef webengine.ResourceRef) string {
	return string(siteRef) + "\x00" + string(profileRef)
}

func writeDigestPart(digest interface{ Write([]byte) (int, error) }, part []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(part)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(part)
}

func uint64Decimal(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte(value%10) + '0'
		value /= 10
	}
	return string(buffer[position:])
}
