package apps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// SignedRecipeDocument is the only form accepted from an application catalog.
// CanonicalPayload is a release-produced canonical JSON representation. The
// verifier authenticates it before it is decoded, and the decoded definition
// must bind to the requested ID, version, epoch, and digest.
type SignedRecipeDocument struct {
	SchemaVersion    uint32 `json:"schema_version"`
	Reference        RecipeReference `json:"reference"`
	CanonicalPayload []byte `json:"canonical_payload"`
	Signature        []byte `json:"signature"`
}

// RecipeEnvelopeSchemaVersion deliberately rejects the original circular
// self-hashing format. V2 signs canonical JSON with the three derived fields
// empty; the envelope carries their authenticated, derived values.
const RecipeEnvelopeSchemaVersion uint32 = 2

func CanonicalRecipePayload(definition ApplicationDefinition) ([]byte, error) {
	definition.Recipe.RecipeDigest = ""
	definition.Recipe.Signature = ""
	definition.DefinitionDigest = ""
	return json.Marshal(definition)
}

// VerifySignedRecipeDocument is shared by offline release assembly and runtime
// resolution. No embedded reference metadata may differ from the signed bytes.
func VerifySignedRecipeDocument(ctx context.Context, document SignedRecipeDocument, verifier RecipeVerifier, now time.Time) (ApplicationDefinition, error) {
	if ctx == nil || verifier == nil || document.SchemaVersion != RecipeEnvelopeSchemaVersion || len(document.CanonicalPayload) == 0 || len(document.CanonicalPayload) > 4<<20 || document.Reference.Validate(now) != nil {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	sum := sha256.Sum256(document.CanonicalPayload)
	if hex.EncodeToString(sum[:]) != document.Reference.RecipeDigest || document.Reference.Signature != base64.StdEncoding.EncodeToString(document.Signature) {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	if err := verifier.VerifyRecipe(ctx, document.Reference.SigningKeyID, document.Reference.CatalogEpoch, document.CanonicalPayload, document.Signature); err != nil {
		return ApplicationDefinition{}, fmt.Errorf("%w: %v", ErrRecipeUntrusted, err)
	}
	var definition ApplicationDefinition
	decoder := json.NewDecoder(bytes.NewReader(document.CanonicalPayload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&definition) != nil || decoder.Decode(&struct{}{}) != io.EOF || definition.Recipe.RecipeDigest != "" || definition.Recipe.Signature != "" || definition.DefinitionDigest != "" {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	canonical, err := CanonicalRecipePayload(definition)
	if err != nil || !bytes.Equal(canonical, document.CanonicalPayload) {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	definition.Recipe.RecipeDigest = document.Reference.RecipeDigest
	definition.Recipe.Signature = document.Reference.Signature
	definition.DefinitionDigest = document.Reference.RecipeDigest
	left, _ := json.Marshal(definition.Recipe)
	right, _ := json.Marshal(document.Reference)
	if !bytes.Equal(left, right) || definition.Validate(now) != nil {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	return definition, nil
}

type RecipeSource interface {
	FetchRecipe(context.Context, RecipeReference) (SignedRecipeDocument, error)
}

type RecipeVerifier interface {
	VerifyRecipe(context.Context, string, uint64, []byte, []byte) error
}

type DefinitionCatalog interface {
	Resolve(context.Context, RecipeReference, CatalogTarget) (ApplicationDefinition, error)
}

type CatalogTarget struct {
	OperatingSystem OperatingSystem `json:"operating_system"`
	Architecture    CPUArchitecture `json:"architecture"`
	WebEngine       WebEngine `json:"web_engine"`
	PHPVersion      string `json:"php_version"`
}

func (target CatalogTarget) Validate() error {
	if target.OperatingSystem != OSUbuntuNoble && target.OperatingSystem != OSAlmaLinux9 {
		return fmt.Errorf("%w: operating system", ErrUnsupported)
	}
	if target.Architecture != ArchitectureAMD64 && target.Architecture != ArchitectureARM64 {
		return fmt.Errorf("%w: architecture", ErrUnsupported)
	}
	if target.WebEngine != EngineOpenLiteSpeed && target.WebEngine != EngineLiteSpeedEnterprise {
		return fmt.Errorf("%w: web engine", ErrUnsupported)
	}
	if !versionPattern.MatchString(target.PHPVersion) {
		return fmt.Errorf("%w: PHP version", ErrInvalid)
	}
	return nil
}

type PinnedCatalog struct {
	Source         RecipeSource
	Verifier       RecipeVerifier
	MinimumEpoch   uint64
	MaximumPayload int
	Now            func() time.Time

	mu    sync.RWMutex
	cache map[string]ApplicationDefinition
}

func (catalog *PinnedCatalog) Resolve(ctx context.Context, reference RecipeReference, target CatalogTarget) (ApplicationDefinition, error) {
	now := time.Now().UTC()
	if catalog.Now != nil { now = catalog.Now().UTC() }
	if err := reference.Validate(now); err != nil { return ApplicationDefinition{}, err }
	if err := target.Validate(); err != nil { return ApplicationDefinition{}, err }
	if catalog.Source == nil || catalog.Verifier == nil || reference.CatalogEpoch < catalog.MinimumEpoch {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	cacheKey := string(reference.ID) + ":" + reference.RecipeDigest + ":" + string(target.OperatingSystem) + ":" + string(target.Architecture) + ":" + string(target.WebEngine) + ":" + target.PHPVersion
	catalog.mu.RLock()
	cached, exists := catalog.cache[cacheKey]
	catalog.mu.RUnlock()
	if exists {
		if !sameRecipeReference(cached.Recipe, reference) { return ApplicationDefinition{}, ErrRecipeUntrusted }
		return cached, nil
	}

	document, err := catalog.Source.FetchRecipe(ctx, reference)
	if err != nil { return ApplicationDefinition{}, fmt.Errorf("%w: %v", ErrRecipeUnavailable, err) }
	limit := catalog.MaximumPayload
	if limit == 0 { limit = 4 << 20 }
	if len(document.CanonicalPayload) == 0 || len(document.CanonicalPayload) > limit || len(document.Signature) == 0 {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	if !sameRecipeReference(document.Reference, reference) {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	digest := sha256.Sum256(document.CanonicalPayload)
	actualDigest := hex.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(actualDigest), []byte(reference.RecipeDigest)) != 1 {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	definition, err := VerifySignedRecipeDocument(ctx, document, catalog.Verifier, now)
	if err != nil { return ApplicationDefinition{}, err }
	if !sameRecipeReference(definition.Recipe, reference) || definition.DefinitionDigest == "" {
		return ApplicationDefinition{}, ErrRecipeUntrusted
	}
	if !definitionSupports(definition, target) {
		return ApplicationDefinition{}, ErrUnsupported
	}
	catalog.mu.Lock()
	if catalog.cache == nil { catalog.cache = make(map[string]ApplicationDefinition) }
	catalog.cache[cacheKey] = definition
	catalog.mu.Unlock()
	return definition, nil
}

func sameRecipeReference(left, right RecipeReference) bool {
	leftPayload, leftErr := json.Marshal(left)
	rightPayload, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftPayload, rightPayload)
}

func definitionSupports(definition ApplicationDefinition, target CatalogTarget) bool {
	hasOS := false
	for _, value := range definition.OperatingSystems { hasOS = hasOS || value == target.OperatingSystem }
	hasArchitecture := false
	for _, value := range definition.Architectures { hasArchitecture = hasArchitecture || value == target.Architecture }
	hasEngine := false
	for _, value := range definition.WebEngines { hasEngine = hasEngine || value == target.WebEngine }
	hasPHP := false
	for _, value := range definition.Runtime.PHPVersions { hasPHP = hasPHP || value == target.PHPVersion }
	return hasOS && hasArchitecture && hasEngine && hasPHP
}

type ComponentQuery struct {
	Application ApplicationKind `json:"application"`
	Kind        ComponentKind `json:"kind"`
	Text        string `json:"text"`
	Channel     UpdateChannel `json:"channel,omitempty"`
	Limit       uint16 `json:"limit"`
	Cursor      string `json:"cursor,omitempty"`
}

func (query ComponentQuery) Validate() error {
	if !query.Application.Valid() || query.Kind == "" || len(query.Text) > 256 || query.Limit == 0 || query.Limit > 100 || len(query.Cursor) > 1024 {
		return fmt.Errorf("%w: component query", ErrInvalid)
	}
	return nil
}

type ComponentRelease struct {
	Application   ApplicationKind `json:"application"`
	Kind          ComponentKind `json:"kind"`
	Name          string `json:"name"`
	DisplayName   string `json:"display_name"`
	Version       string `json:"version"`
	Artifact      ArtifactReference `json:"artifact"`
	PackageDigest string `json:"package_digest"`
	Signature     string `json:"signature"`
	SigningKeyID  string `json:"signing_key_id"`
	CatalogEpoch  uint64 `json:"catalog_epoch"`
	RequiresPHP   []string `json:"requires_php,omitempty"`
	RequiresCore  string `json:"requires_core,omitempty"`
	PublishedAt   time.Time `json:"published_at"`
	SecurityFix   bool `json:"security_fix"`
	Deprecated    bool `json:"deprecated"`
}

func (release ComponentRelease) Validate() error {
	if !release.Application.Valid() || !componentNamePattern.MatchString(release.Name) || strings.TrimSpace(release.DisplayName) == "" || !versionPattern.MatchString(release.Version) || !validDigest(release.PackageDigest) || release.Signature == "" || !validID(release.SigningKeyID) || release.CatalogEpoch == 0 || release.PublishedAt.IsZero() {
		return fmt.Errorf("%w: component release", ErrInvalid)
	}
	return release.Artifact.Validate()
}

type ComponentPage struct {
	Items      []ComponentRelease `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Digest     string `json:"digest"`
	Signature  string `json:"signature"`
	SigningKeyID string `json:"signing_key_id"`
	CatalogEpoch uint64 `json:"catalog_epoch"`
}

type ComponentUpstream interface {
	Search(context.Context, ComponentQuery) (ComponentPage, error)
	Resolve(context.Context, ApplicationKind, ComponentKind, string, string) (ComponentRelease, error)
}

type ComponentBundle struct {
	ID           ID `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Application  ApplicationKind `json:"application"`
	Components   []ComponentRelease `json:"components"`
	BundleDigest string `json:"bundle_digest"`
	Signature    string `json:"signature"`
	SigningKeyID string `json:"signing_key_id"`
	CatalogEpoch uint64 `json:"catalog_epoch"`
	PublishedAt  time.Time `json:"published_at"`
}

func (bundle ComponentBundle) Validate() error {
	if err := requireID("component bundle", string(bundle.ID)); err != nil { return err }
	if strings.TrimSpace(bundle.Name) == "" || !bundle.Application.Valid() || len(bundle.Components) == 0 || !validDigest(bundle.BundleDigest) || bundle.Signature == "" || !validID(bundle.SigningKeyID) || bundle.CatalogEpoch == 0 || bundle.PublishedAt.IsZero() { return ErrInvalid }
	seen := map[string]struct{}{}
	for _, release := range bundle.Components {
		if err := release.Validate(); err != nil { return err }
		if release.Application != bundle.Application { return ErrConflict }
		key := string(release.Kind) + ":" + release.Name
		if _, exists := seen[key]; exists { return ErrConflict }
		seen[key] = struct{}{}
	}
	return nil
}

type ComponentBundleUpstream interface {
	ResolveBundle(context.Context, ID) (ComponentBundle, error)
}

type PinnedComponentCatalog struct {
	Upstream     ComponentUpstream
	Bundles      ComponentBundleUpstream
	Verifier     RecipeVerifier
	MinimumEpoch uint64
	Now          func() time.Time
}

func (catalog PinnedComponentCatalog) ResolveBundle(ctx context.Context, id ID) (ComponentBundle, error) {
	if catalog.Bundles == nil || catalog.Verifier == nil || !validID(string(id)) { return ComponentBundle{}, ErrInvalid }
	bundle, err := catalog.Bundles.ResolveBundle(ctx, id)
	if err != nil { return ComponentBundle{}, err }
	if bundle.ID != id || bundle.CatalogEpoch < catalog.MinimumEpoch { return ComponentBundle{}, ErrRecipeUntrusted }
	if err := bundle.Validate(); err != nil { return ComponentBundle{}, err }
	for _, release := range bundle.Components { if err := catalog.verifyRelease(ctx, release); err != nil { return ComponentBundle{}, err } }
	payload, err := json.Marshal(struct {
		ID ID `json:"id"`
		Application ApplicationKind `json:"application"`
		Components []ComponentRelease `json:"components"`
		PublishedAt time.Time `json:"published_at"`
	}{bundle.ID, bundle.Application, bundle.Components, bundle.PublishedAt})
	if err != nil { return ComponentBundle{}, err }
	digest := sha256.Sum256(payload)
	if subtle.ConstantTimeCompare([]byte(bundle.BundleDigest), []byte(hex.EncodeToString(digest[:]))) != 1 { return ComponentBundle{}, ErrRecipeUntrusted }
	if err := catalog.Verifier.VerifyRecipe(ctx, bundle.SigningKeyID, bundle.CatalogEpoch, payload, []byte(bundle.Signature)); err != nil { return ComponentBundle{}, ErrRecipeUntrusted }
	return bundle, nil
}

func (catalog PinnedComponentCatalog) Search(ctx context.Context, query ComponentQuery) (ComponentPage, error) {
	if err := query.Validate(); err != nil { return ComponentPage{}, err }
	if catalog.Upstream == nil || catalog.Verifier == nil { return ComponentPage{}, ErrRecipeUntrusted }
	page, err := catalog.Upstream.Search(ctx, query)
	if err != nil { return ComponentPage{}, err }
	if page.CatalogEpoch < catalog.MinimumEpoch || !validDigest(page.Digest) || page.Signature == "" || !validID(page.SigningKeyID) {
		return ComponentPage{}, ErrRecipeUntrusted
	}
	for _, release := range page.Items {
		if err := catalog.verifyRelease(ctx, release); err != nil { return ComponentPage{}, err }
	}
	payload, err := json.Marshal(struct {
		Items []ComponentRelease `json:"items"`
		NextCursor string `json:"next_cursor,omitempty"`
	}{Items: page.Items, NextCursor: page.NextCursor})
	if err != nil { return ComponentPage{}, err }
	digest := sha256.Sum256(payload)
	if subtle.ConstantTimeCompare([]byte(page.Digest), []byte(hex.EncodeToString(digest[:]))) != 1 { return ComponentPage{}, ErrRecipeUntrusted }
	if err := catalog.Verifier.VerifyRecipe(ctx, page.SigningKeyID, page.CatalogEpoch, payload, []byte(page.Signature)); err != nil { return ComponentPage{}, ErrRecipeUntrusted }
	return page, nil
}

func (catalog PinnedComponentCatalog) Resolve(ctx context.Context, application ApplicationKind, kind ComponentKind, name, version string) (ComponentRelease, error) {
	if catalog.Upstream == nil || catalog.Verifier == nil || !application.Valid() || !componentNamePattern.MatchString(name) || !versionPattern.MatchString(version) { return ComponentRelease{}, ErrInvalid }
	release, err := catalog.Upstream.Resolve(ctx, application, kind, name, version)
	if err != nil { return ComponentRelease{}, err }
	if release.Application != application || release.Kind != kind || release.Name != name || release.Version != version { return ComponentRelease{}, ErrRecipeUntrusted }
	if err := catalog.verifyRelease(ctx, release); err != nil { return ComponentRelease{}, err }
	return release, nil
}

func (catalog PinnedComponentCatalog) verifyRelease(ctx context.Context, release ComponentRelease) error {
	if err := release.Validate(); err != nil { return err }
	if release.CatalogEpoch < catalog.MinimumEpoch { return ErrRecipeUntrusted }
	payload, err := json.Marshal(struct {
		Application ApplicationKind `json:"application"`
		Kind ComponentKind `json:"kind"`
		Name string `json:"name"`
		Version string `json:"version"`
		PackageDigest string `json:"package_digest"`
		Artifact ArtifactReference `json:"artifact"`
		PublishedAt time.Time `json:"published_at"`
	}{release.Application, release.Kind, release.Name, release.Version, release.PackageDigest, release.Artifact, release.PublishedAt})
	if err != nil { return err }
	if err := catalog.Verifier.VerifyRecipe(ctx, release.SigningKeyID, release.CatalogEpoch, payload, []byte(release.Signature)); err != nil { return ErrRecipeUntrusted }
	return nil
}

// ProductContract defines the lifecycle and runtime capabilities that every
// signed release recipe for a named GA application must implement. Artifact
// URLs, checksums, and exact product versions are intentionally supplied by a
// signed release catalog instead of being mutable source-code constants.
type ProductContract struct {
	Kind             ApplicationKind
	DisplayName      string
	DefaultStorage   StorageMode
	PHPVersions      []string
	PHPExtensions    []string
	DatabaseKinds    []string
	MutableStores    []MutableStore
	InstallProbes    []ProbeDefinition
	UpdateProbes     []ProbeDefinition
	BackupComponents []string
	Lifecycle        LifecycleSupport
}

func CertifiedProductContracts() map[ApplicationKind]ProductContract {
	full := LifecycleSupport{Install: true, Discover: true, Adopt: true, Update: true, Backup: true, Restore: true, Clone: true, Staging: true, Repair: true, Quarantine: true, Uninstall: true}
	web := func(endpoint string) []ProbeDefinition {
		return []ProbeDefinition{
			{Name: "front_controller", Kind: ProbeHTTP, RelativeEndpoint: endpoint, ExpectedStatus: []int{200, 301, 302}, Timeout: 20 * time.Second, Required: true},
			{Name: "database", Kind: ProbeDatabase, Timeout: 20 * time.Second, Required: true},
			{Name: "integrity", Kind: ProbeIntegrity, Timeout: 2 * time.Minute, Required: true},
		}
	}
	return map[ApplicationKind]ProductContract{
		ApplicationWordPress: {
			Kind: ApplicationWordPress, DisplayName: "WordPress", DefaultStorage: StorageMutableTree,
			PHPVersions: []string{"8.1", "8.2", "8.3", "8.4"}, PHPExtensions: []string{"curl", "dom", "exif", "fileinfo", "gd", "intl", "mbstring", "mysqli", "openssl", "zip"}, DatabaseKinds: []string{"mariadb"},
			MutableStores: []MutableStore{{Name: "uploads", Path: MustRelativePath("wp-content/uploads"), Required: true, BackedUp: true}, {Name: "languages", Path: MustRelativePath("wp-content/languages"), BackedUp: true}, {Name: "cache", Path: MustRelativePath("wp-content/cache"), BackedUp: false}},
			InstallProbes: web("/"), UpdateProbes: web("/wp-login.php"), BackupComponents: []string{"files", "database", "configuration", "component_inventory"}, Lifecycle: full,
		},
		ApplicationJoomla: {
			Kind: ApplicationJoomla, DisplayName: "Joomla", DefaultStorage: StorageMutableTree,
			PHPVersions: []string{"8.1", "8.2", "8.3"}, PHPExtensions: []string{"curl", "dom", "fileinfo", "gd", "intl", "mbstring", "mysqli", "openssl", "simplexml", "zip"}, DatabaseKinds: []string{"mariadb"},
			MutableStores: []MutableStore{{Name: "images", Path: MustRelativePath("images"), Required: true, BackedUp: true}, {Name: "cache", Path: MustRelativePath("cache"), BackedUp: false}, {Name: "logs", Path: MustRelativePath("administrator/logs"), BackedUp: false}},
			InstallProbes: web("/"), UpdateProbes: web("/administrator/"), BackupComponents: []string{"files", "database", "configuration"}, Lifecycle: full,
		},
		ApplicationPrestaShop: {
			Kind: ApplicationPrestaShop, DisplayName: "PrestaShop", DefaultStorage: StorageMutableTree,
			PHPVersions: []string{"8.1", "8.2", "8.3"}, PHPExtensions: []string{"curl", "dom", "fileinfo", "gd", "intl", "mbstring", "mysqli", "openssl", "simplexml", "zip"}, DatabaseKinds: []string{"mariadb"},
			MutableStores: []MutableStore{{Name: "images", Path: MustRelativePath("img"), Required: true, BackedUp: true}, {Name: "downloads", Path: MustRelativePath("download"), BackedUp: true}, {Name: "cache", Path: MustRelativePath("var/cache"), BackedUp: false}},
			InstallProbes: web("/"), UpdateProbes: web("/"), BackupComponents: []string{"files", "database", "configuration"}, Lifecycle: full,
		},
		ApplicationMagento: {
			Kind: ApplicationMagento, DisplayName: "Magento Open Source", DefaultStorage: StorageManagedRelease,
			PHPVersions: []string{"8.2", "8.3", "8.4"}, PHPExtensions: []string{"bcmath", "ctype", "curl", "dom", "fileinfo", "filter", "gd", "intl", "mbstring", "openssl", "pdo_mysql", "simplexml", "soap", "sockets", "sodium", "xsl", "zip"}, DatabaseKinds: []string{"mariadb", "mysql"},
			MutableStores: []MutableStore{{Name: "media", Path: MustRelativePath("pub/media"), Required: true, BackedUp: true}, {Name: "generated", Path: MustRelativePath("generated"), BackedUp: false}, {Name: "var", Path: MustRelativePath("var"), BackedUp: false}},
			InstallProbes: append(web("/"), ProbeDefinition{Name: "indexer", Kind: ProbeBackground, Timeout: 5 * time.Minute, Required: true}), UpdateProbes: append(web("/"), ProbeDefinition{Name: "indexer", Kind: ProbeBackground, Timeout: 5 * time.Minute, Required: true}), BackupComponents: []string{"release", "media", "database", "environment_configuration"}, Lifecycle: full,
		},
		ApplicationMautic: {
			Kind: ApplicationMautic, DisplayName: "Mautic", DefaultStorage: StorageManagedRelease,
			PHPVersions: []string{"8.1", "8.2", "8.3"}, PHPExtensions: []string{"bcmath", "curl", "dom", "fileinfo", "gd", "imap", "intl", "mbstring", "openssl", "pdo_mysql", "zip"}, DatabaseKinds: []string{"mariadb"},
			MutableStores: []MutableStore{{Name: "media", Path: MustRelativePath("media"), Required: true, BackedUp: true}, {Name: "config", Path: MustRelativePath("config/local.php"), Required: true, BackedUp: true}, {Name: "cache", Path: MustRelativePath("var/cache"), BackedUp: false}},
			InstallProbes: append(web("/"), ProbeDefinition{Name: "scheduler", Kind: ProbeBackground, Timeout: 2 * time.Minute, Required: true}), UpdateProbes: append(web("/s/login"), ProbeDefinition{Name: "scheduler", Kind: ProbeBackground, Timeout: 2 * time.Minute, Required: true}), BackupComponents: []string{"release", "media", "database", "local_configuration"}, Lifecycle: full,
		},
	}
}

func DefinitionFromContract(contract ProductContract, reference RecipeReference, artifact ArtifactReference, definitionDigest string) ApplicationDefinition {
	stores := append([]MutableStore(nil), contract.MutableStores...)
	extensions := append([]string(nil), contract.PHPExtensions...)
	sort.Strings(extensions)
	return ApplicationDefinition{
		ID: reference.DefinitionID, Kind: contract.Kind, DisplayName: contract.DisplayName, Recipe: reference, Artifact: artifact,
		Architectures: []CPUArchitecture{ArchitectureAMD64, ArchitectureARM64}, OperatingSystems: []OperatingSystem{OSUbuntuNoble, OSAlmaLinux9}, WebEngines: []WebEngine{EngineOpenLiteSpeed, EngineLiteSpeedEnterprise}, StorageMode: contract.DefaultStorage,
		Runtime: RuntimeRequirement{PHPVersions: append([]string(nil), contract.PHPVersions...), PHPExtensions: extensions, DatabaseKinds: append([]string(nil), contract.DatabaseKinds...), MinMemoryBytes: minimumMemory(contract.Kind), MinDiskBytes: minimumDisk(contract.Kind)},
		MutableStores: stores, InstallProbes: append([]ProbeDefinition(nil), contract.InstallProbes...), UpdateProbes: append([]ProbeDefinition(nil), contract.UpdateProbes...), BackupComponents: append([]string(nil), contract.BackupComponents...), Lifecycle: contract.Lifecycle, DefinitionDigest: definitionDigest,
	}
}

func minimumMemory(kind ApplicationKind) uint64 {
	switch kind {
	case ApplicationMagento: return 4 << 30
	case ApplicationMautic: return 2 << 30
	case ApplicationPrestaShop: return 1 << 30
	default: return 512 << 20
	}
}

func minimumDisk(kind ApplicationKind) uint64 {
	switch kind {
	case ApplicationMagento: return 16 << 30
	case ApplicationMautic: return 8 << 30
	case ApplicationPrestaShop: return 4 << 30
	default: return 2 << 30
	}
}
