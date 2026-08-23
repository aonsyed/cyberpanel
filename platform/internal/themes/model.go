// Package themes owns signed, non-executable panel branding packages and their
// scoped A/B activation lifecycle.
package themes

import (
	"crypto/ed25519"
	"errors"
	"io/fs"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid     = errors.New("invalid theme resource")
	ErrDenied      = errors.New("theme operation denied")
	ErrNotFound    = errors.New("theme resource not found")
	ErrConflict    = errors.New("theme generation conflict")
	ErrIntegrity   = errors.New("theme integrity failure")
	ErrCapacity    = errors.New("theme package exceeds capacity")
	ErrUnsupported = errors.New("theme capability unsupported")
)

const (
	DefaultRoot              = "/var/lib/cyberpanel/themes"
	DefaultMaximumAssets     = 512
	DefaultMaximumAssetBytes = 16 << 20
	DefaultMaximumTotalBytes = 64 << 20
	DefaultMaximumStateBytes = 8 << 20
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var themeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)

type BuiltInTheme string

const (
	ThemeSystem BuiltInTheme = "system"
	ThemeLight  BuiltInTheme = "light"
	ThemeDark   BuiltInTheme = "dark"
)

func (theme BuiltInTheme) Valid() bool {
	return theme == ThemeSystem || theme == ThemeLight || theme == ThemeDark
}

type ScopeKind string

const (
	ScopeInstallation ScopeKind = "installation"
	ScopeGlobal       ScopeKind = "global"
	ScopeReseller     ScopeKind = "reseller"
	ScopeTenant       ScopeKind = "tenant"
)

// Scope is an exact authority boundary. Parent identity participates in its
// storage key so the same tenant ID cannot be rebound under another reseller.
type Scope struct {
	Kind       ScopeKind `json:"kind"`
	ID         string    `json:"id"`
	ParentKind ScopeKind `json:"parent_kind,omitempty"`
	ParentID   string    `json:"parent_id,omitempty"`
}

func (scope Scope) Validate() error {
	if !identifierPattern.MatchString(scope.ID) {
		return ErrInvalid
	}
	switch scope.Kind {
	case ScopeInstallation:
		if scope.ParentKind != "" || scope.ParentID != "" {
			return ErrInvalid
		}
	case ScopeGlobal:
		if scope.ID != "global" || scope.ParentKind != ScopeInstallation || !identifierPattern.MatchString(scope.ParentID) {
			return ErrInvalid
		}
	case ScopeReseller:
		if scope.ParentKind != ScopeGlobal || scope.ParentID != "global" {
			return ErrInvalid
		}
	case ScopeTenant:
		if (scope.ParentKind != ScopeGlobal && scope.ParentKind != ScopeReseller) || !identifierPattern.MatchString(scope.ParentID) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type ResolutionPath struct {
	InstallationID string `json:"installation_id"`
	ResellerID     string `json:"reseller_id,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
}

func (value ResolutionPath) Validate() error {
	if !identifierPattern.MatchString(value.InstallationID) || value.ResellerID != "" && !identifierPattern.MatchString(value.ResellerID) || value.TenantID != "" && !identifierPattern.MatchString(value.TenantID) {
		return ErrInvalid
	}
	return nil
}

func (value ResolutionPath) Scopes() ([]Scope, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	result := []Scope{
		{Kind: ScopeInstallation, ID: value.InstallationID},
		{Kind: ScopeGlobal, ID: "global", ParentKind: ScopeInstallation, ParentID: value.InstallationID},
	}
	if value.ResellerID != "" {
		result = append(result, Scope{Kind: ScopeReseller, ID: value.ResellerID, ParentKind: ScopeGlobal, ParentID: "global"})
	}
	if value.TenantID != "" {
		parentKind, parentID := ScopeGlobal, "global"
		if value.ResellerID != "" {
			parentKind, parentID = ScopeReseller, value.ResellerID
		}
		result = append(result, Scope{Kind: ScopeTenant, ID: value.TenantID, ParentKind: parentKind, ParentID: parentID})
	}
	return result, nil
}

type CompatibilityRange struct {
	Minimum string `json:"minimum"`
	Maximum string `json:"maximum"`
}

type DesignTokens struct {
	BrandName        string `json:"brand_name"`
	LogoAsset        string `json:"logo_asset,omitempty"`
	FaviconAsset     string `json:"favicon_asset,omitempty"`
	FontRegularAsset string `json:"font_regular_asset,omitempty"`
	FontBoldAsset    string `json:"font_bold_asset,omitempty"`
	PrimaryColor     string `json:"primary_color"`
	AccentColor      string `json:"accent_color"`
	LightSurface     string `json:"light_surface"`
	LightText        string `json:"light_text"`
	DarkSurface      string `json:"dark_surface"`
	DarkText         string `json:"dark_text"`
}

type AssetDescriptor struct {
	Path   string `json:"path"`
	MIME   string `json:"mime"`
	Size   uint64 `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion uint32             `json:"schema_version"`
	ThemeID       string             `json:"theme_id"`
	Version       string             `json:"version"`
	Issuer        string             `json:"issuer"`
	Compatibility CompatibilityRange `json:"compatibility"`
	Digest        string             `json:"digest"`
	Tokens        DesignTokens       `json:"tokens"`
	Assets        []AssetDescriptor  `json:"assets"`
	IssuedAt      time.Time          `json:"issued_at"`
	SigningKeyID  string             `json:"signing_key_id"`
	Signature     []byte             `json:"signature"`
}

type TrustedKey struct {
	ID        string
	Issuer    string
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	Revoked   bool
}

type TrustPolicy struct {
	Keys              map[string]TrustedKey
	PlatformVersion   string
	MaximumAssets     int
	MaximumAssetBytes uint64
	MaximumTotalBytes uint64
	Clock             func() time.Time
}

type PackageAsset struct {
	Path       string
	Mode       fs.FileMode
	LinkTarget string
	Content    []byte
}

type Package struct {
	Manifest Manifest
	Assets   []PackageAsset
}

type VerifiedPackage struct {
	Manifest Manifest
	assets   []PackageAsset
	total    uint64
}

type ThemeReference struct {
	ThemeID  string `json:"theme_id"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
	AssetRoot string `json:"asset_root"`
}

func (reference ThemeReference) Validate() error {
	if !themeIDPattern.MatchString(reference.ThemeID) || !validVersion(reference.Version) || !validDigest(reference.Digest) || reference.AssetRoot != packageAssetRoot(reference.ThemeID, reference.Version, reference.Digest) {
		return ErrInvalid
	}
	return nil
}

type InstalledTheme struct {
	Reference   ThemeReference `json:"reference"`
	Manifest    Manifest       `json:"manifest"`
	InstalledAt time.Time      `json:"installed_at"`
}

type Inventory struct {
	Generation uint64           `json:"generation"`
	Items      []InstalledTheme `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type Slot string

const (
	SlotA Slot = "A"
	SlotB Slot = "B"
)

type ActivationState struct {
	Scope      Scope           `json:"scope"`
	Generation uint64          `json:"generation"`
	Active     Slot            `json:"active"`
	A          *ThemeReference `json:"a,omitempty"`
	B          *ThemeReference `json:"b,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

func (state ActivationState) ActiveReference() *ThemeReference {
	if state.Active == SlotA && state.A != nil {
		copy := *state.A
		return &copy
	}
	if state.Active == SlotB && state.B != nil {
		copy := *state.B
		return &copy
	}
	return nil
}

type Probe struct {
	Name       string    `json:"name"`
	Passed     bool      `json:"passed"`
	Digest     string    `json:"digest"`
	ObservedAt time.Time `json:"observed_at"`
}

type Receipt struct {
	Operation       string          `json:"operation"`
	Scope           *Scope          `json:"scope,omitempty"`
	Reference       *ThemeReference `json:"reference,omitempty"`
	Previous        *ThemeReference `json:"previous,omitempty"`
	Generation      uint64          `json:"generation"`
	StoreGeneration uint64          `json:"store_generation"`
	ActiveSlot      Slot            `json:"active_slot,omitempty"`
	StateDigest     string          `json:"state_digest"`
	ReceiptDigest   string          `json:"receipt_digest"`
	CompletedAt     time.Time       `json:"completed_at"`
	Probes          []Probe         `json:"probes"`
}

type Inspection struct {
	Theme InstalledTheme `json:"theme"`
	Probe Probe          `json:"probe"`
}

type Preview struct {
	Scope     Scope          `json:"scope"`
	Reference ThemeReference `json:"reference"`
	Tokens    DesignTokens   `json:"tokens"`
	Probe     Probe          `json:"probe"`
}

type ResolvedBranding struct {
	BaseTheme BuiltInTheme    `json:"base_theme"`
	Scope     *Scope          `json:"scope,omitempty"`
	Reference *ThemeReference `json:"reference,omitempty"`
	Tokens    *DesignTokens   `json:"tokens,omitempty"`
	Fallback  bool            `json:"fallback"`
	Degraded  bool            `json:"degraded"`
	Probes    []Probe         `json:"probes"`
}

func validIdentifier(value string) bool {
	return identifierPattern.MatchString(value) && strings.TrimSpace(value) == value
}
