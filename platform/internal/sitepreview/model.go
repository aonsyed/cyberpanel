// Package sitepreview owns exact-generation interactive site previews and
// isolated screenshot refreshes. It deliberately exposes no generic proxy,
// browser argv, native configuration text, or caller-selected backend.
package sitepreview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid             = errors.New("invalid site preview request")
	ErrUnauthorized        = errors.New("site preview unavailable")
	ErrNotFound            = errors.New("site preview unavailable")
	ErrConflict            = errors.New("site preview state conflict")
	ErrStaleGeneration     = errors.New("site generation changed")
	ErrExpired             = errors.New("site preview expired")
	ErrRevoked             = errors.New("site preview revoked")
	ErrBudgetExhausted     = errors.New("site preview budget exhausted")
	ErrAmbiguous           = errors.New("site preview route outcome ambiguous")
	ErrPolicyDenied        = errors.New("site preview destination denied")
	ErrProviderNotInvoked  = errors.New("qualified provider dispatch is external")
	ErrIntegrity           = errors.New("site preview stored state failed validation")
)

const (
	MaximumSessionTTL       = time.Hour
	MaximumIdleTTL          = 15 * time.Minute
	MaximumSessionBytes     = uint64(1 << 30)
	MaximumSessionRequests  = uint32(4096)
	MaximumScreenshotBytes  = uint64(64 << 20)
	MaximumScreenshotPixels = uint64(32_000_000)
	MaximumScreenshotTime   = 2 * time.Minute
	MaximumRedirects        = uint8(5)
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$`)

type TenantID string
type SiteID string
type PrincipalID string
type SessionID string
type RouteLeaseID string
type ScreenshotJobID string
type ArtifactID string
type ReceiptID string

func validID(value string) bool { return identifierPattern.MatchString(value) }
func validDigest(value string) bool {
	return len(value) == sha256.Size*2 && strings.Trim(value, "0123456789abcdef") == ""
}

func digestJSON(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte(domain+"\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

func validHostname(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") || !strings.Contains(value, ".") || netip.ParseAddr(value).IsValid() {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

type Engine string

const (
	EngineOLS Engine = "openlitespeed"
	EngineLSE Engine = "litespeed_enterprise"
)

type BackendProtocol string

const (
	BackendHTTP  BackendProtocol = "http"
	BackendHTTPS BackendProtocol = "https"
)

// Backend is resolved from canonical site state. No public API should decode
// this type directly from an untrusted request.
type Backend struct {
	Address     netip.Addr     `json:"address"`
	Port        uint16         `json:"port"`
	Protocol    BackendProtocol `json:"protocol"`
	ServerName  string         `json:"server_name"`
	CertificateGeneration uint64 `json:"certificate_generation"`
}

func (backend Backend) Validate() error {
	if !backend.Address.IsValid() || backend.Address.IsUnspecified() || backend.Address.IsMulticast() || backend.Port == 0 || !validHostname(backend.ServerName) {
		return ErrInvalid
	}
	if backend.Protocol != BackendHTTP && backend.Protocol != BackendHTTPS {
		return ErrInvalid
	}
	if backend.Protocol == BackendHTTPS && backend.CertificateGeneration == 0 || backend.Protocol == BackendHTTP && backend.CertificateGeneration != 0 {
		return ErrInvalid
	}
	return nil
}

type SiteSnapshot struct {
	TenantID       TenantID `json:"tenant_id"`
	SiteID         SiteID   `json:"site_id"`
	Generation     uint64   `json:"generation"`
	Ready          bool     `json:"ready"`
	Engine         Engine   `json:"engine"`
	CanonicalHost  string   `json:"canonical_host"`
	AllowedHosts   []string `json:"allowed_hosts"`
	PHPGeneration  uint64   `json:"php_generation"`
	TLSGeneration  uint64   `json:"tls_generation"`
	CacheGeneration uint64  `json:"cache_generation"`
	WAFGeneration  uint64   `json:"waf_generation"`
	Backend        Backend  `json:"backend"`
}

func (site SiteSnapshot) Validate() error {
	if !validID(string(site.TenantID)) || !validID(string(site.SiteID)) || site.Generation == 0 || !site.Ready ||
		(site.Engine != EngineOLS && site.Engine != EngineLSE) || !validHostname(site.CanonicalHost) ||
		site.PHPGeneration == 0 || site.TLSGeneration == 0 || site.CacheGeneration == 0 || site.WAFGeneration == 0 ||
		site.Backend.Validate() != nil || len(site.AllowedHosts) == 0 || len(site.AllowedHosts) > 256 {
		return ErrInvalid
	}
	foundCanonical, previous := false, ""
	for _, hostname := range site.AllowedHosts {
		if !validHostname(hostname) || hostname <= previous {
			return ErrInvalid
		}
		foundCanonical = foundCanonical || hostname == site.CanonicalHost
		previous = hostname
	}
	if !foundCanonical || site.Backend.ServerName != site.CanonicalHost {
		return ErrInvalid
	}
	return nil
}

func (site SiteSnapshot) AllowsHostname(hostname string) bool {
	for _, allowed := range site.AllowedHosts {
		if hostname == allowed {
			return true
		}
	}
	return false
}

type AudienceKind string

const (
	AudienceViewer AudienceKind = "viewer_principal"
	AudienceShare  AudienceKind = "share_audience"
)

type Audience struct {
	Kind        AudienceKind `json:"kind"`
	PrincipalID PrincipalID  `json:"principal_id,omitempty"`
	ShareID     string       `json:"share_id,omitempty"`
}

func (audience Audience) Validate() error {
	switch audience.Kind {
	case AudienceViewer:
		if !validID(string(audience.PrincipalID)) || audience.ShareID != "" {
			return ErrInvalid
		}
	case AudienceShare:
		if audience.PrincipalID != "" || !validID(audience.ShareID) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (audience Audience) Key() string {
	if audience.Kind == AudienceViewer {
		return "viewer:" + string(audience.PrincipalID)
	}
	return "share:" + audience.ShareID
}

type GrantMode string

const (
	GrantOneUse    GrantMode = "one_use"
	GrantShortLived GrantMode = "short_lived"
)

type CachePolicy string

const (
	CacheBypassPrivate CachePolicy = "bypass_private"
	CacheSitePolicy    CachePolicy = "site_policy_isolated_namespace"
)

type WAFPolicy string

const (
	WAFEnforceSitePolicy WAFPolicy = "enforce_site_policy"
)

type SessionState string

const (
	SessionPreparing SessionState = "preparing"
	SessionActive    SessionState = "active"
	SessionExhausted SessionState = "exhausted"
	SessionExpired   SessionState = "expired"
	SessionRevoked   SessionState = "revoked"
	SessionAmbiguous SessionState = "ambiguous"
)

type Limits struct {
	AbsoluteTTL time.Duration `json:"absolute_ttl"`
	IdleTTL     time.Duration `json:"idle_ttl"`
	MaxBytes    uint64        `json:"max_bytes"`
	MaxRequests uint32        `json:"max_requests"`
}

func (limits Limits) Validate(mode GrantMode) error {
	if limits.AbsoluteTTL < time.Minute || limits.AbsoluteTTL > MaximumSessionTTL || limits.IdleTTL < time.Second || limits.IdleTTL > MaximumIdleTTL || limits.IdleTTL > limits.AbsoluteTTL ||
		limits.MaxBytes == 0 || limits.MaxBytes > MaximumSessionBytes || limits.MaxRequests == 0 || limits.MaxRequests > MaximumSessionRequests ||
		mode == GrantOneUse && limits.MaxRequests != 1 {
		return ErrInvalid
	}
	return nil
}

type PreviewSession struct {
	ID                SessionID   `json:"id"`
	TenantID          TenantID    `json:"tenant_id"`
	SiteID            SiteID      `json:"site_id"`
	SiteGeneration    uint64      `json:"site_generation"`
	Audience          Audience    `json:"audience"`
	GrantMode         GrantMode   `json:"grant_mode"`
	PreviewHostname   string      `json:"preview_hostname"`
	RequestedHostname string      `json:"requested_hostname"`
	Backend           Backend     `json:"backend"`
	Engine            Engine      `json:"engine"`
	CachePolicy       CachePolicy `json:"cache_policy"`
	WAFPolicy         WAFPolicy   `json:"waf_policy"`
	PHPGeneration     uint64      `json:"php_generation"`
	TLSGeneration     uint64      `json:"tls_generation"`
	CacheGeneration   uint64      `json:"cache_generation"`
	WAFGeneration     uint64      `json:"waf_generation"`
	AuthzEpoch        uint64      `json:"authz_epoch"`
	Limits            Limits      `json:"limits"`
	ConsumedBytes     uint64      `json:"consumed_bytes"`
	ConsumedRequests  uint32      `json:"consumed_requests"`
	State             SessionState `json:"state"`
	Generation        uint64      `json:"generation"`
	CreatedAt         time.Time   `json:"created_at"`
	LastUsedAt        time.Time   `json:"last_used_at"`
	ExpiresAt         time.Time   `json:"expires_at"`
	RevokedAt         time.Time   `json:"revoked_at,omitempty"`
}

func (session PreviewSession) Validate(previewDomain string) error {
	if !validID(string(session.ID)) || !validID(string(session.TenantID)) || !validID(string(session.SiteID)) || session.SiteGeneration == 0 ||
		session.Audience.Validate() != nil || (session.GrantMode != GrantOneUse && session.GrantMode != GrantShortLived) || !validHostname(session.PreviewHostname) ||
		!strings.HasSuffix(session.PreviewHostname, "."+previewDomain) || !validHostname(session.RequestedHostname) || session.Backend.Validate() != nil ||
		(session.Engine != EngineOLS && session.Engine != EngineLSE) || (session.CachePolicy != CacheBypassPrivate && session.CachePolicy != CacheSitePolicy) || session.WAFPolicy != WAFEnforceSitePolicy ||
		session.PHPGeneration == 0 || session.TLSGeneration == 0 || session.CacheGeneration == 0 || session.WAFGeneration == 0 || session.AuthzEpoch == 0 ||
		session.Limits.Validate(session.GrantMode) != nil || session.ConsumedBytes > session.Limits.MaxBytes || session.ConsumedRequests > session.Limits.MaxRequests ||
		session.Generation == 0 || session.CreatedAt.IsZero() || session.LastUsedAt.Before(session.CreatedAt) || !session.ExpiresAt.After(session.CreatedAt) || session.ExpiresAt.Sub(session.CreatedAt) > session.Limits.AbsoluteTTL {
		return ErrInvalid
	}
	switch session.State {
	case SessionPreparing, SessionActive, SessionExhausted, SessionExpired, SessionAmbiguous:
		if !session.RevokedAt.IsZero() {
			return ErrInvalid
		}
	case SessionRevoked:
		if session.RevokedAt.IsZero() || session.RevokedAt.Before(session.CreatedAt) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type RouteSpec struct {
	SessionID          SessionID `json:"session_id"`
	TenantID           TenantID  `json:"tenant_id"`
	SiteID             SiteID    `json:"site_id"`
	SiteGeneration     uint64    `json:"site_generation"`
	PreviewHostname    string    `json:"preview_hostname"`
	HostHeader         string    `json:"host_header"`
	SNI                string    `json:"sni"`
	Backend             Backend   `json:"backend"`
	Engine              Engine    `json:"engine"`
	PHPGeneration       uint64    `json:"php_generation"`
	TLSGeneration       uint64    `json:"tls_generation"`
	CacheGeneration     uint64    `json:"cache_generation"`
	WAFGeneration       uint64    `json:"waf_generation"`
	CachePolicy         CachePolicy `json:"cache_policy"`
	WAFPolicy           WAFPolicy `json:"waf_policy"`
	ExpiresAt           time.Time `json:"expires_at"`
}

func routeSpec(session PreviewSession) RouteSpec {
	return RouteSpec{SessionID: session.ID, TenantID: session.TenantID, SiteID: session.SiteID, SiteGeneration: session.SiteGeneration,
		PreviewHostname: session.PreviewHostname, HostHeader: session.RequestedHostname, SNI: session.RequestedHostname, Backend: session.Backend,
		Engine: session.Engine, PHPGeneration: session.PHPGeneration, TLSGeneration: session.TLSGeneration, CacheGeneration: session.CacheGeneration,
		WAFGeneration: session.WAFGeneration, CachePolicy: session.CachePolicy, WAFPolicy: session.WAFPolicy, ExpiresAt: session.ExpiresAt}
}

func (spec RouteSpec) Validate() error {
	if !validID(string(spec.SessionID)) || !validID(string(spec.TenantID)) || !validID(string(spec.SiteID)) || spec.SiteGeneration == 0 ||
		!validHostname(spec.PreviewHostname) || !validHostname(spec.HostHeader) || spec.SNI != spec.HostHeader || spec.Backend.Validate() != nil ||
		spec.Backend.ServerName != spec.SNI || (spec.Engine != EngineOLS && spec.Engine != EngineLSE) || spec.PHPGeneration == 0 || spec.TLSGeneration == 0 ||
		spec.CacheGeneration == 0 || spec.WAFGeneration == 0 || (spec.CachePolicy != CacheBypassPrivate && spec.CachePolicy != CacheSitePolicy) ||
		spec.WAFPolicy != WAFEnforceSitePolicy || spec.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type RouteProof struct {
	SpecDigest          string    `json:"spec_digest"`
	Engine              Engine    `json:"engine"`
	HostProved          bool      `json:"host_proved"`
	SNIProved           bool      `json:"sni_proved"`
	PHPGeneration       uint64    `json:"php_generation"`
	TLSGeneration       uint64    `json:"tls_generation"`
	CacheGeneration     uint64    `json:"cache_generation"`
	WAFGeneration       uint64    `json:"waf_generation"`
	SiteGeneration      uint64    `json:"site_generation"`
	ObservedAt          time.Time `json:"observed_at"`
	EvidenceDigest      string    `json:"evidence_digest"`
}

func (proof RouteProof) ValidFor(spec RouteSpec) bool {
	return spec.Validate() == nil && proof.SpecDigest == digestJSON("cyberpanel:sitepreview:route:v1", spec) && proof.Engine == spec.Engine && proof.HostProved && proof.SNIProved &&
		proof.PHPGeneration == spec.PHPGeneration && proof.TLSGeneration == spec.TLSGeneration && proof.CacheGeneration == spec.CacheGeneration &&
		proof.WAFGeneration == spec.WAFGeneration && proof.SiteGeneration == spec.SiteGeneration && !proof.ObservedAt.IsZero() && validDigest(proof.EvidenceDigest)
}

type RouteLease struct {
	ID             RouteLeaseID `json:"id"`
	SessionID      SessionID    `json:"session_id"`
	SpecDigest     string       `json:"spec_digest"`
	RuntimeToken   string       `json:"runtime_token"`
	State          string       `json:"state"`
	Generation     uint64       `json:"generation"`
	ExpiresAt      time.Time    `json:"expires_at"`
	RollbackUntil  time.Time    `json:"rollback_until"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

func (lease RouteLease) Validate() error {
	if !validID(string(lease.ID)) || !validID(string(lease.SessionID)) || !validDigest(lease.SpecDigest) || !validID(lease.RuntimeToken) || lease.Generation == 0 ||
		lease.ExpiresAt.IsZero() || lease.RollbackUntil.Before(lease.ExpiresAt) || lease.UpdatedAt.IsZero() || (lease.State != "active" && lease.State != "expired" && lease.State != "rolled_back" && lease.State != "ambiguous") {
		return ErrInvalid
	}
	return nil
}

type ScreenshotMode string

const (
	ScreenshotLocal     ScreenshotMode = "local"
	ScreenshotProvider ScreenshotMode = "qualified_provider"
)

type ScreenshotState string

const (
	ScreenshotQueued    ScreenshotState = "queued"
	ScreenshotRendering ScreenshotState = "rendering"
	ScreenshotSucceeded ScreenshotState = "succeeded"
	ScreenshotFailed    ScreenshotState = "failed"
	ScreenshotStale     ScreenshotState = "stale"
	ScreenshotExternal  ScreenshotState = "waiting_external"
)

type Destination struct {
	URL                  string   `json:"url"`
	AuthorizedBackend    Backend  `json:"authorized_backend"`
	AllowPublicInternet  bool     `json:"allow_public_internet"`
}

func (destination Destination) Validate(site SiteSnapshot) error {
	parsed, err := url.Parse(destination.URL)
	if err != nil || parsed.Scheme != string(destination.AuthorizedBackend.Protocol) || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Hostname() == "" || parsed.RawPath != "" ||
		parsed.Path != "" && (parsed.Path[0] != '/' || parsed.Path != path.Clean(parsed.Path) || strings.Contains(parsed.Path, "\\")) || len(destination.URL) > 2048 || !validHostname(strings.ToLower(parsed.Hostname())) || strings.ToLower(parsed.Hostname()) != parsed.Hostname() ||
		destination.AuthorizedBackend.Validate() != nil || destination.AuthorizedBackend != site.Backend || !site.AllowsHostname(parsed.Hostname()) ||
		parsed.Hostname() != destination.AuthorizedBackend.ServerName || effectiveURLPort(parsed) != destination.AuthorizedBackend.Port {
		return ErrPolicyDenied
	}
	return nil
}

func effectiveURLPort(parsed *url.URL) uint16 {
	if parsed == nil {
		return 0
	}
	if parsed.Port() == "" {
		if parsed.Scheme == "https" {
			return 443
		}
		if parsed.Scheme == "http" {
			return 80
		}
		return 0
	}
	var port uint64
	for _, character := range parsed.Port() {
		if character < '0' || character > '9' {
			return 0
		}
		port = port*10 + uint64(character-'0')
		if port > 65535 {
			return 0
		}
	}
	return uint16(port)
}

type ScreenshotLimits struct {
	Timeout      time.Duration `json:"timeout"`
	MaximumBytes uint64        `json:"maximum_bytes"`
	Width        uint32        `json:"width"`
	Height       uint32        `json:"height"`
	Redirects    uint8         `json:"redirects"`
}

func (limits ScreenshotLimits) Validate() error {
	pixels := uint64(limits.Width) * uint64(limits.Height)
	if limits.Timeout < time.Second || limits.Timeout > MaximumScreenshotTime || limits.MaximumBytes == 0 || limits.MaximumBytes > MaximumScreenshotBytes ||
		limits.Width < 320 || limits.Width > 8192 || limits.Height < 200 || limits.Height > 8192 || pixels == 0 || pixels > MaximumScreenshotPixels || limits.Redirects > MaximumRedirects {
		return ErrInvalid
	}
	return nil
}

type ProviderPolicy struct {
	ProviderID      string        `json:"provider_id"`
	TenantConsented bool          `json:"tenant_consented"`
	DataRegion      string        `json:"data_region"`
	Retention       time.Duration `json:"retention"`
	PolicyVersion   uint64        `json:"policy_version"`
}

func (policy ProviderPolicy) Validate() error {
	if !validID(policy.ProviderID) || !policy.TenantConsented || !validID(policy.DataRegion) || policy.Retention <= 0 || policy.Retention > 30*24*time.Hour || policy.PolicyVersion == 0 {
		return ErrPolicyDenied
	}
	return nil
}

type ScreenshotJob struct {
	ID             ScreenshotJobID `json:"id"`
	TenantID       TenantID        `json:"tenant_id"`
	SiteID         SiteID          `json:"site_id"`
	SiteGeneration uint64          `json:"site_generation"`
	ActorID        PrincipalID     `json:"actor_id"`
	AuthzEpoch     uint64          `json:"authz_epoch"`
	Mode           ScreenshotMode  `json:"mode"`
	Destination    Destination     `json:"destination"`
	Limits         ScreenshotLimits `json:"limits"`
	Provider       *ProviderPolicy `json:"provider,omitempty"`
	State          ScreenshotState `json:"state"`
	Generation     uint64          `json:"generation"`
	WorkerID       string          `json:"worker_id,omitempty"`
	LeaseUntil     time.Time       `json:"lease_until,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func (job ScreenshotJob) Validate() error {
	if !validID(string(job.ID)) || !validID(string(job.TenantID)) || !validID(string(job.SiteID)) || job.SiteGeneration == 0 || !validID(string(job.ActorID)) || job.AuthzEpoch == 0 ||
		job.Limits.Validate() != nil || job.Generation == 0 || job.CreatedAt.IsZero() || job.UpdatedAt.Before(job.CreatedAt) {
		return ErrInvalid
	}
	if job.Mode == ScreenshotLocal {
		if job.Provider != nil {
			return ErrInvalid
		}
	} else if job.Mode == ScreenshotProvider {
		if job.Provider == nil || job.Provider.Validate() != nil {
			return ErrPolicyDenied
		}
	} else {
		return ErrInvalid
	}
	switch job.State {
	case ScreenshotQueued:
		if job.WorkerID != "" || !job.LeaseUntil.IsZero() {
			return ErrInvalid
		}
	case ScreenshotRendering:
		if !validID(job.WorkerID) || job.LeaseUntil.IsZero() {
			return ErrInvalid
		}
	case ScreenshotSucceeded, ScreenshotFailed, ScreenshotStale, ScreenshotExternal:
	default:
		return ErrInvalid
	}
	return nil
}

type ScreenshotArtifact struct {
	ID             ArtifactID      `json:"id"`
	JobID          ScreenshotJobID `json:"job_id"`
	TenantID       TenantID        `json:"tenant_id"`
	SiteID         SiteID          `json:"site_id"`
	SiteGeneration uint64          `json:"site_generation"`
	MediaType      string          `json:"media_type"`
	ByteSize       uint64          `json:"byte_size"`
	PixelWidth     uint32          `json:"pixel_width"`
	PixelHeight    uint32          `json:"pixel_height"`
	Digest         string          `json:"digest"`
	StorageRef     string          `json:"storage_ref"`
	CreatedAt      time.Time       `json:"created_at"`
}

func (artifact ScreenshotArtifact) Validate() error {
	if !validID(string(artifact.ID)) || !validID(string(artifact.JobID)) || !validID(string(artifact.TenantID)) || !validID(string(artifact.SiteID)) || artifact.SiteGeneration == 0 ||
		artifact.MediaType != "image/png" || artifact.ByteSize == 0 || artifact.ByteSize > MaximumScreenshotBytes || uint64(artifact.PixelWidth)*uint64(artifact.PixelHeight) > MaximumScreenshotPixels ||
		artifact.PixelWidth == 0 || artifact.PixelHeight == 0 || !validDigest(artifact.Digest) || !validID(artifact.StorageRef) || artifact.CreatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type Receipt struct {
	ID          ReceiptID `json:"id"`
	TenantID    TenantID  `json:"tenant_id"`
	ResourceKind string   `json:"resource_kind"`
	ResourceID  string    `json:"resource_id"`
	Operation   string    `json:"operation"`
	Outcome     string    `json:"outcome"`
	Generation  uint64    `json:"generation"`
	RequestDigest string  `json:"request_digest"`
	ResultDigest string   `json:"result_digest,omitempty"`
	OccurredAt  time.Time `json:"occurred_at"`
}

func (receipt Receipt) Validate() error {
	if !validID(string(receipt.ID)) || !validID(string(receipt.TenantID)) || !validID(receipt.ResourceKind) || !validID(receipt.ResourceID) || !validID(receipt.Operation) ||
		!validID(receipt.Outcome) || receipt.Generation == 0 || !validDigest(receipt.RequestDigest) || receipt.ResultDigest != "" && !validDigest(receipt.ResultDigest) || receipt.OccurredAt.IsZero() {
		return ErrInvalid
	}
	return nil
}
