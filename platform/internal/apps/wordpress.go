package apps

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type WordPressComponentAction string

const (
	WordPressInstallComponent WordPressComponentAction = "install"
	WordPressActivateComponent WordPressComponentAction = "activate"
	WordPressDeactivateComponent WordPressComponentAction = "deactivate"
	WordPressUpdateComponent WordPressComponentAction = "update"
	WordPressDeleteComponent WordPressComponentAction = "delete"
	WordPressReinstallCore WordPressComponentAction = "reinstall_core"
	WordPressVerifyChecksums WordPressComponentAction = "verify_checksums"
)

type ComponentMutation struct {
	Scope          SiteExecutionScope `json:"scope"`
	InstallationID InstallationID `json:"installation_id"`
	Action         WordPressComponentAction `json:"action"`
	Kind           ComponentKind `json:"kind"`
	Name           string `json:"name"`
	ExpectedVersion string `json:"expected_version,omitempty"`
	ExpectedDigest string `json:"expected_digest,omitempty"`
	Release        *ComponentRelease `json:"release,omitempty"`
	Force          bool `json:"force"`
	NetworkWide    bool `json:"network_wide"`
	RecoveryPointID RecoveryPointID `json:"recovery_point_id,omitempty"`
}

func (mutation ComponentMutation) Validate() error {
	if err := mutation.Scope.Validate(); err != nil { return err }
	if err := requireID("installation", string(mutation.InstallationID)); err != nil { return err }
	switch mutation.Action {
	case WordPressInstallComponent, WordPressActivateComponent, WordPressDeactivateComponent, WordPressUpdateComponent, WordPressDeleteComponent, WordPressReinstallCore, WordPressVerifyChecksums:
	default:
		return fmt.Errorf("%w: WordPress component action", ErrInvalid)
	}
	if mutation.Kind == ComponentCore {
		if mutation.Name != "wordpress" { return fmt.Errorf("%w: WordPress core component", ErrInvalid) }
	} else if !componentNamePattern.MatchString(mutation.Name) {
		return fmt.Errorf("%w: WordPress component name", ErrInvalid)
	}
	if mutation.ExpectedVersion != "" && !versionPattern.MatchString(mutation.ExpectedVersion) { return fmt.Errorf("%w: expected component version", ErrInvalid) }
	if mutation.ExpectedDigest != "" && !validDigest(mutation.ExpectedDigest) { return fmt.Errorf("%w: expected component digest", ErrInvalid) }
	if mutation.Release != nil {
		if err := mutation.Release.Validate(); err != nil { return err }
		if mutation.Release.Application != ApplicationWordPress || mutation.Release.Kind != mutation.Kind || mutation.Release.Name != mutation.Name { return ErrConflict }
	}
	return nil
}

type WordPressURLSettings struct {
	HomeURL string `json:"home_url"`
	SiteURL string `json:"site_url"`
	CanonicalHost string `json:"canonical_host"`
	ForceHTTPS bool `json:"force_https"`
}

func (settings WordPressURLSettings) Validate() error {
	for _, raw := range []string{settings.HomeURL, settings.SiteURL} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" { return fmt.Errorf("%w: WordPress URL", ErrInvalid) }
	}
	if strings.TrimSpace(settings.CanonicalHost) == "" { return fmt.Errorf("%w: canonical host", ErrInvalid) }
	return nil
}

type WordPressGeneralSettings struct {
	Title       string `json:"title"`
	Tagline     string `json:"tagline"`
	AdminEmail  string `json:"admin_email"`
	Locale      string `json:"locale"`
	Timezone    string `json:"timezone"`
	DateFormat  string `json:"date_format"`
	TimeFormat  string `json:"time_format"`
	WeekStartsOn uint8 `json:"week_starts_on"`
	SearchIndexing bool `json:"search_indexing"`
}

type WordPressRuntimeSettings struct {
	PermalinkStructure string `json:"permalink_structure"`
	Debug              bool `json:"debug"`
	DebugLog           bool `json:"debug_log"`
	DisplayErrors      bool `json:"display_errors"`
	Maintenance        bool `json:"maintenance"`
	AutomaticCore      UpdateChannel `json:"automatic_core"`
	DisableFileEditor  bool `json:"disable_file_editor"`
	DisallowFileMods   bool `json:"disallow_file_mods"`
	RevisionLimit      int32 `json:"revision_limit"`
	AutosaveInterval   time.Duration `json:"autosave_interval"`
}

type WordPressSettings struct {
	URLs       WordPressURLSettings `json:"urls"`
	General    WordPressGeneralSettings `json:"general"`
	Runtime    WordPressRuntimeSettings `json:"runtime"`
	Generation uint64 `json:"generation"`
}

func (settings WordPressSettings) Validate() error {
	if err := settings.URLs.Validate(); err != nil { return err }
	if settings.Generation == 0 || len(settings.General.Title) > 256 || len(settings.General.Tagline) > 512 || len(settings.General.AdminEmail) > 320 || !strings.Contains(settings.General.AdminEmail, "@") || settings.General.WeekStartsOn > 6 || len(settings.Runtime.PermalinkStructure) > 256 || strings.ContainsAny(settings.Runtime.PermalinkStructure, "\x00\r\n") || settings.Runtime.AutosaveInterval < 15*time.Second || settings.Runtime.AutosaveInterval > 24*time.Hour {
		return fmt.Errorf("%w: WordPress settings", ErrInvalid)
	}
	return nil
}

type WordPressSettingsMutation struct {
	Scope              SiteExecutionScope `json:"scope"`
	InstallationID     InstallationID `json:"installation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	Settings           WordPressSettings `json:"settings"`
	RecoveryPointID    RecoveryPointID `json:"recovery_point_id,omitempty"`
}

type CacheState string

const (
	CacheDisabled CacheState = "disabled"
	CacheEnabled  CacheState = "enabled"
	CacheDegraded CacheState = "degraded"
)

type LSCachePolicy struct {
	InstallationID InstallationID `json:"installation_id"`
	State          CacheState `json:"state"`
	BrowserCache   bool `json:"browser_cache"`
	ObjectCache    bool `json:"object_cache"`
	PublicTTL      time.Duration `json:"public_ttl"`
	PrivateTTL     time.Duration `json:"private_ttl"`
	Exclusions     []string `json:"exclusions,omitempty"`
	VaryCookies    []string `json:"vary_cookies,omitempty"`
	Generation     uint64 `json:"generation"`
}

func (policy LSCachePolicy) Validate() error {
	if err := requireID("installation", string(policy.InstallationID)); err != nil { return err }
	if policy.Generation == 0 || policy.PublicTTL < 0 || policy.PrivateTTL < 0 || policy.PublicTTL > 365*24*time.Hour || policy.PrivateTTL > 24*time.Hour || policy.State != CacheDisabled && policy.State != CacheEnabled && policy.State != CacheDegraded {
		return fmt.Errorf("%w: LSCache policy", ErrInvalid)
	}
	for _, exclusion := range policy.Exclusions {
		if len(exclusion) == 0 || len(exclusion) > 512 || strings.IndexByte(exclusion, 0) >= 0 || strings.ContainsAny(exclusion, "\r\n") { return fmt.Errorf("%w: cache exclusion", ErrInvalid) }
	}
	return nil
}

type CachePurgeScope string

const (
	PurgeAll CachePurgeScope = "all"
	PurgePath CachePurgeScope = "path"
	PurgeTag CachePurgeScope = "tag"
)

type CacheMutation struct {
	Scope          SiteExecutionScope `json:"scope"`
	InstallationID InstallationID `json:"installation_id"`
	Policy         *LSCachePolicy `json:"policy,omitempty"`
	PurgeScope     CachePurgeScope `json:"purge_scope,omitempty"`
	PurgeValues    []string `json:"purge_values,omitempty"`
}

type AccessProtectionBinding struct {
	InstallationID InstallationID `json:"installation_id"`
	PolicyID       string `json:"policy_id"`
	Route          string `json:"route"`
	Enabled        bool `json:"enabled"`
	Generation     uint64 `json:"generation"`
}

type WordPressExecutor interface {
	MutateComponent(context.Context, ComponentMutation) (ComponentInventory, ExecutionReceipt, error)
	ApplySettings(context.Context, WordPressSettingsMutation) (WordPressSettings, ExecutionReceipt, error)
	ConfigureLSCache(context.Context, CacheMutation) (LSCachePolicy, ExecutionReceipt, error)
	PurgeLSCache(context.Context, CacheMutation) (ExecutionReceipt, error)
	InstallAutologinBridge(context.Context, AutologinBridgeRequest) (ExecutionReceipt, error)
	RemoveAutologinBridge(context.Context, AutologinBridgeRequest) (ExecutionReceipt, error)
}

// WPCLIInvocation invokes the fixed, release-pinned wp-cli binary directly via
// execve as the site UID. It is intentionally argv-based rather than a shell
// string. Options that can escape the registered site or load executable PHP
// supplied outside the application are rejected at admission and again by the
// site worker.
type WPCLIInvocation struct {
	Scope          SiteExecutionScope `json:"scope"`
	InstallationID InstallationID `json:"installation_id"`
	Arguments      []string `json:"arguments"`
	Timeout        time.Duration `json:"timeout"`
	MaximumOutput  uint32 `json:"maximum_output"`
	ReadOnly       bool `json:"read_only"`
}

func (invocation WPCLIInvocation) Validate() error {
	if err := invocation.Scope.Validate(); err != nil { return err }
	if err := requireID("installation", string(invocation.InstallationID)); err != nil { return err }
	if len(invocation.Arguments) == 0 || len(invocation.Arguments) > 128 || invocation.Timeout <= 0 || invocation.Timeout > 2*time.Hour || invocation.MaximumOutput == 0 || invocation.MaximumOutput > 8<<20 {
		return fmt.Errorf("%w: WP-CLI invocation", ErrInvalid)
	}
	blocked := []string{"--path", "--ssh", "--http", "--require", "--exec", "--url="}
	for _, argument := range invocation.Arguments {
		if len(argument) == 0 || len(argument) > 4096 || strings.IndexByte(argument, 0) >= 0 || strings.ContainsAny(argument, "\r\n") {
			return fmt.Errorf("%w: WP-CLI argument", ErrInvalid)
		}
		for _, prefix := range blocked {
			if argument == strings.TrimSuffix(prefix, "=") || strings.HasPrefix(argument, prefix) { return ErrPolicyDenied }
		}
	}
	return nil
}

type WPCLIResult struct {
	ExitCode   int `json:"exit_code"`
	Stdout     []byte `json:"stdout"`
	Stderr     []byte `json:"stderr"`
	Truncated  bool `json:"truncated"`
	Receipt    ExecutionReceipt `json:"receipt"`
}

type WPCLIExecutor interface {
	InvokeWPCLI(context.Context, WPCLIInvocation) (WPCLIResult, error)
}

type LoginGrantState string

const (
	LoginGrantIssued   LoginGrantState = "issued"
	LoginGrantConsumed LoginGrantState = "consumed"
	LoginGrantRevoked  LoginGrantState = "revoked"
	LoginGrantExpired  LoginGrantState = "expired"
)

type LoginGrant struct {
	ID             LoginGrantID `json:"id"`
	TenantID       TenantID `json:"tenant_id"`
	SiteID         SiteID `json:"site_id"`
	InstallationID InstallationID `json:"installation_id"`
	WordPressUserID uint64 `json:"wordpress_user_id"`
	Audience       string `json:"audience"`
	Origin         string `json:"origin"`
	TokenHash      string `json:"token_hash"`
	CSRFBindingHash string `json:"csrf_binding_hash"`
	State          LoginGrantState `json:"state"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	ConsumedAt     time.Time `json:"consumed_at,omitempty"`
	RevokedAt      time.Time `json:"revoked_at,omitempty"`
	Generation     uint64 `json:"generation"`
}

func (grant LoginGrant) Validate() error {
	if err := requireID("login grant", string(grant.ID)); err != nil { return err }
	if err := requireID("tenant", string(grant.TenantID)); err != nil { return err }
	if err := requireID("site", string(grant.SiteID)); err != nil { return err }
	if err := requireID("installation", string(grant.InstallationID)); err != nil { return err }
	if grant.WordPressUserID == 0 || grant.Audience == "" || grant.Origin == "" || !validDigest(grant.TokenHash) || !validDigest(grant.CSRFBindingHash) || grant.IssuedAt.IsZero() || !grant.ExpiresAt.After(grant.IssuedAt) || grant.ExpiresAt.Sub(grant.IssuedAt) > 2*time.Minute || grant.Generation == 0 {
		return fmt.Errorf("%w: login grant", ErrInvalid)
	}
	return nil
}

type LoginCredential struct {
	GrantID LoginGrantID `json:"grant_id"`
	Secret  string `json:"secret"`
	ExchangeEndpoint string `json:"exchange_endpoint"`
	ExpiresAt time.Time `json:"expires_at"`
}

type LoginGrantRequest struct {
	ID              LoginGrantID `json:"id"`
	TenantID        TenantID `json:"tenant_id"`
	SiteID          SiteID `json:"site_id"`
	InstallationID  InstallationID `json:"installation_id"`
	WordPressUserID uint64 `json:"wordpress_user_id"`
	Audience        string `json:"audience"`
	Origin          string `json:"origin"`
	CSRFBinding     string `json:"csrf_binding"`
	TTL             time.Duration `json:"ttl"`
}

type LoginGrantExchange struct {
	GrantID    LoginGrantID `json:"grant_id"`
	Secret     string `json:"secret"`
	Audience   string `json:"audience"`
	Origin     string `json:"origin"`
	CSRFBinding string `json:"csrf_binding"`
	SiteID     SiteID `json:"site_id"`
	InstallationID InstallationID `json:"installation_id"`
}

func (exchange LoginGrantExchange) Validate() error {
	if err := requireID("login grant", string(exchange.GrantID)); err != nil { return err }
	if err := requireID("site", string(exchange.SiteID)); err != nil { return err }
	if err := requireID("installation", string(exchange.InstallationID)); err != nil { return err }
	if len(exchange.Secret) < 43 || len(exchange.Secret) > 256 || len(exchange.Audience) == 0 || len(exchange.Audience) > 512 || len(exchange.Origin) == 0 || len(exchange.Origin) > 2048 || len(exchange.CSRFBinding) < 16 || len(exchange.CSRFBinding) > 512 || strings.ContainsAny(exchange.Audience+exchange.Origin+exchange.CSRFBinding, "\x00\r\n") {
		return fmt.Errorf("%w: login grant exchange", ErrInvalid)
	}
	return nil
}

type LoginGrantStore interface {
	CreateLoginGrant(context.Context, LoginGrant) error
	ConsumeLoginGrant(context.Context, LoginGrantID, uint64, time.Time) (LoginGrant, error)
	LoadLoginGrant(context.Context, LoginGrantID) (LoginGrant, error)
	RevokeLoginGrant(context.Context, LoginGrantID, time.Time) error
}

type RandomTokenSource interface {
	Token(context.Context, uint16) (string, error)
}

type AutologinBridgeRequest struct {
	Scope           SiteExecutionScope `json:"scope"`
	InstallationID  InstallationID `json:"installation_id"`
	BridgeDigest    string `json:"bridge_digest"`
	BridgeSignature string `json:"bridge_signature"`
	SigningKeyID    string `json:"signing_key_id"`
	Endpoint        string `json:"endpoint"`
}

func (request AutologinBridgeRequest) Validate() error {
	if err := request.Scope.Validate(); err != nil { return err }
	if err := requireID("installation", string(request.InstallationID)); err != nil { return err }
	if !validDigest(request.BridgeDigest) || request.BridgeSignature == "" || !validID(request.SigningKeyID) || request.Endpoint == "" || !strings.HasPrefix(request.Endpoint, "/") || strings.ContainsAny(request.Endpoint, "\x00\r\n") {
		return fmt.Errorf("%w: autologin bridge", ErrInvalid)
	}
	return nil
}

type AutologinBridgeVerifier interface {
	VerifyAutologinBridge(context.Context, string, string, string) error
}

type AutologinBridgeManager struct {
	Store    ApplicationStore
	Executor WordPressExecutor
	Verifier AutologinBridgeVerifier
	Now      func() time.Time
}

func (manager AutologinBridgeManager) now() time.Time {
	if manager.Now != nil { return manager.Now().UTC() }
	return time.Now().UTC()
}

func (manager AutologinBridgeManager) Install(ctx context.Context, commandID CommandID, request AutologinBridgeRequest) error {
	if manager.Store == nil || manager.Executor == nil || manager.Verifier == nil { return ErrInvalid }
	if err := request.Validate(); err != nil { return err }
	installation, err := manager.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return err }
	if installation.Kind != ApplicationWordPress || installation.SiteID != request.Scope.SiteID || installation.SiteUID != request.Scope.SiteUID { return ErrConflict }
	if err := manager.Verifier.VerifyAutologinBridge(ctx, request.SigningKeyID, request.BridgeDigest, request.BridgeSignature); err != nil { return ErrRecipeUntrusted }
	digest, err := requestDigest(request)
	if err != nil { return err }
	operation := Operation{CommandID: commandID, Kind: "wordpress_autologin_bridge", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: manager.now(), UpdatedAt: manager.now()}
	operation, created, err := manager.Store.AdmitOperation(ctx, operation)
	if err != nil { return err }
	if !created { if operation.State == OperationCommitted { return nil }; return ErrConflict }
	receipt, err := manager.Executor.InstallAutologinBridge(ctx, request)
	if err != nil { operation.State, operation.Stage, operation.Failure, operation.UpdatedAt = OperationFailed, "install", err.Error(), manager.now(); _ = manager.Store.UpdateOperation(ctx, operation); return err }
	if err := receipt.Validate("install_autologin_bridge", request.Scope, request.InstallationID); err != nil { return err }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, manager.now()
	return manager.Store.UpdateOperation(ctx, operation)
}

func (manager AutologinBridgeManager) Remove(ctx context.Context, commandID CommandID, request AutologinBridgeRequest) error {
	if err := request.Validate(); err != nil { return err }
	installation, err := manager.Store.LoadInstallation(ctx, request.InstallationID)
	if err != nil { return err }
	digest, err := requestDigest(request)
	if err != nil { return err }
	operation := Operation{CommandID: commandID, Kind: "wordpress_autologin_bridge_remove", TenantID: installation.TenantID, SiteID: installation.SiteID, InstallationID: installation.ID, RequestDigest: digest, State: OperationAdmitted, Stage: "admitted", CreatedAt: manager.now(), UpdatedAt: manager.now()}
	operation, created, err := manager.Store.AdmitOperation(ctx, operation)
	if err != nil { return err }
	if !created { if operation.State == OperationCommitted { return nil }; return ErrConflict }
	receipt, err := manager.Executor.RemoveAutologinBridge(ctx, request)
	if err != nil { return err }
	if err := receipt.Validate("remove_autologin_bridge", request.Scope, request.InstallationID); err != nil { return err }
	operation.State, operation.Stage, operation.ResultDigest, operation.UpdatedAt = OperationCommitted, "committed", receipt.OutputDigest, manager.now()
	return manager.Store.UpdateOperation(ctx, operation)
}

type AutologinService struct {
	Store     LoginGrantStore
	Tokens    RandomTokenSource
	Now       func() time.Time
	Endpoint  string
}

func (service AutologinService) Issue(ctx context.Context, request LoginGrantRequest) (LoginGrant, LoginCredential, error) {
	if service.Store == nil || service.Tokens == nil { return LoginGrant{}, LoginCredential{}, fmt.Errorf("%w: autologin dependencies", ErrInvalid) }
	if err := requireID("login grant", string(request.ID)); err != nil { return LoginGrant{}, LoginCredential{}, err }
	if err := requireID("tenant", string(request.TenantID)); err != nil { return LoginGrant{}, LoginCredential{}, err }
	if err := requireID("site", string(request.SiteID)); err != nil { return LoginGrant{}, LoginCredential{}, err }
	if err := requireID("installation", string(request.InstallationID)); err != nil { return LoginGrant{}, LoginCredential{}, err }
	if request.WordPressUserID == 0 || len(request.Audience)==0 || len(request.Audience)>512 || len(request.Origin)==0 || len(request.Origin)>2048 || len(request.CSRFBinding)<16 || len(request.CSRFBinding)>512 || strings.ContainsAny(request.Audience+request.Origin+request.CSRFBinding,"\x00\r\n") || request.TTL <= 0 || request.TTL > 2*time.Minute || service.Endpoint == "" {
		return LoginGrant{}, LoginCredential{}, fmt.Errorf("%w: login grant request", ErrInvalid)
	}
	now := time.Now().UTC()
	if service.Now != nil { now = service.Now().UTC() }
	secret, err := service.Tokens.Token(ctx, 32)
	if err != nil { return LoginGrant{}, LoginCredential{}, err }
	if len(secret) < 43 || len(secret) > 256 { return LoginGrant{}, LoginCredential{}, ErrIntegrity }
	tokenDigest := sha256.Sum256([]byte(secret))
	csrfDigest := sha256.Sum256([]byte(request.CSRFBinding))
	grant := LoginGrant{ID: request.ID, TenantID: request.TenantID, SiteID: request.SiteID, InstallationID: request.InstallationID, WordPressUserID: request.WordPressUserID, Audience: request.Audience, Origin: request.Origin, TokenHash: hex.EncodeToString(tokenDigest[:]), CSRFBindingHash: hex.EncodeToString(csrfDigest[:]), State: LoginGrantIssued, IssuedAt: now, ExpiresAt: now.Add(request.TTL), Generation: 1}
	if err := grant.Validate(); err != nil { return LoginGrant{}, LoginCredential{}, err }
	if err := service.Store.CreateLoginGrant(ctx, grant); err != nil { return LoginGrant{}, LoginCredential{}, err }
	credential := LoginCredential{GrantID: grant.ID, Secret: secret, ExchangeEndpoint: service.Endpoint, ExpiresAt: grant.ExpiresAt}
	return grant, credential, nil
}

func (service AutologinService) Exchange(ctx context.Context, exchange LoginGrantExchange) (LoginGrant, error) {
	if service.Store == nil { return LoginGrant{}, fmt.Errorf("%w: login grant store", ErrInvalid) }
	if err := exchange.Validate(); err != nil { return LoginGrant{}, err }
	now := time.Now().UTC()
	if service.Now != nil { now = service.Now().UTC() }
	grant, err := service.Store.LoadLoginGrant(ctx, exchange.GrantID)
	if err != nil { return LoginGrant{}, err }
	if grant.State == LoginGrantConsumed { return LoginGrant{}, ErrGrantConsumed }
	if grant.State != LoginGrantIssued { return LoginGrant{}, ErrPolicyDenied }
	if !now.Before(grant.ExpiresAt) { return LoginGrant{}, ErrGrantExpired }
	if exchange.Audience != grant.Audience || exchange.Origin != grant.Origin || exchange.SiteID != grant.SiteID || exchange.InstallationID != grant.InstallationID {
		return LoginGrant{}, ErrPolicyDenied
	}
	tokenDigest := sha256.Sum256([]byte(exchange.Secret))
	csrfDigest := sha256.Sum256([]byte(exchange.CSRFBinding))
	if subtle.ConstantTimeCompare([]byte(grant.TokenHash), []byte(hex.EncodeToString(tokenDigest[:]))) != 1 || subtle.ConstantTimeCompare([]byte(grant.CSRFBindingHash), []byte(hex.EncodeToString(csrfDigest[:]))) != 1 {
		return LoginGrant{}, ErrPolicyDenied
	}
	return service.Store.ConsumeLoginGrant(ctx, grant.ID, grant.Generation, now)
}

func (service AutologinService) Revoke(ctx context.Context, id LoginGrantID) error {
	now := time.Now().UTC()
	if service.Now != nil { now = service.Now().UTC() }
	return service.Store.RevokeLoginGrant(ctx, id, now)
}
