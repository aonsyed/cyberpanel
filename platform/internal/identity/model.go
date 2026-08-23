package identity

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalid             = errors.New("identity: invalid value")
	ErrNotFound            = errors.New("identity: not found")
	ErrConflict            = errors.New("identity: conflict")
	ErrForbidden           = errors.New("identity: forbidden")
	ErrUnauthenticated     = errors.New("identity: unauthenticated")
	ErrSuspended           = errors.New("identity: suspended")
	ErrExpired             = errors.New("identity: expired")
	ErrStaleGeneration     = errors.New("identity: stale generation")
	ErrDelegationExceeded  = errors.New("identity: delegation ceiling exceeded")
	ErrQuotaExceeded       = errors.New("identity: quota exceeded")
	ErrAssuranceRequired   = errors.New("identity: additional assurance required")
	ErrSessionBindingStepUp = fmt.Errorf("%w: session binding changed", ErrAssuranceRequired)
	ErrCredentialCompromised = errors.New("identity: credential compromised")
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,62}$`)
var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)
var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,62}:[a-z][a-z0-9_.-]{1,62}$`)

type ID string

func NewID(value string) (ID, error) {
	value = strings.TrimSpace(value)
	if !idPattern.MatchString(value) {
		return "", fmt.Errorf("%w: id", ErrInvalid)
	}
	return ID(value), nil
}

func (id ID) String() string { return string(id) }
func (id ID) Valid() bool    { return idPattern.MatchString(string(id)) }

type PrincipalKind string

const (
	PrincipalHuman   PrincipalKind = "human"
	PrincipalService PrincipalKind = "service"
)

type PrincipalState string

const (
	PrincipalPending   PrincipalState = "pending"
	PrincipalActive    PrincipalState = "active"
	PrincipalSuspended PrincipalState = "suspended"
	PrincipalDeleted   PrincipalState = "deleted"
)

type Theme string

const (
	ThemeSystem Theme = "system"
	ThemeLight  Theme = "light"
	ThemeDark   Theme = "dark"
)

type Principal struct {
	ID              ID
	Kind            PrincipalKind
	Username        string
	Email           string
	DisplayName     string
	State           PrincipalState
	Locale          string
	Theme           Theme
	AuthzEpoch      uint64
	CredentialEpoch uint64
	Generation      uint64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       *time.Time
}

func (p Principal) Validate() error {
	if !p.ID.Valid() || (p.Kind != PrincipalHuman && p.Kind != PrincipalService) || !usernamePattern.MatchString(p.Username) {
		return fmt.Errorf("%w: principal identity", ErrInvalid)
	}
	if p.Kind == PrincipalHuman && (!strings.Contains(p.Email, "@") || len(p.Email) > 254) {
		return fmt.Errorf("%w: email", ErrInvalid)
	}
	if p.State != PrincipalPending && p.State != PrincipalActive && p.State != PrincipalSuspended && p.State != PrincipalDeleted {
		return fmt.Errorf("%w: principal state", ErrInvalid)
	}
	if p.Locale == "" || len(p.Locale) > 35 {
		return fmt.Errorf("%w: locale", ErrInvalid)
	}
	if p.Theme != ThemeSystem && p.Theme != ThemeLight && p.Theme != ThemeDark {
		return fmt.Errorf("%w: theme", ErrInvalid)
	}
	if p.Generation == 0 || p.AuthzEpoch == 0 || p.CredentialEpoch == 0 || p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: principal version", ErrInvalid)
	}
	return nil
}

type TenantKind string

const (
	TenantOwner    TenantKind = "owner"
	TenantReseller TenantKind = "reseller"
	TenantCustomer TenantKind = "customer"
)

type TenantState string

const (
	TenantActive    TenantState = "active"
	TenantSuspended TenantState = "suspended"
	TenantDeleting  TenantState = "deleting"
	TenantDeleted   TenantState = "deleted"
)

type Tenant struct {
	ID             ID
	ParentTenantID ID
	SponsorID      ID
	Kind           TenantKind
	Name           string
	State          TenantState
	PlanID         ID
	Generation     uint64
	AuthzEpoch     uint64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (t Tenant) Validate() error {
	if !t.ID.Valid() || (t.ParentTenantID != "" && !t.ParentTenantID.Valid()) || (t.SponsorID != "" && !t.SponsorID.Valid()) || strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("%w: tenant identity", ErrInvalid)
	}
	if t.Kind != TenantOwner && t.Kind != TenantReseller && t.Kind != TenantCustomer {
		return fmt.Errorf("%w: tenant kind", ErrInvalid)
	}
	if t.State != TenantActive && t.State != TenantSuspended && t.State != TenantDeleting && t.State != TenantDeleted {
		return fmt.Errorf("%w: tenant state", ErrInvalid)
	}
	if t.Kind == TenantOwner && t.ParentTenantID != "" {
		return fmt.Errorf("%w: owner parent", ErrInvalid)
	}
	if t.Kind != TenantOwner && !t.ParentTenantID.Valid() {
		return fmt.Errorf("%w: tenant parent", ErrInvalid)
	}
	if t.Generation == 0 || t.AuthzEpoch == 0 || t.CreatedAt.IsZero() || t.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: tenant version", ErrInvalid)
	}
	return nil
}

type MembershipState string

const (
	MembershipInvited   MembershipState = "invited"
	MembershipActive    MembershipState = "active"
	MembershipSuspended MembershipState = "suspended"
	MembershipRevoked   MembershipState = "revoked"
)

type Membership struct {
	ID          ID
	PrincipalID ID
	TenantID    ID
	State       MembershipState
	Generation  uint64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type InvitationState string

const (
	InvitationPending  InvitationState = "pending"
	InvitationAccepted InvitationState = "accepted"
	InvitationExpired  InvitationState = "expired"
	InvitationRevoked  InvitationState = "revoked"
)

// Invitation is an immutable grant offer except for its lifecycle, delivery,
// token, and generation fields. TokenDigest is persistence-only and must never
// be projected across an API boundary.
type Invitation struct {
	ID              ID
	TenantID        ID
	IntendedEmail   string
	InviterID       ID
	RoleID          ID
	RoleCeiling     []Permission
	Scope           Scope
	State           InvitationState
	Generation      uint64
	TokenEpoch      uint64
	TokenDigest     string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	LastDeliveredAt *time.Time
}

func (i Invitation) Validate() error {
	if !i.ID.Valid() || !i.TenantID.Valid() || !i.InviterID.Valid() || !i.RoleID.Valid() || i.Generation == 0 || i.TokenEpoch == 0 {
		return fmt.Errorf("%w: invitation identity", ErrInvalid)
	}
	if i.IntendedEmail != normalizeInvitationEmail(i.IntendedEmail) || !validInvitationEmail(i.IntendedEmail) {
		return fmt.Errorf("%w: invitation email", ErrInvalid)
	}
	if err := i.Scope.Validate(); err != nil || i.Scope.Kind == ScopeInstallation || i.Scope.TenantID != i.TenantID {
		return fmt.Errorf("%w: invitation scope", ErrInvalid)
	}
	if len(i.RoleCeiling) == 0 {
		return fmt.Errorf("%w: invitation role ceiling", ErrInvalid)
	}
	canonical := CanonicalPermissions(i.RoleCeiling)
	if len(canonical) != len(i.RoleCeiling) {
		return fmt.Errorf("%w: invitation role ceiling", ErrInvalid)
	}
	for index := range canonical {
		if canonical[index] != i.RoleCeiling[index] {
			return fmt.Errorf("%w: invitation role ceiling", ErrInvalid)
		}
		if _, err := NewPermission(string(canonical[index])); err != nil {
			return fmt.Errorf("%w: invitation role ceiling", ErrInvalid)
		}
	}
	if i.CreatedAt.IsZero() || !i.ExpiresAt.After(i.CreatedAt) {
		return fmt.Errorf("%w: invitation lifetime", ErrInvalid)
	}
	if i.LastDeliveredAt != nil && i.LastDeliveredAt.Before(i.CreatedAt) {
		return fmt.Errorf("%w: invitation delivery", ErrInvalid)
	}
	switch i.State {
	case InvitationPending:
		if !validInvitationDigest(i.TokenDigest) {
			return fmt.Errorf("%w: invitation token", ErrInvalid)
		}
	case InvitationAccepted, InvitationExpired, InvitationRevoked:
		if i.TokenDigest != "" {
			return fmt.Errorf("%w: terminal invitation token", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: invitation state", ErrInvalid)
	}
	return nil
}

func (m Membership) Validate() error {
	if !m.ID.Valid() || !m.PrincipalID.Valid() || !m.TenantID.Valid() || m.Generation == 0 {
		return fmt.Errorf("%w: membership identity", ErrInvalid)
	}
	if m.State != MembershipInvited && m.State != MembershipActive && m.State != MembershipSuspended && m.State != MembershipRevoked {
		return fmt.Errorf("%w: membership state", ErrInvalid)
	}
	return nil
}

type Permission string

func NewPermission(value string) (Permission, error) {
	value = strings.TrimSpace(value)
	if value != "*:*" && !permissionPattern.MatchString(value) {
		return "", fmt.Errorf("%w: permission", ErrInvalid)
	}
	return Permission(value), nil
}

func MustPermission(value string) Permission {
	p, err := NewPermission(value)
	if err != nil { panic(err) }
	return p
}

type Role struct {
	ID          ID
	TenantID    ID
	Name        string
	Permissions []Permission
	Builtin     bool
	Generation  uint64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (r Role) Validate() error {
	if !r.ID.Valid() || (r.TenantID != "" && !r.TenantID.Valid()) || strings.TrimSpace(r.Name) == "" || r.Generation == 0 {
		return fmt.Errorf("%w: role identity", ErrInvalid)
	}
	seen := make(map[Permission]struct{}, len(r.Permissions))
	for _, permission := range r.Permissions {
		if permission != "*:*" && !permissionPattern.MatchString(string(permission)) { return fmt.Errorf("%w: role permission", ErrInvalid) }
		if _, ok := seen[permission]; ok { return fmt.Errorf("%w: duplicate permission", ErrInvalid) }
		seen[permission] = struct{}{}
	}
	return nil
}

type ScopeKind string

const (
	ScopeInstallation ScopeKind = "installation"
	ScopeTenant       ScopeKind = "tenant"
	ScopeProject      ScopeKind = "project"
	ScopeSite         ScopeKind = "site"
)

type Scope struct {
	Kind       ScopeKind
	TenantID   ID
	ResourceID ID
}

func (s Scope) Validate() error {
	if s.Kind == ScopeInstallation {
		if s.TenantID != "" || s.ResourceID != "" { return fmt.Errorf("%w: installation scope", ErrInvalid) }
		return nil
	}
	if !s.TenantID.Valid() { return fmt.Errorf("%w: scope tenant", ErrInvalid) }
	if s.Kind == ScopeTenant {
		if s.ResourceID != "" { return fmt.Errorf("%w: tenant scope resource", ErrInvalid) }
		return nil
	}
	if (s.Kind != ScopeProject && s.Kind != ScopeSite) || !s.ResourceID.Valid() { return fmt.Errorf("%w: resource scope", ErrInvalid) }
	return nil
}

type SubjectKind string

const (
	SubjectPrincipal SubjectKind = "principal"
	SubjectService   SubjectKind = "service"
	SubjectTenant    SubjectKind = "tenant"
)

type RoleBinding struct {
	ID         ID
	SubjectKind SubjectKind
	SubjectID  ID
	RoleID     ID
	Scope      Scope
	ExpiresAt  *time.Time
	Generation uint64
	CreatedAt  time.Time
}

func (b RoleBinding) Validate() error {
	if !b.ID.Valid() || !b.SubjectID.Valid() || !b.RoleID.Valid() || b.Generation == 0 || b.CreatedAt.IsZero() || b.Scope.Validate() != nil {
		return fmt.Errorf("%w: role binding", ErrInvalid)
	}
	if b.SubjectKind != SubjectPrincipal && b.SubjectKind != SubjectService && b.SubjectKind != SubjectTenant { return fmt.Errorf("%w: subject kind", ErrInvalid) }
	return nil
}

type DelegationCeiling struct {
	ID              ID
	SponsorTenantID ID
	ChildTenantID   ID
	Permissions     []Permission
	QuotaBudget     ResourceQuota
	Generation      uint64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (d DelegationCeiling) Validate() error {
	if !d.ID.Valid() || !d.SponsorTenantID.Valid() || !d.ChildTenantID.Valid() || d.Generation == 0 || d.SponsorTenantID == d.ChildTenantID || d.QuotaBudget.Validate() != nil {
		return fmt.Errorf("%w: delegation ceiling", ErrInvalid)
	}
	seen := map[Permission]struct{}{}
	for _, p := range d.Permissions {
		if p != "*:*" && !permissionPattern.MatchString(string(p)) { return fmt.Errorf("%w: delegation permission", ErrInvalid) }
		if _, ok := seen[p]; ok { return fmt.Errorf("%w: duplicate delegation permission", ErrInvalid) }
		seen[p] = struct{}{}
	}
	return nil
}

type ResourceQuota struct {
	Sites           uint64
	Domains         uint64
	Databases       uint64
	Mailboxes       uint64
	FTPAccounts     uint64
	DiskBytes       uint64
	Inodes          uint64
	MonthlyTransfer uint64
	CPUQuotaMicros  uint64
	MemoryBytes     uint64
	IOReadBPS       uint64
	IOWriteBPS      uint64
	IOReadIOPS      uint64
	IOWriteIOPS     uint64
	PIDs            uint64
	PHPConcurrency  uint64
}

func (q ResourceQuota) Validate() error {
	if q.Sites == 0 || q.Domains == 0 || q.DiskBytes == 0 || q.Inodes == 0 || q.MemoryBytes == 0 || q.PIDs == 0 || q.PHPConcurrency == 0 {
		return fmt.Errorf("%w: zero required quota", ErrInvalid)
	}
	return nil
}

func (q ResourceQuota) Contains(child ResourceQuota) bool {
	return child.Sites <= q.Sites && child.Domains <= q.Domains && child.Databases <= q.Databases && child.Mailboxes <= q.Mailboxes && child.FTPAccounts <= q.FTPAccounts && child.DiskBytes <= q.DiskBytes && child.Inodes <= q.Inodes && child.MonthlyTransfer <= q.MonthlyTransfer && child.CPUQuotaMicros <= q.CPUQuotaMicros && child.MemoryBytes <= q.MemoryBytes && child.IOReadBPS <= q.IOReadBPS && child.IOWriteBPS <= q.IOWriteBPS && child.IOReadIOPS <= q.IOReadIOPS && child.IOWriteIOPS <= q.IOWriteIOPS && child.PIDs <= q.PIDs && child.PHPConcurrency <= q.PHPConcurrency
}

type Plan struct {
	ID          ID
	OwnerTenantID ID
	Name        string
	Quota       ResourceQuota
	Generation  uint64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (p Plan) Validate() error {
	if !p.ID.Valid() || !p.OwnerTenantID.Valid() || strings.TrimSpace(p.Name) == "" || p.Generation == 0 || p.Quota.Validate() != nil {
		return fmt.Errorf("%w: plan", ErrInvalid)
	}
	return nil
}

type CredentialKind string

const (
	CredentialPassword     CredentialKind = "password"
	CredentialAPIKey       CredentialKind = "api_key"
	CredentialWebAuthn     CredentialKind = "webauthn"
	CredentialTOTP         CredentialKind = "totp"
	CredentialRecoveryCode CredentialKind = "recovery_code"
)

type CredentialState string
const (
	CredentialPending CredentialState = "pending"
	CredentialActive CredentialState = "active"
	CredentialRevoked CredentialState = "revoked"
	CredentialCompromised CredentialState = "compromised"
)

type Credential struct {
	ID             ID
	PrincipalID    ID
	Kind           CredentialKind
	State          CredentialState
	Label          string
	VerifierRef    ID
	PublicData     []byte
	Scopes         []Permission
	AuthzEpoch     uint64
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	ExpiresAt      *time.Time
	RevokedAt      *time.Time
	CompromisedAt  *time.Time
}

func (c Credential) Validate() error {
	if !c.ID.Valid() || !c.PrincipalID.Valid() || !c.VerifierRef.Valid() || c.AuthzEpoch == 0 || c.CreatedAt.IsZero() {
		return fmt.Errorf("%w: credential", ErrInvalid)
	}
	switch c.Kind {
	case CredentialPassword, CredentialAPIKey, CredentialWebAuthn, CredentialTOTP, CredentialRecoveryCode:
	default: return fmt.Errorf("%w: credential kind", ErrInvalid)
	}
	if c.State != CredentialPending && c.State != CredentialActive && c.State != CredentialRevoked && c.State != CredentialCompromised { return fmt.Errorf("%w: credential state", ErrInvalid) }
	for _, p := range c.Scopes { if p != "*:*" && !permissionPattern.MatchString(string(p)) { return fmt.Errorf("%w: credential scope", ErrInvalid) } }
	return nil
}

type AssuranceLevel uint8

const (
	AssurancePassword AssuranceLevel = 1
	AssuranceMFA      AssuranceLevel = 2
	AssurancePhishingResistant AssuranceLevel = 3
)

type SessionBindingMode string

const (
	SessionBindingNone          SessionBindingMode = "none"
	SessionBindingExactAddress  SessionBindingMode = "exact_address"
	SessionBindingPrefix        SessionBindingMode = "prefix"
	SessionBindingRiskBasedStepUp SessionBindingMode = "risk_based_step_up"
)

type SessionBindingPolicy struct {
	Mode           SessionBindingMode
	IPv4PrefixBits uint8
	IPv6PrefixBits uint8
}

func DefaultSessionBindingPolicy() SessionBindingPolicy {
	return SessionBindingPolicy{Mode: SessionBindingExactAddress, IPv4PrefixBits: 32, IPv6PrefixBits: 128}
}

func (p SessionBindingPolicy) Validate() error {
	switch p.Mode {
	case SessionBindingNone:
		if p.IPv4PrefixBits != 0 || p.IPv6PrefixBits != 0 { return fmt.Errorf("%w: session binding none", ErrInvalid) }
	case SessionBindingExactAddress:
		if p.IPv4PrefixBits != 32 || p.IPv6PrefixBits != 128 { return fmt.Errorf("%w: session binding exact address", ErrInvalid) }
	case SessionBindingPrefix, SessionBindingRiskBasedStepUp:
		if p.IPv4PrefixBits == 0 || p.IPv4PrefixBits > 32 || p.IPv6PrefixBits == 0 || p.IPv6PrefixBits > 128 { return fmt.Errorf("%w: session binding prefix", ErrInvalid) }
	default:
		return fmt.Errorf("%w: session binding mode", ErrInvalid)
	}
	return nil
}

func (p SessionBindingPolicy) PrefixFor(source netip.Addr) (netip.Prefix, error) {
	if err := p.Validate(); err != nil || !source.IsValid() { return netip.Prefix{}, ErrInvalid }
	source = source.Unmap()
	bits := source.BitLen()
	if p.Mode == SessionBindingPrefix || p.Mode == SessionBindingRiskBasedStepUp {
		if source.Is4() { bits = int(p.IPv4PrefixBits) } else { bits = int(p.IPv6PrefixBits) }
	}
	return netip.PrefixFrom(source, bits).Masked(), nil
}

type PrincipalSessionPolicy struct {
	PrincipalID ID
	Binding     SessionBindingPolicy
	Generation  uint64
	UpdatedAt   time.Time
}

func (p PrincipalSessionPolicy) Validate() error {
	if !p.PrincipalID.Valid() || p.Generation == 0 || p.UpdatedAt.IsZero() { return fmt.Errorf("%w: principal session policy", ErrInvalid) }
	return p.Binding.Validate()
}

type Session struct {
	ID                ID
	PrincipalID       ID
	CredentialID      ID
	AuthzEpoch        uint64
	CredentialEpoch   uint64
	Assurance         AssuranceLevel
	BindingPolicy     SessionBindingPolicy
	SourcePrefix      netip.Prefix
	UserAgentDigest   string
	CSRFSecretDigest  string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
}

func (s Session) Validate() error {
	if !s.ID.Valid() || !s.PrincipalID.Valid() || !s.CredentialID.Valid() || s.AuthzEpoch == 0 || s.CredentialEpoch == 0 || s.Assurance < AssurancePassword || s.Assurance > AssurancePhishingResistant || s.BindingPolicy.Validate() != nil || !s.SourcePrefix.IsValid() || s.SourcePrefix != s.SourcePrefix.Masked() || s.CreatedAt.IsZero() || s.LastSeenAt.Before(s.CreatedAt) || !s.ExpiresAt.After(s.CreatedAt) || s.AbsoluteExpiresAt.Before(s.ExpiresAt) {
		return fmt.Errorf("%w: session", ErrInvalid)
	}
	expectedBits := s.SourcePrefix.Addr().BitLen()
	if s.BindingPolicy.Mode == SessionBindingPrefix || s.BindingPolicy.Mode == SessionBindingRiskBasedStepUp {
		if s.SourcePrefix.Addr().Is4() { expectedBits = int(s.BindingPolicy.IPv4PrefixBits) } else { expectedBits = int(s.BindingPolicy.IPv6PrefixBits) }
	}
	if s.SourcePrefix.Bits() != expectedBits { return fmt.Errorf("%w: session binding prefix", ErrInvalid) }
	if s.RevokedAt != nil && s.RevokedAt.Before(s.CreatedAt) { return fmt.Errorf("%w: session revocation", ErrInvalid) }
	return nil
}

type SessionMetadata struct {
	ID                ID
	Assurance         AssuranceLevel
	BindingPolicy     SessionBindingPolicy
	SourcePrefix      netip.Prefix
	UserAgentDigest   string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
}

type SupportGrantState string

const (
	SupportGrantPending  SupportGrantState = "pending"
	SupportGrantConsumed SupportGrantState = "consumed"
	SupportGrantExpired  SupportGrantState = "expired"
	SupportGrantRevoked  SupportGrantState = "revoked"
)

type SupportGrantReasonCode string

const (
	SupportGrantReasonInvalidRequest       SupportGrantReasonCode = "invalid_request"
	SupportGrantReasonSessionRequired      SupportGrantReasonCode = "session_required"
	SupportGrantReasonAssuranceRequired    SupportGrantReasonCode = "phishing_resistant_assurance_required"
	SupportGrantReasonAssuranceStale       SupportGrantReasonCode = "phishing_resistant_assurance_stale"
	SupportGrantReasonAuthorizationDenied  SupportGrantReasonCode = "authorization_denied"
	SupportGrantReasonCeilingExceeded      SupportGrantReasonCode = "permission_ceiling_exceeded"
	SupportGrantReasonTenantNotFound       SupportGrantReasonCode = "target_tenant_not_found"
	SupportGrantReasonTenantInactive       SupportGrantReasonCode = "target_tenant_inactive"
	SupportGrantReasonNotFound             SupportGrantReasonCode = "grant_not_found"
	SupportGrantReasonSecretInvalid        SupportGrantReasonCode = "secret_invalid"
	SupportGrantReasonExpired              SupportGrantReasonCode = "grant_expired"
	SupportGrantReasonStateConflict        SupportGrantReasonCode = "state_conflict"
	SupportGrantReasonStaleGeneration      SupportGrantReasonCode = "stale_generation"
	SupportGrantReasonStorageFailure       SupportGrantReasonCode = "storage_failure"
	SupportGrantReasonIssued               SupportGrantReasonCode = "issued"
	SupportGrantReasonAccepted             SupportGrantReasonCode = "accepted"
	SupportGrantReasonRevoked              SupportGrantReasonCode = "revoked"
)

type SupportGrantFailure struct {
	Code SupportGrantReasonCode
	Err  error
}

func (f SupportGrantFailure) Error() string { return "identity: support grant: " + string(f.Code) }
func (f SupportGrantFailure) Unwrap() error { return f.Err }

func SupportGrantFailureReason(err error) (SupportGrantReasonCode, bool) {
	var failure SupportGrantFailure
	if !errors.As(err, &failure) { return "", false }
	return failure.Code, true
}

type SupportContextGrant struct {
	ID                    ID
	IssuerID              ID
	TargetTenantID        ID
	Scope                 Scope
	Permissions           []Permission
	Reason                string
	State                 SupportGrantState
	Generation            uint64
	IssuedAt              time.Time
	ExpiresAt             time.Time
	ConsumedAt            *time.Time
	ConsumedByPrincipalID ID
	ConsumedBySessionID   ID
	ContextID             ID
	ExpiredAt             *time.Time
	RevokedAt             *time.Time
	RevokedByID           ID
	secretEpoch           uint64
	secretDigest          string
}

func (g SupportContextGrant) Validate() error {
	if !g.ID.Valid() || !g.IssuerID.Valid() || !g.TargetTenantID.Valid() || g.Generation == 0 || g.secretEpoch == 0 {
		return fmt.Errorf("%w: support grant identity", ErrInvalid)
	}
	if err := g.Scope.Validate(); err != nil || g.Scope.TenantID != g.TargetTenantID || (g.Scope.Kind != ScopeProject && g.Scope.Kind != ScopeSite) {
		return fmt.Errorf("%w: support grant scope", ErrInvalid)
	}
	if len(g.Permissions) == 0 || len(g.Permissions) > 16 {
		return fmt.Errorf("%w: support grant permissions", ErrInvalid)
	}
	canonical := CanonicalPermissions(g.Permissions)
	if len(canonical) != len(g.Permissions) { return fmt.Errorf("%w: support grant permissions", ErrInvalid) }
	for index, permission := range canonical {
		if permission == "*:*" || permission != g.Permissions[index] { return fmt.Errorf("%w: support grant permissions", ErrInvalid) }
		if _, err := NewPermission(string(permission)); err != nil { return fmt.Errorf("%w: support grant permissions", ErrInvalid) }
	}
	if g.Reason != strings.TrimSpace(g.Reason) || len(g.Reason) < 8 || len(g.Reason) > 512 || strings.ContainsAny(g.Reason, "\x00\r\n") {
		return fmt.Errorf("%w: support grant reason", ErrInvalid)
	}
	if g.IssuedAt.IsZero() || !g.ExpiresAt.After(g.IssuedAt) || g.ExpiresAt.After(g.IssuedAt.Add(time.Hour)) {
		return fmt.Errorf("%w: support grant lifetime", ErrInvalid)
	}
	if g.ConsumedAt != nil && (g.ConsumedAt.Before(g.IssuedAt) || !g.ConsumedAt.Before(g.ExpiresAt)) { return fmt.Errorf("%w: support grant consumption time", ErrInvalid) }
	if g.ExpiredAt != nil && g.ExpiredAt.Before(g.ExpiresAt) { return fmt.Errorf("%w: support grant expiration time", ErrInvalid) }
	if g.RevokedAt != nil && g.RevokedAt.Before(g.IssuedAt) { return fmt.Errorf("%w: support grant revocation time", ErrInvalid) }
	consumed := g.ConsumedAt != nil || g.ConsumedByPrincipalID != "" || g.ConsumedBySessionID != "" || g.ContextID != ""
	switch g.State {
	case SupportGrantPending:
		if !validSupportGrantDigest(g.secretDigest) || consumed || g.ExpiredAt != nil || g.RevokedAt != nil || g.RevokedByID != "" { return fmt.Errorf("%w: pending support grant", ErrInvalid) }
	case SupportGrantConsumed:
		if g.secretDigest != "" || g.ConsumedAt == nil || !g.ConsumedByPrincipalID.Valid() || !g.ConsumedBySessionID.Valid() || !g.ContextID.Valid() || g.ExpiredAt != nil || g.RevokedAt != nil || g.RevokedByID != "" { return fmt.Errorf("%w: consumed support grant", ErrInvalid) }
	case SupportGrantExpired:
		if g.secretDigest != "" || consumed || g.ExpiredAt == nil || g.RevokedAt != nil || g.RevokedByID != "" { return fmt.Errorf("%w: expired support grant", ErrInvalid) }
	case SupportGrantRevoked:
		if g.secretDigest != "" || g.ExpiredAt != nil || g.RevokedAt == nil || !g.RevokedByID.Valid() { return fmt.Errorf("%w: revoked support grant", ErrInvalid) }
		if consumed && (g.ConsumedAt == nil || !g.ConsumedByPrincipalID.Valid() || !g.ConsumedBySessionID.Valid() || !g.ContextID.Valid()) { return fmt.Errorf("%w: revoked support context", ErrInvalid) }
	default:
		return fmt.Errorf("%w: support grant state", ErrInvalid)
	}
	return nil
}

type SupportGrantView struct {
	ID                    ID
	IssuerID              ID
	TargetTenantID        ID
	Scope                 Scope
	Permissions           []Permission
	Reason                string
	State                 SupportGrantState
	Generation            uint64
	IssuedAt              time.Time
	ExpiresAt             time.Time
	ConsumedAt            *time.Time
	ConsumedByPrincipalID ID
	ConsumedBySessionID   ID
	ContextID             ID
	ExpiredAt             *time.Time
	RevokedAt             *time.Time
	RevokedByID           ID
}

type IssuedSupportGrant struct {
	Grant  SupportGrantView
	Secret []byte
}

type SupportContext struct {
	ID                 ID
	GrantID            ID
	SupportPrincipalID ID
	SupportSessionID   ID
	TargetTenantID     ID
	Scope              Scope
	Permissions        []Permission
	Reason             string
	AcceptedAt         time.Time
	ExpiresAt          time.Time
}

func (c SupportContext) Validate() error {
	if !c.ID.Valid() || !c.GrantID.Valid() || !c.SupportPrincipalID.Valid() || !c.SupportSessionID.Valid() || !c.TargetTenantID.Valid() || c.AcceptedAt.IsZero() || !c.ExpiresAt.After(c.AcceptedAt) {
		return fmt.Errorf("%w: support context identity", ErrInvalid)
	}
	if err := c.Scope.Validate(); err != nil || c.Scope.TenantID != c.TargetTenantID || (c.Scope.Kind != ScopeProject && c.Scope.Kind != ScopeSite) { return fmt.Errorf("%w: support context scope", ErrInvalid) }
	if len(c.Permissions) == 0 || len(c.Permissions) > 16 { return fmt.Errorf("%w: support context permissions", ErrInvalid) }
	return nil
}

type Usage struct {
	TenantID        ID
	Sites           uint64
	Domains         uint64
	Databases       uint64
	Mailboxes       uint64
	FTPAccounts     uint64
	DiskBytes       uint64
	Inodes          uint64
	MonthlyTransfer uint64
	UpdatedAt       time.Time
}

func CanonicalPermissions(values []Permission) []Permission {
	seen := make(map[Permission]struct{}, len(values))
	result := make([]Permission, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok { continue }
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
