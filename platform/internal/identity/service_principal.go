package identity

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	serviceCredentialPrefix       = "spk"
	serviceCredentialMaxLifetime = 365 * 24 * time.Hour
	serviceCredentialMaxOverlap  = 15 * time.Minute
	serviceCredentialRecentMFA   = 10 * time.Minute
)

type ServicePrincipalState string

const (
	ServicePrincipalEnabled   ServicePrincipalState = "enabled"
	ServicePrincipalSuspended ServicePrincipalState = "suspended"
	ServicePrincipalDeleted   ServicePrincipalState = "deleted"
)

// ServicePrincipal is a tenant-owned, non-human identity. PrincipalID is
// immutable; the role and selectors form the maximum authorization surface.
type ServicePrincipal struct {
	ID                ID
	PrincipalID       ID
	TenantID          ID
	RoleID            ID
	DisplayName       string
	Description       string
	State             ServicePrincipalState
	PermissionCeiling []Permission
	ScopeCeiling      Scope
	ResourceSelectors []Scope
	AuthzEpoch        uint64
	Generation        uint64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         *time.Time
}

func (p ServicePrincipal) Validate() error {
	if !p.ID.Valid() || p.PrincipalID != p.ID || !p.TenantID.Valid() || !p.RoleID.Valid() || p.AuthzEpoch == 0 || p.Generation == 0 || p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() { return fmt.Errorf("%w: service principal identity", ErrInvalid) }
	if p.DisplayName != strings.TrimSpace(p.DisplayName) || len(p.DisplayName) < 1 || len(p.DisplayName) > 128 || strings.ContainsAny(p.DisplayName, "\x00\r\n\t") || p.Description != strings.TrimSpace(p.Description) || len(p.Description) > 512 || strings.ContainsAny(p.Description, "\x00\r\n") { return fmt.Errorf("%w: service principal metadata", ErrInvalid) }
	if p.State != ServicePrincipalEnabled && p.State != ServicePrincipalSuspended && p.State != ServicePrincipalDeleted { return fmt.Errorf("%w: service principal state", ErrInvalid) }
	if p.ScopeCeiling.Validate() != nil || p.ScopeCeiling.Kind == ScopeInstallation || p.ScopeCeiling.TenantID != p.TenantID { return fmt.Errorf("%w: service principal scope ceiling", ErrInvalid) }
	canonical := CanonicalPermissions(p.PermissionCeiling)
	if len(canonical) < 1 || len(canonical) > 32 || len(canonical) != len(p.PermissionCeiling) { return fmt.Errorf("%w: service principal permission ceiling", ErrInvalid) }
	for index, permission := range canonical { if permission == "*:*" || permission != p.PermissionCeiling[index] { return fmt.Errorf("%w: service principal permission ceiling", ErrInvalid) } }
	if len(p.ResourceSelectors) < 1 || len(p.ResourceSelectors) > 32 { return fmt.Errorf("%w: service principal selectors", ErrInvalid) }
	seen := make(map[string]struct{}, len(p.ResourceSelectors))
	for _, selector := range p.ResourceSelectors {
		if selector.Validate() != nil || selector.Kind == ScopeInstallation || selector.TenantID != p.TenantID || !scopeContains(p.ScopeCeiling, selector) { return fmt.Errorf("%w: service principal selector", ErrInvalid) }
		key := string(selector.Kind) + "\x00" + selector.TenantID.String() + "\x00" + selector.ResourceID.String()
		if _, exists := seen[key]; exists { return fmt.Errorf("%w: duplicate service principal selector", ErrInvalid) }
		seen[key] = struct{}{}
	}
	if p.State == ServicePrincipalDeleted && p.DeletedAt == nil || p.State != ServicePrincipalDeleted && p.DeletedAt != nil { return fmt.Errorf("%w: service principal deletion", ErrInvalid) }
	return nil
}

type APINetworkBindingMode string

const (
	APINetworkBindingNone         APINetworkBindingMode = "none"
	APINetworkBindingExactAddress APINetworkBindingMode = "exact_address"
	APINetworkBindingPrefix       APINetworkBindingMode = "prefix"
)

type APINetworkBinding struct { Mode APINetworkBindingMode; Prefix netip.Prefix }

func (b APINetworkBinding) Validate() error {
	switch b.Mode {
	case APINetworkBindingNone:
		if b.Prefix.IsValid() { return fmt.Errorf("%w: API network binding none", ErrInvalid) }
	case APINetworkBindingExactAddress:
		if !b.Prefix.IsValid() || b.Prefix != b.Prefix.Masked() || b.Prefix.Bits() != b.Prefix.Addr().BitLen() { return fmt.Errorf("%w: API exact-address binding", ErrInvalid) }
	case APINetworkBindingPrefix:
		if !b.Prefix.IsValid() || b.Prefix != b.Prefix.Masked() || b.Prefix.Bits() < 1 { return fmt.Errorf("%w: API prefix binding", ErrInvalid) }
	default:
		return fmt.Errorf("%w: API network binding mode", ErrInvalid)
	}
	return nil
}

func (b APINetworkBinding) Allows(source netip.Addr) bool { if b.Validate() != nil || !source.IsValid() { return false }; if b.Mode == APINetworkBindingNone { return true }; return b.Prefix.Contains(source.Unmap()) }

type ServiceAPICredentialState string

const (
	ServiceAPICredentialActive  ServiceAPICredentialState = "active"
	ServiceAPICredentialRevoked ServiceAPICredentialState = "revoked"
)

// ServiceAPICredential contains only redacted credential metadata. verifierRef
// is persistence-only and the plaintext secret is returned solely by issuance.
type ServiceAPICredential struct {
	ID                 ID
	ServicePrincipalID ID
	TenantID           ID
	Prefix             string
	Label              string
	State              ServiceAPICredentialState
	VerifierVersion    uint8
	AuthzEpoch         uint64
	NotBefore          time.Time
	ExpiresAt          time.Time
	LastUsedAt         *time.Time
	Audience           string
	NetworkBinding     APINetworkBinding
	RotatedFromID      ID
	RotatedToID        ID
	OverlapUntil       *time.Time
	Generation         uint64
	CreatedAt          time.Time
	RevokedAt          *time.Time
	verifierRef        ID
}

func (c ServiceAPICredential) Validate() error {
	if !c.ID.Valid() || !c.ServicePrincipalID.Valid() || !c.TenantID.Valid() || !c.verifierRef.Valid() || len(c.Prefix) != 16 || c.VerifierVersion != 1 || c.AuthzEpoch == 0 || c.Generation == 0 || c.CreatedAt.IsZero() || c.NotBefore.IsZero() || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.NotBefore) { return fmt.Errorf("%w: service API credential identity", ErrInvalid) }
	for _, character := range c.Prefix { if character < '0' || character > '9' && character < 'a' || character > 'f' { return fmt.Errorf("%w: service API credential prefix", ErrInvalid) } }
	if c.Label != strings.TrimSpace(c.Label) || len(c.Label) < 1 || len(c.Label) > 128 || strings.ContainsAny(c.Label, "\x00\r\n\t") || c.Audience == "" || normalizeServiceAudience(c.Audience) != c.Audience { return fmt.Errorf("%w: service API credential metadata", ErrInvalid) }
	if c.NetworkBinding.Validate() != nil { return fmt.Errorf("%w: service API credential network", ErrInvalid) }
	if c.State != ServiceAPICredentialActive && c.State != ServiceAPICredentialRevoked { return fmt.Errorf("%w: service API credential state", ErrInvalid) }
	if c.State == ServiceAPICredentialRevoked && c.RevokedAt == nil || c.State != ServiceAPICredentialRevoked && c.RevokedAt != nil { return fmt.Errorf("%w: service API credential revocation", ErrInvalid) }
	if c.RotatedFromID != "" && !c.RotatedFromID.Valid() || c.RotatedToID != "" && !c.RotatedToID.Valid() { return fmt.Errorf("%w: service API credential rotation", ErrInvalid) }
	if c.RotatedToID == "" && c.OverlapUntil != nil || c.RotatedToID != "" && c.OverlapUntil == nil { return fmt.Errorf("%w: service API credential overlap", ErrInvalid) }
	return nil
}

type IssuedServiceAPICredential struct { Credential ServiceAPICredential; Secret []byte }

type CreateServicePrincipalCommand struct {
	Actor             ActorContext
	ServicePrincipalID ID
	TenantID          ID
	DisplayName       string
	Description       string
	PermissionCeiling []Permission
	ScopeCeiling      Scope
	ResourceSelectors []Scope
}

type UpdateServicePrincipalCommand struct {
	Actor              ActorContext
	ServicePrincipalID ID
	TenantID           ID
	ExpectedGeneration uint64
	DisplayName        string
	Description        string
	PermissionCeiling  []Permission
	ScopeCeiling       Scope
	ResourceSelectors  []Scope
}

type IssueServiceAPICredentialCommand struct {
	Actor              ActorContext
	CredentialID       ID
	ServicePrincipalID ID
	TenantID           ID
	Label              string
	NotBefore          time.Time
	ExpiresAt          time.Time
	Audience           string
	NetworkBinding     APINetworkBinding
}

type RotateServiceAPICredentialCommand struct {
	Actor                 ActorContext
	CredentialID          ID
	PreviousCredentialID  ID
	ServicePrincipalID    ID
	TenantID              ID
	ExpectedGeneration    uint64
	Label                 string
	NotBefore             time.Time
	ExpiresAt             time.Time
	Audience              string
	NetworkBinding        APINetworkBinding
	Overlap               time.Duration
}

const servicePrincipalSelect = `SELECT id,principal_id,tenant_id,role_id,display_name,description,state,permissions_json,scope_kind,scope_resource_id,selectors_json,authz_epoch,generation,created_at,updated_at,deleted_at FROM identity_service_principals`

type servicePrincipalScanner interface{ Scan(...any) error }

func scanServicePrincipal(row servicePrincipalScanner) (ServicePrincipal, error) {
	var value ServicePrincipal
	var state, scopeKind string
	var permissions, selectors []byte
	var deleted sql.NullTime
	err := row.Scan(&value.ID, &value.PrincipalID, &value.TenantID, &value.RoleID, &value.DisplayName, &value.Description, &state, &permissions, &scopeKind, &value.ScopeCeiling.ResourceID, &selectors, &value.AuthzEpoch, &value.Generation, &value.CreatedAt, &value.UpdatedAt, &deleted)
	if errors.Is(err, sql.ErrNoRows) { return ServicePrincipal{}, ErrNotFound }
	if err != nil { return ServicePrincipal{}, err }
	if err = json.Unmarshal(permissions, &value.PermissionCeiling); err != nil { return ServicePrincipal{}, err }
	if err = json.Unmarshal(selectors, &value.ResourceSelectors); err != nil { return ServicePrincipal{}, err }
	value.State = ServicePrincipalState(state)
	value.ScopeCeiling.Kind = ScopeKind(scopeKind)
	value.ScopeCeiling.TenantID = value.TenantID
	if deleted.Valid { value.DeletedAt = &deleted.Time }
	return value, value.Validate()
}

func (s *Store) ServicePrincipal(ctx context.Context, tenantID, id ID) (ServicePrincipal, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || !id.Valid() { return ServicePrincipal{}, ErrInvalid }
	return scanServicePrincipal(s.db.QueryRowContext(ctx, servicePrincipalSelect+` WHERE tenant_id=? AND id=?`, tenantID, id))
}

func (s *Store) ListServicePrincipals(ctx context.Context, tenantID ID, limit int, cursor ID) ([]ServicePrincipal, string, uint64, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || limit < 1 || limit > 100 || cursor != "" && !cursor.Valid() { return nil, "", 0, ErrInvalid }
	var total uint64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_service_principals WHERE tenant_id=?`, tenantID).Scan(&total); err != nil { return nil, "", 0, err }
	rows, err := s.db.QueryContext(ctx, servicePrincipalSelect+` WHERE tenant_id=? AND id>? ORDER BY id LIMIT ?`, tenantID, cursor, limit+1)
	if err != nil { return nil, "", 0, err }
	defer rows.Close()
	values := make([]ServicePrincipal, 0, limit)
	for rows.Next() { value, scanErr := scanServicePrincipal(rows); if scanErr != nil { return nil, "", 0, scanErr }; values = append(values, value) }
	if err = rows.Err(); err != nil { return nil, "", 0, err }
	next := ""
	if len(values) > limit { next = values[limit-1].ID.String(); values = values[:limit] }
	return values, next, total, nil
}

const serviceAPICredentialSelect = `SELECT id,service_principal_id,tenant_id,prefix,verifier_ref,label,state,verifier_version,authz_epoch,not_before,expires_at,last_used_at,audience,network_mode,network_prefix,rotated_from_id,rotated_to_id,overlap_until,generation,created_at,revoked_at FROM identity_service_api_credentials`

type serviceAPICredentialScanner interface{ Scan(...any) error }

func scanServiceAPICredential(row serviceAPICredentialScanner) (ServiceAPICredential, error) {
	var value ServiceAPICredential
	var state, networkMode, networkPrefix string
	var lastUsed, overlap, revoked sql.NullTime
	err := row.Scan(&value.ID, &value.ServicePrincipalID, &value.TenantID, &value.Prefix, &value.verifierRef, &value.Label, &state, &value.VerifierVersion, &value.AuthzEpoch, &value.NotBefore, &value.ExpiresAt, &lastUsed, &value.Audience, &networkMode, &networkPrefix, &value.RotatedFromID, &value.RotatedToID, &overlap, &value.Generation, &value.CreatedAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) { return ServiceAPICredential{}, ErrNotFound }
	if err != nil { return ServiceAPICredential{}, err }
	value.State = ServiceAPICredentialState(state)
	value.NetworkBinding.Mode = APINetworkBindingMode(networkMode)
	if networkPrefix != "" { value.NetworkBinding.Prefix, err = netip.ParsePrefix(networkPrefix); if err != nil || value.NetworkBinding.Prefix.String() != networkPrefix { return ServiceAPICredential{}, ErrInvalid } }
	if lastUsed.Valid { value.LastUsedAt = &lastUsed.Time }
	if overlap.Valid { value.OverlapUntil = &overlap.Time }
	if revoked.Valid { value.RevokedAt = &revoked.Time }
	return value, value.Validate()
}

func (s *Store) ServiceAPICredential(ctx context.Context, tenantID, servicePrincipalID, id ID) (ServiceAPICredential, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || !servicePrincipalID.Valid() || !id.Valid() { return ServiceAPICredential{}, ErrInvalid }
	return scanServiceAPICredential(s.db.QueryRowContext(ctx, serviceAPICredentialSelect+` WHERE tenant_id=? AND service_principal_id=? AND id=?`, tenantID, servicePrincipalID, id))
}

func (s *Store) serviceAPICredentialByID(ctx context.Context, id ID) (ServiceAPICredential, error) {
	if s == nil || s.db == nil || ctx == nil || !id.Valid() { return ServiceAPICredential{}, ErrInvalid }
	return scanServiceAPICredential(s.db.QueryRowContext(ctx, serviceAPICredentialSelect+` WHERE id=?`, id))
}

func (s *Store) ListServiceAPICredentials(ctx context.Context, tenantID, servicePrincipalID ID, limit int, cursor ID) ([]ServiceAPICredential, string, uint64, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || !servicePrincipalID.Valid() || limit < 1 || limit > 100 || cursor != "" && !cursor.Valid() { return nil, "", 0, ErrInvalid }
	var total uint64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_service_api_credentials WHERE tenant_id=? AND service_principal_id=?`, tenantID, servicePrincipalID).Scan(&total); err != nil { return nil, "", 0, err }
	rows, err := s.db.QueryContext(ctx, serviceAPICredentialSelect+` WHERE tenant_id=? AND service_principal_id=? AND id>? ORDER BY id LIMIT ?`, tenantID, servicePrincipalID, cursor, limit+1)
	if err != nil { return nil, "", 0, err }
	defer rows.Close()
	values := make([]ServiceAPICredential, 0, limit)
	for rows.Next() { value, scanErr := scanServiceAPICredential(rows); if scanErr != nil { return nil, "", 0, scanErr }; values = append(values, value) }
	if err = rows.Err(); err != nil { return nil, "", 0, err }
	next := ""
	if len(values) > limit { next = values[limit-1].ID.String(); values = values[:limit] }
	return values, next, total, nil
}

func normalizeServiceAudience(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 1 || len(value) > 255 || strings.ContainsAny(value, "\x00\r\n\t /\\@") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") { return "" }
	return value
}

func normalizeServicePrincipalInput(displayName, description string, permissions []Permission, ceiling Scope, selectors []Scope) (string, string, []Permission, Scope, []Scope) {
	displayName, description = strings.TrimSpace(displayName), strings.TrimSpace(description)
	permissions = CanonicalPermissions(permissions)
	selectors = append([]Scope(nil), selectors...)
	return displayName, description, permissions, ceiling, selectors
}

func samePermissions(left, right []Permission) bool {
	if len(left) != len(right) { return false }
	for index := range left { if left[index] != right[index] { return false } }
	return true
}

func sameScopes(left, right []Scope) bool {
	if len(left) != len(right) { return false }
	for index := range left { if left[index] != right[index] { return false } }
	return true
}

func sameServicePrincipalDefinition(left, right ServicePrincipal) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.DisplayName == right.DisplayName && left.Description == right.Description && left.ScopeCeiling == right.ScopeCeiling && samePermissions(left.PermissionCeiling, right.PermissionCeiling) && sameScopes(left.ResourceSelectors, right.ResourceSelectors)
}

func (s *Service) authorizeServicePrincipalAdmin(ctx context.Context, actor ActorContext, tenantID ID, minimum AssuranceLevel) error {
	_, err := s.authorize(ctx, actor, MustPermission("principal:manage"), Scope{Kind: ScopeTenant, TenantID: tenantID}, minimum)
	return err
}

func (s *Service) validateServicePrincipalCeiling(ctx context.Context, actor ActorContext, value ServicePrincipal) error {
	for _, permission := range value.PermissionCeiling {
		if _, err := s.authorize(ctx, actor, permission, value.ScopeCeiling, AssuranceMFA); err != nil { return ErrDelegationExceeded }
	}
	return nil
}

func servicePrincipalBindingID(principal ID, selector Scope) (ID, error) {
	return derivedID("spb", principal.String()+"\x00"+string(selector.Kind)+"\x00"+selector.TenantID.String()+"\x00"+selector.ResourceID.String())
}

func insertServicePrincipalRecord(ctx context.Context, tx *sql.Tx, value ServicePrincipal) error {
	permissions, err := json.Marshal(value.PermissionCeiling); if err != nil { return err }
	selectors, err := json.Marshal(value.ResourceSelectors); if err != nil { return err }
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_service_principals(id,principal_id,tenant_id,role_id,display_name,description,state,permissions_json,scope_kind,scope_resource_id,selectors_json,authz_epoch,generation,created_at,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.ID, value.PrincipalID, value.TenantID, value.RoleID, value.DisplayName, value.Description, value.State, permissions, value.ScopeCeiling.Kind, value.ScopeCeiling.ResourceID, selectors, value.AuthzEpoch, value.Generation, value.CreatedAt, value.UpdatedAt, value.DeletedAt)
	return err
}

func insertServiceBindings(ctx context.Context, tx *sql.Tx, value ServicePrincipal, generation uint64) error {
	for _, selector := range value.ResourceSelectors {
		bindingID, err := servicePrincipalBindingID(value.ID, selector); if err != nil { return err }
		_, err = tx.ExecContext(ctx, `INSERT INTO identity_role_bindings(id,subject_kind,subject_id,role_id,scope_kind,tenant_id,resource_id,expires_at,generation,created_at) VALUES(?,?,?,?,?,?,?,NULL,?,?)`, bindingID, SubjectService, value.PrincipalID, value.RoleID, selector.Kind, selector.TenantID, selector.ResourceID, generation, value.CreatedAt)
		if err != nil { return err }
	}
	return nil
}

func (s *Service) CreateServicePrincipal(ctx context.Context, command CreateServicePrincipalCommand) (ServicePrincipal, error) {
	if s == nil || s.store == nil || ctx == nil || !command.ServicePrincipalID.Valid() || !command.TenantID.Valid() { return ServicePrincipal{}, ErrInvalid }
	if err := s.authorizeServicePrincipalAdmin(ctx, command.Actor, command.TenantID, AssuranceMFA); err != nil { return ServicePrincipal{}, err }
	displayName, description, permissions, ceiling, selectors := normalizeServicePrincipalInput(command.DisplayName, command.Description, command.PermissionCeiling, command.ScopeCeiling, command.ResourceSelectors)
	roleID, err := derivedID("spr", command.ServicePrincipalID.String()+"\x00role"); if err != nil { return ServicePrincipal{}, err }
	now := s.clock().UTC()
	value := ServicePrincipal{ID: command.ServicePrincipalID, PrincipalID: command.ServicePrincipalID, TenantID: command.TenantID, RoleID: roleID, DisplayName: displayName, Description: description, State: ServicePrincipalEnabled, PermissionCeiling: permissions, ScopeCeiling: ceiling, ResourceSelectors: selectors, AuthzEpoch: 1, Generation: 1, CreatedAt: now, UpdatedAt: now}
	if err = value.Validate(); err != nil { return ServicePrincipal{}, err }
	if err = s.validateServicePrincipalCeiling(ctx, command.Actor, value); err != nil { return ServicePrincipal{}, err }
	tenant, err := s.store.Tenant(ctx, command.TenantID); if err != nil { return ServicePrincipal{}, err }
	if tenant.State != TenantActive { return ServicePrincipal{}, ErrSuspended }
	if existing, loadErr := s.store.ServicePrincipal(ctx, command.TenantID, command.ServicePrincipalID); loadErr == nil {
		if sameServicePrincipalDefinition(existing, value) { return existing, nil }
		return ServicePrincipal{}, ErrConflict
	} else if !errors.Is(loadErr, ErrNotFound) { return ServicePrincipal{}, loadErr }
	usernameID, _ := derivedID("svc", value.ID.String()+"\x00username")
	membershipID, _ := derivedID("spm", value.ID.String()+"\x00"+value.TenantID.String())
	principal := Principal{ID: value.ID, Kind: PrincipalService, Username: usernameID.String(), DisplayName: value.DisplayName, State: PrincipalActive, Locale: "en-US", Theme: ThemeSystem, AuthzEpoch: 1, CredentialEpoch: 1, Generation: 1, CreatedAt: now, UpdatedAt: now}
	membership := Membership{ID: membershipID, PrincipalID: value.ID, TenantID: value.TenantID, State: MembershipActive, Generation: 1, CreatedAt: now, UpdatedAt: now}
	role := Role{ID: roleID, TenantID: value.TenantID, Name: "service/" + value.ID.String(), Permissions: value.PermissionCeiling, Generation: 1, CreatedAt: now, UpdatedAt: now}
	if principal.Validate() != nil || membership.Validate() != nil || role.Validate() != nil { return ServicePrincipal{}, ErrInvalid }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ServicePrincipal{}, err }; defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_principals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, principal.ID, principal.Kind, principal.Username, principal.Email, principal.DisplayName, principal.State, principal.Locale, principal.Theme, principal.AuthzEpoch, principal.CredentialEpoch, principal.Generation, principal.CreatedAt, principal.UpdatedAt, principal.DeletedAt)
	if err == nil { _, err = tx.ExecContext(ctx, `INSERT INTO identity_memberships VALUES(?,?,?,?,?,?,?)`, membership.ID, membership.PrincipalID, membership.TenantID, membership.State, membership.Generation, membership.CreatedAt, membership.UpdatedAt) }
	if err == nil { permissionsJSON, _ := json.Marshal(role.Permissions); _, err = tx.ExecContext(ctx, `INSERT INTO identity_roles VALUES(?,?,?,?,?,?,?,?)`, role.ID, role.TenantID, role.Name, permissionsJSON, 0, role.Generation, role.CreatedAt, role.UpdatedAt) }
	if err == nil { err = insertServicePrincipalRecord(ctx, tx, value) }
	if err == nil { err = insertServiceBindings(ctx, tx, value, 1) }
	if err != nil { return ServicePrincipal{}, err }
	if err = tx.Commit(); err != nil { return ServicePrincipal{}, err }
	s.record(ctx, command.Actor.PrincipalID, value.TenantID, "service_principal.create", "service_principal", value.ID, "applied", value.ID.String()+"\x00display_name,description,permission_ceiling,scope_ceiling,resource_selectors")
	return value, nil
}

func (s *Service) GetServicePrincipal(ctx context.Context, actor ActorContext, tenantID, id ID) (ServicePrincipal, error) {
	if err := s.authorizeServicePrincipalAdmin(ctx, actor, tenantID, AssurancePassword); err != nil { return ServicePrincipal{}, err }
	return s.store.ServicePrincipal(ctx, tenantID, id)
}

func (s *Service) ListServicePrincipals(ctx context.Context, actor ActorContext, tenantID ID, limit int, cursor ID) ([]ServicePrincipal, string, uint64, error) {
	if err := s.authorizeServicePrincipalAdmin(ctx, actor, tenantID, AssurancePassword); err != nil { return nil, "", 0, err }
	return s.store.ListServicePrincipals(ctx, tenantID, limit, cursor)
}

func activeServiceVerifierRefs(ctx context.Context, tx *sql.Tx, principalID ID) ([]ID, error) {
	rows, err := tx.QueryContext(ctx, `SELECT verifier_ref FROM identity_service_api_credentials WHERE service_principal_id=? AND state='active'`, principalID); if err != nil { return nil, err }; defer rows.Close()
	var refs []ID
	for rows.Next() { var ref ID; if err = rows.Scan(&ref); err != nil { return nil, err }; refs = append(refs, ref) }
	return refs, rows.Err()
}

func (s *Service) revokeVerifierRefs(ctx context.Context, refs []ID) { for _, ref := range refs { _ = s.verifier.Revoke(ctx, ref) } }

func (s *Service) UpdateServicePrincipal(ctx context.Context, command UpdateServicePrincipalCommand) (ServicePrincipal, error) {
	if s == nil || s.store == nil || ctx == nil || command.ExpectedGeneration == 0 { return ServicePrincipal{}, ErrInvalid }
	if err := s.authorizeServicePrincipalAdmin(ctx, command.Actor, command.TenantID, AssuranceMFA); err != nil { return ServicePrincipal{}, err }
	current, err := s.store.ServicePrincipal(ctx, command.TenantID, command.ServicePrincipalID); if err != nil { return ServicePrincipal{}, err }
	if current.Generation != command.ExpectedGeneration { return ServicePrincipal{}, ErrStaleGeneration }
	displayName, description, permissions, ceiling, selectors := normalizeServicePrincipalInput(command.DisplayName, command.Description, command.PermissionCeiling, command.ScopeCeiling, command.ResourceSelectors)
	next := current
	next.DisplayName, next.Description, next.PermissionCeiling, next.ScopeCeiling, next.ResourceSelectors = displayName, description, permissions, ceiling, selectors
	next.Generation++
	next.UpdatedAt = s.clock().UTC()
	policyChanged := !samePermissions(current.PermissionCeiling, next.PermissionCeiling) || current.ScopeCeiling != next.ScopeCeiling || !sameScopes(current.ResourceSelectors, next.ResourceSelectors)
	if policyChanged { next.AuthzEpoch++ }
	if next.Validate() != nil || next.State == ServicePrincipalDeleted { return ServicePrincipal{}, ErrConflict }
	if err = s.validateServicePrincipalCeiling(ctx, command.Actor, next); err != nil { return ServicePrincipal{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ServicePrincipal{}, err }; defer tx.Rollback()
	stored, err := scanServicePrincipal(tx.QueryRowContext(ctx, servicePrincipalSelect+` WHERE tenant_id=? AND id=?`, command.TenantID, command.ServicePrincipalID)); if err != nil { return ServicePrincipal{}, err }
	if stored.Generation != command.ExpectedGeneration || stored.AuthzEpoch != current.AuthzEpoch { return ServicePrincipal{}, ErrStaleGeneration }
	principal, err := scanPrincipal(tx.QueryRowContext(ctx, `SELECT id,kind,username,email,display_name,state,locale,theme,authz_epoch,credential_epoch,generation,created_at,updated_at,deleted_at FROM identity_principals WHERE id=?`, current.PrincipalID)); if err != nil { return ServicePrincipal{}, err }
	permissionsJSON, _ := json.Marshal(next.PermissionCeiling); selectorsJSON, _ := json.Marshal(next.ResourceSelectors)
	result, err := tx.ExecContext(ctx, `UPDATE identity_service_principals SET display_name=?,description=?,permissions_json=?,scope_kind=?,scope_resource_id=?,selectors_json=?,authz_epoch=?,generation=?,updated_at=? WHERE id=? AND tenant_id=? AND generation=?`, next.DisplayName, next.Description, permissionsJSON, next.ScopeCeiling.Kind, next.ScopeCeiling.ResourceID, selectorsJSON, next.AuthzEpoch, next.Generation, next.UpdatedAt, next.ID, next.TenantID, current.Generation)
	if err != nil { return ServicePrincipal{}, err }; if rows, _ := result.RowsAffected(); rows != 1 { return ServicePrincipal{}, ErrStaleGeneration }
	result, err = tx.ExecContext(ctx, `UPDATE identity_principals SET display_name=?,authz_epoch=?,generation=?,updated_at=? WHERE id=? AND generation=?`, next.DisplayName, next.AuthzEpoch, principal.Generation+1, next.UpdatedAt, principal.ID, principal.Generation)
	if err != nil { return ServicePrincipal{}, err }; if rows, _ := result.RowsAffected(); rows != 1 { return ServicePrincipal{}, ErrStaleGeneration }
	var refs []ID
	if policyChanged {
		var roleGeneration uint64
		if err = tx.QueryRowContext(ctx, `SELECT generation FROM identity_roles WHERE id=? AND tenant_id=?`, next.RoleID, next.TenantID).Scan(&roleGeneration); err != nil { return ServicePrincipal{}, err }
		result, err = tx.ExecContext(ctx, `UPDATE identity_roles SET permissions_json=?,generation=?,updated_at=? WHERE id=? AND generation=?`, permissionsJSON, roleGeneration+1, next.UpdatedAt, next.RoleID, roleGeneration)
		if err != nil { return ServicePrincipal{}, err }; if rows, _ := result.RowsAffected(); rows != 1 { return ServicePrincipal{}, ErrStaleGeneration }
		if _, err = tx.ExecContext(ctx, `DELETE FROM identity_role_bindings WHERE subject_kind=? AND subject_id=?`, SubjectService, next.PrincipalID); err != nil { return ServicePrincipal{}, err }
		next.CreatedAt = current.CreatedAt
		if err = insertServiceBindings(ctx, tx, next, roleGeneration+1); err != nil { return ServicePrincipal{}, err }
		refs, err = activeServiceVerifierRefs(ctx, tx, next.ID); if err != nil { return ServicePrincipal{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE identity_service_api_credentials SET state='revoked',revoked_at=?,generation=generation+1 WHERE service_principal_id=? AND state='active'`, next.UpdatedAt, next.ID); err != nil { return ServicePrincipal{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE identity_credentials SET state='revoked',revoked_at=? WHERE principal_id=? AND kind='api_key' AND state='active'`, next.UpdatedAt, next.ID); err != nil { return ServicePrincipal{}, err }
	}
	if err = tx.Commit(); err != nil { return ServicePrincipal{}, err }
	s.revokeVerifierRefs(ctx, refs)
	s.record(ctx, command.Actor.PrincipalID, next.TenantID, "service_principal.update", "service_principal", next.ID, "applied", next.ID.String()+"\x00display_name,description,permission_ceiling,scope_ceiling,resource_selectors")
	return next, nil
}

func (s *Service) transitionServicePrincipal(ctx context.Context, actor ActorContext, tenantID, id ID, expected uint64, target ServicePrincipalState) (ServicePrincipal, error) {
	if s == nil || s.store == nil || ctx == nil || expected == 0 || !tenantID.Valid() || !id.Valid() { return ServicePrincipal{}, ErrInvalid }
	if err := s.authorizeServicePrincipalAdmin(ctx, actor, tenantID, AssuranceMFA); err != nil { return ServicePrincipal{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ServicePrincipal{}, err }; defer tx.Rollback()
	current, err := scanServicePrincipal(tx.QueryRowContext(ctx, servicePrincipalSelect+` WHERE tenant_id=? AND id=?`, tenantID, id)); if err != nil { return ServicePrincipal{}, err }
	if current.Generation != expected { return ServicePrincipal{}, ErrStaleGeneration }
	valid := target == ServicePrincipalSuspended && current.State == ServicePrincipalEnabled || target == ServicePrincipalEnabled && current.State == ServicePrincipalSuspended || target == ServicePrincipalDeleted && current.State != ServicePrincipalDeleted
	if !valid { return ServicePrincipal{}, ErrConflict }
	now := s.clock().UTC(); current.State = target; current.Generation++; current.AuthzEpoch++; current.UpdatedAt = now
	principalState := PrincipalActive
	if target == ServicePrincipalSuspended { principalState = PrincipalSuspended }
	if target == ServicePrincipalDeleted { principalState = PrincipalDeleted; current.DeletedAt = &now }
	principal, err := scanPrincipal(tx.QueryRowContext(ctx, `SELECT id,kind,username,email,display_name,state,locale,theme,authz_epoch,credential_epoch,generation,created_at,updated_at,deleted_at FROM identity_principals WHERE id=?`, id)); if err != nil { return ServicePrincipal{}, err }
	result, err := tx.ExecContext(ctx, `UPDATE identity_service_principals SET state=?,authz_epoch=?,generation=?,updated_at=?,deleted_at=? WHERE id=? AND tenant_id=? AND generation=?`, current.State, current.AuthzEpoch, current.Generation, now, current.DeletedAt, id, tenantID, expected)
	if err != nil { return ServicePrincipal{}, err }; if rows, _ := result.RowsAffected(); rows != 1 { return ServicePrincipal{}, ErrStaleGeneration }
	var deletedAt any
	if target == ServicePrincipalDeleted { deletedAt = now }
	result, err = tx.ExecContext(ctx, `UPDATE identity_principals SET state=?,authz_epoch=?,generation=?,updated_at=?,deleted_at=? WHERE id=? AND generation=?`, principalState, current.AuthzEpoch, principal.Generation+1, now, deletedAt, id, principal.Generation)
	if err != nil { return ServicePrincipal{}, err }; if rows, _ := result.RowsAffected(); rows != 1 { return ServicePrincipal{}, ErrStaleGeneration }
	var refs []ID
	if target == ServicePrincipalDeleted {
		refs, err = activeServiceVerifierRefs(ctx, tx, id); if err != nil { return ServicePrincipal{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE identity_memberships SET state='revoked',generation=generation+1,updated_at=? WHERE principal_id=? AND tenant_id=? AND state<>'revoked'`, now, id, tenantID); err != nil { return ServicePrincipal{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE identity_service_api_credentials SET state='revoked',revoked_at=?,generation=generation+1 WHERE service_principal_id=? AND state='active'`, now, id); err != nil { return ServicePrincipal{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE identity_credentials SET state='revoked',revoked_at=? WHERE principal_id=? AND kind='api_key' AND state='active'`, now, id); err != nil { return ServicePrincipal{}, err }
	}
	if err = tx.Commit(); err != nil { return ServicePrincipal{}, err }
	s.revokeVerifierRefs(ctx, refs)
	action := "service_principal." + string(target)
	s.record(ctx, actor.PrincipalID, tenantID, action, "service_principal", id, "applied", id.String()+"\x00state,authz_epoch")
	return current, nil
}

func (s *Service) SuspendServicePrincipal(ctx context.Context, actor ActorContext, tenantID, id ID, expected uint64) (ServicePrincipal, error) { return s.transitionServicePrincipal(ctx, actor, tenantID, id, expected, ServicePrincipalSuspended) }
func (s *Service) ResumeServicePrincipal(ctx context.Context, actor ActorContext, tenantID, id ID, expected uint64) (ServicePrincipal, error) { return s.transitionServicePrincipal(ctx, actor, tenantID, id, expected, ServicePrincipalEnabled) }
func (s *Service) DeleteServicePrincipal(ctx context.Context, actor ActorContext, tenantID, id ID, expected uint64) (ServicePrincipal, error) { return s.transitionServicePrincipal(ctx, actor, tenantID, id, expected, ServicePrincipalDeleted) }

func (s *Service) requireRecentServiceCredentialMFA(ctx context.Context, actor ActorContext) error {
	if actor.SessionID == "" { return ErrAssuranceRequired }
	if err := s.validateActor(ctx, actor, AssuranceMFA); err != nil { return err }
	session, err := s.store.Session(ctx, actor.SessionID); if err != nil { return ErrUnauthenticated }
	now := s.clock().UTC()
	if session.Assurance < AssuranceMFA || session.CreatedAt.After(now) || now.Sub(session.CreatedAt) > serviceCredentialRecentMFA { return ErrAssuranceRequired }
	return nil
}

func validateServiceCredentialPolicy(now time.Time, label string, notBefore, expiresAt time.Time, audience string, binding APINetworkBinding) (string, string, error) {
	label, audience = strings.TrimSpace(label), normalizeServiceAudience(audience)
	if len(label) < 1 || len(label) > 128 || strings.ContainsAny(label, "\x00\r\n\t") || audience == "" || notBefore.IsZero() || expiresAt.IsZero() || notBefore.Before(now.Add(-time.Minute)) || notBefore.After(now.Add(30*24*time.Hour)) || !expiresAt.After(notBefore) || expiresAt.Sub(notBefore) > serviceCredentialMaxLifetime || binding.Validate() != nil { return "", "", ErrInvalid }
	return label, audience, nil
}

func insertServiceAPICredential(ctx context.Context, tx *sql.Tx, value ServiceAPICredential) error {
	if err := value.Validate(); err != nil { return err }
	networkPrefix := ""
	if value.NetworkBinding.Prefix.IsValid() { networkPrefix = value.NetworkBinding.Prefix.String() }
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_service_api_credentials(id,service_principal_id,tenant_id,prefix,verifier_ref,label,state,verifier_version,authz_epoch,not_before,expires_at,last_used_at,audience,network_mode,network_prefix,rotated_from_id,rotated_to_id,overlap_until,generation,created_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.ID, value.ServicePrincipalID, value.TenantID, value.Prefix, value.verifierRef, value.Label, value.State, value.VerifierVersion, value.AuthzEpoch, value.NotBefore, value.ExpiresAt, value.LastUsedAt, value.Audience, value.NetworkBinding.Mode, networkPrefix, value.RotatedFromID, value.RotatedToID, value.OverlapUntil, value.Generation, value.CreatedAt, value.RevokedAt)
	return err
}

func insertGenericServiceCredential(ctx context.Context, tx *sql.Tx, value ServiceAPICredential, permissions []Permission) error {
	scopes, _ := json.Marshal(permissions)
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_credentials(id,principal_id,kind,state,label,verifier_ref,public_data,scopes_json,authz_epoch,created_at,last_used_at,expires_at,revoked_at,compromised_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)`, value.ID, value.ServicePrincipalID, CredentialAPIKey, CredentialActive, value.Label, value.verifierRef, []byte{}, scopes, value.AuthzEpoch, value.CreatedAt, value.LastUsedAt, value.ExpiresAt)
	return err
}

func ensureServicePrincipalUsableTx(ctx context.Context, tx *sql.Tx, value ServicePrincipal) error {
	var count uint64
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_service_principals sp JOIN identity_principals p ON p.id=sp.principal_id JOIN identity_tenants t ON t.id=sp.tenant_id JOIN identity_memberships m ON m.principal_id=sp.principal_id AND m.tenant_id=sp.tenant_id WHERE sp.id=? AND sp.tenant_id=? AND sp.state='enabled' AND sp.authz_epoch=? AND p.kind='service' AND p.state='active' AND p.authz_epoch=sp.authz_epoch AND t.state='active' AND m.state='active'`, value.ID, value.TenantID, value.AuthzEpoch).Scan(&count)
	if err != nil { return err }
	if count != 1 { return ErrStaleGeneration }
	return nil
}

func structuredServiceCredential(id ID, prefix string, raw []byte) []byte {
	value := make([]byte, 0, len(id.String())+len(prefix)+len(raw)+6)
	value = append(value, serviceCredentialPrefix...); value = append(value, '.'); value = append(value, id.String()...); value = append(value, '.'); value = append(value, prefix...); value = append(value, '.'); value = append(value, raw...)
	return value
}

func (s *Service) servicePrincipalForCredentialIssue(ctx context.Context, actor ActorContext, tenantID, principalID ID) (ServicePrincipal, error) {
	if err := s.requireRecentServiceCredentialMFA(ctx, actor); err != nil { return ServicePrincipal{}, err }
	if _, err := s.authorize(ctx, actor, MustPermission("credential:issue"), Scope{Kind: ScopeTenant, TenantID: tenantID}, AssuranceMFA); err != nil { return ServicePrincipal{}, err }
	value, err := s.store.ServicePrincipal(ctx, tenantID, principalID); if err != nil { return ServicePrincipal{}, err }
	if value.State != ServicePrincipalEnabled { return ServicePrincipal{}, ErrSuspended }
	principal, err := s.store.Principal(ctx, principalID); if err != nil { return ServicePrincipal{}, err }
	tenant, err := s.store.Tenant(ctx, tenantID); if err != nil { return ServicePrincipal{}, err }
	memberships, err := s.store.Memberships(ctx, principalID); if err != nil { return ServicePrincipal{}, err }
	if principal.Kind != PrincipalService || principal.State != PrincipalActive || principal.AuthzEpoch != value.AuthzEpoch || tenant.State != TenantActive || !hasActiveMembership(memberships, tenantID) { return ServicePrincipal{}, ErrUnauthenticated }
	return value, nil
}

func (s *Service) IssueServiceAPICredential(ctx context.Context, command IssueServiceAPICredentialCommand) (IssuedServiceAPICredential, error) {
	if s == nil || s.store == nil || ctx == nil || !command.CredentialID.Valid() || !command.ServicePrincipalID.Valid() || !command.TenantID.Valid() { return IssuedServiceAPICredential{}, ErrInvalid }
	principal, err := s.servicePrincipalForCredentialIssue(ctx, command.Actor, command.TenantID, command.ServicePrincipalID); if err != nil { return IssuedServiceAPICredential{}, err }
	now := s.clock().UTC(); label, audience, err := validateServiceCredentialPolicy(now, command.Label, command.NotBefore, command.ExpiresAt, command.Audience, command.NetworkBinding); if err != nil { return IssuedServiceAPICredential{}, err }
	if _, loadErr := s.store.serviceAPICredentialByID(ctx, command.CredentialID); loadErr == nil { return IssuedServiceAPICredential{}, ErrConflict } else if !errors.Is(loadErr, ErrNotFound) { return IssuedServiceAPICredential{}, loadErr }
	ref, raw, err := s.verifier.IssueAPIKey(ctx, principal.PrincipalID, principal.PermissionCeiling, command.ExpiresAt); if err != nil { return IssuedServiceAPICredential{}, err }
	defer clearBytes(raw)
	prefix := digest(raw)[:16]
	value := ServiceAPICredential{ID: command.CredentialID, ServicePrincipalID: principal.ID, TenantID: principal.TenantID, Prefix: prefix, Label: label, State: ServiceAPICredentialActive, VerifierVersion: 1, AuthzEpoch: principal.AuthzEpoch, NotBefore: command.NotBefore.UTC(), ExpiresAt: command.ExpiresAt.UTC(), Audience: audience, NetworkBinding: command.NetworkBinding, Generation: 1, CreatedAt: now, verifierRef: ref}
	if err = value.Validate(); err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }; defer tx.Rollback()
	if err = ensureServicePrincipalUsableTx(ctx, tx, principal); err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }
	if err = insertGenericServiceCredential(ctx, tx, value, principal.PermissionCeiling); err == nil { err = insertServiceAPICredential(ctx, tx, value) }
	if err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }
	if err = tx.Commit(); err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }
	secret := structuredServiceCredential(value.ID, value.Prefix, raw)
	s.record(ctx, command.Actor.PrincipalID, value.TenantID, "service_api_credential.issue", "service_api_credential", value.ID, "applied", value.ID.String()+"\x00label,not_before,expires_at,audience,network_binding")
	return IssuedServiceAPICredential{Credential: value, Secret: secret}, nil
}

func (s *Service) GetServiceAPICredential(ctx context.Context, actor ActorContext, tenantID, servicePrincipalID, credentialID ID) (ServiceAPICredential, error) {
	if err := s.authorizeServicePrincipalAdmin(ctx, actor, tenantID, AssurancePassword); err != nil { return ServiceAPICredential{}, err }
	return s.store.ServiceAPICredential(ctx, tenantID, servicePrincipalID, credentialID)
}

func (s *Service) ListServiceAPICredentials(ctx context.Context, actor ActorContext, tenantID, servicePrincipalID ID, limit int, cursor ID) ([]ServiceAPICredential, string, uint64, error) {
	if err := s.authorizeServicePrincipalAdmin(ctx, actor, tenantID, AssurancePassword); err != nil { return nil, "", 0, err }
	if _, err := s.store.ServicePrincipal(ctx, tenantID, servicePrincipalID); err != nil { return nil, "", 0, err }
	return s.store.ListServiceAPICredentials(ctx, tenantID, servicePrincipalID, limit, cursor)
}

func (s *Service) RotateServiceAPICredential(ctx context.Context, command RotateServiceAPICredentialCommand) (IssuedServiceAPICredential, error) {
	if s == nil || s.store == nil || ctx == nil || command.ExpectedGeneration == 0 || !command.CredentialID.Valid() || !command.PreviousCredentialID.Valid() || command.CredentialID == command.PreviousCredentialID || command.Overlap < 0 || command.Overlap > serviceCredentialMaxOverlap { return IssuedServiceAPICredential{}, ErrInvalid }
	principal, err := s.servicePrincipalForCredentialIssue(ctx, command.Actor, command.TenantID, command.ServicePrincipalID); if err != nil { return IssuedServiceAPICredential{}, err }
	now := s.clock().UTC(); label, audience, err := validateServiceCredentialPolicy(now, command.Label, command.NotBefore, command.ExpiresAt, command.Audience, command.NetworkBinding); if err != nil { return IssuedServiceAPICredential{}, err }
	previous, err := s.store.ServiceAPICredential(ctx, command.TenantID, command.ServicePrincipalID, command.PreviousCredentialID); if err != nil { return IssuedServiceAPICredential{}, err }
	if previous.Generation != command.ExpectedGeneration { return IssuedServiceAPICredential{}, ErrStaleGeneration }
	if previous.State != ServiceAPICredentialActive || previous.RotatedToID != "" || !now.Before(previous.ExpiresAt) { return IssuedServiceAPICredential{}, ErrConflict }
	if _, loadErr := s.store.serviceAPICredentialByID(ctx, command.CredentialID); loadErr == nil { return IssuedServiceAPICredential{}, ErrConflict } else if !errors.Is(loadErr, ErrNotFound) { return IssuedServiceAPICredential{}, loadErr }
	ref, raw, err := s.verifier.IssueAPIKey(ctx, principal.PrincipalID, principal.PermissionCeiling, command.ExpiresAt); if err != nil { return IssuedServiceAPICredential{}, err }
	defer clearBytes(raw)
	value := ServiceAPICredential{ID: command.CredentialID, ServicePrincipalID: principal.ID, TenantID: principal.TenantID, Prefix: digest(raw)[:16], Label: label, State: ServiceAPICredentialActive, VerifierVersion: 1, AuthzEpoch: principal.AuthzEpoch, NotBefore: command.NotBefore.UTC(), ExpiresAt: command.ExpiresAt.UTC(), Audience: audience, NetworkBinding: command.NetworkBinding, RotatedFromID: previous.ID, Generation: 1, CreatedAt: now, verifierRef: ref}
	if err = value.Validate(); err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }; defer tx.Rollback()
	if err = ensureServicePrincipalUsableTx(ctx, tx, principal); err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }
	stored, err := scanServiceAPICredential(tx.QueryRowContext(ctx, serviceAPICredentialSelect+` WHERE tenant_id=? AND service_principal_id=? AND id=?`, command.TenantID, command.ServicePrincipalID, previous.ID)); if err != nil || stored.Generation != command.ExpectedGeneration || stored.State != ServiceAPICredentialActive || stored.RotatedToID != "" { _ = s.verifier.Revoke(ctx, ref); if err != nil { return IssuedServiceAPICredential{}, err }; return IssuedServiceAPICredential{}, ErrStaleGeneration }
	if err = insertGenericServiceCredential(ctx, tx, value, principal.PermissionCeiling); err == nil { err = insertServiceAPICredential(ctx, tx, value) }
	if err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }
	overlapUntil := now.Add(command.Overlap); previous.RotatedToID = value.ID; previous.OverlapUntil = &overlapUntil; previous.Generation++
	if command.Overlap == 0 { previous.State = ServiceAPICredentialRevoked; previous.RevokedAt = &now }
	result, err := tx.ExecContext(ctx, `UPDATE identity_service_api_credentials SET state=?,rotated_to_id=?,overlap_until=?,generation=?,revoked_at=? WHERE id=? AND generation=? AND state='active' AND rotated_to_id=''`, previous.State, previous.RotatedToID, previous.OverlapUntil, previous.Generation, previous.RevokedAt, previous.ID, command.ExpectedGeneration)
	if err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }; if rows, _ := result.RowsAffected(); rows != 1 { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, ErrStaleGeneration }
	if command.Overlap == 0 { if _, err = tx.ExecContext(ctx, `UPDATE identity_credentials SET state='revoked',revoked_at=? WHERE id=? AND state='active'`, now, previous.ID); err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err } }
	if err = tx.Commit(); err != nil { _ = s.verifier.Revoke(ctx, ref); return IssuedServiceAPICredential{}, err }
	if command.Overlap == 0 { _ = s.verifier.Revoke(ctx, previous.verifierRef) }
	secret := structuredServiceCredential(value.ID, value.Prefix, raw)
	s.record(ctx, command.Actor.PrincipalID, value.TenantID, "service_api_credential.rotate", "service_api_credential", value.ID, "applied", value.ID.String()+"\x00previous_id,label,not_before,expires_at,audience,network_binding,overlap")
	return IssuedServiceAPICredential{Credential: value, Secret: secret}, nil
}

func (s *Service) RevokeServiceAPICredential(ctx context.Context, actor ActorContext, tenantID, servicePrincipalID, credentialID ID, expected uint64) (ServiceAPICredential, error) {
	if s == nil || s.store == nil || ctx == nil || expected == 0 { return ServiceAPICredential{}, ErrInvalid }
	if _, err := s.authorize(ctx, actor, MustPermission("credential:issue"), Scope{Kind: ScopeTenant, TenantID: tenantID}, AssuranceMFA); err != nil { return ServiceAPICredential{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ServiceAPICredential{}, err }; defer tx.Rollback()
	value, err := scanServiceAPICredential(tx.QueryRowContext(ctx, serviceAPICredentialSelect+` WHERE tenant_id=? AND service_principal_id=? AND id=?`, tenantID, servicePrincipalID, credentialID)); if err != nil { return ServiceAPICredential{}, err }
	if value.Generation != expected { return ServiceAPICredential{}, ErrStaleGeneration }
	if value.State == ServiceAPICredentialRevoked { return value, nil }
	now := s.clock().UTC(); value.State = ServiceAPICredentialRevoked; value.RevokedAt = &now; value.Generation++
	result, err := tx.ExecContext(ctx, `UPDATE identity_service_api_credentials SET state='revoked',revoked_at=?,generation=? WHERE id=? AND generation=? AND state='active'`, now, value.Generation, value.ID, expected)
	if err != nil { return ServiceAPICredential{}, err }; if rows, _ := result.RowsAffected(); rows != 1 { return ServiceAPICredential{}, ErrStaleGeneration }
	if _, err = tx.ExecContext(ctx, `UPDATE identity_credentials SET state='revoked',revoked_at=? WHERE id=? AND state='active'`, now, value.ID); err != nil { return ServiceAPICredential{}, err }
	if err = tx.Commit(); err != nil { return ServiceAPICredential{}, err }
	_ = s.verifier.Revoke(ctx, value.verifierRef)
	s.record(ctx, actor.PrincipalID, tenantID, "service_api_credential.revoke", "service_api_credential", value.ID, "applied", value.ID.String()+"\x00state,revoked_at")
	return value, nil
}

func parseStructuredServiceCredential(raw []byte) (ID, string, []byte, bool) {
	if len(raw) < 64 || len(raw) > 4096 { return "", "", nil, false }
	parts := bytes.SplitN(raw, []byte{'.'}, 4)
	if len(parts) != 4 || !bytes.Equal(parts[0], []byte(serviceCredentialPrefix)) || len(parts[2]) != 16 || !bytes.HasPrefix(parts[3], []byte("cpk_")) { return "", "", nil, false }
	id, err := NewID(string(parts[1])); if err != nil { return "", "", nil, false }
	prefix := string(parts[2])
	for _, character := range prefix { if character < '0' || character > '9' && character < 'a' || character > 'f' { return "", "", nil, false } }
	return id, prefix, append([]byte(nil), parts[3]...), true
}

func (s *Service) serviceCredentialAuthFailure(ctx context.Context, id ID, reason string) {
	if !id.Valid() { id, _ = derivedID("spk", "invalid\x00"+reason) }
	s.record(ctx, "", "", "service_api_credential.authenticate", "service_api_credential", id, "rejected", id.String()+"\x00"+reason)
}

func (s *Service) AuthenticateServiceAPIKey(ctx context.Context, raw []byte, source netip.Addr, requestedAudience string) (ActorContext, Principal, error) {
	if s == nil || s.store == nil || ctx == nil || !source.IsValid() { clearBytes(raw); return ActorContext{}, Principal{}, ErrUnauthenticated }
	defer clearBytes(raw)
	credentialID, presentedPrefix, secret, ok := parseStructuredServiceCredential(raw)
	if !ok { s.serviceCredentialAuthFailure(ctx, credentialID, "malformed"); return ActorContext{}, Principal{}, ErrUnauthenticated }
	verifiedRef, verified, verifyErr := s.verifier.VerifyAPIKey(ctx, secret)
	clearBytes(secret)
	value, loadErr := s.store.serviceAPICredentialByID(ctx, credentialID)
	if verifyErr != nil || !verified || loadErr != nil || subtle.ConstantTimeCompare([]byte(verifiedRef.String()), []byte(value.verifierRef.String())) != 1 || subtle.ConstantTimeCompare([]byte(presentedPrefix), []byte(value.Prefix)) != 1 {
		s.serviceCredentialAuthFailure(ctx, credentialID, "verification_failed")
		return ActorContext{}, Principal{}, ErrUnauthenticated
	}
	now := s.clock().UTC(); audience := normalizeServiceAudience(requestedAudience)
	if audience == "" || subtle.ConstantTimeCompare([]byte(audience), []byte(value.Audience)) != 1 || value.State != ServiceAPICredentialActive || now.Before(value.NotBefore) || !now.Before(value.ExpiresAt) || value.RevokedAt != nil || value.RotatedToID != "" && (value.OverlapUntil == nil || !now.Before(*value.OverlapUntil)) || !value.NetworkBinding.Allows(source) {
		s.serviceCredentialAuthFailure(ctx, credentialID, "policy_rejected")
		return ActorContext{}, Principal{}, ErrUnauthenticated
	}
	servicePrincipal, err := s.store.ServicePrincipal(ctx, value.TenantID, value.ServicePrincipalID); if err != nil { s.serviceCredentialAuthFailure(ctx, credentialID, "principal_unavailable"); return ActorContext{}, Principal{}, ErrUnauthenticated }
	principal, err := s.store.Principal(ctx, value.ServicePrincipalID); if err != nil { s.serviceCredentialAuthFailure(ctx, credentialID, "principal_unavailable"); return ActorContext{}, Principal{}, ErrUnauthenticated }
	tenant, err := s.store.Tenant(ctx, value.TenantID); if err != nil { s.serviceCredentialAuthFailure(ctx, credentialID, "tenant_unavailable"); return ActorContext{}, Principal{}, ErrUnauthenticated }
	generic, err := s.store.Credential(ctx, value.ID); if err != nil { s.serviceCredentialAuthFailure(ctx, credentialID, "credential_unavailable"); return ActorContext{}, Principal{}, ErrUnauthenticated }
	if servicePrincipal.State != ServicePrincipalEnabled || servicePrincipal.AuthzEpoch != value.AuthzEpoch || principal.Kind != PrincipalService || principal.State != PrincipalActive || principal.AuthzEpoch != value.AuthzEpoch || tenant.State != TenantActive || generic.Kind != CredentialAPIKey || generic.State != CredentialActive || generic.AuthzEpoch != value.AuthzEpoch || subtle.ConstantTimeCompare([]byte(generic.VerifierRef.String()), []byte(value.verifierRef.String())) != 1 || !samePermissions(generic.Scopes, servicePrincipal.PermissionCeiling) {
		s.serviceCredentialAuthFailure(ctx, credentialID, "stale_policy")
		return ActorContext{}, Principal{}, ErrUnauthenticated
	}
	memberships, err := s.store.Memberships(ctx, principal.ID); if err != nil || !hasActiveMembership(memberships, value.TenantID) { s.serviceCredentialAuthFailure(ctx, credentialID, "tenant_scope_rejected"); return ActorContext{}, Principal{}, ErrUnauthenticated }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ActorContext{}, Principal{}, err }; defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE identity_service_api_credentials SET last_used_at=? WHERE id=? AND generation=? AND state='active' AND authz_epoch=? AND not_before<=? AND expires_at>? AND (rotated_to_id='' OR overlap_until>?) AND EXISTS(SELECT 1 FROM identity_service_principals sp JOIN identity_principals p ON p.id=sp.principal_id JOIN identity_tenants t ON t.id=sp.tenant_id JOIN identity_memberships m ON m.principal_id=sp.principal_id AND m.tenant_id=sp.tenant_id JOIN identity_credentials c ON c.id=identity_service_api_credentials.id WHERE sp.id=identity_service_api_credentials.service_principal_id AND sp.state='enabled' AND sp.authz_epoch=identity_service_api_credentials.authz_epoch AND p.state='active' AND p.authz_epoch=sp.authz_epoch AND t.state='active' AND m.state='active' AND c.state='active' AND c.authz_epoch=sp.authz_epoch)`, now, value.ID, value.Generation, value.AuthzEpoch, now, now, now)
	if err != nil { return ActorContext{}, Principal{}, err }; if rows, _ := result.RowsAffected(); rows != 1 { s.serviceCredentialAuthFailure(ctx, credentialID, "concurrent_policy_change"); return ActorContext{}, Principal{}, ErrUnauthenticated }
	if _, err = tx.ExecContext(ctx, `UPDATE identity_credentials SET last_used_at=? WHERE id=? AND state='active' AND authz_epoch=?`, now, value.ID, value.AuthzEpoch); err != nil { return ActorContext{}, Principal{}, err }
	if err = tx.Commit(); err != nil { return ActorContext{}, Principal{}, err }
	s.record(ctx, principal.ID, value.TenantID, "service_api_credential.authenticate", "service_api_credential", value.ID, "applied", value.ID.String()+"\x00last_used_at")
	return ActorContext{PrincipalID: principal.ID, CredentialID: value.ID, AuthzEpoch: principal.AuthzEpoch, Assurance: AssurancePassword}, principal, nil
}
