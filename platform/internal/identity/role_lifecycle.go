package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	roleMaximumPage       = 100
	roleMaximumPermissions = 64
	roleMaximumSelectors   = 32
	roleRecentStepUp       = 10 * time.Minute
)

type RoleLifecycleState string

const (
	RoleActive  RoleLifecycleState = "active"
	RoleRetired RoleLifecycleState = "retired"
	RoleDeleted RoleLifecycleState = "deleted"
)

type BuiltInRoleKey string

const (
	BuiltInOwner              BuiltInRoleKey = "owner"
	BuiltInAdministrator      BuiltInRoleKey = "administrator"
	BuiltInReseller           BuiltInRoleKey = "reseller"
	BuiltInCustomer           BuiltInRoleKey = "customer"
	BuiltInServicePrincipal   BuiltInRoleKey = "service_principal"
	BuiltInSupport            BuiltInRoleKey = "support"
	BuiltInAuditor            BuiltInRoleKey = "auditor"
	BuiltInReadOnlyOperations BuiltInRoleKey = "read_only_operations"
)

type RoleField string

const (
	RoleFieldName        RoleField = "name"
	RoleFieldDescription RoleField = "description"
	RoleFieldPermissions RoleField = "permissions"
	RoleFieldSelectors   RoleField = "selectors"
)

var (
	ErrBuiltInRoleImmutable = fmt.Errorf("%w: built-in role immutable", ErrForbidden)
	ErrRoleRetired          = fmt.Errorf("%w: role retired", ErrConflict)
	ErrRoleInUse            = fmt.Errorf("%w: role in use", ErrConflict)
	ErrLastLocalOwner       = fmt.Errorf("%w: last viable local owner", ErrConflict)
	ErrGrantCeiling         = fmt.Errorf("%w: role grant ceiling", ErrDelegationExceeded)
	ErrBindingInactive      = fmt.Errorf("%w: role binding inactive", ErrConflict)
)

type ManagedRole struct {
	Role
	Description  string
	State        RoleLifecycleState
	BuiltInKey   BuiltInRoleKey
	Version      uint64
	Revision     uint64
	Selectors    []Scope
	ClonedFromID ID
	CreatedByID  ID
	RetiredAt    *time.Time
	DeletedAt    *time.Time
}

type ManagedRoleVersion struct {
	RoleID        ID
	TenantID      ID
	Version       uint64
	Name          string
	Description   string
	Permissions   []Permission
	Selectors     []Scope
	State         RoleLifecycleState
	ChangedFields []RoleField
	ChangedByID   ID
	CreatedAt     time.Time
}

type ManagedRoleBinding struct {
	ID           ID
	TenantID     ID
	SubjectKind  SubjectKind
	SubjectID    ID
	RoleID       ID
	Selectors    []Scope
	EffectiveAt  time.Time
	ExpiresAt    *time.Time
	GrantedByID  ID
	Provenance   []ID
	Revision     uint64
	CreatedAt    time.Time
	RevokedAt    *time.Time
	RevokedByID  ID
}

type CreateManagedRoleCommand struct {
	Actor       ActorContext
	RoleID      ID
	TenantID    ID
	ClonedFromID ID
	Name        string
	Description string
	Permissions []Permission
	Selectors   []Scope
}

type CloneManagedRoleCommand struct {
	Actor        ActorContext
	RoleID       ID
	SourceRoleID ID
	ExpectedSourceRevision uint64
	TenantID     ID
	Name         string
	Description  string
}

type UpdateManagedRoleCommand struct {
	Actor            ActorContext
	RoleID           ID
	TenantID         ID
	ExpectedRevision uint64
	FieldMask        []RoleField
	Name             string
	Description      string
	Permissions      []Permission
	Selectors        []Scope
}

type AssignManagedRoleBindingCommand struct {
	Actor       ActorContext
	BindingID   ID
	TenantID    ID
	SubjectKind SubjectKind
	SubjectID   ID
	RoleID      ID
	ExpectedRoleRevision uint64
	Selectors   []Scope
	EffectiveAt time.Time
	ExpiresAt   *time.Time
}

type builtInRoleDefinition struct {
	Key         BuiltInRoleKey
	Name        string
	Description string
	Permissions []Permission
}

var closedRolePermissions = map[Permission]struct{}{
	"access:manage": {}, "access:terminal": {}, "application:install": {}, "application:manage": {}, "application:update": {},
	"audit:manage": {}, "audit:read": {}, "backup:create": {}, "backup:manage": {}, "backup:restore": {},
	"certificate:manage": {}, "container:expose": {}, "container:manage": {}, "credential:issue": {},
	"database:admin": {}, "database:console": {}, "database:create": {}, "database:delete": {}, "database:manage": {},
	"dns:manage": {}, "file:read": {}, "file:write": {}, "fleet:manage": {}, "fleet:observe": {}, "ha:manage": {},
	"identity:manage": {}, "integration:manage": {}, "mail:manage": {}, "migration:manage": {},
	"operations:manage": {}, "operations:observe": {}, "package:manage": {}, "principal:create": {}, "principal:manage": {},
	"principal:suspend": {}, "role:bind": {}, "role:manage": {}, "security:manage": {}, "security:observe": {},
	"site:create": {}, "site:manage": {}, "support:access": {}, "support:grant": {}, "tenant:create": {}, "webengine:manage": {},
}

var builtInRoleDefinitions = []builtInRoleDefinition{
	{BuiltInOwner, "Owner", "Full tenant ownership and delegation authority.", []Permission{"*:*"}},
	{BuiltInAdministrator, "Administrator", "Tenant administration without owner designation.", allNamedRolePermissions()},
	{BuiltInReseller, "Reseller", "Delegated tenant and customer administration.", []Permission{"identity:manage", "operations:observe", "principal:create", "principal:manage", "role:bind", "role:manage", "site:create", "site:manage", "tenant:create"}},
	{BuiltInCustomer, "Customer", "Customer workload administration.", []Permission{"application:install", "application:manage", "application:update", "backup:create", "backup:restore", "certificate:manage", "database:console", "database:create", "database:delete", "database:manage", "dns:manage", "file:read", "file:write", "mail:manage", "operations:observe", "site:create", "site:manage"}},
	{BuiltInServicePrincipal, "Service principal", "Automation operations suitable for a non-human principal.", []Permission{"application:manage", "application:update", "backup:create", "database:manage", "dns:manage", "file:read", "operations:observe", "site:manage"}},
	{BuiltInSupport, "Support", "Support access without customer impersonation.", []Permission{"audit:read", "database:console", "file:read", "operations:observe", "security:observe", "site:manage", "support:access"}},
	{BuiltInAuditor, "Auditor", "Audit and security observation.", []Permission{"audit:read", "operations:observe", "security:observe"}},
	{BuiltInReadOnlyOperations, "Read-only operations", "Read-only operational visibility.", []Permission{"file:read", "operations:observe"}},
}

func allNamedRolePermissions() []Permission { values := make([]Permission, 0, len(closedRolePermissions)); for permission := range closedRolePermissions { values = append(values, permission) }; sort.Slice(values, func(i, j int) bool { return values[i] < values[j] }); return values }

func (r ManagedRole) Validate() error {
	if r.Role.Validate() != nil || !r.TenantID.Valid() || r.Role.TenantID != r.TenantID || r.Version == 0 || r.Revision == 0 || len(r.Description) > 512 || strings.ContainsAny(r.Description, "\x00\r\n") { return fmt.Errorf("%w: managed role", ErrInvalid) }
	if r.ClonedFromID != "" && !r.ClonedFromID.Valid() || r.CreatedByID != "" && !r.CreatedByID.Valid() { return fmt.Errorf("%w: role provenance", ErrInvalid) }
	if r.State != RoleActive && r.State != RoleRetired && r.State != RoleDeleted { return fmt.Errorf("%w: managed role state", ErrInvalid) }
	if r.Builtin != (r.BuiltInKey != "") || r.Builtin && (r.State != RoleActive || r.Version != 1) { return fmt.Errorf("%w: built-in role", ErrInvalid) }
	if len(r.Selectors) < 1 || len(r.Selectors) > roleMaximumSelectors { return fmt.Errorf("%w: role selectors", ErrInvalid) }
	if err := validateRoleDefinition(r.TenantID, r.Name, r.Description, r.Permissions, r.Selectors, r.Builtin); err != nil { return err }
	if r.State == RoleActive && (r.RetiredAt != nil || r.DeletedAt != nil) || r.State == RoleRetired && (r.RetiredAt == nil || r.DeletedAt != nil) || r.State == RoleDeleted && (r.RetiredAt == nil || r.DeletedAt == nil) { return fmt.Errorf("%w: role lifecycle timestamps", ErrInvalid) }
	return nil
}

func (b ManagedRoleBinding) Validate() error {
	if !b.ID.Valid() || !b.TenantID.Valid() || !b.SubjectID.Valid() || !b.RoleID.Valid() || !b.GrantedByID.Valid() || b.Revision == 0 || b.CreatedAt.IsZero() || b.EffectiveAt.IsZero() { return fmt.Errorf("%w: managed role binding", ErrInvalid) }
	if b.SubjectKind != SubjectPrincipal && b.SubjectKind != SubjectService || len(b.Selectors) < 1 || len(b.Selectors) > roleMaximumSelectors { return fmt.Errorf("%w: managed role binding subject", ErrInvalid) }
	if b.ExpiresAt != nil && !b.ExpiresAt.After(b.EffectiveAt) || b.RevokedAt != nil && (!b.RevokedByID.Valid() || b.RevokedAt.Before(b.CreatedAt)) { return fmt.Errorf("%w: managed role binding time", ErrInvalid) }
	if err := validateRoleSelectors(b.TenantID, b.Selectors); err != nil { return err }
	if len(b.Provenance) < 1 || len(b.Provenance) > 128 { return fmt.Errorf("%w: role binding provenance", ErrInvalid) }
	for _, id := range b.Provenance { if !id.Valid() { return fmt.Errorf("%w: role binding provenance", ErrInvalid) } }
	return nil
}

func validateRoleDefinition(tenantID ID, name, description string, permissions []Permission, selectors []Scope, builtin bool) error {
	name = strings.TrimSpace(name)
	if !tenantID.Valid() || len(name) < 1 || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n\t") || description != strings.TrimSpace(description) || len(description) > 512 || strings.ContainsAny(description, "\x00\r\n") { return fmt.Errorf("%w: role metadata", ErrInvalid) }
	canonical := CanonicalPermissions(permissions)
	if len(canonical) < 1 || len(canonical) > roleMaximumPermissions || len(canonical) != len(permissions) { return fmt.Errorf("%w: role permissions", ErrInvalid) }
	if len(canonical)*len(selectors) > 256 { return fmt.Errorf("%w: role authorization surface", ErrInvalid) }
	for index, permission := range canonical {
		if permission != permissions[index] { return fmt.Errorf("%w: role permission order", ErrInvalid) }
		if permission == "*:*" { if !builtin || len(permissions) != 1 { return fmt.Errorf("%w: wildcard role permission", ErrInvalid) }; continue }
		if _, ok := closedRolePermissions[permission]; !ok { return fmt.Errorf("%w: unknown role permission", ErrInvalid) }
	}
	return validateRoleSelectors(tenantID, selectors)
}

func validateRoleSelectors(tenantID ID, selectors []Scope) error {
	if len(selectors) < 1 || len(selectors) > roleMaximumSelectors { return fmt.Errorf("%w: role selectors", ErrInvalid) }
	seen := make(map[string]struct{}, len(selectors))
	for _, selector := range selectors {
		if selector.Validate() != nil || selector.Kind == ScopeInstallation || selector.TenantID != tenantID { return fmt.Errorf("%w: role selector", ErrInvalid) }
		key := string(selector.Kind) + "\x00" + selector.ResourceID.String()
		if _, exists := seen[key]; exists { return fmt.Errorf("%w: duplicate role selector", ErrInvalid) }
		seen[key] = struct{}{}
	}
	return nil
}

func normalizeRoleDefinition(name, description string, permissions []Permission, selectors []Scope) (string, string, []Permission, []Scope) {
	name, description = strings.TrimSpace(name), strings.TrimSpace(description)
	permissions = CanonicalPermissions(permissions)
	selectors = append([]Scope(nil), selectors...)
	sort.Slice(selectors, func(i, j int) bool { return roleScopeKey(selectors[i]) < roleScopeKey(selectors[j]) })
	return name, description, permissions, selectors
}

func roleScopeKey(value Scope) string { return string(value.Kind) + "\x00" + value.TenantID.String() + "\x00" + value.ResourceID.String() }

func sameRoleFields(left, right []RoleField) bool { if len(left) != len(right) { return false }; for index := range left { if left[index] != right[index] { return false } }; return true }

func builtInRoleID(tenantID ID, key BuiltInRoleKey) (ID, error) { return derivedID("bir", tenantID.String()+"\x00"+string(key)) }

func ensureBuiltInRolesTx(ctx context.Context, tx *sql.Tx, tenantID ID, now time.Time) error {
	selector := []Scope{{Kind: ScopeTenant, TenantID: tenantID}}
	selectorsJSON, _ := json.Marshal(selector)
	fieldsJSON, _ := json.Marshal([]RoleField{RoleFieldName, RoleFieldDescription, RoleFieldPermissions, RoleFieldSelectors})
	for _, definition := range builtInRoleDefinitions {
		roleID, err := builtInRoleID(tenantID, definition.Key); if err != nil { return err }
		permissions := CanonicalPermissions(definition.Permissions)
		permissionsJSON, _ := json.Marshal(permissions)
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_roles(id,tenant_id,name,permissions_json,builtin,generation,created_at,updated_at) VALUES(?,?,?,?,1,1,?,?) ON CONFLICT(id) DO NOTHING`, roleID, tenantID, definition.Name, permissionsJSON, now, now); err != nil { return err }
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_role_catalog(role_id,tenant_id,description,state,builtin_key,version,revision,selectors_json,cloned_from_id,created_by_id,created_at,updated_at,retired_at,deleted_at) VALUES(?,?,?,'active',?,1,1,?,'','',?,?,NULL,NULL) ON CONFLICT(role_id) DO NOTHING`, roleID, tenantID, definition.Description, definition.Key, selectorsJSON, now, now); err != nil { return err }
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_role_versions(role_id,tenant_id,version,name,description,permissions_json,selectors_json,state,changed_fields_json,changed_by_id,created_at) VALUES(?,?,1,?,?,?,?, 'active',?,'',?) ON CONFLICT(role_id,version) DO NOTHING`, roleID, tenantID, definition.Name, definition.Description, permissionsJSON, selectorsJSON, fieldsJSON, now); err != nil { return err }
		stored, loadErr := scanManagedRole(tx.QueryRowContext(ctx, managedRoleSelect+` WHERE c.tenant_id=? AND c.role_id=?`, tenantID, roleID)); if loadErr != nil { return loadErr }
		if !stored.Builtin || stored.BuiltInKey != definition.Key || stored.State != RoleActive || stored.Generation != 1 || stored.Version != 1 || stored.Revision != 1 || stored.Name != definition.Name || stored.Description != definition.Description || !samePermissions(stored.Permissions, permissions) || !sameScopes(stored.Selectors, selector) { return fmt.Errorf("%w: built-in role integrity", ErrConflict) }
		version, versionErr := scanManagedRoleVersion(tx.QueryRowContext(ctx, `SELECT role_id,tenant_id,version,name,description,permissions_json,selectors_json,state,changed_fields_json,changed_by_id,created_at FROM identity_role_versions WHERE role_id=? AND version=1`, roleID)); if versionErr != nil { return versionErr }
		if version.TenantID != tenantID || version.Name != definition.Name || version.Description != definition.Description || version.State != RoleActive || version.ChangedByID != "" || !samePermissions(version.Permissions, permissions) || !sameScopes(version.Selectors, selector) || !sameRoleFields(version.ChangedFields, []RoleField{RoleFieldName, RoleFieldDescription, RoleFieldPermissions, RoleFieldSelectors}) { return fmt.Errorf("%w: built-in role version integrity", ErrConflict) }
	}
	return nil
}

func (s *Service) ensureBuiltInRoles(ctx context.Context, tenantID ID) error {
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return err }; defer tx.Rollback()
	if err = ensureBuiltInRolesTx(ctx, tx, tenantID, s.clock().UTC()); err != nil { return err }
	return tx.Commit()
}

func scanManagedRole(row interface{ Scan(...any) error }) (ManagedRole, error) {
	var value ManagedRole
	var permissions, selectors []byte
	var state, builtinKey string
	var builtin int
	var retired, deleted sql.NullTime
	err := row.Scan(&value.ID, &value.TenantID, &value.Name, &permissions, &builtin, &value.Generation, &value.CreatedAt, &value.UpdatedAt, &value.Description, &state, &builtinKey, &value.Version, &value.Revision, &selectors, &value.ClonedFromID, &value.CreatedByID, &retired, &deleted)
	if errors.Is(err, sql.ErrNoRows) { return ManagedRole{}, ErrNotFound }
	if err != nil { return ManagedRole{}, err }
	if err = json.Unmarshal(permissions, &value.Permissions); err != nil { return ManagedRole{}, err }
	if err = json.Unmarshal(selectors, &value.Selectors); err != nil { return ManagedRole{}, err }
	value.Builtin, value.State, value.BuiltInKey = builtin != 0, RoleLifecycleState(state), BuiltInRoleKey(builtinKey)
	if retired.Valid { value.RetiredAt = &retired.Time }; if deleted.Valid { value.DeletedAt = &deleted.Time }
	return value, value.Validate()
}

const managedRoleSelect = `SELECT r.id,r.tenant_id,r.name,r.permissions_json,r.builtin,r.generation,r.created_at,r.updated_at,c.description,c.state,c.builtin_key,c.version,c.revision,c.selectors_json,c.cloned_from_id,c.created_by_id,c.retired_at,c.deleted_at FROM identity_roles r JOIN identity_role_catalog c ON c.role_id=r.id`

func (s *Store) managedRole(ctx context.Context, tenantID, roleID ID) (ManagedRole, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || !roleID.Valid() { return ManagedRole{}, ErrInvalid }
	return scanManagedRole(s.db.QueryRowContext(ctx, managedRoleSelect+` WHERE c.tenant_id=? AND c.role_id=?`, tenantID, roleID))
}

func (s *Service) authorizeRole(ctx context.Context, actor ActorContext, tenantID ID, permission Permission, minimum AssuranceLevel) error {
	_, err := s.authorize(ctx, actor, permission, Scope{Kind: ScopeTenant, TenantID: tenantID}, minimum)
	return err
}

func (s *Service) validateRecentRoleStepUp(ctx context.Context, actor ActorContext) error {
	if actor.SessionID == "" { return ErrAssuranceRequired }
	if err := s.validateActor(ctx, actor, AssuranceMFA); err != nil { return err }
	session, err := s.store.Session(ctx, actor.SessionID); if err != nil { return ErrAssuranceRequired }
	now := s.clock().UTC()
	if session.Assurance < AssuranceMFA || session.CreatedAt.After(now) || now.Sub(session.CreatedAt) > roleRecentStepUp { return ErrAssuranceRequired }
	return nil
}

func validateRoleActorTx(ctx context.Context, tx *sql.Tx, actor ActorContext, tenantID ID) error {
	var principalState, tenantState string; var epoch uint64
	err := tx.QueryRowContext(ctx, `SELECT p.state,p.authz_epoch,t.state FROM identity_principals p JOIN identity_tenants t ON t.id=? WHERE p.id=?`, tenantID, actor.PrincipalID).Scan(&principalState, &epoch, &tenantState)
	if errors.Is(err, sql.ErrNoRows) { return ErrUnauthenticated }; if err != nil { return err }
	if PrincipalState(principalState) != PrincipalActive || TenantState(tenantState) != TenantActive || epoch != actor.AuthzEpoch { return ErrUnauthenticated }
	if actor.SessionID != "" { var sessionEpoch uint64; var revoked sql.NullTime; if err = tx.QueryRowContext(ctx, `SELECT authz_epoch,revoked_at FROM identity_sessions WHERE id=? AND principal_id=?`, actor.SessionID, actor.PrincipalID).Scan(&sessionEpoch, &revoked); err != nil || revoked.Valid || sessionEpoch != actor.AuthzEpoch { return ErrUnauthenticated } }
	return nil
}

func (s *Service) roleActorCanGrant(ctx context.Context, actor ActorContext, permissions []Permission, selectors []Scope, effectiveAt time.Time, expiresAt *time.Time) ([]ID, error) {
	now := s.clock().UTC()
	enforceWindow := !effectiveAt.IsZero()
	provenance := make(map[ID]struct{})
	for _, permission := range permissions {
		for _, selector := range selectors {
			decision, err := s.authorizer.Decide(ctx, AuthorizationRequest{PrincipalID: actor.PrincipalID, Permission: permission, Scope: selector, At: now, Assurance: actor.Assurance})
			if err != nil { return nil, ErrGrantCeiling }
			if len(decision.BindingIDs) > 128 { return nil, ErrGrantCeiling }
			validWindow := !enforceWindow
			for _, edgeID := range decision.BindingIDs {
				if !enforceWindow { provenance[edgeID] = struct{}{}; continue }
				effective, expiry, loadErr := s.store.bindingGrantWindow(ctx, edgeID)
				if loadErr != nil { return nil, loadErr }
				if effective.After(effectiveAt) { continue }
				if expiresAt == nil && expiry != nil || expiresAt != nil && expiry != nil && expiry.Before(*expiresAt) { continue }
				validWindow = true
				provenance[edgeID] = struct{}{}
			}
			if !validWindow { return nil, ErrGrantCeiling }
			for _, delegationID := range decision.DelegationIDs { provenance[delegationID] = struct{}{} }
		}
	}
	values := make([]ID, 0, len(provenance)); for id := range provenance { values = append(values, id) }
	if len(values) > 128 { return nil, ErrGrantCeiling }
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values, nil
}

func (s *Store) bindingGrantWindow(ctx context.Context, edgeID ID) (time.Time, *time.Time, error) {
	var logical ID; var edgeExpiry sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(e.logical_binding_id,''),b.expires_at FROM identity_role_bindings b LEFT JOIN identity_managed_role_binding_edges e ON e.edge_id=b.id WHERE b.id=?`, edgeID).Scan(&logical, &edgeExpiry)
	if errors.Is(err, sql.ErrNoRows) { return time.Time{}, nil, ErrNotFound }; if err != nil { return time.Time{}, nil, err }
	if logical == "" { if edgeExpiry.Valid { expiry := edgeExpiry.Time; return time.Time{}, &expiry, nil }; return time.Time{}, nil, nil }
	var effective time.Time; var managedExpiry, revoked sql.NullTime
	err = s.db.QueryRowContext(ctx, `SELECT effective_at,expires_at,revoked_at FROM identity_managed_role_bindings WHERE id=?`, logical).Scan(&effective, &managedExpiry, &revoked)
	if errors.Is(err, sql.ErrNoRows) { return time.Time{}, nil, ErrConflict }; if err != nil { return time.Time{}, nil, err }; if revoked.Valid { return time.Time{}, nil, ErrBindingInactive }
	if managedExpiry.Valid { expiry := managedExpiry.Time; return effective, &expiry, nil }
	if edgeExpiry.Valid { expiry := edgeExpiry.Time; return effective, &expiry, nil }
	return effective, nil, nil
}

// BindingEffective makes managed not-before and revocation state part of the
// existing authorization decision. Legacy bindings remain immediately active.
func (s *Store) BindingEffective(ctx context.Context, edgeID ID, at time.Time) (bool, error) {
	if s == nil || s.db == nil || ctx == nil || !edgeID.Valid() || at.IsZero() { return false, ErrInvalid }
	var logical ID
	err := s.db.QueryRowContext(ctx, `SELECT logical_binding_id FROM identity_managed_role_binding_edges WHERE edge_id=?`, edgeID).Scan(&logical)
	if errors.Is(err, sql.ErrNoRows) { return true, nil }; if err != nil { return false, err }; if !logical.Valid() { return false, ErrConflict }
	var effective time.Time
	var expiry, revoked sql.NullTime
	err = s.db.QueryRowContext(ctx, `SELECT effective_at,expires_at,revoked_at FROM identity_managed_role_bindings WHERE id=?`, logical).Scan(&effective, &expiry, &revoked)
	if errors.Is(err, sql.ErrNoRows) { return false, ErrConflict }; if err != nil { return false, err }
	return !revoked.Valid && !at.Before(effective) && (!expiry.Valid || at.Before(expiry.Time)), nil
}

func roleAuditDigest(value any) string { encoded, _ := json.Marshal(value); return digest(encoded) }

func (s *Service) auditRole(ctx context.Context, actor, tenant ID, action, kind string, target ID, before, after any, fields []RoleField, outcome string) {
	names := make([]string, len(fields)); for index, field := range fields { names[index] = string(field) }; sort.Strings(names)
	s.record(ctx, actor, tenant, action, kind, target, outcome, "before:"+roleAuditDigest(before)+"\x00after:"+roleAuditDigest(after)+"\x00fields:"+strings.Join(names, ","))
}

func (s *Service) CreateManagedRole(ctx context.Context, command CreateManagedRoleCommand) (ManagedRole, error) {
	if s == nil || s.store == nil || ctx == nil || !command.RoleID.Valid() || !command.TenantID.Valid() { return ManagedRole{}, ErrInvalid }
	if err := s.authorizeRole(ctx, command.Actor, command.TenantID, "role:manage", AssuranceMFA); err != nil { return ManagedRole{}, err }
	name, description, permissions, selectors := normalizeRoleDefinition(command.Name, command.Description, command.Permissions, command.Selectors)
	if reservedBuiltInRoleName(name) || validateRoleDefinition(command.TenantID, name, description, permissions, selectors, false) != nil { return ManagedRole{}, ErrInvalid }
	if command.ClonedFromID != "" && !command.ClonedFromID.Valid() { return ManagedRole{}, ErrInvalid }
	if existing, loadErr := s.store.managedRole(ctx, command.TenantID, command.RoleID); loadErr == nil {
		if existing.State == RoleActive && existing.Name == name && existing.Description == description && existing.ClonedFromID == command.ClonedFromID && samePermissions(existing.Permissions, permissions) && sameScopes(existing.Selectors, selectors) { return existing, nil }
		return ManagedRole{}, ErrConflict
	} else if !errors.Is(loadErr, ErrNotFound) { return ManagedRole{}, loadErr }
	if _, err := s.roleActorCanGrant(ctx, command.Actor, permissions, selectors, time.Time{}, nil); err != nil { s.auditRole(ctx, command.Actor.PrincipalID, command.TenantID, "role.create", "role", command.RoleID, nil, nil, nil, "rejected"); return ManagedRole{}, err }
	now := s.clock().UTC()
	value := ManagedRole{Role: Role{ID: command.RoleID, TenantID: command.TenantID, Name: name, Permissions: permissions, Generation: 1, CreatedAt: now, UpdatedAt: now}, Description: description, State: RoleActive, Version: 1, Revision: 1, Selectors: selectors, ClonedFromID: command.ClonedFromID, CreatedByID: command.Actor.PrincipalID}
	if err := value.Validate(); err != nil { return ManagedRole{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ManagedRole{}, err }; defer tx.Rollback()
	if err = validateRoleActorTx(ctx, tx, command.Actor, command.TenantID); err != nil { return ManagedRole{}, err }
	if err = ensureBuiltInRolesTx(ctx, tx, command.TenantID, now); err != nil { return ManagedRole{}, err }
	var conflictingID ID; idErr := tx.QueryRowContext(ctx, `SELECT id FROM identity_roles WHERE id=? LIMIT 1`, command.RoleID).Scan(&conflictingID); if idErr == nil { return ManagedRole{}, ErrConflict }; if !errors.Is(idErr, sql.ErrNoRows) { return ManagedRole{}, idErr }
	var conflicting ID; nameErr := tx.QueryRowContext(ctx, `SELECT id FROM identity_roles WHERE tenant_id=? AND lower(name)=lower(?) LIMIT 1`, command.TenantID, name).Scan(&conflicting); if nameErr == nil { return ManagedRole{}, ErrConflict }; if !errors.Is(nameErr, sql.ErrNoRows) { return ManagedRole{}, nameErr }
	err = insertManagedRoleTx(ctx, tx, value, []RoleField{RoleFieldName, RoleFieldDescription, RoleFieldPermissions, RoleFieldSelectors}, command.Actor.PrincipalID)
	if err != nil { return ManagedRole{}, err }; if err = tx.Commit(); err != nil { return ManagedRole{}, err }
	s.auditRole(ctx, command.Actor.PrincipalID, command.TenantID, "role.create", "role", value.ID, nil, value, []RoleField{RoleFieldName, RoleFieldDescription, RoleFieldPermissions, RoleFieldSelectors}, "applied")
	return value, nil
}

func insertManagedRoleTx(ctx context.Context, tx *sql.Tx, value ManagedRole, fields []RoleField, actor ID) error {
	permissions, _ := json.Marshal(value.Permissions); selectors, _ := json.Marshal(value.Selectors); changed, _ := json.Marshal(fields)
	if _, err := tx.ExecContext(ctx, `INSERT INTO identity_roles(id,tenant_id,name,permissions_json,builtin,generation,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, value.ID, value.TenantID, value.Name, permissions, boolInt(value.Builtin), value.Generation, value.CreatedAt, value.UpdatedAt); err != nil { return err }
	if _, err := tx.ExecContext(ctx, `INSERT INTO identity_role_catalog(role_id,tenant_id,description,state,builtin_key,version,revision,selectors_json,cloned_from_id,created_by_id,created_at,updated_at,retired_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.ID, value.TenantID, value.Description, value.State, value.BuiltInKey, value.Version, value.Revision, selectors, value.ClonedFromID, value.CreatedByID, value.CreatedAt, value.UpdatedAt, value.RetiredAt, value.DeletedAt); err != nil { return err }
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_role_versions(role_id,tenant_id,version,name,description,permissions_json,selectors_json,state,changed_fields_json,changed_by_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, value.ID, value.TenantID, value.Version, value.Name, value.Description, permissions, selectors, value.State, changed, actor, value.UpdatedAt)
	return err
}

func reservedBuiltInRoleName(name string) bool { for _, value := range builtInRoleDefinitions { if strings.EqualFold(name, value.Name) { return true } }; return false }

func (s *Service) GetManagedRole(ctx context.Context, actor ActorContext, tenantID, roleID ID) (ManagedRole, error) {
	if err := s.authorizeRole(ctx, actor, tenantID, "role:manage", AssurancePassword); err != nil { return ManagedRole{}, err }
	if err := s.ensureBuiltInRoles(ctx, tenantID); err != nil { return ManagedRole{}, err }
	return s.store.managedRole(ctx, tenantID, roleID)
}

func (s *Service) ListManagedRoles(ctx context.Context, actor ActorContext, tenantID ID, query string, limit int, cursor ID) ([]ManagedRole, string, uint64, error) {
	if err := s.authorizeRole(ctx, actor, tenantID, "role:manage", AssurancePassword); err != nil { return nil, "", 0, err }
	query = strings.TrimSpace(query)
	if !tenantID.Valid() || limit < 1 || limit > roleMaximumPage || len(query) > 128 || cursor != "" && !cursor.Valid() { return nil, "", 0, ErrInvalid }
	if err := s.ensureBuiltInRoles(ctx, tenantID); err != nil { return nil, "", 0, err }
	var total uint64
	if err := s.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_role_catalog c JOIN identity_roles r ON r.id=c.role_id WHERE c.tenant_id=? AND c.state<>'deleted' AND (?='' OR instr(lower(r.name),lower(?))>0 OR instr(lower(c.description),lower(?))>0)`, tenantID, query, query, query).Scan(&total); err != nil { return nil, "", 0, err }
	rows, err := s.store.db.QueryContext(ctx, managedRoleSelect+` WHERE c.tenant_id=? AND c.state<>'deleted' AND c.role_id>? AND (?='' OR instr(lower(r.name),lower(?))>0 OR instr(lower(c.description),lower(?))>0) ORDER BY c.role_id LIMIT ?`, tenantID, cursor, query, query, query, limit+1)
	if err != nil { return nil, "", 0, err }; defer rows.Close()
	values := make([]ManagedRole, 0, limit)
	for rows.Next() { value, scanErr := scanManagedRole(rows); if scanErr != nil { return nil, "", 0, scanErr }; values = append(values, value) }
	if err = rows.Err(); err != nil { return nil, "", 0, err }
	next := ""; if len(values) > limit { next = values[limit-1].ID.String(); values = values[:limit] }
	return values, next, total, nil
}

func (s *Service) SearchManagedRoles(ctx context.Context, actor ActorContext, tenantID ID, query string, limit int, cursor ID) ([]ManagedRole, string, uint64, error) {
	if strings.TrimSpace(query) == "" { return nil, "", 0, ErrInvalid }
	return s.ListManagedRoles(ctx, actor, tenantID, query, limit, cursor)
}

func (s *Service) CloneManagedRole(ctx context.Context, command CloneManagedRoleCommand) (ManagedRole, error) {
	if !command.SourceRoleID.Valid() || command.ExpectedSourceRevision == 0 { return ManagedRole{}, ErrInvalid }
	source, err := s.GetManagedRole(ctx, command.Actor, command.TenantID, command.SourceRoleID); if err != nil { return ManagedRole{}, err }
	if source.Revision != command.ExpectedSourceRevision { return ManagedRole{}, ErrStaleGeneration }
	if source.State == RoleDeleted { return ManagedRole{}, ErrNotFound }
	description := command.Description; if strings.TrimSpace(description) == "" { description = source.Description }
	created, err := s.CreateManagedRole(ctx, CreateManagedRoleCommand{Actor: command.Actor, RoleID: command.RoleID, TenantID: command.TenantID, ClonedFromID: source.ID, Name: command.Name, Description: description, Permissions: source.Permissions, Selectors: source.Selectors})
	if err != nil { return ManagedRole{}, err }
	s.auditRole(ctx, command.Actor.PrincipalID, command.TenantID, "role.clone", "role", created.ID, source, created, []RoleField{RoleFieldName, RoleFieldDescription, RoleFieldPermissions, RoleFieldSelectors}, "applied")
	return created, nil
}

func (s *Service) UpdateManagedRole(ctx context.Context, command UpdateManagedRoleCommand) (ManagedRole, error) {
	if command.ExpectedRevision == 0 || len(command.FieldMask) < 1 || len(command.FieldMask) > 4 { return ManagedRole{}, ErrInvalid }
	if err := s.authorizeRole(ctx, command.Actor, command.TenantID, "role:manage", AssuranceMFA); err != nil { return ManagedRole{}, err }
	current, err := s.store.managedRole(ctx, command.TenantID, command.RoleID); if err != nil { return ManagedRole{}, err }
	if current.Builtin { return ManagedRole{}, ErrBuiltInRoleImmutable }; if current.State != RoleActive { return ManagedRole{}, ErrRoleRetired }; if current.Revision != command.ExpectedRevision { return ManagedRole{}, ErrStaleGeneration }
	next := current; seen := map[RoleField]bool{}
	for _, field := range command.FieldMask {
		if seen[field] { return ManagedRole{}, ErrInvalid }; seen[field] = true
		switch field { case RoleFieldName: next.Name = command.Name; case RoleFieldDescription: next.Description = command.Description; case RoleFieldPermissions: next.Permissions = command.Permissions; case RoleFieldSelectors: next.Selectors = command.Selectors; default: return ManagedRole{}, ErrInvalid }
	}
	if seen[RoleFieldPermissions] || seen[RoleFieldSelectors] { if err = s.validateRecentRoleStepUp(ctx, command.Actor); err != nil { return ManagedRole{}, err } }
	next.Name, next.Description, next.Permissions, next.Selectors = normalizeRoleDefinition(next.Name, next.Description, next.Permissions, next.Selectors)
	if reservedBuiltInRoleName(next.Name) || validateRoleDefinition(next.TenantID, next.Name, next.Description, next.Permissions, next.Selectors, false) != nil { return ManagedRole{}, ErrInvalid }
	if seen[RoleFieldSelectors] { inUse, loadErr := s.roleInUse(ctx, current.ID); if loadErr != nil { return ManagedRole{}, loadErr }; if inUse { return ManagedRole{}, ErrRoleInUse } }
	if seen[RoleFieldPermissions] || seen[RoleFieldSelectors] { if _, err = s.roleActorCanGrant(ctx, command.Actor, next.Permissions, next.Selectors, time.Time{}, nil); err != nil { return ManagedRole{}, err } }
	now := s.clock().UTC(); next.Version++; next.Revision++; next.Generation++; next.UpdatedAt = now
	if err = next.Validate(); err != nil { return ManagedRole{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ManagedRole{}, err }; defer tx.Rollback()
	if err = validateRoleActorTx(ctx, tx, command.Actor, command.TenantID); err != nil { return ManagedRole{}, err }
	permissions, _ := json.Marshal(next.Permissions); selectors, _ := json.Marshal(next.Selectors); changed, _ := json.Marshal(command.FieldMask)
	var conflicting ID; nameErr := tx.QueryRowContext(ctx, `SELECT id FROM identity_roles WHERE tenant_id=? AND id<>? AND lower(name)=lower(?) LIMIT 1`, next.TenantID, next.ID, next.Name).Scan(&conflicting); if nameErr == nil { return ManagedRole{}, ErrConflict }; if !errors.Is(nameErr, sql.ErrNoRows) { return ManagedRole{}, nameErr }
	if seen[RoleFieldSelectors] { inUse, loadErr := roleInUseTx(ctx, tx, next.ID); if loadErr != nil { return ManagedRole{}, loadErr }; if inUse { return ManagedRole{}, ErrRoleInUse } }
	result, err := tx.ExecContext(ctx, `UPDATE identity_role_catalog SET description=?,version=?,revision=?,selectors_json=?,updated_at=? WHERE role_id=? AND tenant_id=? AND revision=? AND state='active' AND builtin_key=''`, next.Description, next.Version, next.Revision, selectors, now, next.ID, next.TenantID, current.Revision)
	if err == nil { if rows, _ := result.RowsAffected(); rows != 1 { err = ErrStaleGeneration } }
	if err == nil { result, err = tx.ExecContext(ctx, `UPDATE identity_roles SET name=?,permissions_json=?,generation=?,updated_at=? WHERE id=? AND generation=? AND builtin=0`, next.Name, permissions, next.Generation, now, next.ID, current.Generation); if err == nil { if rows, _ := result.RowsAffected(); rows != 1 { err = ErrStaleGeneration } } }
	if err == nil { _, err = tx.ExecContext(ctx, `INSERT INTO identity_role_versions VALUES(?,?,?,?,?,?,?,?,?,?,?)`, next.ID, next.TenantID, next.Version, next.Name, next.Description, permissions, selectors, next.State, changed, command.Actor.PrincipalID, now) }
	if err == nil && (seen[RoleFieldPermissions] || seen[RoleFieldSelectors]) { err = invalidateRoleSubjectsTx(ctx, tx, next.ID, now) }
	if err != nil { return ManagedRole{}, err }; if err = tx.Commit(); err != nil { return ManagedRole{}, err }
	s.auditRole(ctx, command.Actor.PrincipalID, next.TenantID, "role.update", "role", next.ID, current, next, command.FieldMask, "applied")
	return next, nil
}

func scanManagedRoleVersion(row interface{ Scan(...any) error }) (ManagedRoleVersion, error) {
	var value ManagedRoleVersion; var permissions, selectors, fields []byte; var state string
	err := row.Scan(&value.RoleID, &value.TenantID, &value.Version, &value.Name, &value.Description, &permissions, &selectors, &state, &fields, &value.ChangedByID, &value.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) { return value, ErrNotFound }; if err != nil { return value, err }
	if json.Unmarshal(permissions, &value.Permissions) != nil || json.Unmarshal(selectors, &value.Selectors) != nil || json.Unmarshal(fields, &value.ChangedFields) != nil { return value, ErrInvalid }
	value.State = RoleLifecycleState(state)
	if !value.RoleID.Valid() || !value.TenantID.Valid() || value.Version == 0 || value.CreatedAt.IsZero() || value.State != RoleActive && value.State != RoleRetired && value.State != RoleDeleted || value.ChangedByID != "" && !value.ChangedByID.Valid() { return value, ErrInvalid }
	builtin := len(value.Permissions) == 1 && value.Permissions[0] == "*:*" && value.ChangedByID == ""
	if err := validateRoleDefinition(value.TenantID, value.Name, value.Description, value.Permissions, value.Selectors, builtin); err != nil { return value, err }
	seen := map[RoleField]bool{}; for _, field := range value.ChangedFields { if seen[field] { return value, ErrInvalid }; seen[field] = true; switch field { case RoleFieldName, RoleFieldDescription, RoleFieldPermissions, RoleFieldSelectors: default: return value, ErrInvalid } }
	return value, nil
}

func (s *Service) ListManagedRoleVersions(ctx context.Context, actor ActorContext, tenantID, roleID ID, limit int, after uint64) ([]ManagedRoleVersion, uint64, uint64, error) {
	if err := s.authorizeRole(ctx, actor, tenantID, "role:manage", AssurancePassword); err != nil { return nil, 0, 0, err }
	if limit < 1 || limit > roleMaximumPage { return nil, 0, 0, ErrInvalid }
	if err := s.ensureBuiltInRoles(ctx, tenantID); err != nil { return nil, 0, 0, err }
	if _, err := s.store.managedRole(ctx, tenantID, roleID); err != nil { return nil, 0, 0, err }
	var total uint64; if err := s.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_role_versions WHERE tenant_id=? AND role_id=?`, tenantID, roleID).Scan(&total); err != nil { return nil, 0, 0, err }
	rows, err := s.store.db.QueryContext(ctx, `SELECT role_id,tenant_id,version,name,description,permissions_json,selectors_json,state,changed_fields_json,changed_by_id,created_at FROM identity_role_versions WHERE tenant_id=? AND role_id=? AND version>? ORDER BY version LIMIT ?`, tenantID, roleID, after, limit+1); if err != nil { return nil, 0, 0, err }; defer rows.Close()
	values := make([]ManagedRoleVersion, 0, limit); for rows.Next() { value, scanErr := scanManagedRoleVersion(rows); if scanErr != nil { return nil, 0, 0, scanErr }; values = append(values, value) }; if err = rows.Err(); err != nil { return nil, 0, 0, err }
	var next uint64; if len(values) > limit { next = values[limit-1].Version; values = values[:limit] }
	return values, next, total, nil
}

func (s *Service) transitionManagedRole(ctx context.Context, actor ActorContext, tenantID, roleID ID, expected uint64, target RoleLifecycleState) (ManagedRole, error) {
	if expected == 0 { return ManagedRole{}, ErrInvalid }; if err := s.authorizeRole(ctx, actor, tenantID, "role:manage", AssuranceMFA); err != nil { return ManagedRole{}, err }
	current, err := s.store.managedRole(ctx, tenantID, roleID); if err != nil { return ManagedRole{}, err }; if current.Builtin { return ManagedRole{}, ErrBuiltInRoleImmutable }; if current.Revision != expected { return ManagedRole{}, ErrStaleGeneration }
	if target == RoleRetired && current.State != RoleActive || target == RoleDeleted && current.State != RoleRetired { return ManagedRole{}, ErrConflict }
	if target == RoleDeleted { inUse, loadErr := s.roleInUse(ctx, roleID); if loadErr != nil { return ManagedRole{}, loadErr }; if inUse { return ManagedRole{}, ErrRoleInUse } }
	now := s.clock().UTC(); next := current; next.State = target; next.Version++; next.Revision++; next.Generation++; next.UpdatedAt = now; if target == RoleRetired { next.RetiredAt = &now }; if target == RoleDeleted { next.DeletedAt = &now }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ManagedRole{}, err }; defer tx.Rollback()
	if err = validateRoleActorTx(ctx, tx, actor, tenantID); err != nil { return ManagedRole{}, err }
	if target == RoleDeleted { inUse, loadErr := roleInUseTx(ctx, tx, roleID); if loadErr != nil { return ManagedRole{}, loadErr }; if inUse { return ManagedRole{}, ErrRoleInUse } }
	result, err := tx.ExecContext(ctx, `UPDATE identity_role_catalog SET state=?,version=?,revision=?,updated_at=?,retired_at=?,deleted_at=? WHERE role_id=? AND tenant_id=? AND revision=? AND builtin_key=''`, next.State, next.Version, next.Revision, now, next.RetiredAt, next.DeletedAt, roleID, tenantID, expected)
	if err == nil { if rows, _ := result.RowsAffected(); rows != 1 { err = ErrStaleGeneration } }
	if err == nil { result, err = tx.ExecContext(ctx, `UPDATE identity_roles SET generation=?,updated_at=? WHERE id=? AND generation=? AND builtin=0`, next.Generation, now, roleID, current.Generation); if err == nil { if rows, _ := result.RowsAffected(); rows != 1 { err = ErrStaleGeneration } } }
	if err == nil { permissions, _ := json.Marshal(next.Permissions); selectors, _ := json.Marshal(next.Selectors); fields, _ := json.Marshal([]RoleField{}); _, err = tx.ExecContext(ctx, `INSERT INTO identity_role_versions VALUES(?,?,?,?,?,?,?,?,?,?,?)`, next.ID, next.TenantID, next.Version, next.Name, next.Description, permissions, selectors, next.State, fields, actor.PrincipalID, now) }
	if err != nil { return ManagedRole{}, err }; if err = tx.Commit(); err != nil { return ManagedRole{}, err }
	action := "role.retire"; if target == RoleDeleted { action = "role.delete" }; s.auditRole(ctx, actor.PrincipalID, tenantID, action, "role", roleID, current, next, nil, "applied")
	return next, nil
}

func (s *Service) RetireManagedRole(ctx context.Context, actor ActorContext, tenantID, roleID ID, expected uint64) (ManagedRole, error) { return s.transitionManagedRole(ctx, actor, tenantID, roleID, expected, RoleRetired) }
func (s *Service) DeleteManagedRole(ctx context.Context, actor ActorContext, tenantID, roleID ID, expected uint64) (ManagedRole, error) { return s.transitionManagedRole(ctx, actor, tenantID, roleID, expected, RoleDeleted) }

func (s *Service) roleInUse(ctx context.Context, roleID ID) (bool, error) {
	var count uint64
	err := s.store.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM identity_role_bindings WHERE role_id=?)+(SELECT COUNT(*) FROM identity_invitations WHERE role_id=? AND state='pending')+(SELECT COUNT(*) FROM identity_service_principals WHERE role_id=? AND state<>'deleted')`, roleID, roleID, roleID).Scan(&count)
	return count != 0, err
}

func roleInUseTx(ctx context.Context, tx *sql.Tx, roleID ID) (bool, error) {
	var count uint64
	err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM identity_role_bindings WHERE role_id=?)+(SELECT COUNT(*) FROM identity_invitations WHERE role_id=? AND state='pending')+(SELECT COUNT(*) FROM identity_service_principals WHERE role_id=? AND state<>'deleted')`, roleID, roleID, roleID).Scan(&count)
	return count != 0, err
}

func invalidateRoleSubjectsTx(ctx context.Context, tx *sql.Tx, roleID ID, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT subject_id FROM identity_role_bindings WHERE role_id=?`, roleID); if err != nil { return err }
	var values []ID; for rows.Next() { var id ID; if err = rows.Scan(&id); err != nil { rows.Close(); return err }; values = append(values, id) }; err = rows.Err(); rows.Close(); if err != nil { return err }
	for _, id := range values { if err = invalidateRoleSubjectTx(ctx, tx, id, now); err != nil { return err } }
	return nil
}

func invalidateRoleSubjectTx(ctx context.Context, tx *sql.Tx, subjectID ID, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE identity_principals SET authz_epoch=authz_epoch+1,generation=generation+1,updated_at=? WHERE id=?`, now, subjectID); err != nil { return err }
	if _, err := tx.ExecContext(ctx, `UPDATE identity_service_principals SET authz_epoch=authz_epoch+1,generation=generation+1,updated_at=? WHERE principal_id=? AND state<>'deleted'`, now, subjectID); err != nil { return err }
	_, err := tx.ExecContext(ctx, `UPDATE identity_human_users SET authz_epoch=(SELECT authz_epoch FROM identity_principals WHERE id=?),revision=revision+1,updated_at=? WHERE identity_id=? AND state IN ('active','suspended')`, subjectID, now, subjectID)
	return err
}

func roleContainsSelector(role ManagedRole, selector Scope) bool { for _, ceiling := range role.Selectors { if scopeContains(ceiling, selector) { return true } }; return false }

func validateBindingSubjectTx(ctx context.Context, tx *sql.Tx, tenantID ID, kind SubjectKind, subjectID ID) error {
	var principalKind, principalState, membershipState string
	err := tx.QueryRowContext(ctx, `SELECT p.kind,p.state,m.state FROM identity_principals p JOIN identity_memberships m ON m.principal_id=p.id AND m.tenant_id=? WHERE p.id=?`, tenantID, subjectID).Scan(&principalKind, &principalState, &membershipState)
	if errors.Is(err, sql.ErrNoRows) { return ErrNotFound }; if err != nil { return err }
	if PrincipalState(principalState) != PrincipalActive || MembershipState(membershipState) != MembershipActive { return ErrSuspended }
	if kind == SubjectPrincipal && PrincipalKind(principalKind) != PrincipalHuman || kind == SubjectService && PrincipalKind(principalKind) != PrincipalService { return ErrInvalid }
	return nil
}

func sameOptionalTime(left, right *time.Time) bool { if left == nil || right == nil { return left == nil && right == nil }; return left.Equal(*right) }

func (s *Service) AssignManagedRoleBinding(ctx context.Context, command AssignManagedRoleBindingCommand) (ManagedRoleBinding, error) {
	if s == nil || s.store == nil || ctx == nil || !command.BindingID.Valid() || !command.TenantID.Valid() || !command.SubjectID.Valid() || !command.RoleID.Valid() || command.ExpectedRoleRevision == 0 { return ManagedRoleBinding{}, ErrInvalid }
	if err := s.authorizeRole(ctx, command.Actor, command.TenantID, "role:bind", AssuranceMFA); err != nil { return ManagedRoleBinding{}, err }
	if err := s.ensureBuiltInRoles(ctx, command.TenantID); err != nil { return ManagedRoleBinding{}, err }
	selectors := append([]Scope(nil), command.Selectors...); sort.Slice(selectors, func(i, j int) bool { return roleScopeKey(selectors[i]) < roleScopeKey(selectors[j]) })
	if validateRoleSelectors(command.TenantID, selectors) != nil { return ManagedRoleBinding{}, ErrInvalid }
	if existing, loadErr := scanManagedBinding(s.store.db.QueryRowContext(ctx, managedBindingSelect+` WHERE tenant_id=? AND id=?`, command.TenantID, command.BindingID)); loadErr == nil {
		if existing.RevokedAt == nil && existing.SubjectKind == command.SubjectKind && existing.SubjectID == command.SubjectID && existing.RoleID == command.RoleID && existing.GrantedByID == command.Actor.PrincipalID && sameScopes(existing.Selectors, selectors) && sameOptionalTime(existing.ExpiresAt, command.ExpiresAt) && (command.EffectiveAt.IsZero() || existing.EffectiveAt.Equal(command.EffectiveAt)) { return existing, nil }
		return ManagedRoleBinding{}, ErrConflict
	} else if !errors.Is(loadErr, ErrNotFound) { return ManagedRoleBinding{}, loadErr }
	if err := s.validateRecentRoleStepUp(ctx, command.Actor); err != nil { return ManagedRoleBinding{}, err }
	role, err := s.store.managedRole(ctx, command.TenantID, command.RoleID); if err != nil { return ManagedRoleBinding{}, err }; if role.Revision != command.ExpectedRoleRevision { return ManagedRoleBinding{}, ErrStaleGeneration }; if role.State != RoleActive { return ManagedRoleBinding{}, ErrRoleRetired }; for _, selector := range selectors { if !roleContainsSelector(role, selector) { return ManagedRoleBinding{}, ErrGrantCeiling } }
	now := s.clock().UTC(); effectiveAt := command.EffectiveAt.UTC(); if effectiveAt.IsZero() { effectiveAt = now }; if effectiveAt.Before(now) { return ManagedRoleBinding{}, ErrGrantCeiling }
	provenance, err := s.roleActorCanGrant(ctx, command.Actor, role.Permissions, selectors, effectiveAt, command.ExpiresAt); if err != nil { s.auditRole(ctx, command.Actor.PrincipalID, command.TenantID, "role_binding.assign", "role_binding", command.BindingID, nil, nil, nil, "rejected"); return ManagedRoleBinding{}, err }
	value := ManagedRoleBinding{ID: command.BindingID, TenantID: command.TenantID, SubjectKind: command.SubjectKind, SubjectID: command.SubjectID, RoleID: role.ID, Selectors: selectors, EffectiveAt: effectiveAt, ExpiresAt: command.ExpiresAt, GrantedByID: command.Actor.PrincipalID, Provenance: provenance, Revision: 1, CreatedAt: now}
	if value.Validate() != nil || role.BuiltInKey == BuiltInOwner && (value.SubjectKind != SubjectPrincipal || len(value.Selectors) != 1 || value.Selectors[0].Kind != ScopeTenant) || role.BuiltInKey == BuiltInServicePrincipal && value.SubjectKind != SubjectService { return ManagedRoleBinding{}, ErrInvalid }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ManagedRoleBinding{}, err }; defer tx.Rollback()
	if err = validateRoleActorTx(ctx, tx, command.Actor, command.TenantID); err != nil { return ManagedRoleBinding{}, err }
	var roleState string; var roleRevision uint64; err = tx.QueryRowContext(ctx, `SELECT state,revision FROM identity_role_catalog WHERE role_id=? AND tenant_id=?`, value.RoleID, value.TenantID).Scan(&roleState, &roleRevision); if errors.Is(err, sql.ErrNoRows) { err = ErrNotFound }; if err == nil && (RoleLifecycleState(roleState) != RoleActive || roleRevision != role.Revision) { err = ErrStaleGeneration }
	if err == nil { err = validateBindingSubjectTx(ctx, tx, value.TenantID, value.SubjectKind, value.SubjectID) }
	if err == nil && value.SubjectKind == SubjectPrincipal { err = validateHumanRoleAssignmentTx(ctx, tx, value.TenantID, value.SubjectID, role) }
	if err == nil { err = insertManagedBindingTx(ctx, tx, value) }; if err == nil { err = invalidateRoleSubjectTx(ctx, tx, value.SubjectID, now) }
	if err != nil { return ManagedRoleBinding{}, err }; if err = tx.Commit(); err != nil { return ManagedRoleBinding{}, err }
	s.auditRole(ctx, command.Actor.PrincipalID, value.TenantID, "role_binding.assign", "role_binding", value.ID, nil, value, nil, "applied")
	return value, nil
}

func insertManagedBindingTx(ctx context.Context, tx *sql.Tx, value ManagedRoleBinding) error {
	selectors, _ := json.Marshal(value.Selectors); provenance, _ := json.Marshal(value.Provenance)
	if _, err := tx.ExecContext(ctx, `INSERT INTO identity_managed_role_bindings(id,tenant_id,subject_kind,subject_id,role_id,selectors_json,effective_at,expires_at,granted_by_id,provenance_json,revision,created_at,revoked_at,revoked_by_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL,'')`, value.ID, value.TenantID, value.SubjectKind, value.SubjectID, value.RoleID, selectors, value.EffectiveAt, value.ExpiresAt, value.GrantedByID, provenance, value.Revision, value.CreatedAt); err != nil { return err }
	for _, selector := range value.Selectors {
		edgeID, err := derivedID("rbe", value.ID.String()+"\x00"+roleScopeKey(selector)); if err != nil { return err }
		binding := RoleBinding{ID: edgeID, SubjectKind: value.SubjectKind, SubjectID: value.SubjectID, RoleID: value.RoleID, Scope: selector, ExpiresAt: value.ExpiresAt, Generation: 1, CreatedAt: value.CreatedAt}
		if err = putBinding(ctx, tx, binding); err != nil { return err }
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_managed_role_binding_edges(edge_id,logical_binding_id) VALUES(?,?)`, edgeID, value.ID); err != nil { return err }
	}
	return nil
}

func scanManagedBinding(row interface{ Scan(...any) error }) (ManagedRoleBinding, error) {
	var value ManagedRoleBinding; var selectors, provenance []byte; var kind string; var expiry, revoked sql.NullTime
	err := row.Scan(&value.ID, &value.TenantID, &kind, &value.SubjectID, &value.RoleID, &selectors, &value.EffectiveAt, &expiry, &value.GrantedByID, &provenance, &value.Revision, &value.CreatedAt, &revoked, &value.RevokedByID)
	if errors.Is(err, sql.ErrNoRows) { return value, ErrNotFound }; if err != nil { return value, err }
	if json.Unmarshal(selectors, &value.Selectors) != nil || json.Unmarshal(provenance, &value.Provenance) != nil { return value, ErrInvalid }
	value.SubjectKind = SubjectKind(kind); if expiry.Valid { value.ExpiresAt = &expiry.Time }; if revoked.Valid { value.RevokedAt = &revoked.Time }
	return value, value.Validate()
}

const managedBindingSelect = `SELECT id,tenant_id,subject_kind,subject_id,role_id,selectors_json,effective_at,expires_at,granted_by_id,provenance_json,revision,created_at,revoked_at,revoked_by_id FROM identity_managed_role_bindings`

func (s *Service) ListManagedRoleBindings(ctx context.Context, actor ActorContext, tenantID ID, subjectID ID, limit int, cursor ID) ([]ManagedRoleBinding, string, uint64, error) {
	if err := s.authorizeRole(ctx, actor, tenantID, "role:bind", AssurancePassword); err != nil { return nil, "", 0, err }
	if !tenantID.Valid() || subjectID != "" && !subjectID.Valid() || limit < 1 || limit > roleMaximumPage || cursor != "" && !cursor.Valid() { return nil, "", 0, ErrInvalid }
	var total uint64; if err := s.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_managed_role_bindings WHERE tenant_id=? AND (?='' OR subject_id=?)`, tenantID, subjectID, subjectID).Scan(&total); err != nil { return nil, "", 0, err }
	rows, err := s.store.db.QueryContext(ctx, managedBindingSelect+` WHERE tenant_id=? AND id>? AND (?='' OR subject_id=?) ORDER BY id LIMIT ?`, tenantID, cursor, subjectID, subjectID, limit+1); if err != nil { return nil, "", 0, err }; defer rows.Close()
	values := make([]ManagedRoleBinding, 0, limit); for rows.Next() { value, scanErr := scanManagedBinding(rows); if scanErr != nil { return nil, "", 0, scanErr }; values = append(values, value) }; if err = rows.Err(); err != nil { return nil, "", 0, err }
	next := ""; if len(values) > limit { next = values[limit-1].ID.String(); values = values[:limit] }
	return values, next, total, nil
}

func (s *Service) RevokeManagedRoleBinding(ctx context.Context, actor ActorContext, tenantID, bindingID ID, expected uint64) (ManagedRoleBinding, error) {
	if expected == 0 { return ManagedRoleBinding{}, ErrInvalid }; if err := s.authorizeRole(ctx, actor, tenantID, "role:bind", AssuranceMFA); err != nil { return ManagedRoleBinding{}, err }
	current, err := scanManagedBinding(s.store.db.QueryRowContext(ctx, managedBindingSelect+` WHERE tenant_id=? AND id=?`, tenantID, bindingID)); if err != nil { return ManagedRoleBinding{}, err }; if current.Revision != expected { return ManagedRoleBinding{}, ErrStaleGeneration }; if current.RevokedAt != nil { return ManagedRoleBinding{}, ErrBindingInactive }
	role, err := s.store.managedRole(ctx, tenantID, current.RoleID); if err != nil { return ManagedRoleBinding{}, err }
	now := s.clock().UTC(); tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}); if err != nil { return ManagedRoleBinding{}, err }; defer tx.Rollback()
	if err = validateRoleActorTx(ctx, tx, actor, tenantID); err != nil { return ManagedRoleBinding{}, err }
	if role.BuiltInKey == BuiltInOwner { var viableSubject uint64; if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_principals p JOIN identity_memberships m ON m.principal_id=p.id AND m.tenant_id=? WHERE p.id=? AND p.kind='human' AND p.state='active' AND m.state='active'`, tenantID, current.SubjectID).Scan(&viableSubject); err != nil { return ManagedRoleBinding{}, err }; currentViable := viableSubject == 1 && !now.Before(current.EffectiveAt) && (current.ExpiresAt == nil || now.Before(*current.ExpiresAt)); if currentViable { viable, loadErr := viableLocalOwnerExistsTx(ctx, tx, tenantID, bindingID, now); if loadErr != nil { return ManagedRoleBinding{}, loadErr }; if !viable { return ManagedRoleBinding{}, ErrLastLocalOwner } } }
	result, err := tx.ExecContext(ctx, `UPDATE identity_managed_role_bindings SET revision=revision+1,revoked_at=?,revoked_by_id=? WHERE id=? AND tenant_id=? AND revision=? AND revoked_at IS NULL`, now, actor.PrincipalID, bindingID, tenantID, expected)
	if err == nil { if rows, _ := result.RowsAffected(); rows != 1 { err = ErrStaleGeneration } }
	if err == nil { _, err = tx.ExecContext(ctx, `DELETE FROM identity_role_bindings WHERE id IN (SELECT edge_id FROM identity_managed_role_binding_edges WHERE logical_binding_id=?)`, bindingID) }
	if err == nil { _, err = tx.ExecContext(ctx, `DELETE FROM identity_managed_role_binding_edges WHERE logical_binding_id=?`, bindingID) }
	if err == nil { err = invalidateRoleSubjectTx(ctx, tx, current.SubjectID, now) }
	if err != nil { return ManagedRoleBinding{}, err }; if err = tx.Commit(); err != nil { return ManagedRoleBinding{}, err }
	next := current; next.Revision++; next.RevokedAt = &now; next.RevokedByID = actor.PrincipalID
	s.auditRole(ctx, actor.PrincipalID, tenantID, "role_binding.revoke", "role_binding", bindingID, current, next, nil, "applied")
	return next, nil
}

func viableLocalOwnerExistsTx(ctx context.Context, tx *sql.Tx, tenantID, excludingBinding ID, now time.Time) (bool, error) {
	ownerID, err := builtInRoleID(tenantID, BuiltInOwner); if err != nil { return false, err }
	rows, err := tx.QueryContext(ctx, `SELECT b.scope_kind,b.tenant_id,b.expires_at,r.id,r.permissions_json,COALESCE(e.logical_binding_id,'') FROM identity_role_bindings b JOIN identity_roles r ON r.id=b.role_id JOIN identity_principals p ON p.id=b.subject_id JOIN identity_memberships m ON m.principal_id=p.id AND m.tenant_id=? LEFT JOIN identity_managed_role_binding_edges e ON e.edge_id=b.id WHERE p.kind='human' AND p.state='active' AND m.state='active' AND r.tenant_id=? AND (r.id=? OR r.builtin=1)`, tenantID, tenantID, ownerID); if err != nil { return false, err }
	var candidates []ID
	for rows.Next() {
		var bindingTenant, roleID, logical ID; var scopeKind string; var expiry sql.NullTime; var permissions []byte
		if err = rows.Scan(&scopeKind, &bindingTenant, &expiry, &roleID, &permissions, &logical); err != nil { rows.Close(); return false, err }
		if logical == excludingBinding || expiry.Valid && !now.Before(expiry.Time) { continue }
		if ScopeKind(scopeKind) != ScopeInstallation && (ScopeKind(scopeKind) != ScopeTenant || bindingTenant != tenantID) { continue }
		var values []Permission; if json.Unmarshal(permissions, &values) != nil { rows.Close(); return false, ErrInvalid }; if roleID != ownerID && !containsPermission(values, "*:*") { continue }
		if logical == "" { rows.Close(); return true, nil }
		candidates = append(candidates, logical)
	}
	if err = rows.Err(); err != nil { rows.Close(); return false, err }; rows.Close()
	for _, logical := range candidates { var effective time.Time; var managedExpiry, revoked sql.NullTime; if err = tx.QueryRowContext(ctx, `SELECT effective_at,expires_at,revoked_at FROM identity_managed_role_bindings WHERE id=?`, logical).Scan(&effective, &managedExpiry, &revoked); err != nil { return false, err }; if !revoked.Valid && !now.Before(effective) && (!managedExpiry.Valid || now.Before(managedExpiry.Time)) { return true, nil } }
	return false, nil
}
