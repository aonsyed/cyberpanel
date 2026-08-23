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
	humanUserMaximumPage        = 100
	humanUserMaximumMemberships = 100
	humanUserRetention          = 30 * 24 * time.Hour
)

type HumanUserState string

const (
	HumanUserActive          HumanUserState = "active"
	HumanUserSuspended       HumanUserState = "suspended"
	HumanUserDeletionPending HumanUserState = "deletion_pending"
	HumanUserDeleted         HumanUserState = "deleted"
)

type HumanUserRoleCeiling string

const (
	HumanUserCeilingMember        HumanUserRoleCeiling = "member"
	HumanUserCeilingAdministrator HumanUserRoleCeiling = "administrator"
	HumanUserCeilingOwner         HumanUserRoleCeiling = "owner"
)

type HumanIdentifierKind string

const (
	HumanIdentifierUsername HumanIdentifierKind = "username"
	HumanIdentifierEmail    HumanIdentifierKind = "email"
)

type HumanUserField string

const (
	HumanUserFieldDisplayName HumanUserField = "display_name"
	HumanUserFieldRoleCeiling HumanUserField = "role_ceiling"
)

type HumanMembershipPlanAction string

const (
	HumanMembershipAdd    HumanMembershipPlanAction = "add"
	HumanMembershipUpdate HumanMembershipPlanAction = "update"
	HumanMembershipRemove HumanMembershipPlanAction = "remove"
)

var (
	ErrHumanUserRoleCeiling      = fmt.Errorf("%w: human user role ceiling", ErrDelegationExceeded)
	ErrHumanUserOwnershipBlocked = fmt.Errorf("%w: human user owns resources", ErrConflict)
	ErrHumanUserRetention        = fmt.Errorf("%w: human user retention period", ErrConflict)
	ErrHumanUserQuarantined      = fmt.Errorf("%w: human user quarantined", ErrSuspended)
)

type HumanIdentifier struct {
	Kind       HumanIdentifierKind
	Value      string
	VerifiedAt time.Time
}

type HumanUserMembership struct {
	MembershipID      ID
	TenantID          ID
	State             MembershipState
	RoleCeiling       HumanUserRoleCeiling
	Generation        uint64
	LifecycleSuspended bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type HumanUser struct {
	IdentityID          ID
	PrimaryTenantID     ID
	DisplayName         string
	ProfilePrincipalID  ID
	State               HumanUserState
	Identifiers         []HumanIdentifier
	Memberships         []HumanUserMembership
	Revision            uint64
	AuthzEpoch          uint64
	CreatedAt           time.Time
	UpdatedAt           time.Time
	SuspendedAt         *time.Time
	DeletionRequestedAt *time.Time
	RetentionDeadline   *time.Time
	DeletedAt           *time.Time
	TombstoneDigest     string
}

type HumanResourceOwnership struct {
	IdentityID  ID
	TenantID    ID
	ResourceKind string
	ResourceID  ID
}

type HumanUserDeletionImpact struct {
	IdentityID          ID
	MembershipCount     uint64
	ActiveSessionCount  uint64
	ActiveCredentialCount uint64
	ActiveAPICredentialCount uint64
	ActiveRoleBindingCount uint64
	OwnershipBlockers   []HumanResourceOwnership
	OwnershipBlockerCount uint64
	LastOwnerTenants    []ID
	RetentionDeadline   time.Time
}

type CreateHumanUserCommand struct {
	Actor       ActorContext
	TenantID    ID
	IdentityID  ID
	RoleCeiling HumanUserRoleCeiling
}

type UpdateHumanUserCommand struct {
	Actor            ActorContext
	TenantID         ID
	IdentityID       ID
	ExpectedRevision uint64
	FieldMask        []HumanUserField
	DisplayName      string
	RoleCeiling      HumanUserRoleCeiling
}

type HumanMembershipPlanStep struct {
	Action             HumanMembershipPlanAction
	MembershipID       ID
	TenantID            ID
	ExpectedGeneration uint64
	RoleCeiling         HumanUserRoleCeiling
}

type TransferHumanUserCommand struct {
	Actor              ActorContext
	TenantID           ID
	IdentityID         ID
	ExpectedRevision   uint64
	NewPrimaryTenantID ID
	Steps              []HumanMembershipPlanStep
}

func validHumanUserRoleCeiling(value HumanUserRoleCeiling) bool {
	return value == HumanUserCeilingMember || value == HumanUserCeilingAdministrator || value == HumanUserCeilingOwner
}

func humanUserCeilingRank(value HumanUserRoleCeiling) int {
	switch value {
	case HumanUserCeilingMember:
		return 1
	case HumanUserCeilingAdministrator:
		return 2
	case HumanUserCeilingOwner:
		return 3
	default:
		return 0
	}
}

func (u HumanUser) Validate() error {
	if !u.IdentityID.Valid() || !u.PrimaryTenantID.Valid() || !u.ProfilePrincipalID.Valid() || u.ProfilePrincipalID != u.IdentityID || u.Revision == 0 || u.AuthzEpoch == 0 || u.CreatedAt.IsZero() || u.UpdatedAt.Before(u.CreatedAt) {
		return fmt.Errorf("%w: human user identity", ErrInvalid)
	}
	if u.State != HumanUserActive && u.State != HumanUserSuspended && u.State != HumanUserDeletionPending && u.State != HumanUserDeleted {
		return fmt.Errorf("%w: human user state", ErrInvalid)
	}
	if u.State != HumanUserDeleted && (strings.TrimSpace(u.DisplayName) == "" || len(u.DisplayName) > 128 || strings.ContainsAny(u.DisplayName, "\x00\r\n\t")) {
		return fmt.Errorf("%w: human user display name", ErrInvalid)
	}
	if len(u.Memberships) < 1 || len(u.Memberships) > humanUserMaximumMemberships {
		return fmt.Errorf("%w: human user memberships", ErrInvalid)
	}
	primary, seenMemberships := false, map[ID]struct{}{}
	for _, membership := range u.Memberships {
		if !membership.MembershipID.Valid() || !membership.TenantID.Valid() || membership.Generation == 0 || !validHumanUserRoleCeiling(membership.RoleCeiling) || membership.CreatedAt.IsZero() || membership.UpdatedAt.Before(membership.CreatedAt) {
			return fmt.Errorf("%w: human user membership", ErrInvalid)
		}
		if membership.State != MembershipInvited && membership.State != MembershipActive && membership.State != MembershipSuspended && membership.State != MembershipRevoked {
			return fmt.Errorf("%w: human user membership state", ErrInvalid)
		}
		if membership.LifecycleSuspended && membership.State != MembershipSuspended {
			return fmt.Errorf("%w: human user lifecycle suspension", ErrInvalid)
		}
		if _, exists := seenMemberships[membership.TenantID]; exists {
			return fmt.Errorf("%w: duplicate human user membership", ErrInvalid)
		}
		seenMemberships[membership.TenantID] = struct{}{}
		primary = primary || membership.TenantID == u.PrimaryTenantID
	}
	if !primary {
		return fmt.Errorf("%w: human user primary membership", ErrInvalid)
	}
	if u.State == HumanUserDeleted {
		if len(u.Identifiers) != 0 || u.DisplayName != "" || u.DeletedAt == nil || u.DeletionRequestedAt == nil || u.RetentionDeadline == nil || len(u.TombstoneDigest) != 64 {
			return fmt.Errorf("%w: human user tombstone", ErrInvalid)
		}
		return nil
	}
	if len(u.Identifiers) != 2 || u.TombstoneDigest != "" {
		return fmt.Errorf("%w: human user identifiers", ErrInvalid)
	}
	seenIdentifiers := map[HumanIdentifierKind]struct{}{}
	for _, identifier := range u.Identifiers {
		if identifier.VerifiedAt.IsZero() || identifier.VerifiedAt.After(u.UpdatedAt) {
			return fmt.Errorf("%w: human user identifier verification", ErrInvalid)
		}
		switch identifier.Kind {
		case HumanIdentifierUsername:
			if identifier.Value != normalizeUsername(identifier.Value) || !usernamePattern.MatchString(identifier.Value) {
				return fmt.Errorf("%w: human username", ErrInvalid)
			}
		case HumanIdentifierEmail:
			if identifier.Value != normalizeInvitationEmail(identifier.Value) || !validInvitationEmail(identifier.Value) {
				return fmt.Errorf("%w: human email", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: human identifier kind", ErrInvalid)
		}
		if _, exists := seenIdentifiers[identifier.Kind]; exists {
			return fmt.Errorf("%w: duplicate human identifier", ErrInvalid)
		}
		seenIdentifiers[identifier.Kind] = struct{}{}
	}
	switch u.State {
	case HumanUserActive:
		if u.SuspendedAt != nil || u.DeletionRequestedAt != nil || u.RetentionDeadline != nil || u.DeletedAt != nil {
			return fmt.Errorf("%w: active human user timestamps", ErrInvalid)
		}
	case HumanUserSuspended:
		if u.SuspendedAt == nil || u.DeletionRequestedAt != nil || u.RetentionDeadline != nil || u.DeletedAt != nil {
			return fmt.Errorf("%w: suspended human user timestamps", ErrInvalid)
		}
	case HumanUserDeletionPending:
		if u.DeletionRequestedAt == nil || u.RetentionDeadline == nil || !u.RetentionDeadline.After(*u.DeletionRequestedAt) || u.DeletedAt != nil {
			return fmt.Errorf("%w: human user deletion retention", ErrInvalid)
		}
	}
	return nil
}

type humanUserQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const humanUserSelect = `SELECT identity_id,primary_tenant_id,display_name,profile_principal_id,state,revision,authz_epoch,created_at,updated_at,suspended_at,deletion_requested_at,retention_deadline,deleted_at,tombstone_digest FROM identity_human_users`

func scanHumanUserBase(row interface{ Scan(...any) error }) (HumanUser, error) {
	var value HumanUser
	var state string
	var suspended, deletionRequested, retention, deleted sql.NullTime
	err := row.Scan(&value.IdentityID, &value.PrimaryTenantID, &value.DisplayName, &value.ProfilePrincipalID, &state, &value.Revision, &value.AuthzEpoch, &value.CreatedAt, &value.UpdatedAt, &suspended, &deletionRequested, &retention, &deleted, &value.TombstoneDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return HumanUser{}, ErrNotFound
	}
	if err != nil {
		return HumanUser{}, err
	}
	value.State = HumanUserState(state)
	if suspended.Valid { value.SuspendedAt = &suspended.Time }
	if deletionRequested.Valid { value.DeletionRequestedAt = &deletionRequested.Time }
	if retention.Valid { value.RetentionDeadline = &retention.Time }
	if deleted.Valid { value.DeletedAt = &deleted.Time }
	return value, nil
}

func loadHumanUser(ctx context.Context, queryer humanUserQueryer, identityID ID, visibleTenant ID) (HumanUser, error) {
	if ctx == nil || !identityID.Valid() || visibleTenant != "" && !visibleTenant.Valid() {
		return HumanUser{}, ErrInvalid
	}
	query := humanUserSelect + ` WHERE identity_id=?`
	args := []any{identityID}
	if visibleTenant != "" {
		query += ` AND EXISTS(SELECT 1 FROM identity_human_user_memberships WHERE identity_id=identity_human_users.identity_id AND tenant_id=?)`
		args = append(args, visibleTenant)
	}
	value, err := scanHumanUserBase(queryer.QueryRowContext(ctx, query, args...))
	if err != nil {
		return HumanUser{}, err
	}
	if err = queryer.QueryRowContext(ctx, `SELECT authz_epoch FROM identity_principals WHERE id=? AND kind='human'`, identityID).Scan(&value.AuthzEpoch); errors.Is(err, sql.ErrNoRows) { return HumanUser{}, ErrNotFound } else if err != nil { return HumanUser{}, err }
	identifierRows, err := queryer.QueryContext(ctx, `SELECT kind,normalized_value,verified_at FROM identity_human_user_identifiers WHERE identity_id=? ORDER BY kind LIMIT 3`, identityID)
	if err != nil {
		return HumanUser{}, err
	}
	for identifierRows.Next() {
		var identifier HumanIdentifier
		var kind string
		if err = identifierRows.Scan(&kind, &identifier.Value, &identifier.VerifiedAt); err != nil { identifierRows.Close(); return HumanUser{}, err }
		identifier.Kind = HumanIdentifierKind(kind)
		value.Identifiers = append(value.Identifiers, identifier)
	}
	if err = identifierRows.Err(); err != nil { identifierRows.Close(); return HumanUser{}, err }
	identifierRows.Close()
	membershipRows, err := queryer.QueryContext(ctx, `SELECT h.membership_id,h.tenant_id,m.state,h.role_ceiling,m.generation,h.lifecycle_suspended,m.created_at,m.updated_at FROM identity_human_user_memberships h JOIN identity_memberships m ON m.id=h.membership_id AND m.principal_id=h.identity_id AND m.tenant_id=h.tenant_id WHERE h.identity_id=? ORDER BY h.tenant_id LIMIT ?`, identityID, humanUserMaximumMemberships+1)
	if err != nil {
		return HumanUser{}, err
	}
	for membershipRows.Next() {
		var membership HumanUserMembership
		var state, ceiling string
		var lifecycleSuspended int
		if err = membershipRows.Scan(&membership.MembershipID, &membership.TenantID, &state, &ceiling, &membership.Generation, &lifecycleSuspended, &membership.CreatedAt, &membership.UpdatedAt); err != nil { membershipRows.Close(); return HumanUser{}, err }
		membership.State = MembershipState(state)
		membership.RoleCeiling = HumanUserRoleCeiling(ceiling)
		membership.LifecycleSuspended = lifecycleSuspended != 0
		value.Memberships = append(value.Memberships, membership)
	}
	if err = membershipRows.Err(); err != nil { membershipRows.Close(); return HumanUser{}, err }
	membershipRows.Close()
	if len(value.Memberships) > humanUserMaximumMemberships {
		return HumanUser{}, ErrQuotaExceeded
	}
	return value, value.Validate()
}

func (s *Store) HumanUser(ctx context.Context, tenantID, identityID ID) (HumanUser, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || !identityID.Valid() {
		return HumanUser{}, ErrInvalid
	}
	return loadHumanUser(ctx, s.db, identityID, tenantID)
}

func (s *Store) PutHumanResourceOwnership(ctx context.Context, value HumanResourceOwnership) error {
	value.ResourceKind = strings.TrimSpace(value.ResourceKind)
	if s == nil || s.db == nil || ctx == nil || !value.IdentityID.Valid() || !value.TenantID.Valid() || !value.ResourceID.Valid() || len(value.ResourceKind) < 1 || len(value.ResourceKind) > 64 || strings.ContainsAny(value.ResourceKind, "\x00\r\n\t ") {
		return ErrInvalid
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO identity_human_resource_ownership(identity_id,tenant_id,resource_kind,resource_id) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM identity_human_users u JOIN identity_human_user_memberships m ON m.identity_id=u.identity_id AND m.tenant_id=? WHERE u.identity_id=? AND u.state IN ('active','suspended')) ON CONFLICT(identity_id,tenant_id,resource_kind,resource_id) DO NOTHING`, value.IdentityID, value.TenantID, value.ResourceKind, value.ResourceID, value.TenantID, value.IdentityID)
	if err != nil { return err }
	if rows, _ := result.RowsAffected(); rows != 1 { var exists uint64; if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_human_users u JOIN identity_human_user_memberships m ON m.identity_id=u.identity_id AND m.tenant_id=? WHERE u.identity_id=? AND u.state IN ('active','suspended')`, value.TenantID, value.IdentityID).Scan(&exists); err != nil { return err }; if exists != 1 { return ErrNotFound } }
	return nil
}

func (s *Store) ReleaseHumanResourceOwnership(ctx context.Context, value HumanResourceOwnership) error {
	if s == nil || s.db == nil || ctx == nil || !value.IdentityID.Valid() || !value.TenantID.Valid() || !value.ResourceID.Valid() || strings.TrimSpace(value.ResourceKind) == "" {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM identity_human_resource_ownership WHERE identity_id=? AND tenant_id=? AND resource_kind=? AND resource_id=?`, value.IdentityID, value.TenantID, value.ResourceKind, value.ResourceID)
	return err
}

func putHumanUserTx(ctx context.Context, tx *sql.Tx, value HumanUser) error {
	if err := value.Validate(); err != nil { return err }
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_human_users(identity_id,primary_tenant_id,display_name,profile_principal_id,state,revision,authz_epoch,created_at,updated_at,suspended_at,deletion_requested_at,retention_deadline,deleted_at,tombstone_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.IdentityID, value.PrimaryTenantID, value.DisplayName, value.ProfilePrincipalID, value.State, value.Revision, value.AuthzEpoch, value.CreatedAt, value.UpdatedAt, value.SuspendedAt, value.DeletionRequestedAt, value.RetentionDeadline, value.DeletedAt, value.TombstoneDigest)
	if err != nil { return err }
	for _, identifier := range value.Identifiers {
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_human_user_identifiers(identity_id,kind,normalized_value,verified_at) VALUES(?,?,?,?)`, value.IdentityID, identifier.Kind, identifier.Value, identifier.VerifiedAt); err != nil { return err }
	}
	for _, membership := range value.Memberships {
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_human_user_memberships(identity_id,membership_id,tenant_id,role_ceiling,lifecycle_suspended,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, value.IdentityID, membership.MembershipID, membership.TenantID, membership.RoleCeiling, boolInt(membership.LifecycleSuspended), membership.CreatedAt, membership.UpdatedAt); err != nil { return err }
	}
	return nil
}

func newHumanUserFromPrincipal(principal Principal, membership Membership, ceiling HumanUserRoleCeiling, now time.Time) HumanUser {
	return HumanUser{
		IdentityID: principal.ID, PrimaryTenantID: membership.TenantID, DisplayName: strings.TrimSpace(principal.DisplayName), ProfilePrincipalID: principal.ID,
		State: HumanUserActive, Revision: 1, AuthzEpoch: principal.AuthzEpoch, CreatedAt: now, UpdatedAt: now,
		Identifiers: []HumanIdentifier{{Kind: HumanIdentifierEmail, Value: normalizeInvitationEmail(principal.Email), VerifiedAt: now}, {Kind: HumanIdentifierUsername, Value: normalizeUsername(principal.Username), VerifiedAt: now}},
		Memberships: []HumanUserMembership{{MembershipID: membership.ID, TenantID: membership.TenantID, State: membership.State, RoleCeiling: ceiling, Generation: membership.Generation, CreatedAt: membership.CreatedAt, UpdatedAt: membership.UpdatedAt}},
	}
}

func humanUserDigest(value HumanUser) string {
	raw, _ := json.Marshal(value)
	return digest(raw)
}

func (s *Service) auditHumanUser(ctx context.Context, actor, tenant ID, action string, before, after *HumanUser, fields []string, outcome string) {
	beforeDigest, afterDigest := "", ""
	if before != nil { beforeDigest = humanUserDigest(*before) }
	if after != nil { afterDigest = humanUserDigest(*after) }
	sorted := append([]string(nil), fields...)
	sort.Strings(sorted)
	s.record(ctx, actor, tenant, action, "human_user", func() ID { if after != nil { return after.IdentityID }; if before != nil { return before.IdentityID }; return "" }(), outcome, strings.Join(sorted, ",")+"\x00"+beforeDigest+"\x00"+afterDigest)
}

func humanUserMembershipForTenant(value HumanUser, tenantID ID) (HumanUserMembership, bool) {
	for _, membership := range value.Memberships {
		if membership.TenantID == tenantID { return membership, true }
	}
	return HumanUserMembership{}, false
}

func humanRoleHasAdministrativePermission(permissions []Permission) bool {
	for _, permission := range permissions {
		switch permission {
		case "*:*", "credential:issue", "identity:manage", "principal:create", "principal:manage", "principal:suspend", "role:bind", "role:manage", "support:grant", "tenant:create":
			return true
		}
	}
	return false
}

func humanCeilingAllowsRole(ceiling HumanUserRoleCeiling, builtin BuiltInRoleKey, permissions []Permission) bool {
	switch ceiling {
	case HumanUserCeilingOwner:
		return true
	case HumanUserCeilingAdministrator:
		return builtin != BuiltInOwner && !containsPermission(permissions, "*:*")
	case HumanUserCeilingMember:
		return builtin != BuiltInOwner && builtin != BuiltInAdministrator && !humanRoleHasAdministrativePermission(permissions)
	default:
		return false
	}
}

func humanCeilingForInvitationRole(ctx context.Context, tx *sql.Tx, role Role) (HumanUserRoleCeiling, error) {
	var builtin string
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(builtin_key,'') FROM identity_role_catalog WHERE role_id=?`, role.ID).Scan(&builtin)
	if errors.Is(err, sql.ErrNoRows) { err = nil }
	if err != nil { return "", err }
	if BuiltInRoleKey(builtin) == BuiltInOwner || containsPermission(role.Permissions, "*:*") { return HumanUserCeilingOwner, nil }
	if BuiltInRoleKey(builtin) == BuiltInAdministrator || humanRoleHasAdministrativePermission(role.Permissions) { return HumanUserCeilingAdministrator, nil }
	return HumanUserCeilingMember, nil
}

func (s *Service) validateHumanCeilingGrant(ctx context.Context, actor ActorContext, tenantID ID, ceiling HumanUserRoleCeiling) error {
	if !validHumanUserRoleCeiling(ceiling) { return ErrInvalid }
	if ceiling == HumanUserCeilingMember { return nil }
	if err := s.ensureBuiltInRoles(ctx, tenantID); err != nil { return err }
	key := BuiltInAdministrator
	if ceiling == HumanUserCeilingOwner { key = BuiltInOwner }
	roleID, err := builtInRoleID(tenantID, key)
	if err != nil { return err }
	role, err := s.store.managedRole(ctx, tenantID, roleID)
	if err != nil { return err }
	_, err = s.roleActorCanGrant(ctx, actor, role.Permissions, role.Selectors, s.clock().UTC(), nil)
	if err != nil { return ErrHumanUserRoleCeiling }
	return nil
}

func (s *Service) CreateHumanUser(ctx context.Context, command CreateHumanUserCommand) (HumanUser, error) {
	if s == nil || s.store == nil || ctx == nil || !command.TenantID.Valid() || !command.IdentityID.Valid() || !validHumanUserRoleCeiling(command.RoleCeiling) || command.Actor.PrincipalID != command.IdentityID || command.Actor.SessionID == "" {
		return HumanUser{}, ErrInvalid
	}
	if err := s.validateActor(ctx, command.Actor, AssurancePassword); err != nil { return HumanUser{}, err }
	if existing, err := s.store.HumanUser(ctx, command.TenantID, command.IdentityID); err == nil {
		membership, visible := humanUserMembershipForTenant(existing, command.TenantID)
		if visible && membership.RoleCeiling == command.RoleCeiling { return existing, nil }
		return HumanUser{}, ErrConflict
	} else if !errors.Is(err, ErrNotFound) { return HumanUser{}, err }
	if err := s.validateHumanCeilingGrant(ctx, command.Actor, command.TenantID, command.RoleCeiling); err != nil { return HumanUser{}, err }
	now := s.clock().UTC()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return HumanUser{}, err }
	defer tx.Rollback()
	if err = validateRoleActorTx(ctx, tx, command.Actor, command.TenantID); err != nil { return HumanUser{}, err }
	principal, err := scanPrincipal(tx.QueryRowContext(ctx, `SELECT id,kind,username,email,display_name,state,locale,theme,authz_epoch,credential_epoch,generation,created_at,updated_at,deleted_at FROM identity_principals WHERE id=?`, command.IdentityID))
	if err != nil { return HumanUser{}, err }
	if principal.Kind != PrincipalHuman || principal.State != PrincipalActive || principal.AuthzEpoch != command.Actor.AuthzEpoch { return HumanUser{}, ErrUnauthenticated }
	var membership Membership
	var membershipState, tenantState string
	err = tx.QueryRowContext(ctx, `SELECT m.id,m.principal_id,m.tenant_id,m.state,m.generation,m.created_at,m.updated_at,t.state FROM identity_memberships m JOIN identity_tenants t ON t.id=m.tenant_id WHERE m.principal_id=? AND m.tenant_id=?`, principal.ID, command.TenantID).Scan(&membership.ID, &membership.PrincipalID, &membership.TenantID, &membershipState, &membership.Generation, &membership.CreatedAt, &membership.UpdatedAt, &tenantState)
	if errors.Is(err, sql.ErrNoRows) { return HumanUser{}, ErrNotFound }
	if err != nil { return HumanUser{}, err }
	membership.State = MembershipState(membershipState)
	if membership.State != MembershipActive || TenantState(tenantState) != TenantActive { return HumanUser{}, ErrSuspended }
	value := newHumanUserFromPrincipal(principal, membership, command.RoleCeiling, now)
	if err = value.Validate(); err != nil { return HumanUser{}, err }
	var duplicate uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_human_user_identifiers WHERE (kind=? AND normalized_value=?) OR (kind=? AND normalized_value=?)`, HumanIdentifierEmail, value.Identifiers[0].Value, HumanIdentifierUsername, value.Identifiers[1].Value).Scan(&duplicate); err != nil { return HumanUser{}, err }
	if duplicate != 0 { return HumanUser{}, ErrConflict }
	if err = putHumanUserTx(ctx, tx, value); err != nil { return HumanUser{}, err }
	if err = tx.Commit(); err != nil { return HumanUser{}, err }
	s.auditHumanUser(ctx, command.Actor.PrincipalID, command.TenantID, "human_user.create", nil, &value, []string{"identity", "verified_identifiers", "display_name", "profile", "membership", "role_ceiling"}, "applied")
	return value, nil
}

func (s *Service) GetHumanUser(ctx context.Context, actor ActorContext, tenantID, identityID ID) (HumanUser, error) {
	if !tenantID.Valid() || !identityID.Valid() { return HumanUser{}, ErrInvalid }
	if _, err := s.AuthorizeActor(ctx, actor, "principal:manage", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssurancePassword); err != nil { return HumanUser{}, err }
	return s.store.HumanUser(ctx, tenantID, identityID)
}

func escapeHumanSearch(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func (s *Service) ListHumanUsers(ctx context.Context, actor ActorContext, tenantID ID, query string, limit int, cursor ID) ([]HumanUser, string, uint64, error) {
	query = strings.ToLower(strings.TrimSpace(query))
	if !tenantID.Valid() || limit < 1 || limit > humanUserMaximumPage || cursor != "" && !cursor.Valid() || len(query) > 128 || strings.ContainsAny(query, "\x00\r\n\t") {
		return nil, "", 0, ErrInvalid
	}
	if _, err := s.AuthorizeActor(ctx, actor, "principal:manage", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssurancePassword); err != nil { return nil, "", 0, err }
	filter, args := "", []any{tenantID}
	if query != "" {
		like := "%" + escapeHumanSearch(query) + "%"
		filter = ` AND (lower(h.display_name) LIKE ? ESCAPE '\' OR lower(h.identity_id) LIKE ? ESCAPE '\' OR EXISTS(SELECT 1 FROM identity_human_user_identifiers i WHERE i.identity_id=h.identity_id AND i.normalized_value LIKE ? ESCAPE '\'))`
		args = append(args, like, like, like)
	}
	var total uint64
	if err := s.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_human_users h JOIN identity_human_user_memberships m ON m.identity_id=h.identity_id WHERE m.tenant_id=?`+filter, args...).Scan(&total); err != nil { return nil, "", 0, err }
	listArgs := append(append([]any(nil), args...), cursor, limit+1)
	rows, err := s.store.db.QueryContext(ctx, `SELECT h.identity_id FROM identity_human_users h JOIN identity_human_user_memberships m ON m.identity_id=h.identity_id WHERE m.tenant_id=?`+filter+` AND h.identity_id>? ORDER BY h.identity_id LIMIT ?`, listArgs...)
	if err != nil { return nil, "", 0, err }
	defer rows.Close()
	identities := make([]ID, 0, limit+1)
	for rows.Next() { var id ID; if err = rows.Scan(&id); err != nil { return nil, "", 0, err }; identities = append(identities, id) }
	if err = rows.Err(); err != nil { return nil, "", 0, err }
	next := ""
	if len(identities) > limit { next = identities[limit-1].String(); identities = identities[:limit] }
	values := make([]HumanUser, 0, len(identities))
	for _, identityID := range identities { value, loadErr := loadHumanUser(ctx, s.store.db, identityID, tenantID); if loadErr != nil { return nil, "", 0, loadErr }; values = append(values, value) }
	return values, next, total, nil
}

func humanRoleDefinitionTx(ctx context.Context, tx *sql.Tx, roleID ID) (BuiltInRoleKey, []Permission, error) {
	var builtin string
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(c.builtin_key,''),r.permissions_json FROM identity_roles r LEFT JOIN identity_role_catalog c ON c.role_id=r.id WHERE r.id=?`, roleID).Scan(&builtin, &raw)
	if errors.Is(err, sql.ErrNoRows) { return "", nil, ErrNotFound }
	if err != nil { return "", nil, err }
	var permissions []Permission
	if err = json.Unmarshal(raw, &permissions); err != nil { return "", nil, ErrConflict }
	return BuiltInRoleKey(builtin), permissions, nil
}

func revokeHumanBindingsAboveCeilingTx(ctx context.Context, tx *sql.Tx, actorID, identityID, tenantID ID, ceiling *HumanUserRoleCeiling, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT b.role_id FROM identity_role_bindings b JOIN identity_roles r ON r.id=b.role_id WHERE b.subject_id=? AND r.tenant_id=? AND (b.tenant_id=? OR b.scope_kind='installation') LIMIT 257`, identityID, tenantID, tenantID)
	if err != nil { return err }
	roleIDs := make([]ID, 0, 8)
	for rows.Next() { var roleID ID; if err = rows.Scan(&roleID); err != nil { rows.Close(); return err }; roleIDs = append(roleIDs, roleID) }
	if err = rows.Err(); err != nil { rows.Close(); return err }
	rows.Close()
	if len(roleIDs) > 256 { return ErrQuotaExceeded }
	for _, roleID := range roleIDs {
		revoke := ceiling == nil
		if !revoke {
			builtin, permissions, loadErr := humanRoleDefinitionTx(ctx, tx, roleID)
			if loadErr != nil { return loadErr }
			revoke = !humanCeilingAllowsRole(*ceiling, builtin, permissions)
		}
		if !revoke { continue }
		logicalRows, loadErr := tx.QueryContext(ctx, `SELECT DISTINCT e.logical_binding_id FROM identity_managed_role_binding_edges e JOIN identity_role_bindings b ON b.id=e.edge_id WHERE b.subject_id=? AND b.role_id=? LIMIT 257`, identityID, roleID)
		if loadErr != nil { return loadErr }
		logicalIDs := make([]ID, 0, 4)
		for logicalRows.Next() { var id ID; if loadErr = logicalRows.Scan(&id); loadErr != nil { logicalRows.Close(); return loadErr }; logicalIDs = append(logicalIDs, id) }
		if loadErr = logicalRows.Err(); loadErr != nil { logicalRows.Close(); return loadErr }
		logicalRows.Close()
		if len(logicalIDs) > 256 { return ErrQuotaExceeded }
		for _, logicalID := range logicalIDs {
			if _, err = tx.ExecContext(ctx, `UPDATE identity_managed_role_bindings SET revision=revision+1,revoked_at=?,revoked_by_id=? WHERE id=? AND revoked_at IS NULL`, now, actorID, logicalID); err != nil { return err }
			if _, err = tx.ExecContext(ctx, `DELETE FROM identity_role_bindings WHERE id IN (SELECT edge_id FROM identity_managed_role_binding_edges WHERE logical_binding_id=?)`, logicalID); err != nil { return err }
			if _, err = tx.ExecContext(ctx, `DELETE FROM identity_managed_role_binding_edges WHERE logical_binding_id=?`, logicalID); err != nil { return err }
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM identity_role_bindings WHERE subject_id=? AND role_id=?`, identityID, roleID); err != nil { return err }
	}
	return nil
}

func humanLastOwnerTenantsTx(ctx context.Context, tx *sql.Tx, identityID ID, tenantIDs []ID, now time.Time) ([]ID, error) {
	blocked := make([]ID, 0, len(tenantIDs))
	seenTenants := map[ID]struct{}{}
	for _, tenantID := range tenantIDs {
		if _, seen := seenTenants[tenantID]; seen { continue }
		seenTenants[tenantID] = struct{}{}
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT b.subject_id,b.scope_kind,b.tenant_id,b.expires_at,r.permissions_json,COALESCE(c.builtin_key,''),COALESCE(e.logical_binding_id,''),mb.effective_at,mb.expires_at,mb.revoked_at FROM identity_role_bindings b JOIN identity_roles r ON r.id=b.role_id LEFT JOIN identity_role_catalog c ON c.role_id=r.id JOIN identity_principals p ON p.id=b.subject_id JOIN identity_memberships m ON m.principal_id=p.id AND m.tenant_id=? LEFT JOIN identity_human_users u ON u.identity_id=p.id LEFT JOIN identity_managed_role_binding_edges e ON e.edge_id=b.id LEFT JOIN identity_managed_role_bindings mb ON mb.id=e.logical_binding_id WHERE r.tenant_id=? AND p.kind='human' AND p.state='active' AND m.state='active' AND (u.identity_id IS NULL OR u.state='active') LIMIT 1001`, tenantID, tenantID)
		if err != nil { return nil, err }
		targetOwner, otherOwner := false, false
		rowCount := 0
		for rows.Next() {
			rowCount++
			if rowCount > 1000 { rows.Close(); return nil, ErrQuotaExceeded }
			var subject, bindingTenant, logical ID
			var scopeKind, builtin string
			var raw []byte
			var edgeExpiry, effective, managedExpiry, revoked sql.NullTime
			if err = rows.Scan(&subject, &scopeKind, &bindingTenant, &edgeExpiry, &raw, &builtin, &logical, &effective, &managedExpiry, &revoked); err != nil { rows.Close(); return nil, err }
			if ScopeKind(scopeKind) != ScopeInstallation && (ScopeKind(scopeKind) != ScopeTenant || bindingTenant != tenantID) || edgeExpiry.Valid && !now.Before(edgeExpiry.Time) { continue }
			var permissions []Permission
			if json.Unmarshal(raw, &permissions) != nil { rows.Close(); return nil, ErrConflict }
			if BuiltInRoleKey(builtin) != BuiltInOwner && !containsPermission(permissions, "*:*") { continue }
			if logical != "" {
				if !effective.Valid { rows.Close(); return nil, ErrConflict }
				if now.Before(effective.Time) || managedExpiry.Valid && !now.Before(managedExpiry.Time) || revoked.Valid { continue }
			}
			if subject == identityID { targetOwner = true } else { otherOwner = true }
		}
		if err = rows.Err(); err != nil { rows.Close(); return nil, err }
		rows.Close()
		if targetOwner && !otherOwner { blocked = append(blocked, tenantID) }
	}
	sort.Slice(blocked, func(i, j int) bool { return blocked[i] < blocked[j] })
	return blocked, nil
}

func updateHumanUserMembership(value *HumanUser, tenantID ID, update func(*HumanUserMembership)) {
	for index := range value.Memberships {
		if value.Memberships[index].TenantID == tenantID { update(&value.Memberships[index]); return }
	}
}

func (s *Service) UpdateHumanUser(ctx context.Context, command UpdateHumanUserCommand) (HumanUser, error) {
	if !command.TenantID.Valid() || !command.IdentityID.Valid() || command.ExpectedRevision == 0 || len(command.FieldMask) < 1 || len(command.FieldMask) > 2 {
		return HumanUser{}, ErrInvalid
	}
	seen, displayChanged, ceilingChanged := map[HumanUserField]struct{}{}, false, false
	for _, field := range command.FieldMask {
		if _, duplicate := seen[field]; duplicate { return HumanUser{}, ErrInvalid }
		seen[field] = struct{}{}
		switch field { case HumanUserFieldDisplayName: displayChanged = true; case HumanUserFieldRoleCeiling: ceilingChanged = true; default: return HumanUser{}, ErrInvalid }
	}
	if displayChanged { command.DisplayName = strings.TrimSpace(command.DisplayName); if command.DisplayName == "" || len(command.DisplayName) > 128 || strings.ContainsAny(command.DisplayName, "\x00\r\n\t") { return HumanUser{}, ErrInvalid } } else if command.DisplayName != "" { return HumanUser{}, ErrInvalid }
	if ceilingChanged { if !validHumanUserRoleCeiling(command.RoleCeiling) { return HumanUser{}, ErrInvalid } } else if command.RoleCeiling != "" { return HumanUser{}, ErrInvalid }
	if _, err := s.AuthorizeActor(ctx, command.Actor, "principal:manage", Scope{Kind: ScopeTenant, TenantID: command.TenantID}, AssuranceMFA); err != nil { return HumanUser{}, err }
	current, err := s.store.HumanUser(ctx, command.TenantID, command.IdentityID)
	if err != nil { return HumanUser{}, err }
	if current.Revision != command.ExpectedRevision { return HumanUser{}, ErrStaleGeneration }
	if current.State != HumanUserActive { return HumanUser{}, ErrHumanUserQuarantined }
	if displayChanged && current.PrimaryTenantID != command.TenantID { return HumanUser{}, ErrForbidden }
	membership, exists := humanUserMembershipForTenant(current, command.TenantID)
	if !exists || membership.State != MembershipActive { return HumanUser{}, ErrNotFound }
	ceilingValueChanged := ceilingChanged && membership.RoleCeiling != command.RoleCeiling
	if ceilingValueChanged {
		if err = s.validateRecentRoleStepUp(ctx, command.Actor); err != nil { return HumanUser{}, err }
		if humanUserCeilingRank(command.RoleCeiling) > humanUserCeilingRank(membership.RoleCeiling) {
			if err = s.validateHumanCeilingGrant(ctx, command.Actor, command.TenantID, command.RoleCeiling); err != nil { return HumanUser{}, err }
		}
	}
	next := current
	if displayChanged { next.DisplayName = command.DisplayName }
	if ceilingChanged { updateHumanUserMembership(&next, command.TenantID, func(value *HumanUserMembership) { value.RoleCeiling = command.RoleCeiling }) }
	if humanUserDigest(current) == humanUserDigest(next) { return current, nil }
	now := s.clock().UTC()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return HumanUser{}, err }
	defer tx.Rollback()
	stored, err := loadHumanUser(ctx, tx, command.IdentityID, command.TenantID)
	if err != nil { return HumanUser{}, err }
	if stored.Revision != command.ExpectedRevision || stored.State != HumanUserActive { return HumanUser{}, ErrStaleGeneration }
	if err = validateRoleActorTx(ctx, tx, command.Actor, command.TenantID); err != nil { return HumanUser{}, err }
	if ceilingValueChanged && humanUserCeilingRank(command.RoleCeiling) < humanUserCeilingRank(membership.RoleCeiling) {
		blocked, blockErr := humanLastOwnerTenantsTx(ctx, tx, command.IdentityID, []ID{command.TenantID}, now)
		if blockErr != nil { return HumanUser{}, blockErr }
		if len(blocked) != 0 { return HumanUser{}, ErrLastLocalOwner }
		if err = revokeHumanBindingsAboveCeilingTx(ctx, tx, command.Actor.PrincipalID, command.IdentityID, command.TenantID, &command.RoleCeiling, now); err != nil { return HumanUser{}, err }
	}
	next.Revision = stored.Revision + 1
	next.UpdatedAt = now
	if ceilingValueChanged {
		next.AuthzEpoch = stored.AuthzEpoch + 1
		if _, err = tx.ExecContext(ctx, `UPDATE identity_human_user_memberships SET role_ceiling=?,updated_at=? WHERE identity_id=? AND tenant_id=?`, command.RoleCeiling, now, command.IdentityID, command.TenantID); err != nil { return HumanUser{}, err }
		updateHumanUserMembership(&next, command.TenantID, func(value *HumanUserMembership) { value.RoleCeiling = command.RoleCeiling; value.UpdatedAt = now })
	}
	result, err := tx.ExecContext(ctx, `UPDATE identity_human_users SET display_name=?,revision=?,authz_epoch=?,updated_at=? WHERE identity_id=? AND revision=?`, next.DisplayName, next.Revision, next.AuthzEpoch, now, next.IdentityID, stored.Revision)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	principalEpoch := stored.AuthzEpoch
	if ceilingValueChanged { principalEpoch++ }
	result, err = tx.ExecContext(ctx, `UPDATE identity_principals SET display_name=?,authz_epoch=?,generation=generation+1,updated_at=? WHERE id=? AND kind='human' AND state='active' AND authz_epoch=?`, next.DisplayName, principalEpoch, now, next.IdentityID, stored.AuthzEpoch)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	if err = tx.Commit(); err != nil { return HumanUser{}, err }
	fields := make([]string, len(command.FieldMask)); for index, field := range command.FieldMask { fields[index] = string(field) }
	s.auditHumanUser(ctx, command.Actor.PrincipalID, command.TenantID, "human_user.update", &current, &next, fields, "applied")
	return next, nil
}

func (s *Service) TransferHumanUser(ctx context.Context, command TransferHumanUserCommand) (HumanUser, error) {
	if !command.TenantID.Valid() || !command.IdentityID.Valid() || !command.NewPrimaryTenantID.Valid() || command.ExpectedRevision == 0 || len(command.Steps) > 32 {
		return HumanUser{}, ErrInvalid
	}
	if _, err := s.AuthorizeActor(ctx, command.Actor, "principal:manage", Scope{Kind: ScopeTenant, TenantID: command.TenantID}, AssuranceMFA); err != nil { return HumanUser{}, err }
	current, err := s.store.HumanUser(ctx, command.TenantID, command.IdentityID)
	if err != nil { return HumanUser{}, err }
	if current.PrimaryTenantID != command.TenantID { return HumanUser{}, ErrForbidden }
	if current.Revision != command.ExpectedRevision { return HumanUser{}, ErrStaleGeneration }
	if current.State != HumanUserActive { return HumanUser{}, ErrHumanUserQuarantined }
	if command.NewPrimaryTenantID == current.PrimaryTenantID && len(command.Steps) == 0 { return current, nil }
	if err = s.validateRecentRoleStepUp(ctx, command.Actor); err != nil { return HumanUser{}, err }
	currentMemberships := make(map[ID]HumanUserMembership, len(current.Memberships))
	for _, membership := range current.Memberships { currentMemberships[membership.TenantID] = membership }
	seenTenants := map[ID]struct{}{}
	for _, step := range command.Steps {
		if !step.TenantID.Valid() { return HumanUser{}, ErrInvalid }
		if _, duplicate := seenTenants[step.TenantID]; duplicate { return HumanUser{}, ErrInvalid }
		seenTenants[step.TenantID] = struct{}{}
		switch step.Action {
		case HumanMembershipAdd:
			if !step.MembershipID.Valid() || step.ExpectedGeneration != 0 || !validHumanUserRoleCeiling(step.RoleCeiling) { return HumanUser{}, ErrInvalid }
			if _, exists := currentMemberships[step.TenantID]; exists { return HumanUser{}, ErrConflict }
		case HumanMembershipUpdate:
			membership, exists := currentMemberships[step.TenantID]
			if !exists || step.MembershipID != membership.MembershipID || step.ExpectedGeneration == 0 || !validHumanUserRoleCeiling(step.RoleCeiling) { return HumanUser{}, ErrInvalid }
		case HumanMembershipRemove:
			membership, exists := currentMemberships[step.TenantID]
			if !exists || step.MembershipID != membership.MembershipID || step.ExpectedGeneration == 0 || step.RoleCeiling != "" { return HumanUser{}, ErrInvalid }
		default:
			return HumanUser{}, ErrInvalid
		}
		if _, authErr := s.AuthorizeActor(ctx, command.Actor, "principal:manage", Scope{Kind: ScopeTenant, TenantID: step.TenantID}, AssuranceMFA); authErr != nil { return HumanUser{}, authErr }
		if step.Action != HumanMembershipRemove {
			previousRank := 0
			if membership, exists := currentMemberships[step.TenantID]; exists { previousRank = humanUserCeilingRank(membership.RoleCeiling) }
			if humanUserCeilingRank(step.RoleCeiling) > previousRank {
				if grantErr := s.validateHumanCeilingGrant(ctx, command.Actor, step.TenantID, step.RoleCeiling); grantErr != nil { return HumanUser{}, grantErr }
			}
		}
	}
	if _, authErr := s.AuthorizeActor(ctx, command.Actor, "principal:manage", Scope{Kind: ScopeTenant, TenantID: command.NewPrimaryTenantID}, AssuranceMFA); authErr != nil { return HumanUser{}, authErr }
	now := s.clock().UTC()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return HumanUser{}, err }
	defer tx.Rollback()
	stored, err := loadHumanUser(ctx, tx, command.IdentityID, command.TenantID)
	if err != nil { return HumanUser{}, err }
	if stored.Revision != command.ExpectedRevision || stored.State != HumanUserActive || stored.PrimaryTenantID != command.TenantID { return HumanUser{}, ErrStaleGeneration }
	for tenantID := range seenTenants { if err = validateRoleActorTx(ctx, tx, command.Actor, tenantID); err != nil { return HumanUser{}, err } }
	if err = validateRoleActorTx(ctx, tx, command.Actor, command.NewPrimaryTenantID); err != nil { return HumanUser{}, err }
	storedMemberships := make(map[ID]HumanUserMembership, len(stored.Memberships))
	for _, membership := range stored.Memberships { storedMemberships[membership.TenantID] = membership }
	lastOwnerCandidates := make([]ID, 0, len(command.Steps))
	for _, step := range command.Steps {
		membership, exists := storedMemberships[step.TenantID]
		switch step.Action {
		case HumanMembershipAdd:
			if exists { return HumanUser{}, ErrConflict }
		case HumanMembershipUpdate:
			if !exists || membership.MembershipID != step.MembershipID || membership.Generation != step.ExpectedGeneration { return HumanUser{}, ErrStaleGeneration }
			if humanUserCeilingRank(step.RoleCeiling) < humanUserCeilingRank(membership.RoleCeiling) { lastOwnerCandidates = append(lastOwnerCandidates, step.TenantID) }
		case HumanMembershipRemove:
			if !exists || membership.MembershipID != step.MembershipID || membership.Generation != step.ExpectedGeneration { return HumanUser{}, ErrStaleGeneration }
			lastOwnerCandidates = append(lastOwnerCandidates, step.TenantID)
		}
	}
	blocked, err := humanLastOwnerTenantsTx(ctx, tx, command.IdentityID, lastOwnerCandidates, now)
	if err != nil { return HumanUser{}, err }
	if len(blocked) != 0 { return HumanUser{}, ErrLastLocalOwner }
	activeAfter := make(map[ID]bool, len(storedMemberships)+len(command.Steps))
	for tenantID, membership := range storedMemberships { activeAfter[tenantID] = membership.State == MembershipActive }
	for _, step := range command.Steps {
		switch step.Action { case HumanMembershipAdd: activeAfter[step.TenantID] = true; case HumanMembershipRemove: activeAfter[step.TenantID] = false }
	}
	if !activeAfter[command.NewPrimaryTenantID] { return HumanUser{}, ErrInvalid }
	for _, step := range command.Steps {
		switch step.Action {
		case HumanMembershipAdd:
			var core Membership
			var state string
			loadErr := tx.QueryRowContext(ctx, `SELECT id,principal_id,tenant_id,state,generation,created_at,updated_at FROM identity_memberships WHERE principal_id=? AND tenant_id=?`, command.IdentityID, step.TenantID).Scan(&core.ID, &core.PrincipalID, &core.TenantID, &state, &core.Generation, &core.CreatedAt, &core.UpdatedAt)
			if errors.Is(loadErr, sql.ErrNoRows) {
				var occupied uint64
				if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_memberships WHERE id=?`, step.MembershipID).Scan(&occupied); err != nil { return HumanUser{}, err }
				if occupied != 0 { return HumanUser{}, ErrConflict }
				core = Membership{ID: step.MembershipID, PrincipalID: command.IdentityID, TenantID: step.TenantID, State: MembershipActive, Generation: 1, CreatedAt: now, UpdatedAt: now}
				if err = putMembership(ctx, tx, core); err != nil { return HumanUser{}, err }
			} else if loadErr != nil { return HumanUser{}, loadErr
			} else {
				core.State = MembershipState(state)
				if core.ID != step.MembershipID || core.State != MembershipActive { return HumanUser{}, ErrConflict }
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO identity_human_user_memberships(identity_id,membership_id,tenant_id,role_ceiling,lifecycle_suspended,created_at,updated_at) VALUES(?,?,?,?,0,?,?)`, command.IdentityID, core.ID, step.TenantID, step.RoleCeiling, now, now); err != nil { return HumanUser{}, err }
		case HumanMembershipUpdate:
			membership := storedMemberships[step.TenantID]
			if humanUserCeilingRank(step.RoleCeiling) < humanUserCeilingRank(membership.RoleCeiling) {
				if err = revokeHumanBindingsAboveCeilingTx(ctx, tx, command.Actor.PrincipalID, command.IdentityID, step.TenantID, &step.RoleCeiling, now); err != nil { return HumanUser{}, err }
			}
			result, updateErr := tx.ExecContext(ctx, `UPDATE identity_memberships SET generation=generation+1,updated_at=? WHERE id=? AND principal_id=? AND tenant_id=? AND generation=? AND state='active'`, now, step.MembershipID, command.IdentityID, step.TenantID, step.ExpectedGeneration)
			if updateErr != nil { return HumanUser{}, updateErr }
			if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
			if _, err = tx.ExecContext(ctx, `UPDATE identity_human_user_memberships SET role_ceiling=?,updated_at=? WHERE identity_id=? AND tenant_id=?`, step.RoleCeiling, now, command.IdentityID, step.TenantID); err != nil { return HumanUser{}, err }
		case HumanMembershipRemove:
			if err = revokeHumanBindingsAboveCeilingTx(ctx, tx, command.Actor.PrincipalID, command.IdentityID, step.TenantID, nil, now); err != nil { return HumanUser{}, err }
			result, updateErr := tx.ExecContext(ctx, `UPDATE identity_memberships SET state='revoked',generation=generation+1,updated_at=? WHERE id=? AND principal_id=? AND tenant_id=? AND generation=? AND state<>'revoked'`, now, step.MembershipID, command.IdentityID, step.TenantID, step.ExpectedGeneration)
			if updateErr != nil { return HumanUser{}, updateErr }
			if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
			if _, err = tx.ExecContext(ctx, `UPDATE identity_human_user_memberships SET lifecycle_suspended=0,updated_at=? WHERE identity_id=? AND tenant_id=?`, now, command.IdentityID, step.TenantID); err != nil { return HumanUser{}, err }
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE identity_human_users SET primary_tenant_id=?,revision=revision+1,authz_epoch=?,updated_at=? WHERE identity_id=? AND revision=? AND state='active'`, command.NewPrimaryTenantID, stored.AuthzEpoch+1, now, command.IdentityID, command.ExpectedRevision)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	result, err = tx.ExecContext(ctx, `UPDATE identity_principals SET authz_epoch=authz_epoch+1,generation=generation+1,updated_at=? WHERE id=? AND kind='human' AND state='active' AND authz_epoch=?`, now, command.IdentityID, stored.AuthzEpoch)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	next, err := loadHumanUser(ctx, tx, command.IdentityID, command.NewPrimaryTenantID)
	if err != nil { return HumanUser{}, err }
	if err = tx.Commit(); err != nil { return HumanUser{}, err }
	s.auditHumanUser(ctx, command.Actor.PrincipalID, command.TenantID, "human_user.transfer", &current, &next, []string{"primary_tenant", "memberships", "role_ceiling", "authz_epoch"}, "applied")
	return next, nil
}

func activeHumanMembershipTenants(value HumanUser) []ID {
	values := make([]ID, 0, len(value.Memberships))
	for _, membership := range value.Memberships {
		if membership.State == MembershipActive { values = append(values, membership.TenantID) }
	}
	return values
}

func (s *Service) authorizeHumanUserTenants(ctx context.Context, actor ActorContext, value HumanUser, permission Permission, minimum AssuranceLevel) error {
	for _, membership := range value.Memberships {
		if membership.State == MembershipRevoked { continue }
		if _, err := s.AuthorizeActor(ctx, actor, permission, Scope{Kind: ScopeTenant, TenantID: membership.TenantID}, minimum); err != nil { return err }
	}
	return nil
}

func collectHumanVerifierRefsTx(ctx context.Context, tx *sql.Tx, identityID ID, all bool) ([]ID, error) {
	query := `SELECT verifier_ref FROM identity_credentials WHERE principal_id=? AND state<>'revoked' AND verifier_ref<>''`
	if !all { query += ` AND kind='api_key'` }
	query += ` ORDER BY id LIMIT 257`
	rows, err := tx.QueryContext(ctx, query, identityID)
	if err != nil { return nil, err }
	defer rows.Close()
	values := make([]ID, 0, 8)
	for rows.Next() { var ref ID; if err = rows.Scan(&ref); err != nil { return nil, err }; if !ref.Valid() { return nil, ErrConflict }; values = append(values, ref) }
	if err = rows.Err(); err != nil { return nil, err }
	if len(values) > 256 { return nil, ErrQuotaExceeded }
	return values, nil
}

func collectEveryHumanVerifierRefTx(ctx context.Context, tx *sql.Tx, identityID ID) ([]ID, error) {
	rows, err := tx.QueryContext(ctx, `SELECT verifier_ref FROM identity_credentials WHERE principal_id=? AND verifier_ref<>'' ORDER BY id LIMIT 257`, identityID)
	if err != nil { return nil, err }
	defer rows.Close()
	values := make([]ID, 0, 8)
	for rows.Next() { var ref ID; if err = rows.Scan(&ref); err != nil { return nil, err }; if !ref.Valid() { return nil, ErrConflict }; values = append(values, ref) }
	if err = rows.Err(); err != nil { return nil, err }
	if len(values) > 256 { return nil, ErrQuotaExceeded }
	return values, nil
}

func (s *Service) revokeHumanVerifierRefs(ctx context.Context, actor, tenant, identityID ID, refs []ID) {
	for _, ref := range refs {
		if err := s.verifier.Revoke(ctx, ref); err != nil {
			s.record(ctx, actor, tenant, "human_user.verifier_revoke", "human_user", identityID, "failed", identityID.String()+"\x00"+ref.String())
		}
	}
}

func applyHumanAccessQuarantineTx(ctx context.Context, tx *sql.Tx, actorID, identityID ID, now time.Time, allCredentials bool) ([]ID, error) {
	refs, err := collectHumanVerifierRefsTx(ctx, tx, identityID, allCredentials)
	if err != nil { return nil, err }
	if _, err = tx.ExecContext(ctx, `UPDATE identity_sessions SET revoked_at=? WHERE principal_id=? AND revoked_at IS NULL`, now, identityID); err != nil { return nil, err }
	credentialFilter := `kind='api_key'`
	if allCredentials { credentialFilter = `1=1` }
	if _, err = tx.ExecContext(ctx, `UPDATE identity_credentials SET state='revoked',revoked_at=? WHERE principal_id=? AND state<>'revoked' AND `+credentialFilter, now, identityID); err != nil { return nil, err }
	if allCredentials {
		if _, err = tx.ExecContext(ctx, `UPDATE identity_managed_role_bindings SET revision=revision+1,revoked_at=?,revoked_by_id=? WHERE subject_id=? AND revoked_at IS NULL`, now, actorID, identityID); err != nil { return nil, err }
		if _, err = tx.ExecContext(ctx, `DELETE FROM identity_managed_role_binding_edges WHERE edge_id IN (SELECT id FROM identity_role_bindings WHERE subject_id=?)`, identityID); err != nil { return nil, err }
		if _, err = tx.ExecContext(ctx, `DELETE FROM identity_role_bindings WHERE subject_id=?`, identityID); err != nil { return nil, err }
	}
	return refs, nil
}

func (s *Service) transitionHumanUser(ctx context.Context, actor ActorContext, tenantID, identityID ID, expected uint64, target HumanUserState) (HumanUser, error) {
	if !tenantID.Valid() || !identityID.Valid() || expected == 0 || target != HumanUserSuspended && target != HumanUserActive { return HumanUser{}, ErrInvalid }
	if _, err := s.AuthorizeActor(ctx, actor, "principal:suspend", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssuranceMFA); err != nil { return HumanUser{}, err }
	current, err := s.store.HumanUser(ctx, tenantID, identityID)
	if err != nil { return HumanUser{}, err }
	if current.PrimaryTenantID != tenantID { return HumanUser{}, ErrForbidden }
	if target == current.State { return current, nil }
	if current.Revision != expected { return HumanUser{}, ErrStaleGeneration }
	if target == HumanUserSuspended && current.State != HumanUserActive || target == HumanUserActive && current.State != HumanUserSuspended { return HumanUser{}, ErrConflict }
	if err = s.authorizeHumanUserTenants(ctx, actor, current, "principal:suspend", AssuranceMFA); err != nil { return HumanUser{}, err }
	now := s.clock().UTC()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return HumanUser{}, err }
	defer tx.Rollback()
	stored, err := loadHumanUser(ctx, tx, identityID, tenantID)
	if err != nil { return HumanUser{}, err }
	if stored.Revision != expected || stored.State != current.State { return HumanUser{}, ErrStaleGeneration }
	if err = validateRoleActorTx(ctx, tx, actor, tenantID); err != nil { return HumanUser{}, err }
	var refs []ID
	if target == HumanUserSuspended {
		blocked, blockErr := humanLastOwnerTenantsTx(ctx, tx, identityID, activeHumanMembershipTenants(stored), now)
		if blockErr != nil { return HumanUser{}, blockErr }
		if len(blocked) != 0 { return HumanUser{}, ErrLastLocalOwner }
		refs, err = applyHumanAccessQuarantineTx(ctx, tx, actor.PrincipalID, identityID, now, false)
		if err != nil { return HumanUser{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE identity_human_user_memberships SET lifecycle_suspended=1,updated_at=? WHERE identity_id=? AND lifecycle_suspended=0 AND membership_id IN (SELECT id FROM identity_memberships WHERE principal_id=? AND state='active')`, now, identityID, identityID); err != nil { return HumanUser{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE identity_memberships SET state='suspended',generation=generation+1,updated_at=? WHERE principal_id=? AND state='active'`, now, identityID); err != nil { return HumanUser{}, err }
	} else {
		if _, err = tx.ExecContext(ctx, `UPDATE identity_memberships SET state='active',generation=generation+1,updated_at=? WHERE principal_id=? AND id IN (SELECT membership_id FROM identity_human_user_memberships WHERE identity_id=? AND lifecycle_suspended=1) AND state='suspended'`, now, identityID, identityID); err != nil { return HumanUser{}, err }
		if _, err = tx.ExecContext(ctx, `UPDATE identity_human_user_memberships SET lifecycle_suspended=0,updated_at=? WHERE identity_id=? AND lifecycle_suspended=1`, now, identityID); err != nil { return HumanUser{}, err }
	}
	principalState := PrincipalSuspended
	principalExpected := PrincipalActive
	if target == HumanUserActive { principalState = PrincipalActive; principalExpected = PrincipalSuspended }
	result, err := tx.ExecContext(ctx, `UPDATE identity_principals SET state=?,authz_epoch=authz_epoch+1,credential_epoch=credential_epoch+1,generation=generation+1,updated_at=? WHERE id=? AND kind='human' AND state=? AND authz_epoch=?`, principalState, now, identityID, principalExpected, stored.AuthzEpoch)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	suspendedAt := any(nil)
	if target == HumanUserSuspended { suspendedAt = now }
	result, err = tx.ExecContext(ctx, `UPDATE identity_human_users SET state=?,revision=revision+1,authz_epoch=?,updated_at=?,suspended_at=? WHERE identity_id=? AND revision=? AND state=?`, target, stored.AuthzEpoch+1, now, suspendedAt, identityID, expected, current.State)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	next, err := loadHumanUser(ctx, tx, identityID, tenantID)
	if err != nil { return HumanUser{}, err }
	if err = tx.Commit(); err != nil { return HumanUser{}, err }
	s.revokeHumanVerifierRefs(ctx, actor.PrincipalID, tenantID, identityID, refs)
	action := "human_user.suspend"
	if target == HumanUserActive { action = "human_user.reactivate" }
	s.auditHumanUser(ctx, actor.PrincipalID, tenantID, action, &current, &next, []string{"state", "authz_epoch", "memberships", "sessions", "api_credentials"}, "applied")
	return next, nil
}

func (s *Service) SuspendHumanUser(ctx context.Context, actor ActorContext, tenantID, identityID ID, expected uint64) (HumanUser, error) {
	return s.transitionHumanUser(ctx, actor, tenantID, identityID, expected, HumanUserSuspended)
}

func (s *Service) ReactivateHumanUser(ctx context.Context, actor ActorContext, tenantID, identityID ID, expected uint64) (HumanUser, error) {
	return s.transitionHumanUser(ctx, actor, tenantID, identityID, expected, HumanUserActive)
}

func humanOwnershipBlockersTx(ctx context.Context, tx *sql.Tx, identityID ID) ([]HumanResourceOwnership, uint64, error) {
	var total uint64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_human_resource_ownership WHERE identity_id=?`, identityID).Scan(&total); err != nil { return nil, 0, err }
	rows, err := tx.QueryContext(ctx, `SELECT identity_id,tenant_id,resource_kind,resource_id FROM identity_human_resource_ownership WHERE identity_id=? ORDER BY tenant_id,resource_kind,resource_id LIMIT ?`, identityID, humanUserMaximumPage)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	values := make([]HumanResourceOwnership, 0, min(int(total), humanUserMaximumPage))
	for rows.Next() { var value HumanResourceOwnership; if err = rows.Scan(&value.IdentityID, &value.TenantID, &value.ResourceKind, &value.ResourceID); err != nil { return nil, 0, err }; values = append(values, value) }
	return values, total, rows.Err()
}

func humanDeletionImpactTx(ctx context.Context, tx *sql.Tx, value HumanUser, now time.Time) (HumanUserDeletionImpact, error) {
	impact := HumanUserDeletionImpact{IdentityID: value.IdentityID, MembershipCount: uint64(len(value.Memberships)), RetentionDeadline: now.Add(humanUserRetention)}
	if value.RetentionDeadline != nil { impact.RetentionDeadline = *value.RetentionDeadline }
	queries := []struct{ query string; destination *uint64 }{
		{`SELECT COUNT(*) FROM identity_sessions WHERE principal_id=? AND revoked_at IS NULL`, &impact.ActiveSessionCount},
		{`SELECT COUNT(*) FROM identity_credentials WHERE principal_id=? AND state<>'revoked'`, &impact.ActiveCredentialCount},
		{`SELECT COUNT(*) FROM identity_credentials WHERE principal_id=? AND kind='api_key' AND state<>'revoked'`, &impact.ActiveAPICredentialCount},
		{`SELECT COUNT(*) FROM identity_role_bindings WHERE subject_id=?`, &impact.ActiveRoleBindingCount},
	}
	for _, query := range queries { if err := tx.QueryRowContext(ctx, query.query, value.IdentityID).Scan(query.destination); err != nil { return HumanUserDeletionImpact{}, err } }
	var err error
	impact.OwnershipBlockers, impact.OwnershipBlockerCount, err = humanOwnershipBlockersTx(ctx, tx, value.IdentityID)
	if err != nil { return HumanUserDeletionImpact{}, err }
	impact.LastOwnerTenants, err = humanLastOwnerTenantsTx(ctx, tx, value.IdentityID, activeHumanMembershipTenants(value), now)
	return impact, err
}

func (s *Service) PreviewHumanUserDeletion(ctx context.Context, actor ActorContext, tenantID, identityID ID) (HumanUserDeletionImpact, error) {
	if !tenantID.Valid() || !identityID.Valid() { return HumanUserDeletionImpact{}, ErrInvalid }
	if _, err := s.AuthorizeActor(ctx, actor, "principal:manage", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssurancePassword); err != nil { return HumanUserDeletionImpact{}, err }
	value, err := s.store.HumanUser(ctx, tenantID, identityID)
	if err != nil { return HumanUserDeletionImpact{}, err }
	if value.PrimaryTenantID != tenantID { return HumanUserDeletionImpact{}, ErrForbidden }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil { return HumanUserDeletionImpact{}, err }
	defer tx.Rollback()
	impact, err := humanDeletionImpactTx(ctx, tx, value, s.clock().UTC())
	if err != nil { return HumanUserDeletionImpact{}, err }
	if err = tx.Commit(); err != nil { return HumanUserDeletionImpact{}, err }
	return impact, nil
}

func (s *Service) BeginHumanUserDeletion(ctx context.Context, actor ActorContext, tenantID, identityID ID, expected uint64) (HumanUser, error) {
	if !tenantID.Valid() || !identityID.Valid() || expected == 0 { return HumanUser{}, ErrInvalid }
	if _, err := s.AuthorizeActor(ctx, actor, "principal:manage", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssuranceMFA); err != nil { return HumanUser{}, err }
	current, err := s.store.HumanUser(ctx, tenantID, identityID)
	if err != nil { return HumanUser{}, err }
	if current.PrimaryTenantID != tenantID { return HumanUser{}, ErrForbidden }
	if current.State == HumanUserDeletionPending || current.State == HumanUserDeleted { return current, nil }
	if current.Revision != expected { return HumanUser{}, ErrStaleGeneration }
	if current.State != HumanUserActive && current.State != HumanUserSuspended { return HumanUser{}, ErrConflict }
	if err = s.validateRecentRoleStepUp(ctx, actor); err != nil { return HumanUser{}, err }
	if err = s.authorizeHumanUserTenants(ctx, actor, current, "principal:manage", AssuranceMFA); err != nil { return HumanUser{}, err }
	now := s.clock().UTC()
	retention := now.Add(humanUserRetention)
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return HumanUser{}, err }
	defer tx.Rollback()
	stored, err := loadHumanUser(ctx, tx, identityID, tenantID)
	if err != nil { return HumanUser{}, err }
	if stored.Revision != expected || stored.State != current.State { return HumanUser{}, ErrStaleGeneration }
	if err = validateRoleActorTx(ctx, tx, actor, tenantID); err != nil { return HumanUser{}, err }
	impact, err := humanDeletionImpactTx(ctx, tx, stored, now)
	if err != nil { return HumanUser{}, err }
	if impact.OwnershipBlockerCount != 0 {
		s.auditHumanUser(ctx, actor.PrincipalID, tenantID, "human_user.deletion.begin", &current, nil, []string{"resource_ownership"}, "rejected")
		return HumanUser{}, ErrHumanUserOwnershipBlocked
	}
	if len(impact.LastOwnerTenants) != 0 {
		s.auditHumanUser(ctx, actor.PrincipalID, tenantID, "human_user.deletion.begin", &current, nil, []string{"last_owner"}, "rejected")
		return HumanUser{}, ErrLastLocalOwner
	}
	refs, err := applyHumanAccessQuarantineTx(ctx, tx, actor.PrincipalID, identityID, now, true)
	if err != nil { return HumanUser{}, err }
	if _, err = tx.ExecContext(ctx, `UPDATE identity_memberships SET state='revoked',generation=generation+1,updated_at=? WHERE principal_id=? AND state<>'revoked'`, now, identityID); err != nil { return HumanUser{}, err }
	if _, err = tx.ExecContext(ctx, `UPDATE identity_human_user_memberships SET lifecycle_suspended=0,updated_at=? WHERE identity_id=?`, now, identityID); err != nil { return HumanUser{}, err }
	principalExpected := PrincipalActive
	if stored.State == HumanUserSuspended { principalExpected = PrincipalSuspended }
	result, err := tx.ExecContext(ctx, `UPDATE identity_principals SET state='suspended',authz_epoch=authz_epoch+1,credential_epoch=credential_epoch+1,generation=generation+1,updated_at=? WHERE id=? AND kind='human' AND state=? AND authz_epoch=?`, now, identityID, principalExpected, stored.AuthzEpoch)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	result, err = tx.ExecContext(ctx, `UPDATE identity_human_users SET state='deletion_pending',revision=revision+1,authz_epoch=?,updated_at=?,deletion_requested_at=?,retention_deadline=? WHERE identity_id=? AND revision=? AND state=?`, stored.AuthzEpoch+1, now, now, retention, identityID, expected, stored.State)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	next, err := loadHumanUser(ctx, tx, identityID, tenantID)
	if err != nil { return HumanUser{}, err }
	if err = tx.Commit(); err != nil { return HumanUser{}, err }
	s.revokeHumanVerifierRefs(ctx, actor.PrincipalID, tenantID, identityID, refs)
	s.auditHumanUser(ctx, actor.PrincipalID, tenantID, "human_user.deletion.begin", &current, &next, []string{"state", "authz_epoch", "memberships", "role_bindings", "sessions", "credentials", "retention_deadline"}, "applied")
	return next, nil
}

func humanDeletedPrincipalIdentifiers(identityID ID) (string, string) {
	sum := digest([]byte(identityID.String() + "\x00deleted"))
	return "deleted_" + sum[:24], sum[:32] + "@deleted.invalid"
}

func (s *Service) PurgeHumanUser(ctx context.Context, actor ActorContext, tenantID, identityID ID, expected uint64) (HumanUser, error) {
	if !tenantID.Valid() || !identityID.Valid() || expected == 0 { return HumanUser{}, ErrInvalid }
	if _, err := s.AuthorizeActor(ctx, actor, "principal:manage", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssuranceMFA); err != nil { return HumanUser{}, err }
	current, err := s.store.HumanUser(ctx, tenantID, identityID)
	if err != nil { return HumanUser{}, err }
	if current.PrimaryTenantID != tenantID { return HumanUser{}, ErrForbidden }
	if current.State == HumanUserDeleted { return current, nil }
	if current.Revision != expected { return HumanUser{}, ErrStaleGeneration }
	if current.State != HumanUserDeletionPending || current.RetentionDeadline == nil { return HumanUser{}, ErrConflict }
	if err = s.validateRecentRoleStepUp(ctx, actor); err != nil { return HumanUser{}, err }
	now := s.clock().UTC()
	if now.Before(*current.RetentionDeadline) { return HumanUser{}, ErrHumanUserRetention }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return HumanUser{}, err }
	defer tx.Rollback()
	stored, err := loadHumanUser(ctx, tx, identityID, tenantID)
	if err != nil { return HumanUser{}, err }
	if stored.Revision != expected || stored.State != HumanUserDeletionPending || stored.RetentionDeadline == nil || now.Before(*stored.RetentionDeadline) { return HumanUser{}, ErrStaleGeneration }
	if err = validateRoleActorTx(ctx, tx, actor, tenantID); err != nil { return HumanUser{}, err }
	blockers, blockerCount, err := humanOwnershipBlockersTx(ctx, tx, identityID)
	if err != nil { return HumanUser{}, err }
	if blockerCount != 0 {
		_ = blockers
		s.auditHumanUser(ctx, actor.PrincipalID, tenantID, "human_user.deletion.purge", &current, nil, []string{"resource_ownership"}, "rejected")
		return HumanUser{}, ErrHumanUserOwnershipBlocked
	}
	refs, err := collectEveryHumanVerifierRefTx(ctx, tx, identityID)
	if err != nil { return HumanUser{}, err }
	tombstone := humanUserDigest(stored)
	username, email := humanDeletedPrincipalIdentifiers(identityID)
	operations := []struct{ query string; args []any }{
		{`DELETE FROM identity_session_binding_policies WHERE session_id IN (SELECT id FROM identity_sessions WHERE principal_id=?)`, []any{identityID}},
		{`DELETE FROM identity_sessions WHERE principal_id=?`, []any{identityID}},
		{`DELETE FROM identity_auth_challenges WHERE principal_id=?`, []any{identityID}},
		{`DELETE FROM identity_credentials WHERE principal_id=?`, []any{identityID}},
		{`DELETE FROM identity_principal_session_policies WHERE principal_id=?`, []any{identityID}},
		{`DELETE FROM identity_profile_preferences WHERE principal_id=?`, []any{identityID}},
		{`DELETE FROM identity_human_user_identifiers WHERE identity_id=?`, []any{identityID}},
	}
	for _, operation := range operations { if _, err = tx.ExecContext(ctx, operation.query, operation.args...); err != nil { return HumanUser{}, err } }
	result, err := tx.ExecContext(ctx, `UPDATE identity_principals SET username=?,email=?,display_name='Deleted user',state='deleted',authz_epoch=authz_epoch+1,credential_epoch=credential_epoch+1,generation=generation+1,updated_at=?,deleted_at=? WHERE id=? AND kind='human' AND state='suspended' AND authz_epoch=?`, username, email, now, now, identityID, stored.AuthzEpoch)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	result, err = tx.ExecContext(ctx, `UPDATE identity_human_users SET display_name='',state='deleted',revision=revision+1,authz_epoch=?,updated_at=?,deleted_at=?,tombstone_digest=? WHERE identity_id=? AND revision=? AND state='deletion_pending'`, stored.AuthzEpoch+1, now, now, tombstone, identityID, expected)
	if err != nil { return HumanUser{}, err }
	if rows, _ := result.RowsAffected(); rows != 1 { return HumanUser{}, ErrStaleGeneration }
	next, err := loadHumanUser(ctx, tx, identityID, tenantID)
	if err != nil { return HumanUser{}, err }
	if err = tx.Commit(); err != nil { return HumanUser{}, err }
	s.revokeHumanVerifierRefs(ctx, actor.PrincipalID, tenantID, identityID, refs)
	s.auditHumanUser(ctx, actor.PrincipalID, tenantID, "human_user.deletion.purge", &current, &next, []string{"state", "identifiers", "profile", "credentials", "sessions", "tombstone"}, "applied")
	return next, nil
}

func ensureHumanUserFromInvitationTx(ctx context.Context, tx *sql.Tx, principal Principal, membership Membership, invitation Invitation, role Role, now time.Time) error {
	ceiling, err := humanCeilingForInvitationRole(ctx, tx, role)
	if err != nil { return err }
	value, err := loadHumanUser(ctx, tx, principal.ID, "")
	if errors.Is(err, ErrNotFound) {
		value = newHumanUserFromPrincipal(principal, membership, ceiling, now)
		return putHumanUserTx(ctx, tx, value)
	}
	if err != nil { return err }
	if value.State != HumanUserActive { return ErrHumanUserQuarantined }
	verifiedEmail := false
	for _, identifier := range value.Identifiers { if identifier.Kind == HumanIdentifierEmail && identifier.Value == invitation.IntendedEmail { verifiedEmail = true } }
	if !verifiedEmail { return ErrForbidden }
	if existing, ok := humanUserMembershipForTenant(value, invitation.TenantID); ok {
		nextCeiling := existing.RoleCeiling
		if humanUserCeilingRank(ceiling) > humanUserCeilingRank(nextCeiling) { nextCeiling = ceiling }
		_, err = tx.ExecContext(ctx, `UPDATE identity_human_user_memberships SET membership_id=?,role_ceiling=?,lifecycle_suspended=0,updated_at=? WHERE identity_id=? AND tenant_id=?`, membership.ID, nextCeiling, now, principal.ID, invitation.TenantID)
		return err
	}
	if len(value.Memberships) >= humanUserMaximumMemberships { return ErrQuotaExceeded }
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_human_user_memberships(identity_id,membership_id,tenant_id,role_ceiling,lifecycle_suspended,created_at,updated_at) VALUES(?,?,?,?,0,?,?)`, principal.ID, membership.ID, invitation.TenantID, ceiling, now, now)
	return err
}

func validateHumanRoleAssignmentTx(ctx context.Context, tx *sql.Tx, tenantID, identityID ID, role ManagedRole) error {
	var state, ceiling string
	err := tx.QueryRowContext(ctx, `SELECT u.state,m.role_ceiling FROM identity_human_users u JOIN identity_human_user_memberships m ON m.identity_id=u.identity_id AND m.tenant_id=? JOIN identity_memberships core ON core.id=m.membership_id AND core.state='active' WHERE u.identity_id=?`, tenantID, identityID).Scan(&state, &ceiling)
	if errors.Is(err, sql.ErrNoRows) { return ErrNotFound }
	if err != nil { return err }
	if HumanUserState(state) != HumanUserActive { return ErrHumanUserQuarantined }
	if !humanCeilingAllowsRole(HumanUserRoleCeiling(ceiling), role.BuiltInKey, role.Permissions) { return ErrHumanUserRoleCeiling }
	return nil
}
