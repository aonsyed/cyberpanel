package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const maximumInvitationLifetime = 30 * 24 * time.Hour

// InvitationDelivery is the sole boundary that receives a plaintext
// invitation token. Persistence and API projections retain only its digest.
type InvitationDelivery struct {
	InvitationID ID
	TenantID     ID
	Email        string
	Token        []byte
	ExpiresAt    time.Time
}

type InvitationDeliveryBoundary interface {
	DeliverInvitation(context.Context, InvitationDelivery) error
}

type CreateInvitationCommand struct {
	Actor         ActorContext
	InvitationID  ID
	TenantID      ID
	IntendedEmail string
	RoleID        ID
	Scope         Scope
	ExpiresAt     time.Time
}

func normalizeInvitationEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validInvitationEmail(value string) bool {
	if len(value) < 3 || len(value) > 254 || strings.ContainsAny(value, "\x00\r\n\t ") || strings.Count(value, "@") != 1 {
		return false
	}
	parts := strings.SplitN(value, "@", 2)
	return parts[0] != "" && parts[1] != "" && !strings.HasPrefix(parts[0], ".") && !strings.HasSuffix(parts[0], ".") && !strings.HasPrefix(parts[1], ".") && !strings.HasSuffix(parts[1], ".")
}

func validInvitationDigest(value string) bool {
	if len(value) != 64 { return false }
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' { return false }
	}
	return true
}

func (s *Store) Invitation(ctx context.Context, tenantID, invitationID ID) (Invitation, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || !invitationID.Valid() {
		return Invitation{}, ErrInvalid
	}
	return scanInvitation(s.db.QueryRowContext(ctx, invitationSelect+` WHERE tenant_id=? AND id=?`, tenantID, invitationID))
}

func (s *Store) ListInvitations(ctx context.Context, tenantID ID, limit int, cursor ID) ([]Invitation, string, uint64, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || limit < 1 || limit > 200 || (cursor != "" && !cursor.Valid()) {
		return nil, "", 0, ErrInvalid
	}
	var total uint64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_invitations WHERE tenant_id=?`, tenantID).Scan(&total); err != nil {
		return nil, "", 0, err
	}
	rows, err := s.db.QueryContext(ctx, invitationSelect+` WHERE tenant_id=? AND id>? ORDER BY id LIMIT ?`, tenantID, cursor, limit+1)
	if err != nil {
		return nil, "", 0, err
	}
	defer rows.Close()
	values := make([]Invitation, 0, limit)
	for rows.Next() {
		value, scanErr := scanInvitation(rows)
		if scanErr != nil {
			return nil, "", 0, scanErr
		}
		values = append(values, value)
	}
	if err = rows.Err(); err != nil {
		return nil, "", 0, err
	}
	next := ""
	if len(values) > limit {
		next = values[limit-1].ID.String()
		values = values[:limit]
	}
	return values, next, total, nil
}

const invitationSelect = `SELECT id,tenant_id,intended_email,inviter_id,role_id,role_ceiling_json,scope_kind,resource_id,state,generation,token_epoch,token_digest,created_at,expires_at,last_delivered_at FROM identity_invitations`

type invitationScanner interface {
	Scan(...any) error
}

func scanInvitation(row invitationScanner) (Invitation, error) {
	var value Invitation
	var ceiling []byte
	var scopeKind, state string
	var delivered sql.NullTime
	err := row.Scan(&value.ID, &value.TenantID, &value.IntendedEmail, &value.InviterID, &value.RoleID, &ceiling, &scopeKind, &value.Scope.ResourceID, &state, &value.Generation, &value.TokenEpoch, &value.TokenDigest, &value.CreatedAt, &value.ExpiresAt, &delivered)
	if errors.Is(err, sql.ErrNoRows) {
		return Invitation{}, ErrNotFound
	}
	if err != nil {
		return Invitation{}, err
	}
	if err = json.Unmarshal(ceiling, &value.RoleCeiling); err != nil {
		return Invitation{}, err
	}
	value.Scope.Kind = ScopeKind(scopeKind)
	value.Scope.TenantID = value.TenantID
	value.State = InvitationState(state)
	if delivered.Valid {
		value.LastDeliveredAt = &delivered.Time
	}
	if err = value.Validate(); err != nil {
		return Invitation{}, err
	}
	return value, nil
}

func insertInvitation(ctx context.Context, tx *sql.Tx, value Invitation) error {
	if err := value.Validate(); err != nil {
		return err
	}
	ceiling, err := json.Marshal(value.RoleCeiling)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_invitations(id,tenant_id,intended_email,inviter_id,role_id,role_ceiling_json,scope_kind,resource_id,state,generation,token_epoch,token_digest,created_at,expires_at,last_delivered_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.ID, value.TenantID, value.IntendedEmail, value.InviterID, value.RoleID, ceiling, value.Scope.Kind, value.Scope.ResourceID, value.State, value.Generation, value.TokenEpoch, value.TokenDigest, value.CreatedAt, value.ExpiresAt, value.LastDeliveredAt)
	return err
}

func invitationTokenDigest(id ID, epoch uint64, token []byte) string {
	bound := make([]byte, 0, len(id.String())+len(token)+32)
	bound = append(bound, id.String()...)
	bound = append(bound, 0)
	bound = strconv.AppendUint(bound, epoch, 10)
	bound = append(bound, 0)
	bound = append(bound, token...)
	value := digest(bound)
	clearBytes(bound)
	return value
}

func issueInvitationToken() []byte {
	random := randomBytes(32)
	encoded := []byte(base64.RawURLEncoding.EncodeToString(random))
	clearBytes(random)
	return encoded
}

func deliverInvitation(ctx context.Context, boundary InvitationDeliveryBoundary, invitation Invitation, token []byte) error {
	if boundary == nil {
		return fmt.Errorf("%w: invitation delivery boundary", ErrConflict)
	}
	deliveryToken := append([]byte(nil), token...)
	defer clearBytes(deliveryToken)
	return boundary.DeliverInvitation(ctx, InvitationDelivery{InvitationID: invitation.ID, TenantID: invitation.TenantID, Email: invitation.IntendedEmail, Token: deliveryToken, ExpiresAt: invitation.ExpiresAt})
}

func (s *Service) CreateInvitation(ctx context.Context, command CreateInvitationCommand, boundary InvitationDeliveryBoundary) (Invitation, error) {
	if s == nil || s.store == nil || ctx == nil || boundary == nil || !command.InvitationID.Valid() || !command.TenantID.Valid() || !command.RoleID.Valid() {
		return Invitation{}, ErrInvalid
	}
	command.IntendedEmail = normalizeInvitationEmail(command.IntendedEmail)
	if !validInvitationEmail(command.IntendedEmail) || command.Scope.TenantID != command.TenantID || command.Scope.Kind == ScopeInstallation || command.Scope.Validate() != nil {
		return Invitation{}, ErrInvalid
	}
	if _, err := s.AuthorizeActor(ctx, command.Actor, "identity:manage", command.Scope, AssuranceMFA); err != nil {
		return Invitation{}, err
	}
	tenant, err := s.store.Tenant(ctx, command.TenantID)
	if err != nil {
		return Invitation{}, err
	}
	if tenant.State != TenantActive {
		return Invitation{}, ErrSuspended
	}
	role, err := s.store.Role(ctx, command.RoleID)
	if err != nil {
		return Invitation{}, err
	}
	if role.TenantID != command.TenantID || len(role.Permissions) == 0 {
		return Invitation{}, ErrForbidden
	}
	ceiling := CanonicalPermissions(role.Permissions)
	now := s.clock().UTC()
	command.ExpiresAt = command.ExpiresAt.UTC()
	if !command.ExpiresAt.After(now) || command.ExpiresAt.After(now.Add(maximumInvitationLifetime)) {
		return Invitation{}, ErrInvalid
	}
	if managed, loadErr := s.store.managedRole(ctx, command.TenantID, command.RoleID); loadErr == nil {
		if !roleContainsSelector(managed, command.Scope) || managed.BuiltInKey == BuiltInOwner && command.Scope.Kind != ScopeTenant { return Invitation{}, ErrGrantCeiling }
	} else if !errors.Is(loadErr, ErrNotFound) { return Invitation{}, loadErr }
	provenance, err := s.roleActorCanGrant(ctx, command.Actor, ceiling, []Scope{command.Scope}, now, nil); if err != nil { return Invitation{}, err }
	token := issueInvitationToken()
	defer clearBytes(token)
	invitation := Invitation{ID: command.InvitationID, TenantID: command.TenantID, IntendedEmail: command.IntendedEmail, InviterID: command.Actor.PrincipalID, RoleID: command.RoleID, RoleCeiling: ceiling, Scope: command.Scope, State: InvitationPending, Generation: 1, TokenEpoch: 1, CreatedAt: now, ExpiresAt: command.ExpiresAt}
	invitation.TokenDigest = invitationTokenDigest(invitation.ID, invitation.TokenEpoch, token)
	if err = invitation.Validate(); err != nil {
		return Invitation{}, err
	}
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Invitation{}, err
	}
	defer tx.Rollback()
	if err = insertInvitation(ctx, tx, invitation); err != nil {
		return Invitation{}, err
	}
	for _, provenanceID := range provenance { if _, err = tx.ExecContext(ctx, `INSERT INTO identity_invitation_role_provenance(invitation_id,provenance_id) VALUES(?,?)`, invitation.ID, provenanceID); err != nil { return Invitation{}, err } }
	if err = tx.Commit(); err != nil {
		return Invitation{}, err
	}
	s.record(ctx, command.Actor.PrincipalID, invitation.TenantID, "invitation.create", "invitation", invitation.ID, "applied", invitation.ID.String())
	if err = deliverInvitation(ctx, boundary, invitation, token); err != nil {
		return Invitation{}, err
	}
	return s.markInvitationDelivered(ctx, invitation)
}

func (s *Service) GetInvitation(ctx context.Context, actor ActorContext, tenantID, invitationID ID) (Invitation, error) {
	if _, err := s.AuthorizeActor(ctx, actor, "identity:manage", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssurancePassword); err != nil {
		return Invitation{}, err
	}
	return s.store.Invitation(ctx, tenantID, invitationID)
}

func (s *Service) ListInvitations(ctx context.Context, actor ActorContext, tenantID ID, limit int, cursor ID) ([]Invitation, string, uint64, error) {
	if _, err := s.AuthorizeActor(ctx, actor, "identity:manage", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssurancePassword); err != nil {
		return nil, "", 0, err
	}
	return s.store.ListInvitations(ctx, tenantID, limit, cursor)
}

func (s *Service) ResendInvitation(ctx context.Context, actor ActorContext, tenantID, invitationID ID, expected uint64, boundary InvitationDeliveryBoundary) (Invitation, error) {
	if expected == 0 || boundary == nil {
		return Invitation{}, ErrInvalid
	}
	if _, err := s.AuthorizeActor(ctx, actor, "identity:manage", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssuranceMFA); err != nil {
		return Invitation{}, err
	}
	invitation, err := s.store.Invitation(ctx, tenantID, invitationID)
	if err != nil {
		return Invitation{}, err
	}
	if invitation.Generation != expected {
		return Invitation{}, ErrStaleGeneration
	}
	if invitation.State != InvitationPending {
		return Invitation{}, ErrConflict
	}
	if !s.clock().UTC().Before(invitation.ExpiresAt) {
		return Invitation{}, ErrExpired
	}
	token := issueInvitationToken()
	defer clearBytes(token)
	previous := invitation.Generation
	invitation.Generation++
	invitation.TokenEpoch++
	invitation.TokenDigest = invitationTokenDigest(invitation.ID, invitation.TokenEpoch, token)
	result, err := s.store.db.ExecContext(ctx, `UPDATE identity_invitations SET generation=?,token_epoch=?,token_digest=? WHERE id=? AND tenant_id=? AND generation=? AND state=?`, invitation.Generation, invitation.TokenEpoch, invitation.TokenDigest, invitation.ID, invitation.TenantID, previous, InvitationPending)
	if err != nil {
		return Invitation{}, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return Invitation{}, ErrStaleGeneration
	}
	s.record(ctx, actor.PrincipalID, invitation.TenantID, "invitation.resend", "invitation", invitation.ID, "applied", invitation.ID.String()+"\x00"+fmt.Sprint(invitation.Generation))
	if err = deliverInvitation(ctx, boundary, invitation, token); err != nil {
		return Invitation{}, err
	}
	return s.markInvitationDelivered(ctx, invitation)
}

func (s *Service) markInvitationDelivered(ctx context.Context, invitation Invitation) (Invitation, error) {
	now := s.clock().UTC()
	result, err := s.store.db.ExecContext(ctx, `UPDATE identity_invitations SET last_delivered_at=? WHERE id=? AND tenant_id=? AND generation=? AND token_epoch=? AND state=?`, now, invitation.ID, invitation.TenantID, invitation.Generation, invitation.TokenEpoch, InvitationPending)
	if err != nil {
		return Invitation{}, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return Invitation{}, ErrStaleGeneration
	}
	invitation.LastDeliveredAt = &now
	return invitation, nil
}

func (s *Service) AcceptInvitation(ctx context.Context, actor ActorContext, tenantID, invitationID ID, expected uint64, token []byte) (Invitation, error) {
	defer clearBytes(token)
	if expected == 0 || !tenantID.Valid() || !invitationID.Valid() || len(token) < 40 || len(token) > 128 {
		return Invitation{}, ErrInvalid
	}
	if err := s.validateActor(ctx, actor, AssurancePassword); err != nil {
		return Invitation{}, err
	}
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Invitation{}, err
	}
	defer tx.Rollback()
	invitation, err := scanInvitation(tx.QueryRowContext(ctx, invitationSelect+` WHERE id=? AND tenant_id=?`, invitationID, tenantID))
	if err != nil {
		return Invitation{}, err
	}
	if invitation.Generation != expected {
		return Invitation{}, ErrStaleGeneration
	}
	if invitation.State != InvitationPending {
		return Invitation{}, ErrConflict
	}
	now := s.clock().UTC()
	if !now.Before(invitation.ExpiresAt) {
		return Invitation{}, ErrExpired
	}
	expectedDigest := invitationTokenDigest(invitation.ID, invitation.TokenEpoch, token)
	if subtle.ConstantTimeCompare([]byte(expectedDigest), []byte(invitation.TokenDigest)) != 1 {
		return Invitation{}, ErrUnauthenticated
	}
	principal, err := scanPrincipal(tx.QueryRowContext(ctx, `SELECT id,kind,username,email,display_name,state,locale,theme,authz_epoch,credential_epoch,generation,created_at,updated_at,deleted_at FROM identity_principals WHERE id=?`, actor.PrincipalID))
	if err != nil || principal.State != PrincipalActive || normalizeInvitationEmail(principal.Email) != invitation.IntendedEmail {
		return Invitation{}, ErrForbidden
	}
	tenant, err := scanInvitationTenant(tx, invitation.TenantID)
	if err != nil {
		return Invitation{}, err
	}
	if tenant.State != TenantActive {
		return Invitation{}, ErrSuspended
	}
	role, err := scanInvitationRole(tx, invitation.RoleID)
	if err != nil {
		return Invitation{}, err
	}
	if role.TenantID != invitation.TenantID || !roleWithinInvitationCeiling(role.Permissions, invitation.RoleCeiling) {
		return Invitation{}, ErrDelegationExceeded
	}
	if err = invitationManagedRoleAllows(ctx, tx, invitation.RoleID, invitation.Scope); err != nil { return Invitation{}, err }
	membership, exists, err := loadInvitationMembership(ctx, tx, principal.ID, invitation.TenantID)
	if err != nil {
		return Invitation{}, err
	}
	if exists {
		switch membership.State {
		case MembershipActive:
		case MembershipInvited:
			membership.State = MembershipActive
			membership.Generation++
			membership.UpdatedAt = now
			if err = putMembership(ctx, tx, membership); err != nil {
				return Invitation{}, err
			}
		default:
			return Invitation{}, ErrConflict
		}
	} else {
		membershipID, idErr := derivedID("member", invitation.ID.String()+"\x00"+principal.ID.String())
		if idErr != nil {
			return Invitation{}, idErr
		}
		membership = Membership{ID: membershipID, PrincipalID: principal.ID, TenantID: invitation.TenantID, State: MembershipActive, Generation: 1, CreatedAt: now, UpdatedAt: now}
		if err = putMembership(ctx, tx, membership); err != nil {
			return Invitation{}, err
		}
	}
	if err = ensureHumanUserFromInvitationTx(ctx, tx, principal, membership, invitation, role, now); err != nil {
		return Invitation{}, err
	}
	bindingID, err := derivedID("binding", invitation.ID.String()+"\x00"+principal.ID.String())
	if err != nil {
		return Invitation{}, err
	}
	provenance, err := invitationRoleProvenance(ctx, tx, invitation.ID); if err != nil { return Invitation{}, err }
	binding := ManagedRoleBinding{ID: bindingID, TenantID: invitation.TenantID, SubjectKind: SubjectPrincipal, SubjectID: principal.ID, RoleID: invitation.RoleID, Selectors: []Scope{invitation.Scope}, EffectiveAt: now, GrantedByID: invitation.InviterID, Provenance: provenance, Revision: 1, CreatedAt: now}
	if err = binding.Validate(); err != nil { return Invitation{}, err }
	if err = insertManagedBindingTx(ctx, tx, binding); err != nil { return Invitation{}, err }
	if err = invalidateRoleSubjectTx(ctx, tx, principal.ID, now); err != nil { return Invitation{}, err }
	previous := invitation.Generation
	invitation.State = InvitationAccepted
	invitation.Generation++
	invitation.TokenEpoch++
	invitation.TokenDigest = ""
	result, err := tx.ExecContext(ctx, `UPDATE identity_invitations SET state=?,generation=?,token_epoch=?,token_digest='' WHERE id=? AND generation=? AND state=?`, invitation.State, invitation.Generation, invitation.TokenEpoch, invitation.ID, previous, InvitationPending)
	if err != nil {
		return Invitation{}, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return Invitation{}, ErrStaleGeneration
	}
	if err = tx.Commit(); err != nil {
		return Invitation{}, err
	}
	s.auditRole(ctx, invitation.InviterID, invitation.TenantID, "role_binding.assign", "role_binding", binding.ID, nil, binding, nil, "applied")
	s.record(ctx, actor.PrincipalID, invitation.TenantID, "invitation.accept", "invitation", invitation.ID, "applied", invitation.ID.String()+"\x00"+fmt.Sprint(invitation.Generation))
	return invitation, nil
}

func scanInvitationTenant(tx *sql.Tx, id ID) (Tenant, error) {
	var value Tenant
	var kind, state string
	err := tx.QueryRow(`SELECT id,parent_tenant_id,sponsor_id,kind,name,state,plan_id,generation,authz_epoch,created_at,updated_at FROM identity_tenants WHERE id=?`, id).Scan(&value.ID, &value.ParentTenantID, &value.SponsorID, &kind, &value.Name, &state, &value.PlanID, &value.Generation, &value.AuthzEpoch, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	if err != nil {
		return Tenant{}, err
	}
	value.Kind = TenantKind(kind)
	value.State = TenantState(state)
	return value, value.Validate()
}

func scanInvitationRole(tx *sql.Tx, id ID) (Role, error) {
	var value Role
	var permissions []byte
	var builtin int
	var state string
	err := tx.QueryRow(`SELECT r.id,r.tenant_id,r.name,r.permissions_json,r.builtin,r.generation,r.created_at,r.updated_at,COALESCE(c.state,'') FROM identity_roles r LEFT JOIN identity_role_catalog c ON c.role_id=r.id WHERE r.id=?`, id).Scan(&value.ID, &value.TenantID, &value.Name, &permissions, &builtin, &value.Generation, &value.CreatedAt, &value.UpdatedAt, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return Role{}, ErrNotFound
	}
	if err != nil {
		return Role{}, err
	}
	if state == string(RoleRetired) {
		return Role{}, ErrRoleRetired
	}
	if state == string(RoleDeleted) {
		return Role{}, ErrNotFound
	}
	value.Builtin = builtin != 0
	if err = json.Unmarshal(permissions, &value.Permissions); err != nil {
		return Role{}, err
	}
	return value, value.Validate()
}

func invitationManagedRoleAllows(ctx context.Context, tx *sql.Tx, roleID ID, scope Scope) error {
	var state, builtinKey string
	var selectorsJSON []byte
	err := tx.QueryRowContext(ctx, `SELECT state,builtin_key,selectors_json FROM identity_role_catalog WHERE role_id=?`, roleID).Scan(&state, &builtinKey, &selectorsJSON)
	if errors.Is(err, sql.ErrNoRows) { return nil }
	if err != nil { return err }
	if RoleLifecycleState(state) != RoleActive { return ErrRoleRetired }
	var selectors []Scope
	if err = json.Unmarshal(selectorsJSON, &selectors); err != nil { return ErrConflict }
	allowed := false; for _, selector := range selectors { if scopeContains(selector, scope) { allowed = true; break } }
	if !allowed || BuiltInRoleKey(builtinKey) == BuiltInOwner && scope.Kind != ScopeTenant { return ErrGrantCeiling }
	return nil
}

func invitationRoleProvenance(ctx context.Context, tx *sql.Tx, invitationID ID) ([]ID, error) {
	rows, err := tx.QueryContext(ctx, `SELECT provenance_id FROM identity_invitation_role_provenance WHERE invitation_id=? ORDER BY provenance_id LIMIT 129`, invitationID); if err != nil { return nil, err }; defer rows.Close()
	values := make([]ID, 0, 8); for rows.Next() { var id ID; if err = rows.Scan(&id); err != nil { return nil, err }; if !id.Valid() { return nil, ErrConflict }; values = append(values, id) }; if err = rows.Err(); err != nil { return nil, err }
	if len(values) == 0 || len(values) > 128 { return nil, ErrGrantCeiling }
	return values, nil
}

func loadInvitationMembership(ctx context.Context, tx *sql.Tx, principalID, tenantID ID) (Membership, bool, error) {
	var value Membership
	var state string
	err := tx.QueryRowContext(ctx, `SELECT id,principal_id,tenant_id,state,generation,created_at,updated_at FROM identity_memberships WHERE principal_id=? AND tenant_id=?`, principalID, tenantID).Scan(&value.ID, &value.PrincipalID, &value.TenantID, &state, &value.Generation, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Membership{}, false, nil
	}
	if err != nil {
		return Membership{}, false, err
	}
	value.State = MembershipState(state)
	return value, true, value.Validate()
}

func roleWithinInvitationCeiling(role, ceiling []Permission) bool {
	for _, permission := range role {
		if !containsPermission(ceiling, permission) {
			return false
		}
	}
	return true
}

func (s *Service) ExpireInvitation(ctx context.Context, actor ActorContext, tenantID, invitationID ID, expected uint64) (Invitation, error) {
	return s.transitionInvitation(ctx, actor, tenantID, invitationID, expected, InvitationExpired)
}

func (s *Service) RevokeInvitation(ctx context.Context, actor ActorContext, tenantID, invitationID ID, expected uint64) (Invitation, error) {
	return s.transitionInvitation(ctx, actor, tenantID, invitationID, expected, InvitationRevoked)
}

func (s *Service) transitionInvitation(ctx context.Context, actor ActorContext, tenantID, invitationID ID, expected uint64, state InvitationState) (Invitation, error) {
	if expected == 0 || (state != InvitationExpired && state != InvitationRevoked) {
		return Invitation{}, ErrInvalid
	}
	if _, err := s.AuthorizeActor(ctx, actor, "identity:manage", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssuranceMFA); err != nil {
		return Invitation{}, err
	}
	invitation, err := s.store.Invitation(ctx, tenantID, invitationID)
	if err != nil {
		return Invitation{}, err
	}
	if invitation.Generation != expected {
		return Invitation{}, ErrStaleGeneration
	}
	if invitation.State != InvitationPending {
		return Invitation{}, ErrConflict
	}
	if state == InvitationExpired && s.clock().UTC().Before(invitation.ExpiresAt) {
		return Invitation{}, ErrConflict
	}
	previous := invitation.Generation
	invitation.State = state
	invitation.Generation++
	invitation.TokenEpoch++
	invitation.TokenDigest = ""
	result, err := s.store.db.ExecContext(ctx, `UPDATE identity_invitations SET state=?,generation=?,token_epoch=?,token_digest='' WHERE id=? AND tenant_id=? AND generation=? AND state=?`, invitation.State, invitation.Generation, invitation.TokenEpoch, invitation.ID, invitation.TenantID, previous, InvitationPending)
	if err != nil {
		return Invitation{}, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return Invitation{}, ErrStaleGeneration
	}
	action := "invitation." + string(state)
	s.record(ctx, actor.PrincipalID, invitation.TenantID, action, "invitation", invitation.ID, "applied", invitation.ID.String()+"\x00"+fmt.Sprint(invitation.Generation))
	return invitation, nil
}
