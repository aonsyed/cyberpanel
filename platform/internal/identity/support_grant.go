package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

const recentSupportGrantAssurance = 10 * time.Minute

type IssueSupportGrantCommand struct {
	Actor          ActorContext
	GrantID        ID
	TargetTenantID ID
	Scope          Scope
	Permissions    []Permission
	Reason         string
	ExpiresAt      time.Time
}

const supportGrantSelect = `SELECT id,issuer_id,target_tenant_id,scope_kind,resource_id,permissions_json,reason,state,generation,secret_epoch,secret_digest,issued_at,expires_at,consumed_at,consumed_by_principal_id,consumed_by_session_id,context_id,expired_at,revoked_at,revoked_by_id FROM identity_support_grants`

type supportGrantScanner interface {
	Scan(...any) error
}

func validSupportGrantDigest(value string) bool {
	if len(value) != 64 { return false }
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' { return false }
	}
	return true
}

func scanSupportGrant(row supportGrantScanner) (SupportContextGrant, error) {
	var value SupportContextGrant
	var scopeKind, state string
	var permissions []byte
	var consumedAt, expiredAt, revokedAt sql.NullTime
	err := row.Scan(&value.ID, &value.IssuerID, &value.TargetTenantID, &scopeKind, &value.Scope.ResourceID, &permissions, &value.Reason, &state, &value.Generation, &value.secretEpoch, &value.secretDigest, &value.IssuedAt, &value.ExpiresAt, &consumedAt, &value.ConsumedByPrincipalID, &value.ConsumedBySessionID, &value.ContextID, &expiredAt, &revokedAt, &value.RevokedByID)
	if errors.Is(err, sql.ErrNoRows) { return SupportContextGrant{}, ErrNotFound }
	if err != nil { return SupportContextGrant{}, err }
	if err = json.Unmarshal(permissions, &value.Permissions); err != nil { return SupportContextGrant{}, err }
	value.Scope = Scope{Kind: ScopeKind(scopeKind), TenantID: value.TargetTenantID, ResourceID: value.Scope.ResourceID}
	value.State = SupportGrantState(state)
	if consumedAt.Valid { value.ConsumedAt = &consumedAt.Time }
	if expiredAt.Valid { value.ExpiredAt = &expiredAt.Time }
	if revokedAt.Valid { value.RevokedAt = &revokedAt.Time }
	if err = value.Validate(); err != nil { return SupportContextGrant{}, err }
	return value, nil
}

func (s *Store) SupportGrant(ctx context.Context, tenantID, grantID ID) (SupportContextGrant, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || !grantID.Valid() { return SupportContextGrant{}, ErrInvalid }
	return scanSupportGrant(s.db.QueryRowContext(ctx, supportGrantSelect+` WHERE target_tenant_id=? AND id=?`, tenantID, grantID))
}

func (s *Store) ListSupportGrants(ctx context.Context, tenantID ID, limit int, cursor ID) ([]SupportContextGrant, string, uint64, error) {
	if s == nil || s.db == nil || ctx == nil || !tenantID.Valid() || limit < 1 || limit > 100 || (cursor != "" && !cursor.Valid()) { return nil, "", 0, ErrInvalid }
	var total uint64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_support_grants WHERE target_tenant_id=?`, tenantID).Scan(&total); err != nil { return nil, "", 0, err }
	rows, err := s.db.QueryContext(ctx, supportGrantSelect+` WHERE target_tenant_id=? AND id>? ORDER BY id LIMIT ?`, tenantID, cursor, limit+1)
	if err != nil { return nil, "", 0, err }
	defer rows.Close()
	values := make([]SupportContextGrant, 0, limit)
	for rows.Next() {
		value, scanErr := scanSupportGrant(rows)
		if scanErr != nil { return nil, "", 0, scanErr }
		values = append(values, value)
	}
	if err = rows.Err(); err != nil { return nil, "", 0, err }
	next := ""
	if len(values) > limit { next = values[limit-1].ID.String(); values = values[:limit] }
	return values, next, total, nil
}

func supportGrantView(value SupportContextGrant) SupportGrantView {
	permissions := append([]Permission(nil), value.Permissions...)
	return SupportGrantView{ID: value.ID, IssuerID: value.IssuerID, TargetTenantID: value.TargetTenantID, Scope: value.Scope, Permissions: permissions, Reason: value.Reason, State: value.State, Generation: value.Generation, IssuedAt: value.IssuedAt, ExpiresAt: value.ExpiresAt, ConsumedAt: value.ConsumedAt, ConsumedByPrincipalID: value.ConsumedByPrincipalID, ConsumedBySessionID: value.ConsumedBySessionID, ContextID: value.ContextID, ExpiredAt: value.ExpiredAt, RevokedAt: value.RevokedAt, RevokedByID: value.RevokedByID}
}

func supportGrantError(code SupportGrantReasonCode, base error) error {
	return SupportGrantFailure{Code: code, Err: base}
}

func supportGrantDigest(id ID, epoch uint64, secret []byte) string {
	bound := make([]byte, 0, len(id.String())+len(secret)+32)
	bound = append(bound, id.String()...)
	bound = append(bound, 0)
	bound = strconv.AppendUint(bound, epoch, 10)
	bound = append(bound, 0)
	bound = append(bound, secret...)
	value := digest(bound)
	clearBytes(bound)
	return value
}

func issueSupportGrantSecret() []byte {
	random := randomBytes(32)
	secret := []byte(base64.RawURLEncoding.EncodeToString(random))
	clearBytes(random)
	return secret
}

func restrictedSupportPermission(permission Permission) bool {
	value := string(permission)
	for _, prefix := range []string{"credential:", "identity:", "principal:", "role:", "support:", "tenant:"} {
		if strings.HasPrefix(value, prefix) { return true }
	}
	return false
}

func (s *Service) supportGrantAudit(ctx context.Context, actor, tenant, target ID, action string, code SupportGrantReasonCode) {
	if s == nil || ctx == nil { return }
	if !target.Valid() {
		target, _ = derivedID("support", actor.String()+"\x00"+action+"\x00"+s.clock().UTC().Format(time.RFC3339Nano))
	}
	outcome := "rejected"
	switch code {
	case SupportGrantReasonIssued, SupportGrantReasonAccepted, SupportGrantReasonRevoked:
		outcome = "applied"
	case SupportGrantReasonAuthorizationDenied, SupportGrantReasonCeilingExceeded:
		outcome = "denied"
	case SupportGrantReasonStorageFailure:
		outcome = "failed"
	}
	s.record(ctx, actor, tenant, action, "support_grant", target, outcome, target.String()+"\x00"+string(code)+"\x00"+s.clock().UTC().Format(time.RFC3339Nano))
}

func (s *Service) requireRecentSupportGrantAssurance(ctx context.Context, actor ActorContext) error {
	if actor.SessionID == "" { return supportGrantError(SupportGrantReasonSessionRequired, ErrForbidden) }
	if err := s.validateActor(ctx, actor, AssurancePhishingResistant); err != nil { return supportGrantError(SupportGrantReasonAssuranceRequired, err) }
	session, err := s.store.Session(ctx, actor.SessionID)
	if err != nil { return supportGrantError(SupportGrantReasonSessionRequired, ErrUnauthenticated) }
	now := s.clock().UTC()
	if session.Assurance != AssurancePhishingResistant || session.CreatedAt.After(now) || now.Sub(session.CreatedAt) > recentSupportGrantAssurance {
		return supportGrantError(SupportGrantReasonAssuranceStale, ErrAssuranceRequired)
	}
	return nil
}

func (s *Service) IssueSupportGrant(ctx context.Context, command IssueSupportGrantCommand) (IssuedSupportGrant, error) {
	var tx *sql.Tx
	fail := func(code SupportGrantReasonCode, err error) (IssuedSupportGrant, error) {
		if tx != nil { _ = tx.Rollback(); tx = nil }
		if s != nil { s.supportGrantAudit(ctx, command.Actor.PrincipalID, command.TargetTenantID, command.GrantID, "support_grant.issue", code) }
		return IssuedSupportGrant{}, supportGrantError(code, err)
	}
	if s == nil || s.store == nil || ctx == nil || !command.GrantID.Valid() || !command.TargetTenantID.Valid() {
		return fail(SupportGrantReasonInvalidRequest, ErrInvalid)
	}
	command.Reason = strings.TrimSpace(command.Reason)
	permissionCount := len(command.Permissions)
	command.Permissions = CanonicalPermissions(command.Permissions)
	command.ExpiresAt = command.ExpiresAt.UTC()
	if command.Scope.TenantID != command.TargetTenantID || (command.Scope.Kind != ScopeProject && command.Scope.Kind != ScopeSite) || command.Scope.Validate() != nil || len(command.Permissions) == 0 || len(command.Permissions) > 16 || len(command.Permissions) != permissionCount {
		return fail(SupportGrantReasonInvalidRequest, ErrInvalid)
	}
	for _, permission := range command.Permissions {
		if permission == "*:*" || restrictedSupportPermission(permission) {
			return fail(SupportGrantReasonCeilingExceeded, ErrDelegationExceeded)
		}
		if _, err := NewPermission(string(permission)); err != nil { return fail(SupportGrantReasonInvalidRequest, ErrInvalid) }
	}
	if err := s.requireRecentSupportGrantAssurance(ctx, command.Actor); err != nil {
		code, _ := SupportGrantFailureReason(err)
		return fail(code, err)
	}
	if _, err := s.AuthorizeActor(ctx, command.Actor, "support:grant", command.Scope, AssurancePhishingResistant); err != nil {
		return fail(SupportGrantReasonAuthorizationDenied, err)
	}
	for _, permission := range command.Permissions {
		if _, err := s.AuthorizeActor(ctx, command.Actor, permission, command.Scope, AssurancePhishingResistant); err != nil {
			return fail(SupportGrantReasonCeilingExceeded, ErrDelegationExceeded)
		}
	}
	tenant, err := s.store.Tenant(ctx, command.TargetTenantID)
	if errors.Is(err, ErrNotFound) { return fail(SupportGrantReasonTenantNotFound, err) }
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	if tenant.State != TenantActive { return fail(SupportGrantReasonTenantInactive, ErrSuspended) }
	now := s.clock().UTC()
	grant := SupportContextGrant{ID: command.GrantID, IssuerID: command.Actor.PrincipalID, TargetTenantID: command.TargetTenantID, Scope: command.Scope, Permissions: command.Permissions, Reason: command.Reason, State: SupportGrantPending, Generation: 1, IssuedAt: now, ExpiresAt: command.ExpiresAt, secretEpoch: 1}
	secret := issueSupportGrantSecret()
	grant.secretDigest = supportGrantDigest(grant.ID, grant.secretEpoch, secret)
	if err = grant.Validate(); err != nil { clearBytes(secret); return fail(SupportGrantReasonInvalidRequest, err) }
	permissions, err := json.Marshal(grant.Permissions)
	if err != nil { clearBytes(secret); return fail(SupportGrantReasonStorageFailure, err) }
	tx, err = s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { clearBytes(secret); return fail(SupportGrantReasonStorageFailure, err) }
	defer func() { if tx != nil { _ = tx.Rollback() } }()
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_support_grants(id,issuer_id,target_tenant_id,scope_kind,resource_id,permissions_json,reason,state,generation,secret_epoch,secret_digest,issued_at,expires_at,consumed_at,consumed_by_principal_id,consumed_by_session_id,context_id,expired_at,revoked_at,revoked_by_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,'','','',NULL,NULL,'')`, grant.ID, grant.IssuerID, grant.TargetTenantID, grant.Scope.Kind, grant.Scope.ResourceID, permissions, grant.Reason, grant.State, grant.Generation, grant.secretEpoch, grant.secretDigest, grant.IssuedAt, grant.ExpiresAt)
	if err != nil { clearBytes(secret); return fail(SupportGrantReasonStorageFailure, err) }
	if err = tx.Commit(); err != nil { clearBytes(secret); return fail(SupportGrantReasonStorageFailure, err) }
	tx = nil
	s.supportGrantAudit(ctx, command.Actor.PrincipalID, grant.TargetTenantID, grant.ID, "support_grant.issue", SupportGrantReasonIssued)
	return IssuedSupportGrant{Grant: supportGrantView(grant), Secret: secret}, nil
}

func (s *Service) ListSupportGrants(ctx context.Context, actor ActorContext, tenantID ID, limit int, cursor ID) ([]SupportGrantView, string, uint64, error) {
	if s == nil || s.store == nil || !tenantID.Valid() { return nil, "", 0, supportGrantError(SupportGrantReasonInvalidRequest, ErrInvalid) }
	if _, err := s.AuthorizeActor(ctx, actor, "support:grant", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssurancePassword); err != nil { return nil, "", 0, supportGrantError(SupportGrantReasonAuthorizationDenied, err) }
	values, next, total, err := s.store.ListSupportGrants(ctx, tenantID, limit, cursor)
	if err != nil { return nil, "", 0, supportGrantError(SupportGrantReasonStorageFailure, err) }
	views := make([]SupportGrantView, 0, len(values))
	for _, value := range values { views = append(views, supportGrantView(value)) }
	return views, next, total, nil
}

func (s *Service) GetSupportGrant(ctx context.Context, actor ActorContext, tenantID, grantID ID) (SupportGrantView, error) {
	if s == nil || s.store == nil || !tenantID.Valid() || !grantID.Valid() { return SupportGrantView{}, supportGrantError(SupportGrantReasonInvalidRequest, ErrInvalid) }
	if _, err := s.AuthorizeActor(ctx, actor, "support:grant", Scope{Kind: ScopeTenant, TenantID: tenantID}, AssurancePassword); err != nil { return SupportGrantView{}, supportGrantError(SupportGrantReasonAuthorizationDenied, err) }
	grant, err := s.store.SupportGrant(ctx, tenantID, grantID)
	if errors.Is(err, ErrNotFound) { return SupportGrantView{}, supportGrantError(SupportGrantReasonNotFound, err) }
	if err != nil { return SupportGrantView{}, supportGrantError(SupportGrantReasonStorageFailure, err) }
	if _, err = s.AuthorizeActor(ctx, actor, "support:grant", grant.Scope, AssurancePassword); err != nil { return SupportGrantView{}, supportGrantError(SupportGrantReasonAuthorizationDenied, err) }
	return supportGrantView(grant), nil
}

func (s *Service) AcceptSupportGrant(ctx context.Context, actor ActorContext, tenantID, grantID ID, expected uint64, secret []byte) (SupportContext, error) {
	defer clearBytes(secret)
	var tx *sql.Tx
	fail := func(code SupportGrantReasonCode, err error) (SupportContext, error) {
		if tx != nil { _ = tx.Rollback(); tx = nil }
		if s != nil { s.supportGrantAudit(ctx, actor.PrincipalID, tenantID, grantID, "support_grant.accept", code) }
		return SupportContext{}, supportGrantError(code, err)
	}
	if s == nil || s.store == nil || ctx == nil || actor.SessionID == "" || !tenantID.Valid() || !grantID.Valid() || expected == 0 || len(secret) < 40 || len(secret) > 128 {
		return fail(SupportGrantReasonInvalidRequest, ErrInvalid)
	}
	if err := s.validateActor(ctx, actor, AssurancePassword); err != nil { return fail(SupportGrantReasonSessionRequired, err) }
	grant, err := s.store.SupportGrant(ctx, tenantID, grantID)
	if errors.Is(err, ErrNotFound) { return fail(SupportGrantReasonNotFound, ErrUnauthenticated) }
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	if _, err = s.AuthorizeActor(ctx, actor, "support:access", Scope{Kind: ScopeInstallation}, AssurancePassword); err != nil { return fail(SupportGrantReasonAuthorizationDenied, err) }
	tx, err = s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	defer func() { if tx != nil { _ = tx.Rollback() } }()
	grant, err = scanSupportGrant(tx.QueryRowContext(ctx, supportGrantSelect+` WHERE target_tenant_id=? AND id=?`, tenantID, grantID))
	if errors.Is(err, ErrNotFound) { return fail(SupportGrantReasonNotFound, ErrUnauthenticated) }
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	expectedDigest := supportGrantDigest(grant.ID, grant.secretEpoch, secret)
	storedDigest := grant.secretDigest
	if !validSupportGrantDigest(storedDigest) { storedDigest = strings.Repeat("0", 64) }
	if subtle.ConstantTimeCompare([]byte(expectedDigest), []byte(storedDigest)) != 1 { return fail(SupportGrantReasonSecretInvalid, ErrUnauthenticated) }
	if grant.Generation != expected { return fail(SupportGrantReasonStaleGeneration, ErrStaleGeneration) }
	if grant.State != SupportGrantPending { return fail(SupportGrantReasonStateConflict, ErrConflict) }
	now := s.clock().UTC()
	if !now.Before(grant.ExpiresAt) {
		previous := grant.Generation
		grant.State = SupportGrantExpired
		grant.Generation++
		grant.secretEpoch++
		grant.secretDigest = ""
		grant.ExpiredAt = &now
		if err = grant.Validate(); err != nil { return fail(SupportGrantReasonStorageFailure, err) }
		result, updateErr := tx.ExecContext(ctx, `UPDATE identity_support_grants SET state=?,generation=?,secret_epoch=?,secret_digest='',expired_at=? WHERE id=? AND target_tenant_id=? AND generation=? AND state=? AND secret_digest=?`, grant.State, grant.Generation, grant.secretEpoch, now, grant.ID, grant.TargetTenantID, previous, SupportGrantPending, expectedDigest)
		if updateErr != nil { return fail(SupportGrantReasonStorageFailure, updateErr) }
		if rows, _ := result.RowsAffected(); rows != 1 { return fail(SupportGrantReasonStaleGeneration, ErrStaleGeneration) }
		if updateErr = tx.Commit(); updateErr != nil { return fail(SupportGrantReasonStorageFailure, updateErr) }
		tx = nil
		return fail(SupportGrantReasonExpired, ErrExpired)
	}
	tenant, err := scanSupportGrantTenant(tx, grant.TargetTenantID)
	if errors.Is(err, ErrNotFound) { return fail(SupportGrantReasonTenantNotFound, err) }
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	if tenant.State != TenantActive { return fail(SupportGrantReasonTenantInactive, ErrSuspended) }
	session, err := scanSession(tx.QueryRowContext(ctx, sessionSelect+` WHERE s.id=?`, actor.SessionID))
	if err != nil || session.PrincipalID != actor.PrincipalID || session.AuthzEpoch != actor.AuthzEpoch || session.RevokedAt != nil || !now.Before(session.ExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		return fail(SupportGrantReasonSessionRequired, ErrUnauthenticated)
	}
	contextID, err := derivedID("supportctx", grant.ID.String()+"\x00"+actor.PrincipalID.String()+"\x00"+actor.SessionID.String())
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	previous := grant.Generation
	grant.State = SupportGrantConsumed
	grant.Generation++
	grant.secretEpoch++
	grant.secretDigest = ""
	grant.ConsumedAt = &now
	grant.ConsumedByPrincipalID = actor.PrincipalID
	grant.ConsumedBySessionID = actor.SessionID
	grant.ContextID = contextID
	contextValue := supportContext(grant)
	if err = grant.Validate(); err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	if err = contextValue.Validate(); err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	result, err := tx.ExecContext(ctx, `UPDATE identity_support_grants SET state=?,generation=?,secret_epoch=?,secret_digest='',consumed_at=?,consumed_by_principal_id=?,consumed_by_session_id=?,context_id=? WHERE id=? AND target_tenant_id=? AND generation=? AND state=? AND secret_digest=?`, grant.State, grant.Generation, grant.secretEpoch, now, grant.ConsumedByPrincipalID, grant.ConsumedBySessionID, grant.ContextID, grant.ID, grant.TargetTenantID, previous, SupportGrantPending, expectedDigest)
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	if rows, _ := result.RowsAffected(); rows != 1 { return fail(SupportGrantReasonStaleGeneration, ErrStaleGeneration) }
	if err = tx.Commit(); err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	tx = nil
	s.supportGrantAudit(ctx, actor.PrincipalID, grant.TargetTenantID, grant.ID, "support_grant.accept", SupportGrantReasonAccepted)
	return contextValue, nil
}

func scanSupportGrantTenant(tx *sql.Tx, id ID) (Tenant, error) {
	var value Tenant
	var kind, state string
	err := tx.QueryRow(`SELECT id,parent_tenant_id,sponsor_id,kind,name,state,plan_id,generation,authz_epoch,created_at,updated_at FROM identity_tenants WHERE id=?`, id).Scan(&value.ID, &value.ParentTenantID, &value.SponsorID, &kind, &value.Name, &state, &value.PlanID, &value.Generation, &value.AuthzEpoch, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) { return Tenant{}, ErrNotFound }
	if err != nil { return Tenant{}, err }
	value.Kind = TenantKind(kind)
	value.State = TenantState(state)
	return value, value.Validate()
}

func supportContext(grant SupportContextGrant) SupportContext {
	return SupportContext{ID: grant.ContextID, GrantID: grant.ID, SupportPrincipalID: grant.ConsumedByPrincipalID, SupportSessionID: grant.ConsumedBySessionID, TargetTenantID: grant.TargetTenantID, Scope: grant.Scope, Permissions: append([]Permission(nil), grant.Permissions...), Reason: grant.Reason, AcceptedAt: *grant.ConsumedAt, ExpiresAt: grant.ExpiresAt}
}

func (s *Service) ResolveSupportContext(ctx context.Context, actor ActorContext, contextID ID, permission Permission, scope Scope) (SupportContext, error) {
	fail := func(code SupportGrantReasonCode, err error, tenant, target ID) (SupportContext, error) {
		if s != nil { s.supportGrantAudit(ctx, actor.PrincipalID, tenant, target, "support_context.resolve", code) }
		return SupportContext{}, supportGrantError(code, err)
	}
	if s == nil || s.store == nil || actor.SessionID == "" || !contextID.Valid() || scope.Validate() != nil { return fail(SupportGrantReasonInvalidRequest, ErrInvalid, scope.TenantID, contextID) }
	if err := s.validateActor(ctx, actor, AssurancePassword); err != nil { return fail(SupportGrantReasonSessionRequired, err, scope.TenantID, contextID) }
	grant, err := scanSupportGrant(s.store.db.QueryRowContext(ctx, supportGrantSelect+` WHERE context_id=?`, contextID))
	if errors.Is(err, ErrNotFound) { return fail(SupportGrantReasonNotFound, ErrNotFound, scope.TenantID, contextID) }
	if err != nil { return fail(SupportGrantReasonStorageFailure, err, scope.TenantID, contextID) }
	if grant.State != SupportGrantConsumed || grant.ContextID != contextID || grant.ConsumedByPrincipalID != actor.PrincipalID || grant.ConsumedBySessionID != actor.SessionID { return fail(SupportGrantReasonAuthorizationDenied, ErrForbidden, grant.TargetTenantID, grant.ID) }
	if !s.clock().UTC().Before(grant.ExpiresAt) { return fail(SupportGrantReasonExpired, ErrExpired, grant.TargetTenantID, grant.ID) }
	if !containsPermission(grant.Permissions, permission) || !scopeContains(grant.Scope, scope) { return fail(SupportGrantReasonCeilingExceeded, ErrForbidden, grant.TargetTenantID, grant.ID) }
	tenant, err := s.store.Tenant(ctx, grant.TargetTenantID)
	if errors.Is(err, ErrNotFound) { return fail(SupportGrantReasonTenantNotFound, ErrNotFound, grant.TargetTenantID, grant.ID) }
	if err != nil { return fail(SupportGrantReasonStorageFailure, err, grant.TargetTenantID, grant.ID) }
	if tenant.State != TenantActive { return fail(SupportGrantReasonTenantInactive, ErrSuspended, grant.TargetTenantID, grant.ID) }
	return supportContext(grant), nil
}

func (s *Service) RevokeSupportGrant(ctx context.Context, actor ActorContext, tenantID, grantID ID, expected uint64) (SupportGrantView, error) {
	var tx *sql.Tx
	fail := func(code SupportGrantReasonCode, err error) (SupportGrantView, error) {
		if tx != nil { _ = tx.Rollback(); tx = nil }
		if s != nil { s.supportGrantAudit(ctx, actor.PrincipalID, tenantID, grantID, "support_grant.revoke", code) }
		return SupportGrantView{}, supportGrantError(code, err)
	}
	if s == nil || s.store == nil || actor.SessionID == "" || !tenantID.Valid() || !grantID.Valid() || expected == 0 { return fail(SupportGrantReasonInvalidRequest, ErrInvalid) }
	if err := s.validateActor(ctx, actor, AssuranceMFA); err != nil { return fail(SupportGrantReasonAssuranceRequired, err) }
	grant, err := s.store.SupportGrant(ctx, tenantID, grantID)
	if errors.Is(err, ErrNotFound) { return fail(SupportGrantReasonNotFound, err) }
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	if _, err = s.AuthorizeActor(ctx, actor, "support:grant", grant.Scope, AssuranceMFA); err != nil { return fail(SupportGrantReasonAuthorizationDenied, err) }
	tx, err = s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	defer func() { if tx != nil { _ = tx.Rollback() } }()
	grant, err = scanSupportGrant(tx.QueryRowContext(ctx, supportGrantSelect+` WHERE target_tenant_id=? AND id=?`, tenantID, grantID))
	if errors.Is(err, ErrNotFound) { return fail(SupportGrantReasonNotFound, err) }
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	if grant.Generation != expected { return fail(SupportGrantReasonStaleGeneration, ErrStaleGeneration) }
	if grant.State != SupportGrantPending && grant.State != SupportGrantConsumed { return fail(SupportGrantReasonStateConflict, ErrConflict) }
	now := s.clock().UTC()
	previous := grant.Generation
	grant.State = SupportGrantRevoked
	grant.Generation++
	grant.secretEpoch++
	grant.secretDigest = ""
	grant.RevokedAt = &now
	grant.RevokedByID = actor.PrincipalID
	if err = grant.Validate(); err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	result, err := tx.ExecContext(ctx, `UPDATE identity_support_grants SET state=?,generation=?,secret_epoch=?,secret_digest='',revoked_at=?,revoked_by_id=? WHERE id=? AND target_tenant_id=? AND generation=? AND (state=? OR state=?)`, grant.State, grant.Generation, grant.secretEpoch, now, grant.RevokedByID, grant.ID, grant.TargetTenantID, previous, SupportGrantPending, SupportGrantConsumed)
	if err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	if rows, _ := result.RowsAffected(); rows != 1 { return fail(SupportGrantReasonStaleGeneration, ErrStaleGeneration) }
	if err = tx.Commit(); err != nil { return fail(SupportGrantReasonStorageFailure, err) }
	tx = nil
	s.supportGrantAudit(ctx, actor.PrincipalID, grant.TargetTenantID, grant.ID, "support_grant.revoke", SupportGrantReasonRevoked)
	return supportGrantView(grant), nil
}
