package identity

import (
	"context"
	"fmt"
	"time"
)

type AuthorizationRepository interface {
	Principal(context.Context, ID) (Principal, error)
	Tenant(context.Context, ID) (Tenant, error)
	Memberships(context.Context, ID) ([]Membership, error)
	Bindings(context.Context, ID) ([]RoleBinding, error)
	Role(context.Context, ID) (Role, error)
	TenantAncestors(context.Context, ID) ([]Tenant, error)
	Delegation(context.Context, ID) (DelegationCeiling, error)
}

type AuthorizationRequest struct {
	PrincipalID ID
	Permission  Permission
	Scope       Scope
	At          time.Time
	Assurance   AssuranceLevel
}

type AuthorizationDecision struct {
	Allowed         bool
	PrincipalID     ID
	Permission      Permission
	Scope           Scope
	PrincipalEpoch  uint64
	TenantEpoch     uint64
	BindingIDs      []ID
	RoleIDs         []ID
	Reason          string
	DecidedAt       time.Time
}

type Authorizer struct { repository AuthorizationRepository }

func NewAuthorizer(repository AuthorizationRepository) (*Authorizer, error) {
	if repository == nil { return nil, fmt.Errorf("%w: authorization repository", ErrInvalid) }
	return &Authorizer{repository: repository}, nil
}

func (a *Authorizer) Decide(ctx context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
	decision := AuthorizationDecision{PrincipalID: request.PrincipalID, Permission: request.Permission, Scope: request.Scope, DecidedAt: request.At}
	if request.At.IsZero() { request.At = time.Now().UTC(); decision.DecidedAt = request.At }
	if !request.PrincipalID.Valid() || (request.Permission != "*:*" && !permissionPattern.MatchString(string(request.Permission))) || request.Scope.Validate() != nil {
		decision.Reason = "invalid_request"
		return decision, fmt.Errorf("%w: authorization request", ErrInvalid)
	}
	principal, err := a.repository.Principal(ctx, request.PrincipalID)
	if err != nil { decision.Reason = "principal_unavailable"; return decision, err }
	decision.PrincipalEpoch = principal.AuthzEpoch
	if principal.State == PrincipalSuspended { decision.Reason = "principal_suspended"; return decision, ErrSuspended }
	if principal.State != PrincipalActive { decision.Reason = "principal_inactive"; return decision, ErrForbidden }
	if request.Scope.Kind != ScopeInstallation {
		tenant, loadErr := a.repository.Tenant(ctx, request.Scope.TenantID)
		if loadErr != nil { decision.Reason = "tenant_unavailable"; return decision, loadErr }
		decision.TenantEpoch = tenant.AuthzEpoch
		if tenant.State != TenantActive { decision.Reason = "tenant_inactive"; return decision, ErrSuspended }
		memberships, membershipErr := a.repository.Memberships(ctx, principal.ID)
		if membershipErr != nil { decision.Reason = "membership_unavailable"; return decision, membershipErr }
		if !hasActiveMembership(memberships, request.Scope.TenantID) {
			ancestors, ancestorErr := a.repository.TenantAncestors(ctx, request.Scope.TenantID)
			if ancestorErr != nil { decision.Reason = "tenant_lineage_unavailable"; return decision, ancestorErr }
			memberTenant, ok := activeMembershipAncestor(memberships, ancestors)
			if !ok { decision.Reason = "not_a_member"; return decision, ErrForbidden }
			ceiling, ceilingErr := a.repository.Delegation(ctx, request.Scope.TenantID)
			if ceilingErr != nil { decision.Reason = "delegation_unavailable"; return decision, ceilingErr }
			if ceiling.SponsorTenantID != memberTenant || !containsPermission(ceiling.Permissions, request.Permission) {
				decision.Reason = "delegation_ceiling"
				return decision, ErrDelegationExceeded
			}
		}
	}
	bindings, err := a.repository.Bindings(ctx, principal.ID)
	if err != nil { decision.Reason = "bindings_unavailable"; return decision, err }
	for _, binding := range bindings {
		if binding.ExpiresAt != nil && !request.At.Before(*binding.ExpiresAt) { continue }
		if !scopeContains(binding.Scope, request.Scope) { continue }
		role, roleErr := a.repository.Role(ctx, binding.RoleID)
		if roleErr != nil { return decision, roleErr }
		if !containsPermission(role.Permissions, request.Permission) { continue }
		decision.Allowed = true
		decision.BindingIDs = append(decision.BindingIDs, binding.ID)
		decision.RoleIDs = append(decision.RoleIDs, role.ID)
	}
	if !decision.Allowed { decision.Reason = "permission_missing"; return decision, ErrForbidden }
	decision.Reason = "allowed"
	return decision, nil
}

func hasActiveMembership(memberships []Membership, tenant ID) bool {
	for _, membership := range memberships { if membership.TenantID == tenant && membership.State == MembershipActive { return true } }
	return false
}

func activeMembershipAncestor(memberships []Membership, ancestors []Tenant) (ID, bool) {
	for _, ancestor := range ancestors { if hasActiveMembership(memberships, ancestor.ID) { return ancestor.ID, true } }
	return "", false
}

func containsPermission(values []Permission, expected Permission) bool {
	for _, value := range values { if value == expected || value == "*:*" { return true } }
	return false
}

func scopeContains(parent Scope, child Scope) bool {
	if parent.Kind == ScopeInstallation { return true }
	if parent.TenantID != child.TenantID { return false }
	switch parent.Kind {
	case ScopeTenant: return true
	case ScopeProject: return child.Kind == ScopeProject && child.ResourceID == parent.ResourceID
	case ScopeSite: return child.Kind == ScopeSite && child.ResourceID == parent.ResourceID
	default: return false
	}
}
