package identity

import (
	"context"
	"sort"
	"time"
)

type ViewerTenant struct {
	MembershipID ID `json:"membership_id"`
	TenantID ID `json:"tenant_id"`
	Name string `json:"name"`
	Kind TenantKind `json:"kind"`
	MembershipState MembershipState `json:"membership_state"`
	TenantState TenantState `json:"tenant_state"`
	Selectable bool `json:"selectable"`
}

type ViewerProjection struct {
	PrincipalID ID `json:"principal_id"`
	Username string `json:"username"`
	Email string `json:"email"`
	DisplayName string `json:"display_name"`
	Locale string `json:"locale"`
	Theme Theme `json:"theme"`
	Assurance AssuranceLevel `json:"assurance"`
	AuthzEpoch uint64 `json:"authz_epoch"`
	SessionExpiresAt *time.Time `json:"session_expires_at,omitempty"`
	Tenants []ViewerTenant `json:"tenants"`
}

func (s *Service) CurrentViewer(ctx context.Context,actor ActorContext)(ViewerProjection,error){
	if s==nil||s.store==nil{return ViewerProjection{},ErrInvalid}
	if err:=s.validateActor(ctx,actor,AssurancePassword);err!=nil{return ViewerProjection{},err}
	principal,err:=s.store.Principal(ctx,actor.PrincipalID);if err!=nil{return ViewerProjection{},err}
	memberships,err:=s.store.Memberships(ctx,principal.ID);if err!=nil{return ViewerProjection{},err}
	viewer:=ViewerProjection{PrincipalID:principal.ID,Username:principal.Username,Email:principal.Email,DisplayName:principal.DisplayName,Locale:principal.Locale,Theme:principal.Theme,Assurance:actor.Assurance,AuthzEpoch:principal.AuthzEpoch,Tenants:make([]ViewerTenant,0,len(memberships))}
	if actor.SessionID!=""{session,loadErr:=s.store.Session(ctx,actor.SessionID);if loadErr!=nil{return ViewerProjection{},loadErr};expires:=session.ExpiresAt;viewer.SessionExpiresAt=&expires}
	for _,membership:=range memberships{
		tenant,loadErr:=s.store.Tenant(ctx,membership.TenantID);if loadErr!=nil{if loadErr==ErrNotFound{continue};return ViewerProjection{},loadErr}
		viewer.Tenants=append(viewer.Tenants,ViewerTenant{MembershipID:membership.ID,TenantID:tenant.ID,Name:tenant.Name,Kind:tenant.Kind,MembershipState:membership.State,TenantState:tenant.State,Selectable:membership.State==MembershipActive&&tenant.State==TenantActive})
	}
	sort.Slice(viewer.Tenants,func(left,right int)bool{if viewer.Tenants[left].Selectable!=viewer.Tenants[right].Selectable{return viewer.Tenants[left].Selectable};if viewer.Tenants[left].Name!=viewer.Tenants[right].Name{return viewer.Tenants[left].Name<viewer.Tenants[right].Name};return viewer.Tenants[left].TenantID<viewer.Tenants[right].TenantID})
	return viewer,nil
}

func (s *Service) RevokeCurrentSession(ctx context.Context,actor ActorContext)error{
	if s==nil||s.store==nil||actor.SessionID==""{return ErrInvalid}
	if err:=s.validateActor(ctx,actor,AssurancePassword);err!=nil{return err}
	session,err:=s.store.Session(ctx,actor.SessionID);if err!=nil{return err}
	if session.PrincipalID!=actor.PrincipalID||session.CredentialID!=actor.CredentialID{return ErrForbidden}
	if session.RevokedAt!=nil{return nil}
	now:=s.clock().UTC();session.RevokedAt=&now
	if err=s.store.Apply(ctx,Mutation{Session:&session});err!=nil{return err}
	s.record(ctx,actor.PrincipalID,"","session.revoke","session",session.ID,"applied",session.ID.String())
	return nil
}
