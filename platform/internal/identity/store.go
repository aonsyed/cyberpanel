package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const Schema = `
CREATE TABLE IF NOT EXISTS identity_principals (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, username TEXT NOT NULL UNIQUE,
 email TEXT NOT NULL, display_name TEXT NOT NULL, state TEXT NOT NULL,
 locale TEXT NOT NULL, theme TEXT NOT NULL, authz_epoch BIGINT NOT NULL,
 credential_epoch BIGINT NOT NULL, generation BIGINT NOT NULL,
 created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, deleted_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS identity_tenants (
 id TEXT PRIMARY KEY, parent_tenant_id TEXT NOT NULL, sponsor_id TEXT NOT NULL,
 kind TEXT NOT NULL, name TEXT NOT NULL, state TEXT NOT NULL, plan_id TEXT NOT NULL,
 generation BIGINT NOT NULL, authz_epoch BIGINT NOT NULL,
 created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_memberships (
 id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
 state TEXT NOT NULL, generation BIGINT NOT NULL, created_at TIMESTAMP NOT NULL,
 updated_at TIMESTAMP NOT NULL, UNIQUE(principal_id, tenant_id)
);
CREATE TABLE IF NOT EXISTS identity_invitations (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, intended_email TEXT NOT NULL,
 inviter_id TEXT NOT NULL, role_id TEXT NOT NULL, role_ceiling_json TEXT NOT NULL,
 scope_kind TEXT NOT NULL, resource_id TEXT NOT NULL, state TEXT NOT NULL,
 generation BIGINT NOT NULL, token_epoch BIGINT NOT NULL, token_digest TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL, last_delivered_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS identity_invitations_tenant ON identity_invitations(tenant_id,id);
CREATE UNIQUE INDEX IF NOT EXISTS identity_invitations_token ON identity_invitations(token_digest) WHERE token_digest <> '';
CREATE TABLE IF NOT EXISTS identity_roles (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
 permissions_json TEXT NOT NULL, builtin INTEGER NOT NULL, generation BIGINT NOT NULL,
 created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL,
 UNIQUE(tenant_id, name)
);
CREATE TABLE IF NOT EXISTS identity_role_bindings (
 id TEXT PRIMARY KEY, subject_kind TEXT NOT NULL, subject_id TEXT NOT NULL,
 role_id TEXT NOT NULL, scope_kind TEXT NOT NULL, tenant_id TEXT NOT NULL,
 resource_id TEXT NOT NULL, expires_at TIMESTAMP, generation BIGINT NOT NULL,
 created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_bindings_subject ON identity_role_bindings(subject_id);
CREATE TABLE IF NOT EXISTS identity_delegations (
 id TEXT PRIMARY KEY, sponsor_tenant_id TEXT NOT NULL, child_tenant_id TEXT NOT NULL UNIQUE,
 permissions_json TEXT NOT NULL, quota_json TEXT NOT NULL, generation BIGINT NOT NULL,
 created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_plans (
 id TEXT PRIMARY KEY, owner_tenant_id TEXT NOT NULL, name TEXT NOT NULL,
 quota_json TEXT NOT NULL, generation BIGINT NOT NULL, created_at TIMESTAMP NOT NULL,
 updated_at TIMESTAMP NOT NULL, UNIQUE(owner_tenant_id, name)
);
CREATE TABLE IF NOT EXISTS identity_credentials (
 id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, label TEXT NOT NULL,
 verifier_ref TEXT NOT NULL, public_data BLOB NOT NULL, scopes_json TEXT NOT NULL,
 authz_epoch BIGINT NOT NULL, created_at TIMESTAMP NOT NULL, last_used_at TIMESTAMP,
 expires_at TIMESTAMP, revoked_at TIMESTAMP, compromised_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS identity_credentials_principal ON identity_credentials(principal_id);
CREATE UNIQUE INDEX IF NOT EXISTS identity_credentials_verifier_ref ON identity_credentials(verifier_ref);
CREATE TABLE IF NOT EXISTS identity_sessions (
 id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, credential_id TEXT NOT NULL,
 authz_epoch BIGINT NOT NULL, credential_epoch BIGINT NOT NULL, assurance INTEGER NOT NULL,
 source_prefix TEXT NOT NULL, user_agent_digest TEXT NOT NULL, csrf_secret_digest TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL, last_seen_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL,
 absolute_expires_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS identity_sessions_principal ON identity_sessions(principal_id);
CREATE TABLE IF NOT EXISTS identity_auth_challenges (
 id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, primary_credential_id TEXT NOT NULL,
 mfa_credential_id TEXT NOT NULL, source_prefix TEXT NOT NULL,
 user_agent_digest TEXT NOT NULL, created_at TIMESTAMP NOT NULL,
 expires_at TIMESTAMP NOT NULL, consumed_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS identity_usage (
 tenant_id TEXT PRIMARY KEY, usage_json TEXT NOT NULL, updated_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_commands (
 command_id TEXT PRIMARY KEY, command_digest TEXT NOT NULL, actor_id TEXT NOT NULL,
 tenant_id TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL, completed_at TIMESTAMP
);
`

type Store struct { db *sql.DB; clock func() time.Time }

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil { return nil, fmt.Errorf("%w: database", ErrInvalid) }
	return &Store{db: db, clock: time.Now}, nil
}

func (s *Store) Bootstrap(ctx context.Context) error {
	if s == nil || s.db == nil { return ErrInvalid }
	_, err := s.db.ExecContext(ctx, Schema)
	return err
}

func (s *Store) Principal(ctx context.Context, id ID) (Principal, error) {
	if !id.Valid() { return Principal{}, ErrInvalid }
	return scanPrincipal(s.db.QueryRowContext(ctx, `SELECT id,kind,username,email,display_name,state,locale,theme,authz_epoch,credential_epoch,generation,created_at,updated_at,deleted_at FROM identity_principals WHERE id=?`, id))
}

func (s *Store) PrincipalByUsername(ctx context.Context, username string) (Principal, error) {
	return scanPrincipal(s.db.QueryRowContext(ctx, `SELECT id,kind,username,email,display_name,state,locale,theme,authz_epoch,credential_epoch,generation,created_at,updated_at,deleted_at FROM identity_principals WHERE username=?`, username))
}

func scanPrincipal(row *sql.Row) (Principal, error) {
	var p Principal; var kind, state, theme string; var deleted sql.NullTime
	err := row.Scan(&p.ID,&kind,&p.Username,&p.Email,&p.DisplayName,&state,&p.Locale,&theme,&p.AuthzEpoch,&p.CredentialEpoch,&p.Generation,&p.CreatedAt,&p.UpdatedAt,&deleted)
	if errors.Is(err, sql.ErrNoRows) { return Principal{}, ErrNotFound }
	if err != nil { return Principal{}, err }
	p.Kind=PrincipalKind(kind); p.State=PrincipalState(state); p.Theme=Theme(theme); if deleted.Valid { p.DeletedAt=&deleted.Time }
	if err:=p.Validate(); err!=nil{return Principal{},err}; return p,nil
}

func (s *Store) Tenant(ctx context.Context, id ID) (Tenant, error) {
	var t Tenant; var kind,state string
	err:=s.db.QueryRowContext(ctx,`SELECT id,parent_tenant_id,sponsor_id,kind,name,state,plan_id,generation,authz_epoch,created_at,updated_at FROM identity_tenants WHERE id=?`,id).Scan(&t.ID,&t.ParentTenantID,&t.SponsorID,&kind,&t.Name,&state,&t.PlanID,&t.Generation,&t.AuthzEpoch,&t.CreatedAt,&t.UpdatedAt)
	if errors.Is(err,sql.ErrNoRows){return Tenant{},ErrNotFound}; if err!=nil{return Tenant{},err}; t.Kind=TenantKind(kind);t.State=TenantState(state);if err=t.Validate();err!=nil{return Tenant{},err};return t,nil
}

func (s *Store) Memberships(ctx context.Context, principal ID) ([]Membership,error) {
	rows,err:=s.db.QueryContext(ctx,`SELECT id,principal_id,tenant_id,state,generation,created_at,updated_at FROM identity_memberships WHERE principal_id=?`,principal);if err!=nil{return nil,err};defer rows.Close();var out []Membership
	for rows.Next(){var m Membership;var state string;if err:=rows.Scan(&m.ID,&m.PrincipalID,&m.TenantID,&state,&m.Generation,&m.CreatedAt,&m.UpdatedAt);err!=nil{return nil,err};m.State=MembershipState(state);if err:=m.Validate();err!=nil{return nil,err};out=append(out,m)};return out,rows.Err()
}

func (s *Store) Bindings(ctx context.Context, principal ID) ([]RoleBinding,error) {
	rows,err:=s.db.QueryContext(ctx,`SELECT id,subject_kind,subject_id,role_id,scope_kind,tenant_id,resource_id,expires_at,generation,created_at FROM identity_role_bindings WHERE subject_id=?`,principal);if err!=nil{return nil,err};defer rows.Close();var out []RoleBinding
	for rows.Next(){var b RoleBinding;var subject,scope string;var expiry sql.NullTime;if err:=rows.Scan(&b.ID,&subject,&b.SubjectID,&b.RoleID,&scope,&b.Scope.TenantID,&b.Scope.ResourceID,&expiry,&b.Generation,&b.CreatedAt);err!=nil{return nil,err};b.SubjectKind=SubjectKind(subject);b.Scope.Kind=ScopeKind(scope);if expiry.Valid{b.ExpiresAt=&expiry.Time};if err:=b.Validate();err!=nil{return nil,err};out=append(out,b)};return out,rows.Err()
}

func (s *Store) Role(ctx context.Context,id ID)(Role,error){var r Role;var raw []byte;var builtin int;err:=s.db.QueryRowContext(ctx,`SELECT id,tenant_id,name,permissions_json,builtin,generation,created_at,updated_at FROM identity_roles WHERE id=?`,id).Scan(&r.ID,&r.TenantID,&r.Name,&raw,&builtin,&r.Generation,&r.CreatedAt,&r.UpdatedAt);if errors.Is(err,sql.ErrNoRows){return Role{},ErrNotFound};if err!=nil{return Role{},err};r.Builtin=builtin!=0;if err=json.Unmarshal(raw,&r.Permissions);err!=nil{return Role{},err};if err=r.Validate();err!=nil{return Role{},err};return r,nil}

func (s *Store) TenantAncestors(ctx context.Context,id ID)([]Tenant,error){var out []Tenant;seen:=map[ID]bool{};current,err:=s.Tenant(ctx,id);if err!=nil{return nil,err};for current.ParentTenantID!=""{if seen[current.ParentTenantID]{return nil,fmt.Errorf("%w: tenant cycle",ErrConflict)};seen[current.ParentTenantID]=true;current,err=s.Tenant(ctx,current.ParentTenantID);if err!=nil{return nil,err};out=append(out,current)};return out,nil}

func(s *Store)Delegation(ctx context.Context,child ID)(DelegationCeiling,error){var d DelegationCeiling;var perms,quota []byte;err:=s.db.QueryRowContext(ctx,`SELECT id,sponsor_tenant_id,child_tenant_id,permissions_json,quota_json,generation,created_at,updated_at FROM identity_delegations WHERE child_tenant_id=?`,child).Scan(&d.ID,&d.SponsorTenantID,&d.ChildTenantID,&perms,&quota,&d.Generation,&d.CreatedAt,&d.UpdatedAt);if errors.Is(err,sql.ErrNoRows){return DelegationCeiling{},ErrNotFound};if err!=nil{return DelegationCeiling{},err};if err=json.Unmarshal(perms,&d.Permissions);err!=nil{return d,err};if err=json.Unmarshal(quota,&d.QuotaBudget);err!=nil{return d,err};return d,d.Validate()}

func(s *Store)Plan(ctx context.Context,id ID)(Plan,error){var p Plan;var quota []byte;err:=s.db.QueryRowContext(ctx,`SELECT id,owner_tenant_id,name,quota_json,generation,created_at,updated_at FROM identity_plans WHERE id=?`,id).Scan(&p.ID,&p.OwnerTenantID,&p.Name,&quota,&p.Generation,&p.CreatedAt,&p.UpdatedAt);if errors.Is(err,sql.ErrNoRows){return Plan{},ErrNotFound};if err!=nil{return Plan{},err};if err=json.Unmarshal(quota,&p.Quota);err!=nil{return p,err};return p,p.Validate()}

type TenantMembership struct{ Membership Membership; Principal Principal }

func(s *Store)ListTenants(ctx context.Context,root ID,limit int,cursor ID)([]Tenant,string,uint64,error){if s==nil||s.db==nil||ctx==nil||!root.Valid()||limit<1||limit>200||(cursor!=""&&!cursor.Valid()){return nil,"",0,ErrInvalid};const tree=`WITH RECURSIVE tenant_tree(id) AS (SELECT id FROM identity_tenants WHERE id=? UNION ALL SELECT child.id FROM identity_tenants child JOIN tenant_tree parent ON child.parent_tenant_id=parent.id)`;var total uint64;if err:=s.db.QueryRowContext(ctx,tree+` SELECT COUNT(*) FROM tenant_tree`).Scan(&total);err!=nil{return nil,"",0,err};rows,err:=s.db.QueryContext(ctx,tree+` SELECT t.id,t.parent_tenant_id,t.sponsor_id,t.kind,t.name,t.state,t.plan_id,t.generation,t.authz_epoch,t.created_at,t.updated_at FROM identity_tenants t JOIN tenant_tree tree ON tree.id=t.id WHERE t.id>? ORDER BY t.id LIMIT ?`,root,cursor,limit+1);if err!=nil{return nil,"",0,err};defer rows.Close();values:=make([]Tenant,0,limit);for rows.Next(){var value Tenant;var kind,state string;if err:=rows.Scan(&value.ID,&value.ParentTenantID,&value.SponsorID,&kind,&value.Name,&state,&value.PlanID,&value.Generation,&value.AuthzEpoch,&value.CreatedAt,&value.UpdatedAt);err!=nil{return nil,"",0,err};value.Kind=TenantKind(kind);value.State=TenantState(state);if err:=value.Validate();err!=nil{return nil,"",0,err};values=append(values,value)};if err:=rows.Err();err!=nil{return nil,"",0,err};next:="";if len(values)>limit{next=values[limit-1].ID.String();values=values[:limit]};return values,next,total,nil}

func(s *Store)ListTenantMemberships(ctx context.Context,tenant ID,limit int,cursor ID)([]TenantMembership,string,uint64,error){if s==nil||s.db==nil||ctx==nil||!tenant.Valid()||limit<1||limit>200||(cursor!=""&&!cursor.Valid()){return nil,"",0,ErrInvalid};var total uint64;if err:=s.db.QueryRowContext(ctx,`SELECT COUNT(*) FROM identity_memberships WHERE tenant_id=?`,tenant).Scan(&total);err!=nil{return nil,"",0,err};rows,err:=s.db.QueryContext(ctx,`SELECT m.id,m.principal_id,m.tenant_id,m.state,m.generation,m.created_at,m.updated_at,p.id,p.kind,p.username,p.email,p.display_name,p.state,p.locale,p.theme,p.authz_epoch,p.credential_epoch,p.generation,p.created_at,p.updated_at,p.deleted_at FROM identity_memberships m JOIN identity_principals p ON p.id=m.principal_id WHERE m.tenant_id=? AND m.id>? ORDER BY m.id LIMIT ?`,tenant,cursor,limit+1);if err!=nil{return nil,"",0,err};defer rows.Close();values:=make([]TenantMembership,0,limit);for rows.Next(){var value TenantMembership;var membershipState,principalKind,principalState,theme string;var deleted sql.NullTime;if err:=rows.Scan(&value.Membership.ID,&value.Membership.PrincipalID,&value.Membership.TenantID,&membershipState,&value.Membership.Generation,&value.Membership.CreatedAt,&value.Membership.UpdatedAt,&value.Principal.ID,&principalKind,&value.Principal.Username,&value.Principal.Email,&value.Principal.DisplayName,&principalState,&value.Principal.Locale,&theme,&value.Principal.AuthzEpoch,&value.Principal.CredentialEpoch,&value.Principal.Generation,&value.Principal.CreatedAt,&value.Principal.UpdatedAt,&deleted);err!=nil{return nil,"",0,err};value.Membership.State=MembershipState(membershipState);value.Principal.Kind=PrincipalKind(principalKind);value.Principal.State=PrincipalState(principalState);value.Principal.Theme=Theme(theme);if deleted.Valid{value.Principal.DeletedAt=&deleted.Time};if value.Membership.Validate()!=nil||value.Principal.Validate()!=nil{return nil,"",0,ErrInvalid};values=append(values,value)};if err:=rows.Err();err!=nil{return nil,"",0,err};next:="";if len(values)>limit{next=values[limit-1].Membership.ID.String();values=values[:limit]};return values,next,total,nil}

func(s *Store)ListTenantRoleBindings(ctx context.Context,tenant ID,limit int,cursor ID)([]RoleBinding,string,uint64,error){if s==nil||s.db==nil||ctx==nil||!tenant.Valid()||limit<1||limit>200||(cursor!=""&&!cursor.Valid()){return nil,"",0,ErrInvalid};var total uint64;if err:=s.db.QueryRowContext(ctx,`SELECT COUNT(*) FROM identity_role_bindings WHERE tenant_id=? AND subject_kind='principal'`,tenant).Scan(&total);err!=nil{return nil,"",0,err};rows,err:=s.db.QueryContext(ctx,`SELECT id,subject_kind,subject_id,role_id,scope_kind,tenant_id,resource_id,expires_at,generation,created_at FROM identity_role_bindings WHERE tenant_id=? AND subject_kind='principal' AND id>? ORDER BY id LIMIT ?`,tenant,cursor,limit+1);if err!=nil{return nil,"",0,err};defer rows.Close();values:=make([]RoleBinding,0,limit);for rows.Next(){var value RoleBinding;var subject,scope string;var expiry sql.NullTime;if err:=rows.Scan(&value.ID,&subject,&value.SubjectID,&value.RoleID,&scope,&value.Scope.TenantID,&value.Scope.ResourceID,&expiry,&value.Generation,&value.CreatedAt);err!=nil{return nil,"",0,err};value.SubjectKind=SubjectKind(subject);value.Scope.Kind=ScopeKind(scope);if expiry.Valid{value.ExpiresAt=&expiry.Time};if err:=value.Validate();err!=nil{return nil,"",0,err};values=append(values,value)};if err:=rows.Err();err!=nil{return nil,"",0,err};next:="";if len(values)>limit{next=values[limit-1].ID.String();values=values[:limit]};return values,next,total,nil}

func(s *Store)Usage(ctx context.Context,tenant ID)(Usage,error){var u Usage;var raw []byte;err:=s.db.QueryRowContext(ctx,`SELECT usage_json,updated_at FROM identity_usage WHERE tenant_id=?`,tenant).Scan(&raw,&u.UpdatedAt);if errors.Is(err,sql.ErrNoRows){return Usage{TenantID:tenant},nil};if err!=nil{return Usage{},err};if err=json.Unmarshal(raw,&u);err!=nil{return Usage{},err};if u.TenantID!=tenant{return Usage{},ErrConflict};return u,nil}

func(s *Store)Credential(ctx context.Context,id ID)(Credential,error){var c Credential;var kind,state string;var scopes []byte;var last,expires,revoked,compromised sql.NullTime;err:=s.db.QueryRowContext(ctx,`SELECT id,principal_id,kind,state,label,verifier_ref,public_data,scopes_json,authz_epoch,created_at,last_used_at,expires_at,revoked_at,compromised_at FROM identity_credentials WHERE id=?`,id).Scan(&c.ID,&c.PrincipalID,&kind,&state,&c.Label,&c.VerifierRef,&c.PublicData,&scopes,&c.AuthzEpoch,&c.CreatedAt,&last,&expires,&revoked,&compromised);if errors.Is(err,sql.ErrNoRows){return Credential{},ErrNotFound};if err!=nil{return Credential{},err};c.Kind=CredentialKind(kind);c.State=CredentialState(state);if err=json.Unmarshal(scopes,&c.Scopes);err!=nil{return c,err};if last.Valid{c.LastUsedAt=&last.Time};if expires.Valid{c.ExpiresAt=&expires.Time};if revoked.Valid{c.RevokedAt=&revoked.Time};if compromised.Valid{c.CompromisedAt=&compromised.Time};return c,c.Validate()}

func(s *Store)CredentialByVerifierRef(ctx context.Context,ref ID)(Credential,error){if !ref.Valid(){return Credential{},ErrInvalid};var id ID;err:=s.db.QueryRowContext(ctx,`SELECT id FROM identity_credentials WHERE verifier_ref=?`,ref).Scan(&id);if errors.Is(err,sql.ErrNoRows){return Credential{},ErrNotFound};if err!=nil{return Credential{},err};return s.Credential(ctx,id)}

func(s *Store)Session(ctx context.Context,id ID)(Session,error){var value Session;var prefix string;var revoked sql.NullTime;err:=s.db.QueryRowContext(ctx,`SELECT id,principal_id,credential_id,authz_epoch,credential_epoch,assurance,source_prefix,user_agent_digest,csrf_secret_digest,created_at,last_seen_at,expires_at,absolute_expires_at,revoked_at FROM identity_sessions WHERE id=?`,id).Scan(&value.ID,&value.PrincipalID,&value.CredentialID,&value.AuthzEpoch,&value.CredentialEpoch,&value.Assurance,&prefix,&value.UserAgentDigest,&value.CSRFSecretDigest,&value.CreatedAt,&value.LastSeenAt,&value.ExpiresAt,&value.AbsoluteExpiresAt,&revoked);if errors.Is(err,sql.ErrNoRows){return Session{},ErrNotFound};if err!=nil{return Session{},err};value.SourcePrefix,err=netip.ParsePrefix(prefix);if err!=nil{return Session{},err};if revoked.Valid{value.RevokedAt=&revoked.Time};return value,value.Validate()}

type Mutation struct{ Principal *Principal; Tenant *Tenant; Membership *Membership; Role *Role; Binding *RoleBinding; Delegation *DelegationCeiling; Plan *Plan; Credential *Credential; Session *Session; Usage *Usage }

func(s *Store)Apply(ctx context.Context,mutation Mutation)error{if s==nil||s.db==nil{return ErrInvalid};tx,err:=s.db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return err};defer tx.Rollback();if mutation.Principal!=nil{err=putPrincipal(ctx,tx,*mutation.Principal)};if err==nil&&mutation.Tenant!=nil{err=putTenant(ctx,tx,*mutation.Tenant)};if err==nil&&mutation.Membership!=nil{err=putMembership(ctx,tx,*mutation.Membership)};if err==nil&&mutation.Role!=nil{err=putRole(ctx,tx,*mutation.Role)};if err==nil&&mutation.Binding!=nil{err=putBinding(ctx,tx,*mutation.Binding)};if err==nil&&mutation.Delegation!=nil{err=putDelegation(ctx,tx,*mutation.Delegation)};if err==nil&&mutation.Plan!=nil{err=putPlan(ctx,tx,*mutation.Plan)};if err==nil&&mutation.Credential!=nil{err=putCredential(ctx,tx,*mutation.Credential)};if err==nil&&mutation.Session!=nil{err=putSession(ctx,tx,*mutation.Session)};if err==nil&&mutation.Usage!=nil{err=putUsage(ctx,tx,*mutation.Usage)};if err!=nil{return err};return tx.Commit()}

func putPrincipal(ctx context.Context,tx *sql.Tx,p Principal)error{if err:=p.Validate();err!=nil{return err};_,err:=tx.ExecContext(ctx,`INSERT INTO identity_principals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET email=excluded.email,display_name=excluded.display_name,state=excluded.state,locale=excluded.locale,theme=excluded.theme,authz_epoch=excluded.authz_epoch,credential_epoch=excluded.credential_epoch,generation=excluded.generation,updated_at=excluded.updated_at,deleted_at=excluded.deleted_at WHERE identity_principals.generation+1=excluded.generation`,p.ID,p.Kind,p.Username,p.Email,p.DisplayName,p.State,p.Locale,p.Theme,p.AuthzEpoch,p.CredentialEpoch,p.Generation,p.CreatedAt,p.UpdatedAt,p.DeletedAt);return err}
func putTenant(ctx context.Context,tx *sql.Tx,t Tenant)error{if err:=t.Validate();err!=nil{return err};_,err:=tx.ExecContext(ctx,`INSERT INTO identity_tenants VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,state=excluded.state,plan_id=excluded.plan_id,generation=excluded.generation,authz_epoch=excluded.authz_epoch,updated_at=excluded.updated_at WHERE identity_tenants.generation+1=excluded.generation`,t.ID,t.ParentTenantID,t.SponsorID,t.Kind,t.Name,t.State,t.PlanID,t.Generation,t.AuthzEpoch,t.CreatedAt,t.UpdatedAt);return err}
func putMembership(ctx context.Context,tx *sql.Tx,m Membership)error{if err:=m.Validate();err!=nil{return err};_,err:=tx.ExecContext(ctx,`INSERT INTO identity_memberships VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,generation=excluded.generation,updated_at=excluded.updated_at WHERE identity_memberships.generation+1=excluded.generation`,m.ID,m.PrincipalID,m.TenantID,m.State,m.Generation,m.CreatedAt,m.UpdatedAt);return err}
func putRole(ctx context.Context,tx *sql.Tx,r Role)error{if err:=r.Validate();err!=nil{return err};raw,_:=json.Marshal(CanonicalPermissions(r.Permissions));_,err:=tx.ExecContext(ctx,`INSERT INTO identity_roles VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,permissions_json=excluded.permissions_json,generation=excluded.generation,updated_at=excluded.updated_at WHERE identity_roles.generation+1=excluded.generation`,r.ID,r.TenantID,r.Name,raw,boolInt(r.Builtin),r.Generation,r.CreatedAt,r.UpdatedAt);return err}
func putBinding(ctx context.Context,tx *sql.Tx,b RoleBinding)error{if err:=b.Validate();err!=nil{return err};_,err:=tx.ExecContext(ctx,`INSERT INTO identity_role_bindings VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET role_id=excluded.role_id,scope_kind=excluded.scope_kind,tenant_id=excluded.tenant_id,resource_id=excluded.resource_id,expires_at=excluded.expires_at,generation=excluded.generation WHERE identity_role_bindings.generation+1=excluded.generation`,b.ID,b.SubjectKind,b.SubjectID,b.RoleID,b.Scope.Kind,b.Scope.TenantID,b.Scope.ResourceID,b.ExpiresAt,b.Generation,b.CreatedAt);return err}
func putDelegation(ctx context.Context,tx *sql.Tx,d DelegationCeiling)error{if err:=d.Validate();err!=nil{return err};p,_:=json.Marshal(CanonicalPermissions(d.Permissions));q,_:=json.Marshal(d.QuotaBudget);_,err:=tx.ExecContext(ctx,`INSERT INTO identity_delegations VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET permissions_json=excluded.permissions_json,quota_json=excluded.quota_json,generation=excluded.generation,updated_at=excluded.updated_at WHERE identity_delegations.generation+1=excluded.generation`,d.ID,d.SponsorTenantID,d.ChildTenantID,p,q,d.Generation,d.CreatedAt,d.UpdatedAt);return err}
func putPlan(ctx context.Context,tx *sql.Tx,p Plan)error{if err:=p.Validate();err!=nil{return err};q,_:=json.Marshal(p.Quota);_,err:=tx.ExecContext(ctx,`INSERT INTO identity_plans VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,quota_json=excluded.quota_json,generation=excluded.generation,updated_at=excluded.updated_at WHERE identity_plans.generation+1=excluded.generation`,p.ID,p.OwnerTenantID,p.Name,q,p.Generation,p.CreatedAt,p.UpdatedAt);return err}
func putCredential(ctx context.Context,tx *sql.Tx,c Credential)error{if err:=c.Validate();err!=nil{return err};scopes,_:=json.Marshal(CanonicalPermissions(c.Scopes));_,err:=tx.ExecContext(ctx,`INSERT INTO identity_credentials VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,label=excluded.label,public_data=excluded.public_data,scopes_json=excluded.scopes_json,last_used_at=excluded.last_used_at,expires_at=excluded.expires_at,revoked_at=excluded.revoked_at,compromised_at=excluded.compromised_at`,c.ID,c.PrincipalID,c.Kind,c.State,c.Label,c.VerifierRef,c.PublicData,scopes,c.AuthzEpoch,c.CreatedAt,c.LastUsedAt,c.ExpiresAt,c.RevokedAt,c.CompromisedAt);return err}
func putSession(ctx context.Context,tx *sql.Tx,s Session)error{if err:=s.Validate();err!=nil{return err};_,err:=tx.ExecContext(ctx,`INSERT INTO identity_sessions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen_at=excluded.last_seen_at,expires_at=excluded.expires_at,revoked_at=excluded.revoked_at`,s.ID,s.PrincipalID,s.CredentialID,s.AuthzEpoch,s.CredentialEpoch,s.Assurance,s.SourcePrefix.String(),s.UserAgentDigest,s.CSRFSecretDigest,s.CreatedAt,s.LastSeenAt,s.ExpiresAt,s.AbsoluteExpiresAt,s.RevokedAt);return err}
func putUsage(ctx context.Context,tx *sql.Tx,u Usage)error{if !u.TenantID.Valid(){return ErrInvalid};raw,_:=json.Marshal(u);_,err:=tx.ExecContext(ctx,`INSERT INTO identity_usage VALUES(?,?,?) ON CONFLICT(tenant_id) DO UPDATE SET usage_json=excluded.usage_json,updated_at=excluded.updated_at`,u.TenantID,raw,u.UpdatedAt);return err}
func boolInt(value bool)int{if value{return 1};return 0}
