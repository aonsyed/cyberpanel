package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	tenantMaximumDepth      = 32
	tenantMaximumChildren   = 10000
	tenantMaximumPage       = 100
	tenantDeletionRetention = 7 * 24 * time.Hour
)

type TenantLifecycleState string

const (
	TenantLifecycleActive          TenantLifecycleState = "active"
	TenantLifecycleSuspended       TenantLifecycleState = "suspended"
	TenantLifecycleDeletionPending TenantLifecycleState = "deletion_pending"
	TenantLifecycleDeleted         TenantLifecycleState = "deleted"
)

type TenantField string

const (
	TenantFieldName                   TenantField = "name"
	TenantFieldPermissions            TenantField = "permissions"
	TenantFieldSelectors              TenantField = "selectors"
	TenantFieldQuota                  TenantField = "quota"
	TenantFieldMaximumChildDepth      TenantField = "maximum_child_depth"
	TenantFieldMaximumChildCount      TenantField = "maximum_child_count"
	TenantFieldAllowServicePrincipals TenantField = "allow_service_principals"
	TenantFieldAllowRoleBindings      TenantField = "allow_role_bindings"
	TenantFieldValidUntil             TenantField = "valid_until"
	TenantFieldPlanReference          TenantField = "plan_reference"
)

type TenantDelegationPolicy struct {
	DelegationID          ID
	Permissions           []Permission
	Selectors             []Scope
	Quota                  ResourceQuota
	MaximumChildDepth      uint8
	MaximumChildCount      uint32
	AllowServicePrincipals bool
	AllowRoleBindings      bool
	ValidUntil             *time.Time
	PlanCeilingID          ID
	Provenance             []ID
}

type ManagedTenant struct {
	Tenant
	LifecycleState       TenantLifecycleState
	ManagerPrincipalID   ID
	ManagerMembershipID  ID
	ManagerBindingID     ID
	Delegation           TenantDelegationPolicy
	OwnershipContacts    []ID
	Revision             uint64
	SuspendedAt          *time.Time
	DeletionRequestedAt  *time.Time
	RetentionDeadline    *time.Time
	DeletedAt            *time.Time
}

func (value ManagedTenant) Validate() error {
	if value.Tenant.Validate() != nil || value.Kind == TenantOwner || !value.ManagerPrincipalID.Valid() || !value.ManagerMembershipID.Valid() || !value.ManagerBindingID.Valid() || value.Revision == 0 || value.AuthzEpoch == 0 {
		return fmt.Errorf("%w: managed tenant identity", ErrInvalid)
	}
	policy := value.Delegation
	if !policy.DelegationID.Valid() || !policy.PlanCeilingID.Valid() || policy.Quota.Validate() != nil || policy.MaximumChildDepth > tenantMaximumDepth || policy.MaximumChildCount > tenantMaximumChildren {
		return fmt.Errorf("%w: tenant delegation", ErrInvalid)
	}
	if len(policy.Permissions) == 0 || len(policy.Permissions) > 128 || len(policy.Selectors) == 0 || len(policy.Selectors) > 32 || len(policy.Provenance) == 0 || len(policy.Provenance) > 128 {
		return fmt.Errorf("%w: tenant delegation bounds", ErrInvalid)
	}
	if !samePermissions(policy.Permissions, CanonicalPermissions(policy.Permissions)) { return fmt.Errorf("%w: tenant permissions", ErrInvalid) }
	for _, permission := range policy.Permissions { if permission == "*:*" { return fmt.Errorf("%w: delegated wildcard", ErrInvalid) } }
	if validateTenantSelectors(value.ID, policy.Selectors) != nil { return fmt.Errorf("%w: tenant selectors", ErrInvalid) }
	for _, id := range policy.Provenance { if !id.Valid() { return fmt.Errorf("%w: tenant provenance", ErrInvalid) } }
	if len(value.OwnershipContacts) == 0 || len(value.OwnershipContacts) > 32 { return fmt.Errorf("%w: ownership contacts", ErrInvalid) }
	seen := map[ID]bool{}
	for _, id := range value.OwnershipContacts { if !id.Valid() || seen[id] { return fmt.Errorf("%w: ownership contacts", ErrInvalid) }; seen[id] = true }
	switch value.LifecycleState {
	case TenantLifecycleActive:
		if value.State != TenantActive || value.SuspendedAt != nil || value.DeletionRequestedAt != nil || value.RetentionDeadline != nil || value.DeletedAt != nil { return fmt.Errorf("%w: active tenant lifecycle", ErrInvalid) }
	case TenantLifecycleSuspended:
		if value.State != TenantSuspended || value.SuspendedAt == nil || value.DeletionRequestedAt != nil || value.RetentionDeadline != nil || value.DeletedAt != nil { return fmt.Errorf("%w: suspended tenant lifecycle", ErrInvalid) }
	case TenantLifecycleDeletionPending:
		if value.State != TenantDeleting || value.DeletionRequestedAt == nil || value.RetentionDeadline == nil || value.DeletedAt != nil { return fmt.Errorf("%w: deleting tenant lifecycle", ErrInvalid) }
	case TenantLifecycleDeleted:
		if value.State != TenantDeleted || value.DeletedAt == nil { return fmt.Errorf("%w: deleted tenant lifecycle", ErrInvalid) }
	default:
		return fmt.Errorf("%w: tenant lifecycle", ErrInvalid)
	}
	return nil
}

type CreateManagedTenantCommand struct {
	CommandID              ID
	Actor                  ActorContext
	TenantID               ID
	ParentTenantID         ID
	ManagerPrincipalID     ID
	ManagerMembershipID    ID
	ManagerBindingID       ID
	DelegationID           ID
	Kind                   TenantKind
	Name                   string
	PlanReferenceID        ID
	Permissions            []Permission
	Selectors              []Scope
	Quota                  ResourceQuota
	MaximumChildDepth      uint8
	MaximumChildCount      uint32
	AllowServicePrincipals bool
	AllowRoleBindings      bool
	ValidUntil             *time.Time
	OwnershipContacts      []ID
}

type UpdateManagedTenantCommand struct {
	CommandID              ID
	Actor                  ActorContext
	AdministrativeTenantID ID
	TenantID               ID
	ExpectedRevision       uint64
	FieldMask              []TenantField
	Name                   string
	PlanReferenceID        ID
	Permissions            []Permission
	Selectors              []Scope
	Quota                  ResourceQuota
	MaximumChildDepth      uint8
	MaximumChildCount      uint32
	AllowServicePrincipals bool
	AllowRoleBindings      bool
	ValidUntil             *time.Time
}

type TenantTransitionCommand struct {
	CommandID              ID
	Actor                  ActorContext
	AdministrativeTenantID ID
	TenantID               ID
	ExpectedRevision       uint64
	ApprovalID             ID
}

type TransferTenantParentCommand struct {
	CommandID              ID
	Actor                  ActorContext
	AdministrativeTenantID ID
	TenantID               ID
	NewParentTenantID      ID
	DelegationID           ID
	ExpectedRevision       uint64
	ApprovalID             ID
}

type TenantApproval struct {
	ID             ID
	Action         string
	TargetTenantID ID
	RequestDigest  string
	ApprovedByID   ID
	ApprovedAt     time.Time
	ExpiresAt      time.Time
}

func (value TenantApproval) Validate() error {
	if !value.ID.Valid() || !value.TargetTenantID.Valid() || !value.ApprovedByID.Valid() || len(value.Action) < 3 || len(value.Action) > 64 || len(value.RequestDigest) != 64 || value.ApprovedAt.IsZero() || !value.ExpiresAt.After(value.ApprovedAt) {
		return fmt.Errorf("%w: tenant approval", ErrInvalid)
	}
	if _, err := hex.DecodeString(value.RequestDigest); err != nil { return fmt.Errorf("%w: tenant approval digest", ErrInvalid) }
	return nil
}

// RecordTenantApproval is the persistence seam for the protected approval
// coordinator. Lifecycle commands consume these immutable, independently
// approved records exactly once; API payloads cannot manufacture approvals.
func (s *Store) RecordTenantApproval(ctx context.Context, value TenantApproval) error {
	if s == nil || s.db == nil || ctx == nil || value.Validate() != nil { return ErrInvalid }
	_, err := s.db.ExecContext(ctx, `INSERT INTO identity_tenant_approvals(id,action,target_tenant_id,request_digest,approved_by_id,approved_at,expires_at,consumed_at,consumed_command_id) VALUES(?,?,?,?,?,?,?,NULL,'')`, value.ID, value.Action, value.TargetTenantID, value.RequestDigest, value.ApprovedByID, value.ApprovedAt, value.ExpiresAt)
	return err
}

type TenantDeletionImpact struct {
	TenantID                 ID
	Revision                 uint64
	LiveChildCount           uint64
	ResourceOwnershipCount   uint64
	UsagePresent             bool
	ActiveServicePrincipals  uint64
	ActiveRoleBindingCount   uint64
	ActiveOwnerCount         uint64
	RetentionDeadline        *time.Time
	CanQuarantine            bool
	CanPurge                 bool
	RequestDigest            string
}

type TenantTransferImpact struct {
	TenantID          ID
	NewParentTenantID ID
	Revision          uint64
	Blockers          []string
	RequestDigest     string
}

const managedTenantSelect = `SELECT t.id,t.parent_tenant_id,t.sponsor_id,t.kind,t.name,t.state,t.plan_id,t.generation,t.authz_epoch,t.created_at,t.updated_at,l.delegation_id,l.manager_principal_id,l.manager_membership_id,l.manager_binding_id,l.permissions_json,l.selectors_json,l.quota_json,l.maximum_child_depth,l.maximum_child_count,l.allow_service_principals,l.allow_role_bindings,l.valid_until,l.plan_ceiling_id,l.ownership_contacts_json,l.provenance_json,l.revision,l.authz_epoch,l.suspended_at,l.deletion_requested_at,l.retention_deadline,l.deleted_at FROM identity_tenants t JOIN identity_tenant_lifecycle l ON l.tenant_id=t.id`

type tenantScanner interface { Scan(...any) error }

func scanManagedTenant(row tenantScanner) (ManagedTenant, error) {
	var value ManagedTenant
	var kind, state string
	var permissions, selectors, quota, contacts, provenance []byte
	var allowService, allowBindings int
	var validUntil, suspendedAt, deletionAt, retention, deletedAt sql.NullTime
	var lifecycleEpoch uint64
	err := row.Scan(&value.ID, &value.ParentTenantID, &value.SponsorID, &kind, &value.Name, &state, &value.PlanID, &value.Generation, &value.AuthzEpoch, &value.CreatedAt, &value.UpdatedAt, &value.Delegation.DelegationID, &value.ManagerPrincipalID, &value.ManagerMembershipID, &value.ManagerBindingID, &permissions, &selectors, &quota, &value.Delegation.MaximumChildDepth, &value.Delegation.MaximumChildCount, &allowService, &allowBindings, &validUntil, &value.Delegation.PlanCeilingID, &contacts, &provenance, &value.Revision, &lifecycleEpoch, &suspendedAt, &deletionAt, &retention, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) { return ManagedTenant{}, ErrNotFound }
	if err != nil { return ManagedTenant{}, err }
	value.Kind, value.State = TenantKind(kind), TenantState(state)
	if lifecycleEpoch != value.AuthzEpoch { return ManagedTenant{}, fmt.Errorf("%w: tenant epoch divergence", ErrConflict) }
	if json.Unmarshal(permissions, &value.Delegation.Permissions) != nil || json.Unmarshal(selectors, &value.Delegation.Selectors) != nil || json.Unmarshal(quota, &value.Delegation.Quota) != nil || json.Unmarshal(contacts, &value.OwnershipContacts) != nil || json.Unmarshal(provenance, &value.Delegation.Provenance) != nil { return ManagedTenant{}, ErrInvalid }
	value.Delegation.AllowServicePrincipals, value.Delegation.AllowRoleBindings = allowService != 0, allowBindings != 0
	if validUntil.Valid { expiry := validUntil.Time; value.Delegation.ValidUntil = &expiry }
	if suspendedAt.Valid { at := suspendedAt.Time; value.SuspendedAt = &at }
	if deletionAt.Valid { at := deletionAt.Time; value.DeletionRequestedAt = &at }
	if retention.Valid { at := retention.Time; value.RetentionDeadline = &at }
	if deletedAt.Valid { at := deletedAt.Time; value.DeletedAt = &at }
	switch value.State { case TenantActive: value.LifecycleState = TenantLifecycleActive; case TenantSuspended: value.LifecycleState = TenantLifecycleSuspended; case TenantDeleting: value.LifecycleState = TenantLifecycleDeletionPending; case TenantDeleted: value.LifecycleState = TenantLifecycleDeleted }
	return value, value.Validate()
}

func (s *Store) ManagedTenant(ctx context.Context, id ID) (ManagedTenant, error) {
	if s == nil || s.db == nil || ctx == nil || !id.Valid() { return ManagedTenant{}, ErrInvalid }
	return scanManagedTenant(s.db.QueryRowContext(ctx, managedTenantSelect+` WHERE t.id=?`, id))
}

func tenantTx(ctx context.Context, tx *sql.Tx, id ID) (Tenant, error) {
	var value Tenant
	var kind, state string
	err := tx.QueryRowContext(ctx, `SELECT id,parent_tenant_id,sponsor_id,kind,name,state,plan_id,generation,authz_epoch,created_at,updated_at FROM identity_tenants WHERE id=?`, id).Scan(&value.ID, &value.ParentTenantID, &value.SponsorID, &kind, &value.Name, &state, &value.PlanID, &value.Generation, &value.AuthzEpoch, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) { return Tenant{}, ErrNotFound }; if err != nil { return Tenant{}, err }
	value.Kind, value.State = TenantKind(kind), TenantState(state)
	return value, value.Validate()
}

func managedTenantTx(ctx context.Context, tx *sql.Tx, id ID) (ManagedTenant, error) { return scanManagedTenant(tx.QueryRowContext(ctx, managedTenantSelect+` WHERE t.id=?`, id)) }

func planTx(ctx context.Context, tx *sql.Tx, id ID) (Plan, error) {
	var value Plan; var quota []byte
	err := tx.QueryRowContext(ctx, `SELECT id,owner_tenant_id,name,quota_json,generation,created_at,updated_at FROM identity_plans WHERE id=?`, id).Scan(&value.ID, &value.OwnerTenantID, &value.Name, &quota, &value.Generation, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) { return Plan{}, ErrNotFound }; if err != nil { return Plan{}, err }
	if json.Unmarshal(quota, &value.Quota) != nil { return Plan{}, ErrInvalid }
	return value, value.Validate()
}

func validateTenantSelectors(tenantID ID, values []Scope) error {
	if !tenantID.Valid() || len(values) == 0 || len(values) > 32 { return ErrInvalid }
	previous := ""
	for _, value := range values {
		if value.Validate() != nil || value.Kind == ScopeInstallation || value.TenantID != tenantID { return ErrInvalid }
		key := roleScopeKey(value); if key <= previous { return ErrInvalid }; previous = key
	}
	return nil
}

func canonicalTenantSelectors(tenantID ID, values []Scope) []Scope {
	result := append([]Scope(nil), values...)
	for index := range result { result[index].TenantID = tenantID }
	sort.Slice(result, func(i, j int) bool { return roleScopeKey(result[i]) < roleScopeKey(result[j]) })
	return result
}

func tenantPolicyContains(parent, child TenantDelegationPolicy) bool {
	if !parent.Quota.Contains(child.Quota) || child.MaximumChildDepth > parent.MaximumChildDepth || child.MaximumChildCount > parent.MaximumChildCount || child.AllowServicePrincipals && !parent.AllowServicePrincipals || child.AllowRoleBindings && !parent.AllowRoleBindings { return false }
	if parent.ValidUntil != nil && (child.ValidUntil == nil || child.ValidUntil.After(*parent.ValidUntil)) { return false }
	for _, permission := range child.Permissions { if !containsPermission(parent.Permissions, permission) { return false } }
	for _, selector := range child.Selectors { found := false; for _, ceiling := range parent.Selectors { left, right := ceiling, selector; right.TenantID = left.TenantID; if scopeContains(left, right) { found = true; break } }; if !found { return false } }
	return true
}

func quotaAdd(left, right ResourceQuota) (ResourceQuota, bool) {
	values := []struct{ left, right uint64 }{{left.Sites,right.Sites},{left.Domains,right.Domains},{left.Databases,right.Databases},{left.Mailboxes,right.Mailboxes},{left.FTPAccounts,right.FTPAccounts},{left.DiskBytes,right.DiskBytes},{left.Inodes,right.Inodes},{left.MonthlyTransfer,right.MonthlyTransfer},{left.CPUQuotaMicros,right.CPUQuotaMicros},{left.MemoryBytes,right.MemoryBytes},{left.IOReadBPS,right.IOReadBPS},{left.IOWriteBPS,right.IOWriteBPS},{left.IOReadIOPS,right.IOReadIOPS},{left.IOWriteIOPS,right.IOWriteIOPS},{left.PIDs,right.PIDs},{left.PHPConcurrency,right.PHPConcurrency}}
	result := make([]uint64, len(values)); for index, value := range values { result[index] = value.left + value.right; if result[index] < value.left { return ResourceQuota{}, false } }
	return ResourceQuota{Sites:result[0],Domains:result[1],Databases:result[2],Mailboxes:result[3],FTPAccounts:result[4],DiskBytes:result[5],Inodes:result[6],MonthlyTransfer:result[7],CPUQuotaMicros:result[8],MemoryBytes:result[9],IOReadBPS:result[10],IOWriteBPS:result[11],IOReadIOPS:result[12],IOWriteIOPS:result[13],PIDs:result[14],PHPConcurrency:result[15]}, true
}

func tenantDigest(value any) string { encoded, _ := json.Marshal(value); sum := sha256.Sum256(encoded); return hex.EncodeToString(sum[:]) }

func appendTenantProvenance(current []ID, additions ...ID) []ID {
	seen := map[ID]bool{}; result := make([]ID, 0, len(current)+len(additions))
	for _, id := range append(append([]ID(nil), current...), additions...) { if id.Valid() && !seen[id] { seen[id] = true; result = append(result, id) } }
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] }); return result
}

func tenantCommandTx(ctx context.Context, tx *sql.Tx, commandID ID, digestValue string, actor, tenant ID) (ID, bool, error) {
	if !commandID.Valid() { return "", false, ErrInvalid }
	var storedDigest, status string; var result []byte
	err := tx.QueryRowContext(ctx, `SELECT command_digest,status,result_json FROM identity_commands WHERE command_id=?`, commandID).Scan(&storedDigest, &status, &result)
	if err == nil {
		if storedDigest != digestValue { return "", false, ErrConflict }
		if status != "complete" { return "", false, ErrConflict }
		var replay struct{ TenantID ID `json:"tenant_id"` }; if json.Unmarshal(result, &replay) != nil || !replay.TenantID.Valid() { return "", false, ErrConflict }
		return replay.TenantID, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) { return "", false, err }
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_commands(command_id,command_digest,actor_id,tenant_id,status,result_json,created_at,completed_at) VALUES(?,?,?,?,?,'{}',?,NULL)`, commandID, digestValue, actor, tenant, "pending", time.Now().UTC())
	return "", false, err
}

func completeTenantCommandTx(ctx context.Context, tx *sql.Tx, commandID, tenantID ID, now time.Time) error {
	result, _ := json.Marshal(struct{ TenantID ID `json:"tenant_id"` }{tenantID})
	updated, err := tx.ExecContext(ctx, `UPDATE identity_commands SET status='complete',result_json=?,completed_at=? WHERE command_id=? AND status='pending'`, result, now, commandID)
	if err != nil { return err }; count, _ := updated.RowsAffected(); if count != 1 { return ErrConflict }; return nil
}

func insertTenantLifecycleTx(ctx context.Context, tx *sql.Tx, value ManagedTenant) error {
	permissions, _ := json.Marshal(value.Delegation.Permissions); selectors, _ := json.Marshal(value.Delegation.Selectors); quota, _ := json.Marshal(value.Delegation.Quota); contacts, _ := json.Marshal(value.OwnershipContacts); provenance, _ := json.Marshal(value.Delegation.Provenance)
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_tenant_lifecycle(tenant_id,delegation_id,manager_principal_id,manager_membership_id,manager_binding_id,permissions_json,selectors_json,quota_json,maximum_child_depth,maximum_child_count,allow_service_principals,allow_role_bindings,valid_until,plan_ceiling_id,ownership_contacts_json,provenance_json,revision,authz_epoch,created_at,updated_at,suspended_at,deletion_requested_at,retention_deadline,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.ID, value.Delegation.DelegationID, value.ManagerPrincipalID, value.ManagerMembershipID, value.ManagerBindingID, permissions, selectors, quota, value.Delegation.MaximumChildDepth, value.Delegation.MaximumChildCount, boolInt(value.Delegation.AllowServicePrincipals), boolInt(value.Delegation.AllowRoleBindings), value.Delegation.ValidUntil, value.Delegation.PlanCeilingID, contacts, provenance, value.Revision, value.AuthzEpoch, value.CreatedAt, value.UpdatedAt, value.SuspendedAt, value.DeletionRequestedAt, value.RetentionDeadline, value.DeletedAt)
	return err
}

func updateTenantLifecycleCASTx(ctx context.Context, tx *sql.Tx, value ManagedTenant, expected uint64) error {
	permissions, _ := json.Marshal(value.Delegation.Permissions); selectors, _ := json.Marshal(value.Delegation.Selectors); quota, _ := json.Marshal(value.Delegation.Quota); contacts, _ := json.Marshal(value.OwnershipContacts); provenance, _ := json.Marshal(value.Delegation.Provenance)
	result, err := tx.ExecContext(ctx, `UPDATE identity_tenant_lifecycle SET delegation_id=?,permissions_json=?,selectors_json=?,quota_json=?,maximum_child_depth=?,maximum_child_count=?,allow_service_principals=?,allow_role_bindings=?,valid_until=?,plan_ceiling_id=?,ownership_contacts_json=?,provenance_json=?,revision=?,authz_epoch=?,updated_at=?,suspended_at=?,deletion_requested_at=?,retention_deadline=?,deleted_at=? WHERE tenant_id=? AND revision=?`, value.Delegation.DelegationID, permissions, selectors, quota, value.Delegation.MaximumChildDepth, value.Delegation.MaximumChildCount, boolInt(value.Delegation.AllowServicePrincipals), boolInt(value.Delegation.AllowRoleBindings), value.Delegation.ValidUntil, value.Delegation.PlanCeilingID, contacts, provenance, value.Revision, value.AuthzEpoch, value.UpdatedAt, value.SuspendedAt, value.DeletionRequestedAt, value.RetentionDeadline, value.DeletedAt, value.ID, expected)
	if err != nil { return err }; count, _ := result.RowsAffected(); if count != 1 { return ErrStaleGeneration }; return nil
}

func updateBaseTenantCASTx(ctx context.Context, tx *sql.Tx, value ManagedTenant, expected uint64) error {
	result, err := tx.ExecContext(ctx, `UPDATE identity_tenants SET parent_tenant_id=?,sponsor_id=?,name=?,state=?,plan_id=?,generation=?,authz_epoch=?,updated_at=? WHERE id=? AND generation=?`, value.ParentTenantID, value.SponsorID, value.Name, value.State, value.PlanID, value.Generation, value.AuthzEpoch, value.UpdatedAt, value.ID, expected)
	if err != nil { return err }; count, _ := result.RowsAffected(); if count != 1 { return ErrStaleGeneration }; return nil
}

func recordDelegationRevisionTx(ctx context.Context, tx *sql.Tx, value ManagedTenant, actor ID, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_tenant_delegation_revisions(tenant_id,revision,delegation_id,sponsor_tenant_id,policy_digest,changed_by_id,created_at) VALUES(?,?,?,?,?,?,?)`, value.ID, value.Revision, value.Delegation.DelegationID, value.ParentTenantID, tenantDigest(value.Delegation), actor, now)
	return err
}

func verifyDelegationTx(ctx context.Context, tx *sql.Tx, value DelegationCeiling) error {
	var id, sponsor ID; var generation uint64
	err := tx.QueryRowContext(ctx, `SELECT id,sponsor_tenant_id,generation FROM identity_delegations WHERE child_tenant_id=?`, value.ChildTenantID).Scan(&id, &sponsor, &generation)
	if errors.Is(err, sql.ErrNoRows) { return ErrNotFound }; if err != nil { return err }
	if id != value.ID || sponsor != value.SponsorTenantID || generation != value.Generation { return ErrStaleGeneration }
	return nil
}

func delegationGenerationTx(ctx context.Context, tx *sql.Tx, childID ID) (uint64, error) {
	var generation uint64; err := tx.QueryRowContext(ctx, `SELECT generation FROM identity_delegations WHERE child_tenant_id=?`, childID).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) { return 0, ErrNotFound }; return generation, err
}

func (s *Service) auditTenantMutation(ctx context.Context, actor ID, action string, value ManagedTenant, commandID ID, before, after any) error {
	request := "command:"+commandID.String()+"\x00before:"+tenantDigest(before)+"\x00after:"+tenantDigest(after)
	sum := sha256.Sum256([]byte(action+"\x00"+request))
	return s.audit.Record(ctx, AuditEvent{ID:hex.EncodeToString(sum[:]), ActorID:actor, TenantID:value.ID, Action:action, TargetKind:"tenant", TargetID:value.ID, Outcome:"prepared", RequestHash:tenantDigest(request), At:s.clock().UTC()})
}

func (s *Service) authorizeVisibleTenant(ctx context.Context, actor ActorContext, administrativeTenantID, targetTenantID ID, permission Permission, minimum AssuranceLevel, recent bool) error {
	if !administrativeTenantID.Valid() || !targetTenantID.Valid() { return ErrInvalid }
	if _, err := s.authorize(ctx, actor, permission, Scope{Kind:ScopeTenant,TenantID:administrativeTenantID}, minimum); err != nil { return err }
	var visible int
	err := s.store.db.QueryRowContext(ctx, `WITH RECURSIVE tree(id,depth) AS (SELECT ?,0 UNION ALL SELECT t.id,tree.depth+1 FROM identity_tenants t JOIN tree ON t.parent_tenant_id=tree.id WHERE tree.depth<?) SELECT 1 FROM tree WHERE id=? LIMIT 1`, administrativeTenantID, tenantMaximumDepth, targetTenantID).Scan(&visible)
	if errors.Is(err, sql.ErrNoRows) { return ErrNotFound }; if err != nil { return err }
	target, err := s.store.Tenant(ctx, targetTenantID); if err != nil { return err }
	if target.State == TenantActive {
		if _, err = s.authorize(ctx, actor, permission, Scope{Kind:ScopeTenant,TenantID:targetTenantID}, minimum); err != nil { return err }
	} else {
		// Inactive targets cannot authorize their own reactivation or purge.
		// The already-authorized administrative ancestor may do so only when
		// every immutable delegation edge still admits the permission.
		childID := target.ID
		for depth := 0; depth < tenantMaximumDepth && childID != administrativeTenantID; depth++ {
			child, loadErr := s.store.Tenant(ctx, childID); if loadErr != nil { return loadErr }
			ceiling, loadErr := s.store.Delegation(ctx, childID); if loadErr != nil { return loadErr }
			if ceiling.SponsorTenantID != child.ParentTenantID || !containsPermission(ceiling.Permissions, permission) { return ErrDelegationExceeded }
			childID = child.ParentTenantID
		}
		if childID != administrativeTenantID { return ErrForbidden }
	}
	if recent { return s.validateRecentRoleStepUp(ctx, actor) }
	return nil
}

func (s *Service) GetManagedTenant(ctx context.Context, actor ActorContext, administrativeTenantID, tenantID ID) (ManagedTenant, error) {
	if err := s.authorizeVisibleTenant(ctx, actor, administrativeTenantID, tenantID, "identity:manage", AssurancePassword, false); err != nil { return ManagedTenant{}, err }
	return s.store.ManagedTenant(ctx, tenantID)
}

func (s *Service) ListManagedTenants(ctx context.Context, actor ActorContext, administrativeTenantID ID, query string, limit int, cursor ID) ([]ManagedTenant, string, uint64, error) {
	if !administrativeTenantID.Valid() || limit < 1 || limit > tenantMaximumPage || cursor != "" && !cursor.Valid() { return nil, "", 0, ErrInvalid }
	query = strings.ToLower(strings.TrimSpace(query)); if len(query) > 128 || strings.ContainsAny(query, "\x00\r\n\t") { return nil, "", 0, ErrInvalid }
	if _, err := s.authorize(ctx, actor, "identity:manage", Scope{Kind:ScopeTenant,TenantID:administrativeTenantID}, AssurancePassword); err != nil { return nil, "", 0, err }
	pattern := "%"+strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(query, "\\", "\\\\"), "%", "\\%"), "_", "\\_")+"%"
	cte := `WITH RECURSIVE tree(id,depth) AS (SELECT id,0 FROM identity_tenants WHERE parent_tenant_id=? UNION ALL SELECT t.id,tree.depth+1 FROM identity_tenants t JOIN tree ON t.parent_tenant_id=tree.id WHERE tree.depth<?)`
	var total uint64
	if err := s.store.db.QueryRowContext(ctx, cte+` SELECT COUNT(*) FROM (SELECT tree.id FROM tree JOIN identity_tenants t ON t.id=tree.id WHERE (?='' OR lower(t.name) LIKE ? ESCAPE '\') LIMIT ?)`, administrativeTenantID, tenantMaximumDepth, query, pattern, tenantMaximumChildren+1).Scan(&total); err != nil { return nil, "", 0, err }
	if total > tenantMaximumChildren { return nil, "", 0, ErrConflict }
	rows, err := s.store.db.QueryContext(ctx, cte+` SELECT `+strings.TrimPrefix(managedTenantSelect, "SELECT ")+` JOIN tree ON tree.id=t.id WHERE t.id>? AND (?='' OR lower(t.name) LIKE ? ESCAPE '\') ORDER BY t.id LIMIT ?`, administrativeTenantID, tenantMaximumDepth, cursor, query, pattern, limit+1)
	if err != nil { return nil, "", 0, err }; defer rows.Close()
	values := make([]ManagedTenant, 0, limit); for rows.Next() { value, scanErr := scanManagedTenant(rows); if scanErr != nil { return nil, "", 0, scanErr }; values = append(values, value) }; if err = rows.Err(); err != nil { return nil, "", 0, err }
	next := ""; if len(values) > limit { next = values[limit-1].ID.String(); values = values[:limit] }
	return values, next, total, nil
}

func (s *Service) SearchManagedTenants(ctx context.Context, actor ActorContext, administrativeTenantID ID, query string, limit int, cursor ID) ([]ManagedTenant, string, uint64, error) {
	if strings.TrimSpace(query) == "" { return nil, "", 0, ErrInvalid }
	return s.ListManagedTenants(ctx, actor, administrativeTenantID, query, limit, cursor)
}

func directChildQuotaTx(ctx context.Context, tx *sql.Tx, parentID, excluded ID) (ResourceQuota, uint64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT l.quota_json FROM identity_tenant_lifecycle l JOIN identity_tenants t ON t.id=l.tenant_id WHERE t.parent_tenant_id=? AND t.id<>? AND t.state<>'deleted'`, parentID, excluded)
	if err != nil { return ResourceQuota{}, 0, err }; defer rows.Close()
	var total ResourceQuota; var count uint64
	for rows.Next() { var raw []byte; var quota ResourceQuota; if err = rows.Scan(&raw); err != nil { return ResourceQuota{}, 0, err }; if json.Unmarshal(raw, &quota) != nil { return ResourceQuota{}, 0, ErrInvalid }; var ok bool; total, ok = quotaAdd(total, quota); if !ok { return ResourceQuota{}, 0, ErrQuotaExceeded }; count++ }
	return total, count, rows.Err()
}

func tenantSubtreeDepthTx(ctx context.Context, tx *sql.Tx, tenantID ID) (uint8, error) {
	var depth uint64
	err := tx.QueryRowContext(ctx, `WITH RECURSIVE tree(id,depth) AS (SELECT ?,0 UNION ALL SELECT t.id,tree.depth+1 FROM identity_tenants t JOIN tree ON t.parent_tenant_id=tree.id WHERE t.state<>'deleted' AND tree.depth<?) SELECT COALESCE(MAX(depth),0) FROM tree`, tenantID, tenantMaximumDepth+1).Scan(&depth)
	if err != nil { return 0, err }; if depth > tenantMaximumDepth { return 0, ErrConflict }; return uint8(depth), nil
}

func tenantPlanOwnedByLineageTx(ctx context.Context, tx *sql.Tx, parentID, ownerID ID) (bool, error) {
	current := parentID
	for depth := 0; depth <= tenantMaximumDepth; depth++ {
		if current == ownerID { return true, nil }
		value, err := tenantTx(ctx, tx, current); if err != nil { return false, err }
		if value.ParentTenantID == "" { return false, nil }; current = value.ParentTenantID
	}
	return false, ErrConflict
}

func validateTenantPolicyAgainstAncestorsTx(ctx context.Context, tx *sql.Tx, parentID ID, policy TenantDelegationPolicy) error {
	currentID := parentID
	for distance := uint8(1); distance <= tenantMaximumDepth; distance++ {
		current, err := tenantTx(ctx, tx, currentID); if err != nil { return err }
		if current.State != TenantActive { return ErrSuspended }
		plan, err := planTx(ctx, tx, current.PlanID); if err != nil { return err }
		if !plan.Quota.Contains(policy.Quota) { return ErrQuotaExceeded }
		if current.Kind == TenantOwner {
			if policy.MaximumChildDepth > tenantMaximumDepth-distance { return ErrDelegationExceeded }
			return nil
		}
		ceiling, err := managedTenantTx(ctx, tx, current.ID); if err != nil { return err }
		adjusted := policy; if adjusted.MaximumChildDepth > tenantMaximumDepth-distance { return ErrDelegationExceeded }; adjusted.MaximumChildDepth += distance
		if !tenantPolicyContains(ceiling.Delegation, adjusted) { return ErrDelegationExceeded }
		if ceiling.Delegation.ValidUntil != nil && !safelyBefore(policy.ValidUntil, ceiling.Delegation.ValidUntil) { return ErrDelegationExceeded }
		if current.ParentTenantID == "" { return nil }; currentID = current.ParentTenantID
	}
	return ErrConflict
}

func safelyBefore(child, parent *time.Time) bool { return parent == nil || child != nil && !child.After(*parent) }

func validateTenantContactsTx(ctx context.Context, tx *sql.Tx, contacts []ID, manager ID) error {
	if len(contacts) == 0 || len(contacts) > 32 { return ErrInvalid }
	seen, managerFound := map[ID]bool{}, false
	for _, id := range contacts {
		if !id.Valid() || seen[id] { return ErrInvalid }; seen[id] = true; managerFound = managerFound || id == manager
		var state string; if err := tx.QueryRowContext(ctx, `SELECT state FROM identity_principals WHERE id=? AND kind='human'`, id).Scan(&state); errors.Is(err, sql.ErrNoRows) { return ErrNotFound } else if err != nil { return err } else if PrincipalState(state) != PrincipalActive { return ErrSuspended }
	}
	if !managerFound { return fmt.Errorf("%w: manager must be an ownership contact", ErrInvalid) }
	return nil
}

func (s *Service) actorTenantProvenance(ctx context.Context, actor ActorContext, tenantID ID, permissions []Permission, selectors []Scope, validUntil *time.Time) ([]ID, error) {
	if len(permissions) == 0 || len(selectors) == 0 { return nil, ErrInvalid }
	return s.roleActorCanGrant(ctx, actor, permissions, selectors, s.clock().UTC(), validUntil)
}

func (s *Service) CreateManagedTenant(ctx context.Context, command CreateManagedTenantCommand) (ManagedTenant, error) {
	if s == nil || s.store == nil || ctx == nil || !command.CommandID.Valid() || !command.TenantID.Valid() || !command.ParentTenantID.Valid() || !command.ManagerPrincipalID.Valid() || !command.ManagerMembershipID.Valid() || !command.ManagerBindingID.Valid() || !command.DelegationID.Valid() || !command.PlanReferenceID.Valid() || command.TenantID == command.ParentTenantID || command.Kind != TenantReseller && command.Kind != TenantCustomer {
		return ManagedTenant{}, ErrInvalid
	}
	command.Name = strings.TrimSpace(command.Name); if command.Name == "" || len(command.Name) > 128 || strings.ContainsAny(command.Name, "\x00\r\n\t") { return ManagedTenant{}, ErrInvalid }
	permissions := CanonicalPermissions(command.Permissions); if len(permissions) != len(command.Permissions) || len(permissions) == 0 { return ManagedTenant{}, ErrInvalid }
	selectors := canonicalTenantSelectors(command.TenantID, command.Selectors); if validateTenantSelectors(command.TenantID, selectors) != nil || command.Quota.Validate() != nil { return ManagedTenant{}, ErrInvalid }
	contacts := append([]ID(nil), command.OwnershipContacts...); sort.Slice(contacts, func(i, j int) bool { return contacts[i] < contacts[j] })
	if _, err := s.authorize(ctx, command.Actor, "tenant:create", Scope{Kind:ScopeTenant,TenantID:command.ParentTenantID}, AssuranceMFA); err != nil { return ManagedTenant{}, err }
	if err := s.validateRecentRoleStepUp(ctx, command.Actor); err != nil { return ManagedTenant{}, err }
	grantSelectors := canonicalTenantSelectors(command.ParentTenantID, selectors)
	actorProvenance, err := s.actorTenantProvenance(ctx, command.Actor, command.ParentTenantID, permissions, grantSelectors, command.ValidUntil); if err != nil { return ManagedTenant{}, err }
	now := s.clock().UTC()
	policy := TenantDelegationPolicy{DelegationID:command.DelegationID,Permissions:permissions,Selectors:selectors,Quota:command.Quota,MaximumChildDepth:command.MaximumChildDepth,MaximumChildCount:command.MaximumChildCount,AllowServicePrincipals:command.AllowServicePrincipals,AllowRoleBindings:command.AllowRoleBindings,ValidUntil:command.ValidUntil,PlanCeilingID:command.PlanReferenceID,Provenance:appendTenantProvenance(actorProvenance, command.DelegationID)}
	digestValue := tenantDigest(struct{ Command CreateManagedTenantCommand; Policy TenantDelegationPolicy }{command,policy})
	// Persist the intent before taking the control database's write lock: the
	// authoritative audit index shares that database. An intent is not an applied
	// change; all admission checks and tenant writes still occur atomically below.
	// Each attempt has its own event ID so retries do not collide on timestamps.
	auditID := tenantDigest(struct{ Digest string; At time.Time }{digestValue, now})
	if err = s.audit.Record(ctx, AuditEvent{ID:auditID, ActorID:command.Actor.PrincipalID, TenantID:command.TenantID, Action:"tenant.create", TargetKind:"tenant", TargetID:command.TenantID, Outcome:"prepared", RequestHash:digestValue, At:now}); err != nil { return ManagedTenant{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable}); if err != nil { return ManagedTenant{}, err }; defer tx.Rollback()
	if replayID, replay, reserveErr := tenantCommandTx(ctx, tx, command.CommandID, digestValue, command.Actor.PrincipalID, command.ParentTenantID); reserveErr != nil { return ManagedTenant{}, reserveErr } else if replay { tx.Rollback(); return s.store.ManagedTenant(ctx, replayID) }
	parent, err := tenantTx(ctx, tx, command.ParentTenantID); if err != nil { return ManagedTenant{}, err }; if parent.State != TenantActive { return ManagedTenant{}, ErrSuspended }
	var nameConflict uint64; if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_tenants WHERE parent_tenant_id=? AND lower(name)=lower(?) AND state<>'deleted'`, parent.ID, command.Name).Scan(&nameConflict); err != nil { return ManagedTenant{}, err }; if nameConflict != 0 { return ManagedTenant{}, ErrConflict }
	plan, err := planTx(ctx, tx, command.PlanReferenceID); if err != nil { return ManagedTenant{}, err }
	owned, err := tenantPlanOwnedByLineageTx(ctx, tx, parent.ID, plan.OwnerTenantID); if err != nil { return ManagedTenant{}, err }; if !owned { return ManagedTenant{}, ErrForbidden }
	if !plan.Quota.Contains(policy.Quota) { return ManagedTenant{}, ErrQuotaExceeded }
	if err = validateTenantPolicyAgainstAncestorsTx(ctx, tx, parent.ID, policy); err != nil { return ManagedTenant{}, err }
	allocated, count, err := directChildQuotaTx(ctx, tx, parent.ID, ""); if err != nil { return ManagedTenant{}, err }
	parentLimit := uint32(tenantMaximumChildren); if parent.Kind != TenantOwner { managedParent, loadErr := managedTenantTx(ctx, tx, parent.ID); if loadErr != nil { return ManagedTenant{}, loadErr }; parentLimit = managedParent.Delegation.MaximumChildCount }
	if count >= uint64(parentLimit) { return ManagedTenant{}, ErrQuotaExceeded }
	allocated, ok := quotaAdd(allocated, policy.Quota); if !ok { return ManagedTenant{}, ErrQuotaExceeded }
	parentPlan, err := planTx(ctx, tx, parent.PlanID); if err != nil { return ManagedTenant{}, err }; if !parentPlan.Quota.Contains(allocated) { return ManagedTenant{}, ErrQuotaExceeded }
	if err = validateTenantContactsTx(ctx, tx, contacts, command.ManagerPrincipalID); err != nil { return ManagedTenant{}, err }
	base := Tenant{ID:command.TenantID,ParentTenantID:parent.ID,SponsorID:parent.ID,Kind:command.Kind,Name:command.Name,State:TenantActive,PlanID:command.PlanReferenceID,Generation:1,AuthzEpoch:1,CreatedAt:now,UpdatedAt:now}
	value := ManagedTenant{Tenant:base,LifecycleState:TenantLifecycleActive,ManagerPrincipalID:command.ManagerPrincipalID,ManagerMembershipID:command.ManagerMembershipID,ManagerBindingID:command.ManagerBindingID,Delegation:policy,OwnershipContacts:contacts,Revision:1}
	if value.Validate() != nil { return ManagedTenant{}, ErrInvalid }
	membership := Membership{ID:command.ManagerMembershipID,PrincipalID:command.ManagerPrincipalID,TenantID:value.ID,State:MembershipActive,Generation:1,CreatedAt:now,UpdatedAt:now}
	legacy := DelegationCeiling{ID:command.DelegationID,SponsorTenantID:parent.ID,ChildTenantID:value.ID,Permissions:permissions,QuotaBudget:policy.Quota,Generation:1,CreatedAt:now,UpdatedAt:now}
	if err = putTenant(ctx, tx, base); err == nil { err = putMembership(ctx, tx, membership) }; if err == nil { err = putDelegation(ctx, tx, legacy) }; if err == nil { err = ensureBuiltInRolesTx(ctx, tx, value.ID, now) }; if err != nil { return ManagedTenant{}, err }
	roleKey := BuiltInCustomer; if value.Kind == TenantReseller { roleKey = BuiltInReseller }; roleID, _ := builtInRoleID(value.ID, roleKey)
	managerBinding := ManagedRoleBinding{ID:value.ManagerBindingID,TenantID:value.ID,SubjectKind:SubjectPrincipal,SubjectID:value.ManagerPrincipalID,RoleID:roleID,Selectors:[]Scope{{Kind:ScopeTenant,TenantID:value.ID}},EffectiveAt:now,ExpiresAt:value.Delegation.ValidUntil,GrantedByID:command.Actor.PrincipalID,Provenance:value.Delegation.Provenance,Revision:1,CreatedAt:now}
	if managerBinding.Validate() != nil { return ManagedTenant{}, ErrInvalid }
	if err = insertManagedBindingTx(ctx, tx, managerBinding); err == nil { err = invalidateRoleSubjectTx(ctx, tx, managerBinding.SubjectID, now) }; if err == nil { err = insertTenantLifecycleTx(ctx, tx, value) }; if err == nil { err = recordDelegationRevisionTx(ctx, tx, value, command.Actor.PrincipalID, now) }; if err != nil { return ManagedTenant{}, err }
	// Subject invalidation may have advanced the manager's principal epoch; the
	// tenant epoch is independent and remains the value admitted above.
	if err = completeTenantCommandTx(ctx, tx, command.CommandID, value.ID, now); err != nil { return ManagedTenant{}, err }
	if err = tx.Commit(); err != nil { return ManagedTenant{}, err }
	return value, nil
}

func validateTenantFieldMask(fields []TenantField) (map[TenantField]bool, error) {
	if len(fields) == 0 || len(fields) > 10 { return nil, ErrInvalid }
	known := map[TenantField]bool{TenantFieldName:true,TenantFieldPermissions:true,TenantFieldSelectors:true,TenantFieldQuota:true,TenantFieldMaximumChildDepth:true,TenantFieldMaximumChildCount:true,TenantFieldAllowServicePrincipals:true,TenantFieldAllowRoleBindings:true,TenantFieldValidUntil:true,TenantFieldPlanReference:true}
	result := map[TenantField]bool{}; for _, field := range fields { if !known[field] || result[field] { return nil, ErrInvalid }; result[field] = true }; return result, nil
}

func actorHasTargetMembershipTx(ctx context.Context, tx *sql.Tx, actor, target ID) (bool, error) {
	var count uint64; err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_memberships WHERE principal_id=? AND tenant_id=? AND state='active'`, actor, target).Scan(&count); return count > 0, err
}

func (s *Service) UpdateManagedTenant(ctx context.Context, command UpdateManagedTenantCommand) (ManagedTenant, error) {
	fields, err := validateTenantFieldMask(command.FieldMask); if err != nil || !command.CommandID.Valid() || command.ExpectedRevision == 0 { return ManagedTenant{}, ErrInvalid }
	if err = s.authorizeVisibleTenant(ctx, command.Actor, command.AdministrativeTenantID, command.TenantID, "identity:manage", AssuranceMFA, true); err != nil { return ManagedTenant{}, err }
	current, err := s.store.ManagedTenant(ctx, command.TenantID); if err != nil { return ManagedTenant{}, err }
	next := current
	if fields[TenantFieldName] { next.Name = strings.TrimSpace(command.Name); if next.Name == "" || len(next.Name) > 128 || strings.ContainsAny(next.Name, "\x00\r\n\t") { return ManagedTenant{}, ErrInvalid } }
	if fields[TenantFieldPermissions] { next.Delegation.Permissions = CanonicalPermissions(command.Permissions); if len(next.Delegation.Permissions) != len(command.Permissions) || len(command.Permissions) == 0 { return ManagedTenant{}, ErrInvalid } }
	if fields[TenantFieldSelectors] { next.Delegation.Selectors = canonicalTenantSelectors(next.ID, command.Selectors); if validateTenantSelectors(next.ID, next.Delegation.Selectors) != nil { return ManagedTenant{}, ErrInvalid } }
	if fields[TenantFieldQuota] { next.Delegation.Quota = command.Quota; if command.Quota.Validate() != nil { return ManagedTenant{}, ErrInvalid } }
	if fields[TenantFieldMaximumChildDepth] { next.Delegation.MaximumChildDepth = command.MaximumChildDepth }
	if fields[TenantFieldMaximumChildCount] { next.Delegation.MaximumChildCount = command.MaximumChildCount }
	if fields[TenantFieldAllowServicePrincipals] { next.Delegation.AllowServicePrincipals = command.AllowServicePrincipals }
	if fields[TenantFieldAllowRoleBindings] { next.Delegation.AllowRoleBindings = command.AllowRoleBindings }
	if fields[TenantFieldValidUntil] { next.Delegation.ValidUntil = command.ValidUntil }
	if fields[TenantFieldPlanReference] { next.PlanID, next.Delegation.PlanCeilingID = command.PlanReferenceID, command.PlanReferenceID }
	if next.State != TenantActive || next.Delegation.ValidUntil != nil && !next.Delegation.ValidUntil.After(s.clock().UTC()) { return ManagedTenant{}, ErrConflict }
	actorProvenance, err := s.actorTenantProvenance(ctx, command.Actor, next.ID, next.Delegation.Permissions, next.Delegation.Selectors, next.Delegation.ValidUntil); if err != nil { return ManagedTenant{}, err }
	next.Delegation.Provenance = appendTenantProvenance(next.Delegation.Provenance, actorProvenance...)
	digestValue := tenantDigest(struct{ Command UpdateManagedTenantCommand; Next ManagedTenant }{command,next})
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable}); if err != nil { return ManagedTenant{}, err }; defer tx.Rollback()
	if replayID, replay, reserveErr := tenantCommandTx(ctx, tx, command.CommandID, digestValue, command.Actor.PrincipalID, command.TenantID); reserveErr != nil { return ManagedTenant{}, reserveErr } else if replay { tx.Rollback(); return s.store.ManagedTenant(ctx, replayID) }
	stored, err := managedTenantTx(ctx, tx, command.TenantID); if err != nil { return ManagedTenant{}, err }; if stored.Revision != command.ExpectedRevision || stored.Revision != current.Revision { return ManagedTenant{}, ErrStaleGeneration }
	selfManaged, err := actorHasTargetMembershipTx(ctx, tx, command.Actor.PrincipalID, next.ID); if err != nil { return ManagedTenant{}, err }; if command.AdministrativeTenantID == next.ID && selfManaged && !tenantPolicyContains(stored.Delegation, next.Delegation) { return ManagedTenant{}, ErrDelegationExceeded }
	plan, err := planTx(ctx, tx, next.PlanID); if err != nil { return ManagedTenant{}, err }; owned, err := tenantPlanOwnedByLineageTx(ctx, tx, stored.ParentTenantID, plan.OwnerTenantID); if err != nil { return ManagedTenant{}, err }; if !owned { return ManagedTenant{}, ErrForbidden }; if !plan.Quota.Contains(next.Delegation.Quota) { return ManagedTenant{}, ErrQuotaExceeded }
	if err = validateTenantPolicyAgainstAncestorsTx(ctx, tx, stored.ParentTenantID, next.Delegation); err != nil { return ManagedTenant{}, err }
	allocated, _, err := directChildQuotaTx(ctx, tx, stored.ParentTenantID, stored.ID); if err != nil { return ManagedTenant{}, err }; allocated, ok := quotaAdd(allocated, next.Delegation.Quota); if !ok { return ManagedTenant{}, ErrQuotaExceeded }; parent, err := tenantTx(ctx, tx, stored.ParentTenantID); if err != nil { return ManagedTenant{}, err }; parentPlan, err := planTx(ctx, tx, parent.PlanID); if err != nil { return ManagedTenant{}, err }; if !parentPlan.Quota.Contains(allocated) { return ManagedTenant{}, ErrQuotaExceeded }
	directQuota, childCount, err := directChildQuotaTx(ctx, tx, next.ID, ""); if err != nil { return ManagedTenant{}, err }; if childCount > uint64(next.Delegation.MaximumChildCount) || !next.Delegation.Quota.Contains(directQuota) { return ManagedTenant{}, ErrQuotaExceeded }; depth, err := tenantSubtreeDepthTx(ctx, tx, next.ID); if err != nil { return ManagedTenant{}, err }; if depth > next.Delegation.MaximumChildDepth { return ManagedTenant{}, ErrDelegationExceeded }
	now := s.clock().UTC(); before := stored; next.Revision, next.Generation, next.AuthzEpoch = stored.Revision+1, stored.Generation+1, stored.AuthzEpoch+1; next.UpdatedAt = now
	delegationGeneration, err := delegationGenerationTx(ctx, tx, next.ID); if err != nil { return ManagedTenant{}, err }
	legacy := DelegationCeiling{ID:next.Delegation.DelegationID,SponsorTenantID:next.ParentTenantID,ChildTenantID:next.ID,Permissions:next.Delegation.Permissions,QuotaBudget:next.Delegation.Quota,Generation:delegationGeneration+1,CreatedAt:stored.CreatedAt,UpdatedAt:now}
	if err = updateBaseTenantCASTx(ctx, tx, next, stored.Generation); err == nil { err = updateTenantLifecycleCASTx(ctx, tx, next, stored.Revision) }; if err == nil { err = putDelegation(ctx, tx, legacy) }; if err == nil { err = verifyDelegationTx(ctx, tx, legacy) }; if err == nil { err = recordDelegationRevisionTx(ctx, tx, next, command.Actor.PrincipalID, now) }; if err != nil { return ManagedTenant{}, err }
	if err = invalidateTenantSubtreeTx(ctx, tx, next.ID, next.AuthzEpoch, now); err != nil { return ManagedTenant{}, err }
	if err = s.auditTenantMutation(ctx, command.Actor.PrincipalID, "tenant.update", next, command.CommandID, before, next); err != nil { return ManagedTenant{}, err }
	if err = completeTenantCommandTx(ctx, tx, command.CommandID, next.ID, now); err != nil { return ManagedTenant{}, err }; if err = tx.Commit(); err != nil { return ManagedTenant{}, err }
	return s.store.ManagedTenant(ctx, next.ID)
}

func invalidateTenantSubtreeTx(ctx context.Context, tx *sql.Tx, root ID, rootEpoch uint64, now time.Time) error {
	// Root was already advanced through its CAS update. Descendants receive an
	// epoch-only invalidation so their user-visible revision/CAS token does not
	// change for an ancestor policy edit.
	_, err := tx.ExecContext(ctx, `WITH RECURSIVE tree(id,depth) AS (SELECT id,0 FROM identity_tenants WHERE parent_tenant_id=? UNION ALL SELECT t.id,tree.depth+1 FROM identity_tenants t JOIN tree ON t.parent_tenant_id=tree.id WHERE tree.depth<?) UPDATE identity_tenants SET authz_epoch=authz_epoch+1,updated_at=? WHERE id IN (SELECT id FROM tree)`, root, tenantMaximumDepth, now)
	if err != nil { return err }
	_, err = tx.ExecContext(ctx, `UPDATE identity_tenant_lifecycle SET authz_epoch=(SELECT authz_epoch FROM identity_tenants WHERE identity_tenants.id=identity_tenant_lifecycle.tenant_id),updated_at=? WHERE tenant_id IN (WITH RECURSIVE tree(id,depth) AS (SELECT id,0 FROM identity_tenants WHERE parent_tenant_id=? UNION ALL SELECT t.id,tree.depth+1 FROM identity_tenants t JOIN tree ON t.parent_tenant_id=tree.id WHERE tree.depth<?) SELECT id FROM tree)`, now, root, tenantMaximumDepth)
	_ = rootEpoch
	return err
}

func (s *Service) transitionManagedTenant(ctx context.Context, command TenantTransitionCommand, suspend bool) (ManagedTenant, error) {
	if !command.CommandID.Valid() || command.ExpectedRevision == 0 { return ManagedTenant{}, ErrInvalid }
	if err := s.authorizeVisibleTenant(ctx, command.Actor, command.AdministrativeTenantID, command.TenantID, "identity:manage", AssuranceMFA, true); err != nil { return ManagedTenant{}, err }
	action := "tenant.suspend"; expected, nextState := TenantActive, TenantSuspended; lifecycle := TenantLifecycleSuspended
	if !suspend { action, expected, nextState, lifecycle = "tenant.reactivate", TenantSuspended, TenantActive, TenantLifecycleActive }
	digestValue := tenantDigest(struct{ Command TenantTransitionCommand; Suspend bool }{command,suspend})
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable}); if err != nil { return ManagedTenant{}, err }; defer tx.Rollback()
	if replayID, replay, reserveErr := tenantCommandTx(ctx, tx, command.CommandID, digestValue, command.Actor.PrincipalID, command.TenantID); reserveErr != nil { return ManagedTenant{}, reserveErr } else if replay { tx.Rollback(); return s.store.ManagedTenant(ctx, replayID) }
	current, err := managedTenantTx(ctx, tx, command.TenantID); if err != nil { return ManagedTenant{}, err }; if current.Revision != command.ExpectedRevision { return ManagedTenant{}, ErrStaleGeneration }; if current.State != expected { return ManagedTenant{}, ErrConflict }
	now := s.clock().UTC(); next := current; next.State, next.LifecycleState = nextState, lifecycle; next.Revision++; next.Generation++; next.AuthzEpoch++; next.UpdatedAt = now
	if suspend { next.SuspendedAt = &now } else { next.SuspendedAt = nil }
	if err = updateBaseTenantCASTx(ctx, tx, next, current.Generation); err == nil { err = updateTenantLifecycleCASTx(ctx, tx, next, current.Revision) }; if err == nil { err = invalidateTenantSubtreeTx(ctx, tx, next.ID, next.AuthzEpoch, now) }; if err != nil { return ManagedTenant{}, err }
	if err = s.auditTenantMutation(ctx, command.Actor.PrincipalID, action, next, command.CommandID, current, next); err != nil { return ManagedTenant{}, err }
	if err = completeTenantCommandTx(ctx, tx, command.CommandID, next.ID, now); err != nil { return ManagedTenant{}, err }; if err = tx.Commit(); err != nil { return ManagedTenant{}, err }
	return s.store.ManagedTenant(ctx, next.ID)
}

func (s *Service) SuspendManagedTenant(ctx context.Context, command TenantTransitionCommand) (ManagedTenant, error) { return s.transitionManagedTenant(ctx, command, true) }
func (s *Service) ReactivateManagedTenant(ctx context.Context, command TenantTransitionCommand) (ManagedTenant, error) { return s.transitionManagedTenant(ctx, command, false) }

func transferBlockersTx(ctx context.Context, tx *sql.Tx, value ManagedTenant, newParentID ID) ([]string, error) {
	blockers := []string{}
	newParent, err := tenantTx(ctx, tx, newParentID); if err != nil { return nil, err }
	if newParent.State != TenantActive { blockers = append(blockers, "new_parent_inactive") }
	if newParent.Kind == TenantCustomer { blockers = append(blockers, "new_parent_cannot_delegate") }
	var cycle uint64
	err = tx.QueryRowContext(ctx, `WITH RECURSIVE tree(id,depth) AS (SELECT ?,0 UNION ALL SELECT t.id,tree.depth+1 FROM identity_tenants t JOIN tree ON t.parent_tenant_id=tree.id WHERE tree.depth<?) SELECT COUNT(*) FROM tree WHERE id=?`, value.ID, tenantMaximumDepth, newParentID).Scan(&cycle); if err != nil { return nil, err }; if cycle != 0 { blockers = append(blockers, "parent_cycle") }
	var conflict uint64; if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_tenants WHERE parent_tenant_id=? AND id<>? AND lower(name)=lower(?) AND state<>'deleted'`, newParentID, value.ID, value.Name).Scan(&conflict); err != nil { return nil, err }; if conflict != 0 { blockers = append(blockers, "name_conflict") }
	plan, err := planTx(ctx, tx, value.PlanID); if err != nil { return nil, err }; owned, err := tenantPlanOwnedByLineageTx(ctx, tx, newParentID, plan.OwnerTenantID); if err != nil { return nil, err }; if !owned || !plan.Quota.Contains(value.Delegation.Quota) { blockers = append(blockers, "plan_incompatible") }
	if err = validateTenantPolicyAgainstAncestorsTx(ctx, tx, newParentID, value.Delegation); errors.Is(err, ErrDelegationExceeded) || errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrSuspended) { blockers = append(blockers, "delegation_incompatible") } else if err != nil { return nil, err }
	allocated, count, err := directChildQuotaTx(ctx, tx, newParentID, value.ID); if err != nil { return nil, err }
	limit := uint32(tenantMaximumChildren); if newParent.Kind != TenantOwner { parentPolicy, loadErr := managedTenantTx(ctx, tx, newParentID); if loadErr != nil { return nil, loadErr }; limit = parentPolicy.Delegation.MaximumChildCount }
	if count >= uint64(limit) { blockers = append(blockers, "child_count_exceeded") }
	allocated, ok := quotaAdd(allocated, value.Delegation.Quota); if !ok { blockers = append(blockers, "quota_exceeded") } else { parentPlan, loadErr := planTx(ctx, tx, newParent.PlanID); if loadErr != nil { return nil, loadErr }; if !parentPlan.Quota.Contains(allocated) { blockers = append(blockers, "quota_exceeded") } }
	depth, err := tenantSubtreeDepthTx(ctx, tx, value.ID); if err != nil { return nil, err }; if newParent.Kind != TenantOwner { parentPolicy, _ := managedTenantTx(ctx, tx, newParentID); if depth+1 > parentPolicy.Delegation.MaximumChildDepth { blockers = append(blockers, "child_depth_exceeded") } }
	sort.Strings(blockers); return blockers, nil
}

func (s *Service) PreviewTenantParentTransfer(ctx context.Context, actor ActorContext, administrativeTenantID, tenantID, newParentID ID) (TenantTransferImpact, error) {
	if err := s.authorizeVisibleTenant(ctx, actor, administrativeTenantID, tenantID, "identity:manage", AssuranceMFA, false); err != nil { return TenantTransferImpact{}, err }
	if err := s.authorizeVisibleTenant(ctx, actor, administrativeTenantID, newParentID, "tenant:create", AssuranceMFA, false); err != nil { return TenantTransferImpact{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly:true,Isolation:sql.LevelSerializable}); if err != nil { return TenantTransferImpact{}, err }; defer tx.Rollback()
	value, err := managedTenantTx(ctx, tx, tenantID); if err != nil { return TenantTransferImpact{}, err }; blockers, err := transferBlockersTx(ctx, tx, value, newParentID); if err != nil { return TenantTransferImpact{}, err }
	impact := TenantTransferImpact{TenantID:tenantID,NewParentTenantID:newParentID,Revision:value.Revision,Blockers:blockers}; impact.RequestDigest = tenantDigest(struct{ Action string; TenantID, NewParentID ID; Revision uint64; Policy TenantDelegationPolicy; Blockers []string }{"tenant.transfer_parent",tenantID,newParentID,value.Revision,value.Delegation,blockers})
	return impact, nil
}

func consumeTenantApprovalTx(ctx context.Context, tx *sql.Tx, approvalID ID, action string, target, actor, commandID ID, requestDigest string, now time.Time) error {
	if !approvalID.Valid() { return ErrForbidden }
	var storedAction, storedDigest string; var storedTarget, approver ID; var approvedAt, expiresAt time.Time; var consumed sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT action,target_tenant_id,request_digest,approved_by_id,approved_at,expires_at,consumed_at FROM identity_tenant_approvals WHERE id=?`, approvalID).Scan(&storedAction, &storedTarget, &storedDigest, &approver, &approvedAt, &expiresAt, &consumed)
	if errors.Is(err, sql.ErrNoRows) { return ErrForbidden }; if err != nil { return err }
	if storedAction != action || storedTarget != target || storedDigest != requestDigest || approver == actor || approvedAt.After(now) || !now.Before(expiresAt) || consumed.Valid { return ErrForbidden }
	result, err := tx.ExecContext(ctx, `UPDATE identity_tenant_approvals SET consumed_at=?,consumed_command_id=? WHERE id=? AND consumed_at IS NULL`, now, commandID, approvalID); if err != nil { return err }; count, _ := result.RowsAffected(); if count != 1 { return ErrConflict }; return nil
}

func (s *Service) TransferTenantParent(ctx context.Context, command TransferTenantParentCommand) (ManagedTenant, error) {
	if !command.CommandID.Valid() || !command.NewParentTenantID.Valid() || !command.DelegationID.Valid() || command.ExpectedRevision == 0 || command.TenantID == command.NewParentTenantID { return ManagedTenant{}, ErrInvalid }
	if err := s.authorizeVisibleTenant(ctx, command.Actor, command.AdministrativeTenantID, command.TenantID, "identity:manage", AssurancePhishingResistant, true); err != nil { return ManagedTenant{}, err }
	if err := s.authorizeVisibleTenant(ctx, command.Actor, command.AdministrativeTenantID, command.NewParentTenantID, "tenant:create", AssurancePhishingResistant, true); err != nil { return ManagedTenant{}, err }
	preview, err := s.PreviewTenantParentTransfer(ctx, command.Actor, command.AdministrativeTenantID, command.TenantID, command.NewParentTenantID); if err != nil { return ManagedTenant{}, err }; if len(preview.Blockers) != 0 { return ManagedTenant{}, ErrConflict }; if preview.Revision != command.ExpectedRevision { return ManagedTenant{}, ErrStaleGeneration }
	digestValue := tenantDigest(command)
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable}); if err != nil { return ManagedTenant{}, err }; defer tx.Rollback()
	if replayID, replay, reserveErr := tenantCommandTx(ctx, tx, command.CommandID, digestValue, command.Actor.PrincipalID, command.TenantID); reserveErr != nil { return ManagedTenant{}, reserveErr } else if replay { tx.Rollback(); return s.store.ManagedTenant(ctx, replayID) }
	current, err := managedTenantTx(ctx, tx, command.TenantID); if err != nil { return ManagedTenant{}, err }; if current.Revision != command.ExpectedRevision { return ManagedTenant{}, ErrStaleGeneration }
	blockers, err := transferBlockersTx(ctx, tx, current, command.NewParentTenantID); if err != nil { return ManagedTenant{}, err }; if len(blockers) != 0 || tenantDigest(struct{ Action string; TenantID, NewParentID ID; Revision uint64; Policy TenantDelegationPolicy; Blockers []string }{"tenant.transfer_parent",current.ID,command.NewParentTenantID,current.Revision,current.Delegation,blockers}) != preview.RequestDigest { return ManagedTenant{}, ErrConflict }
	now := s.clock().UTC(); if err = consumeTenantApprovalTx(ctx, tx, command.ApprovalID, "tenant.transfer_parent", current.ID, command.Actor.PrincipalID, command.CommandID, preview.RequestDigest, now); err != nil { return ManagedTenant{}, err }
	next := current; oldDelegation := next.Delegation.DelegationID; next.ParentTenantID, next.SponsorID, next.Delegation.DelegationID = command.NewParentTenantID, command.NewParentTenantID, command.DelegationID; next.Delegation.Provenance = appendTenantProvenance(next.Delegation.Provenance, command.ApprovalID, command.DelegationID); next.Revision++; next.Generation++; next.AuthzEpoch++; next.UpdatedAt = now
	legacy := DelegationCeiling{ID:next.Delegation.DelegationID,SponsorTenantID:next.ParentTenantID,ChildTenantID:next.ID,Permissions:next.Delegation.Permissions,QuotaBudget:next.Delegation.Quota,Generation:1,CreatedAt:now,UpdatedAt:now}
	if err = updateBaseTenantCASTx(ctx, tx, next, current.Generation); err == nil { err = updateTenantLifecycleCASTx(ctx, tx, next, current.Revision) }; if err == nil { _, err = tx.ExecContext(ctx, `DELETE FROM identity_delegations WHERE id=? AND child_tenant_id=?`, oldDelegation, next.ID) }; if err == nil { err = putDelegation(ctx, tx, legacy) }; if err == nil { err = recordDelegationRevisionTx(ctx, tx, next, command.Actor.PrincipalID, now) }; if err == nil { err = invalidateTenantSubtreeTx(ctx, tx, next.ID, next.AuthzEpoch, now) }; if err != nil { return ManagedTenant{}, err }
	if err = s.auditTenantMutation(ctx, command.Actor.PrincipalID, "tenant.transfer_parent", next, command.CommandID, current, next); err != nil { return ManagedTenant{}, err }; if err = completeTenantCommandTx(ctx, tx, command.CommandID, next.ID, now); err != nil { return ManagedTenant{}, err }; if err = tx.Commit(); err != nil { return ManagedTenant{}, err }
	return s.store.ManagedTenant(ctx, next.ID)
}

func usagePresent(value Usage) bool {
	return value.Sites != 0 || value.Domains != 0 || value.Databases != 0 || value.Mailboxes != 0 || value.FTPAccounts != 0 || value.DiskBytes != 0 || value.Inodes != 0 || value.MonthlyTransfer != 0
}

func tenantDeletionImpactTx(ctx context.Context, tx *sql.Tx, value ManagedTenant, now time.Time) (TenantDeletionImpact, error) {
	impact := TenantDeletionImpact{TenantID:value.ID,Revision:value.Revision,RetentionDeadline:value.RetentionDeadline}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_tenants WHERE parent_tenant_id=? AND state<>'deleted'`, value.ID).Scan(&impact.LiveChildCount); err != nil { return impact, err }
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_human_resource_ownership WHERE tenant_id=?`, value.ID).Scan(&impact.ResourceOwnershipCount); err != nil { return impact, err }
	var raw []byte; err := tx.QueryRowContext(ctx, `SELECT usage_json FROM identity_usage WHERE tenant_id=?`, value.ID).Scan(&raw)
	if err == nil { var usage Usage; if json.Unmarshal(raw, &usage) != nil { return impact, ErrInvalid }; impact.UsagePresent = usagePresent(usage) } else if !errors.Is(err, sql.ErrNoRows) { return impact, err }
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_service_principals WHERE tenant_id=? AND state<>'deleted'`, value.ID).Scan(&impact.ActiveServicePrincipals); err != nil { return impact, err }
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM identity_managed_role_bindings WHERE tenant_id=? AND revoked_at IS NULL)+(SELECT COUNT(*) FROM identity_role_bindings WHERE tenant_id=?)`, value.ID, value.ID).Scan(&impact.ActiveRoleBindingCount); err != nil { return impact, err }
	for _, owner := range value.OwnershipContacts { var count uint64; if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_principals p JOIN identity_memberships m ON m.principal_id=p.id AND m.tenant_id=? WHERE p.id=? AND p.kind='human' AND p.state='active' AND m.state='active'`, value.ID, owner).Scan(&count); err != nil { return impact, err }; impact.ActiveOwnerCount += count }
	impact.CanQuarantine = value.Kind != TenantOwner && (value.State == TenantActive || value.State == TenantSuspended) && impact.LiveChildCount == 0 && impact.ActiveOwnerCount > 0
	impact.CanPurge = value.State == TenantDeleting && value.RetentionDeadline != nil && !now.Before(*value.RetentionDeadline) && impact.LiveChildCount == 0 && impact.ResourceOwnershipCount == 0 && !impact.UsagePresent && impact.ActiveServicePrincipals == 0
	action := "tenant.quarantine"; if value.State == TenantDeleting { action = "tenant.purge" }
	impact.RequestDigest = tenantDigest(struct{ Action string; TenantID ID; Revision, Children, Resources, Services, Bindings, Owners uint64; Usage bool; Retention *time.Time }{action,value.ID,value.Revision,impact.LiveChildCount,impact.ResourceOwnershipCount,impact.ActiveServicePrincipals,impact.ActiveRoleBindingCount,impact.ActiveOwnerCount,impact.UsagePresent,impact.RetentionDeadline})
	return impact, nil
}

func (s *Service) PreviewManagedTenantDeletion(ctx context.Context, actor ActorContext, administrativeTenantID, tenantID ID) (TenantDeletionImpact, error) {
	if err := s.authorizeVisibleTenant(ctx, actor, administrativeTenantID, tenantID, "identity:manage", AssurancePassword, false); err != nil { return TenantDeletionImpact{}, err }
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly:true,Isolation:sql.LevelSerializable}); if err != nil { return TenantDeletionImpact{}, err }; defer tx.Rollback()
	value, err := managedTenantTx(ctx, tx, tenantID); if err != nil { return TenantDeletionImpact{}, err }
	return tenantDeletionImpactTx(ctx, tx, value, s.clock().UTC())
}

func (s *Service) QuarantineManagedTenant(ctx context.Context, command TenantTransitionCommand) (ManagedTenant, error) {
	if !command.CommandID.Valid() || command.ExpectedRevision == 0 { return ManagedTenant{}, ErrInvalid }
	if err := s.authorizeVisibleTenant(ctx, command.Actor, command.AdministrativeTenantID, command.TenantID, "identity:manage", AssurancePhishingResistant, true); err != nil { return ManagedTenant{}, err }
	digestValue := tenantDigest(command)
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable}); if err != nil { return ManagedTenant{}, err }; defer tx.Rollback()
	if replayID, replay, reserveErr := tenantCommandTx(ctx, tx, command.CommandID, digestValue, command.Actor.PrincipalID, command.TenantID); reserveErr != nil { return ManagedTenant{}, reserveErr } else if replay { tx.Rollback(); return s.store.ManagedTenant(ctx, replayID) }
	current, err := managedTenantTx(ctx, tx, command.TenantID); if err != nil { return ManagedTenant{}, err }; if current.Revision != command.ExpectedRevision { return ManagedTenant{}, ErrStaleGeneration }
	impact, err := tenantDeletionImpactTx(ctx, tx, current, s.clock().UTC()); if err != nil { return ManagedTenant{}, err }; if !impact.CanQuarantine { return ManagedTenant{}, ErrConflict }
	now := s.clock().UTC(); if err = consumeTenantApprovalTx(ctx, tx, command.ApprovalID, "tenant.quarantine", current.ID, command.Actor.PrincipalID, command.CommandID, impact.RequestDigest, now); err != nil { return ManagedTenant{}, err }
	next := current; next.State, next.LifecycleState = TenantDeleting, TenantLifecycleDeletionPending; next.SuspendedAt = nil; next.DeletionRequestedAt = &now; retention := now.Add(tenantDeletionRetention); next.RetentionDeadline = &retention; next.Revision++; next.Generation++; next.AuthzEpoch++; next.UpdatedAt = now; next.Delegation.Provenance = appendTenantProvenance(next.Delegation.Provenance, command.ApprovalID)
	if err = updateBaseTenantCASTx(ctx, tx, next, current.Generation); err == nil { err = updateTenantLifecycleCASTx(ctx, tx, next, current.Revision) }; if err == nil { err = invalidateTenantSubtreeTx(ctx, tx, next.ID, next.AuthzEpoch, now) }; if err != nil { return ManagedTenant{}, err }
	if err = s.auditTenantMutation(ctx, command.Actor.PrincipalID, "tenant.quarantine", next, command.CommandID, current, next); err != nil { return ManagedTenant{}, err }; if err = completeTenantCommandTx(ctx, tx, command.CommandID, next.ID, now); err != nil { return ManagedTenant{}, err }; if err = tx.Commit(); err != nil { return ManagedTenant{}, err }
	return s.store.ManagedTenant(ctx, next.ID)
}

func tenantMemberPrincipalsTx(ctx context.Context, tx *sql.Tx, tenantID ID) ([]ID, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT principal_id FROM identity_memberships WHERE tenant_id=?`, tenantID); if err != nil { return nil, err }; defer rows.Close()
	var values []ID; for rows.Next() { var id ID; if err = rows.Scan(&id); err != nil { return nil, err }; values = append(values, id) }; return values, rows.Err()
}

func deleteTenantAuthorityTx(ctx context.Context, tx *sql.Tx, tenantID ID, now time.Time) error {
	principals, err := tenantMemberPrincipalsTx(ctx, tx, tenantID); if err != nil { return err }
	if _, err = tx.ExecContext(ctx, `DELETE FROM identity_managed_role_binding_edges WHERE logical_binding_id IN (SELECT id FROM identity_managed_role_bindings WHERE tenant_id=?)`, tenantID); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `DELETE FROM identity_role_bindings WHERE tenant_id=?`, tenantID); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `DELETE FROM identity_managed_role_bindings WHERE tenant_id=?`, tenantID); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `DELETE FROM identity_role_versions WHERE tenant_id=?`, tenantID); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `DELETE FROM identity_role_catalog WHERE tenant_id=?`, tenantID); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `DELETE FROM identity_roles WHERE tenant_id=?`, tenantID); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `UPDATE identity_memberships SET state='revoked',generation=generation+1,updated_at=? WHERE tenant_id=? AND state<>'revoked'`, now, tenantID); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `UPDATE identity_human_user_memberships SET lifecycle_suspended=1,updated_at=? WHERE tenant_id=?`, now, tenantID); err != nil { return err }
	for _, principal := range principals { if err = invalidateRoleSubjectTx(ctx, tx, principal, now); err != nil { return err } }
	if _, err = tx.ExecContext(ctx, `DELETE FROM identity_delegations WHERE child_tenant_id=?`, tenantID); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `DELETE FROM identity_plans WHERE owner_tenant_id=?`, tenantID); err != nil { return err }
	return nil
}

func (s *Service) PurgeManagedTenant(ctx context.Context, command TenantTransitionCommand) (ManagedTenant, error) {
	if !command.CommandID.Valid() || command.ExpectedRevision == 0 { return ManagedTenant{}, ErrInvalid }
	if err := s.authorizeVisibleTenant(ctx, command.Actor, command.AdministrativeTenantID, command.TenantID, "identity:manage", AssurancePhishingResistant, true); err != nil { return ManagedTenant{}, err }
	digestValue := tenantDigest(command)
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{Isolation:sql.LevelSerializable}); if err != nil { return ManagedTenant{}, err }; defer tx.Rollback()
	if replayID, replay, reserveErr := tenantCommandTx(ctx, tx, command.CommandID, digestValue, command.Actor.PrincipalID, command.TenantID); reserveErr != nil { return ManagedTenant{}, reserveErr } else if replay { tx.Rollback(); return s.store.ManagedTenant(ctx, replayID) }
	current, err := managedTenantTx(ctx, tx, command.TenantID); if err != nil { return ManagedTenant{}, err }; if current.Revision != command.ExpectedRevision { return ManagedTenant{}, ErrStaleGeneration }
	now := s.clock().UTC(); impact, err := tenantDeletionImpactTx(ctx, tx, current, now); if err != nil { return ManagedTenant{}, err }; if !impact.CanPurge { return ManagedTenant{}, ErrConflict }
	if err = consumeTenantApprovalTx(ctx, tx, command.ApprovalID, "tenant.purge", current.ID, command.Actor.PrincipalID, command.CommandID, impact.RequestDigest, now); err != nil { return ManagedTenant{}, err }
	next := current; next.State, next.LifecycleState = TenantDeleted, TenantLifecycleDeleted; next.DeletedAt = &now; next.Revision++; next.Generation++; next.AuthzEpoch++; next.UpdatedAt = now; next.Delegation.Provenance = appendTenantProvenance(next.Delegation.Provenance, command.ApprovalID)
	if err = deleteTenantAuthorityTx(ctx, tx, next.ID, now); err == nil { err = updateBaseTenantCASTx(ctx, tx, next, current.Generation) }; if err == nil { err = updateTenantLifecycleCASTx(ctx, tx, next, current.Revision) }; if err != nil { return ManagedTenant{}, err }
	if err = s.auditTenantMutation(ctx, command.Actor.PrincipalID, "tenant.purge", next, command.CommandID, current, next); err != nil { return ManagedTenant{}, err }; if err = completeTenantCommandTx(ctx, tx, command.CommandID, next.ID, now); err != nil { return ManagedTenant{}, err }; if err = tx.Commit(); err != nil { return ManagedTenant{}, err }
	return s.store.ManagedTenant(ctx, next.ID)
}
