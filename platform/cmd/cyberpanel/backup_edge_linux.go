//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/backup"
)

type backupEdge struct {
	catalog  backup.BackupCatalog
	restores backup.RestoreStore
	now      func() time.Time
}

func newBackupEdge(catalog backup.BackupCatalog, restores backup.RestoreStore, now func() time.Time) (*backupEdge, error) {
	if catalog.DB == nil || restores.DB == nil || now == nil { return nil, backup.ErrInvalidBackup }
	return &backupEdge{catalog: catalog, restores: restores, now: now}, nil
}

func (edge *backupEdge) CreatePolicy(ctx context.Context, call apiserver.EdgeCall, payload apiserver.BackupPolicyCreatePayload) (apiserver.EdgeMutation[apiserver.BackupPolicyProjection], error) {
	if edge == nil || ctx == nil || call.CommandID == "" || call.TenantID == "" || payload.Scope == "" || payload.RepositoryID == "" {
		return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{}, backup.ErrInvalidBackup
	}
	if _, err := edge.catalog.Repository(ctx, call.TenantID, backup.RepositoryID(payload.RepositoryID)); err != nil {
		return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{}, err
	}
	retention, normalizedRetention, err := backupRetention(payload.Retention)
	if err != nil { return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{}, err }
	policyID := backup.PolicyID(backupEdgeID("policy", call.TenantID, call.CommandID))
	policy := backup.BackupPolicySpec{
		ID: policyID, TenantID: call.TenantID, Scope: payload.Scope, Schedule: payload.Schedule,
		Components: backupComponents(payload.Scope), Repositories: []backup.RepositoryID{backup.RepositoryID(payload.RepositoryID)},
		RequiredCopies: 1, Consistency: backup.ConsistencyApplication, Retention: retention, Generation: 1, Enabled: true,
	}
	if err = edge.catalog.PutPolicy(ctx, policy, 0); err != nil {
		// Idempotent retries must resolve to the exact previously admitted policy.
		prior, loadErr := edge.catalog.Policy(ctx, call.TenantID, policyID)
		if loadErr != nil || !equalBackupPolicy(prior, policy) { return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{}, err }
		policy = prior
	}
	name := strings.TrimSpace(payload.Name); if name == "" { name = string(policy.ID) }
	projection := apiserver.BackupPolicyProjection{ID:string(policy.ID),Name:name,Scope:policy.Scope,Schedule:policy.Schedule,RepositoryID:payload.RepositoryID,Retention:normalizedRetention,State:"active",Generation:policy.Generation,UpdatedAt:edge.now().UTC()}
	return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{OperationID:call.CommandID,State:"applied",Generation:policy.Generation,Resource:projection},nil
}

func (edge *backupEdge) PlanRestore(ctx context.Context, call apiserver.EdgeCall, payload apiserver.BackupRestorePlanPayload) (apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection], error) {
	if edge == nil || ctx == nil || call.CommandID == "" || call.TenantID == "" || payload.RecoveryPointID == "" || payload.TargetScope == "" {
		return apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection]{}, backup.ErrInvalidBackup
	}
	manifest, copies, err := edge.catalog.RecoveryPoint(ctx, call.TenantID, backup.RecoveryPointID(payload.RecoveryPointID))
	if err != nil { return apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection]{}, err }
	verified := false
	for _, receipt := range copies { if receipt.Status == backup.CopyVerified && !receipt.VerifiedAt.IsZero() && receipt.ManifestDigest == manifest.ManifestDigest { verified = true; break } }
	if !verified { return apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection]{}, backup.ErrInvalidBackup }
	mapping := make(map[backup.ComponentKind]string,len(manifest.Artifacts)); required := uint64(0)
	for _, artifact := range manifest.Artifacts {
		mapping[artifact.Component] = payload.TargetScope
		if artifact.Bytes > math.MaxUint64-required { return apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection]{}, backup.ErrInvalidBackup }
		required += artifact.Bytes
	}
	if required == 0 { return apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection]{}, backup.ErrInvalidBackup }
	plan := backup.RestorePlanSpec{ID:backup.RestoreID(backupEdgeID("restore",call.TenantID,call.CommandID)),IdempotencyKey:call.IdempotencyKey,TenantID:call.TenantID,RecoveryPointID:manifest.RecoveryPointID,SourceScope:manifest.Scope,TargetScope:payload.TargetScope,ComponentMapping:mapping,CollisionPolicy:backup.CollisionReplaceBlueGreen,SecretPolicy:backup.SecretRotate,DomainMapping:cloneDomainMapping(payload.DomainMapping),RequiredFreeBytes:required,Generation:1}
	if plan.IdempotencyKey == "" { plan.IdempotencyKey = call.CommandID }
	receipt, _, err := edge.restores.Admit(ctx, plan)
	if err != nil { return apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection]{}, err }
	projection := apiserver.BackupRestorePlanProjection{ID:string(plan.ID),RecoveryPointID:string(plan.RecoveryPointID),TargetScope:plan.TargetScope,DomainMapping:cloneDomainMapping(plan.DomainMapping),RequiredBytes:plan.RequiredFreeBytes,PlanDigest:backupPlanDigest(plan),Generation:plan.Generation}
	return apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection]{OperationID:call.CommandID,State:string(receipt.Phase),Generation:plan.Generation,Resource:projection},nil
}

func backupRetention(raw string) (backup.RetentionPolicy,string,error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	policy := backup.RetentionPolicy{MinimumAge:24*time.Hour,MinimumVerifiedCopies:1}
	switch value {
	case "7d", "daily-7": policy.KeepLast=7;policy.KeepDaily=7;value="7d"
	case "30d", "daily-30": policy.KeepLast=30;policy.KeepDaily=30;policy.KeepWeekly=4;value="30d"
	case "90d", "gfs-90": policy.KeepLast=30;policy.KeepDaily=14;policy.KeepWeekly=12;policy.KeepMonthly=3;value="90d"
	case "gfs", "gfs-1y": policy.KeepLast=24;policy.KeepHourly=24;policy.KeepDaily=14;policy.KeepWeekly=8;policy.KeepMonthly=12;value="gfs-1y"
	default: return backup.RetentionPolicy{},"",backup.ErrInvalidBackup
	}
	return policy,value,nil
}

func backupComponents(scope string) []backup.ComponentKind {
	switch scope {
	case "mail": return []backup.ComponentKind{backup.ComponentMail,backup.ComponentDNS,backup.ComponentSecrets}
	case "database": return []backup.ComponentKind{backup.ComponentDatabase,backup.ComponentSecrets}
	case "installation", "node": return []backup.ComponentKind{backup.ComponentFiles,backup.ComponentDatabase,backup.ComponentMail,backup.ComponentDNS,backup.ComponentControlState,backup.ComponentApplication,backup.ComponentSecrets}
	default: return []backup.ComponentKind{backup.ComponentFiles,backup.ComponentDatabase,backup.ComponentDNS,backup.ComponentApplication,backup.ComponentSecrets}
	}
}

func backupEdgeID(prefix string, values ...string) string { sum:=sha256.Sum256([]byte(strings.Join(values,"\x00")));return prefix+"_"+hex.EncodeToString(sum[:])[:48] }
func backupPlanDigest(plan backup.RestorePlanSpec) string { raw,_:=json.Marshal(plan);sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:]) }
func cloneDomainMapping(source map[string]string) map[string]string { if source==nil{return nil};target:=make(map[string]string,len(source));for key,value:=range source{target[key]=value};return target }
func equalBackupPolicy(left,right backup.BackupPolicySpec) bool { a,_:=json.Marshal(left);b,_:=json.Marshal(right);return string(a)==string(b) }
