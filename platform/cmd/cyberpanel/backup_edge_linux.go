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
	restores *backup.RestoreCoordinator
	now      func() time.Time
}

func newBackupEdge(catalog backup.BackupCatalog, restores *backup.RestoreCoordinator, now func() time.Time) (*backupEdge, error) {
	if catalog.DB == nil || restores == nil || restores.Store.DB == nil || restores.Capacity == nil || restores.Source == nil || now == nil { return nil, backup.ErrInvalidBackup }
	return &backupEdge{catalog: catalog, restores: restores, now: now}, nil
}

func (edge *backupEdge) CreatePolicy(ctx context.Context, call apiserver.EdgeCall, payload apiserver.BackupPolicyCreatePayload) (apiserver.EdgeMutation[apiserver.BackupPolicyProjection], error) {
	if edge == nil || ctx == nil || call.CommandID == "" || call.TenantID == "" || payload.Scope == "" || payload.RepositoryID == "" {
		return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{}, backup.ErrInvalidBackup
	}
	repository,err := edge.catalog.Repository(ctx, call.TenantID, backup.RepositoryID(payload.RepositoryID))
	if err != nil {
		return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{}, err
	}
	objectFormat:=repository.ObjectFormat
	if objectFormat==""{objectFormat="legacy-plaintext-v1"}
	retention, normalizedRetention, err := backupRetention(payload.Retention)
	if err != nil { return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{}, err }
	policyID := backup.PolicyID(backupEdgeID("policy", call.TenantID, call.CommandID))
	policy := backup.BackupPolicySpec{
		ID: policyID, TenantID: call.TenantID, Scope: payload.Scope, Schedule: payload.Schedule,
		Components: append([]backup.ComponentKind(nil),payload.Components...), Repositories: []backup.RepositoryID{backup.RepositoryID(payload.RepositoryID)},
		RequiredCopies: 1, Consistency: payload.Consistency, Retention: retention, Generation: 1, Enabled: true,
	}
	if err = apiserver.ValidateLocalBackupPolicy(policy); err != nil { return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{},err }
	if err = edge.catalog.PutPolicy(ctx, policy, 0); err != nil {
		// Idempotent retries must resolve to the exact previously admitted policy.
		prior, loadErr := edge.catalog.Policy(ctx, call.TenantID, policyID)
		if loadErr != nil || !equalBackupPolicy(prior, policy) { return apiserver.EdgeMutation[apiserver.BackupPolicyProjection]{}, err }
		policy = prior
	}
	name := strings.TrimSpace(payload.Name); if name == "" { name = string(policy.ID) }
	projection := apiserver.BackupPolicyProjection{ID:string(policy.ID),Name:name,Scope:policy.Scope,Schedule:policy.Schedule,RepositoryID:payload.RepositoryID,RepositoryObjectFormat:objectFormat,Retention:normalizedRetention,State:"active",Generation:policy.Generation,UpdatedAt:edge.now().UTC()}
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
	plan := backup.RestorePlanSpec{ID:backup.RestoreID(backupEdgeID("restore",call.TenantID,call.CommandID)),IdempotencyKey:call.IdempotencyKey,TenantID:call.TenantID,RecoveryPointID:manifest.RecoveryPointID,SourceScope:manifest.Scope,TargetScope:payload.TargetScope,ComponentMapping:mapping,CollisionPolicy:backup.CollisionReplaceBlueGreen,SecretPolicy:backup.SecretResetRequired,DomainMapping:cloneDomainMapping(payload.DomainMapping),RequiredFreeBytes:required,Generation:1}
	if plan.IdempotencyKey == "" { plan.IdempotencyKey = call.CommandID }
	receipt, err := edge.restores.Plan(ctx, plan)
	if err != nil { return apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection]{}, err }
	projection := apiserver.BackupRestorePlanProjection{ID:string(plan.ID),RecoveryPointID:string(plan.RecoveryPointID),TargetScope:plan.TargetScope,DomainMapping:cloneDomainMapping(plan.DomainMapping),RequiredBytes:plan.RequiredFreeBytes,PlanDigest:receipt.PlanDigest,Generation:receipt.Generation}
	return apiserver.EdgeMutation[apiserver.BackupRestorePlanProjection]{OperationID:call.CommandID,State:string(receipt.Phase),Generation:receipt.Generation,Resource:projection},nil
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

func backupEdgeID(prefix string, values ...string) string { sum:=sha256.Sum256([]byte(strings.Join(values,"\x00")));return prefix+"_"+hex.EncodeToString(sum[:])[:48] }
func cloneDomainMapping(source map[string]string) map[string]string { if source==nil{return nil};target:=make(map[string]string,len(source));for key,value:=range source{target[key]=value};return target }
func equalBackupPolicy(left,right backup.BackupPolicySpec) bool { a,_:=json.Marshal(left);b,_:=json.Marshal(right);return string(a)==string(b) }
