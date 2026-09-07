//go:build linux

package main

import (
	"context"
	"errors"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/catalog"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/composer"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/enterprise"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/management"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/ols"
)

// Rehearsal projects only the approved target into an isolated candidate. It
// never changes the hosting aggregate or publishes that candidate's listener.
type migrationApplicationProbe struct {
	catalog *catalog.SQLCatalog
	runtime *management.Runtime
	installations management.Repository
	scopes *migration.RuntimeScopeStore
}

func (probe *migrationApplicationProbe) VerifyDark(ctx context.Context,value migration.Migration,plan migration.Plan)(migration.Verification,error){return probe.verify(ctx,value,plan,false)}
func (probe *migrationApplicationProbe) VerifyActive(ctx context.Context,value migration.Migration,plan migration.Plan,receipt migration.ActivationReceipt)(migration.Verification,error){
	if receipt.MigrationID!=value.ID||receipt.EvidenceDigest==""{return migration.Verification{},migration.ErrInvalid};return probe.verify(ctx,value,plan,true)
}

func (probe *migrationApplicationProbe) verify(ctx context.Context,value migration.Migration,plan migration.Plan,active bool)(migration.Verification,error){
	if probe==nil||probe.catalog==nil||probe.runtime==nil||probe.installations==nil||probe.scopes==nil||plan.MigrationID!=value.ID||plan.DryRunDigest!=value.PlanDigest||plan.ApprovedAt==nil||plan.ApprovalDigest==""{return migration.Verification{},migration.ErrBlocked}
	scope,err:=probe.scopes.LoadByMigration(ctx,value.ID);if err!=nil{return migration.Verification{},err};installation,err:=probe.installations.Installation(ctx);if err!=nil||installation.Generation==0||installation.Generation==^uint64(0){return migration.Verification{},errors.Join(migration.ErrBlocked,err)}
	state,err:=probe.catalog.NodeState(ctx);if err!=nil||state.SnapshotGeneration==^uint64(0){return migration.Verification{},errors.Join(migration.ErrBlocked,err)};candidate,err:=probe.catalog.PlanForEdition(ctx,installation.Edition,state.SnapshotGeneration+1);if err!=nil{return migration.Verification{},err}
	var targetID string;for _,mapping:=range plan.Mappings{if mapping.SourceKind==string(migration.ImportSite){if targetID!=""||mapping.Disposition!=migration.DispositionCreate{return migration.Verification{},migration.ErrBlocked};targetID=mapping.TargetID.String()}};if targetID==""{return migration.Verification{},migration.ErrBlocked}
	selected:=[]composer.SiteInput{};for _,input:=range candidate.Sites{if input.Scope.SiteID.String()!=targetID{continue};if input.Scope.TenantID.String()!=scope.TenantID||input.Withdraw{return migration.Verification{},migration.ErrConflict};wanted:=site.LifecycleProvisioning;if active{wanted=site.LifecycleActive};if input.Projection.Lifecycle!=wanted{return migration.Verification{},migration.ErrConflict};input.Projection.Lifecycle=site.LifecycleActive;selected=append(selected,input)};if len(selected)!=1{return migration.Verification{},migration.ErrBlocked}
	candidate.Sites=selected;candidate.ProxyRoutes=nil;policies:=candidate.AccessPolicies[:0];for _,policy:=range candidate.AccessPolicies{if policy.Scope.SiteID.String()==targetID&&policy.Scope.TenantID.String()==scope.TenantID{policies=append(policies,policy)}};candidate.AccessPolicies=policies
	composed,err:=composer.Compose(candidate);if err!=nil{return migration.Verification{},err};render:=native.RenderRequest{Desired:composed.Desired,Snapshot:composed.Snapshot};var renderer native.Renderer
	switch installation.Edition{case webengine.EditionOpenLiteSpeed:renderer=ols.New();case webengine.EditionLiteSpeedEnterprise:renderer=enterprise.New();default:return migration.Verification{},migration.ErrBlocked};generation,err:=renderer.Render(ctx,render);if err!=nil{return migration.Verification{},err}
	mode:="dark";if active{mode="active"};request:=management.EffectRequest{EffectID:"migration-probe-"+migrationHostDigest([]string{value.ID.String(),plan.ApprovalDigest,generation.ContentDigest,mode}),ExpectedGeneration:installation.Generation,Fence:installation.Generation+1,PlanDigest:generation.ContentDigest,CommitAuthorizationDigest:plan.ApprovalDigest}
	var receipt management.ProbeReceipt;if active{receipt,err=probe.runtime.ProbeActive(ctx,request,render)}else{receipt,err=probe.runtime.ProbeCandidate(ctx,request,render)}
	verification:=migration.Verification{HTTP:receipt.HTTP,TLS:receipt.TLS&&receipt.HTTPS,PHP:receipt.PHP,EvidenceDigest:receipt.EvidenceDigest,ObservedAt:receipt.ObservedAt};if err!=nil||receipt.EffectID!=request.EffectID||receipt.ConfigDigest!=request.PlanDigest||!verification.HTTP||!verification.PHP||!verification.TLS||receipt.EvidenceDigest==""||receipt.ObservedAt.IsZero(){return verification,errors.Join(migration.ErrBlocked,err)};return verification,nil
}
