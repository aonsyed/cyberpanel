//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/apps"
	hostingservice "github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/sqlrepo"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/accesspolicy"
)

type hostingCloneEdge struct {
	hosting  hostingservice.Service
	sites    *sqlrepo.Repository
	apps     apps.SQLRepository
	staging  *apps.StagingCoordinator
	access   *apps.AccessProtectionService
	executor *apps.LinuxApplicationClient
	secrets *apps.ApplicationSecretIssuer
	policies *accesspolicy.Authority
	now      func() time.Time
}

func newHostingCloneEdge(hosting hostingservice.Service, sites *sqlrepo.Repository, applications apps.SQLRepository, staging *apps.StagingCoordinator, accessProtection *apps.AccessProtectionService, executor *apps.LinuxApplicationClient, secrets *apps.ApplicationSecretIssuer, policies *accesspolicy.Authority, now func() time.Time) (*hostingCloneEdge, error) {
	if sites == nil || applications.DB == nil || staging == nil || accessProtection == nil || executor == nil || secrets == nil || policies == nil { return nil, apps.ErrInvalid }
	if now == nil { now = time.Now }
	return &hostingCloneEdge{hosting:hosting,sites:sites,apps:applications,staging:staging,access:accessProtection,executor:executor,secrets:secrets,policies:policies,now:now},nil
}

func (edge *hostingCloneEdge) CloneSite(ctx context.Context, call apiserver.EdgeCall, payload apiserver.HostingClonePayload, material apiserver.ApplicationCloneMaterial) (apiserver.EdgeMutation[apiserver.HostingSiteProjection], error) {
	if (len(material.DatabaseClientCertificate)==0)!=(len(material.DatabaseClientKey)==0) { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{},apps.ErrInvalid }
	if len(material.DatabaseClientCertificate)>0 { if err:=apps.ValidateApplicationDatabaseClientIdentity(material.DatabaseClientCertificate,material.DatabaseClientKey,edge.now());err!=nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{},err } }
	tenant, err := site.NewTenantID(call.TenantID)
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	sourceSiteID, err := site.NewSiteID(call.ResourceID)
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	sourceSite, err := edge.sites.Load(ctx, tenant, sourceSiteID)
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	if sourceSite.Generation() != call.ExpectedGeneration || sourceSite.Lifecycle() != site.LifecycleActive { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, site.ErrStaleGeneration }
	installations, _, err := edge.apps.ListInstallations(ctx, apps.TenantID(call.TenantID), apps.SiteID(sourceSiteID.String()), 32, "")
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	active := make([]apps.ApplicationInstallation, 0, 1)
	for _, installation := range installations { if installation.State == apps.InstallationActive || installation.State == apps.InstallationMaintenance { active = append(active, installation) } }
	if len(active) != 1 || active[0].Kind != apps.ApplicationWordPress { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, apps.ErrUnsupported }
	sourceApplication := active[0]
	sourceScope, err := edge.executor.ResolveExecutionScope(ctx, sourceApplication)
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	targetToken := cloneToken(call.CommandID)
	targetSiteID, _ := site.NewSiteID("clone-" + targetToken)
	targetProject, err := site.NewProjectID(payload.ProjectID)
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	targetHostname, err := site.ParseHostname(payload.PrimaryHostname)
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	actor := hostingservice.Actor{TenantID: tenant}
	created, err := edge.hosting.Handle(ctx, hostingservice.CreateSite{CommandID: call.CommandID+"-site", Actor: actor, TenantID: tenant, Site: site.CreateInput{ID: targetSiteID, TenantID: tenant, ProjectID: targetProject, PrimaryHostname: targetHostname, PHPProfile: sourceSite.PHPProfile()}})
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	activeReceipt, err := edge.hosting.Handle(ctx, hostingservice.MarkProvisioned{CommandID: call.CommandID+"-site-active", Actor: actor, TenantID: tenant, SiteID: targetSiteID, ExpectedGeneration: created.Request.Projection.Generation})
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	targetScope, err := edge.executor.ResolveSiteBinding(ctx, apps.TenantID(call.TenantID), apps.SiteID(targetSiteID.String()))
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	targetScope.Root = sourceApplication.Root
	engineHostname, err := webengine.ParseHostname(targetHostname.String())
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	policy, err := edge.policies.ConfigureBinding(ctx, accesspolicy.ConfigureBindingRequest{EffectID:call.CommandID+"-access",Scope:hostingservice.CommandScope{TenantID:tenant,SiteID:targetSiteID},Hostname:engineHostname,ResourceID:call.ResourceID,Enabled:true,CredentialRef:payload.AccessCredentialRef,Realm:"Protected staging",Route:"/"})
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	targetInstallationID := apps.InstallationID("clone-" + targetToken)
	relationID := apps.StagingRelationID("staging-" + targetToken)
	var clientIdentity apps.SecretRef
	if len(material.DatabaseClientCertificate)>0 {
		clientIdentity,err=edge.secrets.EnrollDatabaseClientIdentity(ctx,apps.TenantID(call.TenantID),apps.SiteID(targetSiteID.String()),targetInstallationID,material.DatabaseClientCertificate,material.DatabaseClientKey)
		if err!=nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{},err }
	}
	cloneCommand:=apps.CommandID(call.CommandID+"-application")
	targetInstallation, _, err := edge.staging.CreateClone(ctx, apps.CloneRequest{CommandID:cloneCommand,RelationID:relationID,TenantID:apps.TenantID(call.TenantID),Source:sourceApplication,TargetSiteID:apps.SiteID(targetSiteID.String()),TargetProjectID:apps.ProjectID(payload.ProjectID),TargetSiteUID:targetScope.SiteUID,TargetInstallationID:targetInstallationID,TargetDatabaseInstanceID:apps.DatabaseInstanceID(payload.DatabaseInstanceID),TargetDatabaseClientIdentityRef:clientIdentity,TargetRoot:sourceApplication.Root,SourceURL:"https://"+primaryHostname(sourceSite),TargetURL:"https://"+targetHostname.String(),TargetRuntimeID:sourceApplication.RuntimeID,CreateDatabase:payload.CopyDatabase,MailSuppressed:true,ExternalActionsDenied:true,AccessPolicyID:string(policy.PolicyRef)},sourceScope,targetScope)
	if err != nil {
		if clientIdentity!="" {
			cleanup,cancel:=context.WithTimeout(context.WithoutCancel(ctx),30*time.Second);defer cancel()
			operation,loadErr:=edge.apps.LoadOperation(cleanup,cloneCommand)
			if loadErr==nil && (operation.State==apps.OperationFailed || operation.State==apps.OperationCompensated) { err=errors.Join(err,edge.secrets.RevokeApplicationSecret(cleanup,clientIdentity)) }
		}
		return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err
	}
	_, err = edge.access.Configure(ctx, apps.AccessProtectionRequest{
		CommandID:          apps.CommandID(call.CommandID + "-access-binding"),
		InstallationID:     targetInstallation.ID,
		ExpectedGeneration: targetInstallation.Generation,
		Binding: apps.AccessProtectionBinding{
			InstallationID: targetInstallation.ID,
			PolicyID:       string(policy.PolicyRef),
			Route:          policy.Route,
			Enabled:        true,
			Generation:     1,
		},
	})
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	targetSite, err := edge.sites.Load(ctx, tenant, targetSiteID)
	if err != nil { return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{}, err }
	projection := hostingEdgeSiteProjection(targetSite)
	projection.UpdatedAt = edge.now().UTC()
	return apiserver.EdgeMutation[apiserver.HostingSiteProjection]{OperationID:call.CommandID,State:string(activeReceipt.Status),Generation:projection.Generation,Resource:projection},nil
}

func cloneToken(commandID string) string { sum:=sha256.Sum256([]byte("cyberpanel:hosting-clone:v1\x00"+commandID));return hex.EncodeToString(sum[:])[:48] }
func primaryHostname(value site.Site) string { for _,binding:=range value.Bindings(){if binding.Kind==site.BindingPrimary{return binding.Hostname.String()}};return "" }

var _ apiserver.HostingCloneEdgeService = (*hostingCloneEdge)(nil)
