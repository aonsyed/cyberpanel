package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/containers"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/integrations"
)

type ContainerImagePayload struct{RegistryCredentialID containers.ID `json:"registry_credential_id,omitempty"`;Registry string `json:"registry"`;Repository string `json:"repository"`;Tag string `json:"tag"`;Platform string `json:"platform"`}
type ContainerVolumePayload struct{Name string `json:"name"`;Class string `json:"class"`;QuotaBytes uint64 `json:"quota_bytes"`;InodeLimit uint64 `json:"inode_limit"`}
type ContainerNetworkPayload struct{Name string `json:"name"`;IPv4 netip.Prefix `json:"ipv4,omitempty"`;IPv6 netip.Prefix `json:"ipv6,omitempty"`;Internal bool `json:"internal"`;DNSPolicy string `json:"dns_policy"`}
type ContainerWorkloadPayload struct{ProjectID containers.ID `json:"project_id,omitempty"`;SiteID containers.ID `json:"site_id,omitempty"`;Name string `json:"name"`;Tier containers.RuntimeTier `json:"tier"`;Spec containers.WorkloadSpec `json:"spec"`}
type ContainerLifecyclePayload struct{Lifecycle containers.Lifecycle `json:"lifecycle"`;CommitAuthorizationDigest string `json:"commit_authorization_digest"`}
type ContainerExposurePayload struct{Exposure containers.Exposure `json:"exposure"`}
type ContainerDeletePayload struct{}
type ContainerApplicationDeployPayload struct{SiteID containers.ID `json:"site_id"`;RecipeID containers.ID `json:"recipe_id"`;RecipeVersion string `json:"recipe_version"`}
type ContainerApplicationUpdatePayload struct{RecipeID containers.ID `json:"recipe_id"`;RecipeVersion string `json:"recipe_version"`;BackwardCompatibleData bool `json:"backward_compatible_data"`}
type ContainerExecExchangePayload struct{GrantID containers.ID `json:"grant_id"`;Token string `json:"token"`}

type N8NActionPayload struct {
 Installation integrations.N8NInstallation `json:"installation"`
 InstallationID integrations.ID `json:"installation_id"`
 Definition *integrations.N8NDefinition `json:"definition,omitempty"`
 ExpectedGeneration uint64 `json:"expected_generation,omitempty"`
}

func registerContainerContracts(registry *Registry)error{
	operations:=[]Operation{
		{Name:"container.image.pull",Permission:identity.MustPermission("container:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerImagePayload{}},ResolveScope:tenantScope},
		{Name:"container.volume.ensure",Permission:identity.MustPermission("container:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerVolumePayload{}},ResolveScope:tenantScope},
		{Name:"container.volume.delete",Permission:identity.MustPermission("container:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerDeletePayload{}},ResolveScope:tenantScope},
		{Name:"container.network.ensure",Permission:identity.MustPermission("container:manage"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerNetworkPayload{}},ResolveScope:tenantScope},
		{Name:"container.network.delete",Permission:identity.MustPermission("container:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerDeletePayload{}},ResolveScope:tenantScope},
		{Name:"container.workload.apply",Permission:identity.MustPermission("container:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerWorkloadPayload{}},ResolveScope:tenantScope},
		{Name:"container.workload.lifecycle",Permission:identity.MustPermission("container:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerLifecyclePayload{}},ResolveScope:tenantScope},
		{Name:"container.exposure.apply",Permission:identity.MustPermission("container:expose"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerExposurePayload{}},ResolveScope:tenantScope},
		{Name:"container.exposure.delete",Permission:identity.MustPermission("container:expose"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerDeletePayload{}},ResolveScope:tenantScope},
		{Name:"container.application.deploy",Permission:identity.MustPermission("container:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerApplicationDeployPayload{}},ResolveScope:tenantScope},
		{Name:"container.application.update",Permission:identity.MustPermission("container:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ContainerApplicationUpdatePayload{}},ResolveScope:tenantScope},
		{Name:"container.exec.exchange",Auth:AuthNone,Mutating:true,MaximumBodyBytes:16<<10,NewPayload:func()any{return &ContainerExecExchangePayload{}},ValidatePayload:func(value any)error{payload:=value.(*ContainerExecExchangePayload);if !payload.GrantID.Valid()||len(payload.Token)<32||len(payload.Token)>512{return invalid("container exec exchange")};return nil},ResolveScope:globalScope},
	}
	for _, action := range []string{"install","observe","update","suspend","resume","remove"} {
 operations=append(operations,Operation{Name:"integration.n8n."+action,Permission:identity.MustPermission("container:expose"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:action!="observe",MaximumBodyBytes:64<<10,NewPayload:func()any{return &N8NActionPayload{}},ResolveScope:tenantScope})
}
for _,operation:=range operations{if err:=register(registry,operation);err!=nil{return err}}
	return nil
}

func containerMeta(inv Invocation,operation string,resource containers.ID)containers.CommandMeta{tenant,_:=containers.NewID(inv.Request.TenantID);sum:=sha256.Sum256([]byte(inv.Actor.PrincipalID.String()+"\x00"+operation+"\x00"+resource.String()+"\x00"+inv.IdempotencyKey));grant:=containers.Grant{TenantID:tenant,ResourceID:resource,Operation:operation,AuthzEpoch:inv.Actor.AuthzEpoch,ExpiresAt:time.Now().UTC().Add(30*time.Second),Digest:hex.EncodeToString(sum[:])};fence:=inv.Request.ExpectedGeneration+1;if fence==0{fence=1};return containers.CommandMeta{CommandID:commandID(inv),Grant:grant,ExpectedGeneration:inv.Request.ExpectedGeneration,Fence:containers.FenceToken(fence)}}

func bindContainers(registry *Registry,services DomainServices)error{
 if services.N8N != nil {
  for _, action := range []string{"install","observe","update","suspend","resume","remove"} {
   action:=action
   if err:=registry.Bind("integration.n8n."+action,func(ctx context.Context,inv Invocation,value any)(OperationResult,error){
    payload:=value.(*N8NActionPayload)
    id:=payload.InstallationID
    if action=="install"{id=payload.Installation.ID}
    if id==""{id=integrations.ID(inv.Request.ResourceID)}
    resource,err:=containers.NewID(string(id));if err!=nil{return OperationResult{},ErrInvalidRequest}
    if inv.Request.ResourceID!=""&&inv.Request.ResourceID!=string(id){return OperationResult{},ErrInvalidRequest}
    generation:=inv.Request.ExpectedGeneration
    if payload.ExpectedGeneration!=0{if generation!=0&&generation!=payload.ExpectedGeneration{return OperationResult{},ErrInvalidRequest};generation=payload.ExpectedGeneration}
    inv.Request.ExpectedGeneration=generation
    meta:=containerMeta(inv,"application.deploy",resource)
    if action=="observe"{receipt,err:=services.N8N.Observe(ctx,meta,id);if err!=nil{return OperationResult{},n8nAPIError(err)};return OperationResult{Status:http.StatusOK,Value:receipt,Generation:receipt.ObservedGeneration},nil}
    installation:=payload.Installation
    if action!="install"{
     current,err:=services.N8N.Store.LoadN8NInstallation(ctx,id);if err!=nil{return OperationResult{},n8nAPIError(err)}
     if string(current.TenantID)!=inv.Request.TenantID{return OperationResult{},ErrNotFound}
     installation=current
     if action=="update"{if payload.Definition==nil{return OperationResult{},ErrInvalidRequest};installation.Definition=*payload.Definition}
    }
    if action=="install"{installation.TenantID=integrations.TenantID(inv.Request.TenantID)}
    receipt,err:=services.N8N.Apply(ctx,meta,installation,action);if err!=nil{return OperationResult{},n8nAPIError(err)}
    status:=http.StatusOK;if action=="install"{status=http.StatusCreated}
    return OperationResult{Status:status,Value:receipt,Generation:receipt.ObservedGeneration},nil
   });err!=nil{return err}
  }
 }

	if services.Containers!=nil{
		if err:=registry.Bind("container.image.pull",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};p:=value.(*ContainerImagePayload);image,result,err:=services.Containers.PullImage(ctx,containers.PullImageCommand{Meta:containerMeta(inv,"image.pull",resource),ImageID:resource,RegistryCredentialID:p.RegistryCredentialID,Registry:p.Registry,Repository:p.Repository,Tag:p.Tag,Platform:p.Platform});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Image containers.Image `json:"image"`;Operation containers.Result `json:"operation"`}{image,result},Generation:image.Generation},nil});err!=nil{return err}
			if err:=registry.Bind("container.volume.ensure",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};p:=value.(*ContainerVolumePayload);volume,result,err:=services.Containers.EnsureVolume(ctx,containers.EnsureVolumeCommand{Meta:containerMeta(inv,"volume.ensure",resource),VolumeID:resource,Name:p.Name,Class:p.Class,QuotaBytes:p.QuotaBytes,InodeLimit:p.InodeLimit});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Volume containers.Volume `json:"volume"`;Operation containers.Result `json:"operation"`}{volume,result},Generation:volume.Generation},nil});err!=nil{return err}
			if err:=registry.Bind("container.volume.delete",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};volume,result,err:=services.Containers.DeleteVolume(ctx,containers.DeleteVolumeCommand{Meta:containerMeta(inv,"volume.delete",resource),VolumeID:resource});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Volume containers.Volume `json:"volume"`;Operation containers.Result `json:"operation"`}{volume,result},Generation:volume.Generation},nil});err!=nil{return err}
			if err:=registry.Bind("container.network.ensure",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};p:=value.(*ContainerNetworkPayload);network,result,err:=services.Containers.EnsureNetwork(ctx,containers.EnsureNetworkCommand{Meta:containerMeta(inv,"network.ensure",resource),NetworkID:resource,Name:p.Name,IPv4:p.IPv4,IPv6:p.IPv6,Internal:p.Internal,DNSPolicy:p.DNSPolicy});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Network containers.Network `json:"network"`;Operation containers.Result `json:"operation"`}{network,result},Generation:network.Generation},nil});err!=nil{return err}
			if err:=registry.Bind("container.network.delete",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};network,result,err:=services.Containers.DeleteNetwork(ctx,containers.DeleteNetworkCommand{Meta:containerMeta(inv,"network.delete",resource),NetworkID:resource});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Network containers.Network `json:"network"`;Operation containers.Result `json:"operation"`}{network,result},Generation:network.Generation},nil});err!=nil{return err}
		if err:=registry.Bind("container.workload.apply",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};p:=value.(*ContainerWorkloadPayload);workload,result,err:=services.Containers.ApplyWorkload(ctx,containers.ApplyWorkloadCommand{Meta:containerMeta(inv,"workload.apply",resource),WorkloadID:resource,ProjectID:p.ProjectID,SiteID:p.SiteID,Name:p.Name,Tier:p.Tier,Spec:p.Spec});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Workload containers.Workload `json:"workload"`;Operation containers.Result `json:"operation"`}{workload,result},Generation:workload.Generation},nil});err!=nil{return err}
		if err:=registry.Bind("container.workload.lifecycle",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};p:=value.(*ContainerLifecyclePayload);workload,result,err:=services.Containers.SetLifecycle(ctx,containers.LifecycleCommand{Meta:containerMeta(inv,"workload.lifecycle",resource),WorkloadID:resource,Lifecycle:p.Lifecycle,CommitAuthorizationDigest:p.CommitAuthorizationDigest});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Workload containers.Workload `json:"workload"`;Operation containers.Result `json:"operation"`}{workload,result},Generation:workload.Generation},nil});err!=nil{return err}
			if err:=registry.Bind("container.exposure.apply",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};p:=value.(*ContainerExposurePayload);p.Exposure.ID=resource;exposure,result,err:=services.Containers.ApplyExposure(ctx,containers.ApplyExposureCommand{Meta:containerMeta(inv,"exposure.apply",resource),Exposure:p.Exposure});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Exposure containers.Exposure `json:"exposure"`;Operation containers.Result `json:"operation"`}{exposure,result},Generation:exposure.Generation},nil});err!=nil{return err}
			if err:=registry.Bind("container.exposure.delete",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};exposure,result,err:=services.Containers.DeleteExposure(ctx,containers.DeleteExposureCommand{Meta:containerMeta(inv,"exposure.delete",resource),ExposureID:resource});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Exposure containers.Exposure `json:"exposure"`;Operation containers.Result `json:"operation"`}{exposure,result},Generation:exposure.Generation},nil});err!=nil{return err}
	}
	if services.ContainerApplications!=nil{
		if err:=registry.Bind("container.application.deploy",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};p:=value.(*ContainerApplicationDeployPayload);application,results,err:=services.ContainerApplications.Deploy(ctx,containers.DeployApplicationCommand{Meta:containerMeta(inv,"application.deploy",resource),ApplicationID:resource,SiteID:p.SiteID,RecipeID:p.RecipeID,RecipeVersion:p.RecipeVersion});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusCreated,Value:struct{Application containers.ContainerApplication `json:"application"`;Operations []containers.Result `json:"operations"`}{application,results},Generation:application.ActiveGeneration},nil});err!=nil{return err}
		if err:=registry.Bind("container.application.update",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){resource,err:=containers.NewID(inv.Request.ResourceID);if err!=nil{return OperationResult{},ErrInvalidRequest};p:=value.(*ContainerApplicationUpdatePayload);application,results,err:=services.ContainerApplications.Update(ctx,containers.UpdateApplicationCommand{Meta:containerMeta(inv,"application.deploy",resource),ApplicationID:resource,RecipeID:p.RecipeID,RecipeVersion:p.RecipeVersion,BackwardCompatibleData:p.BackwardCompatibleData});if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:struct{Application containers.ContainerApplication `json:"application"`;Operations []containers.Result `json:"operations"`}{application,results},Generation:application.ActiveGeneration},nil});err!=nil{return err}
	}
	if services.Containers!=nil{if err:=registry.Bind("container.exec.exchange",func(ctx context.Context,_ Invocation,value any)(OperationResult,error){payload:=value.(*ContainerExecExchangePayload);receipt,err:=services.Containers.ExchangeExec(ctx,payload.GrantID,payload.Token);payload.Token="";if err!=nil{return OperationResult{},mapDomainError(err)};return OperationResult{Status:http.StatusOK,Value:receipt},nil});err!=nil{return err}}
	return nil
}

// Retain actionable release/trust/recovery diagnostics instead of reporting a
// successful deployment or swallowing the prerequisite behind a generic 500.
type n8nPrerequisiteError struct{ cause error; detail string }
func (err *n8nPrerequisiteError) Error() string{return err.detail}
func (err *n8nPrerequisiteError) Unwrap() error{return err.cause}
func n8nAPIError(err error) error {
 if errors.Is(err,integrations.ErrN8NRecipeUnavailable){return &n8nPrerequisiteError{ErrUnavailable,"The requested signed n8n recipe is not installed. Provision the approved offline container catalog and retry."}}
 if errors.Is(err,integrations.ErrN8NRecipeTrust){return &n8nPrerequisiteError{ErrForbidden,"The n8n recipe signature is invalid or its release signing key is not trusted on this node."}}
 if errors.Is(err,integrations.ErrIntegrity)||errors.Is(err,containers.ErrPolicy){return &n8nPrerequisiteError{ErrInvalidRequest,"The n8n definition, workload graph, or secret bindings do not match the signed release contract."}}
 return mapDomainError(err)
}
