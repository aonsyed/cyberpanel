package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/redisservice"
)

type ResourceProfilePayload struct{NodeID operations.ResourceID `json:"node_id"`;Profile operations.ResourceProfile `json:"profile"`}
type FirewallPayload struct{NodeID operations.ResourceID `json:"node_id"`;ApprovalRef operations.ResourceID `json:"approval_ref"`;Policy operations.FirewallPolicy `json:"policy"`}
type SSHPolicyPayload struct{NodeID operations.ResourceID `json:"node_id"`;ApprovalRef operations.ResourceID `json:"approval_ref"`;Policy operations.SSHPolicy `json:"policy"`}
type SSHPutKeyPayload struct{NodeID operations.ResourceID `json:"node_id"`;Key operations.SSHKey `json:"key"`}
type SSHDeleteKeyPayload struct{NodeID operations.ResourceID `json:"node_id"`;SiteID string `json:"site_id,omitempty"`;KeyID operations.ResourceID `json:"key_id"`}
type WAFPayload struct{NodeID operations.ResourceID `json:"node_id"`;Policy operations.WAFPolicy `json:"policy"`}
type ServicePolicyPayload struct{NodeID operations.ResourceID `json:"node_id"`;Policy operations.ServicePolicy `json:"policy"`}
type ServiceControlPayload struct{NodeID operations.ResourceID `json:"node_id"`;Service operations.ServiceName `json:"service"`;Action operations.ServiceAction `json:"action"`}
type ServiceDiagnosePayload struct{NodeID operations.ResourceID `json:"node_id"`;Service operations.ServiceName `json:"service"`;Depth operations.DiagnosticDepth `json:"depth"`;Since time.Time `json:"since"`}
type ServiceRepairPayload struct{NodeID operations.ResourceID `json:"node_id"`;Service operations.ServiceName `json:"service"`;Strategy operations.RepairStrategy `json:"strategy"`;DiagnosticProofDigest string `json:"diagnostic_proof_digest"`}
type MetricsPayload struct{NodeID operations.ResourceID `json:"node_id"`;SiteID string `json:"site_id,omitempty"`;Names []operations.MetricName `json:"names"`;Start time.Time `json:"start"`;End time.Time `json:"end"`;Step time.Duration `json:"step"`;Limit uint32 `json:"limit"`}
type LogsPayload struct{NodeID operations.ResourceID `json:"node_id"`;SiteID string `json:"site_id,omitempty"`;Source operations.LogSource `json:"source"`;Service operations.ServiceName `json:"service,omitempty"`;Start time.Time `json:"start"`;End time.Time `json:"end"`;MinimumSeverity uint8 `json:"minimum_severity"`;Cursor string `json:"cursor,omitempty"`;Limit uint32 `json:"limit"`}
type PackagePayload struct{NodeID operations.ResourceID `json:"node_id"`;ApprovalRef operations.ResourceID `json:"approval_ref"`;Transaction operations.PackageTransaction `json:"transaction"`}
type ManagedServicePayload struct{NodeID operations.ResourceID `json:"node_id"`;Service operations.ManagedService `json:"service"`}

type RedisSpecPayload struct{InstanceID string `json:"instance_id,omitempty"`;Spec redisservice.InstanceSpec `json:"spec"`;SpecJSON string `json:"spec_json,omitempty"`}
type RedisConsumerPayload struct{ConsumerID string `json:"consumer_id"`;Kind string `json:"kind"`;ACLUser string `json:"acl_user"`;Database uint8 `json:"database"`;Active bool `json:"active"`}
type RedisConsumerDeletePayload struct{ConsumerID string `json:"consumer_id"`}
type RedisUpgradePayload struct{RedisVersion string `json:"redis_version"`;QualificationDigest string `json:"qualification_digest"`;Manager operations.PackageManager `json:"manager"`;Architecture operations.ResourceID `json:"architecture"`;FromPackageVersion string `json:"from_package_version"`;ToPackageVersion string `json:"to_package_version"`;RecoveryPointRef operations.ResourceID `json:"recovery_point_ref"`;MaintenanceRef operations.ResourceID `json:"maintenance_ref"`;ApprovalRef operations.ResourceID `json:"approval_ref"`}
type RedisBackupPayload struct{Artifact redisservice.ArtifactDescriptor `json:"artifact"`;ArtifactJSON string `json:"artifact_json,omitempty"`}
type RedisRestorePayload struct{ArtifactID string `json:"artifact_id"`;RecoveryArtifactRef string `json:"recovery_artifact_ref"`}
type RedisDeletePayload struct{RecoveryArtifactRef string `json:"recovery_artifact_ref"`}

type RedisProjection struct {
	ID string `json:"id"`
	TenantID string `json:"tenant_id,omitempty"`
	Purpose redisservice.Purpose `json:"purpose"`
	Version string `json:"version"`
	Listener redisservice.ListenerMode `json:"listener"`
	Lifecycle redisservice.LifecycleState `json:"lifecycle"`
	Health redisservice.HealthState `json:"health"`
	Drift redisservice.DriftState `json:"drift"`
	Consumers uint64 `json:"consumers"`
	Generation uint64 `json:"generation"`
	ConfigGeneration uint64 `json:"config_generation"`
	ConsumerGeneration uint64 `json:"consumer_generation,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}
type RedisDetail struct{Projection RedisProjection `json:"projection"`;Spec redisservice.InstanceSpec `json:"spec"`;Observed *redisservice.InstanceObservation `json:"observed,omitempty"`;Consumers redisservice.ConsumerSnapshot `json:"consumers"`}
type RedisMutation struct{OperationID string `json:"operation_id"`;State string `json:"state"`;Generation uint64 `json:"generation"`;Resource RedisProjection `json:"resource"`}
type RedisBackupResult struct{State string `json:"state"`;Artifact redisservice.ArtifactDescriptor `json:"artifact"`;Generation uint64 `json:"generation"`}
type RedisRestorePlan struct{State string `json:"state"`;InstanceID redisservice.InstanceID `json:"instance_id"`;Artifact redisservice.ArtifactDescriptor `json:"artifact"`;RecoveryArtifact redisservice.ArtifactDescriptor `json:"recovery_artifact"`;ExpectedGeneration uint64 `json:"expected_generation"`;ConsumerGeneration uint64 `json:"consumer_generation"`}

type RedisEdgeService interface {
	ListRedis(context.Context,EdgeCall,EdgePagePayload)(EdgePage[RedisProjection],error)
	GetRedis(context.Context,EdgeCall)(RedisDetail,error)
	CreateRedis(context.Context,EdgeCall,redisservice.InstanceSpec)(RedisMutation,error)
	ConfigureRedis(context.Context,EdgeCall,redisservice.InstanceSpec)(RedisMutation,error)
	StartRedis(context.Context,EdgeCall)(RedisMutation,error)
	StopRedis(context.Context,EdgeCall)(RedisMutation,error)
	RestartRedis(context.Context,EdgeCall)(RedisMutation,error)
	UpgradeRedis(context.Context,EdgeCall,RedisUpgradePayload)(RedisMutation,error)
	HealthRedis(context.Context,EdgeCall)(RedisMutation,error)
	BindRedisConsumer(context.Context,EdgeCall,RedisConsumerPayload)(RedisMutation,error)
	UnbindRedisConsumer(context.Context,EdgeCall,string)(RedisMutation,error)
	RecordRedisBackup(context.Context,EdgeCall,redisservice.ArtifactDescriptor)(RedisBackupResult,error)
	PlanRedisRestore(context.Context,EdgeCall,RedisRestorePayload)(RedisRestorePlan,error)
	DeleteRedis(context.Context,EdgeCall,string)(RedisMutation,error)
}

func registerOperationsContracts(registry *Registry)error{
	definitions:=[]Operation{
		{Name:"operations.resource_profile.apply",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ResourceProfilePayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"operations.firewall.replace",Permission:identity.MustPermission("security:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &FirewallPayload{}},ResolveScope:installationScope},
		{Name:"operations.ssh_policy.replace",Permission:identity.MustPermission("security:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &SSHPolicyPayload{}},ResolveScope:installationScope},
		{Name:"operations.ssh_key.put",Permission:identity.MustPermission("security:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &SSHPutKeyPayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"operations.ssh_key.delete",Permission:identity.MustPermission("security:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &SSHDeleteKeyPayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"operations.waf.replace",Permission:identity.MustPermission("security:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &WAFPayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"operations.service_policy.set",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ServicePolicyPayload{}},ResolveScope:installationScope},
		{Name:"operations.service.control",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ServiceControlPayload{}},ResolveScope:installationScope},
		{Name:"operations.service.diagnose",Permission:identity.MustPermission("operations:observe"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,NewPayload:func()any{return &ServiceDiagnosePayload{}},ResolveScope:installationScope},
		{Name:"operations.service.repair",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ServiceRepairPayload{}},ResolveScope:installationScope},
		{Name:"operations.metrics.query",Permission:identity.MustPermission("operations:observe"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,NewPayload:func()any{return &MetricsPayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"operations.logs.query",Permission:identity.MustPermission("operations:observe"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,NewPayload:func()any{return &LogsPayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"operations.package.apply",Permission:identity.MustPermission("package:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &PackagePayload{}},ResolveScope:installationScope},
		{Name:"operations.managed_service.reconcile",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &ManagedServicePayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.create",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,MaximumBodyBytes:256<<10,NewPayload:func()any{return &RedisSpecPayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.list",Permission:identity.MustPermission("operations:observe"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,NewPayload:func()any{return &EdgePagePayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.get",Permission:identity.MustPermission("operations:observe"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,NewPayload:func()any{return &struct{}{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.configure",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,MaximumBodyBytes:256<<10,NewPayload:func()any{return &RedisSpecPayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.start",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &struct{}{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.stop",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssurancePhishingResistant,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &struct{}{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.restart",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &struct{}{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.upgrade",Permission:identity.MustPermission("package:manage"),Assurance:identity.AssurancePhishingResistant,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &RedisUpgradePayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.health",Permission:identity.MustPermission("operations:observe"),Assurance:identity.AssurancePassword,Auth:AuthRequired,Mutating:false,NewPayload:func()any{return &struct{}{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.consumer.bind",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &RedisConsumerPayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.consumer.unbind",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &RedisConsumerDeletePayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.backup.record",Permission:identity.MustPermission("backup:manage"),Assurance:identity.AssuranceMFA,Auth:AuthRequired,Mutating:true,MaximumBodyBytes:256<<10,NewPayload:func()any{return &RedisBackupPayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.restore.plan",Permission:identity.MustPermission("backup:restore"),Assurance:identity.AssurancePhishingResistant,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &RedisRestorePayload{}},ResolveScope:tenantOrInstallationScope},
		{Name:"redis.instance.delete",Permission:identity.MustPermission("operations:manage"),Assurance:identity.AssurancePhishingResistant,Auth:AuthRequired,Mutating:true,NewPayload:func()any{return &RedisDeletePayload{}},ResolveScope:tenantOrInstallationScope},
	}
	for _,definition:=range definitions{if err:=register(registry,definition);err!=nil{return err}}
	return nil
}

func tenantOrInstallationScope(request RequestEnvelope,value any)(identity.Scope,error){if request.TenantID==""{return installationScope(request,value)};return tenantScope(request,value)}

func operationHeader(inv Invocation,node,approval operations.ResourceID,siteRaw string,capabilities ...operations.Capability)(operations.CommandHeader,error){principal,err:=operations.NewResourceID(inv.Actor.PrincipalID.String());if err!=nil{return operations.CommandHeader{},ErrInvalidRequest};var tenant site.TenantID;if inv.Request.TenantID!=""{tenant,err=site.NewTenantID(inv.Request.TenantID);if err!=nil{return operations.CommandHeader{},ErrInvalidRequest}};var siteID site.SiteID;if siteRaw!=""{if tenant.String()==""{return operations.CommandHeader{},invalid("site_id without tenant_id")};siteID,err=site.NewSiteID(siteRaw);if err!=nil{return operations.CommandHeader{},invalid("site_id")}};now:=time.Now().UTC();mfa:=operations.ResourceID{};if inv.Actor.Assurance>=identity.AssuranceMFA{sum:=sha256.Sum256([]byte(inv.Actor.SessionID.String()+"\x00"+inv.Actor.CredentialID.String()));mfa,_=operations.NewResourceID("mfa-"+hex.EncodeToString(sum[:16]))};return operations.CommandHeader{CommandID:commandID(inv),NodeID:node,TenantID:tenant,SiteID:siteID,Actor:operations.Actor{PrincipalID:principal,TenantID:tenant,Capabilities:capabilities,MFAProofRef:mfa},RequestedAt:now,Deadline:now.Add(2*time.Minute),ApprovalRef:approval},nil}
func observationCapability(inv Invocation)operations.Capability{if inv.Request.TenantID==""{return operations.CapabilityNodeOperations};return operations.CapabilityTenantObserve}
func enforcementScope(header operations.CommandHeader)operations.EnforcementScope{kind:=operations.ScopeNode;if header.TenantID.String()!=""{kind=operations.ScopeTenant};if header.SiteID.String()!=""{kind=operations.ScopeSite};return operations.EnforcementScope{Kind:kind,NodeID:header.NodeID,TenantID:header.TenantID,SiteID:header.SiteID}}
func generation(expected uint64)uint64{return expected+1}

func bindOperations(registry *Registry,services DomainServices)error{
	if services.Operations==nil{return nil}
	bind:=func(name string,builder func(Invocation,any)(operations.Command,error))error{return registry.Bind(name,func(ctx context.Context,inv Invocation,value any)(OperationResult,error){command,err:=builder(inv,value);if err!=nil{return OperationResult{},err};receipt,err:=services.Operations.Handle(ctx,command);if err!=nil{return OperationResult{},mapOperationsError(err)};return OperationResult{Status:http.StatusOK,Value:receipt},nil})}
	if err:=bind("operations.resource_profile.apply",func(inv Invocation,value any)(operations.Command,error){p:=value.(*ResourceProfilePayload);header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},p.Profile.Metadata.SiteID.String(),operations.CapabilityNodeOperations);p.Profile.Metadata.NodeID=p.NodeID;p.Profile.Metadata.TenantID=header.TenantID;p.Profile.Metadata.SiteID=header.SiteID;p.Profile.Metadata.Generation=generation(inv.Request.ExpectedGeneration);p.Profile.Scope=enforcementScope(header);return operations.ApplyResourceProfile{Header:header,Profile:p.Profile,ExpectedGeneration:inv.Request.ExpectedGeneration},err});err!=nil{return err}
	if err:=bind("operations.firewall.replace",func(inv Invocation,value any)(operations.Command,error){p:=value.(*FirewallPayload);header,err:=operationHeader(inv,p.NodeID,p.ApprovalRef,"",operations.CapabilityNodeSecurity);p.Policy.Metadata.NodeID=p.NodeID;p.Policy.Metadata.Generation=generation(inv.Request.ExpectedGeneration);return operations.ReplaceFirewallPolicy{Header:header,Policy:p.Policy,ExpectedGeneration:inv.Request.ExpectedGeneration},err});err!=nil{return err}
	if err:=bind("operations.ssh_policy.replace",func(inv Invocation,value any)(operations.Command,error){p:=value.(*SSHPolicyPayload);header,err:=operationHeader(inv,p.NodeID,p.ApprovalRef,"",operations.CapabilityNodeSecurity);p.Policy.Metadata.NodeID=p.NodeID;p.Policy.Metadata.Generation=generation(inv.Request.ExpectedGeneration);return operations.ReplaceSSHPolicy{Header:header,Policy:p.Policy,ExpectedGeneration:inv.Request.ExpectedGeneration},err});err!=nil{return err}
	if err:=bind("operations.ssh_key.put",func(inv Invocation,value any)(operations.Command,error){p:=value.(*SSHPutKeyPayload);capability:=operations.CapabilityTenantSecurity;if inv.Request.TenantID==""{capability=operations.CapabilityNodeSecurity};header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},p.Key.Metadata.SiteID.String(),capability);p.Key.Metadata.NodeID=p.NodeID;p.Key.Metadata.Generation=generation(inv.Request.ExpectedGeneration);p.Key.Metadata.TenantID=header.TenantID;p.Key.Metadata.SiteID=header.SiteID;if capability==operations.CapabilityTenantSecurity{p.Key.PrincipalID=header.Actor.PrincipalID};return operations.PutSSHKey{Header:header,Key:p.Key,ExpectedGeneration:inv.Request.ExpectedGeneration},err});err!=nil{return err}
	if err:=bind("operations.ssh_key.delete",func(inv Invocation,value any)(operations.Command,error){p:=value.(*SSHDeleteKeyPayload);capability:=operations.CapabilityTenantSecurity;if inv.Request.TenantID==""{capability=operations.CapabilityNodeSecurity};header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},p.SiteID,capability);return operations.DeleteSSHKey{Header:header,KeyID:p.KeyID,ExpectedGeneration:inv.Request.ExpectedGeneration},err});err!=nil{return err}
	if err:=bind("operations.waf.replace",func(inv Invocation,value any)(operations.Command,error){p:=value.(*WAFPayload);capability:=operations.CapabilityTenantSecurity;if inv.Request.TenantID==""{capability=operations.CapabilityNodeSecurity};header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},p.Policy.Metadata.SiteID.String(),capability);p.Policy.Metadata.NodeID=p.NodeID;p.Policy.Metadata.Generation=generation(inv.Request.ExpectedGeneration);p.Policy.Metadata.TenantID=header.TenantID;p.Policy.Metadata.SiteID=header.SiteID;return operations.ReplaceWAFPolicy{Header:header,Policy:p.Policy,ExpectedGeneration:inv.Request.ExpectedGeneration},err});err!=nil{return err}
	if err:=bind("operations.service_policy.set",func(inv Invocation,value any)(operations.Command,error){p:=value.(*ServicePolicyPayload);header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},"",operations.CapabilityNodeOperations);id,_:=operations.NewResourceID("service-"+string(p.Policy.Service));p.Policy.Metadata.ID=id;p.Policy.Metadata.NodeID=p.NodeID;p.Policy.Metadata.Generation=generation(inv.Request.ExpectedGeneration);return operations.SetServicePolicy{Header:header,Policy:p.Policy,ExpectedGeneration:inv.Request.ExpectedGeneration},err});err!=nil{return err}
	if err:=bind("operations.service.control",func(inv Invocation,value any)(operations.Command,error){p:=value.(*ServiceControlPayload);header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},"",operations.CapabilityNodeOperations);return operations.ControlService{Header:header,Service:p.Service,Action:p.Action,ExpectedPolicyGeneration:inv.Request.ExpectedGeneration},err});err!=nil{return err}
	if err:=bind("operations.service.diagnose",func(inv Invocation,value any)(operations.Command,error){p:=value.(*ServiceDiagnosePayload);header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},"",operations.CapabilityNodeOperations);return operations.DiagnoseService{Header:header,Service:p.Service,Depth:p.Depth,Since:p.Since},err});err!=nil{return err}
	if err:=bind("operations.service.repair",func(inv Invocation,value any)(operations.Command,error){p:=value.(*ServiceRepairPayload);header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},"",operations.CapabilityNodeOperations);return operations.RepairService{Header:header,Service:p.Service,Strategy:p.Strategy,DiagnosticProofDigest:p.DiagnosticProofDigest},err});err!=nil{return err}
	if err:=bind("operations.metrics.query",func(inv Invocation,value any)(operations.Command,error){p:=value.(*MetricsPayload);header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},p.SiteID,observationCapability(inv));return operations.QueryMetrics{Header:header,Scope:enforcementScope(header),Names:p.Names,Start:p.Start,End:p.End,Step:p.Step,Limit:p.Limit},err});err!=nil{return err}
	if err:=bind("operations.logs.query",func(inv Invocation,value any)(operations.Command,error){p:=value.(*LogsPayload);header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},p.SiteID,observationCapability(inv));return operations.OpenLogStream{Header:header,Source:p.Source,Service:p.Service,Start:p.Start,End:p.End,MinimumSeverity:p.MinimumSeverity,Cursor:p.Cursor,Limit:p.Limit},err});err!=nil{return err}
	if err:=bind("operations.package.apply",func(inv Invocation,value any)(operations.Command,error){p:=value.(*PackagePayload);header,err:=operationHeader(inv,p.NodeID,p.ApprovalRef,"",operations.CapabilityNodePackages);p.Transaction.Metadata.NodeID=p.NodeID;p.Transaction.Metadata.Generation=1;return operations.RequestPackageTransaction{Header:header,Transaction:p.Transaction},err});err!=nil{return err}
	if err:=bind("operations.managed_service.reconcile",func(inv Invocation,value any)(operations.Command,error){p:=value.(*ManagedServicePayload);header,err:=operationHeader(inv,p.NodeID,operations.ResourceID{},p.Service.Metadata.SiteID.String(),operations.CapabilityNodeOperations);p.Service.Metadata.NodeID=p.NodeID;p.Service.Metadata.Generation=generation(inv.Request.ExpectedGeneration);p.Service.Metadata.TenantID=header.TenantID;p.Service.Metadata.SiteID=header.SiteID;return operations.ReconcileManagedService{Header:header,Service:p.Service,ExpectedGeneration:inv.Request.ExpectedGeneration},err});err!=nil{return err}
	return bindRedisOperations(registry,services)
}

func mapOperationsError(err error)error{switch{case err==nil:return nil;case errors.Is(err,operations.ErrInvalidCommand)||errors.Is(err,operations.ErrInvalidResource):return ErrInvalidRequest;case errors.Is(err,operations.ErrUnauthorized):return ErrForbidden;case errors.Is(err,operations.ErrNotFound):return ErrNotFound;case errors.Is(err,operations.ErrConflict)||errors.Is(err,operations.ErrIdempotency):return ErrConflict;default:return err}}

func redisSpecFromPayload(payload *RedisSpecPayload)(redisservice.InstanceSpec,error){
	if payload==nil{return redisservice.InstanceSpec{},ErrInvalidRequest}
	direct:=payload.Spec.ID!=""
	encoded:=payload.SpecJSON!=""
	if direct==encoded{return redisservice.InstanceSpec{},ErrInvalidRequest}
	if direct{return payload.Spec,nil}
	if len(payload.SpecJSON)>redisservice.MaxRepositoryBytes{return redisservice.InstanceSpec{},ErrInvalidRequest}
	var spec redisservice.InstanceSpec
	if decodeStrict([]byte(payload.SpecJSON),&spec)!=nil{return redisservice.InstanceSpec{},ErrInvalidRequest}
	return spec,nil
}

func redisArtifactFromPayload(payload *RedisBackupPayload)(redisservice.ArtifactDescriptor,error){
	if payload==nil{return redisservice.ArtifactDescriptor{},ErrInvalidRequest}
	direct:=payload.Artifact.ID!=""
	encoded:=payload.ArtifactJSON!=""
	if direct==encoded{return redisservice.ArtifactDescriptor{},ErrInvalidRequest}
	if direct{return payload.Artifact,nil}
	if len(payload.ArtifactJSON)>redisservice.MaxRepositoryBytes{return redisservice.ArtifactDescriptor{},ErrInvalidRequest}
	var artifact redisservice.ArtifactDescriptor
	if decodeStrict([]byte(payload.ArtifactJSON),&artifact)!=nil{return redisservice.ArtifactDescriptor{},ErrInvalidRequest}
	return artifact,nil
}

func bindRedisOperations(registry *Registry,services DomainServices)error{
	edge,ok:=services.OperationsEdge.(RedisEdgeService)
	if !ok||edge==nil{return nil}
	bind:=func(name string,handler OperationHandler)error{return registry.Bind(name,handler)}
	if err:=bind("redis.instance.list",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=edge.ListRedis(ctx,edgeCall(inv),*value.(*EdgePagePayload));if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusOK,Value:result},nil});err!=nil{return err}
	if err:=bind("redis.instance.get",func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){result,err:=edge.GetRedis(ctx,edgeCall(inv));if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Projection.Generation},nil});err!=nil{return err}
	if err:=bind("redis.instance.create",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){payload:=value.(*RedisSpecPayload);spec,err:=redisSpecFromPayload(payload);if err!=nil{return OperationResult{},err};if payload.InstanceID!=""&&payload.InstanceID!=string(spec.ID){return OperationResult{},ErrInvalidRequest};call:=edgeCall(inv);if call.ResourceID==""{call.ResourceID=string(spec.ID)};result,err:=edge.CreateRedis(ctx,call,spec);if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusCreated,Value:result,Generation:result.Generation},nil});err!=nil{return err}
	if err:=bind("redis.instance.configure",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){spec,err:=redisSpecFromPayload(value.(*RedisSpecPayload));if err!=nil{return OperationResult{},err};result,err:=edge.ConfigureRedis(ctx,edgeCall(inv),spec);if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Generation},nil});err!=nil{return err}
	for name,handler:=range map[string]func(context.Context,EdgeCall)(RedisMutation,error){"redis.instance.start":edge.StartRedis,"redis.instance.stop":edge.StopRedis,"redis.instance.restart":edge.RestartRedis,"redis.instance.health":edge.HealthRedis}{method:=handler;if err:=bind(name,func(ctx context.Context,inv Invocation,_ any)(OperationResult,error){result,err:=method(ctx,edgeCall(inv));if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Generation},nil});err!=nil{return err}}
	if err:=bind("redis.instance.upgrade",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=edge.UpgradeRedis(ctx,edgeCall(inv),*value.(*RedisUpgradePayload));if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Generation},nil});err!=nil{return err}
	if err:=bind("redis.consumer.bind",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=edge.BindRedisConsumer(ctx,edgeCall(inv),*value.(*RedisConsumerPayload));if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Generation},nil});err!=nil{return err}
	if err:=bind("redis.consumer.unbind",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=edge.UnbindRedisConsumer(ctx,edgeCall(inv),value.(*RedisConsumerDeletePayload).ConsumerID);if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Generation},nil});err!=nil{return err}
	if err:=bind("redis.backup.record",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){artifact,err:=redisArtifactFromPayload(value.(*RedisBackupPayload));if err!=nil{return OperationResult{},err};result,err:=edge.RecordRedisBackup(ctx,edgeCall(inv),artifact);if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusCreated,Value:result,Generation:result.Generation},nil});err!=nil{return err}
	if err:=bind("redis.restore.plan",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=edge.PlanRedisRestore(ctx,edgeCall(inv),*value.(*RedisRestorePayload));if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusCreated,Value:result,Generation:result.ExpectedGeneration},nil});err!=nil{return err}
	return bind("redis.instance.delete",func(ctx context.Context,inv Invocation,value any)(OperationResult,error){result,err:=edge.DeleteRedis(ctx,edgeCall(inv),value.(*RedisDeletePayload).RecoveryArtifactRef);if err!=nil{return OperationResult{},mapRedisError(err)};return OperationResult{Status:http.StatusOK,Value:result,Generation:result.Generation},nil})
}

func mapRedisError(err error)error{
	switch{
	case err==nil:return nil
	case errors.Is(err,redisservice.ErrInvalid),errors.Is(err,redisservice.ErrCapacity):return ErrInvalidRequest
	case errors.Is(err,redisservice.ErrUnauthorized):return ErrForbidden
	case errors.Is(err,redisservice.ErrNotFound):return ErrNotFound
	case errors.Is(err,redisservice.ErrConflict),errors.Is(err,redisservice.ErrStale),errors.Is(err,redisservice.ErrConsumersPresent):return ErrConflict
	case errors.Is(err,redisservice.ErrUnsupported),errors.Is(err,redisservice.ErrMaintenanceRequired),errors.Is(err,redisservice.ErrAmbiguous):return ErrOperationUnavailable
	default:return mapOperationsError(err)
	}
}
