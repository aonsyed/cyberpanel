//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/redisservice"
)

type operationsEdgeRepository interface{LoadResource(context.Context,operations.ResourceKind,operations.ResourceID)(operations.ResourceEnvelope,error)}
type operationsEdge struct{commands apiserver.OperationsCommandService;repository operationsEdgeRepository;redis redisservice.Repository;node operations.ResourceID;now func()time.Time;redisMu sync.Mutex}

func newOperationsEdge(commands apiserver.OperationsCommandService,repository operationsEdgeRepository,redisRepository redisservice.Repository,nodeID string)(apiserver.OperationsEdgeService,error){if commands==nil||repository==nil||redisRepository==nil{return nil,errors.New("operations edge dependencies are required")};node,err:=operations.NewResourceID(nodeID);if err!=nil{return nil,err};return &operationsEdge{commands:commands,repository:repository,redis:redisRepository,node:node,now:time.Now},nil}

var operationsEdgeServices=[]operations.ServiceName{operations.ServiceWebEnterprise,operations.ServiceWebOpenLiteSpeed,operations.ServiceMariaDB,operations.ServicePostfix,operations.ServiceDovecot,operations.ServicePowerDNS,operations.ServicePureFTPd,operations.ServiceRedis,operations.ServiceElasticsearch,operations.ServicePanel}

func operationsServiceName(raw string)(operations.ServiceName,error){value:=operations.ServiceName(strings.TrimSpace(raw));for _,candidate:=range operationsEdgeServices{if value==candidate{return value,nil}};return "",operations.ErrInvalidResource}
func operationsPolicyID(service operations.ServiceName)operations.ResourceID{id,_:=operations.NewResourceID("service-"+string(service));return id}
func(edge *operationsEdge)header(call apiserver.EdgeCall,suffix string)(operations.CommandHeader,error){if call.TenantID!=""{return operations.CommandHeader{},operations.ErrUnauthorized};principal,err:=operations.NewResourceID(call.PrincipalID);if err!=nil{return operations.CommandHeader{},operations.ErrUnauthorized};now:=edge.now().UTC();return operations.CommandHeader{CommandID:call.CommandID+suffix,NodeID:edge.node,Actor:operations.Actor{PrincipalID:principal,Capabilities:[]operations.Capability{operations.CapabilityNodeOperations}},RequestedAt:now,Deadline:now.Add(2*time.Minute)},nil}
func(edge *operationsEdge)policy(ctx context.Context,service operations.ServiceName)(*operations.ServicePolicy,error){envelope,err:=edge.repository.LoadResource(ctx,operations.KindServicePolicy,operationsPolicyID(service));if err!=nil{return nil,err};value,err:=operations.DecodeResource(envelope);if err!=nil{return nil,err};policy,ok:=value.(*operations.ServicePolicy);if !ok{return nil,operations.ErrInvalidResource};return policy,nil}
func(edge *operationsEdge)diagnose(ctx context.Context,call apiserver.EdgeCall,service operations.ServiceName,depth operations.DiagnosticDepth,suffix string,since time.Time)(apiserver.OperationsServiceProjection,operations.OperationReceipt,error){header,err:=edge.header(call,suffix);if err!=nil{return apiserver.OperationsServiceProjection{},operations.OperationReceipt{},err};if since.IsZero(){since=edge.now().UTC().Add(-15*time.Minute)};receipt,err:=edge.commands.Handle(ctx,operations.DiagnoseService{Header:header,Service:service,Depth:depth,Since:since});if err!=nil{return apiserver.OperationsServiceProjection{},receipt,err};diagnostics:=receipt.Effect.Result.Diagnostics;if diagnostics==nil{return apiserver.OperationsServiceProjection{},receipt,operations.ErrInvalidReceipt};generation:=uint64(0);if policy,loadErr:=edge.policy(ctx,service);loadErr==nil{generation=policy.Generation};health:="healthy";if diagnostics.ActiveState!="active"{health="unavailable"};for _,check:=range diagnostics.Checks{if check.Outcome==operations.CheckFail{health="degraded";break}else if check.Outcome==operations.CheckWarn&&health=="healthy"{health="warning"}};return apiserver.OperationsServiceProjection{ID:string(service),Name:string(service),ActiveState:diagnostics.ActiveState,SubState:diagnostics.SubState,RestartCount:uint64(diagnostics.RestartCount),Health:health,Generation:generation,UpdatedAt:receipt.Effect.CompletedAt},receipt,nil}

func(edge *operationsEdge)ListServices(ctx context.Context,call apiserver.EdgeCall,page apiserver.EdgePagePayload)(apiserver.EdgePage[apiserver.OperationsServiceProjection],error){if call.TenantID!=""{return apiserver.EdgePage[apiserver.OperationsServiceProjection]{},operations.ErrUnauthorized};start:=0;if page.Cursor!=""{for start<len(operationsEdgeServices)&&string(operationsEdgeServices[start])<=page.Cursor{start++}};limit:=int(page.Limit);if limit==0{limit=100};end:=start+limit;if end>len(operationsEdgeServices){end=len(operationsEdgeServices)};items:=make([]apiserver.OperationsServiceProjection,0,end-start);for index,service:=range operationsEdgeServices[start:end]{projection,_,err:=edge.diagnose(ctx,call,service,operations.DiagnosticSummary,accessEdgeID("-list-",string(service),call.CommandID),time.Time{});if errors.Is(err,operations.ErrNotFound){continue};if err!=nil{return apiserver.EdgePage[apiserver.OperationsServiceProjection]{},err};items=append(items,projection);_ = index};next:="";if end<len(operationsEdgeServices)&&len(items)>0{next=string(operationsEdgeServices[end-1])};return apiserver.EdgePage[apiserver.OperationsServiceProjection]{Items:items,NextCursor:next,Total:uint64(len(operationsEdgeServices))},nil}

func(edge *operationsEdge)control(ctx context.Context,call apiserver.EdgeCall,action operations.ServiceAction)(apiserver.EdgeMutation[apiserver.OperationsServiceProjection],error){service,err:=operationsServiceName(call.ResourceID);if err!=nil{return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{},err};policy,err:=edge.policy(ctx,service);if err!=nil{return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{},err};if call.ExpectedGeneration==0||call.ExpectedGeneration!=policy.Generation{return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{},operations.ErrConflict};header,err:=edge.header(call,"-control");if err!=nil{return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{},err};receipt,err:=edge.commands.Handle(ctx,operations.ControlService{Header:header,Service:service,Action:action,ExpectedPolicyGeneration:policy.Generation});if err!=nil{return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{},err};projection,_,err:=edge.diagnose(ctx,call,service,operations.DiagnosticSummary,"-observe",time.Time{});if err!=nil{return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{},err};return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{OperationID:receipt.CommandID,State:string(receipt.Status),Generation:projection.Generation,Resource:projection},nil}
func(edge *operationsEdge)RestartService(ctx context.Context,call apiserver.EdgeCall)(apiserver.EdgeMutation[apiserver.OperationsServiceProjection],error){return edge.control(ctx,call,operations.ServiceRestart)}
func(edge *operationsEdge)StopService(ctx context.Context,call apiserver.EdgeCall)(apiserver.EdgeMutation[apiserver.OperationsServiceProjection],error){return edge.control(ctx,call,operations.ServiceStop)}
func(edge *operationsEdge)RunDiagnostic(ctx context.Context,call apiserver.EdgeCall,payload apiserver.OperationsDiagnosticPayload)(apiserver.EdgeMutation[apiserver.OperationsServiceProjection],error){service,err:=operationsServiceName(call.ResourceID);if err!=nil{return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{},err};depth:=operations.DiagnosticDependency;switch payload.Depth{case"quick":depth=operations.DiagnosticSummary;case"deep":depth=operations.DiagnosticDeep};projection,receipt,err:=edge.diagnose(ctx,call,service,depth,"-diagnose",payload.Since);if err!=nil{return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{},err};return apiserver.EdgeMutation[apiserver.OperationsServiceProjection]{OperationID:receipt.CommandID,State:string(receipt.Status),Generation:projection.Generation,Resource:projection},nil}

func redisCoreDigest(parts ...string)string{hash:=sha256.New();for _,part:=range parts{_,_=hash.Write([]byte(part));_,_=hash.Write([]byte{0})};return "sha256:"+hex.EncodeToString(hash.Sum(nil))}

func(edge *operationsEdge)redisRecord(ctx context.Context,call apiserver.EdgeCall)(redisservice.InstanceRecord,error){
	if edge==nil||edge.redis==nil||call.ResourceID==""{return redisservice.InstanceRecord{},redisservice.ErrInvalid}
	record,err:=edge.redis.Inspect(ctx,redisservice.InstanceID(call.ResourceID));if err!=nil{return redisservice.InstanceRecord{},err}
	if record.Spec.NodeID!=edge.node.String(){return redisservice.InstanceRecord{},redisservice.ErrUnauthorized}
	if call.TenantID!=""&&(record.Spec.Scope!=redisservice.ScopeTenant||record.Spec.TenantID!=call.TenantID){return redisservice.InstanceRecord{},redisservice.ErrUnauthorized}
	return record,nil
}

func(edge *operationsEdge)redisConsumers(ctx context.Context,id redisservice.InstanceID)(redisservice.ConsumerSnapshot,error){
	snapshot,err:=edge.redis.ConsumerSnapshot(ctx,id)
	if errors.Is(err,redisservice.ErrNotFound){return redisservice.ConsumerSnapshot{InstanceID:id},nil}
	return snapshot,err
}

func redisProjection(record redisservice.InstanceRecord,consumers redisservice.ConsumerSnapshot,now time.Time)apiserver.RedisProjection{
	projection:=apiserver.RedisProjection{ID:string(record.Spec.ID),TenantID:record.Spec.TenantID,Purpose:record.Spec.Purpose,Version:record.Spec.Support.RedisVersion,Listener:record.Spec.Listener.Mode,Lifecycle:record.Spec.DesiredLifecycle,Health:redisservice.HealthIndeterminate,Drift:redisservice.DriftIndeterminate,Consumers:uint64(len(consumers.Consumers)),Generation:record.Spec.Generation,ConfigGeneration:record.Spec.ConfigGeneration,ConsumerGeneration:consumers.Generation,UpdatedAt:record.Spec.UpdatedAt,StatusReason:"runtime_proof_unavailable"}
	if record.Observed!=nil{
		projection.Lifecycle=record.Observed.Lifecycle;projection.Health=record.Observed.Health;projection.Drift=record.Observed.Drift
		if record.Observed.ActualVersion!=""{projection.Version=record.Observed.ActualVersion}
		if record.Observed.ObservedAt.After(projection.UpdatedAt){projection.UpdatedAt=record.Observed.ObservedAt}
		switch{case record.Observed.Drift==redisservice.DriftPresent:projection.StatusReason="desired_state_not_reconciled";case record.Observed.Drift==redisservice.DriftIndeterminate:projection.StatusReason="drift_proof_unavailable";case record.Observed.Health==redisservice.HealthDegraded:projection.StatusReason="runtime_degraded";case record.Observed.Health==redisservice.HealthFailed:projection.StatusReason="runtime_failed";case record.Observed.Health==redisservice.HealthIndeterminate:projection.StatusReason="runtime_proof_unavailable";default:projection.StatusReason=""}
		if record.Observed.ObservedAt.After(now)||now.Sub(record.Observed.ObservedAt)>5*time.Minute{projection.Health=redisservice.HealthIndeterminate;projection.Drift=redisservice.DriftIndeterminate;projection.StatusReason="runtime_proof_stale"}
		if record.Observed.ConfigGeneration!=record.Spec.ConfigGeneration||record.Observed.Lifecycle!=redisObservedLifecycle(record.Spec.DesiredLifecycle){if record.Observed.Drift==redisservice.DriftNone{projection.Health=redisservice.HealthIndeterminate};projection.Drift=redisservice.DriftPresent;projection.StatusReason="desired_state_not_reconciled"}
	}
	return projection
}

func(edge *operationsEdge)redisDetail(ctx context.Context,record redisservice.InstanceRecord)(apiserver.RedisDetail,error){
	consumers,err:=edge.redisConsumers(ctx,record.Spec.ID);if err!=nil{return apiserver.RedisDetail{},err}
	return apiserver.RedisDetail{Projection:redisProjection(record,consumers,edge.now().UTC()),Spec:record.Spec,Observed:record.Observed,Consumers:consumers},nil
}

func(edge *operationsEdge)ListRedis(ctx context.Context,call apiserver.EdgeCall,page apiserver.EdgePagePayload)(apiserver.EdgePage[apiserver.RedisProjection],error){
	limit:=int(page.Limit);if limit==0{limit=redisservice.MaxInstances};if limit>redisservice.MaxInstances{return apiserver.EdgePage[apiserver.RedisProjection]{},redisservice.ErrInvalid}
	filter:=redisservice.ListFilter{NodeID:edge.node.String(),AfterID:redisservice.InstanceID(page.Cursor),Limit:limit}
	if call.TenantID!=""{filter.TenantID=call.TenantID;filter.Scope=redisservice.ScopeTenant}
	records,err:=edge.redis.List(ctx,filter);if err!=nil{return apiserver.EdgePage[apiserver.RedisProjection]{},err}
	items:=make([]apiserver.RedisProjection,0,len(records));now:=edge.now().UTC();for _,record:=range records{consumers,loadErr:=edge.redisConsumers(ctx,record.Spec.ID);if loadErr!=nil{return apiserver.EdgePage[apiserver.RedisProjection]{},loadErr};items=append(items,redisProjection(record,consumers,now))}
	next:="";if len(records)==limit&&len(records)>0{next=string(records[len(records)-1].Spec.ID)}
	return apiserver.EdgePage[apiserver.RedisProjection]{Items:items,NextCursor:next,Total:uint64(len(items))},nil
}

func(edge *operationsEdge)guardRedisScope(ctx context.Context,spec redisservice.InstanceSpec)error{
	filter:=redisservice.ListFilter{NodeID:edge.node.String(),Scope:spec.Scope,Limit:redisservice.MaxInstances};if spec.Scope==redisservice.ScopeTenant{filter.TenantID=spec.TenantID};records,err:=edge.redis.List(ctx,filter);if err!=nil{return err};if len(records)!=0{return redisservice.ErrConflict};return nil
}

func(edge *operationsEdge)guardRedisPackageScope(ctx context.Context,id redisservice.InstanceID)error{
	records,err:=edge.redis.List(ctx,redisservice.ListFilter{NodeID:edge.node.String(),Limit:redisservice.MaxInstances});if err!=nil{return err};for _,record:=range records{if record.Spec.ID!=id&&record.Spec.DesiredLifecycle!=redisservice.LifecycleRemoved{return redisservice.ErrUnsupported}};return nil
}

func(edge *operationsEdge)GetRedis(ctx context.Context,call apiserver.EdgeCall)(apiserver.RedisDetail,error){record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisDetail{},err};return edge.redisDetail(ctx,record)}

func managedRedisEviction(value redisservice.EvictionPolicy)(operations.RedisEvictionPolicy,error){switch value{case redisservice.EvictionNoEviction:return operations.RedisNoEviction,nil;case redisservice.EvictionAllKeysLRU:return operations.RedisAllKeysLRU,nil;case redisservice.EvictionVolatileLRU:return operations.RedisVolatileLRU,nil;default:return "",redisservice.ErrUnsupported}}
func managedRedisPersistence(value redisservice.PersistencePolicy)(operations.RedisPersistence,error){switch{case value.RDB!=redisservice.RDBDisabled&&value.AOF!=redisservice.AOFDisabled:return operations.RedisRDBAOF,nil;case value.RDB!=redisservice.RDBDisabled:return operations.RedisRDB,nil;case value.AOF!=redisservice.AOFDisabled:return operations.RedisAOF,nil;default:return "",redisservice.ErrUnsupported}}

func validateManagedRedisProfile(spec redisservice.InstanceSpec)error{
	sealed,err:=redisservice.SealInstanceSpec(spec);if err!=nil||sealed.Digest!=spec.Digest{return redisservice.ErrInvalid}
	if len(spec.ACLUsers)!=1||spec.ACLUsers[0].Name!="cyberpanel"||spec.Listener.Mode!=redisservice.ListenerUnix||spec.Listener.SocketMode!=0o660||spec.Listener.TLS||spec.Databases!=16{return redisservice.ErrUnsupported}
	if spec.Persistence.RDB!=redisservice.RDBDisabled&&spec.Persistence.RDB!=redisservice.RDBBalanced||spec.Persistence.AOF!=redisservice.AOFDisabled&&spec.Persistence.AOF!=redisservice.AOFEverySec{return redisservice.ErrUnsupported}
	if _,err=operations.NewSecretRef(spec.ACLUsers[0].SecretRef.ID);err!=nil{return redisservice.ErrUnsupported}
	if _,err=managedRedisEviction(spec.Eviction);err!=nil{return err};if _,err=managedRedisPersistence(spec.Persistence);err!=nil{return err}
	return nil
}

func(edge *operationsEdge)redisHeader(call apiserver.EdgeCall,suffix string,approval operations.ResourceID,capabilities ...operations.Capability)(operations.CommandHeader,error){
	principal,err:=operations.NewResourceID(call.PrincipalID);if err!=nil{return operations.CommandHeader{},redisservice.ErrUnauthorized}
	var tenant site.TenantID;if call.TenantID!=""{tenant,err=site.NewTenantID(call.TenantID);if err!=nil{return operations.CommandHeader{},redisservice.ErrUnauthorized}}
	mfa:=operations.ResourceID{};if call.Assurance>=identity.AssuranceMFA{sum:=sha256.Sum256([]byte(call.SessionID+"\x00"+call.CredentialID));mfa,_=operations.NewResourceID("mfa-"+hex.EncodeToString(sum[:16]))}
	now:=edge.now().UTC();return operations.CommandHeader{CommandID:call.CommandID+suffix,NodeID:edge.node,TenantID:tenant,Actor:operations.Actor{PrincipalID:principal,TenantID:tenant,Capabilities:capabilities,MFAProofRef:mfa},RequestedAt:now,Deadline:now.Add(2*time.Minute),ApprovalRef:approval},nil
}

func(edge *operationsEdge)managedRedis(ctx context.Context,spec redisservice.InstanceSpec)(operations.ManagedService,uint64,error){
	if err:=validateManagedRedisProfile(spec);err!=nil{return operations.ManagedService{},0,err}
	id,err:=operations.NewResourceID(string(spec.ID));if err!=nil{return operations.ManagedService{},0,redisservice.ErrInvalid}
	credential,err:=operations.NewSecretRef(spec.ACLUsers[0].SecretRef.ID);if err!=nil{return operations.ManagedService{},0,redisservice.ErrUnsupported}
	expected:=uint64(0);if envelope,loadErr:=edge.repository.LoadResource(ctx,operations.KindManagedService,id);loadErr==nil{resource,decodeErr:=operations.DecodeResource(envelope);service,ok:=resource.(*operations.ManagedService);if decodeErr!=nil||!ok||service.KindName!=operations.ManagedRedis{return operations.ManagedService{},0,redisservice.ErrConflict};expected=service.Generation}else if !errors.Is(loadErr,operations.ErrNotFound){return operations.ManagedService{},0,loadErr}
	var tenant site.TenantID;if spec.TenantID!=""{tenant,err=site.NewTenantID(spec.TenantID);if err!=nil{return operations.ManagedService{},0,redisservice.ErrInvalid}}
	eviction,err:=managedRedisEviction(spec.Eviction);if err!=nil{return operations.ManagedService{},0,err};persistence,err:=managedRedisPersistence(spec.Persistence);if err!=nil{return operations.ManagedService{},0,err}
	maxClients:=uint32(spec.ResourceProfile.FileLimit/4);if maxClients==0{maxClients=1}
	desired:=operations.ServiceStopped;if spec.DesiredLifecycle==redisservice.LifecycleRunning{desired=operations.ServiceRunning}
	status:=operations.ResourceStatus{Lifecycle:operations.LifecycleUpdating,Health:operations.HealthUnknown,Reconciliation:operations.ReconciliationPending}
	runtime:=operations.RedisRuntimeSupport{OSFamily:spec.Support.OSFamily,OSVersion:spec.Support.OSVersion,Architecture:spec.Support.Architecture,RedisVersion:spec.Support.RedisVersion,PackageChannel:spec.Support.PackageChannel,QualificationDigest:strings.TrimPrefix(spec.Support.QualificationDigest,"sha256:")}
	service:=operations.ManagedService{Metadata:operations.Metadata{ID:id,NodeID:edge.node,TenantID:tenant,Generation:expected+1,Status:status},KindName:operations.ManagedRedis,Desired:desired,Redis:&operations.RedisSettings{MemoryMaxBytes:spec.MaxMemoryBytes,MaxClients:maxClients,EvictionPolicy:eviction,Persistence:persistence,TLS:false,CredentialSecretRef:credential,Runtime:runtime},TenantDedicated:spec.Scope==redisservice.ScopeTenant}
	return service,expected,nil
}

func managedRedisArtifact(artifact redisservice.ArtifactDescriptor,complete bool)(operations.ManagedRedisArtifact,error){
	id,err:=operations.NewResourceID(artifact.ID);if err!=nil{return operations.ManagedRedisArtifact{},redisservice.ErrInvalid};group,err:=operations.NewResourceID(artifact.GroupID);if err!=nil{return operations.ManagedRedisArtifact{},redisservice.ErrInvalid};instance,err:=operations.NewResourceID(string(artifact.InstanceID));if err!=nil{return operations.ManagedRedisArtifact{},redisservice.ErrInvalid}
	value:=operations.ManagedRedisArtifact{ID:id.String(),GroupID:group.String(),InstanceID:instance,Kind:string(artifact.Kind),RedisVersion:artifact.RedisVersion,ConfigGeneration:artifact.ConfigGeneration}
	if complete{if !strings.HasPrefix(artifact.SHA256,"sha256:"){return operations.ManagedRedisArtifact{},redisservice.ErrInvalid};value.SizeBytes=artifact.SizeBytes;value.SHA256=strings.TrimPrefix(artifact.SHA256,"sha256:");value.CreatedAt=artifact.CreatedAt.UTC()}else if artifact.SizeBytes!=0||artifact.SHA256!=""||!artifact.CreatedAt.IsZero(){return operations.ManagedRedisArtifact{},redisservice.ErrInvalid}
	return value,nil
}

func redisArtifactDescriptor(artifact operations.ManagedRedisArtifact)(redisservice.ArtifactDescriptor,error){if artifact.ID==""||artifact.GroupID==""||artifact.InstanceID.IsZero()||artifact.Kind!=string(redisservice.ArtifactRDB)||artifact.SizeBytes<=0||len(artifact.SHA256)!=64||artifact.CreatedAt.IsZero(){return redisservice.ArtifactDescriptor{},redisservice.ErrInvalid};return redisservice.ArtifactDescriptor{ID:artifact.ID,GroupID:artifact.GroupID,InstanceID:redisservice.InstanceID(artifact.InstanceID.String()),Kind:redisservice.ArtifactKind(artifact.Kind),RedisVersion:artifact.RedisVersion,ConfigGeneration:artifact.ConfigGeneration,SizeBytes:artifact.SizeBytes,SHA256:"sha256:"+artifact.SHA256,CreatedAt:artifact.CreatedAt.UTC()},nil}

func(edge *operationsEdge)currentManagedRedis(ctx context.Context,spec redisservice.InstanceSpec)(operations.ManagedService,error){candidate,expected,err:=edge.managedRedis(ctx,spec);if err!=nil{return operations.ManagedService{},err};if expected==0{return operations.ManagedService{},redisservice.ErrStale};envelope,err:=edge.repository.LoadResource(ctx,operations.KindManagedService,candidate.ID);if err!=nil{return operations.ManagedService{},err};resource,err:=operations.DecodeResource(envelope);current,ok:=resource.(*operations.ManagedService);if err!=nil||!ok||current.Generation!=expected||current.KindName!=operations.ManagedRedis||current.Desired!=candidate.Desired||current.TenantDedicated!=candidate.TenantDedicated||current.NodeID!=candidate.NodeID||current.TenantID.String()!=candidate.TenantID.String()||!reflect.DeepEqual(current.Redis,candidate.Redis){return operations.ManagedService{},redisservice.ErrStale};return *current,nil}

func redisRuntimeError(err error)error{if errors.Is(err,operations.ErrInvalidEffect)||errors.Is(err,operations.ErrNotFound){return redisservice.ErrUnsupported};return err}

func(edge *operationsEdge)executeManagedRedisData(ctx context.Context,call apiserver.EdgeCall,spec redisservice.InstanceSpec,suffix string,data operations.ManagedRedisDataEffect)(string,*operations.ManagedRedisDataResult,error){
	service,err:=edge.currentManagedRedis(ctx,spec);if err!=nil{return "",nil,err};header,err:=edge.redisHeader(call,suffix,operations.ResourceID{},operations.CapabilityNodeOperations);if err!=nil{return "",nil,err};header.Deadline=header.RequestedAt.Add(15*time.Minute)
	receipt,executionErr:=edge.commands.Handle(ctx,operations.OperateManagedRedisData{Header:header,Service:service,ExpectedGeneration:service.Generation,Data:data});operationID:=receipt.CommandID;if operationID==""{operationID=header.CommandID};if receipt.Status==operations.OperationAmbiguous{return operationID,nil,redisservice.ErrAmbiguous};if executionErr!=nil{return operationID,nil,redisRuntimeError(executionErr)};if receipt.Status!=operations.OperationApplied||receipt.Effect.Result.ManagedRedisData==nil||receipt.Effect.ProofDigest==""{return operationID,nil,redisservice.ErrAmbiguous};return operationID,receipt.Effect.Result.ManagedRedisData,nil
}

func(edge *operationsEdge)reconcileRedisHost(ctx context.Context,call apiserver.EdgeCall,spec redisservice.InstanceSpec,suffix string)(string,error){
	service,expected,err:=edge.managedRedis(ctx,spec);if err!=nil{return "",err}
	header,err:=edge.redisHeader(call,suffix,operations.ResourceID{},operations.CapabilityNodeOperations);if err!=nil{return "",err}
	receipt,err:=edge.commands.Handle(ctx,operations.ReconcileManagedService{Header:header,Service:service,ExpectedGeneration:expected})
	operationID:=receipt.CommandID;if operationID==""{operationID=header.CommandID}
	if err!=nil{return operationID,redisRuntimeError(err)}
	if receipt.Status!=operations.OperationApplied||receipt.Effect.ProofDigest==""{return operationID,redisservice.ErrAmbiguous}
	return operationID,nil
}

func redisObservedLifecycle(desired redisservice.LifecycleState)redisservice.LifecycleState{switch desired{case redisservice.LifecycleRunning:return redisservice.LifecycleRunning;case redisservice.LifecycleRemoved:return redisservice.LifecycleRemoved;case redisservice.LifecycleInstalled:return redisservice.LifecycleInstalled;default:return redisservice.LifecycleStopped}}

func(edge *operationsEdge)recordRedisObservation(ctx context.Context,spec redisservice.InstanceSpec,executionErr error)error{
	previous,err:=edge.redis.Observation(ctx,spec.ID);expected:=uint64(0);if err==nil{expected=previous.Generation}else if !errors.Is(err,redisservice.ErrNotFound){return err}
	now:=edge.now().UTC();observation:=redisservice.InstanceObservation{InstanceID:spec.ID,NodeID:spec.NodeID,Generation:expected+1,ConfigGeneration:spec.ConfigGeneration,Lifecycle:redisObservedLifecycle(spec.DesiredLifecycle),Enabled:spec.DesiredLifecycle==redisservice.LifecycleRunning,Health:redisservice.HealthHealthy,Drift:redisservice.DriftNone,ActualVersion:spec.Support.RedisVersion,ObservedAt:now}
	if executionErr!=nil{
		if expected!=0{observation.Lifecycle=previous.Lifecycle;observation.Enabled=previous.Enabled;observation.ConfigGeneration=previous.ConfigGeneration;observation.ActualVersion=previous.ActualVersion;observation.ActualConfigDigest=previous.ActualConfigDigest;observation.DatasetBytes=previous.DatasetBytes;observation.ConnectedClients=previous.ConnectedClients;observation.LastSuccessfulSaveAt=previous.LastSuccessfulSaveAt}
		observation.Health=redisservice.HealthDegraded;observation.Drift=redisservice.DriftPresent
		if expected==0{observation.Lifecycle=redisservice.LifecycleAbsent;observation.Health=redisservice.HealthIndeterminate;observation.Drift=redisservice.DriftIndeterminate}
	}
	sealed,err:=redisservice.SealObservation(observation);if err!=nil{return err};return edge.redis.PutObservation(ctx,sealed,expected)
}

func(edge *operationsEdge)finishRedisTarget(ctx context.Context,call apiserver.EdgeCall,spec redisservice.InstanceSpec,suffix string)(apiserver.RedisMutation,error){
	operationID,executionErr:=edge.reconcileRedisHost(ctx,call,spec,suffix)
	observationErr:=edge.recordRedisObservation(ctx,spec,executionErr);if executionErr!=nil{return apiserver.RedisMutation{},errors.Join(executionErr,observationErr)};if observationErr!=nil{return apiserver.RedisMutation{},observationErr}
	record,err:=edge.redis.Inspect(ctx,spec.ID);if err!=nil{return apiserver.RedisMutation{},err};detail,err:=edge.redisDetail(ctx,record);if err!=nil{return apiserver.RedisMutation{},err}
	state:="applied";if detail.Projection.Health!=redisservice.HealthHealthy||detail.Projection.Drift!=redisservice.DriftNone{state="degraded"};return apiserver.RedisMutation{OperationID:operationID,State:state,Generation:spec.Generation,Resource:detail.Projection},nil
}

func redisOwnedSpec(edge *operationsEdge,call apiserver.EdgeCall,spec redisservice.InstanceSpec,generation,configGeneration uint64)(redisservice.InstanceSpec,error){
	if call.ResourceID!=""&&call.ResourceID!=string(spec.ID){return redisservice.InstanceSpec{},redisservice.ErrInvalid}
	spec.NodeID=edge.node.String();if call.TenantID==""{spec.Scope=redisservice.ScopeNode;spec.TenantID=""}else{spec.Scope=redisservice.ScopeTenant;spec.TenantID=call.TenantID}
	spec.Generation=generation;spec.ConfigGeneration=configGeneration;spec.UpdatedAt=edge.now().UTC();spec.Digest=""
	sealed,err:=redisservice.SealInstanceSpec(spec);if err!=nil{return redisservice.InstanceSpec{},err};if err=validateManagedRedisProfile(sealed);err!=nil{return redisservice.InstanceSpec{},err};return sealed,nil
}

func(edge *operationsEdge)CreateRedis(ctx context.Context,call apiserver.EdgeCall,spec redisservice.InstanceSpec)(apiserver.RedisMutation,error){
	edge.redisMu.Lock();defer edge.redisMu.Unlock()
	if call.ExpectedGeneration!=0||spec.DesiredLifecycle==redisservice.LifecycleRemoved{return apiserver.RedisMutation{},redisservice.ErrInvalid}
	target,err:=redisOwnedSpec(edge,call,spec,1,1);if err!=nil{return apiserver.RedisMutation{},err}
	if err=edge.guardRedisScope(ctx,target);err!=nil{return apiserver.RedisMutation{},err}
	if err=edge.redis.PutSpec(ctx,target,0);err!=nil{return apiserver.RedisMutation{},err}
	now:=edge.now().UTC();snapshot,err:=redisservice.SealConsumerSnapshot(redisservice.ConsumerSnapshot{InstanceID:target.ID,Generation:1,Complete:true,ObservedAt:now});if err!=nil{return apiserver.RedisMutation{},err};if err=edge.redis.PutConsumerSnapshot(ctx,snapshot,0);err!=nil{return apiserver.RedisMutation{},err}
	initial,err:=redisservice.SealObservation(redisservice.InstanceObservation{InstanceID:target.ID,NodeID:target.NodeID,Generation:1,Lifecycle:redisservice.LifecycleAbsent,Health:redisservice.HealthIndeterminate,Drift:redisservice.DriftIndeterminate,ObservedAt:now});if err!=nil{return apiserver.RedisMutation{},err};if err=edge.redis.PutObservation(ctx,initial,0);err!=nil{return apiserver.RedisMutation{},err}
	return edge.finishRedisTarget(ctx,call,target,"-redis-create")
}

func protectedRedisConsumer(consumer redisservice.Consumer)bool{
	kind:=strings.ToLower(consumer.Kind);if separator:=strings.IndexAny(kind,"._:-");separator>=0{kind=kind[:separator]}
	return kind=="mail"||kind=="cache"||kind=="session"||consumer.Purpose==redisservice.PurposeCache||consumer.Purpose==redisservice.PurposeObjectCache||consumer.Purpose==redisservice.PurposeSession
}

func(edge *operationsEdge)guardRedisConsumers(ctx context.Context,id redisservice.InstanceID,all bool)error{
	snapshot,err:=edge.redis.ConsumerSnapshot(ctx,id);if err!=nil{return err};if !snapshot.Complete{return redisservice.ErrStale}
	for _,consumer:=range snapshot.Consumers{if all||protectedRedisConsumer(consumer){return redisservice.ErrConsumersPresent}}
	return nil
}

func destructiveRedisConfiguration(current,target redisservice.InstanceSpec)bool{
	if current.Purpose!=target.Purpose||current.Support!=target.Support||current.Listener!=target.Listener||current.Databases!=target.Databases||current.Eviction!=target.Eviction||current.Persistence!=target.Persistence||!reflect.DeepEqual(current.ACLUsers,target.ACLUsers){return true}
	if target.MaxMemoryBytes<current.MaxMemoryBytes||target.ResourceProfile.MemoryLimitBytes<current.ResourceProfile.MemoryLimitBytes{return true}
	return false
}

func(edge *operationsEdge)ConfigureRedis(ctx context.Context,call apiserver.EdgeCall,spec redisservice.InstanceSpec)(apiserver.RedisMutation,error){
	edge.redisMu.Lock();defer edge.redisMu.Unlock()
	record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisMutation{},err};if call.ExpectedGeneration==0||call.ExpectedGeneration!=record.Spec.Generation||record.Spec.DesiredLifecycle==redisservice.LifecycleRemoved||spec.ID!=record.Spec.ID||spec.DesiredLifecycle!=record.Spec.DesiredLifecycle||spec.Support!=record.Spec.Support{return apiserver.RedisMutation{},redisservice.ErrConflict}
	disruptiveApply:=(record.Observed!=nil&&record.Observed.Lifecycle==redisservice.LifecycleRunning)||(record.Observed==nil&&record.Spec.DesiredLifecycle==redisservice.LifecycleRunning);if destructiveRedisConfiguration(record.Spec,spec)||disruptiveApply{if err=edge.guardRedisConsumers(ctx,record.Spec.ID,false);err!=nil{return apiserver.RedisMutation{},err}}
	target,err:=redisOwnedSpec(edge,call,spec,record.Spec.Generation+1,record.Spec.ConfigGeneration+1);if err!=nil{return apiserver.RedisMutation{},err};if err=edge.redis.PutSpec(ctx,target,record.Spec.Generation);err!=nil{return apiserver.RedisMutation{},err}
	return edge.finishRedisTarget(ctx,call,target,"-redis-configure")
}

func(edge *operationsEdge)redisLifecycle(ctx context.Context,call apiserver.EdgeCall,desired redisservice.LifecycleState,restart bool)(apiserver.RedisMutation,error){
	edge.redisMu.Lock();defer edge.redisMu.Unlock()
	record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisMutation{},err};if call.ExpectedGeneration==0||call.ExpectedGeneration!=record.Spec.Generation{return apiserver.RedisMutation{},redisservice.ErrConflict}
	if record.Spec.DesiredLifecycle==redisservice.LifecycleRemoved{return apiserver.RedisMutation{},redisservice.ErrConflict}
	if !restart&&record.Spec.DesiredLifecycle==desired&&record.Observed!=nil&&record.Observed.ConfigGeneration==record.Spec.ConfigGeneration&&record.Observed.Lifecycle==redisObservedLifecycle(desired)&&record.Observed.Drift==redisservice.DriftNone{detail,detailErr:=edge.redisDetail(ctx,record);if detailErr!=nil{return apiserver.RedisMutation{},detailErr};state:="unchanged";if detail.Projection.Health!=redisservice.HealthHealthy{state="degraded"};return apiserver.RedisMutation{State:state,Generation:record.Spec.Generation,Resource:detail.Projection},nil}
	disruptiveStart:=desired==redisservice.LifecycleRunning&&record.Spec.DesiredLifecycle==redisservice.LifecycleRunning&&(record.Observed==nil||record.Observed.Lifecycle==redisservice.LifecycleRunning);if desired==redisservice.LifecycleStopped||restart||disruptiveStart{if err=edge.guardRedisConsumers(ctx,record.Spec.ID,false);err!=nil{return apiserver.RedisMutation{},err}}
	target:=record.Spec;target.DesiredLifecycle=desired;target.Generation++;target.UpdatedAt=edge.now().UTC();target.Digest="";target,err=redisservice.SealInstanceSpec(target);if err!=nil{return apiserver.RedisMutation{},err};if err=edge.redis.PutSpec(ctx,target,record.Spec.Generation);err!=nil{return apiserver.RedisMutation{},err}
	suffix:="-redis-start";if desired==redisservice.LifecycleStopped{suffix="-redis-stop"};if restart{suffix="-redis-restart"}
	return edge.finishRedisTarget(ctx,call,target,suffix)
}

func(edge *operationsEdge)StartRedis(ctx context.Context,call apiserver.EdgeCall)(apiserver.RedisMutation,error){return edge.redisLifecycle(ctx,call,redisservice.LifecycleRunning,false)}
func(edge *operationsEdge)StopRedis(ctx context.Context,call apiserver.EdgeCall)(apiserver.RedisMutation,error){return edge.redisLifecycle(ctx,call,redisservice.LifecycleStopped,false)}
func(edge *operationsEdge)RestartRedis(ctx context.Context,call apiserver.EdgeCall)(apiserver.RedisMutation,error){return edge.redisLifecycle(ctx,call,redisservice.LifecycleRunning,true)}

func(edge *operationsEdge)upgradeRedisPackage(ctx context.Context,call apiserver.EdgeCall,payload apiserver.RedisUpgradePayload)(string,error){
	if call.TenantID!=""||payload.FromPackageVersion==""||payload.ToPackageVersion==""||payload.RecoveryPointRef.IsZero()||payload.MaintenanceRef.IsZero()||payload.ApprovalRef.IsZero(){return "",redisservice.ErrUnauthorized}
	manager:=payload.Manager;if manager!="apt"&&manager!="dnf"{return "",redisservice.ErrInvalid}
	architecture:=payload.Architecture;if architecture.IsZero(){return "",redisservice.ErrInvalid};name,_:=operations.NewResourceID("redis");sum:=sha256.Sum256([]byte(call.CommandID+"\x00redis-package"));transactionID,_:=operations.NewResourceID("redis-package-"+hex.EncodeToString(sum[:16]))
	status:=operations.ResourceStatus{Lifecycle:operations.LifecycleUpdating,Health:operations.HealthUnknown,Reconciliation:operations.ReconciliationPending}
	transaction:=operations.PackageTransaction{Metadata:operations.Metadata{ID:transactionID,NodeID:edge.node,Generation:1,Status:status},Manager:manager,Selections:[]operations.PackageSelection{{Name:name,Architecture:architecture,FromVersion:payload.FromPackageVersion,ToVersion:payload.ToPackageVersion,Action:operations.PackageUpgrade}},Risk:operations.RiskDatabase,RecoveryPointRef:payload.RecoveryPointRef,MaintenanceRef:payload.MaintenanceRef,ApprovalRef:payload.ApprovalRef}
	header,err:=edge.redisHeader(call,"-redis-package",payload.ApprovalRef,operations.CapabilityNodePackages);if err!=nil{return "",err};receipt,err:=edge.commands.Handle(ctx,operations.RequestPackageTransaction{Header:header,Transaction:transaction});if err!=nil{return receipt.CommandID,err};if receipt.Status!=operations.OperationApplied{return receipt.CommandID,redisservice.ErrAmbiguous};return receipt.CommandID,nil
}

func(edge *operationsEdge)UpgradeRedis(ctx context.Context,call apiserver.EdgeCall,payload apiserver.RedisUpgradePayload)(apiserver.RedisMutation,error){
	edge.redisMu.Lock();defer edge.redisMu.Unlock()
	record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisMutation{},err};if call.ExpectedGeneration==0||call.ExpectedGeneration!=record.Spec.Generation||record.Spec.DesiredLifecycle==redisservice.LifecycleRemoved||record.Spec.Scope!=redisservice.ScopeNode{return apiserver.RedisMutation{},redisservice.ErrConflict};if err=edge.guardRedisPackageScope(ctx,record.Spec.ID);err!=nil{return apiserver.RedisMutation{},err};if err=edge.guardRedisConsumers(ctx,record.Spec.ID,false);err!=nil{return apiserver.RedisMutation{},err}
	target:=record.Spec;target.Support.RedisVersion=payload.RedisVersion;target.Support.QualificationDigest=payload.QualificationDigest;target.Generation++;target.ConfigGeneration++;target.UpdatedAt=edge.now().UTC();target.Digest="";target,err=redisservice.SealInstanceSpec(target);if err!=nil{return apiserver.RedisMutation{},err};if err=validateManagedRedisProfile(target);err!=nil{return apiserver.RedisMutation{},err};if err=edge.redis.PutSpec(ctx,target,record.Spec.Generation);err!=nil{return apiserver.RedisMutation{},err}
	packageOperation,packageErr:=edge.upgradeRedisPackage(ctx,call,payload);if packageErr!=nil{observationErr:=edge.recordRedisObservation(ctx,target,packageErr);return apiserver.RedisMutation{},errors.Join(packageErr,observationErr)}
	result,err:=edge.finishRedisTarget(ctx,call,target,"-redis-upgrade-reconcile");if result.OperationID==""{result.OperationID=packageOperation};return result,err
}

func(edge *operationsEdge)HealthRedis(ctx context.Context,call apiserver.EdgeCall)(apiserver.RedisMutation,error){
	record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisMutation{},err};if call.ExpectedGeneration!=0&&call.ExpectedGeneration!=record.Spec.Generation{return apiserver.RedisMutation{},redisservice.ErrConflict}
	detail,err:=edge.redisDetail(ctx,record);if err!=nil{return apiserver.RedisMutation{},err};state:="observed";if detail.Projection.Health!=redisservice.HealthHealthy||detail.Projection.Drift!=redisservice.DriftNone{state="degraded"};return apiserver.RedisMutation{State:state,Generation:record.Spec.Generation,Resource:detail.Projection},nil
}

func(edge *operationsEdge)BindRedisConsumer(ctx context.Context,call apiserver.EdgeCall,payload apiserver.RedisConsumerPayload)(apiserver.RedisMutation,error){
	edge.redisMu.Lock();defer edge.redisMu.Unlock()
	record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisMutation{},err};if call.ExpectedGeneration==0||call.ExpectedGeneration!=record.Spec.Generation||record.Spec.DesiredLifecycle==redisservice.LifecycleRemoved{return apiserver.RedisMutation{},redisservice.ErrConflict}
	allowedACL:=false;for _,user:=range record.Spec.ACLUsers{if user.Name==payload.ACLUser{allowedACL=true;break}};if !allowedACL||payload.Database>=record.Spec.Databases{return apiserver.RedisMutation{},redisservice.ErrInvalid}
	snapshot,err:=edge.redisConsumers(ctx,record.Spec.ID);if err!=nil{return apiserver.RedisMutation{},err};expected:=snapshot.Generation;generation:=expected+1;consumer:=redisservice.Consumer{ID:payload.ConsumerID,Kind:payload.Kind,Purpose:record.Spec.Purpose,ACLUser:payload.ACLUser,Database:payload.Database,Active:payload.Active,Generation:generation,EvidenceDigest:redisCoreDigest(payload.ConsumerID,payload.Kind,payload.ACLUser,string(record.Spec.Purpose),call.PrincipalID,call.CommandID)}
	consumers:=append([]redisservice.Consumer(nil),snapshot.Consumers...);found:=false;for index:=range consumers{if consumers[index].ID==payload.ConsumerID{consumers[index]=consumer;found=true;break}};if !found{consumers=append(consumers,consumer)}
	snapshot=redisservice.ConsumerSnapshot{InstanceID:record.Spec.ID,Generation:generation,Complete:true,Consumers:consumers,ObservedAt:edge.now().UTC()};snapshot,err=redisservice.SealConsumerSnapshot(snapshot);if err!=nil{return apiserver.RedisMutation{},err};if err=edge.redis.PutConsumerSnapshot(ctx,snapshot,expected);err!=nil{return apiserver.RedisMutation{},err}
	updated,err:=edge.redis.Inspect(ctx,record.Spec.ID);if err!=nil{return apiserver.RedisMutation{},err};detail,err:=edge.redisDetail(ctx,updated);if err!=nil{return apiserver.RedisMutation{},err};return apiserver.RedisMutation{OperationID:call.CommandID,State:"applied",Generation:updated.Spec.Generation,Resource:detail.Projection},nil
}

func(edge *operationsEdge)UnbindRedisConsumer(ctx context.Context,call apiserver.EdgeCall,consumerID string)(apiserver.RedisMutation,error){
	edge.redisMu.Lock();defer edge.redisMu.Unlock()
	record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisMutation{},err};if call.ExpectedGeneration==0||call.ExpectedGeneration!=record.Spec.Generation{return apiserver.RedisMutation{},redisservice.ErrConflict}
	snapshot,err:=edge.redis.ConsumerSnapshot(ctx,record.Spec.ID);if err!=nil{return apiserver.RedisMutation{},err};consumers:=make([]redisservice.Consumer,0,len(snapshot.Consumers));found:=false;for _,consumer:=range snapshot.Consumers{if consumer.ID==consumerID{if consumer.Active&&protectedRedisConsumer(consumer){return apiserver.RedisMutation{},redisservice.ErrConsumersPresent};found=true;continue};consumers=append(consumers,consumer)};if !found{return apiserver.RedisMutation{},redisservice.ErrNotFound}
	next:=redisservice.ConsumerSnapshot{InstanceID:record.Spec.ID,Generation:snapshot.Generation+1,Complete:true,Consumers:consumers,ObservedAt:edge.now().UTC()};next,err=redisservice.SealConsumerSnapshot(next);if err!=nil{return apiserver.RedisMutation{},err};if err=edge.redis.PutConsumerSnapshot(ctx,next,snapshot.Generation);err!=nil{return apiserver.RedisMutation{},err}
	updated,err:=edge.redis.Inspect(ctx,record.Spec.ID);if err!=nil{return apiserver.RedisMutation{},err};detail,err:=edge.redisDetail(ctx,updated);if err!=nil{return apiserver.RedisMutation{},err};return apiserver.RedisMutation{OperationID:call.CommandID,State:"applied",Generation:updated.Spec.Generation,Resource:detail.Projection},nil
}

func(edge *operationsEdge)RecordRedisBackup(ctx context.Context,call apiserver.EdgeCall,artifact redisservice.ArtifactDescriptor)(apiserver.RedisBackupResult,error){
	edge.redisMu.Lock();defer edge.redisMu.Unlock()
	record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisBackupResult{},err};if call.ExpectedGeneration==0||call.ExpectedGeneration!=record.Spec.Generation||record.Observed==nil||record.Observed.Lifecycle!=redisservice.LifecycleRunning||record.Observed.Health!=redisservice.HealthHealthy||record.Observed.Drift!=redisservice.DriftNone||record.Observed.ConfigGeneration!=record.Spec.ConfigGeneration{return apiserver.RedisBackupResult{},redisservice.ErrStale}
	if record.Spec.Backup.Frequency==redisservice.BackupDisabled||artifact.InstanceID!=record.Spec.ID||artifact.RedisVersion!=record.Spec.Support.RedisVersion||artifact.ConfigGeneration!=record.Spec.ConfigGeneration||artifact.Kind!=redisservice.ArtifactRDB{return apiserver.RedisBackupResult{},redisservice.ErrUnsupported};target,err:=managedRedisArtifact(artifact,false);if err!=nil{return apiserver.RedisBackupResult{},err}
	if existing,loadErr:=edge.redis.Artifact(ctx,artifact.ID);loadErr==nil{existingTarget,targetErr:=managedRedisArtifact(existing,true);if targetErr!=nil||!existingTarget.CreatedAt.Equal(existing.CreatedAt.UTC())||existingTarget.ID!=target.ID||existingTarget.GroupID!=target.GroupID||existingTarget.InstanceID!=target.InstanceID||existingTarget.Kind!=target.Kind||existingTarget.RedisVersion!=target.RedisVersion||existingTarget.ConfigGeneration!=target.ConfigGeneration{return apiserver.RedisBackupResult{},redisservice.ErrConflict};return apiserver.RedisBackupResult{State:"captured",Artifact:existing,Generation:record.Spec.Generation},nil}else if !errors.Is(loadErr,redisservice.ErrNotFound){return apiserver.RedisBackupResult{},loadErr}
	data:=operations.ManagedRedisDataEffect{Action:operations.ManagedRedisSnapshot,ExpectedSpecGeneration:record.Spec.Generation,ExpectedConfigGeneration:record.Spec.ConfigGeneration,Artifact:target};_,result,err:=edge.executeManagedRedisData(ctx,call,record.Spec,"-redis-backup",data);if err!=nil{return apiserver.RedisBackupResult{},err};if result.Action!=operations.ManagedRedisSnapshot||result.Artifact==nil{return apiserver.RedisBackupResult{},redisservice.ErrAmbiguous};captured,err:=redisArtifactDescriptor(*result.Artifact);if err!=nil||captured.InstanceID!=record.Spec.ID||captured.RedisVersion!=record.Spec.Support.RedisVersion||captured.ConfigGeneration!=record.Spec.ConfigGeneration||captured.CreatedAt.After(edge.now().UTC().Add(time.Minute)){return apiserver.RedisBackupResult{},redisservice.ErrAmbiguous};if err=edge.redis.PutArtifact(ctx,captured);err!=nil{return apiserver.RedisBackupResult{},err};return apiserver.RedisBackupResult{State:"captured",Artifact:captured,Generation:record.Spec.Generation},nil
}

func(edge *operationsEdge)PlanRedisRestore(ctx context.Context,call apiserver.EdgeCall,payload apiserver.RedisRestorePayload)(apiserver.RedisRestorePlan,error){
	edge.redisMu.Lock();defer edge.redisMu.Unlock()
	record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisRestorePlan{},err};if call.ExpectedGeneration==0||call.ExpectedGeneration!=record.Spec.Generation||record.Spec.DesiredLifecycle!=redisservice.LifecycleRunning||payload.ArtifactID==payload.RecoveryArtifactRef||record.Observed==nil||record.Observed.Lifecycle!=redisservice.LifecycleRunning||record.Observed.Health!=redisservice.HealthHealthy||record.Observed.Drift!=redisservice.DriftNone||record.Observed.ConfigGeneration!=record.Spec.ConfigGeneration{return apiserver.RedisRestorePlan{},redisservice.ErrConflict}
	if err=edge.guardRedisConsumers(ctx,record.Spec.ID,true);err!=nil{return apiserver.RedisRestorePlan{},err};artifact,err:=edge.redis.Artifact(ctx,payload.ArtifactID);if err!=nil{return apiserver.RedisRestorePlan{},err};recovery,err:=edge.redis.Artifact(ctx,payload.RecoveryArtifactRef);if err!=nil{return apiserver.RedisRestorePlan{},err}
	if artifact.InstanceID!=record.Spec.ID||recovery.InstanceID!=record.Spec.ID||artifact.RedisVersion!=record.Spec.Support.RedisVersion||recovery.RedisVersion!=record.Spec.Support.RedisVersion||artifact.Kind!=redisservice.ArtifactRDB||recovery.Kind!=redisservice.ArtifactRDB||recovery.ConfigGeneration!=record.Spec.ConfigGeneration{return apiserver.RedisRestorePlan{},redisservice.ErrUnsupported};sourceEffect,err:=managedRedisArtifact(artifact,true);if err!=nil{return apiserver.RedisRestorePlan{},err};recoveryEffect,err:=managedRedisArtifact(recovery,true);if err!=nil{return apiserver.RedisRestorePlan{},err}
	snapshot,err:=edge.redis.ConsumerSnapshot(ctx,record.Spec.ID);if err!=nil{return apiserver.RedisRestorePlan{},err};data:=operations.ManagedRedisDataEffect{Action:operations.ManagedRedisRestore,ExpectedSpecGeneration:record.Spec.Generation,ExpectedConfigGeneration:record.Spec.ConfigGeneration,ExpectedConsumerGeneration:snapshot.Generation,Artifact:sourceEffect,RecoveryArtifact:recoveryEffect};_,result,executionErr:=edge.executeManagedRedisData(ctx,call,record.Spec,"-redis-restore",data);observationErr:=edge.recordRedisObservation(ctx,record.Spec,executionErr);if executionErr!=nil{return apiserver.RedisRestorePlan{},errors.Join(executionErr,observationErr)};if observationErr!=nil{return apiserver.RedisRestorePlan{},observationErr};if result.Action!=operations.ManagedRedisRestore{return apiserver.RedisRestorePlan{},redisservice.ErrAmbiguous};return apiserver.RedisRestorePlan{State:"restored",InstanceID:record.Spec.ID,Artifact:artifact,RecoveryArtifact:recovery,ExpectedGeneration:record.Spec.Generation,ConsumerGeneration:snapshot.Generation},nil
}

func(edge *operationsEdge)DeleteRedis(ctx context.Context,call apiserver.EdgeCall,recoveryArtifactRef string)(apiserver.RedisMutation,error){
	edge.redisMu.Lock();defer edge.redisMu.Unlock()
	record,err:=edge.redisRecord(ctx,call);if err!=nil{return apiserver.RedisMutation{},err};if call.ExpectedGeneration==0||call.ExpectedGeneration!=record.Spec.Generation||recoveryArtifactRef==""{return apiserver.RedisMutation{},redisservice.ErrConflict};if err=edge.guardRedisConsumers(ctx,record.Spec.ID,true);err!=nil{return apiserver.RedisMutation{},err};snapshot,err:=edge.redis.ConsumerSnapshot(ctx,record.Spec.ID);if err!=nil{return apiserver.RedisMutation{},err}
	recovery,err:=edge.redis.Artifact(ctx,recoveryArtifactRef);if err!=nil{return apiserver.RedisMutation{},err};if recovery.InstanceID!=record.Spec.ID||recovery.RedisVersion!=record.Spec.Support.RedisVersion||recovery.Kind!=redisservice.ArtifactRDB||recovery.ConfigGeneration!=record.Spec.ConfigGeneration{return apiserver.RedisMutation{},redisservice.ErrStale};recoveryEffect,err:=managedRedisArtifact(recovery,true);if err!=nil{return apiserver.RedisMutation{},err}
	target:=record.Spec;if target.DesiredLifecycle!=redisservice.LifecycleRemoved{target.DesiredLifecycle=redisservice.LifecycleRemoved;target.Generation++;target.UpdatedAt=edge.now().UTC();target.Digest="";target,err=redisservice.SealInstanceSpec(target);if err!=nil{return apiserver.RedisMutation{},err};if err=edge.redis.PutSpec(ctx,target,record.Spec.Generation);err!=nil{return apiserver.RedisMutation{},err}}
	_,stopErr:=edge.reconcileRedisHost(ctx,call,target,"-redis-delete-stop");if stopErr!=nil{observationErr:=edge.recordRedisObservation(ctx,target,stopErr);return apiserver.RedisMutation{},errors.Join(stopErr,observationErr)};data:=operations.ManagedRedisDataEffect{Action:operations.ManagedRedisPurge,ExpectedSpecGeneration:target.Generation,ExpectedConfigGeneration:target.ConfigGeneration,ExpectedConsumerGeneration:snapshot.Generation,RecoveryArtifact:recoveryEffect};operationID,result,purgeErr:=edge.executeManagedRedisData(ctx,call,target,"-redis-delete-purge",data);observationErr:=edge.recordRedisObservation(ctx,target,purgeErr);if purgeErr!=nil{return apiserver.RedisMutation{},errors.Join(purgeErr,observationErr)};if observationErr!=nil{return apiserver.RedisMutation{},observationErr};if result.Action!=operations.ManagedRedisPurge{return apiserver.RedisMutation{},redisservice.ErrAmbiguous};updated,err:=edge.redis.Inspect(ctx,target.ID);if err!=nil{return apiserver.RedisMutation{},err};detail,err:=edge.redisDetail(ctx,updated);if err!=nil{return apiserver.RedisMutation{},err};return apiserver.RedisMutation{OperationID:operationID,State:"applied",Generation:target.Generation,Resource:detail.Projection},nil
}

var _ apiserver.OperationsEdgeService=(*operationsEdge)(nil)
var _ apiserver.RedisEdgeService=(*operationsEdge)(nil)
