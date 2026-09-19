//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
	"github.com/aonsyed/cyberpanel/platform/internal/maintenance"
	"github.com/aonsyed/cyberpanel/platform/internal/operations"
	"github.com/aonsyed/cyberpanel/platform/internal/packagemaint"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/serviceregistry"
)

type rebootControlLocalRuntime struct{db *sql.DB;admissions *rebootcontrol.AdmissionGate;windows *maintenance.Repository;evaluator *maintenance.Evaluator;packages *packagemaint.SQLRepository;packageOutcomes *packageMaintenanceLinuxEdge;reboots *rebootcontrol.Repository;executor operations.HostExecutor;ha ha.SQLRepository;now func()time.Time}

func assembleRebootControlLinuxEdge(ctx context.Context,db *sql.DB,executor operations.HostExecutor,haRepository ha.SQLRepository,packageOutcomes *packageMaintenanceLinuxEdge,now func()time.Time)(*rebootControlLinuxEdge,error){
	if ctx==nil||db==nil||executor==nil||haRepository.DB==nil{return nil,rebootcontrol.ErrInvalid};if now==nil{now=time.Now}
	windows,err:=maintenance.NewRepository(db);if err!=nil{return nil,err};if err=windows.Bootstrap(ctx);err!=nil{return nil,err};evaluator,err:=maintenance.NewEvaluator(windows,maintenance.EvaluatorConfig{});if err!=nil{return nil,err}
	packages,err:=packagemaint.NewSQLRepository(db);if err!=nil{return nil,err};if err=packages.Bootstrap(ctx);err!=nil{return nil,err};reboots,err:=rebootcontrol.NewRepository(db);if err!=nil{return nil,err};if err=reboots.Bootstrap(ctx);err!=nil{return nil,err}
	manager:=packagemaint.ManagerAPT;if _,err=os.Stat("/usr/bin/apt-get");err!=nil{if _,dnfErr:=os.Stat("/usr/bin/dnf");dnfErr!=nil{return nil,fmt.Errorf("package manager unavailable: %w",err)};manager=packagemaint.ManagerDNF}
	runtime:=&rebootControlLocalRuntime{db:db,windows:windows,evaluator:evaluator,packages:packages,packageOutcomes:packageOutcomes,reboots:reboots,executor:executor,ha:haRepository,now:now};boot,err:=runtime.CurrentBootIdentity(ctx,"local");if err!=nil{return nil,err};runtime.admissions,err=rebootcontrol.NewAdmissionGate(ctx,db,boot.BootID,now);if err!=nil{return nil,err};coordinator,err:=rebootcontrol.NewCoordinator(rebootcontrol.Dependencies{Repository:reboots,Maintenance:runtime,BootIdentity:runtime,Authorization:runtime,Listeners:runtime,Operations:runtime,SQLite:runtime,Markers:runtime,Dispatcher:runtime,Reconciler:runtime});if err!=nil{return nil,err};if err=runtime.recoverRebootAtStartup(ctx,coordinator);err!=nil{return nil,fmt.Errorf("recover controlled reboot at startup: %w",err)};return newRebootControlLinuxEdge(coordinator,reboots,packages,runtime,"local","panel-core-local",manager,now)
}

func(runtime *rebootControlLocalRuntime)ResolveRebootPlan(ctx context.Context,request rebootControlPlanRequest)(rebootcontrol.Plan,error){
	if runtime==nil||ctx==nil||request.Requirement.Validate()!=nil||request.Requirement.ID!=request.PackageOperation.ID||request.Requirement.Reason!=request.Reason||request.PackageOperation.CommitAuthorization.DecisionID!=request.ApprovalRef||request.PackageOperation.CommitAuthorization.ActorID!=request.IndependentApprover||request.IndependentApprover==request.Call.PrincipalID||request.PackageOperation.CommitAuthorization.Validate(packagemaint.AssurancePhishingResistant,request.RequestedAt)!=nil{return rebootcontrol.Plan{},rebootcontrol.ErrUnauthorized}
	occurrence,err:=runtime.windows.LoadOccurrence(ctx,request.MaintenanceOccurrenceID);if err!=nil{return rebootcontrol.Plan{},err};if occurrence.Scope.Kind!=maintenance.ScopeNode||occurrence.Scope.NodeID!="local"||!request.RequestedAt.Before(occurrence.EndsAt){return rebootcontrol.Plan{},rebootcontrol.ErrConflict}
	current,err:=runtime.CurrentBootIdentity(ctx,"local");if err!=nil{return rebootcontrol.Plan{},err};if current.BootID!=request.Requirement.SourceBoot.BootID||current.KernelRelease!=request.Requirement.SourceBoot.KernelRelease||current.KernelDigest!=request.Requirement.SourceBoot.KernelDigest{return rebootcontrol.Plan{},rebootcontrol.ErrStaleBoot}
	nextRelease,nextDigest,err:=runtime.nextKernel(request.Reason,current);if err!=nil{return rebootcontrol.Plan{},err};expires:=occurrence.EndsAt.UTC();approval:=request.PackageOperation.CommitAuthorization;if approval.ExpiresAt.Before(expires){expires=approval.ExpiresAt.UTC()};if !expires.After(request.RequestedAt)||!expires.After(occurrence.StartsAt){return rebootcontrol.Plan{},rebootcontrol.ErrUnauthorized}
	rollback:=rebootcontrol.RollbackCapability{Kind:rebootcontrol.RollbackNone};snapshot:=request.PackageOperation.Receipt.Snapshot;if snapshot.SnapshotID!=""&&snapshot.Digest!=""{rollback=rebootcontrol.RollbackCapability{Kind:rebootcontrol.RollbackSnapshot,Proven:true,Reference:snapshot.SnapshotID,EvidenceDigest:snapshot.Digest}}
	plan:=rebootcontrol.Plan{ID:request.PlanID,NodeID:"local",Reason:request.Reason,SourceBoot:request.Requirement.SourceBoot,Maintenance:rebootcontrol.MaintenanceBinding{OccurrenceID:occurrence.ID,OccurrenceDigest:occurrence.Digest,StartsAt:occurrence.StartsAt.UTC(),EndsAt:occurrence.EndsAt.UTC()},Packages:rebootcontrol.PackageState{InventoryDigest:request.PackagePlan.InventoryDigest,TransactionID:request.PackageOperation.ID,TransactionDigest:request.PackageOperation.Receipt.EvidenceDigest,RequirementDigest:request.Requirement.Digest},Kernel:rebootcontrol.KernelState{CurrentRelease:current.KernelRelease,CurrentDigest:current.KernelDigest,NextRelease:nextRelease,NextDigest:nextDigest},ExpectedBoot:rebootcontrol.ExpectedBoot{RequireBootIDChange:true,KernelRelease:nextRelease,KernelDigest:nextDigest,ReturnDeadline:rebootReturnDeadline(request.RequestedAt,occurrence.StartsAt,request.ExpectedReturn).UTC()},Rollback:rollback,Drain:rebootcontrol.DrainPolicy{Mode:request.DrainMode,ListenerGroups:[]string{"ha_scheduler","operations"},Timeout:5*time.Minute,RejectNewWork:true},Checkpoint:rebootcontrol.CheckpointPolicy{SQLiteDatabases:[]string{"control"},RequireOnlineBackup:true,OperationMode:rebootcontrol.CheckpointOrRecordResumable,MaximumOperations:10000,Timeout:10*time.Minute},RequestedAt:request.RequestedAt.UTC(),ExpiresAt:expires}
	scope,err:=rebootcontrol.PlanScopeDigest(plan);if err!=nil{return rebootcontrol.Plan{},err};proof:=rebootRuntimeDigest(request.Call.SessionID,request.Call.CredentialID,strconv.FormatUint(request.Call.AuthzEpoch,10),string(request.Call.Assurance),request.Call.CSRFBinding);plan.Authorization=rebootcontrol.Authorization{ID:"reboot_auth_"+proof[:48],Issuer:"panel-core",Subject:request.Call.PrincipalID,Assurance:rebootcontrol.AssuranceStepUp,ScopeDigest:scope,IssuedAt:request.RequestedAt.UTC(),ExpiresAt:expires,ProofDigest:proof};plan.Approval=rebootcontrol.Approval{ID:"reboot_approval_"+approval.Digest[:48],Reference:approval.DecisionID,Approver:approval.ActorID,Role:"package_maintenance_commit",PlanScopeDigest:scope,ApprovedAt:approval.GrantedAt.UTC(),ExpiresAt:approval.ExpiresAt.UTC(),ProofDigest:approval.Digest};return rebootcontrol.CanonicalPlan(plan)
}

func(runtime *rebootControlLocalRuntime)PreflightReboot(ctx context.Context,request rebootControlPreflightRequest)(rebootControlReadiness,error){probe,err:=runtime.ProbeRebootOccurrence(ctx,request.Plan.Maintenance,request.Plan.NodeID,request.RequestedAt);if err!=nil{return rebootControlReadiness{},err};if err=runtime.VerifyRebootApproval(ctx,request.Plan.Approval,request.Plan);err!=nil{return rebootControlReadiness{},err};safe,writerEvidence,err:=runtime.writerSafe(ctx,request.Plan.NodeID,request.RequestedAt);if err!=nil{return rebootControlReadiness{},err};blockers:=[]string{};if !probe.Active{blockers=append(blockers,"maintenance_inactive")};if !safe{blockers=append(blockers,"ha_writer_authority_active")};return rebootControlReadiness{PlanID:request.Plan.ID,PlanDigest:request.Plan.Digest,RebootFence:request.State.Fence,MaintenanceOccurrenceDigest:request.Plan.Maintenance.OccurrenceDigest,ApprovalDigest:request.Plan.Approval.Digest,WriterAuthorityDigest:writerEvidence,MaintenanceAdmissible:probe.Admissible,HAWriterSafe:safe,EvidenceDigest:rebootRuntimeDigest(probe.EvidenceDigest,request.Plan.Approval.Digest,writerEvidence),Blockers:blockers},nil}

func(runtime *rebootControlLocalRuntime)ReleaseBeforeArm(ctx context.Context,request rebootControlReleaseRequest)(rebootControlReleaseResult,error){if err:=runtime.releaseDrain(ctx,request.Plan.NodeID);err!=nil{return rebootControlReleaseResult{},err};remaining,err:=runtime.acceptedOperations(ctx,request.Plan.NodeID);if err!=nil{return rebootControlReleaseResult{},err};evidence:=rebootRuntimeDigest(request.Plan.Digest,strconv.FormatUint(request.State.Fence,10),strconv.FormatUint(remaining,10),"released");return rebootControlReleaseResult{PlanID:request.Plan.ID,RebootFence:request.State.Fence,DrainReleased:true,OperationsResumed:remaining==0,EvidenceDigest:evidence},nil}

func(runtime *rebootControlLocalRuntime)ReconcileAmbiguousReboot(ctx context.Context,request rebootControlAmbiguousRequest)(rebootControlAmbiguousResult,error){actual,err:=runtime.CurrentBootIdentity(ctx,request.Plan.NodeID);if err!=nil{return rebootControlAmbiguousResult{},err};if actual.BootID==request.Plan.SourceBoot.BootID||!rebootMatchesExpected(actual,request.Plan.ExpectedBoot){return rebootControlAmbiguousResult{},rebootcontrol.ErrStaleBoot};id:="rebootop_"+rebootRuntimeDigest("reconcile",request.Plan.ID,strconv.FormatUint(request.State.Fence,10))[:48];operation:=rebootcontrol.ReconcileOperation{ID:id,PlanID:request.Plan.ID,PlanDigest:request.Plan.Digest,NodeID:request.Plan.NodeID,Fence:request.State.Fence,ActualBootID:actual.BootID,KernelRelease:actual.KernelRelease,KernelDigest:actual.KernelDigest,BootEvidenceDigest:actual.EvidenceDigest,OperationDigest:rebootRuntimeDigest(id,actual.EvidenceDigest)};result,err:=runtime.ReconcileAfterBoot(ctx,operation);if err!=nil||!result.Complete(){if err==nil{err=rebootcontrol.ErrIntegrity};return rebootControlAmbiguousResult{},err};clear,err:=runtime.ClearExact(ctx,request.Plan.NodeID,request.State.MarkerDigest);if err!=nil{return rebootControlAmbiguousResult{},err};safe,writer,err:=runtime.writerSafe(ctx,request.Plan.NodeID,request.RequestedAt);if err!=nil||!safe{if err==nil{err=rebootcontrol.ErrConflict};return rebootControlAmbiguousResult{},err};return rebootControlAmbiguousResult{PlanID:request.Plan.ID,RebootFence:request.State.Fence,MarkerDigest:request.State.MarkerDigest,ActualBoot:actual,SubsystemsReconciled:true,MarkerCleared:clear.Cleared,WriterAuthorityDigest:writer,EvidenceDigest:rebootRuntimeDigest(result.EvidenceDigest,clear.EvidenceDigest,writer)},nil}

func(runtime *rebootControlLocalRuntime)ProbeRebootOccurrence(ctx context.Context,binding rebootcontrol.MaintenanceBinding,node string,at time.Time)(rebootcontrol.MaintenanceProbe,error){occurrence,err:=runtime.windows.LoadOccurrence(ctx,binding.OccurrenceID);if err!=nil{return rebootcontrol.MaintenanceProbe{},err};if occurrence.Digest!=binding.OccurrenceDigest||occurrence.StartsAt.UTC()!=binding.StartsAt||occurrence.EndsAt.UTC()!=binding.EndsAt||occurrence.Scope.Kind!=maintenance.ScopeNode||occurrence.Scope.NodeID!=node{return rebootcontrol.MaintenanceProbe{},rebootcontrol.ErrIntegrity};decision,err:=runtime.evaluator.Admit(ctx,maintenance.AdmissionRequest{ID:"reboot_gate_"+rebootRuntimeDigest(binding.OccurrenceID,at.UTC().Format(time.RFC3339Nano))[:48],Target:maintenance.Target{TenantID:occurrence.Scope.TenantID,NodeID:node},OperationClass:maintenance.OperationDisruptive,ExpectedDuration:time.Second,At:at.UTC()});if err!=nil{return rebootcontrol.MaintenanceProbe{},err};allowed:=decision.Kind==maintenance.DecisionAllow&&decision.OccurrenceID==occurrence.ID;return rebootcontrol.MaintenanceProbe{OccurrenceID:occurrence.ID,OccurrenceDigest:occurrence.Digest,Admissible:allowed,Active:allowed&&decision.Phase==maintenance.PhaseActive,EndsAt:occurrence.EndsAt.UTC(),EvidenceDigest:rebootRuntimeDigest(occurrence.Digest,decision.EvidenceDigest)},nil}

func(runtime *rebootControlLocalRuntime)CurrentBootIdentity(ctx context.Context,node string)(rebootcontrol.BootIdentity,error){if ctx==nil||node!="local"{return rebootcontrol.BootIdentity{},rebootcontrol.ErrInvalid};boot,err:=os.ReadFile("/proc/sys/kernel/random/boot_id");if err!=nil{return rebootcontrol.BootIdentity{},err};kernel,err:=os.ReadFile("/proc/sys/kernel/osrelease");if err!=nil{return rebootcontrol.BootIdentity{},err};at:=runtime.now().UTC();identity:=rebootcontrol.BootIdentity{BootID:rebootRuntimeID(string(boot)),KernelRelease:rebootRuntimeID(string(kernel)),ObservedAt:at};identity.KernelDigest=rebootRuntimeDigest("kernel_release",identity.KernelRelease);identity.EvidenceDigest=rebootRuntimeDigest(identity.BootID,identity.KernelRelease,identity.KernelDigest,at.Format(time.RFC3339Nano));if identity.Validate()!=nil{return rebootcontrol.BootIdentity{},rebootcontrol.ErrIntegrity};return identity,nil}

func(runtime *rebootControlLocalRuntime)VerifyRebootAuthorization(_ context.Context,value rebootcontrol.Authorization,plan rebootcontrol.Plan)error{if plan.Validate()!=nil||value!=plan.Authorization||value.Issuer!="panel-core"||value.Subject==plan.Approval.Approver||!runtime.now().UTC().Before(value.ExpiresAt){return rebootcontrol.ErrUnauthorized};return nil}
func(runtime *rebootControlLocalRuntime)VerifyRebootApproval(ctx context.Context,value rebootcontrol.Approval,plan rebootcontrol.Plan)error{if plan.Validate()!=nil||value!=plan.Approval||!runtime.now().UTC().Before(value.ExpiresAt){return rebootcontrol.ErrUnauthorized};operation,err:=runtime.packages.Operation(ctx,plan.Packages.TransactionID);if err!=nil{return err};source:=operation.CommitAuthorization;if source.DecisionID!=value.Reference||source.ActorID!=value.Approver||source.Digest!=value.ProofDigest||source.Validate(packagemaint.AssurancePhishingResistant,runtime.now().UTC())!=nil{return rebootcontrol.ErrUnauthorized};return nil}

func(runtime *rebootControlLocalRuntime)DrainListeners(ctx context.Context,operation rebootcontrol.DrainOperation)(rebootcontrol.DrainResult,error){
	if operation.NodeID!="local"||operation.OperationDigest==""||runtime.admissions==nil{return rebootcontrol.DrainResult{},rebootcontrol.ErrInvalid}
	if _,err:=runtime.admissions.Close(ctx,operation.PlanID,operation.Fence);err!=nil{return rebootcontrol.DrainResult{},err}
	safe,writer,err:=runtime.writerSafe(ctx,operation.NodeID,runtime.now().UTC());if err!=nil||!safe{if err==nil{err=rebootcontrol.ErrConflict};return rebootcontrol.DrainResult{},err}
	node,err:=runtime.ha.LoadNode(ctx,ha.NodeID(operation.NodeID))
	if err==nil&&node.State!=ha.NodeDraining{if node.State!=ha.NodeReady{return rebootcontrol.DrainResult{},rebootcontrol.ErrConflict};_,err=(ha.GroupService{Store:runtime.ha,Now:runtime.now}).BeginDrain(ctx,node.ID,node.Generation,operation.Deadline,false)}else if errors.Is(err,ha.ErrNotFound){err=nil}
	if err!=nil{return rebootcontrol.DrainResult{},err}
	snapshot,err:=runtime.admissions.Wait(ctx,operation.PlanID,operation.Fence,operation.Deadline,10000)
	result:=rebootcontrol.DrainResult{OperationID:operation.ID,Fence:operation.Fence,Complete:err==nil&&len(snapshot.Blockers)==0,RemainingWork:uint64(len(snapshot.Blockers)),EvidenceDigest:rebootRuntimeDigest(operation.OperationDigest,writer,snapshot.Digest)}
	return result,err
}
func(runtime *rebootControlLocalRuntime)CheckpointOrRecordResumable(ctx context.Context,operation rebootcontrol.OperationCheckpoint)(rebootcontrol.OperationCheckpointResult,error){
	if operation.NodeID!="local"||runtime.admissions==nil{return rebootcontrol.OperationCheckpointResult{},rebootcontrol.ErrInvalid}
	snapshot,err:=runtime.admissions.SealCheckpoint(ctx,operation.PlanID,operation.Fence,operation.MaximumOperations);if err!=nil{return rebootcontrol.OperationCheckpointResult{},err}
	// Exact IDs are durable checkpoints, not invented resumability evidence.
	return rebootcontrol.OperationCheckpointResult{OperationID:operation.ID,Fence:operation.Fence,Complete:len(snapshot.Blockers)==0,NonResumable:uint32(len(snapshot.Blockers)),EvidenceDigest:rebootRuntimeDigest(operation.OperationDigest,snapshot.Digest)},nil
}

func(runtime *rebootControlLocalRuntime)CheckpointSQLite(ctx context.Context,operation rebootcontrol.SQLiteOperation)(rebootcontrol.SQLiteResult,error){if operation.DatabaseID!="control"{return rebootcontrol.SQLiteResult{},rebootcontrol.ErrInvalid};var busy,logged,checkpointed int;if err:=runtime.db.QueryRowContext(ctx,"PRAGMA wal_checkpoint(FULL)").Scan(&busy,&logged,&checkpointed);err!=nil{return rebootcontrol.SQLiteResult{},err};complete:=busy==0;artifact:=rebootRuntimeDigest(operation.OperationDigest,strconv.Itoa(logged),strconv.Itoa(checkpointed));return rebootcontrol.SQLiteResult{OperationID:operation.ID,Fence:operation.Fence,DatabaseID:operation.DatabaseID,Complete:complete,ArtifactDigest:artifact,EvidenceDigest:rebootRuntimeDigest(artifact,strconv.Itoa(busy))},nil}
func(runtime *rebootControlLocalRuntime)OnlineBackupSQLite(ctx context.Context,operation rebootcontrol.SQLiteOperation)(rebootcontrol.SQLiteResult,error){if operation.DatabaseID!="control"{return rebootcontrol.SQLiteResult{},rebootcontrol.ErrInvalid};directory:="/var/lib/cyberpanel/control/reboot-backups";if err:=ensureRebootDirectory(directory);err!=nil{return rebootcontrol.SQLiteResult{},err};path:=filepath.Join(directory,operation.PlanID+".db");if _,err:=os.Lstat(path);errors.Is(err,os.ErrNotExist){if _,err=runtime.db.ExecContext(ctx,"VACUUM INTO ?",path);err!=nil{return rebootcontrol.SQLiteResult{},err};if err=os.Chmod(path,0600);err!=nil{return rebootcontrol.SQLiteResult{},err}}else if err!=nil{return rebootcontrol.SQLiteResult{},err};artifact,err:=rebootFileDigest(path);if err!=nil{return rebootcontrol.SQLiteResult{},err};return rebootcontrol.SQLiteResult{OperationID:operation.ID,Fence:operation.Fence,DatabaseID:operation.DatabaseID,Complete:true,ArtifactDigest:artifact,EvidenceDigest:rebootRuntimeDigest(operation.OperationDigest,artifact)},nil}

func(runtime *rebootControlLocalRuntime)AtomicArm(ctx context.Context,marker rebootcontrol.RecoveryMarker)(rebootcontrol.MarkerArmResult,error){
	request,err:=operations.NewRebootMarkerArmRequest(marker);if err!=nil{return rebootcontrol.MarkerArmResult{},err}
	receipt,err:=runtime.executeMarkerEffect(ctx,request);if err!=nil{return rebootcontrol.MarkerArmResult{Partial:true},err}
	result:=receipt.Result.RebootMarker
	return rebootcontrol.MarkerArmResult{Committed:result.Committed,ExactDigest:result.ExactDigest,EvidenceDigest:receipt.ProofDigest},nil
}
func(runtime *rebootControlLocalRuntime)Probe(ctx context.Context,node string)(rebootcontrol.MarkerProbe,error){
	request,err:=operations.NewRebootMarkerProbeRequest(node);if err!=nil{return rebootcontrol.MarkerProbe{},err}
	receipt,err:=runtime.executeMarkerEffect(ctx,request);if err!=nil{return rebootcontrol.MarkerProbe{Partial:true},err}
	result:=receipt.Result.RebootMarker
	return rebootcontrol.MarkerProbe{Present:result.Present,ExactDigest:result.ExactDigest,EvidenceDigest:receipt.ProofDigest},nil
}
func(runtime *rebootControlLocalRuntime)ClearExact(ctx context.Context,node,digest string)(rebootcontrol.MarkerClearResult,error){
	request,err:=operations.NewRebootMarkerClearRequest(node,digest);if err!=nil{return rebootcontrol.MarkerClearResult{},err}
	receipt,err:=runtime.executeMarkerEffect(ctx,request);if err!=nil{return rebootcontrol.MarkerClearResult{},err}
	if err=runtime.releaseDrain(ctx,node);err!=nil{return rebootcontrol.MarkerClearResult{},err}
	result:=receipt.Result.RebootMarker
	return rebootcontrol.MarkerClearResult{Cleared:result.Cleared,ExactDigest:result.ExactDigest,EvidenceDigest:receipt.ProofDigest},nil
}

func(runtime *rebootControlLocalRuntime)executeMarkerEffect(ctx context.Context,request operations.EffectRequest)(operations.EffectReceipt,error){
	if runtime==nil||runtime.executor==nil||ctx==nil{return operations.EffectReceipt{},rebootcontrol.ErrInvalid}
	receipt,err:=runtime.executor.ObserveOrApply(ctx,request)
	if err!=nil{return receipt,fmt.Errorf("%w: privileged marker operation: %v",rebootcontrol.ErrPartialArm,err)}
	if operations.ValidateRebootMarkerReceipt(request,receipt)!=nil{return receipt,rebootcontrol.ErrIntegrity}
	return receipt,nil
}

func(runtime *rebootControlLocalRuntime)loadRecoveryMarker(ctx context.Context,node string)(rebootcontrol.RecoveryMarker,bool,error){
	request,err:=operations.NewRebootMarkerProbeRequest(node);if err!=nil{return rebootcontrol.RecoveryMarker{},false,err}
	receipt,err:=runtime.executeMarkerEffect(ctx,request);if err!=nil{return rebootcontrol.RecoveryMarker{},false,err}
	result:=receipt.Result.RebootMarker
	if !result.Present{return rebootcontrol.RecoveryMarker{},false,nil}
	return *result.Marker,true,nil
}

func(runtime *rebootControlLocalRuntime)recoverRebootAtStartup(ctx context.Context,coordinator *rebootcontrol.Coordinator)error{
	if runtime==nil||ctx==nil||coordinator==nil{return rebootcontrol.ErrInvalid}
	marker,present,err:=runtime.loadRecoveryMarker(ctx,"local");if err!=nil||!present{return err}
	plan,err:=runtime.reboots.LoadPlan(ctx,marker.PlanID);if err!=nil{return err}
	state,err:=runtime.reboots.LoadState(ctx,marker.PlanID);if err!=nil{return err}
	if err=marker.ValidateBinding(plan,state);err!=nil{return err}
	// Uncertain is a durable operator-recovery state, never an automatic retry.
	if state.Phase==rebootcontrol.PhaseUncertain{return nil}
	actual,err:=runtime.CurrentBootIdentity(ctx,marker.NodeID);if err!=nil{return err}
	if actual.BootID==marker.SourceBootID{return nil}
	switch state.Phase{
	case rebootcontrol.PhaseRebootDispatched:
		state,_,err=coordinator.BeginReconcile(ctx,runtime.startupReconcileCommand(state,marker,"reconcile:begin"));if err!=nil{return err}
	case rebootcontrol.PhaseReconciling:
	default:return rebootcontrol.ErrIntegrity
	}
	_,_,err=coordinator.CompleteReconcile(ctx,runtime.startupReconcileCommand(state,marker,"reconcile:complete"))
	return err
}

func(runtime *rebootControlLocalRuntime)startupReconcileCommand(state rebootcontrol.State,marker rebootcontrol.RecoveryMarker,step string)rebootcontrol.StepCommand{at:=runtime.now().UTC();if at.Before(state.UpdatedAt){at=state.UpdatedAt};seed:=rebootRuntimeDigest("startup_reconcile",marker.Digest,state.ControllerID,strconv.FormatUint(state.Fence,10),strconv.FormatUint(state.Generation,10));return rebootcontrol.StepCommand{PlanID:state.PlanID,ExpectedGeneration:state.Generation,Fence:state.Fence,ControllerID:state.ControllerID,IdempotencyKey:rebootControlStepKey(seed,step),At:at}}

func(runtime *rebootControlLocalRuntime)DispatchReboot(ctx context.Context,operation rebootcontrol.RebootOperation)(rebootcontrol.RebootDispatchResult,error){safe,writer,err:=runtime.writerSafe(ctx,operation.NodeID,runtime.now().UTC());if err!=nil||!safe{if err==nil{err=rebootcontrol.ErrConflict};return rebootcontrol.RebootDispatchResult{},err};node,err:=operations.NewResourceID(operation.NodeID);if err!=nil{return rebootcontrol.RebootDispatchResult{},err};plan,err:=operations.NewResourceID(operation.PlanID);if err!=nil{return rebootcontrol.RebootDispatchResult{},err};boot,err:=operations.NewResourceID(operation.SourceBootID);if err!=nil{return rebootcontrol.RebootDispatchResult{},err};stored,err:=runtime.reboots.LoadPlan(ctx,operation.PlanID);if err!=nil{return rebootcontrol.RebootDispatchResult{},err};request,err:=operations.NewControlledRebootRequest(node,operations.ControlledRebootEffect{PlanID:plan,PlanDigest:operation.PlanDigest,ApprovalReference:stored.Approval.Reference,ApprovalDigest:stored.Approval.Digest,MarkerDigest:operation.MarkerDigest,WriterAuthorityDigest:writer,SourceBootID:boot,Fence:operation.Fence,DispatchBy:operation.DispatchBy.UTC(),OperationDigest:operation.OperationDigest});if err!=nil{return rebootcontrol.RebootDispatchResult{},err};receipt,err:=runtime.executor.ObserveOrApply(ctx,request);if err!=nil{return rebootcontrol.RebootDispatchResult{},err};return rebootcontrol.RebootDispatchResult{OperationID:operation.ID,Fence:operation.Fence,Accepted:receipt.Outcome==operations.EffectConfirmed,EvidenceDigest:receipt.ProofDigest},nil}

func(runtime *rebootControlLocalRuntime)ReconcileAfterBoot(ctx context.Context,operation rebootcontrol.ReconcileOperation)(rebootcontrol.ReconcileResult,error){
	remaining,err:=runtime.acceptedOperations(ctx,operation.NodeID);if err!=nil||remaining!=0{if err==nil{err=rebootcontrol.ErrConflict};return rebootcontrol.ReconcileResult{},err}
	safe,writer,err:=runtime.writerSafe(ctx,operation.NodeID,runtime.now().UTC());if err!=nil||!safe{if err==nil{err=rebootcontrol.ErrConflict};return rebootcontrol.ReconcileResult{},err}
	var integrity string;if err=runtime.db.QueryRowContext(ctx,"PRAGMA integrity_check(1)").Scan(&integrity);err!=nil||integrity!="ok"{if err==nil{err=rebootcontrol.ErrIntegrity};return rebootcontrol.ReconcileResult{},err}
	plan,err:=runtime.reboots.LoadPlan(ctx,operation.PlanID);if err!=nil{return rebootcontrol.ReconcileResult{},err}
	occurrence,err:=runtime.windows.LoadOccurrence(ctx,plan.Maintenance.OccurrenceID);if err!=nil||occurrence.Digest!=plan.Maintenance.OccurrenceDigest{if err==nil{err=rebootcontrol.ErrIntegrity};return rebootcontrol.ReconcileResult{},err}
	operationEvidence,err:=runtime.admissions.Reconcile(ctx,operation.PlanID,operation.Fence);if err!=nil{return rebootcontrol.ReconcileResult{},err}
	services,err:=runtime.qualifyRebootServices(ctx,operation);if err!=nil{return rebootcontrol.ReconcileResult{},err}
	if runtime.packageOutcomes==nil{return rebootcontrol.ReconcileResult{},rebootcontrol.ErrUnproven}
	packageOperation,err:=runtime.packages.Operation(ctx,plan.Packages.TransactionID);if err!=nil{return rebootcontrol.ReconcileResult{},err}
	if packageOperation.Receipt.EvidenceDigest!=plan.Packages.TransactionDigest{return rebootcontrol.ReconcileResult{},rebootcontrol.ErrIntegrity}
	packageInventory,err:=runtime.packageOutcomes.persistPostRebootPackageOutcome(ctx,packageOperation);if err!=nil{return rebootcontrol.ReconcileResult{},err}
	actual:=rebootcontrol.BootIdentity{BootID:operation.ActualBootID,KernelRelease:operation.KernelRelease,KernelDigest:operation.KernelDigest,BootSlot:operation.BootSlot,ObservedAt:runtime.now().UTC(),EvidenceDigest:operation.BootEvidenceDigest}
	if err=runtime.reboots.ClearRequirement(ctx,plan.Packages.TransactionID,actual);err!=nil&&!errors.Is(err,rebootcontrol.ErrNotFound){return rebootcontrol.ReconcileResult{},err}
	configuration:=rebootRuntimeDigest(operation.OperationDigest,integrity)
	locks:=rebootRuntimeDigest(operation.OperationDigest,writer,operationEvidence)
	schedules:=rebootRuntimeDigest(operation.OperationDigest,occurrence.Digest,plan.Packages.TransactionID,packageInventory.ContentDigest,strconv.FormatUint(packageInventory.Generation,10),"cleared")
	result:=rebootcontrol.ReconcileResult{OperationID:operation.ID,Fence:operation.Fence,Services:rebootcontrol.ComponentResult{Complete:true,EvidenceDigest:services},Configuration:rebootcontrol.ComponentResult{Complete:true,EvidenceDigest:configuration},Locks:rebootcontrol.ComponentResult{Complete:true,EvidenceDigest:locks},Schedules:rebootcontrol.ComponentResult{Complete:true,EvidenceDigest:schedules}}
	result.EvidenceDigest=rebootRuntimeDigest(services,configuration,locks,schedules);return result,nil
}

func(runtime *rebootControlLocalRuntime)acceptedOperations(ctx context.Context,node string)(uint64,error){var count uint64;err:=runtime.db.QueryRowContext(ctx,`SELECT COUNT(*) FROM panel_operation_receipts WHERE node_id=? AND status='accepted'`,node).Scan(&count);return count,err}
func(runtime *rebootControlLocalRuntime)writerSafe(ctx context.Context,node string,at time.Time)(bool,string,error){var leases,authorities uint64;if err:=runtime.db.QueryRowContext(ctx,`SELECT COUNT(*) FROM ha_writer_leases WHERE holder_node_id=? AND state='active' AND expires_at>?`,node,at.UTC()).Scan(&leases);err!=nil{return false,"",err};if err:=runtime.db.QueryRowContext(ctx,`SELECT COUNT(*) FROM ha_local_workload_authority WHERE writer_node_id=?`,node).Scan(&authorities);err!=nil{return false,"",err};evidence:=rebootRuntimeDigest(node,strconv.FormatUint(leases,10),strconv.FormatUint(authorities,10),at.UTC().Format(time.RFC3339Nano));return leases==0&&authorities==0,evidence,nil}
func(runtime *rebootControlLocalRuntime)releaseDrain(ctx context.Context,nodeID string)error{
	if runtime.admissions==nil{return rebootcontrol.ErrUnproven}
	if err:=runtime.admissions.Open(ctx);err!=nil{return err}
	node,err:=runtime.ha.LoadNode(ctx,ha.NodeID(nodeID));if errors.Is(err,ha.ErrNotFound){return nil};if err!=nil{return err};if node.State==ha.NodeReady{return nil};if node.State!=ha.NodeDraining{return rebootcontrol.ErrConflict};_,err=(ha.GroupService{Store:runtime.ha,Now:runtime.now}).SetNodeState(ctx,node.ID,node.Generation,ha.NodeReady);return err
}
func(runtime *rebootControlLocalRuntime)nextKernel(reason rebootcontrol.PlanReason,current rebootcontrol.BootIdentity)(string,string,error){if reason!=rebootcontrol.ReasonKernelUpdate{return current.KernelRelease,current.KernelDigest,nil};for _,link:=range []string{"/boot/vmlinuz","/vmlinuz"}{target,err:=os.Readlink(link);if err!=nil{continue};next:=rebootRuntimeID(strings.TrimPrefix(filepath.Base(target),"vmlinuz-"));if next!=""&&next!=current.KernelRelease{return next,rebootRuntimeDigest("kernel_release",next),nil}};return "","",rebootcontrol.ErrUnproven}

func rebootRuntimeDigest(parts ...string)string{hash:=sha256.New();for _,part:=range parts{_,_=hash.Write([]byte(part));_,_=hash.Write([]byte{0})};return hex.EncodeToString(hash.Sum(nil))}
func rebootRuntimeID(value string)string{value=strings.TrimSpace(value);var result strings.Builder;for _,character:=range value{if character>='a'&&character<='z'||character>='A'&&character<='Z'||character>='0'&&character<='9'||character=='-'||character=='_'||character=='.'||character==':'{result.WriteRune(character)}else{result.WriteByte('_')}};normalized:=result.String();if normalized==""||normalized[0]<'0'||normalized[0]>'9'&&normalized[0]<'A'||normalized[0]>'Z'&&normalized[0]<'a'||normalized[0]>'z'{normalized="id_"+normalized};if len(normalized)>128{normalized=normalized[:128]};return normalized}
func ensureRebootDirectory(path string)error{if err:=os.MkdirAll(path,0700);err!=nil{return err};info,err:=os.Lstat(path);if err!=nil{return err};stat,owned:=info.Sys().(*syscall.Stat_t);if !owned||int(stat.Uid)!=os.Geteuid()||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0077!=0{return rebootcontrol.ErrIntegrity};return nil}
func rebootFileDigest(path string)(string,error){info,err:=os.Lstat(path);if err!=nil{return "",err};stat,owned:=info.Sys().(*syscall.Stat_t);if !owned||int(stat.Uid)!=os.Geteuid()||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0022!=0{return "",rebootcontrol.ErrIntegrity};file,err:=os.Open(path);if err!=nil{return "",err};defer file.Close();hash:=sha256.New();if _,err=io.Copy(hash,file);err!=nil{return "",err};return hex.EncodeToString(hash.Sum(nil)),nil}

var _ rebootControlLinuxAuthority=(*rebootControlLocalRuntime)(nil)
var _ rebootcontrol.MaintenanceGate=(*rebootControlLocalRuntime)(nil)
var _ rebootcontrol.RebootDispatcher=(*rebootControlLocalRuntime)(nil)

func(runtime *rebootControlLocalRuntime)AdmitMutation(ctx context.Context,operation,requestID,digest string)(func(bool)error,error){
	if runtime==nil||runtime.admissions==nil{return nil,rebootcontrol.ErrUnproven}
	return runtime.admissions.AdmitMutation(ctx,operation,requestID,digest)
}

func(runtime *rebootControlLocalRuntime)qualifyRebootServices(ctx context.Context,operation rebootcontrol.ReconcileOperation)(string,error){
	registry,store,err:=newCachedServiceRegistry(ctx,runtime.db)
	if err!=nil{return "",err};if registry==nil||store==nil{return "",rebootcontrol.ErrUnproven}
	at:=runtime.now().UTC()
	qualification:=operations.RebootServiceQualification{BootID:operation.ActualBootID}
	desiredDigests:=map[serviceregistry.ServiceID]string{}
	// Use the existing registry as the configured-service authority. Optional
	// services absent from desired state, or explicitly uninstalled, do not block.
	for _,id:=range []serviceregistry.ServiceID{serviceregistry.ServiceOpenLiteSpeed,serviceregistry.ServiceLiteSpeed,serviceregistry.ServiceMariaDB,serviceregistry.ServicePostfix,serviceregistry.ServiceDovecot,serviceregistry.ServicePowerDNS,serviceregistry.ServiceRspamd,serviceregistry.ServiceClamAV,serviceregistry.ServiceRedis}{
		if _,known:=registry.Definition(id);!known{return "",rebootcontrol.ErrIntegrity}
		desired,loadErr:=store.Desired(ctx,operation.NodeID,id)
		if errors.Is(loadErr,serviceregistry.ErrNotFound){desiredDigests[id]="";continue}
		if loadErr!=nil{return "",loadErr}
		if desired.NodeID!=operation.NodeID||desired.ServiceID!=id{return "",rebootcontrol.ErrIntegrity}
		desiredDigests[id]=desired.Digest
		if !desired.Installed{continue}
		if desired.Active!=serviceregistry.ActiveActive{return "",fmt.Errorf("%w: configured service %s is not desired active",rebootcontrol.ErrUnproven,id)}
		observed,loadErr:=store.Observed(ctx,operation.NodeID,id);if loadErr!=nil{return "",fmt.Errorf("%w: service %s health: %v",rebootcontrol.ErrUnproven,id,loadErr)}
		if observed.NodeID!=operation.NodeID||observed.ServiceID!=id||observed.Install!=serviceregistry.InstallInstalled||observed.Active!=serviceregistry.ActiveActive||observed.Config!=serviceregistry.ConfigValid||observed.Health!=serviceregistry.HealthHealthy||observed.Drift!=serviceregistry.DriftNone||!observed.DependenciesReady||!observed.ExpectedListenersOwned||!observed.InternallyHealthy||!observed.ExternallyFunctional||!observed.DesiredGenerationObserved||observed.ConfigGeneration!=desired.ConfigGeneration||observed.Process.BootID!=operation.ActualBootID||observed.Process.MainPID<=0||observed.Process.MainPID>1<<32-1||observed.ObservedAt.Before(desired.UpdatedAt)||observed.ObservedAt.After(at)||at.Sub(observed.ObservedAt)>2*time.Minute{return "",fmt.Errorf("%w: service %s lacks fresh same-boot health",rebootcontrol.ErrUnproven,id)}
		qualification.Required=append(qualification.Required,operations.RebootServiceBinding{Service:operations.ServiceName(id),MainPID:uint32(observed.Process.MainPID),InvocationID:observed.Process.InvocationID,HealthEvidenceDigest:observed.EvidenceDigest,ObservedAt:observed.ObservedAt})
	}
	node,err:=operations.NewResourceID(operation.NodeID);if err!=nil{return "",err}
	plan,err:=operations.NewResourceID(operation.PlanID);if err!=nil{return "",err}
	request,err:=operations.NewControlledRebootServicesProbeRequest(node,plan,at,qualification);if err!=nil{return "",err}
	receipt,err:=runtime.executor.ObserveOrApply(ctx,request);if err!=nil{return "",fmt.Errorf("%w: required reboot services: %v",rebootcontrol.ErrUnproven,err)}
	if operations.ValidateControlledRebootServicesReceipt(request,receipt,runtime.now().UTC())!=nil{return "",rebootcontrol.ErrIntegrity}
	// A desired-state change during the probes invalidates the qualification,
	// including an optional service becoming configured while others are checked.
	for id,digest:=range desiredDigests{
		latest,loadErr:=store.Desired(ctx,operation.NodeID,id)
		if errors.Is(loadErr,serviceregistry.ErrNotFound)&&digest==""{continue}
		if loadErr!=nil||latest.Digest!=digest{return "",rebootcontrol.ErrConflict}
	}
	return rebootRuntimeDigest(operation.OperationDigest,registry.Digest(),receipt.ProofDigest),nil
}
