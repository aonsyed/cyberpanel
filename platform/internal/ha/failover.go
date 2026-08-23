package ha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type PromotionRequest struct {
	Promotion Promotion `json:"promotion"`
	RunID FailoverRunID `json:"run_id"`
	RequiredWritePaths []string `json:"required_write_paths"`
	FencePlans []Fence `json:"fence_plans"`
	Lease WriterLease `json:"lease"`
	DatabaseClusterID ID `json:"database_cluster_id,omitempty"`
	SoakDuration time.Duration `json:"soak_duration"`
	OldWriterRetention time.Duration `json:"old_writer_retention"`
}

func (request PromotionRequest) Validate(now time.Time) error {
	promotion:=request.Promotion
	for kind,value:=range map[string]string{"promotion":string(promotion.ID),"command":string(promotion.CommandID),"group":string(promotion.GroupID),"previous writer":string(promotion.PreviousWriter),"candidate":string(promotion.Candidate),"checkpoint":string(promotion.CheckpointID),"traffic policy":string(promotion.TrafficPolicyID),"run":string(request.RunID)}{if err:=requireID(kind,value);err!=nil{return err}}
	if promotion.PreviousWriter==promotion.Candidate||promotion.ResourceID==""||promotion.ExpectedGeneration==0||promotion.CheckpointFrontier==0||promotion.Generation==0||promotion.CreatedAt.IsZero()||promotion.UpdatedAt.IsZero()||len(request.RequiredWritePaths)==0||len(request.FencePlans)==0||request.SoakDuration<0||request.OldWriterRetention<=0{return ErrInvalid}
	if request.Lease.GroupID!=promotion.GroupID||request.Lease.ResourceID!=promotion.ResourceID||request.Lease.HolderNodeID!=promotion.Candidate||request.Lease.State!=LeasePending||!now.Before(request.Lease.ExpiresAt){return ErrLeaseLost}
	if err:=request.Lease.Validate(now);err!=nil{return err}
	if promotion.PotentialDataLoss { valid:=false;for _,approval:=range promotion.Approvals{if approval.Kind=="potential_data_loss"&&approval.PlanDigest!=""&&now.Before(approval.ExpiresAt)&&approval.Signature!=""{valid=true}};if !valid{return ErrDataLossApproval} }
	if promotion.Automatic&&request.Lease.ID==""&&len(request.FencePlans)==0{return ErrFenceRequired}
	fenceIDs:=map[FenceID]struct{}{}
	for _,fence:=range request.FencePlans{if fence.GroupID!=promotion.GroupID||fence.TargetNodeID!=promotion.PreviousWriter||fence.FencingToken!=request.Lease.FencingToken||fence.AuthorityEpoch!=request.Lease.AuthorityEpoch{return ErrFenceRequired};if _,exists:=fenceIDs[fence.ID];exists{return ErrConflict};fenceIDs[fence.ID]=struct{}{};if err:=fence.Validate(now);err!=nil{return err}}
	return nil
}

type FailoverCoordinator struct {
	Store Store
	Health HealthAuthority
	Leases LeaseAuthority
	Gate WriterGate
	FenceProviders map[FenceClass]FenceProvider
	ManualFence ManualFenceConfirmer
	Traffic TrafficProvider
	Executor PromotionExecutor
	Database DatabaseReplicationExecutor
	Backup BackupConsistency
	Now func() time.Time
}

func (coordinator FailoverCoordinator) now() time.Time { if coordinator.Now!=nil{return coordinator.Now().UTC()};return time.Now().UTC() }

func (coordinator FailoverCoordinator) Execute(ctx context.Context, request PromotionRequest) (Promotion,FailoverRun,error) {
	if err:=request.Validate(coordinator.now());err!=nil{return Promotion{},FailoverRun{},err};if coordinator.Store==nil||coordinator.Health==nil||coordinator.Leases==nil||coordinator.Gate==nil||coordinator.Traffic==nil||coordinator.Executor==nil||coordinator.Backup==nil{return Promotion{},FailoverRun{},ErrInvalid}
	promotion:=request.Promotion;planDigest,err:=promotionDigest(request);if err!=nil{return Promotion{},FailoverRun{},err};for _,approval:=range promotion.Approvals{if approval.PlanDigest!=planDigest{return Promotion{},FailoverRun{},ErrDataLossApproval}}
	if existing,loadErr:=coordinator.Store.LoadPromotion(ctx,promotion.ID);loadErr==nil{if existing.CommandID!=promotion.CommandID||existing.ResourceID!=promotion.ResourceID||existing.Candidate!=promotion.Candidate{return Promotion{},FailoverRun{},ErrConflict};run,runErr:=coordinator.Store.LoadFailoverRun(ctx,request.RunID);if runErr!=nil{return Promotion{},FailoverRun{},runErr};if run.PlanDigest!=planDigest{return Promotion{},FailoverRun{},ErrConflict};if existing.State==PromotionCommitted||existing.State==PromotionRolledBack||existing.State==PromotionFailForward||existing.State==PromotionFailed{return existing,run,nil};return Promotion{},FailoverRun{},ErrConflict}else if !errors.Is(loadErr,ErrNotFound){return Promotion{},FailoverRun{},loadErr}
	authority,err:=coordinator.promotionAuthority(ctx,promotion,coordinator.now());if err!=nil{return Promotion{},FailoverRun{},err}
	if request.Lease.AuthorityEpoch!=authority.AuthorityEpoch||request.Lease.FencingToken<=authority.FencingToken{return Promotion{},FailoverRun{},ErrFenceRequired}
	checkpoint,err:=coordinator.Store.LoadCheckpoint(ctx,promotion.CheckpointID);if err!=nil{return Promotion{},FailoverRun{},err};if checkpoint.WriteFrontier!=promotion.CheckpointFrontier||!checkpoint.Verified{return Promotion{},FailoverRun{},ErrCheckpointStale};if promotion.MaximumDataLoss==0&&checkpoint.LagDuration>0{return Promotion{},FailoverRun{},ErrUnsafePromotion};if checkpoint.LagDuration>promotion.MaximumDataLoss{return Promotion{},FailoverRun{},ErrCheckpointStale}
	backupCopy,err:=coordinator.Backup.VerifyIndependentBackupCopy(ctx,promotion.ResourceID,promotion.Candidate);if err!=nil{return Promotion{},FailoverRun{},err};if !validDigest(backupCopy.ManifestDigest)||backupCopy.CommitMarker==""{return Promotion{},FailoverRun{},ErrInvalid}
	quorum,err:=coordinator.Health.Quorum(ctx,promotion.GroupID);if err!=nil{return Promotion{},FailoverRun{},err};if err:=quorum.Validate(coordinator.now());err!=nil{return Promotion{},FailoverRun{},err}
	previousHealth,_:=coordinator.Health.ObserveNode(ctx,promotion.PreviousWriter);candidateHealth,err:=coordinator.Health.ObserveNode(ctx,promotion.Candidate);if err!=nil||candidateHealth.State!=HealthHealthy||!coordinator.now().Before(candidateHealth.ValidUntil){return Promotion{},FailoverRun{},ErrUnsafePromotion};if previousHealth.State==HealthHealthy&&promotion.Automatic{return Promotion{},FailoverRun{},ErrUnsafePromotion}
	trafficPolicy,err:=coordinator.Store.LoadTrafficPolicy(ctx,promotion.TrafficPolicyID);if err!=nil{return Promotion{},FailoverRun{},err};if promotion.Automatic&&trafficPolicy.ProviderMode!=TrafficAtomicCAS{return Promotion{},FailoverRun{},ErrUnsafePromotion}
	promotion.State, promotion.Generation, promotion.UpdatedAt=PromotionChecking,promotion.Generation+1,coordinator.now();if err:=coordinator.Store.CreatePromotion(ctx,promotion);err!=nil{return Promotion{},FailoverRun{},err}
	run:=FailoverRun{ID:request.RunID,PromotionID:promotion.ID,PlanDigest:planDigest,HealthQuorumDigest:quorum.Digest,State:PromotionChecking,Step:"preflight",Attempt:1,StartedAt:coordinator.now(),UpdatedAt:coordinator.now()};if err:=coordinator.Store.CreateFailoverRun(ctx,run);err!=nil{return Promotion{},FailoverRun{},err}
	fenceReceipts:=make([]FenceReceipt,0,len(request.FencePlans));promotion.State,run.State,run.Step=PromotionFencing,PromotionFencing,"fence_previous_writer";if err:=coordinator.advance(ctx,&promotion,&run);err!=nil{return promotion,run,err}
	for _,plan:=range request.FencePlans{receipt,err:=coordinator.applyFence(ctx,plan,quorum,promotion);if err!=nil{return coordinator.fail(ctx,promotion,run,"fence_previous_writer",err)};fenceReceipts=append(fenceReceipts,receipt)}
	if err:=validateFenceCoverage(fenceReceipts,request.RequiredWritePaths,coordinator.now());err!=nil{return coordinator.fail(ctx,promotion,run,"fence_coverage",err)}
	if err:=coordinator.validatePersistedFenceReceipts(ctx,request.FencePlans,fenceReceipts,coordinator.now());err!=nil{return coordinator.fail(ctx,promotion,run,"fence_receipt",err)}
	currentAuthority,err:=coordinator.promotionAuthority(ctx,promotion,coordinator.now());if err!=nil{return coordinator.fail(ctx,promotion,run,"authority",err)}
	if currentAuthority.ID!=authority.ID||currentAuthority.FencingToken!=authority.FencingToken||currentAuthority.AuthorityEpoch!=authority.AuthorityEpoch||!currentAuthority.ExpiresAt.Equal(authority.ExpiresAt){return coordinator.fail(ctx,promotion,run,"authority",ErrStaleGeneration)}
	promotion.FenceIDs=make([]FenceID,len(fenceReceipts));for index:=range fenceReceipts{promotion.FenceIDs[index]=fenceReceipts[index].FenceID}
	fenceDigest,err:=digestFenceReceipts(fenceReceipts);if err!=nil{return coordinator.fail(ctx,promotion,run,"fence_digest",err)};run.FenceProofDigest=fenceDigest;promotion.State,run.State,run.Step=PromotionFenced,PromotionFenced,"acquire_writer_lease";if err:=coordinator.advance(ctx,&promotion,&run);err!=nil{return promotion,run,err}
	lease:=request.Lease;lease.HolderNodeID=promotion.Candidate;lease.QuorumDigest=quorum.Digest;lease.State=LeaseActive;if err:=lease.Validate(coordinator.now());err!=nil{return coordinator.fail(ctx,promotion,run,"lease",err)};if err:=validateLeaseCoverage(lease,request.RequiredWritePaths);err!=nil{return coordinator.fail(ctx,promotion,run,"lease_coverage",err)};lease,err=coordinator.Leases.AcquireWriterLease(ctx,lease,quorum);if err!=nil{return coordinator.fail(ctx,promotion,run,"lease",err)};if lease.ID!=request.Lease.ID||lease.GroupID!=promotion.GroupID||lease.ResourceID!=promotion.ResourceID||lease.HolderNodeID!=promotion.Candidate||lease.FencingToken!=request.Lease.FencingToken||lease.AuthorityEpoch!=request.Lease.AuthorityEpoch||lease.State!=LeaseActive||lease.Validate(coordinator.now())!=nil{return coordinator.fail(ctx,promotion,run,"lease_receipt",ErrLeaseLost)};if err:=coordinator.Store.CreateLease(ctx,lease);err!=nil{return coordinator.fail(ctx,promotion,run,"persist_lease",err)};promotion.LeaseID=lease.ID
	permit,err:=coordinator.Gate.ActivateResourceWrites(ctx,lease);if err!=nil{return coordinator.fail(ctx,promotion,run,"activate_writer_gate",err)};if permit.ResourceID!=lease.ResourceID||permit.NodeID!=lease.HolderNodeID||permit.LeaseID!=lease.ID||permit.FencingToken!=lease.FencingToken||permit.AuthorityEpoch!=lease.AuthorityEpoch||permit.Signature==""||!coordinator.now().Before(permit.ExpiresAt){return coordinator.fail(ctx,promotion,run,"writer_permit",ErrLeaseLost)}
	if _,err:=coordinator.Executor.FreezeWorkloadWrites(ctx,promotion,lease.FencingToken);err!=nil{return coordinator.fail(ctx,promotion,run,"freeze_writes",err)}
	if request.DatabaseClusterID!="" { if coordinator.Database==nil{return coordinator.fail(ctx,promotion,run,"database",ErrInvalid)};cluster,loadErr:=coordinator.Store.LoadDatabaseCluster(ctx,request.DatabaseClusterID);if loadErr!=nil{return coordinator.fail(ctx,promotion,run,"database",loadErr)};if _,freezeErr:=coordinator.Database.FreezeDatabaseWrites(ctx,cluster,promotion.PreviousWriter,lease.FencingToken);freezeErr!=nil{return coordinator.fail(ctx,promotion,run,"freeze_database",freezeErr)};if _,frontier,promoteErr:=coordinator.Database.PromoteDatabaseWriter(ctx,cluster,promotion.Candidate,lease);promoteErr!=nil{return coordinator.fail(ctx,promotion,run,"promote_database",promoteErr)}else if frontier>promotion.WriteFrontier{promotion.WriteFrontier=frontier;promotion.Irreversible=true} }
	promotion.State,run.State,run.Step=PromotionPromoting,PromotionPromoting,"activate_candidate";if err:=coordinator.advance(ctx,&promotion,&run);err!=nil{return promotion,run,err};_,frontier,err:=coordinator.Executor.ActivateCandidateServices(ctx,promotion,lease);if err!=nil{return coordinator.fail(ctx,promotion,run,"activate_candidate",err)};if frontier>promotion.WriteFrontier{promotion.WriteFrontier=frontier};if promotion.WriteFrontier>checkpoint.WriteFrontier{promotion.Irreversible=true}
	if _,err:=coordinator.Executor.ProbeCandidate(ctx,promotion);err!=nil{return coordinator.rollbackOrForward(ctx,promotion,run,request,trafficPolicy,TrafficReceipt{},err)}
	before,err:=coordinator.Traffic.Observe(ctx,trafficPolicy);if err!=nil{return coordinator.rollbackOrForward(ctx,promotion,run,request,trafficPolicy,TrafficReceipt{},err)};run.TrafficBeforeDigest=before.Digest;desired:=buildTrafficDesired(trafficPolicy,before,promotion.Candidate,promotion.PreviousWriter);change:=TrafficChange{Policy:trafficPolicy,EffectID:string(promotion.ID)+":traffic",Before:before,Desired:desired}
	promotion.State,run.State,run.Step=PromotionRouting,PromotionRouting,"traffic_cutover";if err:=coordinator.advance(ctx,&promotion,&run);err!=nil{return promotion,run,err};var trafficReceipt TrafficReceipt;if trafficPolicy.ProviderMode==TrafficAtomicCAS{trafficReceipt,err=coordinator.Traffic.ApplyConditional(ctx,change)}else{trafficReceipt,err=coordinator.Traffic.ApplyObserve(ctx,change)};if err!=nil{return coordinator.rollbackOrForward(ctx,promotion,run,request,trafficPolicy,trafficReceipt,err)};if trafficReceipt.BeforeDigest!=before.Digest||trafficReceipt.OutputDigest!=desired.Digest||trafficReceipt.ProviderReceipt==""{return coordinator.rollbackOrForward(ctx,promotion,run,request,trafficPolicy,trafficReceipt,ErrProviderAmbiguous)};run.TrafficAfterDigest,run.ProviderRevision=trafficReceipt.OutputDigest,trafficReceipt.Revision
	promotion.State,run.State,run.Step=PromotionProbing,PromotionProbing,"external_probe";if err:=coordinator.advance(ctx,&promotion,&run);err!=nil{return promotion,run,err};if _,err:=coordinator.Executor.ProbeExternalTraffic(ctx,promotion,trafficReceipt);err!=nil{return coordinator.rollbackOrForward(ctx,promotion,run,request,trafficPolicy,trafficReceipt,err)}
	if _,err:=coordinator.Executor.DemotePreviousServices(ctx,promotion,lease.FencingToken);err!=nil{return coordinator.failForward(ctx,promotion,run,"demote_previous",err)};if err:=coordinator.Executor.KeepPreviousFenced(ctx,promotion,coordinator.now().Add(request.OldWriterRetention));err!=nil{return coordinator.failForward(ctx,promotion,run,"retain_fence",err)};if err:=coordinator.Backup.ProtectRecoveryEvidence(ctx,promotion.ResourceID,coordinator.now().Add(request.OldWriterRetention));err!=nil{return coordinator.failForward(ctx,promotion,run,"protect_evidence",err)}
	promotion.State,run.State,run.Step=PromotionSoaking,PromotionSoaking,"soak";if err:=coordinator.advance(ctx,&promotion,&run);err!=nil{return promotion,run,err};promotion.State,run.State,run.Step=PromotionCommitted,PromotionCommitted,"committed";run.CompletedAt=coordinator.now();if err:=coordinator.advance(ctx,&promotion,&run);err!=nil{return promotion,run,err};return promotion,run,nil
}

func (coordinator FailoverCoordinator) applyFence(ctx context.Context,plan Fence,quorum QuorumObservation,promotion Promotion)(FenceReceipt,error){
	if plan.State!=FencePlanned{return FenceReceipt{},ErrConflict}
	if err:=coordinator.Store.SaveFence(ctx,plan,0);err!=nil{return FenceReceipt{},err}
	request:=FenceRequest{Fence:plan,Quorum:quorum}
	var receipt FenceReceipt
	var err error
	if plan.Class==FenceAdministrative{
		if promotion.Automatic||coordinator.ManualFence==nil{return FenceReceipt{},ErrFenceRequired}
		receipt,err=coordinator.ManualFence.VerifyAdministrativeFence(ctx,plan,promotion.Approvals)
	}else{
		provider:=coordinator.FenceProviders[plan.Class]
		if provider==nil||provider.Class()!=plan.Class{return FenceReceipt{},ErrFenceRequired}
		receipt,err=provider.Fence(ctx,request)
		if err==nil{receipt,err=provider.Observe(ctx,request,receipt)}
	}
	if err!=nil{return FenceReceipt{},err}
	if err=validateFenceReceiptAgainstPlan(plan,receipt,coordinator.now());err!=nil{return FenceReceipt{},err}
	previous:=plan.Generation
	plan.State,plan.ProofDigest,plan.ProviderReceipt,plan.AppliedAt,plan.ValidUntil,plan.Generation=FenceProven,receipt.ProofDigest,receipt.ProviderReceipt,receipt.AppliedAt,receipt.ValidUntil,plan.Generation+1
	if err=coordinator.Store.SaveFence(ctx,plan,previous);err!=nil{return FenceReceipt{},err}
	return receipt,nil
}

func (coordinator FailoverCoordinator) promotionAuthority(ctx context.Context,promotion Promotion,now time.Time)(WriterLease,error){
	authority,err:=coordinator.Store.ActiveWriterLeaseByResource(ctx,promotion.ResourceID)
	if errors.Is(err,ErrNotFound){return WriterLease{},ErrLeaseLost}
	if err!=nil{return WriterLease{},err}
	if authority.Generation!=promotion.ExpectedGeneration{return WriterLease{},ErrStaleGeneration}
	if authority.GroupID!=promotion.GroupID||authority.ResourceID!=promotion.ResourceID||authority.HolderNodeID!=promotion.PreviousWriter{return WriterLease{},ErrSplitBrainRisk}
	if authority.State!=LeaseActive||!now.Before(authority.ExpiresAt){return WriterLease{},ErrLeaseLost}
	if err=authority.Validate(now);err!=nil{return WriterLease{},err}
	return authority,nil
}

func (coordinator FailoverCoordinator) validatePersistedFenceReceipts(ctx context.Context,plans []Fence,receipts []FenceReceipt,now time.Time)error{
	if len(plans)==0||len(plans)!=len(receipts){return ErrFenceRequired}
	planByID:=make(map[FenceID]Fence,len(plans))
	for _,plan:=range plans{if _,exists:=planByID[plan.ID];exists{return ErrConflict};planByID[plan.ID]=plan}
	seen:=make(map[FenceID]struct{},len(receipts))
	for _,receipt:=range receipts{
		plan,exists:=planByID[receipt.FenceID];if !exists{return ErrFenceFailed}
		if _,duplicate:=seen[receipt.FenceID];duplicate{return ErrFenceFailed};seen[receipt.FenceID]=struct{}{}
		if err:=validateFenceReceiptAgainstPlan(plan,receipt,now);err!=nil{return err}
		stored,err:=coordinator.Store.LoadFence(ctx,receipt.FenceID);if err!=nil{return err}
		if stored.State!=FenceProven||stored.Generation!=plan.Generation+1||stored.GroupID!=plan.GroupID||stored.TargetNodeID!=plan.TargetNodeID||stored.Class!=plan.Class||stored.FencingToken!=plan.FencingToken||stored.AuthorityEpoch!=plan.AuthorityEpoch||stored.ProofDigest!=receipt.ProofDigest||stored.ProviderReceipt!=receipt.ProviderReceipt||!stored.AppliedAt.Equal(receipt.AppliedAt)||!stored.ValidUntil.Equal(receipt.ValidUntil)||!sameProtectedWritePaths(stored.ProtectedWritePaths,receipt.ProtectedWritePaths){return ErrFenceFailed}
		if err=stored.Validate(now);err!=nil{return err}
	}
	return nil
}

func validateFenceReceiptAgainstPlan(plan Fence,receipt FenceReceipt,now time.Time)error{
	if receipt.FenceID!=plan.ID||receipt.TargetNodeID!=plan.TargetNodeID||receipt.Class!=plan.Class||receipt.FencingToken!=plan.FencingToken||!validDigest(receipt.ProofDigest)||receipt.ProviderReceipt==""||receipt.AppliedAt.IsZero()||receipt.AppliedAt.After(now)||!receipt.ValidUntil.After(receipt.AppliedAt)||!now.Before(receipt.ValidUntil)||!sameProtectedWritePaths(plan.ProtectedWritePaths,receipt.ProtectedWritePaths){return ErrFenceFailed}
	return nil
}

func sameProtectedWritePaths(left,right []string)bool{
	if len(left)==0||len(left)!=len(right){return false}
	values:=make(map[string]struct{},len(left))
	for _,value:=range left{if value==""{return false};if _,duplicate:=values[value];duplicate{return false};values[value]=struct{}{}}
	for _,value:=range right{if _,exists:=values[value];!exists{return false};delete(values,value)}
	return len(values)==0
}
func (coordinator FailoverCoordinator) advance(ctx context.Context,promotion *Promotion,run *FailoverRun)error{previous:=promotion.Generation;promotion.Generation++;promotion.UpdatedAt=coordinator.now();run.UpdatedAt=coordinator.now();if err:=coordinator.Store.UpdatePromotion(ctx,*promotion,previous);err!=nil{return err};return coordinator.Store.UpdateFailoverRun(ctx,*run)}
func (coordinator FailoverCoordinator) fail(ctx context.Context,promotion Promotion,run FailoverRun,step string,cause error)(Promotion,FailoverRun,error){previous:=promotion.Generation;promotion.State,promotion.Failure,promotion.Generation,promotion.UpdatedAt=PromotionFailed,cause.Error(),promotion.Generation+1,coordinator.now();run.State,run.Step,run.Failure,run.UpdatedAt=PromotionFailed,step,cause.Error(),coordinator.now();_ = coordinator.Store.UpdatePromotion(ctx,promotion,previous);_ = coordinator.Store.UpdateFailoverRun(ctx,run);return promotion,run,cause}
func (coordinator FailoverCoordinator) failForward(ctx context.Context,promotion Promotion,run FailoverRun,step string,cause error)(Promotion,FailoverRun,error){previous:=promotion.Generation;promotion.State,promotion.Failure,promotion.Generation,promotion.UpdatedAt=PromotionFailForward,cause.Error(),promotion.Generation+1,coordinator.now();run.State,run.Step,run.Failure,run.UpdatedAt=PromotionFailForward,step,cause.Error(),coordinator.now();_ = coordinator.Store.UpdatePromotion(ctx,promotion,previous);_ = coordinator.Store.UpdateFailoverRun(ctx,run);return promotion,run,errors.Join(ErrIrreversibleFrontier,cause)}
func (coordinator FailoverCoordinator) rollbackOrForward(ctx context.Context,promotion Promotion,run FailoverRun,request PromotionRequest,policy TrafficPolicy,receipt TrafficReceipt,cause error)(Promotion,FailoverRun,error){if promotion.Irreversible||promotion.WriteFrontier>promotion.CheckpointFrontier||run.FenceProofDigest!=""{return coordinator.failForward(ctx,promotion,run,"fail_forward",cause)};previous:=promotion.Generation;promotion.State,promotion.Generation,promotion.UpdatedAt=PromotionRollingBack,promotion.Generation+1,coordinator.now();run.State,run.Step,run.UpdatedAt=PromotionRollingBack,"rollback",coordinator.now();_ = coordinator.Store.UpdatePromotion(ctx,promotion,previous);_ = coordinator.Store.UpdateFailoverRun(ctx,run);var rollbackErr error;if receipt.ProviderReceipt!=""{before,_:=coordinator.Traffic.Observe(ctx,policy);if before.Digest!=receipt.OutputDigest{rollbackErr=ErrProviderAmbiguous}else{desired:=buildTrafficDesired(policy,before,promotion.PreviousWriter,promotion.Candidate);_,rollbackErr=coordinator.Traffic.CompensateConditional(ctx,TrafficChange{Policy:policy,EffectID:string(promotion.ID)+":traffic-rollback",Before:before,Desired:desired},receipt)}};_,serviceErr:=coordinator.Executor.RestorePreviousServices(ctx,promotion,request.Lease.FencingToken);rollbackErr=errors.Join(rollbackErr,serviceErr);if rollbackErr!=nil{return coordinator.failForward(ctx,promotion,run,"rollback_failed",errors.Join(cause,rollbackErr))};previous=promotion.Generation;promotion.State,promotion.Generation,promotion.UpdatedAt=PromotionRolledBack,promotion.Generation+1,coordinator.now();run.State,run.Step,run.Failure,run.CompletedAt,run.UpdatedAt=PromotionRolledBack,"rolled_back",cause.Error(),coordinator.now(),coordinator.now();_ = coordinator.Store.UpdatePromotion(ctx,promotion,previous);_ = coordinator.Store.UpdateFailoverRun(ctx,run);return promotion,run,cause}

func promotionDigest(request PromotionRequest)(string,error){copy:=request;copy.Promotion.Approvals=nil;payload,err:=json.Marshal(copy);if err!=nil{return "",err};sum:=sha256.Sum256(payload);return hex.EncodeToString(sum[:]),nil}
func digestFenceReceipts(receipts []FenceReceipt)(string,error){payload,err:=json.Marshal(receipts);if err!=nil{return "",err};sum:=sha256.Sum256(payload);return hex.EncodeToString(sum[:]),nil}
func buildTrafficDesired(policy TrafficPolicy,before TrafficObservation,writer,old NodeID)TrafficObservation{endpoints:=append([]TrafficEndpoint(nil),before.Endpoints...);for index:=range endpoints{if endpoints[index].NodeID==writer{endpoints[index].Weight=100;endpoints[index].Healthy=true}else if endpoints[index].NodeID==old{endpoints[index].Weight=0}};payload,_:=json.Marshal(endpoints);sum:=sha256.Sum256(payload);return TrafficObservation{PolicyID:policy.ID,Endpoints:endpoints,Digest:hex.EncodeToString(sum[:]),ObservedAt:time.Now().UTC()}}

func validateTrafficReceipt(receipt TrafficReceipt)error{if !validID(string(receipt.PolicyID))||!validID(receipt.EffectID)||!validDigest(receipt.BeforeDigest)||!validDigest(receipt.OutputDigest)||receipt.ProviderReceipt==""||receipt.AppliedAt.IsZero(){return fmt.Errorf("%w: traffic receipt",ErrInvalid)};return nil}
func validateLeaseCoverage(lease WriterLease,required []string)error{covered:=map[string]bool{};for _,path:=range lease.EnforcedWritePaths{covered[path]=true};for _,path:=range required{if !covered[path]{return fmt.Errorf("%w: lease does not cover %s",ErrFenceRequired,path)}};return nil}
