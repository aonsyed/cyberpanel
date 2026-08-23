package migration

import(
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)
type ManifestVerifier interface{Verify(context.Context,Manifest)error}
type SourceReader interface{Discover(context.Context,ID)(Manifest,error);OpenChunk(context.Context,string,uint64,uint64)([]byte,error);Generation(context.Context,ID)(uint64,error)}
type CutoverSource interface{Quiesce(context.Context,ID,Plan,uint64)(SourceFence,error);Unquiesce(context.Context,SourceFence)error;FinalDelta(context.Context,SourceFence,Manifest)(Manifest,error);CommitSource(context.Context,SourceFence)error;RollbackSource(context.Context,SourceFence)error}
type SourceFence struct{MigrationID ID;Generation,Fence uint64;Digest string;ExpiresAt time.Time}
type TargetImporter interface{Capacity(context.Context)(map[string]uint64,error);Plan(context.Context,Manifest)([]Mapping,error);Prepare(context.Context,Migration,Plan)error;ImportResource(context.Context,Migration,Mapping,Manifest)(ResourceProgress,error);ApplyDelta(context.Context,Migration,Manifest)([]ResourceProgress,error);VerifyDark(context.Context,Migration,Plan)(Verification,error);Activate(context.Context,Migration,Plan)(ActivationReceipt,error);VerifyActive(context.Context,Migration,Plan,ActivationReceipt)(Verification,error);Deactivate(context.Context,ActivationReceipt)error;Finalize(context.Context,Migration)error}
type Verification struct{HTTP,TLS,PHP,Database,DNS,Mail,Files,Cron,Containers,Backups bool;EvidenceDigest string;ObservedAt time.Time}
type ActivationReceipt struct{MigrationID ID;TargetGeneration uint64;RoutingDigest,DNSDigest,LoadBalancerDigest,WriteWatermark string;ActivatedAt time.Time;EvidenceDigest string}
type Repository interface{Migration(context.Context,ID)(Migration,error);Create(context.Context,Migration)error;Transition(context.Context,ID,Phase,Phase,string,uint64)(Migration,error);PutManifest(context.Context,Manifest)error;Manifest(context.Context,string)(Manifest,error);PutPlan(context.Context,Plan)error;Plan(context.Context,string)(Plan,error);PutProgress(context.Context,ResourceProgress)error;Progress(context.Context,ID)([]ResourceProgress,error);PutReceipt(context.Context,ID,string,any)error;Receipt(context.Context,ID,string,any)error}
type Orchestrator struct{repository Repository;verifier ManifestVerifier;source SourceReader;cutover CutoverSource;target TargetImporter;stager *ChunkStager;clock func()time.Time}
func NewOrchestrator(repository Repository,verifier ManifestVerifier,source SourceReader,cutover CutoverSource,target TargetImporter)(*Orchestrator,error){if repository==nil||verifier==nil||source==nil||cutover==nil||target==nil{return nil,ErrInvalid};return &Orchestrator{repository:repository,verifier:verifier,source:source,cutover:cutover,target:target,clock:time.Now},nil}
func(o *Orchestrator)WithChunkStager(stager *ChunkStager)*Orchestrator{if o!=nil{o.stager=stager};return o}
func(o *Orchestrator)Create(ctx context.Context,id ID,source SourceKind,attempt string)(Migration,error){value:=Migration{ID:id,Source:source,Phase:PhaseCreated,AttemptID:attempt,Fence:1,CreatedAt:o.clock().UTC(),UpdatedAt:o.clock().UTC()};return value,o.repository.Create(ctx,value)}
func(o *Orchestrator)Inventory(ctx context.Context,id ID)(Manifest,error){migration,err:=o.repository.Migration(ctx,id);if err!=nil{return Manifest{},err};if migration.Phase==PhaseCreated{migration,err=o.repository.Transition(ctx,id,PhaseCreated,PhaseDiscovering,"discover",0)}else if migration.Phase==PhasePausedRetryable{migration,err=o.resumePaused(ctx,migration,PhaseDiscovering)}else if migration.Phase!=PhaseDiscovering{return Manifest{},ErrConflict};if err!=nil{return Manifest{},err};manifest,err:=o.source.Discover(ctx,id);if err!=nil{return Manifest{},o.pause(ctx,migration,"DISCOVERY_FAILED",err)};if err=o.verifier.Verify(ctx,manifest);err!=nil{return Manifest{},o.fail(ctx,migration,"MANIFEST_REJECTED",err)};if err=o.repository.PutManifest(ctx,manifest);err!=nil{return Manifest{},err};_,err=o.repository.Transition(ctx,id,PhaseDiscovering,PhaseInventoried,manifest.MerkleRoot,manifest.SourceGeneration);return manifest,err}
func(o *Orchestrator)DryRun(ctx context.Context,id,planID ID)(Plan,error){migration,err:=o.repository.Migration(ctx,id);if err!=nil{return Plan{},err};if migration.Phase!=PhaseInventoried&&migration.Phase!=PhasePlanned{return Plan{},ErrConflict};manifest,err:=o.repository.Manifest(ctx,migration.ManifestRoot);if err!=nil{return Plan{},err};capacity,err:=o.target.Capacity(ctx);if err!=nil{return Plan{},err};mappings,err:=o.target.Plan(ctx,manifest);if err!=nil{return Plan{},err};required:=aggregateCapacity(mappings);plan:=Plan{ID:planID,MigrationID:id,ManifestRoot:manifest.MerkleRoot,Mappings:mappings,RequiredCapacity:required,AvailableCapacity:capacity,QuiesceMode:"write_fence",CutoverMethod:"dns_or_load_balancer",RollbackWindow:30*time.Minute};for key,value:=range required{if capacity[key]<value{plan.Unsupported=append(plan.Unsupported,fmt.Sprintf("capacity:%s",key))}};for _,mapping:=range mappings{if mapping.Disposition==DispositionBlock{plan.Unsupported=append(plan.Unsupported,mapping.SourceKind+":"+mapping.SourceID.String())}};plan.DryRunDigest=digestJSON(plan);if err=o.repository.PutPlan(ctx,plan);err!=nil{return Plan{},err};if migration.Phase==PhaseInventoried{_,err=o.repository.Transition(ctx,id,PhaseInventoried,PhasePlanned,plan.DryRunDigest,migration.SourceGeneration)};if len(plan.Unsupported)>0{return plan,errors.Join(ErrBlocked,err)};return plan,err}
func(o *Orchestrator)Approve(ctx context.Context,id ID,approvalDigest string)(Migration,error){migration,err:=o.repository.Migration(ctx,id);if err!=nil{return migration,err};if migration.Phase!=PhasePlanned{return migration,ErrConflict};plan,err:=o.repository.Plan(ctx,migration.PlanDigest);if err!=nil{return migration,err};if len(plan.Unsupported)>0{return migration,ErrBlocked};now:=o.clock().UTC();plan.ApprovedAt=&now;plan.ApprovalDigest=approvalDigest;if err=o.repository.PutPlan(ctx,plan);err!=nil{return migration,err};return o.repository.Transition(ctx,id,PhasePlanned,PhaseReady,plan.DryRunDigest,migration.SourceGeneration)}
func(o *Orchestrator)BaseSync(ctx context.Context,id ID)(Migration,error){migration,err:=o.repository.Migration(ctx,id);if err!=nil{return migration,err};if migration.Phase==PhaseReady{migration,err=o.repository.Transition(ctx,id,PhaseReady,PhaseBaseSync,"base-sync",migration.SourceGeneration);if err!=nil{return migration,err}}else if migration.Phase==PhasePausedRetryable{migration,err=o.resumePaused(ctx,migration,PhaseBaseSync);if err!=nil{return migration,err}}else if migration.Phase!=PhaseBaseSync{return migration,ErrConflict};manifest,err:=o.repository.Manifest(ctx,migration.ManifestRoot);if err!=nil{return migration,err};plan,err:=o.repository.Plan(ctx,migration.PlanDigest);if err!=nil{return migration,err};if o.stager!=nil{if err=o.stager.Stage(ctx,id,manifest,o.source);err!=nil{return migration,o.pause(ctx,migration,"CHUNK_STAGE_FAILED",err)}};if err=o.target.Prepare(ctx,migration,plan);err!=nil{return migration,o.pause(ctx,migration,"TARGET_PREPARE_FAILED",err)};completed,err:=o.repository.Progress(ctx,id);if err!=nil{return migration,err};done:=progressSet(completed);for _,mapping:=range plan.Mappings{key:=mapping.SourceKind+":"+mapping.SourceID.String();if done[key]{continue};if mapping.Disposition==DispositionSkip{continue};progress,importErr:=o.target.ImportResource(ctx,migration,mapping,manifest);if importErr!=nil{return migration,o.pause(ctx,migration,"RESOURCE_IMPORT_FAILED",importErr)};if err=o.repository.PutProgress(ctx,progress);err!=nil{return migration,err}};verification,err:=o.target.VerifyDark(ctx,migration,plan);if err!=nil||!verificationHealthy(verification){return migration,o.pause(ctx,migration,"DARK_VERIFY_FAILED",err)};return o.repository.Transition(ctx,id,PhaseBaseSync,PhaseQuiescing,verification.EvidenceDigest,migration.SourceGeneration)}
func (o *Orchestrator) Cutover(ctx context.Context, id ID) (Migration, error) {
	migration, err := o.repository.Migration(ctx, id)
	if err != nil {
		return migration, err
	}
	if migration.Phase == PhasePausedRetryable {
		migration, err = o.resumePausedAny(ctx, migration, PhaseQuiescing, PhaseFinalSync, PhaseCutoverReady, PhaseCutoverCommitting, PhaseVerifying)
		if err != nil {
			return migration, err
		}
	}
	if migration.Phase == PhaseCommitted {
		if err := o.target.Finalize(ctx, migration); err != nil {
			_ = o.repository.PutReceipt(ctx, id, "finalize_error", map[string]string{"message": safeError(err)})
			return migration, err
		}
		return o.repository.Transition(ctx, id, PhaseCommitted, PhaseCleanup, "complete", migration.SourceGeneration)
	}
	if migration.Phase != PhaseQuiescing && migration.Phase != PhaseFinalSync && migration.Phase != PhaseCutoverReady && migration.Phase != PhaseCutoverCommitting && migration.Phase != PhaseVerifying {
		return migration, ErrConflict
	}
	plan, err := o.repository.Plan(ctx, migration.PlanDigest)
	if err != nil {
		return migration, err
	}
	manifest, err := o.repository.Manifest(ctx, migration.ManifestRoot)
	if err != nil {
		return migration, err
	}
	var fence SourceFence
	if migration.Phase == PhaseQuiescing {
		fence, err = o.cutover.Quiesce(ctx, id, plan, migration.Fence)
		if err != nil {
			return migration, o.pause(ctx, migration, "SOURCE_QUIESCE_FAILED", err)
		}
		if err := o.repository.PutReceipt(ctx, id, "source_fence", fence); err != nil {
			_ = o.cutover.Unquiesce(ctx, fence)
			return migration, err
		}
		migration, err = o.repository.Transition(ctx, id, PhaseQuiescing, PhaseFinalSync, fence.Digest, fence.Generation)
		if err != nil {
			_ = o.cutover.Unquiesce(ctx, fence)
			return migration, err
		}
	} else if err := o.repository.Receipt(ctx, id, "source_fence", &fence); err != nil {
		return migration, err
	}
	if fence.MigrationID != id || fence.Fence != migration.Fence || fence.Generation == 0 || !isDigest(fence.Digest) || fence.ExpiresAt.Before(o.clock().UTC()) {
		return migration, ErrConflict
	}
	if migration.Phase == PhaseFinalSync {
		delta, deltaErr := o.cutover.FinalDelta(ctx, fence, manifest)
		if deltaErr != nil {
			_ = o.cutover.Unquiesce(ctx, fence)
			return migration, o.pause(ctx, migration, "FINAL_DELTA_FAILED", deltaErr)
		}
		if verifyErr := o.verifier.Verify(ctx, delta); verifyErr != nil {
			_ = o.cutover.Unquiesce(ctx, fence)
			return migration, o.fail(ctx, migration, "FINAL_DELTA_REJECTED", verifyErr)
		}
		current, generationErr := o.source.Generation(ctx, id)
		if generationErr != nil || current != fence.Generation || delta.SourceGeneration != fence.Generation {
			_ = o.cutover.Unquiesce(ctx, fence)
			return migration, o.pause(ctx, migration, "SOURCE_GENERATION_MOVED", errors.Join(generationErr, ErrConflict))
		}
		if o.stager != nil {
			if stageErr := o.stager.Stage(ctx, id, delta, o.source); stageErr != nil {
				_ = o.cutover.Unquiesce(ctx, fence)
				return migration, o.pause(ctx, migration, "FINAL_CHUNK_STAGE_FAILED", stageErr)
			}
		}
		progress, applyErr := o.target.ApplyDelta(ctx, migration, delta)
		if applyErr != nil {
			_ = o.cutover.Unquiesce(ctx, fence)
			return migration, o.pause(ctx, migration, "FINAL_APPLY_FAILED", applyErr)
		}
		for _, value := range progress {
			if err := o.repository.PutProgress(ctx, value); err != nil {
				return migration, err
			}
		}
		migration, err = o.repository.Transition(ctx, id, PhaseFinalSync, PhaseCutoverReady, delta.MerkleRoot, fence.Generation)
		if err != nil {
			return migration, err
		}
	}
	if migration.Phase == PhaseCutoverReady {
		migration, err = o.repository.Transition(ctx, id, PhaseCutoverReady, PhaseCutoverCommitting, "activate", fence.Generation)
		if err != nil {
			return migration, err
		}
	}
	var activation ActivationReceipt
	if migration.Phase == PhaseCutoverCommitting {
		activation, err = o.target.Activate(ctx, migration, plan)
		if err != nil {
			return migration, o.pause(ctx, migration, "ACTIVATION_AMBIGUOUS", err)
		}
		if activation.MigrationID != id || activation.TargetGeneration == 0 || !isDigest(activation.EvidenceDigest) {
			return migration, o.pause(ctx, migration, "ACTIVATION_RECEIPT_INVALID", ErrAmbiguous)
		}
		if err := o.repository.PutReceipt(ctx, id, "activation", activation); err != nil {
			return migration, err
		}
		migration, err = o.repository.Transition(ctx, id, PhaseCutoverCommitting, PhaseVerifying, activation.EvidenceDigest, fence.Generation)
		if err != nil {
			return migration, err
		}
	} else if err := o.repository.Receipt(ctx, id, "activation", &activation); err != nil {
		return migration, err
	}
	verification, verifyErr := o.target.VerifyActive(ctx, migration, plan, activation)
	if verifyErr != nil || !verificationHealthy(verification) {
		if activation.WriteWatermark == "" {
			_ = o.target.Deactivate(ctx, activation)
			_ = o.cutover.RollbackSource(ctx, fence)
			_, _ = o.repository.Transition(ctx, id, PhaseVerifying, PhaseRollingBack, "pre-write-rollback", fence.Generation)
			rolled, _ := o.repository.Transition(ctx, id, PhaseRollingBack, PhaseRolledBack, "source-restored", fence.Generation)
			return rolled, verifyErr
		}
		return migration, o.pause(ctx, migration, "POST_WRITE_VERIFY_FAILED", errors.Join(ErrWriteFrontier, verifyErr))
	}
	if err := o.cutover.CommitSource(ctx, fence); err != nil {
		return migration, o.pause(ctx, migration, "SOURCE_COMMIT_FAILED", err)
	}
	migration, err = o.repository.Transition(ctx, id, PhaseVerifying, PhaseCommitted, verification.EvidenceDigest, fence.Generation)
	if err != nil {
		return migration, err
	}
	if err := o.target.Finalize(ctx, migration); err != nil {
		_ = o.repository.PutReceipt(ctx, id, "finalize_error", map[string]string{"message": safeError(err)})
		return migration, err
	}
	return o.repository.Transition(ctx, id, PhaseCommitted, PhaseCleanup, "complete", fence.Generation)
}
type pauseReceipt struct{From Phase;Code,Message string;Generation,Fence uint64;PausedAt time.Time}
func(o *Orchestrator)pause(ctx context.Context,m Migration,code string,cause error)error{receipt:=pauseReceipt{From:m.Phase,Code:code,Message:safeError(cause),Generation:m.SourceGeneration,Fence:m.Fence,PausedAt:o.clock().UTC()};storeErr:=o.repository.PutReceipt(ctx,m.ID,"pause",receipt);_,transitionErr:=o.repository.Transition(ctx,m.ID,m.Phase,PhasePausedRetryable,code,m.SourceGeneration);return errors.Join(cause,storeErr,transitionErr)}
func(o *Orchestrator)resumePaused(ctx context.Context,m Migration,target Phase)(Migration,error){return o.resumePausedAny(ctx,m,target)}
func(o *Orchestrator)resumePausedAny(ctx context.Context,m Migration,targets ...Phase)(Migration,error){if m.Phase!=PhasePausedRetryable{return m,ErrConflict};var receipt pauseReceipt;if err:=o.repository.Receipt(ctx,m.ID,"pause",&receipt);err!=nil{return m,err};if receipt.Fence!=m.Fence||receipt.Generation!=m.SourceGeneration{return m,ErrConflict};allowed:=false;for _,target:=range targets{if receipt.From==target{allowed=true;break}};if !allowed{return m,ErrConflict};return o.repository.Transition(ctx,m.ID,PhasePausedRetryable,receipt.From,"resume:"+receipt.Code,m.SourceGeneration)}
func(o *Orchestrator)fail(ctx context.Context,m Migration,code string,cause error)error{_,err:=o.repository.Transition(ctx,m.ID,m.Phase,PhaseFailedTerminal,code,m.SourceGeneration);return errors.Join(cause,err)}
func aggregateCapacity(mappings []Mapping)map[string]uint64{out:=map[string]uint64{};for _,mapping:=range mappings{for key,value:=range mapping.Capacity{out[key]+=value}};return out}
func progressSet(values []ResourceProgress)map[string]bool{out:=map[string]bool{};for _,value:=range values{if value.Phase==PhaseBaseSync||value.Phase==PhaseFinalSync||value.Phase==PhaseCommitted{out[value.Kind+":"+value.SourceID.String()]=true}};return out}
func verificationHealthy(value Verification)bool{return value.HTTP&&value.TLS&&value.PHP&&value.Database&&value.DNS&&value.Mail&&value.Files&&value.Cron&&value.Containers&&value.Backups&&len(value.EvidenceDigest)==64}
func digestJSON(value any)string{raw,_:=json.Marshal(value);sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:])}
func safeError(err error)string{if err==nil{return ""};value:=err.Error();if len(value)>1024{return value[:1024]};return value}
