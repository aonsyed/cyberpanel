package management

import(
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

var(ErrInvalid=errors.New("webengine management: invalid value");ErrNotFound=errors.New("webengine management: not found");ErrConflict=errors.New("webengine management: conflict");ErrAmbiguous=errors.New("webengine management: ambiguous effect");ErrLicense=errors.New("webengine management: license rejected");ErrUnsupported=errors.New("webengine management: unsupported tuple"))
type State string
const(StateAbsent State="absent";StateInstalling State="installing";StateStaged State="staged";StateActive State="active";StateDegraded State="degraded";StateRemoving State="removing")
type Channel string
const(ChannelStable Channel="stable";ChannelLTS Channel="lts";ChannelPinned Channel="pinned")
type Installation struct{ID string;Edition webengine.Edition;Version,ArtifactDigest,RepositorySnapshotDigest string;Channel Channel;State State;License LicenseStatus;Generation uint64;ActiveConfigDigest,PreviousConfigDigest string;InstalledAt,UpdatedAt time.Time;Transition *SwitchReceipt `json:"transition,omitempty"`}
type LicenseStatus struct{Mode string;SecretRef string;SerialFingerprint string;State webengine.LicenseState;Limits LicenseLimits;CheckedAt,ExpiresAt time.Time;ReceiptDigest string}
type LicenseLimits struct{Workers,Domains uint32;MemoryBytes uint64;Features []string}
type ArtifactRequest struct{Edition webengine.Edition;Channel Channel;Version,OS,OSVersion,Architecture string}
type ArtifactPlan struct{Edition webengine.Edition;Version,ArtifactDigest,RepositorySnapshotDigest string;Packages []PackageArtifact;ServiceProfileID string;NativeConfigFormat string}
type PackageArtifact struct{Name,Version,Digest,RepositoryID string}
type ArtifactCatalog interface{Resolve(context.Context,ArtifactRequest)(ArtifactPlan,error)}
type TargetRenderer interface{BuildTarget(context.Context,webengine.Edition,uint64)(native.ConfigGeneration,error)}
type Executor interface{Inspect(context.Context,webengine.Edition)(Installation,error);Install(context.Context,EffectRequest,ArtifactPlan)(EffectReceipt,error);ApplyLicense(context.Context,EffectRequest,LicenseRequest)(LicenseStatus,error);RefreshLicense(context.Context,EffectRequest)(LicenseStatus,error);StageGeneration(context.Context,EffectRequest,native.ConfigGeneration)(EffectReceipt,error);ValidateGeneration(context.Context,EffectRequest,native.ConfigGeneration)(ValidationReceipt,error);ShadowProbe(context.Context,EffectRequest,native.ConfigGeneration)(ProbeReceipt,error);SwitchService(context.Context,SwitchRequest)(SwitchReceipt,error);ConfirmService(context.Context,SwitchReceipt)(ProbeReceipt,error);RestoreService(context.Context,SwitchReceipt)(ProbeReceipt,error);Remove(context.Context,EffectRequest,webengine.Edition)(EffectReceipt,error);InstallPHP(context.Context,EffectRequest,PHPArtifactPlan)(EffectReceipt,error);ApplyPHPProfile(context.Context,EffectRequest,PHPProfile)(EffectReceipt,error);RestartPHPPool(context.Context,EffectRequest,string)(EffectReceipt,error);ApplyGlobalTuning(context.Context,EffectRequest,GlobalTuning)(EffectReceipt,error)}
type EffectRequest struct{EffectID string;ExpectedGeneration uint64;Fence uint64;PlanDigest,CommitAuthorizationDigest,LicenseMode,SecretRef,SerialFingerprint string;ConversionOS string `json:"conversion_os,omitempty"`;ConversionOSVersion string `json:"conversion_os_version,omitempty"`;ConversionArchitecture string `json:"conversion_architecture,omitempty"`;ConversionVersion string `json:"conversion_version,omitempty"`;ConversionChannel Channel `json:"conversion_channel,omitempty"`}
type EffectReceipt struct{EffectID,PlanDigest,EvidenceDigest string;Generation,Fence uint64;Outcome string;ObservedAt time.Time}
type ValidationReceipt struct{EffectID,ConfigDigest,ParserDigest,SemanticDigest string;Valid bool;Findings []string;ObservedAt time.Time}
type ProbeReceipt struct{EffectID,ConfigDigest string;HTTP,HTTPS,PHP,Cache,TLS,HTTP3 bool;EvidenceDigest string;ObservedAt time.Time}
type SwitchRequest struct{EffectRequest EffectRequest;Previous,Target webengine.Edition;PreviousConfigDigest,TargetConfigDigest string;RollbackDeadline time.Time}
type SwitchReceipt struct{EffectID string;Previous,Target webengine.Edition;PreviousConfigDigest,TargetConfigDigest,LeaseID,ConfirmNonce,EvidenceDigest string;Fence uint64;SwitchedAt,RollbackDeadline time.Time;Confirmed,Restored bool;ConversionDigest,HostDigest,PreviousPlanDigest,TargetPlanDigest,ProbeDigest,LicenseDigest,CatalogDigest string;CatalogSequence uint64;PreviousChannel,TargetChannel Channel;PreviousPlan,TargetPlan ArtifactPlan;License LicenseStatus}
type LicenseRequest struct{Mode,SecretRef string;Trial bool}

type PHPProfile struct{ID,Version,BinaryPathID,BinaryArtifactDigest,ConfigDigest,CatalogDigest string;CatalogSequence uint64;Extensions []string;MemoryLimitBytes,UploadLimitBytes,BodyLimitBytes uint64;RequestTimeout time.Duration;MaxConnections,MaxChildren uint32;Detached bool;Generation uint64}
type PHPArtifactPlan struct{Version,RepositorySnapshotDigest,BinaryPathID,CatalogDigest string;CatalogSequence uint64;Packages []PackageArtifact;Extensions []string}
type GlobalTuning struct{WorkerProcesses,MaxConnections,MaxTLSConnections uint32;ConnectionTimeout,KeepAliveTimeout time.Duration;KeepAliveRequests uint32;MemoryCacheBytes uint64;Compression bool;CompressionLevel uint8;Brotli bool;Generation uint64}

type Operation struct{ID,Kind,Status,RequestDigest string;ExpectedGeneration uint64;Installation Installation;Receipt any;CreatedAt,UpdatedAt time.Time}
type Repository interface{Installation(context.Context)(Installation,error);Admit(context.Context,Operation)(Operation,bool,error);Complete(context.Context,string,string,Installation,any)error;PHPProfile(context.Context,string)(PHPProfile,error);PutPHPProfile(context.Context,PHPProfile,uint64)error;GlobalTuning(context.Context)(GlobalTuning,error);PutGlobalTuning(context.Context,GlobalTuning,uint64)error}
type LifecycleExecutor interface{Upgrade(context.Context,EffectRequest,ArtifactPlan)(EffectReceipt,error);ConvertEdition(context.Context,EffectRequest,ArtifactPlan,native.ConfigGeneration,time.Duration)(SwitchReceipt,error)}
type Capabilities struct{Inspect,Install,Convert,Upgrade,Remove,RefreshLicense,InstallPHP,Tune bool}
type CapabilityProvider interface{ManagementCapabilities()Capabilities}
type Service struct{repository Repository;catalog ArtifactCatalog;renderer TargetRenderer;executor Executor;capabilities Capabilities;clock func()time.Time}
func New(repository Repository,catalog ArtifactCatalog,renderer TargetRenderer,executor Executor)(*Service,error){if repository==nil||catalog==nil||renderer==nil||executor==nil{return nil,ErrInvalid};capabilities:=Capabilities{Inspect:true,Install:true,Convert:true,Upgrade:true,Remove:true,RefreshLicense:true,InstallPHP:true,Tune:true};if provider,ok:=executor.(CapabilityProvider);ok{capabilities=provider.ManagementCapabilities()};return &Service{repository:repository,catalog:catalog,renderer:renderer,executor:executor,capabilities:capabilities,clock:time.Now},nil}
func(s *Service)Capabilities()Capabilities{if s==nil{return Capabilities{}};return s.capabilities}
func(s *Service)Installation(ctx context.Context)(Installation,error){if s==nil||s.repository==nil{return Installation{},ErrInvalid};if !s.capabilities.Inspect{return Installation{},ErrUnsupported};return s.repository.Installation(ctx)}
func(s *Service)CurrentTuning(ctx context.Context)(GlobalTuning,error){if s==nil||s.repository==nil{return GlobalTuning{},ErrInvalid};return s.repository.GlobalTuning(ctx)}

type InstallCommand struct{CommandID,OS,OSVersion,Architecture,Version string;Edition webengine.Edition;Channel Channel;License LicenseRequest;ExpectedGeneration,Fence uint64;CommitAuthorizationDigest string}
func(s *Service)Install(ctx context.Context,command InstallCommand)(Installation,error){if s==nil||!s.capabilities.Install{return Installation{},ErrUnsupported};if command.Edition!=webengine.EditionOpenLiteSpeed&&command.Edition!=webengine.EditionLiteSpeedEnterprise{return Installation{},ErrInvalid};plan,err:=s.catalog.Resolve(ctx,ArtifactRequest{Edition:command.Edition,Channel:command.Channel,Version:command.Version,OS:command.OS,OSVersion:command.OSVersion,Architecture:command.Architecture});if err!=nil{return Installation{},err};planDigest:=digestJSON(plan);effect:=effectID(command.CommandID,planDigest);current,loadErr:=s.repository.Installation(ctx);if loadErr!=nil&&!errors.Is(loadErr,ErrNotFound){return Installation{},loadErr};next:=Installation{ID:"node-webengine",Edition:command.Edition,Version:plan.Version,ArtifactDigest:plan.ArtifactDigest,RepositorySnapshotDigest:plan.RepositorySnapshotDigest,Channel:command.Channel,State:StateInstalling,Generation:command.ExpectedGeneration+1,UpdatedAt:s.clock().UTC()};if current.Generation>0{next.InstalledAt=current.InstalledAt;next.PreviousConfigDigest=current.ActiveConfigDigest}else{next.InstalledAt=s.clock().UTC()};operation:=Operation{ID:effect,Kind:"install",Status:"accepted",RequestDigest:planDigest,ExpectedGeneration:command.ExpectedGeneration,Installation:next,CreatedAt:s.clock().UTC(),UpdatedAt:s.clock().UTC()};admitted,isNew,err:=s.repository.Admit(ctx,operation);if err!=nil{return Installation{},err};if !isNew&&admitted.Installation.State!=StateInstalling{return admitted.Installation,nil};request:=EffectRequest{EffectID:effect,ExpectedGeneration:command.ExpectedGeneration,Fence:command.Fence,PlanDigest:planDigest,CommitAuthorizationDigest:command.CommitAuthorizationDigest};receipt,err:=s.executor.Install(ctx,request,plan);if err!=nil||!validLifecycleReceipt(receipt,request,command.ExpectedGeneration+1){if receipt.Outcome=="rolled_back"{restored:=current;if restored.ID==""{restored=next;restored.State=StateAbsent;restored.ActiveConfigDigest=""};restored.Generation=command.ExpectedGeneration+1;restored.UpdatedAt=s.clock().UTC();_ = s.completeLifecycle(ctx,effect,"rolled_back",restored,receipt,command.ExpectedGeneration);return restored,errors.Join(ErrInvalid,err)};next.State=StateDegraded;_ = s.completeLifecycle(ctx,effect,"ambiguous",next,receipt,command.ExpectedGeneration);return next,errors.Join(ErrAmbiguous,err)};next.State=StateActive;next.ActiveConfigDigest=receipt.EvidenceDigest;if err=s.completeLifecycle(ctx,effect,"applied",next,receipt,command.ExpectedGeneration);err!=nil{return next,err};return next,nil}

type ConvertCommand struct{CommandID,OS,OSVersion,Architecture,Version string;Target webengine.Edition;Channel Channel;License LicenseRequest;ExpectedGeneration,SnapshotGeneration,Fence uint64;CommitAuthorizationDigest string;RollbackWindow time.Duration}
func(s *Service)Convert(ctx context.Context,command ConvertCommand)(Installation,error){
	if s==nil||!s.capabilities.Convert{return Installation{},ErrUnsupported}
	lifecycle,ok:=s.executor.(LifecycleExecutor);if !ok{return Installation{},ErrUnsupported}
	current,err:=s.repository.Installation(ctx);if err!=nil{return Installation{},err}
	window:=command.RollbackWindow;if window==0{window=5*time.Minute}
	if !validConversionLicense(command.Target,command.License)||window<time.Minute||window>24*time.Hour||command.ExpectedGeneration==0||command.Fence!=command.ExpectedGeneration+1||!validSHA256(command.CommitAuthorizationDigest){return current,ErrInvalid}
	fresh:=current.Generation==command.ExpectedGeneration&&current.State==StateActive&&current.Edition!=command.Target
	retry:=current.Generation==command.Fence&&current.State==StateInstalling&&current.Edition==command.Target&&validSHA256(current.PreviousConfigDigest)
	if !fresh&&!retry{return current,ErrConflict}
	previousEdition:=current.Edition;previousConfig:=current.ActiveConfigDigest
	if retry { if command.Target==webengine.EditionOpenLiteSpeed{previousEdition=webengine.EditionLiteSpeedEnterprise}else{previousEdition=webengine.EditionOpenLiteSpeed};previousConfig=current.PreviousConfigDigest }
	selection:=ArtifactRequest{Edition:command.Target,Channel:command.Channel,Version:command.Version,OS:command.OS,OSVersion:command.OSVersion,Architecture:command.Architecture}
	if !validLifecycleTuple(selection.OS,selection.OSVersion,selection.Architecture)||!validChannel(selection.Channel)||!safeLifecycleVersion(selection.Version){return current,ErrInvalid}
	plan,err:=s.catalog.Resolve(ctx,selection);if err!=nil{return current,err}
	if retry {
		for _,edition:=range []webengine.Edition{command.Target,previousEdition}{
			observed,inspectErr:=s.executor.Inspect(ctx,edition);if inspectErr!=nil||observed.Transition==nil{continue}
			receipt:=*observed.Transition
			digest:=ConversionPlanDigest(selection,plan,receipt.TargetConfigDigest,command.License,window)
			if !validConversionReceipt(receipt)||receipt.EffectID!=effectID(command.CommandID,digest)||receipt.ConversionDigest!=digest||receipt.Fence!=command.Fence||receipt.Previous!=previousEdition||receipt.Target!=command.Target||receipt.TargetChannel!=command.Channel||digestJSON(receipt.TargetPlan)!=digestJSON(plan)||!conversionInstallationMatches(observed,receipt){continue}
			observed.InstalledAt=current.InstalledAt;observed.UpdatedAt=s.clock().UTC()
			status:="applied";if receipt.Restored{status="rolled_back"}
			if err=s.completeLifecycle(ctx,receipt.EffectID,status,observed,receipt,command.ExpectedGeneration);err!=nil{return observed,errors.Join(ErrAmbiguous,err)}
			if receipt.Restored{return observed,ErrInvalid};return observed,nil
		}
	}
	generation,err:=s.renderer.BuildTarget(ctx,command.Target,command.SnapshotGeneration);if err!=nil{return current,err}
	planDigest:=ConversionPlanDigest(selection,plan,generation.ContentDigest,command.License,window)
	effect:=effectID(command.CommandID,planDigest)
	next:=Installation{ID:current.ID,Edition:command.Target,Version:plan.Version,ArtifactDigest:plan.ArtifactDigest,RepositorySnapshotDigest:plan.RepositorySnapshotDigest,Channel:command.Channel,State:StateInstalling,Generation:command.ExpectedGeneration+1,PreviousConfigDigest:previousConfig,InstalledAt:current.InstalledAt,UpdatedAt:s.clock().UTC()}
	operation:=Operation{ID:effect,Kind:"convert",Status:"accepted",RequestDigest:planDigest,ExpectedGeneration:command.ExpectedGeneration,Installation:next,CreatedAt:s.clock().UTC(),UpdatedAt:s.clock().UTC()}
	admitted,isNew,err:=s.repository.Admit(ctx,operation);if err!=nil{return current,err};if !isNew&&admitted.Installation.State!=StateInstalling{return admitted.Installation,nil}
	request:=EffectRequest{EffectID:effect,ExpectedGeneration:command.ExpectedGeneration,Fence:command.Fence,PlanDigest:planDigest,CommitAuthorizationDigest:command.CommitAuthorizationDigest,LicenseMode:command.License.Mode,SecretRef:command.License.SecretRef,ConversionOS:selection.OS,ConversionOSVersion:selection.OSVersion,ConversionArchitecture:selection.Architecture,ConversionVersion:selection.Version,ConversionChannel:selection.Channel}
	switched,err:=lifecycle.ConvertEdition(ctx,request,plan,generation,window)
	if err!=nil{
		if switched.Restored&&validConversionReceipt(switched)&&switched.ConversionDigest==planDigest&&switched.Fence==command.Fence&&switched.Previous==previousEdition&&switched.Target==command.Target&&switched.TargetConfigDigest==generation.ContentDigest{
			restored:=Installation{ID:current.ID,Edition:switched.Previous,Version:switched.PreviousPlan.Version,ArtifactDigest:switched.PreviousPlan.ArtifactDigest,RepositorySnapshotDigest:switched.PreviousPlan.RepositorySnapshotDigest,Channel:switched.PreviousChannel,State:StateActive,License:switched.License,Generation:command.Fence,ActiveConfigDigest:switched.PreviousConfigDigest,PreviousConfigDigest:switched.PreviousConfigDigest,InstalledAt:current.InstalledAt,UpdatedAt:s.clock().UTC(),Transition:&switched}
			if completeErr:=s.completeLifecycle(ctx,effect,"rolled_back",restored,switched,command.ExpectedGeneration);completeErr!=nil{return restored,errors.Join(ErrAmbiguous,err,completeErr)};return restored,errors.Join(ErrInvalid,err)
		}
		return next,errors.Join(ErrAmbiguous,err)
	}
	if !validSwitchReceipt(switched,request,previousEdition,command.Target,generation.ContentDigest)||!validConversionReceipt(switched)||switched.ConversionDigest!=planDigest||switched.TargetChannel!=command.Channel{return next,ErrAmbiguous}
	next.State=StateActive;next.ActiveConfigDigest=generation.ContentDigest;next.License=switched.License;next.Transition=&switched
	if err=s.completeLifecycle(ctx,effect,"applied",next,switched,command.ExpectedGeneration);err!=nil{return next,err};return next,nil
}

// ConversionPlanDigest binds the exact target packages, native generation,
// license mode/reference (including trial intent), and rollback lease.
func ConversionPlanDigest(selection ArtifactRequest, plan ArtifactPlan, config string, license LicenseRequest, window time.Duration) string {
	return digestJSON(struct{Domain string;Selection ArtifactRequest;Plan ArtifactPlan;Config string;License LicenseRequest;RollbackWindow time.Duration}{"cyberpanel:edition-conversion:v2",selection,plan,config,license,window})
}

func conversionLicense(request EffectRequest) LicenseRequest { return LicenseRequest{Mode:request.LicenseMode,SecretRef:request.SecretRef,Trial:request.LicenseMode==LicenseModeTrial} }
func conversionSelection(request EffectRequest, edition webengine.Edition) ArtifactRequest { return ArtifactRequest{Edition:edition,Channel:request.ConversionChannel,Version:request.ConversionVersion,OS:request.ConversionOS,OSVersion:request.ConversionOSVersion,Architecture:request.ConversionArchitecture} }
func validConversionLicense(edition webengine.Edition, license LicenseRequest) bool {
	if edition==webengine.EditionOpenLiteSpeed{return license==(LicenseRequest{})}
	return edition==webengine.EditionLiteSpeedEnterprise&&validLicenseRequest(license)
}
func validConversionReceipt(receipt SwitchReceipt) bool {
	return validConversionReceiptBase(receipt)&&receipt.Confirmed!=receipt.Restored&&validSHA256(receipt.ProbeDigest)&&receipt.LicenseDigest==digestJSON(receipt.License)&&validSHA256(receipt.EvidenceDigest)
}
func validConversionReceiptBase(receipt SwitchReceipt) bool { return validEffectToken(receipt.EffectID)&&receipt.LeaseID=="edition-"+receipt.EffectID&&validSHA256(receipt.ConfirmNonce)&&receipt.Previous!=receipt.Target&&receipt.PreviousPlan.Edition==receipt.Previous&&receipt.TargetPlan.Edition==receipt.Target&&validateArtifactPlan(receipt.PreviousPlan)==nil&&validateArtifactPlan(receipt.TargetPlan)==nil&&validChannel(receipt.PreviousChannel)&&validChannel(receipt.TargetChannel)&&receipt.PreviousPlanDigest==digestJSON(receipt.PreviousPlan)&&receipt.TargetPlanDigest==digestJSON(receipt.TargetPlan)&&validSHA256(receipt.ConversionDigest)&&validSHA256(receipt.HostDigest)&&validSHA256(receipt.CatalogDigest)&&receipt.CatalogSequence>0&&validSHA256(receipt.PreviousConfigDigest)&&validSHA256(receipt.TargetConfigDigest)&&receipt.PreviousConfigDigest!=receipt.TargetConfigDigest&&receipt.Fence>1&&!receipt.SwitchedAt.IsZero()&&receipt.RollbackDeadline.After(receipt.SwitchedAt) }

type UpgradeCommand struct{CommandID,Version string;Channel Channel;ExpectedGeneration,Fence uint64;CommitAuthorizationDigest string}
func(s *Service)Upgrade(ctx context.Context,command UpgradeCommand)(Installation,error){if s==nil||!s.capabilities.Upgrade{return Installation{},ErrUnsupported};lifecycle,ok:=s.executor.(LifecycleExecutor);if !ok{return Installation{},ErrUnsupported};current,err:=s.repository.Installation(ctx);if err!=nil{return Installation{},err};if current.Generation!=command.ExpectedGeneration||current.State!=StateActive{return current,ErrConflict};channel:=command.Channel;if channel==""{channel=current.Channel};plan,err:=s.catalog.Resolve(ctx,ArtifactRequest{Edition:current.Edition,Channel:channel,Version:command.Version});if err!=nil{return current,err};if plan.Version==current.Version&&plan.ArtifactDigest==current.ArtifactDigest{return current,nil};planDigest:=digestJSON(plan);effect:=effectID(command.CommandID,planDigest);next:=current;next.Version,next.ArtifactDigest,next.RepositorySnapshotDigest,next.Channel=plan.Version,plan.ArtifactDigest,plan.RepositorySnapshotDigest,channel;next.State=StateInstalling;next.Generation++;next.UpdatedAt=s.clock().UTC();operation:=Operation{ID:effect,Kind:"upgrade",Status:"accepted",RequestDigest:planDigest,ExpectedGeneration:command.ExpectedGeneration,Installation:next,CreatedAt:s.clock().UTC(),UpdatedAt:s.clock().UTC()};admitted,isNew,err:=s.repository.Admit(ctx,operation);if err!=nil{return current,err};if !isNew&&admitted.Installation.State!=StateInstalling{return admitted.Installation,nil};request:=EffectRequest{EffectID:effect,ExpectedGeneration:command.ExpectedGeneration,Fence:command.Fence,PlanDigest:planDigest,CommitAuthorizationDigest:command.CommitAuthorizationDigest};receipt,err:=lifecycle.Upgrade(ctx,request,plan);if err!=nil||!validLifecycleReceipt(receipt,request,next.Generation){if receipt.Outcome=="rolled_back"{restored:=current;restored.Generation=next.Generation;restored.UpdatedAt=s.clock().UTC();_ = s.completeLifecycle(ctx,effect,"rolled_back",restored,receipt,command.ExpectedGeneration);return restored,errors.Join(ErrInvalid,err)};next.State=StateDegraded;_ = s.completeLifecycle(ctx,effect,"ambiguous",next,receipt,command.ExpectedGeneration);return next,errors.Join(ErrAmbiguous,err)};next.State=StateActive;next.ActiveConfigDigest=receipt.EvidenceDigest;if err=s.completeLifecycle(ctx,effect,"applied",next,receipt,command.ExpectedGeneration);err!=nil{return next,err};return next,nil}

type RemoveCommand struct{CommandID string;ExpectedGeneration,Fence uint64;CommitAuthorizationDigest string}
func(s *Service)Remove(ctx context.Context,command RemoveCommand)(Installation,error){if s==nil||!s.capabilities.Remove{return Installation{},ErrUnsupported};current,err:=s.repository.Installation(ctx);if err!=nil{return Installation{},err};if current.Generation!=command.ExpectedGeneration||current.State!=StateActive{return current,ErrConflict};planDigest:=digestJSON(struct{Edition webengine.Edition;ArtifactDigest string}{current.Edition,current.ArtifactDigest});effect:=effectID(command.CommandID,planDigest);next:=current;next.State=StateRemoving;next.Generation++;next.UpdatedAt=s.clock().UTC();operation:=Operation{ID:effect,Kind:"remove",Status:"accepted",RequestDigest:planDigest,ExpectedGeneration:command.ExpectedGeneration,Installation:next,CreatedAt:s.clock().UTC(),UpdatedAt:s.clock().UTC()};admitted,isNew,err:=s.repository.Admit(ctx,operation);if err!=nil{return current,err};if !isNew&&admitted.Installation.State!=StateRemoving{return admitted.Installation,nil};request:=EffectRequest{EffectID:effect,ExpectedGeneration:command.ExpectedGeneration,Fence:command.Fence,PlanDigest:planDigest,CommitAuthorizationDigest:command.CommitAuthorizationDigest};receipt,err:=s.executor.Remove(ctx,request,current.Edition);if err!=nil||!validLifecycleReceipt(receipt,request,next.Generation){if receipt.Outcome=="rolled_back"{restored:=current;restored.Generation=next.Generation;restored.UpdatedAt=s.clock().UTC();_ = s.completeLifecycle(ctx,effect,"rolled_back",restored,receipt,command.ExpectedGeneration);return restored,errors.Join(ErrInvalid,err)};next.State=StateDegraded;_ = s.completeLifecycle(ctx,effect,"ambiguous",next,receipt,command.ExpectedGeneration);return next,errors.Join(ErrAmbiguous,err)};next.State=StateAbsent;next.PreviousConfigDigest=current.ActiveConfigDigest;next.ActiveConfigDigest="";if err=s.completeLifecycle(ctx,effect,"applied",next,receipt,command.ExpectedGeneration);err!=nil{return next,err};return next,nil}

func(s *Service)RefreshLicense(ctx context.Context,effect string,expected,fence uint64)(LicenseStatus,error){return s.refreshLicense(ctx,effect,expected,fence)}
func(s *Service)InstallPHP(ctx context.Context,effect string,profile PHPProfile,plan PHPArtifactPlan,expected,fence uint64,authorization string)(PHPProfile,error){if s==nil||!s.capabilities.InstallPHP{return PHPProfile{},ErrUnsupported};if profile.ID==""||profile.Version==""||profile.Generation!=expected+1||profile.MaxConnections==0||profile.MaxChildren==0||profile.MaxChildren<profile.MaxConnections{return PHPProfile{},ErrInvalid};request:=EffectRequest{EffectID:effect,ExpectedGeneration:expected,Fence:fence,PlanDigest:digestJSON(plan),CommitAuthorizationDigest:authorization};receipt,err:=s.executor.InstallPHP(ctx,request,plan);if err!=nil||receipt.Outcome!="confirmed"{return profile,errors.Join(ErrAmbiguous,err)};receipt,err=s.executor.ApplyPHPProfile(ctx,request,profile);if err!=nil||receipt.Outcome!="confirmed"{return profile,errors.Join(ErrAmbiguous,err)};if err=s.repository.PutPHPProfile(ctx,profile,expected);err!=nil{return profile,err};return profile,nil}
func (s *Service) Tune(ctx context.Context, effect string, tuning GlobalTuning, expected, fence uint64, authorization string) (GlobalTuning, error) {
	if s == nil || !s.capabilities.Tune {
		return GlobalTuning{}, ErrUnsupported
	}
	if tuning.Generation != expected+1 {
		return GlobalTuning{}, ErrInvalid
	}
	if _, err := canonicalTuning(tuning); err != nil {
		return GlobalTuning{}, err
	}
	installation, err := s.repository.Installation(ctx)
	if err != nil {
		return GlobalTuning{}, err
	}
	current, err := s.repository.GlobalTuning(ctx)
	if err != nil {
		return GlobalTuning{}, err
	}
	request := EffectRequest{EffectID: effect, ExpectedGeneration: expected, Fence: fence, PlanDigest: digestJSON(tuning), CommitAuthorizationDigest: authorization}
	if installation.Generation == tuning.Generation && current == tuning {
		receipt, replayErr := s.executor.ApplyGlobalTuning(ctx, request, tuning)
		if replayErr != nil {
			return tuning, replayErr
		}
		if !validTuningReceipt(receipt, request, tuning) {
			return tuning, ErrAmbiguous
		}
		return tuning, nil
	}
	if installation.Generation != expected || current.Generation != expected {
		return GlobalTuning{}, ErrConflict
	}
	receipt, err := s.executor.ApplyGlobalTuning(ctx, request, tuning)
	if err != nil {
		return tuning, err
	}
	if !validTuningReceipt(receipt, request, tuning) {
		return tuning, ErrAmbiguous
	}
	next := installation
	next.Generation = tuning.Generation
	next.PreviousConfigDigest = installation.ActiveConfigDigest
	next.ActiveConfigDigest = receipt.EvidenceDigest
	next.State = StateActive
	next.UpdatedAt = s.clock().UTC()
	if committer, ok := s.repository.(interface {
		CommitTuning(context.Context, Installation, GlobalTuning, uint64) error
	}); ok {
		if err = committer.CommitTuning(ctx, next, tuning, expected); err != nil {
			return tuning, err
		}
	} else if err = s.repository.PutGlobalTuning(ctx, tuning, expected); err != nil {
		return tuning, err
	}
	return tuning, nil
}

func validTuningReceipt(receipt EffectReceipt, request EffectRequest, tuning GlobalTuning) bool {
	return receipt.Outcome == "confirmed" && receipt.EffectID == request.EffectID && receipt.PlanDigest == request.PlanDigest &&
		receipt.Generation == tuning.Generation && receipt.Fence == request.Fence && !receipt.ObservedAt.IsZero() && validSHA256(receipt.EvidenceDigest)
}
func validLifecycleReceipt(receipt EffectReceipt,request EffectRequest,generation uint64)bool{return receipt.Outcome=="confirmed"&&receipt.EffectID==request.EffectID&&receipt.PlanDigest==request.PlanDigest&&receipt.Generation==generation&&receipt.Fence==request.Fence&&!receipt.ObservedAt.IsZero()&&validSHA256(receipt.EvidenceDigest)}
func validSwitchReceipt(receipt SwitchReceipt,request EffectRequest,previous,target webengine.Edition,digest string)bool{return receipt.Confirmed&&!receipt.Restored&&receipt.EffectID==request.EffectID&&receipt.Previous==previous&&receipt.Target==target&&receipt.TargetConfigDigest==digest&&receipt.Fence==request.Fence&&!receipt.SwitchedAt.IsZero()&&!receipt.RollbackDeadline.Before(receipt.SwitchedAt)&&validSHA256(receipt.EvidenceDigest)}
func(s *Service)completeLifecycle(ctx context.Context,id,status string,installation Installation,receipt any,expected uint64)error{if committer,ok:=s.repository.(interface{CompleteLifecycle(context.Context,string,string,Installation,any,uint64)error});ok{return committer.CompleteLifecycle(ctx,id,status,installation,receipt,expected)};tuning,err:=s.repository.GlobalTuning(ctx);if errors.Is(err,ErrNotFound){tuning=DefaultGlobalTuning();tuning.Generation=installation.Generation}else if err==nil{tuning.Generation=installation.Generation}else{return err};if err=s.repository.PutGlobalTuning(ctx,tuning,expected);err!=nil{return err};return s.repository.Complete(ctx,id,status,installation,receipt)}
func probeHealthy(value ProbeReceipt)bool{return value.HTTP&&value.HTTPS&&value.PHP&&value.TLS&&value.EvidenceDigest!=""}
func effectID(command,digest string)string{sum:=sha256.Sum256([]byte(command+"\x00"+digest));return "web-"+hex.EncodeToString(sum[:])}
func digestJSON(value any)string{raw,_:=json.Marshal(value);sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:])}
var _=fmt.Sprintf
var _=strings.TrimSpace

const SQLSchema=`
CREATE TABLE IF NOT EXISTS webengine_installation(singleton_id INTEGER PRIMARY KEY,generation BIGINT NOT NULL,state TEXT NOT NULL,value_json TEXT NOT NULL,updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS webengine_management_operations(id TEXT PRIMARY KEY,kind TEXT NOT NULL,status TEXT NOT NULL,request_digest TEXT NOT NULL,expected_generation BIGINT NOT NULL,installation_json TEXT NOT NULL,receipt_json TEXT NOT NULL,created_at TIMESTAMP NOT NULL,updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS webengine_php_profiles(id TEXT PRIMARY KEY,generation BIGINT NOT NULL,value_json TEXT NOT NULL,updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS webengine_global_tuning(singleton_id INTEGER PRIMARY KEY,generation BIGINT NOT NULL,value_json TEXT NOT NULL,updated_at TIMESTAMP NOT NULL);
`
type SQLRepository struct{db *sql.DB;clock func()time.Time}
func NewSQLRepository(db *sql.DB)(*SQLRepository,error){if db==nil{return nil,ErrInvalid};return &SQLRepository{db:db,clock:time.Now},nil}
func(r *SQLRepository)Bootstrap(ctx context.Context)error{_,err:=r.db.ExecContext(ctx,SQLSchema);return err}
func(r *SQLRepository)Installation(ctx context.Context)(Installation,error){var value Installation;var raw []byte;err:=r.db.QueryRowContext(ctx,`SELECT value_json FROM webengine_installation WHERE singleton_id=1`).Scan(&raw);if errors.Is(err,sql.ErrNoRows){return value,ErrNotFound};if err!=nil{return value,err};err=json.Unmarshal(raw,&value);return value,err}
func(r *SQLRepository)Admit(ctx context.Context,operation Operation)(Operation,bool,error){tx,err:=r.db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return operation,false,err};defer tx.Rollback();var raw []byte;var digest string;err=tx.QueryRowContext(ctx,`SELECT request_digest,installation_json FROM webengine_management_operations WHERE id=?`,operation.ID).Scan(&digest,&raw);if err==nil{if digest!=operation.RequestDigest{return operation,false,ErrConflict};_ = json.Unmarshal(raw,&operation.Installation);return operation,false,tx.Commit()};if !errors.Is(err,sql.ErrNoRows){return operation,false,err};current:=uint64(0);_ = tx.QueryRowContext(ctx,`SELECT generation FROM webengine_installation WHERE singleton_id=1`).Scan(&current);if current!=operation.ExpectedGeneration{return operation,false,ErrConflict};installation,_:=json.Marshal(operation.Installation);_,err=tx.ExecContext(ctx,`INSERT INTO webengine_management_operations VALUES(?,?,?,?,?,?,?,?,?)`,operation.ID,operation.Kind,"accepted",operation.RequestDigest,operation.ExpectedGeneration,installation,[]byte(`{}`),operation.CreatedAt,operation.UpdatedAt);if err!=nil{return operation,false,err};_,err=tx.ExecContext(ctx,`INSERT INTO webengine_installation VALUES(1,?,?,?,?) ON CONFLICT(singleton_id) DO UPDATE SET generation=excluded.generation,state=excluded.state,value_json=excluded.value_json,updated_at=excluded.updated_at WHERE webengine_installation.generation=?`,operation.Installation.Generation,operation.Installation.State,installation,r.clock().UTC(),operation.ExpectedGeneration);if err!=nil{return operation,false,err};return operation,true,tx.Commit()}
func(r *SQLRepository)Complete(ctx context.Context,id,status string,installation Installation,receipt any)error{tx,err:=r.db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return err};defer tx.Rollback();raw,_:=json.Marshal(installation);receiptRaw,_:=json.Marshal(receipt);_,err=tx.ExecContext(ctx,`UPDATE webengine_installation SET generation=?,state=?,value_json=?,updated_at=? WHERE singleton_id=1`,installation.Generation,installation.State,raw,r.clock().UTC());if err!=nil{return err};_,err=tx.ExecContext(ctx,`UPDATE webengine_management_operations SET status=?,installation_json=?,receipt_json=?,updated_at=? WHERE id=?`,status,raw,receiptRaw,r.clock().UTC(),id);if err!=nil{return err};return tx.Commit()}
func(r *SQLRepository)CompleteLifecycle(ctx context.Context,id,status string,installation Installation,receipt any,expected uint64)error{if installation.Generation!=expected+1{return ErrInvalid};tx,err:=r.db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable});if err!=nil{return err};defer tx.Rollback();raw,err:=json.Marshal(installation);if err!=nil{return err};receiptRaw,err:=json.Marshal(receipt);if err!=nil{return err};result,err:=tx.ExecContext(ctx,`UPDATE webengine_installation SET state=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`,installation.State,raw,r.clock().UTC(),installation.Generation);if err!=nil{return err};changed,err:=result.RowsAffected();if err!=nil||changed!=1{if err!=nil{return err};return ErrConflict};var tuningRaw []byte;var tuningGeneration uint64;err=tx.QueryRowContext(ctx,`SELECT generation,value_json FROM webengine_global_tuning WHERE singleton_id=1`).Scan(&tuningGeneration,&tuningRaw);var tuning GlobalTuning;if errors.Is(err,sql.ErrNoRows){tuning=DefaultGlobalTuning()}else if err!=nil{return err}else if tuningGeneration!=expected||json.Unmarshal(tuningRaw,&tuning)!=nil{return ErrConflict};tuning.Generation=installation.Generation;tuningRaw,err=json.Marshal(tuning);if err!=nil{return err};if tuningGeneration==0{_,err=tx.ExecContext(ctx,`INSERT INTO webengine_global_tuning(singleton_id,generation,value_json,updated_at) VALUES(1,?,?,?)`,tuning.Generation,tuningRaw,r.clock().UTC())}else{result,err=tx.ExecContext(ctx,`UPDATE webengine_global_tuning SET generation=?,value_json=?,updated_at=? WHERE singleton_id=1 AND generation=?`,tuning.Generation,tuningRaw,r.clock().UTC(),expected);if err==nil{changed,_=result.RowsAffected();if changed!=1{err=ErrConflict}}};if err!=nil{return err};result,err=tx.ExecContext(ctx,`UPDATE webengine_management_operations SET status=?,installation_json=?,receipt_json=?,updated_at=? WHERE id=? AND expected_generation=?`,status,raw,receiptRaw,r.clock().UTC(),id,expected);if err!=nil{return err};changed,err=result.RowsAffected();if err!=nil||changed!=1{if err!=nil{return err};return ErrConflict};return tx.Commit()}
func(r *SQLRepository)PHPProfile(ctx context.Context,id string)(PHPProfile,error){var value PHPProfile;var raw []byte;err:=r.db.QueryRowContext(ctx,`SELECT value_json FROM webengine_php_profiles WHERE id=?`,id).Scan(&raw);if errors.Is(err,sql.ErrNoRows){return value,ErrNotFound};if err!=nil{return value,err};err=json.Unmarshal(raw,&value);return value,err}
func(r *SQLRepository)PutPHPProfile(ctx context.Context,value PHPProfile,expected uint64)error{raw,_:=json.Marshal(value);result,err:=r.db.ExecContext(ctx,`INSERT INTO webengine_php_profiles VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,value_json=excluded.value_json,updated_at=excluded.updated_at WHERE webengine_php_profiles.generation=?`,value.ID,value.Generation,raw,r.clock().UTC(),expected);if err!=nil{return err};count,_:=result.RowsAffected();if count!=1{return ErrConflict};return nil}
func(r *SQLRepository)GlobalTuning(ctx context.Context)(GlobalTuning,error){var value GlobalTuning;var raw []byte;err:=r.db.QueryRowContext(ctx,`SELECT value_json FROM webengine_global_tuning WHERE singleton_id=1`).Scan(&raw);if errors.Is(err,sql.ErrNoRows){return value,ErrNotFound};if err!=nil{return value,err};err=json.Unmarshal(raw,&value);return value,err}
func(r *SQLRepository)PutGlobalTuning(ctx context.Context,value GlobalTuning,expected uint64)error{raw,_:=json.Marshal(value);result,err:=r.db.ExecContext(ctx,`INSERT INTO webengine_global_tuning VALUES(1,?,?,?) ON CONFLICT(singleton_id) DO UPDATE SET generation=excluded.generation,value_json=excluded.value_json,updated_at=excluded.updated_at WHERE webengine_global_tuning.generation=?`,value.Generation,raw,r.clock().UTC(),expected);if err!=nil{return err};count,_:=result.RowsAffected();if count!=1{return ErrConflict};return nil}
