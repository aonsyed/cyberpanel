//go:build linux

package management

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation/fsstore"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

const (
	lifecycleStateRoot = "/var/lib/cyberpanel/webengine"
	lifecyclePackageRoot = "/var/lib/cyberpanel/webengine/packages"
	lifecycleRepositoryRoot = "/etc/cyberpanel/webengine/repositories"
	lifecycleStateFile = "lifecycle.json"
	lifecycleStateTemporary = ".lifecycle.tmp"
	lifecycleEditionPath = "/etc/cyberpanel/engine.edition"
	lifecycleConfigurationRoot = "/usr/local/lsws/conf"
	lifecycleBinaryPath = "/usr/local/lsws/bin/lshttpd"
	lifecycleLicenseAdapterPath = "/usr/local/libexec/cyberpanel/lse-license"
	lifecyclePHPProfileRoot = "/var/lib/cyberpanel/webengine/php-profiles"
	lifecyclePHPActivePath = "/var/lib/cyberpanel/webengine/php-active.json"
	lifecycleService = "lsws.service"
	lifecycleMaximumStateBytes = 32 << 20
	LinuxLicenseSecretAdapterID = "cyberpanel.webengine.lse-license"
	LinuxLicenseSecretAdapterVersion = "v1"
)

type lifecycleHostState struct {
	Active bool `json:"active"`
	Generation uint64 `json:"generation"`
	Fence uint64 `json:"fence"`
	Channel Channel `json:"channel,omitempty"`
	Plan ArtifactPlan `json:"plan,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type lifecycleEffectRecord struct {
	Key string `json:"key"`
	RequestDigest string `json:"request_digest"`
	State string `json:"state"`
	Payload json.RawMessage `json:"payload,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	StartedAt time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type lifecycleJournal struct {
	Version uint32 `json:"version"`
	Host lifecycleHostState `json:"host"`
	Effects map[string]lifecycleEffectRecord `json:"effects"`
	License LicenseStatus `json:"license,omitempty"`
	PHPProfiles map[string]PHPProfile `json:"php_profiles,omitempty"`
	ActivePHP *PHPProfile `json:"active_php,omitempty"`
	PHPCatalogSequence uint64 `json:"php_catalog_sequence,omitempty"`
	EngineCatalogSequence uint64 `json:"engine_catalog_sequence,omitempty"`
	EngineCatalogDigest string `json:"engine_catalog_digest,omitempty"`
	Generations map[string]lifecycleGenerationRecord `json:"generations,omitempty"`
	Switch *lifecycleSwitchRecord `json:"switch,omitempty"`
	Conversion *lifecycleConversionRecord `json:"conversion,omitempty"`
}

type LinuxLifecycleHost struct { mu sync.Mutex; journal lifecycleJournal; now func()time.Time; configurationRelease func(); admission rebootcontrol.ExecutionAdmission }

func(host *LinuxLifecycleHost)validateEngineCatalog(catalog localArtifactCatalog)error{
	if catalog.Sequence==0||!validSHA256(catalog.Digest)||catalog.Sequence<host.journal.EngineCatalogSequence{return ErrConflict}
	if catalog.Sequence==host.journal.EngineCatalogSequence&&host.journal.EngineCatalogDigest!=""&&catalog.Digest!=host.journal.EngineCatalogDigest{return ErrConflict}
	return nil
}

func(host *LinuxLifecycleHost)rememberEngineCatalog(catalog localArtifactCatalog)error{
	if err:=host.validateEngineCatalog(catalog);err!=nil{return err}
	host.journal.EngineCatalogSequence,host.journal.EngineCatalogDigest=catalog.Sequence,catalog.Digest
	return host.persist()
}

func init(){rootOwnedFile=func(info os.FileInfo)bool{metadata,ok:=info.Sys().(*syscall.Stat_t);return ok&&metadata.Uid==0}}

func NewLinuxLifecycleHost(admission rebootcontrol.ExecutionAdmission)(*LinuxLifecycleHost,error){
	if os.Geteuid()!=0||admission==nil{return nil,ErrInvalid}
	if err:=ensureLifecycleDirectory(lifecycleStateRoot,0o700);err!=nil{return nil,err}
	if err:=ensureLifecycleDirectory(lifecyclePackageRoot,0o700);err!=nil{return nil,err}
	if err:=ensurePHPProfileDirectory();err!=nil{return nil,err}
	host:=&LinuxLifecycleHost{journal:lifecycleJournal{Version:1,Effects:map[string]lifecycleEffectRecord{},PHPProfiles:map[string]PHPProfile{}},now:time.Now,admission:admission}
	if err:=host.load();err!=nil{return nil,err}
	if host.journal.Generations == nil { host.journal.Generations = map[string]lifecycleGenerationRecord{} }
	return host,nil
}

type lifecycleChallengeRecoveryReceipt struct {
	ManifestDigest string `json:"manifest_digest"`
	MarkerDigest string `json:"marker_digest"`
	CompletedAt time.Time `json:"completed_at"`
}

type lifecycleConversionRecoveryReceipt struct {
	RequestDigest string `json:"request_digest"`
	Phase string `json:"phase"`
	Switch SwitchReceipt `json:"switch"`
	CompletedAt time.Time `json:"completed_at"`
}

// ResumeStartup reconciles private recovery effects through the raw durable
// gate while the public mutation broker remains behind startup readiness.
func(host *LinuxLifecycleHost)ResumeStartup(ctx context.Context)error{
	if host==nil||ctx==nil||host.admission==nil{return ErrInvalid}
	host.mu.Lock();defer host.mu.Unlock()
	if err:=host.recoverStartupChallenges(ctx);err!=nil{return err}
	if host.journal.Conversion!=nil{if err:=host.recoverEditionConversion(ctx);err!=nil{return err}}
	return host.recoverGenerationSwitch(ctx)
}

func(host *LinuxLifecycleHost)recoverStartupChallenges(ctx context.Context)error{
	content,manifest,markerDigest,err:=readRecoverableLifecycleChallengeManifest();if err!=nil||manifest==nil{return err}
	manifestDigest:=linuxManagementDigest(content)
	requestDigest:=rebootcontrol.ExecutionDigest(struct{Manifest json.RawMessage `json:"manifest"`}{content})
	lease,err:=host.admission.AdmitExecution(ctx,rebootcontrol.ExecutionBinding{Boundary:"webengine-management-recovery",Method:"candidate_challenge_cleanup",EffectID:"candidate-challenges-"+manifestDigest,RequestDigest:requestDigest,Caller:"panel-execd-startup",Resource:rebootcontrol.ExecutionResource(struct{ManifestPath string `json:"manifest_path"`;MarkerPath string `json:"marker_path"`;Digest string `json:"digest"`}{filepath.Join(lifecycleStateRoot,"candidate-challenges.json"),filepath.Join(lifecycleStateRoot,"candidate-challenges-recovery.json"),manifestDigest})});if err!=nil{return err}
	if len(lease.Cached)!=0{var receipt lifecycleChallengeRecoveryReceipt;if json.Unmarshal(lease.Cached,&receipt)!=nil||receipt.ManifestDigest!=manifestDigest||receipt.MarkerDigest==""||receipt.MarkerDigest!=markerDigest||receipt.CompletedAt.IsZero()||receipt.CompletedAt.After(host.now().UTC().Add(time.Minute)){return rebootcontrol.ErrIntegrity};return verifyLifecycleChallengeRecoveryState(content,manifestDigest,markerDigest)}
	defer func(){_ = rebootcontrol.SettleExecution(host.admission,lease,false,nil)}()
	if err=recoverLifecycleChallengeFiles(content,manifest,manifestDigest,true);err!=nil{return err}
	markerDigest,err=writeLifecycleChallengeRecoveryMarker(content,manifestDigest);if err!=nil{return err}
	if err=clearLifecycleChallengeManifest();err!=nil{return err}
	if err=verifyLifecycleChallengeRecoveryState(content,manifestDigest,markerDigest);err!=nil{return err}
	return rebootcontrol.SettleExecution(host.admission,lease,true,lifecycleChallengeRecoveryReceipt{manifestDigest,markerDigest,host.now().UTC()})
}

func(host *LinuxLifecycleHost)recoverEditionConversion(ctx context.Context)error{
	record:=host.journal.Conversion
	if record==nil{return nil}
	if !validConversionRecord(record){return ErrInvalid}
	base:=record.Receipt;base.Confirmed=false;base.Restored=false;base.ProbeDigest="";base.License=LicenseStatus{};base.LicenseDigest="";base.EvidenceDigest=""
	requestDigest:=rebootcontrol.ExecutionDigest(struct{Input lifecycleConvertInput `json:"input"`;Previous lifecycleHostState `json:"previous"`;PreviousService conversionServiceState `json:"previous_service"`;PreviousPackages []conversionPackage `json:"previous_packages"`;TargetPackages []conversionPackage `json:"target_packages"`;CatalogDigest string `json:"catalog_digest"`;CatalogSequence uint64 `json:"catalog_sequence"`;HostDigest string `json:"host_digest"`;Receipt SwitchReceipt `json:"receipt"`}{record.Input,record.Previous,record.PreviousService,record.PreviousPackages,record.TargetPackages,record.CatalogDigest,record.CatalogSequence,record.HostDigest,base})
	lease,err:=host.admission.AdmitExecution(ctx,rebootcontrol.ExecutionBinding{Boundary:"webengine-management-recovery",Method:"edition_conversion_recovery",EffectID:record.Receipt.LeaseID,RequestDigest:requestDigest,Caller:"panel-execd-startup",Resource:rebootcontrol.ExecutionResource(struct{Effect,Previous,Target,PreviousConfig,TargetConfig,Catalog string;CatalogSequence,Fence uint64}{record.Receipt.EffectID,string(record.Receipt.Previous),string(record.Receipt.Target),record.Receipt.PreviousConfigDigest,record.Receipt.TargetConfigDigest,record.CatalogDigest,record.CatalogSequence,record.Receipt.Fence})});if err!=nil{return err}
	if len(lease.Cached)!=0{var receipt lifecycleConversionRecoveryReceipt;if json.Unmarshal(lease.Cached,&receipt)!=nil||!host.validConversionRecoveryReceipt(receipt,requestDigest){return rebootcontrol.ErrIntegrity};return nil}
	defer func(){_ = rebootcontrol.SettleExecution(host.admission,lease,false,nil)}()
	var reconcileErr error
	if host.conversionPending(){if err=host.coordinateConfiguration(ctx);err!=nil{return err};_,reconcileErr=host.reconcileEdition(ctx);host.releaseConfiguration()}
	receipt:=lifecycleConversionRecoveryReceipt{RequestDigest:requestDigest,CompletedAt:host.now().UTC()}
	if current:=host.journal.Conversion;current!=nil{receipt.Phase=current.Phase;receipt.Switch=current.Receipt}
	if !host.validConversionRecoveryReceipt(receipt,requestDigest){return errors.Join(ErrAmbiguous,reconcileErr)}
	if err=rebootcontrol.SettleExecution(host.admission,lease,true,receipt);err!=nil{return err}
	return nil
}

func(host *LinuxLifecycleHost)validConversionRecoveryReceipt(receipt lifecycleConversionRecoveryReceipt,requestDigest string)bool{
	record:=host.journal.Conversion
	if record==nil||(record.Phase!=conversionPhaseConfirmed&&record.Phase!=conversionPhaseRestored)||receipt.RequestDigest!=requestDigest||receipt.Phase!=record.Phase||digestJSON(receipt.Switch)!=digestJSON(record.Receipt)||!validConversionRecord(record)||!validConversionReceipt(record.Receipt)||record.Receipt.EvidenceDigest!=conversionEvidence(record)||receipt.CompletedAt.IsZero()||receipt.CompletedAt.After(host.now().UTC().Add(time.Minute)){return false}
	plan,channel,config:=record.Receipt.TargetPlan,record.Receipt.TargetChannel,record.Receipt.TargetConfigDigest
	if record.Receipt.Restored{plan,channel,config=record.Receipt.PreviousPlan,record.Receipt.PreviousChannel,record.Receipt.PreviousConfigDigest}
	state:=host.journal.Host
	return state.Active&&state.Generation==record.Input.Request.ExpectedGeneration+1&&state.Fence==record.Receipt.Fence&&state.Channel==channel&&digestJSON(state.Plan)==digestJSON(plan)&&state.ConfigDigest==config&&!state.UpdatedAt.IsZero()&&record.Receipt.LicenseDigest==digestJSON(host.journal.License)
}

func(host *LinuxLifecycleHost)HandleManagement(ctx context.Context,request LinuxManagementRequest)(any,error){
	if host==nil||ctx==nil{return nil,ErrInvalid};host.mu.Lock();defer host.mu.Unlock()
	if err := host.coordinateConfiguration(ctx); err != nil { return nil, err }
	defer host.releaseConfiguration()
	if request.Operation==LinuxManagementConvert{var input lifecycleConvertInput;if decodeLifecyclePayload(request.Payload,&input)!=nil{return nil,ErrInvalid};return host.convert(ctx,input)}
	if generationOperation(request.Operation) { return host.handleGeneration(ctx, request) }
	if host.switchPending() && request.Operation != LinuxManagementInspect && request.Operation != LinuxManagementInspectInstalled { return nil, ErrConflict }
	if request.Operation==LinuxManagementInspect||request.Operation==LinuxManagementInspectInstalled{var input struct{Edition webengine.Edition `json:"edition"`};if decodeLifecyclePayload(request.Payload,&input)!=nil{return Installation{},ErrInvalid};return host.inspectState(ctx,input.Edition,request.Operation==LinuxManagementInspect)}
	effect,err:=lifecycleEffect(request);if err!=nil{return nil,err};key:=string(request.Operation)+":"+effect;digest:=linuxManagementDigest(append([]byte(string(request.Operation)+"\x00"),request.Payload...))
	if record,found:=host.journal.Effects[key];found{if record.RequestDigest!=digest{return nil,ErrConflict};if record.State!="completed"{return nil,ErrAmbiguous};return append(json.RawMessage(nil),record.Payload...),linuxManagementFailure(record.ErrorCode)}
	host.prune();if len(host.journal.Effects)>=2048{return nil,ErrConflict};now:=host.now().UTC();host.journal.Effects[key]=lifecycleEffectRecord{Key:key,RequestDigest:digest,State:"pending",StartedAt:now};if err=host.persist();err!=nil{return nil,err}
	var result any
	switch request.Operation{case LinuxManagementInstall:var input lifecyclePlanInput;if decodeLifecyclePayload(request.Payload,&input)==nil{result,err=host.install(ctx,input,false)}else{err=ErrInvalid};case LinuxManagementUpgrade:var input lifecyclePlanInput;if decodeLifecyclePayload(request.Payload,&input)==nil{result,err=host.install(ctx,input,true)}else{err=ErrInvalid};case LinuxManagementConvert:var input lifecycleConvertInput;if decodeLifecyclePayload(request.Payload,&input)==nil{result,err=host.convert(ctx,input)}else{err=ErrInvalid};case LinuxManagementRemove:var input lifecycleRemoveInput;if decodeLifecyclePayload(request.Payload,&input)==nil{result,err=host.remove(ctx,input)}else{err=ErrInvalid};default:err=ErrUnsupported}
	payload,marshalErr:=json.Marshal(result);if marshalErr!=nil{err=errors.Join(ErrAmbiguous,marshalErr);payload=[]byte("null")};record:=host.journal.Effects[key];record.State,record.Payload,record.ErrorCode,record.CompletedAt="completed",payload,classifyLinuxManagementError(err),host.now().UTC();if err==nil{record.ErrorCode=""};host.journal.Effects[key]=record
	if persistErr:=host.persist();persistErr!=nil{return result,errors.Join(ErrAmbiguous,persistErr)};return result,err
}

func(host *LinuxLifecycleHost)HandleLicensePHP(ctx context.Context,request LinuxManagementRequest)(any,error){
	if host==nil||ctx==nil||!linuxLicensePHPOperation(request.Operation){return nil,ErrInvalid};host.mu.Lock();defer host.mu.Unlock()
	if err := host.coordinateConfiguration(ctx); err != nil { return nil, err }
	defer host.releaseConfiguration()
	if host.switchPending() { return nil, ErrConflict }
	effect,err:=licensePHPEffect(request);if err!=nil{return nil,err};key:=string(request.Operation)+":"+effect;digest:=linuxManagementDigest(append([]byte(string(request.Operation)+"\x00"),request.Payload...))
	if record,found:=host.journal.Effects[key];found{if record.RequestDigest!=digest{return nil,ErrConflict};if record.State!="completed"{return nil,ErrAmbiguous};return append(json.RawMessage(nil),record.Payload...),linuxManagementFailure(record.ErrorCode)}
	host.prune();if len(host.journal.Effects)>=2048{return nil,ErrConflict};now:=host.now().UTC();host.journal.Effects[key]=lifecycleEffectRecord{Key:key,RequestDigest:digest,State:"pending",StartedAt:now};if err=host.persist();err!=nil{return nil,err}
	var result any
	switch request.Operation{
	case LinuxManagementLicenseConfigure:var input licenseConfigureInput;if decodeLifecyclePayload(request.Payload,&input)==nil{result,err=host.configureLicense(ctx,input)}else{err=ErrInvalid}
	case LinuxManagementLicenseRefresh:var input licenseRefreshInput;if decodeLifecyclePayload(request.Payload,&input)==nil{result,err=host.refreshLicense(ctx,input)}else{err=ErrInvalid}
	case LinuxManagementPHPInstall:var input phpInstallInput;if decodeLifecyclePayload(request.Payload,&input)==nil{result,err=host.installPHP(ctx,input)}else{err=ErrInvalid}
	case LinuxManagementPHPProfileApply:var input phpProfileInput;if decodeLifecyclePayload(request.Payload,&input)==nil{result,err=host.applyPHPProfile(ctx,input)}else{err=ErrInvalid}
	case LinuxManagementPHPRollback:var input phpRollbackInput;if decodeLifecyclePayload(request.Payload,&input)==nil{result,err=host.rollbackPHP(ctx,input)}else{err=ErrInvalid}
	default:err=ErrUnsupported}
	payload,marshalErr:=json.Marshal(result);if marshalErr!=nil{err=errors.Join(ErrAmbiguous,marshalErr);payload=[]byte("null")};record:=host.journal.Effects[key];record.State,record.Payload,record.ErrorCode,record.CompletedAt="completed",payload,classifyLinuxManagementError(err),host.now().UTC();if err==nil{record.ErrorCode=""};host.journal.Effects[key]=record
	if persistErr:=host.persist();persistErr!=nil{return result,errors.Join(ErrAmbiguous,persistErr)};return result,err
}

type localLicenseObservation struct{State webengine.LicenseState `json:"state"`;Limits LicenseLimits `json:"limits"`;ExpiresAt time.Time `json:"expires_at,omitempty"`}

func(host *LinuxLifecycleHost)configureLicense(ctx context.Context,input licenseConfigureInput)(LicenseStatus,error){
	request,license:=input.Request,input.License;expected:=digestJSON(struct{Mode string `json:"mode"`;SecretRef string `json:"secret_ref,omitempty"`;Trial bool `json:"trial"`;Generation uint64 `json:"generation"`}{license.Mode,license.SecretRef,license.Trial,request.ExpectedGeneration})
	if validateLicensePHPEffect(request,expected,true)!=nil||!validLicenseRequest(license){return LicenseStatus{},ErrInvalid};if err:=host.requireEnterpriseGeneration(ctx,request.ExpectedGeneration);err!=nil{return LicenseStatus{},err}
	var material []byte
	if !license.Trial{var err error;material,err=readLicenseMaterial(ctx,license.SecretRef);if err!=nil{return LicenseStatus{},ErrLicense};defer wipeLicenseMaterial(material)}
	observation,err:=runLicenseAdapter(ctx,"configure",license.Mode,material);fingerprint:="";if len(material)>0{sum:=sha256.Sum256(material);fingerprint=hex.EncodeToString(sum[:])}
	status:=LicenseStatus{Mode:license.Mode,SecretRef:license.SecretRef,SerialFingerprint:fingerprint,State:observation.State,Limits:observation.Limits,CheckedAt:host.now().UTC(),ExpiresAt:observation.ExpiresAt}
	status.ReceiptDigest=licenseReceiptDigest(status,request);if err!=nil{return status,err};host.journal.License=status;host.journal.Host.Generation=request.ExpectedGeneration+1;host.journal.Host.Fence=request.Fence;host.journal.Host.UpdatedAt=status.CheckedAt;return status,nil
}

func(host *LinuxLifecycleHost)refreshLicense(ctx context.Context,input licenseRefreshInput)(LicenseStatus,error){
	request:=input.Request;stored:=host.journal.License;expected:=digestJSON(struct{Mode,SecretRef,PriorReceipt string;Generation uint64}{stored.Mode,stored.SecretRef,stored.ReceiptDigest,request.ExpectedGeneration})
	if validateLicensePHPEffect(request,expected,false)!=nil||!validStoredLicense(stored)||request.LicenseMode!=stored.Mode||request.SecretRef!=stored.SecretRef||request.SerialFingerprint!=stored.SerialFingerprint{return LicenseStatus{},ErrConflict};if err:=host.requireEnterpriseGeneration(ctx,request.ExpectedGeneration);err!=nil{return LicenseStatus{},err}
	observation,err:=runLicenseAdapter(ctx,"refresh",stored.Mode,nil);status:=LicenseStatus{Mode:stored.Mode,SecretRef:stored.SecretRef,SerialFingerprint:stored.SerialFingerprint,State:observation.State,Limits:observation.Limits,CheckedAt:host.now().UTC(),ExpiresAt:observation.ExpiresAt};status.ReceiptDigest=licenseReceiptDigest(status,request);if err!=nil{return status,err};host.journal.License=status;host.journal.Host.Generation=request.ExpectedGeneration+1;host.journal.Host.Fence=request.Fence;host.journal.Host.UpdatedAt=status.CheckedAt;return status,nil
}

func(host *LinuxLifecycleHost)installPHP(ctx context.Context,input phpInstallInput)(EffectReceipt,error){
	request,plan:=input.Request,input.Plan;receipt:=EffectReceipt{EffectID:request.EffectID,PlanDigest:request.PlanDigest,Generation:request.ExpectedGeneration+1,Fence:request.Fence}
	if validateLicensePHPEffect(request,request.PlanDigest,true)!=nil{return receipt,ErrInvalid};if err:=host.adoptGeneration(ctx,request.ExpectedGeneration);err!=nil{return receipt,err};resolved,paths,err:=authorizePHPPlan(ctx,plan);if err!=nil{return receipt,err};if resolved.CatalogSequence<host.journal.PHPCatalogSequence{return receipt,ErrConflict}
	if err=installLifecyclePackages(ctx,paths);err==nil{err=verifyPHPBinary(ctx,resolved)};receipt.ObservedAt=host.now().UTC();if err!=nil{return receipt,errors.Join(ErrAmbiguous,err)};host.journal.PHPCatalogSequence=resolved.CatalogSequence;receipt.Outcome="confirmed";receipt.EvidenceDigest=digestJSON(resolved);return receipt,nil
}

func(host *LinuxLifecycleHost)applyPHPProfile(ctx context.Context,input phpProfileInput)(EffectReceipt,error){
	request,profile:=input.Request,input.Profile;receipt:=EffectReceipt{EffectID:request.EffectID,PlanDigest:request.PlanDigest,Generation:request.ExpectedGeneration+1,Fence:request.Fence}
	plan,_,err:=authorizePHPPlan(ctx,PHPArtifactPlan{Version:profile.Version,BinaryPathID:profile.BinaryPathID,CatalogDigest:profile.CatalogDigest,CatalogSequence:profile.CatalogSequence,Extensions:profile.Extensions});if err!=nil{return receipt,err}
	expected:=digestJSON(struct{Plan PHPArtifactPlan `json:"plan"`;Profile PHPProfile `json:"profile"`}{plan,profile});if validateLicensePHPEffect(request,expected,true)!=nil||!validPHPProfile(profile,plan){return receipt,ErrInvalid};if err=host.adoptGeneration(ctx,request.ExpectedGeneration);err!=nil{return receipt,err};if plan.CatalogSequence<host.journal.PHPCatalogSequence{return receipt,ErrConflict};if err=installedLifecyclePlan(ctx,ArtifactPlan{Packages:plan.Packages});err==nil{err=verifyPHPBinary(ctx,plan)};if err==nil{err=writePHPProfile(profile)};receipt.ObservedAt=host.now().UTC();if err!=nil{return receipt,errors.Join(ErrAmbiguous,err)}
	copy:=profile;host.journal.PHPProfiles[profile.ID]=profile;host.journal.ActivePHP=&copy;host.journal.PHPCatalogSequence=plan.CatalogSequence;host.journal.Host.Generation=request.ExpectedGeneration+1;host.journal.Host.Fence=request.Fence;host.journal.Host.UpdatedAt=receipt.ObservedAt;receipt.Outcome="confirmed";receipt.EvidenceDigest=digestJSON(profile);return receipt,nil
}

func(host *LinuxLifecycleHost)rollbackPHP(ctx context.Context,input phpRollbackInput)(EffectReceipt,error){
	request:=input.Request;receipt:=EffectReceipt{EffectID:request.EffectID,PlanDigest:request.PlanDigest,Generation:request.ExpectedGeneration+1,Fence:request.Fence,ObservedAt:host.now().UTC()};if validateLicensePHPEffect(request,request.PlanDigest,true)!=nil{return receipt,ErrInvalid}
	var err error;if input.Previous==nil{err=removePHPActiveProfile();host.journal.ActivePHP=nil}else{previous:=*input.Previous;plan,_,resolveErr:=authorizePHPPlan(ctx,PHPArtifactPlan{Version:previous.Version,BinaryPathID:previous.BinaryPathID,CatalogDigest:previous.CatalogDigest,CatalogSequence:previous.CatalogSequence,Extensions:previous.Extensions});if resolveErr!=nil||!validPHPProfile(previous,plan){return receipt,errors.Join(ErrAmbiguous,resolveErr)};if err=verifyPHPBinary(ctx,plan);err==nil{err=writePHPProfile(previous)};if err==nil{copy:=previous;host.journal.PHPProfiles[previous.ID]=previous;host.journal.ActivePHP=&copy}}
	if err!=nil{return receipt,errors.Join(ErrAmbiguous,err)};host.journal.Host.Generation=request.ExpectedGeneration;receipt.Outcome="rolled_back";receipt.EvidenceDigest=digestJSON(input.Previous);return receipt,nil
}

func(host *LinuxLifecycleHost)requireEnterpriseGeneration(ctx context.Context,expected uint64)error{if err:=host.adoptGeneration(ctx,expected);err!=nil{return err};edition,err:=readLifecycleEdition();if err!=nil||edition!=webengine.EditionLiteSpeedEnterprise||host.journal.Host.Plan.Edition!=webengine.EditionLiteSpeedEnterprise{return ErrConflict};return nil}
func validateLicensePHPEffect(request EffectRequest,digest string,authorization bool)error{if !validEffectToken(request.EffectID)||request.ExpectedGeneration==0||request.Fence!=request.ExpectedGeneration+1||!validSHA256(request.PlanDigest)||request.PlanDigest!=digest||authorization&&!validSHA256(request.CommitAuthorizationDigest){return ErrInvalid};return nil}
func licensePHPEffect(request LinuxManagementRequest)(string,error){switch request.Operation{case LinuxManagementLicenseConfigure:var input licenseConfigureInput;if decodeLifecyclePayload(request.Payload,&input)!=nil{return "",ErrInvalid};return input.Request.EffectID,nil;case LinuxManagementLicenseRefresh:var input licenseRefreshInput;if decodeLifecyclePayload(request.Payload,&input)!=nil{return "",ErrInvalid};return input.Request.EffectID,nil;case LinuxManagementPHPInstall:var input phpInstallInput;if decodeLifecyclePayload(request.Payload,&input)!=nil{return "",ErrInvalid};return input.Request.EffectID,nil;case LinuxManagementPHPProfileApply:var input phpProfileInput;if decodeLifecyclePayload(request.Payload,&input)!=nil{return "",ErrInvalid};return input.Request.EffectID,nil;case LinuxManagementPHPRollback:var input phpRollbackInput;if decodeLifecyclePayload(request.Payload,&input)!=nil{return "",ErrInvalid};return input.Request.EffectID,nil;default:return "",ErrUnsupported}}

func readLicenseMaterial(ctx context.Context,reference string)([]byte,error){secretID,err:=secrets.NewID(reference);if err!=nil{return nil,ErrInvalid};owner,err:=secrets.NewID("installation");if err!=nil{return nil,ErrInvalid};resource,err:=secrets.NewID("node-webengine");if err!=nil{return nil,ErrInvalid};client,err:=secrets.NewLocalMaterialClient();if err!=nil{return nil,err};response,err:=client.Read(ctx,secrets.MaterialRequest{SecretID:secretID,OwnerTenantID:owner,Purpose:secrets.PurposeAuthentication,Operation:secrets.OperationAuthenticate,AdapterID:LinuxLicenseSecretAdapterID,AdapterVersion:LinuxLicenseSecretAdapterVersion,ResourceID:resource});if err!=nil{return nil,err};if len(response.Material)==0||len(response.Material)>1<<20{wipeLicenseMaterial(response.Material);return nil,ErrInvalid};return response.Material,nil}
func wipeLicenseMaterial(material []byte){for index:=range material{material[index]=0}}

func runLicenseAdapter(ctx context.Context,action,mode string,material []byte)(localLicenseObservation,error){var observation localLicenseObservation;if ctx==nil||(action!="configure"&&action!="refresh")||(mode!=LicenseModeSerial&&mode!=LicenseModeLicenseKey&&mode!=LicenseModeTrial){return observation,ErrInvalid};info,err:=os.Lstat(lifecycleLicenseAdapterPath);if err!=nil||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0o111==0||info.Mode().Perm()&0o022!=0||!rootOwnedFile(info){return observation,ErrUnsupported};command:=exec.CommandContext(ctx,lifecycleLicenseAdapterPath,action,mode);command.Env=[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","LC_ALL=C.UTF-8"};command.Stdin=bytes.NewReader(material);var output bytes.Buffer;command.Stdout=&output;command.Stderr=io.Discard;if err=command.Run();err!=nil||output.Len()==0||output.Len()>1<<20{return observation,ErrLicense};decoder:=json.NewDecoder(bytes.NewReader(output.Bytes()));decoder.DisallowUnknownFields();if decoder.Decode(&observation)!=nil||decoder.Decode(&struct{}{})!=io.EOF||!validLicenseObservation(observation){return localLicenseObservation{},ErrLicense};return observation,nil}
func validLicenseObservation(value localLicenseObservation)bool{switch value.State{case webengine.LicenseActive,webengine.LicenseTrial,LicenseUnknown,LicenseGrace,LicenseExpired,LicenseRevoked,LicenseInvalid,LicenseOverLimit,LicenseUnavailable:default:return false};if value.Limits.Workers>100000||value.Limits.Domains>10000000||value.Limits.MemoryBytes>1<<50||len(value.Limits.Features)>128{return false};for index,feature:=range value.Limits.Features{if !safeLifecycleToken(feature)||index>0&&value.Limits.Features[index-1]>=feature{return false}};return true}

func authorizePHPPlan(ctx context.Context,requested PHPArtifactPlan)(PHPArtifactPlan,[]string,error){resolved,err:=resolveLocalPHPArtifact(ctx,requested.Version,requested.Extensions,true);if err!=nil{return PHPArtifactPlan{},nil,err};if requested.BinaryPathID!=resolved.BinaryPathID||requested.CatalogDigest!=resolved.CatalogDigest||requested.CatalogSequence!=resolved.CatalogSequence{return PHPArtifactPlan{},nil,ErrConflict};if len(requested.Packages)>0&&digestJSON(requested)!=digestJSON(resolved){return PHPArtifactPlan{},nil,ErrConflict};osName,_,architecture,err:=localPlatformTuple();if err!=nil{return PHPArtifactPlan{},nil,err};paths:=make([]string,0,len(resolved.Packages));for _,item:=range resolved.Packages{path,resolveErr:=resolveLifecyclePackage(ctx,item,resolved.RepositorySnapshotDigest,osName,architecture);if resolveErr!=nil{return PHPArtifactPlan{},nil,resolveErr};paths=append(paths,path)};sort.Strings(paths);return resolved,paths,nil}

func verifyPHPBinary(ctx context.Context,plan PHPArtifactPlan)error{if !validPHPVersion(plan.Version)||plan.BinaryPathID!="lsphp"+strings.ReplaceAll(plan.Version,".",""){return ErrInvalid};path:=filepath.Join("/usr/local/lsws",plan.BinaryPathID,"bin","lsphp");if filepath.Clean(path)!=path{return ErrInvalid};info,err:=os.Lstat(path);if err!=nil||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0o111==0||info.Mode().Perm()&0o022!=0||!rootOwnedFile(info){return ErrAmbiguous};command:=exec.CommandContext(ctx,path,"-v");command.Env=[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","LC_ALL=C.UTF-8"};output,err:=command.Output();if err!=nil||len(output)==0||len(output)>1<<20||!strings.HasPrefix(strings.TrimSpace(string(output)),"PHP "+plan.Version+"."){return ErrAmbiguous};return nil}

func ensurePHPProfileDirectory()error{if err:=os.Mkdir(lifecyclePHPProfileRoot,0o700);err!=nil&&!errors.Is(err,fs.ErrExist){return err};info,err:=os.Lstat(lifecyclePHPProfileRoot);if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=0o700||!rootOwnedFile(info){return ErrInvalid};real,err:=filepath.EvalSymlinks(lifecyclePHPProfileRoot);if err!=nil||real!=lifecyclePHPProfileRoot{return ErrInvalid};return nil}
func writePHPProfile(profile PHPProfile)error{content,err:=json.Marshal(profile);if err!=nil||len(content)==0||len(content)>1<<20{return ErrInvalid};if err=atomicPHPFile(filepath.Join(lifecyclePHPProfileRoot,profile.ID+".json"),content);err!=nil{return err};return atomicPHPFile(lifecyclePHPActivePath,content)}
func atomicPHPFile(path string,content []byte)error{if filepath.Dir(path)!=lifecycleStateRoot&&filepath.Dir(path)!=lifecyclePHPProfileRoot{return ErrInvalid};temporary:=path+".new";_ = os.Remove(temporary);file,err:=os.OpenFile(temporary,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0o600);if err!=nil{return err};written,writeErr:=file.Write(content);syncErr:=file.Sync();closeErr:=file.Close();if writeErr!=nil||syncErr!=nil||closeErr!=nil||written!=len(content){_ = os.Remove(temporary);return errors.Join(writeErr,syncErr,closeErr)};if err=os.Rename(temporary,path);err!=nil{_ = os.Remove(temporary);return err};directory,err:=os.Open(filepath.Dir(path));if err!=nil{return err};err=directory.Sync();return errors.Join(err,directory.Close())}
func removePHPActiveProfile()error{err:=os.Remove(lifecyclePHPActivePath);if errors.Is(err,fs.ErrNotExist){return nil};if err!=nil{return err};directory,err:=os.Open(lifecycleStateRoot);if err!=nil{return err};err=directory.Sync();return errors.Join(err,directory.Close())}

func(host *LinuxLifecycleHost)inspect(ctx context.Context,edition webengine.Edition)(Installation,error){return host.inspectState(ctx,edition,true)}
func(host *LinuxLifecycleHost)inspectState(ctx context.Context,edition webengine.Edition,requireRunning bool)(Installation,error){
	if host.conversionPending(){return Installation{},ErrAmbiguous}
	if edition!=webengine.EditionOpenLiteSpeed&&edition!=webengine.EditionLiteSpeedEnterprise{return Installation{},ErrInvalid}
	if host.journal.Host.Generation>0&&!host.journal.Host.Active{return Installation{},ErrNotFound}
	plan,channel,err:=host.activePlan(ctx,edition,false);if err!=nil{return Installation{},err}
	if requireRunning {err=verifyLifecycleService(ctx,plan)}else{err=verifyLifecycleInstallation(ctx,plan)};if err!=nil{return Installation{},err}
	observed:=host.journal.Host
	if !observed.Active{observed.Active=true;observed.Plan=plan;observed.Channel=channel;observed.ConfigDigest=currentLifecycleConfig(ctx,edition);observed.UpdatedAt=host.now().UTC()}
	updated:=observed.UpdatedAt;if updated.IsZero(){updated=host.now().UTC()}
	actual:=currentLifecycleConfig(ctx,edition);if !validSHA256(actual){return Installation{},ErrAmbiguous}
	installation:=Installation{ID:"node-webengine",Edition:plan.Edition,Version:plan.Version,ArtifactDigest:plan.ArtifactDigest,RepositorySnapshotDigest:plan.RepositorySnapshotDigest,Channel:channel,State:StateActive,License:host.journal.License,Generation:observed.Generation,ActiveConfigDigest:actual,InstalledAt:updated,UpdatedAt:updated}
	if record:=host.journal.Conversion;record!=nil&&validConversionRecord(record)&&validConversionReceipt(record.Receipt)&&record.Receipt.EvidenceDigest==conversionEvidence(record)&&record.Receipt.Fence==installation.Generation{
		bound:=record.Receipt.TargetConfigDigest;if record.Receipt.Restored{bound=record.Receipt.PreviousConfigDigest}
		if bound==actual{copy:=record.Receipt;installation.Transition=&copy}
	}
	return installation,nil
}

func(host *LinuxLifecycleHost)install(ctx context.Context,input lifecyclePlanInput,upgrade bool)(EffectReceipt,error){
	catalogValue,catalogErr:=readLocalArtifactCatalog(true);if catalogErr!=nil{return EffectReceipt{},catalogErr};if catalogErr=host.validateEngineCatalog(catalogValue);catalogErr!=nil{return EffectReceipt{},catalogErr}
	request,plan:=input.Request,input.Plan;receipt:=EffectReceipt{EffectID:request.EffectID,PlanDigest:request.PlanDigest,Generation:request.ExpectedGeneration+1,Fence:request.Fence}
	if validateLifecycleEffect(request,digestJSON(plan))!=nil||validateArtifactPlan(plan)!=nil{return receipt,ErrInvalid};pinned,channel,err:=pinConversionPlan(ctx,catalogValue,plan,"");if err!=nil{return receipt,err};var paths []string;for _,item:=range pinned{paths=append(paths,item.Path)};sort.Strings(paths)
	if err=host.adoptGeneration(ctx,request.ExpectedGeneration);err!=nil{return receipt,err}
	if err=host.rememberEngineCatalog(catalogValue);err!=nil{return receipt,err}
	previous:=host.journal.Host
	if upgrade{if !previous.Active||previous.Plan.Edition!=plan.Edition{return receipt,ErrConflict};if previous.Plan.ArtifactDigest==plan.ArtifactDigest&&previous.Plan.Version==plan.Version{receipt.Outcome="confirmed";receipt.EvidenceDigest=lifecycleEvidence(plan,previous.ConfigDigest);receipt.ObservedAt=host.now().UTC();return receipt,nil}}else if previous.Active{return receipt,ErrConflict}
	if previous.Active{if err=runLifecycle(ctx,"/usr/bin/systemctl","stop",lifecycleService);err!=nil{return receipt,ErrAmbiguous}}
	if err=installLifecyclePackages(ctx,paths);err==nil{err=writeLifecycleEdition(plan.Edition)};if err==nil{err=runLifecycle(ctx,"/usr/bin/systemctl","restart",lifecycleService)};if err==nil{err=verifyLifecycleService(ctx,plan)}
	if err!=nil{if !previous.Active{_ = removeLifecyclePackages(ctx,plan)};restored:=host.restorePlan(ctx,previous);receipt.ObservedAt=host.now().UTC();if restored==nil{receipt.Outcome="rolled_back";receipt.EvidenceDigest=lifecycleEvidence(previous.Plan,previous.ConfigDigest);return receipt,ErrInvalid};return receipt,errors.Join(ErrAmbiguous,err,restored)}
	host.journal.Host=lifecycleHostState{Active:true,Generation:request.ExpectedGeneration+1,Fence:request.Fence,Channel:channel,Plan:plan,ConfigDigest:previous.ConfigDigest,UpdatedAt:host.now().UTC()};receipt.Outcome="confirmed";receipt.EvidenceDigest=lifecycleEvidence(plan,host.journal.Host.ConfigDigest);receipt.ObservedAt=host.now().UTC();return receipt,nil
}

func(host *LinuxLifecycleHost)convert(ctx context.Context,input lifecycleConvertInput)(SwitchReceipt,error){
	return host.convertEdition(ctx,input)
}

func(host *LinuxLifecycleHost)remove(ctx context.Context,input lifecycleRemoveInput)(EffectReceipt,error){
	request:=input.Request;receipt:=EffectReceipt{EffectID:request.EffectID,PlanDigest:request.PlanDigest,Generation:request.ExpectedGeneration+1,Fence:request.Fence}
	if err:=host.adoptGeneration(ctx,request.ExpectedGeneration);err!=nil{return receipt,err};expected:=digestJSON(struct{Edition webengine.Edition;ArtifactDigest string}{input.Edition,host.journal.Host.Plan.ArtifactDigest});if validateLifecycleEffect(request,expected)!=nil{return receipt,ErrInvalid};previous:=host.journal.Host;if !previous.Active||previous.Plan.Edition!=input.Edition{return receipt,ErrConflict}
	err:=runLifecycle(ctx,"/usr/bin/systemctl","stop",lifecycleService);if err==nil{err=removeLifecyclePackages(ctx,previous.Plan)};if err==nil{err=verifyLifecycleRemoved(ctx,previous.Plan)}
	if err!=nil{rollbackErr:=host.restorePlan(ctx,previous);receipt.ObservedAt=host.now().UTC();if rollbackErr==nil{receipt.Outcome="rolled_back";receipt.EvidenceDigest=lifecycleEvidence(previous.Plan,previous.ConfigDigest);return receipt,ErrInvalid};return receipt,errors.Join(ErrAmbiguous,err,rollbackErr)}
	host.journal.Host=lifecycleHostState{Active:false,Generation:request.ExpectedGeneration+1,Fence:request.Fence,Channel:previous.Channel,Plan:previous.Plan,ConfigDigest:"",UpdatedAt:host.now().UTC()};receipt.Outcome="confirmed";receipt.EvidenceDigest=lifecycleEvidence(previous.Plan,"removed");receipt.ObservedAt=host.now().UTC();return receipt,nil
}

func(host *LinuxLifecycleHost)adoptGeneration(ctx context.Context,expected uint64)error{if host.journal.Host.Generation==0{edition,err:=readLifecycleEdition();if err==nil{plan,channel,discoverErr:=host.activePlan(ctx,edition,true);if discoverErr==nil{host.journal.Host.Active,host.journal.Host.Plan,host.journal.Host.Channel=true,plan,channel;host.journal.Host.ConfigDigest=currentLifecycleConfig(ctx,edition)}};host.journal.Host.Generation=expected};if host.journal.Host.Generation!=expected{return ErrConflict};return nil}
func(host *LinuxLifecycleHost)activePlan(ctx context.Context,edition webengine.Edition,remember bool)(ArtifactPlan,Channel,error){current,err:=readLifecycleEdition();if err!=nil||current!=edition{return ArtifactPlan{},"",ErrNotFound};if host.journal.Host.Active&&host.journal.Host.Plan.Edition==edition&&validateArtifactPlan(host.journal.Host.Plan)==nil{if installedLifecyclePlan(ctx,host.journal.Host.Plan)==nil{return host.journal.Host.Plan,host.journal.Host.Channel,nil}};catalog,err:=readLocalArtifactCatalog(true);if err!=nil{return ArtifactPlan{},"",err};if err=host.validateEngineCatalog(catalog);err!=nil{return ArtifactPlan{},"",err};osName,osVersion,architecture,err:=localPlatformTuple();if err!=nil{return ArtifactPlan{},"",err};var plan ArtifactPlan;var channel Channel;for _,entry:=range catalog.Entries{if entry.OS!=osName||entry.OSVersion!=osVersion||entry.Architecture!=architecture||entry.Plan.Edition!=edition||installedLifecyclePlan(ctx,entry.Plan)!=nil{continue};if plan.Version!=""{return ArtifactPlan{},"",ErrConflict};plan,channel=entry.Plan,entry.Channel};if plan.Version==""{return ArtifactPlan{},"",ErrUnsupported};if remember{if err=host.rememberEngineCatalog(catalog);err!=nil{return ArtifactPlan{},"",err}};return plan,channel,nil}

func(host *LinuxLifecycleHost)restorePlan(ctx context.Context,state lifecycleHostState)error{if !state.Active{return runLifecycle(ctx,"/usr/bin/systemctl","stop",lifecycleService)};_,paths,err:=authorizeLifecyclePlan(ctx,state.Plan);if err!=nil{return err};if err=installLifecyclePackages(ctx,paths);err==nil{err=writeLifecycleEdition(state.Plan.Edition)};if err==nil{err=runLifecycle(ctx,"/usr/bin/systemctl","restart",lifecycleService)};if err==nil{err=verifyLifecycleService(ctx,state.Plan)};if err==nil{host.journal.Host=state};return err}

type lifecycleRepositoryRecord struct{SchemaVersion uint32 `json:"schema_version"`;ID string `json:"id"`;SnapshotDigest string `json:"snapshot_digest"`;Packages []lifecycleRepositoryPackage `json:"packages"`}
type lifecycleRepositoryPackage struct{Name,Version,Digest,Path string}

func authorizeLifecyclePlan(ctx context.Context,plan ArtifactPlan)(Channel,[]string,error){catalog,err:=readLocalArtifactCatalog(true);if err!=nil{return "",nil,err};osName,osVersion,architecture,err:=localPlatformTuple();if err!=nil{return "",nil,err};matches:=0;channel:=Channel("");wanted:=digestJSON(plan);for _,entry:=range catalog.Entries{if entry.OS==osName&&entry.OSVersion==osVersion&&entry.Architecture==architecture&&digestJSON(entry.Plan)==wanted{matches++;channel=entry.Channel}};if matches!=1{return "",nil,ErrConflict};paths:=make([]string,0,len(plan.Packages));for _,item:=range plan.Packages{path,resolveErr:=resolveLifecyclePackage(ctx,item,plan.RepositorySnapshotDigest,osName,architecture);if resolveErr!=nil{return "",nil,resolveErr};paths=append(paths,path)};sort.Strings(paths);return channel,paths,nil}
func resolveLifecyclePackage(ctx context.Context,item PackageArtifact,snapshot,osName,architecture string)(string,error){path:=filepath.Join(lifecycleRepositoryRoot,item.RepositoryID+".json");content,err:=readCatalogFile(path,4<<20,true);if err!=nil{return "",err};var record lifecycleRepositoryRecord;if decodeLifecyclePayload(content,&record)!=nil||record.SchemaVersion!=1||record.ID!=item.RepositoryID||record.SnapshotDigest!=snapshot||len(record.Packages)==0||len(record.Packages)>128{return "",ErrInvalid};var selected string;for _,candidate:=range record.Packages{if candidate.Name!=item.Name||candidate.Version!=item.Version||candidate.Digest!=item.Digest{continue};if selected!=""{return "",ErrConflict};selected=candidate.Path};if selected==""||!filepath.IsAbs(selected)||filepath.Clean(selected)!=selected||!strings.HasPrefix(selected,lifecyclePackageRoot+string(os.PathSeparator)){return "",ErrInvalid};info,err:=os.Lstat(selected);if err!=nil||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0o022!=0||!rootOwnedFile(info)||info.Size()<=0||info.Size()>16<<30{return "",ErrInvalid};file,err:=os.Open(selected);if err!=nil{return "",err};hash:=sha256.New();_,copyErr:=io.Copy(hash,io.LimitReader(file,16<<30+1));closeErr:=file.Close();if copyErr!=nil||closeErr!=nil{return "",errors.Join(copyErr,closeErr)};if hex.EncodeToString(hash.Sum(nil))!=item.Digest{return "",ErrConflict};if err=verifyLifecyclePackageMetadata(ctx,selected,item,osName,architecture);err!=nil{return "",err};return selected,nil}

func verifyLifecyclePackageMetadata(ctx context.Context,path string,item PackageArtifact,osName,architecture string)error{if osName=="ubuntu"{name,err:=runLifecycleOutput(ctx,"/usr/bin/dpkg-deb","--field",path,"Package");if err!=nil||strings.TrimSpace(name)!=item.Name{return ErrConflict};version,err:=runLifecycleOutput(ctx,"/usr/bin/dpkg-deb","--field",path,"Version");if err!=nil||strings.TrimSpace(version)!=item.Version{return ErrConflict};arch,err:=runLifecycleOutput(ctx,"/usr/bin/dpkg-deb","--field",path,"Architecture");expected:=architecture;if expected=="arm64"{expected="arm64"};if err!=nil||strings.TrimSpace(arch)!=expected{return ErrUnsupported};return nil};output,err:=runLifecycleOutput(ctx,"/usr/bin/rpm","-qp","--qf","%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}\n",path);if err!=nil{return err};lines:=strings.Split(strings.TrimSpace(output),"\n");expected:="x86_64";if architecture=="arm64"{expected="aarch64"};if len(lines)!=3||lines[0]!=item.Name||lines[1]!=item.Version||lines[2]!=expected{return ErrConflict};return nil}
func installLifecyclePackages(ctx context.Context,paths []string)error{osName,_,_,err:=localPlatformTuple();if err!=nil{return err};if osName=="ubuntu"{arguments:=append([]string{"--install"},paths...);return runLifecycle(ctx,"/usr/bin/dpkg",arguments...)};arguments:=append([]string{"-Uvh","--replacepkgs","--oldpackage"},paths...);return runLifecycle(ctx,"/usr/bin/rpm",arguments...)}
func removeLifecyclePackages(ctx context.Context,plan ArtifactPlan)error{names:=make([]string,0,len(plan.Packages));for _,item:=range plan.Packages{names=append(names,item.Name)};sort.Strings(names);osName,_,_,err:=localPlatformTuple();if err!=nil{return err};if osName=="ubuntu"{arguments:=append([]string{"--remove"},names...);return runLifecycle(ctx,"/usr/bin/dpkg",arguments...)};arguments:=append([]string{"-e"},names...);return runLifecycle(ctx,"/usr/bin/rpm",arguments...)}
func installedLifecyclePlan(ctx context.Context,plan ArtifactPlan)error{osName,_,architecture,err:=localPlatformTuple();if err!=nil{return err};for _,item:=range plan.Packages{if osName=="ubuntu"{output,queryErr:=runLifecycleOutput(ctx,"/usr/bin/dpkg-query","-W","-f=${Status}\n${Version}\n${Architecture}\n",item.Name);lines:=strings.Split(strings.TrimSpace(output),"\n");if queryErr!=nil||len(lines)!=3||lines[0]!="install ok installed"||lines[1]!=item.Version||lines[2]!=architecture{return ErrNotFound}}else{output,queryErr:=runLifecycleOutput(ctx,"/usr/bin/rpm","-q","--qf","%{VERSION}-%{RELEASE}\n%{ARCH}\n",item.Name);lines:=strings.Split(strings.TrimSpace(output),"\n");expected:="x86_64";if architecture=="arm64"{expected="aarch64"};if queryErr!=nil||len(lines)!=2||lines[0]!=item.Version||lines[1]!=expected{return ErrNotFound}}};return nil}
func verifyLifecycleInstallation(ctx context.Context,plan ArtifactPlan)error{if err:=validateArtifactPlan(plan);err!=nil{return err};if err:=installedLifecyclePlan(ctx,plan);err!=nil{return err};return trustedLifecycleProgram(lifecycleBinaryPath)}
func verifyLifecycleService(ctx context.Context,plan ArtifactPlan)error{if err:=verifyLifecycleInstallation(ctx,plan);err!=nil{return err};return runLifecycle(ctx,"/usr/bin/systemctl","is-active","--quiet",lifecycleService)}
func verifyLifecycleRemoved(ctx context.Context,plan ArtifactPlan)error{if installedLifecyclePlan(ctx,plan)==nil{return ErrAmbiguous};if runLifecycle(ctx,"/usr/bin/systemctl","is-active","--quiet",lifecycleService)==nil{return ErrAmbiguous};return nil}

func currentLifecycleConfig(ctx context.Context,edition webengine.Edition)string{store,err:=fsstore.New(lifecycleConfigurationRoot,edition);if err!=nil{return ""};defer store.Close();receipt,err:=store.Current(ctx);if err!=nil{return ""};return receipt.Digest}
func writeLifecycleEdition(edition webengine.Edition)error{if edition!=webengine.EditionOpenLiteSpeed&&edition!=webengine.EditionLiteSpeedEnterprise{return ErrInvalid};temporary:=lifecycleEditionPath+".new";_ = os.Remove(temporary);file,err:=os.OpenFile(temporary,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0o644);if err!=nil{return err};content:=[]byte(string(edition)+"\n");written,writeErr:=file.Write(content);syncErr:=file.Sync();closeErr:=file.Close();if writeErr!=nil||syncErr!=nil||closeErr!=nil||written!=len(content){_ = os.Remove(temporary);return errors.Join(writeErr,syncErr,closeErr)};if err=os.Rename(temporary,lifecycleEditionPath);err!=nil{_ = os.Remove(temporary);return err};directory,err:=os.Open(filepath.Dir(lifecycleEditionPath));if err!=nil{return err};err=directory.Sync();return errors.Join(err,directory.Close())}

func validateLifecycleEffect(request EffectRequest,digest string)error{if !validEffectToken(request.EffectID)||request.Fence!=request.ExpectedGeneration+1||request.PlanDigest!=digest||!validSHA256(request.PlanDigest)||!validSHA256(request.CommitAuthorizationDigest){return ErrInvalid};return nil}
func lifecycleEffect(request LinuxManagementRequest)(string,error){switch request.Operation{case LinuxManagementInstall,LinuxManagementUpgrade:var input lifecyclePlanInput;if decodeLifecyclePayload(request.Payload,&input)!=nil{return "",ErrInvalid};return input.Request.EffectID,nil;case LinuxManagementConvert:var input lifecycleConvertInput;if decodeLifecyclePayload(request.Payload,&input)!=nil{return "",ErrInvalid};return input.Request.EffectID,nil;case LinuxManagementRemove:var input lifecycleRemoveInput;if decodeLifecyclePayload(request.Payload,&input)!=nil{return "",ErrInvalid};return input.Request.EffectID,nil;default:return "",ErrUnsupported}}
func nativeGeneration(value native.ConfigGeneration)(native.ConfigGeneration,error){rebuilt,err:=native.NewCompleteGeneration(value.Edition,value.DesiredDigest,value.SnapshotGeneration,value.Artifacts);if err!=nil||rebuilt.Kind!=value.Kind||rebuilt.ContentDigest!=value.ContentDigest{return native.ConfigGeneration{},ErrInvalid};return rebuilt,nil}
func lifecycleEvidence(plan ArtifactPlan,config string)string{return digestJSON(struct{Plan ArtifactPlan;Config string}{plan,config})}
func decodeLifecyclePayload(content []byte,target any)error{decoder:=json.NewDecoder(bytes.NewReader(content));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{return err};if decoder.Decode(&struct{}{})!=io.EOF{return ErrInvalid};return nil}

func runLifecycle(ctx context.Context,program string,arguments ...string)error{_,err:=runLifecycleOutput(ctx,program,arguments...);return err}
func runLifecycleOutput(ctx context.Context,program string,arguments ...string)(string,error){allowed:=map[string]bool{"/usr/bin/systemctl":true,"/usr/bin/dpkg":true,"/usr/bin/dpkg-deb":true,"/usr/bin/dpkg-query":true,"/usr/bin/rpm":true,lifecycleBinaryPath:true};if ctx==nil||!allowed[program]{return "",ErrUnsupported};command:=exec.CommandContext(ctx,program,arguments...);command.Env=[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","LC_ALL=C.UTF-8","DEBIAN_FRONTEND=noninteractive"};output,err:=command.CombinedOutput();if len(output)>1<<20{output=output[:1<<20]};if err!=nil{return string(output),fmt.Errorf("%s: %w",filepath.Base(program),err)};return string(output),nil}

type LinuxManagementPeerPolicy struct{controlUID uint32}
func NewLinuxManagementPeerPolicy(controlUID uint32)(*LinuxManagementPeerPolicy,error){if controlUID==0{return nil,ErrInvalid};return &LinuxManagementPeerPolicy{controlUID},nil}
func(policy *LinuxManagementPeerPolicy)Authorize(connection net.Conn)error{unix,ok:=connection.(*net.UnixConn);if !ok||policy==nil{return ErrInvalid};raw,err:=unix.SyscallConn();if err!=nil{return ErrInvalid};var credential *syscall.Ucred;var peerErr error;err=raw.Control(func(fd uintptr){credential,peerErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)});if err!=nil||peerErr!=nil||credential==nil||credential.Pid<=1||credential.Uid!=policy.controlUID{return ErrInvalid};return nil}
func ListenLinuxManagementBroker(controlGID uint32)(*net.UnixListener,error){if os.Geteuid()!=0||controlGID==0{return nil,ErrInvalid};info,err:=os.Lstat("/run/cyberpanel");if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=0o711{return nil,ErrInvalid};if info,err=os.Lstat(LinuxManagementSocketPath);err==nil{if info.Mode()&os.ModeSocket==0{return nil,ErrInvalid};if err=os.Remove(LinuxManagementSocketPath);err!=nil{return nil,err}}else if !errors.Is(err,fs.ErrNotExist){return nil,err};listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:LinuxManagementSocketPath,Net:"unix"});if err!=nil{return nil,err};if err=os.Chown(LinuxManagementSocketPath,0,int(controlGID));err==nil{err=os.Chmod(LinuxManagementSocketPath,0o660)};if err!=nil{listener.Close();return nil,err};return listener,nil}

func ensureLifecycleDirectory(path string,mode fs.FileMode)error{if path!=lifecycleStateRoot&&path!=lifecyclePackageRoot{return ErrInvalid};if err:=os.Mkdir(path,mode);err!=nil&&!errors.Is(err,fs.ErrExist){return err};info,err:=os.Lstat(path);if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=mode||!rootOwnedFile(info){return ErrInvalid};real,err:=filepath.EvalSymlinks(path);if err!=nil||real!=path{return ErrInvalid};return nil}
func(host *LinuxLifecycleHost)load()error{path:=filepath.Join(lifecycleStateRoot,lifecycleStateFile);info,err:=os.Lstat(path);if errors.Is(err,fs.ErrNotExist){return nil};if err!=nil||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()!=0o600||!rootOwnedFile(info)||info.Size()<=0||info.Size()>lifecycleMaximumStateBytes{return ErrInvalid};content,err:=os.ReadFile(path);if err!=nil{return err};var journal lifecycleJournal;if decodeLifecyclePayload(content,&journal)!=nil||journal.Version!=1||journal.Effects==nil||len(journal.Effects)>2048{return ErrInvalid};if journal.PHPProfiles==nil{journal.PHPProfiles=map[string]PHPProfile{}};host.journal=journal;return nil}
func(host *LinuxLifecycleHost)persist()error{content,err:=json.Marshal(host.journal);if err!=nil||len(content)==0||len(content)>lifecycleMaximumStateBytes{return ErrInvalid};temporary:=filepath.Join(lifecycleStateRoot,lifecycleStateTemporary);target:=filepath.Join(lifecycleStateRoot,lifecycleStateFile);_ = os.Remove(temporary);file,err:=os.OpenFile(temporary,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0o600);if err!=nil{return err};written,writeErr:=file.Write(content);syncErr:=file.Sync();closeErr:=file.Close();if writeErr!=nil||syncErr!=nil||closeErr!=nil||written!=len(content){_ = os.Remove(temporary);return errors.Join(writeErr,syncErr,closeErr)};if err=os.Rename(temporary,target);err!=nil{_ = os.Remove(temporary);return err};directory,err:=os.Open(lifecycleStateRoot);if err!=nil{return err};err=directory.Sync();return errors.Join(err,directory.Close())}
func(host *LinuxLifecycleHost)prune(){if len(host.journal.Effects)<2048{return};completed:=make([]lifecycleEffectRecord,0,len(host.journal.Effects));for _,record:=range host.journal.Effects{if record.State=="completed"{completed=append(completed,record)}};sort.Slice(completed,func(left,right int)bool{return completed[left].CompletedAt.Before(completed[right].CompletedAt)});remove:=len(host.journal.Effects)-2047;for index:=0;index<remove&&index<len(completed);index++{delete(host.journal.Effects,completed[index].Key)}}

var _ LinuxManagementBrokerHandler = (*LinuxLifecycleHost)(nil)
var _ LinuxLicensePHPBrokerHandler = (*LinuxLifecycleHost)(nil)
