//go:build linux

package apps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

const (
	LinuxApplicationSocketPath = "/run/cyberpanel/applications.sock"
	linuxApplicationFrameLimit = 64 << 20
)

type linuxApplicationOperation string

const (
	applicationInstall linuxApplicationOperation = "install"
	applicationDiscover linuxApplicationOperation = "discover"
	applicationAdopt linuxApplicationOperation = "adopt"
	applicationInspect linuxApplicationOperation = "inspect"
	applicationRepair linuxApplicationOperation = "repair"
	applicationPrepareUpdate linuxApplicationOperation = "prepare_update"
	applicationApplyUpdate linuxApplicationOperation = "apply_update"
	applicationProbeUpdate linuxApplicationOperation = "probe_update"
	applicationPromote linuxApplicationOperation = "promote"
	applicationRollback linuxApplicationOperation = "rollback"
	applicationQuarantine linuxApplicationOperation = "quarantine"
	applicationRemove linuxApplicationOperation = "remove"
	applicationWPCLI linuxApplicationOperation = "wp_cli"
	applicationWPComponent linuxApplicationOperation = "wordpress_component"
	applicationWPSettings linuxApplicationOperation = "wordpress_settings"
	applicationLSCacheConfigure linuxApplicationOperation = "lscache_configure"
	applicationLSCachePurge linuxApplicationOperation = "lscache_purge"
	applicationAutologinInstall linuxApplicationOperation = "autologin_install"
	applicationAutologinRemove linuxApplicationOperation = "autologin_remove"
	applicationRouteCreate linuxApplicationOperation = "route_create"
	applicationRouteRemove linuxApplicationOperation = "route_remove"
	applicationRouteActivate linuxApplicationOperation = "route_activate"
	applicationRouteRestore linuxApplicationOperation = "route_restore"
	applicationSnapshotCreate linuxApplicationOperation = "snapshot_create"
	applicationSnapshotVerify linuxApplicationOperation = "snapshot_verify"
	applicationSnapshotRelease linuxApplicationOperation = "snapshot_release"
	applicationRecoveryCreate linuxApplicationOperation = "recovery_create"
	applicationRecoveryVerify linuxApplicationOperation = "recovery_verify"
	applicationCloneCreate linuxApplicationOperation = "clone_create"
	applicationCloneProbe linuxApplicationOperation = "clone_probe"
	applicationSyncApply linuxApplicationOperation = "staging_sync_apply"
	applicationSyncRewrite linuxApplicationOperation = "staging_sync_rewrite"
	applicationSyncProbe linuxApplicationOperation = "staging_sync_probe"
	applicationSyncRollback linuxApplicationOperation = "staging_sync_rollback"
	applicationCloneDelete linuxApplicationOperation = "clone_delete"
	applicationResolveScope linuxApplicationOperation = "resolve_scope"
	applicationResolveSite linuxApplicationOperation = "resolve_site"
	applicationSecurityScan linuxApplicationOperation = "security_scan"
	applicationRemediationApply linuxApplicationOperation = "security_remediation_apply"
	applicationRemediationRollback linuxApplicationOperation = "security_remediation_rollback"
)

type linuxApplicationRequest struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	Operation linuxApplicationOperation `json:"operation"`
	SiteID SiteID `json:"site_id"`
	Deadline time.Time `json:"deadline"`
	Payload json.RawMessage `json:"payload"`
	PayloadDigest string `json:"payload_digest"`
}

type linuxApplicationResponse struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	Operation linuxApplicationOperation `json:"operation"`
	Succeeded bool `json:"succeeded"`
	Payload json.RawMessage `json:"payload,omitempty"`
	PayloadDigest string `json:"payload_digest,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}

type LinuxApplicationClient struct{}

func NewLocalLinuxApplicationClient() (*LinuxApplicationClient,error) {
	info,err:=os.Lstat(LinuxApplicationSocketPath)
	if err!=nil{return nil,err}
	if info.Mode()&os.ModeSocket==0||info.Mode().Perm()&0002!=0{return nil,ErrPolicyDenied}
	return &LinuxApplicationClient{},nil
}

func (client *LinuxApplicationClient) call(ctx context.Context,operation linuxApplicationOperation,site SiteID,input,output any) error {
	if client==nil||ctx==nil{return ErrInvalid}
	payload,err:=json.Marshal(input);if err!=nil||len(payload)>linuxApplicationFrameLimit{return ErrInvalid}
	digest:=linuxApplicationDigest(payload)
	deadline:=time.Now().UTC().Add(2*time.Hour);if value,ok:=ctx.Deadline();ok&&value.Before(deadline){deadline=value.UTC()}
	request:=linuxApplicationRequest{Version:1,RequestID:"app-"+digest[:40],Operation:operation,SiteID:site,Deadline:deadline,Payload:payload,PayloadDigest:digest}
	connection,err:=(&net.Dialer{}).DialContext(ctx,"unix",LinuxApplicationSocketPath);if err!=nil{return err};defer connection.Close()
	stop:=context.AfterFunc(ctx,func(){_ = connection.SetDeadline(time.Now())});defer stop();_ = connection.SetDeadline(deadline)
	if err=writeLinuxApplicationFrame(connection,request);err!=nil{return err}
	var response linuxApplicationResponse;if err=readLinuxApplicationFrame(connection,&response);err!=nil{return err}
	if response.Version!=1||response.RequestID!=request.RequestID||response.Operation!=operation||response.CompletedAt.IsZero(){return ErrIntegrity}
	if !response.Succeeded{return linuxApplicationFailure(response.ErrorCode)}
	if response.PayloadDigest!=linuxApplicationDigest(response.Payload){return ErrIntegrity}
	if output==nil{return nil}
	decoder:=json.NewDecoder(bytes.NewReader(response.Payload));decoder.DisallowUnknownFields();if err=decoder.Decode(output);err!=nil||decoder.Decode(&struct{}{})!=io.EOF{return ErrIntegrity};return nil
}

type inspectResult struct{Inventory ComponentInventory `json:"inventory"`;Health HealthObservation `json:"health"`;Receipt ExecutionReceipt `json:"receipt"`}
type discoverResult struct{Candidates []DiscoveryCandidate `json:"candidates"`;Receipt ExecutionReceipt `json:"receipt"`}
type wpComponentResult struct{Inventory ComponentInventory `json:"inventory"`;Receipt ExecutionReceipt `json:"receipt"`}
type wpSettingsResult struct{Settings WordPressSettings `json:"settings"`;Receipt ExecutionReceipt `json:"receipt"`}
type lsCacheResult struct{Policy LSCachePolicy `json:"policy"`;Receipt ExecutionReceipt `json:"receipt"`}
type applicationRouteRequest struct{SiteID SiteID `json:"site_id"`;InstallationID InstallationID `json:"installation_id"`;ReleaseID ReleaseID `json:"release_id"`;Shadow string `json:"shadow,omitempty"`}
type applicationRecoveryInput struct{Request RecoveryRequest `json:"request"`;Installation ApplicationInstallation `json:"installation"`}
type applicationRecoveryOutput struct{ID RecoveryPointID `json:"id"`;Frontier uint64 `json:"frontier"`}
type applicationStagingHealthResult struct{Health HealthObservation `json:"health"`;Receipt ExecutionReceipt `json:"receipt"`}

func(c *LinuxApplicationClient)Install(ctx context.Context,v InstallExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationInstall,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)Discover(ctx context.Context,v DiscoveryExecution)([]DiscoveryCandidate,ExecutionReceipt,error){var o discoverResult;e:=c.call(ctx,applicationDiscover,v.Scope.SiteID,v,&o);return o.Candidates,o.Receipt,e}
func(c *LinuxApplicationClient)Adopt(ctx context.Context,v AdoptExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationAdopt,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)Inspect(ctx context.Context,v InspectExecution)(ComponentInventory,HealthObservation,ExecutionReceipt,error){var o inspectResult;e:=c.call(ctx,applicationInspect,v.Scope.SiteID,v,&o);return o.Inventory,o.Health,o.Receipt,e}
func(c *LinuxApplicationClient)Repair(ctx context.Context,v RepairExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationRepair,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)PrepareUpdate(ctx context.Context,v UpdateExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationPrepareUpdate,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)ApplyUpdate(ctx context.Context,v UpdateExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationApplyUpdate,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)ProbeUpdate(ctx context.Context,v UpdateExecution)(HealthObservation,ExecutionReceipt,error){var o struct{Health HealthObservation `json:"health"`;Receipt ExecutionReceipt `json:"receipt"`};e:=c.call(ctx,applicationProbeUpdate,v.Scope.SiteID,v,&o);return o.Health,o.Receipt,e}
func(c *LinuxApplicationClient)Promote(ctx context.Context,v PromotionExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationPromote,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)Rollback(ctx context.Context,v PromotionExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationRollback,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)Quarantine(ctx context.Context,v RemovalExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationQuarantine,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)Remove(ctx context.Context,v RemovalExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationRemove,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)InvokeWPCLI(ctx context.Context,v WPCLIInvocation)(o WPCLIResult,e error){e=c.call(ctx,applicationWPCLI,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)MutateComponent(ctx context.Context,v ComponentMutation)(ComponentInventory,ExecutionReceipt,error){var o wpComponentResult;e:=c.call(ctx,applicationWPComponent,v.Scope.SiteID,v,&o);return o.Inventory,o.Receipt,e}
func(c *LinuxApplicationClient)ApplySettings(ctx context.Context,v WordPressSettingsMutation)(WordPressSettings,ExecutionReceipt,error){var o wpSettingsResult;e:=c.call(ctx,applicationWPSettings,v.Scope.SiteID,v,&o);return o.Settings,o.Receipt,e}
func(c *LinuxApplicationClient)ConfigureLSCache(ctx context.Context,v CacheMutation)(LSCachePolicy,ExecutionReceipt,error){var o lsCacheResult;e:=c.call(ctx,applicationLSCacheConfigure,v.Scope.SiteID,v,&o);return o.Policy,o.Receipt,e}
func(c *LinuxApplicationClient)PurgeLSCache(ctx context.Context,v CacheMutation)(o ExecutionReceipt,e error){e=c.call(ctx,applicationLSCachePurge,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)InstallAutologinBridge(ctx context.Context,v AutologinBridgeRequest)(o ExecutionReceipt,e error){e=c.call(ctx,applicationAutologinInstall,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)RemoveAutologinBridge(ctx context.Context,v AutologinBridgeRequest)(o ExecutionReceipt,e error){e=c.call(ctx,applicationAutologinRemove,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)CreateShadowRoute(ctx context.Context,s SiteID,i InstallationID,r ReleaseID)(o string,e error){e=c.call(ctx,applicationRouteCreate,s,applicationRouteRequest{s,i,r,""},&o);return}
func(c *LinuxApplicationClient)RemoveShadowRoute(ctx context.Context,s SiteID,i InstallationID,r ReleaseID)error{return c.call(ctx,applicationRouteRemove,s,applicationRouteRequest{s,i,r,""},nil)}
func(c *LinuxApplicationClient)ActivateReleaseRoute(ctx context.Context,s SiteID,i InstallationID,r ReleaseID,shadow string)error{return c.call(ctx,applicationRouteActivate,s,applicationRouteRequest{s,i,r,shadow},nil)}
func(c *LinuxApplicationClient)RestoreReleaseRoute(ctx context.Context,s SiteID,i InstallationID,r ReleaseID)error{return c.call(ctx,applicationRouteRestore,s,applicationRouteRequest{s,i,r,""},nil)}
func(c *LinuxApplicationClient)CreateApplicationSnapshot(ctx context.Context,v SnapshotRequest)(o Snapshot,e error){e=c.call(ctx,applicationSnapshotCreate,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)VerifyApplicationSnapshot(ctx context.Context,id SnapshotID)error{return c.call(ctx,applicationSnapshotVerify,"",id,nil)}
func(c *LinuxApplicationClient)ReleaseApplicationSnapshot(ctx context.Context,id SnapshotID)error{return c.call(ctx,applicationSnapshotRelease,"",id,nil)}
func(c *LinuxApplicationClient)CreateClone(ctx context.Context,v CloneExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationCloneCreate,v.TargetScope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)ProbeClone(ctx context.Context,v CloneExecution)(HealthObservation,ExecutionReceipt,error){var o applicationStagingHealthResult;e:=c.call(ctx,applicationCloneProbe,v.TargetScope.SiteID,v,&o);return o.Health,o.Receipt,e}
func(c *LinuxApplicationClient)ApplySync(ctx context.Context,v SyncExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationSyncApply,v.TargetScope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)RewriteApplicationIdentity(ctx context.Context,v SyncExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationSyncRewrite,v.TargetScope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)ProbeSynchronizedApplication(ctx context.Context,v SyncExecution)(HealthObservation,ExecutionReceipt,error){var o applicationStagingHealthResult;e:=c.call(ctx,applicationSyncProbe,v.TargetScope.SiteID,v,&o);return o.Health,o.Receipt,e}
func(c *LinuxApplicationClient)RollbackSync(ctx context.Context,v SyncExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationSyncRollback,v.TargetScope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)DeleteClone(ctx context.Context,v StagingDeleteExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationCloneDelete,v.TargetScope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)ResolveExecutionScope(ctx context.Context,installation ApplicationInstallation)(o SiteExecutionScope,e error){e=c.call(ctx,applicationResolveScope,installation.SiteID,installation,&o);return}
func(c *LinuxApplicationClient)ResolveSiteBinding(ctx context.Context,tenant TenantID,site SiteID)(o SiteExecutionScope,e error){e=c.call(ctx,applicationResolveSite,site,struct{TenantID TenantID `json:"tenant_id"`;SiteID SiteID `json:"site_id"`}{tenant,site},&o);return}
func(c *LinuxApplicationClient)ID()string{return "cyberpanel-local"}
func(c *LinuxApplicationClient)Kind()ScannerKind{return ScannerLocal}
func(c *LinuxApplicationClient)Scan(ctx context.Context,v ScanRequest,_ *DataEgressConsent)(o ScanResult,e error){e=c.call(ctx,applicationSecurityScan,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)ApplyRemediation(ctx context.Context,v RemediationExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationRemediationApply,v.Scope.SiteID,v,&o);return}
func(c *LinuxApplicationClient)RollbackRemediation(ctx context.Context,v RemediationExecution)(o ExecutionReceipt,e error){e=c.call(ctx,applicationRemediationRollback,v.Scope.SiteID,v,&o);return}

type LinuxApplicationRecoveryProvider struct{Client *LinuxApplicationClient;Store ApplicationStore}
func(provider *LinuxApplicationRecoveryProvider)CreateRecoveryPoint(ctx context.Context,request RecoveryRequest)(RecoveryPointID,uint64,error){if provider==nil||provider.Client==nil||provider.Store==nil{return "",0,ErrInvalid};installation,err:=provider.Store.LoadInstallation(ctx,request.InstallationID);if err!=nil{return "",0,err};var output applicationRecoveryOutput;err=provider.Client.call(ctx,applicationRecoveryCreate,request.SiteID,applicationRecoveryInput{request,installation},&output);return output.ID,output.Frontier,err}
func(provider *LinuxApplicationRecoveryProvider)VerifyRecoveryPoint(ctx context.Context,id RecoveryPointID)error{if provider==nil||provider.Client==nil{return ErrInvalid};return provider.Client.call(ctx,applicationRecoveryVerify,"",id,nil)}

type LinuxApplicationBrokerPeerPolicy struct{controlUID uint32}
func NewLinuxApplicationBrokerPeerPolicy(controlUID uint32)(*LinuxApplicationBrokerPeerPolicy,error){if controlUID==0{return nil,ErrPolicyDenied};return &LinuxApplicationBrokerPeerPolicy{controlUID},nil}
func(policy *LinuxApplicationBrokerPeerPolicy)Authorize(connection net.Conn)error{unix,ok:=connection.(*net.UnixConn);if !ok||policy==nil{return ErrPolicyDenied};raw,err:=unix.SyscallConn();if err!=nil{return ErrPolicyDenied};var credential *syscall.Ucred;var peerErr error;err=raw.Control(func(fd uintptr){credential,peerErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)});if err!=nil||peerErr!=nil||credential==nil||credential.Pid<=1||credential.Uid!=0&&credential.Uid!=policy.controlUID{return ErrPolicyDenied};return nil}

func ListenLinuxApplicationBroker(controlGID uint32)(*net.UnixListener,error){if os.Geteuid()!=0||controlGID==0{return nil,ErrPolicyDenied};if info,err:=os.Lstat("/run/cyberpanel");err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0002!=0{return nil,ErrPolicyDenied};if info,err:=os.Lstat(LinuxApplicationSocketPath);err==nil{if info.Mode()&os.ModeSocket==0{return nil,ErrPolicyDenied};if err=os.Remove(LinuxApplicationSocketPath);err!=nil{return nil,err}}else if !errors.Is(err,os.ErrNotExist){return nil,err};listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:LinuxApplicationSocketPath,Net:"unix"});if err!=nil{return nil,err};if err=os.Chown(LinuxApplicationSocketPath,0,int(controlGID));err==nil{err=os.Chmod(LinuxApplicationSocketPath,0660)};if err!=nil{listener.Close();return nil,err};return listener,nil}

type LinuxApplicationBrokerServer struct{Authorizer *LinuxApplicationBrokerPeerPolicy;Runtime *LinuxApplicationRuntime;MaximumConcurrent uint32}
func(server *LinuxApplicationBrokerServer)Serve(listener *net.UnixListener)error{if server==nil||listener==nil||server.Authorizer==nil||server.Runtime==nil{return ErrInvalid};maximum:=server.MaximumConcurrent;if maximum==0{maximum=32};slots:=make(chan struct{},maximum);var workers sync.WaitGroup;defer workers.Wait();for{connection,err:=listener.AcceptUnix();if err!=nil{return err};slots<-struct{}{};workers.Add(1);go func(){defer workers.Done();defer func(){<-slots}();defer connection.Close();if server.Authorizer.Authorize(connection)!=nil{return};var request linuxApplicationRequest;if readLinuxApplicationFrame(connection,&request)!=nil{return};now:=time.Now().UTC();if request.Version!=1||request.RequestID==""||request.Deadline.Before(now)||request.Deadline.After(now.Add(2*time.Hour))||request.PayloadDigest!=linuxApplicationDigest(request.Payload){return};_ = connection.SetDeadline(request.Deadline);ctx,cancel:=context.WithDeadline(context.Background(),request.Deadline);defer cancel();value,handleErr:=server.Runtime.Handle(ctx,request.Operation,request.Payload);response:=linuxApplicationResponse{Version:1,RequestID:request.RequestID,Operation:request.Operation,CompletedAt:time.Now().UTC()};if handleErr!=nil{response.ErrorCode=classifyLinuxApplicationError(handleErr)}else{response.Succeeded=true;response.Payload=value;response.PayloadDigest=linuxApplicationDigest(value)};_ = writeLinuxApplicationFrame(connection,response)}()}}

func linuxApplicationDigest(value []byte)string{sum:=sha256.Sum256(value);return hex.EncodeToString(sum[:])}
func classifyLinuxApplicationError(err error)string{switch{case errors.Is(err,ErrNotFound):return "not_found";case errors.Is(err,ErrConflict),errors.Is(err,ErrStaleGeneration):return "conflict";case errors.Is(err,ErrPolicyDenied),errors.Is(err,ErrRecipeUntrusted):return "forbidden";case errors.Is(err,ErrUnsupported):return "unsupported";case errors.Is(err,ErrIntegrity):return "integrity";case errors.Is(err,ErrInvalid):return "invalid";default:return "failed"}}
func linuxApplicationFailure(code string)error{switch code{case "not_found":return ErrNotFound;case "conflict":return ErrConflict;case "forbidden":return ErrPolicyDenied;case "unsupported":return ErrUnsupported;case "integrity":return ErrIntegrity;case "invalid":return ErrInvalid;default:return errors.New("application runtime failed")}}
func writeLinuxApplicationFrame(writer io.Writer,value any)error{encoded,err:=json.Marshal(value);if err!=nil||len(encoded)==0||len(encoded)>linuxApplicationFrameLimit{return ErrInvalid};var header [4]byte;binary.BigEndian.PutUint32(header[:],uint32(len(encoded)));if _,err=writer.Write(header[:]);err!=nil{return err};for len(encoded)>0{count,writeErr:=writer.Write(encoded);if writeErr!=nil{return writeErr};if count<=0{return io.ErrShortWrite};encoded=encoded[count:]};return nil}
func readLinuxApplicationFrame(reader io.Reader,value any)error{var header [4]byte;if _,err:=io.ReadFull(reader,header[:]);err!=nil{return err};size:=binary.BigEndian.Uint32(header[:]);if size==0||size>linuxApplicationFrameLimit{return ErrInvalid};body:=make([]byte,size);if _,err:=io.ReadFull(reader,body);err!=nil{return err};decoder:=json.NewDecoder(bytes.NewReader(body));decoder.DisallowUnknownFields();if err:=decoder.Decode(value);err!=nil||decoder.Decode(&struct{}{})!=io.EOF{return ErrInvalid};return nil}

var _ SiteApplicationExecutor=(*LinuxApplicationClient)(nil)
var _ WordPressExecutor=(*LinuxApplicationClient)(nil)
var _ WPCLIExecutor=(*LinuxApplicationClient)(nil)
var _ ApplicationRouteController=(*LinuxApplicationClient)(nil)
var _ SnapshotProvider=(*LinuxApplicationClient)(nil)
var _ StagingExecutor=(*LinuxApplicationClient)(nil)
var _ RecoveryPointProvider=(*LinuxApplicationRecoveryProvider)(nil)
var _ ScannerProvider=(*LinuxApplicationClient)(nil)
var _ RemediationExecutor=(*LinuxApplicationClient)(nil)
