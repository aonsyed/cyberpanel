package access

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

const AccessBrokerMaximumFrameBytes = 64 << 20

var (
	ErrAccessBrokerProtocol = errors.New("invalid access broker protocol")
	ErrAccessBrokerPeer = errors.New("unauthorized access broker peer")
)

type AccessBrokerTransport interface { Execute(context.Context, ExecutorEnvelope) (ExecutorResult, error) }
type AccessBrokerDialer interface { DialContext(context.Context) (net.Conn, error) }

type FramedAccessBrokerTransport struct { Dialer AccessBrokerDialer }

func (transport FramedAccessBrokerTransport) Execute(ctx context.Context, request ExecutorEnvelope) (ExecutorResult, error) {
	if transport.Dialer == nil || ctx == nil { return ExecutorResult{}, ErrAccessBrokerProtocol }
	connection, err := transport.Dialer.DialContext(ctx); if err != nil { return ExecutorResult{}, err }; defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) }); defer stop()
	deadline := request.Deadline; if value, ok := ctx.Deadline(); ok && value.Before(deadline) { deadline = value }
	if err = connection.SetDeadline(deadline); err != nil { return ExecutorResult{}, err }
	if err = writeAccessFrame(connection, request); err != nil { return ExecutorResult{}, err }
	var response ExecutorResult; if err = readAccessFrame(connection, &response); err != nil { return ExecutorResult{}, err }
	return response, nil
}

type AccessBrokerClient struct { transport AccessBrokerTransport; now func() time.Time }

func NewAccessBrokerClient(transport AccessBrokerTransport) (*AccessBrokerClient, error) {
	if transport == nil { return nil, ErrAccessBrokerProtocol }
	return &AccessBrokerClient{transport: transport, now: time.Now}, nil
}

func (client *AccessBrokerClient) call(ctx context.Context, operation ExecutorOperation, site SiteID, input any, output any) error {
	if client == nil || client.transport == nil || ctx == nil || !validAccessBrokerOperation(operation) { return ErrAccessBrokerProtocol }
	payload, err := json.Marshal(input); if err != nil || len(payload) > AccessBrokerMaximumFrameBytes { return ErrAccessBrokerProtocol }
	identifier := make([]byte, 16); if isAccessReadOperation(operation) { if _, err = io.ReadFull(rand.Reader, identifier); err != nil { return err } } else { digest := deploymentPayloadDigest(append([]byte(string(operation)+"\x00"), payload...)); decoded, decodeErr := hex.DecodeString(digest[:32]); if decodeErr != nil { return decodeErr }; copy(identifier, decoded) }
	now := client.now().UTC(); deadline := now.Add(5*time.Minute); if value, ok := ctx.Deadline(); ok && value.Before(deadline) { deadline = value.UTC() }
	request := ExecutorEnvelope{Version:ExecutorProtocolVersion,RequestID:"req-"+hex.EncodeToString(identifier),Operation:operation,SiteID:site,Deadline:deadline,Payload:payload,PayloadHash:deploymentPayloadDigest(payload)}
	if err = request.Validate(now); err != nil { return err }
	response, err := client.transport.Execute(ctx, request); if err != nil { return err }
	if err = response.Validate(request, client.now().UTC()); err != nil { return err }
	if !response.Succeeded { return accessBrokerFailure(response.ErrorCode) }
	if output == nil { if len(response.Payload) != 0 && string(response.Payload) != "null" { return ErrAccessBrokerProtocol }; return nil }
	decoder := json.NewDecoder(bytes.NewReader(response.Payload)); decoder.DisallowUnknownFields()
	if err = decoder.Decode(output); err != nil || decoder.Decode(&struct{}{}) != io.EOF { return ErrAccessBrokerProtocol }
	return nil
}

func isAccessReadOperation(operation ExecutorOperation)bool{switch operation{case ExecutorFileList,ExecutorFileStat,ExecutorFileRead,ExecutorDownloadRead,ExecutorGitStatus,ExecutorGitLog,ExecutorCronRun,ExecutorTerminalIssue:return true;default:return false}}

type listInput struct { Root SiteRoot `json:"root"`; Directory RelativePath `json:"directory"`; Page PageRequest `json:"page"` }
type statInput struct { Locator FileLocator `json:"locator"` }
type readRangeInput struct { Locator FileLocator `json:"locator"`; Offset int64 `json:"offset"`; Length int64 `json:"length"` }
type readRangeOutput struct { Content []byte `json:"content"`; Integrity Integrity `json:"integrity"` }
type createInput struct { Locator FileLocator `json:"locator"`; Content []byte `json:"content,omitempty"`; Metadata FileMetadata `json:"metadata"`; Condition WriteCondition `json:"condition"` }
type transferInput struct { Source FileLocator `json:"source"`; Destination FileLocator `json:"destination"`; Condition WriteCondition `json:"condition"` }
type metadataInput struct { Locator FileLocator `json:"locator"`; Metadata FileMetadata `json:"metadata"`; Condition WriteCondition `json:"condition"` }
type symlinkInput struct { Locator FileLocator `json:"locator"`; Target RelativePath `json:"target"`; Condition WriteCondition `json:"condition"` }
type trashInput struct { Locator FileLocator `json:"locator"`; TrashID TrashEntryID `json:"trash_id"` }
type trashOutput struct { Entry TrashEntry `json:"entry"`; Receipt FileMutationReceipt `json:"receipt"` }
type restoreInput struct { Entry TrashEntry `json:"entry"`; Destination FileLocator `json:"destination"`; Condition WriteCondition `json:"condition"` }
type uploadAppendInput struct { Handle string `json:"handle"`; Chunk UploadChunk `json:"chunk"` }
type uploadAbortInput struct { Handle string `json:"handle"` }
type downloadReadInput struct { Lease DownloadLease `json:"lease"`; Offset int64 `json:"offset"`; Length int64 `json:"length"` }
type extractInput struct { Archive FileLocator `json:"archive"`; Destination FileLocator `json:"destination"`; Policy ExtractPolicy `json:"policy"` }

func (client *AccessBrokerClient) List(ctx context.Context, root SiteRoot, directory RelativePath, page PageRequest)(value FilePage,err error){err=client.call(ctx,ExecutorFileList,root.SiteID,listInput{root,directory,page},&value);return}
func (client *AccessBrokerClient) Stat(ctx context.Context, locator FileLocator)(value FileEntry,err error){err=client.call(ctx,ExecutorFileStat,locator.Root.SiteID,statInput{locator},&value);return}
func (client *AccessBrokerClient) ReadRange(ctx context.Context, locator FileLocator, offset,length int64)([]byte,Integrity,error){var value readRangeOutput;err:=client.call(ctx,ExecutorFileRead,locator.Root.SiteID,readRangeInput{locator,offset,length},&value);return value.Content,value.Integrity,err}
func (client *AccessBrokerClient) CreateDirectory(ctx context.Context,l FileLocator,m FileMetadata)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFileCreate,l.Root.SiteID,createInput{Locator:l,Metadata:m},&value);return}
func (client *AccessBrokerClient) CreateFile(ctx context.Context,l FileLocator,b []byte,m FileMetadata,c WriteCondition)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFileCreate,l.Root.SiteID,createInput{l,b,m,c},&value);return}
func (client *AccessBrokerClient) ReplaceFile(ctx context.Context,l FileLocator,b []byte,m FileMetadata,c WriteCondition)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFileReplace,l.Root.SiteID,createInput{l,b,m,c},&value);return}
func (client *AccessBrokerClient) Move(ctx context.Context,s,d FileLocator,c WriteCondition)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFileMove,s.Root.SiteID,transferInput{s,d,c},&value);return}
func (client *AccessBrokerClient) Copy(ctx context.Context,s,d FileLocator,c WriteCondition)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFileCopy,s.Root.SiteID,transferInput{s,d,c},&value);return}
func (client *AccessBrokerClient) SetMetadata(ctx context.Context,l FileLocator,m FileMetadata,c WriteCondition)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFileMetadata,l.Root.SiteID,metadataInput{l,m,c},&value);return}
func (client *AccessBrokerClient) CreateSymlink(ctx context.Context,l FileLocator,t RelativePath,c WriteCondition)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFileSymlink,l.Root.SiteID,symlinkInput{l,t,c},&value);return}
func (client *AccessBrokerClient) MoveToTrash(ctx context.Context,l FileLocator,id TrashEntryID)(TrashEntry,FileMutationReceipt,error){var value trashOutput;err:=client.call(ctx,ExecutorFileTrash,l.Root.SiteID,trashInput{l,id},&value);return value.Entry,value.Receipt,err}
func (client *AccessBrokerClient) RestoreTrash(ctx context.Context,e TrashEntry,d FileLocator,c WriteCondition)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFileRestore,e.SiteID,restoreInput{e,d,c},&value);return}
func (client *AccessBrokerClient) PurgeTrash(ctx context.Context,e TrashEntry)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFilePurge,e.SiteID,e,&value);return}
func (client *AccessBrokerClient) BeginUpload(ctx context.Context,s UploadSession)(value string,err error){err=client.call(ctx,ExecutorUpload,s.Destination.Root.SiteID,s,&value);return}
func (client *AccessBrokerClient) AppendUpload(ctx context.Context,h string,c UploadChunk)error{return client.call(ctx,ExecutorUploadAppend,"",uploadAppendInput{h,c},nil)}
func (client *AccessBrokerClient) CommitUpload(ctx context.Context,s UploadSession)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorUploadCommit,s.Destination.Root.SiteID,s,&value);return}
func (client *AccessBrokerClient) AbortUpload(ctx context.Context,h string)error{return client.call(ctx,ExecutorUploadAbort,"",uploadAbortInput{h},nil)}
func (client *AccessBrokerClient) OpenDownload(ctx context.Context,l DownloadLease)(value DownloadLease,err error){err=client.call(ctx,ExecutorDownload,l.Source.Root.SiteID,l,&value);return}
func (client *AccessBrokerClient) ReadDownload(ctx context.Context,l DownloadLease,o,n int64)(value []byte,err error){err=client.call(ctx,ExecutorDownloadRead,l.Source.Root.SiteID,downloadReadInput{l,o,n},&value);return}
func (client *AccessBrokerClient) CloseDownload(ctx context.Context,l DownloadLease)error{return client.call(ctx,ExecutorDownloadClose,l.Source.Root.SiteID,l,nil)}
func (client *AccessBrokerClient) CreateArchive(ctx context.Context,a Archive)(value Archive,err error){err=client.call(ctx,ExecutorFileArchive,a.SiteID,a,&value);return}
func (client *AccessBrokerClient) ExtractArchive(ctx context.Context,a,d FileLocator,p ExtractPolicy)(value FileMutationReceipt,err error){err=client.call(ctx,ExecutorFileExtract,a.Root.SiteID,extractInput{a,d,p},&value);return}

type ftpsInput struct { Account FTPSAccount `json:"account"`; Password []byte `json:"password,omitempty"`; Enabled *bool `json:"enabled,omitempty"` }
type sshGrantInput struct { Grant AccessGrant `json:"grant"`; Key SSHKey `json:"key"` }
func(client *AccessBrokerClient)ApplyFTPSAccount(ctx context.Context,a FTPSAccount,s SecretMaterial)(v string,e error){e=client.call(ctx,ExecutorFTPS,a.SiteID,ftpsInput{Account:a,Password:s.bytes()},&v);return}
func(client *AccessBrokerClient)RotateFTPSPassword(ctx context.Context,a FTPSAccount,s SecretMaterial)(v string,e error){e=client.call(ctx,ExecutorFTPSRotate,a.SiteID,ftpsInput{Account:a,Password:s.bytes()},&v);return}
func(client *AccessBrokerClient)SetFTPSAccountEnabled(ctx context.Context,a FTPSAccount,b bool)(v string,e error){e=client.call(ctx,ExecutorFTPSEnable,a.SiteID,ftpsInput{Account:a,Enabled:&b},&v);return}
func(client *AccessBrokerClient)DeleteFTPSAccount(ctx context.Context,a FTPSAccount)(v string,e error){e=client.call(ctx,ExecutorFTPSDelete,a.SiteID,ftpsInput{Account:a},&v);return}
func(client *AccessBrokerClient)ApplySSHKey(ctx context.Context,k SSHKey)(v string,e error){e=client.call(ctx,ExecutorSSHKey,"",k,&v);return}
func(client *AccessBrokerClient)RemoveSSHKey(ctx context.Context,k SSHKey)(v string,e error){e=client.call(ctx,ExecutorSSHKeyRemove,"",k,&v);return}
func(client *AccessBrokerClient)ApplyAccessGrant(ctx context.Context,g AccessGrant,k SSHKey)(v string,e error){e=client.call(ctx,ExecutorSSHGrant,g.SiteID,sshGrantInput{g,k},&v);return}
func(client *AccessBrokerClient)RemoveAccessGrant(ctx context.Context,g AccessGrant)(v string,e error){e=client.call(ctx,ExecutorSSHGrantRemove,g.SiteID,g,&v);return}
func(client *AccessBrokerClient)Issue(ctx context.Context,g AccessGrant,r TerminalRequest)(v TerminalSession,e error){e=client.call(ctx,ExecutorTerminalIssue,g.SiteID,struct{Grant AccessGrant `json:"grant"`;Request TerminalRequest `json:"request"`}{g,r},&v);return}
func(client *AccessBrokerClient)Revoke(ctx context.Context,s TerminalSession)error{return client.call(ctx,ExecutorTerminalRevoke,"",s,nil)}

func(client *AccessBrokerClient)ApplySchedule(ctx context.Context,s SiteID,g uint64,j []CronJob)(v CronApplyReceipt,e error){e=client.call(ctx,ExecutorCronApply,s,struct{SiteID SiteID `json:"site_id"`;Generation uint64 `json:"generation"`;Jobs []CronJob `json:"jobs"`}{s,g,j},&v);return}
func(client *AccessBrokerClient)RunNow(ctx context.Context,j CronJob)(v CronRun,e error){e=client.call(ctx,ExecutorCronRun,j.SiteID,j,&v);return}
func(client *AccessBrokerClient)CancelRun(ctx context.Context,r CronRun)error{return client.call(ctx,ExecutorCronCancel,"",r,nil)}

func(client *AccessBrokerClient)GenerateDeployKey(ctx context.Context,k DeployKey)(v DeployKey,e error){e=client.call(ctx,ExecutorGitKey,k.SiteID,k,&v);return}
func(client *AccessBrokerClient)DeleteDeployKey(ctx context.Context,k DeployKey)error{return client.call(ctx,ExecutorGitKeyDelete,k.SiteID,k,nil)}
type repositoryKeyInput struct{Repository GitRepository `json:"repository"`;Key DeployKey `json:"key"`}
type pairOutput struct{First string `json:"first"`;Second string `json:"second"`}
func(client *AccessBrokerClient)Attach(ctx context.Context,r GitRepository,k DeployKey)(string,string,error){var v pairOutput;e:=client.call(ctx,ExecutorGitRepository,r.SiteID,repositoryKeyInput{r,k},&v);return v.First,v.Second,e}
func(client *AccessBrokerClient)Initialize(ctx context.Context,r GitRepository)(v string,e error){e=client.call(ctx,ExecutorGitInitialize,r.SiteID,r,&v);return}
func(client *AccessBrokerClient)Detach(ctx context.Context,r GitRepository,b bool)(v string,e error){e=client.call(ctx,ExecutorGitDetach,r.SiteID,struct{Repository GitRepository `json:"repository"`;Retain bool `json:"retain"`}{r,b},&v);return}
func(client *AccessBrokerClient)Status(ctx context.Context,r GitRepository)(v GitStatus,e error){e=client.call(ctx,ExecutorGitStatus,r.SiteID,r,&v);return}
func(client *AccessBrokerClient)Fetch(ctx context.Context,r GitRepository,b bool)(v GitStatus,e error){e=client.call(ctx,ExecutorGitFetch,r.SiteID,struct{Repository GitRepository `json:"repository"`;Prune bool `json:"prune"`}{r,b},&v);return}
func(client *AccessBrokerClient)Checkout(ctx context.Context,r GitRepository,s string,b bool)(v GitStatus,e error){e=client.call(ctx,ExecutorGitCheckout,r.SiteID,struct{Repository GitRepository `json:"repository"`;Branch string `json:"branch"`;Force bool `json:"force"`}{r,s,b},&v);return}
func(client *AccessBrokerClient)Pull(ctx context.Context,r GitRepository)(v GitStatus,e error){e=client.call(ctx,ExecutorGitPull,r.SiteID,r,&v);return}
func(client *AccessBrokerClient)Commit(ctx context.Context,r GitRepository,c GitChangeSet)(v GitCommit,e error){e=client.call(ctx,ExecutorGitCommit,r.SiteID,struct{Repository GitRepository `json:"repository"`;Changes GitChangeSet `json:"changes"`}{r,c},&v);return}
func(client *AccessBrokerClient)Push(ctx context.Context,r GitRepository,s string)(v GitStatus,e error){e=client.call(ctx,ExecutorGitPush,r.SiteID,struct{Repository GitRepository `json:"repository"`;Ref string `json:"ref"`}{r,s},&v);return}
func(client *AccessBrokerClient)Log(ctx context.Context,r GitRepository,p PageRequest)(v GitPage,e error){e=client.call(ctx,ExecutorGitLog,r.SiteID,struct{Repository GitRepository `json:"repository"`;Page PageRequest `json:"page"`}{r,p},&v);return}
func(client *AccessBrokerClient)WriteIgnore(ctx context.Context,r GitRepository,p []string)(v string,e error){e=client.call(ctx,ExecutorGitIgnore,r.SiteID,struct{Repository GitRepository `json:"repository"`;Patterns []string `json:"patterns"`}{r,p},&v);return}
type deploymentInput struct{Repository GitRepository `json:"repository"`;Deployment Deployment `json:"deployment"`}
func(client *AccessBrokerClient)PrepareDeployment(ctx context.Context,r GitRepository,d Deployment)(v DeploymentPreparation,e error){e=client.call(ctx,ExecutorGitDeployment,r.SiteID,deploymentInput{r,d},&v);return}
func(client *AccessBrokerClient)PromoteDeployment(ctx context.Context,r GitRepository,d Deployment)(v string,e error){e=client.call(ctx,ExecutorGitPromote,r.SiteID,deploymentInput{r,d},&v);return}
func(client *AccessBrokerClient)VerifyDeployment(ctx context.Context,r GitRepository,d Deployment)(v DeploymentHealth,e error){e=client.call(ctx,ExecutorGitVerify,r.SiteID,deploymentInput{r,d},&v);return}
func(client *AccessBrokerClient)RollbackDeployment(ctx context.Context,r GitRepository,d Deployment)(v string,e error){e=client.call(ctx,ExecutorGitRollback,r.SiteID,deploymentInput{r,d},&v);return}
func(client *AccessBrokerClient)DiscardDeployment(ctx context.Context,r GitRepository,d Deployment)error{return client.call(ctx,ExecutorGitDiscard,r.SiteID,deploymentInput{r,d},nil)}

func(client *AccessBrokerClient)SnapshotSyncSource(ctx context.Context,s StagingSync)(v SyncSnapshot,e error){e=client.call(ctx,ExecutorStagingSync,s.LiveSiteID,s,&v);return}
type syncSnapshotInput struct{Sync StagingSync `json:"sync"`;Snapshot SyncSnapshot `json:"snapshot"`}
type syncApplicationInput struct{Sync StagingSync `json:"sync"`;Application SyncApplication `json:"application"`}
func(client *AccessBrokerClient)ApplyStagingSync(ctx context.Context,s StagingSync,p SyncSnapshot)(v SyncApplication,e error){e=client.call(ctx,ExecutorStagingApply,s.LiveSiteID,syncSnapshotInput{s,p},&v);return}
func(client *AccessBrokerClient)VerifyStagingSync(ctx context.Context,s StagingSync,a SyncApplication)(v string,e error){e=client.call(ctx,ExecutorStagingVerify,s.LiveSiteID,syncApplicationInput{s,a},&v);return}
func(client *AccessBrokerClient)PromoteStagingSync(ctx context.Context,s StagingSync,a SyncApplication)(v string,e error){e=client.call(ctx,ExecutorStagingPromote,s.LiveSiteID,syncApplicationInput{s,a},&v);return}
func(client *AccessBrokerClient)RollbackStagingSync(ctx context.Context,s StagingSync,a SyncApplication)(v string,e error){e=client.call(ctx,ExecutorStagingRollback,s.LiveSiteID,syncApplicationInput{s,a},&v);return}
func(client *AccessBrokerClient)ReleaseSyncSnapshot(ctx context.Context,s SyncSnapshot)error{return client.call(ctx,ExecutorStagingRelease,"",s,nil)}

type AccessBrokerPeerAuthorizer interface { Authorize(net.Conn) error }
type AccessReceiptJournal interface { Lookup(ExecutorEnvelope)(ExecutorResult,bool,error); Commit(ExecutorEnvelope,ExecutorResult)error }

type AccessBrokerServer struct { Authorizer AccessBrokerPeerAuthorizer; Handler ExecutorHandler; Journal AccessReceiptJournal; Admission rebootcontrol.ExecutionAdmission; MaximumConcurrent uint32 }
func(server *AccessBrokerServer)Serve(listener net.Listener)error{if server==nil||listener==nil||server.Authorizer==nil||server.Handler==nil||server.Journal==nil{return ErrAccessBrokerProtocol};maximum:=server.MaximumConcurrent;if maximum==0{maximum=64};gate:=make(chan struct{},maximum);var group sync.WaitGroup;defer group.Wait();for{connection,err:=listener.Accept();if err!=nil{return err};gate<-struct{}{};group.Add(1);go func(){defer func(){<-gate;group.Done();connection.Close()}();server.serve(connection)}()}}
func(server *AccessBrokerServer)serve(connection net.Conn){
	if server.Authorizer.Authorize(connection)!=nil{return}
	now:=time.Now().UTC();_=connection.SetDeadline(now.Add(10*time.Minute))
	var request ExecutorEnvelope
	if readAccessFrame(connection,&request)!=nil||request.Validate(now)!=nil||!validAccessBrokerOperation(request.Operation){return}
	_=connection.SetDeadline(request.Deadline);ctx,cancel:=context.WithDeadline(context.Background(),request.Deadline);defer cancel()
	// Do not reuse isAccessReadOperation: it controls request-ID randomness and
	// includes cron execution and terminal issuance, both genuine mutations.
	mutation:=true
	switch request.Operation { case ExecutorFileList,ExecutorFileStat,ExecutorFileRead,ExecutorDownloadRead,ExecutorGitLog: mutation=false }
	var lease rebootcontrol.ExecutionLease
	if mutation {
		if server.Admission==nil{return}
		binding:=rebootcontrol.ExecutionBinding{Boundary:"access",Method:string(request.Operation),EffectID:request.RequestID,RequestDigest:request.PayloadHash,Caller:"authenticated-panel-core",Resource:"site:"+string(request.SiteID)}
		var err error;lease,err=server.Admission.AdmitExecution(ctx,binding);if err!=nil{return}
		if len(lease.Cached)!=0 {
			var cached ExecutorResult
			if json.Unmarshal(lease.Cached,&cached)==nil && cached.Validate(request,time.Now().UTC())==nil{_=writeAccessFrame(connection,cached)};return
		}
		defer func(){_=rebootcontrol.SettleExecution(server.Admission,lease,false,nil)}()
	}
	// A journal lookup error is not evidence that an effect has never run.
	cached,found,err:=server.Journal.Lookup(request);if err!=nil{return}
	response:=cached
	if !found { response,err=server.Handler.Handle(ctx,request);if err!=nil{response=failedExecutorResult(request,err)} }
	if response.Validate(request,time.Now().UTC())!=nil{return}
	if !found && server.Journal.Commit(request,response)!=nil{return}
	if mutation && rebootcontrol.SettleExecution(server.Admission,lease,response.Succeeded,response)!=nil{return}
	_=writeAccessFrame(connection,response)
}

func succeededExecutorResult(request ExecutorEnvelope,value any)(ExecutorResult,error){payload,err:=json.Marshal(value);if err!=nil{return ExecutorResult{},err};return ExecutorResult{Version:ExecutorProtocolVersion,RequestID:request.RequestID,Operation:request.Operation,Succeeded:true,Payload:payload,PayloadHash:deploymentPayloadDigest(payload),Receipt:deploymentPayloadDigest(append([]byte(string(request.Operation)+"\x00"),payload...)),CompletedAt:time.Now().UTC()},nil}
func failedExecutorResult(request ExecutorEnvelope,err error)ExecutorResult{return ExecutorResult{Version:ExecutorProtocolVersion,RequestID:request.RequestID,Operation:request.Operation,Succeeded:false,ErrorCode:classifyAccessBrokerFailure(err),Receipt:deploymentPayloadDigest([]byte(request.RequestID+"\x00"+classifyAccessBrokerFailure(err))),CompletedAt:time.Now().UTC()}}
func classifyAccessBrokerFailure(err error)string{switch{case errors.Is(err,ErrUnauthorized):return "unauthorized";case errors.Is(err,ErrNotFound):return "not_found";case errors.Is(err,ErrConflict),errors.Is(err,ErrStaleGeneration):return "conflict";case errors.Is(err,ErrLimitExceeded):return "limit_exceeded";case errors.Is(err,ErrIntegrity):return "integrity";case errors.Is(err,ErrInvalidPath),errors.Is(err,ErrInvalidID),errors.Is(err,ErrInvalidState),errors.Is(err,ErrInvalidTransition):return "invalid_request";default:return "operation_failed"}}
func accessBrokerFailure(code string)error{switch code{case "unauthorized":return ErrUnauthorized;case "not_found":return ErrNotFound;case "conflict":return ErrConflict;case "limit_exceeded":return ErrLimitExceeded;case "integrity":return ErrIntegrity;case "invalid_request":return ErrInvalidState;default:return errors.New("access executor operation failed")}}
func writeAccessFrame(writer io.Writer,value any)error{encoded,err:=json.Marshal(value);if err!=nil||len(encoded)==0||len(encoded)>AccessBrokerMaximumFrameBytes{return ErrAccessBrokerProtocol};var header [4]byte;binary.BigEndian.PutUint32(header[:],uint32(len(encoded)));if err=writeAccessAll(writer,header[:]);err!=nil{return err};return writeAccessAll(writer,encoded)}
func writeAccessAll(writer io.Writer,content []byte)error{for len(content)>0{count,err:=writer.Write(content);if err!=nil{return err};if count<=0||count>len(content){return io.ErrShortWrite};content=content[count:]};return nil}
func readAccessFrame(reader io.Reader,target any)error{var header [4]byte;if _,err:=io.ReadFull(reader,header[:]);err!=nil{return err};size:=binary.BigEndian.Uint32(header[:]);if size==0||size>AccessBrokerMaximumFrameBytes{return ErrAccessBrokerProtocol};content:=make([]byte,size);if _,err:=io.ReadFull(reader,content);err!=nil{return err};decoder:=json.NewDecoder(bytes.NewReader(content));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil||decoder.Decode(&struct{}{})!=io.EOF{return ErrAccessBrokerProtocol};return nil}

var _ FileExecutor=(*AccessBrokerClient)(nil)
var _ CredentialExecutor=(*AccessBrokerClient)(nil)
var _ TerminalBroker=(*AccessBrokerClient)(nil)
var _ CronExecutor=(*AccessBrokerClient)(nil)
var _ GitExecutor=(*AccessBrokerClient)(nil)
var _ StagingExecutor=(*AccessBrokerClient)(nil)
