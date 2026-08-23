package containers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	ContainerBrokerProtocolVersion uint16 = 1
	ContainerBrokerMaximumFrameBytes = 8 << 20
	ContainerBrokerMaximumLogBytes uint64 = 1 << 20
)

var (
	ErrContainerBrokerProtocol = errors.New("containers: invalid broker protocol")
	ErrContainerBrokerPeer = errors.New("containers: unauthorized broker peer")
)

type BrokerMethod string

const (
	BrokerInspectRuntime BrokerMethod = "runtime.inspect"
	BrokerInstallRuntime BrokerMethod = "runtime.install"
	BrokerRemoveRuntime BrokerMethod = "runtime.remove"
	BrokerResolveImage BrokerMethod = "image.resolve"
	BrokerPullImage BrokerMethod = "image.pull"
	BrokerDeleteImage BrokerMethod = "image.delete"
	BrokerEnsureVolume BrokerMethod = "volume.ensure"
	BrokerDeleteVolume BrokerMethod = "volume.delete"
	BrokerEnsureNetwork BrokerMethod = "network.ensure"
	BrokerDeleteNetwork BrokerMethod = "network.delete"
	BrokerApplyWorkload BrokerMethod = "workload.apply"
	BrokerObserveWorkload BrokerMethod = "workload.observe"
	BrokerSetLifecycle BrokerMethod = "workload.lifecycle"
	BrokerDeleteWorkload BrokerMethod = "workload.delete"
	BrokerApplyExposure BrokerMethod = "exposure.apply"
	BrokerDeleteExposure BrokerMethod = "exposure.delete"
	BrokerExec BrokerMethod = "workload.exec"
	BrokerReadLogs BrokerMethod = "workload.logs.read"
	BrokerStats BrokerMethod = "workload.stats"
	BrokerSnapshotVolumes BrokerMethod = "volume.snapshot"
	BrokerRestoreVolumes BrokerMethod = "volume.restore"
)

// BrokerWireRequest is deliberately a closed union. Exactly one field is
// accepted for every method; there is no daemon endpoint, argv, OCI JSON or
// host path field in the privileged protocol.
type BrokerWireRequest struct {
	Version uint16 `json:"version"`
	RequestID string `json:"request_id"`
	Method BrokerMethod `json:"method"`
	Deadline time.Time `json:"deadline"`
	InstallRuntime *RuntimeInstallRequest `json:"install_runtime,omitempty"`
	RuntimeMutation *RuntimeMutationRequest `json:"runtime_mutation,omitempty"`
	ResolveImage *ResolveImageRequest `json:"resolve_image,omitempty"`
	PullImage *PullImageRequest `json:"pull_image,omitempty"`
	ImageMutation *ImageMutationRequest `json:"image_mutation,omitempty"`
	VolumeMutation *VolumeMutationRequest `json:"volume_mutation,omitempty"`
	NetworkMutation *NetworkMutationRequest `json:"network_mutation,omitempty"`
	WorkloadMutation *WorkloadMutationRequest `json:"workload_mutation,omitempty"`
	WorkloadObservation *WorkloadObservationRequest `json:"workload_observation,omitempty"`
	WorkloadLifecycle *WorkloadLifecycleRequest `json:"workload_lifecycle,omitempty"`
	ExposureMutation *ExposureMutationRequest `json:"exposure_mutation,omitempty"`
	Exec *ExecRequest `json:"exec,omitempty"`
	Logs *LogRequest `json:"logs,omitempty"`
	VolumeSnapshot *VolumeSnapshotRequest `json:"volume_snapshot,omitempty"`
	VolumeRestore *VolumeRestoreRequest `json:"volume_restore,omitempty"`
}

func (request BrokerWireRequest) Validate(now time.Time) error {
	if request.Version != ContainerBrokerProtocolVersion || !validBrokerRequestID(request.RequestID) || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.After(now.Add(10*time.Minute)) { return ErrContainerBrokerProtocol }
	count := 0
	for _, present := range []bool{request.InstallRuntime!=nil,request.RuntimeMutation!=nil,request.ResolveImage!=nil,request.PullImage!=nil,request.ImageMutation!=nil,request.VolumeMutation!=nil,request.NetworkMutation!=nil,request.WorkloadMutation!=nil,request.WorkloadObservation!=nil,request.WorkloadLifecycle!=nil,request.ExposureMutation!=nil,request.Exec!=nil,request.Logs!=nil,request.VolumeSnapshot!=nil,request.VolumeRestore!=nil} { if present { count++ } }
	if request.Method == BrokerInspectRuntime { if count != 0 { return ErrContainerBrokerProtocol }; return nil }
	if count != 1 { return ErrContainerBrokerProtocol }
	switch request.Method {
	case BrokerInstallRuntime: if request.InstallRuntime == nil { return ErrContainerBrokerProtocol }
	case BrokerRemoveRuntime: if request.RuntimeMutation == nil { return ErrContainerBrokerProtocol }
	case BrokerResolveImage: if request.ResolveImage == nil { return ErrContainerBrokerProtocol }
	case BrokerPullImage: if request.PullImage == nil { return ErrContainerBrokerProtocol }
	case BrokerDeleteImage: if request.ImageMutation == nil { return ErrContainerBrokerProtocol }
	case BrokerEnsureVolume, BrokerDeleteVolume: if request.VolumeMutation == nil { return ErrContainerBrokerProtocol }
	case BrokerEnsureNetwork, BrokerDeleteNetwork: if request.NetworkMutation == nil { return ErrContainerBrokerProtocol }
	case BrokerApplyWorkload, BrokerDeleteWorkload: if request.WorkloadMutation == nil { return ErrContainerBrokerProtocol }
	case BrokerObserveWorkload, BrokerStats: if request.WorkloadObservation == nil { return ErrContainerBrokerProtocol }
	case BrokerSetLifecycle: if request.WorkloadLifecycle == nil { return ErrContainerBrokerProtocol }
	case BrokerApplyExposure, BrokerDeleteExposure: if request.ExposureMutation == nil { return ErrContainerBrokerProtocol }
	case BrokerExec: if request.Exec == nil { return ErrContainerBrokerProtocol }
	case BrokerReadLogs:
		if request.Logs == nil || request.Logs.MaxBytes == 0 || request.Logs.MaxBytes > ContainerBrokerMaximumLogBytes || request.Logs.TailLines > 10000 || request.Logs.Deadline.IsZero() || request.Logs.Deadline.After(request.Deadline) { return ErrContainerBrokerProtocol }
	case BrokerSnapshotVolumes: if request.VolumeSnapshot==nil||validateSnapshotRequest(*request.VolumeSnapshot)!=nil{return ErrContainerBrokerProtocol}
	case BrokerRestoreVolumes: if request.VolumeRestore==nil||validateRestoreRequest(*request.VolumeRestore)!=nil{return ErrContainerBrokerProtocol}
	default: return ErrContainerBrokerProtocol
	}
	return nil
}

type BrokerWireResponse struct {
	Version uint16 `json:"version"`
	RequestID string `json:"request_id"`
	Method BrokerMethod `json:"method"`
	ErrorCode string `json:"error_code,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
	Capability *RuntimeCapability `json:"capability,omitempty"`
	Runtime *RuntimeReceipt `json:"runtime,omitempty"`
	Image *ImageReference `json:"image,omitempty"`
	Pull *PullReceipt `json:"pull,omitempty"`
	Volume *VolumeReceipt `json:"volume,omitempty"`
	Network *NetworkReceipt `json:"network,omitempty"`
	Exposure *ExposureReceipt `json:"exposure,omitempty"`
	Exec *ExecReceipt `json:"exec,omitempty"`
	Log *StreamChunk `json:"log,omitempty"`
	Observation *WorkloadObservation `json:"observation,omitempty"`
	VolumeSnapshot *VolumeSnapshotReceipt `json:"volume_snapshot,omitempty"`
}

func (response BrokerWireResponse) Validate(request BrokerWireRequest, now time.Time) error {
	if response.Version != ContainerBrokerProtocolVersion || response.RequestID != request.RequestID || response.Method != request.Method || response.CompletedAt.IsZero() || response.CompletedAt.After(now.Add(time.Minute)) || !validBrokerErrorCode(response.ErrorCode) { return ErrContainerBrokerProtocol }
	count := 0
	for _, present := range []bool{response.Capability!=nil,response.Runtime!=nil,response.Image!=nil,response.Pull!=nil,response.Volume!=nil,response.Network!=nil,response.Exposure!=nil,response.Exec!=nil,response.Log!=nil,response.Observation!=nil,response.VolumeSnapshot!=nil} { if present { count++ } }
	if count != 1 { return ErrContainerBrokerProtocol }
	switch request.Method {
	case BrokerInspectRuntime: if response.Capability == nil { return ErrContainerBrokerProtocol }
	case BrokerInstallRuntime, BrokerRemoveRuntime, BrokerApplyWorkload, BrokerObserveWorkload, BrokerSetLifecycle, BrokerDeleteWorkload: if response.Runtime == nil { return ErrContainerBrokerProtocol }
	case BrokerResolveImage: if response.Image == nil { return ErrContainerBrokerProtocol }
	case BrokerPullImage, BrokerDeleteImage: if response.Pull == nil { return ErrContainerBrokerProtocol }
	case BrokerEnsureVolume, BrokerDeleteVolume: if response.Volume == nil { return ErrContainerBrokerProtocol }
	case BrokerEnsureNetwork, BrokerDeleteNetwork: if response.Network == nil { return ErrContainerBrokerProtocol }
	case BrokerApplyExposure, BrokerDeleteExposure: if response.Exposure == nil { return ErrContainerBrokerProtocol }
	case BrokerExec: if response.Exec == nil { return ErrContainerBrokerProtocol }
	case BrokerReadLogs: if response.Log == nil || uint64(len(response.Log.Data)) > request.Logs.MaxBytes { return ErrContainerBrokerProtocol }
	case BrokerStats: if response.Observation == nil { return ErrContainerBrokerProtocol }
	case BrokerSnapshotVolumes,BrokerRestoreVolumes:if response.VolumeSnapshot==nil{return ErrContainerBrokerProtocol}
	default: return ErrContainerBrokerProtocol
	}
	return nil
}

func validBrokerErrorCode(value string) bool { switch value { case "", "invalid_request", "unauthorized", "not_found", "conflict", "stale", "policy_rejected", "in_use", "ambiguous", "unavailable": return true }; return false }
func validBrokerRequestID(value string) bool { if len(value)!=36 || value[:4]!="req-" { return false }; _,err:=hex.DecodeString(value[4:]);return err==nil }

type ContainerBrokerTransport interface { RoundTrip(context.Context,BrokerWireRequest)(BrokerWireResponse,error) }
type ContainerBrokerDialer interface { DialContext(context.Context)(net.Conn,error) }
type FramedContainerBrokerTransport struct { Dialer ContainerBrokerDialer }

func (transport FramedContainerBrokerTransport) RoundTrip(ctx context.Context, request BrokerWireRequest)(BrokerWireResponse,error){
	if ctx==nil||transport.Dialer==nil{return BrokerWireResponse{},ErrContainerBrokerProtocol};connection,err:=transport.Dialer.DialContext(ctx);if err!=nil{return BrokerWireResponse{},err};defer connection.Close();stop:=context.AfterFunc(ctx,func(){_=connection.SetDeadline(time.Now())});defer stop();deadline:=request.Deadline;if candidate,ok:=ctx.Deadline();ok&&candidate.Before(deadline){deadline=candidate};if err=connection.SetDeadline(deadline);err!=nil{return BrokerWireResponse{},err};if err=writeContainerBrokerFrame(connection,request);err!=nil{return BrokerWireResponse{},err};var response BrokerWireResponse;if err=readContainerBrokerFrame(connection,&response);err!=nil{return BrokerWireResponse{},err};return response,nil
}

type ContainerBrokerClient struct{transport ContainerBrokerTransport;now func()time.Time}
func NewContainerBrokerClient(transport ContainerBrokerTransport)(*ContainerBrokerClient,error){if transport==nil{return nil,ErrContainerBrokerProtocol};return &ContainerBrokerClient{transport:transport,now:time.Now},nil}

func(client *ContainerBrokerClient)call(ctx context.Context,request BrokerWireRequest)(BrokerWireResponse,error){if client==nil||client.transport==nil||ctx==nil{return BrokerWireResponse{},ErrContainerBrokerProtocol};identifier:=make([]byte,16);if _,err:=io.ReadFull(rand.Reader,identifier);err!=nil{return BrokerWireResponse{},err};now:=client.now().UTC();request.Version=ContainerBrokerProtocolVersion;request.RequestID="req-"+hex.EncodeToString(identifier);request.Deadline=now.Add(5*time.Minute);if deadline,ok:=ctx.Deadline();ok&&deadline.Before(request.Deadline){request.Deadline=deadline.UTC()};if request.Logs!=nil&&request.Logs.Deadline.After(request.Deadline){copy:=*request.Logs;copy.Deadline=request.Deadline;request.Logs=&copy};if err:=request.Validate(now);err!=nil{return BrokerWireResponse{},err};response,err:=client.transport.RoundTrip(ctx,request);if err!=nil{return BrokerWireResponse{},err};if err=response.Validate(request,client.now().UTC());err!=nil{return BrokerWireResponse{},err};if response.ErrorCode!=""{return response,containerBrokerError(response.ErrorCode)};return response,nil}

func(client *ContainerBrokerClient)InspectRuntime(ctx context.Context)(RuntimeCapability,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerInspectRuntime});if r.Capability==nil{return RuntimeCapability{},e};return *r.Capability,e}
func(client *ContainerBrokerClient)InstallRuntime(ctx context.Context,v RuntimeInstallRequest)(RuntimeReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerInstallRuntime,InstallRuntime:&v});if r.Runtime==nil{return RuntimeReceipt{},e};return *r.Runtime,e}
func(client *ContainerBrokerClient)RemoveRuntime(ctx context.Context,v RuntimeMutationRequest)(RuntimeReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerRemoveRuntime,RuntimeMutation:&v});if r.Runtime==nil{return RuntimeReceipt{},e};return *r.Runtime,e}
func(client *ContainerBrokerClient)ResolveImage(ctx context.Context,v ResolveImageRequest)(ImageReference,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerResolveImage,ResolveImage:&v});if r.Image==nil{return ImageReference{},e};return *r.Image,e}
func(client *ContainerBrokerClient)PullImage(ctx context.Context,v PullImageRequest)(PullReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerPullImage,PullImage:&v});if r.Pull==nil{return PullReceipt{},e};return *r.Pull,e}
func(client *ContainerBrokerClient)DeleteImage(ctx context.Context,v ImageMutationRequest)(PullReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerDeleteImage,ImageMutation:&v});if r.Pull==nil{return PullReceipt{},e};return *r.Pull,e}
func(client *ContainerBrokerClient)EnsureVolume(ctx context.Context,v VolumeMutationRequest)(VolumeReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerEnsureVolume,VolumeMutation:&v});if r.Volume==nil{return VolumeReceipt{},e};return *r.Volume,e}
func(client *ContainerBrokerClient)DeleteVolume(ctx context.Context,v VolumeMutationRequest)(VolumeReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerDeleteVolume,VolumeMutation:&v});if r.Volume==nil{return VolumeReceipt{},e};return *r.Volume,e}
func(client *ContainerBrokerClient)EnsureNetwork(ctx context.Context,v NetworkMutationRequest)(NetworkReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerEnsureNetwork,NetworkMutation:&v});if r.Network==nil{return NetworkReceipt{},e};return *r.Network,e}
func(client *ContainerBrokerClient)DeleteNetwork(ctx context.Context,v NetworkMutationRequest)(NetworkReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerDeleteNetwork,NetworkMutation:&v});if r.Network==nil{return NetworkReceipt{},e};return *r.Network,e}
func(client *ContainerBrokerClient)ApplyWorkload(ctx context.Context,v WorkloadMutationRequest)(RuntimeReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerApplyWorkload,WorkloadMutation:&v});if r.Runtime==nil{return RuntimeReceipt{},e};return *r.Runtime,e}
func(client *ContainerBrokerClient)ObserveWorkload(ctx context.Context,v WorkloadObservationRequest)(RuntimeReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerObserveWorkload,WorkloadObservation:&v});if r.Runtime==nil{return RuntimeReceipt{},e};return *r.Runtime,e}
func(client *ContainerBrokerClient)SetLifecycle(ctx context.Context,v WorkloadLifecycleRequest)(RuntimeReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerSetLifecycle,WorkloadLifecycle:&v});if r.Runtime==nil{return RuntimeReceipt{},e};return *r.Runtime,e}
func(client *ContainerBrokerClient)DeleteWorkload(ctx context.Context,v WorkloadMutationRequest)(RuntimeReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerDeleteWorkload,WorkloadMutation:&v});if r.Runtime==nil{return RuntimeReceipt{},e};return *r.Runtime,e}
func(client *ContainerBrokerClient)ApplyExposure(ctx context.Context,v ExposureMutationRequest)(ExposureReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerApplyExposure,ExposureMutation:&v});if r.Exposure==nil{return ExposureReceipt{},e};return *r.Exposure,e}
func(client *ContainerBrokerClient)DeleteExposure(ctx context.Context,v ExposureMutationRequest)(ExposureReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerDeleteExposure,ExposureMutation:&v});if r.Exposure==nil{return ExposureReceipt{},e};return *r.Exposure,e}
func(client *ContainerBrokerClient)Exec(ctx context.Context,v ExecRequest)(ExecReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerExec,Exec:&v});if r.Exec==nil{return ExecReceipt{},e};return *r.Exec,e}
func(client *ContainerBrokerClient)Stats(ctx context.Context,v WorkloadObservationRequest)(WorkloadObservation,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerStats,WorkloadObservation:&v});if r.Observation==nil{return WorkloadObservation{},e};return *r.Observation,e}
func(client *ContainerBrokerClient)SnapshotVolumes(ctx context.Context,v VolumeSnapshotRequest)(VolumeSnapshotReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerSnapshotVolumes,VolumeSnapshot:&v});if r.VolumeSnapshot==nil{return VolumeSnapshotReceipt{},e};return *r.VolumeSnapshot,e}
func(client *ContainerBrokerClient)RestoreVolumes(ctx context.Context,v VolumeRestoreRequest)(VolumeSnapshotReceipt,error){r,e:=client.call(ctx,BrokerWireRequest{Method:BrokerRestoreVolumes,VolumeRestore:&v});if r.VolumeSnapshot==nil{return VolumeSnapshotReceipt{},e};return *r.VolumeSnapshot,e}
func(client *ContainerBrokerClient)OpenLogs(_ context.Context,v LogRequest)(LogStream,error){if client==nil||!v.WorkloadID.Valid()||v.MaxBytes==0||v.MaxBytes>ContainerBrokerMaximumLogBytes{return nil,ErrInvalid};return &remoteContainerLogStream{client:client,request:v},nil}

type remoteContainerLogStream struct{client *ContainerBrokerClient;request LogRequest;mu sync.Mutex;closed bool}
func(stream *remoteContainerLogStream)Next(ctx context.Context)(StreamChunk,error){stream.mu.Lock();defer stream.mu.Unlock();if stream.closed{return StreamChunk{},io.EOF};response,err:=stream.client.call(ctx,BrokerWireRequest{Method:BrokerReadLogs,Logs:&stream.request});if err!=nil{return StreamChunk{},err};chunk:=*response.Log;stream.request.Cursor=chunk.Cursor;if chunk.EOF{stream.closed=true};return chunk,nil}
func(stream *remoteContainerLogStream)Close()error{stream.mu.Lock();stream.closed=true;stream.mu.Unlock();return nil}

type ContainerBrokerPeerAuthorizer interface{Authorize(net.Conn)error}
type ContainerReceiptJournal interface{Lookup(BrokerMethod,EffectID,string)(BrokerWireResponse,bool,error);Commit(BrokerMethod,EffectID,string,BrokerWireResponse)error}
type ContainerBrokerServer struct{Authorizer ContainerBrokerPeerAuthorizer;Broker Broker;Journal ContainerReceiptJournal;MaximumConcurrent uint32}

func(server *ContainerBrokerServer)Serve(listener net.Listener)error{if server==nil||listener==nil||server.Authorizer==nil||server.Broker==nil||server.Journal==nil{return ErrContainerBrokerProtocol};maximum:=server.MaximumConcurrent;if maximum==0{maximum=64};if maximum>512{maximum=512};gate:=make(chan struct{},maximum);var group sync.WaitGroup;defer group.Wait();for{connection,err:=listener.Accept();if err!=nil{return err};select{case gate<-struct{}{}:group.Add(1);go func(){defer func(){<-gate;group.Done();connection.Close()}();server.serve(connection)}();default:_=connection.Close()}}}
func(server *ContainerBrokerServer)serve(connection net.Conn){if server.Authorizer.Authorize(connection)!=nil{return};now:=time.Now().UTC();_=connection.SetDeadline(now.Add(10*time.Minute));var request BrokerWireRequest;if readContainerBrokerFrame(connection,&request)!=nil||request.Validate(now)!=nil{return};_=connection.SetDeadline(request.Deadline);ctx,cancel:=context.WithDeadline(context.Background(),request.Deadline);defer cancel();digest:=brokerRequestDigest(request);effect:=brokerRequestEffect(request);if effect!=""{if cached,found,err:=server.Journal.Lookup(request.Method,effect,digest);err==nil&&found{cached.RequestID=request.RequestID;cached.CompletedAt=time.Now().UTC();_=writeContainerBrokerFrame(connection,cached);return}else if err!=nil{return}};response:=server.dispatch(ctx,request);response.Version=ContainerBrokerProtocolVersion;response.RequestID=request.RequestID;response.Method=request.Method;response.CompletedAt=time.Now().UTC();if response.Validate(request,time.Now().UTC())!=nil{return};if effect!=""{if server.Journal.Commit(request.Method,effect,digest,response)!=nil{return}};_=writeContainerBrokerFrame(connection,response)}

func(server *ContainerBrokerServer)dispatch(ctx context.Context,request BrokerWireRequest)BrokerWireResponse{response:=BrokerWireResponse{};var err error;switch request.Method{
	case BrokerInspectRuntime:var v RuntimeCapability;v,err=server.Broker.InspectRuntime(ctx);response.Capability=&v
	case BrokerInstallRuntime:var v RuntimeReceipt;v,err=server.Broker.InstallRuntime(ctx,*request.InstallRuntime);response.Runtime=&v
	case BrokerRemoveRuntime:var v RuntimeReceipt;v,err=server.Broker.RemoveRuntime(ctx,*request.RuntimeMutation);response.Runtime=&v
	case BrokerResolveImage:var v ImageReference;v,err=server.Broker.ResolveImage(ctx,*request.ResolveImage);response.Image=&v
	case BrokerPullImage:var v PullReceipt;v,err=server.Broker.PullImage(ctx,*request.PullImage);response.Pull=&v
	case BrokerDeleteImage:var v PullReceipt;v,err=server.Broker.DeleteImage(ctx,*request.ImageMutation);response.Pull=&v
	case BrokerEnsureVolume:var v VolumeReceipt;v,err=server.Broker.EnsureVolume(ctx,*request.VolumeMutation);response.Volume=&v
	case BrokerDeleteVolume:var v VolumeReceipt;v,err=server.Broker.DeleteVolume(ctx,*request.VolumeMutation);response.Volume=&v
	case BrokerEnsureNetwork:var v NetworkReceipt;v,err=server.Broker.EnsureNetwork(ctx,*request.NetworkMutation);response.Network=&v
	case BrokerDeleteNetwork:var v NetworkReceipt;v,err=server.Broker.DeleteNetwork(ctx,*request.NetworkMutation);response.Network=&v
	case BrokerApplyWorkload:var v RuntimeReceipt;v,err=server.Broker.ApplyWorkload(ctx,*request.WorkloadMutation);response.Runtime=&v
	case BrokerObserveWorkload:var v RuntimeReceipt;v,err=server.Broker.ObserveWorkload(ctx,*request.WorkloadObservation);response.Runtime=&v
	case BrokerSetLifecycle:var v RuntimeReceipt;v,err=server.Broker.SetLifecycle(ctx,*request.WorkloadLifecycle);response.Runtime=&v
	case BrokerDeleteWorkload:var v RuntimeReceipt;v,err=server.Broker.DeleteWorkload(ctx,*request.WorkloadMutation);response.Runtime=&v
	case BrokerApplyExposure:var v ExposureReceipt;v,err=server.Broker.ApplyExposure(ctx,*request.ExposureMutation);response.Exposure=&v
	case BrokerDeleteExposure:var v ExposureReceipt;v,err=server.Broker.DeleteExposure(ctx,*request.ExposureMutation);response.Exposure=&v
	case BrokerExec:var v ExecReceipt;v,err=server.Broker.Exec(ctx,*request.Exec);response.Exec=&v
	case BrokerReadLogs:var stream LogStream;stream,err=server.Broker.OpenLogs(ctx,*request.Logs);if err==nil{var v StreamChunk;v,err=stream.Next(ctx);_=stream.Close();response.Log=&v}else{response.Log=&StreamChunk{Cursor:request.Logs.Cursor,EOF:true}}
	case BrokerStats:var v WorkloadObservation;v,err=server.Broker.Stats(ctx,*request.WorkloadObservation);response.Observation=&v
	case BrokerSnapshotVolumes:var v VolumeSnapshotReceipt;v,err=server.Broker.SnapshotVolumes(ctx,*request.VolumeSnapshot);response.VolumeSnapshot=&v
	case BrokerRestoreVolumes:var v VolumeSnapshotReceipt;v,err=server.Broker.RestoreVolumes(ctx,*request.VolumeRestore);response.VolumeSnapshot=&v
	};response.ErrorCode=classifyContainerBrokerError(err);return response}

func brokerRequestEffect(request BrokerWireRequest)EffectID{switch request.Method{case BrokerInstallRuntime:return request.InstallRuntime.EffectID;case BrokerRemoveRuntime:return request.RuntimeMutation.EffectID;case BrokerResolveImage:return request.ResolveImage.EffectID;case BrokerPullImage:return request.PullImage.EffectID;case BrokerDeleteImage:return request.ImageMutation.EffectID;case BrokerEnsureVolume,BrokerDeleteVolume:return request.VolumeMutation.EffectID;case BrokerEnsureNetwork,BrokerDeleteNetwork:return request.NetworkMutation.EffectID;case BrokerApplyWorkload,BrokerDeleteWorkload:return request.WorkloadMutation.EffectID;case BrokerSetLifecycle:return request.WorkloadLifecycle.EffectID;case BrokerApplyExposure,BrokerDeleteExposure:return request.ExposureMutation.EffectID;case BrokerExec:return request.Exec.EffectID;case BrokerSnapshotVolumes:return request.VolumeSnapshot.EffectID;case BrokerRestoreVolumes:return request.VolumeRestore.EffectID};return ""}

func validateSnapshotRequest(request VolumeSnapshotRequest)error{if request.EffectID==""||!request.SnapshotID.Valid()||!request.TenantID.Valid()||!request.ApplicationID.Valid()||request.Fence==0||len(request.VolumeIDs)==0||len(request.VolumeIDs)>64{return ErrInvalid};seen:=map[ID]bool{};for _,id:=range request.VolumeIDs{if !id.Valid()||seen[id]{return ErrInvalid};seen[id]=true};return nil}
func validateRestoreRequest(request VolumeRestoreRequest)error{if request.EffectID==""||!request.SnapshotID.Valid()||!request.TenantID.Valid()||request.Fence==0||len(request.VolumeIDs)==0||len(request.VolumeIDs)>64{return ErrInvalid};seen:=map[ID]bool{};for _,id:=range request.VolumeIDs{if !id.Valid()||seen[id]{return ErrInvalid};seen[id]=true};return nil}
func brokerRequestDigest(request BrokerWireRequest)string{copy:=request;copy.RequestID="";copy.Deadline=time.Time{};encoded,_:=json.Marshal(copy);sum:=sha256.Sum256(encoded);return hex.EncodeToString(sum[:])}
func classifyContainerBrokerError(err error)string{switch{case err==nil:return "";case errors.Is(err,ErrInvalid),errors.Is(err,ErrContainerBrokerProtocol):return "invalid_request";case errors.Is(err,ErrForbidden),errors.Is(err,ErrContainerBrokerPeer):return "unauthorized";case errors.Is(err,ErrNotFound):return "not_found";case errors.Is(err,ErrConflict):return "conflict";case errors.Is(err,ErrStale):return "stale";case errors.Is(err,ErrPolicy):return "policy_rejected";case errors.Is(err,ErrInUse):return "in_use";case errors.Is(err,ErrAmbiguous):return "ambiguous";default:return "unavailable"}}
func containerBrokerError(code string)error{switch code{case "invalid_request":return ErrInvalid;case "unauthorized":return ErrForbidden;case "not_found":return ErrNotFound;case "conflict":return ErrConflict;case "stale":return ErrStale;case "policy_rejected":return ErrPolicy;case "in_use":return ErrInUse;case "ambiguous":return ErrAmbiguous;default:return errors.New("containers: broker unavailable")}}

func writeContainerBrokerFrame(writer io.Writer,value any)error{encoded,err:=json.Marshal(value);if err!=nil||len(encoded)==0||len(encoded)>ContainerBrokerMaximumFrameBytes{return ErrContainerBrokerProtocol};var header [4]byte;binary.BigEndian.PutUint32(header[:],uint32(len(encoded)));if err=writeContainerBrokerAll(writer,header[:]);err!=nil{return err};return writeContainerBrokerAll(writer,encoded)}
func writeContainerBrokerAll(writer io.Writer,content []byte)error{for len(content)>0{count,err:=writer.Write(content);if err!=nil{return err};if count<=0||count>len(content){return io.ErrShortWrite};content=content[count:]};return nil}
func readContainerBrokerFrame(reader io.Reader,target any)error{var header [4]byte;if _,err:=io.ReadFull(reader,header[:]);err!=nil{return err};size:=binary.BigEndian.Uint32(header[:]);if size==0||size>ContainerBrokerMaximumFrameBytes{return ErrContainerBrokerProtocol};content:=make([]byte,size);if _,err:=io.ReadFull(reader,content);err!=nil{return err};decoder:=json.NewDecoder(bytes.NewReader(content));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil||decoder.Decode(&struct{}{})!=io.EOF{return ErrContainerBrokerProtocol};return nil}

var _ Broker=(*ContainerBrokerClient)(nil)
