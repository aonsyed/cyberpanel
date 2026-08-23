package management

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
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

const (
	LinuxManagementSocketPath = "/run/cyberpanel/webengine-management.sock"
	linuxManagementProtocolVersion uint32 = 1
	linuxManagementMaximumFrame = 64 << 20
)

type LinuxManagementOperation string

const (
	LinuxManagementInspect LinuxManagementOperation = "lifecycle.inspect"
	LinuxManagementInstall LinuxManagementOperation = "lifecycle.install"
	LinuxManagementUpgrade LinuxManagementOperation = "lifecycle.upgrade"
	LinuxManagementConvert LinuxManagementOperation = "lifecycle.convert"
	LinuxManagementRemove LinuxManagementOperation = "lifecycle.remove"
)

type LinuxManagementRequest struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	Operation LinuxManagementOperation `json:"operation"`
	Deadline time.Time `json:"deadline"`
	Payload json.RawMessage `json:"payload"`
	PayloadDigest string `json:"payload_digest"`
}

type linuxManagementResponse struct {
	Version uint32 `json:"version"`
	RequestID string `json:"request_id"`
	Operation LinuxManagementOperation `json:"operation"`
	Succeeded bool `json:"succeeded"`
	Payload json.RawMessage `json:"payload,omitempty"`
	PayloadDigest string `json:"payload_digest,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}

type lifecyclePlanInput struct{Request EffectRequest `json:"request"`;Plan ArtifactPlan `json:"plan"`}
type lifecycleConvertInput struct{Request EffectRequest `json:"request"`;Plan ArtifactPlan `json:"plan"`;Generation native.ConfigGeneration `json:"generation"`;RollbackWindow time.Duration `json:"rollback_window"`}
type lifecycleRemoveInput struct{Request EffectRequest `json:"request"`;Edition webengine.Edition `json:"edition"`}

type LinuxManagementBrokerHandler interface { HandleManagement(context.Context, LinuxManagementRequest) (any, error) }
type LinuxManagementPeerAuthorizer interface { Authorize(net.Conn) error }

type LinuxManagementBrokerServer struct {
	Authorizer LinuxManagementPeerAuthorizer
	Handler LinuxManagementBrokerHandler
	MaximumConcurrent uint32
}

func (server *LinuxManagementBrokerServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.Authorizer == nil || server.Handler == nil { return ErrInvalid }
	maximum:=server.MaximumConcurrent;if maximum==0{maximum=8};if maximum>32{maximum=32}
	gate:=make(chan struct{},maximum);var workers sync.WaitGroup;defer workers.Wait()
	for { connection,err:=listener.Accept();if err!=nil{return err};select{case gate<-struct{}{}:workers.Add(1);go func(){defer func(){<-gate;workers.Done();connection.Close()}();server.serve(connection)}();default:_=connection.Close()} }
}

func (server *LinuxManagementBrokerServer) serve(connection net.Conn) {
	if server.Authorizer.Authorize(connection)!=nil{return}
	now:=time.Now().UTC();_=connection.SetReadDeadline(now.Add(15*time.Second))
	var request LinuxManagementRequest
	if readLinuxManagementFrame(connection,&request)!=nil||request.validate(now)!=nil{return}
	_=connection.SetDeadline(request.Deadline);ctx,cancel:=context.WithDeadline(context.Background(),request.Deadline);defer cancel()
	result,handleErr:=server.Handler.HandleManagement(ctx,request);payload,_:=json.Marshal(result)
	response:=linuxManagementResponse{Version:linuxManagementProtocolVersion,RequestID:request.RequestID,Operation:request.Operation,Succeeded:handleErr==nil,Payload:payload,PayloadDigest:linuxManagementDigest(payload),CompletedAt:time.Now().UTC()}
	if handleErr!=nil{response.ErrorCode=classifyLinuxManagementError(handleErr)}
	if response.validate(request,time.Now().UTC())!=nil{return};_=writeLinuxManagementFrame(connection,response)
}

type LinuxManagementClient struct{}

func NewLocalLinuxManagementClient() (*LinuxManagementClient,error) {
	info,err:=os.Lstat(LinuxManagementSocketPath);if err!=nil{return nil,err}
	if info.Mode()&os.ModeSocket==0||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0o002!=0{return nil,ErrInvalid}
	return &LinuxManagementClient{},nil
}

func(client *LinuxManagementClient)call(ctx context.Context,operation LinuxManagementOperation,input,output any)error{
	if client==nil||ctx==nil{return ErrInvalid};payload,err:=json.Marshal(input);if err!=nil||len(payload)==0||len(payload)>linuxManagementMaximumFrame{return ErrInvalid}
	digest:=linuxManagementDigest(payload);deadline:=time.Now().UTC().Add(30*time.Minute);if value,ok:=ctx.Deadline();ok&&value.Before(deadline){deadline=value.UTC()}
	request:=LinuxManagementRequest{Version:linuxManagementProtocolVersion,RequestID:"wem-"+linuxManagementDigest([]byte(string(operation)+"\x00"+digest))[:40],Operation:operation,Deadline:deadline,Payload:payload,PayloadDigest:digest}
	connection,err:=(&net.Dialer{}).DialContext(ctx,"unix",LinuxManagementSocketPath);if err!=nil{return err};defer connection.Close();stop:=context.AfterFunc(ctx,func(){_=connection.SetDeadline(time.Now())});defer stop();_=connection.SetDeadline(deadline)
	if err=writeLinuxManagementFrame(connection,request);err!=nil{return err};var response linuxManagementResponse;if err=readLinuxManagementFrame(connection,&response);err!=nil{return err};if err=response.validate(request,time.Now().UTC());err!=nil{return err}
	if output!=nil&&len(response.Payload)!=0{decoder:=json.NewDecoder(bytes.NewReader(response.Payload));decoder.DisallowUnknownFields();if decoder.Decode(output)!=nil||decoder.Decode(&struct{}{})!=io.EOF{return ErrAmbiguous}}
	if !response.Succeeded{return linuxManagementFailure(response.ErrorCode)};return nil
}

func(client *LinuxManagementClient)Inspect(ctx context.Context,edition webengine.Edition)(output Installation,err error){err=client.call(ctx,LinuxManagementInspect,struct{Edition webengine.Edition `json:"edition"`}{edition},&output);return}
func(client *LinuxManagementClient)Install(ctx context.Context,request EffectRequest,plan ArtifactPlan)(output EffectReceipt,err error){err=client.call(ctx,LinuxManagementInstall,lifecyclePlanInput{request,plan},&output);return}
func(client *LinuxManagementClient)Upgrade(ctx context.Context,request EffectRequest,plan ArtifactPlan)(output EffectReceipt,err error){err=client.call(ctx,LinuxManagementUpgrade,lifecyclePlanInput{request,plan},&output);return}
func(client *LinuxManagementClient)ConvertEdition(ctx context.Context,request EffectRequest,plan ArtifactPlan,generation native.ConfigGeneration,window time.Duration)(output SwitchReceipt,err error){err=client.call(ctx,LinuxManagementConvert,lifecycleConvertInput{request,plan,generation,window},&output);return}
func(client *LinuxManagementClient)Remove(ctx context.Context,request EffectRequest,edition webengine.Edition)(output EffectReceipt,err error){err=client.call(ctx,LinuxManagementRemove,lifecycleRemoveInput{request,edition},&output);return}

func(request LinuxManagementRequest)validate(now time.Time)error{if request.Version!=linuxManagementProtocolVersion||len(request.RequestID)<8||len(request.RequestID)>96||request.Operation==""||request.Deadline.IsZero()||!request.Deadline.After(now)||request.Deadline.After(now.Add(31*time.Minute))||len(request.Payload)==0||len(request.Payload)>linuxManagementMaximumFrame||request.PayloadDigest!=linuxManagementDigest(request.Payload){return ErrInvalid};return nil}
func(response linuxManagementResponse)validate(request LinuxManagementRequest,now time.Time)error{if response.Version!=linuxManagementProtocolVersion||response.RequestID!=request.RequestID||response.Operation!=request.Operation||response.CompletedAt.IsZero()||response.CompletedAt.After(now.Add(time.Minute))||response.PayloadDigest!=linuxManagementDigest(response.Payload){return ErrAmbiguous};if response.Succeeded{if response.ErrorCode!=""{return ErrAmbiguous}}else if response.ErrorCode==""{return ErrAmbiguous};return nil}
func linuxManagementDigest(value []byte)string{sum:=sha256.Sum256(value);return hex.EncodeToString(sum[:])}
func classifyLinuxManagementError(err error)string{switch{case errors.Is(err,ErrInvalid):return "invalid";case errors.Is(err,ErrNotFound):return "not_found";case errors.Is(err,ErrConflict):return "conflict";case errors.Is(err,ErrUnsupported):return "unsupported";case errors.Is(err,ErrLicense):return "license";case errors.Is(err,ErrAmbiguous):return "ambiguous";default:return "failed"}}
func linuxManagementFailure(code string)error{switch code{case"":return nil;case"invalid":return ErrInvalid;case"not_found":return ErrNotFound;case"conflict":return ErrConflict;case"unsupported":return ErrUnsupported;case"license":return ErrLicense;case"ambiguous":return ErrAmbiguous;default:return errors.New("webengine management broker failed")}}
func writeLinuxManagementFrame(writer io.Writer,value any)error{content,err:=json.Marshal(value);if err!=nil||len(content)==0||len(content)>linuxManagementMaximumFrame{return ErrInvalid};var header[4]byte;binary.BigEndian.PutUint32(header[:],uint32(len(content)));if err=writeLinuxManagementAll(writer,header[:]);err!=nil{return err};return writeLinuxManagementAll(writer,content)}
func writeLinuxManagementAll(writer io.Writer,content []byte)error{for len(content)>0{written,err:=writer.Write(content);if err!=nil{return err};if written<=0||written>len(content){return io.ErrShortWrite};content=content[written:]};return nil}
func readLinuxManagementFrame(reader io.Reader,target any)error{var header[4]byte;if _,err:=io.ReadFull(reader,header[:]);err!=nil{return err};size:=binary.BigEndian.Uint32(header[:]);if size==0||size>linuxManagementMaximumFrame{return ErrInvalid};content:=make([]byte,size);if _,err:=io.ReadFull(reader,content);err!=nil{return err};decoder:=json.NewDecoder(bytes.NewReader(content));decoder.DisallowUnknownFields();if decoder.Decode(target)!=nil||decoder.Decode(&struct{}{})!=io.EOF{return ErrInvalid};canonical,err:=json.Marshal(target);if err!=nil||!bytes.Equal(canonical,content){return ErrInvalid};return nil}

var _ LifecycleExecutor = (*LinuxManagementClient)(nil)
