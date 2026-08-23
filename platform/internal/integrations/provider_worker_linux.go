//go:build linux

package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

const ProviderWorkerSocketPath = "/run/cyberpanel-provider/provider-worker.sock"
const ProviderWorkerExecutablePath = "/usr/local/libexec/cyberpanel/panel-providerd"

func ProviderWorkerReleaseDigest(path string)(string,error){if path==""{path=ProviderWorkerExecutablePath};file,err:=os.Open(path);if err!=nil{return "",err};defer file.Close();hash:=sha256.New();copied,err:=io.Copy(hash,io.LimitReader(file,1<<30));if err!=nil||copied<=0||copied>=1<<30{return "",ErrIntegrity};return hex.EncodeToString(hash.Sum(nil)),nil}

func DefaultProviderWorkerRegistrations(releaseDigest string, providers map[ProviderKind]Provider) ([]ProviderRegistration,error) {
	if !validDigest(releaseDigest)||len(providers)==0{return nil,ErrInvalid}
	profiles,err:=DefaultProviderWorkerSecretProfiles(releaseDigest);if err!=nil{return nil,err};definitions:=defaultProviderWorkerDefinitions()
	result:=make([]ProviderRegistration,0,len(definitions));for _,definition:=range definitions{provider:=providers[definition.Kind];if provider==nil{continue};definition.Provider=provider;definition.Secret=profiles[definition.Kind];result=append(result,definition)};if len(result)==0{return nil,ErrUnsupported};return result,nil
}

func DefaultProviderWorkerSecretProfiles(releaseDigest string)(map[ProviderKind]SecretConsumerProfile,error){if !validDigest(releaseDigest){return nil,ErrInvalid};profiles:=map[ProviderKind]SecretConsumerProfile{};for _,definition:=range defaultProviderWorkerDefinitions(){profiles[definition.Kind]=SecretConsumerProfile{AdapterID:ProviderWorkerAdapterID,AdapterVersion:ProviderWorkerAdapterVersion,Account:"binding",Origin:definition.Endpoint.URL,ConsumerReleaseDigest:releaseDigest,Operations:[]secrets.Operation{secrets.OperationAuthenticate}}};return profiles,nil}

func defaultProviderWorkerDefinitions()[]ProviderRegistration{endpoint:=func(raw,server string)EndpointPolicy{return EndpointPolicy{URL:raw,ServerName:server,AllowPublicInternet:true,DenyPrivateRanges:true,MaximumRedirects:0}};return []ProviderRegistration{{PublicName:"cloudflare",Kind:ProviderCloudflare,Purpose:PurposeDNS,Endpoint:endpoint("https://api.cloudflare.com","api.cloudflare.com")},{PublicName:"aws_s3",Kind:ProviderAWSS3,Purpose:PurposeBackup,Endpoint:endpoint("https://s3.amazonaws.com","s3.amazonaws.com")},{PublicName:"wasabi_s3",Kind:ProviderWasabi,Purpose:PurposeBackup,Endpoint:endpoint("https://s3.wasabisys.com","s3.wasabisys.com")},{PublicName:"backblaze_b2_s3",Kind:ProviderBackblaze,Purpose:PurposeBackup,Endpoint:endpoint("https://s3.us-west-004.backblazeb2.com","s3.us-west-004.backblazeb2.com")}}}

type LocalProviderWorkerDialer struct{}

func (LocalProviderWorkerDialer) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", ProviderWorkerSocketPath)
}

func NewLocalProviderWorkerClient(kind ProviderKind) (*ProviderWorkerClient, error) {
	if !kind.Valid() {
		return nil, ErrInvalid
	}
	info, err := os.Lstat(ProviderWorkerSocketPath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0002 != 0 {
		return nil, ErrPolicyDenied
	}
	return &ProviderWorkerClient{Transport:FramedProviderWorkerTransport{Dialer:LocalProviderWorkerDialer{}},Kind:kind,Now:time.Now}, nil
}

func ListenProviderWorker(ownerUID, groupGID int) (*net.UnixListener, error) {
	if ownerUID < 0 || groupGID <= 0 {
		return nil, ErrInvalid
	}
	directory := "/run/cyberpanel-provider"
	if err := os.Mkdir(directory, 0750); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0002 != 0 {
		return nil, ErrPolicyDenied
	}
	if info, err = os.Lstat(ProviderWorkerSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, ErrPolicyDenied
		}
		if err = os.Remove(ProviderWorkerSocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name:ProviderWorkerSocketPath,Net:"unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chown(ProviderWorkerSocketPath, ownerUID, groupGID); err == nil {
		err = os.Chmod(ProviderWorkerSocketPath, 0660)
	}
	if err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

type ProviderWorkerPeerPolicy struct{ AllowedUID uint32 }

func (policy ProviderWorkerPeerPolicy) Authorize(connection net.Conn) error {
	if policy.AllowedUID == 0 {
		return ErrPolicyDenied
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return ErrPolicyDenied
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return ErrPolicyDenied
	}
	var credential *syscall.Ucred
	var credentialErr error
	if err = raw.Control(func(fd uintptr){ credential, credentialErr = syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED) }); err != nil || credentialErr != nil || credential == nil || credential.Pid <= 1 || credential.Uid != policy.AllowedUID {
		return ErrPolicyDenied
	}
	return nil
}

type ProviderWorkerServer struct {
	Authorizer ProviderWorkerPeerPolicy
	Providers map[ProviderKind]Provider
	Now        func() time.Time
	MaximumConcurrent uint32
	once sync.Once
	semaphore chan struct{}
}

func (server *ProviderWorkerServer) Serve(listener *net.UnixListener) error {
	if server == nil || listener == nil || len(server.Providers) == 0 {
		return ErrInvalid
	}
	server.once.Do(func(){ maximum:=server.MaximumConcurrent;if maximum==0{maximum=32};if maximum>256{maximum=256};server.semaphore=make(chan struct{},maximum) })
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		select {
		case server.semaphore <- struct{}{}:
			go func(){ defer func(){<-server.semaphore;_ = connection.Close()}();server.serve(connection) }()
		default:
			_ = connection.Close()
		}
	}
}

func (server *ProviderWorkerServer) serve(connection *net.UnixConn) {
	if server.Authorizer.Authorize(connection) != nil {
		return
	}
	now:=time.Now().UTC();if server.Now!=nil{now=server.Now().UTC()}
	_ = connection.SetReadDeadline(now.Add(15*time.Second))
	var request ProviderWorkerRequest
	if readProviderWorkerFrame(connection,&request)!=nil||request.Validate(now)!=nil{return}
	_ = connection.SetDeadline(request.Deadline)
	ctx,cancel:=context.WithDeadline(context.Background(),request.Deadline);defer cancel()
	response:=ProviderWorkerResponse{Version:ProviderWorkerProtocolVersion,RequestID:request.RequestID,Action:request.Action}
	provider:=server.Providers[request.Binding.Kind]
	if provider==nil{response.Failure=ErrorPermanent;response.FailureCode="unsupported_provider";_ = writeProviderWorkerFrame(connection,response);return}
	var err error
	switch request.Action {
	case ProviderWorkerDiscover:
		var value CapabilitySet
		value,err=provider.DiscoverCapabilities(ctx,request.Binding)
		if err==nil{response.Capabilities=&value}
	case ProviderWorkerHealth:
		var value ProviderHealth
		value,err=provider.Health(ctx,request.Binding)
		if err==nil{response.Health=&value}
	case ProviderWorkerValidate:
		err=provider.ValidateCredential(ctx,request.Binding)
	case ProviderWorkerRevoke:
		err=provider.RevokeCredential(ctx,request.Binding)
	default:
		err=ErrUnsupported
	}
	if err==nil{response.Succeeded=true}else{response.Failure,response.FailureCode=classifyProviderWorkerError(err)}
	_ = writeProviderWorkerFrame(connection,response)
}

func classifyProviderWorkerError(err error)(ErrorClass,string){var providerError *ProviderError;if errors.As(err,&providerError){return providerError.Class,providerError.Code};switch{case errors.Is(err,ErrUnauthorized):return ErrorUnauthorized,"credential_rejected";case errors.Is(err,ErrRateLimited):return ErrorRateLimited,"rate_limited";case errors.Is(err,ErrConflict):return ErrorConflict,"conflict";case errors.Is(err,ErrPartial):return ErrorPartial,"partial";case errors.Is(err,ErrAmbiguous):return ErrorAmbiguous,"ambiguous";case errors.Is(err,ErrInvalid),errors.Is(err,ErrPolicyDenied):return ErrorInvalid,"invalid_request";default:return ErrorUnavailable,"provider_unavailable"}}
