//go:build linux

package containers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	ContainerBrokerSocketPath = "/run/cyberpanel/containers.sock"
	DefaultContainerReceiptRoot = "/var/lib/cyberpanel/containers/receipts"
)

type LocalContainerBrokerDialer struct{}
func(LocalContainerBrokerDialer)DialContext(ctx context.Context)(net.Conn,error){return (&net.Dialer{}).DialContext(ctx,"unix",ContainerBrokerSocketPath)}

// NewLocalContainerBrokerClient is the panel-core composition constructor.
// It exposes only the typed containers.Broker contract over the protected UDS.
func NewLocalContainerBrokerClient()(*ContainerBrokerClient,error){info,err:=os.Lstat(ContainerBrokerSocketPath);if err!=nil{return nil,err};if info.Mode()&os.ModeSocket==0||info.Mode().Perm()&0o002!=0{return nil,ErrContainerBrokerPeer};return NewContainerBrokerClient(FramedContainerBrokerTransport{Dialer:LocalContainerBrokerDialer{}})}

type LinuxContainerBrokerPeerPolicy struct{allowedUID uint32}
func NewLinuxContainerBrokerPeerPolicy(controlUID uint32)(*LinuxContainerBrokerPeerPolicy,error){if controlUID==0{return nil,ErrContainerBrokerPeer};return &LinuxContainerBrokerPeerPolicy{allowedUID:controlUID},nil}
func(policy *LinuxContainerBrokerPeerPolicy)Authorize(connection net.Conn)error{if policy==nil||policy.allowedUID==0{return ErrContainerBrokerPeer};unixConnection,ok:=connection.(*net.UnixConn);if !ok{return ErrContainerBrokerPeer};raw,err:=unixConnection.SyscallConn();if err!=nil{return ErrContainerBrokerPeer};var credential *syscall.Ucred;var credentialErr error;if err=raw.Control(func(fd uintptr){credential,credentialErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)});err!=nil||credentialErr!=nil||credential==nil||credential.Pid<=1||credential.Uid!=policy.allowedUID{return ErrContainerBrokerPeer};return nil}

func ListenContainerBroker(controlGID uint32)(*net.UnixListener,error){if os.Geteuid()!=0||controlGID==0{return nil,ErrContainerBrokerPeer};if err:=ensureContainerDirectory("/run/cyberpanel",0o711,0,int(controlGID));err!=nil{return nil,err};if info,err:=os.Lstat(ContainerBrokerSocketPath);err==nil{if info.Mode()&os.ModeSocket==0{return nil,ErrContainerBrokerPeer};if err=os.Remove(ContainerBrokerSocketPath);err!=nil{return nil,err}}else if !errors.Is(err,os.ErrNotExist){return nil,err};listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:ContainerBrokerSocketPath,Net:"unix"});if err!=nil{return nil,err};if err=os.Chown(ContainerBrokerSocketPath,0,int(controlGID));err==nil{err=os.Chmod(ContainerBrokerSocketPath,0o660)};if err!=nil{listener.Close();return nil,err};return listener,nil}

type fileContainerReceipt struct{Method BrokerMethod `json:"method"`;EffectID EffectID `json:"effect_id"`;RequestDigest string `json:"request_digest"`;Response BrokerWireResponse `json:"response"`;CommittedAt time.Time `json:"committed_at"`}
type FileContainerReceiptJournal struct{root string;mu sync.Mutex}
func NewFileContainerReceiptJournal(root string)(*FileContainerReceiptJournal,error){if root==""||!filepath.IsAbs(root){return nil,ErrInvalid};if err:=ensureContainerDirectory(root,0o700,0,0);err!=nil{return nil,err};return &FileContainerReceiptJournal{root:root},nil}
func(journal *FileContainerReceiptJournal)Lookup(method BrokerMethod,effect EffectID,digest string)(BrokerWireResponse,bool,error){if journal==nil||effect==""||len(digest)!=64{return BrokerWireResponse{},false,ErrInvalid};journal.mu.Lock();defer journal.mu.Unlock();content,err:=os.ReadFile(journal.path(method,effect));if errors.Is(err,os.ErrNotExist){return BrokerWireResponse{},false,nil};if err!=nil||len(content)>ContainerBrokerMaximumFrameBytes{return BrokerWireResponse{},false,err};var record fileContainerReceipt;if json.Unmarshal(content,&record)!=nil{return BrokerWireResponse{},false,ErrContainerBrokerProtocol};if record.Method!=method||record.EffectID!=effect||record.RequestDigest!=digest{conflict:=record.Response;conflict.ErrorCode="conflict";return conflict,true,nil};return record.Response,true,nil}
func(journal *FileContainerReceiptJournal)Commit(method BrokerMethod,effect EffectID,digest string,response BrokerWireResponse)error{if journal==nil||effect==""||len(digest)!=64{return ErrInvalid};journal.mu.Lock();defer journal.mu.Unlock();path:=journal.path(method,effect);if content,err:=os.ReadFile(path);err==nil{var record fileContainerReceipt;if json.Unmarshal(content,&record)!=nil{return ErrContainerBrokerProtocol};if record.Method!=method||record.EffectID!=effect||record.RequestDigest!=digest{return ErrConflict};return nil}else if !errors.Is(err,os.ErrNotExist){return err};record:=fileContainerReceipt{Method:method,EffectID:effect,RequestDigest:digest,Response:response,CommittedAt:time.Now().UTC()};content,err:=json.Marshal(record);if err!=nil||len(content)>ContainerBrokerMaximumFrameBytes{return ErrContainerBrokerProtocol};return atomicContainerFile(path,content,0o600)}
func(journal *FileContainerReceiptJournal)path(_ BrokerMethod,effect EffectID)string{sum:=sha256.Sum256([]byte("cyberpanel:container-effect:v1\x00"+string(effect)));return filepath.Join(journal.root,hex.EncodeToString(sum[:])+".json")}

func ensureContainerDirectory(path string,mode os.FileMode,uid,gid int)error{if !filepath.IsAbs(path){return ErrInvalid};if err:=os.MkdirAll(path,mode);err!=nil{return err};info,err:=os.Lstat(path);if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0o002!=0{return ErrForbidden};if os.Geteuid()==0{if err=os.Chown(path,uid,gid);err!=nil{return err}};return os.Chmod(path,mode)}
func atomicContainerFile(path string,content []byte,mode os.FileMode)error{directory:=filepath.Dir(path);temporary,err:=os.CreateTemp(directory,".container-");if err!=nil{return err};name:=temporary.Name();defer os.Remove(name);if err=temporary.Chmod(mode);err==nil{_,err=temporary.Write(content)};if err==nil{err=temporary.Sync()};closeErr:=temporary.Close();if err==nil{err=closeErr};if err!=nil{return err};if err=os.Rename(name,path);err!=nil{return err};dir,err:=os.Open(directory);if err!=nil{return err};defer dir.Close();return dir.Sync()}
func readBoundedContainerFile(path string,maximum int64)([]byte,error){file,err:=os.Open(path);if err!=nil{return nil,err};defer file.Close();content,err:=io.ReadAll(io.LimitReader(file,maximum+1));if err!=nil||int64(len(content))>maximum{return nil,ErrInvalid};return content,nil}
