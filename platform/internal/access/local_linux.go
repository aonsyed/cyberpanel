//go:build linux

package access

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
)

const (
	AccessBrokerSocketPath = "/run/cyberpanel/access.sock"
	DefaultAccessJournalRoot = "/var/lib/cyberpanel/access-executor"
)

type LocalAccessBrokerDialer struct{}
func(LocalAccessBrokerDialer)DialContext(ctx context.Context)(net.Conn,error){return (&net.Dialer{}).DialContext(ctx,"unix",AccessBrokerSocketPath)}
func NewLocalAccessClient()(*AccessBrokerClient,error){info,err:=os.Lstat(AccessBrokerSocketPath);if err!=nil{return nil,err};if info.Mode()&os.ModeSocket==0||info.Mode().Perm()&0002!=0{return nil,ErrAccessBrokerPeer};return NewAccessBrokerClient(FramedAccessBrokerTransport{Dialer:LocalAccessBrokerDialer{}})}

type AccessBrokerPeerPolicy struct{allowed map[uint32]struct{}}
func NewAccessBrokerPeerPolicy(controlUID uint32)(*AccessBrokerPeerPolicy,error){if controlUID==0{return nil,ErrAccessBrokerPeer};return &AccessBrokerPeerPolicy{allowed:map[uint32]struct{}{0:{},controlUID:{}}},nil}
func(policy *AccessBrokerPeerPolicy)Authorize(connection net.Conn)error{if policy==nil||len(policy.allowed)==0{return ErrAccessBrokerPeer};unixConnection,ok:=connection.(*net.UnixConn);if !ok{return ErrAccessBrokerPeer};raw,err:=unixConnection.SyscallConn();if err!=nil{return ErrAccessBrokerPeer};var credential *syscall.Ucred;var credentialErr error;if err=raw.Control(func(fd uintptr){credential,credentialErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)});err!=nil||credentialErr!=nil||credential==nil||credential.Pid<=1{return ErrAccessBrokerPeer};if _,allowed:=policy.allowed[credential.Uid];!allowed{return ErrAccessBrokerPeer};return nil}
func ListenAccessBroker(controlGID uint32)(*net.UnixListener,error){if os.Geteuid()!=0||controlGID==0{return nil,ErrAccessBrokerPeer};if err:=ensureAccessDirectory("/run/cyberpanel",0711,0,int(controlGID));err!=nil{return nil,err};if info,err:=os.Lstat(AccessBrokerSocketPath);err==nil{if info.Mode()&os.ModeSocket==0{return nil,errors.New("access broker path is not a socket")};if err=os.Remove(AccessBrokerSocketPath);err!=nil{return nil,err}}else if !errors.Is(err,os.ErrNotExist){return nil,err};listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:AccessBrokerSocketPath,Net:"unix"});if err!=nil{return nil,err};if err=os.Chown(AccessBrokerSocketPath,0,int(controlGID));err==nil{err=os.Chmod(AccessBrokerSocketPath,0660)};if err!=nil{listener.Close();return nil,err};return listener,nil}
func LookupAccessControlIdentity()(uint32,uint32,error){account,err:=user.Lookup("cyberpanel");if err!=nil{return 0,0,err};uid,err:=strconv.ParseUint(account.Uid,10,32);if err!=nil||uid==0{return 0,0,ErrAccessBrokerPeer};gid,err:=strconv.ParseUint(account.Gid,10,32);if err!=nil||gid==0{return 0,0,ErrAccessBrokerPeer};return uint32(uid),uint32(gid),nil}
func ensureAccessDirectory(path string,mode os.FileMode,uid,gid int)error{info,err:=os.Lstat(path);if errors.Is(err,os.ErrNotExist){if err=os.Mkdir(path,mode);err!=nil{return err};info,err=os.Lstat(path)};if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0002!=0{return fmt.Errorf("unsafe access directory %s",path)};if err=os.Chown(path,uid,gid);err!=nil{return err};return os.Chmod(path,mode)}

type accessJournalEntry struct{Request ExecutorEnvelope `json:"request"`;Result ExecutorResult `json:"result"`}
type LinuxAccessReceiptJournal struct{mu sync.Mutex;file *os.File;entries map[string]accessJournalEntry}
func NewLinuxAccessReceiptJournal(root string)(*LinuxAccessReceiptJournal,error){if root==""||root[0]!='/'{return nil,ErrAccessBrokerProtocol};if err:=ensureAccessDirectory(root,0700,0,0);err!=nil{return nil,err};path:=root+"/receipts.jsonl";file,err:=os.OpenFile(path,os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW,0600);if err!=nil{return nil,err};if err=os.Chmod(path,0600);err!=nil{file.Close();return nil,err};journal:=&LinuxAccessReceiptJournal{file:file,entries:map[string]accessJournalEntry{}};limited:=&ioLimitReader{reader:file,remaining:64<<20};scanner:=bufio.NewScanner(limited);buffer:=make([]byte,64<<10);scanner.Buffer(buffer,AccessBrokerMaximumFrameBytes);for scanner.Scan(){var entry accessJournalEntry;decoder:=json.NewDecoder(bytes.NewReader(scanner.Bytes()));decoder.DisallowUnknownFields();if decoder.Decode(&entry)!=nil||entry.Request.RequestID==""||entry.Result.RequestID!=entry.Request.RequestID{file.Close();return nil,ErrAccessBrokerProtocol};journal.entries[entry.Request.RequestID]=entry};if err=scanner.Err();err!=nil{file.Close();return nil,err};if _,err=file.Seek(0,2);err!=nil{file.Close();return nil,err};return journal,nil}
func(journal *LinuxAccessReceiptJournal)Close()error{if journal==nil||journal.file==nil{return nil};journal.mu.Lock();defer journal.mu.Unlock();err:=journal.file.Close();journal.file=nil;return err}
func(journal *LinuxAccessReceiptJournal)Lookup(request ExecutorEnvelope)(ExecutorResult,bool,error){journal.mu.Lock();defer journal.mu.Unlock();entry,found:=journal.entries[request.RequestID];if !found{return ExecutorResult{},false,nil};if entry.Request.Operation!=request.Operation||entry.Request.PayloadHash!=request.PayloadHash||entry.Request.SiteID!=request.SiteID{return ExecutorResult{},false,ErrConflict};return entry.Result,true,nil}
func(journal *LinuxAccessReceiptJournal)Commit(request ExecutorEnvelope,result ExecutorResult)error{journal.mu.Lock();defer journal.mu.Unlock();if prior,found:=journal.entries[request.RequestID];found{if prior.Request.PayloadHash!=request.PayloadHash||prior.Request.Operation!=request.Operation{return ErrConflict};return nil};encoded,err:=json.Marshal(accessJournalEntry{request,result});if err!=nil{return err};encoded=append(encoded,'\n');if _,err=journal.file.Write(encoded);err==nil{err=journal.file.Sync()};if err!=nil{return err};journal.entries[request.RequestID]=accessJournalEntry{request,result};return nil}
type ioLimitReader struct{reader *os.File;remaining int64}
func(reader *ioLimitReader)Read(p []byte)(int,error){if reader.remaining<=0{return 0,errors.New("access journal exceeds limit")};if int64(len(p))>reader.remaining{p=p[:reader.remaining]};count,err:=reader.reader.Read(p);reader.remaining-=int64(count);return count,err}
