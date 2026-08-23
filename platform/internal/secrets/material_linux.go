//go:build linux

package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const MaterialSocketPath = "/run/cyberpanel-secrets/material.sock"

type LocalMaterialDialer struct{}
func (LocalMaterialDialer) DialContext(ctx context.Context)(net.Conn,error){return (&net.Dialer{}).DialContext(ctx,"unix",MaterialSocketPath)}

func NewLocalMaterialClient()(*MaterialClient,error){
	info,err:=os.Lstat(MaterialSocketPath);if err!=nil{return nil,err}
	if info.Mode()&os.ModeSocket==0||info.Mode().Perm()&0002!=0{return nil,ErrForbidden}
	return NewMaterialClient(FramedMaterialTransport{Dialer:LocalMaterialDialer{}})
}

type LinuxMaterialPeerAuthorizer struct{allowed map[uint32]struct{}}
func NewLinuxMaterialPeerAuthorizer(allowedUIDs ...uint32)(*LinuxMaterialPeerAuthorizer,error){result:=&LinuxMaterialPeerAuthorizer{allowed:map[uint32]struct{}{}};for _,uid:=range allowedUIDs{if uid==0{result.allowed[uid]=struct{}{};continue};result.allowed[uid]=struct{}{}};if len(result.allowed)==0{return nil,ErrInvalid};return result,nil}
func(policy *LinuxMaterialPeerAuthorizer)Authorize(connection net.Conn)(VerifiedPeer,error){
	if policy==nil{return VerifiedPeer{},ErrForbidden};unixConnection,ok:=connection.(*net.UnixConn);if !ok{return VerifiedPeer{},ErrForbidden};raw,err:=unixConnection.SyscallConn();if err!=nil{return VerifiedPeer{},ErrForbidden}
	var credential *syscall.Ucred;var credentialErr error;if err=raw.Control(func(fd uintptr){credential,credentialErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)});err!=nil||credentialErr!=nil||credential==nil||credential.Pid<=1{return VerifiedPeer{},ErrForbidden};if _,ok=policy.allowed[credential.Uid];!ok{return VerifiedPeer{},ErrForbidden}
	start,err:=linuxProcessStart(uint32(credential.Pid));if err!=nil{return VerifiedPeer{},ErrForbidden};digest,err:=linuxExecutableDigest(uint32(credential.Pid));if err!=nil{return VerifiedPeer{},ErrForbidden};return VerifiedPeer{UID:credential.Uid,PID:uint32(credential.Pid),ProcessStart:start,ExecutableDigest:digest},nil
}

type LinuxConsumerRegistry struct{}
func(LinuxConsumerRegistry)Verify(_ context.Context,consumer ConsumerIdentity)(bool,error){if consumer.Validate()!=nil{return false,nil};start,err:=linuxProcessStart(consumer.PID);if err!=nil{return false,err};digest,err:=linuxExecutableDigest(consumer.PID);if err!=nil{return false,err};return start==consumer.ProcessStart&&digest==consumer.ExecutableDigest&&digest==consumer.ReleaseDigest,nil}

func ListenMaterialBroker(ownerUID int,groupGID int)(*net.UnixListener,error){
	if ownerUID<0||groupGID<=0{return nil,ErrInvalid};directory:="/run/cyberpanel-secrets";if err:=os.Mkdir(directory,0750);err!=nil&&!errors.Is(err,os.ErrExist){return nil,err};info,err:=os.Lstat(directory);if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0002!=0{return nil,ErrForbidden};if err=os.Chown(directory,ownerUID,groupGID);err!=nil{return nil,err};if err=os.Chmod(directory,0750);err!=nil{return nil,err}
	if info,err=os.Lstat(MaterialSocketPath);err==nil{if info.Mode()&os.ModeSocket==0{return nil,ErrForbidden};if err=os.Remove(MaterialSocketPath);err!=nil{return nil,err}}else if !errors.Is(err,os.ErrNotExist){return nil,err};listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:MaterialSocketPath,Net:"unix"});if err!=nil{return nil,err};if err=os.Chown(MaterialSocketPath,ownerUID,groupGID);err==nil{err=os.Chmod(MaterialSocketPath,0660)};if err!=nil{listener.Close();return nil,err};return listener,nil
}

func linuxProcessStart(pid uint32)(uint64,error){content,err:=os.ReadFile("/proc/"+strconv.FormatUint(uint64(pid),10)+"/stat");if err!=nil||len(content)>1<<20{return 0,ErrForbidden};closeIndex:=strings.LastIndexByte(string(content),')');if closeIndex<0||closeIndex+2>=len(content){return 0,ErrForbidden};fields:=strings.Fields(string(content[closeIndex+2:]));if len(fields)<=19{return 0,ErrForbidden};value,err:=strconv.ParseUint(fields[19],10,64);if err!=nil||value==0{return 0,ErrForbidden};return value,nil}
func linuxExecutableDigest(pid uint32)(string,error){path:="/proc/"+strconv.FormatUint(uint64(pid),10)+"/exe";file,err:=os.Open(path);if err!=nil{return "",err};defer file.Close();hasher:=sha256.New();copied,err:=io.Copy(hasher,io.LimitReader(file,1<<30));if err!=nil||copied<=0||copied>=1<<30{return "",fmt.Errorf("executable digest unavailable")};return hex.EncodeToString(hasher.Sum(nil)),nil}
