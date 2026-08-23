//go:build linux

package apiserver

import (
	"net"
	"syscall"
)

func(policy *StaticPeerPolicy)Authorize(connection net.Conn)error{if policy==nil||len(policy.AllowedUIDs)==0{return ErrUntrustedPeer};unixConnection,ok:=connection.(*net.UnixConn);if !ok{return ErrUntrustedPeer};raw,err:=unixConnection.SyscallConn();if err!=nil{return ErrUntrustedPeer};var credential *syscall.Ucred;var controlErr error;if err=raw.Control(func(fd uintptr){credential,controlErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)});err!=nil||controlErr!=nil||credential==nil||credential.Pid<=1{return ErrUntrustedPeer};if _,allowed:=policy.AllowedUIDs[credential.Uid];!allowed{return ErrUntrustedPeer};return nil}
