//go:build linux

package siteops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

type UnixDialer struct{}

func (UnixDialer) DialContext(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, "unix", DefaultSocketPath)
}

func NewLocalClient() (*Client, error) { return NewClient(FramedTransport{Dialer: UnixDialer{}}) }

type PeerPolicy struct{ allowed map[uint32]struct{} }

func NewPeerPolicy(controlUID uint32) (*PeerPolicy, error) {
	if controlUID == 0 { return nil, errors.New("control-plane UID must be non-root") }
	return &PeerPolicy{allowed: map[uint32]struct{}{0: {}, controlUID: {}}}, nil
}

func (policy *PeerPolicy) Authorize(connection net.Conn) error {
	if policy == nil || len(policy.allowed) == 0 { return ErrUnauthorizedPeer }
	unixConnection, ok := connection.(*net.UnixConn); if !ok { return ErrUnauthorizedPeer }
	raw, err := unixConnection.SyscallConn(); if err != nil { return ErrUnauthorizedPeer }
	var credential *syscall.Ucred; var controlErr error
	if err = raw.Control(func(fd uintptr) { credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) }); err != nil || controlErr != nil || credential == nil || credential.Pid <= 1 { return ErrUnauthorizedPeer }
	if _, allowed := policy.allowed[credential.Uid]; !allowed { return ErrUnauthorizedPeer }
	return nil
}

func LookupControlIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("cyberpanel"); if err != nil { return 0, 0, err }
	uid, err := strconv.ParseUint(account.Uid, 10, 32); if err != nil || uid == 0 { return 0, 0, errors.New("invalid cyberpanel control-plane UID") }
	gid, err := strconv.ParseUint(account.Gid, 10, 32); if err != nil || gid == 0 { return 0, 0, errors.New("invalid cyberpanel control-plane GID") }
	return uint32(uid), uint32(gid), nil
}

func ListenDefault(controlGID uint32) (*net.UnixListener, error) {
	if controlGID == 0 { return nil, errors.New("control-plane GID must be non-root") }
	if err := secureAbsoluteDirectory("/run/cyberpanel", 0711); err != nil { return nil, err }
	if err := os.Chown("/run/cyberpanel", 0, int(controlGID)); err != nil { return nil, err }
	if info, err := os.Lstat(DefaultSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 { return nil, fmt.Errorf("siteops socket path exists and is not a socket") }
		if err = os.Remove(DefaultSocketPath); err != nil { return nil, err }
	} else if !errors.Is(err, os.ErrNotExist) { return nil, err }
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: DefaultSocketPath, Net: "unix"}); if err != nil { return nil, err }
	if err = os.Chown(DefaultSocketPath, 0, int(controlGID)); err == nil { err = os.Chmod(DefaultSocketPath, 0660) }
	if err != nil { listener.Close(); return nil, err }
	return listener, nil
}
