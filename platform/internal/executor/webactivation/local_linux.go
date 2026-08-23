//go:build linux

package webactivation

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
	return (&net.Dialer{}).DialContext(ctx, "unix", DefaultSocketPath)
}

func NewLocalClient() (*Client, error) {
	return NewClient(FramedTransport{Dialer: UnixDialer{}})
}

type PeerPolicy struct { allowed map[uint32]struct{} }

func NewPeerPolicy(controlUID uint32) (*PeerPolicy, error) {
	if controlUID == 0 { return nil, errors.New("control-plane UID must be non-root") }
	return &PeerPolicy{allowed: map[uint32]struct{}{0: {}, controlUID: {}}}, nil
}

func (policy *PeerPolicy) Authorize(connection net.Conn) error {
	if policy == nil || len(policy.allowed) == 0 { return ErrUnauthorized }
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok { return ErrUnauthorized }
	raw, err := unixConnection.SyscallConn()
	if err != nil { return ErrUnauthorized }
	var credential *syscall.Ucred
	var credentialErr error
	if err = raw.Control(func(fd uintptr) { credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) }); err != nil || credentialErr != nil || credential == nil || credential.Pid <= 1 {
		return ErrUnauthorized
	}
	if _, allowed := policy.allowed[credential.Uid]; !allowed { return ErrUnauthorized }
	return nil
}

func LookupControlIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("cyberpanel")
	if err != nil { return 0, 0, err }
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 { return 0, 0, errors.New("invalid cyberpanel control-plane UID") }
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 { return 0, 0, errors.New("invalid cyberpanel control-plane GID") }
	return uint32(uid), uint32(gid), nil
}

func ListenDefault(controlGID uint32) (*net.UnixListener, error) {
	if controlGID == 0 { return nil, errors.New("control-plane GID must be non-root") }
	info, err := os.Lstat("/run/cyberpanel")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o711 {
		return nil, errors.New("web-engine activation runtime directory is unsafe")
	}
	if err = os.Chown("/run/cyberpanel", 0, int(controlGID)); err != nil { return nil, err }
	if info, err = os.Lstat(DefaultSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 { return nil, fmt.Errorf("activation socket path exists and is not a socket") }
		if err = os.Remove(DefaultSocketPath); err != nil { return nil, err }
	} else if !errors.Is(err, os.ErrNotExist) { return nil, err }
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: DefaultSocketPath, Net: "unix"})
	if err != nil { return nil, err }
	if err = os.Chown(DefaultSocketPath, 0, int(controlGID)); err == nil { err = os.Chmod(DefaultSocketPath, 0o660) }
	if err != nil { listener.Close(); return nil, err }
	return listener, nil
}
