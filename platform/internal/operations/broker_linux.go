//go:build linux

package operations

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

const OperationsBrokerSocketPath = "/run/cyberpanel/operations.sock"

type LocalOperationsBrokerDialer struct{}

func (LocalOperationsBrokerDialer) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", OperationsBrokerSocketPath)
}

func NewLocalOperationsClient() (*OperationsBrokerClient, error) {
	info, err := os.Lstat(OperationsBrokerSocketPath)
	if err != nil { return nil, err }
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o002 != 0 { return nil, ErrOperationsBrokerPeer }
	return NewOperationsBrokerClient(FramedOperationsBrokerTransport{Dialer: LocalOperationsBrokerDialer{}})
}

type OperationsBrokerPeerPolicy struct { allowedUID uint32 }

func NewOperationsBrokerPeerPolicy(controlUID uint32) (*OperationsBrokerPeerPolicy, error) {
	if controlUID == 0 { return nil, ErrOperationsBrokerPeer }
	return &OperationsBrokerPeerPolicy{allowedUID: controlUID}, nil
}

func (policy *OperationsBrokerPeerPolicy) Authorize(connection net.Conn) error {
	if policy == nil || policy.allowedUID == 0 { return ErrOperationsBrokerPeer }
	unixConnection, ok := connection.(*net.UnixConn); if !ok { return ErrOperationsBrokerPeer }
	raw, err := unixConnection.SyscallConn(); if err != nil { return ErrOperationsBrokerPeer }
	var credential *syscall.Ucred; var credentialErr error
	if err = raw.Control(func(fd uintptr) { credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) }); err != nil || credentialErr != nil || credential == nil || credential.Pid <= 1 || credential.Uid != policy.allowedUID {
		return ErrOperationsBrokerPeer
	}
	return nil
}

func ListenOperationsBroker(controlGID uint32) (*net.UnixListener, error) {
	if os.Geteuid() != 0 || controlGID == 0 { return nil, ErrOperationsBrokerPeer }
	if err := ensureOperationsRuntimeDirectory(controlGID); err != nil { return nil, err }
	if info, err := os.Lstat(OperationsBrokerSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 { return nil, errors.New("operations broker path is not a socket") }
		if err = os.Remove(OperationsBrokerSocketPath); err != nil { return nil, err }
	} else if !errors.Is(err, os.ErrNotExist) { return nil, err }
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: OperationsBrokerSocketPath, Net: "unix"}); if err != nil { return nil, err }
	if err = os.Chown(OperationsBrokerSocketPath, 0, int(controlGID)); err == nil { err = os.Chmod(OperationsBrokerSocketPath, 0o660) }
	if err != nil { _ = listener.Close(); return nil, err }
	return listener, nil
}

func LookupOperationsControlIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("cyberpanel"); if err != nil { return 0, 0, err }
	uid, err := strconv.ParseUint(account.Uid, 10, 32); if err != nil || uid == 0 { return 0, 0, ErrOperationsBrokerPeer }
	gid, err := strconv.ParseUint(account.Gid, 10, 32); if err != nil || gid == 0 { return 0, 0, ErrOperationsBrokerPeer }
	return uint32(uid), uint32(gid), nil
}

func ensureOperationsRuntimeDirectory(controlGID uint32) error {
	const directory = "/run/cyberpanel"
	if err := os.Mkdir(directory, 0o711); err != nil && !errors.Is(err, os.ErrExist) { return err }
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o002 != 0 { return fmt.Errorf("unsafe operations runtime directory") }
	if err = os.Chown(directory, 0, int(controlGID)); err != nil { return err }
	return os.Chmod(directory, 0o711)
}
