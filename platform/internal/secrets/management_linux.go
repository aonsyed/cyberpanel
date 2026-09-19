//go:build linux

package secrets

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

const ManagementSocketPath = "/run/cyberpanel-secrets/manage.sock"

// Management admits only the configured administrative UIDs. It returns no
// material and does not use executable identity. Keep it separate from the
// material socket, where executable and process-start binding are mandatory.
type LinuxManagementPeerAuthorizer struct { allowed map[uint32]struct{} }

func NewLinuxManagementPeerAuthorizer(allowedUIDs ...uint32) (*LinuxManagementPeerAuthorizer, error) {
	if len(allowedUIDs) == 0 { return nil, ErrInvalid }
	policy := &LinuxManagementPeerAuthorizer{allowed:make(map[uint32]struct{})}
	for _, uid := range allowedUIDs { policy.allowed[uid] = struct{}{} }
	return policy, nil
}

func (policy *LinuxManagementPeerAuthorizer) Authorize(connection net.Conn) (VerifiedPeer, error) {
	if policy == nil { return VerifiedPeer{}, ErrForbidden }
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok { return VerifiedPeer{}, ErrForbidden }
	raw, err := unixConnection.SyscallConn()
	if err != nil { return VerifiedPeer{}, ErrForbidden }
	var credential *syscall.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) { credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) }); err != nil || credentialErr != nil || credential == nil || credential.Pid <= 1 { return VerifiedPeer{}, ErrForbidden }
	if _, allowed := policy.allowed[credential.Uid]; !allowed { return VerifiedPeer{}, ErrForbidden }
	return VerifiedPeer{UID:credential.Uid, PID:uint32(credential.Pid)}, nil
}

type LocalManagementDialer struct{}

func (LocalManagementDialer) DialContext(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", ManagementSocketPath)
}

func NewLocalManagementClient() (*ManagementClient, error) {
	info, err := os.Lstat(ManagementSocketPath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0002 != 0 {
		return nil, ErrForbidden
	}
	return NewManagementClient(FramedManagementTransport{Dialer: LocalManagementDialer{}})
}

func ListenManagementBroker(ownerUID, groupGID int) (*net.UnixListener, error) {
	if ownerUID < 0 || groupGID <= 0 {
		return nil, ErrInvalid
	}
	directory := "/run/cyberpanel-secrets"
	if err := os.Mkdir(directory, 0750); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0002 != 0 {
		return nil, ErrForbidden
	}
	if err = os.Chown(directory, ownerUID, groupGID); err != nil {
		return nil, err
	}
	if err = os.Chmod(directory, 0750); err != nil {
		return nil, err
	}
	if info, err = os.Lstat(ManagementSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, ErrForbidden
		}
		if err = os.Remove(ManagementSocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: ManagementSocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chown(ManagementSocketPath, ownerUID, groupGID); err == nil {
		err = os.Chmod(ManagementSocketPath, 0660)
	}
	if err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
