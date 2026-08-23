//go:build linux

package authn

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

const DefaultSocketPath = "/run/cyberpanel-auth/auth-verifier.sock"

type UnixDialer struct {
	Path string
}

func (dialer UnixDialer) DialContext(ctx context.Context) (net.Conn, error) {
	path := dialer.Path
	if path == "" {
		path = DefaultSocketPath
	}
	if path != DefaultSocketPath {
		return nil, ErrInvalid
	}
	networkDialer := net.Dialer{}
	return networkDialer.DialContext(ctx, "unix", path)
}

func NewLocalClient() (*Client, error) {
	return NewClient(FramedTransport{Dialer: UnixDialer{Path: DefaultSocketPath}})
}

type PeerPolicy struct {
	allowed map[uint32]struct{}
}

func NewPeerPolicy(controlUID uint32) (*PeerPolicy, error) {
	if controlUID == 0 {
		return nil, errors.New("authn: control-plane UID must be non-root")
	}
	return &PeerPolicy{allowed: map[uint32]struct{}{0: {}, controlUID: {}}}, nil
}

func (policy *PeerPolicy) Authorize(connection net.Conn) error {
	if policy == nil || len(policy.allowed) == 0 {
		return ErrUnavailable
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return ErrUnavailable
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return ErrUnavailable
	}
	var credential *syscall.Ucred
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || controlErr != nil || credential == nil || credential.Pid <= 1 {
		return ErrUnavailable
	}
	if _, allowed := policy.allowed[credential.Uid]; !allowed {
		return ErrUnavailable
	}
	return nil
}

func LookupControlIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("cyberpanel")
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, 0, errors.New("authn: invalid cyberpanel UID")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return 0, 0, errors.New("authn: invalid cyberpanel GID")
	}
	return uint32(uid), uint32(gid), nil
}

func ListenDefault(controlGID uint32) (*net.UnixListener, error) {
	if controlGID == 0 || os.Geteuid() == 0 {
		return nil, errors.New("authn: verifier must use its dedicated non-root identity")
	}
	if err := ensureRuntimeDirectory(controlGID); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(DefaultSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("authn: socket path exists and is not a socket")
		}
		connection, dialErr := net.DialTimeout("unix", DefaultSocketPath, 250000000)
		if dialErr == nil {
			_ = connection.Close()
			return nil, fmt.Errorf("%w: verifier socket is already active", ErrConflict)
		}
		if err = os.Remove(DefaultSocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: DefaultSocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chown(DefaultSocketPath, os.Geteuid(), int(controlGID)); err == nil {
		err = os.Chmod(DefaultSocketPath, 0660)
	}
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func ensureRuntimeDirectory(controlGID uint32) error {
	const path = "/run/cyberpanel-auth"
	if err := os.Mkdir(path, 0750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := os.Chown(path, os.Geteuid(), int(controlGID)); err != nil {
		return err
	}
	if err := os.Chmod(path, 0750); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0750 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != controlGID {
		return errors.New("authn: unsafe verifier runtime directory")
	}
	return nil
}

var _ ConnectionDialer = UnixDialer{}
var _ PeerAuthorizer = (*PeerPolicy)(nil)
