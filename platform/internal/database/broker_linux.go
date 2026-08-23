//go:build linux

package database

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

const DatabaseBrokerSocketPath = "/run/cyberpanel/database.sock"

type LocalDatabaseBrokerDialer struct{}

func (LocalDatabaseBrokerDialer) DialContext(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, "unix", DatabaseBrokerSocketPath)
}

func NewLocalMariaDBClient() (*BrokerClient, error) {
	info, err := os.Lstat(DatabaseBrokerSocketPath)
	if err != nil { return nil, err }
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0002 != 0 { return nil, ErrUnauthorized }
	return NewBrokerClient(FramedDatabaseBrokerTransport{Dialer: LocalDatabaseBrokerDialer{}})
}

type DatabaseBrokerPeerPolicy struct{ allowedUID uint32 }

func NewDatabaseBrokerPeerPolicy(controlUID uint32) (*DatabaseBrokerPeerPolicy, error) {
	if controlUID == 0 { return nil, ErrUnauthorized }
	return &DatabaseBrokerPeerPolicy{allowedUID: controlUID}, nil
}

func (policy *DatabaseBrokerPeerPolicy) Authorize(connection net.Conn) error {
	if policy == nil || policy.allowedUID == 0 { return ErrUnauthorized }
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok { return ErrUnauthorized }
	raw, err := unixConnection.SyscallConn()
	if err != nil { return ErrUnauthorized }
	var credential *syscall.Ucred
	var credentialErr error
	if err = raw.Control(func(fileDescriptor uintptr) {
		credential, credentialErr = syscall.GetsockoptUcred(int(fileDescriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credentialErr != nil || credential == nil || credential.Pid <= 1 || credential.Uid != policy.allowedUID {
		return ErrUnauthorized
	}
	return nil
}

func ListenDatabaseBroker(controlGID uint32) (*net.UnixListener, error) {
	if os.Geteuid() != 0 || controlGID == 0 { return nil, ErrUnauthorized }
	if err := ensureDatabaseBrokerDirectory("/run/cyberpanel", controlGID); err != nil { return nil, err }
	if info, err := os.Lstat(DatabaseBrokerSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 { return nil, errors.New("database broker path is not a socket") }
		if err = os.Remove(DatabaseBrokerSocketPath); err != nil { return nil, err }
	} else if !errors.Is(err, os.ErrNotExist) { return nil, err }
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: DatabaseBrokerSocketPath, Net: "unix"})
	if err != nil { return nil, err }
	if err = os.Chown(DatabaseBrokerSocketPath, 0, int(controlGID)); err == nil { err = os.Chmod(DatabaseBrokerSocketPath, 0660) }
	if err != nil { _ = listener.Close(); return nil, err }
	return listener, nil
}

func LookupDatabaseBrokerControlIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("cyberpanel")
	if err != nil { return 0, 0, err }
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 { return 0, 0, errors.New("invalid cyberpanel UID") }
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 { return 0, 0, errors.New("invalid cyberpanel GID") }
	return uint32(uid), uint32(gid), nil
}

func ensureDatabaseBrokerDirectory(path string, controlGID uint32) error {
	if path != "/run/cyberpanel" { return ErrInvalidCommand }
	if err := os.Mkdir(path, 0711); err != nil && !errors.Is(err, os.ErrExist) { return err }
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("unsafe database broker directory")
	}
	if err = os.Chown(path, 0, int(controlGID)); err != nil { return err }
	return os.Chmod(path, 0711)
}
