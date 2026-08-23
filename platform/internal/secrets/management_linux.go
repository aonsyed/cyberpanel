//go:build linux

package secrets

import (
	"context"
	"errors"
	"net"
	"os"
)

const ManagementSocketPath = "/run/cyberpanel-secrets/manage.sock"

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
