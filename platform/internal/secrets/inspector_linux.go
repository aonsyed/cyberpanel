//go:build linux

package secrets

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const MaterialInspectorSocketPath = "/run/cyberpanel-identity/inspect.sock"

// SocketConsumerRegistry re-inspects the actual connection at grant and delivery.
// A caller-supplied PID is never an inspection authority.
type SocketConsumerRegistry struct{}

func (SocketConsumerRegistry) Verify(ctx context.Context, consumer ConsumerIdentity) (bool, error) {
	connection, ok := ctx.Value(materialConnectionKey{}).(net.Conn)
	if !ok || consumer.Validate() != nil {
		return false, ErrForbidden
	}
	peer, err := inspectMaterialConnection(ctx, connection)
	if err != nil {
		return false, err
	}
	return peer.PID == consumer.PID && peer.ProcessStart == consumer.ProcessStart && peer.ExecutableDigest == consumer.ExecutableDigest && peer.ExecutableDigest == consumer.ReleaseDigest, nil
}

func socketCredential(connection *net.UnixConn) (*syscall.Ucred, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credential *syscall.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) {
		credential, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || inner != nil || credential == nil || credential.Pid <= 1 {
		return nil, ErrForbidden
	}
	return credential, nil
}

func inspectMaterialConnection(ctx context.Context, connection net.Conn) (VerifiedPeer, error) {
	peer, ok := connection.(*net.UnixConn)
	if !ok {
		return VerifiedPeer{}, ErrForbidden
	}
	helperConnection, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", MaterialInspectorSocketPath)
	if err != nil {
		return VerifiedPeer{}, err
	}
	defer helperConnection.Close()
	helper, ok := helperConnection.(*net.UnixConn)
	if !ok {
		return VerifiedPeer{}, ErrForbidden
	}
	credential, err := socketCredential(helper)
	if err != nil || credential.Uid != 0 {
		return VerifiedPeer{}, ErrForbidden
	}
	deadline := time.Now().Add(10 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = helper.SetDeadline(deadline)
	raw, err := peer.SyscallConn()
	if err != nil {
		return VerifiedPeer{}, err
	}
	var sendErr error
	err = raw.Control(func(fd uintptr) { _, _, sendErr = helper.WriteMsgUnix([]byte{1}, syscall.UnixRights(int(fd)), nil) })
	if err != nil || sendErr != nil {
		return VerifiedPeer{}, ErrForbidden
	}
	var response inspectorResponse
	if readMaterialFrame(helper, &response) != nil || response.Denied || response.Peer.PID <= 1 || response.Peer.ProcessStart == 0 || len(response.Peer.ExecutableDigest) != 64 {
		return VerifiedPeer{}, ErrForbidden
	}
	return response.Peer, nil
}

type inspectorResponse struct {
	Peer   VerifiedPeer
	Denied bool
}

// ServeMaterialInspector has no secret-store or credential access. Its only
// input is one connected socket descriptor from the configured broker UID.
func ServeMaterialInspector(listener *net.UnixListener, brokerUID uint32) error {
	if listener == nil {
		return ErrInvalid
	}
	slots := make(chan struct{}, 8)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots; connection.Close() }(); serveMaterialInspection(connection, brokerUID) }()
		default:
			connection.Close()
		}
	}
}

func serveMaterialInspection(connection *net.UnixConn, brokerUID uint32) {
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	caller, err := socketCredential(connection)
	if err != nil || caller.Uid != brokerUID {
		return
	}
	payload := make([]byte, 2)
	control := make([]byte, syscall.CmsgSpace(16*4))
	n, oobn, flags, _, err := connection.ReadMsgUnix(payload, control)
	var descriptors []int
	messages, parseErr := syscall.ParseSocketControlMessage(control[:oobn])
	for _, message := range messages {
		rights, rightsErr := syscall.ParseUnixRights(&message)
		if rightsErr != nil {
			parseErr = rightsErr
		}
		descriptors = append(descriptors, rights...)
	}
	defer func() {
		for _, fd := range descriptors {
			syscall.Close(fd)
		}
	}()
	response := inspectorResponse{Denied: true}
	if err == nil && parseErr == nil && n == 1 && payload[0] == 1 && flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) == 0 && len(descriptors) == 1 {
		fd := descriptors[0]
		syscall.CloseOnExec(fd)
		kind, kindErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
		address, addressErr := syscall.Getpeername(fd)
		_, unixPeer := address.(*syscall.SockaddrUnix)
		credential, credentialErr := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if kindErr == nil && kind == syscall.SOCK_STREAM && addressErr == nil && unixPeer && credentialErr == nil && credential.Pid > 1 {
			start, startErr := linuxProcessStart(uint32(credential.Pid))
			uidOK := inspectorUIDMatches(uint32(credential.Pid), credential.Uid)
			digest, digestErr := linuxExecutableDigest(uint32(credential.Pid))
			after, afterErr := linuxProcessStart(uint32(credential.Pid))
			if startErr == nil && digestErr == nil && afterErr == nil && start == after && uidOK && inspectorUIDMatches(uint32(credential.Pid), credential.Uid) {
				response = inspectorResponse{Peer: VerifiedPeer{UID: credential.Uid, PID: uint32(credential.Pid), ProcessStart: start, ExecutableDigest: digest}}
			}
		}
	}
	_ = writeMaterialFrame(connection, response)
}

func inspectorUIDMatches(pid, uid uint32) bool {
	content, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/status")
	if err != nil || len(content) > 1<<20 {
		return false
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) != 5 {
				return false
			}
			effective, err := strconv.ParseUint(fields[2], 10, 32)
			return err == nil && uint32(effective) == uid
		}
	}
	return false
}

func ListenMaterialInspector(brokerGID int) (*net.UnixListener, error) {
	if os.Geteuid() != 0 || brokerGID <= 0 {
		return nil, ErrForbidden
	}
	const directory = "/run/cyberpanel-identity"
	if err := os.Mkdir(directory, 0710); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, ErrForbidden
	}
	if err = os.Chown(directory, 0, brokerGID); err != nil {
		return nil, err
	}
	if err = os.Chmod(directory, 0710); err != nil {
		return nil, err
	}
	if info, err = os.Lstat(MaterialInspectorSocketPath); err == nil {
		stat, ok = info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSocket == 0 {
			return nil, ErrForbidden
		}
		if err = os.Remove(MaterialInspectorSocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: MaterialInspectorSocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chown(MaterialInspectorSocketPath, 0, brokerGID); err == nil {
		err = os.Chmod(MaterialInspectorSocketPath, 0660)
	}
	if err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
