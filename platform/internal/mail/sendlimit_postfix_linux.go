//go:build linux

package mail

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	SendLimitPolicySocketPath = "/run/cyberpanel/sendlimit-policy.sock"
	sendLimitPolicyLockPath   = "/run/cyberpanel/sendlimit-policy.lock"
	sendLimitPolicyLineBytes  = 4096
	sendLimitPolicyRequestBytes = 32 << 10
	sendLimitPolicyAttributes = 48
	SendLimitPolicyMaximumConnections uint32 = 64
	SendLimitPolicyMaximumRequests     uint32 = 100
)

const (
	sendLimitPostfixPermit = "action=DUNNO\n\n"
	sendLimitPostfixLimited = "action=DEFER_IF_PERMIT 450 4.7.1 outbound send limit exceeded\n\n"
	sendLimitPostfixUnavailable = "action=DEFER_IF_PERMIT 451 4.3.0 outbound policy unavailable\n\n"
	sendLimitPostfixInvalid = "action=REJECT 550 5.7.1 invalid outbound policy request\n\n"
)

type SendLimitPolicyDecider interface {
	Decide(context.Context, SendLimitRuntimeRequest) (SendLimitDecisionReceipt, error)
}

type SendLimitPeerPolicy struct {
	AllowedUIDs map[uint32]bool
}

func NewSendLimitPeerPolicy(postfixUID uint32) (*SendLimitPeerPolicy, error) {
	if postfixUID == 0 {
		return nil, ErrInvalidCommand
	}
	return &SendLimitPeerPolicy{AllowedUIDs: map[uint32]bool{0: true, postfixUID: true}}, nil
}

func (policy *SendLimitPeerPolicy) Authorize(connection net.Conn) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || policy == nil || len(policy.AllowedUIDs) == 0 {
		return ErrUnauthorized
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return ErrUnauthorized
	}
	var credential *syscall.Ucred
	var controlErr error
	if err = raw.Control(func(descriptor uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || controlErr != nil || credential == nil || credential.Pid <= 1 || !policy.AllowedUIDs[credential.Uid] {
		return ErrUnauthorized
	}
	return nil
}

type SendLimitPolicyListener struct {
	*net.UnixListener
	lock *os.File
	once sync.Once
}

func ListenSendLimitPolicy(postfixGID uint32) (*SendLimitPolicyListener, error) {
	if postfixGID == 0 {
		return nil, ErrInvalidCommand
	}
	directory := filepath.Dir(SendLimitPolicySocketPath)
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, ErrUnauthorized
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		return nil, ErrUnauthorized
	}
	lock, err := acquireSendLimitPolicyLock()
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*SendLimitPolicyListener, error) {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
		return nil, cause
	}
	if existing, statErr := os.Lstat(SendLimitPolicySocketPath); statErr == nil {
		socketMetadata, socketOK := existing.Sys().(*syscall.Stat_t)
		if existing.Mode()&os.ModeSocket == 0 || existing.Mode()&os.ModeSymlink != 0 || !socketOK || socketMetadata.Uid != 0 {
			return fail(ErrUnauthorized)
		}
		if err = os.Remove(SendLimitPolicySocketPath); err != nil {
			return fail(err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fail(statErr)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: SendLimitPolicySocketPath, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chown(SendLimitPolicySocketPath, 0, int(postfixGID)); err == nil {
		err = os.Chmod(SendLimitPolicySocketPath, 0660)
	}
	if err != nil {
		listener.Close()
		_ = os.Remove(SendLimitPolicySocketPath)
		return fail(err)
	}
	return &SendLimitPolicyListener{UnixListener: listener, lock: lock}, nil
}

func (listener *SendLimitPolicyListener) Close() error {
	if listener == nil {
		return nil
	}
	var result error
	listener.once.Do(func() {
		if listener.UnixListener != nil {
			result = listener.UnixListener.Close()
		}
		if err := os.Remove(SendLimitPolicySocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
		if listener.lock != nil {
			result = errors.Join(result, syscall.Flock(int(listener.lock.Fd()), syscall.LOCK_UN), listener.lock.Close())
		}
	})
	return result
}

func acquireSendLimitPolicyLock() (*os.File, error) {
	descriptor, err := syscall.Open(sendLimitPolicyLockPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(descriptor), sendLimitPolicyLockPath)
	info, err := lock.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		lock.Close()
		return nil, ErrUnauthorized
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 {
		lock.Close()
		return nil, ErrUnauthorized
	}
	if err = syscall.Flock(descriptor, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}

type SendLimitPolicyServer struct {
	Decider            SendLimitPolicyDecider
	Peer               *SendLimitPeerPolicy
	MaximumConnections uint32
	MaximumRequests    uint32
	RequestTimeout     time.Duration
	once               sync.Once
	semaphore          chan struct{}
}

func NewSendLimitPolicyServer(decider SendLimitPolicyDecider, peer *SendLimitPeerPolicy) (*SendLimitPolicyServer, error) {
	if decider == nil || peer == nil {
		return nil, ErrInvalidCommand
	}
	return &SendLimitPolicyServer{Decider: decider, Peer: peer}, nil
}

func (server *SendLimitPolicyServer) Serve(listener net.Listener) error {
	if server == nil || server.Decider == nil || server.Peer == nil || listener == nil {
		return ErrInvalidCommand
	}
	server.once.Do(func() {
		maximum := server.MaximumConnections
		if maximum == 0 {
			maximum = 16
		}
		if maximum > SendLimitPolicyMaximumConnections {
			maximum = SendLimitPolicyMaximumConnections
		}
		server.semaphore = make(chan struct{}, maximum)
	})
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		if server.Peer.Authorize(connection) != nil {
			_ = connection.Close()
			continue
		}
		select {
		case server.semaphore <- struct{}{}:
			go func(connection net.Conn) {
				defer func() {
					<-server.semaphore
					_ = connection.Close()
				}()
				server.serveConnection(connection)
			}(connection)
		default:
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			_ = writeSendLimitPolicyResponse(connection, sendLimitPostfixUnavailable)
			_ = connection.Close()
		}
	}
}

func (server *SendLimitPolicyServer) serveConnection(connection net.Conn) {
	if server.Peer.Authorize(connection) != nil {
		return
	}
	maximum := server.MaximumRequests
	if maximum == 0 {
		maximum = 20
	}
	if maximum > SendLimitPolicyMaximumRequests {
		maximum = SendLimitPolicyMaximumRequests
	}
	timeout := server.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if timeout < time.Second || timeout > 10*time.Second {
		_ = writeSendLimitPolicyResponse(connection, sendLimitPostfixUnavailable)
		return
	}
	reader := bufio.NewReaderSize(connection, sendLimitPolicyLineBytes)
	for requestNumber := uint32(0); requestNumber < maximum; requestNumber++ {
		_ = connection.SetDeadline(time.Now().Add(timeout))
		attributes, err := readSendLimitPolicyRequest(reader)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			_ = writeSendLimitPolicyResponse(connection, sendLimitPostfixInvalid)
			return
		}
		request, err := sendLimitRuntimeRequest(attributes)
		if err != nil {
			_ = writeSendLimitPolicyResponse(connection, sendLimitPostfixInvalid)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		receipt, decideErr := server.Decider.Decide(ctx, request)
		cancel()
		response := sendLimitPostfixResponse(receipt, decideErr)
		if writeSendLimitPolicyResponse(connection, response) != nil {
			return
		}
	}
	_ = writeSendLimitPolicyResponse(connection, sendLimitPostfixUnavailable)
}

func readSendLimitPolicyRequest(reader *bufio.Reader) (map[string]string, error) {
	if reader == nil {
		return nil, ErrInvalidCommand
	}
	attributes := make(map[string]string)
	total := 0
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) && total == 0 && len(line) == 0 {
			return nil, io.EOF
		}
		if err != nil || len(line) == 0 || len(line) > sendLimitPolicyLineBytes {
			return nil, ErrInvalidCommand
		}
		total += len(line)
		if total > sendLimitPolicyRequestBytes {
			return nil, ErrInvalidCommand
		}
		line = line[:len(line)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			if len(attributes) == 0 {
				return nil, ErrInvalidCommand
			}
			return attributes, nil
		}
		separator := strings.IndexByte(string(line), '=')
		if separator <= 0 {
			return nil, ErrInvalidCommand
		}
		key := string(line[:separator])
		value := string(line[separator+1:])
		if !validSendLimitPolicyKey(key) || !sendLimitPolicyAllowedKey(key) || len(value) > sendLimitPolicyLineBytes-len(key)-1 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, ErrInvalidCommand
		}
		if _, exists := attributes[key]; exists || len(attributes) >= sendLimitPolicyAttributes {
			return nil, ErrInvalidCommand
		}
		attributes[key] = value
	}
}

func sendLimitRuntimeRequest(attributes map[string]string) (SendLimitRuntimeRequest, error) {
	if attributes["request"] != "smtpd_access_policy" || attributes["protocol_state"] != "END-OF-MESSAGE" || !validSendLimitQueueID(attributes["queue_id"]) || !validOpaque(attributes["instance"]) {
		return SendLimitRuntimeRequest{}, ErrInvalidCommand
	}
	sasl := Address(strings.ToLower(strings.TrimSpace(attributes["sasl_username"])))
	sender := Address(strings.ToLower(strings.TrimSpace(attributes["sender"])))
	if !sendLimitCanonicalAddress(sasl) || !sendLimitCanonicalAddress(sender) {
		return SendLimitRuntimeRequest{}, ErrInvalidCommand
	}
	recipients, err := parseSendLimitPolicyUint(attributes["recipient_count"])
	if err != nil || recipients == 0 || recipients > uint64(SendLimitMaximumRecipients) {
		return SendLimitRuntimeRequest{}, ErrInvalidCommand
	}
	size, err := parseSendLimitPolicyUint(attributes["size"])
	if err != nil || size == 0 || size > SendLimitMaximumMessageBytes {
		return SendLimitRuntimeRequest{}, ErrInvalidCommand
	}
	keyInput := []string{attributes["queue_id"], attributes["instance"], string(sender)}
	messageDigest, err := sendLimitDigest("mail-send-limit-postfix-message-v1", keyInput)
	if err != nil {
		return SendLimitRuntimeRequest{}, err
	}
	effectDigest, err := sendLimitDigest("mail-send-limit-postfix-effect-v1", []any{keyInput, recipients, size})
	if err != nil {
		return SendLimitRuntimeRequest{}, err
	}
	return SendLimitRuntimeRequest{MessageKey: "slmsg_" + messageDigest[:48], EffectKey: "sleff_" + effectDigest[:48], SASLUsername: sasl, Sender: sender, Recipients: uint32(recipients), MessageBytes: size}, nil
}

func sendLimitPostfixResponse(receipt SendLimitDecisionReceipt, err error) string {
	if err != nil {
		if errors.Is(err, ErrInvalidCommand) || errors.Is(err, ErrUnauthorized) {
			return sendLimitPostfixInvalid
		}
		return sendLimitPostfixUnavailable
	}
	if receipt.Validate() != nil {
		return sendLimitPostfixUnavailable
	}
	switch receipt.Decision {
	case SendLimitPermit:
		return sendLimitPostfixPermit
	case SendLimitDefer:
		if receipt.Code == SendLimitCodeDependencyUnavailable || receipt.Code == SendLimitCodePolicyUnavailable {
			return sendLimitPostfixUnavailable
		}
		return sendLimitPostfixLimited
	case SendLimitReject:
		return sendLimitPostfixInvalid
	default:
		return sendLimitPostfixUnavailable
	}
}

func writeSendLimitPolicyResponse(writer io.Writer, response string) error {
	if writer == nil || response != sendLimitPostfixPermit && response != sendLimitPostfixLimited && response != sendLimitPostfixUnavailable && response != sendLimitPostfixInvalid {
		return ErrInvalidCommand
	}
	content := []byte(response)
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func sendLimitPolicyAllowedKey(key string) bool {
	switch key {
	case "request", "protocol_state", "protocol_name", "helo_name", "queue_id", "instance", "sender", "recipient", "recipient_count", "size", "sasl_method", "sasl_username", "sasl_sender", "client_address", "client_name", "reverse_client_name", "client_port", "server_address", "server_port", "etrn_domain", "stress", "ccert_subject", "ccert_issuer", "ccert_fingerprint", "ccert_pubkey_fingerprint", "encryption_protocol", "encryption_cipher", "encryption_keysize", "policy_context", "compatibility_level", "mail_version":
		return true
	default:
		return false
	}
}

func validSendLimitPolicyKey(key string) bool {
	if len(key) == 0 || len(key) > 64 {
		return false
	}
	for _, character := range key {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_') {
			return false
		}
	}
	return true
}

func validSendLimitQueueID(value string) bool {
	if len(value) < 5 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z') {
			return false
		}
	}
	return true
}

func parseSendLimitPolicyUint(value string) (uint64, error) {
	if value == "" || len(value) > 20 {
		return 0, ErrInvalidCommand
	}
	var result uint64
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, ErrInvalidCommand
		}
		next := result*10 + uint64(character-'0')
		if next < result {
			return 0, ErrInvalidCommand
		}
		result = next
	}
	return result, nil
}
