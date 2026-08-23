//go:build linux

package localrecovery

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	DefaultSocketPath    = "/run/cyberpanel/local-recovery.sock"
	initialReadTimeout   = 5 * time.Second
	auditPersistenceLimit = 2 * time.Second
	failureWindow        = time.Minute
	failureLockout       = time.Minute
	maximumFailures      = uint8(5)
	maximumServerWorkers = uint8(8)
)

func Listen() (*net.UnixListener, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnauthorized
	}
	if err := ensureSocketDirectory(); err != nil {
		return nil, err
	}
	if existing, err := os.Lstat(DefaultSocketPath); err == nil {
		metadata, ok := existing.Sys().(*syscall.Stat_t)
		if !ok || existing.Mode()&os.ModeSocket == 0 || existing.Mode()&os.ModeSymlink != 0 || metadata.Uid != 0 || metadata.Gid != 0 || existing.Mode().Perm()&0077 != 0 {
			return nil, ErrUnauthorized
		}
		connection, dialErr := net.DialTimeout("unix", DefaultSocketPath, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, ErrConflict
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, dialErr
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
	listener.SetUnlinkOnClose(true)
	if err = os.Chown(DefaultSocketPath, 0, 0); err == nil {
		err = os.Chmod(DefaultSocketPath, 0600)
	}
	if err == nil {
		err = inspectSocketPath()
	}
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

type Server struct {
	Authority         RecoveryAuthority
	Identity          IdentityRecovery
	Audit             AuditSink
	MaximumConcurrent uint8
	Now               func() time.Time

	failures failureLimiter
}

func (server *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	if server == nil || ctx == nil || listener == nil || nilInterface(server.Authority) || nilInterface(server.Identity) || nilInterface(server.Audit) || listener.Addr().Network() != "unix" || listener.Addr().String() != DefaultSocketPath || inspectSocketPath() != nil {
		return ErrInvalid
	}
	maximum := server.MaximumConcurrent
	if maximum == 0 {
		maximum = 2
	}
	if maximum > maximumServerWorkers {
		return ErrInvalid
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, maximum)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				defer connection.Close()
				server.serveConnection(ctx, connection)
			}()
		default:
			_ = connection.SetDeadline(time.Now())
			_ = connection.Close()
		}
	}
}

func (server *Server) serveConnection(parent context.Context, connection *net.UnixConn) {
	if rootPeer(connection) != nil {
		return
	}
	now := server.currentTime()
	_ = connection.SetReadDeadline(now.Add(initialReadTimeout))
	var request Request
	if readFrame(connection, &request) != nil {
		return
	}
	if request.Authorization != nil {
		defer wipeBytes(request.Authorization.Proof)
		defer wipeBytes(request.Authorization.Nonce)
	}
	now = server.currentTime()
	if request.Validate(now) != nil {
		return
	}
	if err := connection.SetDeadline(request.Deadline); err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(parent, request.Deadline)
	defer cancel()
	if server.appendAudit(ctx, newAuditRecord(request, AuditAttempt, AuditStarted, "", 0, now)) != nil {
		return
	}
	response := Response{Version: ProtocolVersion, RequestID: request.RequestID, Action: request.Action}
	if !server.failures.allow(now) {
		response.ErrorCode = ErrorRateLimited
	} else {
		response = server.dispatch(ctx, request)
	}
	response.CompletedAt = server.currentTime()
	response.Succeeded = response.ErrorCode == ""
	outcome := AuditApplied
	if !response.Succeeded {
		outcome = AuditFailed
		if response.ErrorCode == ErrorAuthorityDenied || response.ErrorCode == ErrorUnauthorized || response.ErrorCode == ErrorRateLimited {
			outcome = AuditDenied
		}
		server.failures.fail(response.CompletedAt)
	} else if request.Action != ActionBeginChallenge {
		server.failures.succeed(response.CompletedAt)
	}
	generation := uint64(0)
	if response.Receipt != nil {
		generation = response.Receipt.Generation
	} else if response.Status != nil {
		generation = response.Status.OwnerGeneration
	}
	auditContext, stopAudit := context.WithTimeout(context.WithoutCancel(parent), auditPersistenceLimit)
	defer stopAudit()
	if server.appendAudit(auditContext, newAuditRecord(request, AuditResult, outcome, response.ErrorCode, generation, response.CompletedAt)) != nil {
		return
	}
	if response.Validate(request, server.currentTime()) != nil {
		return
	}
	_ = writeFrame(connection, response)
}

func (server *Server) dispatch(ctx context.Context, request Request) Response {
	response := Response{Version: ProtocolVersion, RequestID: request.RequestID, Action: request.Action}
	localHost, err := readHostIdentity()
	claimedHost := request.Host
	if request.Action == ActionBeginChallenge && request.Binding != nil {
		claimedHost = request.Binding.Host
	}
	if err != nil || localHost != claimedHost {
		response.ErrorCode = ErrorUnauthorized
		return response
	}
	if request.Action == ActionBeginChallenge {
		challenge, beginErr := server.Authority.Begin(ctx, *request.Binding)
		if beginErr != nil || challenge.Validate(*request.Binding, server.currentTime()) != nil {
			response.ErrorCode = ErrorAuthorityDenied
			return response
		}
		response.Challenge = &challenge
		return response
	}
	binding := request.binding()
	authorization := request.Authorization
	claim := ProofClaim{Binding: binding, ChallengeID: authorization.ChallengeID, Nonce: authorization.Nonce, Proof: authorization.Proof}
	if err = server.Authority.VerifyAndConsume(ctx, claim); err != nil {
		response.ErrorCode = ErrorAuthorityDenied
		return response
	}
	recoveryContext := RecoveryContext{RequestID: request.RequestID, Reason: request.Reason, Host: request.Host, RequestDigest: request.RequestDigest, ExpectedGeneration: request.ExpectedGeneration}
	switch request.Action {
	case ActionStatus:
		status, statusErr := server.Identity.Status(ctx, recoveryContext)
		if statusErr != nil || status.Validate(server.currentTime()) != nil {
			response.ErrorCode = classifyRecoveryError(statusErr)
			return response
		}
		response.Status = &status
	case ActionResetOwnerPassword:
		receipt, recoveryErr := server.Identity.ResetOwnerPasswordCredentialRef(ctx, recoveryContext, request.CredentialRef)
		return receiptResponse(response, request, receipt, recoveryErr, server.currentTime())
	case ActionResetOwnerMFA:
		receipt, recoveryErr := server.Identity.ResetOwnerMFA(ctx, recoveryContext)
		return receiptResponse(response, request, receipt, recoveryErr, server.currentTime())
	case ActionRevokeOwnerAccess:
		receipt, recoveryErr := server.Identity.RevokeOwnerSessionsAndAPICredentials(ctx, recoveryContext)
		return receiptResponse(response, request, receipt, recoveryErr, server.currentTime())
	case ActionRotateRecoveryAuthority:
		receipt, recoveryErr := server.Identity.RotateRecoveryAuthority(ctx, recoveryContext, request.RecoveryAuthorityRef)
		return receiptResponse(response, request, receipt, recoveryErr, server.currentTime())
	default:
		response.ErrorCode = ErrorInvalidRequest
	}
	return response
}

func receiptResponse(response Response, request Request, receipt RecoveryReceipt, err error, now time.Time) Response {
	if err != nil {
		response.ErrorCode = classifyRecoveryError(err)
		return response
	}
	if receipt.Validate(request, now) != nil {
		response.ErrorCode = ErrorRecoveryFailed
		return response
	}
	response.Receipt = &receipt
	return response
}

func classifyRecoveryError(err error) ErrorCode {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrorDeadlineExceeded
	}
	if errors.Is(err, ErrConflict) {
		return ErrorConflict
	}
	return ErrorRecoveryFailed
}

func (server *Server) appendAudit(ctx context.Context, record AuditRecord) error {
	if record.Validate() != nil || server.Audit.Append(ctx, record) != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (server *Server) currentTime() time.Time {
	if server.Now != nil {
		return server.Now().UTC()
	}
	return time.Now().UTC()
}

type failureLimiter struct {
	mu           sync.Mutex
	windowStart  time.Time
	failures     uint8
	blockedUntil time.Time
}

func (limiter *failureLimiter) allow(now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if now.Before(limiter.blockedUntil) {
		return false
	}
	if limiter.windowStart.IsZero() || now.Sub(limiter.windowStart) >= failureWindow {
		limiter.windowStart, limiter.failures = now, 0
	}
	return true
}

func (limiter *failureLimiter) fail(now time.Time) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.windowStart.IsZero() || now.Sub(limiter.windowStart) >= failureWindow {
		limiter.windowStart, limiter.failures = now, 0
	}
	limiter.failures++
	if limiter.failures >= maximumFailures {
		limiter.blockedUntil = now.Add(failureLockout)
		limiter.failures = 0
	}
}

func (limiter *failureLimiter) succeed(now time.Time) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.windowStart, limiter.failures = now, 0
}

func rootPeer(connection *net.UnixConn) error {
	if connection == nil {
		return ErrUnauthorized
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return ErrUnauthorized
	}
	var credential *syscall.Ucred
	var credentialErr error
	err = raw.Control(func(descriptor uintptr) {
		credential, credentialErr = syscall.GetsockoptUcred(int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || credentialErr != nil || credential == nil || credential.Pid <= 1 || credential.Uid != 0 {
		return ErrUnauthorized
	}
	return nil
}

func ensureSocketDirectory() error {
	if err := inspectSocketParents(false); err != nil {
		return err
	}
	if err := os.Mkdir("/run/cyberpanel", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return inspectSocketParents(true)
}

func inspectSocketParents(includeSocketDirectory bool) error {
	paths := []string{"/run"}
	if includeSocketDirectory {
		paths = append(paths, "/run/cyberpanel")
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || metadata.Uid != 0 {
			return ErrUnauthorized
		}
	}
	return nil
}

func inspectSocketPath() error {
	if err := inspectSocketParents(true); err != nil {
		return err
	}
	info, err := os.Lstat(DefaultSocketPath)
	if err != nil {
		return err
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || metadata.Uid != 0 || metadata.Gid != 0 {
		return ErrUnauthorized
	}
	return nil
}

func readHostIdentity() (HostIdentity, error) {
	bootID, err := readOpenedID(os.Open("/proc/sys/kernel/random/boot_id"))
	if err != nil {
		return HostIdentity{}, err
	}
	machineID, err := readOpenedID(os.Open("/etc/machine-id"))
	if err != nil {
		return HostIdentity{}, err
	}
	identity := HostIdentity{BootID: bootID, MachineID: machineID}
	if identity.Validate() != nil {
		return HostIdentity{}, ErrUnauthorized
	}
	return identity, nil
}

func readOpenedID(file *os.File, openErr error) (string, error) {
	if openErr != nil {
		return "", openErr
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(content) > 256 {
		return "", ErrUnauthorized
	}
	return strings.ToLower(strings.TrimSpace(string(content))), nil
}
