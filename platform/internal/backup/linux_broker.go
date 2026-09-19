//go:build linux

package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

const LinuxBackupBrokerSocketPath = "/run/cyberpanel/backup.sock"
const linuxBackupProtocolVersion uint16 = 1
const linuxBackupMaximumFrame = 16 << 20

type LinuxBackupOperation string

const (
	LinuxBackupCreateViews       LinuxBackupOperation = "create_views"
	LinuxBackupReleaseViews      LinuxBackupOperation = "release_views"
	LinuxBackupCaptureComponent  LinuxBackupOperation = "capture_component"
	LinuxBackupOpenObject        LinuxBackupOperation = "open_object"
	LinuxBackupVerifyCapacity    LinuxBackupOperation = "verify_capacity"
	LinuxBackupCreateScratch     LinuxBackupOperation = "create_scratch"
	LinuxBackupStageArtifact     LinuxBackupOperation = "stage_artifact"
	LinuxBackupVerifyScratch     LinuxBackupOperation = "verify_scratch"
	LinuxBackupCurrentGeneration LinuxBackupOperation = "current_generation"
	LinuxBackupPromote           LinuxBackupOperation = "promote"
	LinuxBackupObserveWrites     LinuxBackupOperation = "observe_writes"
	LinuxBackupRestorePrevious   LinuxBackupOperation = "restore_previous"
	LinuxBackupQuarantine        LinuxBackupOperation = "quarantine"
	LinuxBackupFinalize          LinuxBackupOperation = "finalize"
	LinuxBackupCreateSafety      LinuxBackupOperation = "create_safety"
	LinuxBackupFreeze            LinuxBackupOperation = "freeze"
	LinuxBackupUnfreeze          LinuxBackupOperation = "unfreeze"
	LinuxBackupVerifyHealth      LinuxBackupOperation = "verify_health"
)

type LinuxBackupRequest struct {
	Version            uint16                `json:"version"`
	RequestID          string                `json:"request_id"`
	Operation          LinuxBackupOperation  `json:"operation"`
	Deadline           time.Time             `json:"deadline"`
	Policy             BackupPolicySpec      `json:"policy,omitempty"`
	Views              []ReadView            `json:"views,omitempty"`
	View               ReadView              `json:"view,omitempty"`
	EffectID           string                `json:"effect_id,omitempty"`
	Object             ObjectDescriptor      `json:"object,omitempty"`
	Offset             uint64                `json:"offset,omitempty"`
	Plan               RestorePlanSpec       `json:"plan,omitempty"`
	Manifest           RecoveryPointManifest `json:"manifest,omitempty"`
	Artifact           ArtifactManifest      `json:"artifact,omitempty"`
	ScratchID          string                `json:"scratch_id,omitempty"`
	Generation         string                `json:"generation,omitempty"`
	PreviousGeneration string                `json:"previous_generation,omitempty"`
	Watermark          uint64                `json:"watermark,omitempty"`
	RequiredBytes      uint64                `json:"required_bytes,omitempty"`
}

type LinuxBackupResponse struct {
	Version      uint16               `json:"version"`
	RequestID    string               `json:"request_id"`
	Operation    LinuxBackupOperation `json:"operation"`
	Views        []ReadView           `json:"views,omitempty"`
	Artifact     ArtifactManifest     `json:"artifact,omitempty"`
	Value        string               `json:"value,omitempty"`
	SecondValue  string               `json:"second_value,omitempty"`
	Watermark    uint64               `json:"watermark,omitempty"`
	FirstWriteAt *time.Time           `json:"first_write_at,omitempty"`
	StreamSize   uint64               `json:"stream_size,omitempty"`
	Failure      string               `json:"failure,omitempty"`
}

// LinuxBackupExecutor is the complete privileged backup vocabulary. The
// caller supplies logical tenant/site/component identities only; the executor
// resolves every host path and native resource from its own registries.
type LinuxBackupExecutor interface {
	CreateViews(context.Context, BackupPolicySpec, string) ([]ReadView, error)
	ReleaseViews(context.Context, []ReadView, string) error
	CaptureComponent(context.Context, BackupPolicySpec, ReadView, string) (ArtifactManifest, error)
	OpenObject(context.Context, ObjectDescriptor, string, uint64) (io.ReadCloser, error)
	VerifyCapacity(context.Context, string, uint64) error
	CreateScratch(context.Context, RestorePlanSpec, RecoveryPointManifest, string) (string, error)
	StageArtifactStream(context.Context, RestorePlanSpec, string, ArtifactManifest, io.Reader, string) (string, error)
	VerifyScratch(context.Context, RestorePlanSpec, string, RecoveryPointManifest) (string, error)
	CurrentGeneration(context.Context, RestorePlanSpec, string) (string, uint64, error)
	Promote(context.Context, RestorePlanSpec, string, string) (string, error)
	ObserveWrites(context.Context, RestorePlanSpec, string, string) (uint64, *time.Time, error)
	RestorePrevious(context.Context, RestorePlanSpec, string, string) error
	Quarantine(context.Context, RestorePlanSpec, string, string) error
	Finalize(context.Context, RestorePlanSpec, string, string) error
	CreateSafetySnapshot(context.Context, RestorePlanSpec, string, uint64, string) (string, error)
	FreezeTargetWrites(context.Context, RestorePlanSpec, string) (uint64, error)
	UnfreezeTargetWrites(context.Context, RestorePlanSpec, string, string) error
	VerifyPromotedHealth(context.Context, RestorePlanSpec, string, string) (string, error)
}

type LinuxBackupPeerAuthorizer interface{ Authorize(net.Conn) error }

type LinuxBackupPeerPolicy struct{ allowedUID uint32 }

func NewLinuxBackupPeerPolicy(controlUID uint32) (*LinuxBackupPeerPolicy, error) {
	if controlUID == 0 {
		return nil, ErrInvalidBackup
	}
	return &LinuxBackupPeerPolicy{allowedUID: controlUID}, nil
}

func (policy *LinuxBackupPeerPolicy) Authorize(connection net.Conn) error {
	if policy == nil || policy.allowedUID == 0 {
		return ErrInvalidBackup
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return ErrInvalidBackup
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return ErrInvalidBackup
	}
	var credential *syscall.Ucred
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || credentialErr != nil || credential == nil || credential.Pid <= 1 || credential.Uid != policy.allowedUID {
		return ErrInvalidBackup
	}
	return nil
}

func ListenLinuxBackupBroker(controlGID uint32) (*net.UnixListener, error) {
	if os.Geteuid() != 0 || controlGID == 0 {
		return nil, ErrInvalidBackup
	}
	if err := os.Mkdir("/run/cyberpanel", 0711); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat("/run/cyberpanel")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0002 != 0 {
		return nil, ErrInvalidBackup
	}
	if err = os.Chown("/run/cyberpanel", 0, int(controlGID)); err != nil {
		return nil, err
	}
	if prior, statErr := os.Lstat(LinuxBackupBrokerSocketPath); statErr == nil {
		if prior.Mode()&os.ModeSocket == 0 {
			return nil, ErrInvalidBackup
		}
		if err = os.Remove(LinuxBackupBrokerSocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: LinuxBackupBrokerSocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chown(LinuxBackupBrokerSocketPath, 0, int(controlGID)); err == nil {
		err = os.Chmod(LinuxBackupBrokerSocketPath, 0660)
	}
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func LookupLinuxBackupControlIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("cyberpanel")
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, 0, ErrInvalidBackup
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return 0, 0, ErrInvalidBackup
	}
	return uint32(uid), uint32(gid), nil
}

type LinuxBackupBrokerServer struct {
	Authorizer        LinuxBackupPeerAuthorizer
	Executor          LinuxBackupExecutor
	Admission         rebootcontrol.ExecutionAdmission
	MaximumConcurrent int
}

func (server *LinuxBackupBrokerServer) Serve(listener net.Listener) error {
	if server == nil || server.Authorizer == nil || server.Executor == nil || listener == nil {
		return ErrInvalidBackup
	}
	maximum := server.MaximumConcurrent
	if maximum < 1 || maximum > 256 {
		maximum = 32
	}
	guard := make(chan struct{}, maximum)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		guard <- struct{}{}
		go func() { defer func() { <-guard }(); server.serveConnection(connection) }()
	}
}

func (server *LinuxBackupBrokerServer) serveConnection(connection net.Conn) {
	defer connection.Close()
	if server.Authorizer.Authorize(connection) != nil {
		return
	}
	var request LinuxBackupRequest
	if readLinuxBackupFrame(connection, &request) != nil || request.Version != linuxBackupProtocolVersion || request.RequestID == "" || request.Deadline.IsZero() || time.Now().After(request.Deadline) {
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	_ = connection.SetDeadline(request.Deadline)
	mutation := true
	switch request.Operation {
	case LinuxBackupOpenObject, LinuxBackupVerifyCapacity, LinuxBackupVerifyScratch, LinuxBackupVerifyHealth:
		mutation = false
	case LinuxBackupCreateViews, LinuxBackupReleaseViews, LinuxBackupCaptureComponent, LinuxBackupCreateScratch, LinuxBackupStageArtifact, LinuxBackupCurrentGeneration, LinuxBackupPromote, LinuxBackupObserveWrites, LinuxBackupRestorePrevious, LinuxBackupQuarantine, LinuxBackupFinalize, LinuxBackupCreateSafety, LinuxBackupFreeze, LinuxBackupUnfreeze:
	default:
		return
	}
	var lease rebootcontrol.ExecutionLease
	if mutation {
		if server.Admission == nil || request.EffectID == "" {
			return
		}
		canonical := request
		canonical.RequestID = ""
		canonical.Deadline = time.Time{}
		digest := rebootcontrol.ExecutionDigest(canonical)
		// A backup run intentionally reuses its domain effect across components
		// and recovery phases. The durable effect identity therefore includes the
		// complete canonical request, while retaining the caller's effect in the
		// resource record for correlation.
		binding := rebootcontrol.ExecutionBinding{Boundary: "backup", Method: string(request.Operation), EffectID: digest, RequestDigest: digest, Caller: "authenticated-panel-core", Resource: rebootcontrol.ExecutionResource(struct{ Tenant, Source, Target, Effect, Payload string }{request.Plan.TenantID, request.Plan.SourceScope, request.Plan.TargetScope, request.EffectID, digest})}
		var err error
		lease, err = server.Admission.AdmitExecution(ctx, binding)
		if err != nil {
			return
		}
		if len(lease.Cached) != 0 {
			var cached LinuxBackupResponse
			if json.Unmarshal(lease.Cached, &cached) != nil || !terminalLinuxBackupResponse(request, cached) {
				return
			}
			// A streaming retry still sends its body before reading the response.
			// Consume and hash every exact object before replaying the receipt.
			if request.Operation == LinuxBackupStageArtifact && verifyLinuxBackupReplayStream(connection, request.Artifact) != nil {
				return
			}
			cached.RequestID = request.RequestID
			_ = writeLinuxBackupFrame(connection, cached)
			return
		}
		defer func() { _ = rebootcontrol.SettleExecution(server.Admission, lease, false, nil) }()
	}
	response := LinuxBackupResponse{Version: linuxBackupProtocolVersion, RequestID: request.RequestID, Operation: request.Operation}
	var err error
	var stream io.ReadCloser
	switch request.Operation {
	case LinuxBackupCreateViews:
		response.Views, err = server.Executor.CreateViews(ctx, request.Policy, request.EffectID)
	case LinuxBackupReleaseViews:
		err = server.Executor.ReleaseViews(ctx, request.Views, request.EffectID)
	case LinuxBackupCaptureComponent:
		response.Artifact, err = server.Executor.CaptureComponent(ctx, request.Policy, request.View, request.EffectID)
	case LinuxBackupOpenObject:
		stream, err = server.Executor.OpenObject(ctx, request.Object, request.EffectID, request.Offset)
		response.StreamSize = request.Object.Size - request.Offset
	case LinuxBackupVerifyCapacity:
		err = server.Executor.VerifyCapacity(ctx, request.Plan.TargetScope, request.RequiredBytes)
	case LinuxBackupCreateScratch:
		response.Value, err = server.Executor.CreateScratch(ctx, request.Plan, request.Manifest, request.EffectID)
	case LinuxBackupStageArtifact:
		response.Value, err = server.Executor.StageArtifactStream(ctx, request.Plan, request.ScratchID, request.Artifact, connection, request.EffectID)
	case LinuxBackupVerifyScratch:
		response.Value, err = server.Executor.VerifyScratch(ctx, request.Plan, request.ScratchID, request.Manifest)
	case LinuxBackupCurrentGeneration:
		response.Value, response.Watermark, err = server.Executor.CurrentGeneration(ctx, request.Plan, request.EffectID)
	case LinuxBackupPromote:
		response.Value, err = server.Executor.Promote(ctx, request.Plan, request.ScratchID, request.EffectID)
	case LinuxBackupObserveWrites:
		response.Watermark, response.FirstWriteAt, err = server.Executor.ObserveWrites(ctx, request.Plan, request.Generation, request.EffectID)
	case LinuxBackupRestorePrevious:
		err = server.Executor.RestorePrevious(ctx, request.Plan, request.PreviousGeneration, request.EffectID)
	case LinuxBackupQuarantine:
		err = server.Executor.Quarantine(ctx, request.Plan, request.ScratchID, request.EffectID)
	case LinuxBackupFinalize:
		err = server.Executor.Finalize(ctx, request.Plan, request.ScratchID, request.EffectID)
	case LinuxBackupCreateSafety:
		response.Value, err = server.Executor.CreateSafetySnapshot(ctx, request.Plan, request.PreviousGeneration, request.Watermark, request.EffectID)
	case LinuxBackupFreeze:
		response.Watermark, err = server.Executor.FreezeTargetWrites(ctx, request.Plan, request.EffectID)
	case LinuxBackupUnfreeze:
		err = server.Executor.UnfreezeTargetWrites(ctx, request.Plan, request.Generation, request.EffectID)
	case LinuxBackupVerifyHealth:
		response.Value, err = server.Executor.VerifyPromotedHealth(ctx, request.Plan, request.Generation, request.EffectID)
	default:
		err = ErrInvalidBackup
	}
	if err != nil {
		response.Failure = err.Error()
	}
	if mutation && rebootcontrol.SettleExecution(server.Admission, lease, err == nil && terminalLinuxBackupResponse(request, response), response) != nil {
		return
	}
	if writeLinuxBackupFrame(connection, response) != nil || err != nil {
		if stream != nil {
			_ = stream.Close()
		}
		return
	}
	if stream != nil {
		_, _ = io.CopyN(connection, stream, int64(response.StreamSize))
		_ = stream.Close()
	}
}

func terminalLinuxBackupResponse(request LinuxBackupRequest, response LinuxBackupResponse) bool {
	if response.Version != linuxBackupProtocolVersion || response.Operation != request.Operation || response.Failure != "" {
		return false
	}
	switch request.Operation {
	case LinuxBackupCreateViews:
		return validateViews(request.Policy, response.Views) == nil
	case LinuxBackupCaptureComponent:
		return validateArtifact(response.Artifact, request.View) == nil
	case LinuxBackupCreateScratch:
		return response.Value == linuxBackupID("scratch", string(request.Plan.ID), string(request.Plan.RecoveryPointID), request.Plan.TargetScope)
	case LinuxBackupStageArtifact:
		expected := linuxBackupID("stage", request.ScratchID, string(request.Artifact.ID), request.Artifact.RootDigest)
		if _, required := request.Plan.ComponentMapping[request.Artifact.Component]; !required {
			expected = linuxBackupID("skipped", request.ScratchID, string(request.Artifact.ID))
		}
		return response.Value == expected
	case LinuxBackupPromote:
		return response.Value == linuxBackupID("restored", string(request.Plan.ID), request.ScratchID)
	case LinuxBackupCreateSafety:
		return response.Value == linuxBackupID("safety", string(request.Plan.ID), request.PreviousGeneration, strconv.FormatUint(request.Watermark, 10))
	case LinuxBackupFreeze:
		return response.Watermark != 0
	case LinuxBackupCurrentGeneration:
		return len(response.Value) == 50 && response.Value[:2] == "b_" && response.Watermark != 0
	case LinuxBackupObserveWrites:
		return response.Value == "" && response.Watermark != 0
	case LinuxBackupReleaseViews, LinuxBackupRestorePrevious, LinuxBackupQuarantine, LinuxBackupFinalize, LinuxBackupUnfreeze:
		return response.Value == "" && response.Watermark == 0 && len(response.Views) == 0 && response.Artifact.ID == ""
	default:
		return false
	}
}

func verifyLinuxBackupReplayStream(stream io.Reader, artifact ArtifactManifest) error {
	if validateArtifact(artifact, ReadView{Component: artifact.Component, Consistency: artifact.Consistency}) != nil {
		return ErrInvalidBackup
	}
	for _, descriptor := range artifact.Objects {
		hash := sha256.New()
		written, err := io.CopyN(hash, stream, int64(descriptor.Size))
		if err != nil || uint64(written) != descriptor.Size || hex.EncodeToString(hash.Sum(nil)) != descriptor.Digest {
			return errors.Join(ErrInvalidBackup, err)
		}
	}
	return nil
}

type LocalLinuxBackupClient struct {
	Dialer func(context.Context) (net.Conn, error)
}

func NewLocalLinuxBackupClient() (*LocalLinuxBackupClient, error) {
	info, err := os.Lstat(LinuxBackupBrokerSocketPath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0002 != 0 {
		return nil, ErrInvalidBackup
	}
	return &LocalLinuxBackupClient{Dialer: func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", LinuxBackupBrokerSocketPath)
	}}, nil
}

func (client *LocalLinuxBackupClient) request(ctx context.Context, operation LinuxBackupOperation) (LinuxBackupRequest, error) {
	if client == nil || client.Dialer == nil || ctx == nil {
		return LinuxBackupRequest{}, ErrInvalidBackup
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(6 * time.Hour)
	}
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		return LinuxBackupRequest{}, err
	}
	return LinuxBackupRequest{Version: linuxBackupProtocolVersion, RequestID: "backup-" + hex.EncodeToString(identifier), Operation: operation, Deadline: deadline}, nil
}

func (client *LocalLinuxBackupClient) roundTrip(ctx context.Context, request LinuxBackupRequest) (LinuxBackupResponse, error) {
	connection, err := client.Dialer(ctx)
	if err != nil {
		return LinuxBackupResponse{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err = writeLinuxBackupFrame(connection, request); err != nil {
		return LinuxBackupResponse{}, err
	}
	var response LinuxBackupResponse
	if err = readLinuxBackupFrame(connection, &response); err != nil {
		return response, err
	}
	if response.Version != request.Version || response.RequestID != request.RequestID || response.Operation != request.Operation {
		return response, ErrInvalidBackup
	}
	if response.Failure != "" {
		return response, fmt.Errorf("backup executor: %s", response.Failure)
	}
	return response, nil
}

func (client *LocalLinuxBackupClient) CreateViews(ctx context.Context, policy BackupPolicySpec, effect string) ([]ReadView, error) {
	request, err := client.request(ctx, LinuxBackupCreateViews)
	if err != nil {
		return nil, err
	}
	request.Policy, request.EffectID = policy, effect
	response, err := client.roundTrip(ctx, request)
	return response.Views, err
}
func (client *LocalLinuxBackupClient) ReleaseViews(ctx context.Context, views []ReadView, effect string) error {
	request, err := client.request(ctx, LinuxBackupReleaseViews)
	if err != nil {
		return err
	}
	request.Views, request.EffectID = views, effect
	_, err = client.roundTrip(ctx, request)
	return err
}
func (client *LocalLinuxBackupClient) CaptureComponent(ctx context.Context, policy BackupPolicySpec, view ReadView, effect string) (ArtifactManifest, error) {
	request, err := client.request(ctx, LinuxBackupCaptureComponent)
	if err != nil {
		return ArtifactManifest{}, err
	}
	request.Policy, request.View, request.EffectID = policy, view, effect
	response, err := client.roundTrip(ctx, request)
	return response.Artifact, err
}

func (client *LocalLinuxBackupClient) OpenObject(ctx context.Context, object ObjectDescriptor, effect string, offset uint64) (io.ReadCloser, error) {
	request, err := client.request(ctx, LinuxBackupOpenObject)
	if err != nil {
		return nil, err
	}
	request.Object, request.EffectID, request.Offset = object, effect, offset
	connection, err := client.Dialer(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err = writeLinuxBackupFrame(connection, request); err != nil {
		connection.Close()
		return nil, err
	}
	var response LinuxBackupResponse
	if err = readLinuxBackupFrame(connection, &response); err != nil {
		connection.Close()
		return nil, err
	}
	if response.Version != request.Version || response.RequestID != request.RequestID || response.Operation != request.Operation || response.StreamSize != object.Size-offset || response.Failure != "" {
		connection.Close()
		if response.Failure != "" {
			return nil, fmt.Errorf("backup executor: %s", response.Failure)
		}
		return nil, ErrInvalidBackup
	}
	return &linuxBackupStream{connection: connection, reader: io.LimitReader(connection, int64(response.StreamSize)), remaining: response.StreamSize}, nil
}

type linuxBackupStream struct {
	connection net.Conn
	reader     io.Reader
	remaining  uint64
}

func (stream *linuxBackupStream) Read(value []byte) (int, error) {
	if stream.remaining == 0 {
		return 0, io.EOF
	}
	if uint64(len(value)) > stream.remaining {
		value = value[:stream.remaining]
	}
	count, err := stream.reader.Read(value)
	stream.remaining -= uint64(count)
	return count, err
}
func (stream *linuxBackupStream) Close() error {
	if stream == nil || stream.connection == nil {
		return nil
	}
	err := stream.connection.Close()
	stream.connection = nil
	return err
}

func (client *LocalLinuxBackupClient) VerifyCapacity(ctx context.Context, target string, bytes uint64) error {
	request, err := client.request(ctx, LinuxBackupVerifyCapacity)
	if err != nil {
		return err
	}
	request.Plan.TargetScope = target
	request.RequiredBytes = bytes
	_, err = client.roundTrip(ctx, request)
	return err
}
func (client *LocalLinuxBackupClient) CreateScratch(ctx context.Context, plan RestorePlanSpec, manifest RecoveryPointManifest, effect string) (string, error) {
	request, err := client.request(ctx, LinuxBackupCreateScratch)
	if err != nil {
		return "", err
	}
	request.Plan, request.Manifest, request.EffectID = plan, manifest, effect
	response, err := client.roundTrip(ctx, request)
	return response.Value, err
}
func (client *LocalLinuxBackupClient) StageArtifact(ctx context.Context, plan RestorePlanSpec, scratch string, artifact ArtifactManifest, open func(context.Context, ObjectDescriptor) (ReadObject, error), effect string) (string, error) {
	if open == nil {
		return "", ErrInvalidBackup
	}
	request, err := client.request(ctx, LinuxBackupStageArtifact)
	if err != nil {
		return "", err
	}
	request.Plan, request.ScratchID, request.Artifact, request.EffectID = plan, scratch, artifact, effect
	connection, err := client.Dialer(ctx)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err = writeLinuxBackupFrame(connection, request); err != nil {
		return "", err
	}
	for _, descriptor := range artifact.Objects {
		object, openErr := open(ctx, descriptor)
		if openErr != nil {
			return "", openErr
		}
		if object.Reader == nil || object.Descriptor != descriptor {
			if object.Reader != nil {
				_ = object.Reader.Close()
			}
			return "", ErrInvalidBackup
		}
		written, copyErr := io.CopyN(connection, object.Reader, int64(descriptor.Size))
		closeErr := object.Reader.Close()
		if copyErr != nil || closeErr != nil || uint64(written) != descriptor.Size {
			return "", errors.Join(copyErr, closeErr, ErrInvalidBackup)
		}
	}
	var response LinuxBackupResponse
	if err = readLinuxBackupFrame(connection, &response); err != nil {
		return "", err
	}
	if response.Version != request.Version || response.RequestID != request.RequestID || response.Operation != request.Operation {
		return "", ErrInvalidBackup
	}
	if response.Failure != "" {
		return "", fmt.Errorf("backup executor: %s", response.Failure)
	}
	return response.Value, nil
}
func (client *LocalLinuxBackupClient) VerifyScratch(ctx context.Context, plan RestorePlanSpec, scratch string, manifest RecoveryPointManifest) (string, error) {
	request, err := client.request(ctx, LinuxBackupVerifyScratch)
	if err != nil {
		return "", err
	}
	request.Plan, request.ScratchID, request.Manifest = plan, scratch, manifest
	response, err := client.roundTrip(ctx, request)
	return response.Value, err
}
func (client *LocalLinuxBackupClient) CurrentGeneration(ctx context.Context, plan RestorePlanSpec, effect string) (string, uint64, error) {
	request, err := client.request(ctx, LinuxBackupCurrentGeneration)
	if err != nil {
		return "", 0, err
	}
	request.Plan, request.EffectID = plan, effect
	response, err := client.roundTrip(ctx, request)
	return response.Value, response.Watermark, err
}
func (client *LocalLinuxBackupClient) Promote(ctx context.Context, plan RestorePlanSpec, scratch, effect string) (string, error) {
	request, err := client.request(ctx, LinuxBackupPromote)
	if err != nil {
		return "", err
	}
	request.Plan, request.ScratchID, request.EffectID = plan, scratch, effect
	response, err := client.roundTrip(ctx, request)
	return response.Value, err
}
func (client *LocalLinuxBackupClient) ObserveWrites(ctx context.Context, plan RestorePlanSpec, generation, effect string) (uint64, *time.Time, error) {
	request, err := client.request(ctx, LinuxBackupObserveWrites)
	if err != nil {
		return 0, nil, err
	}
	request.Plan, request.Generation, request.EffectID = plan, generation, effect
	response, err := client.roundTrip(ctx, request)
	return response.Watermark, response.FirstWriteAt, err
}
func (client *LocalLinuxBackupClient) RestorePrevious(ctx context.Context, plan RestorePlanSpec, previous, effect string) error {
	request, err := client.request(ctx, LinuxBackupRestorePrevious)
	if err != nil {
		return err
	}
	request.Plan, request.PreviousGeneration, request.EffectID = plan, previous, effect
	_, err = client.roundTrip(ctx, request)
	return err
}
func (client *LocalLinuxBackupClient) Quarantine(ctx context.Context, plan RestorePlanSpec, scratch, effect string) error {
	request, err := client.request(ctx, LinuxBackupQuarantine)
	if err != nil {
		return err
	}
	request.Plan, request.ScratchID, request.EffectID = plan, scratch, effect
	_, err = client.roundTrip(ctx, request)
	return err
}
func (client *LocalLinuxBackupClient) Finalize(ctx context.Context, plan RestorePlanSpec, scratch, effect string) error {
	request, err := client.request(ctx, LinuxBackupFinalize)
	if err != nil {
		return err
	}
	request.Plan, request.ScratchID, request.EffectID = plan, scratch, effect
	_, err = client.roundTrip(ctx, request)
	return err
}
func (client *LocalLinuxBackupClient) CreateSafetySnapshot(ctx context.Context, plan RestorePlanSpec, previous string, watermark uint64, effect string) (string, error) {
	request, err := client.request(ctx, LinuxBackupCreateSafety)
	if err != nil {
		return "", err
	}
	request.Plan, request.PreviousGeneration, request.Watermark, request.EffectID = plan, previous, watermark, effect
	response, err := client.roundTrip(ctx, request)
	return response.Value, err
}
func (client *LocalLinuxBackupClient) FreezeTargetWrites(ctx context.Context, plan RestorePlanSpec, effect string) (uint64, error) {
	request, err := client.request(ctx, LinuxBackupFreeze)
	if err != nil {
		return 0, err
	}
	request.Plan, request.EffectID = plan, effect
	response, err := client.roundTrip(ctx, request)
	return response.Watermark, err
}
func (client *LocalLinuxBackupClient) UnfreezeTargetWrites(ctx context.Context, plan RestorePlanSpec, generation, effect string) error {
	request, err := client.request(ctx, LinuxBackupUnfreeze)
	if err != nil {
		return err
	}
	request.Plan, request.Generation, request.EffectID = plan, generation, effect
	_, err = client.roundTrip(ctx, request)
	return err
}
func (client *LocalLinuxBackupClient) VerifyPromotedHealth(ctx context.Context, plan RestorePlanSpec, generation, effect string) (string, error) {
	request, err := client.request(ctx, LinuxBackupVerifyHealth)
	if err != nil {
		return "", err
	}
	request.Plan, request.Generation, request.EffectID = plan, generation, effect
	response, err := client.roundTrip(ctx, request)
	return response.Value, err
}

// IntegrityRestoreScanner reads every committed object and binds the scan
// receipt to the complete object inventory. It intentionally performs no
// content execution or format-specific parsing.
type IntegrityRestoreScanner struct{}

func (IntegrityRestoreScanner) Inspect(ctx context.Context, manifest RecoveryPointManifest, open func(context.Context, ObjectDescriptor) (ReadObject, error)) (string, error) {
	if open == nil || manifest.ManifestDigest == "" {
		return "", ErrInvalidBackup
	}
	hash := sha256.New()
	for _, artifact := range manifest.Artifacts {
		for _, descriptor := range artifact.Objects {
			object, err := open(ctx, descriptor)
			if err != nil {
				return "", err
			}
			if object.Reader == nil || object.Descriptor != descriptor {
				if object.Reader != nil {
					_ = object.Reader.Close()
				}
				return "", ErrInvalidBackup
			}
			objectHash := sha256.New()
			written, copyErr := io.Copy(objectHash, io.LimitReader(object.Reader, int64(descriptor.Size)+1))
			closeErr := object.Reader.Close()
			if copyErr != nil || closeErr != nil || uint64(written) != descriptor.Size || hex.EncodeToString(objectHash.Sum(nil)) != descriptor.Digest {
				return "", errors.Join(ErrInvalidBackup, copyErr, closeErr)
			}
			_, _ = io.WriteString(hash, string(artifact.Component))
			_, _ = io.WriteString(hash, "\x00"+descriptor.Key+"\x00"+descriptor.Digest+"\x00")
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeLinuxBackupFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > linuxBackupMaximumFrame {
		return ErrInvalidBackup
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if err = writeLinuxBackupAll(writer, prefix[:]); err != nil {
		return err
	}
	return writeLinuxBackupAll(writer, payload)
}
func writeLinuxBackupAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
func readLinuxBackupFrame(reader io.Reader, value any) error {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || size > linuxBackupMaximumFrame {
		return ErrInvalidBackup
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(&linuxBackupBytesReader{value: payload})
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidBackup
	}
	return nil
}

type linuxBackupBytesReader struct {
	value  []byte
	offset int
}

func (reader *linuxBackupBytesReader) Read(target []byte) (int, error) {
	if reader.offset == len(reader.value) {
		return 0, io.EOF
	}
	count := copy(target, reader.value[reader.offset:])
	reader.offset += count
	return count, nil
}
