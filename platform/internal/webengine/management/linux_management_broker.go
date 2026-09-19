package management

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

const (
	LinuxManagementSocketPath             = "/run/cyberpanel/webengine-management.sock"
	linuxManagementProtocolVersion uint32 = 1
	linuxManagementMaximumFrame           = 64 << 20
)

type LinuxManagementOperation string

const (
	LinuxManagementInspect          LinuxManagementOperation = "lifecycle.inspect"
	LinuxManagementInstall          LinuxManagementOperation = "lifecycle.install"
	LinuxManagementUpgrade          LinuxManagementOperation = "lifecycle.upgrade"
	LinuxManagementConvert          LinuxManagementOperation = "lifecycle.convert"
	LinuxManagementRemove           LinuxManagementOperation = "lifecycle.remove"
	LinuxManagementLicenseConfigure LinuxManagementOperation = "license.configure"
	LinuxManagementLicenseRefresh   LinuxManagementOperation = "license.refresh"
	LinuxManagementPHPInstall       LinuxManagementOperation = "php.install"
	LinuxManagementPHPProfileApply  LinuxManagementOperation = "php.profile.apply"
	LinuxManagementPHPRollback      LinuxManagementOperation = "php.rollback"
	LinuxManagementStage            LinuxManagementOperation = "generation.stage"
	LinuxManagementValidate         LinuxManagementOperation = "generation.validate"
	LinuxManagementShadow           LinuxManagementOperation = "generation.shadow"
	LinuxManagementActiveProbe      LinuxManagementOperation = "generation.active_probe"
	LinuxManagementSwitch           LinuxManagementOperation = "generation.switch"
	LinuxManagementConfirm          LinuxManagementOperation = "generation.confirm"
	LinuxManagementRestore          LinuxManagementOperation = "generation.restore"
)

type LinuxManagementRequest struct {
	Version       uint32                   `json:"version"`
	RequestID     string                   `json:"request_id"`
	Operation     LinuxManagementOperation `json:"operation"`
	Deadline      time.Time                `json:"deadline"`
	Payload       json.RawMessage          `json:"payload"`
	PayloadDigest string                   `json:"payload_digest"`
}

type linuxManagementResponse struct {
	Version       uint32                   `json:"version"`
	RequestID     string                   `json:"request_id"`
	Operation     LinuxManagementOperation `json:"operation"`
	Succeeded     bool                     `json:"succeeded"`
	Payload       json.RawMessage          `json:"payload,omitempty"`
	PayloadDigest string                   `json:"payload_digest,omitempty"`
	ErrorCode     string                   `json:"error_code,omitempty"`
	CompletedAt   time.Time                `json:"completed_at"`
}

type lifecyclePlanInput struct {
	Request EffectRequest `json:"request"`
	Plan    ArtifactPlan  `json:"plan"`
}
type lifecycleGenerationInput struct {
	Request      EffectRequest        `json:"request"`
	Render       native.RenderRequest `json:"render"`
	ConfigDigest string               `json:"config_digest"`
	PrivateTLS   []PrivateTLSMaterial `json:"private_tls,omitempty"`
}
type lifecycleConvertInput struct {
	Request              EffectRequest           `json:"request"`
	Plan                 ArtifactPlan            `json:"plan"`
	Generation           native.ConfigGeneration `json:"generation"`
	RollbackWindow       time.Duration           `json:"rollback_window"`
	License              LicenseRequest          `json:"license"`
	Target               native.RenderRequest    `json:"target"`
	Previous             native.RenderRequest    `json:"previous"`
	PreviousConfigDigest string                  `json:"previous_config_digest"`
}
type lifecycleRemoveInput struct {
	Request EffectRequest     `json:"request"`
	Edition webengine.Edition `json:"edition"`
}
type licenseConfigureInput struct {
	Request EffectRequest  `json:"request"`
	License LicenseRequest `json:"license"`
}
type licenseRefreshInput struct {
	Request EffectRequest `json:"request"`
}
type phpInstallInput struct {
	Request EffectRequest   `json:"request"`
	Plan    PHPArtifactPlan `json:"plan"`
}
type phpProfileInput struct {
	Request EffectRequest `json:"request"`
	Profile PHPProfile    `json:"profile"`
}
type phpRollbackInput struct {
	Request  EffectRequest   `json:"request"`
	Plan     PHPArtifactPlan `json:"plan"`
	Previous *PHPProfile     `json:"previous,omitempty"`
}

type LinuxManagementBrokerHandler interface {
	HandleManagement(context.Context, LinuxManagementRequest) (any, error)
}
type LinuxLicensePHPBrokerHandler interface {
	HandleLicensePHP(context.Context, LinuxManagementRequest) (any, error)
}
type LinuxManagementPeerAuthorizer interface{ Authorize(net.Conn) error }

type LinuxManagementBrokerServer struct {
	Authorizer        LinuxManagementPeerAuthorizer
	Handler           LinuxManagementBrokerHandler
	Admission         rebootcontrol.ExecutionAdmission
	MaximumConcurrent uint32
}

func (server *LinuxManagementBrokerServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.Authorizer == nil || server.Handler == nil {
		return ErrInvalid
	}
	maximum := server.MaximumConcurrent
	if maximum == 0 {
		maximum = 8
	}
	if maximum > 32 {
		maximum = 32
	}
	gate := make(chan struct{}, maximum)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case gate <- struct{}{}:
			workers.Add(1)
			go func() { defer func() { <-gate; workers.Done(); connection.Close() }(); server.serve(connection) }()
		default:
			_ = connection.Close()
		}
	}
}

func (server *LinuxManagementBrokerServer) serve(connection net.Conn) {
	if server.Authorizer.Authorize(connection) != nil {
		return
	}
	now := time.Now().UTC()
	_ = connection.SetReadDeadline(now.Add(15 * time.Second))
	var request LinuxManagementRequest
	if readLinuxManagementFrame(connection, &request) != nil || request.validate(now) != nil {
		return
	}
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	mutation := true
	switch request.Operation {
	case LinuxManagementInspect:
		mutation = false
	case LinuxManagementInstall, LinuxManagementUpgrade, LinuxManagementConvert, LinuxManagementRemove, LinuxManagementLicenseConfigure, LinuxManagementLicenseRefresh, LinuxManagementPHPInstall, LinuxManagementPHPProfileApply, LinuxManagementPHPRollback, LinuxManagementStage, LinuxManagementValidate, LinuxManagementShadow, LinuxManagementActiveProbe, LinuxManagementSwitch, LinuxManagementConfirm, LinuxManagementRestore:
	default:
		return
	}
	var lease rebootcontrol.ExecutionLease
	if mutation {
		if server.Admission == nil {
			return
		}
		binding, err := linuxManagementExecutionBinding(request)
		if err != nil {
			return
		}
		lease, err = server.Admission.AdmitExecution(ctx, binding)
		if err != nil {
			return
		}
		if len(lease.Cached) != 0 {
			var cached linuxManagementResponse
			if json.Unmarshal(lease.Cached, &cached) == nil {
				cached.RequestID = request.RequestID
				if terminalLinuxManagementResponse(request, cached.Payload) && cached.validate(request, time.Now().UTC()) == nil {
					_ = writeLinuxManagementFrame(connection, cached)
				}
			}
			return
		}
		defer func() { _ = rebootcontrol.SettleExecution(server.Admission, lease, false, nil) }()
	}
	var result any
	var handleErr error
	if linuxLicensePHPOperation(request.Operation) {
		handler, ok := server.Handler.(LinuxLicensePHPBrokerHandler)
		if !ok {
			handleErr = ErrUnsupported
		} else {
			result, handleErr = handler.HandleLicensePHP(ctx, request)
		}
	} else {
		result, handleErr = server.Handler.HandleManagement(ctx, request)
	}
	payload, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		handleErr = errors.Join(ErrAmbiguous, marshalErr)
		payload = nil
	}
	response := linuxManagementResponse{Version: linuxManagementProtocolVersion, RequestID: request.RequestID, Operation: request.Operation, Succeeded: handleErr == nil, Payload: payload, PayloadDigest: linuxManagementDigest(payload), CompletedAt: time.Now().UTC()}
	if handleErr != nil {
		response.ErrorCode = classifyLinuxManagementError(handleErr)
	}
	if response.validate(request, time.Now().UTC()) != nil {
		return
	}
	if mutation && rebootcontrol.SettleExecution(server.Admission, lease, handleErr == nil && terminalLinuxManagementResponse(request, payload), response) != nil {
		return
	}
	_ = writeLinuxManagementFrame(connection, response)
}

func linuxManagementExecutionBinding(request LinuxManagementRequest) (rebootcontrol.ExecutionBinding, error) {
	effect := ""
	var err error
	switch request.Operation {
	case LinuxManagementInstall, LinuxManagementUpgrade, LinuxManagementConvert, LinuxManagementRemove:
		effect, err = lifecycleEffect(request)
	case LinuxManagementLicenseConfigure, LinuxManagementLicenseRefresh, LinuxManagementPHPInstall, LinuxManagementPHPProfileApply, LinuxManagementPHPRollback:
		effect, err = licensePHPEffect(request)
	case LinuxManagementStage, LinuxManagementValidate, LinuxManagementShadow, LinuxManagementActiveProbe:
		var input lifecycleGenerationInput
		if err = decodeLifecyclePayload(request.Payload, &input); err == nil {
			effect = input.Request.EffectID
		}
	case LinuxManagementSwitch:
		var input SwitchRequest
		if err = decodeLifecyclePayload(request.Payload, &input); err == nil {
			effect = input.EffectRequest.EffectID
		}
	case LinuxManagementConfirm, LinuxManagementRestore:
		var input SwitchReceipt
		if err = decodeLifecyclePayload(request.Payload, &input); err == nil {
			effect = input.EffectID
		}
	default:
		err = ErrUnsupported
	}
	if err != nil || effect == "" {
		return rebootcontrol.ExecutionBinding{}, ErrInvalid
	}
	digest := rebootcontrol.ExecutionDigest(struct {
		Operation LinuxManagementOperation
		Payload   json.RawMessage
	}{request.Operation, request.Payload})
	return rebootcontrol.ExecutionBinding{Boundary: "webengine-management", Method: string(request.Operation), EffectID: effect, RequestDigest: digest, Caller: "authenticated-panel-core", Resource: rebootcontrol.ExecutionResource(struct{ Effect, Payload string }{effect, request.PayloadDigest})}, nil
}

func terminalLinuxManagementResponse(request LinuxManagementRequest, payload []byte) bool {
	switch request.Operation {
	case LinuxManagementInstall, LinuxManagementUpgrade:
		var input lifecyclePlanInput
		var receipt EffectReceipt
		return decodeLifecyclePayload(request.Payload, &input) == nil && decodeLifecyclePayload(payload, &receipt) == nil && validLifecycleReceipt(receipt, input.Request, input.Request.ExpectedGeneration+1)
	case LinuxManagementRemove:
		var input lifecycleRemoveInput
		var receipt EffectReceipt
		return decodeLifecyclePayload(request.Payload, &input) == nil && decodeLifecyclePayload(payload, &receipt) == nil && validLifecycleReceipt(receipt, input.Request, input.Request.ExpectedGeneration+1)
	case LinuxManagementConvert:
		var input lifecycleConvertInput
		var receipt SwitchReceipt
		if decodeLifecyclePayload(request.Payload, &input) != nil || decodeLifecyclePayload(payload, &receipt) != nil {
			return false
		}
		selection := conversionSelection(input.Request, input.Plan.Edition)
		return validConversionReceipt(receipt) && receipt.Confirmed && !receipt.Restored && receipt.EffectID == input.Request.EffectID && receipt.Previous == input.Previous.Desired.Engine.Edition && receipt.Target == input.Plan.Edition && receipt.Target == input.Generation.Edition && receipt.PreviousConfigDigest == input.PreviousConfigDigest && receipt.TargetConfigDigest == input.Generation.ContentDigest && receipt.ConversionDigest == input.Request.PlanDigest && receipt.TargetPlanDigest == digestJSON(input.Plan) && digestJSON(receipt.TargetPlan) == digestJSON(input.Plan) && receipt.TargetChannel == selection.Channel && receipt.Fence == input.Request.Fence && receipt.RollbackDeadline.Sub(receipt.SwitchedAt) == input.RollbackWindow
	case LinuxManagementLicenseConfigure:
		var input licenseConfigureInput
		var status LicenseStatus
		return decodeLifecyclePayload(request.Payload, &input) == nil && decodeLifecyclePayload(payload, &status) == nil && validLicenseStatus(status, input.Request, input.License)
	case LinuxManagementLicenseRefresh:
		var input licenseRefreshInput
		var status LicenseStatus
		if decodeLifecyclePayload(request.Payload, &input) != nil || decodeLifecyclePayload(payload, &status) != nil {
			return false
		}
		return validLicenseStatus(status, input.Request, LicenseRequest{Mode: input.Request.LicenseMode, SecretRef: input.Request.SecretRef, Trial: input.Request.LicenseMode == LicenseModeTrial})
	case LinuxManagementPHPInstall, LinuxManagementPHPProfileApply:
		var receipt EffectReceipt
		var effect EffectRequest
		if decodeLifecyclePayload(payload, &receipt) != nil {
			return false
		}
		if request.Operation == LinuxManagementPHPInstall {
			var input phpInstallInput
			if decodeLifecyclePayload(request.Payload, &input) != nil {
				return false
			}
			effect = input.Request
		} else {
			var input phpProfileInput
			if decodeLifecyclePayload(request.Payload, &input) != nil {
				return false
			}
			effect = input.Request
		}
		return validPHPReceipt(receipt, effect, effect.ExpectedGeneration+1)
	case LinuxManagementPHPRollback:
		var input phpRollbackInput
		var receipt EffectReceipt
		return decodeLifecyclePayload(request.Payload, &input) == nil && decodeLifecyclePayload(payload, &receipt) == nil && validPHPRollbackReceipt(receipt, input.Request, input.Request.ExpectedGeneration)
	case LinuxManagementStage:
		var input lifecycleGenerationInput
		var receipt EffectReceipt
		return decodeLifecyclePayload(request.Payload, &input) == nil && decodeLifecyclePayload(payload, &receipt) == nil && receipt.Outcome == "staged" && receipt.EffectID == input.Request.EffectID && receipt.PlanDigest == input.Request.PlanDigest && receipt.Generation == input.Request.ExpectedGeneration+1 && receipt.Fence == input.Request.Fence && receipt.EvidenceDigest == input.ConfigDigest && !receipt.ObservedAt.IsZero()
	case LinuxManagementValidate:
		var input lifecycleGenerationInput
		var receipt ValidationReceipt
		return decodeLifecyclePayload(request.Payload, &input) == nil && decodeLifecyclePayload(payload, &receipt) == nil && receipt.Valid && receipt.EffectID == input.Request.EffectID && receipt.ConfigDigest == input.ConfigDigest && validSHA256(receipt.ParserDigest) && validSHA256(receipt.SemanticDigest) && !receipt.ObservedAt.IsZero()
	case LinuxManagementShadow, LinuxManagementActiveProbe:
		var input lifecycleGenerationInput
		var receipt ProbeReceipt
		return decodeLifecyclePayload(request.Payload, &input) == nil && decodeLifecyclePayload(payload, &receipt) == nil && receipt.EffectID == input.Request.EffectID && receipt.ConfigDigest == input.ConfigDigest && receipt.PHP && validSHA256(receipt.EvidenceDigest) && !receipt.ObservedAt.IsZero()
	case LinuxManagementSwitch:
		var input SwitchRequest
		var receipt SwitchReceipt
		return decodeLifecyclePayload(request.Payload, &input) == nil && decodeLifecyclePayload(payload, &receipt) == nil && !receipt.Confirmed && !receipt.Restored && receipt.EffectID == input.EffectRequest.EffectID && receipt.Previous == input.Previous && receipt.Target == input.Target && receipt.PreviousConfigDigest == input.PreviousConfigDigest && receipt.TargetConfigDigest == input.TargetConfigDigest && receipt.Fence == input.EffectRequest.Fence && receipt.LeaseID != "" && validSHA256(receipt.ConfirmNonce) && receipt.RollbackDeadline.Equal(input.RollbackDeadline) && !receipt.SwitchedAt.IsZero() && receipt.EvidenceDigest == ""
	case LinuxManagementConfirm, LinuxManagementRestore:
		var input SwitchReceipt
		var receipt ProbeReceipt
		if decodeLifecyclePayload(request.Payload, &input) != nil || decodeLifecyclePayload(payload, &receipt) != nil || receipt.EffectID != input.EffectID || !receipt.PHP || !validSHA256(receipt.EvidenceDigest) || receipt.ObservedAt.IsZero() {
			return false
		}
		if request.Operation == LinuxManagementConfirm {
			return receipt.ConfigDigest == input.TargetConfigDigest
		}
		return receipt.ConfigDigest == input.PreviousConfigDigest
	default:
		return false
	}
}

type LinuxManagementClient struct{}

func NewLocalLinuxManagementClient() (*LinuxManagementClient, error) {
	info, err := os.Lstat(LinuxManagementSocketPath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o002 != 0 {
		return nil, ErrInvalid
	}
	return &LinuxManagementClient{}, nil
}

func (client *LinuxManagementClient) call(ctx context.Context, operation LinuxManagementOperation, input, output any) error {
	if client == nil || ctx == nil {
		return ErrInvalid
	}
	payload, err := json.Marshal(input)
	if err != nil || len(payload) == 0 || len(payload) > linuxManagementMaximumFrame {
		return ErrInvalid
	}
	digest := linuxManagementDigest(payload)
	deadline := time.Now().UTC().Add(30 * time.Minute)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value.UTC()
	}
	request := LinuxManagementRequest{Version: linuxManagementProtocolVersion, RequestID: "wem-" + linuxManagementDigest([]byte(string(operation) + "\x00" + digest))[:40], Operation: operation, Deadline: deadline, Payload: payload, PayloadDigest: digest}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", LinuxManagementSocketPath)
	if err != nil {
		return err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	_ = connection.SetDeadline(deadline)
	if err = writeLinuxManagementFrame(connection, request); err != nil {
		return err
	}
	var response linuxManagementResponse
	if err = readLinuxManagementFrame(connection, &response); err != nil {
		return err
	}
	if err = response.validate(request, time.Now().UTC()); err != nil {
		return err
	}
	if output != nil && len(response.Payload) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(response.Payload))
		decoder.DisallowUnknownFields()
		if decoder.Decode(output) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return ErrAmbiguous
		}
	}
	if !response.Succeeded {
		return linuxManagementFailure(response.ErrorCode)
	}
	return nil
}

func (client *LinuxManagementClient) Inspect(ctx context.Context, edition webengine.Edition) (output Installation, err error) {
	err = client.call(ctx, LinuxManagementInspect, struct {
		Edition webengine.Edition `json:"edition"`
	}{edition}, &output)
	return
}
func (client *LinuxManagementClient) Install(ctx context.Context, request EffectRequest, plan ArtifactPlan) (output EffectReceipt, err error) {
	err = client.call(ctx, LinuxManagementInstall, lifecyclePlanInput{request, plan}, &output)
	return
}
func (client *LinuxManagementClient) Upgrade(ctx context.Context, request EffectRequest, plan ArtifactPlan) (output EffectReceipt, err error) {
	err = client.call(ctx, LinuxManagementUpgrade, lifecyclePlanInput{request, plan}, &output)
	return
}
func (client *LinuxManagementClient) ConvertEdition(ctx context.Context, request EffectRequest, plan ArtifactPlan, generation native.ConfigGeneration, window time.Duration) (output SwitchReceipt, err error) {
	err = client.call(ctx, LinuxManagementConvert, lifecycleConvertInput{Request: request, Plan: plan, Generation: generation, RollbackWindow: window, License: conversionLicense(request)}, &output)
	return
}
func (client *LinuxManagementClient) Remove(ctx context.Context, request EffectRequest, edition webengine.Edition) (output EffectReceipt, err error) {
	err = client.call(ctx, LinuxManagementRemove, lifecycleRemoveInput{request, edition}, &output)
	return
}
func (client *LinuxManagementClient) ApplyLicense(ctx context.Context, request EffectRequest, license LicenseRequest) (output LicenseStatus, err error) {
	err = client.call(ctx, LinuxManagementLicenseConfigure, licenseConfigureInput{request, license}, &output)
	return
}
func (client *LinuxManagementClient) RefreshLicense(ctx context.Context, request EffectRequest) (output LicenseStatus, err error) {
	err = client.call(ctx, LinuxManagementLicenseRefresh, licenseRefreshInput{request}, &output)
	return
}
func (client *LinuxManagementClient) InstallPHP(ctx context.Context, request EffectRequest, plan PHPArtifactPlan) (output EffectReceipt, err error) {
	err = client.call(ctx, LinuxManagementPHPInstall, phpInstallInput{request, plan}, &output)
	return
}
func (client *LinuxManagementClient) ApplyPHPProfile(ctx context.Context, request EffectRequest, profile PHPProfile) (output EffectReceipt, err error) {
	err = client.call(ctx, LinuxManagementPHPProfileApply, phpProfileInput{request, profile}, &output)
	return
}
func (client *LinuxManagementClient) RollbackPHP(ctx context.Context, request EffectRequest, plan PHPArtifactPlan, previous *PHPProfile) (output EffectReceipt, err error) {
	err = client.call(ctx, LinuxManagementPHPRollback, phpRollbackInput{request, plan, previous}, &output)
	return
}

func (request LinuxManagementRequest) validate(now time.Time) error {
	if request.Version != linuxManagementProtocolVersion || len(request.RequestID) < 8 || len(request.RequestID) > 96 || request.Operation == "" || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.After(now.Add(31*time.Minute)) || len(request.Payload) == 0 || len(request.Payload) > linuxManagementMaximumFrame || request.PayloadDigest != linuxManagementDigest(request.Payload) {
		return ErrInvalid
	}
	return nil
}
func linuxLicensePHPOperation(operation LinuxManagementOperation) bool {
	switch operation {
	case LinuxManagementLicenseConfigure, LinuxManagementLicenseRefresh, LinuxManagementPHPInstall, LinuxManagementPHPProfileApply, LinuxManagementPHPRollback:
		return true
	default:
		return false
	}
}
func (response linuxManagementResponse) validate(request LinuxManagementRequest, now time.Time) error {
	if response.Version != linuxManagementProtocolVersion || response.RequestID != request.RequestID || response.Operation != request.Operation || response.CompletedAt.IsZero() || response.CompletedAt.After(now.Add(time.Minute)) || response.PayloadDigest != linuxManagementDigest(response.Payload) {
		return ErrAmbiguous
	}
	if response.Succeeded {
		if response.ErrorCode != "" {
			return ErrAmbiguous
		}
	} else if response.ErrorCode == "" {
		return ErrAmbiguous
	}
	return nil
}
func linuxManagementDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
func classifyLinuxManagementError(err error) string {
	switch {
	case errors.Is(err, ErrInvalid):
		return "invalid"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrLicense):
		return "license"
	case errors.Is(err, ErrAmbiguous):
		return "ambiguous"
	default:
		return "failed"
	}
}
func linuxManagementFailure(code string) error {
	switch code {
	case "":
		return nil
	case "invalid":
		return ErrInvalid
	case "not_found":
		return ErrNotFound
	case "conflict":
		return ErrConflict
	case "unsupported":
		return ErrUnsupported
	case "license":
		return ErrLicense
	case "ambiguous":
		return ErrAmbiguous
	default:
		return errors.New("webengine management broker failed")
	}
}
func writeLinuxManagementFrame(writer io.Writer, value any) error {
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > linuxManagementMaximumFrame {
		return ErrInvalid
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(content)))
	if err = writeLinuxManagementAll(writer, header[:]); err != nil {
		return err
	}
	return writeLinuxManagementAll(writer, content)
}
func writeLinuxManagementAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(content) {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}
func readLinuxManagementFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > linuxManagementMaximumFrame {
		return ErrInvalid
	}
	content := make([]byte, size)
	if _, err := io.ReadFull(reader, content); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, content) {
		return ErrInvalid
	}
	return nil
}

var _ LifecycleExecutor = (*LinuxManagementClient)(nil)
