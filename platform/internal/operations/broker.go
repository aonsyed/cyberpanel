package operations

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	OperationsBrokerProtocolVersion uint16 = 1
	OperationsBrokerMaximumFrameBytes     = 64 << 20
)

var (
	ErrOperationsBrokerProtocol = errors.New("invalid operations broker protocol")
	ErrOperationsBrokerPeer     = errors.New("unauthorized operations broker peer")
)

type BrokerMethod string

const (
	BrokerObserveOrApply BrokerMethod = "observe_or_apply"
	BrokerCompensate     BrokerMethod = "compensate"
)

type BrokerRequest struct {
	Version      uint16               `json:"version"`
	Method       BrokerMethod         `json:"method"`
	Effect       *EffectRequest       `json:"effect,omitempty"`
	Compensation *CompensationRequest `json:"compensation,omitempty"`
	Deadline     time.Time            `json:"deadline"`
}

func (request BrokerRequest) Validate(now time.Time) error {
	if request.Version != OperationsBrokerProtocolVersion || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.After(now.Add(10*time.Minute)) {
		return ErrOperationsBrokerProtocol
	}
	switch request.Method {
	case BrokerObserveOrApply:
		if request.Effect == nil || request.Compensation != nil || validateEffectRequest(*request.Effect) != nil { return ErrOperationsBrokerProtocol }
	case BrokerCompensate:
		if request.Effect != nil || request.Compensation == nil || validateCompensationRequest(*request.Compensation) != nil { return ErrOperationsBrokerProtocol }
	default:
		return ErrOperationsBrokerProtocol
	}
	return nil
}

func validateCompensationRequest(request CompensationRequest) error {
	if request.EffectID == "" || !validSHA256(request.RequestDigest) || request.Scope.NodeID.IsZero() || request.Scope.ID.IsZero() || request.CompensationToken.IsZero() || request.FailureCode == "" || len(request.FailureCode) > 128 {
		return ErrInvalidEffect
	}
	return nil
}

type BrokerResponse struct {
	Version      uint16               `json:"version"`
	Method       BrokerMethod         `json:"method"`
	Effect       *EffectReceipt       `json:"effect,omitempty"`
	Compensation *CompensationReceipt `json:"compensation,omitempty"`
	ErrorCode    string               `json:"error_code,omitempty"`
	CompletedAt  time.Time            `json:"completed_at"`
}

func (response BrokerResponse) Validate(request BrokerRequest, now time.Time) error {
	if response.Version != OperationsBrokerProtocolVersion || response.Method != request.Method || response.CompletedAt.IsZero() || response.CompletedAt.After(now.Add(time.Minute)) || !validBrokerErrorCode(response.ErrorCode) {
		return ErrOperationsBrokerProtocol
	}
	switch request.Method {
	case BrokerObserveOrApply:
		if response.Effect == nil || response.Compensation != nil || !effectReceiptMatches(*request.Effect, *response.Effect) { return ErrOperationsBrokerProtocol }
	case BrokerCompensate:
		if response.Effect != nil || response.Compensation == nil || !compensationReceiptMatches(*request.Compensation, *response.Compensation) { return ErrOperationsBrokerProtocol }
	default:
		return ErrOperationsBrokerProtocol
	}
	return nil
}

func validBrokerErrorCode(code string) bool {
	switch code {
	case "", "invalid_request", "unauthorized", "rejected", "ambiguous", "idempotency_conflict", "internal_error": return true
	default: return false
	}
}

type OperationsBrokerTransport interface { RoundTrip(context.Context, BrokerRequest) (BrokerResponse, error) }
type OperationsBrokerDialer interface { DialContext(context.Context) (net.Conn, error) }

type FramedOperationsBrokerTransport struct { Dialer OperationsBrokerDialer }

func (transport FramedOperationsBrokerTransport) RoundTrip(ctx context.Context, request BrokerRequest) (BrokerResponse, error) {
	if ctx == nil || transport.Dialer == nil { return BrokerResponse{}, ErrOperationsBrokerProtocol }
	connection, err := transport.Dialer.DialContext(ctx); if err != nil { return BrokerResponse{}, err }
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) }); defer stop()
	deadline := request.Deadline
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) { deadline = contextDeadline }
	if err = connection.SetDeadline(deadline); err != nil { return BrokerResponse{}, err }
	if err = writeOperationsFrame(connection, request); err != nil { return BrokerResponse{}, err }
	var response BrokerResponse
	if err = readOperationsFrame(connection, &response); err != nil { return BrokerResponse{}, err }
	return response, nil
}

type OperationsBrokerClient struct { transport OperationsBrokerTransport; clock Clock }

func NewOperationsBrokerClient(transport OperationsBrokerTransport) (*OperationsBrokerClient, error) {
	if transport == nil { return nil, ErrOperationsBrokerProtocol }
	return &OperationsBrokerClient{transport: transport, clock: SystemClock{}}, nil
}

func (client *OperationsBrokerClient) ObserveOrApply(ctx context.Context, effect EffectRequest) (EffectReceipt, error) {
	request := BrokerRequest{Version: OperationsBrokerProtocolVersion, Method: BrokerObserveOrApply, Effect: &effect, Deadline: brokerDeadline(ctx, client.clock.Now())}
	if err := request.Validate(client.clock.Now()); err != nil { return EffectReceipt{}, err }
	response, err := client.transport.RoundTrip(ctx, request); if err != nil { return EffectReceipt{}, err }
	if err = response.Validate(request, client.clock.Now()); err != nil { return EffectReceipt{}, err }
	if response.ErrorCode != "" { return *response.Effect, brokerError(response.ErrorCode) }
	return *response.Effect, nil
}

func (client *OperationsBrokerClient) Compensate(ctx context.Context, compensation CompensationRequest) (CompensationReceipt, error) {
	request := BrokerRequest{Version: OperationsBrokerProtocolVersion, Method: BrokerCompensate, Compensation: &compensation, Deadline: brokerDeadline(ctx, client.clock.Now())}
	if err := request.Validate(client.clock.Now()); err != nil { return CompensationReceipt{}, err }
	response, err := client.transport.RoundTrip(ctx, request); if err != nil { return CompensationReceipt{}, err }
	if err = response.Validate(request, client.clock.Now()); err != nil { return CompensationReceipt{}, err }
	if response.ErrorCode != "" { return *response.Compensation, brokerError(response.ErrorCode) }
	return *response.Compensation, nil
}

func brokerDeadline(ctx context.Context, now time.Time) time.Time {
	deadline := now.Add(5 * time.Minute)
	if candidate, ok := ctx.Deadline(); ok && candidate.Before(deadline) { deadline = candidate }
	return deadline.UTC()
}

func brokerError(code string) error {
	switch code {
	case "invalid_request": return ErrInvalidEffect
	case "unauthorized": return ErrOperationsBrokerPeer
	case "rejected": return ErrInvalidCommand
	case "idempotency_conflict": return ErrIdempotency
	default: return ErrCompensationFailed
	}
}

type OperationsBrokerPeerAuthorizer interface { Authorize(net.Conn) error }

type OperationsBrokerServer struct {
	Authorizer OperationsBrokerPeerAuthorizer
	Handler HostExecutor
	MaximumConcurrent uint32
}

func (server *OperationsBrokerServer) Serve(listener net.Listener) error {
	if listener == nil || server.Authorizer == nil || server.Handler == nil { return ErrOperationsBrokerProtocol }
	maximum := server.MaximumConcurrent; if maximum == 0 { maximum = 64 }
	gate := make(chan struct{}, maximum)
	var group sync.WaitGroup
	defer group.Wait()
	for {
		connection, err := listener.Accept(); if err != nil { return err }
		gate <- struct{}{}; group.Add(1)
		go func() { defer func() { <-gate; group.Done() }(); server.serve(connection) }()
	}
}

func (server *OperationsBrokerServer) serve(connection net.Conn) {
	defer connection.Close()
	if err := server.Authorizer.Authorize(connection); err != nil { return }
	_ = connection.SetDeadline(time.Now().Add(10 * time.Minute))
	var request BrokerRequest
	if err := readOperationsFrame(connection, &request); err != nil || request.Validate(time.Now().UTC()) != nil { return }
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline); defer cancel()
	response := BrokerResponse{Version: OperationsBrokerProtocolVersion, Method: request.Method, CompletedAt: time.Now().UTC()}
	switch request.Method {
	case BrokerObserveOrApply:
		receipt, err := server.Handler.ObserveOrApply(ctx, *request.Effect); response.Effect = &receipt; response.ErrorCode = brokerCode(err, receipt.Outcome)
	case BrokerCompensate:
		receipt, err := server.Handler.Compensate(ctx, *request.Compensation); response.Compensation = &receipt; response.ErrorCode = brokerCode(err, receipt.Outcome)
	}
	response.CompletedAt = time.Now().UTC()
	if response.Validate(request, time.Now().UTC()) == nil { _ = writeOperationsFrame(connection, response) }
}

func brokerCode(err error, outcome EffectOutcome) string {
	if err == nil { return "" }
	if errors.Is(err, ErrIdempotency) { return "idempotency_conflict" }
	if errors.Is(err, ErrInvalidEffect) || errors.Is(err, ErrInvalidCommand) { return "invalid_request" }
	if outcome == EffectRejected { return "rejected" }
	if outcome == EffectAmbiguous { return "ambiguous" }
	return "internal_error"
}

func writeOperationsFrame(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value); if err != nil || len(encoded) == 0 || len(encoded) > OperationsBrokerMaximumFrameBytes { return ErrOperationsBrokerProtocol }
	var header [4]byte; binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
	if err = writeOperationsAll(writer, header[:]); err != nil { return err }
	return writeOperationsAll(writer, encoded)
}

func writeOperationsAll(writer io.Writer, content []byte) error {
	for len(content) > 0 { count, err := writer.Write(content); if err != nil { return err }; if count <= 0 || count > len(content) { return io.ErrShortWrite }; content = content[count:] }
	return nil
}

func readOperationsFrame(reader io.Reader, target any) error {
	var header [4]byte; if _, err := io.ReadFull(reader, header[:]); err != nil { return err }
	size := binary.BigEndian.Uint32(header[:]); if size == 0 || size > OperationsBrokerMaximumFrameBytes { return ErrOperationsBrokerProtocol }
	content := make([]byte, size); if _, err := io.ReadFull(reader, content); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(content)); decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF { return ErrOperationsBrokerProtocol }
	canonical, err := json.Marshal(target); if err != nil || !bytes.Equal(canonical, content) { return ErrOperationsBrokerProtocol }
	return nil
}
