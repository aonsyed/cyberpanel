package database

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	DatabaseBrokerProtocolVersion uint32 = 1
	DatabaseBrokerMaximumFrame          = 1 << 20
)

type BrokerOperation string

const (
	BrokerObserveOrApply BrokerOperation = "observe_or_apply"
	BrokerCompensate     BrokerOperation = "compensate"
)

type BrokerRequest struct {
	Version      uint32               `json:"version"`
	RequestID    string               `json:"request_id"`
	Operation    BrokerOperation      `json:"operation"`
	Deadline     time.Time            `json:"deadline"`
	Effect       *EffectRequest       `json:"effect,omitempty"`
	Compensation *CompensationRequest `json:"compensation,omitempty"`
}

type BrokerResponse struct {
	Version      uint32                `json:"version"`
	RequestID    string                `json:"request_id"`
	Operation    BrokerOperation       `json:"operation"`
	Effect       *EffectReceipt        `json:"effect,omitempty"`
	Compensation *CompensationReceipt  `json:"compensation,omitempty"`
	FailureCode  string                `json:"failure_code,omitempty"`
}

func (request BrokerRequest) validate(now time.Time) error {
	if request.Version != DatabaseBrokerProtocolVersion || !validBrokerRequestID(request.RequestID) || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.After(now.Add(2*time.Minute)) {
		return ErrInvalidCommand
	}
	switch request.Operation {
	case BrokerObserveOrApply:
		if request.Effect == nil || request.Compensation != nil || validateEffectRequest(*request.Effect) != nil {
			return ErrInvalidCommand
		}
	case BrokerCompensate:
		if request.Effect != nil || request.Compensation == nil || !validCompensationRequest(*request.Compensation) {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func (response BrokerResponse) validate(request BrokerRequest) error {
	if response.Version != DatabaseBrokerProtocolVersion || response.RequestID != request.RequestID || response.Operation != request.Operation {
		return ErrInvalidReceipt
	}
	if response.FailureCode != "" {
		if response.Effect != nil || response.Compensation != nil || !validBrokerFailure(response.FailureCode) {
			return ErrInvalidReceipt
		}
		return nil
	}
	switch request.Operation {
	case BrokerObserveOrApply:
		return validateBrokerEffectResponse(request, response)
	case BrokerCompensate:
		return validateBrokerCompensationResponse(request, response)
	default:
		return ErrInvalidReceipt
	}
}

func validateBrokerEffectResponse(request BrokerRequest, response BrokerResponse) error {
	if response.Effect == nil || response.Compensation != nil || request.Effect == nil || !effectReceiptMatches(*request.Effect, *response.Effect) {
		return ErrInvalidReceipt
	}
	return nil
}

func validateBrokerCompensationResponse(request BrokerRequest, response BrokerResponse) error {
	if response.Effect != nil || response.Compensation == nil || request.Compensation == nil || !compensationReceiptMatches(*request.Compensation, *response.Compensation) {
		return ErrInvalidReceipt
	}
	return nil
}

func validCompensationRequest(request CompensationRequest) bool {
	return request.EffectID != "" && validSHA256(request.RequestDigest) && !request.Scope.ID.IsZero() && !request.CompensationToken.IsZero() && request.FailureCode != ""
}

func validBrokerRequestID(value string) bool {
	if len(value) != 36 || value[:4] != "req-" { return false }
	_, err := hex.DecodeString(value[4:])
	return err == nil
}

func validBrokerFailure(value string) bool {
	switch value {
	case "invalid_request", "unauthorized", "deadline", "unavailable", "internal", "ambiguous":
		return true
	default:
		return false
	}
}

type DatabaseBrokerTransport interface {
	RoundTrip(context.Context, BrokerRequest) (BrokerResponse, error)
}

type BrokerClient struct {
	transport DatabaseBrokerTransport
	now       func() time.Time
}

var _ MariaDBExecutor = (*BrokerClient)(nil)

func NewBrokerClient(transport DatabaseBrokerTransport) (*BrokerClient, error) {
	if transport == nil { return nil, ErrInvalidCommand }
	return &BrokerClient{transport: transport, now: time.Now}, nil
}

func (client *BrokerClient) ObserveOrApply(ctx context.Context, effect EffectRequest) (EffectReceipt, error) {
	request, err := client.request(ctx, BrokerObserveOrApply)
	if err != nil { return EffectReceipt{}, err }
	request.Effect = &effect
	if err = request.validate(client.now().UTC()); err != nil { return EffectReceipt{}, err }
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil { return EffectReceipt{}, err }
	if err = response.validate(request); err != nil { return EffectReceipt{}, err }
	if response.FailureCode != "" { return EffectReceipt{}, brokerFailure(response.FailureCode) }
	return *response.Effect, nil
}

func (client *BrokerClient) Compensate(ctx context.Context, compensation CompensationRequest) (CompensationReceipt, error) {
	request, err := client.request(ctx, BrokerCompensate)
	if err != nil { return CompensationReceipt{}, err }
	request.Compensation = &compensation
	if err = request.validate(client.now().UTC()); err != nil { return CompensationReceipt{}, err }
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil { return CompensationReceipt{}, err }
	if err = response.validate(request); err != nil { return CompensationReceipt{}, err }
	if response.FailureCode != "" { return CompensationReceipt{}, brokerFailure(response.FailureCode) }
	return *response.Compensation, nil
}

func (client *BrokerClient) request(ctx context.Context, operation BrokerOperation) (BrokerRequest, error) {
	if client == nil || client.transport == nil || ctx == nil { return BrokerRequest{}, ErrInvalidCommand }
	identifier := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, identifier); err != nil { return BrokerRequest{}, err }
	now := client.now().UTC()
	deadline := now.Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) { deadline = value.UTC() }
	return BrokerRequest{Version: DatabaseBrokerProtocolVersion, RequestID: "req-" + hex.EncodeToString(identifier), Operation: operation, Deadline: deadline}, nil
}

type DatabaseBrokerDialer interface {
	DialContext(context.Context) (net.Conn, error)
}

type FramedDatabaseBrokerTransport struct{ Dialer DatabaseBrokerDialer }

func (transport FramedDatabaseBrokerTransport) RoundTrip(ctx context.Context, request BrokerRequest) (BrokerResponse, error) {
	if transport.Dialer == nil { return BrokerResponse{}, ErrInvalidCommand }
	connection, err := transport.Dialer.DialContext(ctx)
	if err != nil { return BrokerResponse{}, err }
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	deadline := request.Deadline
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) { deadline = value }
	if err = connection.SetDeadline(deadline); err != nil { return BrokerResponse{}, err }
	if err = writeDatabaseBrokerFrame(connection, request); err != nil { return BrokerResponse{}, err }
	var response BrokerResponse
	if err = readDatabaseBrokerFrame(connection, &response); err != nil { return BrokerResponse{}, err }
	return response, nil
}

type DatabaseBrokerAuthorizer interface{ Authorize(net.Conn) error }

type DatabaseBrokerServer struct {
	Authorizer        DatabaseBrokerAuthorizer
	Executor          MariaDBExecutor
	MaximumConcurrent uint32
	Now               func() time.Time
	once              sync.Once
	semaphore         chan struct{}
}

func (server *DatabaseBrokerServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.Authorizer == nil || server.Executor == nil { return ErrInvalidCommand }
	server.once.Do(func() {
		maximum := server.MaximumConcurrent
		if maximum == 0 { maximum = 64 }
		if maximum > 1024 { maximum = 1024 }
		server.semaphore = make(chan struct{}, maximum)
	})
	for {
		connection, err := listener.Accept()
		if err != nil { return err }
		select {
		case server.semaphore <- struct{}{}:
			go func() { defer func() { <-server.semaphore; _ = connection.Close() }(); server.serve(connection) }()
		default:
			_ = connection.Close()
		}
	}
}

func (server *DatabaseBrokerServer) serve(connection net.Conn) {
	if server.Authorizer.Authorize(connection) != nil { return }
	now := time.Now().UTC()
	if server.Now != nil { now = server.Now().UTC() }
	_ = connection.SetReadDeadline(now.Add(15 * time.Second))
	var request BrokerRequest
	if readDatabaseBrokerFrame(connection, &request) != nil || request.validate(now) != nil {
		_ = writeDatabaseBrokerFrame(connection, BrokerResponse{Version: DatabaseBrokerProtocolVersion, RequestID: request.RequestID, Operation: request.Operation, FailureCode: "invalid_request"})
		return
	}
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	response := BrokerResponse{Version: DatabaseBrokerProtocolVersion, RequestID: request.RequestID, Operation: request.Operation}
	var err error
	switch request.Operation {
	case BrokerObserveOrApply:
		var receipt EffectReceipt
		receipt, err = server.Executor.ObserveOrApply(ctx, *request.Effect)
		if effectReceiptMatches(*request.Effect, receipt) { response.Effect = &receipt }
	case BrokerCompensate:
		var receipt CompensationReceipt
		receipt, err = server.Executor.Compensate(ctx, *request.Compensation)
		if compensationReceiptMatches(*request.Compensation, receipt) { response.Compensation = &receipt }
	}
	if response.Effect == nil && response.Compensation == nil {
		response.FailureCode = classifyBrokerFailure(err)
	}
	_ = writeDatabaseBrokerFrame(connection, response)
}

func writeDatabaseBrokerFrame(writer io.Writer, value any) error {
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > DatabaseBrokerMaximumFrame { return ErrInvalidCommand }
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(content)))
	if err = writeDatabaseBrokerBytes(writer, header[:]); err != nil { return err }
	return writeDatabaseBrokerBytes(writer, content)
}

func writeDatabaseBrokerBytes(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil { return err }
		if written <= 0 || written > len(content) { return io.ErrShortWrite }
		content = content[written:]
	}
	return nil
}

func readDatabaseBrokerFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil { return err }
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > DatabaseBrokerMaximumFrame { return ErrInvalidCommand }
	content := make([]byte, size)
	if _, err := io.ReadFull(reader, content); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return ErrInvalidCommand }
	if decoder.Decode(&struct{}{}) != io.EOF { return ErrInvalidCommand }
	return nil
}

func classifyBrokerFailure(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled): return "deadline"
	case errors.Is(err, ErrUnauthorized): return "unauthorized"
	case errors.Is(err, ErrInvalidCommand), errors.Is(err, ErrInvalidResource): return "invalid_request"
	case errors.Is(err, ErrAmbiguous): return "ambiguous"
	case err == nil: return "internal"
	default: return "internal"
	}
}

func brokerFailure(code string) error {
	switch code {
	case "invalid_request": return ErrInvalidCommand
	case "unauthorized": return ErrUnauthorized
	case "deadline": return context.DeadlineExceeded
	case "ambiguous": return ErrAmbiguous
	case "unavailable", "internal": return errors.New("database broker unavailable")
	default: return ErrInvalidReceipt
	}
}
