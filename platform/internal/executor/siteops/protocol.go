package siteops

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

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
)

type Transport interface { RoundTrip(context.Context, Request) (Response, error) }

// Client implements provisioning.PrivilegedExecutor over the typed local
// protocol. It never exposes the transport's wire request to hosting callers.
type Client struct {
	transport Transport
	now       func() time.Time
}

var _ provisioning.PrivilegedExecutor = (*Client)(nil)

func NewClient(transport Transport) (*Client, error) {
	if nilInterface(transport) { return nil, errors.New("siteops transport is required") }
	return &Client{transport: transport}, nil
}

func (client *Client) WithClock(clock func() time.Time) *Client { if client != nil && clock != nil { client.now = clock }; return client }
func (client *Client) currentTime() time.Time { if client.now != nil { return client.now().UTC() }; return time.Now().UTC() }

func (client *Client) execute(ctx context.Context, operation Operation, spec provisioning.RuntimeSpec, attestation string) (any, error) {
	if client == nil || nilInterface(client.transport) || nilInterface(ctx) { return nil, ErrInvalidRequest }
	now := client.currentTime(); deadline := now.Add(30*time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) { deadline = contextDeadline }
	requestID, err := newRequestID(); if err != nil { return nil, err }
	request := requestFromSpec(operation, requestID, spec, attestation, now, deadline)
	if err = request.Validate(now); err != nil { return nil, err }
	response, err := client.transport.RoundTrip(ctx, request); if err != nil { return nil, err }
	if err = response.Validate(request, client.currentTime()); err != nil { return nil, err }
	return receiptFromResponse(request, response)
}

func (client *Client) EnsureIdentity(ctx context.Context, spec provisioning.RuntimeSpec) (provisioning.IdentityReceipt, error) {
	value, err := client.execute(ctx, OperationEnsureIdentity, spec, ""); if err != nil { return provisioning.IdentityReceipt{}, err }; receipt, ok := value.(provisioning.IdentityReceipt); if !ok { return provisioning.IdentityReceipt{}, ErrInvalidResponse }; return receipt, nil
}
func (client *Client) EnsureDirectories(ctx context.Context, spec provisioning.RuntimeSpec) (provisioning.DirectoryReceipt, error) {
	value, err := client.execute(ctx, OperationEnsureDirectories, spec, ""); if err != nil { return provisioning.DirectoryReceipt{}, err }; receipt, ok := value.(provisioning.DirectoryReceipt); if !ok { return provisioning.DirectoryReceipt{}, ErrInvalidResponse }; return receipt, nil
}
func (client *Client) EnsureLSAPIPool(ctx context.Context, spec provisioning.RuntimeSpec) (provisioning.LSAPIPoolReceipt, error) {
	value, err := client.execute(ctx, OperationEnsureLSAPIPool, spec, ""); if err != nil { return provisioning.LSAPIPoolReceipt{}, err }; receipt, ok := value.(provisioning.LSAPIPoolReceipt); if !ok { return provisioning.LSAPIPoolReceipt{}, ErrInvalidResponse }; return receipt, nil
}
func (client *Client) WriteHealthAttestation(ctx context.Context, spec provisioning.RuntimeSpec, attestation provisioning.HealthAttestation) (provisioning.HealthReceipt, error) {
	value, err := client.execute(ctx, OperationWriteHealth, spec, attestation.Digest()); if err != nil { return provisioning.HealthReceipt{}, err }; receipt, ok := value.(provisioning.HealthReceipt); if !ok { return provisioning.HealthReceipt{}, ErrInvalidResponse }; return receipt, nil
}
func (client *Client) Suspend(ctx context.Context, spec provisioning.RuntimeSpec) (provisioning.LifecycleReceipt, error) { return client.lifecycle(ctx, OperationSuspend, spec) }
func (client *Client) Quarantine(ctx context.Context, spec provisioning.RuntimeSpec) (provisioning.LifecycleReceipt, error) { return client.lifecycle(ctx, OperationQuarantine, spec) }
func (client *Client) Purge(ctx context.Context, spec provisioning.RuntimeSpec) (provisioning.LifecycleReceipt, error) { return client.lifecycle(ctx, OperationPurge, spec) }
func (client *Client) lifecycle(ctx context.Context, operation Operation, spec provisioning.RuntimeSpec) (provisioning.LifecycleReceipt, error) { value, err := client.execute(ctx, operation, spec, ""); if err != nil { return provisioning.LifecycleReceipt{}, err }; receipt, ok := value.(provisioning.LifecycleReceipt); if !ok { return provisioning.LifecycleReceipt{}, ErrInvalidResponse }; return receipt, nil }

func newRequestID() (string, error) { var value [16]byte; if _, err := io.ReadFull(rand.Reader, value[:]); err != nil { return "", err }; return "req-" + hex.EncodeToString(value[:]), nil }

type ConnectionDialer interface { DialContext(context.Context) (net.Conn, error) }

type FramedTransport struct{ Dialer ConnectionDialer }

func (transport FramedTransport) RoundTrip(ctx context.Context, request Request) (Response, error) {
	if transport.Dialer == nil { return Response{}, errors.New("siteops connection dialer is required") }
	connection, err := transport.Dialer.DialContext(ctx); if err != nil { return Response{}, err }; defer connection.Close()
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) }); defer stopCancellation()
	deadline := request.Deadline; if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) { deadline = contextDeadline }
	if err = connection.SetDeadline(deadline); err != nil { return Response{}, err }
	if err = writeFrame(connection, request); err != nil { return Response{}, err }
	var reply wireReply; if err = readFrame(connection, &reply); err != nil { return Response{}, err }
	if reply.ProtocolError != "" { return Response{}, joinError(reply.ProtocolError) }
	return reply.Response, nil
}

type wireReply struct {
	Response      Response `json:"response"`
	ProtocolError string   `json:"protocol_error,omitempty"`
}

func writeFrame(writer io.Writer, value any) error {
	content, err := json.Marshal(value); if err != nil { return err }
	if len(content) == 0 || len(content) > MaximumFrameBytes { return ErrInvalidRequest }
	var header [4]byte; binary.BigEndian.PutUint32(header[:], uint32(len(content)))
	if err = writeAll(writer, header[:]); err != nil { return err }; return writeAll(writer, content)
}

func writeAll(writer io.Writer, content []byte) error { for len(content) > 0 { written, err := writer.Write(content); if err != nil { return err }; if written <= 0 || written > len(content) { return io.ErrShortWrite }; content = content[written:] }; return nil }

func readFrame(reader io.Reader, target any) error {
	var header [4]byte; if _, err := io.ReadFull(reader, header[:]); err != nil { return err }
	size := binary.BigEndian.Uint32(header[:]); if size == 0 || size > MaximumFrameBytes { return ErrInvalidRequest }
	content := make([]byte, size); if _, err := io.ReadFull(reader, content); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(content)); decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return ErrInvalidRequest }
	if decoder.Decode(&struct{}{}) != io.EOF { return ErrInvalidRequest }
	return nil
}

type PeerAuthorizer interface { Authorize(net.Conn) error }
type RequestHandler interface { Execute(context.Context, Request) (Response, error) }

type Server struct {
	Authorizer PeerAuthorizer
	Handler    RequestHandler
	Admission  rebootcontrol.ExecutionAdmission
	MaximumConcurrent uint32
	Now        func() time.Time
	semaphore  chan struct{}
	once       sync.Once
}

func (server *Server) Serve(listener net.Listener) error {
	if server == nil || listener == nil || nilInterface(server.Authorizer) || nilInterface(server.Handler) { return errors.New("siteops server listener, authorizer, and handler are required") }
	server.once.Do(func() { maximum := server.MaximumConcurrent; if maximum == 0 { maximum = 128 }; if maximum > 4096 { maximum = 4096 }; server.semaphore = make(chan struct{}, maximum) })
	for {
		connection, err := listener.Accept(); if err != nil { return err }
		select {
		case server.semaphore <- struct{}{}:
			go func() { defer func() { <-server.semaphore; connection.Close() }(); server.serveConnection(connection) }()
		default:
			_ = connection.SetDeadline(time.Now()); _ = connection.Close()
		}
	}
}

func (server *Server) serveConnection(connection net.Conn) {
	if err := server.Authorizer.Authorize(connection); err != nil { return }
	now := time.Now().UTC(); if server.Now != nil { now = server.Now().UTC() }
	_ = connection.SetReadDeadline(now.Add(15*time.Second))
	var request Request
	if err := readFrame(connection, &request); err != nil { _ = writeFrame(connection, wireReply{ProtocolError: "invalid_frame"}); return }
	if err := request.Validate(now); err != nil { _ = writeFrame(connection, wireReply{ProtocolError: "invalid_request"}); return }
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline); defer cancel()
	if server.Admission==nil{return}
	binding:=rebootcontrol.ExecutionBinding{Boundary:"siteops",Method:string(request.Operation),EffectID:string(request.EffectKey),RequestDigest:request.Digest(),Caller:"authenticated-panel-core",Resource:string(request.RuntimeKey)}
	lease,err:=server.admitSiteExecution(ctx,request,binding);if err!=nil{return}
	if len(lease.Cached)!=0 {
		var cached Response
		if json.Unmarshal(lease.Cached,&cached)==nil { cached.RequestID=request.RequestID;if cached.Validate(request,time.Now().UTC())==nil{_=writeFrame(connection,wireReply{Response:cached})} };return
	}
	defer func(){_=rebootcontrol.SettleExecution(server.Admission,lease,false,nil)}()
	response, err := server.Handler.Execute(ctx, request)
	if err != nil { _ = writeFrame(connection, wireReply{ProtocolError: errorCode(err)}); return }
	if err = response.Validate(request, time.Now().UTC()); err != nil { _ = writeFrame(connection, wireReply{ProtocolError: "invalid_response"}); return }
	if rebootcontrol.SettleExecution(server.Admission,lease,response.Succeeded,response)!=nil{return}
	_ = writeFrame(connection, wireReply{Response: response})
}
