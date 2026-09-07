package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	MaterialProtocolVersion uint32 = 1
	MaterialMaximumFrame           = 1 << 20
	MaterialMaximumBytes           = 16 << 20
)

type MaterialRequest struct {
	Version         uint32    `json:"version"`
	RequestID       string    `json:"request_id"`
	SecretID        ID        `json:"secret_id"`
	OwnerTenantID   ID        `json:"owner_tenant_id"`
	Purpose         Purpose   `json:"purpose"`
	Operation       Operation `json:"operation"`
	AdapterID       string    `json:"adapter_id"`
	AdapterVersion  string    `json:"adapter_version"`
	ResourceID      ID        `json:"resource_id"`
	Deadline        time.Time `json:"deadline"`
}

type MaterialResponse struct {
	Version       uint32 `json:"version"`
	RequestID     string `json:"request_id"`
	SecretID      ID     `json:"secret_id"`
	SecretVersion uint64 `json:"secret_version,omitempty"`
	BindingDigest string `json:"binding_digest,omitempty"`
	Material      []byte `json:"material,omitempty"`
	FailureCode   string `json:"failure_code,omitempty"`
}

func (request MaterialRequest) Validate(now time.Time) error {
	if request.Version != MaterialProtocolVersion || !validMaterialRequestID(request.RequestID) || !request.SecretID.Valid() || !request.OwnerTenantID.Valid() || !request.ResourceID.Valid() || !validPurpose(request.Purpose) || request.AdapterID == "" || request.AdapterVersion == "" || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.After(now.Add(2*time.Minute)) {
		return ErrInvalid
	}
	switch request.Operation {
	case OperationAuthenticate, OperationRead, OperationWrite, OperationSign, OperationEncrypt, OperationDecrypt, OperationRotate:
	default:
		return ErrInvalid
	}
	return nil
}

func (response MaterialResponse) Validate(request MaterialRequest) error {
	if response.Version != MaterialProtocolVersion || response.RequestID != request.RequestID || response.SecretID != request.SecretID {
		return ErrInvalid
	}
	if response.FailureCode != "" {
		if len(response.Material) != 0 || response.SecretVersion != 0 || response.BindingDigest != "" || !validMaterialFailure(response.FailureCode) { return ErrInvalid }
		return nil
	}
	if response.SecretVersion == 0 || len(response.BindingDigest) != 64 || len(response.Material) == 0 || len(response.Material) > MaterialMaximumBytes { return ErrInvalid }
	return nil
}

func validMaterialRequestID(value string) bool {
	if len(value) != 36 || value[:4] != "req-" { return false }
	_, err := hex.DecodeString(value[4:])
	return err == nil
}

func validMaterialFailure(value string) bool {
	switch value {
	case "invalid_request", "not_found", "forbidden", "expired", "revoked", "conflict", "unavailable": return true
	default: return false
	}
}

type MaterialTransport interface{ RoundTrip(context.Context, MaterialRequest) (MaterialResponse, error) }

type MaterialClient struct {
	transport MaterialTransport
	now       func() time.Time
}

func NewMaterialClient(transport MaterialTransport) (*MaterialClient, error) {
	if transport == nil { return nil, ErrInvalid }
	return &MaterialClient{transport: transport, now: time.Now}, nil
}

func (client *MaterialClient) Read(ctx context.Context, request MaterialRequest) (MaterialResponse, error) {
	if client == nil || client.transport == nil || ctx == nil { return MaterialResponse{}, ErrInvalid }
	identifier := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, identifier); err != nil { return MaterialResponse{}, err }
	now := client.now().UTC()
	request.Version = MaterialProtocolVersion
	request.RequestID = "req-" + hex.EncodeToString(identifier)
	request.Deadline = now.Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(request.Deadline) { request.Deadline = deadline.UTC() }
	if err := request.Validate(now); err != nil { return MaterialResponse{}, err }
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil { return MaterialResponse{}, err }
	if err = response.Validate(request); err != nil { wipe(response.Material); return MaterialResponse{}, err }
	if response.FailureCode != "" { return MaterialResponse{}, materialFailure(response.FailureCode) }
	return response, nil
}

type MaterialDialer interface{ DialContext(context.Context) (net.Conn, error) }
type FramedMaterialTransport struct{ Dialer MaterialDialer }

func (transport FramedMaterialTransport) RoundTrip(ctx context.Context, request MaterialRequest) (MaterialResponse, error) {
	if transport.Dialer == nil { return MaterialResponse{}, ErrInvalid }
	connection, err := transport.Dialer.DialContext(ctx)
	if err != nil { return MaterialResponse{}, err }
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	deadline := request.Deadline
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) { deadline = value }
	if err = connection.SetDeadline(deadline); err != nil { return MaterialResponse{}, err }
	if err = writeMaterialFrame(connection, request); err != nil { return MaterialResponse{}, err }
	var response MaterialResponse
	if err = readMaterialFrame(connection, &response); err != nil { return MaterialResponse{}, err }
	return response, nil
}

type VerifiedPeer struct {
	UID          uint32
	PID          uint32
	ProcessStart uint64
	ExecutableDigest string
}

type MaterialPeerAuthorizer interface{ Authorize(net.Conn) (VerifiedPeer, error) }

type MaterialServer struct {
	Authorizer MaterialPeerAuthorizer
	Broker     *Broker
	MaximumConcurrent uint32
	Now        func() time.Time
	once       sync.Once
	semaphore  chan struct{}
}

func (server *MaterialServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.Authorizer == nil || server.Broker == nil { return ErrInvalid }
	server.once.Do(func() { maximum := server.MaximumConcurrent; if maximum == 0 { maximum = 64 }; if maximum > 1024 { maximum = 1024 }; server.semaphore = make(chan struct{}, maximum) })
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

func (server *MaterialServer) serve(connection net.Conn) {
	peer, err := server.Authorizer.Authorize(connection)
	if err != nil { return }
	now := time.Now().UTC(); if server.Now != nil { now = server.Now().UTC() }
	_ = connection.SetReadDeadline(now.Add(15*time.Second))
	var request MaterialRequest
	if readMaterialFrame(connection, &request) != nil || request.Validate(now) != nil {
		_ = writeMaterialFrame(connection, MaterialResponse{Version:MaterialProtocolVersion,RequestID:request.RequestID,SecretID:request.SecretID,FailureCode:"invalid_request"})
		return
	}
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline); defer cancel()
	response := MaterialResponse{Version:MaterialProtocolVersion,RequestID:request.RequestID,SecretID:request.SecretID}
	head, err := server.Broker.store.Head(ctx, request.SecretID)
	if err == nil && (head.OwnerTenantID != request.OwnerTenantID || head.Purpose != request.Purpose || head.Audience.ResourceID != request.ResourceID || head.Audience.AdapterID != request.AdapterID || head.Audience.AdapterVersion != request.AdapterVersion) { err = ErrForbidden }
	if err == nil {
		consumerID, parseErr := NewID("consumer_" + request.RequestID[4:])
		if parseErr != nil { err = parseErr } else {
			consumer := ConsumerIdentity{ID:consumerID,PID:peer.PID,ProcessStart:peer.ProcessStart,ExecutableDigest:peer.ExecutableDigest,ReleaseDigest:peer.ExecutableDigest,TenantID:request.OwnerTenantID,AdapterID:request.AdapterID,AdapterVersion:request.AdapterVersion}
			grantID, _ := NewID("grant_" + request.RequestID[4:])
			requestDigest := sha256.Sum256([]byte("cyberpanel:secret-material:v1\x00"+request.RequestID+"\x00"+request.SecretID.String()))
			grant, grantErr := server.Broker.Grant(ctx, GrantRequest{ID:grantID,SecretID:request.SecretID,TenantID:request.OwnerTenantID,Version:head.Version,Operation:request.Operation,Consumer:consumer,RequestDigest:hex.EncodeToString(requestDigest[:]),TTL:time.Until(request.Deadline)})
			if grantErr != nil { err = grantErr } else {
				reader, metadata, deliveryErr := server.Broker.Deliver(ctx, grant.ID)
				if deliveryErr != nil { err = deliveryErr } else {
					material, readErr := io.ReadAll(io.LimitReader(reader, MaterialMaximumBytes+1)); closeErr := reader.Close()
					if readErr != nil || closeErr != nil || len(material) == 0 || len(material) > MaterialMaximumBytes { wipe(material); err = ErrInvalid } else { response.SecretVersion=metadata.Version;response.BindingDigest=metadata.BindingDigest;response.Material=material }
				}
			}
		}
	}
	if err != nil { response.FailureCode=classifyMaterialFailure(err);response.SecretVersion=0;response.BindingDigest="";wipe(response.Material);response.Material=nil }
	_ = writeMaterialFrame(connection,response)
	wipe(response.Material)
}

func writeMaterialFrame(writer io.Writer, value any) error {
	content, err := json.Marshal(value); defer wipe(content); if err != nil || len(content)==0 || len(content)>MaterialMaximumFrame{return ErrInvalid}
	var header [4]byte; binary.BigEndian.PutUint32(header[:],uint32(len(content)))
	if err=writeMaterialBytes(writer,header[:]);err!=nil{return err};return writeMaterialBytes(writer,content)
}
func writeMaterialBytes(writer io.Writer, content []byte) error { for len(content)>0{written,err:=writer.Write(content);if err!=nil{return err};if written<=0||written>len(content){return io.ErrShortWrite};content=content[written:]};return nil }
func readMaterialFrame(reader io.Reader,target any)error{var header [4]byte;if _,err:=io.ReadFull(reader,header[:]);err!=nil{return err};size:=binary.BigEndian.Uint32(header[:]);if size==0||size>MaterialMaximumFrame{return ErrInvalid};content:=make([]byte,size);defer wipe(content);if _,err:=io.ReadFull(reader,content);err!=nil{return err};decoder:=json.NewDecoder(bytes.NewReader(content));decoder.DisallowUnknownFields();if err:=decoder.Decode(target);err!=nil{return ErrInvalid};if decoder.Decode(&struct{}{})!=io.EOF{return ErrInvalid};return nil}
func classifyMaterialFailure(err error)string{switch{case errors.Is(err,ErrNotFound):return "not_found";case errors.Is(err,ErrForbidden):return "forbidden";case errors.Is(err,ErrExpired):return "expired";case errors.Is(err,ErrRevoked):return "revoked";case errors.Is(err,ErrConflict),errors.Is(err,ErrRollback):return "conflict";case errors.Is(err,ErrInvalid):return "invalid_request";default:return "unavailable"}}
func materialFailure(code string)error{switch code{case "invalid_request":return ErrInvalid;case "not_found":return ErrNotFound;case "forbidden":return ErrForbidden;case "expired":return ErrExpired;case "revoked":return ErrRevoked;case "conflict":return ErrConflict;default:return errors.New("secret material broker unavailable")}}
