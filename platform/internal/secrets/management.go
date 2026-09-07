package secrets

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
	ManagementProtocolVersion uint32 = 1
	ManagementMaximumFrame           = 18 << 20
	ManagementMaximumMaterial        = 16 << 20
)

type ManagementAction string

const (
	ManagementEnroll ManagementAction = "enroll"
	ManagementRotate ManagementAction = "rotate"
	ManagementRevoke ManagementAction = "revoke"
	ManagementProvisionMalwareApproval ManagementAction = "provision_malware_approval"
)

type ManagementRequest struct {
	Version         uint32          `json:"version"`
	RequestID       string          `json:"request_id"`
	Action          ManagementAction `json:"action"`
	SecretID        ID              `json:"secret_id"`
	OwnerTenantID   ID              `json:"owner_tenant_id"`
	Purpose         Purpose         `json:"purpose"`
	Audience        AudienceBinding `json:"audience"`
	ExpectedVersion uint64          `json:"expected_version"`
	ExpectedBindingDigest string    `json:"expected_binding_digest,omitempty"`
	Material        []byte          `json:"material"`
	Deadline        time.Time       `json:"deadline"`
}

func (request ManagementRequest) Validate(now time.Time) error {
	if request.Version != ManagementProtocolVersion || !validManagementRequestID(request.RequestID) || !request.SecretID.Valid() || !request.OwnerTenantID.Valid() || !validPurpose(request.Purpose) || request.Audience.Validate() != nil || len(request.Material) > ManagementMaximumMaterial || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.After(now.Add(2*time.Minute)) {
		return ErrInvalid
	}
	switch request.Action {
	case ManagementProvisionMalwareApproval:
		if request.ExpectedVersion != 0 || request.ExpectedBindingDigest != "" || validateMalwareApprovalProvision(request) != nil {
			return ErrInvalid
		}
	case ManagementEnroll:
		if len(request.Material) == 0 || request.ExpectedVersion != 0 || request.ExpectedBindingDigest != "" {
			return ErrInvalid
		}
	case ManagementRotate:
		if len(request.Material) == 0 || request.ExpectedVersion == 0 || len(request.ExpectedBindingDigest) != 64 {
			return ErrInvalid
		}
	case ManagementRevoke:
		if len(request.Material) != 0 || request.ExpectedVersion == 0 || len(request.ExpectedBindingDigest) != 64 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type ManagementResponse struct {
	Version     uint32   `json:"version"`
	RequestID   string   `json:"request_id"`
	SecretID    ID       `json:"secret_id"`
	Metadata    Metadata `json:"metadata,omitempty"`
	FailureCode string   `json:"failure_code,omitempty"`
	PublicKey   []byte   `json:"public_key,omitempty"`
}

func (response ManagementResponse) Validate(request ManagementRequest) error {
	if response.Version != ManagementProtocolVersion || response.RequestID != request.RequestID || response.SecretID != request.SecretID {
		return ErrInvalid
	}
	if response.FailureCode != "" {
		if response.Metadata.ID != "" || len(response.PublicKey) != 0 || !validMaterialFailure(response.FailureCode) {
			return ErrInvalid
		}
		return nil
	}
	if request.Action == ManagementProvisionMalwareApproval {
		return validateMalwareApprovalProvisionResponse(request, response)
	}
	if len(response.PublicKey) != 0 {
		return ErrInvalid
	}
	expectedVersion := request.ExpectedVersion + 1
	expectedState := StateActive
	if request.Action == ManagementRevoke {
		expectedVersion = request.ExpectedVersion
		expectedState = StateRevoked
	}
	metadataValid := response.Metadata.Validate() == nil
	if !metadataValid || response.Metadata.ID != request.SecretID || response.Metadata.OwnerTenantID != request.OwnerTenantID || response.Metadata.Purpose != request.Purpose || response.Metadata.Version != expectedVersion || response.Metadata.Audience.ResourceID != request.Audience.ResourceID || response.Metadata.BindingDigest == "" || response.Metadata.State != expectedState {
		return ErrInvalid
	}
	return nil
}

type ManagementTransport interface {
	RoundTrip(context.Context, ManagementRequest) (ManagementResponse, error)
}

type ManagementClient struct {
	transport ManagementTransport
	now       func() time.Time
}

type RevokeRequest struct {
	ID                    ID
	OwnerTenantID         ID
	Purpose               Purpose
	Audience              AudienceBinding
	ExpectedVersion       uint64
	ExpectedBindingDigest string
}

func NewManagementClient(transport ManagementTransport) (*ManagementClient, error) {
	if transport == nil {
		return nil, ErrInvalid
	}
	return &ManagementClient{transport: transport, now: time.Now}, nil
}

func (client *ManagementClient) Put(ctx context.Context, request PutRequest) (Metadata, error) {
	if client == nil || client.transport == nil || ctx == nil {
		wipe(request.Plaintext)
		return Metadata{}, ErrInvalid
	}
	material := append([]byte(nil), request.Plaintext...)
	wipe(request.Plaintext)
	defer wipe(material)
	action := ManagementEnroll
	if request.ExpectedVersion > 0 {
		action = ManagementRotate
	}
	identifier := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, identifier); err != nil {
		return Metadata{}, err
	}
	now := client.now().UTC()
	deadline := now.Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value.UTC()
	}
	message := ManagementRequest{
		Version:         ManagementProtocolVersion,
		RequestID:       "mgt-" + hex.EncodeToString(identifier),
		Action:          action,
		SecretID:        request.ID,
		OwnerTenantID:   request.OwnerTenantID,
		Purpose:         request.Purpose,
		Audience:        request.Audience,
		ExpectedVersion: request.ExpectedVersion,
		ExpectedBindingDigest: request.ExpectedBindingDigest,
		Material:        material,
		Deadline:        deadline,
	}
	if err := message.Validate(now); err != nil {
		return Metadata{}, err
	}
	response, err := client.transport.RoundTrip(ctx, message)
	if err != nil {
		return Metadata{}, err
	}
	if err = response.Validate(message); err != nil {
		return Metadata{}, err
	}
	if response.FailureCode != "" {
		return Metadata{}, materialFailure(response.FailureCode)
	}
	return response.Metadata, nil
}

func (client *ManagementClient) Revoke(ctx context.Context, request RevokeRequest) (Metadata, error) {
	if client == nil || client.transport == nil || ctx == nil || request.ExpectedVersion == 0 || len(request.ExpectedBindingDigest) != 64 {
		return Metadata{}, ErrInvalid
	}
	identifier := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, identifier); err != nil {
		return Metadata{}, err
	}
	now := client.now().UTC()
	deadline := now.Add(30 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value.UTC()
	}
	message := ManagementRequest{
		Version:                   ManagementProtocolVersion,
		RequestID:                 "mgt-" + hex.EncodeToString(identifier),
		Action:                    ManagementRevoke,
		SecretID:                  request.ID,
		OwnerTenantID:             request.OwnerTenantID,
		Purpose:                   request.Purpose,
		Audience:                  request.Audience,
		ExpectedVersion:           request.ExpectedVersion,
		ExpectedBindingDigest:     request.ExpectedBindingDigest,
		Deadline:                  deadline,
	}
	if err := message.Validate(now); err != nil {
		return Metadata{}, err
	}
	response, err := client.transport.RoundTrip(ctx, message)
	if err != nil {
		return Metadata{}, err
	}
	if err = response.Validate(message); err != nil {
		return Metadata{}, err
	}
	if response.FailureCode != "" {
		return Metadata{}, materialFailure(response.FailureCode)
	}
	return response.Metadata, nil
}

type ManagementDialer interface {
	DialContext(context.Context) (net.Conn, error)
}

type FramedManagementTransport struct{ Dialer ManagementDialer }

func (transport FramedManagementTransport) RoundTrip(ctx context.Context, request ManagementRequest) (ManagementResponse, error) {
	if transport.Dialer == nil {
		return ManagementResponse{}, ErrInvalid
	}
	connection, err := transport.Dialer.DialContext(ctx)
	if err != nil {
		return ManagementResponse{}, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	deadline := request.Deadline
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err = connection.SetDeadline(deadline); err != nil {
		return ManagementResponse{}, err
	}
	if err = writeManagementFrame(connection, request); err != nil {
		return ManagementResponse{}, err
	}
	var response ManagementResponse
	if err = readManagementFrame(connection, &response); err != nil {
		return ManagementResponse{}, err
	}
	return response, nil
}

type ManagementServer struct {
	Authorizer        MaterialPeerAuthorizer
	Broker            *Broker
	MaximumConcurrent uint32
	Now               func() time.Time
	once              sync.Once
	semaphore         chan struct{}
}

func (server *ManagementServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.Authorizer == nil || server.Broker == nil {
		return ErrInvalid
	}
	server.once.Do(func() {
		maximum := server.MaximumConcurrent
		if maximum == 0 {
			maximum = 8
		}
		if maximum > 64 {
			maximum = 64
		}
		server.semaphore = make(chan struct{}, maximum)
	})
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case server.semaphore <- struct{}{}:
			go func() {
				defer func() { <-server.semaphore; _ = connection.Close() }()
				server.serve(connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (server *ManagementServer) serve(connection net.Conn) {
	peer, err := server.Authorizer.Authorize(connection)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	if server.Now != nil {
		now = server.Now().UTC()
	}
	_ = connection.SetReadDeadline(now.Add(15 * time.Second))
	var request ManagementRequest
	if readManagementFrame(connection, &request) != nil || request.Validate(now) != nil {
		wipe(request.Material)
		_ = writeManagementFrame(connection, ManagementResponse{Version: ManagementProtocolVersion, RequestID: request.RequestID, SecretID: request.SecretID, FailureCode: "invalid_request"})
		return
	}
	defer wipe(request.Material)
	_ = connection.SetDeadline(request.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
	defer cancel()
	response := ManagementResponse{Version: ManagementProtocolVersion, RequestID: request.RequestID, SecretID: request.SecretID}
	var metadata Metadata
	if request.Purpose == PurposeMalwareApproval && peer.UID != 0 {
		err = ErrForbidden
	} else if request.Action == ManagementProvisionMalwareApproval {
		if peer.UID != 0 {
			err = ErrForbidden
		} else {
			metadata, response.PublicKey, err = server.Broker.provisionMalwareApproval(ctx, request)
		}
	} else if request.Action == ManagementRevoke {
		metadata, err = server.Broker.store.Head(ctx, request.SecretID)
		if err == nil && (metadata.OwnerTenantID != request.OwnerTenantID || metadata.Purpose != request.Purpose || metadata.Version != request.ExpectedVersion || metadata.BindingDigest != request.ExpectedBindingDigest || digestJSON(metadata.Audience) != digestJSON(request.Audience)) {
			err = ErrConflict
		}
		if err == nil {
			err = server.Broker.Revoke(ctx, request.SecretID, request.ExpectedVersion, false)
		}
		if err == nil {
			metadata, err = server.Broker.store.Head(ctx, request.SecretID)
		}
	} else {
		metadata, err = server.Broker.Put(ctx, PutRequest{
			ID:              request.SecretID,
			OwnerTenantID:   request.OwnerTenantID,
			Purpose:         request.Purpose,
			Audience:        request.Audience,
			Plaintext:       append([]byte(nil), request.Material...),
			ExpectedVersion: request.ExpectedVersion,
			ExpectedBindingDigest: request.ExpectedBindingDigest,
		})
	}
	if err != nil {
		response.PublicKey = nil
		response.FailureCode = classifyMaterialFailure(err)
	} else {
		response.Metadata = metadata
	}
	_ = writeManagementFrame(connection, response)
}

func validManagementRequestID(value string) bool {
	if len(value) != 36 || len(value) < 4 || value[:4] != "mgt-" {
		return false
	}
	_, err := hex.DecodeString(value[4:])
	return err == nil
}

func writeManagementFrame(writer io.Writer, value any) error {
	content, err := json.Marshal(value)
	defer wipe(content)
	if err != nil || len(content) == 0 || len(content) > ManagementMaximumFrame {
		return ErrInvalid
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(content)))
	if err = writeMaterialBytes(writer, header[:]); err != nil {
		return err
	}
	return writeMaterialBytes(writer, content)
}

func readManagementFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > ManagementMaximumFrame {
		return ErrInvalid
	}
	content := make([]byte, size)
	defer wipe(content)
	if _, err := io.ReadFull(reader, content); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	return nil
}

var _ = errors.Is
