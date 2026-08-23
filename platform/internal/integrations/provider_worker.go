package integrations

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
	"time"
)

const (
	ProviderWorkerProtocolVersion uint32 = 1
	ProviderWorkerMaximumFrame          = 1 << 20
)

type ProviderWorkerAction string

const (
	ProviderWorkerDiscover ProviderWorkerAction = "discover"
	ProviderWorkerHealth   ProviderWorkerAction = "health"
	ProviderWorkerValidate ProviderWorkerAction = "validate_credential"
	ProviderWorkerRevoke   ProviderWorkerAction = "revoke_credential"
)

type ProviderWorkerRequest struct {
	Version   uint32               `json:"version"`
	RequestID string               `json:"request_id"`
	Action    ProviderWorkerAction `json:"action"`
	Binding   ProviderBinding      `json:"binding"`
	Deadline  time.Time            `json:"deadline"`
	Cloudflare *ProviderWorkerCloudflareRequest `json:"cloudflare,omitempty"`
}

func (request ProviderWorkerRequest) Validate(now time.Time) error {
	if request.Version != ProviderWorkerProtocolVersion || !validID(request.RequestID) || request.Binding.Validate() != nil || request.Deadline.IsZero() || !request.Deadline.After(now) || request.Deadline.After(now.Add(2*time.Minute)) {
		return ErrInvalid
	}
	switch request.Action {
	case ProviderWorkerDiscover, ProviderWorkerHealth, ProviderWorkerValidate, ProviderWorkerRevoke:
		if request.Cloudflare != nil {
			return ErrInvalid
		}
		return nil
	default:
		if !providerWorkerCloudflareAction(request.Action) {
			return ErrUnsupported
		}
		if request.Binding.Kind != ProviderCloudflare || request.Binding.Purpose != PurposeDNS || request.Binding.State != BindingActive || request.Cloudflare == nil {
			return ErrPolicyDenied
		}
		return request.Cloudflare.Validate(request.Action, request.Binding, now)
	}
}

type ProviderWorkerResponse struct {
	Version      uint32         `json:"version"`
	RequestID    string         `json:"request_id"`
	Action       ProviderWorkerAction `json:"action"`
	Capabilities *CapabilitySet `json:"capabilities,omitempty"`
	Health       *ProviderHealth `json:"health,omitempty"`
	Cloudflare   *ProviderWorkerCloudflareResponse `json:"cloudflare,omitempty"`
	Succeeded    bool           `json:"succeeded"`
	Failure      ErrorClass     `json:"failure,omitempty"`
	FailureCode  string         `json:"failure_code,omitempty"`
}

type ProviderWorkerTransport interface {
	RoundTrip(context.Context, ProviderWorkerRequest) (ProviderWorkerResponse, error)
}

type ProviderWorkerClient struct {
	Transport ProviderWorkerTransport
	Kind      ProviderKind
	Now       func() time.Time
}

func (client *ProviderWorkerClient) request(ctx context.Context, action ProviderWorkerAction, binding ProviderBinding) (ProviderWorkerResponse, error) {
	return client.requestCloudflare(ctx, action, binding, nil)
}

func (client *ProviderWorkerClient) requestCloudflare(ctx context.Context, action ProviderWorkerAction, binding ProviderBinding, payload *ProviderWorkerCloudflareRequest) (ProviderWorkerResponse, error) {
	if client == nil || client.Transport == nil || ctx == nil || binding.Kind != client.Kind {
		return ProviderWorkerResponse{}, ErrInvalid
	}
	now := time.Now().UTC()
	if client.Now != nil {
		now = client.Now().UTC()
	}
	deadline := now.Add(30*time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value.UTC()
	}
	sum := sha256.Sum256([]byte(string(action)+"\x00"+string(binding.ID)+"\x00"+hex.EncodeToString([]byte(now.Format(time.RFC3339Nano)))))
	request := ProviderWorkerRequest{Version:ProviderWorkerProtocolVersion,RequestID:"provider_"+hex.EncodeToString(sum[:])[:48],Action:action,Binding:binding,Deadline:deadline,Cloudflare:payload}
	if err := request.Validate(now); err != nil {
		return ProviderWorkerResponse{}, err
	}
	response, err := client.Transport.RoundTrip(ctx, request)
	if err != nil {
		return ProviderWorkerResponse{}, err
	}
	if response.ValidateFor(request) != nil {
		return ProviderWorkerResponse{}, ErrIntegrity
	}
	if !response.Succeeded {
		return ProviderWorkerResponse{}, providerWorkerFailure(action, response)
	}
	return response, nil
}

func (client *ProviderWorkerClient) DiscoverCapabilities(ctx context.Context, binding ProviderBinding) (CapabilitySet, error) {
	response, err := client.request(ctx, ProviderWorkerDiscover, binding)
	if err != nil || response.Capabilities == nil || response.Health != nil {
		return CapabilitySet{}, errors.Join(err, ErrIntegrity)
	}
	return *response.Capabilities, response.Capabilities.Validate()
}

func (client *ProviderWorkerClient) Health(ctx context.Context, binding ProviderBinding) (ProviderHealth, error) {
	response, err := client.request(ctx, ProviderWorkerHealth, binding)
	if err != nil || response.Health == nil || response.Capabilities != nil {
		return ProviderHealth{}, errors.Join(err, ErrIntegrity)
	}
	return *response.Health, nil
}

func (client *ProviderWorkerClient) ValidateCredential(ctx context.Context, binding ProviderBinding) error {
	response, err := client.request(ctx, ProviderWorkerValidate, binding)
	if err == nil && (response.Health != nil || response.Capabilities != nil) {
		return ErrIntegrity
	}
	return err
}

func (client *ProviderWorkerClient) RevokeCredential(ctx context.Context, binding ProviderBinding) error {
	response, err := client.request(ctx, ProviderWorkerRevoke, binding)
	if err == nil && (response.Health != nil || response.Capabilities != nil) {
		return ErrIntegrity
	}
	return err
}

func providerWorkerFailure(action ProviderWorkerAction, response ProviderWorkerResponse) error {
	if response.Failure == "" || response.FailureCode == "" {
		return ErrIntegrity
	}
	providerError := &ProviderError{Class:response.Failure,Operation:string(action),Code:response.FailureCode}
	if response.FailureCode == "unsupported" {
		return errors.Join(ErrUnsupported, providerError)
	}
	return providerError
}

func writeProviderWorkerFrame(writer io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > ProviderWorkerMaximumFrame {
		return ErrInvalid
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if err = writeProviderWorkerBytes(writer, header[:]); err != nil {
		return err
	}
	return writeProviderWorkerBytes(writer, raw)
}

func readProviderWorkerFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > ProviderWorkerMaximumFrame {
		return ErrInvalid
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func writeProviderWorkerBytes(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

type ProviderWorkerDialer interface { DialContext(context.Context) (net.Conn, error) }

type FramedProviderWorkerTransport struct{ Dialer ProviderWorkerDialer }

func (transport FramedProviderWorkerTransport) RoundTrip(ctx context.Context, request ProviderWorkerRequest) (ProviderWorkerResponse, error) {
	if transport.Dialer == nil || ctx == nil {
		return ProviderWorkerResponse{}, ErrInvalid
	}
	if err := request.Validate(time.Now().UTC()); err != nil {
		return ProviderWorkerResponse{}, err
	}
	connection, err := transport.Dialer.DialContext(ctx)
	if err != nil {
		return ProviderWorkerResponse{}, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func(){ _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if err = connection.SetDeadline(request.Deadline); err != nil {
		return ProviderWorkerResponse{}, err
	}
	if err = writeProviderWorkerFrame(connection, request); err != nil {
		return ProviderWorkerResponse{}, err
	}
	var response ProviderWorkerResponse
	if err = readProviderWorkerFrame(connection, &response); err != nil {
		return ProviderWorkerResponse{}, err
	}
	if err = response.ValidateFor(request); err != nil {
		return ProviderWorkerResponse{}, ErrIntegrity
	}
	return response, nil
}

var _ Provider = (*ProviderWorkerClient)(nil)
