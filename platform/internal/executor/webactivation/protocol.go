// Package webactivation implements the closed local protocol used to ask the
// root executor to verify and activate a complete web-engine desired state.
package webactivation

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
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

const (
	ProtocolVersion   uint16 = 1
	DefaultSocketPath        = "/run/cyberpanel/webengine-activation.sock"
	MaximumFrameBytes        = 4 << 20
	maximumListeners         = 256
	maximumApplications      = 4096
	maximumBindings          = 4096
	maximumAccessPolicies    = 4096
	maximumRuntimeEntries    = 4096
)

var (
	ErrInvalidRequest  = errors.New("invalid web-engine activation request")
	ErrInvalidResponse = errors.New("invalid web-engine activation response")
	ErrDigestMismatch  = errors.New("web-engine activation digest mismatch")
	ErrEditionMismatch = errors.New("web-engine activation edition mismatch")
	ErrOutcomeUnknown  = errors.New("web-engine activation outcome is unknown")
	ErrRejected        = errors.New("web-engine activation was rejected")
	ErrUnauthorized    = errors.New("unauthorized web-engine activation peer")
)

type Request struct {
	Version        uint16               `json:"version"`
	EffectID       string               `json:"effect_id"`
	ExpectedDigest string               `json:"expected_digest"`
	Render         native.RenderRequest `json:"render"`
	IssuedAt       time.Time            `json:"issued_at"`
	Deadline       time.Time            `json:"deadline"`
}

func NewRequest(render native.RenderRequest, expectedDigest string, now time.Time) (Request, error) {
	request := Request{
		Version: ProtocolVersion, ExpectedDigest: expectedDigest, Render: render,
		IssuedAt: now.UTC(), Deadline: now.UTC().Add(2 * time.Minute),
	}
	request.EffectID = effectIdentity(expectedDigest)
	if err := request.Validate(now.UTC()); err != nil {
		return Request{}, err
	}
	return request, nil
}

func (request Request) Validate(now time.Time) error {
	if request.Version != ProtocolVersion || !validDigest(request.ExpectedDigest) || request.EffectID != effectIdentity(request.ExpectedDigest) {
		return ErrInvalidRequest
	}
	if request.IssuedAt.IsZero() || request.Deadline.IsZero() || request.IssuedAt.After(now.Add(time.Minute)) || request.IssuedAt.Before(now.Add(-10*time.Minute)) || !request.Deadline.After(now) || request.Deadline.After(now.Add(3*time.Minute)) {
		return ErrInvalidRequest
	}
	if len(request.Render.Desired.Engine.Listeners) == 0 || len(request.Render.Desired.Engine.Listeners) > maximumListeners || len(request.Render.Desired.Applications) == 0 || len(request.Render.Desired.Applications) > maximumApplications || len(request.Render.Desired.Bindings) == 0 || len(request.Render.Desired.Bindings) > maximumBindings || len(request.Render.Desired.AccessPolicies) > maximumAccessPolicies {
		return ErrInvalidRequest
	}
	if len(request.Render.Snapshot.Sites) == 0 || len(request.Render.Snapshot.Sites) > maximumRuntimeEntries || len(request.Render.Snapshot.LSAPIPools) > maximumRuntimeEntries || len(request.Render.Snapshot.TLSMaterials) > maximumRuntimeEntries || len(request.Render.Snapshot.AccessVerifiers) > maximumRuntimeEntries {
		return ErrInvalidRequest
	}
	if err := native.ValidateRequest(request.Render, request.Render.Desired.Engine.Edition); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

func (request Request) Digest() string {
	canonical := request
	canonical.IssuedAt = time.Time{}
	canonical.Deadline = time.Time{}
	encoded, _ := json.Marshal(canonical)
	digest := sha256.Sum256(append([]byte("cyberpanel:webactivation:request:v1\x00"), encoded...))
	return hex.EncodeToString(digest[:])
}

type Response struct {
	Version        uint16             `json:"version"`
	EffectID       string             `json:"effect_id"`
	ExpectedDigest string             `json:"expected_digest"`
	Receipt        activation.Receipt `json:"receipt"`
	ErrorCode      string             `json:"error_code,omitempty"`
	CompletedAt    time.Time          `json:"completed_at"`
}

func (response Response) Validate(request Request, now time.Time) error {
	if response.Version != ProtocolVersion || response.EffectID != request.EffectID || response.ExpectedDigest != request.ExpectedDigest || response.CompletedAt.IsZero() || response.CompletedAt.After(now.Add(time.Minute)) {
		return ErrInvalidResponse
	}
	if !validReceipt(response.Receipt, request.ExpectedDigest) || !validErrorCode(response.ErrorCode) {
		return ErrInvalidResponse
	}
	if response.Receipt.Status == activation.Applied {
		if response.ErrorCode != "" || response.Receipt.Digest != request.ExpectedDigest || !response.Receipt.Confirmed {
			return ErrInvalidResponse
		}
	} else if response.ErrorCode == "" {
		return ErrInvalidResponse
	}
	return nil
}

func validReceipt(receipt activation.Receipt, expected string) bool {
	switch receipt.Status {
	case activation.Applied:
		return validEdition(receipt.Edition) && validDigest(receipt.Digest) && receipt.Digest == expected && receipt.CandidateDigest == expected && receipt.Confirmed
	case activation.RolledBack:
		return validEdition(receipt.Edition) && validDigest(receipt.Digest) && receipt.CandidateDigest == expected && validDigest(receipt.PreviousDigest) && receipt.RollbackRestored && receipt.RollbackReloaded && receipt.PreviousProbed && !receipt.Confirmed
	case activation.Ambiguous:
		return receipt.Digest == "" && !receipt.Confirmed && (receipt.CandidateDigest == "" || receipt.CandidateDigest == expected) && (receipt.PreviousDigest == "" || validDigest(receipt.PreviousDigest))
	default:
		return false
	}
}

func validEdition(edition webengine.Edition) bool {
	return edition == webengine.EditionOpenLiteSpeed || edition == webengine.EditionLiteSpeedEnterprise
}

func validDigest(value string) bool {
	return len(value) == sha256.Size*2 && strings.Trim(value, "0123456789abcdef") == ""
}

func validErrorCode(value string) bool {
	switch value {
	case "", "digest_mismatch", "edition_mismatch", "activation_rejected", "outcome_unknown", "invalid_request", "internal_error":
		return true
	default:
		return false
	}
}

func effectIdentity(expectedDigest string) string {
	digest := sha256.Sum256([]byte("cyberpanel:webactivation:effect:v1\x00" + expectedDigest))
	return "wa-" + hex.EncodeToString(digest[:])
}

func errorForCode(code string) error {
	switch code {
	case "": return nil
	case "digest_mismatch": return ErrDigestMismatch
	case "edition_mismatch": return ErrEditionMismatch
	case "activation_rejected": return ErrRejected
	case "outcome_unknown": return ErrOutcomeUnknown
	case "invalid_request": return ErrInvalidRequest
	default: return ErrOutcomeUnknown
	}
}

type Transport interface {
	RoundTrip(context.Context, Request) (Response, error)
}

type ConnectionDialer interface {
	DialContext(context.Context) (net.Conn, error)
}

type FramedTransport struct { Dialer ConnectionDialer }

func (transport FramedTransport) RoundTrip(ctx context.Context, request Request) (Response, error) {
	if transport.Dialer == nil || ctx == nil { return Response{}, ErrInvalidRequest }
	connection, err := transport.Dialer.DialContext(ctx)
	if err != nil { return Response{}, err }
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	deadline := request.Deadline
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) { deadline = contextDeadline }
	if err = connection.SetDeadline(deadline); err != nil { return Response{}, err }
	if err = writeFrame(connection, request); err != nil { return Response{}, err }
	var response Response
	if err = readFrame(connection, &response); err != nil { return Response{}, err }
	return response, nil
}

func writeFrame(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > MaximumFrameBytes { return ErrInvalidRequest }
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
	if err = writeAll(writer, header[:]); err != nil { return err }
	return writeAll(writer, encoded)
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) != 0 {
		written, err := writer.Write(content)
		if err != nil { return err }
		if written <= 0 || written > len(content) { return io.ErrShortWrite }
		content = content[written:]
	}
	return nil
}

func readFrame(reader io.Reader, target any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil { return err }
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaximumFrameBytes { return ErrInvalidRequest }
	content := make([]byte, size)
	if _, err := io.ReadFull(reader, content); err != nil { return err }
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return ErrInvalidRequest }
	if decoder.Decode(&struct{}{}) != io.EOF { return ErrInvalidRequest }
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(content, canonical) { return ErrInvalidRequest }
	return nil
}
