package webactivation

import (
	"context"
	"errors"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/controller"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

// Client is the unprivileged controller adapter. Apply deliberately rejects
// native generations so production callers can only cross this boundary via
// ApplyVerified with typed desired state and an independently rendered digest.
type Client struct {
	transport Transport
	now func() time.Time
}

var _ controller.Activator = (*Client)(nil)
var _ controller.VerifiedActivator = (*Client)(nil)

func NewClient(transport Transport) (*Client, error) {
	if transport == nil { return nil, errors.New("web-engine activation transport is required") }
	return &Client{transport: transport}, nil
}

func (client *Client) Apply(context.Context, native.ConfigGeneration) (activation.Receipt, error) {
	return activation.Receipt{Status: activation.Ambiguous}, errors.New("native generations cannot cross the privileged activation boundary")
}

func (client *Client) ApplyVerified(ctx context.Context, render native.RenderRequest, expectedDigest string) (activation.Receipt, error) {
	if client == nil || client.transport == nil || ctx == nil {
		return activation.Receipt{Status: activation.Ambiguous}, ErrInvalidRequest
	}
	now := time.Now().UTC()
	if client.now != nil { now = client.now().UTC() }
	request, err := NewRequest(render, expectedDigest, now)
	if err != nil { return activation.Receipt{Status: activation.Ambiguous}, err }
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil { return activation.Receipt{Status: activation.Ambiguous, CandidateDigest: expectedDigest}, err }
	completed := time.Now().UTC()
	if client.now != nil { completed = client.now().UTC() }
	if err = response.Validate(request, completed); err != nil {
		return activation.Receipt{Status: activation.Ambiguous, CandidateDigest: expectedDigest}, err
	}
	return response.Receipt, errorForCode(response.ErrorCode)
}
