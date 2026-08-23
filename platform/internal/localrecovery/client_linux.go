//go:build linux

package localrecovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"time"
)

type Client struct {
	proofs ProofProvider
	now    func() time.Time
}

func NewClient(proofs ProofProvider) (*Client, error) {
	if nilInterface(proofs) {
		return nil, ErrInvalid
	}
	return &Client{proofs: proofs}, nil
}

func (client *Client) WithClock(now func() time.Time) *Client {
	if client != nil && now != nil {
		client.now = now
	}
	return client
}

func (client *Client) Status(ctx context.Context, reason string) (RecoveryStatus, error) {
	request, err := client.newRequest(ctx, ActionStatus, reason, 0, "", "")
	if err != nil {
		return RecoveryStatus{}, err
	}
	response, err := client.authorizedRoundTrip(ctx, request)
	if err != nil {
		return RecoveryStatus{}, err
	}
	if response.Status == nil {
		return RecoveryStatus{}, ErrInvalid
	}
	return *response.Status, nil
}

func (client *Client) ResetOwnerPasswordCredentialRef(ctx context.Context, reason string, credentialRef CredentialReference, expectedGeneration uint64) (RecoveryReceipt, error) {
	request, err := client.newRequest(ctx, ActionResetOwnerPassword, reason, expectedGeneration, credentialRef, "")
	if err != nil {
		return RecoveryReceipt{}, err
	}
	return client.mutation(ctx, request)
}

func (client *Client) ResetOwnerMFA(ctx context.Context, reason string, expectedGeneration uint64) (RecoveryReceipt, error) {
	request, err := client.newRequest(ctx, ActionResetOwnerMFA, reason, expectedGeneration, "", "")
	if err != nil {
		return RecoveryReceipt{}, err
	}
	return client.mutation(ctx, request)
}

func (client *Client) RevokeOwnerSessionsAndAPICredentials(ctx context.Context, reason string, expectedGeneration uint64) (RecoveryReceipt, error) {
	request, err := client.newRequest(ctx, ActionRevokeOwnerAccess, reason, expectedGeneration, "", "")
	if err != nil {
		return RecoveryReceipt{}, err
	}
	return client.mutation(ctx, request)
}

func (client *Client) RotateRecoveryAuthority(ctx context.Context, reason string, authorityRef AuthorityReference, expectedGeneration uint64) (RecoveryReceipt, error) {
	request, err := client.newRequest(ctx, ActionRotateRecoveryAuthority, reason, expectedGeneration, "", authorityRef)
	if err != nil {
		return RecoveryReceipt{}, err
	}
	return client.mutation(ctx, request)
}

func (client *Client) mutation(ctx context.Context, request Request) (RecoveryReceipt, error) {
	response, err := client.authorizedRoundTrip(ctx, request)
	if err != nil {
		return RecoveryReceipt{}, err
	}
	if response.Receipt == nil {
		return RecoveryReceipt{}, ErrInvalid
	}
	return *response.Receipt, nil
}

func (client *Client) newRequest(ctx context.Context, action Action, reason string, expectedGeneration uint64, credentialRef CredentialReference, authorityRef AuthorityReference) (Request, error) {
	if client == nil || nilInterface(client.proofs) || nilInterface(ctx) {
		return Request{}, ErrInvalid
	}
	now := client.currentTime()
	deadline := now.Add(MaximumRequestLifetime)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline.UTC()
	}
	requestID, err := newRequestID()
	if err != nil {
		return Request{}, err
	}
	host, err := readHostIdentity()
	if err != nil {
		return Request{}, err
	}
	request := Request{
		Version: ProtocolVersion, RequestID: requestID, Action: action, Deadline: deadline,
		Reason: reason, Host: host, ExpectedGeneration: expectedGeneration,
		CredentialRef: credentialRef, RecoveryAuthorityRef: authorityRef,
	}
	request.RequestDigest = request.digest()
	if request.validateProtectedIntent(now) != nil {
		return Request{}, ErrInvalid
	}
	return request, nil
}

func (client *Client) authorizedRoundTrip(ctx context.Context, request Request) (Response, error) {
	binding := request.binding()
	beginID, err := newRequestID()
	if err != nil {
		return Response{}, err
	}
	begin := Request{Version: ProtocolVersion, RequestID: beginID, Action: ActionBeginChallenge, Deadline: request.Deadline, Binding: &binding}
	if begin.Validate(client.currentTime()) != nil {
		return Response{}, ErrInvalid
	}
	challengeResponse, err := client.roundTrip(ctx, begin)
	if err != nil {
		return Response{}, err
	}
	if challengeResponse.Challenge == nil {
		return Response{}, ErrInvalid
	}
	challenge := *challengeResponse.Challenge
	defer wipeBytes(challenge.Nonce)
	if challenge.Validate(binding, client.currentTime()) != nil {
		return Response{}, ErrAuthorityDenied
	}
	providerChallenge := challenge
	providerChallenge.Nonce = append([]byte(nil), challenge.Nonce...)
	defer wipeBytes(providerChallenge.Nonce)
	proof, err := client.proofs.Prove(ctx, binding, providerChallenge)
	if err != nil {
		wipeBytes(proof)
		return Response{}, ErrAuthorityDenied
	}
	defer wipeBytes(proof)
	request.Authorization = &Authorization{
		ChallengeID: challenge.ID,
		Nonce: append([]byte(nil), challenge.Nonce...),
		Proof: append([]byte(nil), proof...),
	}
	defer wipeBytes(request.Authorization.Nonce)
	defer wipeBytes(request.Authorization.Proof)
	if request.Validate(client.currentTime()) != nil {
		return Response{}, ErrInvalid
	}
	return client.roundTrip(ctx, request)
}

func (client *Client) roundTrip(ctx context.Context, request Request) (Response, error) {
	if request.Validate(client.currentTime()) != nil {
		return Response{}, ErrInvalid
	}
	if os.Geteuid() != 0 || inspectSocketPath() != nil {
		return Response{}, ErrUnauthorized
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", DefaultSocketPath)
	if err != nil {
		return Response{}, err
	}
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || rootPeer(unixConnection) != nil {
		return Response{}, ErrUnauthorized
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stopCancellation()
	deadline := request.Deadline
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err = connection.SetDeadline(deadline); err != nil {
		return Response{}, err
	}
	if err = writeFrame(connection, request); err != nil {
		return Response{}, err
	}
	var response Response
	if err = readFrame(connection, &response); err != nil {
		return Response{}, err
	}
	if err = response.Validate(request, client.currentTime()); err != nil {
		if response.Challenge != nil {
			wipeBytes(response.Challenge.Nonce)
		}
		return Response{}, err
	}
	if !response.Succeeded {
		return Response{}, responseError(response.ErrorCode)
	}
	return response, nil
}

func responseError(code ErrorCode) error {
	switch code {
	case ErrorInvalidRequest:
		return ErrInvalid
	case ErrorUnauthorized:
		return ErrUnauthorized
	case ErrorRateLimited:
		return ErrRateLimited
	case ErrorAuthorityDenied:
		return ErrAuthorityDenied
	case ErrorAuditUnavailable:
		return ErrAuditUnavailable
	case ErrorConflict:
		return ErrConflict
	case ErrorDeadlineExceeded:
		return context.DeadlineExceeded
	case ErrorRecoveryFailed:
		return ErrRecoveryFailed
	default:
		return ErrInvalid
	}
}

func (client *Client) currentTime() time.Time {
	if client != nil && client.now != nil {
		return client.now().UTC()
	}
	return time.Now().UTC()
}

func newRequestID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return "lrr-" + hex.EncodeToString(value[:]), nil
}
