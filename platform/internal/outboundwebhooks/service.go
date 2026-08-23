package outboundwebhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

type AuthorizationAction string

const (
	AuthorizeEndpointWrite AuthorizationAction = "endpoint.write"
	AuthorizeEndpointRead  AuthorizationAction = "endpoint.read"
	AuthorizeEventEnqueue  AuthorizationAction = "event.enqueue"
	AuthorizeDeliverySend  AuthorizationAction = "delivery.send"
	AuthorizeHealthRead    AuthorizationAction = "health.read"
)

type AuthorizationRequest struct {
	Actor      ActorID
	TenantID   TenantID
	EndpointID EndpointID
	Action     AuthorizationAction
}

func (request AuthorizationRequest) Validate() error {
	if !validIdentifier(string(request.Actor)) || !validIdentifier(string(request.TenantID)) ||
		request.EndpointID != "" && !validIdentifier(string(request.EndpointID)) {
		return ErrInvalid
	}
	switch request.Action {
	case AuthorizeEndpointWrite, AuthorizeEndpointRead, AuthorizeEventEnqueue, AuthorizeDeliverySend, AuthorizeHealthRead:
		return nil
	default:
		return ErrInvalid
	}
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) error
}

type AuditRecord struct {
	Actor         ActorID             `json:"actor"`
	TenantID      TenantID            `json:"tenant_id"`
	EndpointID    EndpointID          `json:"endpoint_id,omitempty"`
	Action        string              `json:"action"`
	ResourceID    string              `json:"resource_id"`
	Generation    uint64              `json:"generation,omitempty"`
	Outcome       string              `json:"outcome"`
	ReceiptDigest string              `json:"receipt_digest,omitempty"`
	OccurredAt    time.Time           `json:"occurred_at"`
	Digest        string              `json:"digest"`
}

func (record AuditRecord) Validate() error {
	if !validIdentifier(string(record.Actor)) || !validIdentifier(string(record.TenantID)) ||
		record.EndpointID != "" && !validIdentifier(string(record.EndpointID)) || record.Action == "" || len(record.Action) > 128 ||
		record.ResourceID == "" || len(record.ResourceID) > 256 || record.Outcome == "" || record.OccurredAt.IsZero() ||
		record.ReceiptDigest != "" && !validDigest(record.ReceiptDigest) || !validDigest(record.Digest) || auditRecordDigest(record) != record.Digest {
		return ErrIntegrity
	}
	return nil
}

func auditRecordDigest(record AuditRecord) string {
	record.Digest = ""
	content, _ := json.Marshal(record)
	return digestBytes(content)
}

type AuditSink interface {
	RecordOutboundWebhook(context.Context, AuditRecord) error
}

type SecretRequest struct {
	TenantID TenantID
	Reference SecretRef
	Version   uint64
	Purpose   string
}

func (request SecretRequest) Validate() error {
	if !validIdentifier(string(request.TenantID)) || !validIdentifier(string(request.Reference)) || request.Version == 0 ||
		request.Purpose != SecretPurposeWebhookSigning {
		return ErrInvalid
	}
	return nil
}

type SecretMaterial struct {
	Value   []byte
	Cleanup func()
}

func (material SecretMaterial) Validate() error {
	if len(material.Value) < 32 || len(material.Value) > 4096 || material.Cleanup == nil {
		return ErrInvalid
	}
	return nil
}

type SecretResolver interface {
	ResolveWebhookSecret(context.Context, SecretRequest) (SecretMaterial, error)
}

type SendResult struct {
	Delivered      bool
	Retryable      bool
	HTTPStatus     int
	Code           string
	RetryAfter     time.Duration
	ResponseDigest string
	StartedAt      time.Time
	FinishedAt     time.Time
}

func (result SendResult) Validate() error {
	if result.Delivered && result.Retryable || result.Code == "" || len(result.Code) > 128 || result.RetryAfter < 0 || result.RetryAfter > 24*time.Hour ||
		result.ResponseDigest != "" && !validDigest(result.ResponseDigest) || result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) ||
		result.Delivered && (result.HTTPStatus < 200 || result.HTTPStatus > 299) {
		return ErrInvalid
	}
	return nil
}

type SignedDelivery struct {
	Body                []byte
	BodyDigest          string
	DeliveryID          DeliveryID
	DeduplicationID     DeduplicationID
	Audience            string
	SignatureVersion    string
	SecretVersion       uint64
	Timestamp           int64
	Signature           string
}

func (delivery SignedDelivery) Validate(now time.Time) error {
	if len(delivery.Body) == 0 || len(delivery.Body) > MaximumEnvelopeBytes || digestBytes(delivery.Body) != delivery.BodyDigest ||
		!validDeliveryID(string(delivery.DeliveryID), "whd_") || !validDeliveryID(string(delivery.DeduplicationID), "whx_") ||
		!audiencePattern.MatchString(delivery.Audience) || delivery.SignatureVersion != "v1" || delivery.SecretVersion == 0 ||
		delivery.Timestamp < now.Add(-5*time.Minute).Unix() || delivery.Timestamp > now.Add(time.Minute).Unix() || !validDigest(delivery.Signature) {
		return ErrInvalid
	}
	return nil
}

type DeliverySender interface {
	Send(context.Context, Endpoint, SignedDelivery) (SendResult, error)
}

type Repository interface {
	Bootstrap(context.Context) error
	PutEndpoint(context.Context, Endpoint, uint64) error
	LoadEndpoint(context.Context, TenantID, EndpointID) (Endpoint, error)
	Enqueue(context.Context, PreparedDelivery, time.Time) (bool, error)
	Claim(context.Context, WorkerID, time.Time, time.Duration) (DeliveryClaim, error)
	Finalize(context.Context, DeliveryClaim, SendResult, time.Time) (AttemptReceipt, error)
	Health(context.Context, TenantID, EndpointID, time.Time) (DeliveryHealth, error)
}

type Service struct {
	repository Repository
	authorizer Authorizer
	audit      AuditSink
	now        func() time.Time
}

func NewService(repository Repository, authorizer Authorizer, audit AuditSink, now func() time.Time) (*Service, error) {
	if repository == nil || authorizer == nil || audit == nil {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &Service{repository: repository, authorizer: authorizer, audit: audit, now: now}, nil
}

func (service *Service) Bootstrap(ctx context.Context) error { return service.repository.Bootstrap(ctx) }

func (service *Service) PutEndpoint(ctx context.Context, actor ActorID, endpoint Endpoint, expectedGeneration uint64) error {
	now := service.now().UTC()
	request := AuthorizationRequest{Actor: actor, TenantID: endpoint.TenantID, EndpointID: endpoint.ID, Action: AuthorizeEndpointWrite}
	if request.Validate() != nil || endpoint.Validate() != nil || endpoint.Generation != expectedGeneration+1 || endpoint.Generation == 0 {
		return ErrInvalid
	}
	if err := service.authorizer.Authorize(ctx, request); err != nil {
		return errors.Join(ErrUnauthorized, err)
	}
	if expectedGeneration == 0 {
		if endpoint.Generation != 1 || endpoint.Secret.PreviousVersion != 0 || endpoint.CreatedAt.Before(now.Add(-time.Minute)) || endpoint.CreatedAt.After(now.Add(time.Minute)) ||
			endpoint.UpdatedAt.Before(now.Add(-time.Minute)) || endpoint.UpdatedAt.After(now.Add(time.Minute)) {
			return ErrInvalid
		}
	} else {
		current, err := service.repository.LoadEndpoint(ctx, endpoint.TenantID, endpoint.ID)
		if err != nil {
			return err
		}
		if current.Generation != expectedGeneration {
			return ErrStale
		}
		if err := validateRotation(current, endpoint, now); err != nil {
			return err
		}
	}
	if err := service.repository.PutEndpoint(ctx, endpoint, expectedGeneration); err != nil {
		return err
	}
	return service.recordAudit(ctx, AuditRecord{Actor: actor, TenantID: endpoint.TenantID, EndpointID: endpoint.ID, Action: "endpoint.put",
		ResourceID: string(endpoint.ID), Generation: endpoint.Generation, Outcome: "applied", OccurredAt: now})
}

func (service *Service) InspectEndpoint(ctx context.Context, actor ActorID, tenantID TenantID, endpointID EndpointID) (Endpoint, error) {
	request := AuthorizationRequest{Actor: actor, TenantID: tenantID, EndpointID: endpointID, Action: AuthorizeEndpointRead}
	if request.Validate() != nil {
		return Endpoint{}, ErrInvalid
	}
	if err := service.authorizer.Authorize(ctx, request); err != nil {
		return Endpoint{}, errors.Join(ErrUnauthorized, err)
	}
	return service.repository.LoadEndpoint(ctx, tenantID, endpointID)
}

func (service *Service) Enqueue(ctx context.Context, actor ActorID, endpointID EndpointID, event Event) (PreparedDelivery, bool, error) {
	now := service.now().UTC()
	request := AuthorizationRequest{Actor: actor, TenantID: event.TenantID, EndpointID: endpointID, Action: AuthorizeEventEnqueue}
	if request.Validate() != nil || event.Validate(now) != nil {
		return PreparedDelivery{}, false, ErrInvalid
	}
	if err := service.authorizer.Authorize(ctx, request); err != nil {
		return PreparedDelivery{}, false, errors.Join(ErrUnauthorized, err)
	}
	endpoint, err := service.repository.LoadEndpoint(ctx, event.TenantID, endpointID)
	if err != nil {
		return PreparedDelivery{}, false, err
	}
	delivery, err := PrepareDelivery(endpoint, event, now)
	if err != nil {
		return PreparedDelivery{}, false, err
	}
	inserted, err := service.repository.Enqueue(ctx, delivery, now)
	if err != nil {
		return PreparedDelivery{}, false, err
	}
	outcome := "enqueued"
	if !inserted {
		outcome = "deduplicated"
	}
	if err := service.recordAudit(ctx, AuditRecord{Actor: actor, TenantID: event.TenantID, EndpointID: endpointID, Action: "delivery.enqueue",
		ResourceID: string(delivery.Envelope.DeliveryID), Outcome: outcome, OccurredAt: now}); err != nil {
		return delivery, inserted, err
	}
	return delivery, inserted, nil
}

func (service *Service) Health(ctx context.Context, actor ActorID, tenantID TenantID, endpointID EndpointID) (DeliveryHealth, error) {
	request := AuthorizationRequest{Actor: actor, TenantID: tenantID, EndpointID: endpointID, Action: AuthorizeHealthRead}
	if request.Validate() != nil {
		return DeliveryHealth{}, ErrInvalid
	}
	if err := service.authorizer.Authorize(ctx, request); err != nil {
		return DeliveryHealth{}, errors.Join(ErrUnauthorized, err)
	}
	return service.repository.Health(ctx, tenantID, endpointID, service.now().UTC())
}

func (service *Service) recordAudit(ctx context.Context, record AuditRecord) error {
	record.Digest = auditRecordDigest(record)
	if record.Validate() != nil {
		return ErrIntegrity
	}
	return service.audit.RecordOutboundWebhook(ctx, record)
}

type Dispatcher struct {
	repository Repository
	secrets    SecretResolver
	authorizer Authorizer
	audit      AuditSink
	sender     DeliverySender
	now        func() time.Time
	lease      time.Duration
}

func NewDispatcher(repository Repository, secrets SecretResolver, authorizer Authorizer, audit AuditSink, sender DeliverySender, lease time.Duration, now func() time.Time) (*Dispatcher, error) {
	if repository == nil || secrets == nil || authorizer == nil || audit == nil || sender == nil || lease < 5*time.Second || lease > 5*time.Minute {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &Dispatcher{repository: repository, secrets: secrets, authorizer: authorizer, audit: audit, sender: sender, now: now, lease: lease}, nil
}

func (dispatcher *Dispatcher) DispatchOne(ctx context.Context, worker WorkerID) (AttemptReceipt, error) {
	started := dispatcher.now().UTC()
	if !validIdentifier(string(worker)) {
		return AttemptReceipt{}, ErrInvalid
	}
	claim, err := dispatcher.repository.Claim(ctx, worker, started, dispatcher.lease)
	if err != nil {
		return AttemptReceipt{}, err
	}
	request := AuthorizationRequest{Actor: ActorID(worker), TenantID: claim.Endpoint.TenantID, EndpointID: claim.Endpoint.ID, Action: AuthorizeDeliverySend}
	if request.Validate() != nil {
		return dispatcher.finalizeFailure(ctx, claim, "invalid_authorization_context", false, started, ErrIntegrity)
	}
	if err := dispatcher.authorizer.Authorize(ctx, request); err != nil {
		retryable := retryableError(err)
		code := "authorization_denied"
		if retryable {
			code = "authorization_unavailable"
		}
		return dispatcher.finalizeFailure(ctx, claim, code, retryable, started, errors.Join(ErrUnauthorized, err))
	}
	secretRequest := SecretRequest{TenantID: claim.Endpoint.TenantID, Reference: claim.Endpoint.Secret.Reference,
		Version: claim.Endpoint.Secret.Version, Purpose: SecretPurposeWebhookSigning}
	if secretRequest.Validate() != nil {
		return dispatcher.finalizeFailure(ctx, claim, "invalid_secret_request", false, started, ErrIntegrity)
	}
	secret, err := dispatcher.secrets.ResolveWebhookSecret(ctx, secretRequest)
	if err != nil {
		return dispatcher.finalizeFailure(ctx, claim, "secret_unavailable", retryableError(err), started, err)
	}
	if secret.Validate() != nil {
		wipe(secret.Value)
		if secret.Cleanup != nil {
			secret.Cleanup()
		}
		return dispatcher.finalizeFailure(ctx, claim, "invalid_secret_material", false, started, ErrIntegrity)
	}
	defer func() {
		wipe(secret.Value)
		secret.Cleanup()
	}()
	signed, err := SignDelivery(claim.Endpoint, claim.Delivery, secret.Value, started)
	if err != nil {
		return dispatcher.finalizeFailure(ctx, claim, "signing_failed", false, started, err)
	}
	result, sendErr := dispatcher.sender.Send(ctx, claim.Endpoint, signed)
	if result.Validate() != nil {
		result = SendResult{Code: "invalid_sender_result", Retryable: true, StartedAt: started, FinishedAt: dispatcher.now().UTC()}
		sendErr = errors.Join(sendErr, ErrIntegrity)
	}
	receipt, finalizeErr := dispatcher.repository.Finalize(ctx, claim, result, dispatcher.now().UTC())
	if finalizeErr != nil {
		return AttemptReceipt{}, errors.Join(sendErr, finalizeErr)
	}
	auditErr := dispatcher.recordDispatchAudit(ctx, worker, claim, receipt)
	return receipt, errors.Join(sendErr, auditErr)
}

func (dispatcher *Dispatcher) finalizeFailure(ctx context.Context, claim DeliveryClaim, code string, retryable bool, started time.Time, cause error) (AttemptReceipt, error) {
	result := SendResult{Code: code, Retryable: retryable, StartedAt: started, FinishedAt: dispatcher.now().UTC()}
	receipt, err := dispatcher.repository.Finalize(ctx, claim, result, dispatcher.now().UTC())
	if err != nil {
		return AttemptReceipt{}, errors.Join(cause, err)
	}
	auditErr := dispatcher.recordDispatchAudit(ctx, claim.LeaseOwner, claim, receipt)
	return receipt, errors.Join(cause, auditErr)
}

func (dispatcher *Dispatcher) recordDispatchAudit(ctx context.Context, worker WorkerID, claim DeliveryClaim, receipt AttemptReceipt) error {
	record := AuditRecord{Actor: ActorID(worker), TenantID: claim.Endpoint.TenantID, EndpointID: claim.Endpoint.ID, Action: "delivery.attempt",
		ResourceID: string(claim.Delivery.Envelope.DeliveryID), Generation: claim.Generation, Outcome: string(receipt.Outcome), ReceiptDigest: receipt.Digest,
		OccurredAt: receipt.FinishedAt}
	record.Digest = auditRecordDigest(record)
	if record.Validate() != nil {
		return ErrIntegrity
	}
	return dispatcher.audit.RecordOutboundWebhook(ctx, record)
}

func SignDelivery(endpoint Endpoint, delivery PreparedDelivery, key []byte, now time.Time) (SignedDelivery, error) {
	if endpoint.Validate() != nil || delivery.Validate() != nil || delivery.Envelope.EndpointID != endpoint.ID || delivery.Envelope.Audience != endpoint.Audience ||
		len(key) < 32 || len(key) > 4096 || now.IsZero() {
		return SignedDelivery{}, ErrInvalid
	}
	timestamp := now.UTC().Unix()
	canonical := strings.Join([]string{"v1", strconv.FormatUint(endpoint.Secret.Version, 10), strconv.FormatInt(timestamp, 10), endpoint.Audience,
		delivery.BodyDigest, string(delivery.Envelope.DeliveryID), string(delivery.Envelope.DeduplicationID)}, "\n")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))
	return SignedDelivery{Body: append([]byte(nil), delivery.CanonicalBody...), BodyDigest: delivery.BodyDigest, DeliveryID: delivery.Envelope.DeliveryID,
		DeduplicationID: delivery.Envelope.DeduplicationID, Audience: endpoint.Audience, SignatureVersion: "v1", SecretVersion: endpoint.Secret.Version,
		Timestamp: timestamp, Signature: signature}, nil
}

func VerifyDeliverySignature(delivery SignedDelivery, key []byte, now time.Time) error {
	if delivery.Validate(now) != nil || len(key) < 32 || len(key) > 4096 {
		return ErrInvalid
	}
	canonical := strings.Join([]string{delivery.SignatureVersion, strconv.FormatUint(delivery.SecretVersion, 10), strconv.FormatInt(delivery.Timestamp, 10), delivery.Audience,
		delivery.BodyDigest, string(delivery.DeliveryID), string(delivery.DeduplicationID)}, "\n")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(canonical))
	expected := mac.Sum(nil)
	provided, err := hex.DecodeString(delivery.Signature)
	if err != nil || len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
		return ErrUnauthorized
	}
	return nil
}

type retryable interface{ Retryable() bool }

func retryableError(err error) bool {
	var classified retryable
	if errors.As(err, &classified) {
		return classified.Retryable()
	}
	return !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrPolicyDenied) && !errors.Is(err, ErrIntegrity)
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
