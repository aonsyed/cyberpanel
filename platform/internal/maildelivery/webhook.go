package maildelivery

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
)

type WebhookKeyAlgorithm string

const (
	WebhookHMACSHA256V1 WebhookKeyAlgorithm = "hmac-sha256-v1"
	WebhookEd25519V1    WebhookKeyAlgorithm = "ed25519-v1"
)

type WebhookKeyRequest struct {
	TenantID TenantID
	BindingID BindingID
	DomainID DomainID
	KeyID string
	KeyVersion uint64
	Algorithm WebhookKeyAlgorithm
}

type WebhookVerificationKey struct {
	TenantID TenantID
	BindingID BindingID
	DomainID DomainID
	KeyID string
	Version uint64
	Algorithm WebhookKeyAlgorithm
	Material []byte
	NotBefore time.Time
	NotAfter time.Time
	Cleanup func()
}

func (key WebhookVerificationKey) Validate(request WebhookKeyRequest, at time.Time) error {
	if key.TenantID != request.TenantID || key.BindingID != request.BindingID || key.DomainID != request.DomainID ||
		key.KeyID != request.KeyID || key.Version != request.KeyVersion || key.Algorithm != request.Algorithm ||
		key.NotBefore.IsZero() || key.NotAfter.IsZero() || at.Before(key.NotBefore) || !at.Before(key.NotAfter) || key.Cleanup == nil {
		return ErrInvalid
	}
	if key.Algorithm == WebhookHMACSHA256V1 && (len(key.Material) < 32 || len(key.Material) > 4096) {
		return ErrInvalid
	}
	if key.Algorithm == WebhookEd25519V1 && len(key.Material) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	return nil
}

type WebhookKeyResolver interface {
	ResolveMailDeliveryWebhookKey(context.Context, WebhookKeyRequest) (WebhookVerificationKey, error)
}

type WebhookReplayStore interface {
	ClaimWebhookReplay(context.Context, TenantID, BindingID, DeliveryID, time.Time, time.Time, uint32) error
}

type SignedProviderWebhook struct {
	TenantID TenantID
	BindingID BindingID
	DomainID DomainID
	DeliveryID DeliveryID
	Audience string
	SchemaVersion uint32
	Timestamp int64
	KeyID string
	KeyVersion uint64
	Algorithm WebhookKeyAlgorithm
	Signature string
	Body io.Reader
	ReceivedAt time.Time
}

type ProviderWebhookEnvelope struct {
	SchemaVersion uint32 `json:"schema_version"`
	TenantID TenantID `json:"tenant_id"`
	BindingID BindingID `json:"binding_id"`
	DomainID DomainID `json:"domain_id"`
	DeliveryID DeliveryID `json:"delivery_id"`
	Audience string `json:"audience"`
	ProviderEventID string `json:"provider_event_id"`
	OccurredAt time.Time `json:"occurred_at"`
	Data json.RawMessage `json:"data"`
}

type VerifiedProviderWebhook struct {
	Envelope ProviderWebhookEnvelope
	Raw RawProviderEvent
	PayloadDigest string
	ReceivedAt time.Time
	clear func()
}

func (verified *VerifiedProviderWebhook) Clear() {
	if verified == nil || verified.clear == nil {
		return
	}
	verified.clear()
	verified.clear = nil
	verified.Raw.Body = nil
}

type WebhookVerifier struct {
	Keys WebhookKeyResolver
	Replay WebhookReplayStore
	Audience string
	AcceptedSchemaVersions map[uint32]struct{}
	MaximumBodyBytes int64
	ReplayWindow time.Duration
	FutureSkew time.Duration
	MaximumReplayEntries uint32
	Now func() time.Time
}

func (verifier WebhookVerifier) Verify(ctx context.Context, request SignedProviderWebhook) (VerifiedProviderWebhook, error) {
	rejected := func(body []byte) (VerifiedProviderWebhook, error) {
		clearBytes(body)
		return VerifiedProviderWebhook{}, ErrWebhookRejected
	}
	maximum := verifier.MaximumBodyBytes
	if maximum == 0 {
		maximum = MaximumWebhookBodyBytes
	}
	window := verifier.ReplayWindow
	if window == 0 {
		window = 5 * time.Minute
	}
	futureSkew := verifier.FutureSkew
	if futureSkew == 0 {
		futureSkew = time.Minute
	}
	maximumEntries := verifier.MaximumReplayEntries
	if maximumEntries == 0 {
		maximumEntries = 100000
	}
	if verifier.Keys == nil || verifier.Replay == nil || verifier.Audience == "" || len(verifier.Audience) > 256 ||
		len(verifier.AcceptedSchemaVersions) == 0 || maximum <= 0 || maximum > MaximumWebhookBodyBytes ||
		window < time.Minute || window > 24*time.Hour || futureSkew < 0 || futureSkew > 5*time.Minute ||
		request.Body == nil || !validID(string(request.TenantID)) || !validID(string(request.BindingID)) ||
		!validID(string(request.DomainID)) || !validID(string(request.DeliveryID)) || request.Audience != verifier.Audience ||
		request.Timestamp <= 0 || !validID(request.KeyID) || request.KeyVersion == 0 || request.Signature == "" {
		return rejected(nil)
	}
	if request.Algorithm != WebhookHMACSHA256V1 && request.Algorithm != WebhookEd25519V1 {
		return rejected(nil)
	}
	if _, accepted := verifier.AcceptedSchemaVersions[request.SchemaVersion]; !accepted {
		return rejected(nil)
	}
	now := verifier.Now
	if now == nil {
		now = time.Now
	}
	receivedAt := now().UTC()
	if receivedAt.IsZero() || !request.ReceivedAt.IsZero() && (request.ReceivedAt.Before(receivedAt.Add(-time.Minute)) || request.ReceivedAt.After(receivedAt.Add(time.Minute))) {
		return rejected(nil)
	}
	signedAt := time.Unix(request.Timestamp, 0).UTC()
	if signedAt.Before(receivedAt.Add(-window)) || signedAt.After(receivedAt.Add(futureSkew)) {
		return rejected(nil)
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximum+1))
	if err != nil || int64(len(body)) == 0 || int64(len(body)) > maximum {
		return rejected(body)
	}
	payloadHash := sha256.Sum256(body)
	payloadDigest := hex.EncodeToString(payloadHash[:])
	keyRequest := WebhookKeyRequest{TenantID: request.TenantID, BindingID: request.BindingID, DomainID: request.DomainID,
		KeyID: request.KeyID, KeyVersion: request.KeyVersion, Algorithm: request.Algorithm}
	key, err := verifier.Keys.ResolveMailDeliveryWebhookKey(ctx, keyRequest)
	if err != nil || key.Validate(keyRequest, signedAt) != nil {
		if key.Cleanup != nil {
			key.Cleanup()
		}
		clearBytes(key.Material)
		return rejected(body)
	}
	defer key.Cleanup()
	defer clearBytes(key.Material)
	canonical, err := json.Marshal(struct {
		Version string `json:"version"`
		Timestamp int64 `json:"timestamp"`
		Audience string `json:"audience"`
		DeliveryID DeliveryID `json:"delivery_id"`
		SchemaVersion uint32 `json:"schema_version"`
		TenantID TenantID `json:"tenant_id"`
		BindingID BindingID `json:"binding_id"`
		DomainID DomainID `json:"domain_id"`
		PayloadDigest string `json:"payload_digest"`
	}{Version: string(request.Algorithm), Timestamp: request.Timestamp, Audience: request.Audience, DeliveryID: request.DeliveryID,
		SchemaVersion: request.SchemaVersion, TenantID: request.TenantID, BindingID: request.BindingID, DomainID: request.DomainID, PayloadDigest: payloadDigest})
	if err != nil || !verifyWebhookSignature(request.Algorithm, key.Material, canonical, request.Signature) {
		return rejected(body)
	}
	var envelope ProviderWebhookEnvelope
	if decodeStrict(body, &envelope) != nil || envelope.SchemaVersion != request.SchemaVersion || envelope.TenantID != request.TenantID ||
		envelope.BindingID != request.BindingID || envelope.DomainID != request.DomainID || envelope.DeliveryID != request.DeliveryID ||
		envelope.Audience != request.Audience || !validID(envelope.ProviderEventID) || envelope.OccurredAt.IsZero() ||
		len(envelope.Data) == 0 || len(envelope.Data) > MaximumWebhookBodyBytes {
		return rejected(body)
	}
	if err = verifier.Replay.ClaimWebhookReplay(ctx, request.TenantID, request.BindingID, request.DeliveryID, receivedAt, receivedAt.Add(window), maximumEntries); err != nil {
		return rejected(body)
	}
	verified := VerifiedProviderWebhook{Envelope: envelope, PayloadDigest: payloadDigest, ReceivedAt: receivedAt,
		Raw: RawProviderEvent{BindingID: request.BindingID, TenantID: request.TenantID, DomainID: request.DomainID,
			DeliveryID: request.DeliveryID, SchemaVersion: request.SchemaVersion, ReceivedAt: receivedAt, PayloadDigest: payloadDigest, Body: body}}
	verified.clear = func() { clearBytes(body) }
	return verified, nil
}

func verifyWebhookSignature(algorithm WebhookKeyAlgorithm, key, message []byte, encoded string) bool {
	signature, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	switch algorithm {
	case WebhookHMACSHA256V1:
		if len(signature) != sha256.Size {
			return false
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(message)
		expected := mac.Sum(nil)
		valid := subtle.ConstantTimeCompare(signature, expected) == 1
		clearBytes(expected)
		return valid
	case WebhookEd25519V1:
		return len(signature) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(key), message, signature)
	default:
		return false
	}
}

func IngestProviderWebhook(ctx context.Context, verifier WebhookVerifier, adapter ProviderAdapterV1, repository Repository, request SignedProviderWebhook) (NormalizedProviderEvent, error) {
	if adapter == nil || repository == nil {
		return NormalizedProviderEvent{}, ErrWebhookRejected
	}
	verified, err := verifier.Verify(ctx, request)
	if err != nil {
		return NormalizedProviderEvent{}, ErrWebhookRejected
	}
	defer verified.Clear()
	event, err := adapter.NormalizeEvent(ctx, verified.Raw)
	if err != nil || event.Validate() != nil || event.SchemaVersion != 1 || event.ProviderEventID != verified.Envelope.ProviderEventID ||
		event.DeliveryID != verified.Envelope.DeliveryID || event.TenantID != verified.Envelope.TenantID ||
		event.BindingID != verified.Envelope.BindingID || event.DomainID != verified.Envelope.DomainID || event.PayloadDigest != verified.PayloadDigest ||
		event.OccurredAt != verified.Envelope.OccurredAt || event.ReceivedAt != verified.ReceivedAt {
		return NormalizedProviderEvent{}, ErrWebhookRejected
	}
	if err = repository.AppendProviderEvent(ctx, event); err != nil {
		return NormalizedProviderEvent{}, ErrWebhookRejected
	}
	return event, nil
}

func clearBytes(content []byte) {
	for index := range content {
		content[index] = 0
	}
}
