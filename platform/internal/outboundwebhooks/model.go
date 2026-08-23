// Package outboundwebhooks implements tenant-scoped, signed outbound event
// delivery. It intentionally exposes neither an inbound callback surface nor
// a generic HTTP request primitive.
package outboundwebhooks

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid      = errors.New("outboundwebhooks: invalid value")
	ErrNotFound     = errors.New("outboundwebhooks: not found")
	ErrConflict     = errors.New("outboundwebhooks: conflict")
	ErrStale        = errors.New("outboundwebhooks: stale generation")
	ErrUnauthorized = errors.New("outboundwebhooks: unauthorized")
	ErrPolicyDenied = errors.New("outboundwebhooks: policy denied")
	ErrUnavailable  = errors.New("outboundwebhooks: unavailable")
	ErrRateLimited  = errors.New("outboundwebhooks: rate limited")
	ErrIntegrity    = errors.New("outboundwebhooks: integrity failure")
	ErrLeaseLost    = errors.New("outboundwebhooks: lease lost")
)

const (
	SecretPurposeWebhookSigning = "outbound_webhook_signing"
	MaximumEventDataBytes        = 240 << 10
	MaximumEnvelopeBytes         = 256 << 10
	MaximumResponseBytes         = 64 << 10
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var selectorPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,15}$`)
var audiencePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._:/-]{0,255}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type TenantID string
type EndpointID string
type EventID string
type DeliveryID string
type DeduplicationID string
type SecretRef string
type ActorID string
type WorkerID string

func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }
func validDigest(value string) bool { return digestPattern.MatchString(value) }

type SecretBinding struct {
	Purpose         string    `json:"purpose"`
	Reference       SecretRef `json:"reference"`
	Version         uint64    `json:"version"`
	PreviousVersion uint64    `json:"previous_version,omitempty"`
	OverlapUntil    time.Time `json:"overlap_until,omitempty"`
}

func (binding SecretBinding) Validate(updatedAt time.Time) error {
	if binding.Purpose != SecretPurposeWebhookSigning || !validIdentifier(string(binding.Reference)) || binding.Version == 0 {
		return ErrInvalid
	}
	if binding.PreviousVersion == 0 {
		if !binding.OverlapUntil.IsZero() {
			return ErrInvalid
		}
		return nil
	}
	if binding.PreviousVersion == binding.Version || binding.OverlapUntil.IsZero() || !binding.OverlapUntil.After(updatedAt) ||
		binding.OverlapUntil.After(updatedAt.Add(30*24*time.Hour)) {
		return ErrInvalid
	}
	return nil
}

type RatePolicy struct {
	RequestsPerMinute uint32 `json:"requests_per_minute"`
	Burst             uint16 `json:"burst"`
}

func (policy RatePolicy) Validate() error {
	if policy.RequestsPerMinute == 0 || policy.RequestsPerMinute > 6000 || policy.Burst == 0 || uint32(policy.Burst) > policy.RequestsPerMinute {
		return ErrInvalid
	}
	return nil
}

type RetryPolicy struct {
	MaximumAttempts uint16        `json:"maximum_attempts"`
	InitialBackoff  time.Duration `json:"initial_backoff"`
	MaximumBackoff  time.Duration `json:"maximum_backoff"`
}

func (policy RetryPolicy) Validate() error {
	if policy.MaximumAttempts == 0 || policy.MaximumAttempts > 32 || policy.InitialBackoff < time.Second ||
		policy.InitialBackoff > time.Hour || policy.MaximumBackoff < policy.InitialBackoff || policy.MaximumBackoff > 24*time.Hour {
		return ErrInvalid
	}
	return nil
}

type Endpoint struct {
	ID             EndpointID    `json:"id"`
	TenantID       TenantID      `json:"tenant_id"`
	URL            string        `json:"url"`
	Audience       string        `json:"audience"`
	EventSelectors []string      `json:"event_selectors"`
	Enabled        bool          `json:"enabled"`
	Secret         SecretBinding `json:"secret"`
	Rate           RatePolicy    `json:"rate"`
	Retry          RetryPolicy   `json:"retry"`
	Generation     uint64        `json:"generation"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

func (endpoint Endpoint) Validate() error {
	if !validIdentifier(string(endpoint.ID)) || !validIdentifier(string(endpoint.TenantID)) || !audiencePattern.MatchString(endpoint.Audience) ||
		endpoint.Generation == 0 || endpoint.CreatedAt.IsZero() || endpoint.UpdatedAt.IsZero() || endpoint.UpdatedAt.Before(endpoint.CreatedAt) ||
		validateEndpointURL(endpoint.URL) != nil || endpoint.Secret.Validate(endpoint.UpdatedAt) != nil || endpoint.Rate.Validate() != nil || endpoint.Retry.Validate() != nil ||
		len(endpoint.EventSelectors) == 0 || len(endpoint.EventSelectors) > 64 {
		return ErrInvalid
	}
	previous := ""
	for _, selector := range endpoint.EventSelectors {
		if !selectorPattern.MatchString(selector) || selector <= previous {
			return ErrInvalid
		}
		previous = selector
	}
	return nil
}

func (endpoint Endpoint) Selects(eventType string) bool {
	for _, selector := range endpoint.EventSelectors {
		if selector == eventType {
			return true
		}
	}
	return false
}

func validateEndpointURL(raw string) error {
	if len(raw) == 0 || len(raw) > 2048 {
		return ErrInvalid
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() != "" || parsed.Fragment != "" ||
		parsed.RawQuery != "" || parsed.RawPath != "" || net.ParseIP(parsed.Hostname()) != nil {
		return ErrPolicyDenied
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host != parsed.Hostname() || !validWebhookHostname(host) || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return ErrPolicyDenied
	}
	if parsed.Path != "" && (parsed.Path[0] != '/' || path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "\\")) {
		return ErrPolicyDenied
	}
	return nil
}

func validWebhookHostname(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	hasLetter := false
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' {
				hasLetter = true
				continue
			}
			if character < '0' || character > '9' {
				if character != '-' {
					return false
				}
			}
		}
	}
	return hasLetter
}

func validateRotation(previous, next Endpoint, now time.Time) error {
	if previous.ID != next.ID || previous.TenantID != next.TenantID || next.Generation != previous.Generation+1 || next.CreatedAt != previous.CreatedAt ||
		next.UpdatedAt.Before(now.Add(-time.Minute)) || next.UpdatedAt.After(now.Add(time.Minute)) {
		return ErrInvalid
	}
	if previous.Secret.Reference != next.Secret.Reference {
		return ErrPolicyDenied
	}
	if previous.Secret.Version == next.Secret.Version {
		unchanged := next.Secret.PreviousVersion == previous.Secret.PreviousVersion && next.Secret.OverlapUntil == previous.Secret.OverlapUntil
		clearedAfterOverlap := previous.Secret.PreviousVersion != 0 && !previous.Secret.OverlapUntil.After(now) &&
			next.Secret.PreviousVersion == 0 && next.Secret.OverlapUntil.IsZero()
		if !unchanged && !clearedAfterOverlap {
			return ErrPolicyDenied
		}
		return nil
	}
	if previous.Secret.PreviousVersion != 0 && previous.Secret.OverlapUntil.After(now) {
		return ErrPolicyDenied
	}
	if next.Secret.Version <= previous.Secret.Version || next.Secret.PreviousVersion != previous.Secret.Version || !next.Secret.OverlapUntil.After(now) {
		return ErrPolicyDenied
	}
	return nil
}

type Event struct {
	SchemaVersion uint32          `json:"schema_version"`
	ID            EventID         `json:"id"`
	TenantID      TenantID        `json:"tenant_id"`
	Type          string          `json:"type"`
	Subject       string          `json:"subject"`
	OccurredAt    time.Time       `json:"occurred_at"`
	Data          json.RawMessage `json:"data"`
}

func (event Event) Validate(now time.Time) error {
	if event.SchemaVersion != 1 || !validIdentifier(string(event.ID)) || !validIdentifier(string(event.TenantID)) || !selectorPattern.MatchString(event.Type) ||
		!validSubject(event.Subject) || event.OccurredAt.IsZero() || event.OccurredAt.After(now.Add(time.Minute)) || event.OccurredAt.Before(now.Add(-30*24*time.Hour)) ||
		len(event.Data) == 0 || len(event.Data) > MaximumEventDataBytes {
		return ErrInvalid
	}
	return nil
}

func validSubject(subject string) bool {
	return len(subject) > 0 && len(subject) <= 256 && strings.TrimSpace(subject) == subject && !strings.ContainsAny(subject, "\x00\r\n\t")
}

type EventEnvelope struct {
	SchemaVersion   uint32          `json:"schema_version"`
	DeliveryID      DeliveryID      `json:"delivery_id"`
	DeduplicationID DeduplicationID `json:"deduplication_id"`
	EndpointID      EndpointID      `json:"endpoint_id"`
	TenantID        TenantID        `json:"tenant_id"`
	EventID         EventID         `json:"event_id"`
	Type            string          `json:"type"`
	Subject         string          `json:"subject"`
	Audience        string          `json:"audience"`
	OccurredAt      time.Time       `json:"occurred_at"`
	Data            json.RawMessage `json:"data"`
}

func (envelope EventEnvelope) Validate() error {
	if envelope.SchemaVersion != 1 || !validIdentifier(string(envelope.EndpointID)) || !validIdentifier(string(envelope.TenantID)) ||
		!validIdentifier(string(envelope.EventID)) || !validDeliveryID(string(envelope.DeliveryID), "whd_") ||
		!validDeliveryID(string(envelope.DeduplicationID), "whx_") || !selectorPattern.MatchString(envelope.Type) || !validSubject(envelope.Subject) ||
		!audiencePattern.MatchString(envelope.Audience) || envelope.OccurredAt.IsZero() ||
		len(envelope.Data) == 0 || len(envelope.Data) > MaximumEventDataBytes {
		return ErrInvalid
	}
	expectedDeduplicationID := DeduplicationID("whx_" + deterministicDigest("cyberpanel.outbound-webhook.dedup.v1", string(envelope.TenantID), string(envelope.EventID), envelope.Type))
	expectedDeliveryID := DeliveryID("whd_" + deterministicDigest("cyberpanel.outbound-webhook.delivery.v1", string(envelope.EndpointID), string(expectedDeduplicationID)))
	if envelope.DeduplicationID != expectedDeduplicationID || envelope.DeliveryID != expectedDeliveryID {
		return ErrIntegrity
	}
	return nil
}

func validDeliveryID(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && len(value) == len(prefix)+64 && validDigest(strings.TrimPrefix(value, prefix))
}

type PreparedDelivery struct {
	Envelope      EventEnvelope `json:"envelope"`
	CanonicalBody []byte        `json:"canonical_body"`
	BodyDigest    string        `json:"body_digest"`
}

func PrepareDelivery(endpoint Endpoint, event Event, now time.Time) (PreparedDelivery, error) {
	now = now.UTC()
	if endpoint.Validate() != nil || !endpoint.Enabled || event.Validate(now) != nil || endpoint.TenantID != event.TenantID || !endpoint.Selects(event.Type) {
		return PreparedDelivery{}, ErrPolicyDenied
	}
	canonicalData, err := canonicalJSONObject(event.Data)
	if err != nil {
		return PreparedDelivery{}, err
	}
	deduplicationID := DeduplicationID("whx_" + deterministicDigest("cyberpanel.outbound-webhook.dedup.v1", string(event.TenantID), string(event.ID), event.Type))
	deliveryID := DeliveryID("whd_" + deterministicDigest("cyberpanel.outbound-webhook.delivery.v1", string(endpoint.ID), string(deduplicationID)))
	envelope := EventEnvelope{SchemaVersion: 1, DeliveryID: deliveryID, DeduplicationID: deduplicationID, EndpointID: endpoint.ID,
		TenantID: event.TenantID, EventID: event.ID, Type: event.Type, Subject: event.Subject, Audience: endpoint.Audience,
		OccurredAt: event.OccurredAt.UTC(), Data: canonicalData}
	body, err := canonicalEnvelopeBytes(envelope)
	if err != nil || len(body) > MaximumEnvelopeBytes {
		return PreparedDelivery{}, ErrInvalid
	}
	return PreparedDelivery{Envelope: envelope, CanonicalBody: body, BodyDigest: digestBytes(body)}, nil
}

func (delivery PreparedDelivery) Validate() error {
	if delivery.Envelope.Validate() != nil || len(delivery.CanonicalBody) == 0 || len(delivery.CanonicalBody) > MaximumEnvelopeBytes || !validDigest(delivery.BodyDigest) ||
		digestBytes(delivery.CanonicalBody) != delivery.BodyDigest {
		return ErrIntegrity
	}
	canonical, err := canonicalEnvelopeBytes(delivery.Envelope)
	if err != nil || len(canonical) != len(delivery.CanonicalBody) || subtle.ConstantTimeCompare(canonical, delivery.CanonicalBody) != 1 {
		return ErrIntegrity
	}
	return nil
}

func canonicalEnvelopeBytes(envelope EventEnvelope) ([]byte, error) {
	if envelope.Validate() != nil {
		return nil, ErrInvalid
	}
	wire := struct {
		SchemaVersion   uint32          `json:"schema_version"`
		DeliveryID      DeliveryID      `json:"delivery_id"`
		DeduplicationID DeduplicationID `json:"deduplication_id"`
		EndpointID      EndpointID      `json:"endpoint_id"`
		TenantID        TenantID        `json:"tenant_id"`
		EventID         EventID         `json:"event_id"`
		Type            string          `json:"type"`
		Subject         string          `json:"subject"`
		Audience        string          `json:"audience"`
		OccurredAt      string          `json:"occurred_at"`
		Data            json.RawMessage `json:"data"`
	}{envelope.SchemaVersion, envelope.DeliveryID, envelope.DeduplicationID, envelope.EndpointID, envelope.TenantID, envelope.EventID,
		envelope.Type, envelope.Subject, envelope.Audience, envelope.OccurredAt.UTC().Format(time.RFC3339Nano), envelope.Data}
	return json.Marshal(wire)
}

func deterministicDigest(domain string, values ...string) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, domain)
	for _, value := range values {
		hash.Write([]byte{0})
		_, _ = io.WriteString(hash, value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func canonicalJSONObject(raw []byte) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaximumEventDataBytes || raw[0] != '{' {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readCanonicalJSONValue(decoder, 0, new(int))
	if err != nil {
		return nil, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(object)
	if err != nil || len(canonical) > MaximumEventDataBytes {
		return nil, ErrInvalid
	}
	return json.RawMessage(canonical), nil
}

func readCanonicalJSONValue(decoder *json.Decoder, depth int, nodes *int) (any, error) {
	if depth > 32 || *nodes >= 4096 {
		return nil, ErrInvalid
	}
	*nodes = *nodes + 1
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		switch value := token.(type) {
		case nil, bool, string, json.Number:
			if text, ok := value.(string); ok && len(text) > 64<<10 {
				return nil, ErrInvalid
			}
			return value, nil
		default:
			return nil, ErrInvalid
		}
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok || key == "" || len(key) > 512 {
				return nil, ErrInvalid
			}
			if _, duplicate := object[key]; duplicate {
				return nil, ErrInvalid
			}
			child, childErr := readCanonicalJSONValue(decoder, depth+1, nodes)
			if childErr != nil {
				return nil, childErr
			}
			object[key] = child
		}
		if end, endErr := decoder.Token(); endErr != nil || end != json.Delim('}') {
			return nil, ErrInvalid
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			child, childErr := readCanonicalJSONValue(decoder, depth+1, nodes)
			if childErr != nil {
				return nil, childErr
			}
			array = append(array, child)
		}
		if end, endErr := decoder.Token(); endErr != nil || end != json.Delim(']') {
			return nil, ErrInvalid
		}
		return array, nil
	default:
		return nil, ErrInvalid
	}
}

type DeliveryState string

const (
	StatePending    DeliveryState = "pending"
	StateLeased     DeliveryState = "leased"
	StateRetry      DeliveryState = "retry"
	StateSucceeded  DeliveryState = "succeeded"
	StateDeadLetter DeliveryState = "dead_letter"
)

type DeliveryClaim struct {
	Delivery     PreparedDelivery `json:"delivery"`
	Endpoint     Endpoint         `json:"endpoint"`
	State        DeliveryState    `json:"state"`
	Attempt      uint16           `json:"attempt"`
	Generation   uint64           `json:"generation"`
	LeaseOwner   WorkerID         `json:"lease_owner"`
	LeaseToken   string           `json:"lease_token"`
	LeaseUntil   time.Time        `json:"lease_until"`
	NextAttemptAt time.Time       `json:"next_attempt_at"`
}

func (claim DeliveryClaim) Validate(now time.Time) error {
	if claim.Delivery.Validate() != nil || claim.Endpoint.Validate() != nil || claim.Delivery.Envelope.EndpointID != claim.Endpoint.ID ||
		claim.Delivery.Envelope.TenantID != claim.Endpoint.TenantID || claim.State != StateLeased || claim.Attempt == 0 || claim.Generation == 0 ||
		!validIdentifier(string(claim.LeaseOwner)) || !validDigest(claim.LeaseToken) || !claim.LeaseUntil.After(now) {
		return ErrInvalid
	}
	return nil
}

type AttemptOutcome string

const (
	OutcomeDelivered   AttemptOutcome = "delivered"
	OutcomeRetry       AttemptOutcome = "retry"
	OutcomeDeadLetter  AttemptOutcome = "dead_letter"
	OutcomeLeaseExpired AttemptOutcome = "lease_expired"
)

type AttemptReceipt struct {
	DeliveryID    DeliveryID    `json:"delivery_id"`
	Attempt       uint16        `json:"attempt"`
	FenceToken    string        `json:"fence_token"`
	Outcome       AttemptOutcome `json:"outcome"`
	HTTPStatus    int           `json:"http_status,omitempty"`
	Code          string        `json:"code"`
	RetryAfter    time.Duration `json:"retry_after,omitempty"`
	ResponseDigest string       `json:"response_digest,omitempty"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Digest        string        `json:"digest"`
}

func (receipt AttemptReceipt) Validate() error {
	if !validDeliveryID(string(receipt.DeliveryID), "whd_") || receipt.Attempt == 0 || !validDigest(receipt.FenceToken) ||
		receipt.Outcome != OutcomeDelivered && receipt.Outcome != OutcomeRetry && receipt.Outcome != OutcomeDeadLetter && receipt.Outcome != OutcomeLeaseExpired ||
		receipt.Code == "" || len(receipt.Code) > 128 || receipt.StartedAt.IsZero() || receipt.FinishedAt.Before(receipt.StartedAt) ||
		receipt.ResponseDigest != "" && !validDigest(receipt.ResponseDigest) || !validDigest(receipt.Digest) || attemptReceiptDigest(receipt) != receipt.Digest {
		return ErrIntegrity
	}
	return nil
}

func attemptReceiptDigest(receipt AttemptReceipt) string {
	receipt.Digest = ""
	content, _ := json.Marshal(receipt)
	return digestBytes(content)
}

type DeliveryHealth struct {
	TenantID     TenantID  `json:"tenant_id"`
	EndpointID   EndpointID `json:"endpoint_id,omitempty"`
	Pending      uint64    `json:"pending"`
	Leased       uint64    `json:"leased"`
	Retrying     uint64    `json:"retrying"`
	Succeeded    uint64    `json:"succeeded"`
	DeadLetter   uint64    `json:"dead_letter"`
	OldestPending time.Time `json:"oldest_pending,omitempty"`
	State        string    `json:"state"`
	Reason       string    `json:"reason,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}
