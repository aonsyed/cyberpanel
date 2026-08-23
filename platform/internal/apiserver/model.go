package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

const (
	APIVersion = "panel.cyberpanel.io/v1"
	InternalProtocolVersion = "panel-core.cyberpanel.io/v1"
	ContentTypeJSON = "application/json"
	ContentTypeProblem = "application/problem+json"
	DefaultMaximumBodyBytes int64 = 2 << 20
	AbsoluteMaximumBodyBytes int64 = 16 << 20
	DefaultMaximumResponseBytes int64 = 8 << 20
)

var requestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,127}$`)
var idempotencyPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{15,191}$`)
var operationPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}(\.[a-z][a-z0-9_]{1,31}){1,4}$`)
var keyIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,62}$`)

type AuthMode string
const (
	AuthNone AuthMode = "none"
	AuthRequired AuthMode = "required"
)

type CredentialKind string
const (
	CredentialSession CredentialKind = "session"
	CredentialAPIKey CredentialKind = "api_key"
)

type AuthMaterial struct {
	Kind CredentialKind `json:"kind"`
	SessionID string `json:"session_id,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
	CSRFToken string `json:"csrf_token,omitempty"`
	APIKey string `json:"api_key,omitempty"`
}

func (material AuthMaterial) Validate() error {
	switch material.Kind {
	case CredentialSession:
		if material.SessionID == "" || material.SessionToken == "" || material.APIKey != "" || len(material.SessionID)>96 || len(material.SessionToken)>8192 || len(material.CSRFToken)>8192 || strings.ContainsAny(material.SessionID+material.SessionToken+material.CSRFToken,"\r\n\t ") { return invalid("session credential") }
	case CredentialAPIKey:
		if material.APIKey == "" || material.SessionID != "" || material.SessionToken != "" || material.CSRFToken != "" || len(material.APIKey)>4096 || strings.ContainsAny(material.APIKey,"\r\n\t ") { return invalid("api key credential") }
	default:
		return invalid("credential kind")
	}
	return nil
}

type RequestEnvelope struct {
	APIVersion string `json:"api_version"`
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	TenantID string `json:"tenant_id,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
	ExpectedGeneration uint64 `json:"expected_generation,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

func (request RequestEnvelope) Validate() error {
	if request.APIVersion != APIVersion { return invalid("api_version") }
	if !requestIDPattern.MatchString(request.RequestID) { return invalid("request_id") }
	if !operationPattern.MatchString(request.Operation) { return invalid("operation") }
	if request.TenantID != "" { if _, err := identity.NewID(request.TenantID); err != nil { return invalid("tenant_id") } }
	if request.ResourceID != "" && (len(request.ResourceID) > 128 || strings.ContainsAny(request.ResourceID, "\x00\r\n\t /\\")) { return invalid("resource_id") }
	if len(request.Payload) == 0 || string(request.Payload) == "null" { request.Payload = json.RawMessage(`{}`) }
	return nil
}

type ResponseEnvelope struct {
	APIVersion string `json:"api_version"`
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	Result json.RawMessage `json:"result"`
	Generation uint64 `json:"generation,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}

type RequestMeta struct {
	ClientIP netip.Addr `json:"client_ip"`
	UserAgentDigest string `json:"user_agent_digest"`
	Origin string `json:"origin,omitempty"`
	Host string `json:"host"`
	TLS bool `json:"tls"`
	ForwardedBy string `json:"forwarded_by,omitempty"`
}

func (meta RequestMeta) Validate() error {
	if !meta.ClientIP.IsValid() || len(meta.UserAgentDigest) != sha256.Size*2 || meta.Host == "" || len(meta.Host) > 255 { return invalid("request metadata") }
	if _, err := hex.DecodeString(meta.UserAgentDigest); err != nil { return invalid("user_agent_digest") }
	return nil
}

type Actor struct {
	PrincipalID identity.ID
	CredentialID identity.ID
	SessionID identity.ID
	AuthzEpoch uint64
	Assurance identity.AssuranceLevel
	CredentialKind CredentialKind
}

func (actor Actor) IdentityContext() identity.ActorContext {
	return identity.ActorContext{PrincipalID: actor.PrincipalID, CredentialID: actor.CredentialID, SessionID: actor.SessionID, AuthzEpoch: actor.AuthzEpoch, Assurance: actor.Assurance}
}

type Invocation struct {
	Actor Actor
	Request RequestEnvelope
	IdempotencyKey string
	Meta RequestMeta
}

type OperationResult struct {
	Status int
	Value any
	Generation uint64
	Headers map[string]string
	Session *SessionDelivery
	ClearSession bool
}

type SessionDelivery struct {
	SessionID string `json:"session_id"`
	SessionToken string `json:"session_token"`
	CSRFToken string `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (delivery SessionDelivery) Validate() error {
	if _, err := identity.NewID(delivery.SessionID); err != nil || delivery.ExpiresAt.IsZero() { return invalid("session delivery") }
	session,err:=decodeCredential(delivery.SessionToken);if err!=nil{return invalid("session delivery")};clearSecret(session)
	csrf,err:=decodeCredential(delivery.CSRFToken);if err!=nil{return invalid("session delivery")};clearSecret(csrf)
	return nil
}

type CoreRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Request RequestEnvelope `json:"request"`
	Auth *AuthMaterial `json:"auth,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Meta RequestMeta `json:"meta"`
	SentAt time.Time `json:"sent_at"`
	Nonce string `json:"nonce"`
	KeyID string `json:"key_id"`
	Signature string `json:"signature"`
}

type CoreResponse struct {
	ProtocolVersion string `json:"protocol_version"`
	Status int `json:"status"`
	Envelope *ResponseEnvelope `json:"response,omitempty"`
	Problem *Problem `json:"problem,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Session *SessionDelivery `json:"session,omitempty"`
	ClearSession bool `json:"clear_session,omitempty"`
}

type CoreCatalog struct {
	ProtocolVersion string `json:"protocol_version"`
	APIVersion string `json:"api_version"`
	Operations []operationDescription `json:"operations"`
}

func (request CoreRequest) Validate(now time.Time) error {
	if request.ProtocolVersion != InternalProtocolVersion || request.Request.Validate() != nil || request.Meta.Validate() != nil || !keyIDPattern.MatchString(request.KeyID) || !idempotencyPattern.MatchString(request.Nonce) { return invalid("internal request") }
	if request.SentAt.IsZero() || request.SentAt.Before(now.Add(-30*time.Second)) || request.SentAt.After(now.Add(10*time.Second)) { return invalid("internal request time") }
	if request.Auth != nil && request.Auth.Validate() != nil { return invalid("internal auth") }
	if request.IdempotencyKey != "" && !idempotencyPattern.MatchString(request.IdempotencyKey) { return invalid("idempotency_key") }
	return nil
}

type signedRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Request RequestEnvelope `json:"request"`
	Auth *AuthMaterial `json:"auth,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Meta RequestMeta `json:"meta"`
	SentAt time.Time `json:"sent_at"`
	Nonce string `json:"nonce"`
	KeyID string `json:"key_id"`
}

func (request CoreRequest) signedBytes() ([]byte, error) {
	return json.Marshal(signedRequest{ProtocolVersion: request.ProtocolVersion, Request: request.Request, Auth: request.Auth, IdempotencyKey: request.IdempotencyKey, Meta: request.Meta, SentAt: request.SentAt.UTC(), Nonce: request.Nonce, KeyID: request.KeyID})
}

func digestRequest(principal identity.ID, operation, idempotency string, request RequestEnvelope) (string, error) {
	payload, err := json.Marshal(struct { Principal string `json:"principal"`; Operation string `json:"operation"`; Idempotency string `json:"idempotency"`; Request RequestEnvelope `json:"request"` }{principal.String(), operation, idempotency, request})
	if err != nil { return "", err }
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func (request RequestEnvelope) String() string { return fmt.Sprintf("%s:%s", request.RequestID, request.Operation) }
