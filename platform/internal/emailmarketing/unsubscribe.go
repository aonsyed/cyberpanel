package emailmarketing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	unsubscribeTokenVersion = 1
	maxUnsubscribeTokenBytes = 4096
	maxUnsubscribeLifetime   = 30 * 24 * time.Hour
)

type UnsubscribeKeyMaterial struct {
	Version     uint32
	Secret      []byte
	NotBefore   time.Time
	SignUntil   time.Time
	VerifyUntil time.Time
	Destroy     func()
}

type UnsubscribeKeyResolver interface {
	CurrentUnsubscribeKey(context.Context) (UnsubscribeKeyMaterial, error)
	ResolveUnsubscribeKey(context.Context, uint32) (UnsubscribeKeyMaterial, error)
}

type UnsubscribeClaims struct {
	Version              uint32       `json:"v"`
	KeyVersion           uint32       `json:"kv"`
	TenantID             TenantID     `json:"tenant"`
	ListID               ListID       `json:"list"`
	SubscriberID         SubscriberID `json:"subscriber"`
	ListGeneration       uint64       `json:"list_generation"`
	SubscriberGeneration uint64       `json:"subscriber_generation"`
	Audience             string       `json:"audience"`
	IssuedAt             time.Time    `json:"issued_at"`
	ExpiresAt            time.Time    `json:"expires_at"`
	Nonce                string       `json:"nonce"`
}

func (claims UnsubscribeClaims) Validate(now time.Time) error {
	if claims.Version != unsubscribeTokenVersion || claims.KeyVersion == 0 || validateIdentifier(string(claims.TenantID)) != nil ||
		validateIdentifier(string(claims.ListID)) != nil || validateIdentifier(string(claims.SubscriberID)) != nil ||
		claims.ListGeneration == 0 || claims.SubscriberGeneration == 0 || claims.Audience == "" || len(claims.Audience) > 256 ||
		strings.TrimSpace(claims.Audience) != claims.Audience || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() ||
		!claims.ExpiresAt.After(claims.IssuedAt) || claims.ExpiresAt.Sub(claims.IssuedAt) > maxUnsubscribeLifetime ||
		now.Before(claims.IssuedAt.Add(-5*time.Minute)) || !now.Before(claims.ExpiresAt) || len(claims.Nonce) < 32 || len(claims.Nonce) > 128 {
		return ErrInvalid
	}
	return nil
}

type UnsubscribeGrantRequest struct {
	TenantID             TenantID
	ListID               ListID
	SubscriberID         SubscriberID
	ListGeneration       uint64
	SubscriberGeneration uint64
	Audience             string
	Lifetime             time.Duration
}

type UnsubscribeRepository interface {
	ConsumeUnsubscribe(context.Context, UnsubscribeClaims, string, time.Time) (bool, error)
}

type UnsubscribeService struct {
	Keys       UnsubscribeKeyResolver
	Repository UnsubscribeRepository
	Audit      AuditSink
	Now        func() time.Time
}

func (service UnsubscribeService) Issue(ctx context.Context, request UnsubscribeGrantRequest) (string, error) {
	if service.Keys == nil || service.Now == nil || request.Lifetime < time.Minute || request.Lifetime > maxUnsubscribeLifetime {
		return "", ErrInvalid
	}
	now := service.Now().UTC()
	key, err := service.Keys.CurrentUnsubscribeKey(ctx)
	if err != nil {
		return "", err
	}
	defer destroyKey(&key)
	if err := validateSigningKey(key, now); err != nil {
		return "", err
	}
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	claims := UnsubscribeClaims{
		Version: unsubscribeTokenVersion, KeyVersion: key.Version, TenantID: request.TenantID, ListID: request.ListID,
		SubscriberID: request.SubscriberID, ListGeneration: request.ListGeneration, SubscriberGeneration: request.SubscriberGeneration,
		Audience: request.Audience, IssuedAt: now, ExpiresAt: now.Add(request.Lifetime), Nonce: base64.RawURLEncoding.EncodeToString(nonce),
	}
	if err := claims.Validate(now); err != nil {
		return "", err
	}
	header := unsubscribeHeader{Version: unsubscribeTokenVersion, KeyVersion: key.Version, Algorithm: "HS256", Type: "unsubscribe"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	secret := append([]byte(nil), key.Secret...)
	defer wipe(secret)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

type UnsubscribeResponse struct {
	Code string `json:"code"`
}

var genericUnsubscribeResponse = UnsubscribeResponse{Code: "preference_processed"}

// Process always returns the same public response for malformed, expired,
// unknown, already-used, and successfully consumed grants. Operational storage
// failures are returned so the HTTP layer can retry without exposing identity.
func (service UnsubscribeService) Process(ctx context.Context, token, audience string) (UnsubscribeResponse, error) {
	if service.Keys == nil || service.Repository == nil || service.Now == nil || audience == "" {
		return genericUnsubscribeResponse, ErrInvalid
	}
	now := service.Now().UTC()
	claims, tokenDigest, err := service.verify(ctx, token, audience, now)
	if err != nil {
		return genericUnsubscribeResponse, nil
	}
	applied, err := service.Repository.ConsumeUnsubscribe(ctx, claims, tokenDigest, now)
	if err != nil {
		return genericUnsubscribeResponse, err
	}
	if service.Audit != nil {
		outcome := "replay"
		if applied {
			outcome = "suppressed"
		}
		auditErr := service.Audit.RecordAudit(ctx, AuditRecord{TenantID: claims.TenantID, ActorID: "public_unsubscribe", Action: "emailmarketing.unsubscribe", Resource: string(claims.ListID) + ":" + string(claims.SubscriberID), Outcome: outcome, EvidenceDigest: tokenDigest, OccurredAt: now})
		if auditErr != nil {
			return genericUnsubscribeResponse, auditErr
		}
	}
	return genericUnsubscribeResponse, nil
}

func (service UnsubscribeService) verify(ctx context.Context, token, audience string, now time.Time) (UnsubscribeClaims, string, error) {
	if len(token) == 0 || len(token) > maxUnsubscribeTokenBytes || strings.Count(token, ".") != 2 {
		return UnsubscribeClaims{}, "", ErrInvalid
	}
	parts := strings.Split(token, ".")
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(headerBytes) > 512 {
		return UnsubscribeClaims{}, "", ErrInvalid
	}
	var header unsubscribeHeader
	if decodeStrictJSON(headerBytes, &header) != nil || header.Version != unsubscribeTokenVersion || header.KeyVersion == 0 || header.Algorithm != "HS256" || header.Type != "unsubscribe" {
		return UnsubscribeClaims{}, "", ErrInvalid
	}
	key, err := service.Keys.ResolveUnsubscribeKey(ctx, header.KeyVersion)
	if err != nil {
		return UnsubscribeClaims{}, "", ErrInvalid
	}
	defer destroyKey(&key)
	if validateVerificationKey(key, header.KeyVersion, now) != nil {
		return UnsubscribeClaims{}, "", ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != sha256.Size {
		return UnsubscribeClaims{}, "", ErrInvalid
	}
	secret := append([]byte(nil), key.Secret...)
	defer wipe(secret)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return UnsubscribeClaims{}, "", ErrInvalid
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(claimsBytes) > 2048 {
		return UnsubscribeClaims{}, "", ErrInvalid
	}
	var claims UnsubscribeClaims
	if decodeStrictJSON(claimsBytes, &claims) != nil || claims.KeyVersion != header.KeyVersion || claims.Audience != audience || claims.Validate(now) != nil {
		return UnsubscribeClaims{}, "", ErrInvalid
	}
	return claims, DigestEvidence([]byte(token)), nil
}

type unsubscribeHeader struct {
	Version    uint32 `json:"v"`
	KeyVersion uint32 `json:"kid"`
	Algorithm  string `json:"alg"`
	Type       string `json:"typ"`
}

func validateSigningKey(key UnsubscribeKeyMaterial, now time.Time) error {
	if key.Version == 0 || len(key.Secret) < 32 || len(key.Secret) > 128 || key.NotBefore.IsZero() || key.SignUntil.IsZero() || key.VerifyUntil.Before(key.SignUntil) || now.Before(key.NotBefore) || now.After(key.SignUntil) {
		return errors.New("emailmarketing: unsubscribe signing key is unavailable")
	}
	return nil
}

func validateVerificationKey(key UnsubscribeKeyMaterial, expected uint32, now time.Time) error {
	if key.Version != expected || len(key.Secret) < 32 || len(key.Secret) > 128 || key.NotBefore.IsZero() || key.VerifyUntil.IsZero() || now.Before(key.NotBefore) || now.After(key.VerifyUntil) {
		return errors.New("emailmarketing: unsubscribe verification key is unavailable")
	}
	return nil
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("emailmarketing: trailing token data")
	}
	return nil
}

func destroyKey(key *UnsubscribeKeyMaterial) {
	wipe(key.Secret)
	if key.Destroy != nil {
		key.Destroy()
	}
	*key = UnsubscribeKeyMaterial{}
}

func wipe(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}
