//go:build linux

package integrations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maximumNotificationSecret          = 16 << 10
	maximumNotificationEnvelope        = 512 << 10
	maximumNotificationSMTPMessage     = 1 << 20
	maximumNotificationWebhookResponse = 64 << 10
	maximumNotificationRecipients      = 100
)

type NotificationRemoteAdapter struct {
	Kind     ProviderKind
	Secrets  ProviderSecretReader
	Resolver *net.Resolver
	Dialer   *net.Dialer
	Now      func() time.Time
}

func NewNotificationRemoteAdapter(kind ProviderKind, reader ProviderSecretReader) (*NotificationRemoteAdapter, error) {
	if reader.Client == nil {
		return nil, ErrInvalid
	}
	switch kind {
	case ProviderNotificationSMTP, ProviderNotificationWebhook:
	default:
		return nil, ErrUnsupported
	}
	return &NotificationRemoteAdapter{Kind: kind, Secrets: reader, Resolver: net.DefaultResolver, Dialer: &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}, Now: time.Now}, nil
}

func (adapter *NotificationRemoteAdapter) now() time.Time {
	if adapter != nil && adapter.Now != nil {
		return adapter.Now().UTC()
	}
	return time.Now().UTC()
}

func (adapter *NotificationRemoteAdapter) DiscoverCapabilities(ctx context.Context, binding ProviderBinding) (CapabilitySet, error) {
	if err := adapter.ValidateCredential(ctx, binding); err != nil {
		return CapabilitySet{}, err
	}
	return adapter.capabilities(), nil
}

func (adapter *NotificationRemoteAdapter) Health(ctx context.Context, binding ProviderBinding) (ProviderHealth, error) {
	started := adapter.now()
	capabilities := adapter.capabilities()
	err := adapter.ValidateCredential(ctx, binding)
	observed := adapter.now()
	health := ProviderHealth{BindingID: binding.ID, State: HealthHealthy, Latency: observed.Sub(started), CredentialValid: err == nil, CapabilitiesDigest: capabilities.Digest, RateLimitRemaining: -1, ObservedAt: observed, StaleAfter: observed.Add(5 * time.Minute)}
	if err != nil {
		health.State = HealthUnavailable
		health.Reason = "notification credential validation failed"
		return health, err
	}
	return health, nil
}

func (adapter *NotificationRemoteAdapter) ValidateCredential(ctx context.Context, binding ProviderBinding) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := adapter.validateBinding(binding, false); err != nil {
		return err
	}
	material, cleanup, err := adapter.Secrets.Read(ctx, binding)
	if err != nil {
		return err
	}
	defer cleanup()
	switch adapter.Kind {
	case ProviderNotificationSMTP:
		credential, parseErr := parseNotificationSMTPCredential(material)
		credential.clear()
		return parseErr
	case ProviderNotificationWebhook:
		credential, parseErr := parseNotificationWebhookCredential(material)
		credential.clear()
		return parseErr
	default:
		return ErrUnsupported
	}
}

func (adapter *NotificationRemoteAdapter) RevokeCredential(ctx context.Context, binding ProviderBinding) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := adapter.validateBinding(binding, false); err != nil {
		return err
	}
	material, cleanup, err := adapter.Secrets.Read(ctx, binding)
	if err != nil {
		return err
	}
	cleanup()
	wipeIntegrationSecret(material)
	return nil
}

func (adapter *NotificationRemoteAdapter) DeliverSMTP(ctx context.Context, binding ProviderBinding, target SMTPNotificationTarget, envelope NotificationEnvelope) (NotificationReceipt, error) {
	if ctx == nil {
		return NotificationReceipt{}, ErrInvalid
	}
	if err := adapter.validateBinding(binding, true); err != nil {
		return NotificationReceipt{}, err
	}
	recipients, err := validateNotificationSMTPTarget(binding, target)
	if err != nil {
		return NotificationReceipt{}, err
	}
	payload, err := validateNotificationEnvelope(envelope, "notification.smtp", binding.SecretVersion, adapter.now())
	if err != nil {
		return NotificationReceipt{}, err
	}
	defer wipeIntegrationSecret(payload)
	message, err := buildNotificationSMTPMessage(target, recipients, envelope, payload)
	if err != nil {
		return NotificationReceipt{}, err
	}
	defer wipeIntegrationSecret(message)
	material, cleanup, err := adapter.Secrets.Read(ctx, binding)
	if err != nil {
		return NotificationReceipt{}, err
	}
	defer cleanup()
	credential, err := parseNotificationSMTPCredential(material)
	if err != nil {
		return NotificationReceipt{}, err
	}
	defer credential.clear()
	if err = adapter.sendNotificationSMTP(ctx, binding.Endpoint, target, recipients, credential, message); err != nil {
		return NotificationReceipt{}, err
	}
	evidence := sha256.Sum256([]byte(binding.Endpoint.URL + "\x00" + target.From + "\x00" + strings.Join(recipients, "\x00")))
	return makeNotificationReceipt("smtp", envelope, hex.EncodeToString(evidence[:]), adapter.now()), nil
}

func (adapter *NotificationRemoteAdapter) DeliverWebhook(ctx context.Context, binding ProviderBinding, target WebhookNotificationTarget, envelope NotificationEnvelope) (NotificationReceipt, error) {
	if ctx == nil {
		return NotificationReceipt{}, ErrInvalid
	}
	if err := adapter.validateBinding(binding, true); err != nil {
		return NotificationReceipt{}, err
	}
	if err := validateNotificationWebhookTarget(binding, target); err != nil {
		return NotificationReceipt{}, err
	}
	payload, err := validateNotificationEnvelope(envelope, target.Audience, target.KeyVersion, adapter.now())
	if err != nil {
		return NotificationReceipt{}, err
	}
	defer wipeIntegrationSecret(payload)
	material, cleanup, err := adapter.Secrets.Read(ctx, binding)
	if err != nil {
		return NotificationReceipt{}, err
	}
	defer cleanup()
	credential, err := parseNotificationWebhookCredential(material)
	if err != nil {
		return NotificationReceipt{}, err
	}
	defer credential.clear()
	responseBody, err := adapter.sendNotificationWebhook(ctx, target, envelope, credential.BearerToken, payload)
	if err != nil {
		return NotificationReceipt{}, err
	}
	defer wipeIntegrationSecret(responseBody)
	evidence := sha256.Sum256([]byte(binding.Endpoint.URL + "\x00" + target.Audience))
	return makeNotificationReceipt("webhook", envelope, hex.EncodeToString(evidence[:]), adapter.now()), nil
}

func (adapter *NotificationRemoteAdapter) capabilities() CapabilitySet {
	capabilities := []Capability{CapabilityHealth, CapabilityNotify}
	version := "notification-provider-v1"
	if adapter != nil && adapter.Kind == ProviderNotificationSMTP {
		version = "notification-smtp-v1"
	} else if adapter != nil && adapter.Kind == ProviderNotificationWebhook {
		version = "notification-webhook-v1"
	}
	now := adapter.now()
	return CapabilitySet{SchemaVersion: 1, ProviderVersion: version, Capabilities: capabilities, DiscoveredAt: now, Digest: capabilityDigest(capabilities)}
}

func (adapter *NotificationRemoteAdapter) validateBinding(binding ProviderBinding, requireActive bool) error {
	if adapter == nil || adapter.Kind != binding.Kind || binding.Purpose != PurposeNotification || binding.Validate() != nil || validateProviderEndpoint(binding.Kind, binding.Endpoint) != nil {
		return ErrPolicyDenied
	}
	if requireActive && binding.State != BindingActive {
		return ErrPolicyDenied
	}
	if len(binding.Endpoint.URL) == 0 || len(binding.Endpoint.URL) > 2048 || binding.Endpoint.MaximumRedirects != 0 || binding.Endpoint.PinnedCARef != "" || binding.Endpoint.PinnedPublicKey != "" || !validNotificationServerName(binding.Endpoint.ServerName) {
		return ErrPolicyDenied
	}
	parsed, err := url.Parse(binding.Endpoint.URL)
	if err != nil || parsed.User != nil || parsed.Fragment != "" {
		return ErrPolicyDenied
	}
	switch adapter.Kind {
	case ProviderNotificationSMTP:
		if parsed.Scheme != "smtp+tls" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Hostname() == "" || !validNotificationPort(parsed.Port()) {
			return ErrPolicyDenied
		}
	case ProviderNotificationWebhook:
		if parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Port() != "" && !validNotificationPort(parsed.Port()) {
			return ErrPolicyDenied
		}
	default:
		return ErrUnsupported
	}
	return nil
}

type notificationSMTPCredential struct {
	Username string
	Password string
}

func (credential *notificationSMTPCredential) clear() {
	if credential == nil {
		return
	}
	credential.Username = ""
	credential.Password = ""
}

type notificationWebhookCredential struct {
	BearerToken string
}

func (credential *notificationWebhookCredential) clear() {
	if credential != nil {
		credential.BearerToken = ""
	}
}

func parseNotificationSMTPCredential(material []byte) (notificationSMTPCredential, error) {
	var credential notificationSMTPCredential
	if err := decodeNotificationSecret(material, map[string]*string{"username": &credential.Username, "password": &credential.Password}); err != nil {
		return notificationSMTPCredential{}, err
	}
	if credential.Username == "" || len(credential.Username) > 512 || credential.Password == "" || len(credential.Password) > 8192 || strings.ContainsAny(credential.Username, "\x00\r\n") || strings.ContainsAny(credential.Password, "\x00\r\n") {
		credential.clear()
		return notificationSMTPCredential{}, ErrInvalid
	}
	return credential, nil
}

func parseNotificationWebhookCredential(material []byte) (notificationWebhookCredential, error) {
	var credential notificationWebhookCredential
	if err := decodeNotificationSecret(material, map[string]*string{"bearer_token": &credential.BearerToken}); err != nil {
		return notificationWebhookCredential{}, err
	}
	if len(credential.BearerToken) < 16 || len(credential.BearerToken) > 8192 || strings.ContainsAny(credential.BearerToken, "\x00\r\n\t ") {
		credential.clear()
		return notificationWebhookCredential{}, ErrInvalid
	}
	return credential, nil
}

func decodeNotificationSecret(material []byte, fields map[string]*string) error {
	if len(material) == 0 || len(material) > maximumNotificationSecret || len(fields) == 0 {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(material))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for decoder.More() {
		rawKey, tokenErr := decoder.Token()
		key, ok := rawKey.(string)
		target := fields[key]
		if tokenErr != nil || !ok || target == nil || seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		if decoder.Decode(target) != nil {
			return ErrInvalid
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF || len(seen) != len(fields) {
		return ErrInvalid
	}
	return nil
}

func validateNotificationSMTPTarget(binding ProviderBinding, target SMTPNotificationTarget) ([]string, error) {
	if target.Port == 0 || target.TLS != RelayTLSRequired && target.TLS != RelayTLSImplicit || !validNotificationDNSName(target.Host) || !validNotificationServerName(target.ServerName) || target.ServerName != binding.Endpoint.ServerName {
		return nil, ErrInvalid
	}
	expectedEndpoint := "smtp+tls://" + net.JoinHostPort(target.Host, strconv.FormatUint(uint64(target.Port), 10))
	if binding.Endpoint.URL != expectedEndpoint {
		return nil, ErrPolicyDenied
	}
	from, err := strictNotificationMailbox(target.From)
	if err != nil || len(target.Recipients) == 0 || len(target.Recipients) > maximumNotificationRecipients {
		return nil, ErrInvalid
	}
	recipients := make([]string, 0, len(target.Recipients))
	seen := map[string]bool{}
	total := len(from)
	for _, raw := range target.Recipients {
		recipient, parseErr := strictNotificationMailbox(raw)
		key := strings.ToLower(recipient)
		if parseErr != nil || seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
		total += len(recipient)
		if total > 32<<10 {
			return nil, ErrInvalid
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

func strictNotificationMailbox(value string) (string, error) {
	if value == "" || len(value) > 320 || !notificationASCII(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return "", ErrInvalid
	}
	address, err := mail.ParseAddress(value)
	separator := strings.LastIndexByte(value, '@')
	if err != nil || address.Name != "" || address.Address != value || strings.Count(address.Address, "@") != 1 || separator <= 0 || separator == len(value)-1 || !validNotificationMailboxLocal(value[:separator]) || !validNotificationDNSName(value[separator+1:]) {
		return "", ErrInvalid
	}
	return address.Address, nil
}

func buildNotificationSMTPMessage(target SMTPNotificationTarget, recipients []string, envelope NotificationEnvelope, payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maximumNotificationEnvelope || !safeNotificationSubject(envelope.Notification.Subject) {
		return nil, ErrInvalid
	}
	var message strings.Builder
	message.Grow(len(payload)*2 + 4096)
	message.WriteString("From: <")
	message.WriteString(target.From)
	message.WriteString(">\r\nTo: <")
	for index, recipient := range recipients {
		if index > 0 {
			message.WriteString(">,\r\n <")
		}
		message.WriteString(recipient)
	}
	message.WriteString(">\r\nSubject: ")
	message.WriteString(mime.QEncoding.Encode("utf-8", envelope.Notification.Subject))
	message.WriteString("\r\nDate: ")
	message.WriteString(envelope.IssuedAt.UTC().Format(time.RFC1123Z))
	message.WriteString("\r\nMIME-Version: 1.0\r\nContent-Type: application/json; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\nX-CyberPanel-Delivery-ID: ")
	message.WriteString(string(envelope.DeliveryID))
	message.WriteString("\r\nX-CyberPanel-Audience: ")
	message.WriteString(envelope.Audience)
	message.WriteString("\r\nX-CyberPanel-Body-Digest: ")
	message.WriteString(envelope.BodyDigest)
	message.WriteString("\r\n\r\n")
	encoded := base64.StdEncoding.EncodeToString(payload)
	for len(encoded) > 76 {
		message.WriteString(encoded[:76])
		message.WriteString("\r\n")
		encoded = encoded[76:]
	}
	message.WriteString(encoded)
	message.WriteString("\r\n")
	if message.Len() > maximumNotificationSMTPMessage {
		return nil, ErrInvalid
	}
	return []byte(message.String()), nil
}

func (adapter *NotificationRemoteAdapter) sendNotificationSMTP(ctx context.Context, policy EndpointPolicy, target SMTPNotificationTarget, recipients []string, credential notificationSMTPCredential, message []byte) error {
	connection, err := adapter.dialNotificationEndpoint(ctx, target.Host, strconv.FormatUint(uint64(target.Port), 10), policy)
	if err != nil {
		return normalizeNotificationNetworkError("notification.smtp.connect", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func(){ _ = connection.SetDeadline(time.Now()) })
	defer stop()
	tlsConfiguration := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.ServerName}
	var client *smtp.Client
	if target.TLS == RelayTLSImplicit {
		secured := tls.Client(connection, tlsConfiguration)
		if err = secured.HandshakeContext(ctx); err != nil {
			return normalizeNotificationNetworkError("notification.smtp.tls", err)
		}
		client, err = smtp.NewClient(secured, target.ServerName)
	} else {
		client, err = smtp.NewClient(connection, target.ServerName)
		if err == nil {
			if available, _ := client.Extension("STARTTLS"); !available {
				_ = client.Close()
				return &ProviderError{Class: ErrorPermanent, Operation: "notification.smtp.tls", Code: "starttls_required", Cause: ErrPolicyDenied}
			}
			err = client.StartTLS(tlsConfiguration)
		}
	}
	if err != nil {
		return normalizeNotificationSMTPError("notification.smtp.handshake", err)
	}
	defer client.Close()
	available, mechanisms := client.Extension("AUTH")
	if !available || !smtpMechanismAvailable(mechanisms, "PLAIN") {
		return &ProviderError{Class: ErrorPermanent, Operation: "notification.smtp.authenticate", Code: "auth_plain_unsupported", Cause: ErrUnsupported}
	}
	if err = client.Auth(smtp.PlainAuth("", credential.Username, credential.Password, target.ServerName)); err != nil {
		return normalizeNotificationSMTPError("notification.smtp.authenticate", err)
	}
	if err = client.Mail(target.From); err != nil {
		return normalizeNotificationSMTPError("notification.smtp.mail_from", err)
	}
	for _, recipient := range recipients {
		if err = client.Rcpt(recipient); err != nil {
			return normalizeNotificationSMTPError("notification.smtp.recipient", err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return normalizeNotificationSMTPError("notification.smtp.data", err)
	}
	if _, err = writer.Write(message); err == nil {
		err = writer.Close()
	} else {
		_ = writer.Close()
	}
	if err != nil {
		return normalizeNotificationSMTPError("notification.smtp.deliver", err)
	}
	_ = client.Quit()
	return nil
}

func smtpMechanismAvailable(raw, expected string) bool {
	for _, mechanism := range strings.Fields(raw) {
		if strings.EqualFold(mechanism, expected) {
			return true
		}
	}
	return false
}

func normalizeNotificationSMTPError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var protocolError *textproto.Error
	if errors.As(err, &protocolError) {
		switch protocolError.Code {
		case 530, 534, 535, 538:
			return &ProviderError{Class: ErrorUnauthorized, Operation: operation, Code: "credential_rejected", Cause: ErrUnauthorized}
		case 421, 450, 451, 452, 454:
			return &ProviderError{Class: ErrorUnavailable, Operation: operation, Code: "temporary_failure", Cause: ErrUnavailable}
		default:
			if protocolError.Code >= 500 && protocolError.Code < 600 {
				return &ProviderError{Class: ErrorPermanent, Operation: operation, Code: "request_rejected", Cause: ErrPolicyDenied}
			}
		}
	}
	return normalizeNotificationNetworkError(operation, err)
}

func validateNotificationWebhookTarget(binding ProviderBinding, target WebhookNotificationTarget) error {
	if target.Endpoint.Validate() != nil || !sameNotificationEndpointPolicy(binding.Endpoint, target.Endpoint) || target.Endpoint.MaximumRedirects != 0 || len(target.Audience) == 0 || len(target.Audience) > 512 || !safeNotificationHeaderValue(target.Audience) || !validID(string(target.SigningKeyRef)) || target.KeyVersion == 0 || !validNotificationToken(target.SigningAlgorithm) {
		return ErrPolicyDenied
	}
	parsed, err := url.Parse(target.Endpoint.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return ErrPolicyDenied
	}
	return nil
}

func sameNotificationEndpointPolicy(left, right EndpointPolicy) bool {
	if left.URL != right.URL || left.ServerName != right.ServerName || left.PinnedCARef != right.PinnedCARef || left.PinnedPublicKey != right.PinnedPublicKey || left.AllowPublicInternet != right.AllowPublicInternet || left.DenyPrivateRanges != right.DenyPrivateRanges || left.MaximumRedirects != right.MaximumRedirects || len(left.AllowedCIDRs) != len(right.AllowedCIDRs) {
		return false
	}
	for index := range left.AllowedCIDRs {
		if left.AllowedCIDRs[index] != right.AllowedCIDRs[index] {
			return false
		}
	}
	return true
}

func (adapter *NotificationRemoteAdapter) sendNotificationWebhook(ctx context.Context, target WebhookNotificationTarget, envelope NotificationEnvelope, bearerToken string, payload []byte) ([]byte, error) {
	parsed, _ := url.Parse(target.Endpoint.URL)
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.Endpoint.ServerName}}
	transport.DialContext = func(dialContext context.Context, network, address string) (net.Conn, error) {
		host, requestedPort, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(host, parsed.Hostname()) || requestedPort != port {
			return nil, ErrPolicyDenied
		}
		return adapter.dialNotificationEndpoint(dialContext, parsed.Hostname(), port, target.Endpoint)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.Endpoint.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, ErrInvalid
	}
	payloadDigest := sha256.Sum256(payload)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+bearerToken)
	request.Header.Set("Idempotency-Key", string(envelope.DeliveryID))
	request.Header.Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(payloadDigest[:]))
	request.Header.Set("X-CyberPanel-Delivery-ID", string(envelope.DeliveryID))
	request.Header.Set("X-CyberPanel-Audience", envelope.Audience)
	request.Header.Set("X-CyberPanel-Timestamp", envelope.IssuedAt.UTC().Format(time.RFC3339Nano))
	request.Header.Set("X-CyberPanel-Body-Digest", envelope.BodyDigest)
	request.Header.Set("X-CyberPanel-Signing-Key-ID", envelope.SigningKeyID)
	request.Header.Set("X-CyberPanel-Signing-Key-Version", strconv.FormatUint(envelope.SigningKeyVersion, 10))
	request.Header.Set("X-CyberPanel-Signature-Algorithm", target.SigningAlgorithm)
	request.Header.Set("X-CyberPanel-Signature", envelope.Signature)
	response, err := client.Do(request)
	if err != nil {
		return nil, normalizeNotificationNetworkError("notification.webhook.deliver", err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumNotificationWebhookResponse+1))
	if readErr != nil || len(body) > maximumNotificationWebhookResponse {
		return nil, &ProviderError{Class: ErrorUnavailable, Operation: "notification.webhook.deliver", Code: "response_too_large", Cause: ErrUnavailable}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, normalizeNotificationWebhookStatus(response.StatusCode, response.Header.Get("Retry-After"), adapter.now())
	}
	if len(bytes.TrimSpace(body)) > 0 {
		contentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
		if contentType != "application/json" || !json.Valid(body) {
			return nil, &ProviderError{Class: ErrorUnavailable, Operation: "notification.webhook.deliver", Code: "invalid_response", Cause: ErrIntegrity}
		}
	}
	return body, nil
}

func normalizeNotificationWebhookStatus(status int, retryAfter string, now time.Time) error {
	delay := notificationRetryAfter(retryAfter, now)
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return &ProviderError{Class: ErrorUnauthorized, Operation: "notification.webhook.deliver", Code: "credential_rejected", Cause: ErrUnauthorized}
	case http.StatusTooManyRequests:
		return &ProviderError{Class: ErrorRateLimited, Operation: "notification.webhook.deliver", Code: "rate_limited", RetryAfter: delay, Cause: ErrRateLimited}
	case http.StatusServiceUnavailable:
		return &ProviderError{Class: ErrorUnavailable, Operation: "notification.webhook.deliver", Code: "service_unavailable", RetryAfter: delay, Cause: ErrUnavailable}
	default:
		if status >= 500 {
			return &ProviderError{Class: ErrorUnavailable, Operation: "notification.webhook.deliver", Code: "server_failure", Cause: ErrUnavailable}
		}
		return &ProviderError{Class: ErrorPermanent, Operation: "notification.webhook.deliver", Code: "request_rejected", Cause: ErrPolicyDenied}
	}
}

func notificationRetryAfter(raw string, now time.Time) time.Duration {
	raw = strings.TrimSpace(raw)
	if seconds, err := strconv.ParseUint(raw, 10, 32); err == nil {
		delay := time.Duration(seconds) * time.Second
		if delay > 24*time.Hour {
			return 24 * time.Hour
		}
		return delay
	}
	parsed, err := http.ParseTime(raw)
	if err != nil || !parsed.After(now) {
		return 0
	}
	delay := parsed.Sub(now)
	if delay > 24*time.Hour {
		return 24 * time.Hour
	}
	return delay
}

func validateNotificationEnvelope(envelope NotificationEnvelope, audience string, keyVersion uint64, now time.Time) ([]byte, error) {
	if !validID(string(envelope.DeliveryID)) || envelope.Notification.Validate() != nil || envelope.Audience != audience || len(envelope.Audience) == 0 || len(envelope.Audience) > 512 || !safeNotificationHeaderValue(envelope.Audience) || !validDigest(envelope.BodyDigest) || !validID(envelope.SigningKeyID) || envelope.SigningKeyVersion == 0 || envelope.SigningKeyVersion != keyVersion || len(envelope.Signature) == 0 || len(envelope.Signature) > 8192 || !safeNotificationHeaderValue(envelope.Signature) {
		return nil, ErrInvalid
	}
	if envelope.IssuedAt.IsZero() || envelope.ExpiresAt.IsZero() || !envelope.ExpiresAt.After(envelope.IssuedAt) || envelope.ExpiresAt.Sub(envelope.IssuedAt) > 10*time.Minute || envelope.IssuedAt.After(now.Add(time.Minute)) || !now.Before(envelope.ExpiresAt) || !envelope.Notification.ExpiresAt.IsZero() && !now.Before(envelope.Notification.ExpiresAt) {
		return nil, ErrPolicyDenied
	}
	computedDigest, err := digest(envelope.Notification)
	if err != nil || computedDigest != envelope.BodyDigest {
		return nil, ErrIntegrity
	}
	payload, err := json.Marshal(envelope)
	if err != nil || len(payload) == 0 || len(payload) > maximumNotificationEnvelope {
		return nil, ErrInvalid
	}
	return payload, nil
}

func makeNotificationReceipt(kind string, envelope NotificationEnvelope, evidence string, deliveredAt time.Time) NotificationReceipt {
	providerHash := sha256.Sum256([]byte("cyberpanel:notification-provider-receipt:v1\x00" + kind + "\x00" + string(envelope.DeliveryID) + "\x00" + envelope.BodyDigest + "\x00" + evidence))
	providerReceipt := kind + "_" + hex.EncodeToString(providerHash[:16])
	receiptHash := sha256.Sum256([]byte("cyberpanel:notification-receipt:v1\x00" + string(envelope.DeliveryID) + "\x00" + providerReceipt + "\x00" + envelope.BodyDigest))
	return NotificationReceipt{DeliveryID: envelope.DeliveryID, ProviderReceipt: providerReceipt, ReceiptDigest: hex.EncodeToString(receiptHash[:]), DeliveredAt: deliveredAt.UTC()}
}

func (adapter *NotificationRemoteAdapter) dialNotificationEndpoint(ctx context.Context, host, port string, policy EndpointPolicy) (net.Conn, error) {
	if ctx == nil || host == "" || port == "" {
		return nil, ErrInvalid
	}
	prefixes, err := notificationAllowedPrefixes(policy.AllowedCIDRs)
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		addresses = []netip.Addr{literal.Unmap()}
	} else {
		resolver := adapter.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addresses, err = resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 {
			return nil, ErrUnavailable
		}
	}
	dialer := adapter.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	}
	allowed := false
	for _, candidate := range addresses {
		candidate = candidate.Unmap()
		if !notificationAddressAllowed(candidate, policy.AllowPublicInternet, prefixes) {
			continue
		}
		allowed = true
		connection, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
	}
	if !allowed {
		return nil, ErrPolicyDenied
	}
	return nil, ErrUnavailable
}

func notificationAllowedPrefixes(raw []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value {
			return nil, ErrInvalid
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func notificationAddressAllowed(address netip.Addr, allowPublic bool, prefixes []netip.Prefix) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return allowPublic && address.IsGlobalUnicast() && publicProviderAddress(address)
}

func normalizeNotificationNetworkError(operation string, err error) error {
	if errors.Is(err, ErrPolicyDenied) || errors.Is(err, ErrInvalid) {
		return ErrPolicyDenied
	}
	code := "network"
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
		code = "timeout"
	}
	return &ProviderError{Class: ErrorUnavailable, Operation: operation, Code: code, Cause: ErrUnavailable}
}

func validNotificationDNSName(value string) bool {
	if net.ParseIP(value) != nil || len(value) == 0 || len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

func validNotificationServerName(value string) bool {
	if net.ParseIP(value) != nil {
		return len(value) <= 64
	}
	return validNotificationDNSName(value)
}

func validNotificationPort(value string) bool {
	port, err := strconv.ParseUint(value, 10, 16)
	return err == nil && port != 0 && strconv.FormatUint(port, 10) == value
}

func validNotificationMailboxLocal(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '.' || value[len(value)-1] == '.' || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", character)) {
			return false
		}
	}
	return true
}

func validNotificationToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", character)) {
			return false
		}
	}
	return true
}

func safeNotificationHeaderValue(value string) bool {
	if value == "" || len(value) > 8192 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func safeNotificationSubject(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func notificationASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

var _ NotificationProvider = (*NotificationRemoteAdapter)(nil)
