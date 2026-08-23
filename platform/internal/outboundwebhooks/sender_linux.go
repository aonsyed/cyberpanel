//go:build linux

package outboundwebhooks

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type HTTPSender struct {
	client *http.Client
	now    func() time.Time
}

func NewHTTPSender() *HTTPSender {
	return &HTTPSender{client: newWebhookHTTPClient(), now: time.Now}
}

func (sender *HTTPSender) currentTime() time.Time {
	if sender != nil && sender.now != nil {
		return sender.now().UTC()
	}
	return time.Now().UTC()
}

func (sender *HTTPSender) Send(ctx context.Context, endpoint Endpoint, delivery SignedDelivery) (SendResult, error) {
	started := sender.currentTime()
	if sender == nil || sender.client == nil || endpoint.Validate() != nil || delivery.Validate(started) != nil {
		return SendResult{}, ErrInvalid
	}
	target, err := url.Parse(endpoint.URL)
	if err != nil || validateEndpointURL(target.String()) != nil {
		return SendResult{}, ErrPolicyDenied
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(delivery.Body))
	if err != nil {
		return SendResult{}, ErrInvalid
	}
	request.ContentLength = int64(len(delivery.Body))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "CyberPanel-Outbound-Webhook/1")
	request.Header.Set("X-CyberPanel-Audience", delivery.Audience)
	request.Header.Set("X-CyberPanel-Body-SHA256", delivery.BodyDigest)
	request.Header.Set("X-CyberPanel-Deduplication-ID", string(delivery.DeduplicationID))
	request.Header.Set("X-CyberPanel-Delivery-ID", string(delivery.DeliveryID))
	request.Header.Set("X-CyberPanel-Key-Version", strconv.FormatUint(delivery.SecretVersion, 10))
	request.Header.Set("X-CyberPanel-Signature", "v1="+delivery.Signature)
	request.Header.Set("X-CyberPanel-Signature-Version", delivery.SignatureVersion)
	request.Header.Set("X-CyberPanel-Timestamp", strconv.FormatInt(delivery.Timestamp, 10))
	response, requestErr := sender.client.Do(request)
	request.Header.Del("X-CyberPanel-Signature")
	finished := sender.currentTime()
	if requestErr != nil {
		result, classified := classifyWebhookNetworkError(requestErr, started, finished)
		return result, classified
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, MaximumResponseBytes+1))
	finished = sender.currentTime()
	if readErr != nil {
		return SendResult{Retryable: true, HTTPStatus: response.StatusCode, Code: "response_read_failed", StartedAt: started, FinishedAt: finished},
			errors.Join(ErrUnavailable, readErr)
	}
	if len(body) > MaximumResponseBytes {
		return SendResult{HTTPStatus: response.StatusCode, Code: "response_too_large", StartedAt: started, FinishedAt: finished}, ErrPolicyDenied
	}
	responseDigest := digestBytes(body)
	retryAfter := parseWebhookRetryAfter(response.Header.Values("Retry-After"), finished)
	result := classifyWebhookStatus(response.StatusCode, retryAfter, started, finished)
	result.ResponseDigest = responseDigest
	if result.Delivered {
		return result, nil
	}
	if result.Retryable {
		if response.StatusCode == http.StatusTooManyRequests {
			return result, ErrRateLimited
		}
		return result, ErrUnavailable
	}
	return result, ErrPolicyDenied
}

func classifyWebhookStatus(status int, retryAfter time.Duration, started, finished time.Time) SendResult {
	result := SendResult{HTTPStatus: status, RetryAfter: retryAfter, StartedAt: started, FinishedAt: finished}
	if status >= 200 && status <= 299 {
		result.Delivered = true
		result.Code = "delivered"
		result.RetryAfter = 0
		return result
	}
	switch status {
	case http.StatusRequestTimeout:
		result.Retryable = true
		result.Code = "http_408_request_timeout"
	case http.StatusTooEarly:
		result.Retryable = true
		result.Code = "http_425_too_early"
	case http.StatusTooManyRequests:
		result.Retryable = true
		result.Code = "http_429_rate_limited"
	case http.StatusUnauthorized:
		result.Code = "http_401_unauthorized"
	case http.StatusForbidden:
		result.Code = "http_403_forbidden"
	case http.StatusNotFound:
		result.Code = "http_404_not_found"
	case http.StatusConflict:
		result.Code = "http_409_conflict"
	case http.StatusGone:
		result.Code = "http_410_gone"
	default:
		if status >= 500 && status <= 599 {
			result.Retryable = true
			result.Code = "http_" + strconv.Itoa(status) + "_server_error"
		} else if status >= 300 && status <= 399 {
			result.Code = "redirect_denied"
		} else if status >= 400 && status <= 499 {
			result.Code = "http_" + strconv.Itoa(status) + "_permanent"
		} else {
			result.Code = "unexpected_http_status"
		}
	}
	if !result.Retryable {
		result.RetryAfter = 0
	}
	return result
}

func classifyWebhookNetworkError(err error, started, finished time.Time) (SendResult, error) {
	result := SendResult{Retryable: true, Code: "network_error", StartedAt: started, FinishedAt: finished}
	if errors.Is(err, context.Canceled) {
		result.Code = "request_canceled"
		return result, errors.Join(ErrUnavailable, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		result.Code = "request_timeout"
		return result, errors.Join(ErrUnavailable, err)
	}
	if errors.Is(err, ErrPolicyDenied) {
		result.Retryable = false
		result.Code = "network_policy_denied"
		return result, errors.Join(ErrPolicyDenied, err)
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError.IsNotFound {
		result.Retryable = false
		result.Code = "dns_name_not_found"
		return result, errors.Join(ErrPolicyDenied, err)
	}
	var verificationError *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	if errors.As(err, &verificationError) || errors.As(err, &unknownAuthority) || errors.As(err, &hostnameError) || errors.As(err, &invalidCertificate) {
		result.Retryable = false
		result.Code = "tls_certificate_invalid"
		return result, errors.Join(ErrPolicyDenied, err)
	}
	return result, errors.Join(ErrUnavailable, err)
}

func parseWebhookRetryAfter(values []string, now time.Time) time.Duration {
	if len(values) != 1 || strings.TrimSpace(values[0]) != values[0] || values[0] == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(values[0], 10, 32); err == nil {
		delay := time.Duration(seconds) * time.Second
		if delay > 24*time.Hour {
			return 24 * time.Hour
		}
		return delay
	}
	parsed, err := http.ParseTime(values[0])
	if err != nil || !parsed.After(now) {
		return 0
	}
	delay := parsed.Sub(now)
	if delay > 24*time.Hour {
		return 24 * time.Hour
	}
	return delay
}

func newWebhookHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true, MaxIdleConns: 32, MaxIdleConnsPerHost: 4,
		MaxConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 32 << 10, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" || network != "tcp" && network != "tcp4" && network != "tcp6" || net.ParseIP(host) != nil {
				return nil, ErrPolicyDenied
			}
			addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			if len(addresses) == 0 {
				return nil, ErrUnavailable
			}
			for _, candidate := range addresses {
				if !publicWebhookAddress(candidate.Unmap()) {
					return nil, ErrPolicyDenied
				}
			}
			var lastErr error
			for _, candidate := range addresses {
				connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.Unmap().String(), port))
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		}}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var reservedWebhookPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func publicWebhookAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range reservedWebhookPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var _ DeliverySender = (*HTTPSender)(nil)
