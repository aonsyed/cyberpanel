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
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	dockerHubRegistryOrigin = "https://registry-1.docker.io"
	dockerHubAuthOrigin     = "https://auth.docker.io"
	dockerHubAPIOrigin      = "https://hub.docker.com"
	dockerHubTokenService   = "registry.docker.io"

	dockerHubMaximumSecretBytes   = 16 << 10
	dockerHubMaximumJSONBytes     = 1 << 20
	dockerHubMaximumManifestBytes = 4 << 20
	dockerHubMaximumPageSize      = 100
	dockerHubMaximumTokenLifetime = 15 * time.Minute
)

var dockerHubTagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
var dockerHubRepositorySegmentPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*$`)
var reservedDockerHubPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
}

type DockerHubAdapter struct {
	secrets ProviderSecretReader
	client  *http.Client
	now     func() time.Time
}

func NewDockerHubAdapter(reader ProviderSecretReader) (*DockerHubAdapter, error) {
	profile, ok := reader.Profiles[ProviderDockerHub]
	if reader.Client == nil || !ok || profile.validate() != nil || !dockerHubEnrolledOrigin(profile.Origin) {
		return nil, ErrInvalid
	}
	return &DockerHubAdapter{secrets: reader, client: newDockerHubHTTPClient(), now: time.Now}, nil
}

func NewDockerHubProvider(reader ProviderSecretReader) (*DockerHubAdapter, error) {
	return NewDockerHubAdapter(reader)
}

func (adapter *DockerHubAdapter) currentTime() time.Time {
	if adapter != nil && adapter.now != nil {
		return adapter.now().UTC()
	}
	return time.Now().UTC()
}

func (adapter *DockerHubAdapter) DiscoverCapabilities(ctx context.Context, binding ProviderBinding) (CapabilitySet, error) {
	if err := adapter.ValidateCredential(ctx, binding); err != nil {
		return CapabilitySet{}, err
	}
	capabilities := []Capability{CapabilityHealth, CapabilityOCIPull, CapabilityOCIResolve}
	now := adapter.currentTime()
	return CapabilitySet{SchemaVersion: 1, ProviderVersion: "docker-distribution-v2", Capabilities: capabilities, DiscoveredAt: now, Digest: capabilityDigest(capabilities)}, nil
}

func (adapter *DockerHubAdapter) Health(ctx context.Context, binding ProviderBinding) (ProviderHealth, error) {
	started := adapter.currentTime()
	err := adapter.ValidateCredential(ctx, binding)
	observed := adapter.currentTime()
	capabilities := []Capability{CapabilityHealth, CapabilityOCIPull, CapabilityOCIResolve}
	health := ProviderHealth{BindingID: binding.ID, State: HealthHealthy, Latency: observed.Sub(started), CredentialValid: true,
		CapabilitiesDigest: capabilityDigest(capabilities), RateLimitRemaining: -1, ObservedAt: observed, StaleAfter: observed.Add(5 * time.Minute)}
	if err == nil {
		return health, nil
	}
	health.CredentialValid = false
	health.State = HealthUnavailable
	health.Reason = "docker hub unavailable"
	if errors.Is(err, ErrUnauthorized) {
		health.State = HealthDegraded
		health.Reason = "docker hub credential rejected"
	} else if errors.Is(err, ErrRateLimited) {
		health.State = HealthDegraded
		health.CredentialValid = true
		health.Reason = "docker hub rate limited"
	}
	return health, err
}

func (adapter *DockerHubAdapter) ValidateCredential(ctx context.Context, binding ProviderBinding) error {
	if err := adapter.validateBinding(binding); err != nil {
		return err
	}
	return adapter.withCredential(ctx, binding, func(credential *dockerHubCredential) error {
		response, err := adapter.registryRead(ctx, credential, "dockerhub.validate", "/v2/", "", "application/json", 8<<10)
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(response.body)) != 0 && !bytes.Equal(bytes.TrimSpace(response.body), []byte(`{}`)) {
			return dockerHubProviderError("dockerhub.validate", ErrorPermanent, "invalid_registry_response", ErrIntegrity, 0)
		}
		return nil
	})
}

// Docker Hub has no pull-scoped password-revocation API. The integration
// broker revokes and destroys the enrolled secret; this adapter intentionally
// refuses to invoke account password, token administration, or delete APIs.
func (adapter *DockerHubAdapter) RevokeCredential(_ context.Context, binding ProviderBinding) error {
	return adapter.validateBinding(binding)
}

func (adapter *DockerHubAdapter) Search(ctx context.Context, binding ProviderBinding, query string, page PageRequest) ([]OCIReference, string, error) {
	query = strings.TrimSpace(query)
	if err := adapter.validateBinding(binding); err != nil {
		return nil, "", err
	}
	if page.Validate() != nil || page.Limit > dockerHubMaximumPageSize ||
		len(query) < 2 || len(query) > 128 || strings.ContainsAny(query, "\x00\r\n\t") {
		return nil, "", ErrInvalid
	}
	pageNumber, err := dockerHubPageNumber(page.Cursor)
	if err != nil {
		return nil, "", err
	}
	if err := adapter.withCredential(ctx, binding, func(credential *dockerHubCredential) error {
		response, readErr := adapter.registryRead(ctx, credential, "dockerhub.search_auth", "/v2/", "", "application/json", 8<<10)
		if readErr != nil {
			return readErr
		}
		if len(bytes.TrimSpace(response.body)) != 0 && !bytes.Equal(bytes.TrimSpace(response.body), []byte(`{}`)) {
			return ErrIntegrity
		}
		return nil
	}); err != nil {
		return nil, "", err
	}
	endpoint, _ := url.Parse(dockerHubAPIOrigin + "/v2/search/repositories/")
	values := endpoint.Query()
	values.Set("query", query)
	values.Set("page", strconv.Itoa(pageNumber))
	values.Set("page_size", strconv.Itoa(int(page.Limit)))
	endpoint.RawQuery = values.Encode()
	response, err := adapter.do(ctx, "dockerhub.search", http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	body, err := dockerHubReadResponse(response, "dockerhub.search", dockerHubMaximumJSONBytes, "application/json")
	if err != nil {
		return nil, "", err
	}
	var result dockerHubSearchResponse
	if dockerHubDecodeJSON(body, &result) != nil || result.Count < 0 || len(result.Results) > int(page.Limit) {
		return nil, "", dockerHubProviderError("dockerhub.search", ErrorPermanent, "invalid_json", ErrIntegrity, 0)
	}
	references := make([]OCIReference, 0, len(result.Results))
	seen := make(map[string]struct{}, len(result.Results))
	for _, item := range result.Results {
		repository := item.RepoName
		if repository == "" && item.Namespace != "" && item.Name != "" {
			repository = item.Namespace + "/" + item.Name
		}
		if !strings.Contains(repository, "/") && item.IsOfficial {
			repository = "library/" + repository
		} else if !strings.Contains(repository, "/") && item.Namespace != "" {
			repository = item.Namespace + "/" + repository
		}
		if !validDockerHubRepository(repository) {
			return nil, "", dockerHubProviderError("dockerhub.search", ErrorPermanent, "invalid_repository", ErrIntegrity, 0)
		}
		if _, duplicate := seen[repository]; duplicate {
			return nil, "", dockerHubProviderError("dockerhub.search", ErrorPermanent, "duplicate_repository", ErrIntegrity, 0)
		}
		seen[repository] = struct{}{}
		references = append(references, OCIReference{Registry: "registry-1.docker.io", Repository: repository})
	}
	sort.Slice(references, func(i, j int) bool { return references[i].Repository < references[j].Repository })
	next := ""
	if result.Next != "" {
		if err := validateDockerHubSearchNext(result.Next, query, int(page.Limit), pageNumber+1); err != nil {
			return nil, "", err
		}
		next = strconv.Itoa(pageNumber + 1)
	}
	return references, next, nil
}

func (adapter *DockerHubAdapter) ListTags(ctx context.Context, binding ProviderBinding, repository string, page PageRequest) ([]string, string, error) {
	if err := adapter.validateBinding(binding); err != nil {
		return nil, "", err
	}
	if !validDockerHubRepository(repository) || page.Validate() != nil || page.Limit > dockerHubMaximumPageSize ||
		page.Cursor != "" && !dockerHubTagPattern.MatchString(page.Cursor) {
		return nil, "", ErrInvalid
	}
	var tags []string
	var next string
	err := adapter.withCredential(ctx, binding, func(credential *dockerHubCredential) error {
		path := "/v2/" + escapeDockerHubRepository(repository) + "/tags/list?n=" + strconv.Itoa(int(page.Limit))
		if page.Cursor != "" {
			path += "&last=" + url.QueryEscape(page.Cursor)
		}
		response, readErr := adapter.registryRead(ctx, credential, "dockerhub.list_tags", path, dockerHubPullScope(repository), "application/json", dockerHubMaximumJSONBytes)
		if readErr != nil {
			return readErr
		}
		var document dockerHubTagsResponse
		if dockerHubDecodeJSON(response.body, &document) != nil || document.Name != repository || len(document.Tags) > int(page.Limit) {
			return dockerHubProviderError("dockerhub.list_tags", ErrorPermanent, "invalid_json", ErrIntegrity, 0)
		}
		previous := page.Cursor
		for _, tag := range document.Tags {
			if !dockerHubTagPattern.MatchString(tag) || tag <= previous {
				return dockerHubProviderError("dockerhub.list_tags", ErrorPermanent, "invalid_tag_order", ErrIntegrity, 0)
			}
			previous = tag
		}
		tags = append([]string(nil), document.Tags...)
		link := strings.TrimSpace(response.header.Get("Link"))
		if link != "" {
			cursor, linkErr := validateDockerHubTagLink(link, repository, int(page.Limit), tags)
			if linkErr != nil {
				return linkErr
			}
			next = cursor
		}
		return nil
	})
	return tags, next, err
}

func (adapter *DockerHubAdapter) Resolve(ctx context.Context, binding ProviderBinding, reference OCIReference) (OCIManifest, error) {
	if err := adapter.validateBinding(binding); err != nil {
		return OCIManifest{}, err
	}
	if !validDockerHubReference(reference) {
		return OCIManifest{}, ErrInvalid
	}
	selector := reference.Tag
	if selector == "" {
		selector = reference.Digest
	}
	var manifest OCIManifest
	err := adapter.withCredential(ctx, binding, func(credential *dockerHubCredential) error {
		path := "/v2/" + escapeDockerHubRepository(reference.Repository) + "/manifests/" + url.PathEscape(selector)
		response, readErr := adapter.registryRead(ctx, credential, "dockerhub.resolve", path, dockerHubPullScope(reference.Repository), dockerHubManifestAccept, dockerHubMaximumManifestBytes)
		if readErr != nil {
			return readErr
		}
		digestHeader := response.header.Values("Docker-Content-Digest")
		if len(digestHeader) != 1 || !validDockerHubDigest(digestHeader[0]) {
			return dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "missing_content_digest", ErrIntegrity, 0)
		}
		bodyDigest := sha256.Sum256(response.body)
		resolvedDigest := "sha256:" + hex.EncodeToString(bodyDigest[:])
		if digestHeader[0] != resolvedDigest || reference.Digest != "" && reference.Digest != resolvedDigest {
			return dockerHubProviderError("dockerhub.resolve", ErrorPermanent, "digest_mismatch", ErrIntegrity, 0)
		}
		normalized, normalizeErr := normalizeDockerHubManifest(reference, response.mediaType, response.body, resolvedDigest, adapter.currentTime())
		if normalizeErr != nil {
			return normalizeErr
		}
		manifest = normalized
		return nil
	})
	return manifest, err
}

func (adapter *DockerHubAdapter) AuthorizePull(ctx context.Context, binding ProviderBinding, manifest OCIManifest, subject string, expiresAt time.Time) (string, error) {
	now := adapter.currentTime()
	if err := adapter.validateBinding(binding); err != nil {
		return "", err
	}
	if !validDockerHubManifestEvidence(manifest, now) || !validID(subject) ||
		!expiresAt.After(now.Add(15*time.Second)) || expiresAt.After(now.Add(dockerHubMaximumTokenLifetime)) {
		return "", ErrInvalid
	}
	verified, err := adapter.Resolve(ctx, binding, OCIReference{Registry: "registry-1.docker.io", Repository: manifest.Reference.Repository, Digest: manifest.ResolvedDigest})
	if err != nil {
		return "", err
	}
	if verified.ResolvedDigest != manifest.ResolvedDigest || verified.MediaType != manifest.MediaType {
		return "", dockerHubProviderError("dockerhub.authorize_pull", ErrorPermanent, "manifest_changed", ErrIntegrity, 0)
	}
	var authorization string
	err = adapter.withCredential(ctx, binding, func(credential *dockerHubCredential) error {
		token, tokenErr := adapter.requestToken(ctx, credential, "dockerhub.authorize_pull", manifest.Reference.Repository, subject)
		if tokenErr != nil {
			return tokenErr
		}
		defer token.wipe()
		if token.expiresAt.Before(expiresAt.UTC()) || token.expiresAt.After(now.Add(dockerHubMaximumTokenLifetime)) {
			return dockerHubProviderError("dockerhub.authorize_pull", ErrorPermanent, "invalid_token_lifetime", ErrIntegrity, 0)
		}
		authorization = string(token.value)
		return nil
	})
	return authorization, err
}

type dockerHubCredential struct {
	username []byte
	password []byte
}

func parseDockerHubCredential(material []byte) (*dockerHubCredential, error) {
	if len(material) == 0 || len(material) > dockerHubMaximumSecretBytes || material[0] != '{' {
		return nil, ErrInvalid
	}
	var document struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(bytes.NewReader(material))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(document.Username) == 0 || len(document.Username) > 256 ||
		len(document.Password) == 0 || len(document.Password) > 4096 || strings.TrimSpace(document.Username) != document.Username ||
		strings.ContainsAny(document.Username, ":\x00\r\n\t ") || strings.ContainsAny(document.Password, "\x00\r\n") {
		return nil, ErrInvalid
	}
	return &dockerHubCredential{username: []byte(document.Username), password: []byte(document.Password)}, nil
}

func (credential *dockerHubCredential) wipe() {
	if credential == nil {
		return
	}
	wipeIntegrationSecret(credential.username)
	wipeIntegrationSecret(credential.password)
}

func (credential *dockerHubCredential) basicAuthorization() string {
	raw := make([]byte, 0, len(credential.username)+len(credential.password)+1)
	raw = append(raw, credential.username...)
	raw = append(raw, ':')
	raw = append(raw, credential.password...)
	encoded := base64.StdEncoding.EncodeToString(raw)
	wipeIntegrationSecret(raw)
	return "Basic " + encoded
}

func (adapter *DockerHubAdapter) withCredential(ctx context.Context, binding ProviderBinding, operation func(*dockerHubCredential) error) error {
	material, cleanup, err := adapter.secrets.Read(ctx, binding)
	if err != nil {
		return err
	}
	defer cleanup()
	credential, err := parseDockerHubCredential(material)
	if err != nil {
		return err
	}
	defer credential.wipe()
	return operation(credential)
}

func (adapter *DockerHubAdapter) validateBinding(binding ProviderBinding) error {
	if adapter == nil || adapter.client == nil || binding.Kind != ProviderDockerHub || binding.Purpose != PurposeRegistry || binding.Endpoint.Validate() != nil ||
		!dockerHubEnrolledOrigin(binding.Endpoint.URL) || binding.Endpoint.MaximumRedirects != 0 || !binding.Endpoint.AllowPublicInternet || !binding.Endpoint.DenyPrivateRanges ||
		len(binding.Endpoint.AllowedCIDRs) != 0 || binding.Endpoint.PinnedCARef != "" || binding.Endpoint.PinnedPublicKey != "" {
		return ErrPolicyDenied
	}
	endpoint, _ := url.Parse(binding.Endpoint.URL)
	if binding.Endpoint.ServerName != endpoint.Hostname() {
		return ErrPolicyDenied
	}
	return nil
}

type dockerHubRegistryResponse struct {
	body      []byte
	header    http.Header
	mediaType string
}

func (adapter *DockerHubAdapter) registryRead(ctx context.Context, credential *dockerHubCredential, operation, path, expectedScope, accept string, maximum int64) (dockerHubRegistryResponse, error) {
	endpoint, err := url.Parse(dockerHubRegistryOrigin + path)
	if err != nil || endpoint.Path == "" {
		return dockerHubRegistryResponse{}, ErrInvalid
	}
	headers := make(http.Header)
	headers.Set("Accept", accept)
	response, err := adapter.do(ctx, operation, http.MethodGet, endpoint, headers)
	if err != nil {
		return dockerHubRegistryResponse{}, err
	}
	if response.StatusCode == http.StatusUnauthorized {
		challenge := response.Header.Values("Www-Authenticate")
		dockerHubDiscardResponse(response)
		if len(challenge) != 1 || validateDockerHubBearerChallenge(challenge[0], expectedScope) != nil {
			return dockerHubRegistryResponse{}, dockerHubProviderError(operation, ErrorPermanent, "invalid_auth_challenge", ErrPolicyDenied, 0)
		}
		repository := ""
		if expectedScope != "" {
			repository = strings.TrimSuffix(strings.TrimPrefix(expectedScope, "repository:"), ":pull")
			if dockerHubPullScope(repository) != expectedScope {
				return dockerHubRegistryResponse{}, ErrPolicyDenied
			}
		}
		token, tokenErr := adapter.requestToken(ctx, credential, operation+".token", repository, "")
		if tokenErr != nil {
			return dockerHubRegistryResponse{}, tokenErr
		}
		defer token.wipe()
		headers.Set("Authorization", "Bearer "+string(token.value))
		response, err = adapter.do(ctx, operation, http.MethodGet, endpoint, headers)
		headers.Del("Authorization")
		if err != nil {
			return dockerHubRegistryResponse{}, err
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		statusErr := dockerHubHTTPStatusError(operation, response)
		dockerHubDiscardResponse(response)
		return dockerHubRegistryResponse{}, statusErr
	}
	body, mediaType, err := dockerHubReadTypedResponse(response, operation, maximum, accept)
	if err != nil {
		return dockerHubRegistryResponse{}, err
	}
	return dockerHubRegistryResponse{body: body, header: response.Header.Clone(), mediaType: mediaType}, nil
}

type dockerHubToken struct {
	value     []byte
	expiresAt time.Time
}

func (token *dockerHubToken) wipe() { wipeIntegrationSecret(token.value) }

func (adapter *DockerHubAdapter) requestToken(ctx context.Context, credential *dockerHubCredential, operation, repository, subject string) (dockerHubToken, error) {
	if repository != "" && !validDockerHubRepository(repository) || subject != "" && !validID(subject) {
		return dockerHubToken{}, ErrInvalid
	}
	endpoint, _ := url.Parse(dockerHubAuthOrigin + "/token")
	query := endpoint.Query()
	query.Set("service", dockerHubTokenService)
	query.Set("account", string(credential.username))
	if repository != "" {
		query.Set("scope", dockerHubPullScope(repository))
	}
	if subject != "" {
		query.Set("client_id", subject)
	}
	endpoint.RawQuery = query.Encode()
	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	headers.Set("Authorization", credential.basicAuthorization())
	response, err := adapter.do(ctx, operation, http.MethodGet, endpoint, headers)
	headers.Del("Authorization")
	if err != nil {
		return dockerHubToken{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		statusErr := dockerHubHTTPStatusError(operation, response)
		dockerHubDiscardResponse(response)
		return dockerHubToken{}, statusErr
	}
	body, err := dockerHubReadResponse(response, operation, 64<<10, "application/json")
	if err != nil {
		return dockerHubToken{}, err
	}
	var document struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		IssuedAt    string `json:"issued_at"`
	}
	if dockerHubDecodeJSON(body, &document) != nil || document.Token == "" && document.AccessToken == "" ||
		document.Token != "" && document.AccessToken != "" && document.Token != document.AccessToken || document.ExpiresIn <= 0 ||
		document.ExpiresIn > int64(dockerHubMaximumTokenLifetime/time.Second) {
		return dockerHubToken{}, dockerHubProviderError(operation, ErrorPermanent, "invalid_token", ErrIntegrity, 0)
	}
	value := document.Token
	if value == "" {
		value = document.AccessToken
	}
	if len(value) < 20 || len(value) > 16<<10 || strings.ContainsAny(value, "\x00\r\n\t ") {
		return dockerHubToken{}, dockerHubProviderError(operation, ErrorPermanent, "invalid_token", ErrIntegrity, 0)
	}
	issuedAt := adapter.currentTime()
	if document.IssuedAt != "" {
		parsed, parseErr := time.Parse(time.RFC3339Nano, document.IssuedAt)
		if parseErr != nil || parsed.After(issuedAt.Add(time.Minute)) || parsed.Before(issuedAt.Add(-5*time.Minute)) {
			return dockerHubToken{}, dockerHubProviderError(operation, ErrorPermanent, "invalid_token_time", ErrIntegrity, 0)
		}
		issuedAt = parsed.UTC()
	}
	expiresAt := issuedAt.Add(time.Duration(document.ExpiresIn) * time.Second)
	if !expiresAt.After(adapter.currentTime().Add(15 * time.Second)) {
		return dockerHubToken{}, dockerHubProviderError(operation, ErrorPermanent, "expired_token", ErrIntegrity, 0)
	}
	return dockerHubToken{value: []byte(value), expiresAt: expiresAt}, nil
}

func (adapter *DockerHubAdapter) do(ctx context.Context, operation, method string, endpoint *url.URL, headers http.Header) (*http.Response, error) {
	if endpoint == nil || validateDockerHubOutboundURL(endpoint) != nil || method != http.MethodGet {
		return nil, ErrPolicyDenied
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), nil)
	if err != nil {
		return nil, ErrInvalid
	}
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	response, err := adapter.client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return nil, dockerHubNetworkError(operation, err)
	}
	if response.Request == nil || response.Request.URL.String() != endpoint.String() {
		dockerHubDiscardResponse(response)
		return nil, dockerHubProviderError(operation, ErrorPermanent, "redirect_denied", ErrPolicyDenied, 0)
	}
	return response, nil
}

func newDockerHubHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true, MaxIdleConns: 12, MaxIdleConnsPerHost: 4,
		MaxConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" || !dockerHubAllowedHost(host) || network != "tcp" && network != "tcp4" && network != "tcp6" {
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
				candidate = candidate.Unmap()
				if !publicDockerHubAddress(candidate) {
					return nil, ErrPolicyDenied
				}
			}
			var lastErr error
			for _, candidate := range addresses {
				candidate = candidate.Unmap()
				connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		}}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func publicDockerHubAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range reservedDockerHubPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func dockerHubAllowedHost(host string) bool {
	switch strings.ToLower(strings.TrimSuffix(host, ".")) {
	case "registry-1.docker.io", "auth.docker.io", "hub.docker.com":
		return true
	default:
		return false
	}
}

func dockerHubEnrolledOrigin(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && validateDockerHubOutboundURL(parsed) == nil && (parsed.Path == "" || parsed.Path == "/") && parsed.RawQuery == ""
}

func validateDockerHubOutboundURL(endpoint *url.URL) error {
	if endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Hostname() == "" || endpoint.Port() != "" || !dockerHubAllowedHost(endpoint.Hostname()) ||
		endpoint.Fragment != "" || endpoint.RawPath != "" || !strings.HasPrefix(endpoint.Path, "/") || strings.Contains(endpoint.Path, "\\") {
		return ErrPolicyDenied
	}
	return nil
}

func validDockerHubRepository(repository string) bool {
	if len(repository) < 3 || len(repository) > 255 || strings.ToLower(repository) != repository || strings.HasPrefix(repository, "/") || strings.HasSuffix(repository, "/") {
		return false
	}
	segments := strings.Split(repository, "/")
	if len(segments) < 2 || len(segments) > 8 {
		return false
	}
	for _, segment := range segments {
		if len(segment) > 128 || !dockerHubRepositorySegmentPattern.MatchString(segment) {
			return false
		}
	}
	return true
}

func escapeDockerHubRepository(repository string) string {
	segments := strings.Split(repository, "/")
	for index := range segments {
		segments[index] = url.PathEscape(segments[index])
	}
	return strings.Join(segments, "/")
}

func validDockerHubDigest(digest string) bool {
	return strings.HasPrefix(digest, "sha256:") && validDigest(strings.TrimPrefix(digest, "sha256:"))
}

func validDockerHubReference(reference OCIReference) bool {
	registry := strings.TrimSuffix(strings.ToLower(reference.Registry), "/")
	return (registry == "docker.io" || registry == "registry-1.docker.io") && validDockerHubRepository(reference.Repository) &&
		(reference.Tag != "") != (reference.Digest != "") && (reference.Tag == "" || dockerHubTagPattern.MatchString(reference.Tag)) &&
		(reference.Digest == "" || validDockerHubDigest(reference.Digest))
}

func dockerHubPullScope(repository string) string { return "repository:" + repository + ":pull" }

func dockerHubPageNumber(cursor string) (int, error) {
	if cursor == "" {
		return 1, nil
	}
	if len(cursor) > 5 || cursor[0] == '0' {
		return 0, ErrInvalid
	}
	page, err := strconv.Atoi(cursor)
	if err != nil || page < 2 || page > 10000 {
		return 0, ErrInvalid
	}
	return page, nil
}

type dockerHubSearchResponse struct {
	Count    int                     `json:"count"`
	Next     string                  `json:"next"`
	Previous string                  `json:"previous"`
	Results  []dockerHubSearchResult `json:"results"`
}

type dockerHubSearchResult struct {
	RepoName         string `json:"repo_name"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	RepoOwner        string `json:"repo_owner"`
	ShortDescription string `json:"short_description"`
	StarCount        int64  `json:"star_count"`
	PullCount        int64  `json:"pull_count"`
	IsAutomated      bool   `json:"is_automated"`
	IsOfficial       bool   `json:"is_official"`
	IsPrivate        bool   `json:"is_private"`
	LastUpdated      string `json:"last_updated"`
}

type dockerHubTagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

func validateDockerHubSearchNext(raw, query string, limit, nextPage int) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "hub.docker.com" || parsed.Path != "/v2/search/repositories/" || parsed.Fragment != "" {
		return dockerHubProviderError("dockerhub.search", ErrorPermanent, "invalid_next_page", ErrIntegrity, 0)
	}
	values := parsed.Query()
	if len(values) != 3 || len(values["query"]) != 1 || len(values["page_size"]) != 1 || len(values["page"]) != 1 ||
		values.Get("query") != query || values.Get("page_size") != strconv.Itoa(limit) || values.Get("page") != strconv.Itoa(nextPage) {
		return dockerHubProviderError("dockerhub.search", ErrorPermanent, "invalid_next_page", ErrIntegrity, 0)
	}
	return nil
}

func validateDockerHubTagLink(raw, repository string, limit int, tags []string) (string, error) {
	if !strings.HasSuffix(raw, `; rel="next"`) || len(tags) == 0 {
		return "", dockerHubProviderError("dockerhub.list_tags", ErrorPermanent, "invalid_next_page", ErrIntegrity, 0)
	}
	target := strings.TrimSuffix(raw, `; rel="next"`)
	if len(target) < 3 || target[0] != '<' || target[len(target)-1] != '>' {
		return "", ErrIntegrity
	}
	parsed, err := url.Parse(target[1 : len(target)-1])
	if err != nil {
		return "", ErrIntegrity
	}
	if parsed.IsAbs() {
		if parsed.Scheme != "https" || parsed.Host != "registry-1.docker.io" {
			return "", ErrPolicyDenied
		}
	} else if parsed.Host != "" {
		return "", ErrPolicyDenied
	}
	if parsed.Path != "/v2/"+escapeDockerHubRepository(repository)+"/tags/list" || parsed.Fragment != "" {
		return "", ErrIntegrity
	}
	values := parsed.Query()
	last := values.Get("last")
	if len(values) != 2 || len(values["n"]) != 1 || len(values["last"]) != 1 || values.Get("n") != strconv.Itoa(limit) ||
		last != tags[len(tags)-1] || !dockerHubTagPattern.MatchString(last) {
		return "", ErrIntegrity
	}
	return last, nil
}

func validateDockerHubBearerChallenge(raw, expectedScope string) error {
	if len(raw) > 4096 || len(raw) < 8 || !strings.EqualFold(raw[:7], "Bearer ") {
		return ErrPolicyDenied
	}
	parameters := make(map[string]string)
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw[7:], ",") {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) != 2 || pair[0] == "" || len(pair[1]) < 2 || pair[1][0] != '"' || pair[1][len(pair[1])-1] != '"' || strings.Contains(pair[1][1:len(pair[1])-1], `"`) {
			return ErrPolicyDenied
		}
		key := strings.ToLower(pair[0])
		if key != "realm" && key != "service" && key != "scope" {
			return ErrPolicyDenied
		}
		if _, duplicate := seen[key]; duplicate {
			return ErrPolicyDenied
		}
		seen[key] = struct{}{}
		parameters[key] = pair[1][1 : len(pair[1])-1]
	}
	if parameters["realm"] != dockerHubAuthOrigin+"/token" || parameters["service"] != dockerHubTokenService || parameters["scope"] != expectedScope {
		return ErrPolicyDenied
	}
	return nil
}

func dockerHubDecodeJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func dockerHubReadResponse(response *http.Response, operation string, maximum int64, allowed ...string) ([]byte, error) {
	body, _, err := dockerHubReadTypedResponse(response, operation, maximum, allowed...)
	return body, err
}

func dockerHubReadTypedResponse(response *http.Response, operation string, maximum int64, allowed ...string) ([]byte, string, error) {
	defer response.Body.Close()
	if response.ContentLength > maximum || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, "", dockerHubProviderError(operation, ErrorPermanent, "body_policy", ErrIntegrity, 0)
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return nil, "", dockerHubProviderError(operation, ErrorPermanent, "media_type", ErrIntegrity, 0)
	}
	mediaType, parameters, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" && len(parameters) != 0 ||
		mediaType == "application/json" && len(parameters) != 0 && !(len(parameters) == 1 && strings.EqualFold(parameters["charset"], "utf-8")) {
		return nil, "", dockerHubProviderError(operation, ErrorPermanent, "media_type", ErrIntegrity, 0)
	}
	accepted := false
	for _, value := range allowed {
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimSpace(candidate)
			if mediaType == candidate {
				accepted = true
			}
		}
	}
	if !accepted {
		return nil, "", dockerHubProviderError(operation, ErrorPermanent, "media_type", ErrIntegrity, 0)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, "", dockerHubProviderError(operation, ErrorUnavailable, "body_read", ErrUnavailable, 0)
	}
	if int64(len(body)) > maximum {
		return nil, "", dockerHubProviderError(operation, ErrorPermanent, "body_too_large", ErrIntegrity, 0)
	}
	return body, mediaType, nil
}

func dockerHubDiscardResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
}

func dockerHubHTTPStatusError(operation string, response *http.Response) error {
	retryAfter := dockerHubRetryAfter(response.Header.Get("Retry-After"), time.Now().UTC())
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return dockerHubProviderError(operation, ErrorUnauthorized, "http_401_unauthenticated", ErrUnauthorized, 0)
	case http.StatusForbidden:
		return dockerHubProviderError(operation, ErrorUnauthorized, "http_403_forbidden", ErrUnauthorized, 0)
	case http.StatusTooManyRequests:
		return dockerHubProviderError(operation, ErrorRateLimited, "http_429_rate_limited", ErrRateLimited, retryAfter)
	case http.StatusNotFound:
		return dockerHubProviderError(operation, ErrorPermanent, "http_404_not_found", ErrNotFound, 0)
	}
	if response.StatusCode >= 500 && response.StatusCode <= 599 {
		return dockerHubProviderError(operation, ErrorUnavailable, "http_"+strconv.Itoa(response.StatusCode), ErrUnavailable, retryAfter)
	}
	if response.StatusCode >= 300 && response.StatusCode <= 399 {
		return dockerHubProviderError(operation, ErrorPermanent, "redirect_denied", ErrPolicyDenied, 0)
	}
	if response.StatusCode >= 400 && response.StatusCode <= 499 {
		return dockerHubProviderError(operation, ErrorInvalid, "http_"+strconv.Itoa(response.StatusCode), ErrInvalid, 0)
	}
	return dockerHubProviderError(operation, ErrorPermanent, "unexpected_status", ErrIntegrity, 0)
}

func dockerHubRetryAfter(raw string, now time.Time) time.Duration {
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(raw, 10, 32); err == nil {
		if seconds > uint64((24 * time.Hour) / time.Second) {
			return 24 * time.Hour
		}
		return time.Duration(seconds) * time.Second
	}
	if parsed, err := http.ParseTime(raw); err == nil && parsed.After(now) {
		delay := parsed.Sub(now)
		if delay > 24*time.Hour {
			return 24 * time.Hour
		}
		return delay
	}
	return 0
}

func dockerHubNetworkError(operation string, err error) error {
	if errors.Is(err, ErrPolicyDenied) {
		return dockerHubProviderError(operation, ErrorPermanent, "network_policy", ErrPolicyDenied, 0)
	}
	code := "network"
	if errors.Is(err, context.DeadlineExceeded) {
		code = "timeout"
	}
	return dockerHubProviderError(operation, ErrorUnavailable, code, ErrUnavailable, 0)
}

func dockerHubProviderError(operation string, class ErrorClass, code string, cause error, retryAfter time.Duration) error {
	return &ProviderError{Class: class, Operation: operation, Code: code, RetryAfter: retryAfter, Cause: cause}
}

var _ Provider = (*DockerHubAdapter)(nil)
var _ DockerHubProvider = (*DockerHubAdapter)(nil)
