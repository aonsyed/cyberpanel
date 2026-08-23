//go:build linux

package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	cloudflareAPIEndpoint       = "https://api.cloudflare.com"
	cloudflareResponseBodyLimit = 2 << 20
	cloudflareRequestBodyLimit  = 64 << 10
	cloudflareMaximumPage       = 1_000_000
	cloudflareObservePageSize   = 100
	cloudflareObservePages      = 10
)

type cloudflareAPIError struct {
	Code int `json:"code"`
}

type cloudflareResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

type cloudflareAPIEnvelope struct {
	Success    bool                 `json:"success"`
	Errors     []cloudflareAPIError `json:"errors"`
	Result     json.RawMessage      `json:"result"`
	ResultInfo cloudflareResultInfo `json:"result_info"`
}

type cloudflareZoneResult struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Paused     bool   `json:"paused"`
	ModifiedOn string `json:"modified_on"`
}

type cloudflareRecordResult struct {
	ID         string  `json:"id"`
	ZoneID     string  `json:"zone_id"`
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Content    string  `json:"content"`
	TTL        uint32  `json:"ttl"`
	Priority   *uint16 `json:"priority,omitempty"`
	Proxied    bool    `json:"proxied"`
	ModifiedOn string  `json:"modified_on"`
}

type cloudflareRecordWrite struct {
	Type     RRType  `json:"type"`
	Name     string  `json:"name"`
	Content  string  `json:"content"`
	TTL      uint32  `json:"ttl"`
	Priority *uint16 `json:"priority,omitempty"`
	Proxied  bool    `json:"proxied"`
}

type cloudflareRecordMarker struct {
	ID         string `json:"id"`
	ModifiedOn string `json:"modified_on"`
}

type cloudflareReceiptPayload struct {
	Version        uint8    `json:"version"`
	Kind           string   `json:"kind"`
	BindingID      string   `json:"binding_id"`
	EffectID       string   `json:"effect_id"`
	ZoneID         string   `json:"zone_id"`
	Owner          string   `json:"owner"`
	Type           RRType   `json:"type"`
	RecordIDs      []string `json:"record_ids"`
	BeforeDigest   string   `json:"before_digest,omitempty"`
	OutputDigest   string   `json:"output_digest"`
	Revision       string   `json:"revision"`
	AppliedAt      string   `json:"applied_at"`
	ChallengeUntil string   `json:"challenge_until,omitempty"`
}

func validateCloudflareEndpointPolicy(endpoint EndpointPolicy) error {
	if endpoint.URL != cloudflareAPIEndpoint || endpoint.ServerName != "api.cloudflare.com" || endpoint.MaximumRedirects != 0 || !endpoint.AllowPublicInternet || !endpoint.DenyPrivateRanges {
		return ErrPolicyDenied
	}
	return nil
}

func (adapter *RemoteProviderAdapter) cloudflareReady(ctx context.Context, binding ProviderBinding) error {
	if ctx == nil || adapter == nil || adapter.Kind != ProviderCloudflare || adapter.Client == nil || binding.Kind != ProviderCloudflare {
		return ErrInvalid
	}
	if binding.Validate() != nil || validateCloudflareEndpointPolicy(binding.Endpoint) != nil {
		return ErrPolicyDenied
	}
	return nil
}

func (adapter *RemoteProviderAdapter) cloudflareAccess(ctx context.Context, binding ProviderBinding) (string, func(), error) {
	if err := adapter.cloudflareReady(ctx, binding); err != nil {
		return "", func() {}, err
	}
	material, cleanup, err := adapter.Secrets.Read(ctx, binding)
	if err != nil {
		return "", func() {}, err
	}
	token, err := cloudflareCredential(material)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return token, cleanup, nil
}

func cloudflareNoRedirectClient(client *http.Client) *http.Client {
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copy
}

func (adapter *RemoteProviderAdapter) cloudflareRequest(ctx context.Context, token, operation, method, path string, query url.Values, body any, target any, mutation bool) (cloudflareResultInfo, error) {
	if ctx == nil || token == "" || !strings.HasPrefix(path, "/client/v4/") || strings.ContainsAny(path, "?#\x00\r\n") {
		return cloudflareResultInfo{}, ErrInvalid
	}
	endpoint, err := url.Parse(cloudflareAPIEndpoint + path)
	if err != nil {
		return cloudflareResultInfo{}, ErrIntegrity
	}
	endpoint.RawQuery = query.Encode()
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil || len(payload) == 0 || len(payload) > cloudflareRequestBodyLimit {
			return cloudflareResultInfo{}, ErrInvalid
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return cloudflareResultInfo{}, ErrInvalid
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := cloudflareNoRedirectClient(adapter.Client).Do(request)
	if err != nil {
		return cloudflareResultInfo{}, cloudflareTransportError(operation, mutation, err)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, cloudflareResponseBodyLimit+1))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return cloudflareResultInfo{}, cloudflareStatusError(operation, response.StatusCode, response.Header)
	}
	if readErr != nil || len(raw) == 0 || len(raw) > cloudflareResponseBodyLimit {
		return cloudflareResultInfo{}, cloudflareMalformedResponse(operation, mutation, "response_body")
	}
	var envelope cloudflareAPIEnvelope
	if json.Unmarshal(raw, &envelope) != nil {
		return cloudflareResultInfo{}, cloudflareMalformedResponse(operation, mutation, "response_json")
	}
	if !envelope.Success || len(envelope.Errors) != 0 {
		return cloudflareResultInfo{}, cloudflareEnvelopeError(operation, envelope.Errors)
	}
	if target != nil {
		if len(envelope.Result) == 0 || bytes.Equal(envelope.Result, []byte("null")) || json.Unmarshal(envelope.Result, target) != nil {
			return cloudflareResultInfo{}, cloudflareMalformedResponse(operation, mutation, "result_json")
		}
	}
	return envelope.ResultInfo, nil
}

func cloudflareTransportError(operation string, mutation bool, err error) error {
	class, code, cause := ErrorUnavailable, "network", ErrUnavailable
	if mutation {
		class, code, cause = ErrorAmbiguous, "network_after_send", ErrAmbiguous
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = "timeout"
	}
	return &ProviderError{Class: class, Operation: operation, Code: code, Cause: cause}
}

func cloudflareMalformedResponse(operation string, mutation bool, code string) error {
	if mutation {
		return &ProviderError{Class: ErrorAmbiguous, Operation: operation, Code: code, Cause: ErrAmbiguous}
	}
	return &ProviderError{Class: ErrorUnavailable, Operation: operation, Code: code, Cause: ErrIntegrity}
}

func cloudflareStatusError(operation string, status int, header http.Header) error {
	providerError := &ProviderError{Operation: operation}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		providerError.Class, providerError.Code, providerError.Cause = ErrorUnauthorized, "credential_rejected", ErrUnauthorized
	case status == http.StatusTooManyRequests:
		providerError.Class, providerError.Code, providerError.Cause = ErrorRateLimited, "rate_limited", ErrRateLimited
		providerError.RetryAfter = cloudflareRetryAfter(header.Get("Retry-After"), time.Now().UTC())
	case status == http.StatusNotFound || status == http.StatusConflict:
		providerError.Class, providerError.Code, providerError.Cause = ErrorConflict, "not_found_or_conflict", ErrConflict
	case status == http.StatusBadRequest || status == http.StatusMethodNotAllowed || status == http.StatusUnprocessableEntity:
		providerError.Class, providerError.Code, providerError.Cause = ErrorInvalid, "request_rejected", ErrInvalid
	case status >= 300 && status < 400:
		providerError.Class, providerError.Code, providerError.Cause = ErrorPermanent, "redirect_refused", ErrPolicyDenied
	case status >= 500:
		providerError.Class, providerError.Code, providerError.Cause = ErrorUnavailable, "provider_unavailable", ErrUnavailable
	default:
		providerError.Class, providerError.Code, providerError.Cause = ErrorPermanent, "provider_rejected", ErrUnavailable
	}
	return providerError
}

func cloudflareEnvelopeError(operation string, values []cloudflareAPIError) error {
	class, code, cause := ErrorPermanent, "provider_rejected", ErrUnavailable
	if len(values) > 0 {
		switch values[0].Code {
		case 9103, 9109, 10000:
			class, code, cause = ErrorUnauthorized, "credential_rejected", ErrUnauthorized
		case 1015:
			class, code, cause = ErrorRateLimited, "rate_limited", ErrRateLimited
		}
	}
	return &ProviderError{Class: class, Operation: operation, Code: code, Cause: cause}
}

func cloudflareRetryAfter(raw string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if value, err := http.ParseTime(raw); err == nil && value.After(now) {
		return value.Sub(now)
	}
	return 0
}

func cloudflarePage(page PageRequest, maximum uint16) (int, uint16, error) {
	if err := page.Validate(); err != nil {
		return 0, 0, err
	}
	current := 1
	if page.Cursor != "" {
		value, err := strconv.ParseUint(page.Cursor, 10, 32)
		if err != nil || value == 0 || value > cloudflareMaximumPage || strconv.FormatUint(value, 10) != page.Cursor {
			return 0, 0, ErrInvalid
		}
		current = int(value)
	}
	limit := page.Limit
	if limit > maximum {
		limit = maximum
	}
	return current, limit, nil
}

func cloudflareNextPage(info cloudflareResultInfo, current int, count, perPage int) string {
	if info.TotalPages > current || info.TotalPages == 0 && count == perPage {
		return strconv.Itoa(current + 1)
	}
	return ""
}

func (adapter *RemoteProviderAdapter) ListZones(ctx context.Context, binding ProviderBinding, page PageRequest) ([]CloudflareZone, string, error) {
	current, perPage, err := cloudflarePage(page, 50)
	if err != nil {
		return nil, "", err
	}
	token, cleanup, err := adapter.cloudflareAccess(ctx, binding)
	if err != nil {
		return nil, "", err
	}
	defer cleanup()
	query := url.Values{"page": {strconv.Itoa(current)}, "per_page": {strconv.Itoa(int(perPage))}}
	var raw []cloudflareZoneResult
	info, err := adapter.cloudflareRequest(ctx, token, "cloudflare.list_zones", http.MethodGet, "/client/v4/zones", query, nil, &raw, false)
	if err != nil {
		return nil, "", err
	}
	if len(raw) > int(perPage) {
		return nil, "", ErrIntegrity
	}
	observedAt := adapter.now()
	result := make([]CloudflareZone, 0, len(raw))
	for _, zone := range raw {
		name, nameErr := cloudflareName(zone.Name)
		if !validID(zone.ID) || nameErr != nil || zone.Status == "" || len(zone.Status) > 64 {
			return nil, "", ErrIntegrity
		}
		revision := cloudflareHash(struct {
			Version    uint8  `json:"version"`
			ID         string `json:"id"`
			Name       string `json:"name"`
			Status     string `json:"status"`
			Paused     bool   `json:"paused"`
			ModifiedOn string `json:"modified_on"`
		}{1, zone.ID, name, zone.Status, zone.Paused, zone.ModifiedOn})
		result = append(result, CloudflareZone{ID: zone.ID, Name: name, Status: zone.Status, Paused: zone.Paused, Revision: revision, ObservedAt: observedAt})
	}
	sort.Slice(result, func(i, j int) bool { if result[i].Name == result[j].Name { return result[i].ID < result[j].ID }; return result[i].Name < result[j].Name })
	return result, cloudflareNextPage(info, current, len(raw), int(perPage)), nil
}

func (adapter *RemoteProviderAdapter) ListRRsets(ctx context.Context, binding ProviderBinding, zoneID string, page PageRequest) ([]CloudflareRRSet, string, error) {
	if !validID(zoneID) {
		return nil, "", ErrInvalid
	}
	current, perPage, err := cloudflarePage(page, 1000)
	if err != nil {
		return nil, "", err
	}
	token, cleanup, err := adapter.cloudflareAccess(ctx, binding)
	if err != nil {
		return nil, "", err
	}
	defer cleanup()
	query := url.Values{"page": {strconv.Itoa(current)}, "per_page": {strconv.Itoa(int(perPage))}}
	var raw []cloudflareRecordResult
	info, err := adapter.cloudflareRequest(ctx, token, "cloudflare.list_rrsets", http.MethodGet, "/client/v4/zones/"+url.PathEscape(zoneID)+"/dns_records", query, nil, &raw, false)
	if err != nil {
		return nil, "", err
	}
	if len(raw) > int(perPage) {
		return nil, "", ErrIntegrity
	}
	sets, err := cloudflareGroupRecords(zoneID, raw)
	if err != nil {
		return nil, "", err
	}
	return sets, cloudflareNextPage(info, current, len(raw), int(perPage)), nil
}

func (adapter *RemoteProviderAdapter) ObserveRRSet(ctx context.Context, binding ProviderBinding, zoneID, owner string, recordType RRType) (*CloudflareRRSet, error) {
	if !validID(zoneID) || !cloudflareRRType(recordType) {
		return nil, ErrInvalid
	}
	canonicalOwner, err := cloudflareName(owner)
	if err != nil {
		return nil, err
	}
	token, cleanup, err := adapter.cloudflareAccess(ctx, binding)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return adapter.cloudflareObserveWithToken(ctx, token, zoneID, canonicalOwner, recordType)
}

func (adapter *RemoteProviderAdapter) cloudflareObserveWithToken(ctx context.Context, token, zoneID, owner string, recordType RRType) (*CloudflareRRSet, error) {
	records := make([]cloudflareRecordResult, 0)
	for page := 1; page <= cloudflareObservePages; page++ {
		query := url.Values{"name": {owner}, "type": {string(recordType)}, "match": {"all"}, "page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(cloudflareObservePageSize)}}
		var raw []cloudflareRecordResult
		info, err := adapter.cloudflareRequest(ctx, token, "cloudflare.observe_rrset", http.MethodGet, "/client/v4/zones/"+url.PathEscape(zoneID)+"/dns_records", query, nil, &raw, false)
		if err != nil {
			return nil, err
		}
		if len(raw) > cloudflareObservePageSize {
			return nil, ErrIntegrity
		}
		for _, record := range raw {
			name, nameErr := cloudflareName(record.Name)
			if nameErr != nil {
				return nil, ErrIntegrity
			}
			if name == owner && strings.EqualFold(record.Type, string(recordType)) {
				records = append(records, record)
			}
		}
		if info.TotalPages > cloudflareObservePages || len(records) > cloudflareObservePageSize*cloudflareObservePages {
			return nil, &ProviderError{Class: ErrorPermanent, Operation: "cloudflare.observe_rrset", Code: "result_limit", Cause: ErrPolicyDenied}
		}
		if info.TotalPages > 0 && page >= info.TotalPages || info.TotalPages == 0 && len(raw) < cloudflareObservePageSize {
			break
		}
		if page == cloudflareObservePages {
			return nil, &ProviderError{Class: ErrorPermanent, Operation: "cloudflare.observe_rrset", Code: "page_limit", Cause: ErrPolicyDenied}
		}
	}
	sets, err := cloudflareGroupRecords(zoneID, records)
	if err != nil {
		return nil, err
	}
	if len(sets) == 0 {
		return nil, nil
	}
	if len(sets) != 1 || sets[0].Owner != owner || sets[0].Type != recordType {
		return nil, ErrIntegrity
	}
	return &sets[0], nil
}

func cloudflareGroupRecords(zoneID string, records []cloudflareRecordResult) ([]CloudflareRRSet, error) {
	type accumulator struct {
		set     CloudflareRRSet
		values  map[string]struct{}
		ids     map[string]struct{}
		markers []cloudflareRecordMarker
	}
	groups := map[string]*accumulator{}
	for _, record := range records {
		owner, err := cloudflareName(record.Name)
		recordType := RRType(strings.ToUpper(record.Type))
		value, valueErr := cloudflareValue(recordType, record.Content)
		if err != nil || valueErr != nil || !validID(record.ID) || record.ZoneID != "" && record.ZoneID != zoneID || !cloudflareRRType(recordType) || record.TTL != 1 && record.TTL < 60 {
			return nil, ErrIntegrity
		}
		if record.Proxied && !cloudflareProxyType(recordType) {
			return nil, ErrIntegrity
		}
		key := owner + "\x00" + string(recordType)
		group := groups[key]
		if group == nil {
			group = &accumulator{set: CloudflareRRSet{ZoneID: zoneID, Owner: owner, Type: recordType, TTL: record.TTL, Priority: cloneUint16(record.Priority), Proxied: record.Proxied}, values: map[string]struct{}{}, ids: map[string]struct{}{}}
			groups[key] = group
		} else if group.set.TTL != record.TTL || group.set.Proxied != record.Proxied || !sameUint16(group.set.Priority, record.Priority) {
			return nil, ErrIntegrity
		}
		group.values[value] = struct{}{}
		if _, exists := group.ids[record.ID]; exists {
			return nil, ErrIntegrity
		}
		group.ids[record.ID] = struct{}{}
		group.markers = append(group.markers, cloudflareRecordMarker{ID: record.ID, ModifiedOn: record.ModifiedOn})
	}
	result := make([]CloudflareRRSet, 0, len(groups))
	for _, group := range groups {
		for value := range group.values {
			group.set.Values = append(group.set.Values, value)
		}
		for id := range group.ids {
			group.set.ProviderIDs = append(group.set.ProviderIDs, id)
		}
		sort.Strings(group.set.Values)
		sort.Strings(group.set.ProviderIDs)
		sort.Slice(group.markers, func(i, j int) bool { return group.markers[i].ID < group.markers[j].ID })
		group.set.Revision = cloudflareHash(struct {
			Version uint8                     `json:"version"`
			Records []cloudflareRecordMarker `json:"records"`
		}{1, group.markers})
		group.set.Digest = cloudflareRRSetDigest(group.set)
		if group.set.Validate() != nil {
			return nil, ErrIntegrity
		}
		result = append(result, group.set)
	}
	sort.Slice(result, func(i, j int) bool { if result[i].Owner == result[j].Owner { return result[i].Type < result[j].Type }; return result[i].Owner < result[j].Owner })
	return result, nil
}

func cloudflareRRSetDigest(set CloudflareRRSet) string {
	values := append([]string(nil), set.Values...)
	providerIDs := append([]string(nil), set.ProviderIDs...)
	sort.Strings(values)
	sort.Strings(providerIDs)
	return cloudflareHash(struct {
		Version     uint8    `json:"version"`
		ZoneID      string   `json:"zone_id"`
		Owner       string   `json:"owner"`
		Type        RRType   `json:"type"`
		TTL         uint32   `json:"ttl"`
		Values      []string `json:"values"`
		Priority    *uint16  `json:"priority,omitempty"`
		Proxied     bool     `json:"proxied"`
		ProviderIDs []string `json:"provider_ids"`
		Revision    string   `json:"revision"`
	}{1, set.ZoneID, set.Owner, set.Type, set.TTL, values, set.Priority, set.Proxied, providerIDs, set.Revision})
}

func cloudflareAbsentDigest() string {
	sum := sha256.Sum256([]byte("cloudflare.rrset.absent.v1"))
	return hex.EncodeToString(sum[:])
}

func cloudflareHash(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func cloudflareName(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00\r\n\t /?#\\") {
		return "", ErrInvalid
	}
	value := strings.ToLower(strings.TrimSuffix(raw, "."))
	if value == "" || len(value) > 253 || strings.Contains(value, "..") {
		return "", ErrInvalid
	}
	for index, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || strings.Contains(label, "*") && !(index == 0 && label == "*") {
			return "", ErrInvalid
		}
	}
	return value, nil
}

func cloudflareValue(recordType RRType, raw string) (string, error) {
	if raw == "" || len(raw) > 65535 || strings.ContainsRune(raw, '\x00') {
		return "", ErrInvalid
	}
	switch recordType {
	case RRTypeA, RRTypeAAAA:
		address, err := netip.ParseAddr(raw)
		if err != nil || recordType == RRTypeA && !address.Is4() || recordType == RRTypeAAAA && !address.Is6() {
			return "", ErrInvalid
		}
		return address.String(), nil
	case RRTypeCNAME, RRTypeMX, RRTypeNS:
		return cloudflareName(raw)
	case RRTypeTXT, RRTypeSRV, RRTypeCAA, RRTypeHTTPS, RRTypeSVCB:
		if raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\r\n") {
			return "", ErrInvalid
		}
		return raw, nil
	default:
		return "", ErrUnsupported
	}
}

func cloudflareRRType(recordType RRType) bool {
	switch recordType {
	case RRTypeA, RRTypeAAAA, RRTypeCNAME, RRTypeTXT, RRTypeMX, RRTypeSRV, RRTypeCAA, RRTypeNS, RRTypeHTTPS, RRTypeSVCB:
		return true
	default:
		return false
	}
}

func cloudflareProxyType(recordType RRType) bool {
	return recordType == RRTypeA || recordType == RRTypeAAAA || recordType == RRTypeCNAME
}

func cloneUint16(value *uint16) *uint16 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func sameUint16(left, right *uint16) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func cloudflareCanonicalInput(set CloudflareRRSet, requireExact bool) (CloudflareRRSet, error) {
	if set.Validate() != nil || !cloudflareRRType(set.Type) || set.TTL > 2147483647 || set.Proxied && set.TTL != 1 {
		return CloudflareRRSet{}, ErrInvalid
	}
	owner, err := cloudflareName(set.Owner)
	if err != nil || owner != set.Owner {
		return CloudflareRRSet{}, ErrInvalid
	}
	canonical := set
	canonical.Values = make([]string, 0, len(set.Values))
	for _, raw := range set.Values {
		value, valueErr := cloudflareValue(set.Type, raw)
		if valueErr != nil || value != raw {
			return CloudflareRRSet{}, ErrInvalid
		}
		canonical.Values = append(canonical.Values, value)
	}
	if len(canonical.Values) > 1000 || set.Type == RRTypeMX && set.Priority == nil || set.Type != RRTypeMX && set.Priority != nil {
		return CloudflareRRSet{}, ErrInvalid
	}
	sort.Strings(canonical.Values)
	for index := 1; index < len(canonical.Values); index++ {
		if canonical.Values[index] == canonical.Values[index-1] {
			return CloudflareRRSet{}, ErrInvalid
		}
	}
	canonical.ProviderIDs = append([]string(nil), set.ProviderIDs...)
	sort.Strings(canonical.ProviderIDs)
	for index, id := range canonical.ProviderIDs {
		if !validID(id) || index > 0 && id == canonical.ProviderIDs[index-1] {
			return CloudflareRRSet{}, ErrInvalid
		}
	}
	if requireExact && (canonical.Revision == "" || len(canonical.ProviderIDs) == 0 || canonical.Digest != cloudflareRRSetDigest(canonical)) {
		return CloudflareRRSet{}, ErrIntegrity
	}
	return canonical, nil
}

func (adapter *RemoteProviderAdapter) DryRun(ctx context.Context, binding ProviderBinding, change CloudflareChange) error {
	if err := adapter.cloudflareReady(ctx, binding); err != nil {
		return err
	}
	if binding.State != BindingActive || change.Binding.BindingID != binding.ID || change.Effect.BindingID != binding.ID || !validID(string(change.Effect.ID)) {
		return ErrPolicyDenied
	}
	if err := change.Binding.Validate(binding.Capabilities); err != nil {
		return err
	}
	if change.Binding.Concurrency != ConcurrencyObserveApply {
		return ErrUnsupported
	}
	if change.Binding.InitialImportOnly || change.Binding.AccountID != "" && !validID(change.Binding.AccountID) {
		return ErrPolicyDenied
	}
	var before, desired *CloudflareRRSet
	if change.Before != nil {
		value, err := cloudflareCanonicalInput(*change.Before, true)
		if err != nil {
			return err
		}
		before = &value
	}
	if change.Desired != nil {
		value, err := cloudflareCanonicalInput(*change.Desired, false)
		if err != nil {
			return err
		}
		desired = &value
	}
	target := desired
	if target == nil {
		target = before
	}
	if target == nil || !cloudflareZoneAllowed(change.Binding.ZoneIDs, target.ZoneID) {
		return ErrPolicyDenied
	}
	if before != nil && desired != nil && (before.ZoneID != desired.ZoneID || before.Owner != desired.Owner || before.Type != desired.Type) {
		return ErrInvalid
	}
	if change.ExpectedRevision != "" && before != nil && change.ExpectedRevision != before.Revision {
		return ErrConflict
	}
	switch change.Kind {
	case DNSCreate:
		if before != nil || desired == nil || len(desired.ProviderIDs) != 0 || desired.Revision != "" {
			return ErrInvalid
		}
	case DNSReplace:
		if before == nil || desired == nil {
			return ErrInvalid
		}
	case DNSDelete:
		if before == nil || desired != nil {
			return ErrInvalid
		}
	case DNSSetProxy:
		if before == nil || desired == nil || !cloudflareProxyType(desired.Type) || before.Proxied == desired.Proxied || before.Priority != nil || desired.Priority != nil || strings.Join(before.Values, "\x00") != strings.Join(desired.Values, "\x00") {
			return ErrInvalid
		}
	default:
		return ErrUnsupported
	}
	return nil
}

func cloudflareZoneAllowed(allowed []string, zoneID string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, value := range allowed {
		if value == zoneID {
			return true
		}
	}
	return false
}

func (adapter *RemoteProviderAdapter) Apply(ctx context.Context, binding ProviderBinding, change CloudflareChange) (DNSApplyReceipt, error) {
	if err := adapter.DryRun(ctx, binding, change); err != nil {
		return DNSApplyReceipt{}, err
	}
	token, cleanup, err := adapter.cloudflareAccess(ctx, binding)
	if err != nil {
		return DNSApplyReceipt{}, err
	}
	defer cleanup()
	target := change.Desired
	if target == nil {
		target = change.Before
	}
	beforeDigest := cloudflareAbsentDigest()
	if change.Before != nil {
		beforeDigest = change.Before.Digest
	}
	result, recordIDs, err := adapter.cloudflareApplyChange(ctx, token, change)
	if err != nil {
		return DNSApplyReceipt{}, err
	}
	appliedAt := adapter.now()
	outputDigest, revision := cloudflareAbsentDigest(), cloudflareHash(struct { Version uint8 `json:"version"`; EffectID EffectID `json:"effect_id"`; AppliedAt string `json:"applied_at"` }{1, change.Effect.ID, appliedAt.Format(time.RFC3339Nano)})
	if change.Desired != nil {
		sets, groupErr := cloudflareGroupRecords(target.ZoneID, result)
		if groupErr != nil || len(sets) != 1 {
			return DNSApplyReceipt{}, cloudflareMalformedResponse("cloudflare.apply_rrset", true, "mutation_result")
		}
		outputDigest, revision = sets[0].Digest, sets[0].Revision
	}
	payload := cloudflareReceiptPayload{Version: 1, Kind: "rrset_apply", BindingID: string(binding.ID), EffectID: string(change.Effect.ID), ZoneID: target.ZoneID, Owner: target.Owner, Type: target.Type, RecordIDs: recordIDs, BeforeDigest: beforeDigest, OutputDigest: outputDigest, Revision: revision, AppliedAt: appliedAt.Format(time.RFC3339Nano)}
	providerReceipt, err := cloudflareSignReceipt(token, payload)
	if err != nil {
		return DNSApplyReceipt{}, ErrIntegrity
	}
	return DNSApplyReceipt{EffectID: change.Effect.ID, BeforeDigest: beforeDigest, OutputDigest: outputDigest, ProviderRevision: revision, ProviderReceipt: providerReceipt, AppliedAt: appliedAt}, nil
}

func (adapter *RemoteProviderAdapter) cloudflareApplyChange(ctx context.Context, token string, change CloudflareChange) ([]cloudflareRecordResult, []string, error) {
	zoneID := ""
	if change.Desired != nil {
		zoneID = change.Desired.ZoneID
	} else {
		zoneID = change.Before.ZoneID
	}
	existing := []string{}
	if change.Before != nil {
		existing = append(existing, change.Before.ProviderIDs...)
		sort.Strings(existing)
	}
	values := []string{}
	if change.Desired != nil {
		values = append(values, change.Desired.Values...)
		sort.Strings(values)
	}
	results := make([]cloudflareRecordResult, 0, len(values))
	completed := make([]string, 0, len(existing)+len(values))
	fail := func(err error) ([]cloudflareRecordResult, []string, error) {
		if len(completed) == 0 {
			return nil, nil, err
		}
		target := change.Desired
		if target == nil {
			target = change.Before
		}
		now := adapter.now()
		partialDigest := cloudflareHash(struct { Version uint8 `json:"version"`; RecordIDs []string `json:"record_ids"` }{1, completed})
		partialPayload := cloudflareReceiptPayload{Version: 1, Kind: "rrset_partial", BindingID: string(change.Binding.BindingID), EffectID: string(change.Effect.ID), ZoneID: zoneID, Owner: target.Owner, Type: target.Type, RecordIDs: append([]string(nil), completed...), OutputDigest: partialDigest, Revision: partialDigest, AppliedAt: now.Format(time.RFC3339Nano)}
		partialReceipt, _ := cloudflareSignReceipt(token, partialPayload)
		return nil, nil, &ProviderError{Class: ErrorPartial, Operation: "cloudflare.apply_rrset", Code: "partial_apply", PartialReceipt: partialReceipt, Cause: ErrPartial}
	}
	common := len(existing)
	if len(values) < common {
		common = len(values)
	}
	for index := 0; index < common; index++ {
		write := cloudflareWrite(*change.Desired, values[index])
		var record cloudflareRecordResult
		_, err := adapter.cloudflareRequest(ctx, token, "cloudflare.update_record", http.MethodPut, "/client/v4/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(existing[index]), nil, write, &record, true)
		if err != nil {
			return fail(err)
		}
		if !validID(record.ID) || record.ID != existing[index] {
			return fail(cloudflareMalformedResponse("cloudflare.update_record", true, "record_id"))
		}
		results, completed = append(results, record), append(completed, record.ID)
	}
	for index := common; index < len(values); index++ {
		write := cloudflareWrite(*change.Desired, values[index])
		var record cloudflareRecordResult
		_, err := adapter.cloudflareRequest(ctx, token, "cloudflare.create_record", http.MethodPost, "/client/v4/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, write, &record, true)
		if err != nil {
			return fail(err)
		}
		if !validID(record.ID) {
			return fail(cloudflareMalformedResponse("cloudflare.create_record", true, "record_id"))
		}
		results, completed = append(results, record), append(completed, record.ID)
	}
	for index := common; index < len(existing); index++ {
		var deleted struct { ID string `json:"id"` }
		_, err := adapter.cloudflareRequest(ctx, token, "cloudflare.delete_record", http.MethodDelete, "/client/v4/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(existing[index]), nil, nil, &deleted, true)
		if err != nil {
			return fail(err)
		}
		if deleted.ID != "" && deleted.ID != existing[index] {
			return fail(ErrIntegrity)
		}
		completed = append(completed, existing[index])
	}
	recordIDs := make([]string, 0, len(results))
	for _, record := range results {
		if !validID(record.ID) {
			return nil, nil, cloudflareMalformedResponse("cloudflare.apply_rrset", true, "record_id")
		}
		recordIDs = append(recordIDs, record.ID)
	}
	if change.Desired == nil {
		recordIDs = append(recordIDs, existing...)
	}
	sort.Strings(recordIDs)
	return results, recordIDs, nil
}

func cloudflareWrite(set CloudflareRRSet, value string) cloudflareRecordWrite {
	return cloudflareRecordWrite{Type: set.Type, Name: set.Owner, Content: value, TTL: set.TTL, Priority: cloneUint16(set.Priority), Proxied: set.Proxied}
}

func (adapter *RemoteProviderAdapter) ApplyConditional(context.Context, ProviderBinding, CloudflareChange) (DNSApplyReceipt, error) {
	return DNSApplyReceipt{}, ErrUnsupported
}

func (adapter *RemoteProviderAdapter) CompensateConditional(context.Context, ProviderBinding, CloudflareChange, DNSApplyReceipt) (DNSApplyReceipt, error) {
	return DNSApplyReceipt{}, ErrUnsupported
}

func (adapter *RemoteProviderAdapter) PresentDNSChallenge(ctx context.Context, binding ProviderBinding, zoneID, owner, value string, expiresAt time.Time) (DNSApplyReceipt, error) {
	canonicalOwner, err := cloudflareName(owner)
	if !validID(zoneID) || err != nil || value == "" || len(value) > 4096 || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\x00\r\n") || !expiresAt.After(adapter.now()) || expiresAt.After(adapter.now().Add(30*24*time.Hour)) {
		return DNSApplyReceipt{}, ErrInvalid
	}
	if binding.State != BindingActive {
		return DNSApplyReceipt{}, ErrPolicyDenied
	}
	token, cleanup, err := adapter.cloudflareAccess(ctx, binding)
	if err != nil {
		return DNSApplyReceipt{}, err
	}
	defer cleanup()
	before, err := adapter.cloudflareObserveWithToken(ctx, token, zoneID, canonicalOwner, RRTypeTXT)
	if err != nil {
		return DNSApplyReceipt{}, err
	}
	beforeDigest := cloudflareAbsentDigest()
	if before != nil {
		beforeDigest = before.Digest
	}
	var created cloudflareRecordResult
	write := cloudflareRecordWrite{Type: RRTypeTXT, Name: canonicalOwner, Content: value, TTL: 60, Proxied: false}
	_, err = adapter.cloudflareRequest(ctx, token, "cloudflare.present_dns01", http.MethodPost, "/client/v4/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, write, &created, true)
	if err != nil {
		return DNSApplyReceipt{}, err
	}
	if !validID(created.ID) {
		return DNSApplyReceipt{}, cloudflareMalformedResponse("cloudflare.present_dns01", true, "record_id")
	}
	after, observeErr := adapter.cloudflareObserveWithToken(ctx, token, zoneID, canonicalOwner, RRTypeTXT)
	if observeErr != nil || after == nil {
		return DNSApplyReceipt{}, &ProviderError{Class: ErrorAmbiguous, Operation: "cloudflare.present_dns01", Code: "post_observation", PartialReceipt: created.ID, Cause: ErrAmbiguous}
	}
	appliedAt := adapter.now()
	sum := sha256.Sum256([]byte(string(binding.ID) + "\x00" + zoneID + "\x00" + canonicalOwner + "\x00" + value + "\x00" + expiresAt.UTC().Format(time.RFC3339Nano)))
	effectID := EffectID("dns01_" + hex.EncodeToString(sum[:24]))
	payload := cloudflareReceiptPayload{Version: 1, Kind: "dns01", BindingID: string(binding.ID), EffectID: string(effectID), ZoneID: zoneID, Owner: canonicalOwner, Type: RRTypeTXT, RecordIDs: []string{created.ID}, BeforeDigest: beforeDigest, OutputDigest: after.Digest, Revision: after.Revision, AppliedAt: appliedAt.Format(time.RFC3339Nano), ChallengeUntil: expiresAt.UTC().Format(time.RFC3339Nano)}
	providerReceipt, err := cloudflareSignReceipt(token, payload)
	if err != nil {
		return DNSApplyReceipt{}, ErrIntegrity
	}
	return DNSApplyReceipt{EffectID: effectID, BeforeDigest: beforeDigest, OutputDigest: after.Digest, ProviderRevision: after.Revision, ProviderReceipt: providerReceipt, AppliedAt: appliedAt}, nil
}

func (adapter *RemoteProviderAdapter) CleanDNSChallenge(ctx context.Context, binding ProviderBinding, receipt DNSApplyReceipt) error {
	if binding.State != BindingActive || receipt.ProviderReceipt == "" || !validID(string(receipt.EffectID)) || !validDigest(receipt.OutputDigest) || receipt.ProviderRevision == "" || receipt.AppliedAt.IsZero() {
		return ErrInvalid
	}
	token, cleanup, err := adapter.cloudflareAccess(ctx, binding)
	if err != nil {
		return err
	}
	defer cleanup()
	payload, err := cloudflareVerifyReceipt(token, receipt.ProviderReceipt)
	if err != nil || payload.Kind != "dns01" || payload.BindingID != string(binding.ID) || payload.EffectID != string(receipt.EffectID) || payload.Type != RRTypeTXT || payload.OutputDigest != receipt.OutputDigest || payload.Revision != receipt.ProviderRevision || payload.AppliedAt != receipt.AppliedAt.UTC().Format(time.RFC3339Nano) || !validID(payload.ZoneID) || len(payload.RecordIDs) != 1 || !validID(payload.RecordIDs[0]) {
		return ErrIntegrity
	}
	for index, recordID := range payload.RecordIDs {
		var deleted struct { ID string `json:"id"` }
		_, deleteErr := adapter.cloudflareRequest(ctx, token, "cloudflare.clean_dns01", http.MethodDelete, "/client/v4/zones/"+url.PathEscape(payload.ZoneID)+"/dns_records/"+url.PathEscape(recordID), nil, nil, &deleted, true)
		if deleteErr != nil {
			var providerError *ProviderError
			if errors.As(deleteErr, &providerError) && providerError.Class == ErrorConflict {
				continue
			}
			if index > 0 {
				return &ProviderError{Class: ErrorPartial, Operation: "cloudflare.clean_dns01", Code: "partial_cleanup", PartialReceipt: receipt.ProviderReceipt, Cause: ErrPartial}
			}
			return deleteErr
		}
		if deleted.ID != "" && deleted.ID != recordID {
			return ErrIntegrity
		}
	}
	return nil
}

func cloudflareSignReceipt(token string, payload cloudflareReceiptPayload) (string, error) {
	if token == "" || payload.Version != 1 || payload.BindingID == "" || payload.EffectID == "" || len(payload.RecordIDs) > 1000 {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > cloudflareRequestBodyLimit {
		return "", ErrIntegrity
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte("cloudflare.receipt.v1\x00" + encoded))
	return "cf1." + encoded + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

func cloudflareVerifyReceipt(token, receipt string) (cloudflareReceiptPayload, error) {
	if token == "" || len(receipt) > 128<<10 {
		return cloudflareReceiptPayload{}, ErrIntegrity
	}
	parts := strings.Split(receipt, ".")
	if len(parts) != 3 || parts[0] != "cf1" {
		return cloudflareReceiptPayload{}, ErrIntegrity
	}
	provided, err := hex.DecodeString(parts[2])
	if err != nil || len(provided) != sha256.Size {
		return cloudflareReceiptPayload{}, ErrIntegrity
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte("cloudflare.receipt.v1\x00" + parts[1]))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return cloudflareReceiptPayload{}, ErrIntegrity
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(raw) == 0 || len(raw) > cloudflareRequestBodyLimit {
		return cloudflareReceiptPayload{}, ErrIntegrity
	}
	var payload cloudflareReceiptPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF || payload.Version != 1 {
		return cloudflareReceiptPayload{}, ErrIntegrity
	}
	return payload, nil
}

var _ CloudflareProvider = (*RemoteProviderAdapter)(nil)
