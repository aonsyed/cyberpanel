//go:build linux

package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CloudflareError is a typed API error with the provider's own failure codes.
type CloudflareError struct {
	StatusCode int    `json:"status_code"`
	Code       int    `json:"code"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable"`
}

func (e *CloudflareError) Error() string {
	return fmt.Sprintf("cloudflare api %d code=%d: %s", e.StatusCode, e.Code, e.Message)
}

var (
	ErrCloudflareConfig   = errors.New("cloudflare: invalid provider configuration")
	ErrCloudflareAuth     = errors.New("cloudflare: authentication failed")
	ErrCloudflareNotFound = errors.New("cloudflare: zone or record not found")
)

// CloudflareCredentials hold the API token and optional account identifier.
// The token is a scoped API token (Zone:Edit), never a global key.
type CloudflareCredentials struct {
	APIToken  string `json:"api_token"`
	AccountID string `json:"account_id,omitempty"`
}

func (c CloudflareCredentials) Valid() bool {
	return len(c.APIToken) >= 40 && !strings.Contains(c.APIToken, " ")
}

// CloudflareTransport issues the HTTP round trip; tests substitute a stub.
type CloudflareTransport interface {
	RoundTrip(ctx context.Context, method string, path string, body []byte) (int, []byte, error)
}

// CloudflareHTTP is the production transport against api.cloudflare.com.
type CloudflareHTTP struct {
	Client *http.Client
}

func (t *CloudflareHTTP) RoundTrip(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if t.Client == nil { t.Client = &http.Client{Timeout: 30 * time.Second} }
	var reader io.Reader
	if body != nil { reader = bytes.NewReader(body) }
	req, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+path, reader)
	if err != nil { return 0, nil, err }
	req.Header.Set("Content-Type", "application/json")
	return t.do(req)
}

func (t *CloudflareHTTP) do(req *http.Request) (int, []byte, error) {
	resp, err := t.Client.Do(req)
	if err != nil { return 0, nil, err }
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, data, err
}

// CloudflareClient implements the dns.Cloudflare interface.
type CloudflareClient struct {
	Credentials CloudflareCredentials
	Transport   CloudflareTransport
}

func NewCloudflareClient(creds CloudflareCredentials, transport CloudflareTransport) (*CloudflareClient, error) {
	if !creds.Valid() { return nil, ErrCloudflareConfig }
	if transport == nil { transport = &CloudflareHTTP{} }
	return &CloudflareClient{Credentials: creds, Transport: transport}, nil
}

// cfEnvelope is the common Cloudflare API response wrapper.
type cfEnvelope struct {
	Success bool              `json:"success"`
	Errors  []cfAPIError      `json:"errors"`
	Result  json.RawMessage   `json:"result"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cfZone is the zone object from the Cloudflare API.
type cfZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// cfRecord is a DNS record from the Cloudflare API.
type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// EnsureZone creates the zone if absent and returns the provider zone ID.
func (c *CloudflareClient) EnsureZone(ctx context.Context, zone Zone) error {
	if zone.Name == "" { return ErrInvalidDNS }
	zoneID, err := c.zoneID(ctx, string(zone.Name))
	if err != nil && !errors.Is(err, ErrCloudflareNotFound) { return err }
	if zoneID != "" { return nil }

	body, _ := json.Marshal(map[string]any{
		"name": string(zone.Name),
		"account": map[string]string{"id": c.Credentials.AccountID},
		"type": "full",
	})
	status, data, err := c.Transport.RoundTrip(ctx, "POST", "/zones", body)
	if err != nil { return err }
	if status == http.StatusUnauthorized { return ErrCloudflareAuth }
	var env cfEnvelope
	if err := json.Unmarshal(data, &env); err != nil { return err }
	if !env.Success {
		return &CloudflareError{StatusCode: status, Code: firstCode(env.Errors), Message: firstMessage(env.Errors)}
	}
	return nil
}

// ReplaceRRSet replaces all records for a given name+type with the values.
func (c *CloudflareClient) ReplaceRRSet(ctx context.Context, set RRSet) error {
	if set.ZoneID == "" || set.Name == "" || set.Type == "" { return ErrInvalidDNS }
	zoneID, err := c.zoneID(ctx, string(set.ZoneID))
	if err != nil { return err }

	// Fetch existing records for this name+type.
	path := fmt.Sprintf("/zones/%s/dns_records?per_page=100&type=%s&name=%s", zoneID, set.Type, url.QueryEscape(string(set.Name)))
	status, data, err := c.Transport.RoundTrip(ctx, "GET", path, nil)
	if err != nil { return err }
	if status == http.StatusUnauthorized { return ErrCloudflareAuth }
	var listEnv struct {
		Success bool         `json:"success"`
		Errors  []cfAPIError `json:"errors"`
		Result  []cfRecord   `json:"result"`
	}
	if err := json.Unmarshal(data, &listEnv); err != nil { return err }
	if !listEnv.Success {
		return &CloudflareError{StatusCode: status, Code: firstCode(listEnv.Errors), Message: firstMessage(listEnv.Errors)}
	}

	// Delete records not in the new set, upsert the rest.
	wanted := make(map[string]bool, len(set.Values))
	for _, v := range set.Values { wanted[v] = true }
	for _, record := range listEnv.Result {
		if !wanted[record.Content] {
			delPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, record.ID)
			dStatus, dData, dErr := c.Transport.RoundTrip(ctx, "DELETE", delPath, nil)
			if dErr != nil { return dErr }
			if dStatus == http.StatusUnauthorized { return ErrCloudflareAuth }
			if dStatus >= 400 {
				var delEnv cfEnvelope
				_ = json.Unmarshal(dData, &delEnv)
				return &CloudflareError{StatusCode: dStatus, Code: firstCode(delEnv.Errors), Message: firstMessage(delEnv.Errors)}
			}
		}
	}
	existing := make(map[string]string, len(listEnv.Result))
	for _, record := range listEnv.Result { existing[record.Content] = record.ID }
	for _, value := range set.Values {
		body, _ := json.Marshal(map[string]any{
			"type": set.Type, "name": string(set.Name),
			"content": value, "ttl": set.TTL,
		})
		if id, ok := existing[value]; ok {
			putPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, id)
			status, data, err = c.Transport.RoundTrip(ctx, "PUT", putPath, body)
		} else {
			postPath := fmt.Sprintf("/zones/%s/dns_records", zoneID)
			status, data, err = c.Transport.RoundTrip(ctx, "POST", postPath, body)
		}
		if err != nil { return err }
		if status == http.StatusUnauthorized { return ErrCloudflareAuth }
		var env cfEnvelope
		if err := json.Unmarshal(data, &env); err != nil { return err }
		if !env.Success {
			return &CloudflareError{StatusCode: status, Code: firstCode(env.Errors), Message: firstMessage(env.Errors)}
		}
	}
	return nil
}

// DeleteRRSet removes all records of a given name+type in a zone.
func (c *CloudflareClient) DeleteRRSet(ctx context.Context, zoneID ZoneID, name string, recordType RecordType) error {
	if zoneID == "" || name == "" || recordType == "" { return ErrInvalidDNS }
	cfid, err := c.zoneID(ctx, string(zoneID))
	if err != nil { return err }
	path := fmt.Sprintf("/zones/%s/dns_records?per_page=100&type=%s&name=%s", cfid, recordType, url.QueryEscape(name))
	status, data, err := c.Transport.RoundTrip(ctx, "GET", path, nil)
	if err != nil { return err }
	if status == http.StatusNotFound { return nil }
	if status == http.StatusUnauthorized { return ErrCloudflareAuth }
	var listEnv struct {
		Success bool         `json:"success"`
		Errors  []cfAPIError `json:"errors"`
		Result  []cfRecord   `json:"result"`
	}
	if err := json.Unmarshal(data, &listEnv); err != nil { return err }
	if !listEnv.Success && len(listEnv.Errors) > 0 {
		if listEnv.Errors[0].Code == 7003 { return ErrCloudflareNotFound }
		return &CloudflareError{StatusCode: status, Code: firstCode(listEnv.Errors), Message: firstMessage(listEnv.Errors)}
	}
	for _, record := range listEnv.Result {
		delPath := fmt.Sprintf("/zones/%s/dns_records/%s", cfid, record.ID)
		dStatus, dData, dErr := c.Transport.RoundTrip(ctx, "DELETE", delPath, nil)
		if dErr != nil { return dErr }
		if dStatus >= 400 {
			var delEnv cfEnvelope
			_ = json.Unmarshal(dData, &delEnv)
			return &CloudflareError{StatusCode: dStatus, Code: firstCode(delEnv.Errors), Message: firstMessage(delEnv.Errors)}
		}
	}
	return nil
}

// SyncZone pushes a complete zone (all RRSet) to Cloudflare, matching classic
// CyberPanel's syncCF operation: the provider state converges to the local state.
func (c *CloudflareClient) SyncZone(ctx context.Context, zone Zone, sets []RRSet) error {
	if err := c.EnsureZone(ctx, zone); err != nil { return err }
	for _, set := range sets {
		if set.ZoneID != zone.ID { return ErrInvalidDNS }
		if err := c.ReplaceRRSet(ctx, set); err != nil { return err }
	}
	return nil
}

// zoneID resolves a zone name to its Cloudflare zone identifier.
// zoneID accepts either a zone name or a raw Cloudflare zone ID.
func (c *CloudflareClient) zoneID(ctx context.Context, nameOrID string) (string, error) {
	if nameOrID == "" { return "", ErrInvalidDNS }
	// If it looks like a Cloudflare zone ID (32 hex chars), verify it exists.
	if isCloudflareID(nameOrID) {
		status, data, err := c.Transport.RoundTrip(ctx, "GET", "/zones/"+nameOrID, nil)
		if err != nil { return "", err }
		if status == http.StatusNotFound { return "", ErrCloudflareNotFound }
		if status == http.StatusUnauthorized { return "", ErrCloudflareAuth }
		var env cfEnvelope
		if err := json.Unmarshal(data, &env); err != nil { return "", err }
		if !env.Success { return "", &CloudflareError{StatusCode: status, Code: firstCode(env.Errors), Message: firstMessage(env.Errors)} }
		return nameOrID, nil
	}
	// Otherwise, search by name.
	path := "/zones?name=" + url.QueryEscape(nameOrID) + "&per_page=1"
	status, data, err := c.Transport.RoundTrip(ctx, "GET", path, nil)
	if err != nil { return "", err }
	if status == http.StatusUnauthorized { return "", ErrCloudflareAuth }
	var zoneEnv struct {
		Success bool         `json:"success"`
		Errors  []cfAPIError `json:"errors"`
		Result  []cfZone     `json:"result"`
	}
	if err := json.Unmarshal(data, &zoneEnv); err != nil { return "", err }
	if !zoneEnv.Success {
		return "", &CloudflareError{StatusCode: status, Code: firstCode(zoneEnv.Errors), Message: firstMessage(zoneEnv.Errors)}
	}
	if len(zoneEnv.Result) == 0 { return "", ErrCloudflareNotFound }
	return zoneEnv.Result[0].ID, nil
}

func isCloudflareID(s string) bool {
	if len(s) != 32 { return false }
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') { return false }
	}
	return true
}

func firstCode(errs []cfAPIError) int {
	if len(errs) == 0 { return 0 }
	return errs[0].Code
}

func firstMessage(errs []cfAPIError) string {
	if len(errs) == 0 { return "" }
	return errs[0].Message
}

// CloudflareProvider adapts the client to the dns.Provider interface so
// repository ApplyForTenant can dispatch changes to Cloudflare directly.
type CloudflareProvider struct{ Client *CloudflareClient }

func (p CloudflareProvider) Apply(ctx context.Context, zone Zone, change Change) error {
	if p.Client == nil { return ErrCloudflareConfig }
	if change.Delete { return p.Delete(ctx, zone, change) }
	return p.Client.ReplaceRRSet(ctx, change.RRSet)
}

func (p CloudflareProvider) Delete(ctx context.Context, zone Zone, change Change) error {
	if p.Client == nil { return ErrCloudflareConfig }
	return p.Client.DeleteRRSet(ctx, zone.ID, string(change.RRSet.Name), change.RRSet.Type)
}

var _ Provider = CloudflareProvider{}
var _ Cloudflare = (*CloudflareClient)(nil)

// ParseCloudflareTTL converts a string TTL to uint32, defaulting to 300.
func ParseCloudflareTTL(ttl string) uint32 {
	if n, err := strconv.ParseUint(ttl, 10, 32); err == nil && n >= 60 && n <= 86400 {
		return uint32(n)
	}
	return 300
}
