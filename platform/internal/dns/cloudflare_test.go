package dns

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// stubTransport captures HTTP calls and returns canned responses.
type stubTransport struct {
	calls    []stubCall
	response map[string]stubResponse // path prefix -> response
}

type stubCall struct {
	Method string
	Path   string
	Body   string
}

type stubResponse struct {
	Status int
	Body   string
}

func (t *stubTransport) RoundTrip(_ context.Context, method, path string, body []byte) (int, []byte, error) {
	t.calls = append(t.calls, stubCall{Method: method, Path: path, Body: string(body)})
	for prefix, resp := range t.response {
		if strings.HasPrefix(path, prefix) || strings.Contains(path, prefix) {
			return resp.Status, []byte(resp.Body), nil
		}
	}
	return 200, []byte(`{"success":true,"result":[]}`), nil
}

func validCreds() CloudflareCredentials {
	return CloudflareCredentials{APIToken: strings.Repeat("a", 40), AccountID: "abc123"}
}

func TestCloudflareCredentialsValid(t *testing.T) {
	if (CloudflareCredentials{}).Valid() { t.Fatal("empty creds must be invalid") }
	if (CloudflareCredentials{APIToken: "short"}).Valid() { t.Fatal("short token must be invalid") }
	if (CloudflareCredentials{APIToken: "has space " + strings.Repeat("a", 33)}).Valid() { t.Fatal("token with space must be invalid") }
	if !validCreds().Valid() { t.Fatal("40+ char token without spaces must be valid") }
}

func TestNewCloudflareClientRejectsInvalidCreds(t *testing.T) {
	if _, err := NewCloudflareClient(CloudflareCredentials{}, nil); !errors.Is(err, ErrCloudflareConfig) {
		t.Fatalf("want ErrCloudflareConfig, got %v", err)
	}
}

func TestCloudflareEnsureZoneLookupExisting(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones?name": {200, `{"success":true,"result":[{"id":"023e105f4ecef8ad9ca470d33f1f656e","name":"example.com","status":"active"}]}`},
	}}
	client, err := NewCloudflareClient(validCreds(), transport)
	if err != nil { t.Fatal(err) }
	zone := Zone{ID: ZoneID("example.com"), Name: "example.com"}
	if err := client.EnsureZone(context.Background(), zone); err != nil { t.Fatal(err) }
	// Should NOT have POSTed a new zone.
	for _, call := range transport.calls {
		if call.Method == "POST" && strings.HasPrefix(call.Path, "/zones") { t.Fatal("should not create zone when it exists") }
	}
}

func TestCloudflareEnsureZoneCreates(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones?name": {200, `{"success":true,"result":[]}`},
		"POST /zones": {200, `{"success":true,"result":{"id":"new","name":"example.com"}}`},
	}}
	// stubTransport matches on path prefix, adjust for POST
	transport.response["/zones"] = transport.response["POST /zones"]
	client, _ := NewCloudflareClient(validCreds(), transport)
	zone := Zone{ID: ZoneID("example.com"), Name: "example.com"}
	if err := client.EnsureZone(context.Background(), zone); err != nil { t.Fatal(err) }
	found := false
	for _, call := range transport.calls {
		if call.Method == "POST" { found = true }
	}
	if !found { t.Fatal("should have POSTed to create zone") }
}

func TestCloudflareReplaceRRSet(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones?name": {200, `{"success":true,"result":[{"id":"z1","name":"example.com"}]}`},
	}}
	client, _ := NewCloudflareClient(validCreds(), transport)
	set := RRSet{ZoneID: ZoneID("example.com"), Name: "www.example.com", Type: A, TTL: 3600, Values: []string{"1.2.3.4"}}
	if err := client.ReplaceRRSet(context.Background(), set); err != nil { t.Fatal(err) }
	// Should have: GET zone, GET records, POST record
	if len(transport.calls) < 3 { t.Fatalf("expected at least 3 calls, got %d", len(transport.calls)) }
	var posted bool
	for _, call := range transport.calls {
		if call.Method == "POST" && strings.Contains(call.Path, "/dns_records") {
			posted = true
			var body map[string]any
			if err := json.Unmarshal([]byte(call.Body), &body); err != nil { t.Fatal(err) }
			if body["content"] != "1.2.3.4" { t.Fatalf("content mismatch: %v", body["content"]) }
			if body["type"] != "A" { t.Fatalf("type mismatch: %v", body["type"]) }
		}
	}
	if !posted { t.Fatal("should have POSTed a DNS record") }
}

func TestCloudflareReplaceRRSetDeletesStale(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones?name": {200, `{"success":true,"result":[{"id":"z1"}]}`},
		"dns_records?": {200, `{"success":true,"result":[{"id":"old1","type":"A","name":"www","content":"9.9.9.9","ttl":300}]}`},
	}}
	client, _ := NewCloudflareClient(validCreds(), transport)
	set := RRSet{ZoneID: ZoneID("example.com"), Name: "www.example.com", Type: A, TTL: 3600, Values: []string{"1.2.3.4"}}
	if err := client.ReplaceRRSet(context.Background(), set); err != nil { t.Fatal(err) }
	var deleted bool
	for _, call := range transport.calls {
		if call.Method == "DELETE" && strings.Contains(call.Path, "old1") { deleted = true }
	}
	if !deleted { t.Fatal("should have DELETEd the stale record") }
}

func TestCloudflareDeleteRRSet(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones?name": {200, `{"success":true,"result":[{"id":"z1"}]}`},
		"dns_records?": {200, `{"success":true,"result":[{"id":"r1","type":"A","name":"old","content":"1.1.1.1","ttl":300}]}`},
	}}
	client, _ := NewCloudflareClient(validCreds(), transport)
	if err := client.DeleteRRSet(context.Background(), ZoneID("example.com"), "old.example.com", A); err != nil { t.Fatal(err) }
	var deleted bool
	for _, call := range transport.calls {
		if call.Method == "DELETE" { deleted = true }
	}
	if !deleted { t.Fatal("should have DELETEd records") }
}

func TestCloudflareSyncZone(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones?name": {200, `{"success":true,"result":[{"id":"z1"}]}`},
	}}
	client, _ := NewCloudflareClient(validCreds(), transport)
	zone := Zone{ID: ZoneID("example.com"), Name: "example.com"}
	sets := []RRSet{
		{ZoneID: zone.ID, Name: "@.example.com", Type: A, TTL: 3600, Values: []string{"1.2.3.4"}},
		{ZoneID: zone.ID, Name: "www.example.com", Type: CNAME, TTL: 3600, Values: []string{"example.com"}},
	}
	if err := client.SyncZone(context.Background(), zone, sets); err != nil { t.Fatal(err) }
	if len(transport.calls) < 5 { t.Fatalf("expected >= 5 calls, got %d", len(transport.calls)) }
}

func TestCloudflareAuthError(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones": {401, `{"success":false,"errors":[{"code":9103,"message":"Unknown X-Auth-Key or X-Auth-Email"}]}`},
	}}
	client, _ := NewCloudflareClient(validCreds(), transport)
	zone := Zone{ID: ZoneID("example.com"), Name: "example.com"}
	err := client.EnsureZone(context.Background(), zone)
	if !errors.Is(err, ErrCloudflareAuth) { t.Fatalf("want ErrCloudflareAuth, got %v", err) }
}

func TestCloudflareProviderApply(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones?name": {200, `{"success":true,"result":[{"id":"z1"}]}`},
	}}
	client, _ := NewCloudflareClient(validCreds(), transport)
	provider := CloudflareProvider{Client: client}
	change := Change{Zone: ZoneID("example.com"), Key: "test-1", RRSet: RRSet{ZoneID: ZoneID("example.com"), Name: "www.example.com", Type: A, TTL: 300, Values: []string{"1.2.3.4"}}}
	if err := provider.Apply(context.Background(), Zone{ID: ZoneID("example.com"), Name: "example.com"}, change); err != nil { t.Fatal(err) }
}

func TestCloudflareProviderDelete(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones?name": {200, `{"success":true,"result":[{"id":"z1"}]}`},
		"dns_records?": {200, `{"success":true,"result":[]}`},
	}}
	client, _ := NewCloudflareClient(validCreds(), transport)
	provider := CloudflareProvider{Client: client}
	change := Change{Zone: ZoneID("example.com"), Key: "del-1", Delete: true, RRSet: RRSet{ZoneID: ZoneID("example.com"), Name: "gone.example.com", Type: A}}
	if err := provider.Delete(context.Background(), Zone{ID: ZoneID("example.com"), Name: "example.com"}, change); err != nil { t.Fatal(err) }
}

func TestCloudflareZoneIDByRawID(t *testing.T) {
	rawID := "023e105f4ecef8ad9ca470d33f1f656e"
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones/" + rawID: {200, `{"success":true,"result":{"id":"` + rawID + `","name":"example.com"}}`},
	}}
	client, _ := NewCloudflareClient(validCreds(), transport)
	id, err := client.zoneID(context.Background(), rawID)
	if err != nil { t.Fatal(err) }
	if id != rawID { t.Fatalf("want %s, got %s", rawID, id) }
}

func TestCloudflareNotFound(t *testing.T) {
	transport := &stubTransport{response: map[string]stubResponse{
		"/zones?name": {200, `{"success":true,"result":[]}`},
	}}
	client, _ := NewCloudflareClient(validCreds(), transport)
	_, err := client.zoneID(context.Background(), "missing.example.com")
	if !errors.Is(err, ErrCloudflareNotFound) { t.Fatalf("want ErrCloudflareNotFound, got %v", err) }
}

func TestParseCloudflareTTL(t *testing.T) {
	tests := []struct{ in string; want uint32 }{
		{"300", 300}, {"60", 60}, {"86400", 86400},
		{"30", 300}, {"0", 300}, {"100000", 300}, {"abc", 300}, {"", 300},
	}
	for _, tt := range tests {
		if got := ParseCloudflareTTL(tt.in); got != tt.want {
			t.Errorf("ParseCloudflareTTL(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
