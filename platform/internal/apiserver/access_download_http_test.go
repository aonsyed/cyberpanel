package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/access"
)

type fileDownloadTransport struct {
	data      []byte
	integrity access.Integrity
	reads     int
}

func (*fileDownloadTransport) Health(context.Context) error { return nil }
func (transport *fileDownloadTransport) Invoke(_ context.Context, request CoreRequest) (CoreResponse, error) {
	var result any
	switch request.Request.Operation {
	case "access.download.get":
		result = DownloadIssueResult{ID: "file-proof", Integrity: transport.integrity, ExpiresAt: time.Now().Add(time.Minute)}
	case "access.download.read":
		var payload DownloadReadPayload
		if err := json.Unmarshal(request.Request.Payload, &payload); err != nil {
			return CoreResponse{}, err
		}
		// Use the real admission validator: a gateway chunk must fit the API contract.
		if err := validateDownloadRead(&payload); err != nil {
			return CoreResponse{}, err
		}
		transport.reads++
		result = DownloadReadResult{DownloadID: payload.DownloadID, Offset: payload.Offset, Integrity: transport.integrity, ContentBase64: base64.RawStdEncoding.EncodeToString(transport.data[payload.Offset : payload.Offset+payload.Length])}
	case "access.download.close":
		result = map[string]string{"status": "closed"}
	default:
		return CoreResponse{}, ErrInvalidRequest
	}
	encoded, _ := json.Marshal(result)
	return CoreResponse{Envelope: &ResponseEnvelope{Result: encoded}}, nil
}

type fileDownloadSigner struct{}

func (fileDownloadSigner) Sign(*CoreRequest) error { return nil }

func TestFileDownloadHTTPChunksFitReadContract(t *testing.T) {
	data := bytes.Repeat([]byte{0, 1, 2, 255}, (5<<20)/4)
	digest := sha256.Sum256(data)
	transport := &fileDownloadTransport{data: data, integrity: access.Integrity{Algorithm: "sha256", Digest: hex.EncodeToString(digest[:]), Size: int64(len(data))}}
	registry, err := NewDomainRegistry()
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGateway(registry, transport, fileDownloadSigner{}, GatewayPolicy{AllowedHosts: []string{"localhost"}, AllowPlaintextLoopback: true, RatePerSecond: 100, RateBurst: 100})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://localhost/api/v1/downloads/file-proof?tenant_id=tenant-proof&site_id=site-proof", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), data) {
		t.Fatalf("5 MiB exact download failed: HTTP %d, bytes=%d", response.Code, response.Body.Len())
	}
	if transport.reads != 2 {
		t.Fatalf("want two admitted bounded chunks, got %d", transport.reads)
	}
}
