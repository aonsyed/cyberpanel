//go:build linux

package integrations

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Socket-boundary qualification only: no external provider or credential is
// contacted. Run the compiled test as cyberpanel inside the QEMU guest.
func TestQEMULiveProviderWorkerBoundary(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_PROVIDER") != "1" {
		t.Skip("requires installed QEMU provider worker and explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	binding := ProviderBinding{
		ID: "qemu-unsupported", TenantID: "qemu-tenant", Kind: ProviderImunify, DisplayName: "QEMU boundary check", Purpose: PurposeSecurity,
		SecretRef: "qemu-unused", SecretVersion: 1, SecretBindingDigest: strings.Repeat("a", 64),
		Endpoint:     EndpointPolicy{URL: "local://imunify", ServerName: "imunify"},
		Capabilities: CapabilitySet{SchemaVersion: 1, ProviderVersion: "qemu", Capabilities: []Capability{CapabilityHealth}, DiscoveredAt: now, Digest: strings.Repeat("b", 64)},
		State:        BindingActive, Generation: 1, CreatedAt: now, UpdatedAt: now,
	}
	request := ProviderWorkerRequest{Version: ProviderWorkerProtocolVersion, RequestID: "qemu-boundary", Action: ProviderWorkerHealth, Binding: binding, Deadline: now.Add(5 * time.Second)}
	response, err := (FramedProviderWorkerTransport{Dialer: LocalProviderWorkerDialer{}}).RoundTrip(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.RequestID != request.RequestID || response.Succeeded || response.Failure != ErrorPermanent || response.FailureCode != "unsupported_provider" {
		t.Fatalf("unexpected worker response: %+v", response)
	}
	connection, err := (LocalProviderWorkerDialer{}).DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(now.Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request.Version = 0
	if err := writeProviderWorkerFrame(connection, request); err != nil {
		t.Fatal(err)
	}
	err = readProviderWorkerFrame(connection, &response)
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("invalid protocol version was not rejected by closing the connection: %v", err)
	}
}
