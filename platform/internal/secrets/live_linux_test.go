//go:build linux

package secrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// Run the compiled test as cyberpanel in the disposable QEMU guest. This tests
// the real management socket, encrypted store, KEK and version checks; it does
// not grant a fake consumer permission to read secret material.
func TestQEMULiveSecretManagement(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_SECRETS") != "1" {
		t.Skip("requires installed QEMU secret broker and explicit opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := NewLocalManagementClient()
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	defer wipe(material)
	id, _ := NewID("qemu-secret-" + hex.EncodeToString(material[:8]))
	tenant, _ := NewID("qemu-tenant")
	resource, _ := NewID("qemu-resource")
	request := PutRequest{ID: id, OwnerTenantID: tenant, Purpose: PurposeAuthentication, Audience: AudienceBinding{AdapterID: "qemu.test", AdapterVersion: "v1", Account: "qualification", Origin: "local://qemu", ResourceKind: "test", ResourceID: resource, ResourceGeneration: 1, Operations: []Operation{OperationAuthenticate}, ConsumerReleaseDigest: strings.Repeat("a", 64)}}
	request.Plaintext = append([]byte(nil), material...)
	head, err := client.PutExact(ctx, request)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	defer func() {
		_, _ = client.Revoke(context.Background(), RevokeRequest{ID: id, OwnerTenantID: tenant, Purpose: request.Purpose, Audience: request.Audience, ExpectedVersion: head.Version, ExpectedBindingDigest: head.BindingDigest})
	}()
	request.Plaintext = append([]byte(nil), material...)
	replayed, err := client.PutExact(ctx, request)
	if err != nil || replayed.Version != head.Version || replayed.BindingDigest != head.BindingDigest {
		t.Fatalf("exact replay: %v", err)
	}
	request.Plaintext = []byte("different material")
	if _, err := client.PutExact(ctx, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting replay: %v", err)
	}
	request.ExpectedVersion, request.ExpectedBindingDigest = head.Version, head.BindingDigest
	request.Plaintext = []byte("rotated qualification material")
	rotated, err := client.Put(ctx, request)
	if err != nil || rotated.Version != head.Version+1 {
		t.Fatalf("rotate: %v", err)
	}
	head = rotated
	request.Plaintext = []byte("stale rotation")
	if _, err := client.Put(ctx, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale rotation: %v", err)
	}
	revoked, err := client.Revoke(ctx, RevokeRequest{ID: id, OwnerTenantID: tenant, Purpose: request.Purpose, Audience: request.Audience, ExpectedVersion: head.Version, ExpectedBindingDigest: head.BindingDigest})
	if err != nil || revoked.State != StateRevoked {
		t.Fatalf("revoke: %v", err)
	}
}

// Run as cyberpanel-secrets: this account can open its own socket but is not
// an administrative peer. The server must reject it before a store mutation.
func TestQEMULiveSecretManagementDenied(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_SECRETS_DENIED") != "1" {
		t.Skip("requires QEMU broker and non-administrative service identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := NewLocalManagementClient()
	if err != nil {
		t.Fatalf("test requires socket access before peer rejection: %v", err)
	}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	defer wipe(material)
	id, _ := NewID("qemu-denied-" + hex.EncodeToString(material[:8]))
	tenant, _ := NewID("qemu-tenant")
	resource, _ := NewID("qemu-resource")
	request := PutRequest{ID: id, OwnerTenantID: tenant, Purpose: PurposeAuthentication, Plaintext: append([]byte(nil), material...), Audience: AudienceBinding{AdapterID: "qemu.test", AdapterVersion: "v1", Account: "qualification", Origin: "local://qemu", ResourceKind: "test", ResourceID: resource, ResourceGeneration: 1, Operations: []Operation{OperationAuthenticate}, ConsumerReleaseDigest: strings.Repeat("a", 64)}}
	if _, err := client.PutExact(ctx, request); err == nil {
		t.Fatal("broker admitted an unauthorized management peer")
	}
}
