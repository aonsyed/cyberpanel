//go:build linux

package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// This fixture pins the running test executable, not a production provider.
// It exercises the installed broker/helper and never uses real credentials.
func TestQEMULiveInspectedMaterial(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_INSPECTED_MATERIAL") != "1" {
		t.Skip("requires installed QEMU inspector and broker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	management, err := NewLocalManagementClient()
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewLocalMaterialClient()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := linuxExecutableDigest(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, wrongDigest := range []bool{false, true} {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		defer wipe(secret)
		id, _ := NewID("qemu-material-" + hex.EncodeToString(secret[:8]))
		release := executable
		if wrongDigest {
			release = strings.Repeat("a", 64)
		}
		request := PutRequest{ID: id, OwnerTenantID: "qemu-tenant", Purpose: PurposeAuthentication, Plaintext: append([]byte(nil), secret...), Audience: AudienceBinding{AdapterID: "qemu.inspection", AdapterVersion: "v1", Account: "fixture", Origin: "local://qemu", ResourceKind: "test", ResourceID: "qemu-resource", ResourceGeneration: 1, Operations: []Operation{OperationAuthenticate}, ConsumerReleaseDigest: release}}
		head, err := management.PutExact(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, err := management.Revoke(context.Background(), RevokeRequest{ID: id, OwnerTenantID: request.OwnerTenantID, Purpose: request.Purpose, Audience: request.Audience, ExpectedVersion: head.Version, ExpectedBindingDigest: head.BindingDigest})
			if err != nil {
				t.Error(err)
			}
		}()
		read := MaterialRequest{OwnerTenantID: request.OwnerTenantID, SecretID: id, Purpose: request.Purpose, Operation: OperationAuthenticate, AdapterID: request.Audience.AdapterID, AdapterVersion: request.Audience.AdapterVersion, ResourceID: request.Audience.ResourceID, Deadline: time.Now().Add(10 * time.Second)}
		response, err := material.Read(ctx, read)
		if wrongDigest {
			if err == nil {
				wipe(response.Material)
				t.Fatal("untrusted executable digest received material")
			}
			continue
		}
		if err != nil {
			t.Fatalf("installed inspected delivery: %v", err)
		}
		if !bytes.Equal(response.Material, secret) {
			wipe(response.Material)
			t.Fatal("incorrect delivered material")
		}
		wipe(response.Material)
	}
}
