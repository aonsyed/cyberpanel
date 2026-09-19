//go:build linux

package authn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

// Explicit opt-in: this creates and revokes test verifiers on the installed
// QEMU daemon. Run the compiled test as the cyberpanel control-plane account.
func TestQEMULiveVerifierPasswordAndAPIKey(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_AUTH") != "1" {
		t.Skip("requires installed QEMU authd and explicit live-test opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := NewLocalClient()
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	defer wipe(random)
	principal, err := identity.NewID("qemu-auth-" + hex.EncodeToString(random[:8]))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := client.EnrollPassword(ctx, principal, append([]byte(nil), random...))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	defer client.Revoke(context.Background(), ref)
	if ok, err := client.VerifyPassword(ctx, ref, []byte("deliberately-wrong-password")); err != nil || ok {
		t.Fatalf("wrong password: verified=%v error=%v", ok, err)
	}
	if ok, err := client.VerifyPassword(ctx, ref, append([]byte(nil), random...)); err != nil || !ok {
		t.Fatalf("correct password: verified=%v error=%v", ok, err)
	}
	if err := client.Revoke(ctx, ref); err != nil {
		t.Fatalf("revoke password: %v", err)
	}
	if ok, err := client.VerifyPassword(ctx, ref, append([]byte(nil), random...)); err == nil || ok {
		t.Fatalf("revoked password accepted: verified=%v error=%v", ok, err)
	}
	keyRef, key, err := client.IssueAPIKey(ctx, principal, nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue API key: %v", err)
	}
	defer wipe(key)
	defer client.Revoke(context.Background(), keyRef)
	if got, ok, err := client.VerifyAPIKey(ctx, append([]byte(nil), key...)); err != nil || !ok || got != keyRef {
		t.Fatalf("API key verify: verified=%v error=%v", ok, err)
	}
	if err := client.Revoke(ctx, keyRef); err != nil {
		t.Fatalf("revoke API key: %v", err)
	}
	if _, ok, err := client.VerifyAPIKey(ctx, append([]byte(nil), key...)); err == nil || ok {
		t.Fatalf("revoked API key accepted: verified=%v error=%v", ok, err)
	}
}
