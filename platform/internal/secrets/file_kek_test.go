package secrets

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKEKOwnershipAndWrapping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrapping.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 32), 0400); err != nil {
		t.Fatal(err)
	}
	key, err := NewFileKEK(path, 1, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := key.Wrap(context.Background(), 1, []byte("test material"), []byte("binding"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := key.Unwrap(context.Background(), 1, ciphertext, []byte("binding"))
	if err != nil || string(plaintext) != "test material" {
		t.Fatalf("round-trip: %v", err)
	}
	if _, err := key.Unwrap(context.Background(), 1, ciphertext, []byte("other binding")); err == nil {
		t.Fatal("accepted different binding")
	}
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if _, err := key.Wrap(context.Background(), 1, []byte("test"), nil); err == nil {
		t.Fatal("ordinary key accepted group-readable mode")
	}
	if _, err := NewSystemdCredentialKEK(path, 1); err == nil {
		t.Fatal("accepted unregistered credential path")
	}
}

func TestSystemdKEKProtectedModes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned credential fixture; execute inside QEMU as root")
	}
	path := filepath.Join(t.TempDir(), "wrapping.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 32), 0440); err != nil {
		t.Fatal(err)
	}
	key, err := newFileKEK(path, 1, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.Wrap(context.Background(), 1, []byte("test"), nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := key.Wrap(context.Background(), 1, []byte("test"), nil); err == nil {
		t.Fatal("accepted world-readable credential")
	}
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 12345); err != nil {
		t.Fatal(err)
	}
	if _, err := key.Wrap(context.Background(), 1, []byte("test"), nil); err == nil {
		t.Fatal("accepted non-root credential group")
	}
}
