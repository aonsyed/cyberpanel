//go:build linux

package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

func uploadFixture(t *testing.T, compression TransferCompression) (*LinuxTransferUploadStore, TransferUploadIntent, []byte) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("QEMU root-owned upload fixture")
	}
	now := time.Now().UTC()
	store, err := NewLinuxTransferUploadStore(filepath.Join(t.TempDir(), "uploads"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("CREATE TABLE example(id INT, value BLOB);\nINSERT INTO example VALUES (1,0x00FF),(2,NULL);\n")
	if compression == TransferCompressionGzip {
		var buffer bytes.Buffer
		zip := gzip.NewWriter(&buffer)
		_, err = zip.Write(data)
		if err != nil {
			t.Fatal(err)
		}
		if err = zip.Close(); err != nil {
			t.Fatal(err)
		}
		data = buffer.Bytes()
	}
	id, _ := NewResourceID("upload-test")
	tenant, _ := site.NewTenantID("upload-tenant")
	siteID, _ := site.NewSiteID("upload-site")
	database, _ := NewResourceID("upload-database")
	intent, err := SealTransferUploadIntent(TransferUploadIntent{ID: id, TenantID: tenant, SiteID: siteID, DatabaseID: database, DatabaseGeneration: 1, CreatedBy: "upload-owner", Compression: compression, Bytes: uint64(len(data)), PayloadDigest: transferDigest(data), CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return store, intent, data
}

func TestTransferUploadResumesAndPublishesVerifiedSQLAndGzip(t *testing.T) {
	for _, compression := range []TransferCompression{TransferCompressionNone, TransferCompressionGzip} {
		t.Run(string(compression), func(t *testing.T) {
			store, intent, data := uploadFixture(t, compression)
			ctx := context.Background()
			if offset, err := store.Begin(ctx, intent); err != nil || offset != 0 {
				t.Fatalf("begin: %d %v", offset, err)
			}
			if _, err := store.Finish(ctx, intent); !errors.Is(err, ErrConflict) {
				t.Fatalf("partial finish: %v", err)
			}
			if offset, err := store.Append(ctx, intent, 0, data[:11]); err != nil || offset != 11 {
				t.Fatalf("append: %d %v", offset, err)
			}
			// Recreate the store to prove continuation does not rely on process memory.
			reopened, err := NewLinuxTransferUploadStore(store.artifacts.root, store.artifacts.now)
			if err != nil {
				t.Fatal(err)
			}
			if offset, err := reopened.Begin(ctx, intent); err != nil || offset != 11 {
				t.Fatalf("resume: %d %v", offset, err)
			}
			if offset, err := reopened.Append(ctx, intent, 0, data[:11]); err != nil || offset != 11 {
				t.Fatalf("chunk replay: %d %v", offset, err)
			}
			if _, err := reopened.Append(ctx, intent, 0, bytes.Repeat([]byte("x"), 11)); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed replay: %v", err)
			}
			if _, err := reopened.Append(ctx, intent, 12, data[12:]); !errors.Is(err, ErrConflict) {
				t.Fatalf("gap: %v", err)
			}
			if _, err := reopened.Append(ctx, intent, 11, data[11:]); err != nil {
				t.Fatal(err)
			}
			artifact, err := reopened.Finish(ctx, intent)
			if err != nil || !intent.matchesArtifact(artifact) {
				t.Fatalf("finish: %v", err)
			}
			replay, err := reopened.Finish(ctx, intent)
			if err != nil || replay != artifact {
				t.Fatalf("finish replay: %v", err)
			}
			if offset, err := reopened.Begin(ctx, intent); err != nil || offset != intent.Bytes {
				t.Fatalf("completed begin replay: %d %v", offset, err)
			}
			reader, err := reopened.artifacts.OpenTransferArtifact(ctx, intent.ArtifactIdentity())
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || !bytes.Equal(got, data) {
				t.Fatal("published bytes differ")
			}
			if _, err = os.Lstat(filepath.Join(store.artifacts.root, ".upload-"+intent.Digest)); !os.IsNotExist(err) {
				t.Fatalf("upload staging survived publication: %v", err)
			}
		})
	}
}

func TestTransferUploadRejectsTamperingExpiryAndUnsafeFiles(t *testing.T) {
	for _, variant := range []string{"digest", "tenant", "actor", "generation", "expiry", "symlink", "hardlink", "permissions", "partial-chunk"} {
		t.Run(variant, func(t *testing.T) {
			store, intent, data := uploadFixture(t, TransferCompressionNone)
			ctx := context.Background()
			if variant == "digest" {
				intent.PayloadDigest = transferDigest([]byte("different"))
				intent, _ = SealTransferUploadIntent(intent)
			}
			if _, err := store.Begin(ctx, intent); err != nil {
				t.Fatal(err)
			}
			payload := filepath.Join(store.artifacts.root, ".upload-"+intent.Digest, "payload")
			switch variant {
			case "tenant":
				intent.TenantID, _ = site.NewTenantID("other-tenant")
				intent, _ = SealTransferUploadIntent(intent)
			case "actor":
				intent.CreatedBy = "other-owner"
				intent, _ = SealTransferUploadIntent(intent)
			case "generation":
				intent.DatabaseGeneration++
				intent, _ = SealTransferUploadIntent(intent)
			case "expiry":
				store.artifacts.now = func() time.Time { return intent.ExpiresAt }
			case "symlink":
				if err := os.Remove(payload); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("intent.json", payload); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(payload, payload+"-link"); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(payload, 0644); err != nil {
					t.Fatal(err)
				}
			case "partial-chunk":
				if _, err := store.Append(ctx, intent, 0, data[:3]); err != nil {
					t.Fatal(err)
				}
			}
			_, err := store.Append(ctx, intent, 0, data)
			if variant == "digest" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.Finish(ctx, intent); !errors.Is(err, ErrTransferInvalid) {
					t.Fatalf("bad digest published: %v", err)
				}
				if _, err = store.artifacts.OpenTransferArtifact(ctx, intent.ArtifactIdentity()); !os.IsNotExist(err) {
					t.Fatal("bad digest artifact visible")
				}
			} else if err == nil {
				t.Fatal("unsafe upload accepted")
			}
		})
	}
}

func TestTransferUploadBoundsAndCancellation(t *testing.T) {
	store, intent, _ := uploadFixture(t, TransferCompressionNone)
	for _, mutate := range []func(*TransferUploadIntent){func(i *TransferUploadIntent) { i.Bytes = 0 }, func(i *TransferUploadIntent) { i.Bytes = MaximumTransferUploadBytes + 1 }, func(i *TransferUploadIntent) { i.ExpiresAt = i.CreatedAt.Add(25 * time.Hour) }, func(i *TransferUploadIntent) { i.Compression = "zip" }} {
		invalid := intent
		mutate(&invalid)
		if _, err := SealTransferUploadIntent(invalid); err == nil {
			t.Fatal("invalid intent accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Begin(ctx, intent); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := store.Append(context.Background(), intent, 0, make([]byte, MaximumTransferUploadChunk+1)); !errors.Is(err, ErrTransferLimit) {
		t.Fatalf("chunk bound: %v", err)
	}
}

func TestTransferUploadCapacityDiscardAndExpiredReclamation(t *testing.T) {
	store, intent, data := uploadFixture(t, TransferCompressionNone)
	ctx := context.Background()
	for i := 0; i < 32; i++ {
		candidate := intent
		candidate.ID, _ = NewResourceID(fmt.Sprintf("bounded-upload-%d", i))
		candidate, _ = SealTransferUploadIntent(candidate)
		if _, err := store.Begin(ctx, candidate); err != nil {
			t.Fatal("bounded upload", i, err)
		}
	}
	if _, err := store.Begin(ctx, intent); !errors.Is(err, ErrTransferLimit) {
		t.Fatalf("capacity not enforced: %v", err)
	}
	now := intent.ExpiresAt.Add(time.Second)
	store.artifacts.now = func() time.Time { return now }
	current := intent
	current.CreatedAt = now
	current.ExpiresAt = now.Add(time.Hour)
	current, _ = SealTransferUploadIntent(current)
	if _, err := store.Begin(ctx, current); err != nil {
		t.Fatal("expired capacity not reclaimed", err)
	}
	if _, err := store.Append(ctx, current, 0, data[:3]); err != nil {
		t.Fatal(err)
	}
	if err := store.Discard(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err := store.Discard(ctx, current); err != nil {
		t.Fatal("discard replay", err)
	}
	entries, err := os.ReadDir(store.artifacts.root)
	if err != nil || len(entries) != 1 || entries[0].Name() != ".upload-lock" {
		t.Fatalf("pending bytes leaked: %d %v", len(entries), err)
	}
}
