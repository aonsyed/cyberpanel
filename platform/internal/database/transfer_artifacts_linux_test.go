//go:build linux

package database

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func transferArtifactFixture(t *testing.T) (*LinuxTransferArtifactStore, TransferArtifactIdentity, TransferRetention) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("QEMU root-owned artifact fixture")
	}
	root := filepath.Join(t.TempDir(), "artifacts")
	store, err := NewLinuxTransferArtifactStore(root, 1024, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	storeID, _ := NewResourceID("transfer-test-store")
	artifactID, _ := NewResourceID("transfer-test-artifact")
	return store, TransferArtifactIdentity{StoreID: storeID, ArtifactID: artifactID, Generation: 1}, TransferRetention{RetainUntil: time.Now().UTC().Add(time.Hour)}
}

func TestTransferArtifactPublicationAndAbort(t *testing.T) {
	store, id, retention := transferArtifactFixture(t)
	ctx := context.Background()
	writer, err := store.BeginTransferArtifact(ctx, id, TransferFormatSQL, TransferCompressionNone, retention)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("-- cyberpanel-mariadb-transfer-v1\nCREATE TABLE example (id INT);\n")
	if _, err = writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err = store.OpenTransferArtifact(ctx, id); err == nil {
		t.Fatal("uncommitted artifact visible")
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Commit(ctx, transferDigest([]byte("wrong")), uint64(len(data)), 0); err == nil {
		t.Fatal("wrong hash accepted")
	}
	descriptor, err := writer.Commit(ctx, transferDigest(data), uint64(len(data)), 0)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := writer.Commit(ctx, transferDigest(data), uint64(len(data)), 0)
	if err != nil || replay != descriptor {
		t.Fatalf("commit replay: %v", err)
	}
	if err = writer.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewLinuxTransferArtifactStore(store.root, 1024, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := reopened.OpenTransferArtifact(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(got, data) || reader.Descriptor() != descriptor {
		t.Fatal("reopened artifact differs")
	}
	if _, err = store.BeginTransferArtifact(ctx, id, TransferFormatSQL, TransferCompressionNone, retention); !errors.Is(err, ErrConflict) {
		t.Fatalf("existing generation overwritten: %v", err)
	}
	id.Generation++
	writer, err = store.BeginTransferArtifact(ctx, id, TransferFormatSQL, TransferCompressionNone, retention)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(make([]byte, 1025)); !errors.Is(err, ErrTransferLimit) {
		t.Fatalf("write limit: %v", err)
	}
	if err = writer.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(store.root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("aborted staging leaked: %d %v", len(entries), err)
	}
}

func TestTransferArtifactRejectsExpiredAndUnsafeFiles(t *testing.T) {
	for _, variant := range []string{"expired", "generation", "symlink", "hardlink", "mode", "size", "metadata-size", "directory-mode", "root-mode"} {
		t.Run(variant, func(t *testing.T) {
			store, id, retention := transferArtifactFixture(t)
			ctx := context.Background()
			writer, err := store.BeginTransferArtifact(ctx, id, TransferFormatSQL, TransferCompressionNone, retention)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("safe fixture")
			if _, err = writer.Write(data); err != nil {
				t.Fatal(err)
			}
			if _, err = writer.Commit(ctx, transferDigest(data), uint64(len(data)), 0); err != nil {
				t.Fatal(err)
			}
			directory, _ := store.artifactPath(id)
			payload := filepath.Join(directory, "payload")
			switch variant {
			case "metadata-size":
				path := filepath.Join(directory, "descriptor.json")
				metadata, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				metadata = append(metadata, bytes.Repeat([]byte(" "), 65536)...)
				if err = os.WriteFile(path, metadata, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err = os.Chmod(directory, 0755); err != nil {
					t.Fatal(err)
				}
			case "root-mode":
				if err = os.Chmod(store.root, 0755); err != nil {
					t.Fatal(err)
				}
			case "expired":
				store.now = func() time.Time { return retention.RetainUntil.Add(time.Second) }
			case "generation":
				id.Generation++
			case "symlink":
				if err = os.Rename(payload, payload+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(payload+"-retained", payload); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err = os.Link(payload, payload+"-link"); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err = os.Chmod(payload, 0644); err != nil {
					t.Fatal(err)
				}
			case "size":
				if err = os.WriteFile(payload, []byte("short"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if reader, err := store.OpenTransferArtifact(ctx, id); err == nil {
				reader.Close()
				t.Fatal("unsafe artifact accepted")
			}
		})
	}
}

func TestTransferArtifactConcurrentPublication(t *testing.T) {
	store, id, retention := transferArtifactFixture(t)
	ctx := context.Background()
	first, err := store.BeginTransferArtifact(ctx, id, TransferFormatSQL, TransferCompressionNone, retention)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.BeginTransferArtifact(ctx, id, TransferFormatSQL, TransferCompressionNone, retention)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Abort(ctx)
	defer second.Abort(ctx)
	data := []byte("immutable winner")
	if _, err = first.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err = second.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err = first.Commit(ctx, transferDigest(data), uint64(len(data)), 1); err != nil {
		t.Fatal(err)
	}
	if _, err = second.Commit(ctx, transferDigest(data), uint64(len(data)), 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("second writer replaced artifact: %v", err)
	}
}
