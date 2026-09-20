//go:build linux

package database

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTransferRetentionCollection(t *testing.T) {
	for _, variant := range []string{"expired", "live", "hold", "renamed", "payload-removed", "empty-tombstone", "unknown-file", "bad-metadata", "identity", "symlink", "hardlink", "mode", "cancelled"} {
		t.Run(variant, func(t *testing.T) {
			store, id, retention := transferArtifactFixture(t)
			ctx := context.Background()
			retention.LegalHold = variant == "hold"
			writer, err := store.BeginTransferArtifact(ctx, id, TransferFormatSQL, TransferCompressionNone, retention)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("retention fixture")
			if _, err = writer.Write(data); err != nil {
				t.Fatal(err)
			}
			if _, err = writer.Commit(ctx, transferDigest(data), uint64(len(data)), 0); err != nil {
				t.Fatal(err)
			}
			directory, _ := store.artifactPath(id)
			store.now = func() time.Time { return retention.RetainUntil }
			want := 0
			wantErr := false
			switch variant {
			case "expired":
				want = 1
			case "live":
				store.now = time.Now
			case "hold":
			case "renamed", "payload-removed", "empty-tombstone":
				target := filepath.Join(store.root, ".expired-"+filepath.Base(directory))
				if err = os.Rename(directory, target); err != nil {
					t.Fatal(err)
				}
				directory = target
				if variant != "renamed" {
					if err = os.Remove(filepath.Join(directory, "payload")); err != nil {
						t.Fatal(err)
					}
				}
				if variant == "empty-tombstone" {
					if err = os.Remove(filepath.Join(directory, "descriptor.json")); err != nil {
						t.Fatal(err)
					}
				}
				want = 1
			case "unknown-file":
				err = os.WriteFile(filepath.Join(directory, "do-not-delete"), data, 0600)
				wantErr = true
			case "bad-metadata":
				err = os.WriteFile(filepath.Join(directory, "descriptor.json"), []byte("{}"), 0600)
				wantErr = true
			case "identity":
				path := filepath.Join(directory, "descriptor.json")
				raw, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal(readErr)
				}
				var meta transferArtifactMetadata
				if err = json.Unmarshal(raw, &meta); err != nil {
					t.Fatal(err)
				}
				meta.Descriptor.Identity.Generation++
				raw, err = json.Marshal(meta)
				if err != nil {
					t.Fatal(err)
				}
				err = os.WriteFile(path, raw, 0600)
				wantErr = true
			case "symlink", "hardlink":
				payload := filepath.Join(directory, "payload")
				outside := filepath.Join(filepath.Dir(store.root), "preserved")
				if err = os.Rename(payload, outside); err != nil {
					t.Fatal(err)
				}
				if variant == "symlink" {
					err = os.Symlink(outside, payload)
				} else {
					err = os.Link(outside, payload)
				}
				wantErr = true
			case "mode":
				err = os.Chmod(directory, 0755)
				wantErr = true
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				wantErr = true
			}
			if err != nil {
				t.Fatal(err)
			}
			count, err := store.CollectExpired(ctx, 64)
			if count != want || (err != nil) != wantErr {
				t.Fatalf("collected=%d err=%v", count, err)
			}
			_, statErr := os.Lstat(directory)
			if want == 1 && !os.IsNotExist(statErr) {
				t.Fatalf("expired artifact retained: %v", statErr)
			}
			if want == 0 && statErr != nil {
				t.Fatalf("protected artifact lost: %v", statErr)
			}
			if variant == "symlink" || variant == "hardlink" {
				raw, err := os.ReadFile(filepath.Join(filepath.Dir(store.root), "preserved"))
				if err != nil || string(raw) != string(data) {
					t.Fatal("outside file changed")
				}
			}
			if want == 1 {
				if count, err = store.CollectExpired(ctx, 64); count != 0 || err != nil {
					t.Fatalf("replay: %d %v", count, err)
				}
			}
		})
	}
}

func TestTransferRetentionBoundAndActiveWriter(t *testing.T) {
	store, id, retention := transferArtifactFixture(t)
	ctx := context.Background()
	for generation := uint64(1); generation <= 3; generation++ {
		id.Generation = generation
		writer, err := store.BeginTransferArtifact(ctx, id, TransferFormatSQL, TransferCompressionNone, retention)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = writer.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, err = writer.Commit(ctx, transferDigest([]byte("x")), 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	id.Generation++
	active, err := store.BeginTransferArtifact(ctx, id, TransferFormatSQL, TransferCompressionNone, retention)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Abort(ctx)
	store.now = func() time.Time { return retention.RetainUntil.Add(time.Second) }
	for _, expected := range []int{2, 1, 0} {
		if count, err := store.CollectExpired(ctx, 2); count != expected || err != nil {
			t.Fatalf("bound: %d %v", count, err)
		}
	}
	if _, err := active.Write([]byte("still open")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(store.root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("incoming writer lost: %v", err)
	}
	if _, err = store.CollectExpired(ctx, 0); !errors.Is(err, ErrTransferInvalid) {
		t.Fatal("invalid bound accepted")
	}
}

// Opt-in installed-daemon probe. Seed immediately before a signed upgrade, then
// verify after service activation. Ordinary test runs never touch installed data.
func TestQEMURetentionDaemonFixture(t *testing.T) {
	phase := os.Getenv("CYBERPANEL_QEMU_RETENTION_PHASE")
	if phase == "" {
		t.Skip("explicit QEMU installed-daemon probe only")
	}
	if os.Getenv("CYBERPANEL_QEMU_LIVE_TRANSFER") != "1" || os.Geteuid() != 0 || (phase != "seed" && phase != "verify") {
		t.Fatal("invalid QEMU fixture invocation")
	}
	now := time.Now().UTC()
	store, err := NewLinuxTransferArtifactStore(workspaceExportRoot, MaximumTransferBytes, func() time.Time { return now.Add(-2 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	storeID, _ := NewResourceID("qemu-retention-daemon-fixture")
	for _, variant := range []string{"expired", "held", "live", "interrupted"} {
		artifactID, _ := NewResourceID("qemu-retention-daemon-" + variant)
		id := TransferArtifactIdentity{StoreID: storeID, ArtifactID: artifactID, Generation: 1}
		directory, _ := store.artifactPath(id)
		if phase == "seed" {
			retention := TransferRetention{RetainUntil: now.Add(-time.Hour), LegalHold: variant == "held"}
			if variant == "live" {
				retention.RetainUntil = now.Add(time.Hour)
			}
			writer, err := store.BeginTransferArtifact(context.Background(), id, TransferFormatSQL, TransferCompressionNone, retention)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("-- synthetic QEMU retention probe; no customer data\n")
			if _, err = writer.Write(data); err != nil {
				t.Fatal(err)
			}
			if _, err = writer.Commit(context.Background(), transferDigest(data), uint64(len(data)), 0); err != nil {
				t.Fatal(err)
			}
			if variant == "interrupted" {
				target := filepath.Join(store.root, ".expired-"+filepath.Base(directory))
				if err = os.Rename(directory, target); err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(filepath.Join(target, "payload")); err != nil {
					t.Fatal(err)
				}
			}
			continue
		}
		if variant == "interrupted" {
			directory = filepath.Join(store.root, ".expired-"+filepath.Base(directory))
		}
		_, err := os.Lstat(directory)
		if variant == "expired" || variant == "interrupted" {
			if !os.IsNotExist(err) {
				t.Fatalf("daemon failed to collect %s: %v", variant, err)
			}
		} else if err != nil {
			t.Fatalf("daemon removed protected %s: %v", variant, err)
		}
	}
	if phase == "verify" {
		// Only after all preservation assertions pass, remove the two exact
		// synthetic fixtures; never recursively clean the installed export root.
		for _, variant := range []string{"held", "live"} {
			artifactID, _ := NewResourceID("qemu-retention-daemon-" + variant)
			directory, _ := store.artifactPath(TransferArtifactIdentity{StoreID: storeID, ArtifactID: artifactID, Generation: 1})
			for _, name := range []string{"payload", "descriptor.json"} {
				if err := os.Remove(filepath.Join(directory, name)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(directory); err != nil {
				t.Fatal(err)
			}
		}
	}
}
