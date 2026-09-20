//go:build linux

package database

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTransferIncomingRetention(t *testing.T) {
	for _, variant := range []string{"active", "closed-active", "abandoned", "unexpired", "hold", "unknown", "symlink", "hardlink", "bad-metadata", "missing-metadata", "tombstone", "empty-tombstone"} {
		t.Run(variant, func(t *testing.T) {
			store, id, retention := transferArtifactFixture(t)
			retention.LegalHold = variant == "hold"
			w, err := store.BeginTransferArtifact(context.Background(), id, TransferFormatSQL, TransferCompressionNone, retention)
			if err != nil {
				t.Fatal(err)
			}
			writer := w.(*transferArtifactFileWriter)
			defer func() { writer.file.Close(); writer.lease.Close() }()
			if _, err := writer.Write([]byte("interrupted transfer")); err != nil {
				t.Fatal(err)
			}
			if variant == "closed-active" {
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if variant != "active" && variant != "closed-active" {
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				if err := writer.lease.Close(); err != nil {
					t.Fatal(err)
				}
			}
			store.now = func() time.Time { return retention.RetainUntil }
			if variant == "unexpired" {
				store.now = time.Now
			}
			want, wantErr := 0, false
			switch variant {
			case "abandoned":
				want = 1
			case "unknown":
				if err := os.WriteFile(filepath.Join(writer.staging, "preserve"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
				wantErr = true
			case "symlink":
				path := filepath.Join(writer.staging, "payload")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("descriptor.json", path); err != nil {
					t.Fatal(err)
				}
				wantErr = true
			case "hardlink":
				if err := os.Link(filepath.Join(writer.staging, "payload"), filepath.Join(filepath.Dir(store.root), "outside-payload")); err != nil {
					t.Fatal(err)
				}
				wantErr = true
			case "bad-metadata":
				if err := os.WriteFile(filepath.Join(writer.staging, "descriptor.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				wantErr = true
			case "missing-metadata":
				if err := os.Remove(filepath.Join(writer.staging, "descriptor.json")); err != nil {
					t.Fatal(err)
				}
			case "tombstone", "empty-tombstone":
				path := filepath.Join(store.root, ".abandoned-12345")
				if err := os.Rename(writer.staging, path); err != nil {
					t.Fatal(err)
				}
				writer.staging = path
				if variant == "empty-tombstone" {
					for _, name := range []string{"payload", "descriptor.json"} {
						if err := os.Remove(filepath.Join(path, name)); err != nil {
							t.Fatal(err)
						}
					}
				}
				want = 1
			}
			count, err := store.CollectExpired(context.Background(), 1)
			if count != want || (err != nil) != wantErr {
				t.Fatalf("count=%d err=%v", count, err)
			}
			_, err = os.Lstat(writer.staging)
			if (want == 1) != os.IsNotExist(err) {
				t.Fatal("unexpected staging lifetime", err)
			}
		})
	}
}

func TestTransferIncomingCrashHelper(t *testing.T) {
	root := os.Getenv("CYBERPANEL_INCOMING_CRASH_ROOT")
	if root == "" {
		t.Skip("subprocess helper")
	}
	store, err := NewLinuxTransferArtifactStore(root, 1<<20, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := NewResourceID("crashed-writer")
	writer, err := store.BeginTransferArtifact(context.Background(), TransferArtifactIdentity{StoreID: id, ArtifactID: id, Generation: 1}, TransferFormatSQL, TransferCompressionNone, TransferRetention{RetainUntil: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("real process crash")); err != nil {
		t.Fatal(err)
	}
	fmt.Println("writer-ready")
	for {
		time.Sleep(time.Hour)
	}
}

func TestTransferIncomingProcessCrash(t *testing.T) {
	store, _, _ := transferArtifactFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTransferIncomingCrashHelper$")
	child.Env = append(os.Environ(), "CYBERPANEL_INCOMING_CRASH_ROOT="+store.root)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "writer-ready\n" {
		t.Fatal("child did not establish live writer", err)
	}
	store.now = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }
	if count, err := store.CollectExpired(ctx, 1); err != nil || count != 0 {
		t.Fatal("live process collected", count, err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("child was not killed")
	}
	if count, err := store.CollectExpired(ctx, 1); err != nil || count != 1 {
		t.Fatal("crashed process not collected", count, err)
	}
	entries, err := os.ReadDir(store.root)
	if err != nil || len(entries) != 0 {
		t.Fatal("crash bytes remain", err)
	}
}
