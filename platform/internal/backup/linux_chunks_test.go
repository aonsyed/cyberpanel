//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLinuxChunkCaptureReassembly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires native root-owned backup spool")
	}
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "capture")
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	for i := 0; i < 18; i++ {
		if _, err = io.Copy(io.MultiWriter(file, hash), strings.NewReader(strings.Repeat(strconv.Itoa(i%10), 1<<20))); err != nil {
			t.Fatal(err)
		}
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	objects, total, digest, err := commitLinuxBackupChunks(ctx, source, root, "site/files.tar")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 || total != 18<<20 {
		t.Fatalf("chunks=%d bytes=%d", len(objects), total)
	}
	artifact := ArtifactManifest{ID: "artifact", Component: ComponentFiles, ObjectCount: uint64(len(objects)), Bytes: total, RootDigest: digest, Tool: "fixture", SchemaVersion: 1, SourceGeneration: 1, Consistency: ConsistencyFuzzy, Objects: objects}
	component := filepath.Join(root, "scratch", string(ComponentFiles))
	if err = os.MkdirAll(component, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := RecoveryPointManifest{RecoveryPointID: "point", PolicyID: "policy", TenantID: "tenant", Scope: "site", WriteFrontier: 1, SourceGeneration: 1, CreatedAt: time.Now().UTC(), RequiredComponents: []ComponentKind{ComponentFiles}, Artifacts: []ArtifactManifest{artifact}}
	manifest.ManifestDigest, err = RecoveryPointDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeLinuxBackupJSON(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	if err = writeLinuxBackupJSON(filepath.Join(component, "artifact.json"), artifact); err != nil {
		t.Fatal(err)
	}
	plan := RestorePlanSpec{ComponentMapping: map[ComponentKind]string{ComponentFiles: "site"}}
	restore := func() {
		t.Helper()
		for i, object := range objects {
			raw, err := os.ReadFile(filepath.Join(root, object.Digest))
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(component, "object-"+strconv.Itoa(i)), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	restore()
	if err = verifyLinuxBackupComponents(ctx, root, "scratch", plan); err != nil {
		t.Fatal(err)
	}
	got, size, err := digestLinuxBackupFile(filepath.Join(component, "assembled"))
	if err != nil || size != total || got != hex.EncodeToString(hash.Sum(nil)) {
		t.Fatal("reassembly mismatch", err)
	}
	for _, mutation := range []string{"missing", "reordered", "corrupt", "truncated"} {
		t.Run(mutation, func(t *testing.T) {
			restore()
			first := filepath.Join(component, "object-0")
			second := filepath.Join(component, "object-1")
			switch mutation {
			case "missing":
				err = os.Remove(second)
			case "reordered":
				err = os.Rename(first, first+".swap")
				if err == nil {
					err = os.Rename(second, first)
				}
				if err == nil {
					err = os.Rename(first+".swap", second)
				}
			case "corrupt":
				err = os.WriteFile(second, []byte("corrupt"), 0600)
			case "truncated":
				err = os.Truncate(second, 1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if verifyLinuxBackupComponents(ctx, root, "scratch", plan) == nil {
				t.Fatal("invalid chunks accepted")
			}
			for _, name := range []string{"assembled", "assembled.partial"} {
				if _, err = os.Stat(filepath.Join(component, name)); !os.IsNotExist(err) {
					t.Fatal("failed reassembly left consumable/partial file", name, err)
				}
			}
		})
	}
	// Existing single-object inventories use the same verified reassembly path.
	small := filepath.Join(root, "legacy")
	if err = os.WriteFile(small, []byte("legacy tar bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	legacy, bytes, rootDigest, err := commitLinuxBackupChunks(ctx, small, root, "site/files.tar")
	if err != nil || len(legacy) != 1 || legacy[0].Key != "site/files.tar" {
		t.Fatal("legacy single object", err)
	}
	artifact.Objects = legacy
	artifact.Bytes = bytes
	artifact.RootDigest = rootDigest
	artifact.ObjectCount = 1
	raw, err := os.ReadFile(filepath.Join(root, legacy[0].Digest))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(component, "object-0"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = assembleLinuxBackupArtifact(ctx, component, artifact); err != nil {
		t.Fatal(err)
	}
}
