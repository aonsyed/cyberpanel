//go:build linux

package apps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWordPressSnapshotImportStreamsVerifiedDump(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("QEMU root required for runtime credential switching")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "wp-content"), 0700); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(root, "wp-fixture")
	// This captures the production call boundary; the separate live database
	// test exercises real WP-CLI with MariaDB and rejects invalid TLS identities.
	if err := os.WriteFile(command, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > arguments\ncat > input.sql\n"), 0700); err != nil {
		t.Fatal(err)
	}
	runtime := &LinuxApplicationRuntime{WPCLI: command}
	scope := linuxApplicationScope{root: root, binding: LinuxApplicationSiteBinding{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}}
	payload := []byte("SET SESSION sql_mode='NO_AUTO_VALUE_ON_ZERO';\nSELECT 7;\n")
	dump := filepath.Join(root, "snapshot.sql")
	if err := os.WriteFile(dump, payload, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{DatabaseDigest: linuxApplicationDigest(payload)}
	if err := runtime.importWordPressSnapshot(context.Background(), scope, snapshot, dump); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(filepath.Join(root, "arguments"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(args), "db\nimport\n-\n") || strings.Contains(string(args), dump) {
		t.Fatalf("snapshot not streamed: %s", args)
	}
	got, err := os.ReadFile(filepath.Join(root, "input.sql"))
	if err != nil || string(got) != string(payload) {
		t.Fatal("snapshot stream changed")
	}
	if err := os.Remove(filepath.Join(root, "arguments")); err != nil {
		t.Fatal(err)
	}
	snapshot.DatabaseDigest = linuxApplicationDigest([]byte("different"))
	if err := runtime.importWordPressSnapshot(context.Background(), scope, snapshot, dump); !errors.Is(err, ErrIntegrity) {
		t.Fatal("mismatched snapshot imported")
	}
	if _, err := os.Stat(filepath.Join(root, "arguments")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("command launched before digest verification")
	}
	symlink := filepath.Join(root, "snapshot-link.sql")
	if err := os.Symlink(dump, symlink); err != nil {
		t.Fatal(err)
	}
	if err := runtime.importWordPressSnapshot(context.Background(), scope, snapshot, symlink); !errors.Is(err, ErrIntegrity) {
		t.Fatal("symlink snapshot accepted")
	}
}
