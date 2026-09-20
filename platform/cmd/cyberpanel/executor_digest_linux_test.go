//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

func TestInstalledExecutorDigest(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_NODE_RELEASE") != "1" {
		t.Skip("requires installed QEMU node release")
	}
	const path = "/usr/local/libexec/cyberpanel/panel-execd"
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("fixture must exercise installed release symlink", err)
	}
	got, err := webEngineExecutableDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("digest differs from installed executor bytes")
	}
}
