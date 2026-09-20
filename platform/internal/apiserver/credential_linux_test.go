//go:build linux

package apiserver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignerRejectsOrdinaryGroupReadableFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway-signer")
	if err := os.WriteFile(path, []byte("not a credential"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(path, 1024); err == nil {
		t.Fatal("accepted ordinary group-readable file")
	}
}

func TestQEMUGatewaySystemdSigner(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_GATEWAY_CREDENTIAL") != "1" {
		t.Skip("requires actual gateway systemd credential namespace")
	}
	if _, err := LoadSigner("/run/credentials/panel-gateway.service/gateway-signer"); err != nil {
		t.Fatal(err)
	}
}
