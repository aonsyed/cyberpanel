//go:build linux

package apps

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestQEMUCertifiedBootstrapExecutesPackagedPHPCLI(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_APP_PHP") != "1" {
		t.Skip("requires installed native PHP CLI in QEMU")
	}
	if os.Geteuid() != 0 {
		t.Fatal("QEMU root required for credential boundary")
	}
	root := t.TempDir()
	entry := `<?php
if (PHP_SAPI !== 'cli' || $argv !== [__FILE__, 'fixture-value']) { exit(23); }
file_put_contents(__DIR__ . '/executed', 'bootstrap-cli-ok');
`
	if err := os.WriteFile(filepath.Join(root, "entry.php"), []byte(entry), 0600); err != nil {
		t.Fatal(err)
	}
	runtime := &LinuxApplicationRuntime{}
	scope := linuxApplicationScope{root: root, binding: LinuxApplicationSiteBinding{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}}
	if err := runtime.runApplicationBootstrap(context.Background(), scope, "php83", "entry.php", []string{"fixture-value"}); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(filepath.Join(root, "executed"))
	if err != nil || string(value) != "bootstrap-cli-ok" {
		t.Fatalf("native bootstrap did not execute: %v, %q", err, value)
	}
	for _, name := range []string{".cyberpanel-bootstrap.php", ".cyberpanel-bootstrap.json"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("bootstrap material remains: %s", name)
		}
	}
}
