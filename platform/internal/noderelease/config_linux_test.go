//go:build linux

package noderelease

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedConfigResolution(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned fixture; run inside QEMU with TMPDIR beneath /root")
	}
	for _, variant := range []string{"valid", "executable", "writable executable", "arbitrary link", "wrong generation", "writable ancestor", "symlink payload", "credential"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			configRoot := filepath.Join(root, "etc", "cyberpanel")
			active := filepath.Join(root, "opt", "node-current")
			releases := filepath.Join(root, "opt", "node-releases")
			generation := filepath.Join(releases, strings.Repeat("a", 64))
			path := filepath.Join(configRoot, "panel.json")
			if variant == "credential" {
				path = filepath.Join(configRoot, "secrets", "key.json")
			}
			resolved := filepath.Join(generation, "root", strings.TrimPrefix(path, "/"))
			for _, dir := range []string{filepath.Dir(path), filepath.Dir(resolved)} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(resolved, []byte("{}\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if variant == "executable" || variant == "writable executable" {
				mode := os.FileMode(0755)
				if variant == "writable executable" {
					mode = 0775
				}
				if err := os.Chmod(resolved, mode); err != nil {
					t.Fatal(err)
				}
			}
			target := filepath.Join(active, "root", strings.TrimPrefix(path, "/"))
			if variant == "arbitrary link" {
				target = resolved
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			activeTarget := generation
			if variant == "wrong generation" {
				activeTarget = filepath.Join(releases, "unverified")
			}
			if err := os.Symlink(activeTarget, active); err != nil {
				t.Fatal(err)
			}
			if variant == "writable ancestor" {
				if err := os.Chmod(filepath.Join(root, "opt"), 0777); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "symlink payload" {
				if err := os.Rename(resolved, resolved+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(resolved+".real", resolved); err != nil {
					t.Fatal(err)
				}
			}
			got, err := resolveConfigPath(path, configRoot, active, releases)
			if variant == "executable" || variant == "writable executable" {
				if err == nil {
					t.Fatal("config resolver accepted executable permissions")
				}
				got, err = resolveManagedPath(path, configRoot, active, releases, 0755)
			}
			if variant == "valid" || variant == "executable" {
				if err != nil || got != resolved {
					t.Fatalf("resolve = %q, %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("accepted %s: %s", variant, got)
			}
		})
	}
}
