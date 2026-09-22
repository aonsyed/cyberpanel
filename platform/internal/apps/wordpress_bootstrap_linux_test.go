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

func TestWordPressBootstrapUsesOnlyLocalInputs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("QEMU root required for runtime credential switching")
	}
	for _, locale := range []string{"en_US", "fr_FR"} {
		t.Run(locale, func(t *testing.T) {
			root := t.TempDir()
			binary := filepath.Join(root, "wp-fixture")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> arguments\n"), 0700); err != nil {
				t.Fatal(err)
			}
			runtime := &LinuxApplicationRuntime{WPCLI: binary}
			scope := linuxApplicationScope{root: root, binding: LinuxApplicationSiteBinding{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}}
			err := runtime.finishWordPressBootstrap(context.Background(), scope, locale, "UTC")
			args, readErr := os.ReadFile(filepath.Join(root, "arguments"))
			if locale != "en_US" {
				if !errors.Is(err, ErrRecipeUnavailable) || !strings.Contains(err.Error(), "unavailable locally") || !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("missing language must fail before commands: error=%v, args=%s", err, args)
				}
				return
			}
			if err != nil || readErr != nil {
				t.Fatalf("default bootstrap: %v / %v", err, readErr)
			}
			if strings.Contains(string(args), "install") || strings.Contains(string(args), "language") || strings.Contains(string(args), "plugin") || !strings.HasSuffix(string(args), "option\nupdate\ntimezone_string\nUTC\n") {
				t.Fatalf("unexpected default bootstrap commands: %s", args)
			}
		})
	}
}

func TestWordPressBootstrapActivatesLocalLanguageAndReportsCommandFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("QEMU root required for runtime credential switching")
	}
	root := t.TempDir()
	languages := filepath.Join(root, "wp-content", "languages")
	if err := os.MkdirAll(languages, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(languages, "fr_FR.mo"), []byte("local fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "wp-fixture")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> arguments\n"), 0700); err != nil {
		t.Fatal(err)
	}
	runtime := &LinuxApplicationRuntime{WPCLI: binary}
	scope := linuxApplicationScope{root: root, binding: LinuxApplicationSiteBinding{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}}
	if err := runtime.finishWordPressBootstrap(context.Background(), scope, "fr_FR", "UTC"); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(filepath.Join(root, "arguments"))
	if err != nil || !strings.Contains(string(args), "language\ncore\nactivate\nfr_FR\n") || strings.Contains(string(args), "install") {
		t.Fatalf("local language activation: %v: %s", err, args)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, locale := range []string{"en_US", "fr_FR"} {
		if err := runtime.finishWordPressBootstrap(context.Background(), scope, locale, "UTC"); err == nil {
			t.Fatalf("%s command failure was silently ignored", locale)
		}
	}
}
