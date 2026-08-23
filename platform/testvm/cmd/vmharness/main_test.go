package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRunDoctorWritesOnlyJSONToStdout(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	called := false
	exitCode := run(context.Background(), []string{"doctor", "--config", "/etc/vmharness/qemu.json"}, &stdout, &stderr, operations{
		Doctor: func(_ context.Context, configPath string) (any, error) {
			called = true
			if configPath != "/etc/vmharness/qemu.json" {
				t.Fatalf("doctor config path = %q", configPath)
			}
			return map[string]any{"status": "ready", "qemuVersion": "11.0.3"}, nil
		},
	})
	if exitCode != 0 || !called {
		t.Fatalf("run() exit code = %d, doctor called = %t", exitCode, called)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty on success", stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout = %q, want exactly one JSON document: %v", stdout.String(), err)
	}
	if report["status"] != "ready" || strings.TrimSpace(stdout.String()) == "" {
		t.Fatalf("doctor JSON = %#v", report)
	}
}

func TestRunImageVerifyPassesOnlyConfigLockAndStableIDAuthorities(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	var gotConfig, gotLock, gotID string
	exitCode := run(context.Background(), []string{
		"image-verify",
		"--config", "/etc/vmharness/qemu.json",
		"--lock", "/srv/vmharness/images.lock.json",
		"--image", "ubuntu-24.04-20260801-arm64",
	}, &stdout, &stderr, operations{
		ImageVerify: func(_ context.Context, configPath, lockPath, stableID string) (any, error) {
			gotConfig, gotLock, gotID = configPath, lockPath, stableID
			return map[string]any{"status": "verified", "stableId": stableID}, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if gotConfig != "/etc/vmharness/qemu.json" || gotLock != "/srv/vmharness/images.lock.json" || gotID != "ubuntu-24.04-20260801-arm64" {
		t.Fatalf("image verification authority = (%q, %q, %q)", gotConfig, gotLock, gotID)
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout = %q, want JSON: %v", stdout.String(), err)
	}
}

func TestRunRejectsUnknownCommandsFlagsAndMissingClosedInputs(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"start", "--config", "/etc/vmharness/qemu.json"},
		{"doctor"},
		{"doctor", "--qemu", "/tmp/untrusted-qemu"},
		{"doctor", "--config", "/etc/vmharness/qemu.json", "unexpected"},
		{"image-verify", "--config", "/etc/vmharness/qemu.json", "--lock", "/srv/vmharness/images.lock.json"},
		{"image-verify", "--image-path", "/tmp/untrusted.qcow2"},
	}

	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			called := false
			exitCode := run(context.Background(), args, &stdout, &stderr, operations{
				Doctor: func(context.Context, string) (any, error) { called = true; return nil, errors.New("must not run") },
				ImageVerify: func(context.Context, string, string, string) (any, error) { called = true; return nil, errors.New("must not run") },
			})
			if exitCode == 0 {
				t.Fatalf("run(%#v) exit code = 0, want nonzero", args)
			}
			if called {
				t.Fatalf("run(%#v) invoked an operation after invalid input", args)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want no non-JSON diagnostics", stdout.String())
			}
			if strings.TrimSpace(stderr.String()) == "" {
				t.Fatal("stderr = empty, want diagnostic")
			}
		})
	}
}
