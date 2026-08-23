// vmharness provides the closed host checks and locked-image verifier used by
// the platform test VM workflow.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/testvm/internal/doctor"
	"github.com/aonsyed/cyberpanel/platform/testvm/internal/images"
	"github.com/aonsyed/cyberpanel/platform/testvm/internal/qemu"
)

type operations struct {
	Doctor      func(context.Context, string) (any, error)
	ImageVerify func(context.Context, string, string, string) (any, error)
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, defaultOperations()))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, operation operations) int {
	if len(args) == 0 {
		return diagnostic(stderr, "missing command")
	}
	if ctx == nil {
		return diagnostic(stderr, "context is nil")
	}
	if err := ctx.Err(); err != nil {
		return diagnostic(stderr, err.Error())
	}

	var result any
	var err error
	switch args[0] {
	case "doctor":
		flags, parseErr := parseFlags(args[1:], "config")
		if parseErr != nil {
			return diagnostic(stderr, parseErr.Error())
		}
		configPath := flags["config"]
		if err := validateAbsolutePath("config", configPath); err != nil {
			return diagnostic(stderr, err.Error())
		}
		if operation.Doctor == nil {
			return diagnostic(stderr, "doctor operation is unavailable")
		}
		result, err = operation.Doctor(ctx, configPath)
	case "image-verify":
		flags, parseErr := parseFlags(args[1:], "config", "lock", "image")
		if parseErr != nil {
			return diagnostic(stderr, parseErr.Error())
		}
		configPath, lockPath, stableID := flags["config"], flags["lock"], flags["image"]
		if err := validateAbsolutePath("config", configPath); err != nil {
			return diagnostic(stderr, err.Error())
		}
		if err := validateAbsolutePath("lock", lockPath); err != nil {
			return diagnostic(stderr, err.Error())
		}
		if !validStableID(stableID) {
			return diagnostic(stderr, "image must be a non-empty stable identifier")
		}
		if operation.ImageVerify == nil {
			return diagnostic(stderr, "image-verify operation is unavailable")
		}
		result, err = operation.ImageVerify(ctx, configPath, lockPath, stableID)
	default:
		return diagnostic(stderr, fmt.Sprintf("unknown command %q", args[0]))
	}
	if err != nil {
		return diagnostic(stderr, err.Error())
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return diagnostic(stderr, fmt.Sprintf("write JSON result: %v", err))
	}
	return 0
}

func parseFlags(args []string, allowed ...string) (map[string]string, error) {
	flags := make(map[string]string, len(allowed))
	permitted := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		permitted[name] = struct{}{}
	}
	for len(args) > 0 {
		if len(args) < 2 || !strings.HasPrefix(args[0], "--") || strings.Contains(args[0], "=") {
			return nil, fmt.Errorf("invalid flag syntax")
		}
		name := strings.TrimPrefix(args[0], "--")
		if _, ok := permitted[name]; !ok {
			return nil, fmt.Errorf("unknown flag %q", args[0])
		}
		if _, duplicate := flags[name]; duplicate {
			return nil, fmt.Errorf("duplicate flag %q", args[0])
		}
		if args[1] == "" || strings.HasPrefix(args[1], "--") {
			return nil, fmt.Errorf("flag %q requires a value", args[0])
		}
		flags[name] = args[1]
		args = args[2:]
	}
	for _, name := range allowed {
		if flags[name] == "" {
			return nil, fmt.Errorf("missing required flag --%s", name)
		}
	}
	return flags, nil
}

func validateAbsolutePath(name, value string) error {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%s must be an absolute canonical path", name)
	}
	return nil
}

func validStableID(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func diagnostic(stderr io.Writer, message string) int {
	_, _ = fmt.Fprintln(stderr, "vmharness:", message)
	return 1
}

func defaultOperations() operations {
	return operations{
		Doctor: doctorOperation,
		ImageVerify: imageVerifyOperation,
	}
}

func doctorOperation(ctx context.Context, configPath string) (any, error) {
	config, err := readDoctorConfig(configPath)
	if err != nil {
		return nil, err
	}
	return doctor.Check(ctx, config, qemu.ExecRunner{}, osStatter{})
}

func imageVerifyOperation(ctx context.Context, configPath, lockPath, stableID string) (any, error) {
	config, err := readDoctorConfig(configPath)
	if err != nil {
		return nil, err
	}
	if _, err := doctor.Check(ctx, config, qemu.ExecRunner{}, osStatter{}); err != nil {
		return nil, err
	}
	lockData, err := readRegularFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read image lock: %w", err)
	}
	lock, err := images.Parse(lockData)
	if err != nil {
		return nil, err
	}
	for _, image := range lock.Images {
		if image.StableID != stableID {
			continue
		}
		imagePath, err := filepath.Abs(image.RuntimePath)
		if err != nil {
			return nil, fmt.Errorf("resolve locked image path: %w", err)
		}
		if err := images.Verify(ctx, image, imagePath, config.QEMUImgPath, imageRunner{runner: qemu.ExecRunner{}}); err != nil {
			return nil, err
		}
		return map[string]string{"status": "verified", "stableId": image.StableID}, nil
	}
	return nil, fmt.Errorf("image %q is not in the lock", stableID)
}

func readDoctorConfig(path string) (doctor.Config, error) {
	data, err := readRegularFile(path)
	if err != nil {
		return doctor.Config{}, fmt.Errorf("read doctor config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var config doctor.Config
	if err := decoder.Decode(&config); err != nil {
		return doctor.Config{}, fmt.Errorf("decode doctor config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return doctor.Config{}, fmt.Errorf("decode doctor config: trailing JSON value")
		}
		return doctor.Config{}, fmt.Errorf("decode doctor config trailing data: %w", err)
	}
	return config, nil
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("must be a regular file without symlinks")
	}
	return os.ReadFile(path)
}

type osStatter struct{}

func (osStatter) Lstat(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

type imageRunner struct{ runner qemu.Runner }

func (runner imageRunner) Run(ctx context.Context, path string, args []string, maxOutputBytes int64) (images.CommandResult, error) {
	result, err := runner.runner.Run(ctx, qemu.Command{
		Path:           path,
		Args:           args,
		Env:            []string{},
		Dir:            "/",
		Timeout:        30 * time.Second,
		MaxOutputBytes: maxOutputBytes,
	})
	return images.CommandResult{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode}, err
}
