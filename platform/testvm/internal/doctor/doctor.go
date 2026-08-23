// Package doctor verifies the fixed host contract used by vmharness.
package doctor

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/testvm/internal/qemu"
)

const maxProbeOutputBytes int64 = 64 << 10

// Config is the closed host-tool contract for the supported Apple Silicon
// QEMU profile. Tool paths are executable identities, not search terms.
type Config struct {
	QEMUPath    string `json:"qemuPath"`
	QEMUImgPath string `json:"qemuImgPath"`
	HostOS      string `json:"hostOS"`
	HostArch    string `json:"hostArch"`
	Accelerator string `json:"accelerator"`
	Machine     string `json:"machine"`
}

// Report records the observations used to accept a host. It deliberately
// contains values observed from the configured binary rather than mutable host
// configuration.
type Report struct {
	QEMUPath     string   `json:"qemuPath"`
	QEMUImgPath  string   `json:"qemuImgPath"`
	QEMUVersion  string   `json:"qemuVersion"`
	HostOS       string   `json:"hostOS"`
	HostArch     string   `json:"hostArch"`
	Accelerators []string `json:"accelerators"`
	Machines     []string `json:"machines"`
}

// Statter supplies lstat observations. Check is read-only and never mutates
// either the filesystem or the host configuration.
type Statter interface {
	Lstat(string) (fs.FileInfo, error)
}

// Check validates config and gathers the exact QEMU observations needed for
// the supported tuple. It fails closed on any unavailable or unexpected value.
func Check(ctx context.Context, config Config, runner qemu.Runner, stat Statter) (Report, error) {
	if ctx == nil {
		return Report{}, fmt.Errorf("doctor context is nil")
	}
	if runner == nil {
		return Report{}, fmt.Errorf("doctor runner is nil")
	}
	if stat == nil {
		return Report{}, fmt.Errorf("doctor statter is nil")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if err := validateConfig(config); err != nil {
		return Report{}, err
	}
	for _, tool := range []string{config.QEMUPath, config.QEMUImgPath} {
		info, err := stat.Lstat(tool)
		if err != nil {
			return Report{}, fmt.Errorf("inspect tool %q: %w", tool, err)
		}
		if !info.Mode().IsRegular() {
			return Report{}, fmt.Errorf("tool %q must be a regular file without symlinks", tool)
		}
	}

	version, err := probe(ctx, runner, config.QEMUPath, []string{"--version"})
	if err != nil {
		return Report{}, err
	}
	if !hasVersion(version.Stdout, qemu.SupportedQEMUVersion) {
		return Report{}, fmt.Errorf("qemu version must be exactly %s", qemu.SupportedQEMUVersion)
	}
	acceleratorsResult, err := probe(ctx, runner, config.QEMUPath, []string{"-accel", "help"})
	if err != nil {
		return Report{}, err
	}
	accelerators := helpNames(acceleratorsResult.Stdout)
	if !contains(accelerators, config.Accelerator) {
		return Report{}, fmt.Errorf("required accelerator %q is unavailable", config.Accelerator)
	}
	machinesResult, err := probe(ctx, runner, config.QEMUPath, []string{"-machine", "help"})
	if err != nil {
		return Report{}, err
	}
	machines := helpNames(machinesResult.Stdout)
	if !contains(machines, config.Machine) {
		return Report{}, fmt.Errorf("required machine %q is unavailable", config.Machine)
	}

	return Report{
		QEMUPath:     config.QEMUPath,
		QEMUImgPath:  config.QEMUImgPath,
		QEMUVersion:  qemu.SupportedQEMUVersion,
		HostOS:       config.HostOS,
		HostArch:     config.HostArch,
		Accelerators: accelerators,
		Machines:     machines,
	}, nil
}

func validateConfig(config Config) error {
	if err := validateToolPath("qemu path", config.QEMUPath, "qemu-system-aarch64"); err != nil {
		return err
	}
	if err := validateToolPath("qemu-img path", config.QEMUImgPath, "qemu-img"); err != nil {
		return err
	}
	if config.HostOS != "darwin" {
		return fmt.Errorf("host OS must be darwin")
	}
	if config.HostArch != "arm64" {
		return fmt.Errorf("host architecture must be arm64")
	}
	if config.Accelerator != "hvf" {
		return fmt.Errorf("accelerator must be hvf")
	}
	if config.Machine != "virt-11.0" {
		return fmt.Errorf("machine must be virt-11.0")
	}
	return nil
}

func validateToolPath(name, path, executable string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("%s must be an absolute canonical path", name)
	}
	if filepath.Base(path) != executable {
		return fmt.Errorf("%s must name %s", name, executable)
	}
	return nil
}

func probe(ctx context.Context, runner qemu.Runner, path string, args []string) (qemu.Result, error) {
	result, err := runner.Run(ctx, qemu.Command{Path: path, Args: args})
	if err != nil {
		return qemu.Result{}, fmt.Errorf("qemu probe %q: %w", args, err)
	}
	if result.ExitCode != 0 {
		return qemu.Result{}, fmt.Errorf("qemu probe %q exited with status %d", args, result.ExitCode)
	}
	if int64(len(result.Stdout)+len(result.Stderr)) > maxProbeOutputBytes {
		return qemu.Result{}, fmt.Errorf("qemu probe %q exceeded output limit", args)
	}
	return result, nil
}

func hasVersion(output []byte, version string) bool {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "QEMU" && fields[1] == "emulator" && fields[2] == "version" && fields[3] == version {
			return true
		}
	}
	return false
}

func helpNames(output []byte) []string {
	var names []string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasSuffix(fields[0], ":") {
			continue
		}
		names = append(names, fields[0])
	}
	return names
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
