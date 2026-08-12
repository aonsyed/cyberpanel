// Package qemu builds closed, shell-free QEMU invocations.
package qemu

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SupportedQEMUVersion is the only QEMU command-line contract implemented by
// this package. Binary provenance and the output of --version are verified by
// the caller before Build is used.
const SupportedQEMUVersion = "11.0.3"

const maxUnixSocketPathBytes = 103

// Profile selects one complete machine, accelerator, CPU, and executable
// contract. It is deliberately not an open-ended collection of QEMU options.
type Profile string

const (
	// ProfileARM64HVF runs an AArch64 guest natively on Apple Silicon.
	ProfileARM64HVF Profile = "arm64-hvf"
	// ProfileAMD64TCG runs an x86-64 guest under software translation on
	// Apple Silicon. Results from this profile are not performance evidence.
	ProfileAMD64TCG Profile = "amd64-tcg"
)

// Config contains the complete set of per-run values that may enter the QEMU
// argv. Callers cannot append arbitrary options or select forwarding addresses.
type Config struct {
	Profile     Profile
	QEMUVersion string
	QEMUPath    string
	Name        string

	PFlashCodePath string
	PFlashVarsPath string
	DiskPath       string
	SeedPath       string
	QMPSocketPath  string
	SerialPath     string

	// SSHHostPort is bound on 127.0.0.1. Zero asks QEMU to choose a free
	// loopback port, which must subsequently be discovered through QMP.
	SSHHostPort uint16
}

// Invocation separates the executable from its argument vector so it can be
// passed directly to exec.Command without a shell or a command string.
type Invocation struct {
	Path                   string
	Args                   []string
	NonPerformanceEvidence bool
}

type profileSpec struct {
	executable             string
	machine                string
	accelerator            string
	cpu                    string
	nonPerformanceEvidence bool
}

// Build returns the one literal QEMU 11.0.3 invocation allowed by cfg's
// profile. It performs no filesystem access and never invokes a shell.
func Build(cfg Config) (Invocation, error) {
	spec, err := validateConfig(cfg)
	if err != nil {
		return Invocation{}, err
	}

	inv := buildInvocation(cfg, spec)
	if err := validateSemantics(spec, inv); err != nil {
		return Invocation{}, fmt.Errorf("internal qemu invocation: %w", err)
	}
	return inv, nil
}

// Validate proves that inv is byte-for-byte the closed invocation derived from
// cfg, in addition to independently rejecting dangerous QEMU semantics. It is
// intended to be called immediately before process creation.
func Validate(cfg Config, inv Invocation) error {
	spec, err := validateConfig(cfg)
	if err != nil {
		return err
	}
	if err := validateSemantics(spec, inv); err != nil {
		return err
	}

	want := buildInvocation(cfg, spec)
	if inv.Path != want.Path {
		return fmt.Errorf("qemu path differs from closed configuration")
	}
	if inv.NonPerformanceEvidence != want.NonPerformanceEvidence {
		return fmt.Errorf("qemu evidence classification differs from profile")
	}
	if len(inv.Args) != len(want.Args) {
		return fmt.Errorf("qemu argv length differs from closed configuration")
	}
	for i := range want.Args {
		if inv.Args[i] != want.Args[i] {
			return fmt.Errorf("qemu argv argument %d differs from closed configuration", i)
		}
	}
	return nil
}

func buildInvocation(cfg Config, spec profileSpec) Invocation {
	hostPort := strconv.FormatUint(uint64(cfg.SSHHostPort), 10)
	return Invocation{
		Path: cfg.QEMUPath,
		Args: []string{
			"-no-user-config",
			"-nodefaults",
			"-name", cfg.Name,
			"-machine", spec.machine,
			"-accel", spec.accelerator,
			"-cpu", spec.cpu,
			"-m", "2048",
			"-smp", "2",
			"-display", "none",
			"-monitor", "none",
			"-no-reboot",
			"-boot", "order=c,strict=on",
			"-rtc", "base=utc",
			"-object", "rng-random,id=rng0,filename=/dev/urandom",
			"-device", "virtio-rng-pci,rng=rng0",
			"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=" + cfg.PFlashCodePath,
			"-drive", "if=pflash,format=raw,unit=1,file=" + cfg.PFlashVarsPath,
			"-drive", "if=none,id=osdisk,format=qcow2,cache=none,aio=threads,file=" + cfg.DiskPath,
			"-device", "virtio-blk-pci,drive=osdisk",
			"-drive", "if=none,id=seed,format=raw,readonly=on,file=" + cfg.SeedPath,
			"-device", "virtio-blk-pci,drive=seed",
			"-netdev", "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:" + hostPort + "-:22",
			"-device", "virtio-net-pci,netdev=net0",
			"-qmp", "unix:" + cfg.QMPSocketPath + ",server=on,wait=off",
			"-serial", "file:" + cfg.SerialPath,
		},
		NonPerformanceEvidence: spec.nonPerformanceEvidence,
	}
}

func validateConfig(cfg Config) (profileSpec, error) {
	if cfg.QEMUVersion != SupportedQEMUVersion {
		return profileSpec{}, fmt.Errorf("qemu version must be %s", SupportedQEMUVersion)
	}

	spec, err := specification(cfg.Profile)
	if err != nil {
		return profileSpec{}, err
	}
	if err := validatePath("qemu path", cfg.QEMUPath, false); err != nil {
		return profileSpec{}, err
	}
	if filepath.Base(cfg.QEMUPath) != spec.executable {
		return profileSpec{}, fmt.Errorf("qemu path must name %s for profile %s", spec.executable, cfg.Profile)
	}
	if err := validateName(cfg.Name); err != nil {
		return profileSpec{}, err
	}

	paths := []struct {
		name  string
		value string
	}{
		{"pflash code path", cfg.PFlashCodePath},
		{"pflash vars path", cfg.PFlashVarsPath},
		{"disk path", cfg.DiskPath},
		{"seed path", cfg.SeedPath},
		{"qmp socket path", cfg.QMPSocketPath},
		{"serial path", cfg.SerialPath},
	}
	seen := make(map[string]string, len(paths))
	for _, path := range paths {
		if err := validatePath(path.name, path.value, true); err != nil {
			return profileSpec{}, err
		}
		if previous, ok := seen[path.value]; ok {
			return profileSpec{}, fmt.Errorf("%s must differ from %s", path.name, previous)
		}
		seen[path.value] = path.name
	}
	if len([]byte(cfg.QMPSocketPath)) > maxUnixSocketPathBytes {
		return profileSpec{}, fmt.Errorf("qmp socket path exceeds %d bytes", maxUnixSocketPathBytes)
	}

	return spec, nil
}

func specification(profile Profile) (profileSpec, error) {
	switch profile {
	case ProfileARM64HVF:
		return profileSpec{
			executable:             "qemu-system-aarch64",
			machine:                "virt-11.0",
			accelerator:            "hvf",
			cpu:                    "host",
			nonPerformanceEvidence: false,
		}, nil
	case ProfileAMD64TCG:
		return profileSpec{
			executable:             "qemu-system-x86_64",
			machine:                "pc-q35-11.0",
			accelerator:            "tcg,thread=multi",
			cpu:                    "max",
			nonPerformanceEvidence: true,
		}, nil
	default:
		return profileSpec{}, fmt.Errorf("unsupported qemu profile %q", profile)
	}
}

func validatePath(name, value string, qemuSuboption bool) error {
	if value == "" {
		return fmt.Errorf("%s is empty", name)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be absolute", name)
	}
	if filepath.Clean(value) != value || value == string(filepath.Separator) {
		return fmt.Errorf("%s must be a canonical file path", name)
	}
	if qemuSuboption && strings.Contains(value, ",") {
		return fmt.Errorf("%s contains a QEMU suboption delimiter", name)
	}
	return nil
}

func validateName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("qemu name must contain 1 to 64 safe ASCII characters")
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("qemu name contains an unsafe character")
	}
	return nil
}

func validateSemantics(spec profileSpec, inv Invocation) error {
	if err := validatePath("qemu path", inv.Path, false); err != nil {
		return err
	}
	if filepath.Base(inv.Path) != spec.executable {
		return fmt.Errorf("qemu path does not match the selected profile")
	}
	if inv.NonPerformanceEvidence != spec.nonPerformanceEvidence {
		return fmt.Errorf("qemu evidence classification does not match the selected profile")
	}

	for _, arg := range inv.Args {
		if !utf8.ValidString(arg) {
			return fmt.Errorf("qemu argv contains invalid UTF-8")
		}
		for _, r := range arg {
			if unicode.IsControl(r) {
				return fmt.Errorf("qemu argv contains a control character")
			}
		}
		lower := strings.ToLower(arg)
		withoutDashes := strings.TrimLeft(arg, "-")
		if withoutDashes == "daemonize" || strings.HasPrefix(withoutDashes, "daemonize=") {
			return fmt.Errorf("qemu must remain a foreground child")
		}
		if arg == "-virtfs" || arg == "-fsdev" ||
			strings.Contains(lower, "virtio-9p") ||
			strings.Contains(lower, "vhost-user-fs") ||
			strings.Contains(lower, "fat:rw:") {
			return fmt.Errorf("qemu writable host sharing is forbidden")
		}
	}

	if countToken(inv.Args, "-no-user-config") != 1 {
		return fmt.Errorf("qemu requires exactly one -no-user-config")
	}
	if countToken(inv.Args, "-nodefaults") != 1 {
		return fmt.Errorf("qemu requires exactly one -nodefaults")
	}
	if err := requireOption(inv.Args, "-display", "none"); err != nil {
		return err
	}
	if err := requireOption(inv.Args, "-monitor", "none"); err != nil {
		return err
	}

	accelerators := optionValues(inv.Args, "-accel")
	if len(accelerators) != 1 {
		return fmt.Errorf("qemu requires exactly one accelerator")
	}
	if strings.Contains(accelerators[0], ":") {
		return fmt.Errorf("qemu accelerator fallback lists are forbidden")
	}
	if accelerators[0] != spec.accelerator {
		return fmt.Errorf("qemu accelerator differs from the selected profile")
	}
	for _, machine := range append(optionValues(inv.Args, "-machine"), optionValues(inv.Args, "-M")...) {
		if strings.Contains(machine, "accel=") {
			return fmt.Errorf("qemu machine may not declare a second accelerator")
		}
	}

	networks := optionValues(inv.Args, "-netdev")
	if len(networks) != 1 {
		return fmt.Errorf("qemu requires exactly one closed user network")
	}
	if !strings.HasPrefix(networks[0], "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:") ||
		!strings.HasSuffix(networks[0], "-:22") {
		return fmt.Errorf("qemu network must be restricted with loopback-only SSH forwarding")
	}
	if countToken(inv.Args, "-nic") != 0 || countToken(inv.Args, "-net") != 0 {
		return fmt.Errorf("qemu contains an additional network configuration")
	}

	return nil
}

func requireOption(args []string, option, value string) error {
	values := optionValues(args, option)
	if len(values) != 1 || values[0] != value {
		return fmt.Errorf("qemu requires exactly one %s %s", option, value)
	}
	return nil
}

func optionValues(args []string, option string) []string {
	values := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		if args[i] != option {
			continue
		}
		if i+1 >= len(args) {
			values = append(values, "")
			continue
		}
		values = append(values, args[i+1])
	}
	return values
}

func countToken(args []string, token string) int {
	count := 0
	for _, arg := range args {
		if arg == token {
			count++
		}
	}
	return count
}
