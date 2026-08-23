package doctor

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/testvm/internal/qemu"
)

func TestCheckProbesOnlyConfiguredRegularToolsAndReturnsStructuredObservations(t *testing.T) {
	t.Parallel()

	config := supportedConfig()
	stat := &recordingStat{files: map[string]fs.FileInfo{
		config.QEMUPath:    testFileInfo{mode: 0o755},
		config.QEMUImgPath: testFileInfo{mode: 0o755},
	}}
	runner := &recordingRunner{results: []qemu.Result{
		{Stdout: []byte("QEMU emulator version 11.0.3\n")},
		{Stdout: []byte("Accelerators supported in QEMU binary:\nhvf\n")},
		{Stdout: []byte("virt-11.0  QEMU Virtual Machine\n")},
	}}

	report, err := Check(context.Background(), config, runner, stat)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if report.QEMUVersion != qemu.SupportedQEMUVersion {
		t.Fatalf("report QEMU version = %q, want %q", report.QEMUVersion, qemu.SupportedQEMUVersion)
	}
	if !slices.Contains(report.Accelerators, config.Accelerator) {
		t.Fatalf("report accelerators = %#v, want %q", report.Accelerators, config.Accelerator)
	}
	if !slices.Contains(report.Machines, config.Machine) {
		t.Fatalf("report machines = %#v, want %q", report.Machines, config.Machine)
	}

	if got, want := stat.paths, []string{config.QEMUPath, config.QEMUImgPath}; !slices.Equal(got, want) {
		t.Fatalf("stat paths = %#v, want %#v", got, want)
	}
	wantCommands := []qemu.Command{
		{Path: config.QEMUPath, Args: []string{"--version"}},
		{Path: config.QEMUPath, Args: []string{"-accel", "help"}},
		{Path: config.QEMUPath, Args: []string{"-machine", "help"}},
	}
	if len(runner.commands) != len(wantCommands) {
		t.Fatalf("runner commands = %#v, want %#v", runner.commands, wantCommands)
	}
	for index := range wantCommands {
		if runner.commands[index].Path != wantCommands[index].Path || !slices.Equal(runner.commands[index].Args, wantCommands[index].Args) {
			t.Errorf("command %d = %#v, want %#v", index, runner.commands[index], wantCommands[index])
		}
	}
}

func TestCheckFailsClosedForUnsafeToolsAndUnsupportedQEMUCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		statInfo  fs.FileInfo
		results   []qemu.Result
		wantError string
	}{
		{name: "symlink tool", statInfo: testFileInfo{mode: fs.ModeSymlink | 0o777}, wantError: "regular"},
		{name: "directory tool", statInfo: testFileInfo{mode: fs.ModeDir | 0o755}, wantError: "regular"},
		{name: "wrong version", statInfo: testFileInfo{mode: 0o755}, results: []qemu.Result{{Stdout: []byte("QEMU emulator version 10.2.0\n")}}, wantError: "11.0.3"},
		{name: "missing accelerator", statInfo: testFileInfo{mode: 0o755}, results: []qemu.Result{{Stdout: []byte("QEMU emulator version 11.0.3\n")}, {Stdout: []byte("tcg\n")}}, wantError: "accelerator"},
		{name: "missing machine", statInfo: testFileInfo{mode: 0o755}, results: []qemu.Result{{Stdout: []byte("QEMU emulator version 11.0.3\n")}, {Stdout: []byte("hvf\n")}, {Stdout: []byte("virt-10.2\n")}}, wantError: "machine"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := supportedConfig()
			stat := &recordingStat{files: map[string]fs.FileInfo{
				config.QEMUPath:    tt.statInfo,
				config.QEMUImgPath: tt.statInfo,
			}}
			runner := &recordingRunner{results: tt.results}

			_, err := Check(context.Background(), config, runner, stat)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantError)) {
				t.Fatalf("Check() error = %v, want rejection containing %q", err, tt.wantError)
			}
			if (tt.name == "symlink tool" || tt.name == "directory tool") && len(runner.commands) != 0 {
				t.Fatalf("runner commands = %#v, want no probing for unsafe tool", runner.commands)
			}
		})
	}
}

func TestCheckRejectsOpenEndedConfigurationBeforeFilesystemOrProcessAccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "relative qemu", mutate: func(config *Config) { config.QEMUPath = "qemu-system-aarch64" }},
		{name: "wrong qemu basename", mutate: func(config *Config) { config.QEMUPath = "/opt/qemu/bin/qemu-system-x86_64" }},
		{name: "wrong qemu-img basename", mutate: func(config *Config) { config.QEMUImgPath = "/opt/qemu/bin/convert" }},
		{name: "unsupported host", mutate: func(config *Config) { config.HostOS = "linux" }},
		{name: "unsupported architecture", mutate: func(config *Config) { config.HostArch = "amd64" }},
		{name: "accelerator fallback", mutate: func(config *Config) { config.Accelerator = "hvf:tcg" }},
		{name: "unapproved machine", mutate: func(config *Config) { config.Machine = "virt" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := supportedConfig()
			tt.mutate(&config)
			stat := &recordingStat{}
			runner := &recordingRunner{}

			_, err := Check(context.Background(), config, runner, stat)
			if err == nil {
				t.Fatal("Check() error = nil, want closed configuration rejection")
			}
			if len(stat.paths) != 0 || len(runner.commands) != 0 {
				t.Fatalf("unsafe configuration reached dependencies: stat=%#v commands=%#v", stat.paths, runner.commands)
			}
		})
	}
}

func supportedConfig() Config {
	return Config{
		QEMUPath:    "/opt/qemu/11.0.3/bin/qemu-system-aarch64",
		QEMUImgPath: "/opt/qemu/11.0.3/bin/qemu-img",
		HostOS:      "darwin",
		HostArch:    "arm64",
		Accelerator: "hvf",
		Machine:     "virt-11.0",
	}
}

type recordingRunner struct {
	commands []qemu.Command
	results  []qemu.Result
}

func (runner *recordingRunner) Run(_ context.Context, command qemu.Command) (qemu.Result, error) {
	runner.commands = append(runner.commands, command)
	if len(runner.commands) > len(runner.results) {
		return qemu.Result{}, errors.New("unexpected command")
	}
	return runner.results[len(runner.commands)-1], nil
}

type recordingStat struct {
	paths []string
	files map[string]fs.FileInfo
}

func (stat *recordingStat) Lstat(path string) (fs.FileInfo, error) {
	stat.paths = append(stat.paths, path)
	info, ok := stat.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return info, nil
}

type testFileInfo struct{ mode fs.FileMode }

func (info testFileInfo) Name() string       { return "tool" }
func (info testFileInfo) Size() int64        { return 0 }
func (info testFileInfo) Mode() fs.FileMode  { return info.mode }
func (info testFileInfo) ModTime() time.Time { return time.Time{} }
func (info testFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info testFileInfo) Sys() any           { return nil }
