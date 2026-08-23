package qemu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerUsesLiteralArgvExplicitEnvironmentAndWorkingDirectory(t *testing.T) {
	t.Setenv("VMHARNESS_SHOULD_NOT_LEAK", "1")

	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("find test executable: %v", err)
	}
	workingDirectory := t.TempDir()
	result, err := (ExecRunner{}).Run(context.Background(), Command{
		Path: binary,
		Args: []string{
			"-test.run=TestExecRunnerHelperProcess",
			"--",
			"report",
			"literal; touch should-not-run",
		},
		Env:            []string{"VMHARNESS_EXEC_HELPER=1", "VMHARNESS_VISIBLE=only-this"},
		Dir:            workingDirectory,
		Timeout:        time.Second,
		MaxOutputBytes: 4 << 10,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	var observation struct {
		Args    []string `json:"args"`
		Dir     string   `json:"dir"`
		Visible string   `json:"visible"`
		Leaked  bool     `json:"leaked"`
	}
	if err := json.Unmarshal(result.Stdout, &observation); err != nil {
		t.Fatalf("decode helper output %q: %v", result.Stdout, err)
	}
	if got, want := observation.Args, []string{"report", "literal; touch should-not-run"}; !sameStrings(got, want) {
		t.Fatalf("argv = %#v, want %#v", got, want)
	}
	if observation.Dir != workingDirectory {
		t.Fatalf("working directory = %q, want %q", observation.Dir, workingDirectory)
	}
	if observation.Visible != "only-this" || observation.Leaked {
		t.Fatalf("environment observation = %#v, want only the explicit environment", observation)
	}
	if result.ExitCode != 0 || len(result.Stderr) != 0 {
		t.Fatalf("Run() result = %#v, want clean success", result)
	}
}

func TestExecRunnerRejectsNonAbsoluteExecutableBeforeStartingAProcess(t *testing.T) {
	t.Parallel()

	_, err := (ExecRunner{}).Run(context.Background(), Command{
		Path:           "qemu-system-aarch64",
		Timeout:        time.Second,
		MaxOutputBytes: 1024,
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "absolute") {
		t.Fatalf("Run() error = %v, want absolute executable rejection", err)
	}
}

func TestExecRunnerReturnsTypedExitTimeoutAndOutputLimitErrors(t *testing.T) {
	t.Parallel()

	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("find test executable: %v", err)
	}
	runner := ExecRunner{}

	tests := []struct {
		name      string
		command   string
		maxOutput int64
		timeout   time.Duration
		matches   func(error) bool
	}{
		{name: "exit", command: "exit-23", maxOutput: 1024, timeout: time.Second, matches: isExitError},
		{name: "timeout", command: "sleep", maxOutput: 1024, timeout: 20 * time.Millisecond, matches: isTimeoutError},
		{name: "stdout limit", command: "stdout", maxOutput: 8, timeout: time.Second, matches: isOutputLimitError},
		{name: "stderr limit", command: "stderr", maxOutput: 8, timeout: time.Second, matches: isOutputLimitError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := runner.Run(context.Background(), Command{
				Path:           binary,
				Args:           []string{"-test.run=TestExecRunnerHelperProcess", "--", tt.command},
				Env:            []string{"VMHARNESS_EXEC_HELPER=1"},
				Dir:            t.TempDir(),
				Timeout:        tt.timeout,
				MaxOutputBytes: tt.maxOutput,
			})
			if err == nil {
				t.Fatalf("Run() result = %#v, error = nil, want typed error", result)
			}
			if !tt.matches(err) {
				t.Fatalf("Run() error = %T %v, want expected typed error", err, err)
			}
			if int64(len(result.Stdout)+len(result.Stderr)) > tt.maxOutput {
				t.Fatalf("retained output = %d bytes, limit = %d", len(result.Stdout)+len(result.Stderr), tt.maxOutput)
			}
		})
	}
}

func isExitError(err error) bool {
	var typed *ExitError
	return errors.As(err, &typed)
}

func isTimeoutError(err error) bool {
	var typed *TimeoutError
	return errors.As(err, &typed)
}

func isOutputLimitError(err error) bool {
	var typed *OutputLimitError
	return errors.As(err, &typed)
}

func TestExecRunnerHelperProcess(t *testing.T) {
	if os.Getenv("VMHARNESS_EXEC_HELPER") != "1" {
		return
	}

	separator := -1
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator == -1 || separator+1 >= len(os.Args) {
		fmt.Fprint(os.Stderr, "missing helper command")
		os.Exit(2)
	}

	switch os.Args[separator+1] {
	case "report":
		workingDirectory, err := os.Getwd()
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(2)
		}
		_, leaked := os.LookupEnv("VMHARNESS_SHOULD_NOT_LEAK")
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			Args    []string `json:"args"`
			Dir     string   `json:"dir"`
			Visible string   `json:"visible"`
			Leaked  bool     `json:"leaked"`
		}{
			Args:    os.Args[separator+1:],
			Dir:     workingDirectory,
			Visible: os.Getenv("VMHARNESS_VISIBLE"),
			Leaked:  leaked,
		})
	case "exit-23":
		os.Exit(23)
	case "sleep":
		time.Sleep(time.Second)
	case "stdout":
		fmt.Fprint(os.Stdout, "0123456789")
	case "stderr":
		fmt.Fprint(os.Stderr, "0123456789")
	default:
		fmt.Fprintf(os.Stderr, "unknown helper command %q", os.Args[separator+1])
		os.Exit(2)
	}
	os.Exit(0)
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
