package qemu

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultCommandTimeout   = 30 * time.Second
	defaultMaxOutputBytes   = 64 << 10
)

// Command is one shell-free, bounded process invocation. Path is always an
// absolute executable path; Args is passed directly as argv.
type Command struct {
	Path           string
	Args           []string
	Env            []string
	Dir            string
	Timeout        time.Duration
	MaxOutputBytes int64
}

// Result retains bounded stdout and stderr from a command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner executes a closed command directly, without invoking a shell.
type Runner interface {
	Run(context.Context, Command) (Result, error)
}

// ExecRunner executes Commands with os/exec.
type ExecRunner struct{}

// ExitError reports a non-zero command exit status.
type ExitError struct {
	Path     string
	ExitCode int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("command %q exited with status %d", e.Path, e.ExitCode)
}

// TimeoutError reports expiration of the command's deadline.
type TimeoutError struct {
	Path    string
	Timeout time.Duration
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("command %q exceeded timeout %s", e.Path, e.Timeout)
}

// OutputLimitError reports that command output exceeded the retention limit.
type OutputLimitError struct {
	Path  string
	Limit int64
}

func (e *OutputLimitError) Error() string {
	return fmt.Sprintf("command %q exceeded output limit of %d bytes", e.Path, e.Limit)
}

// Run executes command as an argv vector, with an explicitly supplied (and
// therefore sanitized) environment. It never constructs or interprets a shell
// command string.
func (ExecRunner) Run(ctx context.Context, command Command) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("command context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := validateCommand(command); err != nil {
		return Result{}, err
	}

	timeout := command.Timeout
	if timeout == 0 {
		timeout = defaultCommandTimeout
	}
	maxOutput := command.MaxOutputBytes
	if maxOutput == 0 {
		maxOutput = defaultMaxOutputBytes
	}
	dir := command.Dir
	if dir == "" {
		dir = "/"
	}

	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	output := newBoundedOutput(maxOutput)
	process := exec.CommandContext(runContext, command.Path, command.Args...)
	process.Args = append([]string{command.Path}, command.Args...)
	process.Env = append([]string{}, command.Env...)
	process.Dir = dir
	process.Stdout = output.stdoutWriter()
	process.Stderr = output.stderrWriter()
	runErr := process.Run()
	result := Result{
		Stdout:   output.stdout(),
		Stderr:   output.stderr(),
		ExitCode: exitCode(process),
	}

	if runContext.Err() == context.DeadlineExceeded {
		return result, &TimeoutError{Path: command.Path, Timeout: timeout}
	}
	if output.outputLimitExceeded() {
		return result, &OutputLimitError{Path: command.Path, Limit: maxOutput}
	}
	if runErr != nil {
		if process.ProcessState != nil {
			return result, &ExitError{Path: command.Path, ExitCode: result.ExitCode}
		}
		return result, fmt.Errorf("start command %q: %w", command.Path, runErr)
	}
	return result, nil
}

func validateCommand(command Command) error {
	if command.Path == "" || !filepath.IsAbs(command.Path) || filepath.Clean(command.Path) != command.Path {
		return fmt.Errorf("command path must be an absolute canonical path")
	}
	if strings.IndexByte(command.Path, 0) >= 0 {
		return fmt.Errorf("command path contains NUL")
	}
	if command.Dir != "" && (!filepath.IsAbs(command.Dir) || filepath.Clean(command.Dir) != command.Dir || strings.IndexByte(command.Dir, 0) >= 0) {
		return fmt.Errorf("command working directory must be an absolute canonical path")
	}
	if command.Timeout < 0 {
		return fmt.Errorf("command timeout must not be negative")
	}
	if command.MaxOutputBytes < 0 {
		return fmt.Errorf("command output limit must not be negative")
	}
	for _, argument := range command.Args {
		if strings.IndexByte(argument, 0) >= 0 {
			return fmt.Errorf("command argument contains NUL")
		}
	}
	seen := make(map[string]struct{}, len(command.Env))
	for _, entry := range command.Env {
		name, _, found := strings.Cut(entry, "=")
		if !found || name == "" || strings.ContainsAny(name, "\x00=") || strings.IndexByte(entry, 0) >= 0 {
			return fmt.Errorf("command environment contains an invalid entry")
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("command environment repeats %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func exitCode(command *exec.Cmd) int {
	if command.ProcessState == nil {
		return -1
	}
	return command.ProcessState.ExitCode()
}

type boundedOutput struct {
	mu       sync.Mutex
	limit    int64
	used     int64
	exceeded bool
	stdoutBuffer bytes.Buffer
	stderrBuffer bytes.Buffer
}

func newBoundedOutput(limit int64) *boundedOutput {
	return &boundedOutput{limit: limit}
}

func (output *boundedOutput) stdoutWriter() *boundedWriter {
	return &boundedWriter{output: output, buffer: &output.stdoutBuffer}
}

func (output *boundedOutput) stderrWriter() *boundedWriter {
	return &boundedWriter{output: output, buffer: &output.stderrBuffer}
}

func (output *boundedOutput) stdout() []byte {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.stdoutBuffer.Bytes()...)
}

func (output *boundedOutput) stderr() []byte {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.stderrBuffer.Bytes()...)
}

func (output *boundedOutput) exceededOutput() bool {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.exceeded
}

func (output *boundedOutput) outputLimitExceeded() bool {
	return output.exceededOutput()
}

type boundedWriter struct {
	output *boundedOutput
	buffer *bytes.Buffer
}

func (writer *boundedWriter) Write(data []byte) (int, error) {
	writer.output.mu.Lock()
	defer writer.output.mu.Unlock()

	remaining := writer.output.limit - writer.output.used
	if remaining < 0 {
		remaining = 0
	}
	write := int64(len(data))
	if write > remaining {
		write = remaining
		writer.output.exceeded = true
	}
	if write > 0 {
		_, _ = writer.buffer.Write(data[:int(write)])
		writer.output.used += write
	}
	return len(data), nil
}
