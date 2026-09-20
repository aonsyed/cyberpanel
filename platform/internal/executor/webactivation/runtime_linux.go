//go:build linux

package webactivation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const lswsControlPath = "/usr/local/lsws/bin/lswsctrl"

// FixedRunner implements the runtime runner without exposing a generic root
// process primitive. Only the product-owned reload invocation is accepted.
type FixedRunner struct{}

func (FixedRunner) Run(ctx context.Context, program string, arguments ...string) error {
	if ctx == nil || program != lswsControlPath || len(arguments) != 1 || arguments[0] != "reload" {
		return errors.New("unregistered web-engine runtime invocation")
	}
	// Run the vendor's ExecReload in its own service context. Directly
	// launching lswsctrl inherits our private /tmp and read-only filesystem,
	// hiding its PID file and preventing its native log writes.
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "reload", "lsws.service").Run()
}

func (FixedRunner) CheckStopped(ctx context.Context) error {
	if ctx == nil {
		return errors.New("bootstrap context required")
	}
	output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "lsws.service", "--property=ActiveState", "--property=MainPID", "--property=ControlPID").Output()
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	if (values["ActiveState"] != "inactive" && values["ActiveState"] != "failed") || values["MainPID"] != "0" || values["ControlPID"] != "0" {
		return errors.New("initial web activation requires a stopped service")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// The normal executor intentionally lacks ptrace authority. Grant only
	// read/observe capabilities to this fixed, short-lived observer rather
	// than broadening the long-lived mutation broker's privileges.
	return exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
		"--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
		"--property=PrivateNetwork=yes", "--property=NoNewPrivileges=yes",
		"--property=RuntimeMaxSec=10s", "--property=CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH",
		self, StoppedProofMode).Run()
}

const StoppedProofMode = "--webengine-stopped-proof"

func RunStoppedProof() error {
	if os.Geteuid() != 0 {
		return errors.New("native process observation requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return requireExecutableStopped(ctx, "/usr/local/lsws/bin/lshttpd")
}

// A daemon launched outside systemd has MainPID=0 in the unit. Inspect the
// kernel's executable links as well; process titles and stale PID files are
// not proof that the engine is stopped.
func requireExecutableStopped(ctx context.Context, executable string) error {
	wanted, err := os.Stat(executable)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, process := range processes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := strconv.ParseUint(process.Name(), 10, 32); err != nil {
			continue
		}
		path := "/proc/" + process.Name() + "/exe"
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		target, err := os.Readlink(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if os.SameFile(wanted, info) || strings.TrimSuffix(target, " (deleted)") == resolved {
			return errors.New("initial web activation found a running native engine outside stopped-service proof")
		}
	}
	return nil
}
func (FixedRunner) ValidateInitial(ctx context.Context) error {
	if ctx == nil {
		return errors.New("bootstrap context required")
	}
	// Native OLS validation also runs its conf-permission repair. A transient
	// service gives the parser a read-only view instead of allowing it to
	// transfer panel-owned state back to the vendor WebAdmin account.
	return exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
		"--property=ReadOnlyPaths=/usr/local/lsws/conf /etc",
		"--property=CapabilityBoundingSet=~CAP_SYS_ADMIN", "--property=PrivateTmp=yes",
		"--property=RuntimeMaxSec=20s", "--property=TimeoutStopSec=5s",
		"/usr/local/lsws/bin/lshttpd", "-t").Run()
}
func (FixedRunner) StartInitial(ctx context.Context) error {
	if ctx == nil {
		return errors.New("bootstrap context required")
	}
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "start", "lsws.service").Run(); err != nil {
		return err
	}
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "lsws.service").Run()
}
func (runner FixedRunner) StopInitial(ctx context.Context) error {
	if ctx == nil {
		return errors.New("bootstrap context required")
	}
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", "lsws.service").Run(); err != nil {
		return err
	}
	return runner.CheckStopped(ctx)
}

func NewLoopbackTransport() *http.Transport {
	dialer := &net.Dialer{}
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxIdleConns: 0,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, errors.New("health probe requires TCP")
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil || host != "127.0.0.1" {
				return nil, errors.New("health probe destination is not fixed loopback")
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
}
