//go:build linux

package webactivation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os/exec"
	"strings"
)

const lswsControlPath = "/usr/local/lsws/bin/lswsctrl"

// FixedRunner implements the runtime runner without exposing a generic root
// process primitive. Only the product-owned reload invocation is accepted.
type FixedRunner struct{}

func (FixedRunner) Run(ctx context.Context, program string, arguments ...string) error {
	if ctx == nil || program != lswsControlPath || len(arguments) != 1 || arguments[0] != "reload" {
		return errors.New("unregistered web-engine runtime invocation")
	}
	return exec.CommandContext(ctx, lswsControlPath, "reload").Run()
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
	return nil
}
func (FixedRunner) ValidateInitial(ctx context.Context) error {
	if ctx == nil {
		return errors.New("bootstrap context required")
	}
	return exec.CommandContext(ctx, "/usr/local/lsws/bin/lshttpd", "-t").Run()
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
