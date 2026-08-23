//go:build linux

package webactivation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os/exec"
)

const lswsControlPath = "/usr/local/lsws/bin/lswsctrl"

// FixedRunner implements the runtime runner without exposing a generic root
// process primitive. Only the product-owned reload invocation is accepted.
type FixedRunner struct{}

func (FixedRunner) Run(ctx context.Context, program string, arguments ...string) error {
	if ctx == nil || program != lswsControlPath || len(arguments) != 1 || arguments[0] != "reload" { return errors.New("unregistered web-engine runtime invocation") }
	return exec.CommandContext(ctx, lswsControlPath, "reload").Run()
}

func NewLoopbackTransport() *http.Transport {
	dialer := &net.Dialer{}
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxIdleConns: 0,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" { return nil, errors.New("health probe requires TCP") }
			host, _, err := net.SplitHostPort(address)
			if err != nil || host != "127.0.0.1" { return nil, errors.New("health probe destination is not fixed loopback") }
			return dialer.DialContext(ctx, network, address)
		},
	}
}
