//go:build linux

package dns

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

type LinuxDiagnosticRunner struct{}

func NewLinuxDiagnosticResolver() DiagnosticResolver {
	return newRunnerDiagnosticResolver(LinuxDiagnosticRunner{}, time.Now)
}

func (LinuxDiagnosticRunner) Run(ctx context.Context, query diagnosticQuery) ([]byte, error) {
	if ctx == nil || !validDiagnosticQuery(query) {
		return nil, ErrInvalidDNS
	}
	arguments := []string{
		"+time=2",
		"+tries=1",
		"+nocmd",
		"+noquestion",
		"+nostats",
		"+noall",
		"+comments",
		"+answer",
		"+authority",
		"+additional",
	}
	if query.Authoritative {
		arguments = append(arguments, "+norecurse")
	} else {
		arguments = append(arguments, "+recurse")
	}
	if query.DNSSEC {
		arguments = append(arguments, "+dnssec")
	} else {
		arguments = append(arguments, "+nodnssec")
	}
	arguments = append(arguments, "@"+query.Server.Unmap().String(), query.Name.FQDN(), string(query.Kind))
	command := exec.CommandContext(ctx, "/usr/bin/dig", arguments...)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Stdin = nil
	output := &diagnosticBoundedOutput{limit: maxDiagnosticOutput}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		if output.overflow {
			return nil, ErrDNSDiagnosticOutputLimit
		}
		return nil, ErrDNSDiagnosticUnavailable
	}
	if output.overflow {
		return nil, ErrDNSDiagnosticOutputLimit
	}
	return append([]byte(nil), output.buffer.Bytes()...), nil
}

type diagnosticBoundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (output *diagnosticBoundedOutput) Write(value []byte) (int, error) {
	written := len(value)
	remaining := output.limit - output.buffer.Len()
	if remaining <= 0 {
		output.overflow = true
		return written, nil
	}
	if len(value) > remaining {
		output.overflow = true
		value = value[:remaining]
	}
	_, _ = output.buffer.Write(value)
	return written, nil
}
