//go:build linux

package mail

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Redis has no configuration-only switch. Parse and start it with networking
// and persistence confined to a private temporary directory, probe the socket,
// then reap it. The live instance and its data are never opened by this check.
func (host *LinuxMailHost) validateRedisConfig(ctx context.Context, path string) (evidence string, result error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	directory, err := os.MkdirTemp("/run/cyberpanel", "mail-redis-validation-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "redis.sock")
	command := exec.CommandContext(ctx, host.profile.redisServer, path, "--port", "0", "--unixsocket", socket, "--unixsocketperm", "0600", "--supervised", "no", "--daemonize", "no", "--appendonly", "no", "--save", "", "--dir", directory)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	output := &mailBoundedOutput{limit: 1 << 20}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			<-done
		}
		if output.overflow {
			result = errors.Join(result, ErrInvalidReceipt)
		}
		evidence = digestMailEvidence(output.buffer.String(), errorText(result))
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			waited = true
			return "", errors.Join(ErrInvalidReceipt, err)
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			info, err := os.Lstat(socket)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || info.Mode()&os.ModeSocket == 0 {
				return "", ErrInvalidReceipt
			}
			pong, err := runMailProcess(ctx, host.profile.redisCLI, "-s", socket, "PING")
			if err != nil || strings.TrimSpace(string(pong)) != "PONG" {
				return "", errors.Join(ErrInvalidReceipt, err)
			}
			return "", nil
		}
	}
}

func validateClamAVConfig(ctx context.Context, directory string) (string, error) {
	output, err := runMailProcess(ctx, "/usr/bin/clamconf", "--config-dir="+directory, "--non-default")
	// clamconf can print a parse error while returning success, so require the
	// actual clamd section and reject its explicit error diagnostics as well.
	if err == nil && (!strings.Contains(string(output), "Config file: clamd.conf") || strings.Contains(string(output), "ERROR:")) {
		err = ErrInvalidReceipt
	}
	return digestMailEvidence(string(output), errorText(err)), err
}
