package containers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ProvisionRootlessContainerPolicy is called by the authenticated local root
// installer. Policy bytes come only from this executable, never a caller path.
// Keep earlier generations: removing a profile can unconfine live workloads.
func ProvisionRootlessContainerPolicy(ctx context.Context) (string, error) {
	if ctx == nil || os.Geteuid() != 0 {
		return "", ErrForbidden
	}
	if !containerAppArmorAvailable() {
		mode, err := os.ReadFile("/sys/fs/selinux/enforce")
		if err != nil || strings.TrimSpace(string(mode)) != "1" {
			return "", fmt.Errorf("%w: enforcing MAC required", ErrPolicy)
		}
		return "", nil
	}
	name, policy := RootlessAppArmorPolicy()
	const directory = "/etc/apparmor.d"
	const parser = "/usr/sbin/apparmor_parser"
	for _, path := range []string{"/etc", directory} {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return "", fmt.Errorf("%w: unsafe policy parent", ErrPolicy)
		}
	}
	info, err := os.Lstat(parser)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return "", fmt.Errorf("%w: untrusted policy parser", ErrPolicy)
	}
	path := filepath.Join(directory, name)
	existing, err := os.Lstat(path)
	create := errors.Is(err, os.ErrNotExist)
	if err != nil && !create {
		return "", err
	}
	if !create {
		stat, ok := existing.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !existing.Mode().IsRegular() || existing.Mode().Perm() != 0644 || existing.Size() != int64(len(policy)) {
			return "", fmt.Errorf("%w: policy generation metadata", ErrPolicy)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if !bytes.Equal(content, policy) {
			return "", fmt.Errorf("%w: policy generation content", ErrPolicy)
		}
	}
	// Reload even when a disk file/installer receipt exists: neither proves the
	// kernel still enforces this generation. Feed only the embedded bytes.
	loadCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(loadCtx, parser, "-r")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	command.Stdin = bytes.NewReader(policy)
	output := &limitedContainerOutput{limit: 64 << 10}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil || output.overflow {
		return "", fmt.Errorf("load container policy: %w: %s", errors.Join(ErrPolicy, err), output.Bytes())
	}
	if create {
		if err := atomicContainerFile(path, policy, 0644); err != nil {
			return "", err
		}
	}
	if err := rootlessContainerProfileReady(); err != nil {
		return "", err
	}
	return path, nil
}
