//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const mailClamAVPolicy = `# CyberPanel: read only ClamAV's immutable config and use its scan socket.
/var/lib/cyberpanel/mail/generations/*/clamav/clamd.conf r,
/{,var/}run/clamd/cyberpanel.sock rw,
`

func installMailRuntimeUnits() error {
	if err := installMailRedisUnit(); err != nil {
		return err
	}
	if err := installMailClamAVUnit(); err != nil {
		return err
	}
	return installMailMilterUnits()
}

func installMailMilterUnits() error {
	for _, service := range []string{"opendkim", "rspamd"} {
		directory := "/etc/systemd/system/" + service + ".service.d"
		if err := trustedDNSAncestors(filepath.Dir(directory)); err != nil {
			return err
		}
		if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := trustedDNSAncestors(directory); err != nil {
			return err
		}
		content := []byte("[Service]\nExecStartPost=+/usr/local/libexec/cyberpanel/panel-execd --mail-milter-access " + service + "\n")
		path := directory + "/50-cyberpanel-milter.conf"
		if _, err := ensureOwnedFile(path, 0644, 0, 0, content); err != nil {
			return err
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, content) {
			return errors.New("mail milter unit differs from managed definition")
		}
	}
	return exec.Command("/usr/bin/systemctl", "daemon-reload").Run()
}

func installMailClamAVUnit() error {
	for unit, content := range map[string]string{
		"clamav-daemon.socket": "[Socket]\nListenStream=\nListenStream=/run/clamd/cyberpanel.sock\nSocketUser=clamav\nSocketGroup=clamav\nSocketMode=0660\nDirectoryMode=0755\nRemoveOnStop=true\n",
		"panel-core.service":   "[Service]\nSupplementaryGroups=clamav\n",
		"rspamd.service":       "[Service]\nSupplementaryGroups=clamav\n",
	} {
		directory := "/etc/systemd/system/" + unit + ".d"
		if err := trustedDNSAncestors(filepath.Dir(directory)); err != nil {
			return err
		}
		if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := trustedDNSAncestors(directory); err != nil {
			return err
		}
		path := directory + "/50-cyberpanel-scan.conf"
		if _, err := ensureOwnedFile(path, 0644, 0, 0, []byte(content)); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != content {
			return errors.New("mail scan unit differs from managed definition")
		}
	}
	const policy = "/etc/apparmor.d/local/usr.sbin.clamd"
	if err := trustedDNSAncestors(filepath.Dir(policy)); err != nil {
		return err
	}
	if _, err := ensureOwnedFile(policy, 0644, 0, 0, []byte(mailClamAVPolicy)); err != nil {
		return err
	}
	f, err := os.OpenFile(policy, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != 0 || metadata.Gid != 0 || metadata.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		return errors.New("unsafe ClamAV local policy")
	}
	if info.Size() != 0 && info.Size() != int64(len(mailClamAVPolicy)) {
		return errors.New("custom ClamAV local policy requires explicit integration")
	}
	if info.Size() == 0 {
		// The distro ships an empty local policy. Never replace operator rules.
		if _, err := f.WriteString(mailClamAVPolicy); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
	} else {
		data, err := os.ReadFile(policy)
		if err != nil || !bytes.Equal(data, []byte(mailClamAVPolicy)) {
			return errors.New("custom ClamAV local policy requires explicit integration")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/usr/sbin/apparmor_parser", "-r", "/etc/apparmor.d/usr.sbin.clamd").Run(); err != nil {
		return err
	}
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload").Run()
}
