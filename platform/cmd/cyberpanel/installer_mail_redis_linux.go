//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const mailRedisUnit = `[Service]
# The vendor /etc/redis directory is daemon-writable; never place authority there.
LoadCredential=redis.conf:/var/lib/cyberpanel/mail/current/redis/redis.conf
ExecStart=
ExecStart=/usr/bin/redis-server /run/credentials/%n/redis.conf --supervised systemd --daemonize no
Group=_rspamd
PIDFile=
StateDirectory=
StateDirectory=cyberpanel-mail-redis
StateDirectoryMode=0700
RuntimeDirectory=
RuntimeDirectory=cyberpanel-mail-redis
RuntimeDirectoryMode=0750
ReadWritePaths=
ReadWritePaths=/var/lib/cyberpanel-mail-redis /run/cyberpanel-mail-redis
`

func installMailRedisUnit() error {
	const directory = "/etc/systemd/system/redis-server@cyberpanel-mail.service.d"
	if err := trustedDNSAncestors(filepath.Dir(directory)); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := trustedDNSAncestors(directory); err != nil {
		return err
	}
	path := directory + "/50-cyberpanel-mail.conf"
	if _, err := ensureOwnedFile(path, 0644, 0, 0, []byte(mailRedisUnit)); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != mailRedisUnit {
		return errors.New("mail Redis unit differs from managed definition")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload").Run()
}
