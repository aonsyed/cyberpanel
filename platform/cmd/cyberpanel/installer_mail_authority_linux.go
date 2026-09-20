//go:build linux

package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Ubuntu generates several mail configs using ucf/debconf rather than dpkg
// conffiles. Adopt only verified defaults, preserving the original bytes. Other
// platform layouts continue to fail closed at their native binding boundary.
func reconcileMailAuthority() error {
	if os.Geteuid() != 0 {
		return errors.New("mail adoption requires root installer")
	}
	if _, err := os.Stat("/usr/bin/dpkg-query"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	type binding struct{ path, target, digest string }
	bindings := []binding{
		{path: "/etc/postfix/main.cf", target: "postfix/main.cf"},
		{path: "/etc/postfix/master.cf", target: "postfix/master.cf"},
		{path: "/etc/dovecot/dovecot.conf", target: "dovecot/dovecot.conf"},
		{path: "/etc/opendkim.conf", target: "opendkim/opendkim.conf"},
		{path: "/etc/clamav/clamd.conf", target: "clamav/clamd.conf"},
	}
	needsAdoption := false
	found := false
	for i := range bindings {
		item := &bindings[i]
		item.target = "/var/lib/cyberpanel/mail/current/" + item.target
		info, err := os.Lstat(item.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		found = true
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(item.path)
			metadata, ok := info.Sys().(*syscall.Stat_t)
			if err != nil || !ok || metadata.Uid != 0 || target != item.target {
				return errors.New("unmanaged mail configuration link")
			}
			continue
		}
		content, err := readRootMailDefault(item.path)
		if err != nil {
			return err
		}
		digest, err := pristineUbuntuMailDigest(item.path, content)
		if err != nil {
			return err
		}
		sum := md5.Sum(content)
		if hex.EncodeToString(sum[:]) != digest {
			return errors.New("mail configuration differs from package default: " + item.path)
		}
		item.digest = digest
		needsAdoption = true
	}
	if !needsAdoption {
		if found {
			if err := bootstrapDefaultMailCertificate(); err != nil {
				return err
			}
			return installMailRuntimeUnits()
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, unit := range []string{"postfix.service", "dovecot.service", "rspamd.service", "opendkim.service", "clamav-daemon.service"} {
		state, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", unit).Output()
		if err == nil || strings.TrimSpace(string(state)) != "inactive" {
			return errors.New("stop mail services before adopting package defaults")
		}
	}
	for _, item := range bindings {
		if item.digest != "" {
			if err := adoptPristineDNSConfig(item.path, item.target, item.digest); err != nil {
				return err
			}
		}
	}
	if err := bootstrapDefaultMailCertificate(); err != nil {
		return err
	}
	return installMailRuntimeUnits()
}

func pristineUbuntuMailDigest(path string, content []byte) (string, error) {
	var record, match string
	switch path {
	case "/etc/postfix/main.cf":
		hostname, err := os.Hostname()
		if err != nil || !defaultUbuntuPostfixMain(string(content), hostname) {
			return "", errors.New("custom Postfix configuration requires explicit migration")
		}
		sum := md5.Sum(content)
		return hex.EncodeToString(sum[:]), nil
	case "/etc/postfix/master.cf":
		record, match = "/var/lib/dpkg/info/postfix.md5sums", "usr/share/postfix/master.cf.dist"
	case "/etc/dovecot/dovecot.conf", "/etc/clamav/clamd.conf":
		record, match = "/var/lib/ucf/hashfile", path
	case "/etc/opendkim.conf":
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "-W", "-f=${Conffiles}\n", "opendkim").Output()
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == path {
				return fields[1], nil
			}
		}
		return "", errors.New("missing OpenDKIM package config digest")
	default:
		return "", errors.New("unsupported mail adoption path")
	}
	data, err := readRootMailDefault(record)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == match {
			return fields[0], nil
		}
	}
	return "", errors.New("missing mail package config digest")
}

func readRootMailDefault(record string) ([]byte, error) {
	if err := trustedDNSAncestors(filepath.Dir(record)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(record, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
		return nil, errors.New("unsafe native mail package record")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("cannot read native mail default")
	}
	return data, nil
}

func defaultUbuntuPostfixMain(content, hostname string) bool {
	wanted := map[string]string{
		"smtpd_banner": "$myhostname ESMTP $mail_name (Ubuntu)", "biff": "no", "append_dot_mydomain": "no", "readme_directory": "no", "compatibility_level": "3.6",
		"smtpd_tls_cert_file": "/etc/ssl/certs/ssl-cert-snakeoil.pem", "smtpd_tls_key_file": "/etc/ssl/private/ssl-cert-snakeoil.key", "smtpd_tls_security_level": "may",
		"smtp_tls_CApath": "/etc/ssl/certs", "smtp_tls_security_level": "may", "smtp_tls_session_cache_database": "btree:${data_directory}/smtp_scache",
		"smtpd_relay_restrictions": "permit_mynetworks permit_sasl_authenticated defer_unauth_destination", "myhostname": hostname, "alias_maps": "hash:/etc/aliases", "alias_database": "hash:/etc/aliases",
		"mydestination": "$myhostname, /etc/mailname, " + hostname + ", localhost.localdomain, localhost", "relayhost": "", "mynetworks": "127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128",
		"mailbox_size_limit": "0", "recipient_delimiter": "+", "inet_interfaces": "all", "inet_protocols": "all",
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		expected, ok := wanted[key]
		if !found || !ok || value != expected {
			return false
		}
		delete(wanted, key)
	}
	return len(wanted) == 0
}
