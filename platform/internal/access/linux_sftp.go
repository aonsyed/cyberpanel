//go:build linux

package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// SFTP uses a distinct login, not a Match on the site's shell account. Both
// identities own the same files, but enabling SFTP cannot constrain SSH grants.
func SFTPUsername(site SiteID, principal PrincipalID) string {
	sum := sha256.Sum256([]byte(string(site) + "\x00" + string(principal)))
	return "cpsftp_" + hex.EncodeToString(sum[:10])
}

type linuxSFTPHost struct {
	root, config, snippets string
	reload                 func(context.Context) error
}
type sftpSavedGrant struct {
	Grant AccessGrant
	Key   SSHKey
}
type sftpState struct {
	Identity AccessGrant
	Grants   map[AccessGrantID]sftpSavedGrant
}

var sftpLock sync.Mutex

func (e *LinuxCredentialExecutor) sftpHost() linuxSFTPHost {
	if e.sftp != nil {
		return *e.sftp
	}
	return linuxSFTPHost{root: "/var/lib/cyberpanel/sftp", config: "/etc/ssh/sshd_config", snippets: "/etc/ssh/cyberpanel-sftp.d", reload: func(ctx context.Context) error {
		return reloadSFTPUnit(func(unit string) error {
			_, err := runFixedAccess(ctx, "/usr/bin/systemctl", nil, "try-reload-or-restart", unit)
			return err
		})
	}}
}
func reloadSFTPUnit(reload func(string) error) error {
	if err := reload("sshd.service"); err != nil {
		if fallback := reload("ssh.service"); fallback != nil {
			return errors.Join(err, fallback)
		}
	}
	return nil
}
func sftpDirectory(path string) error {
	if err := os.Mkdir(path, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return ErrIntegrity
	}
	// The executor runs with UMask=0027. The chroot itself must remain
	// traversable after sshd drops to the site UID; this never chmods site data.
	return os.Chmod(path, 0755)
}
func sftpWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func (h linuxSFTPHost) state(name string) (sftpState, error) {
	result := sftpState{Grants: map[AccessGrantID]sftpSavedGrant{}}
	raw, err := os.ReadFile(filepath.Join(h.root, name+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(raw, &result)
	if result.Grants == nil {
		return result, ErrIntegrity
	}
	return result, err
}
func (h linuxSFTPHost) save(name string, state sftpState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return sftpWrite(filepath.Join(h.root, name+".json"), raw, 0600)
}
func sftpUnmount(ctx context.Context, target string) error {
	encoded, err := runFixedAccess(ctx, "/usr/bin/systemd-escape", nil, "--path", "--suffix=mount", target)
	if err != nil {
		return err
	}
	active, err := runFixedAccess(ctx, "/usr/bin/systemctl", nil, "show", "--value", "--property=ActiveState", strings.TrimSpace(string(encoded)))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(active)) != "active" {
		return nil
	}
	_, err = runFixedAccess(ctx, "/usr/bin/systemd-mount", nil, "--umount", "--no-ask-password", "--quiet", target)
	return err
}
func sftpStopSessions(ctx context.Context, name string) error {
	// Do not kill by UID: the PHP/shell account deliberately shares this UID.
	account, err := user.Lookup(name)
	if _, missing := err.(user.UnknownUserError); missing {
		return nil
	}
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return ErrIntegrity
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	type monitor struct{ pid, fd int }
	var monitors []monitor
	defer func() {
		for _, m := range monitors {
			unix.Close(m.fd)
		}
	}()
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			if errors.Is(err, syscall.ESRCH) {
				continue
			}
			return err
		}
		owner, _, title, readErr := sftpProcess(pid)
		// A tenant can rename its own argv, but cannot manufacture a root-owned
		// SSH privilege monitor. Pin the process before inspecting its identity.
		if readErr != nil || owner != 0 || title != "sshd: "+name+" [priv]" || unix.PidfdSendSignal(fd, 0, nil, 0) != nil {
			unix.Close(fd)
			continue
		}
		monitors = append(monitors, monitor{pid, fd})
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			if errors.Is(err, syscall.ESRCH) {
				continue
			}
			return err
		}
		owner, parent, title, readErr := sftpProcess(pid)
		if readErr == nil && owner == uid && (title == "sshd: "+name+"@internal-sftp" || title == "sshd: "+name+"@notty") {
			for _, m := range monitors {
				if parent == m.pid && unix.PidfdSendSignal(m.fd, 0, nil, 0) == nil && unix.PidfdSendSignal(fd, 0, nil, 0) == nil {
					err = unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0)
					if err != nil && !errors.Is(err, syscall.ESRCH) {
						unix.Close(fd)
						return err
					}
				}
			}
		}
		unix.Close(fd)
	}
	for _, m := range monitors {
		if err = unix.PidfdSendSignal(m.fd, syscall.SIGKILL, nil, 0); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	return nil
}
func sftpProcess(pid int) (uid, parent int, title string, err error) {
	uid, parent = -1, -1
	path := "/proc/" + strconv.Itoa(pid)
	raw, err := os.ReadFile(path + "/status")
	if err != nil {
		return uid, parent, "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			uid, err = strconv.Atoi(fields[1])
		case "PPid:":
			parent, err = strconv.Atoi(fields[1])
		}
		if err != nil {
			return uid, parent, "", err
		}
	}
	raw, err = os.ReadFile(path + "/cmdline")
	return uid, parent, strings.TrimRight(string(raw), "\x00 "), err
}
func (h linuxSFTPHost) configure(ctx context.Context, name string, grant AccessGrant) (result error) {
	if err := sftpDirectory(h.snippets); err != nil {
		return err
	}
	jail := filepath.Join(h.root, name)
	command := "internal-sftp -d /site"
	if grant.Permission == AccessReadOnly {
		command += " -R"
	}
	snippet := fmt.Sprintf("Match User %s\n    ChrootDirectory %s\n    ForceCommand %s\n    DisableForwarding yes\n    PermitTTY no\n    PasswordAuthentication no\n    AuthenticationMethods publickey\n    AuthorizedKeysFile %s/cyberpanel-%%u\nMatch all\n", name, jail, command, linuxAuthorizedKeysRoot)
	raw, err := os.ReadFile(h.config)
	if err != nil {
		return err
	}
	include := "Match all\nInclude " + h.snippets + "/*.conf\nMatch all\n"
	path := filepath.Join(h.snippets, name+".conf")
	prior, priorErr := os.ReadFile(path)
	if priorErr != nil && !errors.Is(priorErr, os.ErrNotExist) {
		return priorErr
	}
	if err = sftpWrite(path, []byte(snippet), 0644); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			if priorErr == nil {
				_ = sftpWrite(path, prior, 0644)
			} else {
				_ = os.Remove(path)
			}
		}
	}()
	// Match belongs at the end, not in sshd_config.d (included ahead of global
	// directives such as Subsystem). Include is installed once and remains inert
	// after the last SFTP principal is removed.
	candidate := raw
	if !strings.Contains(string(raw), "\n"+include) {
		candidate = append(append([]byte(nil), raw...), []byte("\n"+include)...)
	}
	check := h.config + ".sftp-check"
	if err = sftpWrite(check, candidate, 0600); err != nil {
		return err
	}
	defer os.Remove(check)
	if _, err = runFixedAccess(ctx, "/usr/sbin/sshd", nil, "-t", "-f", check); err != nil {
		return err
	}
	if err = sftpWrite(h.config, candidate, 0600); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			_ = sftpWrite(h.config, raw, 0600)
		}
	}()
	return h.reload(ctx)
}
func (e *LinuxCredentialExecutor) applySFTP(ctx context.Context, grant AccessGrant, key SSHKey) (string, error) {
	sftpLock.Lock()
	defer sftpLock.Unlock()
	return e.applySFTPLocked(ctx, grant, key)
}
func (e *LinuxCredentialExecutor) applySFTPLocked(ctx context.Context, grant AccessGrant, key SSHKey) (receipt string, result error) {
	if err := grant.Validate(time.Now().UTC()); err != nil {
		return "", err
	}
	if err := key.Validate(); err != nil {
		return "", err
	}
	if grant.Permission != AccessReadOnly && grant.Permission != AccessReadWrite {
		return "", ErrUnauthorized
	}
	if key.ID != grant.SSHKeyID || key.TenantID != grant.TenantID || key.PrincipalID != grant.PrincipalID {
		return "", ErrUnauthorized
	}
	h := e.sftpHost()
	if err := sftpDirectory(h.root); err != nil {
		return "", err
	}
	if err := ensureAuthorizedKeysRoot(); err != nil {
		return "", err
	}
	name := SFTPUsername(grant.SiteID, grant.PrincipalID)
	state, err := h.state(name)
	if err != nil {
		return "", err
	}
	previous := sftpState{Identity: state.Identity, Grants: make(map[AccessGrantID]sftpSavedGrant, len(state.Grants))}
	for id, saved := range state.Grants {
		previous.Grants[id] = saved
	}
	for _, saved := range state.Grants {
		g := saved.Grant
		if g.Root != grant.Root || g.WorkingDirectory != grant.WorkingDirectory || g.Permission != grant.Permission || g.TenantID != grant.TenantID {
			return "", ErrUnauthorized
		}
	}
	fd, binding, err := e.Files.openRoot(ctx, grant.Root)
	if err != nil {
		return "", err
	}
	defer syscall.Close(fd)
	parts, err := splitRelative(grant.WorkingDirectory)
	if err != nil {
		return "", err
	}
	source, err := descendLinux(fd, parts)
	if err != nil {
		return "", err
	}
	defer syscall.Close(source)
	var sourceStat syscall.Stat_t
	if err = syscall.Fstat(source, &sourceStat); err != nil {
		return "", err
	}
	if sourceStat.Uid != binding.UID || sourceStat.Gid != binding.GID {
		return "", ErrUnauthorized
	}
	fresh := len(state.Grants) == 0
	if fresh {
		state.Identity = grant
		if err = h.save(name, state); err != nil {
			return "", err
		}
	}
	defer func() {
		if result != nil && fresh {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result = errors.Join(result, e.removeSFTPLocked(cleanup, grant))
		} else if result != nil {
			// Failed native publication must not be replayed as a new grant.
			result = errors.Join(result, h.save(name, previous))
		}
	}()
	jail := filepath.Join(h.root, name)
	if err = sftpDirectory(jail); err != nil {
		return "", err
	}
	target := filepath.Join(jail, "site")
	account, lookupErr := user.Lookup(name)
	if lookupErr != nil {
		if _, ok := lookupErr.(user.UnknownUserError); !ok {
			return "", lookupErr
		}
		_, err = runFixedAccess(ctx, "/usr/sbin/useradd", nil, "--non-unique", "--uid", strconv.FormatUint(uint64(binding.UID), 10), "--gid", strconv.FormatUint(uint64(binding.GID), 10), "--no-create-home", "--home-dir", "/site", "--shell", "/usr/sbin/nologin", "--password", "x", name)
		if err != nil {
			return "", err
		}
	} else if account.Uid != strconv.FormatUint(uint64(binding.UID), 10) || account.Gid != strconv.FormatUint(uint64(binding.GID), 10) || account.HomeDir != "/site" {
		return "", ErrIntegrity
	}
	// A held O_NOFOLLOW directory descriptor, not a mutable site pathname, is
	// the bind source. The host mount propagates to the native SSH daemon.
	// Withdraw keys before changing any mount. Even a raced source subsequently
	// rejected by the inode check must never be visible to a concurrent login.
	if err = h.keys(name, sftpState{}); err != nil {
		return "", err
	}
	if err = sftpStopSessions(ctx, name); err != nil {
		return "", err
	}
	if err = sftpUnmount(ctx, target); err != nil {
		return "", err
	}
	if err = sftpDirectory(target); err != nil {
		return "", err
	}
	if _, err = runFixedAccess(ctx, "/usr/bin/systemd-mount", nil, "--collect", "--no-ask-password", "--fsck=no", "--type=none", "--options=bind", fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), source), target); err != nil {
		return "", err
	}
	defer func() {
		if result != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result = errors.Join(result, h.keys(name, sftpState{}), sftpUnmount(cleanup, target))
		}
	}()
	var original, mounted syscall.Stat_t
	if err = syscall.Fstat(source, &original); err != nil {
		return "", err
	}
	if err = syscall.Stat(target, &mounted); err != nil {
		return "", err
	}
	if original.Dev != mounted.Dev || original.Ino != mounted.Ino {
		return "", ErrIntegrity
	}
	if err = h.configure(ctx, name, grant); err != nil {
		return "", err
	}
	state.Identity = grant
	state.Grants[grant.ID] = sftpSavedGrant{grant, key}
	if err = h.save(name, state); err != nil {
		return "", err
	}
	if err = h.keys(name, state); err != nil {
		return "", err
	}
	return accessReceipt("sftp-grant", string(grant.ID), key.PublicKey.Fingerprint), nil
}
func (h linuxSFTPHost) keys(name string, state sftpState) error {
	var lines []string
	for _, saved := range state.Grants {
		g := saved.Grant
		options := []string{"restrict"}
		if !g.ExpiresAt.IsZero() {
			options = append(options, "expiry-time=\""+g.ExpiresAt.UTC().Format("20060102150405Z")+"\"")
		}
		if len(g.AllowedNetworks) > 0 {
			options = append(options, "from=\""+strings.Join(g.AllowedNetworks, ",")+"\"")
		}
		lines = append(lines, strings.Join(options, ",")+" "+saved.Key.PublicKey.AuthorizedKey()+" cyberpanel grant="+string(g.ID)+" key="+string(saved.Key.ID))
	}
	return sftpWrite(linuxAuthorizedKeysRoot+"/cyberpanel-"+name, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}
func (e *LinuxCredentialExecutor) removeSFTP(ctx context.Context, grant AccessGrant) (string, error) {
	sftpLock.Lock()
	defer sftpLock.Unlock()
	err := e.removeSFTPLocked(ctx, grant)
	return accessReceipt("sftp-grant-remove", string(grant.ID)), err
}
func (e *LinuxCredentialExecutor) removeSFTPLocked(ctx context.Context, grant AccessGrant) error {
	h := e.sftpHost()
	name := SFTPUsername(grant.SiteID, grant.PrincipalID)
	state, err := h.state(name)
	if err != nil {
		return err
	}
	state.Identity = grant
	delete(state.Grants, grant.ID)
	// Persist revocation before touching mounts so restart cannot reauthorize it.
	if _, err = os.Stat(h.root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err = h.save(name, state); err != nil {
		return err
	}
	if err = h.keys(name, state); err != nil {
		return err
	}
	if err = sftpStopSessions(ctx, name); err != nil {
		return err
	}
	if len(state.Grants) > 0 {
		return nil
	}
	target := filepath.Join(h.root, name, "site")
	if err = sftpUnmount(ctx, target); err != nil {
		return err
	}
	for _, path := range []string{target, filepath.Join(h.root, name), filepath.Join(h.snippets, name+".conf"), linuxAuthorizedKeysRoot + "/cyberpanel-" + name} {
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if _, err = user.Lookup(name); err == nil {
		if _, err = runFixedAccess(ctx, "/usr/sbin/userdel", nil, name); err != nil {
			return err
		}
	}
	if err = h.reload(ctx); err != nil {
		return err
	}
	return os.Remove(filepath.Join(h.root, name+".json"))
}
func (e *LinuxCredentialExecutor) removeSFTPKey(ctx context.Context, key SSHKeyID) error {
	sftpLock.Lock()
	defer sftpLock.Unlock()
	h := e.sftpHost()
	entries, err := os.ReadDir(h.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "cpsftp_") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		state, err := h.state(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return err
		}
		for _, saved := range state.Grants {
			if saved.Key.ID == key {
				if err = e.removeSFTPLocked(ctx, saved.Grant); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ReconcileSFTP restores descriptor-validated bind mounts after daemon restart or
// reboot. Expired/revoked records are removed rather than revived.
func (e *LinuxCredentialExecutor) ReconcileSFTP(ctx context.Context) error {
	sftpLock.Lock()
	defer sftpLock.Unlock()
	h := e.sftpHost()
	entries, err := os.ReadDir(h.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "cpsftp_") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		state, err := h.state(name)
		if err != nil {
			return err
		}
		if SFTPUsername(state.Identity.SiteID, state.Identity.PrincipalID) != name {
			return ErrIntegrity
		}
		if err = h.keys(name, sftpState{}); err != nil {
			return err
		}
		if err = sftpStopSessions(ctx, name); err != nil {
			return err
		}
		if err = sftpUnmount(ctx, filepath.Join(h.root, name, "site")); err != nil {
			return err
		}
		if len(state.Grants) == 0 {
			if err = e.removeSFTPLocked(ctx, state.Identity); err != nil {
				return err
			}
			continue
		}
		for _, saved := range state.Grants {
			if saved.Grant.Validate(time.Now().UTC()) != nil {
				err = e.removeSFTPLocked(ctx, saved.Grant)
			} else {
				_, err = e.applySFTPLocked(ctx, saved.Grant, saved.Key)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}
