//go:build linux

package access

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in: reserve the guest native-account lease first. Uses disposable accounts,
// keys, site roots and a separate loopback sshd, never the system SSH daemon.
func TestNativeSFTPGrantRootIsolation(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_SFTP") != "1" || os.Geteuid() != 0 {
		t.Skip("requires reserved root QEMU SFTP fixture")
	}
	for _, permission := range []AccessPermission{AccessReadWrite, AccessReadOnly} {
		t.Run(string(permission), func(t *testing.T) { testNativeSFTPGrantRootIsolation(t, permission) })
	}
}
func testNativeSFTPGrantRootIsolation(t *testing.T, permission AccessPermission) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	run := func(binary string, args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", filepath.Base(binary), err, out)
		}
		return out
	}
	uid := 62171
	for _, id := range []int{uid, uid + 1} {
		if _, err := user.LookupId(strconv.Itoa(id)); err == nil {
			t.Fatalf("reserved fixture UID %d occupied", id)
		}
		if _, err := user.LookupGroupId(strconv.Itoa(id)); err == nil {
			t.Fatalf("reserved fixture GID %d occupied", id)
		}
	}
	workspace := t.TempDir()
	root, err := os.MkdirTemp(LinuxAccessSitesRoot, "s-sftp-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	name := fmt.Sprintf("cp_qasftp_%d", os.Getpid())
	run("/usr/sbin/groupadd", "--gid", strconv.Itoa(uid), name)
	t.Cleanup(func() { exec.Command("/usr/sbin/groupdel", name).Run() })
	run("/usr/sbin/useradd", "--uid", strconv.Itoa(uid), "--gid", name, "--home-dir", root, "--no-create-home", "--shell", "/usr/sbin/nologin", "--password", "x", name)
	t.Cleanup(func() { exec.Command("/usr/sbin/userdel", name).Run() })
	if err = os.Chmod(root, 0711); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(root, "roots/g1/releases/current/public")
	if err = os.MkdirAll(public, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(public, uid, uid); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(public, 0750); err != nil {
		t.Fatal(err)
	}
	marker := []byte("native-sftp-exact-root\x00\xff\n")
	if err = os.WriteFile(filepath.Join(public, "allowed.bin"), marker, 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(filepath.Join(public, "allowed.bin"), uid, uid); err != nil {
		t.Fatal(err)
	}
	run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(workspace, "client"))
	run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(workspace, "host"))
	publicKey, err := os.ReadFile(filepath.Join(workspace, "client.pub"))
	if err != nil {
		t.Fatal(err)
	}
	keyValue, err := ParsePublicKey(strings.TrimSpace(string(publicKey)))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := NewLinuxFileExecutor(LinuxSiteResolverFunc(func(context.Context, SiteID) (LinuxSiteBinding, error) {
		return LinuxSiteBinding{SiteKey: filepath.Base(root), Username: name, UID: uint32(uid), GID: uint32(uid), Generation: 1}, nil
	}))
	credentials, _ := NewLinuxCredentialExecutor(files)
	jailRoot, err := os.MkdirTemp("/var/lib/cyberpanel", "sftp-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(jailRoot) })
	key := SSHKey{ID: "sftp-key", TenantID: "sftp-tenant", PrincipalID: "sftp-principal", Name: "SFTP proof", PublicKey: keyValue, Generation: 1}
	grant := AccessGrant{ID: "sftp-grant", SiteID: "sftp-site", TenantID: key.TenantID, PrincipalID: key.PrincipalID, SSHKeyID: key.ID, Protocol: ProtocolSFTP, Permission: permission, Root: SiteRoot{SiteID: "sftp-site", Kind: RootPublic}, Generation: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if permission == AccessReadOnly {
		grant.ExpiresAt = time.Time{}
	}
	login := SFTPUsername(grant.SiteID, grant.PrincipalID)
	keyPath := linuxAuthorizedKeysRoot + "/cyberpanel-" + login
	t.Cleanup(func() { os.Remove(keyPath) })
	t.Cleanup(func() {
		exec.Command("/usr/bin/systemd-mount", "--umount", filepath.Join(jailRoot, login, "site")).Run()
		exec.Command("/usr/sbin/userdel", login).Run()
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config := fmt.Sprintf("ListenAddress 127.0.0.1\nPort %d\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s/cyberpanel-%%u\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM yes\nStrictModes yes\nAllowUsers %s\nSubsystem sftp internal-sftp\nLogLevel VERBOSE\n", port, filepath.Join(workspace, "host"), filepath.Join(workspace, "sshd.pid"), linuxAuthorizedKeysRoot, login)
	config += "Match User unrelated-never-matches\n    PermitTTY no\n"
	configPath := filepath.Join(workspace, "sshd_config")
	if err = os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	credentials.sftp = &linuxSFTPHost{root: jailRoot, config: configPath, snippets: filepath.Join(workspace, "sftp.d"), reload: func(context.Context) error { return nil }}
	if err = os.Chown(public, uid+1, uid+1); err != nil {
		t.Fatal(err)
	}
	if _, err = credentials.ApplyAccessGrant(ctx, grant, key); err == nil {
		t.Fatal("foreign-owned source accepted")
	}
	if err = os.Chown(public, uid, uid); err != nil {
		t.Fatal(err)
	}
	credentials.sftp.reload = func(context.Context) error { return fmt.Errorf("injected native reload failure") }
	if _, err = credentials.ApplyAccessGrant(ctx, grant, key); err == nil {
		t.Fatal("reload failure ignored")
	}
	if _, err = os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("failed apply left authorized keys: %v", err)
	}
	if _, err = os.Stat(filepath.Join(jailRoot, login, "site")); !os.IsNotExist(err) {
		t.Fatalf("failed apply left jail/mount: %v", err)
	}
	if _, err = user.Lookup(login); err == nil {
		t.Fatal("failed apply left SFTP account")
	}
	credentials.sftp.reload = func(context.Context) error { return nil }
	if _, err = credentials.ApplyAccessGrant(ctx, grant, key); err != nil {
		t.Fatal(err)
	}
	unrelated := string(run("/usr/sbin/sshd", "-T", "-f", configPath, "-C", "user="+name+",host=localhost,addr=127.0.0.1"))
	if !strings.Contains(unrelated, "chrootdirectory none\n") || !strings.Contains(unrelated, "forcecommand none\n") {
		t.Fatal("SFTP policy changed unrelated SSH principal")
	}
	run("/usr/sbin/sshd", "-t", "-f", configPath)
	log, err := os.Create(filepath.Join(workspace, "sshd.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	daemon := exec.CommandContext(ctx, "/usr/sbin/sshd", "-D", "-e", "-f", configPath)
	daemon.Stdout = log
	daemon.Stderr = log
	if err = daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { daemon.Process.Kill(); daemon.Wait() }()
	for attempt := 0; attempt < 50; attempt++ {
		connection, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Millisecond*50)
		if e == nil {
			connection.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	hostKey, err := os.ReadFile(filepath.Join(workspace, "host.pub"))
	if err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(workspace, "known_hosts")
	if err = os.WriteFile(known, []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, hostKey)), 0600); err != nil {
		t.Fatal(err)
	}
	batch := filepath.Join(workspace, "batch")
	download := filepath.Join(workspace, "received.bin")
	if err = os.WriteFile(batch, []byte("get allowed.bin "+download+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-b", batch, "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known, "-o", "IdentitiesOnly=yes", "-i", filepath.Join(workspace, "client"), "-P", strconv.Itoa(port), login + "@127.0.0.1"}
	out, err := exec.CommandContext(ctx, "/usr/bin/sftp", args...).CombinedOutput()
	if err != nil {
		diagnostic, _ := os.ReadFile(filepath.Join(workspace, "sshd.log"))
		t.Fatalf("product SFTP grant cannot access its allowed root: %v\n%s\n%s", err, out, diagnostic)
	}
	got, err := os.ReadFile(download)
	if err != nil || string(got) != string(marker) {
		t.Fatalf("allowed-root bytes differ: %v", err)
	}
	t.Log("PASS native SFTP login and exact binary allowed-root download")
	if err = os.WriteFile(batch, []byte("put "+download+" uploaded.bin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = exec.CommandContext(ctx, "/usr/bin/sftp", args...).CombinedOutput()
	if permission == AccessReadOnly {
		if err == nil {
			t.Fatal("read-only grant wrote file")
		}
	} else {
		if err != nil {
			t.Fatalf("allowed-root upload: %v %s", err, out)
		}
		got, err = os.ReadFile(filepath.Join(public, "uploaded.bin"))
		if err != nil || string(got) != string(marker) {
			t.Fatalf("upload roundtrip bytes: %v", err)
		}
	}
	t.Log("PASS native write permission enforced")
	other, err := os.MkdirTemp(LinuxAccessSitesRoot, "s-sftp-other-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(other) })
	if err = os.Chmod(other, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(other, "cross-site.bin"), []byte("other-site-unique-marker"), 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(filepath.Join(other, "cross-site.bin"), uid+1, uid+1); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(batch, []byte("get "+filepath.Join(other, "cross-site.bin")+" "+download+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err = exec.CommandContext(ctx, "/usr/bin/sftp", args...).CombinedOutput(); err == nil {
		t.Fatalf("cross-site path leaked: %s", out)
	}
	if err = os.Symlink(filepath.Join(other, "cross-site.bin"), filepath.Join(public, "other-site")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(batch, []byte("get other-site "+download+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err = exec.CommandContext(ctx, "/usr/bin/sftp", args...).CombinedOutput(); err == nil {
		t.Fatalf("cross-site symlink leaked: %s", out)
	}
	t.Log("PASS known cross-site content inaccessible by absolute path and symlink")
	for _, path := range []string{"/etc/passwd", "../../etc/passwd", public + "/allowed.bin"} {
		if err = os.WriteFile(batch, []byte("get "+path+" "+download+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if out, err = exec.CommandContext(ctx, "/usr/bin/sftp", args...).CombinedOutput(); err == nil {
			t.Fatalf("escaped jail via %s: %s", path, out)
		}
	}
	if err = os.Symlink("/etc/passwd", filepath.Join(public, "escape")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(batch, []byte("get escape "+download+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err = exec.CommandContext(ctx, "/usr/bin/sftp", args...).CombinedOutput(); err == nil {
		t.Fatalf("symlink escaped jail: %s", out)
	}
	t.Log("PASS host absolute path, dot-dot and symlink escape denied")
	conflict := grant
	conflict.ID = "conflicting-root"
	conflict.Root.Kind = RootSite
	if _, err = credentials.ApplyAccessGrant(ctx, conflict, key); err == nil {
		t.Fatal("conflicting principal root accepted")
	}
	if _, err = credentials.ApplyAccessGrant(ctx, grant, key); err != nil {
		t.Fatalf("idempotent grant: %v", err)
	}
	run("/usr/bin/systemd-mount", "--umount", filepath.Join(jailRoot, login, "site"))
	if err = credentials.ReconcileSFTP(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err = os.WriteFile(batch, []byte("get allowed.bin "+download+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err = exec.CommandContext(ctx, "/usr/bin/sftp", args...).CombinedOutput(); err != nil {
		t.Fatalf("reconciled grant failed: %v %s", err, out)
	}
	t.Log("PASS conflicting root rejected and reapply/reconcile remains usable")
	liveArgs := append([]string(nil), args...)
	liveArgs[1] = "-"
	live := exec.CommandContext(ctx, "/usr/bin/sftp", liveArgs...)
	input, err := live.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	liveOutput, err := os.Create(filepath.Join(workspace, "live.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer liveOutput.Close()
	live.Stdout = liveOutput
	live.Stderr = liveOutput
	if err = live.Start(); err != nil {
		t.Fatal(err)
	}
	defer live.Process.Kill()
	sessionFile := filepath.Join(workspace, "session.bin")
	fmt.Fprintf(input, "get allowed.bin %s\n", sessionFile)
	for attempt := 0; attempt < 100; attempt++ {
		if _, err = os.Stat(sessionFile); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = os.Stat(sessionFile); err != nil {
		t.Fatal("live session did not become ready")
	}
	if _, err = credentials.RemoveAccessGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(input, "get allowed.bin %s\n", filepath.Join(workspace, "after-revoke.bin"))
	input.Close()
	if err = live.Wait(); err == nil {
		t.Fatal("revocation did not terminate live SFTP session")
	}
	if out, err = exec.CommandContext(ctx, "/usr/bin/sftp", args...).CombinedOutput(); err == nil {
		t.Fatalf("revoked login accepted: %s", out)
	}
	if _, err = credentials.RemoveAccessGrant(ctx, grant); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if err = credentials.ReconcileSFTP(ctx); err != nil {
		t.Fatalf("reconcile revoked: %v", err)
	}
	if _, err = user.Lookup(login); err == nil {
		t.Fatal("reconcile revived revoked account")
	}
	t.Log("PASS revoked login denied and repeated revoke succeeds")
	if _, err = credentials.ApplyAccessGrant(ctx, grant, key); err != nil {
		t.Fatal(err)
	}
	expired, err := credentials.sftp.state(login)
	if err != nil {
		t.Fatal(err)
	}
	saved := expired.Grants[grant.ID]
	saved.Grant.ExpiresAt = time.Now().Add(-time.Hour)
	expired.Grants[grant.ID] = saved
	if err = credentials.sftp.save(login, expired); err != nil {
		t.Fatal(err)
	}
	if err = credentials.sftp.keys(login, expired); err != nil {
		t.Fatal(err)
	}
	if out, err = exec.CommandContext(ctx, "/usr/bin/sftp", args...).CombinedOutput(); err == nil {
		t.Fatalf("expired key login accepted: %s", out)
	}
	run("/usr/bin/systemd-mount", "--umount", filepath.Join(jailRoot, login, "site"))
	restarted, _ := NewLinuxCredentialExecutor(files)
	restarted.sftp = credentials.sftp
	if err = restarted.ReconcileSFTP(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = user.Lookup(login); err == nil {
		t.Fatal("restart revived expired account")
	}
	t.Log("PASS expired key denied by native sshd and not revived after mount loss/restart")
}
