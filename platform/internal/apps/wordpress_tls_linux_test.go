//go:build linux

package apps

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWordPressTLSManagedFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root inside QEMU for production private directory layout")
	}
	installer := installWordPressTLSFiles
	installation := InstallationID("test-wordpress")
	installWordPressTLSFiles := func(scope linuxApplicationScope, payloads map[string][]byte) error {
		return installer(scope, installation, payloads)
	}
	newScope := func(t *testing.T) linuxApplicationScope {
		t.Helper()
		key := "s-tls-" + strings.ToLower(rand.Text())
		site := filepath.Join(linuxApplicationSitesRoot, key)
		root := filepath.Join(site, "roots", "g1", "releases", "current")
		if err := os.MkdirAll(filepath.Join(root, "wp-content"), 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(site); err != nil {
				t.Error(err)
			}
		})
		return linuxApplicationScope{root: root, binding: LinuxApplicationSiteBinding{SiteKey: key, Generation: 1, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}}
	}
	payloads := func(mutual bool) map[string][]byte {
		configuration := `{"version":1,"host":"database.example.test","port":3307,"mutual":false}`
		if mutual {
			configuration = strings.Replace(configuration, "false", "true", 1)
		}
		return map[string][]byte{".cyberpanel-db-ca.pem": []byte("CA fixture"), ".cyberpanel-db-client.pem": []byte("certificate fixture"), ".cyberpanel-db-client.key": []byte("key fixture"), ".cyberpanel-db-tls.json": []byte(configuration)}
	}
	t.Run("install replay and local transition", func(t *testing.T) {
		scope := newScope(t)
		for i := 0; i < 2; i++ {
			if err := installWordPressTLSFiles(scope, payloads(false)); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range append(append([]string{}, wordpressTLSFiles...), "db.php") {
			private, err := wordpressTLSPrivatePath(scope, installation)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(private, name)
			if name == "db.php" {
				path = filepath.Join(scope.root, "wp-content", name)
			} else if _, err := os.Stat(filepath.Join(scope.root, "wp-content", name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("material in document root: %s", name)
			}
			info, err := os.Stat(path)
			mode := os.FileMode(0600)
			if name == "mariadb" || name == "mysql" {
				mode = 0700
			}
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("private artifact %s: %v", name, err)
			}
		}
		args, err := wordpressDatabaseCLIArguments(scope, []string{"db", "import", "/private/dump.sql"})
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		for _, required := range []string{"--protocol=tcp", "--host=database.example.test", "--port=3307", "--ssl=1", "--ssl-verify-server-cert=1", "--ssl-ca="} {
			if !strings.Contains(joined, required) {
				t.Fatalf("missing TLS argument %s", required)
			}
		}
		if strings.Contains(joined, "--ssl-key") {
			t.Fatal("ordinary TLS received a client key")
		}
		environment, err := wordpressDatabaseCLIEnvironment(scope, args)
		if err != nil || len(environment) != 1 || !strings.Contains(environment[0], "application-db-") {
			t.Fatalf("missing verified import client: %v", err)
		}
		if err := installWordPressTLSFiles(scope, payloads(true)); err != nil {
			t.Fatal(err)
		}
		args, err = wordpressDatabaseCLIArguments(scope, []string{"db", "export", "/private/dump.sql"})
		if err != nil || !strings.Contains(strings.Join(args, " "), "--ssl-key=") {
			t.Fatalf("mutual TLS export: %v", err)
		}
		if _, err := wordpressDatabaseCLIArguments(scope, []string{"db", "import", "--skip-ssl"}); !errors.Is(err, ErrPolicyDenied) {
			t.Fatal("TLS override accepted")
		}
		if err := installWordPressTLSFiles(scope, nil); err != nil {
			t.Fatal(err)
		}
		if err := installWordPressTLSFiles(scope, nil); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(filepath.Join(scope.root, "wp-content"))
		if err != nil || len(entries) != 0 {
			t.Fatalf("managed files left after local transition: %v", err)
		}
	})
	t.Run("partial managed install resumes", func(t *testing.T) {
		scope := newScope(t)
		private, err := wordpressTLSPrivatePath(scope, installation)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(scope.root, "wp-content", "db.php"), renderWordPressTLSDropin(private), 0600); err != nil {
			t.Fatal(err)
		}
		if err := installWordPressTLSFiles(scope, payloads(false)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("purge removes material without dropin", func(t *testing.T) {
		scope := newScope(t)
		if err := installWordPressTLSFiles(scope, payloads(true)); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(scope.root, "wp-content", "db.php")); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := removeWordPressTLSMaterial(scope, installation); err != nil {
				t.Fatal(err)
			}
		}
		private, err := wordpressTLSPrivatePath(scope, installation)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(private)
		if err != nil || len(entries) != 0 {
			t.Fatalf("private client identity left after purge: %v", err)
		}
	})
	t.Run("unrelated dropin preserved", func(t *testing.T) {
		scope := newScope(t)
		path := filepath.Join(scope.root, "wp-content", "db.php")
		original := []byte("<?php // customer database integration")
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		if err := installWordPressTLSFiles(scope, payloads(false)); !errors.Is(err, ErrConflict) {
			t.Fatalf("unrelated dropin overwritten: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("unrelated dropin changed")
		}
	})
	t.Run("symlink leaf and ancestor rejected", func(t *testing.T) {
		scope := newScope(t)
		outside := filepath.Join(t.TempDir(), "sentinel")
		if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(scope.root, "wp-content", "db.php")); err != nil {
			t.Fatal(err)
		}
		if err := installWordPressTLSFiles(scope, payloads(false)); err == nil {
			t.Fatal("symlink leaf accepted")
		}
		got, _ := os.ReadFile(outside)
		if string(got) != "unchanged" {
			t.Fatal("symlink target modified")
		}
		alias := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(scope.root, alias); err != nil {
			t.Fatal(err)
		}
		scope.root = alias
		if _, err := openWordPressTLSDirectory(scope); err == nil {
			t.Fatal("symlink ancestor accepted")
		}
	})
	t.Run("clone isolation and promotion", func(t *testing.T) {
		source := newScope(t)
		target := newScope(t)
		if err := installWordPressTLSFiles(source, payloads(true)); err != nil {
			t.Fatal(err)
		}
		dropin, err := os.ReadFile(filepath.Join(source.root, "wp-content", "db.php"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target.root, "wp-content", "db.php"), dropin, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := wordpressDatabaseCLIArguments(target, []string{"db", "export"}); !errors.Is(err, ErrPolicyDenied) {
			t.Fatal("clone read source material")
		}
		if err := installWordPressTLSFiles(target, nil); err != nil {
			t.Fatal(err)
		}
		sourcePrivate, _ := wordpressTLSPrivatePath(source, installation)
		if _, err := os.Stat(filepath.Join(sourcePrivate, ".cyberpanel-db-client.key")); err != nil {
			t.Fatal("clone cleanup removed source identity")
		}
		if err := os.WriteFile(filepath.Join(target.root, "wp-content", "db.php"), dropin, 0600); err != nil {
			t.Fatal(err)
		}
		if err := installWordPressTLSFiles(target, payloads(true)); err != nil {
			t.Fatal(err)
		}
		promoted := filepath.Join(filepath.Dir(target.root), "promoted")
		if err := os.Rename(target.root, promoted); err != nil {
			t.Fatal(err)
		}
		target.root = promoted
		args, err := wordpressDatabaseCLIArguments(target, []string{"db", "export"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(args, " "), sourcePrivate) {
			t.Fatal("clone retained source credential path")
		}
	})
}
