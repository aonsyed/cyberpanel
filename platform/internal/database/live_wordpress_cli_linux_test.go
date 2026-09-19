//go:build linux

package database

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Exercise the real WP-CLI -> MariaDB client path, separately from mysqli.
// The parent fixture owns the temporary server, database and all material.
func checkQEMUWordPressDatabaseCLI(t *testing.T, ctx context.Context, root, privateRoot, host string, port int, password []byte, mutual, accept, tlsError bool, rootQuery func(string) ([]byte, error)) {
	t.Helper()
	wordpress := filepath.Join(root, "wordpress-cli")
	if _, err := os.Stat(wordpress); os.IsNotExist(err) {
		if output, err := exec.CommandContext(ctx, "/bin/cp", "-a", "/home/harness/wordpress-7.1", wordpress).CombinedOutput(); err != nil {
			t.Fatalf("prepare WP-CLI core: %v: %s", err, output)
		}
	}
	configuration := fmt.Sprintf("<?php\ndefine('DB_NAME', 'qemu_wordpress');\ndefine('DB_USER', 'qemu_tls');\ndefine('DB_PASSWORD', base64_decode('%s'));\ndefine('DB_HOST', '%s:%d');\n$table_prefix = 'wp_';\nif (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }\nrequire_once ABSPATH . 'wp-settings.php';\n", base64.StdEncoding.EncodeToString(password), host, port)
	if err := os.WriteFile(filepath.Join(wordpress, "wp-config.php"), []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	dropin, err := os.ReadFile(filepath.Join(root, "wordpress", "db.php"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wordpress, "wp-content", "db.php"), dropin, 0600); err != nil {
		t.Fatal(err)
	}
	if accept {
		bootstrap := func(input []byte, args ...string) ([]byte, error) {
			command := exec.CommandContext(ctx, "/usr/bin/php8.3", append([]string{"/home/harness/wp-cli-2.12.0.phar", "--allow-root", "--path=" + wordpress}, args...)...)
			command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "LANG=C.UTF-8"}
			if input != nil {
				command.Stdin = strings.NewReader(string(input))
			}
			return command.CombinedOutput()
		}
		if !mutual {
			input := append(append([]byte(nil), password...), '\n')
			output, err := bootstrap(input, "core", "install", "--url=https://qemu-wordpress.invalid", "--title=QEMU WordPress TLS", "--admin_user=qemu_admin", "--admin_email=qemu@example.invalid", "--skip-email", "--prompt=admin_password")
			wipeBytes(input)
			if err != nil {
				t.Fatalf("full WordPress install: %v: %s", err, output)
			}
		}
		if output, err := bootstrap(nil, "core", "is-installed"); err != nil {
			t.Fatalf("full WordPress bootstrap: %v: %s", err, output)
		}
		input := append(append([]byte(nil), password...), '\n')
		output, authErr := bootstrap(input, "eval", "$user = wp_authenticate('qemu_admin', trim(stream_get_contents(STDIN))); if (is_wp_error($user) || !user_can($user, 'manage_options')) { WP_CLI::error('Fixture administrator authentication failed'); } WP_CLI::success('Fixture administrator authenticated');")
		wipeBytes(input)
		if authErr != nil {
			t.Fatalf("WordPress administrator authentication: %v: %s", authErr, output)
		}
		if output, err := bootstrap(nil, "option", "get", "siteurl"); err != nil || strings.TrimSpace(string(output)) != "https://qemu-wordpress.invalid" {
			t.Fatalf("WordPress option roundtrip: %v: %s", err, output)
		}
		admin, err := rootQuery("SELECT COUNT(*) FROM qemu_wordpress.wp_users WHERE user_login='qemu_admin' AND user_pass <> '';")
		if err != nil || strings.TrimSpace(string(admin)) != "1" {
			t.Fatalf("WordPress administrator was not persisted: %v", err)
		}
		t.Log("full WordPress bootstrap and persisted administrator/site URL verified through managed TLS drop-in")
	}
	dump := filepath.Join(root, "wordpress-cli.sql")
	transport := []string{"--protocol=tcp", "--host=" + host, "--port=" + strconv.Itoa(port), "--ssl=1", "--ssl-verify-server-cert=1", "--ssl-ca=" + filepath.Join(privateRoot, ".cyberpanel-db-ca.pem")}
	client, err := os.ReadFile("../apps/wordpress_mariadb_tls.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mariadb", "mysql"} {
		if err := os.WriteFile(filepath.Join(privateRoot, name), client, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if mutual {
		transport = append(transport, "--ssl-cert="+filepath.Join(privateRoot, ".cyberpanel-db-client.pem"), "--ssl-key="+filepath.Join(privateRoot, ".cyberpanel-db-client.key"))
	}
	run := func(action string) ([]byte, error) {
		args := []string{"/home/harness/wp-cli-2.12.0.phar", "--allow-root", "--path=" + wordpress, "db", action, dump}
		var input *os.File
		if action == "import" {
			var err error
			input, err = os.Open(dump)
			if err != nil {
				return nil, err
			}
			defer input.Close()
			args[len(args)-1] = "-"
		}
		args = append(args, transport...)
		command := exec.CommandContext(ctx, "/usr/bin/php8.3", args...)
		if input != nil {
			command.Stdin = input
		}
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "LANG=C.UTF-8"}
		if action == "import" {
			command.Env[0] = "PATH=" + privateRoot + ":/usr/bin:/bin"
		}
		return command.CombinedOutput()
	}
	if _, err := rootQuery("CREATE TABLE IF NOT EXISTS qemu_wordpress.tls_roundtrip (id INT PRIMARY KEY, value VARCHAR(32)); REPLACE INTO qemu_wordpress.tls_roundtrip VALUES (1, 'verified-roundtrip');"); err != nil {
		t.Fatal(err)
	}
	output, err := run("export")
	if !accept {
		reject := func(output []byte, err error) {
			t.Helper()
			if err == nil {
				t.Fatal("WP-CLI accepted an untrusted database connection")
			}
			if tlsError && !strings.Contains(string(output), "2026") && !strings.Contains(strings.ToLower(string(output)), "certificate") {
				t.Fatalf("WP-CLI failed for a non-TLS reason: %s", output)
			}
			if !tlsError && !strings.Contains(string(output), "1045") {
				t.Fatalf("WP-CLI missing identity did not reach database authentication: %s", output)
			}
		}
		reject(output, err)
		if err := os.WriteFile(dump, []byte("UPDATE tls_roundtrip SET value='untrusted-import' WHERE id=1;\n"), 0600); err != nil {
			t.Fatal(err)
		}
		reject(run("import"))
		value, err := rootQuery("SELECT value FROM qemu_wordpress.tls_roundtrip WHERE id=1;")
		if err != nil || strings.TrimSpace(string(value)) != "verified-roundtrip" {
			t.Fatal("untrusted import modified the database")
		}
		t.Log("WP-CLI export and import rejected invalid database TLS identity")
		return
	}
	if err != nil {
		t.Fatalf("WP-CLI export: %v: %s", err, output)
	}
	if _, err := rootQuery("DELETE FROM qemu_wordpress.tls_roundtrip;"); err != nil {
		t.Fatal(err)
	}
	if output, err := run("import"); err != nil {
		t.Fatalf("WP-CLI import: %v: %s", err, output)
	}
	value, err := rootQuery("SELECT value FROM qemu_wordpress.tls_roundtrip WHERE id=1;")
	if err != nil || strings.TrimSpace(string(value)) != "verified-roundtrip" {
		t.Fatalf("WP-CLI database roundtrip lost data: %v", err)
	}
	t.Log("WP-CLI exported and imported real data over verified database TLS")
}
