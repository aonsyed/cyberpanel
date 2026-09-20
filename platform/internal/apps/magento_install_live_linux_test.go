package apps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This exercises real Magento, OpenSearch and MariaDB through the production argument
// bootstrap. It deliberately does not claim an installed LSPHP/OLS lifecycle.
func TestQEMURealMagentoInstallation(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_INSTALL_MAGENTO") != "1" {
		t.Skip("QEMU real archive, PHP and MariaDB required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("run fixture as root inside QEMU")
	}
	if digest, err := digestLinuxApplicationFile("/home/harness/magento-2.4.7-p10-rooted.tar.gz", 256<<20); err != nil || digest != "a08e75ea5b7c0534194328106ee46d4d2dbdbd83ec1e333594d670a99cfa69fd" {
		t.Fatal("Magento fixture does not match the verified prepared archive")
	}
	account, err := user.Lookup("harness")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/home/harness", "qemu-magento-install-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chown(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	runAsSite := func(binary string, args ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, binary, args...)
		command.Dir = root
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "TMPDIR=" + root, "LANG=C.UTF-8"}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		return command.CombinedOutput()
	}
	if output, err := runAsSite("/usr/bin/tar", "--no-same-owner", "--no-same-permissions", "--strip-components=1", "-xzf", "/home/harness/magento-2.4.7-p10-rooted.tar.gz", "-C", root); err != nil {
		t.Fatalf("extract: %v: %s", err, output)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	name := "qg" + hex.EncodeToString(random[:8])
	password := hex.EncodeToString(random[8:]) + "Az!9"
	defer wipeLinuxApplicationBytes(random)
	sql := func(input string) ([]byte, error) {
		queryCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		command := exec.CommandContext(queryCtx, "/usr/bin/mariadb", "--protocol=socket", "--batch", "--skip-column-names")
		command.Stdin = strings.NewReader(input)
		output, err := command.CombinedOutput()
		return []byte(strings.ReplaceAll(string(output), password, "[REDACTED]")), err
	}
	t.Cleanup(func() {
		if _, err := sql("DROP DATABASE IF EXISTS " + name + "; DROP USER IF EXISTS '" + name + "'@'localhost';"); err != nil {
			t.Errorf("fixture database cleanup: %v", err)
		}
	})
	if output, err := sql("CREATE DATABASE " + name + " CHARACTER SET utf8mb4; CREATE USER '" + name + "'@'localhost' IDENTIFIED BY '" + password + "'; GRANT ALL ON " + name + ".* TO '" + name + "'@'localhost';"); err != nil {
		t.Fatalf("fixture database: %v: %s", err, output)
	}
	arguments := []string{"setup:install", "--base-url=https://magento.example.invalid/", "--base-url-secure=https://magento.example.invalid/", "--use-secure=1", "--use-secure-admin=1", "--db-host=localhost", "--db-name=" + name, "--db-user=" + name, "--db-password=" + password, "--admin-firstname=QEMU", "--admin-lastname=Administrator", "--admin-email=qemu@example.invalid", "--admin-user=qemuadmin", "--admin-password=" + password, "--language=en_US", "--currency=USD", "--timezone=UTC", "--use-rewrites=1", "--search-engine=opensearch", "--opensearch-host=127.0.0.1", "--opensearch-port=9200", "--opensearch-enable-auth=0", "--cleanup-database", "--no-interaction"}
	payload, err := json.Marshal(struct {
		Arguments []string `json:"arguments"`
	}{arguments})
	if err != nil {
		t.Fatal(err)
	}
	defer wipeLinuxApplicationBytes(payload)
	scope := linuxApplicationScope{root: root, binding: LinuxApplicationSiteBinding{UID: uint32(uid), GID: uint32(gid)}}
	bootstrap := filepath.Join(root, ".cyberpanel-bootstrap.php")
	input := filepath.Join(root, ".cyberpanel-bootstrap.json")
	if err := writeSiteBootstrapFile(bootstrap, []byte(certifiedApplicationArgumentBootstrap), scope); err != nil {
		t.Fatal(err)
	}
	defer wipeApplicationBootstrapFile(bootstrap)
	if err := writeSiteBootstrapFile(input, payload, scope); err != nil {
		t.Fatal(err)
	}
	defer wipeApplicationBootstrapFile(input)
	output, err := runAsSite("/usr/bin/php8.3", "-d", "memory_limit=1G", "-d", "auto_prepend_file="+bootstrap, "bin/magento")
	if err != nil {
		t.Fatalf("real installation: %v: %s", err, strings.ReplaceAll(string(output), password, "[REDACTED]"))
	}
	if _, err := os.Stat(filepath.Join(root, "app", "etc", "env.php")); err != nil {
		t.Fatal("installer did not create configuration")
	}
	if _, err := os.Stat(input); !os.IsNotExist(err) {
		t.Fatal("argument bootstrap input was not consumed")
	}
	output, err = sql("SELECT COUNT(*) FROM " + name + ".admin_user WHERE email='qemu@example.invalid' AND username='qemuadmin' AND is_active=1;")
	if err != nil || strings.TrimSpace(string(output)) != "1" {
		t.Fatalf("administrator not installed: %v: %s", err, output)
	}
}
