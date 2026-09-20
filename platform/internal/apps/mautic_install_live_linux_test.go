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

// This exercises real Mautic and MariaDB through the production argument
// bootstrap. It deliberately does not claim an installed LSPHP/OLS lifecycle.
func TestQEMURealMauticInstallation(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_INSTALL_MAUTIC") != "1" {
		t.Skip("QEMU real archive, PHP and MariaDB required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("run fixture as root inside QEMU")
	}
	if digest, err := digestLinuxApplicationFile("/home/harness/mautic-7.2.0-rooted.tar.gz", 128<<20); err != nil || digest != "a4be4794815496fa3ce15ea4b79474b98296d209bb5ce3d32d2f7a819d6134db" {
		t.Fatal("Mautic fixture does not match the verified prepared archive")
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
	root, err := os.MkdirTemp("/home/harness", "qemu-mautic-install-")
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	runAsSite := func(binary string, args ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, binary, args...)
		command.Dir = root
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "TMPDIR=" + root, "LANG=C.UTF-8"}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		return command.CombinedOutput()
	}
	if output, err := runAsSite("/usr/bin/tar", "--no-same-owner", "--no-same-permissions", "--strip-components=1", "-xzf", "/home/harness/mautic-7.2.0-rooted.tar.gz", "-C", root); err != nil {
		t.Fatalf("extract: %v: %s", err, output)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	name := "qm" + hex.EncodeToString(random[:8])
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
	arguments := []string{"mautic:install", "https://mautic.example.invalid", "--db_driver=pdo_mysql", "--db_host=localhost", "--db_port=3306", "--db_name=" + name, "--db_user=" + name, "--db_password=" + password, "--db_backup_tables=false", "--admin_firstname=QEMU", "--admin_lastname=Administrator", "--admin_username=qemuadmin", "--admin_email=qemu@example.invalid", "--admin_password=" + password, "--force", "--no-interaction"}
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
	output, err := runAsSite("/usr/bin/php8.3", "-d", "auto_prepend_file="+bootstrap, "bin/console")
	if err != nil {
		t.Fatalf("real installation: %v: %s", err, strings.ReplaceAll(string(output), password, "[REDACTED]"))
	}
	if _, err := os.Stat(filepath.Join(root, "config", "local.php")); err != nil {
		t.Fatal("installer did not create configuration")
	}
	if _, err := os.Stat(input); !os.IsNotExist(err) {
		t.Fatal("argument bootstrap input was not consumed")
	}
	output, err = sql("SELECT COUNT(*) FROM " + name + ".users WHERE username='qemuadmin';")
	if err != nil || strings.TrimSpace(string(output)) != "1" {
		t.Fatalf("administrator not installed: %v: %s", err, output)
	}
}
