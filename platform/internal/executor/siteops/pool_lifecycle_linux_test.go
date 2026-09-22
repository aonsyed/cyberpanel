//go:build linux

package siteops

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/provisioning"
	"github.com/aonsyed/cyberpanel/platform/internal/rebootcontrol"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestQEMUPoolDependencyMigration(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_POOL_LIFECYCLE") != "1" {
		t.Skip("isolated QEMU systemd fixture")
	}
	ctx := context.Background()
	registry, q, lease := identityRetryFixture(t)
	binding := lease.Binding
	binding.State = BindingActive
	binding.RootGeneration = 1
	binding.PoolGeneration = 1
	binding.InstalledPools = []uint64{1}
	if err := registry.Complete(q, binding, strings.Repeat("a", 64), time.Now()); err != nil {
		t.Fatal(err)
	}
	spec := poolSpec(binding, q, EditionOpenLiteSpeed, "/usr/local/lsws/lsphp83/bin/lsphp")
	next, err := spec.RenderSystemdUnit()
	if err != nil {
		t.Fatal(err)
	}
	old := bytes.Replace(next, []byte("WantedBy=multi-user.target lsws.service"), []byte("WantedBy=multi-user.target"), 1)
	name := spec.UnitName()
	path := filepath.Join(SystemdUnitRootPath, name)
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("refuse existing fixture unit", err)
	}
	defer func() {
		exec.Command("/usr/bin/systemctl", "disable", "--now", name).Run()
		os.Remove(path)
		exec.Command("/usr/bin/systemctl", "daemon-reload").Run()
	}()
	if err = os.WriteFile(path, old, 0644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/systemctl", "enable", name).CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}
	fd, err := openDirectory(SystemdUnitRootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	host := &LinuxHost{unitFD: fd}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	repo, err := rebootcontrol.NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = rebootcontrol.NewAdmissionGate(ctx, db, "pool-test-boot", time.Now); err != nil {
		t.Fatal(err)
	}
	admission := &rebootcontrol.SQLExecutionAdmission{DB: db, BootID: "pool-test-boot"}
	for i := 0; i < 2; i++ {
		if err = host.ReconcilePoolDependencies(ctx, registry, admission); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, next) {
		t.Fatal("canonical unit not migrated", err)
	}
	if exec.Command("/usr/bin/systemctl", "is-active", "--quiet", name).Run() == nil {
		t.Fatal("migration started pool")
	}
	if err = os.WriteFile(path, old, 0644); err != nil {
		t.Fatal(err)
	}
	if err = host.ReconcilePoolDependencies(ctx, registry, admission); err == nil {
		t.Fatal("cached migration accepted reverted unit bytes")
	}
	if output, err := exec.Command("/usr/bin/systemctl", "disable", name).CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}
	if err = host.ReconcilePoolDependencies(ctx, registry, admission); err != nil {
		t.Fatal(err)
	}
	actual, _ = os.ReadFile(path)
	if !bytes.Equal(actual, old) {
		t.Fatal("disabled unit migrated")
	}
	if exec.Command("/usr/bin/systemctl", "is-enabled", "--quiet", name).Run() == nil {
		t.Fatal("disabled pool reenabled")
	}
	t.Log("real enabled legacy unit migrated under SQL admission; replay verified; no start; reverted bytes denied; disabled unit untouched")
}

func TestPoolFollowsEngineStart(t *testing.T) {
	key := "s-0123456789abcdef01234567"
	spec := LSAPISpec{Edition: EditionOpenLiteSpeed, SiteKey: key, Username: deriveUsername(key), UID: 20000, GID: 20000, Generation: 2, MaxConnections: 8, PHPBinary: "/usr/local/lsws/lsphp83/bin/lsphp", ProcessProfile: provisioning.DefaultSiteProcessResourceProfile(2, 8)}
	unit, err := spec.RenderSystemdUnit()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "WantedBy=multi-user.target lsws.service\n") {
		t.Fatal("enabled pool is not pulled back in by engine start")
	}
	binding := RuntimeBinding{SiteKey: key, Username: spec.Username, UID: spec.UID, GID: spec.GID, PoolGeneration: 2}
	old := bytes.Replace(unit, []byte("WantedBy=multi-user.target lsws.service"), []byte("WantedBy=multi-user.target"), 1)
	next, ok := poolDependencyUpgrade(binding, old)
	if !ok || !bytes.Equal(next, unit) {
		t.Fatal("legacy migration mismatch")
	}
	again, ok := poolDependencyUpgrade(binding, next)
	if !ok || !bytes.Equal(again, next) {
		t.Fatal("migration not idempotent")
	}
	if _, ok = poolDependencyUpgrade(binding, append(old, []byte("# custom\n")...)); ok {
		t.Fatal("custom unit migrated")
	}
	binding.PoolGeneration = 3
	if _, ok = poolDependencyUpgrade(binding, old); ok {
		t.Fatal("stale generation migrated")
	}
}

func TestPoolUnitTrust(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root metadata fixture")
	}
	directory := t.TempDir()
	fd, err := openDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	path := filepath.Join(directory, "pool.service")
	if err = os.WriteFile(path, []byte("unit"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readPoolUnit(fd, "pool.service"); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err = readPoolUnit(fd, "pool.service"); err == nil {
		t.Fatal("writable unit accepted")
	}
	if err = os.Symlink(path, filepath.Join(directory, "link.service")); err != nil {
		t.Fatal(err)
	}
	if _, err = readPoolUnit(fd, "link.service"); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestQEMUPoolEngineStopStart(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_POOL_LIFECYCLE") != "1" {
		t.Skip("isolated QEMU systemd fixture")
	}
	prefix := fmt.Sprintf("cyberpanel-pool-test-%d", os.Getpid())
	engine := prefix + ".service"
	alias := prefix + "-alias.service"
	pool := prefix + "-active.service"
	retired := prefix + "-retired.service"
	command := func(args ...string) {
		t.Helper()
		if output, err := exec.Command("/usr/bin/systemctl", args...).CombinedOutput(); err != nil {
			t.Fatalf("systemctl %v: %v %s", args, err, output)
		}
	}
	defer func() {
		exec.Command("/usr/bin/systemctl", "disable", "--now", pool, retired, engine).Run()
		for _, name := range []string{engine, alias, pool, retired} {
			os.Remove(filepath.Join("/run/systemd/system", name))
		}
		exec.Command("/usr/bin/systemctl", "daemon-reload").Run()
	}()
	key := "s-0123456789abcdef01234567"
	spec := LSAPISpec{Edition: EditionOpenLiteSpeed, SiteKey: key, Username: deriveUsername(key), UID: 20000, GID: 20000, Generation: 2, MaxConnections: 8, PHPBinary: "/usr/local/lsws/lsphp83/bin/lsphp", ProcessProfile: provisioning.DefaultSiteProcessResourceProfile(2, 8)}
	rendered, err := spec.RenderSystemdUnit()
	if err != nil {
		t.Fatal(err)
	}
	unitPart, _, _ := strings.Cut(string(rendered), "[Service]")
	_, installPart, _ := strings.Cut(string(rendered), "[Install]")
	fixture := strings.ReplaceAll(unitPart+"[Service]\nExecStart=/usr/bin/sleep infinity\n[Install]"+installPart, "lsws.service", alias)
	fixture = strings.ReplaceAll(fixture, "multi-user.target ", "")
	for name, body := range map[string]string{engine: "[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n", pool: fixture, retired: fixture} {
		if err = os.WriteFile(filepath.Join("/run/systemd/system", name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Symlink(engine, filepath.Join("/run/systemd/system", alias)); err != nil {
		t.Fatal(err)
	}
	command("daemon-reload")
	command("enable", pool)
	command("enable", retired)
	command("disable", retired)
	active := func(name string) bool {
		return exec.Command("/usr/bin/systemctl", "is-active", "--quiet", name).Run() == nil
	}
	assertState := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for active(pool) != want && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if active(pool) != want || active(retired) {
			t.Fatal("engine lifecycle failed or revived disabled pool")
		}
	}
	command("start", engine)
	assertState(true)
	command("stop", engine)
	assertState(false)
	command("start", engine)
	assertState(true)
	t.Log("generated dependency restores enabled pool across stop/start; disabled pool stays stopped")
}
