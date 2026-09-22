//go:build linux

package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupFingerprintDetectsSameSizePreservedTimestampWrite(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "data")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := linuxBackupTreeFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := linuxBackupTreeFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("persistent file write hidden by unchanged size and mtime")
	}
}

func TestNativeBackupFingerprintDetectsScopedSQLWrite(t *testing.T) {
	if os.Getenv("CYBERPANEL_NATIVE_BACKUP_TEST") != "1" {
		t.Skip("requires QEMU MariaDB")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root QEMU fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id := fmt.Sprintf("backup_write_%d", time.Now().UnixNano())
	registry := filepath.Join(linuxBackupDatabaseStateRoot, id+".json")
	run := func(sql string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "/usr/bin/mariadb", "--protocol=socket", "--user=root", "--execute="+sql).CombinedOutput(); err != nil {
			t.Fatalf("fixture: %v: %s", err, out)
		}
	}
	if _, err := os.Lstat(registry); !os.IsNotExist(err) {
		t.Fatal("fixture registry already exists")
	}
	run("CREATE DATABASE `" + id + "`; CREATE TABLE `" + id + "`.probe (id INT PRIMARY KEY, value TEXT) ENGINE=Aria; INSERT INTO `" + id + "`.probe VALUES(1,'before')")
	t.Cleanup(func() {
		if out, err := exec.Command("/usr/bin/mariadb", "--protocol=socket", "--user=root", "--execute=DROP DATABASE `"+id+"`").CombinedOutput(); err != nil {
			t.Errorf("cleanup: %v: %s", err, out)
		}
		if err := os.Remove(registry); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(registry, []byte(fmt.Sprintf(`{"id":%q,"tenant_id":%q,"site_id":%q,"generation":1,"name":%q}`, id, id, id, id)), 0600); err != nil {
		t.Fatal(err)
	}
	host := &LinuxBackupHost{}
	plan := RestorePlanSpec{TenantID: id, ComponentMapping: map[ComponentKind]string{ComponentDatabase: id}}
	binding := LinuxBackupSiteBinding{TenantID: id, SiteID: id}
	before, err := host.targetFingerprint(ctx, plan, binding)
	if err != nil {
		t.Fatal(err)
	}
	run("UPDATE `" + id + "`.probe SET value='after!' WHERE id=1")
	after, err := host.targetFingerprint(ctx, plan, binding)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("persistent scoped SQL write was not observed")
	}
	stable, err := host.targetFingerprint(ctx, plan, binding)
	if err != nil || stable != after {
		t.Fatalf("unchanged database observation unstable: %v", err)
	}
	for _, engine := range []string{"InnoDB", "MyISAM"} {
		run("ALTER TABLE `" + id + "`.probe ENGINE=" + engine)
		before, err = host.targetFingerprint(ctx, plan, binding)
		if err != nil {
			t.Fatal(err)
		}
		run("UPDATE `" + id + "`.probe SET value=CONCAT(value,'x') WHERE id=1")
		after, err = host.targetFingerprint(ctx, plan, binding)
		if err != nil || before == after {
			t.Fatalf("%s write not observed: %v", engine, err)
		}
	}
	other := LinuxBackupSiteBinding{TenantID: id + "_other", SiteID: id + "_other"}
	unrelatedBefore, err := host.targetFingerprint(ctx, plan, other)
	if err != nil {
		t.Fatal(err)
	}
	run("UPDATE `" + id + "`.probe SET value='changed again' WHERE id=1")
	unrelatedAfter, err := host.targetFingerprint(ctx, plan, other)
	if err != nil || unrelatedBefore != unrelatedAfter {
		t.Fatalf("unrelated site affected by global writes: %v", err)
	}
}

func TestNativeBackupObserveWritesDoesNotTrustFrozenFlag(t *testing.T) {
	if os.Getenv("CYBERPANEL_NATIVE_BACKUP_TEST") != "1" {
		t.Skip("requires QEMU root filesystem fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root QEMU fixture")
	}
	id := fmt.Sprintf("backup_frozen_%d", time.Now().UnixNano())
	binding := LinuxBackupSiteBinding{SiteKey: id, TenantID: id, SiteID: id, Generation: 1, UID: 62001, GID: 62001}
	host := &LinuxBackupHost{Root: t.TempDir(), Resolver: LinuxBackupSiteResolverFunc(func(context.Context, string, string) (LinuxBackupSiteBinding, error) { return binding, nil })}
	siteRoot := filepath.Join("/var/lib/cyberpanel/sites", id)
	if _, err := os.Lstat(siteRoot); !os.IsNotExist(err) {
		t.Fatal("fixture site exists")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(siteRoot); err != nil {
			t.Error(err)
		}
	})
	root := host.generationRoot(binding)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "data")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := RestorePlanSpec{ID: RestoreID(id), TenantID: id, TargetScope: id, ComponentMapping: map[ComponentKind]string{ComponentFiles: id}}
	baseline, err := host.targetFingerprint(context.Background(), plan, binding)
	if err != nil {
		t.Fatal(err)
	}
	state := linuxRestoreState{PlanID: plan.ID, TenantID: id, TargetScope: id, Frozen: true, TargetGeneration: "target", PreviousGeneration: "previous", Fingerprint: baseline, Watermark: 1}
	if err = writeLinuxBackupJSON(filepath.Join(host.restoreRoot(plan), "state.json"), state); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	watermark, firstWrite, err := host.ObserveWrites(context.Background(), plan, "target", "observe")
	if err != nil {
		t.Fatal(err)
	}
	if watermark != 2 || firstWrite == nil {
		t.Fatal("frozen boolean concealed actual persistent writes")
	}
	if err = os.WriteFile(path, []byte("later!"), 0600); err != nil {
		t.Fatal(err)
	}
	watermark, laterWrite, err := host.ObserveWrites(context.Background(), plan, "target", "observe-again")
	if err != nil || watermark != 3 || laterWrite == nil || !laterWrite.Equal(*firstWrite) {
		t.Fatalf("first write frontier changed on later mutation: watermark=%d err=%v", watermark, err)
	}
	state.Fingerprint = ""
	if err = writeLinuxBackupJSON(filepath.Join(host.restoreRoot(plan), "state.json"), state); err != nil {
		t.Fatal(err)
	}
	if _, _, err = host.ObserveWrites(context.Background(), plan, "target", "missing-baseline"); !errors.Is(err, ErrBackupAmbiguous) {
		t.Fatalf("missing baseline must fail closed, got %v", err)
	}
}
