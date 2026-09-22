//go:build linux

package providers

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/backup"
)

// This adapter connects the coordinator's reader callback to the same stream
// entry point used by the privileged broker; no capture/restore effect is mocked.
type nativeRestoreTarget struct{ *backup.LinuxBackupHost }

func (target nativeRestoreTarget) StageArtifact(ctx context.Context, plan backup.RestorePlanSpec, scratch string, artifact backup.ArtifactManifest, open func(context.Context, backup.ObjectDescriptor) (backup.ReadObject, error), effect string) (string, error) {
	var readers []io.Reader
	for _, descriptor := range artifact.Objects {
		object, err := open(ctx, descriptor)
		if err != nil {
			return "", err
		}
		defer object.Reader.Close()
		readers = append(readers, object.Reader)
	}
	return target.StageArtifactStream(ctx, plan, scratch, artifact, io.MultiReader(readers...), effect)
}

// Run only on a disposable native host: promotion briefly stops lsws, and the
// fixture uses the real site registry paths, MariaDB socket and local repository.
func TestNativeLocalBackupRestore(t *testing.T) {
	if os.Getenv("CYBERPANEL_NATIVE_BACKUP_TEST") != "1" {
		t.Skip("requires disposable native Linux host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native backup test requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	webWasActive := exec.Command("/usr/bin/systemctl", "is-active", "--quiet", "lsws.service").Run() == nil
	t.Cleanup(func() {
		if webWasActive {
			if output, err := exec.Command("/usr/bin/systemctl", "start", "lsws.service").CombinedOutput(); err != nil {
				t.Errorf("restore web service: %v: %s", err, output)
			}
		}
	})
	id := fmt.Sprintf("backup_probe_%d", time.Now().UnixNano())
	dbname := id
	siteRoot := filepath.Join("/var/lib/cyberpanel/sites", id)
	generation := filepath.Join(siteRoot, "roots/g1")
	release := filepath.Join(generation, "releases/original")
	runtimeRoot := filepath.Join(backup.LinuxBackupRuntimeRoot, id)
	repoRoot := filepath.Join(DefaultLocalRepositoryRoot, id)
	registry := filepath.Join("/var/lib/cyberpanel/database/databases", id+".json")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	mkdir := func(path string, mode os.FileMode) {
		t.Helper()
		must(os.MkdirAll(path, mode))
		must(os.Chmod(path, mode))
	}
	write := func(path, value string, mode os.FileMode) { t.Helper(); must(os.WriteFile(path, []byte(value), mode)) }
	sqlCommand := func(statement string) string {
		t.Helper()
		command := exec.CommandContext(ctx, "/usr/bin/mariadb", "--protocol=socket", "--socket=/run/mysqld/mysqld.sock", "--user=root", "--batch", "--skip-column-names", "--execute="+statement)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("MariaDB fixture: %v: %s", err, output)
		}
		return strings.TrimSpace(string(output))
	}
	for _, path := range []string{siteRoot, runtimeRoot, repoRoot, registry} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("fixture path already exists: %s", path)
		}
	}
	t.Cleanup(func() {
		command := exec.Command("/usr/bin/mariadb", "--protocol=socket", "--socket=/run/mysqld/mysqld.sock", "--user=root", "--execute=DROP DATABASE IF EXISTS `"+dbname+"`")
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("cleanup database: %v: %s", err, output)
		}
		for _, path := range []string{siteRoot, runtimeRoot, repoRoot} {
			if err := os.RemoveAll(path); err != nil {
				t.Error(err)
			}
		}
		if err := os.Remove(registry); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
	})
	for _, path := range []string{siteRoot, filepath.Join(siteRoot, "roots"), generation, filepath.Join(generation, "releases")} {
		mkdir(path, 0711)
	}
	mkdir(release, 0750)
	mkdir(filepath.Join(generation, "private"), 0700)
	write(filepath.Join(release, "index.txt"), "restored site bytes\n", 0640)
	write(filepath.Join(generation, "private/secret.txt"), "private fixture bytes\n", 0600)
	must(os.Symlink("original", filepath.Join(generation, "releases/current")))
	const uid = 62001
	for _, path := range []string{release, filepath.Join(release, "index.txt"), filepath.Join(generation, "private"), filepath.Join(generation, "private/secret.txt")} {
		must(os.Chown(path, uid, uid))
	}
	mkdir(runtimeRoot, 0700)
	for _, sub := range []string{"effects", "restores", "watermarks"} {
		mkdir(filepath.Join(runtimeRoot, sub), 0700)
	}
	mkdir(repoRoot, 0750)
	for _, sub := range []string{".staging", "blobs", "points"} {
		mkdir(filepath.Join(repoRoot, sub), 0700)
	}
	must(os.MkdirAll(filepath.Dir(registry), 0700))
	write(registry, fmt.Sprintf(`{"id":%q,"tenant_id":%q,"site_id":%q,"generation":1,"name":%q}`, id, id, id, dbname), 0600)
	sqlCommand("CREATE DATABASE `" + dbname + "`; CREATE TABLE `" + dbname + "`.probe (id INT PRIMARY KEY, value TEXT, bytes BLOB); INSERT INTO `" + dbname + "`.probe VALUES (1,'original Ω',0x0001ff),(2,NULL,NULL)")
	binding := backup.LinuxBackupSiteBinding{SiteKey: id, TenantID: id, SiteID: id, UID: uid, GID: uid, Generation: 1}
	host := &backup.LinuxBackupHost{Root: runtimeRoot, Resolver: backup.LinuxBackupSiteResolverFunc(func(_ context.Context, tenant, scope string) (backup.LinuxBackupSiteBinding, error) {
		if scope != id || tenant != "" && tenant != id {
			return backup.LinuxBackupSiteBinding{}, backup.ErrInvalidBackup
		}
		return binding, nil
	})}
	repository, err := OpenLocalRepository(backup.RepositoryID(id), repoRoot)
	must(err)
	defer repository.Close()
	provider := &LocalProvider{Repositories: map[backup.RepositoryID]*LocalRepository{backup.RepositoryID(id): repository}, Source: host}
	handle, err := sql.Open("sqlite", filepath.Join(runtimeRoot, "catalog.db"))
	must(err)
	defer handle.Close()
	runtime := NewRuntime(handle, ProviderSet{Local: provider})
	must(runtime.Bootstrap(ctx))
	spec := backup.RepositorySpec{Repository: backup.Repository{ID: backup.RepositoryID(id), Kind: backup.Local, Endpoint: "file://" + repoRoot, CredentialRef: "fixture-local"}, TenantID: id, FailureDomain: "local", EncryptionDomain: "plaintext-local-current-implementation", MaximumConcurrency: 1}
	must(runtime.Catalog.PutRepository(ctx, spec))
	policy := backup.BackupPolicySpec{ID: backup.PolicyID(id), TenantID: id, Scope: id, Schedule: "manual", Components: []backup.ComponentKind{backup.ComponentFiles, backup.ComponentDatabase}, Repositories: []backup.RepositoryID{spec.Repository.ID}, RequiredCopies: 1, Consistency: backup.ConsistencyFuzzy, Retention: backup.RetentionPolicy{KeepLast: 1, MinimumVerifiedCopies: 1}, Generation: 1}
	run, err := runtime.BackupCoordinator(host, host).Run(ctx, id, id, policy, []backup.RepositorySpec{spec})
	must(err)
	if run.Status != backup.RunRestorable {
		t.Fatalf("backup status: %s", run.Status)
	}
	t.Logf("native files+MariaDB capture committed: %s", run.RecoveryPointID)
	// Remove captured content rather than merely comparing the still-live source.
	must(os.Remove(filepath.Join(release, "index.txt")))
	must(os.Remove(filepath.Join(generation, "private/secret.txt")))
	sqlCommand("DROP TABLE `" + dbname + "`.probe")
	plan := backup.RestorePlanSpec{ID: backup.RestoreID(id), IdempotencyKey: id, TenantID: id, RecoveryPointID: run.RecoveryPointID, SourceScope: id, TargetScope: id, ComponentMapping: map[backup.ComponentKind]string{backup.ComponentFiles: id, backup.ComponentDatabase: id}, CollisionPolicy: backup.CollisionReplaceBlueGreen, SecretPolicy: backup.SecretResetRequired, RequiredFreeBytes: 1 << 20, Generation: 1}
	coordinator := backup.RestoreCoordinator{Store: runtime.Restores, Capacity: host, Source: runtime.RestoreSource(), Scanner: backup.IntegrityRestoreScanner{}, Target: nativeRestoreTarget{host}, Safety: host}
	receipt, err := coordinator.Execute(ctx, plan)
	must(err)
	if receipt.Phase != backup.RestoreActive {
		t.Fatalf("restore phase: %s", receipt.Phase)
	}
	for path, expected := range map[string]string{filepath.Join(generation, "releases/current/index.txt"): "restored site bytes\n", filepath.Join(generation, "private/secret.txt"): "private fixture bytes\n"} {
		command := exec.CommandContext(ctx, "/usr/bin/cat", path)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		output, err := command.CombinedOutput()
		if err != nil || string(output) != expected {
			t.Errorf("site UID cannot read exact restored content: %s: %v: %q", path, err, output)
		}
	}
	rows := sqlCommand("SELECT id,IFNULL(value,'<NULL>'),IFNULL(HEX(bytes),'<NULL>') FROM `" + dbname + "`.probe ORDER BY id")
	if rows != "1\toriginal Ω\t0001FF\n2\t<NULL>\t<NULL>" {
		t.Errorf("restored database mismatch: %q", rows)
	}
	t.Log("restored native SQL text/NULL/BLOB rows and site/private bytes checked")
	object := run.Manifest.Artifacts[0].Objects[0]
	blob := filepath.Join(repoRoot, objectPath(object))
	file, err := os.OpenFile(blob, os.O_WRONLY, 0)
	must(err)
	_, err = file.WriteAt([]byte{0xff}, 0)
	must(err)
	must(file.Close())
	badPlan := plan
	badPlan.ID += "-corrupt"
	badPlan.IdempotencyKey += "-corrupt"
	badReceipt, err := coordinator.Execute(ctx, badPlan)
	if err == nil || badReceipt.Phase != backup.RestoreFailed || badReceipt.ScratchID != "" {
		t.Fatalf("corrupt committed object not rejected before staging: %+v %v", badReceipt, err)
	}
	t.Log("corrupt committed object rejected before staging/promotion")
}
