//go:build linux

package access

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestQEMULocalGitDeploymentRollback(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_GIT") != "1" {
		t.Skip("isolated QEMU native Git fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("QEMU root required")
	}
	site, err := os.MkdirTemp(LinuxAccessSitesRoot, "s-git-qa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(site); err != nil {
			t.Error(err)
		}
	})
	root := filepath.Join(site, "roots/g1/releases/current")
	for _, path := range []string{filepath.Join(root, "public"), filepath.Join(site, "roots/g1/tmp")} {
		if err := os.MkdirAll(path, 0750); err != nil {
			t.Fatal(err)
		}
	}
	if err := filepath.Walk(site, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, 1000, 1000)
	}); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, "private-sentinel")
	if err := os.WriteFile(private, []byte("private untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	binding := LinuxSiteBinding{SiteKey: filepath.Base(site), Username: "harness", UID: 1000, GID: 1000, Generation: 1}
	executor := &LinuxGitExecutor{Files: &LinuxFileExecutor{Resolver: LinuxSiteResolverFunc(func(context.Context, SiteID) (LinuxSiteBinding, error) { return binding, nil })}}
	path, _ := ParseRelativePath("public/repo")
	repository := GitRepository{ID: "git-qa", SiteID: "site-qa", Provider: GitGeneric, Worktree: FileLocator{Root: SiteRoot{SiteID: "site-qa", Kind: RootSite}, Path: path}, Branch: "main", Strategy: GitHardDeploy, Generation: 1}
	ctx := context.Background()
	if _, err := executor.Initialize(ctx, repository); err != nil {
		t.Fatalf("initialize local repository: %v", err)
	}
	repo := filepath.Join(root, "public/repo")
	entry, _ := ParseRelativePath("index.txt")
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, "index.txt"), []byte(value), 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(filepath.Join(repo, "index.txt"), 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(value string) string {
		t.Helper()
		write(value)
		result, err := executor.Commit(ctx, repository, GitChangeSet{Paths: []RelativePath{entry}, Message: value, AuthorName: "QEMU", AuthorEmail: "qemu@example.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		return result.Revision
	}
	first := commit("first")
	if _, err := runGit(ctx, repo, nil, "branch", "previous", first); err != nil {
		t.Fatal(err)
	}
	second := commit("second")
	if _, err := executor.Checkout(ctx, repository, "previous", false); err != nil {
		t.Fatalf("checkout previous branch: %v", err)
	}
	untracked := filepath.Join(repo, "local-private.txt")
	if err := os.WriteFile(untracked, []byte("untracked retained"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(untracked, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	deployment := Deployment{ID: "deploy-qa", RepositoryID: repository.ID, SiteID: repository.SiteID, Trigger: TriggerManual, RequestedRevision: second, State: DeploymentQueued, Generation: 1, RequestedAt: time.Now().UTC()}
	prepared, err := executor.PrepareDeployment(ctx, repository, deployment)
	if err != nil {
		t.Fatal(err)
	}
	deployment.WorkspaceToken, deployment.ResolvedRevision, deployment.PreviousRelease = prepared.WorkspaceToken, prepared.ResolvedRevision, prepared.PreviousRelease
	foreign := deployment
	foreign.WorkspaceToken += "-unrelated"
	if _, err := executor.PromoteDeployment(ctx, repository, foreign); err == nil {
		t.Fatal("unrelated deployment token accepted")
	}
	if _, err := executor.PromoteDeployment(ctx, repository, deployment); err != nil {
		t.Fatal(err)
	}
	health, err := executor.VerifyDeployment(ctx, repository, deployment)
	if err != nil || !health.Healthy {
		t.Fatalf("promoted revision not verified: %+v %v", health, err)
	}
	if value, err := os.ReadFile(filepath.Join(repo, "index.txt")); err != nil || string(value) != "second" {
		t.Fatal("target bytes not deployed")
	}
	write("failed deployed content")
	health, err = executor.VerifyDeployment(ctx, repository, deployment)
	if err != nil {
		t.Fatal(err)
	}
	if health.Healthy {
		t.Fatal("changed tracked deployment passed health")
	}
	if _, err := executor.RollbackDeployment(ctx, repository, deployment); err != nil {
		t.Fatal(err)
	}
	status, err := executor.Status(ctx, repository)
	if err != nil || status.HeadRevision != first {
		t.Fatalf("rollback revision: %+v %v", status, err)
	}
	if value, err := os.ReadFile(filepath.Join(repo, "index.txt")); err != nil || string(value) != "first" {
		t.Fatal("rollback did not restore original bytes")
	}
	if value, err := os.ReadFile(private); err != nil || string(value) != "private untouched" {
		t.Fatal("private sibling changed")
	}
	if value, err := os.ReadFile(untracked); err != nil || string(value) != "untracked retained" {
		t.Fatal("untracked private file changed")
	}
	if err := filepath.Walk(repo, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != 1000 || stat.Gid != 1000 {
			t.Errorf("foreign owned Git path: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := executor.DiscardDeployment(ctx, repository, deployment); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(deployment.WorkspaceToken); !os.IsNotExist(err) {
		t.Fatal("deployment workspace remains")
	}
	// Drive the actual service recovery transitions, with only persistence and
	// a post-promotion failure trigger supplied by this isolated fixture.
	repository.State = StateActive
	queued := Deployment{ID: "deploy-service-qa", RepositoryID: repository.ID, SiteID: repository.SiteID, Trigger: TriggerManual, RequestedRevision: second, State: DeploymentQueued, Generation: 1, RequestedAt: time.Now().UTC()}
	store := &gitDeploymentFixtureStore{repository: repository, deployment: queued}
	service := GitService{Store: store, Executor: gitDeploymentFailHealth{GitExecutor: executor, path: filepath.Join(repo, "index.txt")}}
	rolledBack, err := service.ExecuteDeployment(ctx, queued.ID)
	if err == nil || rolledBack.State != DeploymentRolledBack || store.deployment.State != DeploymentRolledBack {
		t.Fatalf("service failure recovery: %s %v", rolledBack.State, err)
	}
	status, err = executor.Status(ctx, repository)
	if err != nil || status.HeadRevision != first {
		t.Fatal("service rollback did not restore prior HEAD")
	}
	if value, err := os.ReadFile(filepath.Join(repo, "index.txt")); err != nil || string(value) != "first" {
		t.Fatal("service rollback did not restore bytes")
	}
	if _, err := os.Stat(rolledBack.WorkspaceToken); !os.IsNotExist(err) {
		t.Fatal("service rollback retained workspace")
	}
	if err := os.Chown(repo, 1001, 1001); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Status(ctx, repository); err == nil {
		t.Fatal("foreign-owned repository accepted")
	}
	if err := os.Chown(repo, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	credentialDir, err := os.MkdirTemp("/run/cyberpanel", "git-credential-qa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(credentialDir) })
	credentialPath := filepath.Join(credentialDir, "identity")
	if err := os.WriteFile(credentialPath, []byte("non-secret test input"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := executor.ownGitCredential(ctx, repository.SiteID, credentialDir, credentialPath); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []uint32{1000, 1001} {
		command := exec.Command("/usr/bin/test", "-r", credentialPath)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		err := command.Run()
		if (err == nil) != (uid == 1000) {
			t.Fatalf("credential access isolation uid %d", uid)
		}
	}
	for _, path := range []string{credentialDir, credentialPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if path == credentialDir {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatal("credential mode widened")
		}
	}
	t.Logf("real Git target=%s rollback=%s; owned bytes restored; private sibling retained; workspace removed", second, first)
}

type gitDeploymentFixtureStore struct {
	GitStore
	repository GitRepository
	deployment Deployment
}

func (store *gitDeploymentFixtureStore) LoadRepository(context.Context, GitRepositoryID) (GitRepository, error) {
	return store.repository, nil
}
func (store *gitDeploymentFixtureStore) LoadDeployment(context.Context, DeploymentID) (Deployment, error) {
	return store.deployment, nil
}
func (store *gitDeploymentFixtureStore) AdvanceDeployment(_ context.Context, value Deployment, expected uint64) error {
	if store.deployment.Generation != expected {
		return ErrStaleGeneration
	}
	store.deployment = value
	return nil
}

type gitDeploymentFailHealth struct {
	GitExecutor
	path string
}

func (executor gitDeploymentFailHealth) VerifyDeployment(ctx context.Context, r GitRepository, d Deployment) (DeploymentHealth, error) {
	if err := os.WriteFile(executor.path, []byte("post-promotion failure"), 0640); err != nil {
		return DeploymentHealth{}, err
	}
	return executor.GitExecutor.VerifyDeployment(ctx, r, d)
}
