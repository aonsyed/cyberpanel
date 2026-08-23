package fsstore

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/native"
)

var _ activation.Store = (*Store)(nil)

func TestStageWritesPrivateGenerationForEachEdition(t *testing.T) {
	for _, edition := range []webengine.Edition{webengine.EditionOpenLiteSpeed, webengine.EditionLiteSpeedEnterprise} {
		t.Run(string(edition), func(t *testing.T) {
			root := privateRoot(t)
			store, err := New(root, edition)
			if err != nil {
				t.Fatal(err)
			}
			generation := testGeneration(t, edition, 42, "master", "vhost")
			receipt, err := store.Stage(context.Background(), generation)
			if err != nil {
				t.Fatal(err)
			}
			if want := (activation.Receipt{Edition: edition, Digest: generation.ContentDigest}); receipt != want {
				t.Fatalf("receipt = %#v, want %#v", receipt, want)
			}
			master, vhost := "httpd_config.conf", "vhost.conf"
			if edition == webengine.EditionLiteSpeedEnterprise {
				master, vhost = "httpd_config.xml", "vhconf.xml"
			}
			base := filepath.Join(root, ".panel-generations", "g42", generation.ContentDigest)
			assertPrivateFile(t, filepath.Join(base, master), "master")
			vhostBase := filepath.Join(root, "vhosts", ".panel-generations", "g42", "site-a")
			assertPrivateFile(t, filepath.Join(vhostBase, vhost), "vhost")
			assertPrivateDir(t, vhostBase)
		})
	}
}

func TestStageRecomputesGenerationDigestBeforeWriting(t *testing.T) {
	root := privateRoot(t)
	store, err := New(root, webengine.EditionOpenLiteSpeed)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*native.ConfigGeneration){
		func(g *native.ConfigGeneration) { g.Artifacts[0].Content = []byte("tampered") },
		func(g *native.ConfigGeneration) { g.Artifacts[0].Mode = 0o644 },
	} {
		generation := testGeneration(t, webengine.EditionOpenLiteSpeed, 42, "master", "vhost")
		mutate(&generation)
		if _, err := store.Stage(context.Background(), generation); err == nil {
			t.Fatal("Stage accepted tampered generation")
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, ".panel-generations"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Stage wrote artifacts for invalid input: %v", entries)
	}
}

func TestNewRejectsUnsafeRootsAndEdition(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root, webengine.EditionOpenLiteSpeed); err == nil {
		t.Fatal("New accepted non-private root")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link, webengine.EditionOpenLiteSpeed); err == nil {
		t.Fatal("New accepted symlink root")
	}
	if err := os.Symlink(root, filepath.Join(root, "httpd_config.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root, webengine.EditionOpenLiteSpeed); err == nil {
		t.Fatal("New accepted symlink master")
	}
	if _, err := New(privateRoot(t), webengine.Edition("unsafe")); err == nil {
		t.Fatal("New accepted unsafe edition")
	}
}

func TestSwapConfirmAndReopenPersistAppliedMaster(t *testing.T) {
	root := privateRoot(t)
	store, err := New(root, webengine.EditionOpenLiteSpeed)
	if err != nil {
		t.Fatal(err)
	}
	generation := testGeneration(t, webengine.EditionOpenLiteSpeed, 42, "master", "vhost")
	receipt, err := store.Stage(context.Background(), generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SwapMaster(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.SwapMaster(context.Background(), activation.Receipt{Edition: receipt.Edition, Digest: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("SwapMaster accepted arbitrary receipt")
	}
	reopened, err := New(root, webengine.EditionOpenLiteSpeed)
	if err != nil {
		t.Fatal(err)
	}
	current, err := reopened.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := activation.Receipt{Edition: receipt.Edition, Digest: receipt.Digest, Status: activation.Applied, Confirmed: true}
	if !reflect.DeepEqual(current, want) {
		t.Fatalf("Current = %#v, want %#v", current, want)
	}
	assertPrivateFile(t, filepath.Join(root, "httpd_config.conf"), "master")
}

func TestRestoreMasterPreservesPreviousAndIgnoresCrashResidue(t *testing.T) {
	root := privateRoot(t)
	store, err := New(root, webengine.EditionOpenLiteSpeed)
	if err != nil {
		t.Fatal(err)
	}
	previous := testGeneration(t, webengine.EditionOpenLiteSpeed, 41, "old-master", "old-vhost")
	previousReceipt, err := store.Stage(context.Background(), previous)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SwapMaster(context.Background(), previousReceipt); err != nil {
		t.Fatal(err)
	}
	candidate := testGeneration(t, webengine.EditionOpenLiteSpeed, 42, "new-master", "new-vhost")
	candidateReceipt, err := store.Stage(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SwapMaster(context.Background(), candidateReceipt); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".panel-state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".panel-state", ".crash-residue"), []byte("new-master"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreMaster(context.Background(), previousReceipt); err != nil {
		t.Fatal(err)
	}
	assertPrivateFile(t, filepath.Join(root, "httpd_config.conf"), "old-master")
	if err := store.Confirm(context.Background(), previousReceipt); err != nil {
		t.Fatal(err)
	}
	assertPrivateFile(t, filepath.Join(root, "httpd_config.conf"), "old-master")
}

func testGeneration(t *testing.T, edition webengine.Edition, snapshot uint64, master, vhost string) native.ConfigGeneration {
	t.Helper()
	generation, err := native.NewCompleteGeneration(edition, strings.Repeat("d", 64), snapshot, []native.Artifact{
		{Role: native.ArtifactServer, Key: "engine", Mode: 0o600, Content: []byte(master)},
		{Role: native.ArtifactVirtualHost, Key: "site-a", Mode: 0o600, Content: []byte(vhost)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func privateRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func assertPrivateFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode = %o, want 0600", path, info.Mode().Perm())
	}
}

func assertPrivateDir(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("%s mode = %o, want directory 0700", path, info.Mode().Perm())
	}
}
