package fsstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aonsyed/cyberpanel/platform/internal/webengine"
	"github.com/aonsyed/cyberpanel/platform/internal/webengine/activation"
)

func TestCurrentRejectsDriftFromTheSealedGeneration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, root string, generationDigest string)
	}{
		{
			name: "tampered live master",
			mutate: func(t *testing.T, root, _ string) {
				t.Helper()
				writePrivateFile(t, filepath.Join(root, "httpd_config.conf"), "tampered-master")
			},
		},
		{
			name: "missing staged vhost",
			mutate: func(t *testing.T, root, _ string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "vhosts", ".panel-generations", "g42", "site-a", "vhost.conf")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "tampered staged vhost",
			mutate: func(t *testing.T, root, _ string) {
				t.Helper()
				writePrivateFile(t, filepath.Join(root, "vhosts", ".panel-generations", "g42", "site-a", "vhost.conf"), "tampered-vhost")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, store, generation := confirmedStore(t)
			test.mutate(t, root, generation.ContentDigest)

			if receipt, err := store.Current(context.Background()); err == nil {
				t.Fatalf("Current() = %#v, nil; want sealed-generation drift error", receipt)
			}
		})
	}
}

func TestActivationMethodsRejectUnsafeOrEvidenceBearingReceipts(t *testing.T) {
	operations := []struct {
		name string
		call func(*Store, activation.Receipt) error
	}{
		{name: "swap", call: func(store *Store, receipt activation.Receipt) error {
			return store.SwapMaster(context.Background(), receipt)
		}},
		{name: "confirm", call: func(store *Store, receipt activation.Receipt) error {
			return store.Confirm(context.Background(), receipt)
		}},
		{name: "restore", call: func(store *Store, receipt activation.Receipt) error {
			return store.RestoreMaster(context.Background(), receipt)
		}},
	}
	invalidReceipts := []struct {
		name    string
		receipt activation.Receipt
		forge   bool
	}{
		{
			name:    "path traversal",
			receipt: activation.Receipt{Edition: webengine.EditionOpenLiteSpeed, Digest: "segment/../forged-generation"},
			forge:   true,
		},
		{
			name:    "non SHA-256 digest",
			receipt: activation.Receipt{Edition: webengine.EditionOpenLiteSpeed, Digest: strings.Repeat("z", 64)},
			forge:   true,
		},
		{
			name: "staged receipt with evidence",
			receipt: activation.Receipt{
				Edition:         webengine.EditionOpenLiteSpeed,
				CandidateDigest: strings.Repeat("c", 64),
			},
		},
	}

	for _, operation := range operations {
		for _, invalid := range invalidReceipts {
			t.Run(operation.name+"/"+invalid.name, func(t *testing.T) {
				root := privateRoot(t)
				store, err := New(root, webengine.EditionOpenLiteSpeed)
				if err != nil {
					t.Fatal(err)
				}
				receipt := invalid.receipt
				if invalid.forge {
					forgeResolvableGeneration(t, root, receipt, "forged-master")
				} else {
					generation := testGeneration(t, webengine.EditionOpenLiteSpeed, 42, "master", "vhost")
					staged, err := store.Stage(context.Background(), generation)
					if err != nil {
						t.Fatal(err)
					}
					receipt.Edition = staged.Edition
					receipt.Digest = staged.Digest
				}
				if operation.name == "confirm" {
					live := "forged-master"
					if !invalid.forge {
						live = "master"
					}
					writePrivateFile(t, filepath.Join(root, "httpd_config.conf"), live)
				}

				if err := operation.call(store, receipt); err == nil {
					t.Fatalf("%s accepted unsafe receipt %#v", operation.name, receipt)
				}
			})
		}
	}
}

func TestCurrentRejectsNonCanonicalOrOversizedState(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name string
		data string
	}{
		{
			name: "unknown field",
			data: fmt.Sprintf(`{"Edition":"openlitespeed","Digest":%q,"Status":"applied","Confirmed":true,"Unknown":true}`, digest),
		},
		{
			name: "duplicate field",
			data: fmt.Sprintf(`{"Edition":"openlitespeed","Digest":%q,"Digest":%q,"Status":"applied","Confirmed":true}`, digest, digest),
		},
		{
			name: "oversized document",
			data: fmt.Sprintf(`{"Edition":"openlitespeed","Digest":%q,"Status":"applied","Confirmed":true,"Padding":%q}`, digest, strings.Repeat("x", 64<<10)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, store, generation := confirmedStore(t)
			data := strings.Replace(test.data, digest, generation.ContentDigest, 2)
			writePrivateFile(t, filepath.Join(root, stateDir, "current"), data)

			if receipt, err := store.Current(context.Background()); err == nil {
				t.Fatalf("Current() = %#v, nil; want strict bounded-state error", receipt)
			}
		})
	}
}

func TestSwapRejectsNonCanonicalOrOversizedManifest(t *testing.T) {
	tests := []struct {
		name     string
		manifest func(activation.Receipt) string
	}{
		{
			name: "unknown field",
			manifest: func(receipt activation.Receipt) string {
				return fmt.Sprintf(`{"edition":"openlitespeed","digest":%q,"snapshot":42,"unknown":true}`, receipt.Digest)
			},
		},
		{
			name: "duplicate field",
			manifest: func(receipt activation.Receipt) string {
				return fmt.Sprintf(`{"edition":"openlitespeed","digest":%q,"digest":%q,"snapshot":42}`, receipt.Digest, receipt.Digest)
			},
		},
		{
			name: "oversized document",
			manifest: func(receipt activation.Receipt) string {
				return fmt.Sprintf(`{"edition":"openlitespeed","digest":%q,"snapshot":42,"padding":%q}`, receipt.Digest, strings.Repeat("x", 64<<10))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			writePrivateFile(t, filepath.Join(root, stateDir, "generations", receipt.Digest), test.manifest(receipt))

			if err := store.SwapMaster(context.Background(), receipt); err == nil {
				t.Fatal("SwapMaster accepted a non-canonical or oversized manifest")
			}
		})
	}
}

func TestSwapRejectsOversizedOrMissingStagedArtifacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, path string)
	}{
		{
			name: "oversized master",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				writePrivateFile(t, path, strings.Repeat("x", (16<<20)+1))
			},
		},
		{
			name: "missing master",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			master := filepath.Join(root, ".panel-generations", "g42", receipt.Digest, "httpd_config.conf")
			test.mutate(t, master)

			if err := store.SwapMaster(context.Background(), receipt); err == nil {
				t.Fatal("SwapMaster accepted an oversized or missing staged artifact")
			}
		})
	}
}

func TestNewRejectsRelativeRootAndWrongModeMaster(t *testing.T) {
	t.Run("relative root", func(t *testing.T) {
		working := t.TempDir()
		previous, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(working); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chdir(previous); err != nil {
				t.Errorf("restore working directory: %v", err)
			}
		})
		if err := os.Mkdir("relative-root", 0o700); err != nil {
			t.Fatal(err)
		}

		if store, err := New("relative-root", webengine.EditionOpenLiteSpeed); err == nil {
			t.Fatalf("New(relative root) = %#v, nil", store)
		}
	})

	t.Run("wrong mode master", func(t *testing.T) {
		root := privateRoot(t)
		master := filepath.Join(root, "httpd_config.conf")
		if err := os.WriteFile(master, []byte("master"), 0o644); err != nil {
			t.Fatal(err)
		}

		if store, err := New(root, webengine.EditionOpenLiteSpeed); err == nil {
			t.Fatalf("New(wrong-mode master) = %#v, nil", store)
		}
	})
}

func confirmedStore(t *testing.T) (string, *Store, nativeGeneration) {
	t.Helper()
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
	return root, store, nativeGeneration{ContentDigest: generation.ContentDigest}
}

type nativeGeneration struct {
	ContentDigest string
}

func forgeResolvableGeneration(t *testing.T, root string, receipt activation.Receipt, master string) {
	t.Helper()
	data, err := json.Marshal(manifest{Edition: receipt.Edition, Digest: receipt.Digest, Snapshot: 42})
	if err != nil {
		t.Fatal(err)
	}
	writePrivateFile(t, filepath.Join(root, stateDir, "generations", receipt.Digest), string(data))
	writePrivateFile(t, filepath.Join(root, ".panel-generations", "g42", receipt.Digest, "httpd_config.conf"), master)
}

func writePrivateFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
