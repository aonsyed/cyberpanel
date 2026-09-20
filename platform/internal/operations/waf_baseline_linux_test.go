//go:build linux

package operations

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWAFBaselineRecursiveIntegrity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU asset ownership check")
	}
	for _, change := range []string{"none", "rule-bytes", "extra-rule", "symlink", "hardlink", "writable", "manifest"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			relative := "usr/share/modsecurity-crs/rules/rule.conf"
			path := filepath.Join(root, relative)
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			content := []byte("SecRuleEngine On\n")
			if err := os.WriteFile(path, content, 0644); err != nil {
				t.Fatal(err)
			}
			manifest := []byte(digestBytes(content) + "  " + relative + "\n")
			if err := os.WriteFile(filepath.Join(root, "manifest"), manifest, 0644); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "rule-bytes":
				if err := os.WriteFile(path, []byte("SecRuleEngine Off\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "extra-rule":
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), "extra.conf"), content, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, filepath.Join(root, "target")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "target"), path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(root, "target")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				if err := os.WriteFile(filepath.Join(root, "manifest"), []byte("altered"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			err := verifyWAFAssets(root, "manifest", digestBytes(manifest))
			if (err == nil) != (change == "none") {
				t.Fatalf("integrity result: %v", err)
			}
		})
	}
}

func TestInitialWAFRecognitionIsExact(t *testing.T) {
	if !isInitialWAFConfiguration(InitialWAFConfiguration()) {
		t.Fatal("baseline not recognized")
	}
	if isInitialWAFConfiguration(append(InitialWAFConfiguration(), '\n')) {
		t.Fatal("foreign content accepted")
	}
}

func TestInstalledWAFManifestCanAdvanceWithoutPanelRebuild(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU ownership check")
	}
	root := t.TempDir()
	relative := "usr/share/modsecurity-crs/rules/rule.conf"
	path := filepath.Join(root, relative)
	manifestPath := filepath.Join(root, baselineManifestPath)
	for _, directory := range []string{filepath.Dir(path), filepath.Dir(manifestPath)} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	var previous string
	for _, content := range []string{"# installed rules release one\n", "# installed rules release two\n"} {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		manifest := []byte(digestBytes([]byte(content)) + "  " + relative + "\n")
		if err := os.WriteFile(manifestPath, manifest, 0644); err != nil {
			t.Fatal(err)
		}
		evidence, err := installedWAFAssets(root)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Digest != digestBytes(manifest) || evidence.Digest == previous || evidence.Version != "installed" {
			t.Fatal("installed release evidence not updated")
		}
		previous = evidence.Digest
	}
	if err := os.WriteFile(path, []byte("unmanifested change"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := installedWAFAssets(root); err == nil {
		t.Fatal("unmanifested rule change accepted")
	}
	if err := os.WriteFile(manifestPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := installedWAFAssets(root); err == nil {
		t.Fatal("empty manifest accepted")
	}
}

func TestInitialWAFJournalHandoff(t *testing.T) {
	baseline := operationsFileSnapshot{Existed: true, Mode: 0600, Content: InitialWAFConfiguration()}
	if err := validateWAFPreviousGeneration(wafActiveIndex{}, nil, baseline); err != nil {
		t.Fatal(err)
	}
	if err := validateWAFPreviousGeneration(wafActiveIndex{}, nil, operationsFileSnapshot{}); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"content", "owner", "group", "mode", "journal", "current"} {
		t.Run(variant, func(t *testing.T) {
			snapshot := baseline
			index := wafActiveIndex{}
			var current *wafNativeGeneration
			switch variant {
			case "content":
				snapshot.Content = []byte("SecRuleEngine Off\n")
			case "owner":
				snapshot.UID = 1000
			case "group":
				snapshot.GID = 1000
			case "mode":
				snapshot.Mode = 0644
			case "journal":
				index.Policies = []wafPolicyPointer{{ScopeKey: "node"}}
			case "current":
				current = &wafNativeGeneration{}
			}
			if err := validateWAFPreviousGeneration(index, current, snapshot); err == nil {
				t.Fatal("foreign/ambiguous prior state accepted")
			}
		})
	}
}

func TestQEMUInitialWAFAssets(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_WAF") != "1" {
		t.Skip("installed QEMU native WAF required")
	}
	if err := VerifyInitialWAFAssets(); err != nil {
		t.Fatal(err)
	}
	// Native parsing is exercised by TestQEMURenderedInitialWebParser using
	// the installed vendor server/module, not a separately compiled parser.
}
