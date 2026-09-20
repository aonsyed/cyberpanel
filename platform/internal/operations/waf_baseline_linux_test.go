//go:build linux

package operations

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWAFBaselineRecursiveIntegrity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU asset ownership check")
	}
	for _, change := range []string{"none", "rule-bytes", "extra-rule", "symlink", "hardlink", "writable", "directory-writable", "owner", "empty-entry", "missing-entry"} {
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
			entryPath := filepath.Join(root, baselineCRSEntry)
			if err := os.WriteFile(entryPath, []byte("Include rules/*.conf\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, baselineAssetsPath, "unicode.mapping"), []byte("20127\n"), 0644); err != nil {
				t.Fatal(err)
			}
			before, err := installedWAFAssets(root)
			if err != nil {
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
			case "directory-writable":
				if err := os.Chmod(filepath.Dir(path), 0777); err != nil {
					t.Fatal(err)
				}
			case "owner":
				if err := os.Chown(path, 200000, 200000); err != nil {
					t.Fatal(err)
				}
			case "empty-entry":
				if err := os.WriteFile(entryPath, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "missing-entry":
				if err := os.Remove(entryPath); err != nil {
					t.Fatal(err)
				}
			}
			after, err := installedWAFAssets(root)
			allowed := change == "none" || change == "rule-bytes" || change == "extra-rule"
			if (err == nil) != allowed {
				t.Fatalf("integrity result: %v", err)
			}
			if allowed && (after.Digest == before.Digest) != (change == "none") {
				t.Fatal("installed asset change not reflected in evidence")
			}
		})
	}
}

func TestInitialWAFRecognitionIsExact(t *testing.T) {
	baseline := initialWAFConfiguration("/etc/modsecurity/unicode.mapping")
	if !isInitialWAFConfiguration(baseline) {
		t.Fatal("baseline not recognized")
	}
	if isInitialWAFConfiguration(append(baseline, '\n')) {
		t.Fatal("foreign content accepted")
	}
}

func TestInstalledWAFRulesNeedNoCustomPackageManifest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU ownership check")
	}
	root := t.TempDir()
	relative := "usr/share/modsecurity-crs/rules/rule.conf"
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, baselineCRSEntry), []byte("Include rules/*.conf\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, baselineAssetsPath, "unicode.mapping"), []byte("20127\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var previous string
	for _, content := range []string{"# installed rules release one\n", "# installed rules release two\n"} {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		evidence, err := installedWAFAssets(root)
		if err != nil {
			t.Fatal(err)
		}
		if !validSHA256(evidence.Digest) || evidence.Digest == previous || evidence.Version != "installed" || evidence.Path != baselineAssetsPath {
			t.Fatal("installed release evidence not updated")
		}
		previous = evidence.Digest
	}
}

func TestInitialWAFJournalHandoff(t *testing.T) {
	baseline := operationsFileSnapshot{Existed: true, Mode: 0600, Content: initialWAFConfiguration("/etc/modsecurity/unicode.mapping")}
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
	configuration, err := InitialWAFConfiguration()
	if err != nil || !isInitialWAFConfiguration(configuration) {
		t.Fatal("installed baseline not generated/recognized", err)
	}
	_, mapping, err := installedWAFUnicodeMapping("/")
	if err != nil {
		t.Fatal(err)
	}
	// Test the real vendor parser against both its installed mapping path and a
	// conventional unversioned layout. Bind only in a private mount namespace;
	// live policy, mapping files and daemon state are not changed.
	for _, layout := range []string{"installed", "unversioned"} {
		t.Run(layout, func(t *testing.T) {
			directory := t.TempDir()
			policy := configuration
			if layout == "unversioned" {
				if err := os.WriteFile(filepath.Join(directory, "unicode.mapping"), mapping, 0644); err != nil {
					t.Fatal(err)
				}
				policy = initialWAFConfiguration("/usr/local/lsws/conf/modsec/unicode.mapping")
			}
			if err := os.WriteFile(filepath.Join(directory, "cyberpanel.conf"), policy, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
				"--property=ReadOnlyPaths=/usr/local/lsws/conf /etc /usr/share/modsecurity-crs",
				"--property=CapabilityBoundingSet=~CAP_SYS_ADMIN",
				"--property=RuntimeMaxSec=20s", "--property=TimeoutStopSec=5s",
				"--property=BindReadOnlyPaths="+directory+":/usr/local/lsws/conf/modsec",
				"/usr/local/lsws/bin/lshttpd", "-t").CombinedOutput()
			if err != nil {
				if len(output) > 4096 {
					output = output[len(output)-4096:]
				}
				t.Fatalf("native parser: %v\n%s", err, output)
			}
		})
	}
}

func TestInstalledUnicodeMappingDoesNotPinARelease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU ownership check")
	}
	for _, location := range []string{"/etc/modsecurity/unicode.mapping", "/etc/modsecurity.d/unicode.mapping", "/usr/local/lsws/conf/modsec/unicode.mapping", baselineAssetsPath + "/unicode.mapping", baselineAssetsPath + "/any-installed-release/unicode.mapping"} {
		t.Run(location, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, location)
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("20127\n"), 0644); err != nil {
				t.Fatal(err)
			}
			selected, _, err := installedWAFUnicodeMapping(root)
			if err != nil || selected != location {
				t.Fatalf("selected %q: %v", selected, err)
			}
			configuration := initialWAFConfiguration(selected)
			if !strings.Contains(string(configuration), "SecUnicodeMapFile "+location+" 20127\n") || !isInitialWAFConfiguration(configuration) {
				t.Fatal("installed mapping not rendered/recognized")
			}
			if err := os.Chmod(path, 0666); err != nil {
				t.Fatal(err)
			}
			if _, _, err := installedWAFUnicodeMapping(root); err == nil {
				t.Fatal("writable mapping accepted")
			}
		})
	}
	for _, path := range []string{"/tmp/unicode.mapping", baselineAssetsPath + "/../unicode.mapping", baselineAssetsPath + "/bad\nSecRuleEngine Off/unicode.mapping"} {
		if isInitialWAFConfiguration(initialWAFConfiguration(path)) {
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
}

func TestInstalledUnicodeMappingRejectsMissingOrAmbiguousAssets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root QEMU ownership check")
	}
	root := t.TempDir()
	if _, _, err := installedWAFUnicodeMapping(root); err == nil {
		t.Fatal("missing mapping accepted")
	}
	for _, version := range []string{"release-a", "release-b"} {
		path := filepath.Join(root, baselineAssetsPath, version, "unicode.mapping")
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("20127\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := installedWAFUnicodeMapping(root); err == nil {
		t.Fatal("ambiguous mappings accepted")
	}
	path := filepath.Join(root, baselineAssetsPath, "unicode.mapping")
	if err := os.WriteFile(path, []byte("20127\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if selected, _, err := installedWAFUnicodeMapping(root); err != nil || selected != baselineAssetsPath+"/unicode.mapping" {
		t.Fatal("conventional mapping did not take precedence", err)
	}
}
