package architecture

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testModulePath = "github.com/aonsyed/cyberpanel/platform"

func TestPlatformImportBoundaries(t *testing.T) {
	got, err := Scan(filepath.Join("..", ".."), testModulePath)
	if err != nil {
		t.Fatalf("Scan() platform module: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("forbidden platform imports:\n%s", strings.Join(diagnosticStrings(got), "\n"))
	}
}

func TestScanAllowsStandardLibraryModuleAndExplicitVendorImports(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "vendor/modules.txt", strings.Join([]string{
		"# example.com/approved/dependency v1.2.3",
		"## explicit; go 1.26",
		"example.com/approved/dependency/subpackage",
		"",
	}, "\n"))
	writeTestFile(t, root, "internal/good/good.go", `package good

import (
	_ "context"
	_ "github.com/aonsyed/cyberpanel/platform/internal/other"
	_ "example.com/approved/dependency/subpackage"
)
`)

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Scan() diagnostics = %v, want none", diagnosticStrings(got))
	}
}

func TestScanSkipsVendorAndTestdataTrees(t *testing.T) {
	root := t.TempDir()
	badSource := `package ignored

import _ "example.invalid/must-not-be-scanned"
`
	writeTestFile(t, root, "vendor/example.invalid/bad/bad.go", badSource)
	writeTestFile(t, root, "internal/hosting/testdata/bad.go", badSource)

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Scan() diagnostics = %v, want none", diagnosticStrings(got))
	}
}

func TestScanSkipsGoIgnoredFileNames(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "internal/hosting/._metadata.go", "\x00AppleDouble metadata")
	writeTestFile(t, root, "internal/hosting/_ignored.go", `package ignored

import _ "github.com/aonsyed/cyberpanel/CyberCP"
`)

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Scan() diagnostics = %v, want none", diagnosticStrings(got))
	}
}

func TestScanRejectsLegacyRepositoryImportWithStableDiagnostic(t *testing.T) {
	root := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("testdata", "forbidden-import.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	writeTestFile(t, root, "internal/hosting/legacy.go", string(fixture))

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	want := []string{
		`internal/hosting/legacy.go:3: import "github.com/aonsyed/cyberpanel/CyberCP" violates legacy-repository`,
	}
	if gotStrings := diagnosticStrings(got); !reflect.DeepEqual(gotStrings, want) {
		t.Fatalf("Scan() diagnostics = %#v, want %#v", gotStrings, want)
	}
}

func TestScanRejectsOriginalUpstreamLegacyImport(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "internal/hosting/upstream.go", `package hosting

import _ "github.com/usmannasir/cyberpanel/CyberCP"
`)

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	want := []string{
		`internal/hosting/upstream.go:3: import "github.com/usmannasir/cyberpanel/CyberCP" violates legacy-repository`,
	}
	if gotStrings := diagnosticStrings(got); !reflect.DeepEqual(gotStrings, want) {
		t.Fatalf("Scan() diagnostics = %#v, want %#v", gotStrings, want)
	}
}

func TestScanRejectsUnapprovedExternalAndUnknownNoDotImports(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "internal/ops/external.go", `package ops

import (
	_ "example.invalid/not-vendored"
	_ "notstdlib/package"
)
`)

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	want := []string{
		`internal/ops/external.go:4: import "example.invalid/not-vendored" violates unapproved-external`,
		`internal/ops/external.go:5: import "notstdlib/package" violates unapproved-external`,
	}
	if gotStrings := diagnosticStrings(got); !reflect.DeepEqual(gotStrings, want) {
		t.Fatalf("Scan() diagnostics = %#v, want %#v", gotStrings, want)
	}
}

func TestScanRejectsPythonSubprocessWrapperImport(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "internal/ops/runtime.go", `package ops

import _ "github.com/aonsyed/cyberpanel/platform/internal/platform/pythonexec"
`)

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	want := []string{
		`internal/ops/runtime.go:3: import "github.com/aonsyed/cyberpanel/platform/internal/platform/pythonexec" violates python-subprocess-wrapper`,
	}
	if gotStrings := diagnosticStrings(got); !reflect.DeepEqual(gotStrings, want) {
		t.Fatalf("Scan() diagnostics = %#v, want %#v", gotStrings, want)
	}
}

func TestScanRejectsHostExecutorImportFromDomainPackage(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "internal/hosting/sites/service.go", `package sites

import _ "github.com/aonsyed/cyberpanel/platform/internal/platform/hostexec"
`)

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	want := []string{
		`internal/hosting/sites/service.go:3: import "github.com/aonsyed/cyberpanel/platform/internal/platform/hostexec" violates domain-host-executor`,
	}
	if gotStrings := diagnosticStrings(got); !reflect.DeepEqual(gotStrings, want) {
		t.Fatalf("Scan() diagnostics = %#v, want %#v", gotStrings, want)
	}
}

func TestScanAllowsHostExecutorImportFromPlatformPackage(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "internal/platform/supervisor/service.go", `package supervisor

import _ "github.com/aonsyed/cyberpanel/platform/internal/platform/hostexec"
`)

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Scan() diagnostics = %v, want none", diagnosticStrings(got))
	}
}

func TestScanSortsDiagnosticsByFileLineAndImport(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "internal/zeta/z.go", `package zeta

import _ "z.invalid/dependency"
`)
	writeTestFile(t, root, "internal/alpha/a.go", `package alpha

import (
	_ "z.invalid/dependency"
	_ "a.invalid/dependency"
)
`)

	got, err := Scan(root, testModulePath)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	want := []string{
		`internal/alpha/a.go:4: import "z.invalid/dependency" violates unapproved-external`,
		`internal/alpha/a.go:5: import "a.invalid/dependency" violates unapproved-external`,
		`internal/zeta/z.go:3: import "z.invalid/dependency" violates unapproved-external`,
	}
	if gotStrings := diagnosticStrings(got); !reflect.DeepEqual(gotStrings, want) {
		t.Fatalf("Scan() diagnostics = %#v, want %#v", gotStrings, want)
	}
}

func writeTestFile(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
}

func diagnosticStrings(diagnostics []Diagnostic) []string {
	result := make([]string, len(diagnostics))
	for i, diagnostic := range diagnostics {
		result[i] = diagnostic.String()
	}
	return result
}
