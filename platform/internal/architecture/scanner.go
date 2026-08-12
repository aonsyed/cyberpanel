// Package architecture enforces compile-time dependency boundaries without
// invoking the Go command or loading application code.
package architecture

import (
	"bufio"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Rule identifies a dependency boundary violated by an import.
type Rule string

const (
	RuleLegacyRepository        Rule = "legacy-repository"
	RulePythonSubprocessWrapper Rule = "python-subprocess-wrapper"
	RuleDomainHostExecutor      Rule = "domain-host-executor"
	RuleUnapprovedExternal      Rule = "unapproved-external"
)

// Diagnostic is a stable, root-relative import policy failure.
type Diagnostic struct {
	File       string
	Line       int
	ImportPath string
	Rule       Rule
}

// String renders a diagnostic without absolute paths or environment-specific
// details, so independent guest runs produce the same result.
func (d Diagnostic) String() string {
	return fmt.Sprintf("%s:%d: import %q violates %s", d.File, d.Line, d.ImportPath, d.Rule)
}

// Scan parses every first-party Go file below root and reports forbidden
// imports. It deliberately does not invoke go list. Standard-library imports,
// imports within modulePath, and packages recorded in vendor/modules.txt are
// allowed. Go files below vendor or testdata directories are not first-party
// runtime inputs and are skipped.
func Scan(root, modulePath string) ([]Diagnostic, error) {
	modulePath = strings.TrimSpace(modulePath)
	if !validImportPath(modulePath) {
		return nil, fmt.Errorf("invalid module path %q", modulePath)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve scan root: %w", err)
	}
	rootInfo, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect scan root: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("scan root is not a directory")
	}

	vendored, err := loadVendoredPackages(absRoot)
	if err != nil {
		return nil, err
	}

	fileSet := token.NewFileSet()
	diagnostics := make([]Diagnostic, 0)
	err = filepath.WalkDir(absRoot, func(fileName string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk source tree: %w", walkErr)
		}
		if entry.IsDir() {
			if fileName != absRoot && ignoredDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(entry.Name()) != ".go" ||
			strings.HasPrefix(entry.Name(), ".") ||
			strings.HasPrefix(entry.Name(), "_") {
			return nil
		}

		relativeName, err := filepath.Rel(absRoot, fileName)
		if err != nil {
			return fmt.Errorf("make source path relative: %w", err)
		}
		relativeName = filepath.ToSlash(relativeName)
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s: symbolic-link Go source is not supported", relativeName)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s: non-regular Go source is not supported", relativeName)
		}

		source, err := os.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("read %s: %w", relativeName, err)
		}
		parsed, err := parser.ParseFile(fileSet, relativeName, source, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relativeName, err)
		}

		sourcePackage := packageImportPath(modulePath, relativeName)
		for _, importSpec := range parsed.Imports {
			importPath, err := strconv.Unquote(importSpec.Path.Value)
			if err != nil {
				return fmt.Errorf("parse import in %s: %w", relativeName, err)
			}
			rule := classifyImport(sourcePackage, importPath, modulePath, vendored)
			if rule == "" {
				continue
			}
			diagnostics = append(diagnostics, Diagnostic{
				File:       relativeName,
				Line:       fileSet.Position(importSpec.Pos()).Line,
				ImportPath: importPath,
				Rule:       rule,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(diagnostics, func(i, j int) bool {
		left, right := diagnostics[i], diagnostics[j]
		if left.File != right.File {
			return left.File < right.File
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.ImportPath != right.ImportPath {
			return left.ImportPath < right.ImportPath
		}
		return left.Rule < right.Rule
	})
	return diagnostics, nil
}

func classifyImport(sourcePackage, importPath, modulePath string, vendored map[string]struct{}) Rule {
	if matchesImportPath(importPath, modulePath) {
		if isPythonSubprocessWrapper(importPath, modulePath) {
			return RulePythonSubprocessWrapper
		}
		if isDomainPackage(sourcePackage, modulePath) && isHostExecutor(importPath, modulePath) {
			return RuleDomainHostExecutor
		}
		return ""
	}

	for _, legacyModulePath := range legacyRepositoryPaths(modulePath) {
		if matchesImportPath(importPath, legacyModulePath) {
			return RuleLegacyRepository
		}
	}
	if isStandardLibrary(importPath) {
		return ""
	}
	if _, ok := vendored[importPath]; ok {
		return ""
	}
	return RuleUnapprovedExternal
}

func legacyRepositoryPaths(modulePath string) []string {
	result := []string{"github.com/usmannasir/cyberpanel"}
	parent := path.Dir(modulePath)
	if parent != "." && parent != result[0] {
		result = append(result, parent)
	}
	return result
}

func loadVendoredPackages(root string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	file, err := os.Open(filepath.Join(root, "vendor", "modules.txt"))
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, fmt.Errorf("read vendor/modules.txt: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "=>") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 1 || !validImportPath(fields[0]) {
			return nil, fmt.Errorf("vendor/modules.txt:%d: malformed package entry", lineNumber)
		}
		result[fields[0]] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read vendor/modules.txt: %w", err)
	}
	return result, nil
}

func packageImportPath(modulePath, relativeFileName string) string {
	directory := path.Dir(relativeFileName)
	if directory == "." {
		return modulePath
	}
	return modulePath + "/" + directory
}

func isStandardLibrary(importPath string) bool {
	if !validImportPath(importPath) || importPath == "C" {
		return false
	}
	firstSegment := strings.SplitN(importPath, "/", 2)[0]
	if strings.Contains(firstSegment, ".") {
		return false
	}
	pkg, err := build.Default.Import(importPath, "", build.FindOnly)
	return err == nil && pkg.Goroot
}

func validImportPath(importPath string) bool {
	return importPath != "" &&
		importPath != "." &&
		!path.IsAbs(importPath) &&
		path.Clean(importPath) == importPath &&
		!strings.Contains(importPath, "\\")
}

func matchesImportPath(importPath, prefix string) bool {
	return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
}

func isPythonSubprocessWrapper(importPath, modulePath string) bool {
	relative := strings.TrimPrefix(importPath, modulePath+"/")
	for _, segment := range strings.Split(relative, "/") {
		switch strings.ToLower(segment) {
		case "python", "pythonexec", "pyexec", "pysubprocess", "subprocess":
			return true
		}
	}
	return false
}

func isDomainPackage(importPath, modulePath string) bool {
	relative := strings.TrimPrefix(importPath, modulePath+"/")
	segments := strings.Split(relative, "/")
	if len(segments) < 2 || segments[0] != "internal" {
		return false
	}
	_, ok := domainPackages[segments[1]]
	return ok
}

var domainPackages = map[string]struct{}{
	"access":     {},
	"apps":       {},
	"backup":     {},
	"container":  {},
	"database":   {},
	"dns":        {},
	"federation": {},
	"hosting":    {},
	"identity":   {},
	"mail":       {},
	"migration":  {},
	"ops":        {},
	"security":   {},
	"tls":        {},
}

func isHostExecutor(importPath, modulePath string) bool {
	for _, executorPath := range []string{
		modulePath + "/internal/executor",
		modulePath + "/internal/hostexec",
		modulePath + "/internal/platform/executor",
		modulePath + "/internal/platform/hostexec",
	} {
		if matchesImportPath(importPath, executorPath) {
			return true
		}
	}
	return false
}

func ignoredDirectory(name string) bool {
	return name == "vendor" || name == "testdata"
}
