//go:build linux

package noderelease

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "syscall"
)

// Offline dependency admission. The bundle is the complete install unit on a
// clean host: every Depends/Pre-Depends (dpkg) or Requires (rpm) relation of
// every bundle package must be satisfied by the installed system state plus
// the bundle itself, directly or through a declared Provides virtual. The
// check runs before the native transaction so a missing prerequisite fails
// with the exact names instead of a half-configured dpkg state.

var dependencyName = func(name string) string {
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '+' || character == '-' || character == '.' {
			continue
		}
		return strings.TrimSpace(name[:index])
	}
	return strings.TrimSpace(name)
}

// A dependency group holds |-separated alternatives; the group is satisfied
// when any candidate name resolves.
func splitDependencyGroup(group string) []string {
	parts := strings.Split(group, "|")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if bracket := strings.IndexByte(part, '['); bracket >= 0 {
			part = part[:bracket]
		}
		if name := dependencyName(part); name != "" {
			result = append(result, name)
		}
	}
	return result
}

type offlineClosureChecker struct {
	satisfied map[string]bool
	missing   []string
}

func (checker *offlineClosureChecker) declare(name string) {
	if name = dependencyName(name); name != "" {
		checker.satisfied[name] = true
	}
}

func (checker *offlineClosureChecker) require(group, dependent string) {
	for _, candidate := range splitDependencyGroup(group) {
		if checker.satisfied[candidate] {
			return
		}
	}
	checker.missing = append(checker.missing, strings.TrimSpace(group)+" (required by "+dependent+")")
}

// OfflineDependencyError names every unsatisfied offline relation. It is a
// host-precondition failure: the bundle does not fit this target as-is.
type OfflineDependencyError struct{ Missing []string }

func (err *OfflineDependencyError) Error() string {
	return "offline dependency closure unsatisfied: " + strings.Join(err.Missing, "; ")
}

func verifyOfflineDependencyClosure(ctx context.Context, root string, artifacts []Artifact, target Target) error {
	if len(artifacts) == 0 {
		return nil
	}
	checker := &offlineClosureChecker{satisfied: map[string]bool{}}
	for _, artifact := range artifacts {
		checker.declare(artifact.Package.Name)
	}
	if target.Distribution == DistributionAlma {
		return verifyRPMOfflineDependencyClosure(ctx, root, artifacts, checker)
	}
	return verifyDPKGOfflineDependencyClosure(ctx, root, artifacts, checker)
}

func verifyDPKGOfflineDependencyClosure(ctx context.Context, root string, artifacts []Artifact, checker *offlineClosureChecker) error {
	installed, err := runFixed(ctx, "/usr/bin/dpkg-query", "--show", "--showformat=${db:Status-Abbrev}\\t${Package}\\t${Provides}\\n")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(installed, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[0] == "" || fields[0][0] != 'i' && fields[0][0] != 'u' {
			continue
		}
		checker.declare(fields[1])
		for _, provided := range strings.Split(fields[2], ",") {
			checker.declare(provided)
		}
	}
	// Bundle declarations first: a later package's Provides must satisfy an
	// earlier package's dependency, regardless of bundle ordering.
	for _, artifact := range artifacts {
		packagePath := filepath.Join(root, "packages", artifact.ID)
		provided, err := runFixed(ctx, "/usr/bin/dpkg-deb", "--field", packagePath, "Provides")
		if err != nil {
			return err
		}
		for _, virtual := range strings.Split(provided, ",") {
			checker.declare(virtual)
		}
	}
	for _, artifact := range artifacts {
		packagePath := filepath.Join(root, "packages", artifact.ID)
		for _, field := range []string{"Depends", "Pre-Depends"} {
			declared, err := runFixed(ctx, "/usr/bin/dpkg-deb", "--field", packagePath, field)
			if err != nil {
				return err
			}
			for _, group := range strings.Split(declared, ",") {
				if strings.TrimSpace(group) != "" {
					checker.require(group, artifact.Package.Name)
				}
			}
		}
	}
	return offlineClosureError(checker)
}

func verifyRPMOfflineDependencyClosure(ctx context.Context, root string, artifacts []Artifact, checker *offlineClosureChecker) error {
	installed, err := runFixed(ctx, "/usr/bin/rpm", "-qa", "--qf", "%{NAME}\\n")
	if err != nil {
		return err
	}
	for _, name := range strings.Split(installed, "\n") {
		checker.declare(name)
	}
	// Bundle declarations first: a later package's Provides must satisfy an
	// earlier package's requirement, regardless of bundle ordering.
	for _, artifact := range artifacts {
		packagePath := filepath.Join(root, "packages", artifact.ID)
		provided, err := runFixed(ctx, "/usr/bin/rpm", "-qp", "--provides", packagePath)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(provided, "\n") {
			if name := dependencyName(line); name != "" && !strings.HasPrefix(line, "/") {
				checker.declare(name)
			}
		}
	}
	for _, artifact := range artifacts {
		packagePath := filepath.Join(root, "packages", artifact.ID)
		required, err := runFixed(ctx, "/usr/bin/rpm", "-qp", "--requires", packagePath)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(required, "\n") {
			line = strings.TrimSpace(line)
			// rpm enriches requirements with rpmlib()/rtld()/path capabilities.
			if line == "" || strings.HasPrefix(line, "rpmlib(") || strings.HasPrefix(line, "rtld(") || strings.HasPrefix(line, "packed(") || strings.HasPrefix(line, "/") {
				continue
			}
			checker.require(line, artifact.Package.Name)
		}
	}
	return offlineClosureError(checker)
}

func offlineClosureError(checker *offlineClosureChecker) error {
	if len(checker.missing) == 0 {
		return nil
	}
	unique := map[string]bool{}
	for _, missing := range checker.missing {
		unique[missing] = true
	}
	missing := make([]string, 0, len(unique))
	for value := range unique {
		missing = append(missing, value)
	}
	sort.Strings(missing)
	return &OfflineDependencyError{Missing: missing}
}

// ensureMailname provisions the host mail name before mail packages
// configure, mirroring debian-installer's noninteractive preparation.
// Postfix derives its pristine mydestination from this file; adopting the
// packaged default later requires exactly that shape.
func ensureMailname(target Target) error {
	if target.Distribution != DistributionUbuntu {
		return nil
	}
	path := "/etc/mailname"
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.Join(ErrIntegrity, err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" || strings.ContainsAny(hostname, "\n\r") {
		return ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(hostname + "\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.Join(writeErr, syncErr, closeErr)
	}
	if err = os.Chown(path, 0, 0); err != nil {
		return err
	}
	return os.Chmod(path, 0644)
}
