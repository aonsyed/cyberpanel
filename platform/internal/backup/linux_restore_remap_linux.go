//go:build linux

package backup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

// Cross-scope database restore remapping.
//
// A database artifact captured at another scope carries the source site's
// database names. Importing it verbatim would mutate the source databases
// instead of the requested destination, so a cross-scope restore maps every
// source database to a fresh deterministic name before import (the
// restore-isolated-first posture of requirement DB-020). The dump's
// database-level statements are rewritten to the mapped names; any other
// reference to a source name fails closed because it would escape the
// renamed context. The restored databases are then registered as target-scope
// resources so the panel owns them, and rollback drops them again.

var (
	linuxBackupDropDatabaseLine = regexp.MustCompile(`^/\*![0-9]{4,6} DROP DATABASE IF EXISTS ` + "`([^`]+)`" + `\*/;$`)
	// mariadb-dump emits "CREATE DATABASE /*!32312 IF NOT EXISTS*/ `name` ...".
	linuxBackupCreateDatabaseLine = regexp.MustCompile(`^CREATE DATABASE\s+(?:/\*![0-9]{4,6}\s+IF NOT EXISTS\*/\s+)?` + "`([^`]+)`")
	linuxBackupUseDatabaseLine = regexp.MustCompile(`^USE ` + "`([^`]+)`" + `;$`)
)

// linuxBackupDumpDatabases scans a mariadb-dump --databases stream and
// returns the distinct database names its database-level statements target.
func linuxBackupDumpDatabases(dump string) ([]string, error) {
	file, err := openLinuxBackupRegular(dump)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	names := map[string]bool{}
	reader := bufio.NewReader(file)
	for {
		line, readErr := reader.ReadString('\n')
		if name, ok := linuxBackupDatabaseStatementName(line); ok {
			names[name] = true
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	return ordered, nil
}

// linuxBackupDatabaseStatementName reports the database named by a
// database-level dump statement (DROP/CREATE DATABASE, USE).
func linuxBackupDatabaseStatementName(line string) (string, bool) {
	for _, pattern := range []*regexp.Regexp{linuxBackupDropDatabaseLine, linuxBackupCreateDatabaseLine, linuxBackupUseDatabaseLine} {
		if matches := pattern.FindStringSubmatch(strings.TrimRight(line, "\n")); matches != nil {
			return matches[1], true
		}
	}
	return "", false
}

// rewriteLinuxBackupDump copies the dump to target, rewriting database-level
// statements to the mapped names. Any other occurrence of a source name —
// including qualified references inside routine or trigger bodies — fails
// closed, because the imported statement would still act on the source
// database after the rename.
func rewriteLinuxBackupDump(source, target string, remap map[string]string) error {
	file, err := openLinuxBackupRegular(source)
	if err != nil {
		return err
	}
	defer file.Close()
	rewritten, err := createLinuxBackupFile(target)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(rewritten)
	quoted := make(map[string]string, len(remap))
	for from, to := range remap {
		quoted["`"+from+"`"] = "`" + to + "`"
	}
	reader := bufio.NewReader(file)
	fail := func(cause error) error {
		// A refused rewrite must not leave a partial remapped dump behind.
		return errors.Join(cause, rewritten.Close(), os.Remove(target))
	}
	for {
		line, readErr := reader.ReadString('\n')
		if name, ok := linuxBackupDatabaseStatementName(line); ok {
			if mapped, mappedOk := remap[name]; mappedOk {
				line = strings.Replace(line, "`"+name+"`", "`"+mapped+"`", 1)
			}
		} else if len(line) > 0 && !strings.HasPrefix(line, "--") && strings.TrimSpace(line) != "" {
			for quotedSource := range quoted {
				if strings.Contains(line, quotedSource) {
					return fail(fmt.Errorf("%w: dump body references source database %s; cross-scope remap refuses to import it", ErrInvalidBackup, strings.Trim(quotedSource, "`")))
				}
			}
		}
		if line != "" {
			if _, err = writer.WriteString(line); err != nil {
				return fail(err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fail(readErr)
		}
	}
	if err = writer.Flush(); err != nil {
		return fail(err)
	}
	if err = rewritten.Sync(); err != nil {
		return fail(err)
	}
	return rewritten.Close()
}

// linuxBackupRemappedDatabaseName derives the deterministic target name for a
// restored source database: unique per (source, destination scope) and never
// equal to the source name.
func linuxBackupRemappedDatabaseName(source, targetScope string) (string, error) {
	suffix := linuxBackupDigest("restore-remap", source, targetScope)[:8]
	base := source
	if len(base) > 55 {
		base = base[:55]
	}
	name, err := database.ParseSQLIdentifier(base + "_" + suffix)
	if err != nil {
		return "", errors.Join(ErrInvalidBackup, err)
	}
	if name.String() == source {
		return "", fmt.Errorf("%w: remapped name collides with the source name", ErrInvalidBackup)
	}
	return name.String(), nil
}

// linuxBackupRegistryDatabaseNames returns every database name the panel
// registry claims, at any scope: the physical namespace is shared.
func linuxBackupRegistryDatabaseNames() (map[string]bool, error) {
	entries, err := os.ReadDir(linuxBackupDatabaseStateRoot)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !safeLinuxBackupName(entry.Name()) {
			return nil, ErrInvalidBackup
		}
		var resource database.Database
		if err = readLinuxBackupJSON(filepath.Join(linuxBackupDatabaseStateRoot, entry.Name()), &resource); err != nil {
			return nil, err
		}
		if resource.Name.String() != "" && resource.Metadata.Status.Lifecycle != database.LifecycleDeleted {
			names[strings.ToLower(resource.Name.String())] = true
		}
	}
	return names, nil
}

func (host *LinuxBackupHost) physicalDatabases(ctx context.Context) (map[string]bool, error) {
	command := exec.CommandContext(ctx, "/usr/bin/mariadb", "--protocol=socket", "--socket=/run/mysqld/mysqld.sock", "--user=root", "--skip-column-names", "--batch", "--execute=SHOW DATABASES")
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/root"}
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("physical database inventory failed: %w", err)
	}
	names := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names[strings.ToLower(line)] = true
		}
	}
	return names, nil
}

// crossScopeDatabaseRemap resolves the source-to-target database name map for
// a restore whose database component crosses scopes. The result is computed
// once, checked against every existing claim on the shared namespace, and
// persisted in the restore state so retries reuse the identical mapping.
func (host *LinuxBackupHost) crossScopeDatabaseRemap(ctx context.Context, plan RestorePlanSpec, state *linuxRestoreState, dump string) (map[string]string, error) {
	if plan.TargetScope == plan.SourceScope {
		return nil, nil
	}
	if len(state.DatabaseRemap) > 0 {
		return state.DatabaseRemap, nil
	}
	sources, err := linuxBackupDumpDatabases(dump)
	if err != nil {
		return nil, err
	}
	remap := map[string]string{}
	if len(sources) > 0 {
		physical, err := host.physicalDatabases(ctx)
		if err != nil {
			return nil, err
		}
		registry, err := linuxBackupRegistryDatabaseNames()
		if err != nil {
			return nil, err
		}
		remap, err = linuxBackupDatabaseRemapPlan(sources, plan.TargetScope, physical, registry)
		if err != nil {
			return nil, err
		}
	}
	state.DatabaseRemap = remap
	return remap, nil
}

// linuxBackupDatabaseRemapPlan maps each source database to its deterministic
// target name, refusing any name already claimed physically or in the panel
// registry: the MariaDB namespace is shared, so a collision at another scope
// is still a collision.
func linuxBackupDatabaseRemapPlan(sources []string, targetScope string, physical, registry map[string]bool) (map[string]string, error) {
	remap := map[string]string{}
	for _, source := range sources {
		target, nameErr := linuxBackupRemappedDatabaseName(source, targetScope)
		if nameErr != nil {
			return nil, nameErr
		}
		lowered := strings.ToLower(target)
		if physical[lowered] || registry[lowered] {
			return nil, fmt.Errorf("%w: remapped database %s already exists", ErrInvalidBackup, target)
		}
		for _, existing := range remap {
			if strings.ToLower(existing) == lowered {
				return nil, fmt.Errorf("%w: remapped database %s duplicates another mapping", ErrInvalidBackup, target)
			}
		}
		remap[source] = target
	}
	return remap, nil
}

// registerRestoredDatabases records each remapped database as a target-scope
// resource so the panel owns what the restore created.
func (host *LinuxBackupHost) registerRestoredDatabases(ctx context.Context, plan RestorePlanSpec, binding LinuxBackupSiteBinding, remap map[string]string, state *linuxRestoreState) error {
	instance, err := database.DefaultLocalInstance()
	if err != nil {
		return err
	}
	sources := make([]string, 0, len(remap))
	for source := range remap {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		identifier := "restoredb-" + linuxBackupDigest("restoredb", string(plan.ID), plan.TenantID, source, remap[source])
		record := filepath.Join(linuxBackupDatabaseStateRoot, identifier+".json")
		if _, statErr := os.Lstat(record); statErr == nil {
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		tenant, tenantErr := site.NewTenantID(plan.TenantID)
		if tenantErr != nil {
			return errors.Join(ErrInvalidBackup, tenantErr)
		}
		siteID, siteErr := site.NewSiteID(binding.SiteID)
		if siteErr != nil {
			return errors.Join(ErrInvalidBackup, siteErr)
		}
		resourceID, idErr := database.NewResourceID(identifier)
		if idErr != nil {
			return errors.Join(ErrInvalidBackup, idErr)
		}
		name, nameErr := database.ParseSQLIdentifier(remap[source])
		if nameErr != nil {
			return errors.Join(ErrInvalidBackup, nameErr)
		}
		charset, charsetErr := database.ParseSQLIdentifier("utf8mb4")
		if charsetErr != nil {
			return errors.Join(ErrInvalidBackup, charsetErr)
		}
		collation, collationErr := database.ParseSQLIdentifier("utf8mb4_unicode_ci")
		if collationErr != nil {
			return errors.Join(ErrInvalidBackup, collationErr)
		}
		resource := database.Database{Metadata: database.Metadata{ID: resourceID, TenantID: tenant, SiteID: siteID, Generation: 1, Status: database.ResourceStatus{Lifecycle: database.LifecycleProvisioning, Health: database.HealthUnknown, Reconciliation: database.ReconciliationPending}}, InstanceID: instance.ID, Name: name, Charset: charset, Collation: collation, QuotaBytes: 64 << 30}
		if resource.Validate() != nil {
			return ErrInvalidBackup
		}
		if err = writeLinuxBackupJSON(record, resource); err != nil {
			return err
		}
		state.RestoredDatabaseRecords = append(state.RestoredDatabaseRecords, record)
	}
	return nil
}

// dropRestoredDatabases removes the databases a cross-scope restore created.
// It runs on rollback only: the mapped names did not exist at the safety
// snapshot, so restoring that snapshot alone would leave them behind.
func (host *LinuxBackupHost) dropRestoredDatabases(ctx context.Context, state *linuxRestoreState) error {
	if len(state.DatabaseRemap) == 0 {
		return nil
	}
	targets := make([]string, 0, len(state.DatabaseRemap))
	for _, target := range state.DatabaseRemap {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		command := exec.CommandContext(ctx, "/usr/bin/mariadb", "--protocol=socket", "--socket=/run/mysqld/mysqld.sock", "--user=root", "--execute=DROP DATABASE IF EXISTS `"+target+"`")
		command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/root"}
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("rollback of remapped database %s failed: %w: %s", target, err, output)
		}
	}
	for _, record := range state.RestoredDatabaseRecords {
		if err := os.Remove(record); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	state.RestoredDatabaseRecords = nil
	return nil
}
