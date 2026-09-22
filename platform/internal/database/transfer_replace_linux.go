//go:build linux

package database

import "strings"

// transferReplacementRenameSQL is the native move seam, not promotion authority.
// Callers must first durably journal the restore schema and fence application
// writers, validate MariaDB >=10.6.1 and all table engines, and reject views,
// triggers and unplanned objects. A single statement retains the old tables and
// installs the new ones atomically; two separate RENAME statements are unsafe.
// It deliberately is not exposed through the broker until that lifecycle exists.
func transferReplacementRenameSQL(live, staged, restore Database, oldTables, newTables []string) (string, error) {
	if live.Validate() != nil || staged.Validate() != nil || restore.Validate() != nil ||
		live.Name == staged.Name || live.Name == restore.Name || staged.Name == restore.Name ||
		live.ID == staged.ID || live.ID == restore.ID || staged.ID == restore.ID ||
		len(oldTables) == 0 || len(newTables) == 0 {
		return "", ErrInvalidResource
	}
	for _, other := range []Database{staged, restore} {
		if live.InstanceID != other.InstanceID || live.TenantID != other.TenantID || live.SiteID != other.SiteID {
			return "", ErrUnauthorized
		}
	}
	for _, tables := range [][]string{oldTables, newTables} {
		seen := make(map[string]bool, len(tables))
		for _, name := range tables {
			if seen[name] {
				return "", ErrInvalidResource
			}
			seen[name] = true
		}
	}
	oldMove, err := transferRenameSQL(isolatedTransferRename{From: live, To: restore, Tables: oldTables})
	if err != nil {
		return "", err
	}
	newMove, err := transferRenameSQL(isolatedTransferRename{From: staged, To: live, Tables: newTables})
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(oldMove, ";\n") + ", " + strings.TrimPrefix(newMove, "RENAME TABLE "), nil
}
