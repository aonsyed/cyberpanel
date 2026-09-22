//go:build linux

package database

import (
	"context"
	"strconv"
	"strings"
)

// The dump/loader/promotion path supports tables and views, not executable
// schema objects. Audit using the instance administrator, never the workspace
// SELECT account (whose information_schema projection can hide such objects).
func (executor *LinuxMariaDBExecutor) checkExportProgramObjects(ctx context.Context, database Database) error {
	executor.mu.Lock()
	instance, err := executor.instance(database.InstanceID)
	executor.mu.Unlock()
	if err != nil {
		return err
	}
	connection, closeConnection, err := executor.connection(ctx, instance)
	if err != nil {
		return ErrTransferUnsupportedObjects
	}
	defer closeConnection()
	output, err := connection.query(ctx, sqlObserveTransferPrograms, database)
	if err != nil {
		return ErrTransferUnsupportedObjects
	}
	fields := strings.Fields(string(output))
	if len(fields) != 4 {
		return ErrTransferUnsupportedObjects
	}
	for index, field := range fields {
		count, err := strconv.ParseUint(field, 10, 64)
		if err != nil || index < 3 && count != 0 || index == 3 && count == 0 {
			return ErrTransferUnsupportedObjects
		}
	}
	return nil
}

func transferProgramObjectsSQL(database Database) (string, error) {
	if database.Validate() != nil {
		return "", ErrInvalidResource
	}
	name := "'" + database.Name.String() + "'"
	grantee := "CONCAT(QUOTE(SUBSTRING_INDEX(CURRENT_USER(),'@',1)),'@',QUOTE(SUBSTRING_INDEX(CURRENT_USER(),'@',-1)))"
	// mysql.proc and mysql.event require complete catalog visibility. An admin
	// lacking those reads or schema/global TRIGGER visibility is not evidence
	// that no omitted objects exist; deny export rather than guess.
	return "SELECT (SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=" + name + ")," +
		"(SELECT COUNT(*) FROM mysql.proc WHERE db=" + name + ")," +
		"(SELECT COUNT(*) FROM mysql.event WHERE db=" + name + ")," +
		"((SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=" + grantee + " AND PRIVILEGE_TYPE='TRIGGER')+" +
		"(SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=" + grantee + " AND TABLE_SCHEMA=" + name + " AND PRIVILEGE_TYPE='TRIGGER'));\n", nil
}
