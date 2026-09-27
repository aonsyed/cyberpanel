//go:build linux

package database

import (
	"context"
	"strconv"
	"strings"
)

// The dump/loader/promotion path supports tables, views and INVOKER routines,
// not triggers or events. Audit using the instance administrator, never the
// workspace SELECT account (whose information_schema projection can hide such
// objects).
func (executor *LinuxMariaDBExecutor) exportTransferRoutines(ctx context.Context,database Database)([]transferNativeRoutine,error){
	executor.mu.Lock()
	instance, err := executor.instance(database.InstanceID)
	executor.mu.Unlock()
	if err != nil {
		return nil,err
	}
	connection, closeConnection, err := executor.connection(ctx, instance)
	if err != nil {
		return nil,ErrTransferUnsupportedObjects
	}
	defer closeConnection()
	output, err := connection.query(ctx, sqlObserveTransferPrograms, database)
	if err != nil {
		return nil,ErrTransferUnsupportedObjects
	}
	fields := strings.Fields(string(output))
	if len(fields) != 4 {
		return nil,ErrTransferUnsupportedObjects
	}
	for index, field := range fields {
		count, err := strconv.ParseUint(field, 10, 64)
		if err != nil || (index == 0 || index == 2) && count != 0 || index == 3 && count == 0 {
			return nil,ErrTransferUnsupportedObjects
		}
	}
	routines,err:=observeTransferRoutines(ctx,connection,database)
	if err!=nil{return nil,err}
	if len(routines)>0 {tables,e:=connection.query(ctx,sqlObserveImportTables,database);if e!=nil{return nil,e};if strings.Contains(string(tables),"\tVIEW\t"){return nil,ErrTransferUnsupportedObjects}}
	return routines,nil
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
