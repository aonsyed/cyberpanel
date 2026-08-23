//go:build linux

package database

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type mariaDBConnection struct {
	arguments []string
}

type mariaDBStatement uint8

const (
	sqlObserveStatus mariaDBStatement = iota + 1
	sqlObserveDatabase
	sqlCreateDatabase
	sqlDropDatabase
	sqlObservePrincipal
	sqlCreatePrincipal
	sqlDropPrincipal
	sqlRotatePrincipal
	sqlReplaceGrants
	sqlClearGrants
	sqlObserveGrants
	sqlApplyExternalTuning
	sqlObserveTuning
)

type principalMutation struct {
	Principal DatabasePrincipal
	Password  []byte
	TLS       TLSMode
}

type grantMutation struct {
	Database  Database
	Principal DatabasePrincipal
	GrantSet  GrantSet
}

func (executor *LinuxMariaDBExecutor) connection(ctx context.Context, instance DatabaseInstance) (*mariaDBConnection, func(), error) {
	if instance.Validate() != nil {
		return nil, func() {}, ErrInvalidResource
	}
	base := []string{"--batch", "--skip-column-names", "--raw", "--binary-mode", "--connect-timeout=8", "--default-character-set=utf8mb4"}
	if instance.Placement == PlacementLocal {
		arguments := append(base, "--protocol=socket", "--socket="+mariaDBSocket, "--user=root")
		return &mariaDBConnection{arguments: arguments}, func() {}, nil
	}
	if instance.External == nil || !sameServerName(instance.External.Endpoint.Host, instance.External.ServerName) {
		return nil, func() {}, ErrInvalidResource
	}
	external := *instance.External
	administrator, err := executor.secrets.ExternalAdministrator(ctx, external.AdminSecretRef, external.CredentialAudience, instance.ID)
	if err != nil {
		return nil, func() {}, err
	}
	defer wipeBytes(administrator.Password, administrator.ClientCertificatePEM, administrator.ClientKeyPEM)
	if err := validateAdministrator(administrator, external.RequiredTLS == TLSMutual); err != nil {
		return nil, func() {}, err
	}
	ca, err := executor.secrets.PinnedCertificateAuthority(ctx, external.PinnedCASecretRef, external.CredentialAudience)
	if err != nil {
		return nil, func() {}, err
	}
	defer wipeBytes(ca)
	if len(ca) == 0 || len(ca) > maximumSecretBytes {
		return nil, func() {}, ErrInvalidResource
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, func() {}, ErrInvalidResource
	}
	runtimeDirectory, err := os.MkdirTemp(mariaDBRunRoot, "connection-")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(runtimeDirectory) }
	if err := os.Chmod(runtimeDirectory, 0700); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	credentialValue, err := optionFileValue(administrator.Password)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	credentialFile := filepath.Join(runtimeDirectory, "client.cnf")
	credential := []byte("[client]\nuser=" + administrator.Username.String() + "\npassword=\"" + credentialValue + "\"\n")
	if err := atomicRootFile(credentialFile, credential, 0600); err != nil {
		wipeBytes(credential)
		cleanup()
		return nil, func() {}, err
	}
	wipeBytes(credential)
	caFile := filepath.Join(runtimeDirectory, "ca.pem")
	if err := atomicRootFile(caFile, ca, 0600); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	arguments := []string{"--defaults-extra-file=" + credentialFile}
	arguments = append(arguments, base...)
	arguments = append(arguments,
		"--protocol=tcp",
		"--host="+external.Endpoint.Host,
		"--port="+strconv.FormatUint(uint64(external.Endpoint.Port), 10),
		"--ssl",
		"--ssl-ca="+caFile,
		"--ssl-verify-server-cert",
	)
	if external.RequiredTLS == TLSMutual {
		certificateFile := filepath.Join(runtimeDirectory, "client-cert.pem")
		keyFile := filepath.Join(runtimeDirectory, "client-key.pem")
		if err := atomicRootFile(certificateFile, administrator.ClientCertificatePEM, 0600); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		if err := atomicRootFile(keyFile, administrator.ClientKeyPEM, 0600); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		arguments = append(arguments, "--ssl-cert="+certificateFile, "--ssl-key="+keyFile)
	}
	return &mariaDBConnection{arguments: arguments}, cleanup, nil
}

func sameServerName(host, serverName string) bool {
	return strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(serverName, "."))
}

func optionFileValue(value []byte) (string, error) {
	var result strings.Builder
	result.Grow(len(value) + 8)
	for _, character := range value {
		switch character {
		case 0:
			return "", ErrInvalidResource
		case '\\':
			result.WriteString("\\\\")
		case '"':
			result.WriteString("\\\"")
		case '\n':
			result.WriteString("\\n")
		case '\r':
			result.WriteString("\\r")
		case '\t':
			result.WriteString("\\t")
		default:
			if character < 0x20 || character == 0x7f {
				return "", ErrInvalidResource
			}
			result.WriteByte(character)
		}
	}
	return result.String(), nil
}

func (connection *mariaDBConnection) query(ctx context.Context, statement mariaDBStatement, value ...any) ([]byte, error) {
	if connection == nil {
		return nil, ErrInvalidCommand
	}
	script, err := buildMariaDBStatement(statement, value...)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, "/usr/bin/mariadb", connection.arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/root"}
	command.Stdin = strings.NewReader(script)
	output := &limitedBuffer{remaining: maximumProcessOutput}
	command.Stdout, command.Stderr = output, output
	err = command.Run()
	if output.overflow {
		return nil, errors.New("mariadb output exceeded the fixed limit")
	}
	if err != nil {
		return nil, fmt.Errorf("mariadb client failed: %w", err)
	}
	return append([]byte(nil), output.buffer.Bytes()...), nil
}

func buildMariaDBStatement(statement mariaDBStatement, values ...any) (string, error) {
	switch statement {
	case sqlObserveStatus:
		if len(values) != 0 {
			return "", ErrInvalidCommand
		}
		return "SELECT @@version,@@version_comment,@@hostname,@@port,@@require_secure_transport;\n", nil
	case sqlObserveDatabase:
		database, ok := oneValue[Database](values)
		if !ok || database.Validate() != nil {
			return "", ErrInvalidResource
		}
		return databaseObservation(database), nil
	case sqlCreateDatabase:
		database, ok := oneValue[Database](values)
		if !ok || database.Validate() != nil {
			return "", ErrInvalidResource
		}
		return "CREATE DATABASE " + quotedIdentifier(database.Name) + " CHARACTER SET " + database.Charset.String() + " COLLATE " + database.Collation.String() + ";\n" + databaseObservation(database), nil
	case sqlDropDatabase:
		database, ok := oneValue[Database](values)
		if !ok || database.Validate() != nil {
			return "", ErrInvalidResource
		}
		return "DROP DATABASE " + quotedIdentifier(database.Name) + ";\n" + databaseObservation(database), nil
	case sqlObservePrincipal:
		principal, ok := oneValue[DatabasePrincipal](values)
		if !ok || principal.Validate() != nil {
			return "", ErrInvalidResource
		}
		return principalObservation(principal), nil
	case sqlCreatePrincipal:
		mutation, ok := oneValue[principalMutation](values)
		if !ok || mutation.Principal.Validate() != nil || len(mutation.Password) == 0 {
			return "", ErrInvalidResource
		}
		return "CREATE USER " + quotedAccount(mutation.Principal) + " IDENTIFIED VIA mysql_native_password USING '" + nativePasswordHash(mutation.Password) + "'" + principalRequirements(mutation.Principal, mutation.TLS) + ";\n" + principalObservation(mutation.Principal), nil
	case sqlDropPrincipal:
		principal, ok := oneValue[DatabasePrincipal](values)
		if !ok || principal.Validate() != nil {
			return "", ErrInvalidResource
		}
		return "DROP USER " + quotedAccount(principal) + ";\n" + principalObservation(principal), nil
	case sqlRotatePrincipal:
		mutation, ok := oneValue[principalMutation](values)
		if !ok || mutation.Principal.Validate() != nil || len(mutation.Password) == 0 {
			return "", ErrInvalidResource
		}
		return "ALTER USER " + quotedAccount(mutation.Principal) + " IDENTIFIED VIA mysql_native_password USING '" + nativePasswordHash(mutation.Password) + "'" + principalRequirements(mutation.Principal, mutation.TLS) + ";\n" + principalObservation(mutation.Principal), nil
	case sqlReplaceGrants:
		mutation, ok := oneValue[grantMutation](values)
		if !ok || mutation.Database.Validate() != nil || mutation.Principal.Validate() != nil || mutation.GrantSet.Validate() != nil {
			return "", ErrInvalidResource
		}
		return grantStatements(mutation)
	case sqlClearGrants:
		principal, ok := oneValue[DatabasePrincipal](values)
		if !ok || principal.Validate() != nil {
			return "", ErrInvalidResource
		}
		return "REVOKE ALL PRIVILEGES, GRANT OPTION FROM " + quotedAccount(principal) + ";\nSHOW GRANTS FOR " + quotedAccount(principal) + ";\n", nil
	case sqlObserveGrants:
		principal, ok := oneValue[DatabasePrincipal](values)
		if !ok || principal.Validate() != nil {
			return "", ErrInvalidResource
		}
		return "SHOW GRANTS FOR " + quotedAccount(principal) + ";\n", nil
	case sqlApplyExternalTuning:
		profile, ok := oneValue[TuningProfile](values)
		if !ok || profile.Validate() != nil {
			return "", ErrInvalidResource
		}
		settings := profile.Settings
		return "SET GLOBAL innodb_buffer_pool_size=" + strconv.FormatUint(settings.BufferPoolBytes, 10) + ";\n" +
			"SET GLOBAL max_connections=" + strconv.FormatUint(uint64(settings.MaxConnections), 10) + ";\n" +
			"SET GLOBAL tmp_table_size=" + strconv.FormatUint(settings.TempTableBytes, 10) + ";\n" +
			"SET GLOBAL max_heap_table_size=" + strconv.FormatUint(settings.TempTableBytes, 10) + ";\n" +
			"SET GLOBAL long_query_time=" + slowQuerySeconds(settings.SlowQueryMillis) + ";\n" + tuningObservation(), nil
	case sqlObserveTuning:
		if len(values) != 0 {
			return "", ErrInvalidCommand
		}
		return tuningObservation(), nil
	default:
		return "", ErrInvalidCommand
	}
}

func oneValue[T any](values []any) (T, bool) {
	var zero T
	if len(values) != 1 {
		return zero, false
	}
	value, ok := values[0].(T)
	return value, ok
}

func databaseObservation(database Database) string {
	return "SELECT DEFAULT_CHARACTER_SET_NAME,DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + database.Name.String() + "';\n"
}

func principalObservation(principal DatabasePrincipal) string {
	return "SELECT User,Host,plugin FROM mysql.user WHERE User='" + principal.Name.String() + "' AND Host='" + principalHost(principal) + "';\n"
}

func tuningObservation() string {
	return "SELECT @@innodb_buffer_pool_size,@@max_connections,@@tmp_table_size,@@max_heap_table_size,@@long_query_time,@@innodb_flush_method;\n"
}

func quotedIdentifier(identifier SQLIdentifier) string {
	return "`" + identifier.String() + "`"
}

func quotedAccount(principal DatabasePrincipal) string {
	return "'" + principal.Name.String() + "'@'" + principalHost(principal) + "'"
}

func principalHost(principal DatabasePrincipal) string {
	if principal.HostScope == HostScopeLoopback {
		return "localhost"
	}
	return "%"
}

func principalRequirements(principal DatabasePrincipal, mode TLSMode) string {
	requirement := " REQUIRE SSL"
	if mode == TLSMutual {
		requirement = " REQUIRE X509"
	}
	if principal.HostScope == HostScopeLoopback {
		requirement = ""
	}
	if principal.Disabled {
		return requirement + " ACCOUNT LOCK"
	}
	return requirement + " ACCOUNT UNLOCK"
}

func nativePasswordHash(password []byte) string {
	first := sha1.Sum(password)
	second := sha1.Sum(first[:])
	return "*" + strings.ToUpper(hex.EncodeToString(second[:]))
}

func grantStatements(mutation grantMutation) (string, error) {
	var script strings.Builder
	script.WriteString("REVOKE ALL PRIVILEGES, GRANT OPTION FROM ")
	script.WriteString(quotedAccount(mutation.Principal))
	script.WriteString(";\n")
	for _, grant := range mutation.GrantSet.Grants {
		privileges, err := privilegeList(grant.Privileges)
		if err != nil {
			return "", err
		}
		script.WriteString("GRANT ")
		script.WriteString(privileges)
		script.WriteString(" ON ")
		switch grant.Scope {
		case GrantScopeDatabase:
			script.WriteString(quotedIdentifier(mutation.Database.Name))
			script.WriteString(".*")
		case GrantScopeTable:
			script.WriteString(quotedIdentifier(mutation.Database.Name))
			script.WriteByte('.')
			script.WriteString(quotedIdentifier(grant.ObjectName))
		case GrantScopeRoutine:
			script.WriteString("PROCEDURE ")
			script.WriteString(quotedIdentifier(mutation.Database.Name))
			script.WriteByte('.')
			script.WriteString(quotedIdentifier(grant.ObjectName))
		default:
			return "", ErrInvalidResource
		}
		script.WriteString(" TO ")
		script.WriteString(quotedAccount(mutation.Principal))
		script.WriteString(";\n")
	}
	script.WriteString("SHOW GRANTS FOR ")
	script.WriteString(quotedAccount(mutation.Principal))
	script.WriteString(";\n")
	return script.String(), nil
}

func privilegeList(privileges []Privilege) (string, error) {
	result := make([]string, 0, len(privileges))
	for _, privilege := range privileges {
		var sqlName string
		switch privilege {
		case PrivilegeSelect:
			sqlName = "SELECT"
		case PrivilegeInsert:
			sqlName = "INSERT"
		case PrivilegeUpdate:
			sqlName = "UPDATE"
		case PrivilegeDelete:
			sqlName = "DELETE"
		case PrivilegeCreate:
			sqlName = "CREATE"
		case PrivilegeAlter:
			sqlName = "ALTER"
		case PrivilegeIndex:
			sqlName = "INDEX"
		case PrivilegeDrop:
			sqlName = "DROP"
		case PrivilegeCreateTemporary:
			sqlName = "CREATE TEMPORARY TABLES"
		case PrivilegeExecute:
			sqlName = "EXECUTE"
		case PrivilegeCreateView:
			sqlName = "CREATE VIEW"
		case PrivilegeShowView:
			sqlName = "SHOW VIEW"
		case PrivilegeTrigger:
			sqlName = "TRIGGER"
		case PrivilegeEvent:
			sqlName = "EVENT"
		default:
			return "", ErrInvalidResource
		}
		result = append(result, sqlName)
	}
	return strings.Join(result, ","), nil
}

func slowQuerySeconds(milliseconds uint32) string {
	seconds := milliseconds / 1000
	remainder := milliseconds % 1000
	return strconv.FormatUint(uint64(seconds), 10) + "." + fmt.Sprintf("%03d", remainder)
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	remaining int
	overflow  bool
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	if len(value) > buffer.remaining {
		value = value[:buffer.remaining]
		buffer.overflow = true
	}
	if len(value) > 0 {
		_, _ = buffer.buffer.Write(value)
		buffer.remaining -= len(value)
	}
	return original, nil
}

var _ io.Writer = (*limitedBuffer)(nil)
