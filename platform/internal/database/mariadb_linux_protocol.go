//go:build linux

package database

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/ha"
)

type mariaDBConnection struct {
	arguments []string
	executor *LinuxMariaDBExecutor
	localRoot bool
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
	sqlObserveHA
	sqlFreezeHA
	sqlPromoteHA
	sqlObserveNativePrincipal
	sqlStableGTIDCheckpoint
	sqlObserveReplication
	sqlConfigureReplication
	sqlWaitReplication
	sqlObserveReplicationPrincipal
	sqlCreateReplicationPrincipal
	sqlWriterSessionAudit
	sqlWriterSessions
	sqlKillWriterSession
	sqlStopWriterReplication
	sqlObserveDataDirectory
	sqlObserveImportTables
	sqlObserveImportSchema
	sqlCountImportRows
	sqlCheckImportTable
	sqlPromoteImportTables
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
		// --no-defaults must be first. Otherwise a root-owned client option file
		// can silently select another account, transport, or initialization path
		// and bypass the exclusive root@localhost unix_socket prerequisite.
		arguments := append([]string{"--no-defaults"}, base...)
		arguments = append(arguments, "--protocol=socket", "--socket="+mariaDBSocket, "--user=root")
		return &mariaDBConnection{arguments: arguments, executor:executor, localRoot:true}, func() {}, nil
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
	arguments := []string{"--defaults-file=" + credentialFile}
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
	if connection == nil || ctx == nil {
		return nil, ErrInvalidCommand
	}
	if connection.executor != nil {
		guarded,release,err:=connection.executor.guardRootSQL(ctx,statement)
		if err!=nil{return nil,err};defer release();ctx=guarded
	}
	if connection.localRoot {
		info, err := os.Lstat(mariaDBSocket)
		if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnauthorized
		}
	}
	script, err := buildMariaDBStatement(statement, value...)
	if err != nil {
		return nil, err
	}
	arguments:=connection.arguments
	if statement==sqlObserveReplication{arguments=append(append([]string(nil),arguments...),"--vertical")}
	command := exec.CommandContext(ctx, "/usr/bin/mariadb", arguments...)
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
	if statement==sqlWriterSessionAudit||statement==sqlWriterSessions||statement==sqlKillWriterSession||statement==sqlStopWriterReplication{return buildWriterGateStatement(statement,values...)}
	if statement==sqlObserveReplication||statement==sqlConfigureReplication||statement==sqlWaitReplication||statement==sqlObserveReplicationPrincipal||statement==sqlCreateReplicationPrincipal{return buildReplicationStatement(statement,values...)}
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
	case sqlObserveDataDirectory:
		if len(values) != 0 { return "", ErrInvalidCommand }
		return "SELECT @@datadir;\n", nil
	case sqlPromoteImportTables:
		rename,ok:=oneValue[isolatedTransferRename](values);if !ok{return "",ErrInvalidResource}
		return transferRenameSQL(rename)
	case sqlObserveImportTables:
		database,ok:=oneValue[Database](values)
		if !ok || database.Validate()!=nil{return "",ErrInvalidResource}
		return "SELECT HEX(TABLE_NAME),TABLE_TYPE,COALESCE(ENGINE,''),COALESCE(DATA_LENGTH,0)+COALESCE(INDEX_LENGTH,0) FROM information_schema.TABLES WHERE TABLE_SCHEMA='"+database.Name.String()+"' ORDER BY BINARY TABLE_NAME;\n",nil
	case sqlObserveImportSchema,sqlCountImportRows,sqlCheckImportTable:
		table,ok:=oneValue[isolatedTransferTable](values);if !ok{return "",ErrInvalidResource}
		name,err:=isolatedTableSQL(table);if err!=nil{return "",err}
		switch statement{
		case sqlObserveImportSchema:return "SHOW CREATE TABLE "+name+";\n",nil
		case sqlCountImportRows:return "SELECT COUNT(*) FROM "+name+";\n",nil
		default:return "CHECK TABLE "+name+" QUICK;\n",nil
		}
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
	case sqlStableGTIDCheckpoint:
		// One process owns the global read lock for both observations. Closing
		// its socket releases the lock even on cancellation or client failure.
		if len(values)!=0{return "",ErrInvalidResource}
		return "FLUSH TABLES WITH READ LOCK;\nSELECT @@server_id,@@hostname,@@read_only,@@gtid_binlog_pos,@@log_bin,@@gtid_strict_mode;\nSELECT @@server_id,@@hostname,@@read_only,@@gtid_binlog_pos,@@log_bin,@@gtid_strict_mode;\nUNLOCK TABLES;\n",nil
	case sqlObserveNativePrincipal:
		mutation,ok:=oneValue[principalMutation](values)
		if !ok||mutation.Principal.Validate()!=nil||mutation.Principal.CredentialFormat!=CredentialFormatNativeHash||!validNativePasswordHash(mutation.Password){return "",ErrInvalidResource}
		return "SELECT User,Host,plugin FROM mysql.user WHERE User='"+mutation.Principal.Name.String()+"' AND Host='"+principalHost(mutation.Principal)+"' AND plugin='mysql_native_password' AND authentication_string='"+string(mutation.Password)+"';\n",nil
	case sqlCreatePrincipal:
		mutation, ok := oneValue[principalMutation](values)
		if !ok || mutation.Principal.Validate() != nil || len(mutation.Password) == 0 {
			return "", ErrInvalidResource
		}
		hash,err:=principalAuthenticationHash(mutation);if err!=nil{return "",err}
		return "CREATE USER " + quotedAccount(mutation.Principal) + " IDENTIFIED VIA mysql_native_password USING '" + hash + "'" + principalRequirements(mutation.Principal, mutation.TLS) + ";\n" + principalObservation(mutation.Principal), nil
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
		hash,err:=principalAuthenticationHash(mutation);if err!=nil{return "",err}
		return "ALTER USER " + quotedAccount(mutation.Principal) + " IDENTIFIED VIA mysql_native_password USING '" + hash + "'" + principalRequirements(mutation.Principal, mutation.TLS) + ";\n" + principalObservation(mutation.Principal), nil
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
	case sqlObserveHA:
		if len(values) != 0 { return "", ErrInvalidCommand }
		return mariaDBHAObservation(), nil
	case sqlFreezeHA:
		if len(values) != 0 { return "", ErrInvalidCommand }
		return "SET GLOBAL read_only=ON;\n" + mariaDBHAObservation(), nil
	case sqlPromoteHA:
		if len(values) != 0 { return "", ErrInvalidCommand }
		return "SET GLOBAL read_only=OFF;\n" + mariaDBHAObservation(), nil
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

func mariaDBHAObservation() string {
	return "SELECT @@server_id,@@hostname,@@read_only,@@gtid_binlog_pos;\n"
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

func principalAuthenticationHash(mutation principalMutation)(string,error){
	switch mutation.Principal.CredentialFormat {
	case "":
		if bytes.HasPrefix(mutation.Password,[]byte(nativeHashCredentialPrefix)){return "",ErrInvalidResource}
		return nativePasswordHash(mutation.Password),nil
	case CredentialFormatNativeHash:
		if !validNativePasswordHash(mutation.Password){return "",ErrInvalidResource};return string(mutation.Password),nil
	default:return "",ErrInvalidResource
	}
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
			// Database-wide GRANT names are patterns even inside backticks.
			// SQLIdentifier permits underscores, which must remain literal here.
			script.WriteString("`" + strings.ReplaceAll(mutation.Database.Name.String(), "_", "\\_") + "`")
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

type localMariaDBHAReceipt struct {
	EffectID     string          `json:"effect_id"`
	Action       MariaDBHAAction `json:"action"`
	ClusterID    ha.ID           `json:"cluster_id"`
	NodeID       ha.NodeID       `json:"node_id"`
	FencingToken uint64          `json:"fencing_token"`
	LeaseID      ha.WriterLeaseID `json:"lease_id,omitempty"`
	ReadOnly     bool            `json:"read_only"`
	GTID         string          `json:"gtid"`
	Frontier     uint64          `json:"frontier"`
	ProofDigest  string          `json:"proof_digest"`
	AppliedAt    time.Time       `json:"applied_at"`
}

type localMariaDBPermitKey struct { Key string `json:"key"` }

func (executor *LinuxMariaDBExecutor) ObserveCluster(ctx context.Context, cluster ha.DatabaseCluster) (ha.DatabaseCluster, error) {
	if executor == nil || ctx == nil || !validLocalHACluster(cluster) { return ha.DatabaseCluster{}, ErrInvalidCommand }
	executor.mu.Lock()
	defer executor.mu.Unlock()
	member, _, err := executor.observeLocalHAMember(ctx)
	if err != nil { return ha.DatabaseCluster{}, err }
	found := false
	for index := range cluster.Members {
		if cluster.Members[index].NodeID == ha.NodeID("local") {
			member.PeerCIDRs = append([]string(nil), cluster.Members[index].PeerCIDRs...)
			cluster.Members[index] = member
			found = true
			break
		}
	}
	if !found { return ha.DatabaseCluster{}, ErrInvalidResource }
	if member.ReadOnly {
		if cluster.WriterNodeID == member.NodeID { cluster.WriterNodeID, cluster.WriterLeaseID = "", "" }
	} else {
		cluster.WriterNodeID = member.NodeID
	}
	cluster.UpdatedAt = member.ObservedAt
	if cluster.Validate() != nil { return ha.DatabaseCluster{}, ErrInvalidResource }
	return cluster, nil
}

func (executor *LinuxMariaDBExecutor) FreezeDatabaseWrites(ctx context.Context, cluster ha.DatabaseCluster, node ha.NodeID, fencingToken uint64) (string, error) {
	return executor.applyLocalHA(ctx, MariaDBHAFreeze, cluster, node, fencingToken, "", sqlFreezeHA, true)
}

func (executor *LinuxMariaDBExecutor) PromoteDatabaseWriter(ctx context.Context, cluster ha.DatabaseCluster, node ha.NodeID, lease ha.WriterLease) (string, uint64, error) {
	return executor.activateDatabaseWriter(ctx,cluster,node,lease)
}

func (executor *LinuxMariaDBExecutor) DemoteDatabaseWriter(ctx context.Context, cluster ha.DatabaseCluster, node ha.NodeID, fencingToken uint64) (string, error) {
	return executor.applyLocalHA(ctx, MariaDBHADemote, cluster, node, fencingToken, "", sqlFreezeHA, true)
}

func (executor *LinuxMariaDBExecutor) SignWritePermit(ctx context.Context, permit ha.WritePermit) (ha.WritePermit, error) {
	if executor == nil || ctx == nil || permit.ResourceID != "mariadb-local" || permit.NodeID == "" || permit.LeaseID == "" || permit.FencingToken == 0 || permit.AuthorityEpoch == 0 || len(permit.WritePaths) == 0 || permit.Signature != "" || permit.IssuedAt.IsZero() || !permit.ExpiresAt.After(permit.IssuedAt) || !executor.now().UTC().Before(permit.ExpiresAt) {
		return ha.WritePermit{}, ErrInvalidCommand
	}
	select { case <-ctx.Done(): return ha.WritePermit{}, ctx.Err(); default: }
	executor.mu.Lock()
	defer executor.mu.Unlock()
	guarded,release,gateErr:=executor.beginWriterMutation(ctx)
	if gateErr!=nil{return ha.WritePermit{},gateErr};defer release();ctx=guarded
	executor.writer.mu.Lock();active,managed:=executor.writer.active,executor.writer.managed;executor.writer.mu.Unlock()
	if managed{
		if active==nil{return ha.WritePermit{},ErrUnauthorized}
		permitNode:=permit.NodeID;if permitNode==ha.NodeID("local"){permitNode=active.Certificate.Candidate}
		if active.Certificate.Candidate!=permitNode||active.Certificate.Lease.ID!=permit.LeaseID||active.Certificate.Lease.FencingToken!=permit.FencingToken||active.Certificate.Lease.AuthorityEpoch!=permit.AuthorityEpoch||active.Certificate.Lease.ResourceID!=permit.ResourceID||!sameWriterValue(active.Certificate.Lease.EnforcedWritePaths,permit.WritePaths)||permit.IssuedAt.Before(active.Certificate.Lease.IssuedAt)||permit.IssuedAt.After(executor.now().UTC().Add(5*time.Second))||permit.ExpiresAt.After(active.Certificate.ExpiresAt)||permit.ExpiresAt.After(active.Certificate.Lease.ExpiresAt){return ha.WritePermit{},ErrUnauthorized}
	}
	if !managed&&permit.NodeID!=ha.NodeID("local"){return ha.WritePermit{},ErrUnauthorized}
	key, err := executor.localHAPermitKey()
	if err != nil { return ha.WritePermit{}, err }
	unsigned, err := json.Marshal(struct {
		Domain string         `json:"domain"`
		Permit ha.WritePermit `json:"permit"`
	}{Domain:"cyberpanel-local-mariadb-write-permit-v1", Permit:permit})
	if err != nil { wipeBytes(key); return ha.WritePermit{}, err }
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(unsigned)
	permit.Signature = "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	wipeBytes(key, unsigned)
	return permit, nil
}

func validLocalHACluster(cluster ha.DatabaseCluster) bool {
	return cluster.Validate() == nil && cluster.ID == ha.ID("mariadb-local") && cluster.Topology == ha.DatabasePrimaryReplica
}

func (executor *LinuxMariaDBExecutor) applyLocalHA(ctx context.Context, action MariaDBHAAction, cluster ha.DatabaseCluster, node ha.NodeID, fencingToken uint64, leaseID ha.WriterLeaseID, statement mariaDBStatement, wantReadOnly bool) (string, error) {
	if executor == nil || ctx == nil || !validLocalHACluster(cluster) || node != ha.NodeID("local") || fencingToken == 0 { return "", ErrInvalidCommand }
	if !wantReadOnly||statement!=sqlFreezeHA||(action!=MariaDBHAFreeze&&action!=MariaDBHADemote)||leaseID!=""{return "",ErrUnauthorized}
	effectID := localMariaDBHAEffectID(action, cluster.ID, node, fencingToken, leaseID)
	executor.mu.Lock()
	defer executor.mu.Unlock()
	var cursor localMariaDBHAReceipt
	if cursorErr:=executor.readNamed("effects","ha-fence-cursor.json",&cursor);cursorErr==nil{
		if cursor.ClusterID!=cluster.ID||fencingToken<cursor.FencingToken{return "",ErrUnauthorized}
	}else if !errors.Is(cursorErr,ErrNotFound){return "",cursorErr}
	if err:=executor.latchWriterGate("explicit_fence");err!=nil{return "",err}
	if err:=executor.closeWriterGate(ctx,"explicit_fence");err!=nil{return "",err}
	var existing localMariaDBHAReceipt
	if err := executor.readNamed("effects", effectID+".json", &existing); err == nil {
		if existing.EffectID != effectID || existing.Action != action || existing.ClusterID != cluster.ID || existing.NodeID != node || existing.FencingToken != fencingToken || existing.LeaseID != leaseID || existing.ReadOnly != wantReadOnly || existing.ProofDigest == "" || existing.AppliedAt.IsZero() {
			return "", ErrIdempotency
		}
		if cursor.EffectID!=effectID{return "",ErrUnauthorized}
		if err=executor.writeNamed("effects","ha-fence-cursor.json",existing);err!=nil{return "",err}
		encoded, encodeErr := json.Marshal(existing)
		return string(encoded), encodeErr
	} else if !errors.Is(err, ErrNotFound) { return "", err }
	instanceID, err := NewResourceID(string(cluster.ID))
	if err != nil { return "", err }
	instance, err := executor.instance(instanceID)
	if err != nil || instance.Placement != PlacementLocal { return "", errors.Join(err, ErrInvalidResource) }
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil { return "", err }
	defer cleanup()
	if err=executor.writeNamed("effects","ha-fence-cursor.json",localMariaDBHAReceipt{EffectID:effectID,Action:action,ClusterID:cluster.ID,NodeID:node,FencingToken:fencingToken,LeaseID:leaseID,ReadOnly:wantReadOnly});err!=nil{return "",err}
	fenceContext:=context.WithValue(ctx,writerFenceCapability{},true)
	output, err := connection.query(fenceContext, statement)
	if err != nil { return "", errors.Join(ErrAmbiguous, err) }
	member, proof, err := parseLocalHAMember(output, executor.now().UTC())
	if err != nil || member.ReadOnly != wantReadOnly { return "", errors.Join(ErrAmbiguous, err) }
	receipt := localMariaDBHAReceipt{EffectID:effectID, Action:action, ClusterID:cluster.ID, NodeID:node, FencingToken:fencingToken, LeaseID:leaseID, ReadOnly:member.ReadOnly, GTID:member.GTID, Frontier:member.Sequence, ProofDigest:proof, AppliedAt:member.ObservedAt}
	if err = executor.writeNamed("effects", effectID+".json", receipt); err != nil { return "", errors.Join(ErrAmbiguous, err) }
	if err=executor.writeNamed("effects","ha-fence-cursor.json",receipt);err!=nil{return "",errors.Join(ErrAmbiguous,err)}
	encoded, err := json.Marshal(receipt)
	if err != nil { return "", err }
	return string(encoded), nil
}

func (executor *LinuxMariaDBExecutor) observeLocalHAMember(ctx context.Context) (ha.DatabaseMember, string, error) {
	instanceID, err := NewResourceID("mariadb-local")
	if err != nil { return ha.DatabaseMember{}, "", err }
	instance, err := executor.instance(instanceID)
	if err != nil || instance.Placement != PlacementLocal { return ha.DatabaseMember{}, "", errors.Join(err, ErrInvalidResource) }
	connection, cleanup, err := executor.connection(ctx, instance)
	if err != nil { return ha.DatabaseMember{}, "", err }
	defer cleanup()
	output, err := connection.query(ctx, sqlObserveHA)
	if err != nil { return ha.DatabaseMember{}, "", err }
	return parseLocalHAMember(output, executor.now().UTC())
}

func parseLocalHAMember(output []byte, observedAt time.Time) (ha.DatabaseMember, string, error) {
	line := strings.TrimSuffix(strings.TrimSuffix(string(output), "\n"), "\r")
	fields := strings.Split(line, "\t")
	if len(fields) != 4 || observedAt.IsZero() || strings.TrimSpace(fields[0]) == "" || strings.TrimSpace(fields[1]) == "" || fields[2] != "0" && fields[2] != "1" {
		return ha.DatabaseMember{}, "", ErrInvalidResource
	}
	frontier, err := mariaDBGTIDFrontier(strings.TrimSpace(fields[3]))
	if err != nil { return ha.DatabaseMember{}, "", err }
	identity := sha256.Sum256([]byte(fields[0] + "\x00" + fields[1]))
	proof := sha256.Sum256(output)
	member := ha.DatabaseMember{NodeID:ha.NodeID("local"), ServerUUID:"mariadb-"+hex.EncodeToString(identity[:16]), State:ha.DBSynced, ClusterStatus:"Primary", GTID:strings.TrimSpace(fields[3]), Sequence:frontier, ReadOnly:fields[2]=="1", PublicListener:false, ObservedAt:observedAt.UTC()}
	return member, hex.EncodeToString(proof[:]), nil
}

func mariaDBGTIDFrontier(value string) (uint64, error) {
	if value == "" { return 0, nil }
	var frontier uint64
	for _, item := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(item), "-")
		if len(parts) != 3 { return 0, ErrInvalidResource }
		sequence, err := strconv.ParseUint(parts[2], 10, 64)
		if err != nil { return 0, ErrInvalidResource }
		if sequence > frontier { frontier = sequence }
	}
	return frontier, nil
}

func localMariaDBHAEffectID(action MariaDBHAAction, cluster ha.ID, node ha.NodeID, token uint64, lease ha.WriterLeaseID) string {
	sum := sha256.Sum256([]byte("cyberpanel-local-mariadb-ha-v1\x00"+string(action)+"\x00"+string(cluster)+"\x00"+string(node)+"\x00"+strconv.FormatUint(token,10)+"\x00"+string(lease)))
	return "ha-" + string(action) + "-" + hex.EncodeToString(sum[:24])
}

func (executor *LinuxMariaDBExecutor) localHAPermitKey() ([]byte, error) {
	const name = "ha-permit-key.json"
	var stored localMariaDBPermitKey
	if err := executor.readNamed("effects", name, &stored); err == nil {
		key, decodeErr := hex.DecodeString(stored.Key)
		if decodeErr != nil || len(key) != 32 { wipeBytes(key); return nil, ErrInvalidResource }
		return key, nil
	} else if !errors.Is(err, ErrNotFound) { return nil, err }
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil { return nil, err }
	stored.Key = hex.EncodeToString(key)
	if err := executor.writeNamed("effects", name, stored); err != nil { wipeBytes(key); return nil, err }
	return key, nil
}

var _ ha.DatabaseReplicationExecutor = (*LinuxMariaDBExecutor)(nil)
var _ ha.WritePermitSigner = (*LinuxMariaDBExecutor)(nil)

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
