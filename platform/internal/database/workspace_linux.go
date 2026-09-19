//go:build linux

package database

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var errWorkspaceOutputLimit = errors.New("workspace output limit")

type workspaceMariaDBConnection struct {
	arguments []string
}

const workspaceMetadataStatement = "SELECT IF(TABLE_TYPE='VIEW','view','table') AS entry_kind,TABLE_NAME AS object_name,'' AS name_value,CONCAT_WS(':',COALESCE(ENGINE,''),COALESCE(TABLE_COLLATION,'')) AS definition_value,0 AS ordinal_value,0 AS nullable_value,0 AS unique_value,'' AS column_name,'' AS referenced_table,'' AS referenced_column,COALESCE(TABLE_ROWS,0) AS row_estimate,COALESCE(DATA_LENGTH,0) AS data_bytes,COALESCE(INDEX_LENGTH,0) AS index_bytes,'' AS default_value FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() " +
	"UNION ALL SELECT 'column',TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,ORDINAL_POSITION,IF(IS_NULLABLE='YES',1,0),0,COLUMN_NAME,'','',0,0,0,COALESCE(COLUMN_DEFAULT,'') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() " +
	"UNION ALL SELECT 'index',TABLE_NAME,INDEX_NAME,INDEX_TYPE,SEQ_IN_INDEX,IF(NULLABLE='YES',1,0),IF(NON_UNIQUE=0,1,0),COALESCE(COLUMN_NAME,''),'','',0,0,0,'' FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() " +
	"UNION ALL SELECT 'constraint',tc.TABLE_NAME,tc.CONSTRAINT_NAME,tc.CONSTRAINT_TYPE,COALESCE(kcu.ORDINAL_POSITION,0),0,0,COALESCE(kcu.COLUMN_NAME,''),COALESCE(kcu.REFERENCED_TABLE_NAME,''),COALESCE(kcu.REFERENCED_COLUMN_NAME,''),0,0,0,'' FROM information_schema.TABLE_CONSTRAINTS tc LEFT JOIN information_schema.KEY_COLUMN_USAGE kcu ON kcu.CONSTRAINT_SCHEMA=tc.CONSTRAINT_SCHEMA AND kcu.TABLE_NAME=tc.TABLE_NAME AND kcu.CONSTRAINT_NAME=tc.CONSTRAINT_NAME WHERE tc.CONSTRAINT_SCHEMA=DATABASE() ORDER BY object_name,entry_kind,ordinal_value,name_value"

func (executor *LinuxMariaDBExecutor) BrowseWorkspaceMetadata(ctx context.Context, access WorkspaceAccess) (WorkspaceMetadataResult, error) {
	if executor == nil || executor.now == nil || ctx == nil {
		return WorkspaceMetadataResult{}, ErrInvalidCommand
	}
	bounded, cancel := workspaceContext(ctx, access, executor.now().UTC())
	defer cancel()
	connection, database, cleanup, err := executor.openWorkspace(bounded, access)
	if err != nil {
		return WorkspaceMetadataResult{}, err
	}
	defer cleanup()
	query, err := connection.query(bounded, WorkspaceStatementSelect, workspaceMetadataStatement, access.Limits)
	if err != nil {
		return WorkspaceMetadataResult{}, err
	}
	entries := make([]WorkspaceMetadataEntry, 0, len(query.Rows))
	for _, row := range query.Rows {
		entry, err := decodeWorkspaceMetadata(row)
		if err != nil {
			return WorkspaceMetadataResult{}, err
		}
		entries = append(entries, entry)
	}
	result := WorkspaceMetadataResult{Database: database.Name, Entries: entries, Truncated: query.Truncated}
	if err := validateWorkspaceMetadata(result, access); err != nil {
		return WorkspaceMetadataResult{}, err
	}
	return result, nil
}

func (executor *LinuxMariaDBExecutor) ExecuteWorkspaceStatement(ctx context.Context, access WorkspaceAccess, statement string) (WorkspaceQueryResult, error) {
	if executor == nil || executor.now == nil || ctx == nil {
		return WorkspaceQueryResult{}, ErrInvalidCommand
	}
	normalized, kind, err := ParseWorkspaceStatement(statement)
	if err != nil || normalized != statement {
		return WorkspaceQueryResult{}, ErrInvalidCommand
	}
	bounded, cancel := workspaceContext(ctx, access, executor.now().UTC())
	defer cancel()
	connection, _, cleanup, err := executor.openWorkspace(bounded, access)
	if err != nil {
		return WorkspaceQueryResult{}, err
	}
	defer cleanup()
	result, err := connection.query(bounded, kind, statement, access.Limits)
	if err != nil {
		return WorkspaceQueryResult{}, err
	}
	if err := validateWorkspaceResult(result, access); err != nil {
		return WorkspaceQueryResult{}, err
	}
	return result, nil
}

func (executor *LinuxMariaDBExecutor) openWorkspace(ctx context.Context, access WorkspaceAccess) (*workspaceMariaDBConnection, Database, func(), error) {
	if executor == nil || executor.secrets == nil || os.Geteuid() != 0 || ctx == nil || access.validate(executor.now().UTC()) != nil {
		return nil, Database{}, func() {}, ErrUnauthorized
	}
	bounded, cancel := workspaceContext(ctx, access, executor.now().UTC())
	session, database, principal, instance, err := executor.workspaceResources(bounded, access)
	if err != nil {
		cancel()
		return nil, Database{}, func() {}, err
	}
	release, err := executor.acquireWorkspace(session)
	if err != nil {
		cancel()
		return nil, Database{}, func() {}, err
	}
	password, err := executor.secrets.PrincipalPassword(bounded, session.SessionSecretRef, principal.ID, session.TenantID.String(), session.SiteID.String())
	if err != nil {
		release()
		cancel()
		return nil, Database{}, func() {}, err
	}
	if len(password) == 0 || len(password) > maximumSecretBytes {
		wipeBytes(password)
		release()
		cancel()
		return nil, Database{}, func() {}, ErrUnauthorized
	}
	connection, connectionCleanup, err := executor.workspaceConnection(bounded, instance, database, principal, password)
	wipeBytes(password)
	if err != nil {
		release()
		cancel()
		return nil, Database{}, func() {}, err
	}
	cleanup := func() {
		connectionCleanup()
		release()
		cancel()
	}
	return connection, database, cleanup, nil
}

func (executor *LinuxMariaDBExecutor) workspaceResources(ctx context.Context, access WorkspaceAccess) (DatabaseWorkspaceSession, Database, DatabasePrincipal, DatabaseInstance, error) {
	var session DatabaseWorkspaceSession
	if err := executor.readResource("sessions", access.SessionID, &session); err != nil {
		return session, Database{}, DatabasePrincipal{}, DatabaseInstance{}, err
	}
	if session.Validate() != nil || session.ID != access.SessionID || session.Generation != access.SessionGeneration || session.TenantID != access.TenantID ||
		session.SiteID != access.SiteID || session.DatabaseID != access.DatabaseID || session.PrincipalID != access.PrincipalID ||
		!session.ExpiresAt.Equal(access.ExpiresAt) || session.Limits != access.Limits || !session.ExpiresAt.After(executor.now().UTC()) {
		return session, Database{}, DatabasePrincipal{}, DatabaseInstance{}, ErrUnauthorized
	}
	var database Database
	if err := executor.readResource("databases", access.DatabaseID, &database); err != nil {
		return session, database, DatabasePrincipal{}, DatabaseInstance{}, err
	}
	if database.Validate() != nil || database.ID != access.DatabaseID || database.Generation != access.DatabaseGeneration ||
		database.TenantID != access.TenantID || database.SiteID != access.SiteID {
		return session, database, DatabasePrincipal{}, DatabaseInstance{}, ErrUnauthorized
	}
	var principal DatabasePrincipal
	if err := executor.readResource("principals", access.PrincipalID, &principal); err != nil {
		return session, database, principal, DatabaseInstance{}, err
	}
	if principal.Validate() != nil || principal.ID != access.PrincipalID || principal.Generation != access.PrincipalGeneration || principal.Disabled ||
		principal.TenantID != access.TenantID || principal.SiteID != access.SiteID || principal.InstanceID != database.InstanceID {
		return session, database, principal, DatabaseInstance{}, ErrUnauthorized
	}
	instance, err := executor.instance(database.InstanceID)
	if err != nil {
		return session, database, principal, instance, err
	}
	select {
	case <-ctx.Done():
		return session, database, principal, instance, ctx.Err()
	default:
	}
	return session, database, principal, instance, nil
}

func (executor *LinuxMariaDBExecutor) acquireWorkspace(session DatabaseWorkspaceSession) (func(), error) {
	executor.workspaceMu.Lock()
	defer executor.workspaceMu.Unlock()
	if executor.workspaceConnections == nil {
		executor.workspaceConnections = make(map[string]uint16)
	}
	key := session.ID.String()
	if executor.workspaceConnections[key] >= session.Limits.MaxConnections {
		return nil, ErrConflict
	}
	executor.workspaceConnections[key]++
	return func() {
		executor.workspaceMu.Lock()
		defer executor.workspaceMu.Unlock()
		if executor.workspaceConnections[key] <= 1 {
			delete(executor.workspaceConnections, key)
			return
		}
		executor.workspaceConnections[key]--
	}, nil
}

func (executor *LinuxMariaDBExecutor) workspaceConnection(ctx context.Context, instance DatabaseInstance, database Database, principal DatabasePrincipal, password []byte) (*workspaceMariaDBConnection, func(), error) {
	if instance.Validate() != nil || database.Validate() != nil || principal.Validate() != nil || len(password) == 0 {
		return nil, func() {}, ErrInvalidResource
	}
	runtimeDirectory, err := os.MkdirTemp(mariaDBRunRoot, "workspace-")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(runtimeDirectory) }
	if err := os.Chmod(runtimeDirectory, 0700); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	credentialValue, err := optionFileValue(password)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	credentialFile := filepath.Join(runtimeDirectory, "client.cnf")
	credential := []byte("[client]\nuser=" + principal.Name.String() + "\npassword=\"" + credentialValue + "\"\n")
	if err := atomicRootFile(credentialFile, credential, 0600); err != nil {
		wipeBytes(credential)
		cleanup()
		return nil, func() {}, err
	}
	wipeBytes(credential)
	arguments := []string{"--defaults-file=" + credentialFile, "--batch", "--binary-mode", "--xml", "--quick", "--binary-as-hex", "--connect-timeout=8", "--default-character-set=utf8mb4", "--database=" + database.Name.String()}
	if instance.Placement == PlacementLocal {
		arguments = append(arguments, "--protocol=socket", "--socket="+mariaDBSocket)
		return &workspaceMariaDBConnection{arguments: arguments}, cleanup, nil
	}
	if instance.External == nil || !sameServerName(instance.External.Endpoint.Host, instance.External.ServerName) || instance.External.RequiredTLS == TLSMutual {
		cleanup()
		return nil, func() {}, ErrUnauthorized
	}
	external := *instance.External
	ca, err := executor.secrets.PinnedCertificateAuthority(ctx, external.PinnedCASecretRef, external.CredentialAudience)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	defer wipeBytes(ca)
	pool := x509.NewCertPool()
	if len(ca) == 0 || len(ca) > maximumSecretBytes || !pool.AppendCertsFromPEM(ca) {
		cleanup()
		return nil, func() {}, ErrInvalidResource
	}
	caFile := filepath.Join(runtimeDirectory, "ca.pem")
	if err := atomicRootFile(caFile, ca, 0600); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	arguments = append(arguments, "--protocol=tcp", "--host="+external.Endpoint.Host, "--port="+strconv.FormatUint(uint64(external.Endpoint.Port), 10),
		"--ssl", "--ssl-ca="+caFile, "--ssl-verify-server-cert")
	return &workspaceMariaDBConnection{arguments: arguments}, cleanup, nil
}

func (connection *workspaceMariaDBConnection) query(ctx context.Context, kind WorkspaceStatementKind, statement string, limits SessionLimits) (WorkspaceQueryResult, error) {
	if connection == nil || ctx == nil || !validWorkspaceLimits(limits) {
		return WorkspaceQueryResult{}, ErrInvalidCommand
	}
	seconds := limits.StatementTimeout.Seconds()
	if seconds < 0.001 {
		seconds = 0.001
	}
	script := "SET STATEMENT max_statement_time=" + strconv.FormatFloat(seconds, 'f', 3, 64) + " FOR " + statement + ";\n"
	command := exec.CommandContext(ctx, "/usr/bin/mariadb", connection.arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/root"}
	command.Stdin = strings.NewReader(script)
	command.WaitDelay = 2 * time.Second
	stderr := &limitedBuffer{remaining: 64 << 10}
	command.Stderr = stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return WorkspaceQueryResult{}, err
	}
	if err := command.Start(); err != nil {
		return WorkspaceQueryResult{}, err
	}
	columns, rows, truncated, parseErr := parseWorkspaceXML(stdout, limits)
	if truncated && command.Process != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if ctx.Err() != nil {
		return WorkspaceQueryResult{}, ctx.Err()
	}
	if parseErr != nil {
		return WorkspaceQueryResult{}, parseErr
	}
	if waitErr != nil && !truncated {
		return WorkspaceQueryResult{}, fmt.Errorf("mariadb workspace query failed: %w", waitErr)
	}
	return WorkspaceQueryResult{Kind: kind, Columns: columns, Rows: rows, Truncated: truncated}, nil
}

type workspaceCountingReader struct {
	reader    io.Reader
	remaining int64
	exceeded  bool
}

func (reader *workspaceCountingReader) Read(buffer []byte) (int, error) {
	if reader.remaining <= 0 {
		reader.exceeded = true
		return 0, errWorkspaceOutputLimit
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	count, err := reader.reader.Read(buffer)
	reader.remaining -= int64(count)
	return count, err
}

func parseWorkspaceXML(reader io.Reader, limits SessionLimits) ([]WorkspaceColumn, []WorkspaceRow, bool, error) {
	rawLimit := int64(limits.MaxResultBytes)*2 + 1<<20
	counting := &workspaceCountingReader{reader: reader, remaining: rawLimit}
	decoder := xml.NewDecoder(counting)
	var columns []WorkspaceColumn
	rows := make([]WorkspaceRow, 0)
	var values []WorkspaceValue
	var names []string
	inRow := false
	var resultBytes uint64
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return columns, rows, false, nil
			}
			if errors.Is(err, errWorkspaceOutputLimit) || counting.exceeded {
				return columns, rows, true, nil
			}
			return nil, nil, false, ErrInvalidReceipt
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Local == "row" {
				inRow = true
				values = nil
				names = nil
				continue
			}
			if value.Name.Local != "field" || !inRow {
				continue
			}
			name := ""
			nullValue := false
			for _, attribute := range value.Attr {
				if attribute.Name.Local == "name" {
					name = attribute.Value
				}
				if attribute.Name.Local == "nil" && (attribute.Value == "true" || attribute.Value == "1") {
					nullValue = true
				}
			}
			if name == "" || len(name) > 1024 {
				return nil, nil, false, ErrInvalidReceipt
			}
			var textValue string
			if err := decoder.DecodeElement(&textValue, &value); err != nil {
				if errors.Is(err, errWorkspaceOutputLimit) || counting.exceeded {
					return columns, rows, true, nil
				}
				return nil, nil, false, ErrInvalidReceipt
			}
			names = append(names, name)
			if nullValue {
				values = append(values, WorkspaceValue{Kind: WorkspaceValueNull})
			} else {
				values = append(values, WorkspaceValue{Kind: WorkspaceValueText, Text: textValue})
			}
		case xml.EndElement:
			if value.Name.Local != "row" || !inRow {
				continue
			}
			inRow = false
			if columns == nil {
				columns = make([]WorkspaceColumn, len(names))
				for index, name := range names {
					columns[index] = WorkspaceColumn{Name: name, Type: WorkspaceValueText}
				}
			} else if len(names) != len(columns) {
				return nil, nil, false, ErrInvalidReceipt
			} else {
				for index, name := range names {
					if name != columns[index].Name {
						return nil, nil, false, ErrInvalidReceipt
					}
				}
			}
			if uint32(len(rows)) >= limits.MaxRows {
				return columns, rows, true, nil
			}
			row := WorkspaceRow{Values: append([]WorkspaceValue(nil), values...)}
			encoded, err := json.Marshal(row)
			if err != nil {
				return nil, nil, false, ErrInvalidReceipt
			}
			if resultBytes+uint64(len(encoded)) > limits.MaxResultBytes {
				return columns, rows, true, nil
			}
			resultBytes += uint64(len(encoded))
			rows = append(rows, row)
		}
	}
}

func decodeWorkspaceMetadata(row WorkspaceRow) (WorkspaceMetadataEntry, error) {
	if len(row.Values) != 14 {
		return WorkspaceMetadataEntry{}, ErrInvalidReceipt
	}
	text := func(index int) string {
		if row.Values[index].Kind == WorkspaceValueText {
			return row.Values[index].Text
		}
		return ""
	}
	number := func(index int, bits int) (uint64, error) {
		value := text(index)
		if value == "" {
			value = "0"
		}
		return strconv.ParseUint(value, 10, bits)
	}
	entry := WorkspaceMetadataEntry{Kind: WorkspaceMetadataKind(text(0)), ObjectName: text(1), Name: text(2), Definition: text(3),
		ColumnName: text(7), ReferencedTable: text(8), ReferencedColumn: text(9)}
	ordinal, err := number(4, 32)
	if err != nil { return WorkspaceMetadataEntry{}, ErrInvalidReceipt }
	nullable, err := number(5, 1)
	if err != nil { return WorkspaceMetadataEntry{}, ErrInvalidReceipt }
	unique, err := number(6, 1)
	if err != nil { return WorkspaceMetadataEntry{}, ErrInvalidReceipt }
	rowEstimate, err := number(10, 64)
	if err != nil { return WorkspaceMetadataEntry{}, ErrInvalidReceipt }
	dataBytes, err := number(11, 64)
	if err != nil { return WorkspaceMetadataEntry{}, ErrInvalidReceipt }
	indexBytes, err := number(12, 64)
	if err != nil { return WorkspaceMetadataEntry{}, ErrInvalidReceipt }
	entry.Ordinal = uint32(ordinal)
	entry.Nullable = nullable == 1
	entry.Unique = unique == 1
	entry.RowEstimate = rowEstimate
	entry.DataBytes = dataBytes
	entry.IndexBytes = indexBytes
	if defaultValue := text(13); defaultValue != "" {
		entry.Definition += " DEFAULT " + defaultValue
	}
	return entry, nil
}

var _ WorkspaceExecutor = (*LinuxMariaDBExecutor)(nil)
