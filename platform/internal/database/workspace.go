package database

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

const MaximumWorkspaceStatementBytes = 256 << 10

type WorkspaceCall struct {
	TenantID          site.TenantID
	SiteID            site.SiteID
	SessionID         ResourceID
	SessionGeneration uint64
}

type WorkspaceAccess struct {
	TenantID           site.TenantID `json:"tenant_id"`
	SiteID             site.SiteID   `json:"site_id"`
	SessionID          ResourceID    `json:"session_id"`
	SessionGeneration  uint64        `json:"session_generation"`
	DatabaseID         ResourceID    `json:"database_id"`
	DatabaseGeneration uint64        `json:"database_generation"`
	PrincipalID        ResourceID    `json:"principal_id"`
	PrincipalGeneration uint64       `json:"principal_generation"`
	ExpiresAt          time.Time     `json:"expires_at"`
	Limits             SessionLimits `json:"limits"`
}

type WorkspaceStatementKind string

const (
	WorkspaceStatementSelect   WorkspaceStatementKind = "select"
	WorkspaceStatementShow     WorkspaceStatementKind = "show"
	WorkspaceStatementDescribe WorkspaceStatementKind = "describe"
	WorkspaceStatementExplain  WorkspaceStatementKind = "explain"
)

type WorkspaceValueKind string

const (
	WorkspaceValueNull WorkspaceValueKind = "null"
	WorkspaceValueText WorkspaceValueKind = "text"
)

type WorkspaceColumn struct {
	Name string             `json:"name"`
	Type WorkspaceValueKind `json:"type"`
}

type WorkspaceValue struct {
	Kind WorkspaceValueKind `json:"kind"`
	Text string             `json:"text,omitempty"`
}

type WorkspaceRow struct {
	Values []WorkspaceValue `json:"values"`
}

type WorkspaceQueryResult struct {
	Kind      WorkspaceStatementKind `json:"kind"`
	Columns   []WorkspaceColumn       `json:"columns"`
	Rows      []WorkspaceRow          `json:"rows"`
	Truncated bool                    `json:"truncated"`
}

type WorkspaceMetadataKind string

const (
	WorkspaceMetadataTable      WorkspaceMetadataKind = "table"
	WorkspaceMetadataView       WorkspaceMetadataKind = "view"
	WorkspaceMetadataColumn     WorkspaceMetadataKind = "column"
	WorkspaceMetadataIndex      WorkspaceMetadataKind = "index"
	WorkspaceMetadataConstraint WorkspaceMetadataKind = "constraint"
)

type WorkspaceMetadataEntry struct {
	Kind             WorkspaceMetadataKind `json:"kind"`
	ObjectName       string                `json:"object_name"`
	Name             string                `json:"name,omitempty"`
	Definition       string                `json:"definition,omitempty"`
	Ordinal          uint32                `json:"ordinal,omitempty"`
	Nullable         bool                  `json:"nullable,omitempty"`
	Unique           bool                  `json:"unique,omitempty"`
	ColumnName       string                `json:"column_name,omitempty"`
	ReferencedTable  string                `json:"referenced_table,omitempty"`
	ReferencedColumn string                `json:"referenced_column,omitempty"`
	RowEstimate      uint64                `json:"row_estimate,omitempty"`
	DataBytes        uint64                `json:"data_bytes,omitempty"`
	IndexBytes       uint64                `json:"index_bytes,omitempty"`
}

type WorkspaceMetadataResult struct {
	Database  SQLIdentifier             `json:"database"`
	Entries   []WorkspaceMetadataEntry  `json:"entries"`
	Truncated bool                      `json:"truncated"`
}

type WorkspaceService interface {
	BrowseWorkspaceMetadata(context.Context, WorkspaceCall) (WorkspaceMetadataResult, error)
	ExecuteWorkspaceStatement(context.Context, WorkspaceCall, string) (WorkspaceQueryResult, error)
}

type WorkspaceExecutor interface {
	BrowseWorkspaceMetadata(context.Context, WorkspaceAccess) (WorkspaceMetadataResult, error)
	ExecuteWorkspaceStatement(context.Context, WorkspaceAccess, string) (WorkspaceQueryResult, error)
}

func (coordinator Coordinator) BrowseWorkspaceMetadata(ctx context.Context, call WorkspaceCall) (WorkspaceMetadataResult, error) {
	access, err := coordinator.authorizeWorkspace(ctx, call)
	if err != nil {
		return WorkspaceMetadataResult{}, err
	}
	executor, ok := coordinator.executor.(WorkspaceExecutor)
	if !ok {
		return WorkspaceMetadataResult{}, ErrInvalidCommand
	}
	bounded, cancel := workspaceContext(ctx, access, coordinator.clock.Now().UTC())
	defer cancel()
	return executor.BrowseWorkspaceMetadata(bounded, access)
}

func (coordinator Coordinator) ExecuteWorkspaceStatement(ctx context.Context, call WorkspaceCall, statement string) (WorkspaceQueryResult, error) {
	normalized, _, err := ParseWorkspaceStatement(statement)
	if err != nil {
		return WorkspaceQueryResult{}, err
	}
	access, err := coordinator.authorizeWorkspace(ctx, call)
	if err != nil {
		return WorkspaceQueryResult{}, err
	}
	executor, ok := coordinator.executor.(WorkspaceExecutor)
	if !ok {
		return WorkspaceQueryResult{}, ErrInvalidCommand
	}
	bounded, cancel := workspaceContext(ctx, access, coordinator.clock.Now().UTC())
	defer cancel()
	return executor.ExecuteWorkspaceStatement(bounded, access, normalized)
}

func (coordinator Coordinator) authorizeWorkspace(ctx context.Context, call WorkspaceCall) (WorkspaceAccess, error) {
	if coordinator.repository == nil || coordinator.executor == nil || coordinator.clock == nil || ctx == nil ||
		call.TenantID.String() == "" || call.SiteID.String() == "" || call.SessionID.IsZero() || call.SessionGeneration == 0 {
		return WorkspaceAccess{}, ErrInvalidCommand
	}
	envelope, err := coordinator.repository.LoadResource(ctx, KindConsoleSession, call.SessionID)
	if err != nil {
		return WorkspaceAccess{}, err
	}
	decoded, err := DecodeResource(envelope)
	if err != nil {
		return WorkspaceAccess{}, err
	}
	session, ok := decoded.(*DatabaseWorkspaceSession)
	now := coordinator.clock.Now().UTC()
	if !ok || session.Generation != call.SessionGeneration || session.TenantID != call.TenantID || session.SiteID != call.SiteID ||
		!workspaceReady(session.Metadata) || !session.ExpiresAt.After(now) {
		return WorkspaceAccess{}, ErrUnauthorized
	}
	databaseEnvelope, err := coordinator.repository.LoadResource(ctx, KindDatabase, session.DatabaseID)
	if err != nil {
		return WorkspaceAccess{}, err
	}
	databaseResource, err := DecodeResource(databaseEnvelope)
	if err != nil {
		return WorkspaceAccess{}, err
	}
	database, ok := databaseResource.(*Database)
	if !ok || database.TenantID != call.TenantID || database.SiteID != call.SiteID || !workspaceReady(database.Metadata) {
		return WorkspaceAccess{}, ErrUnauthorized
	}
	principalEnvelope, err := coordinator.repository.LoadResource(ctx, KindPrincipal, session.PrincipalID)
	if err != nil {
		return WorkspaceAccess{}, err
	}
	principalResource, err := DecodeResource(principalEnvelope)
	if err != nil {
		return WorkspaceAccess{}, err
	}
	principal, ok := principalResource.(*DatabasePrincipal)
	if !ok || principal.TenantID != call.TenantID || principal.SiteID != call.SiteID || principal.Disabled ||
		principal.InstanceID != database.InstanceID || !workspaceReady(principal.Metadata) {
		return WorkspaceAccess{}, ErrUnauthorized
	}
	access := WorkspaceAccess{
		TenantID: call.TenantID, SiteID: call.SiteID, SessionID: session.ID, SessionGeneration: session.Generation,
		DatabaseID: database.ID, DatabaseGeneration: database.Generation, PrincipalID: principal.ID,
		PrincipalGeneration: principal.Generation, ExpiresAt: session.ExpiresAt.UTC(), Limits: session.Limits,
	}
	if access.validate(now) != nil {
		return WorkspaceAccess{}, ErrInvalidCommand
	}
	return access, nil
}

func workspaceReady(metadata Metadata) bool {
	return metadata.Generation != 0 && metadata.Status.Lifecycle == LifecycleReady &&
		metadata.Status.Reconciliation == ReconciliationInSync && metadata.Status.ObservedGeneration == metadata.Generation
}

func (access WorkspaceAccess) validate(now time.Time) error {
	if access.TenantID.String() == "" || access.SiteID.String() == "" || access.SessionID.IsZero() || access.SessionGeneration == 0 ||
		access.DatabaseID.IsZero() || access.DatabaseGeneration == 0 || access.PrincipalID.IsZero() || access.PrincipalGeneration == 0 ||
		!access.ExpiresAt.After(now) || !validWorkspaceLimits(access.Limits) {
		return ErrInvalidCommand
	}
	return nil
}

func validWorkspaceLimits(limits SessionLimits) bool {
	return limits.StatementTimeout > 0 && limits.StatementTimeout <= 2*time.Minute && limits.MaxRows > 0 && limits.MaxRows <= 100000 &&
		limits.MaxResultBytes > 0 && limits.MaxResultBytes <= 64<<20 && limits.MaxConnections > 0 && limits.MaxConnections <= 8
}

func workspaceContext(ctx context.Context, access WorkspaceAccess, now time.Time) (context.Context, context.CancelFunc) {
	deadline := now.Add(access.Limits.StatementTimeout)
	if access.ExpiresAt.Before(deadline) {
		deadline = access.ExpiresAt
	}
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	return context.WithDeadline(ctx, deadline)
}

func validateWorkspaceResult(result WorkspaceQueryResult, access WorkspaceAccess) error {
	if result.Kind != WorkspaceStatementSelect && result.Kind != WorkspaceStatementShow && result.Kind != WorkspaceStatementDescribe && result.Kind != WorkspaceStatementExplain {
		return ErrInvalidReceipt
	}
	if uint64(len(result.Rows)) > uint64(access.Limits.MaxRows) || len(result.Columns) > 4096 {
		return ErrInvalidReceipt
	}
	for _, column := range result.Columns {
		if column.Name == "" || len(column.Name) > 1024 || column.Type != WorkspaceValueText {
			return ErrInvalidReceipt
		}
	}
	for _, row := range result.Rows {
		if len(row.Values) != len(result.Columns) {
			return ErrInvalidReceipt
		}
		for _, value := range row.Values {
			if value.Kind != WorkspaceValueNull && value.Kind != WorkspaceValueText || value.Kind == WorkspaceValueNull && value.Text != "" {
				return ErrInvalidReceipt
			}
		}
	}
	return nil
}

func validateWorkspaceMetadata(result WorkspaceMetadataResult, access WorkspaceAccess) error {
	if result.Database.IsZero() || uint64(len(result.Entries)) > uint64(access.Limits.MaxRows) {
		return ErrInvalidReceipt
	}
	for _, entry := range result.Entries {
		switch entry.Kind {
		case WorkspaceMetadataTable, WorkspaceMetadataView, WorkspaceMetadataColumn, WorkspaceMetadataIndex, WorkspaceMetadataConstraint:
		default:
			return ErrInvalidReceipt
		}
		if entry.ObjectName == "" || len(entry.ObjectName) > 64 || len(entry.Name) > 64 || len(entry.Definition) > 4096 {
			return ErrInvalidReceipt
		}
	}
	return nil
}

func ParseWorkspaceStatement(raw string) (string, WorkspaceStatementKind, error) {
	if raw == "" || len(raw) > MaximumWorkspaceStatementBytes || !utf8.ValidString(raw) || strings.IndexByte(raw, 0) >= 0 {
		return "", "", ErrInvalidCommand
	}
	tokens, semicolon, err := workspaceTokens(raw)
	if err != nil || len(tokens) == 0 {
		return "", "", ErrInvalidCommand
	}
	var kind WorkspaceStatementKind
	switch tokens[0] {
	case "SELECT":
		kind = WorkspaceStatementSelect
	case "SHOW":
		kind = WorkspaceStatementShow
		if !safeWorkspaceShow(tokens) {
			return "", "", ErrUnauthorized
		}
	case "DESCRIBE", "DESC":
		kind = WorkspaceStatementDescribe
	case "EXPLAIN":
		kind = WorkspaceStatementExplain
		foundSelect := false
		for _, token := range tokens[1:] {
			if token == "SELECT" {
				foundSelect = true
				break
			}
		}
		if !foundSelect {
			return "", "", ErrUnauthorized
		}
	default:
		return "", "", ErrUnauthorized
	}
	denied := map[string]struct{}{
		"ALTER": {}, "ANALYZE": {}, "BENCHMARK": {}, "BINLOG": {}, "CALL": {}, "CHARSET": {}, "COMMIT": {}, "CONNECT": {}, "CREATE": {},
		"DEALLOCATE": {}, "DELETE": {}, "DELIMITER": {}, "DO": {}, "DROP": {}, "DUMPFILE": {}, "EGO": {}, "EXECUTE": {}, "EXIT": {}, "EXPORT": {},
		"FILE": {}, "FLUSH": {}, "FUNCTION": {}, "GET_LOCK": {}, "GLOBAL": {}, "GRANT": {}, "HANDLER": {},
		"GO": {}, "HELP": {}, "IMPORT": {}, "INFORMATION_SCHEMA": {}, "INSERT": {}, "INSTALL": {}, "INTO": {}, "KILL": {}, "LOAD": {},
		"LOAD_FILE": {}, "LOCK": {}, "MASTER": {}, "MYSQL": {}, "OPTIMIZE": {}, "OUTFILE": {}, "PERFORMANCE_SCHEMA": {},
		"NOPAGER": {}, "NOTEE": {}, "PAGER": {}, "PERSIST": {}, "PERSIST_ONLY": {}, "PLUGIN": {}, "PLUGINS": {}, "PREPARE": {}, "PRINT": {}, "PROCESSLIST": {}, "PROMPT": {}, "PURGE": {}, "QUIT": {}, "REHASH": {},
		"RELEASE_LOCK": {}, "RENAME": {}, "REPAIR": {}, "REPLACE": {}, "RESET": {}, "REVOKE": {}, "ROLLBACK": {},
		"SET": {}, "SHUTDOWN": {}, "SIGNAL": {}, "SLAVE": {}, "SLEEP": {}, "SONAME": {}, "SOURCE": {}, "START": {}, "STATUS": {}, "STOP": {},
		"SYS": {}, "SYS_EVAL": {}, "SYS_EXEC": {}, "SYSTEM": {}, "TRUNCATE": {}, "UDF": {}, "UNINSTALL": {},
		"UNLOCK": {}, "UPDATE": {}, "USE": {}, "VARIABLES": {}, "TEE": {},
	}
	for index, token := range tokens {
		if _, blocked := denied[token]; !blocked {
			continue
		}
		if kind == WorkspaceStatementShow && token == "CREATE" && index == 1 {
			continue
		}
		return "", "", ErrUnauthorized
	}
	normalized := strings.TrimSpace(raw)
	if semicolon {
		normalized = strings.TrimSpace(normalized[:len(normalized)-1])
	}
	return normalized, kind, nil
}

func safeWorkspaceShow(tokens []string) bool {
	if len(tokens) < 2 {
		return false
	}
	index := 1
	if tokens[index] == "FULL" {
		index++
		if index >= len(tokens) {
			return false
		}
	}
	switch tokens[index] {
	case "TABLES", "COLUMNS", "FIELDS", "INDEX", "INDEXES", "KEYS":
		return true
	case "CREATE":
		return index+1 < len(tokens) && (tokens[index+1] == "TABLE" || tokens[index+1] == "VIEW")
	default:
		return false
	}
}

func workspaceTokens(raw string) ([]string, bool, error) {
	tokens := make([]string, 0, 32)
	semicolon := false
	for index := 0; index < len(raw); {
		character := raw[index]
		if character == ';' {
			if semicolon || strings.TrimSpace(raw[index+1:]) != "" {
				return nil, false, ErrInvalidCommand
			}
			semicolon = true
			index++
			continue
		}
		if character == '\\' || character == '@' || character == '#' || character == '/' && index+1 < len(raw) && raw[index+1] == '*' ||
			character == '-' && index+1 < len(raw) && raw[index+1] == '-' {
			return nil, false, ErrUnauthorized
		}
		if character == '\'' || character == '"' || character == '`' {
			quote := character
			start := index + 1
			index++
			var quoted strings.Builder
			for index < len(raw) {
				character = raw[index]
				if character == '\\' {
					if index+1 >= len(raw) {
						return nil, false, ErrInvalidCommand
					}
					if quote == '`' {
						quoted.WriteByte(raw[index+1])
					}
					index += 2
					continue
				}
				if character == quote {
					if index+1 < len(raw) && raw[index+1] == quote {
						if quote == '`' {
							quoted.WriteByte(quote)
						}
						index += 2
						continue
					}
					if quote == '`' {
						if quoted.Len() == 0 {
							quoted.WriteString(raw[start:index])
						}
						tokens = append(tokens, strings.ToUpper(quoted.String()))
					}
					index++
					goto quoteClosed
				}
				if quote == '`' {
					quoted.WriteByte(character)
				}
				index++
			}
			return nil, false, ErrInvalidCommand
		quoteClosed:
			continue
		}
		if character >= 0x80 {
			return nil, false, ErrInvalidCommand
		}
		if asciiLetter(character) || asciiDigit(character) || character == '_' || character == '$' {
			start := index
			for index < len(raw) && (asciiLetter(raw[index]) || asciiDigit(raw[index]) || raw[index] == '_' || raw[index] == '$') {
				index++
			}
			tokens = append(tokens, strings.ToUpper(raw[start:index]))
			continue
		}
		index++
	}
	return tokens, semicolon, nil
}

var _ WorkspaceService = Coordinator{}
