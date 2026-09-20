//go:build linux

package database

import (
	"context"
	"encoding/hex"
	"strings"
)

type transferNativeView struct {
	Name         string   `json:"name"`
	Definition   string   `json:"definition"`
	Columns      []string `json:"columns"`
	CharacterSet string   `json:"character_set"`
	Collation    string   `json:"collation"`
}

func (executor *LinuxMariaDBExecutor) observeTransferView(ctx context.Context, connection *mariaDBConnection, table isolatedTransferTable) (transferNativeView, error) {
	view := transferNativeView{Name: table.Table}
	raw, err := connection.query(ctx, sqlObserveImportView, table)
	if err != nil {
		return view, err
	}
	// --raw output can contain literal tabs/newlines inside the CREATE body.
	// Split the known name and trailing charset/collation columns, not the body.
	output := strings.TrimSuffix(string(raw), "\n")
	first := strings.IndexByte(output, '\t')
	last := strings.LastIndexByte(output, '\t')
	if first < 0 || last <= first || output[:first] != table.Table {
		return view, ErrTransferInvalid
	}
	previous := strings.LastIndexByte(output[:last], '\t')
	if previous <= first {
		return view, ErrTransferInvalid
	}
	view.CharacterSet, view.Collation = output[previous+1:last], output[last+1:]
	if _, err := ParseSQLIdentifier(view.CharacterSet); err != nil {
		return view, ErrTransferInvalid
	}
	if _, err := ParseSQLIdentifier(view.Collation); err != nil {
		return view, ErrTransferInvalid
	}
	statement := []byte(output[first+1 : previous])
	definition, err := prepareTransferSQLStatement(statement)
	if err != nil {
		return view, err
	}
	match := transferViewEnvelope.FindStringSubmatch(strings.TrimSpace(string(definition)))
	if match == nil {
		return view, ErrTransferInvalid
	}
	// A server-returned CREATE must name the observed view, not another object.
	quoted := "`" + strings.ReplaceAll(table.Table, "`", "``") + "`"
	if match[2] != quoted && match[2] != table.Table {
		return view, ErrTransferInvalid
	}
	view.Definition = string(definition)
	columns, err := connection.query(ctx, sqlObserveImportViewColumns, table)
	if err != nil {
		return view, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(columns)), "\n") {
		name, err := hex.DecodeString(line)
		if err != nil || len(view.Columns) >= 4096 {
			return view, ErrTransferInvalid
		}
		if _, err := isolatedTableSQL(isolatedTransferTable{Database: table.Database, Table: string(name)}); err != nil {
			return view, err
		}
		view.Columns = append(view.Columns, string(name))
	}
	return view, nil
}

func (view transferNativeView) canonicalDefinition() string {
	return view.Definition + "\x00" + view.CharacterSet + "\x00" + view.Collation
}
