//go:build linux

package database

import (
	"regexp"
	"strings"
)

const transferViewIdentifier = "(?:`(?:``|[^`\\x00])+`|[A-Za-z_][A-Za-z0-9_$]*)"
const transferViewAccount = "(?:`(?:``|[^`\\x00])*`|'(?:''|\\\\.|[^'\\\\])*'|[A-Za-z0-9_$.-]+)"

// This recognizes the CREATE VIEW envelope, not the SELECT grammar. MariaDB
// still parses the query under the isolated loader's limited native grants.
var transferViewEnvelope = regexp.MustCompile("(?is)^\\s*CREATE\\s+(?:OR\\s+REPLACE\\s+)?(?:ALGORITHM\\s*=\\s*(UNDEFINED|MERGE|TEMPTABLE)\\s+)?(?:DEFINER\\s*=\\s*" + transferViewAccount + "\\s*@\\s*" + transferViewAccount + "\\s+)?(?:SQL\\s+SECURITY\\s+(?:DEFINER|INVOKER)\\s+)?VIEW\\s+(" + transferViewIdentifier + ")(\\s*\\(\\s*" + transferViewIdentifier + "(?:\\s*,\\s*" + transferViewIdentifier + ")*\\s*\\))?\\s+AS\\s+(.+)$")

func prepareTransferSQLStatement(statement []byte) ([]byte, error) {
	fields := strings.Fields(normalizeTransferSQL(statement))
	if len(fields) == 0 || fields[0] != "CREATE" || !containsTransferToken(fields, "VIEW") {
		if err := validateTransferSQLStatement(statement); err != nil {
			return nil, err
		}
		return statement, nil
	}
	flat, err := flattenTransferViewComments(string(statement))
	if err != nil {
		return nil, err
	}
	match := transferViewEnvelope.FindStringSubmatch(flat)
	if match == nil {
		return nil, ErrTransferUnsafeSQL
	}
	query, kind, err := ParseWorkspaceStatement(match[4])
	if err != nil || kind != WorkspaceStatementSelect {
		return nil, ErrTransferUnsafeSQL
	}
	algorithm := ""
	if match[1] != "" {
		algorithm = "ALGORITHM=" + strings.ToUpper(match[1]) + " "
	}
	// Never preserve a dump's definer, including root/current administrator.
	// An unqualified view name also prevents CREATE in a different schema.
	return []byte("CREATE " + algorithm + "SQL SECURITY INVOKER VIEW " + match[2] + match[3] + " AS " + query + ";\n"), nil
}

// Native dumps wrap view clauses in versioned executable comments. Preserve
// literal bytes but expose executable content to both envelope and SELECT checks.
func flattenTransferViewComments(input string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(input); {
		if input[i] == '\'' || input[i] == '"' || input[i] == '`' {
			start, quote := i, input[i]
			i++
			closed := false
			for i < len(input) {
				if input[i] == '\\' {
					i += 2
					continue
				}
				if input[i] == quote {
					i++
					if i < len(input) && input[i] == quote {
						i++
						continue
					}
					closed = true
					break
				}
				i++
			}
			if !closed || i > len(input) {
				return "", ErrTransferUnsafeSQL
			}
			out.WriteString(input[start:i])
			continue
		}
		if strings.HasPrefix(input[i:], "/*") {
			end := strings.Index(input[i+2:], "*/")
			if end < 0 {
				return "", ErrTransferUnsafeSQL
			}
			end += i + 2
			start := i + 2
			executable := false
			if start < end && input[start] == '!' {
				start++
				executable = true
			} else if start+1 < end && input[start] == 'M' && input[start+1] == '!' {
				start += 2
				executable = true
			}
			out.WriteByte(' ')
			if executable {
				for start < end && input[start] >= '0' && input[start] <= '9' {
					start++
				}
				out.WriteString(input[start:end])
			}
			out.WriteByte(' ')
			i = end + 2
			continue
		}
		if input[i] == '#' || strings.HasPrefix(input[i:], "--") {
			end := strings.IndexByte(input[i:], '\n')
			if end < 0 {
				break
			}
			i += end + 1
			out.WriteByte(' ')
			continue
		}
		out.WriteByte(input[i])
		i++
	}
	return out.String(), nil
}
