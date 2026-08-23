//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const mariaDBClient = "/usr/bin/mariadb"
const mariaDBDefaults = "/etc/cyberpanel/migration/mariadb-readonly.cnf"
const mariaDBSocket = "/run/mysqld/mysqld.sock"
const mariaDBDatabase = "cyberpanel"
const mariaDBUser = "cyberpanel_migration_reader"
const extractSessionDirectory = "/var/lib/cyberpanel-migration/source-sessions"
const extractRuntimeDirectory = "/run/cyberpanel-extract"
const maximumQueryBytes = 1 << 20
const maximumBoundQueryBytes = 4 << 20
const maximumFieldBytes = 64 << 20
const maximumResultBytes = 256 << 20
const maximumStderrBytes = 4 << 20

var errBatchProtocol = errors.New("cyberpanel extract: invalid MariaDB batch response")
var errReadOnlyQuery = errors.New("cyberpanel extract: query is not an approved read operation")
var errMariaDBStatement = errors.New("cyberpanel extract: MariaDB rejected a fixed read operation")

type batchConnector struct{}
type batchDriver struct{}

type batchConnection struct {
	mu sync.Mutex
	command *exec.Cmd
	stdin io.WriteCloser
	stdout *bufio.Scanner
	stderr *os.File
	stderrPath string
	stderrOffset int64
	initialized bool
	inTransaction bool
	broken bool
	closed bool
}

type batchTransaction struct { connection *batchConnection }
type batchRows struct { columns []string; values [][]driver.Value; index int }
type batchXMLResult struct { Rows []batchXMLRow `xml:"row"` }
type batchXMLRow struct { Fields []batchXMLField `xml:"field"` }
type batchXMLField struct { Name string; Null bool; Value string }

func openBatchDatabase(ctx context.Context) (*sql.DB, error) {
	if ctx == nil { return nil, errBatchProtocol }
	database := sql.OpenDB(batchConnector{})
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	database.SetConnMaxLifetime(0)
	if err := database.PingContext(ctx); err != nil { database.Close(); return nil, err }
	return database, nil
}

func (batchDriver) Open(string) (driver.Conn, error) { return nil, errBatchProtocol }
func (batchConnector) Driver() driver.Driver { return batchDriver{} }

func (batchConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if ctx == nil || os.Geteuid() == 0 { return nil, errBatchProtocol }
	defaults, err := validateDefaultsFile()
	if err != nil { return nil, err }
	if err = validatePrivateDirectory(extractRuntimeDirectory); err != nil { return nil, err }
	stderr, err := os.CreateTemp(extractRuntimeDirectory, ".mariadb-stderr-")
	if err != nil { return nil, err }
	stderrPath := stderr.Name()
	cleanup := func() { stderr.Close(); os.Remove(stderrPath) }
	arguments := []string{"--defaults-extra-file="+mariaDBDefaults, "--user="+mariaDBUser, "--protocol=socket", "--socket="+mariaDBSocket, "--database="+mariaDBDatabase, "--batch", "--xml", "--binary-as-hex", "--binary-mode", "--force", "--unbuffered", "--skip-auto-rehash", "--connect-timeout=8", "--default-character-set=utf8mb4"}
	command := exec.Command(mariaDBClient, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/var/empty"}
	command.Dir = "/"
	command.Stderr = stderr
	command.WaitDelay = 2 * time.Second
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stdin, err := command.StdinPipe()
	if err != nil { cleanup(); return nil, err }
	stdout, err := command.StdoutPipe()
	if err != nil { stdin.Close(); cleanup(); return nil, err }
	if err = command.Start(); err != nil { stdin.Close(); cleanup(); return nil, err }
	after, err := fixedReadableFile(mariaDBDefaults, 64<<10)
	if err != nil || !os.SameFile(defaults, after) { _ = command.Process.Kill(); _ = command.Wait(); stdin.Close(); cleanup(); return nil, errors.Join(err, errBatchProtocol) }
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), maximumFieldBytes)
	connection := &batchConnection{command: command, stdin: stdin, stdout: scanner, stderr: stderr, stderrPath: stderrPath}
	connection.mu.Lock()
	err = connection.initialize(ctx)
	connection.mu.Unlock()
	if err != nil { connection.Close(); return nil, err }
	return connection, nil
}

func (c *batchConnection) Prepare(string) (driver.Stmt, error) { return nil, errReadOnlyQuery }
func (c *batchConnection) Begin() (driver.Tx, error) { return nil, errReadOnlyQuery }

func (c *batchConnection) Close() error {
	if c == nil { return nil }
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed { return nil }
	c.closed = true
	if c.stdin != nil { _ = c.stdin.Close() }
	if c.command != nil && c.command.Process != nil { _ = c.command.Process.Kill(); _ = c.command.Wait() }
	var failures []error
	if c.stderr != nil { failures = append(failures, c.stderr.Close()) }
	if c.stderrPath != "" { failures = append(failures, os.Remove(c.stderrPath)) }
	return errors.Join(failures...)
}

func (c *batchConnection) Ping(ctx context.Context) error {
	c.mu.Lock(); defer c.mu.Unlock()
	if err := c.initialize(ctx); err != nil { return err }
	results, err := c.roundTrip(ctx, "SELECT 1", true)
	if err != nil { return err }
	if len(results) != 1 || len(results[0].Rows) != 1 || len(results[0].Rows[0].Fields) != 1 || results[0].Rows[0].Fields[0].Value != "1" { return errBatchProtocol }
	return nil
}

func (c *batchConnection) ResetSession(ctx context.Context) error {
	c.mu.Lock(); defer c.mu.Unlock()
	if err := ctx.Err(); err != nil { return err }
	if c.closed || c.broken || c.inTransaction { return driver.ErrBadConn }
	return nil
}

func (c *batchConnection) IsValid() bool {
	c.mu.Lock(); defer c.mu.Unlock()
	return !c.closed && !c.broken && c.command != nil && c.command.Process != nil
}

func (c *batchConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	c.mu.Lock(); defer c.mu.Unlock()
	if options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || !options.ReadOnly || c.inTransaction { return nil, errReadOnlyQuery }
	if err := c.initialize(ctx); err != nil { return nil, err }
	if _, err := c.roundTrip(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", false); err != nil { return nil, err }
	if _, err := c.roundTrip(ctx, "START TRANSACTION READ ONLY", false); err != nil { c.broken = true; if c.command != nil && c.command.Process != nil { _ = c.command.Process.Kill() }; return nil, err }
	c.inTransaction = true
	results, err := c.roundTrip(ctx, "SELECT @@session.tx_isolation,@@session.tx_read_only", true)
	if err != nil { c.broken = true; if c.command != nil && c.command.Process != nil { _ = c.command.Process.Kill() }; return nil, err }
	if len(results) != 1 || len(results[0].Rows) != 1 || len(results[0].Rows[0].Fields) != 2 || results[0].Rows[0].Fields[0].Value != "REPEATABLE-READ" || results[0].Rows[0].Fields[1].Value != "1" { c.broken = true; _ = c.command.Process.Kill(); return nil, errBatchProtocol }
	return &batchTransaction{connection: c}, nil
}

func (t *batchTransaction) Commit() error { return t.finish("COMMIT") }
func (t *batchTransaction) Rollback() error { return t.finish("ROLLBACK") }
func (t *batchTransaction) finish(statement string) error {
	if t == nil || t.connection == nil { return driver.ErrBadConn }
	c := t.connection
	c.mu.Lock(); defer c.mu.Unlock()
	if !c.inTransaction { return driver.ErrBadConn }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second); defer cancel()
	_, err := c.roundTrip(ctx, statement, false)
	c.inTransaction = false
	if err != nil { c.broken = true; if c.command != nil && c.command.Process != nil { _ = c.command.Process.Kill() } }
	return err
}

func (c *batchConnection) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) { return nil, errReadOnlyQuery }

func (c *batchConnection) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	statement, err := bindReadQuery(query, arguments)
	if err != nil { return nil, err }
	c.mu.Lock(); defer c.mu.Unlock()
	if err = c.initialize(ctx); err != nil { return nil, err }
	results, err := c.roundTrip(ctx, statement, true)
	if err != nil { return nil, err }
	if len(results) != 1 { return nil, errBatchProtocol }
	return rowsFromXML(results[0])
}

func (c *batchConnection) initialize(ctx context.Context) error {
	if c == nil || c.closed || c.broken { return driver.ErrBadConn }
	if c.initialized { return nil }
	if _, err := c.roundTrip(ctx, "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ", false); err != nil { return err }
	if _, err := c.roundTrip(ctx, "SET SESSION TRANSACTION READ ONLY", false); err != nil { return err }
	results, err := c.roundTrip(ctx, "SELECT SUBSTRING_INDEX(CURRENT_USER(),'@',1),@@session.tx_read_only", true)
	if err != nil { return err }
	if len(results) != 1 || len(results[0].Rows) != 1 || len(results[0].Rows[0].Fields) != 2 || results[0].Rows[0].Fields[0].Value != mariaDBUser || results[0].Rows[0].Fields[1].Value != "1" { return errBatchProtocol }
	c.initialized = true
	return nil
}

func (c *batchConnection) roundTrip(ctx context.Context, statement string, expectResult bool) ([]batchXMLResult, error) {
	if c.closed || c.broken || ctx == nil || statement == "" || len(statement) > maximumBoundQueryBytes { return nil, driver.ErrBadConn }
	markerRaw := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, markerRaw); err != nil { return nil, err }
	marker := "cp_frame_" + hex.EncodeToString(markerRaw)
	script := statement + ";\nSELECT '" + marker + "' AS `" + marker + "`;\n"
	done := make(chan struct{})
	go func() { select { case <-ctx.Done(): if c.command != nil && c.command.Process != nil { _ = c.command.Process.Kill() }; case <-done: } }()
	_, writeErr := io.WriteString(c.stdin, script)
	if writeErr != nil { close(done); c.broken = true; return nil, driver.ErrBadConn }
	results := []batchXMLResult{}
	for {
		result, err := c.readXMLResult()
		if err != nil { close(done); c.broken = true; if ctx.Err() != nil { return nil, ctx.Err() }; return nil, driver.ErrBadConn }
		if result.marker(marker) { break }
		results = append(results, result)
		if len(results) > 1 { close(done); c.broken = true; return nil, errBatchProtocol }
	}
	close(done)
	if ctx.Err() != nil { c.broken = true; return nil, ctx.Err() }
	stat, err := c.stderr.Stat()
	if err != nil || stat.Size() < c.stderrOffset || stat.Size() > maximumStderrBytes { c.broken = true; return nil, errors.Join(err, errBatchProtocol) }
	hadError := stat.Size() != c.stderrOffset
	c.stderrOffset = stat.Size()
	if hadError { return nil, errMariaDBStatement }
	if expectResult && len(results) != 1 || !expectResult && len(results) != 0 { return nil, errBatchProtocol }
	return results, nil
}

func (c *batchConnection) readXMLResult() (batchXMLResult, error) {
	var encoded bytes.Buffer
	collecting := false
	for c.stdout.Scan() {
		line := append([]byte(nil), c.stdout.Bytes()...)
		trimmed := bytes.TrimSpace(line)
		if !collecting {
			if bytes.HasPrefix(trimmed, []byte("<resultset")) { collecting = true } else if len(trimmed) == 0 || bytes.HasPrefix(trimmed, []byte("<?xml")) { continue } else { return batchXMLResult{}, errBatchProtocol }
		}
		if _, err := encoded.Write(line); err != nil { return batchXMLResult{}, err }
		_ = encoded.WriteByte('\n')
		if encoded.Len() > maximumResultBytes { return batchXMLResult{}, errBatchProtocol }
		if collecting && bytes.Contains(trimmed, []byte("</resultset>")) {
			var result batchXMLResult
			if err := xml.Unmarshal(encoded.Bytes(), &result); err != nil { return batchXMLResult{}, errBatchProtocol }
			return result, nil
		}
	}
	if err := c.stdout.Err(); err != nil { return batchXMLResult{}, err }
	return batchXMLResult{}, io.EOF
}

func (field *batchXMLField) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	for _, attribute := range start.Attr { switch attribute.Name.Local { case "name": field.Name = attribute.Value; case "nil": field.Null = attribute.Value == "true" || attribute.Value == "1" } }
	return decoder.DecodeElement(&field.Value, &start)
}

func (result batchXMLResult) marker(value string) bool { return len(result.Rows) == 1 && len(result.Rows[0].Fields) == 1 && !result.Rows[0].Fields[0].Null && result.Rows[0].Fields[0].Name == value && result.Rows[0].Fields[0].Value == value }

func rowsFromXML(result batchXMLResult) (*batchRows, error) {
	rows := &batchRows{}
	if len(result.Rows) == 0 { return rows, nil }
	rows.columns = make([]string, len(result.Rows[0].Fields))
	for index, field := range result.Rows[0].Fields { if field.Name == "" { return nil, errBatchProtocol }; rows.columns[index] = field.Name }
	rows.values = make([][]driver.Value, len(result.Rows))
	for rowIndex, row := range result.Rows {
		if len(row.Fields) != len(rows.columns) { return nil, errBatchProtocol }
		rows.values[rowIndex] = make([]driver.Value, len(row.Fields))
		for fieldIndex, field := range row.Fields {
			if field.Name != rows.columns[fieldIndex] || len(field.Value) > maximumFieldBytes { return nil, errBatchProtocol }
			if field.Null { rows.values[rowIndex][fieldIndex] = nil } else { rows.values[rowIndex][fieldIndex] = field.Value }
		}
	}
	return rows, nil
}

func (rows *batchRows) Columns() []string { return append([]string(nil), rows.columns...) }
func (rows *batchRows) Close() error { rows.values = nil; return nil }
func (rows *batchRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) { return io.EOF }
	if len(destination) != len(rows.columns) { return errBatchProtocol }
	copy(destination, rows.values[rows.index]); rows.index++; return nil
}

func bindReadQuery(query string, arguments []driver.NamedValue) (string, error) {
	if len(query) == 0 || len(query) > maximumQueryBytes || !utf8.ValidString(query) || strings.ContainsAny(query, ";\x00") || strings.Contains(query, "--") || strings.Contains(query, "/*") || strings.Contains(query, "*/") || strings.Contains(query, "#") { return "", errReadOnlyQuery }
	fields := strings.Fields(query)
	if len(fields) == 0 || strings.ToUpper(fields[0]) != "SELECT" && strings.ToUpper(fields[0]) != "SHOW" { return "", errReadOnlyQuery }
	upper := strings.ToUpper(strings.TrimSpace(query))
	if strings.EqualFold(fields[0], "SHOW") && !strings.HasPrefix(upper, "SHOW CREATE ") { return "", errReadOnlyQuery }
	for _, blocked := range []string{" INTO OUTFILE", " INTO DUMPFILE", " FOR UPDATE", " LOCK IN SHARE MODE", "LOAD_FILE(", "SLEEP(", "BENCHMARK(", "GET_LOCK(", "RELEASE_LOCK(", ":="} { if strings.Contains(upper, blocked) { return "", errReadOnlyQuery } }
	var output strings.Builder
	output.Grow(len(query) + len(arguments)*32)
	argument := 0
	var quote byte
	for index := 0; index < len(query); index++ {
		character := query[index]
		if quote != 0 {
			output.WriteByte(character)
			if character == '\\' && quote != '`' && index+1 < len(query) { index++; output.WriteByte(query[index]); continue }
			if character == quote { if index+1 < len(query) && query[index+1] == quote { index++; output.WriteByte(query[index]); continue }; quote = 0 }
			continue
		}
		if character == '\'' || character == '"' || character == '`' { quote = character; output.WriteByte(character); continue }
		if character != '?' { output.WriteByte(character); continue }
		if argument >= len(arguments) { return "", errReadOnlyQuery }
		encoded, err := encodeBoundValue(arguments[argument], argument+1)
		if err != nil { return "", err }
		output.WriteString(encoded); argument++
		if output.Len() > maximumBoundQueryBytes { return "", errReadOnlyQuery }
	}
	if quote != 0 || argument != len(arguments) { return "", errReadOnlyQuery }
	return output.String(), nil
}

func encodeBoundValue(argument driver.NamedValue, ordinal int) (string, error) {
	if argument.Name != "" || argument.Ordinal != ordinal { return "", errReadOnlyQuery }
	switch value := argument.Value.(type) {
	case nil: return "NULL", nil
	case int64: return strconv.FormatInt(value, 10), nil
	case float64: if math.IsNaN(value) || math.IsInf(value, 0) { return "", errReadOnlyQuery }; return strconv.FormatFloat(value, 'g', -1, 64), nil
	case bool: if value { return "1", nil }; return "0", nil
	case []byte: if len(value) > maximumQueryBytes { return "", errReadOnlyQuery }; return "0x"+hex.EncodeToString(value), nil
	case string: if len(value) > maximumQueryBytes || !utf8.ValidString(value) { return "", errReadOnlyQuery }; return "CONVERT(0x"+hex.EncodeToString([]byte(value))+" USING utf8mb4)", nil
	case time.Time: return "CONVERT(0x"+hex.EncodeToString([]byte(value.UTC().Format("2006-01-02 15:04:05.999999")))+" USING utf8mb4)", nil
	default: return "", errReadOnlyQuery
	}
}

func validateDefaultsFile() (os.FileInfo, error) {
	info, err := fixedReadableFile(mariaDBDefaults, 64<<10)
	if err != nil { return nil, err }
	raw, err := os.ReadFile(mariaDBDefaults)
	if err != nil { return nil, err }
	defer func() { for index := range raw { raw[index] = 0 } }()
	scanner := bufio.NewScanner(bytes.NewReader(raw)); scanner.Buffer(make([]byte, 4096), 64<<10)
	section := ""; password := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") { continue }
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") { section = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))); if section != "client" { return nil, errBatchProtocol }; continue }
		parts := strings.SplitN(line, "=", 2)
		if section != "client" || len(parts) != 2 || strings.ToLower(strings.TrimSpace(parts[0])) != "password" || strings.TrimSpace(parts[1]) == "" || password { return nil, errBatchProtocol }
		password = true
	}
	if err := scanner.Err(); err != nil || !password { return nil, errors.Join(err, errBatchProtocol) }
	return info, nil
}

func fixedReadableFile(path string, maximum int64) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path { return nil, errBatchProtocol }
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o640 || stat.Uid != 0 || stat.Gid != uint32(os.Getegid()) || info.Size() < 1 || info.Size() > maximum { return nil, errBatchProtocol }
	return info, nil
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil { return err }
	stat, ok := info.Sys().(*syscall.Stat_t)
	resolved, resolveErr := filepath.EvalSymlinks(path)
	if !ok || resolveErr != nil || resolved != path || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) { return errors.Join(resolveErr, errBatchProtocol) }
	return nil
}

var _ driver.Connector = batchConnector{}
var _ driver.Conn = (*batchConnection)(nil)
var _ driver.ConnBeginTx = (*batchConnection)(nil)
var _ driver.QueryerContext = (*batchConnection)(nil)
var _ driver.ExecerContext = (*batchConnection)(nil)
var _ driver.Pinger = (*batchConnection)(nil)
var _ driver.SessionResetter = (*batchConnection)(nil)
var _ driver.Validator = (*batchConnection)(nil)
var _ driver.Tx = (*batchTransaction)(nil)
var _ driver.Rows = (*batchRows)(nil)
