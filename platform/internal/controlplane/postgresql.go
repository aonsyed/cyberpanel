package controlplane

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// authorityDB is the only central SQL boundary. Node-local repositories do not
// use it. Repositories retain positional ? parameters; only this boundary knows
// PostgreSQL binding. There is deliberately no SQLite compatibility fallback.
type authorityDB struct { raw *sql.DB }
type authorityTx struct { raw *sql.Tx }
type authorityRow struct { raw *sql.Row }
type authorityRows struct { raw *sql.Rows }

// ErrAuthorityUnavailable never implies that a submitted operation did not
// commit. It authorizes only a whole-request retry with the original identity.
var ErrAuthorityUnavailable = errors.New("central authority temporarily unavailable; retry the original request")

func (row *authorityRow) Scan(dest ...any) error { return authorityError(row.raw.Scan(dest...)) }
func (rows *authorityRows) Next() bool { return rows.raw.Next() }
func (rows *authorityRows) Scan(dest ...any) error { return authorityError(rows.raw.Scan(dest...)) }
func (rows *authorityRows) Err() error { return authorityError(rows.raw.Err()) }
func (rows *authorityRows) Close() error { return authorityError(rows.raw.Close()) }

func newAuthorityDB(database *sql.DB) (*authorityDB, error) {
	if database == nil { return nil, ErrInvalid }
	if _, ok := database.Driver().(*stdlib.Driver); !ok {
		return nil, errors.New("central authority requires PostgreSQL via pgx; SQLite authority must be explicitly exported and reconciled before adoption")
	}
	return &authorityDB{raw: database}, nil
}

func (db *authorityDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, err := db.raw.ExecContext(ctx, postgresBind(query), args...)
	return result, authorityError(err)
}
func (db *authorityDB) QueryContext(ctx context.Context, query string, args ...any) (*authorityRows, error) {
	rows, err := db.raw.QueryContext(ctx, postgresBind(query), args...)
	if err != nil { return nil, authorityError(err) }
	return &authorityRows{raw: rows}, nil
}
func (db *authorityDB) QueryRowContext(ctx context.Context, query string, args ...any) *authorityRow {
	return &authorityRow{raw: db.raw.QueryRowContext(ctx, postgresBind(query), args...)}
}
func (db *authorityDB) BeginTx(ctx context.Context, options *sql.TxOptions) (*authorityTx, error) {
	if options == nil || options.Isolation != sql.LevelSerializable {
		return nil, errors.New("central authority transactions must be serializable")
	}
	tx, err := db.raw.BeginTx(ctx, options)
	if err != nil { return nil, authorityError(err) }
	return &authorityTx{raw: tx}, nil
}
func (tx *authorityTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	result, err := tx.raw.ExecContext(ctx, postgresBind(query), args...)
	return result, authorityError(err)
}
func (tx *authorityTx) QueryContext(ctx context.Context, query string, args ...any) (*authorityRows, error) {
	rows, err := tx.raw.QueryContext(ctx, postgresBind(query), args...)
	if err != nil { return nil, authorityError(err) }
	return &authorityRows{raw: rows}, nil
}
func (tx *authorityTx) QueryRowContext(ctx context.Context, query string, args ...any) *authorityRow {
	return &authorityRow{raw: tx.raw.QueryRowContext(ctx, postgresBind(query), args...)}
}
func (tx *authorityTx) Commit() error { return authorityError(tx.raw.Commit()) }
func (tx *authorityTx) Rollback() error { return authorityError(tx.raw.Rollback()) }

// Do not retry individual statements inside a failed PostgreSQL transaction.
// Callers retry the whole operation with its original idempotency/request digest;
// committed responses remain byte-for-byte replayable after an uncertain commit.
func authorityError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) { return err }
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		switch postgres.Code {
		case "40001", "40P01", "25006", "57P01", "57P02", "57P03", "53300", "53400", "55P03":
			return ErrAuthorityUnavailable
		case "23505":
			return ErrConflict
		}
		if strings.HasPrefix(postgres.Code, "08") { return ErrAuthorityUnavailable }
	}
	var connectionError *pgconn.ConnectError
	var networkError net.Error
	if errors.As(err, &connectionError) || errors.As(err, &networkError) || errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) { return ErrAuthorityUnavailable }
	return err
}

// AuthorityReadiness checks the live, pooled authority connection, not a cached
// process flag. A row lock proves primary write eligibility and update rights
// without modifying authority data. It does not prove backup currency, synchronous
// replication, or exclusive writer fencing; those require external evidence.
func (s *Store) AuthorityReadiness(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil { return ErrInvalid }
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	var ready bool
	if err = tx.QueryRowContext(ctx, `SELECT identity='cyberpanel-central-postgresql' AND version=1 AND current_schema()='cyberpanel_authority' AND NOT pg_catalog.pg_is_in_recovery() AND current_setting('transaction_read_only')='off' AND current_setting('transaction_isolation')='serializable' AND current_setting('synchronous_commit')='on' FROM cyberpanel_authority.authority_postgresql_v1 WHERE singleton=1 FOR UPDATE`).Scan(&ready); err != nil { return err }
	if !ready { return ErrAuthorityUnavailable }
	return tx.Commit()
}

// Only SQL parameters are rebound: literals, quoted identifiers, comments and
// PostgreSQL dollar-quoted bodies are copied unchanged. Queries are static code,
// never user-provided SQL; JSON operators must use their named SQL functions.
func postgresBind(query string) string {
	var out strings.Builder
	out.Grow(len(query) + 16)
	parameter := 0
	for i := 0; i < len(query); {
		start := i
		switch {
		case query[i] == '\'' || query[i] == '"':
			quote := query[i]; i++
			for i < len(query) {
				if query[i] == quote {
					i++
					if i < len(query) && query[i] == quote { i++; continue }
					break
				}
				i++
			}
		case strings.HasPrefix(query[i:], "--"):
			for i < len(query) && query[i] != '\n' { i++ }
		case strings.HasPrefix(query[i:], "/*"):
			i += 2; depth := 1
			for i < len(query) && depth > 0 {
				if strings.HasPrefix(query[i:], "/*") { depth++; i += 2 } else if strings.HasPrefix(query[i:], "*/") { depth--; i += 2 } else { i++ }
			}
		case query[i] == '$':
			end := i + 1
			for end < len(query) && (query[end] >= 'a' && query[end] <= 'z' || query[end] >= 'A' && query[end] <= 'Z' || query[end] == '_') { end++ }
			if end < len(query) && query[end] == '$' {
				tag := query[i:end+1]
				if closeAt := strings.Index(query[end+1:], tag); closeAt >= 0 { i = end + 1 + closeAt + len(tag) } else { i = len(query) }
			} else { i++ }
		case query[i] == '?':
			parameter++; out.WriteByte('$'); out.WriteString(strconv.Itoa(parameter)); i++; continue
		default:
			i++
		}
		out.WriteString(query[start:i])
	}
	return out.String()
}

const authorityIdentitySchema = `CREATE TABLE IF NOT EXISTS authority_postgresql_v1(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 identity TEXT NOT NULL CHECK(identity='cyberpanel-central-postgresql'),
 version INTEGER NOT NULL CHECK(version=1),
 created_at TIMESTAMPTZ NOT NULL
);`

func (s *Store) bootstrapPostgreSQL(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil { return ErrInvalid }
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return err }
	defer tx.Rollback()
	// The fixed schema is created and assigned to the service role by the DBA,
	// not implicitly created in public or adopted from a differently owned store.
	var schema string
	var owner, unsafeRole, unsafeSchema bool
	if err = tx.QueryRowContext(ctx, `SELECT current_schema(),n.nspowner=r.oid,r.rolsuper OR r.rolbypassrls,EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a WHERE a.grantee<>n.nspowner AND a.privilege_type='CREATE') FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.rolname=current_user WHERE n.nspname=current_schema()`).Scan(&schema, &owner, &unsafeRole, &unsafeSchema); err != nil { return err }
	if schema != "cyberpanel_authority" || !owner || unsafeRole || unsafeSchema {
		return errors.New("central PostgreSQL requires its dedicated cyberpanel_authority schema writable only by its non-superuser, non-BYPASSRLS owner role")
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(1129333072,1)`); err != nil { return err }
	var marked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_catalog.to_regclass('cyberpanel_authority.authority_postgresql_v1') IS NOT NULL`).Scan(&marked); err != nil { return err }
	if !marked {
		var existing int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cyberpanel_authority' AND c.relkind IN ('r','p','v','m','S','f')`).Scan(&existing); err != nil { return err }
		if existing != 0 { return errors.New("unqualified central PostgreSQL schema is not empty; explicit export/reconciliation required") }
	} else {
		var identity string
		var version int
		if err = tx.QueryRowContext(ctx, `SELECT identity,version FROM authority_postgresql_v1 WHERE singleton=1`).Scan(&identity, &version); err != nil { return err }
		if identity != "cyberpanel-central-postgresql" || version != 1 { return errors.New("unsupported central PostgreSQL authority schema") }
	}
	// Bytea intentionally retains original JSON, including signed response bytes.
	// PostgreSQL SSI serializes per-node event cursors and the audit-chain tail
	// reads with their inserts; a conflicting writer aborts, never forks a chain.
	for _, statement := range strings.Split(Schema + operatorSchema + authorityIdentitySchema, ";") {
		if strings.TrimSpace(statement) == "" { continue }
		if _, err = tx.ExecContext(ctx, statement); err != nil { return err }
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO authority_postgresql_v1(singleton,identity,version,created_at) VALUES(1,'cyberpanel-central-postgresql',1,?) ON CONFLICT(singleton) DO NOTHING`, s.clock().UTC()); err != nil { return err }
	if _, err = tx.ExecContext(ctx, `INSERT INTO controlplane_schema_migrations(version,applied_at) VALUES(2,?) ON CONFLICT(version) DO NOTHING`, s.clock().UTC()); err != nil { return err }
	return tx.Commit()
}

func authorityNow() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
