package dns

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
)

const PowerDNSSchemaVersion uint32 = 1

var ErrPowerDNSSchema = errors.New("PowerDNS authoritative schema is unavailable")

type PowerDNSSchemaReceipt struct {
	Version uint32 `json:"version"`
	SchemaDigest string `json:"schema_digest"`
	DatabaseFingerprint string `json:"database_fingerprint"`
	ObservedAt time.Time `json:"observed_at"`
}

var powerDNSSchemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS domains (id INT AUTO_INCREMENT NOT NULL,name VARCHAR(255) CHARACTER SET ascii NOT NULL,master VARCHAR(128) CHARACTER SET ascii DEFAULT NULL,last_check INT DEFAULT NULL,type VARCHAR(10) CHARACTER SET ascii NOT NULL,notified_serial BIGINT UNSIGNED DEFAULT NULL,account VARCHAR(40) CHARACTER SET utf8mb4 DEFAULT NULL,options TEXT DEFAULT NULL,catalog VARCHAR(255) CHARACTER SET ascii DEFAULT NULL,PRIMARY KEY(id),UNIQUE KEY domains_name_unique(name),KEY domains_catalog_index(catalog)) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS records (id BIGINT AUTO_INCREMENT NOT NULL,domain_id INT DEFAULT NULL,name VARCHAR(255) CHARACTER SET ascii DEFAULT NULL,type VARCHAR(10) CHARACTER SET ascii DEFAULT NULL,content TEXT DEFAULT NULL,ttl INT DEFAULT NULL,prio INT DEFAULT NULL,disabled TINYINT(1) DEFAULT 0,ordername VARCHAR(255) CHARACTER SET binary DEFAULT NULL,auth TINYINT(1) DEFAULT 1,PRIMARY KEY(id),KEY records_name_type_index(name,type),KEY records_domain_index(domain_id),KEY records_order_index(auth,ordername)) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS supermasters (ip VARCHAR(64) CHARACTER SET ascii NOT NULL,nameserver VARCHAR(255) CHARACTER SET ascii NOT NULL,account VARCHAR(40) CHARACTER SET utf8mb4 NOT NULL,PRIMARY KEY(ip,nameserver)) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS comments (id INT AUTO_INCREMENT NOT NULL,domain_id INT NOT NULL,name VARCHAR(255) CHARACTER SET ascii NOT NULL,type VARCHAR(10) CHARACTER SET ascii NOT NULL,modified_at INT NOT NULL,account VARCHAR(40) CHARACTER SET utf8mb4 DEFAULT NULL,comment TEXT CHARACTER SET utf8mb4 NOT NULL,PRIMARY KEY(id),KEY comments_name_type_index(name,type),KEY comments_domain_index(domain_id)) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS domainmetadata (id INT AUTO_INCREMENT NOT NULL,domain_id INT NOT NULL,kind VARCHAR(32) CHARACTER SET ascii DEFAULT NULL,content TEXT DEFAULT NULL,PRIMARY KEY(id),KEY domainmetadata_domain_kind_index(domain_id,kind)) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS cryptokeys (id INT AUTO_INCREMENT NOT NULL,domain_id INT NOT NULL,flags INT NOT NULL,active TINYINT(1) NOT NULL,published TINYINT(1) DEFAULT 1,content TEXT NOT NULL,PRIMARY KEY(id),KEY cryptokeys_domain_index(domain_id)) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS tsigkeys (id INT AUTO_INCREMENT NOT NULL,name VARCHAR(255) CHARACTER SET ascii DEFAULT NULL,algorithm VARCHAR(50) CHARACTER SET ascii DEFAULT NULL,secret VARCHAR(255) CHARACTER SET ascii DEFAULT NULL,PRIMARY KEY(id),UNIQUE KEY tsigkeys_name_algorithm_unique(name,algorithm)) ENGINE=InnoDB`,
	`CREATE TABLE IF NOT EXISTS cyberpanel_pdns_schema (version INT UNSIGNED NOT NULL,schema_digest CHAR(64) CHARACTER SET ascii NOT NULL,applied_at DATETIME(6) NOT NULL,PRIMARY KEY(version)) ENGINE=InnoDB`,
}

var powerDNSRequiredColumns = map[string][]string{
	"domains": {"id", "name", "master", "last_check", "type", "notified_serial", "account", "options", "catalog"},
	"records": {"id", "domain_id", "name", "type", "content", "ttl", "prio", "disabled", "ordername", "auth"},
	"supermasters": {"ip", "nameserver", "account"},
	"comments": {"id", "domain_id", "name", "type", "modified_at", "account", "comment"},
	"domainmetadata": {"id", "domain_id", "kind", "content"},
	"cryptokeys": {"id", "domain_id", "flags", "active", "published", "content"},
	"tsigkeys": {"id", "name", "algorithm", "secret"},
	"cyberpanel_pdns_schema": {"version", "schema_digest", "applied_at"},
}

func (database PowerDNSAuthoritativeDatabase) Bootstrap(ctx context.Context) (PowerDNSSchemaReceipt, error) {
	receipt := PowerDNSSchemaReceipt{Version: PowerDNSSchemaVersion, DatabaseFingerprint: database.identity.Fingerprint, ObservedAt: time.Now().UTC()}
	if ctx == nil || !database.valid() {
		return receipt, ErrPowerDNSDatabaseIsolation
	}
	receipt.SchemaDigest = powerDNSSchemaDigest()
	connection, err := database.database.Conn(ctx)
	if err != nil {
		return receipt, errors.Join(ErrPowerDNSSchema, err)
	}
	defer connection.Close()
	var acquired sql.NullInt64
	if err = connection.QueryRowContext(ctx, `SELECT GET_LOCK('cyberpanel-powerdns-schema-v1',30)`).Scan(&acquired); err != nil || !acquired.Valid || acquired.Int64 != 1 {
		return receipt, errors.Join(ErrPowerDNSSchema, err)
	}
	defer func() {
		releaseContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = connection.ExecContext(releaseContext, `SELECT RELEASE_LOCK('cyberpanel-powerdns-schema-v1')`)
	}()
	for _, statement := range powerDNSSchemaStatements {
		if _, err = connection.ExecContext(ctx, statement); err != nil {
			return receipt, errors.Join(ErrPowerDNSSchema, err)
		}
	}
	if _, err = connection.ExecContext(ctx, `INSERT INTO cyberpanel_pdns_schema(version,schema_digest,applied_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE schema_digest=VALUES(schema_digest),applied_at=VALUES(applied_at)`, PowerDNSSchemaVersion, receipt.SchemaDigest, receipt.ObservedAt); err != nil {
		return receipt, errors.Join(ErrPowerDNSSchema, err)
	}
	if err = verifyPowerDNSSchema(ctx, connection); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func (database PowerDNSAuthoritativeDatabase) VerifySchema(ctx context.Context) (PowerDNSSchemaReceipt, error) {
	receipt := PowerDNSSchemaReceipt{Version: PowerDNSSchemaVersion, SchemaDigest: powerDNSSchemaDigest(), DatabaseFingerprint: database.identity.Fingerprint, ObservedAt: time.Now().UTC()}
	if ctx == nil || !database.valid() {
		return receipt, ErrPowerDNSDatabaseIsolation
	}
	if err := verifyPowerDNSSchema(ctx, database.database); err != nil {
		return receipt, err
	}
	var stored string
	if err := database.database.QueryRowContext(ctx, `SELECT schema_digest FROM cyberpanel_pdns_schema WHERE version=? LIMIT 1`, PowerDNSSchemaVersion).Scan(&stored); err != nil || stored != receipt.SchemaDigest {
		return receipt, errors.Join(ErrPowerDNSSchema, err)
	}
	return receipt, nil
}

type powerDNSSchemaQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func verifyPowerDNSSchema(ctx context.Context, database powerDNSSchemaQuerier) error {
	rows, err := database.QueryContext(ctx, `SELECT LOWER(TABLE_NAME),LOWER(COLUMN_NAME) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('domains','records','supermasters','comments','domainmetadata','cryptokeys','tsigkeys','cyberpanel_pdns_schema')`)
	if err != nil {
		return errors.Join(ErrPowerDNSSchema, err)
	}
	defer rows.Close()
	present := map[string]map[string]bool{}
	for rows.Next() {
		var table string
		var column string
		if err = rows.Scan(&table, &column); err != nil {
			return errors.Join(ErrPowerDNSSchema, err)
		}
		table = strings.ToLower(table)
		column = strings.ToLower(column)
		if present[table] == nil {
			present[table] = map[string]bool{}
		}
		present[table][column] = true
	}
	if err = rows.Err(); err != nil {
		return errors.Join(ErrPowerDNSSchema, err)
	}
	for table, columns := range powerDNSRequiredColumns {
		for _, column := range columns {
			if !present[table][column] {
				return ErrPowerDNSSchema
			}
		}
	}
	return nil
}

func powerDNSSchemaDigest() string {
	statements := append([]string(nil), powerDNSSchemaStatements...)
	sort.Strings(statements)
	hash := sha256.New()
	for _, statement := range statements {
		_, _ = io.WriteString(hash, statement)
		_, _ = io.WriteString(hash, "\x00")
	}
	return hex.EncodeToString(hash.Sum(nil))
}
