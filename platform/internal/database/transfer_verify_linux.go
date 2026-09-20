//go:build linux

package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

type isolatedTransferTable struct {
	Database Database
	Table    string
}

func isolatedTableSQL(table isolatedTransferTable) (string, error) {
	if table.Database.Validate() != nil || table.Table == "" || !utf8.ValidString(table.Table) || utf8.RuneCountInString(table.Table) > 64 || strings.ContainsRune(table.Table, 0) {
		return "", ErrInvalidResource
	}
	return quotedIdentifier(table.Database.Name) + ".`" + strings.ReplaceAll(table.Table, "`", "``") + "`", nil
}

// Verification observes the actual isolated database after its loader is gone.
// It is not promotion authority by itself: promotion must fence/revalidate it.
func (executor *LinuxMariaDBExecutor) verifyTransferImport(ctx context.Context, job TransferJob, isolated IsolatedTransferDatabase) (TransferVerification, error) {
	if executor == nil || ctx == nil {
		return TransferVerification{}, ErrUnauthorized
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if _, err := executor.transferImportSource(job); err != nil {
		return TransferVerification{}, err
	}
	record, err := executor.loadTransferImport(job, isolated)
	if err != nil {
		return TransferVerification{}, err
	}
	if record.State != "closed" && record.State != "verified" {
		return TransferVerification{}, ErrConflict
	}
	// A failed recheck must not leave an earlier healthy proof usable.
	record.State, record.Verification = "closed", nil
	if err = executor.writeResource("transfer-imports", record.Target.ID, record); err != nil {
		return TransferVerification{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, job.Limits.MaximumDuration)
	defer cancel()
	instance, err := executor.instance(job.InstanceID)
	if err != nil {
		return TransferVerification{}, err
	}
	connection, closeConnection, err := executor.connection(bounded, instance)
	if err != nil {
		return TransferVerification{}, err
	}
	defer closeConnection()
	verification, err := executor.observeTransferDatabase(bounded, connection, job, isolated, record.Target)
	if err != nil {
		return TransferVerification{}, err
	}
	record.State, record.Verification = "verified", &verification
	if err = executor.writeResource("transfer-imports", record.Target.ID, record); err != nil {
		return TransferVerification{}, err
	}
	return verification, nil
}

func (executor *LinuxMariaDBExecutor) observeTransferDatabase(bounded context.Context, connection *mariaDBConnection, job TransferJob, isolated IsolatedTransferDatabase, target Database) (TransferVerification, error) {
	observed, err := connection.query(bounded, sqlObserveDatabase, target)
	if err != nil {
		return TransferVerification{}, err
	}
	if len(strings.TrimSpace(string(observed))) == 0 {
		return TransferVerification{}, ErrNotFound
	}
	metadata, err := connection.query(bounded, sqlObserveImportTables, target)
	if err != nil {
		return TransferVerification{}, err
	}
	lines := []string{}
	if strings.TrimSpace(string(metadata)) != "" {
		lines = strings.Split(strings.TrimSpace(string(metadata)), "\n")
	}
	if len(lines) > MaximumTransferTables {
		return TransferVerification{}, ErrTransferLimit
	}
	schema, integrity := sha256.New(), sha256.New()
	verification := TransferVerification{IsolatedToken: isolated.Token, Health: HealthHealthy}
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || (fields[1] != "BASE TABLE" && fields[1] != "VIEW") {
			return TransferVerification{}, ErrTransferInvalid
		}
		name, err := hex.DecodeString(fields[0])
		if err != nil {
			return TransferVerification{}, ErrTransferInvalid
		}
		if fields[1] == "VIEW" {
			view, err := executor.observeTransferView(bounded, connection, isolatedTransferTable{Database: target, Table: string(name)})
			if err != nil {
				return TransferVerification{}, err
			}
			schema.Write([]byte(fields[0] + "\x00VIEW\x00" + view.canonicalDefinition() + "\x00"))
			check, err := connection.query(bounded, sqlCheckImportTable, isolatedTransferTable{Database: target, Table: string(name)})
			if err != nil || !healthyTransferTableCheck(check) {
				return TransferVerification{}, ErrTransferInvalid
			}
			integrity.Write([]byte(fields[0] + "\x00VIEW\x00"))
			integrity.Write(check)
			continue
		}
		switch fields[2] {
		case "InnoDB", "MyISAM", "Aria", "MEMORY":
		default:
			return TransferVerification{}, ErrTransferInvalid
		}
		size, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil || size > job.Limits.MaximumBytes-verification.Bytes {
			return TransferVerification{}, ErrTransferLimit
		}
		verification.Bytes += size
		table := isolatedTransferTable{Database: target, Table: string(name)}
		definition, err := connection.query(bounded, sqlObserveImportSchema, table)
		if err != nil {
			return TransferVerification{}, err
		}
		schema.Write([]byte(fields[0] + "\x00"))
		schema.Write(definition)
		schema.Write([]byte{0})
		count, err := connection.query(bounded, sqlCountImportRows, table)
		if err != nil {
			return TransferVerification{}, err
		}
		rows, err := strconv.ParseUint(strings.TrimSpace(string(count)), 10, 64)
		if err != nil || rows > job.Limits.MaximumRows-verification.RowCount {
			return TransferVerification{}, ErrTransferLimit
		}
		verification.RowCount += rows
		check, err := connection.query(bounded, sqlCheckImportTable, table)
		if err != nil {
			return TransferVerification{}, err
		}
		if !healthyTransferTableCheck(check) {
			return TransferVerification{}, ErrTransferInvalid
		}
		integrity.Write([]byte(fields[0] + "\x00"))
		integrity.Write(count)
		integrity.Write(check)
		integrity.Write([]byte{0})
	}
	verification.SchemaDigest = hex.EncodeToString(schema.Sum(nil))
	verification.IntegrityDigest = hex.EncodeToString(integrity.Sum(nil))
	verification.VerifiedAt = executor.now().UTC()
	verification.Digest = transferVerificationDigest(verification)
	if err = verification.Validate(job, isolated); err != nil {
		return TransferVerification{}, err
	}
	return verification, nil
}

func healthyTransferTableCheck(check []byte) bool {
	results := strings.Split(strings.TrimSpace(string(check)), "\n")
	if len(results) != 1 {
		return false
	}
	result := strings.Split(results[0], "\t")
	return len(result) == 4 && result[1] == "check" && result[2] == "status" && result[3] == "OK"
}
