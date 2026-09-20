//go:build linux

package database

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"
)

// Preview measures the current destination, not the source dump. Promotion
// checks again under writer authority; a preview is never mutation authority.
func (executor *LinuxMariaDBExecutor) previewTransferImport(ctx context.Context, job TransferJob) (TransferImpactPreview, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	database, err := executor.transferImportSource(job)
	if err != nil {
		return TransferImpactPreview{}, err
	}
	instance, err := executor.instance(job.InstanceID)
	if err != nil {
		return TransferImpactPreview{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, job.Limits.MaximumDuration)
	defer cancel()
	connection, closeConnection, err := executor.connection(ctx, instance)
	if err != nil {
		return TransferImpactPreview{}, err
	}
	defer closeConnection()
	exists, err := connection.query(ctx, sqlObserveDatabase, database)
	if err != nil {
		return TransferImpactPreview{}, err
	}
	if strings.TrimSpace(string(exists)) == "" {
		return TransferImpactPreview{}, ErrNotFound
	}
	metadata, err := connection.query(ctx, sqlObserveImportTables, database)
	if err != nil {
		return TransferImpactPreview{}, err
	}
	preview := TransferImpactPreview{DatabaseID: job.DatabaseID, DatabaseGeneration: job.DatabaseGeneration, CapturedAt: executor.now().UTC()}
	if strings.TrimSpace(string(metadata)) != "" {
		for _, line := range strings.Split(strings.TrimSpace(string(metadata)), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) != 4 || fields[1] != "BASE TABLE" || preview.SchemaObjects >= MaximumTransferTables {
				return TransferImpactPreview{}, ErrTransferInvalid
			}
			name, err := hex.DecodeString(fields[0])
			if err != nil {
				return TransferImpactPreview{}, ErrTransferInvalid
			}
			size, err := strconv.ParseUint(fields[3], 10, 64)
			if err != nil || size > MaximumTransferBytes-preview.Bytes {
				return TransferImpactPreview{}, ErrTransferLimit
			}
			count, err := connection.query(ctx, sqlCountImportRows, isolatedTransferTable{Database: database, Table: string(name)})
			if err != nil {
				return TransferImpactPreview{}, err
			}
			rows, err := strconv.ParseUint(strings.TrimSpace(string(count)), 10, 64)
			if err != nil || rows > MaximumTransferRows-preview.Rows {
				return TransferImpactPreview{}, ErrTransferLimit
			}
			preview.SchemaObjects++
			preview.Bytes += size
			preview.Rows += rows
		}
	}
	return SealTransferImpactPreview(preview), nil
}
