//go:build linux

package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
)

type isolatedTransferRename struct {
	From, To Database
	Tables   []string
}

// Written only after the native move, verification and isolated-schema cleanup
// succeeded. Recovery can finish this exact metadata transition without SQL.
type transferPromotionCommit struct {
	Before Database `json:"before"`
	After  Database `json:"after"`
}

func (executor *LinuxMariaDBExecutor) finishVerifiedTransferPromotion(record isolatedTransferRecord) (TransferPromotion, error) {
	job, isolated := record.Job, record.Isolated
	ambiguous := TransferPromotion{JobID: job.ID, IsolatedToken: isolated.Token, SourceDatabaseID: job.DatabaseID, SourceGeneration: job.DatabaseGeneration}
	commit := record.PromotionCommit
	if record.State != "promotion-verified" || commit == nil || record.Promotion == nil || record.Promotion.Validate(job, isolated) != nil || commit.Before.Validate() != nil || commit.Before.ID != job.DatabaseID || commit.Before.Generation != job.DatabaseGeneration || commit.Before.Generation == ^uint64(0) || commit.Before.TenantID != job.TenantID || commit.Before.SiteID != job.SiteID || commit.Before.InstanceID != job.InstanceID {
		return ambiguous, ErrAmbiguous
	}
	expected := commit.Before
	expected.Generation++
	expected.Status = pendingStatus(LifecycleUpdating)
	if commit.After != expected || record.Promotion.TargetGeneration != expected.Generation {
		return ambiguous, ErrAmbiguous
	}
	var current Database
	if err := executor.readResource("databases", job.DatabaseID, &current); err != nil {
		return ambiguous, ErrAmbiguous
	}
	if current == commit.Before {
		if err := executor.writeResource("databases", job.DatabaseID, commit.After); err != nil {
			return ambiguous, ErrAmbiguous
		}
	} else if current != commit.After {
		return ambiguous, ErrAmbiguous
	}
	record.State = "promoted"
	if err := executor.writeResource("transfer-imports", record.Target.ID, record); err != nil {
		return ambiguous, ErrAmbiguous
	}
	return *record.Promotion, nil
}

func transferRenameSQL(rename isolatedTransferRename) (string, error) {
	if rename.From.Validate() != nil || rename.To.Validate() != nil || rename.From.Name == rename.To.Name || rename.From.InstanceID != rename.To.InstanceID || len(rename.Tables) == 0 || len(rename.Tables) > MaximumTransferTables {
		return "", ErrInvalidResource
	}
	parts := make([]string, 0, len(rename.Tables))
	for _, name := range rename.Tables {
		from, err := isolatedTableSQL(isolatedTransferTable{Database: rename.From, Table: name})
		if err != nil {
			return "", err
		}
		to, err := isolatedTableSQL(isolatedTransferTable{Database: rename.To, Table: name})
		if err != nil {
			return "", err
		}
		parts = append(parts, from+" TO "+to)
	}
	return "RENAME TABLE " + strings.Join(parts, ", ") + ";\n", nil
}

// Non-replacing promotion keeps the destination schema/name/grants intact and
// moves tables in one native statement. Replace mode needs restore-point support.
func (executor *LinuxMariaDBExecutor) promoteEmptyTransferImport(ctx context.Context, job TransferJob, isolated IsolatedTransferDatabase) (TransferPromotion, error) {
	result := TransferPromotion{JobID: job.ID, IsolatedToken: isolated.Token, SourceDatabaseID: job.DatabaseID, SourceGeneration: job.DatabaseGeneration, SourcePreserved: true}
	if executor == nil || ctx == nil || job.ConflictPolicy != TransferConflictFail {
		return result, ErrUnauthorized
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	record, err := executor.loadTransferImport(job, isolated)
	if err != nil {
		return result, err
	}
	if record.State == "promoted" && record.Promotion != nil && record.Promotion.Validate(job, isolated) == nil {
		return *record.Promotion, nil
	}
	if record.State == "promotion-verified" {
		_, release, err := executor.beginWriterMutation(ctx)
		if err != nil {
			result.SourcePreserved = false
			return result, ErrAmbiguous
		}
		defer release()
		return executor.finishVerifiedTransferPromotion(record)
	}
	if record.State == "promoting" {
		result.SourcePreserved = false
		return result, ErrAmbiguous
	}
	if record.State != "verified" || record.Verification == nil || record.Verification.Validate(job, isolated) != nil {
		return result, ErrConflict
	}
	live, err := executor.transferImportSource(job)
	if err != nil {
		return result, err
	}
	if live.Generation == ^uint64(0) {
		return result, ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, job.Limits.MaximumDuration)
	defer cancel()
	ctx, release, err := executor.beginWriterMutation(ctx)
	if err != nil {
		return result, err
	}
	defer release()
	instance, err := executor.instance(job.InstanceID)
	if err != nil {
		return result, err
	}
	connection, closeConnection, err := executor.connection(ctx, instance)
	if err != nil {
		return result, err
	}
	defer closeConnection()
	status, err := connection.query(ctx, sqlObserveStatus)
	if err != nil {
		return result, err
	}
	versionText := strings.Split(strings.TrimSpace(string(status)), "\t")[0]
	version, err := parseMariaDBVersion(versionText)
	if err != nil || !strings.Contains(versionText, "MariaDB") || compareVersion(version, MariaDBVersion{Major: 10, Minor: 6, Patch: 1}) < 0 {
		return result, ErrUnavailable
	}
	existing, err := connection.query(ctx, sqlObserveImportTables, live)
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(string(existing)) != "" {
		return result, ErrConflict
	}
	verified, err := executor.observeTransferDatabase(ctx, connection, job, isolated, record.Target)
	if err != nil {
		return result, err
	}
	if verified.SchemaDigest != record.Verification.SchemaDigest || verified.RowCount != record.Verification.RowCount {
		return result, ErrTransferStale
	}
	metadata, err := connection.query(ctx, sqlObserveImportTables, record.Target)
	if err != nil {
		return result, err
	}
	var tables []string
	if strings.TrimSpace(string(metadata)) != "" {
		for _, line := range strings.Split(strings.TrimSpace(string(metadata)), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) != 4 || fields[1] != "BASE TABLE" || fields[2] != "InnoDB" {
				return result, ErrUnavailable
			}
			name, err := hex.DecodeString(fields[0])
			if err != nil {
				return result, ErrTransferInvalid
			}
			tables = append(tables, string(name))
		}
	}
	record.State = "promoting"
	if err = executor.writeResource("transfer-imports", record.Target.ID, record); err != nil {
		return result, err
	}
	// From this point a lost response is ambiguous, never a reason to repeat a
	// destructive operation or discard a possibly partially activated import.
	result.SourcePreserved = false
	if len(tables) > 0 {
		if _, err = connection.query(ctx, sqlPromoteImportTables, isolatedTransferRename{From: record.Target, To: live, Tables: tables}); err != nil {
			return result, ErrAmbiguous
		}
	}
	confirmed, err := executor.observeTransferDatabase(ctx, connection, job, isolated, live)
	if err != nil || confirmed.SchemaDigest != verified.SchemaDigest {
		return result, ErrAmbiguous
	}
	remaining, err := connection.query(ctx, sqlObserveImportTables, record.Target)
	if err != nil || strings.TrimSpace(string(remaining)) != "" {
		return result, ErrAmbiguous
	}
	if _, err = connection.query(ctx, sqlDropDatabase, record.Target); err != nil {
		return result, ErrAmbiguous
	}
	before := live
	live.Generation++
	live.Status = pendingStatus(LifecycleUpdating)
	proof, _ := json.Marshal(struct {
		Before, After TransferVerification
		Tables        []string
	}{verified, confirmed, tables})
	result.TargetGeneration, result.SourcePreserved, result.Promoted = live.Generation, true, true
	result.ProofDigest, result.CompletedAt = transferDigest(proof), executor.now().UTC()
	record.State, record.Promotion = "promotion-verified", &result
	record.PromotionCommit = &transferPromotionCommit{Before: before, After: live}
	if err = executor.writeResource("transfer-imports", record.Target.ID, record); err != nil {
		result.SourcePreserved = false
		return result, ErrAmbiguous
	}
	return executor.finishVerifiedTransferPromotion(record)
}
