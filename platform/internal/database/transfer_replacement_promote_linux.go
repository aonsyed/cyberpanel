//go:build linux

package database

import (
	"context"
	"encoding/json"
	"strings"
)

type transferReplacementPlan struct {
	Restore transferReplacementRestorePoint `json:"restore"`
	Before  Database                        `json:"before"`
	Tables  []string                        `json:"tables"`
}

func sameReplacementTables(a, b []string) bool {
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

// Classify only the two complete atomic placements. A partial/unexpected layout
// is not a retry instruction. All schemas and the writer fence remain intact.
func (executor *LinuxMariaDBExecutor) replacementPlacement(ctx context.Context, c *mariaDBConnection, r isolatedTransferRecord) (string, error) {
	p := r.Replacement
	if p == nil || r.Verification == nil {
		return "", ErrAmbiguous
	}
	live, err := replacementTableNames(ctx, c, p.Before)
	if err != nil {
		return "", err
	}
	staged, err := replacementTableNames(ctx, c, r.Target)
	if err != nil {
		return "", err
	}
	restore, err := replacementTableNames(ctx, c, p.Restore.Database)
	if err != nil {
		return "", err
	}
	placement := ""
	if sameReplacementTables(live, p.Restore.Tables) && sameReplacementTables(staged, p.Tables) && len(restore) == 0 {
		placement = "before"
	}
	if sameReplacementTables(live, p.Tables) && len(staged) == 0 && sameReplacementTables(restore, p.Restore.Tables) {
		placement = "after"
	}
	if placement == "" {
		return "", ErrAmbiguous
	}
	oldDB, newDB := p.Before, r.Target
	if placement == "after" {
		oldDB, newDB = p.Restore.Database, p.Before
	}
	old, err := executor.observeTransferDatabase(ctx, c, TransferJob{Limits: p.Restore.Limits}, IsolatedTransferDatabase{Token: p.Restore.Point.Reference}, oldDB)
	if err != nil || old.SchemaDigest != p.Restore.Original.SchemaDigest || old.RowCount != p.Restore.Original.RowCount {
		return "", ErrAmbiguous
	}
	next, err := executor.observeTransferDatabase(ctx, c, r.Job, r.Isolated, newDB)
	if err != nil || next.SchemaDigest != r.Verification.SchemaDigest || next.RowCount != r.Verification.RowCount {
		return "", ErrAmbiguous
	}
	return placement, nil
}

func (executor *LinuxMariaDBExecutor) promoteReplacementTransferImport(ctx context.Context, job TransferJob, isolated IsolatedTransferDatabase, rollback bool) (TransferPromotion, error) {
	result := TransferPromotion{JobID: job.ID, IsolatedToken: isolated.Token, SourceDatabaseID: job.DatabaseID, SourceGeneration: job.DatabaseGeneration, SourcePreserved: true}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	r, err := executor.loadTransferImport(job, isolated)
	if err != nil {
		return result, err
	}
	if r.State == "promoted" && r.Promotion != nil && r.Promotion.Validate(job, isolated) == nil {
		if rollback {
			return result, ErrConflict
		}
		return *r.Promotion, nil
	}
	if r.State == "promotion-verified" {
		if rollback {
			return result, ErrConflict
		}
		if err = executor.releaseTransferWriterFenceLocked(ctx, job.DatabaseID, job.RestorePointRef); err != nil {
			return result, ErrAmbiguous
		}
		return executor.finishVerifiedTransferPromotion(r)
	}
	var f transferWriterFence
	if err = executor.readResource("transfer-fences", job.DatabaseID, &f); err != nil || f.Token != job.RestorePointRef || f.Restore == nil || f.Restore.Point.ProofDigest != job.RestorePointDigest {
		return result, ErrUnauthorized
	}
	instance, err := executor.instance(job.InstanceID)
	if err != nil {
		return result, err
	}
	c, closeC, err := executor.connection(ctx, instance)
	if err != nil {
		return result, err
	}
	defer closeC()
	if r.State == "replacement-rolled-back" {
		return result, executor.releaseTransferWriterFenceLocked(ctx, job.DatabaseID, job.RestorePointRef)
	}
	if err = executor.verifyHeldTransferFence(ctx, c, f); err != nil {
		return result, ErrAmbiguous
	}
	if r.State == "verified" {
		if r.Process == nil || !successfulTransferImport(*r.Process, job) || r.Verification == nil || r.Verification.Validate(job, isolated) != nil {
			return result, ErrConflict
		}
		live, err := executor.transferImportSource(job)
		if err != nil || live.Generation == ^uint64(0) {
			return result, ErrConflict
		}
		tables, err := replacementTableNames(ctx, c, r.Target)
		if err != nil || len(tables) == 0 {
			return result, ErrUnavailable
		}
		r.Replacement = &transferReplacementPlan{Restore: *f.Restore, Before: live, Tables: tables}
		placement, err := executor.replacementPlacement(ctx, c, r)
		if err != nil || placement != "before" {
			return result, ErrAmbiguous
		}
		r.State = "replacement-moving"
		if err = executor.writeResource("transfer-imports", r.Target.ID, r); err != nil {
			return result, err
		}
	}
	if r.State != "replacement-moving" && r.State != "replacement-restoring" {
		return result, ErrAmbiguous
	}
	result.SourcePreserved = false
	placement, err := executor.replacementPlacement(ctx, c, r)
	if err != nil {
		return result, ErrAmbiguous
	}
	if r.State == "replacement-restoring" {
		rollback = true
	}
	if rollback {
		r.State = "replacement-restoring"
		if err = executor.writeResource("transfer-imports", r.Target.ID, r); err != nil {
			return result, ErrAmbiguous
		}
		if placement == "after" {
			if _, err = c.query(ctx, sqlReplaceImportTables, transferReplacementMutation{r.Replacement.Before, r.Replacement.Restore.Database, r.Target, r.Replacement.Tables, r.Replacement.Restore.Tables}); err != nil {
				return result, ErrAmbiguous
			}
		}
		if placement, err = executor.replacementPlacement(ctx, c, r); err != nil || placement != "before" {
			return result, ErrAmbiguous
		}
		r.State = "replacement-rolled-back"
		if err = executor.writeResource("transfer-imports", r.Target.ID, r); err != nil {
			return result, ErrAmbiguous
		}
		if err = executor.releaseTransferWriterFenceLocked(ctx, job.DatabaseID, job.RestorePointRef); err != nil {
			return result, ErrAmbiguous
		}
		result.SourcePreserved = true
		return result, nil
	}
	if placement == "before" {
		if _, err = c.query(ctx, sqlReplaceImportTables, transferReplacementMutation{r.Replacement.Before, r.Target, r.Replacement.Restore.Database, r.Replacement.Restore.Tables, r.Replacement.Tables}); err != nil {
			return result, ErrAmbiguous
		}
	}
	if placement, err = executor.replacementPlacement(ctx, c, r); err != nil || placement != "after" {
		return result, ErrAmbiguous
	}
	after := r.Replacement.Before
	after.Generation++
	after.Status = pendingStatus(LifecycleUpdating)
	proof, _ := json.Marshal(r.Replacement)
	result.TargetGeneration, result.SourcePreserved, result.Promoted = after.Generation, true, true
	result.ProofDigest, result.CompletedAt = transferDigest(proof), executor.now().UTC()
	r.State, r.Promotion = "promotion-verified", &result
	r.PromotionCommit = &transferPromotionCommit{Before: r.Replacement.Before, After: after}
	if err = executor.writeResource("transfer-imports", r.Target.ID, r); err != nil {
		return result, ErrAmbiguous
	}
	if err = executor.releaseTransferWriterFenceLocked(ctx, job.DatabaseID, job.RestorePointRef); err != nil {
		return result, ErrAmbiguous
	}
	return executor.finishVerifiedTransferPromotion(r)
}

type transferReplacementMutation struct {
	Live, Staged, Restore Database
	Old, New              []string
}
