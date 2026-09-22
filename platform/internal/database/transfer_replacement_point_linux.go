//go:build linux

package database

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func (executor *LinuxMariaDBExecutor) executeReplacementPoint(ctx context.Context, request TransferImportRequest) (TransferRestorePoint, error) {
	job := request.Job
	if request.Action == "replacement-prepare" {
		db, err := executor.transferImportSource(job)
		if err != nil {
			return TransferRestorePoint{}, err
		}
		if _, err = executor.importArtifactStore(ctx, job); err != nil {
			return TransferRestorePoint{}, err
		}
		entries, err := os.ReadDir(filepath.Join(mariaDBStateRoot, "grants"))
		if err != nil {
			return TransferRestorePoint{}, err
		}
		var ids []ResourceID
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			var g GrantSet
			if err = executor.readNamed("grants", entry.Name(), &g); err != nil {
				return TransferRestorePoint{}, err
			}
			if g.DatabaseID == db.ID {
				ids = append(ids, g.ID)
			}
		}
		return executor.prepareReplacementRestorePoint(ctx, db, job.ID, ids, job.Limits)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	admit, err := transferFenceAdmissionLock(true)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	defer admit()
	unlock, err := transferFenceJournalLock(job.DatabaseID)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	defer unlock()
	ctx = context.WithValue(ctx, transferFenceMutationAuthority{}, true)
	var f transferWriterFence
	if err = executor.readResource("transfer-fences", job.DatabaseID, &f); err != nil {
		return TransferRestorePoint{}, err
	}
	if request.Action == "replacement-abort" {
		if f.Token != job.ID || f.Database.Generation != job.DatabaseGeneration || f.Database.TenantID != job.TenantID || f.Database.SiteID != job.SiteID || f.Database.InstanceID != job.InstanceID {
			return TransferRestorePoint{}, ErrConflict
		}
		if f.Restore != nil && !f.Restore.ImportID.IsZero() {
			var imp isolatedTransferRecord
			if e := executor.readResource("transfer-imports", f.Restore.ImportID, &imp); e == nil {
				switch imp.State {
				case "allocated", "closed", "verified":
				default:
					return TransferRestorePoint{}, ErrAmbiguous
				}
			} else if !errors.Is(e, ErrNotFound) {
				return TransferRestorePoint{}, e
			}
			job.Digest = f.Restore.JobDigest
		}
		if f.Restore == nil {
			return TransferRestorePoint{}, executor.releaseTransferWriterFenceLocked(ctx, job.DatabaseID, f.Token)
		}
		job.RestorePointRef = f.Restore.Point.Reference
		job.RestorePointDigest = f.Restore.Point.ProofDigest
		job.RestorePointCreatedAt = f.Restore.Point.CreatedAt
	}
	p := TransferRestorePoint{Reference: job.RestorePointRef, DatabaseID: job.DatabaseID, DatabaseGeneration: job.DatabaseGeneration, ProofDigest: job.RestorePointDigest, CreatedAt: job.RestorePointCreatedAt}
	if f.Restore == nil || f.Restore.Point != p || f.Database.TenantID != job.TenantID || f.Database.SiteID != job.SiteID || f.Database.InstanceID != job.InstanceID || f.Restore.JobDigest != "" && f.Restore.JobDigest != job.Digest {
		return TransferRestorePoint{}, ErrUnauthorized
	}
	if request.Action == "replacement-inspect" {
		if f.Restore.State != "ready" || f.State != "held" {
			return TransferRestorePoint{}, ErrAmbiguous
		}
		return p, nil
	}
	if f.Restore.State == "retired" {
		return p, nil
	}
	instance, err := executor.instance(job.InstanceID)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	c, closeC, err := executor.connection(ctx, instance)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	defer closeC()
	nativeIdentity, err := c.query(ctx, sqlTransferFenceIdentity)
	if err != nil || strings.TrimSpace(string(nativeIdentity)) != f.NativeIdentity {
		return TransferRestorePoint{}, ErrAmbiguous
	}
	if request.Action == "replacement-abort" {
		names, err := replacementTableNames(ctx, c, f.Restore.Database)
		if err != nil || len(names) != 0 {
			return TransferRestorePoint{}, ErrAmbiguous
		}
		if f.State != "released" {
			original, err := executor.observeTransferDatabase(ctx, c, TransferJob{Limits: f.Restore.Limits}, IsolatedTransferDatabase{Token: f.Token}, f.Database)
			if err != nil || original.SchemaDigest != f.Restore.Original.SchemaDigest || original.RowCount != f.Restore.Original.RowCount {
				return TransferRestorePoint{}, ErrAmbiguous
			}
		}
		if err = executor.releaseTransferWriterFenceLocked(ctx, job.DatabaseID, f.Token); err != nil {
			return TransferRestorePoint{}, err
		}
		if err = executor.readResource("transfer-fences", job.DatabaseID, &f); err != nil {
			return TransferRestorePoint{}, err
		}
	} else {
		var imp isolatedTransferRecord
		if f.State != "released" || f.Restore.ImportID.IsZero() || executor.readResource("transfer-imports", f.Restore.ImportID, &imp) != nil || imp.State != "promoted" || imp.Job.Digest != job.Digest || imp.Promotion == nil || !imp.Promotion.Promoted {
			return TransferRestorePoint{}, ErrAmbiguous
		}
		var current Database
		if executor.readResource("databases", job.DatabaseID, &current) != nil || current.Generation != job.DatabaseGeneration+1 {
			return TransferRestorePoint{}, ErrTransferStale
		}
	}
	present, err := c.query(ctx, sqlObserveDatabase, f.Restore.Database)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	if strings.TrimSpace(string(present)) != "" {
		if f.Restore.State != "retiring" {
			names, err := replacementTableNames(ctx, c, f.Restore.Database)
			if err != nil {
				return TransferRestorePoint{}, err
			}
			if request.Action == "replacement-abort" {
				if len(names) != 0 {
					return TransferRestorePoint{}, ErrAmbiguous
				}
			} else {
				if !sameReplacementTables(names, f.Restore.Tables) {
					return TransferRestorePoint{}, ErrAmbiguous
				}
				original, err := executor.observeTransferDatabase(ctx, c, TransferJob{Limits: f.Restore.Limits}, IsolatedTransferDatabase{Token: f.Token}, f.Restore.Database)
				if err != nil || original.SchemaDigest != f.Restore.Original.SchemaDigest || original.RowCount != f.Restore.Original.RowCount {
					return TransferRestorePoint{}, ErrAmbiguous
				}
			}
		}
		f.Restore.State = "retiring"
		if err = executor.writeResource("transfer-fences", job.DatabaseID, f); err != nil {
			return TransferRestorePoint{}, err
		}
		if _, err = c.query(ctx, sqlDropDatabase, f.Restore.Database); err != nil {
			return TransferRestorePoint{}, ErrAmbiguous
		}
	} else if f.Restore.State != "retiring" && !(request.Action == "replacement-abort" && f.Restore.State == "creating") {
		return TransferRestorePoint{}, ErrAmbiguous
	}
	f.Restore.State = "retired"
	if err = executor.writeResource("transfer-fences", job.DatabaseID, f); err != nil {
		return TransferRestorePoint{}, err
	}
	return p, nil
}
