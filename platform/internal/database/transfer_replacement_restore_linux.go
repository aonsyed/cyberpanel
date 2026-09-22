//go:build linux

package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type transferReplacementRestorePoint struct {
	ImportID  ResourceID           `json:"import_id,omitempty"`
	JobDigest string               `json:"job_digest,omitempty"`
	Point     TransferRestorePoint `json:"point"`
	Database  Database             `json:"database"`
	Original  TransferVerification `json:"original"`
	Tables    []string             `json:"tables"`
	Limits    TransferLimits       `json:"limits"`
	State     string               `json:"state"`
}

func replacementTableNames(ctx context.Context, c *mariaDBConnection, db Database) ([]string, error) {
	raw, err := c.query(ctx, sqlObserveImportTables, db)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil, nil
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || f[1] != "BASE TABLE" || !atomicTransferRenameEngine(f[2]) {
			return nil, ErrUnavailable
		}
		name, err := hex.DecodeString(f[0])
		if err != nil {
			return nil, ErrTransferInvalid
		}
		names = append(names, string(name))
	}
	if len(names) > MaximumTransferTables {
		return nil, ErrTransferLimit
	}
	return names, nil
}

func (executor *LinuxMariaDBExecutor) verifyHeldTransferFence(ctx context.Context, c *mariaDBConnection, f transferWriterFence) error {
	if f.State != "held" {
		return ErrAmbiguous
	}
	if err := verifyTransferFenceScope(ctx, c, f); err != nil {
		return err
	}
	for _, a := range f.Accounts {
		identity, locked, grants, err := observeTransferFenceAccount(ctx, c, a.Principal)
		if err != nil || identity != a.Identity || !locked || grants != a.Grants {
			return ErrAmbiguous
		}
		n, err := c.query(ctx, sqlTransferFenceSessions, a.Principal)
		if err != nil || strings.TrimSpace(string(n)) != "0" {
			return ErrAmbiguous
		}
	}
	return nil
}

// The point anchors the original live tables under a durable writer fence. The
// empty restore schema becomes their location in the SAME atomic rename that
// installs the candidate. No original table is copied, overwritten or dropped.
func (executor *LinuxMariaDBExecutor) prepareReplacementRestorePoint(ctx context.Context, db Database, token ResourceID, grants []ResourceID, limits TransferLimits) (TransferRestorePoint, error) {
	if limits.Validate() != nil {
		return TransferRestorePoint{}, ErrTransferInvalid
	}
	drain := limits.MaximumDuration
	if drain > time.Minute {
		drain = time.Minute
	}
	f, err := executor.acquireTransferWriterFence(ctx, db, token, grants, drain)
	if err != nil && (!errors.Is(err, ErrConflict) || f.Token != token || f.Database != db || f.State != "held") {
		return TransferRestorePoint{}, err
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	admit, err := transferFenceAdmissionLock(true)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	defer admit()
	unlock, err := transferFenceJournalLock(db.ID)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	defer unlock()
	ctx = context.WithValue(ctx, transferFenceMutationAuthority{}, true)
	if err = executor.readResource("transfer-fences", db.ID, &f); err != nil || f.Token != token || f.Database != db {
		return TransferRestorePoint{}, ErrUnauthorized
	}
	instance, err := executor.instance(db.InstanceID)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	c, closeC, err := executor.connection(ctx, instance)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	defer closeC()
	if err = executor.verifyHeldTransferFence(ctx, c, f); err != nil {
		return TransferRestorePoint{}, err
	}
	versionRaw, err := c.query(ctx, sqlObserveStatus)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	versionText := strings.Split(strings.TrimSpace(string(versionRaw)), "\t")[0]
	version, err := parseMariaDBVersion(versionText)
	if err != nil || !strings.Contains(versionText, "MariaDB") || compareVersion(version, MariaDBVersion{Major: 10, Minor: 6, Patch: 1}) < 0 {
		return TransferRestorePoint{}, ErrUnavailable
	}
	if f.Restore == nil {
		tables, err := replacementTableNames(ctx, c, db)
		if err != nil || len(tables) == 0 {
			return TransferRestorePoint{}, ErrUnavailable
		}
		original, err := executor.observeTransferDatabase(ctx, c, TransferJob{Limits: limits}, IsolatedTransferDatabase{Token: token}, db)
		if err != nil {
			return TransferRestorePoint{}, err
		}
		restore := db
		suffix := transferDigest([]byte(token.String()))[:24]
		restore.ID, _ = NewResourceID("restore-" + suffix)
		restore.Name, _ = ParseSQLIdentifier("cprst" + suffix)
		restore.Generation = 1
		present, err := c.query(ctx, sqlObserveDatabase, restore)
		if err != nil {
			return TransferRestorePoint{}, err
		}
		if strings.TrimSpace(string(present)) != "" {
			return TransferRestorePoint{}, ErrConflict
		}
		r := &transferReplacementRestorePoint{Database: restore, Original: original, Tables: tables, Limits: limits, State: "creating"}
		r.Point = TransferRestorePoint{Reference: token, DatabaseID: db.ID, DatabaseGeneration: db.Generation, CreatedAt: executor.now().UTC()}
		proof, _ := json.Marshal(r)
		r.Point.ProofDigest = transferDigest(proof)
		f.Restore = r
		if err = executor.writeResource("transfer-fences", db.ID, f); err != nil {
			return TransferRestorePoint{}, err
		}
	}
	r := f.Restore
	if r.Point.Validate() != nil || r.Point.Reference != token || r.Point.DatabaseID != db.ID || r.Point.DatabaseGeneration != db.Generation {
		return TransferRestorePoint{}, ErrAmbiguous
	}
	if r.State == "ready" {
		return r.Point, nil
	}
	if r.State != "creating" {
		return TransferRestorePoint{}, ErrAmbiguous
	}
	present, err := c.query(ctx, sqlObserveDatabase, r.Database)
	if err != nil {
		return TransferRestorePoint{}, err
	}
	if strings.TrimSpace(string(present)) == "" {
		if _, err = c.query(ctx, sqlCreateDatabase, r.Database); err != nil {
			return TransferRestorePoint{}, ErrAmbiguous
		}
	}
	names, err := replacementTableNames(ctx, c, r.Database)
	if err != nil || len(names) != 0 {
		return TransferRestorePoint{}, ErrAmbiguous
	}
	r.State = "ready"
	if err = executor.writeResource("transfer-fences", db.ID, f); err != nil {
		return TransferRestorePoint{}, ErrAmbiguous
	}
	return r.Point, nil
}

// Used only by the authenticated executor, after source-artifact authorization.
// Keep the admission and per-database locks for the complete native phase.
func (executor *LinuxMariaDBExecutor) replacementTransferContext(ctx context.Context, job TransferJob, action string) (context.Context, func(), error) {
	admit, err := transferFenceAdmissionLock(true)
	if err != nil {
		return ctx, nil, err
	}
	unlock, err := transferFenceJournalLock(job.DatabaseID)
	if err != nil {
		admit()
		return ctx, nil, err
	}
	release := func() { unlock(); admit() }
	var f transferWriterFence
	if err = executor.readResource("transfer-fences", job.DatabaseID, &f); err != nil {
		release()
		return ctx, nil, err
	}
	p := TransferRestorePoint{Reference: job.RestorePointRef, DatabaseID: job.DatabaseID, DatabaseGeneration: job.DatabaseGeneration, ProofDigest: job.RestorePointDigest, CreatedAt: job.RestorePointCreatedAt}
	if f.Token != job.RestorePointRef || f.Database.TenantID != job.TenantID || f.Database.SiteID != job.SiteID || f.Database.InstanceID != job.InstanceID || f.Restore == nil || f.Restore.State != "ready" || f.Restore.Point != p {
		release()
		return ctx, nil, ErrUnauthorized
	}
	if f.State != "held" && (action != "recover" && action != "promote" || f.State != "releasing" && f.State != "released") {
		release()
		return ctx, nil, ErrAmbiguous
	}
	if f.Restore.JobDigest != "" && f.Restore.JobDigest != job.Digest {
		release()
		return ctx, nil, ErrUnauthorized
	}
	if f.Restore.JobDigest == "" {
		if f.State != "held" {
			release()
			return ctx, nil, ErrAmbiguous
		}
		f.Restore.JobDigest = job.Digest
		f.Restore.ImportID, _ = isolatedTransferIdentity(job)
		if err = executor.writeResource("transfer-fences", job.DatabaseID, f); err != nil {
			release()
			return ctx, nil, err
		}
	}
	return context.WithValue(ctx, transferFenceMutationAuthority{}, true), release, nil
}
