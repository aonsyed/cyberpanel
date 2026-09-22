package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"time"
)

func (operations *DatabaseTransferOperations) authorizeReplacement(ctx context.Context, inv Invocation, p DatabaseReplacementPayload, action string) (database.Database, error) {
	job, a := p.Job, p.Approval
	if job.Validate() != nil || job.Direction != database.TransferImport || job.ExportSource == nil || job.UploadSource != nil || job.CreatedBy != inv.Actor.PrincipalID.String() || job.TenantID.String() != inv.Request.TenantID || job.SiteID.String() != inv.Request.ResourceID || a.DatabaseID != job.DatabaseID || a.Generation != job.DatabaseGeneration || a.JobDigest != job.Digest || a.Action != action || a.DatabaseName == "" || a.RestorePointRef.IsZero() {
		return database.Database{}, database.ErrUnauthorized
	}
	gate := databaseTransferAuthority{operations: operations, invocation: inv}
	if err := gate.AuthorizeDatabaseTransfer(ctx, database.TransferAuthorizationRequest{Actor: job.CreatedBy, TenantID: job.TenantID, SiteID: job.SiteID, DatabaseID: job.DatabaseID, JobID: job.ID, Action: database.AuthorizeTransferExecute}); err != nil {
		return database.Database{}, err
	}
	envelope, err := operations.repository.LoadResource(ctx, database.KindDatabase, job.DatabaseID)
	if err != nil {
		return database.Database{}, err
	}
	r, err := database.DecodeResource(envelope)
	if err != nil {
		return database.Database{}, err
	}
	db, ok := r.(*database.Database)
	if !ok || db.Name.String() != a.DatabaseName || db.InstanceID != job.InstanceID {
		return database.Database{}, database.ErrUnauthorized
	}
	return *db, nil
}

func (operations *DatabaseTransferOperations) RunDatabaseReplacement(ctx context.Context, inv Invocation, p DatabaseReplacementPayload) (database.TransferReceipt, error) {
	if inv.Request.Operation != "database.import.replace.run" || p.Job.ConflictPolicy != database.TransferConflictFail || p.Approval.RestorePointRef != p.Job.ID || inv.Request.ExpectedGeneration != p.Job.DatabaseGeneration {
		return database.TransferReceipt{}, database.ErrUnauthorized
	}
	target, err := operations.authorizeReplacement(ctx, inv, p, "replace")
	if err != nil {
		return database.TransferReceipt{}, err
	}
	// Replay reconstructs the final job from durable state, never reacquires an
	// already committed replacement or silently creates a new recovery point.
	if state, e := operations.jobs.LoadTransfer(ctx, p.Job.ID); e == nil {
		base := state.Job
		base.ConflictPolicy = database.TransferConflictFail
		base.RestorePointRef = database.ResourceID{}
		base.RestorePointDigest = ""
		base.RestorePointCreatedAt = time.Time{}
		base, e = database.SealTransferJob(base)
		if e != nil || base.Digest != p.Job.Digest {
			return database.TransferReceipt{}, database.ErrTransferStale
		}
		return operations.runDatabaseImport(ctx, inv, state.Job, &p.Approval)
	} else if !errors.Is(e, database.ErrNotFound) {
		return database.TransferReceipt{}, e
	}
	if target.Generation != p.Job.DatabaseGeneration {
		return database.TransferReceipt{}, database.ErrTransferStale
	}
	if target.Status.Lifecycle != database.LifecycleReady || target.Status.Health != database.HealthHealthy || target.Status.Reconciliation != database.ReconciliationInSync {
		return database.TransferReceipt{}, database.ErrUnavailable
	}
	now := time.Now().UTC()
	if p.Job.CreatedAt.After(now.Add(time.Minute)) || now.Sub(p.Job.CreatedAt) > 15*time.Minute || p.Job.Impact.CapturedAt.After(now.Add(time.Minute)) || now.Sub(p.Job.Impact.CapturedAt) > 15*time.Minute {
		return database.TransferReceipt{}, database.ErrTransferStale
	}
	if _, err = operations.service(inv, p.Job); err != nil {
		return database.TransferReceipt{}, err
	}
	if err = operations.recordReplacementApproval(ctx, inv, p); err != nil {
		return database.TransferReceipt{}, err
	}
	point, err := operations.coordinator.ReplacementPoint(ctx, p.Job, "replacement-prepare")
	if err != nil {
		return database.TransferReceipt{}, err
	}
	job := p.Job
	job.ConflictPolicy = database.TransferConflictReplace
	job.RestorePointRef = point.Reference
	job.RestorePointDigest = point.ProofDigest
	job.RestorePointCreatedAt = point.CreatedAt
	job, err = database.SealTransferJob(job)
	if err != nil {
		return database.TransferReceipt{}, err
	}
	return operations.runDatabaseImport(ctx, inv, job, &p.Approval)
}

func (operations *DatabaseTransferOperations) RetireDatabaseReplacement(ctx context.Context, inv Invocation, p DatabaseReplacementPayload) (database.TransferRestorePoint, error) {
	if inv.Request.Operation != "database.import.restore_point.retire" || p.Job.ConflictPolicy != database.TransferConflictReplace || p.Approval.RestorePointRef != p.Job.RestorePointRef {
		return database.TransferRestorePoint{}, database.ErrUnauthorized
	}
	target, err := operations.authorizeReplacement(ctx, inv, p, "retire")
	if err != nil {
		return database.TransferRestorePoint{}, err
	}
	if target.Generation != p.Job.DatabaseGeneration+1 || inv.Request.ExpectedGeneration != target.Generation {
		return database.TransferRestorePoint{}, database.ErrTransferStale
	}
	state, err := operations.jobs.LoadTransfer(ctx, p.Job.ID)
	if err != nil {
		return database.TransferRestorePoint{}, err
	}
	if state.Job.Digest != p.Job.Digest || state.Status != database.TransferCompleted {
		return database.TransferRestorePoint{}, database.ErrConflict
	}
	if err = operations.recordReplacementApproval(ctx, inv, p); err != nil {
		return database.TransferRestorePoint{}, err
	}
	return operations.coordinator.ReplacementPoint(ctx, p.Job, "replacement-retire")
}

func (operations *DatabaseTransferOperations) AbortDatabaseReplacement(ctx context.Context, inv Invocation, p DatabaseReplacementPayload) error {
	if inv.Request.Operation != "database.import.replace.abort" || p.Job.ConflictPolicy != database.TransferConflictFail || p.Approval.RestorePointRef != p.Job.ID {
		return database.ErrUnauthorized
	}
	target, err := operations.authorizeReplacement(ctx, inv, p, "abort")
	if err != nil {
		return err
	}
	if target.Generation != p.Job.DatabaseGeneration || inv.Request.ExpectedGeneration != target.Generation {
		return database.ErrTransferStale
	}
	if state, e := operations.jobs.LoadTransfer(ctx, p.Job.ID); e == nil {
		if state.Status != database.TransferFailed && state.Status != database.TransferCancelled {
			return database.ErrConflict
		}
		base := state.Job
		base.ConflictPolicy = database.TransferConflictFail
		base.RestorePointRef = database.ResourceID{}
		base.RestorePointDigest = ""
		base.RestorePointCreatedAt = time.Time{}
		base, e = database.SealTransferJob(base)
		if e != nil || base.Digest != p.Job.Digest {
			return database.ErrTransferStale
		}
	} else if !errors.Is(e, database.ErrNotFound) {
		return e
	}
	if err = operations.recordReplacementApproval(ctx, inv, p); err != nil {
		return err
	}
	_, err = operations.coordinator.ReplacementPoint(ctx, p.Job, "replacement-abort")
	return err
}

func (operations *DatabaseTransferOperations) recordReplacementApproval(ctx context.Context, inv Invocation, p DatabaseReplacementPayload) error {
	if operations.audit == nil {
		return database.ErrUnavailable
	}
	raw, err := json.Marshal(p.Approval)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	eventSum := sha256.Sum256([]byte(inv.Request.RequestID + "\x00" + digest + "\x00" + now.Format(time.RFC3339Nano)))
	_, err = operations.audit.Append(ctx, audit.Event{ID: "dbreplacement-" + hex.EncodeToString(eventSum[:]), Class: audit.ClassAuthorization, Action: inv.Request.Operation, Actor: audit.Actor{PrincipalID: inv.Actor.PrincipalID.String(), CredentialID: inv.Actor.CredentialID.String(), SessionID: inv.Actor.SessionID.String(), TenantID: inv.Request.TenantID, AuthzEpoch: inv.Actor.AuthzEpoch, Assurance: fmt.Sprint(inv.Actor.Assurance), Origin: inv.Meta.Origin}, Target: audit.Target{Kind: "database", ID: p.Job.DatabaseID.String(), TenantID: inv.Request.TenantID, Generation: fmt.Sprint(inv.Request.ExpectedGeneration)}, Outcome: audit.OutcomeAllowed, RequestDigest: digest, TraceID: inv.Request.RequestID, Attributes: map[string]string{"database_name": p.Approval.DatabaseName, "restore_point_ref": p.Approval.RestorePointRef.String(), "job_digest": p.Approval.JobDigest, "approval_action": p.Approval.Action}, OccurredAt: now})
	return err
}
