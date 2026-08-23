package database

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

type TransferAuthorizationAction string

const (
	AuthorizeTransferCreate  TransferAuthorizationAction = "transfer.create"
	AuthorizeTransferRead    TransferAuthorizationAction = "transfer.read"
	AuthorizeTransferCancel  TransferAuthorizationAction = "transfer.cancel"
	AuthorizeTransferExecute TransferAuthorizationAction = "transfer.execute"
)

type TransferAuthorizationRequest struct {
	Actor      string                      `json:"actor"`
	TenantID   site.TenantID               `json:"tenant_id"`
	SiteID     site.SiteID                 `json:"site_id"`
	DatabaseID ResourceID                  `json:"database_id"`
	JobID      ResourceID                  `json:"job_id"`
	Action     TransferAuthorizationAction `json:"action"`
}

func (request TransferAuthorizationRequest) Validate() error {
	if !validTransferIdentifier(request.Actor) || request.TenantID.String() == "" || request.SiteID.String() == "" || request.DatabaseID.IsZero() || request.JobID.IsZero() { return ErrTransferInvalid }
	switch request.Action {
	case AuthorizeTransferCreate, AuthorizeTransferRead, AuthorizeTransferCancel, AuthorizeTransferExecute:
		return nil
	default:
		return ErrTransferInvalid
	}
}

type TransferAuthorizer interface {
	AuthorizeDatabaseTransfer(context.Context, TransferAuthorizationRequest) error
}

type TransferStepUpRequest struct {
	Actor        string     `json:"actor"`
	TenantID     site.TenantID `json:"tenant_id"`
	DatabaseID   ResourceID `json:"database_id"`
	JobID        ResourceID `json:"job_id"`
	AssertionRef ResourceID `json:"assertion_ref"`
	Revision     uint64     `json:"revision"`
}

func (request TransferStepUpRequest) Validate() error {
	if !validTransferIdentifier(request.Actor) || request.TenantID.String() == "" || request.DatabaseID.IsZero() || request.JobID.IsZero() || request.AssertionRef.IsZero() || request.Revision == 0 { return ErrTransferInvalid }
	return nil
}

type TransferStepUpVerifier interface {
	VerifyDatabaseTransferStepUp(context.Context, TransferStepUpRequest) error
}

type TransferAuditRecord struct {
	Actor          string                      `json:"actor"`
	TenantID       site.TenantID               `json:"tenant_id"`
	SiteID         site.SiteID                 `json:"site_id"`
	DatabaseID     ResourceID                  `json:"database_id"`
	JobID          ResourceID                  `json:"job_id"`
	Action         TransferAuthorizationAction `json:"action"`
	Outcome        string                      `json:"outcome"`
	ResourceDigest string                      `json:"resource_digest,omitempty"`
	EvidenceDigest string                      `json:"evidence_digest,omitempty"`
	Generation     uint64                      `json:"generation,omitempty"`
	OccurredAt     time.Time                   `json:"occurred_at"`
	Digest         string                      `json:"digest"`
}

func (record TransferAuditRecord) Validate() error {
	if (TransferAuthorizationRequest{Actor: record.Actor, TenantID: record.TenantID, SiteID: record.SiteID, DatabaseID: record.DatabaseID, JobID: record.JobID, Action: record.Action}).Validate() != nil ||
		!validTransferCode(record.Outcome) || record.ResourceDigest != "" && !validSHA256(record.ResourceDigest) || record.EvidenceDigest != "" && !validSHA256(record.EvidenceDigest) ||
		record.OccurredAt.IsZero() || !validSHA256(record.Digest) || transferAuditDigest(record) != record.Digest { return ErrTransferInvalid }
	return nil
}

func transferAuditDigest(record TransferAuditRecord) string {
	record.Digest = ""
	encoded, _ := json.Marshal(record)
	return transferDigest(encoded)
}

type TransferAuditSink interface {
	RecordDatabaseTransfer(context.Context, TransferAuditRecord) error
}

type TransferRestorePoint struct {
	Reference          ResourceID `json:"reference"`
	DatabaseID         ResourceID `json:"database_id"`
	DatabaseGeneration uint64     `json:"database_generation"`
	ProofDigest        string     `json:"proof_digest"`
	CreatedAt          time.Time  `json:"created_at"`
}

func (point TransferRestorePoint) Validate() error {
	if point.Reference.IsZero() || point.DatabaseID.IsZero() || point.DatabaseGeneration == 0 || !validSHA256(point.ProofDigest) || point.CreatedAt.IsZero() { return ErrTransferInvalid }
	return nil
}

type TransferRecoveryPoints interface {
	CreateDatabaseTransferRestorePoint(context.Context, TransferJob, Database) (TransferRestorePoint, error)
}

type IsolatedTransferDatabase struct {
	Token              ResourceID    `json:"token"`
	InstanceID         ResourceID    `json:"instance_id"`
	Name               SQLIdentifier `json:"name"`
	SourceDatabaseID   ResourceID    `json:"source_database_id"`
	SourceGeneration   uint64        `json:"source_generation"`
	CreatedAt          time.Time     `json:"created_at"`
}

func (database IsolatedTransferDatabase) Validate(job TransferJob) error {
	if database.Token.IsZero() || database.InstanceID != job.InstanceID || database.Name.IsZero() || database.SourceDatabaseID != job.DatabaseID || database.SourceGeneration != job.DatabaseGeneration || database.CreatedAt.IsZero() { return ErrTransferInvalid }
	return nil
}

type TransferVerification struct {
	IsolatedToken   ResourceID `json:"isolated_token"`
	SchemaDigest    string     `json:"schema_digest"`
	RowCount        uint64     `json:"row_count"`
	Bytes           uint64     `json:"bytes"`
	IntegrityDigest string     `json:"integrity_digest"`
	Health          Health     `json:"health"`
	VerifiedAt      time.Time  `json:"verified_at"`
	Digest          string     `json:"digest"`
}

func (verification TransferVerification) Validate(job TransferJob, isolated IsolatedTransferDatabase) error {
	if verification.IsolatedToken != isolated.Token || !validSHA256(verification.SchemaDigest) || verification.RowCount > job.Limits.MaximumRows || verification.Bytes > job.Limits.MaximumBytes ||
		!validSHA256(verification.IntegrityDigest) || verification.Health != HealthHealthy || verification.VerifiedAt.IsZero() || !validSHA256(verification.Digest) || transferVerificationDigest(verification) != verification.Digest { return ErrTransferInvalid }
	if job.Source != nil && verification.RowCount != job.Source.Rows { return ErrTransferInvalid }
	return nil
}

func transferVerificationDigest(verification TransferVerification) string {
	verification.Digest = ""
	encoded, _ := json.Marshal(verification)
	return transferDigest(encoded)
}

type TransferPromotion struct {
	JobID               ResourceID `json:"job_id"`
	IsolatedToken       ResourceID `json:"isolated_token"`
	SourceDatabaseID    ResourceID `json:"source_database_id"`
	SourceGeneration    uint64     `json:"source_generation"`
	TargetGeneration    uint64     `json:"target_generation"`
	SourcePreserved     bool       `json:"source_preserved"`
	Promoted            bool       `json:"promoted"`
	ProofDigest         string     `json:"proof_digest"`
	CompletedAt         time.Time  `json:"completed_at"`
}

func (promotion TransferPromotion) Validate(job TransferJob, isolated IsolatedTransferDatabase) error {
	if promotion.JobID != job.ID || promotion.IsolatedToken != isolated.Token || promotion.SourceDatabaseID != job.DatabaseID || promotion.SourceGeneration != job.DatabaseGeneration ||
		promotion.TargetGeneration <= promotion.SourceGeneration || !promotion.SourcePreserved || !promotion.Promoted || !validSHA256(promotion.ProofDigest) || promotion.CompletedAt.IsZero() { return ErrTransferInvalid }
	return nil
}

type TransferDatabaseCatalog interface {
	LoadTransferDatabase(context.Context, site.TenantID, site.SiteID, ResourceID) (Database, error)
	PreviewDatabaseTransfer(context.Context, Database, TransferDirection, TransferSelection, *TransferArtifactDescriptor) (TransferImpactPreview, error)
	AllocateIsolatedTransferDatabase(context.Context, TransferJob, Database) (IsolatedTransferDatabase, error)
	VerifyIsolatedTransferDatabase(context.Context, TransferJob, IsolatedTransferDatabase) (TransferVerification, error)
	PromoteIsolatedTransferDatabase(context.Context, TransferJob, Database, IsolatedTransferDatabase, TransferRestorePoint) (TransferPromotion, error)
	DiscardIsolatedTransferDatabase(context.Context, TransferJob, IsolatedTransferDatabase) error
}

type TransferBackend interface {
	Export(context.Context, TransferJob, SQLIdentifier, TransferCheckpoint) (TransferProcessReceipt, error)
	Import(context.Context, TransferJob, SQLIdentifier, TransferCheckpoint) (TransferProcessReceipt, error)
}

type TransferStateRepository interface {
	BootstrapTransfers(context.Context) error
	CreateTransfer(context.Context, TransferJob) (TransferJobState, error)
	LoadTransfer(context.Context, ResourceID) (TransferJobState, error)
	LatestTransferReceipt(context.Context, ResourceID) (TransferReceipt, error)
	ClaimTransfer(context.Context, ResourceID, string, uint64, time.Time, time.Duration) (TransferLease, error)
	CheckpointTransfer(context.Context, TransferLease, TransferProgress) (TransferLease, error)
	RequestTransferCancellation(context.Context, ResourceID, uint64, time.Time) error
	CompleteTransfer(context.Context, TransferLease, TransferReceipt) error
}

type TransferService struct {
	repository TransferStateRepository
	catalog    TransferDatabaseCatalog
	recovery   TransferRecoveryPoints
	backend    TransferBackend
	authorizer TransferAuthorizer
	stepUp     TransferStepUpVerifier
	audit      TransferAuditSink
	now        func() time.Time
}

func NewTransferService(repository TransferStateRepository, catalog TransferDatabaseCatalog, recovery TransferRecoveryPoints, backend TransferBackend,
	authorizer TransferAuthorizer, stepUp TransferStepUpVerifier, audit TransferAuditSink, now func() time.Time) (TransferService, error) {
	if repository == nil || catalog == nil || recovery == nil || backend == nil || authorizer == nil || stepUp == nil || audit == nil { return TransferService{}, ErrTransferInvalid }
	if now == nil { now = time.Now }
	return TransferService{repository: repository, catalog: catalog, recovery: recovery, backend: backend, authorizer: authorizer, stepUp: stepUp, audit: audit, now: now}, nil
}

func (service TransferService) Bootstrap(ctx context.Context) error { return service.repository.BootstrapTransfers(ctx) }

func (service TransferService) Create(ctx context.Context, actor string, job TransferJob, stepUp *TransferStepUpRequest) (TransferJobState, error) {
	authorization := transferAuthorization(actor, job, AuthorizeTransferCreate)
	if job.Validate() != nil || authorization.Validate() != nil || job.CreatedBy != actor { return TransferJobState{}, ErrTransferInvalid }
	now := service.now().UTC()
	if job.CreatedAt.After(now.Add(time.Minute)) || now.Sub(job.CreatedAt) > 15*time.Minute || job.Impact.CapturedAt.After(now.Add(time.Minute)) || now.Sub(job.Impact.CapturedAt) > 15*time.Minute { return TransferJobState{}, ErrTransferStale }
	if err := service.authorize(ctx, authorization); err != nil { return TransferJobState{}, err }
	database, err := service.reauthorizeDatabase(ctx, job)
	if err != nil { return TransferJobState{}, err }
	if existing, loadErr := service.repository.LoadTransfer(ctx, job.ID); loadErr == nil {
		if existing.Job.Digest != job.Digest { return TransferJobState{}, ErrTransferStale }
		return existing, nil
	} else if !errors.Is(loadErr, ErrNotFound) { return TransferJobState{}, loadErr }
	preview, err := service.catalog.PreviewDatabaseTransfer(ctx, database, job.Direction, job.Selection, job.Source)
	if err != nil || preview.Validate() != nil || preview.Digest != job.Impact.Digest || preview.DatabaseID != job.DatabaseID || preview.DatabaseGeneration != job.DatabaseGeneration ||
		preview.Rows > job.Limits.MaximumRows || preview.Bytes > job.Limits.MaximumBytes { return TransferJobState{}, ErrTransferStale }
	if job.Direction == TransferImport && job.ConflictPolicy == TransferConflictReplace {
		if stepUp == nil || stepUp.Validate() != nil || stepUp.Actor != actor || stepUp.TenantID != job.TenantID || stepUp.DatabaseID != job.DatabaseID || stepUp.JobID != job.ID { return TransferJobState{}, ErrUnauthorized }
		if err = service.stepUp.VerifyDatabaseTransferStepUp(ctx, *stepUp); err != nil { service.recordAudit(ctx, authorization, "step_up_denied", job.Digest, preview.Digest, 0); return TransferJobState{}, ErrUnauthorized }
		point, pointErr := service.recovery.CreateDatabaseTransferRestorePoint(ctx, job, database)
		if pointErr != nil || point.Validate() != nil || point.Reference != job.RestorePointRef || point.DatabaseID != job.DatabaseID || point.DatabaseGeneration != job.DatabaseGeneration ||
			point.ProofDigest != job.RestorePointDigest || !point.CreatedAt.Equal(job.RestorePointCreatedAt) { return TransferJobState{}, ErrTransferStale }
	} else if stepUp != nil { return TransferJobState{}, ErrTransferInvalid }
	state, err := service.repository.CreateTransfer(ctx, job)
	if err != nil { return TransferJobState{}, err }
	if err = service.recordAudit(ctx, authorization, "transfer_created", redactedTransferProjection(job), preview.Digest, state.Generation); err != nil { return TransferJobState{}, err }
	return state, nil
}

func (service TransferService) Inspect(ctx context.Context, actor string, jobID ResourceID) (TransferJobState, error) {
	state, err := service.repository.LoadTransfer(ctx, jobID)
	if err != nil { return TransferJobState{}, err }
	authorization := transferAuthorization(actor, state.Job, AuthorizeTransferRead)
	if err = service.authorize(ctx, authorization); err != nil { return TransferJobState{}, err }
	if _, err = service.reauthorizeDatabase(ctx, state.Job); err != nil { return TransferJobState{}, err }
	if err = service.recordAudit(ctx, authorization, "transfer_read", redactedTransferProjection(state.Job), state.Progress.Digest, state.Generation); err != nil { return TransferJobState{}, err }
	return state, nil
}

func (service TransferService) InspectReceipt(ctx context.Context, actor string, jobID ResourceID) (TransferReceipt, error) {
	state, err := service.repository.LoadTransfer(ctx, jobID)
	if err != nil { return TransferReceipt{}, err }
	authorization := transferAuthorization(actor, state.Job, AuthorizeTransferRead)
	if err = service.authorize(ctx, authorization); err != nil { return TransferReceipt{}, err }
	if _, err = service.reauthorizeDatabase(ctx, state.Job); err != nil { return TransferReceipt{}, err }
	receipt, err := service.repository.LatestTransferReceipt(ctx, jobID)
	if err != nil { return TransferReceipt{}, err }
	if err = service.recordAudit(ctx, authorization, "receipt_read", state.Job.Digest, receipt.Digest, receipt.Generation); err != nil { return TransferReceipt{}, err }
	return receipt, nil
}

func (service TransferService) Cancel(ctx context.Context, actor string, jobID ResourceID, expectedGeneration uint64) error {
	state, err := service.repository.LoadTransfer(ctx, jobID)
	if err != nil { return err }
	authorization := transferAuthorization(actor, state.Job, AuthorizeTransferCancel)
	if err = service.authorize(ctx, authorization); err != nil { return err }
	if _, err = service.reauthorizeDatabase(ctx, state.Job); err != nil { return err }
	if state.Generation != expectedGeneration { return ErrTransferStale }
	if err = service.repository.RequestTransferCancellation(ctx, jobID, expectedGeneration, service.now().UTC()); err != nil { return err }
	return service.recordAudit(ctx, authorization, "cancellation_requested", state.Job.Digest, state.Progress.Digest, state.Generation)
}

func (service TransferService) Run(ctx context.Context, actor, workerID string, jobID ResourceID, expectedGeneration uint64, leaseDuration time.Duration) (TransferReceipt, error) {
	state, err := service.repository.LoadTransfer(ctx, jobID)
	if err != nil { return TransferReceipt{}, err }
	authorization := transferAuthorization(actor, state.Job, AuthorizeTransferExecute)
	if err = service.authorize(ctx, authorization); err != nil { return TransferReceipt{}, err }
	database, err := service.reauthorizeDatabase(ctx, state.Job)
	if err != nil { return TransferReceipt{}, err }
	lease, err := service.repository.ClaimTransfer(ctx, jobID, workerID, expectedGeneration, service.now().UTC(), leaseDuration)
	if err != nil { return TransferReceipt{}, err }
	bounded, cancel := context.WithTimeout(ctx, state.Job.Limits.MaximumDuration)
	defer cancel()
	var lock sync.Mutex
	lastBytes, lastRows := state.Progress.BytesProcessed, state.Progress.RowsProcessed
	checkpoint := func(stream TransferStreamProgress) error {
		lock.Lock()
		defer lock.Unlock()
		if stream.Bytes < lastBytes { stream.Bytes = lastBytes }
		if stream.Rows < lastRows { stream.Rows = lastRows }
		progress := SealTransferProgress(TransferProgress{JobID: state.Job.ID, Generation: lease.Generation + 1, Phase: TransferPhaseStreaming,
			BytesProcessed: stream.Bytes, RowsProcessed: stream.Rows, SafePoint: stream.SafePoint, UpdatedAt: service.now().UTC()})
		updated, checkpointErr := service.repository.CheckpointTransfer(bounded, lease, progress)
		if checkpointErr != nil { return checkpointErr }
		lease, lastBytes, lastRows = updated, stream.Bytes, stream.Rows
		return nil
	}
	if err = checkpoint(TransferStreamProgress{Bytes: lastBytes, Rows: lastRows, SafePoint: true}); err != nil { return service.finishTransfer(ctx, authorization, state.Job, lease, nil, nil, nil, err) }
	if state.Job.Direction == TransferExport {
		process, processErr := service.backend.Export(bounded, state.Job, database.Name, checkpoint)
		if processErr != nil { return service.finishTransfer(ctx, authorization, state.Job, lease, &process, nil, nil, processErr) }
		if process.Validate(state.Job) != nil { return service.finishTransfer(ctx, authorization, state.Job, lease, &process, nil, nil, ErrTransferInvalid) }
		if process.BytesProcessed < lastBytes { process.BytesProcessed = lastBytes; process = SealTransferProcessReceipt(process) }
		if err = service.phaseCheckpoint(bounded, state.Job, &lease, TransferPhaseVerifying, process.BytesProcessed, process.RowsProcessed, true); err != nil {
			return service.finishTransfer(ctx, authorization, state.Job, lease, &process, nil, nil, err)
		}
		return service.finishTransfer(ctx, authorization, state.Job, lease, &process, nil, nil, nil)
	}
	isolated, err := service.catalog.AllocateIsolatedTransferDatabase(bounded, state.Job, database)
	if err != nil || isolated.Validate(state.Job) != nil { return service.finishTransfer(ctx, authorization, state.Job, lease, nil, nil, nil, ErrTransferStale) }
	discard := true
	defer func() { if discard { _ = service.catalog.DiscardIsolatedTransferDatabase(context.WithoutCancel(ctx), state.Job, isolated) } }()
	process, processErr := service.backend.Import(bounded, state.Job, isolated.Name, checkpoint)
	if processErr != nil { return service.finishTransfer(ctx, authorization, state.Job, lease, &process, nil, nil, processErr) }
	if process.Validate(state.Job) != nil || !process.InputVerified { return service.finishTransfer(ctx, authorization, state.Job, lease, &process, nil, nil, ErrTransferInvalid) }
	if err = service.phaseCheckpoint(bounded, state.Job, &lease, TransferPhaseVerifying, process.BytesProcessed, process.RowsProcessed, true); err != nil {
		return service.finishTransfer(ctx, authorization, state.Job, lease, &process, nil, nil, err)
	}
	verification, err := service.catalog.VerifyIsolatedTransferDatabase(bounded, state.Job, isolated)
	if err != nil || verification.Validate(state.Job, isolated) != nil { return service.finishTransfer(ctx, authorization, state.Job, lease, &process, &verification, nil, ErrTransferStale) }
	if err = service.phaseCheckpoint(bounded, state.Job, &lease, TransferPhasePromoting, process.BytesProcessed, verification.RowCount, true); err != nil {
		return service.finishTransfer(ctx, authorization, state.Job, lease, &process, &verification, nil, err)
	}
	point := TransferRestorePoint{}
	if state.Job.ConflictPolicy == TransferConflictReplace {
		point = TransferRestorePoint{Reference: state.Job.RestorePointRef, DatabaseID: state.Job.DatabaseID, DatabaseGeneration: state.Job.DatabaseGeneration,
			ProofDigest: state.Job.RestorePointDigest, CreatedAt: state.Job.RestorePointCreatedAt}
	}
	promotion, promoteErr := service.catalog.PromoteIsolatedTransferDatabase(bounded, state.Job, database, isolated, point)
	if promoteErr != nil || promotion.Validate(state.Job, isolated) != nil {
		if !promotion.SourcePreserved { discard = false; return service.finishTransfer(ctx, authorization, state.Job, lease, &process, &verification, &promotion, ErrAmbiguous) }
		return service.finishTransfer(ctx, authorization, state.Job, lease, &process, &verification, &promotion, ErrTransferStale)
	}
	discard = false
	return service.finishTransfer(ctx, authorization, state.Job, lease, &process, &verification, &promotion, nil)
}

func (service TransferService) phaseCheckpoint(ctx context.Context, job TransferJob, lease *TransferLease, phase TransferPhase, bytes, rows uint64, safe bool) error {
	progress := SealTransferProgress(TransferProgress{JobID: job.ID, Generation: lease.Generation + 1, Phase: phase, BytesProcessed: bytes, RowsProcessed: rows, SafePoint: safe, UpdatedAt: service.now().UTC()})
	updated, err := service.repository.CheckpointTransfer(ctx, *lease, progress)
	if err == nil { *lease = updated }
	return err
}

func (service TransferService) finishTransfer(ctx context.Context, authorization TransferAuthorizationRequest, job TransferJob, lease TransferLease, process *TransferProcessReceipt,
	verification *TransferVerification, promotion *TransferPromotion, operationErr error) (TransferReceipt, error) {
	status, code, mutation, sourcePreserved := TransferCompleted, "", false, true
	if operationErr != nil {
		status, code = TransferFailed, "transfer_failed"
		if errors.Is(operationErr, ErrTransferCancelled) || errors.Is(operationErr, context.Canceled) || errors.Is(operationErr, context.DeadlineExceeded) { status, code = TransferCancelled, "cancelled" }
		if errors.Is(operationErr, ErrAmbiguous) { status, code, mutation = TransferAmbiguous, "outcome_ambiguous", true }
	}
	if process != nil { mutation = mutation || process.Partial || job.Direction == TransferImport; if process.Validate(job) != nil { process = nil } }
	verificationDigest, promotionDigest := "", ""
	if verification != nil && validSHA256(verification.Digest) && transferVerificationDigest(*verification) == verification.Digest && verification.RowCount <= job.Limits.MaximumRows && verification.Bytes <= job.Limits.MaximumBytes && verification.Health == HealthHealthy {
		verificationDigest = verification.Digest
	}
	if promotion != nil { if validSHA256(promotion.ProofDigest) { promotionDigest = promotion.ProofDigest }; sourcePreserved = promotion.SourcePreserved }
	resume := transferResumeFor(job, status, TransferPhaseTerminal)
	if status == TransferCompleted || status == TransferAmbiguous { resume = TransferResumeNotSafe }
	receipt := SealTransferReceipt(TransferReceipt{JobID: job.ID, JobDigest: job.Digest, Attempt: lease.Attempt, Generation: lease.Generation + 1, Status: status,
		ResumeClass: resume,
		Process: process, VerificationDigest: verificationDigest, PromotionDigest: promotionDigest, FailureCode: code, SourcePreserved: sourcePreserved, MutationPossible: mutation,
		OccurredAt: service.now().UTC()})
	if receipt.Validate(job) != nil { return TransferReceipt{}, ErrTransferInvalid }
	if err := service.repository.CompleteTransfer(ctx, lease, receipt); err != nil { return receipt, err }
	outcome := "transfer_completed"
	if status == TransferFailed { outcome = "transfer_failed" } else if status == TransferCancelled { outcome = "transfer_cancelled" } else if status == TransferAmbiguous { outcome = "transfer_ambiguous" }
	if err := service.recordAudit(ctx, authorization, outcome, job.Digest, receipt.Digest, receipt.Generation); err != nil { return receipt, err }
	return receipt, operationErr
}

func (service TransferService) reauthorizeDatabase(ctx context.Context, job TransferJob) (Database, error) {
	database, err := service.catalog.LoadTransferDatabase(ctx, job.TenantID, job.SiteID, job.DatabaseID)
	if err != nil { return Database{}, err }
	if database.Validate() != nil || database.ID != job.DatabaseID || database.Generation != job.DatabaseGeneration || database.TenantID != job.TenantID || database.SiteID != job.SiteID || database.InstanceID != job.InstanceID ||
		database.Status.Lifecycle != LifecycleReady || database.Status.Health != HealthHealthy { return Database{}, ErrUnauthorized }
	return database, nil
}

func transferAuthorization(actor string, job TransferJob, action TransferAuthorizationAction) TransferAuthorizationRequest {
	return TransferAuthorizationRequest{Actor: actor, TenantID: job.TenantID, SiteID: job.SiteID, DatabaseID: job.DatabaseID, JobID: job.ID, Action: action}
}

func (service TransferService) authorize(ctx context.Context, request TransferAuthorizationRequest) error {
	if request.Validate() != nil { return ErrTransferInvalid }
	if err := service.authorizer.AuthorizeDatabaseTransfer(ctx, request); err != nil { service.recordAudit(ctx, request, "authorization_denied", "", "", 0); return ErrUnauthorized }
	return nil
}

func (service TransferService) recordAudit(ctx context.Context, request TransferAuthorizationRequest, outcome, resourceDigest, evidenceDigest string, generation uint64) error {
	record := TransferAuditRecord{Actor: request.Actor, TenantID: request.TenantID, SiteID: request.SiteID, DatabaseID: request.DatabaseID, JobID: request.JobID, Action: request.Action,
		Outcome: outcome, ResourceDigest: resourceDigest, EvidenceDigest: evidenceDigest, Generation: generation, OccurredAt: service.now().UTC()}
	record.Digest = transferAuditDigest(record)
	if record.Validate() != nil { return ErrTransferInvalid }
	return service.audit.RecordDatabaseTransfer(ctx, record)
}
