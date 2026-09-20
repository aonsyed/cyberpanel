package apiserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type databaseTransferSites interface {
	Load(context.Context, site.TenantID, site.SiteID) (site.Site, error)
}

type DatabaseTransferService interface {
	PrepareDatabaseImport(context.Context, Invocation, DatabaseImportPreparePayload) (database.TransferJob, error)
	RunDatabaseImport(context.Context, Invocation, database.TransferJob) (database.TransferReceipt, error)
	InspectDatabaseImport(context.Context, Invocation, database.ResourceID) (database.TransferJobState, error)
}

type DatabaseTransferOperations struct {
	repository  *database.SQLRepository
	jobs        *database.SQLiteTransferRepository
	coordinator database.Coordinator
	sites       databaseTransferSites
	identity    *identity.Service
	audit       *audit.Writer
}

func NewDatabaseTransferOperations(ctx context.Context, db *sql.DB, repository *database.SQLRepository, coordinator database.Coordinator, sites databaseTransferSites, identityService *identity.Service, writer *audit.Writer) (*DatabaseTransferOperations, error) {
	if ctx == nil || db == nil || repository == nil || sites == nil || identityService == nil || writer == nil {
		return nil, ErrInvalidRequest
	}
	jobs, err := database.NewSQLiteTransferRepository(db)
	if err != nil {
		return nil, err
	}
	if err = jobs.BootstrapTransfers(ctx); err != nil {
		return nil, err
	}
	return &DatabaseTransferOperations{repository: repository, jobs: jobs, coordinator: coordinator, sites: sites, identity: identityService, audit: writer}, nil
}

func (operations *DatabaseTransferOperations) PrepareDatabaseImport(ctx context.Context, inv Invocation, p DatabaseImportPreparePayload) (database.TransferJob, error) {
	tenant, err := site.NewTenantID(inv.Request.TenantID)
	if err != nil {
		return database.TransferJob{}, ErrInvalidRequest
	}
	siteID, err := site.NewSiteID(inv.Request.ResourceID)
	if err != nil || inv.Request.ExpectedGeneration == 0 {
		return database.TransferJob{}, ErrInvalidRequest
	}
	now := time.Now().UTC()
	id, command := databaseImportIdentity(inv)
	gate := databaseTransferAuthority{operations: operations, invocation: inv}
	if err = gate.AuthorizeDatabaseTransfer(ctx, database.TransferAuthorizationRequest{Actor: inv.Actor.PrincipalID.String(), TenantID: tenant, SiteID: siteID, DatabaseID: p.DatabaseID, JobID: id, Action: database.AuthorizeTransferCreate}); err != nil {
		return database.TransferJob{}, err
	}
	envelope, err := operations.repository.LoadResource(ctx, database.KindDatabase, p.DatabaseID)
	if err != nil {
		return database.TransferJob{}, err
	}
	resource, err := database.DecodeResource(envelope)
	if err != nil {
		return database.TransferJob{}, err
	}
	target, ok := resource.(*database.Database)
	if !ok || target.Generation != inv.Request.ExpectedGeneration {
		return database.TransferJob{}, database.ErrTransferStale
	}
	if target.Status.Lifecycle != database.LifecycleReady || target.Status.Health != database.HealthHealthy || target.Status.Reconciliation != database.ReconciliationInSync {
		return database.TransferJob{}, database.ErrUnavailable
	}
	job := database.TransferJob{ID: id, IdempotencyKey: command, TenantID: tenant, SiteID: siteID, DatabaseID: target.ID, DatabaseGeneration: target.Generation, InstanceID: target.InstanceID, Direction: database.TransferImport, Format: p.Artifact.Format, Compression: p.Artifact.Compression, Source: &p.Artifact, ExportSource: &p.SourceExport, Selection: p.SourceExport.Selection, Limits: database.TransferLimits{MaximumBytes: 64 << 20, MaximumRows: 1_000_000, MaximumDuration: 90 * time.Second}, ConflictPolicy: database.TransferConflictFail, Retention: database.TransferRetention{RetainUntil: p.Artifact.ExpiresAt}, CreatedBy: inv.Actor.PrincipalID.String(), CreatedAt: now, Impact: database.SealTransferImpactPreview(database.TransferImpactPreview{DatabaseID: target.ID, DatabaseGeneration: target.Generation, CapturedAt: now})}
	job, err = database.SealTransferJob(job)
	if err != nil {
		return database.TransferJob{}, err
	}
	execution, err := database.NewBrokerImportExecution(operations.coordinator, job)
	if err != nil {
		return database.TransferJob{}, err
	}
	job.Impact, err = execution.PreviewDatabaseTransfer(ctx, *target, job.Direction, job.Selection, job.Source)
	if err != nil {
		return database.TransferJob{}, err
	}
	return database.SealTransferJob(job)
}

func databaseImportIdentity(inv Invocation) (database.ResourceID, string) {
	// Prepare is read-only and must not carry an idempotency key. Bind each
	// durable intent to its authenticated actor and request identity instead.
	digest := sha256.Sum256([]byte(inv.Request.TenantID + "\x00" + inv.Actor.PrincipalID.String() + "\x00" + inv.Request.RequestID))
	id, _ := database.NewResourceID("import-" + hex.EncodeToString(digest[:]))
	return id, id.String()
}

func (operations *DatabaseTransferOperations) service(inv Invocation, job database.TransferJob) (database.TransferService, error) {
	if job.Validate() != nil || job.Direction != database.TransferImport || job.ExportSource == nil || job.TenantID.String() != inv.Request.TenantID || job.SiteID.String() != inv.Request.ResourceID || job.Limits.MaximumBytes > 64<<20 || job.Limits.MaximumRows > 1_000_000 || job.Limits.MaximumDuration > 90*time.Second {
		return database.TransferService{}, database.ErrUnauthorized
	}
	execution, err := database.NewBrokerImportExecution(operations.coordinator, job)
	if err != nil {
		return database.TransferService{}, err
	}
	gate := databaseTransferAuthority{operations: operations, invocation: inv}
	return database.NewTransferService(operations.jobs, execution, gate, execution, gate, gate, gate, time.Now)
}

func (operations *DatabaseTransferOperations) RunDatabaseImport(ctx context.Context, inv Invocation, job database.TransferJob) (database.TransferReceipt, error) {
	if inv.Request.ExpectedGeneration != job.DatabaseGeneration {
		return database.TransferReceipt{}, database.ErrTransferStale
	}
	service, err := operations.service(inv, job)
	if err != nil {
		return database.TransferReceipt{}, err
	}
	state, loadErr := operations.jobs.LoadTransfer(ctx, job.ID)
	if loadErr == nil {
		if state.Job.Digest != job.Digest {
			return database.TransferReceipt{}, database.ErrTransferStale
		}
		if state.Status != database.TransferQueued {
			return service.InspectReceipt(ctx, inv.Actor.PrincipalID.String(), job.ID)
		}
	} else if !errors.Is(loadErr, database.ErrNotFound) {
		return database.TransferReceipt{}, loadErr
	}
	state, err = service.Create(ctx, inv.Actor.PrincipalID.String(), job, nil)
	if err != nil {
		return database.TransferReceipt{}, err
	}
	return service.Run(ctx, inv.Actor.PrincipalID.String(), "api-import-"+inv.Request.RequestID, job.ID, state.Generation, 2*time.Minute)
}

func (operations *DatabaseTransferOperations) InspectDatabaseImport(ctx context.Context, inv Invocation, id database.ResourceID) (database.TransferJobState, error) {
	state, err := operations.jobs.LoadTransfer(ctx, id)
	if err != nil {
		return database.TransferJobState{}, err
	}
	service, err := operations.service(inv, state.Job)
	if err != nil {
		return database.TransferJobState{}, err
	}
	return service.Inspect(ctx, inv.Actor.PrincipalID.String(), id)
}

type databaseTransferAuthority struct {
	operations *DatabaseTransferOperations
	invocation Invocation
}

func (gate databaseTransferAuthority) AuthorizeDatabaseTransfer(ctx context.Context, r database.TransferAuthorizationRequest) error {
	inv := gate.invocation
	if gate.operations == nil || r.Validate() != nil || r.Actor != inv.Actor.PrincipalID.String() || r.TenantID.String() != inv.Request.TenantID || r.SiteID.String() != inv.Request.ResourceID {
		return database.ErrUnauthorized
	}
	scope, err := siteScope(inv.Request, nil)
	if err != nil {
		return database.ErrUnauthorized
	}
	if _, err = gate.operations.identity.AuthorizeActor(ctx, inv.Actor.IdentityContext(), identity.MustPermission("database:manage"), scope, identity.AssuranceMFA); err != nil {
		return database.ErrUnauthorized
	}
	aggregate, err := gate.operations.sites.Load(ctx, r.TenantID, r.SiteID)
	if err != nil || aggregate.TenantID() != r.TenantID || aggregate.ID() != r.SiteID || aggregate.Lifecycle() != site.LifecycleActive {
		return database.ErrUnauthorized
	}
	envelope, err := gate.operations.repository.LoadResource(ctx, database.KindDatabase, r.DatabaseID)
	if err != nil || envelope.Metadata.TenantID != r.TenantID || envelope.Metadata.SiteID != r.SiteID {
		return database.ErrUnauthorized
	}
	return nil
}

// Replacement is not exposed by this export-backed, non-replacing API.
func (databaseTransferAuthority) VerifyDatabaseTransferStepUp(context.Context, database.TransferStepUpRequest) error {
	return database.ErrUnavailable
}
func (databaseTransferAuthority) CreateDatabaseTransferRestorePoint(context.Context, database.TransferJob, database.Database) (database.TransferRestorePoint, error) {
	return database.TransferRestorePoint{}, database.ErrUnavailable
}

func (gate databaseTransferAuthority) RecordDatabaseTransfer(ctx context.Context, r database.TransferAuditRecord) error {
	inv := gate.invocation
	if gate.operations == nil || gate.operations.audit == nil || r.Validate() != nil || r.Actor != inv.Actor.PrincipalID.String() || r.TenantID.String() != inv.Request.TenantID || r.SiteID.String() != inv.Request.ResourceID {
		return database.ErrUnauthorized
	}
	class, outcome := audit.ClassMutation, audit.OutcomeApplied
	if r.Action == database.AuthorizeTransferRead {
		class, outcome = audit.ClassSensitiveRead, audit.OutcomeAllowed
	}
	switch r.Outcome {
	case "authorization_denied", "step_up_denied":
		class, outcome = audit.ClassAuthorization, audit.OutcomeDenied
	case "transfer_ambiguous":
		outcome = audit.OutcomeAmbiguous
	case "transfer_failed", "transfer_cancelled":
		outcome = audit.OutcomeFailed
	}
	_, err := gate.operations.audit.Append(ctx, audit.Event{ID: "dbtransfer-" + r.Digest, Class: class, Action: string(r.Action), Actor: audit.Actor{PrincipalID: r.Actor, CredentialID: inv.Actor.CredentialID.String(), SessionID: inv.Actor.SessionID.String(), TenantID: r.TenantID.String(), AuthzEpoch: inv.Actor.AuthzEpoch, Assurance: fmt.Sprint(inv.Actor.Assurance), Origin: inv.Meta.Origin}, Target: audit.Target{Kind: "database_transfer", ID: r.JobID.String(), TenantID: r.TenantID.String(), Generation: fmt.Sprint(r.Generation)}, Outcome: outcome, RequestDigest: r.Digest, TraceID: inv.Request.RequestID, Attributes: map[string]string{"database_id": r.DatabaseID.String(), "site_id": r.SiteID.String(), "outcome": r.Outcome, "evidence_digest": r.EvidenceDigest}, OccurredAt: r.OccurredAt})
	return err
}
