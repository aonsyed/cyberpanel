package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	marketing "github.com/aonsyed/cyberpanel/platform/internal/emailmarketing"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
)

const emailMarketingSchemaVersion = "cyberpanel-emailmarketing-schema-v1"

type MarketingPolicyProjection struct {
	Generation               uint64    `json:"generation"`
	MaxRecipientsPerCampaign uint64    `json:"max_recipients_per_campaign"`
	MaxRecipientsPerHour     uint64    `json:"max_recipients_per_hour"`
	MaxRecipientsPerDay      uint64    `json:"max_recipients_per_day"`
	MaxConcurrentCampaigns   uint32    `json:"max_concurrent_campaigns"`
	WarmupStartedAt          time.Time `json:"warmup_started_at"`
	WarmupInitialDailyLimit  uint64    `json:"warmup_initial_daily_limit"`
	WarmupDoublingSeconds    uint64    `json:"warmup_doubling_seconds"`
	MinimumApprovals         uint8     `json:"minimum_approvals"`
	CapacityMaximumAgeSeconds uint64   `json:"capacity_maximum_age_seconds"`
	Abuse                    string    `json:"abuse"`
	AbuseEvidenceDigest      string    `json:"abuse_evidence_digest"`
	LocalAuthorityReady      bool      `json:"local_authority_ready"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type MarketingSenderProjection struct {
	Domain         string    `json:"domain"`
	Generation     uint64    `json:"generation"`
	EvidenceDigest string    `json:"evidence_digest"`
	VerifiedAt     time.Time `json:"verified_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type MarketingCapacityProjection struct {
	ProfileRef                       string    `json:"profile_ref"`
	Generation                       uint64    `json:"generation"`
	Kind                             string    `json:"kind"`
	Online                           bool      `json:"online"`
	MaximumConcurrency               uint32    `json:"maximum_concurrency"`
	MaximumRecipientsPerHour         uint64    `json:"maximum_recipients_per_hour"`
	ReservedTransactionalConcurrency uint32    `json:"reserved_transactional_concurrency"`
	ReservedTransactionalPerHour     uint64    `json:"reserved_transactional_per_hour"`
	ObservedAt                       time.Time `json:"observed_at"`
	UpdatedAt                        time.Time `json:"updated_at"`
}

type MarketingReservationProjection struct {
	ID               string    `json:"id"`
	CampaignID       string    `json:"campaign_id"`
	CampaignRevision uint64    `json:"campaign_revision"`
	RecipientCount   uint64    `json:"recipient_count"`
	ProfileRef       string    `json:"profile_ref"`
	CapacityKind     string    `json:"capacity_kind"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type MarketingPolicyStatus struct {
	Policy       *MarketingPolicyProjection       `json:"policy,omitempty"`
	Senders      []MarketingSenderProjection      `json:"senders"`
	Capacities   []MarketingCapacityProjection    `json:"capacities"`
	Reservations []MarketingReservationProjection `json:"reservations"`
	SafetyReady  bool                             `json:"safety_ready"`
	WaitReason   string                           `json:"wait_reason,omitempty"`
	AsOf         time.Time                        `json:"as_of"`
}

type MarketingArchiveJob struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Kind           string    `json:"kind"`
	State          string    `json:"state"`
	Generation     uint64    `json:"generation"`
	SourceJobID    string    `json:"source_job_id,omitempty"`
	Result         string    `json:"result,omitempty"`
	EvidenceDigest string    `json:"evidence_digest,omitempty"`
	ErrorCode      string    `json:"error_code,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type marketingArchiveJobRecord struct {
	MarketingArchiveJob
	ArtifactPath   string
	SchemaDigest  string
	PolicyDigest  string
	ScopeDigest   string
	MaximumRecords uint64
	MaximumBytes  int64
}

type EmailMarketingOperations struct {
	DB         *sql.DB
	Repository *marketing.SQLiteRepository
	Identity   *identity.Service
	Audit      *audit.Service
	Events     marketing.DeliveryEventService
	Metrics    marketing.CampaignMetricsService
	Policy     marketing.CampaignPolicyService
	Backup     marketing.CampaignBackupService
	Restore    *emailMarketingRestoreActivation
	Artifacts  emailMarketingArtifactStore
	LocalDelivery marketing.DeliveryProvider
	DeliveryProviders map[string]marketing.DeliveryProvider
	VerificationProviders map[string]EmailMarketingVerificationProvider
	verificationMu sync.Mutex
	verificationRates map[marketing.TenantID]emailMarketingVerificationRate
	ArchiveRoot string
	Now        func() time.Time
}

func NewEmailMarketingOperations(ctx context.Context, db *sql.DB, identityService *identity.Service, auditService *audit.Service, eventMasterKey []byte, archiveRoot string) (*EmailMarketingOperations, error) {
	if ctx == nil || db == nil || identityService == nil || auditService == nil || auditService.Writer == nil || len(eventMasterKey) != 32 || !filepath.IsAbs(archiveRoot) || filepath.Clean(archiveRoot) == "/" {
		return nil, invalid("email marketing operations")
	}
	if err := os.MkdirAll(archiveRoot, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(archiveRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, invalid("email marketing archive root")
	}
	repository, err := marketing.NewSQLiteRepository(db)
	if err != nil {
		return nil, err
	}
	for _, bootstrap := range []func(context.Context) error{repository.Bootstrap, repository.BootstrapCampaignCore, repository.BootstrapCampaignEvents, repository.BootstrapCampaignPolicy} {
		if err = bootstrap(ctx); err != nil {
			return nil, err
		}
	}
	if err = bootstrapEmailMarketingArchiveJobs(ctx, db); err != nil {
		return nil, err
	}
	verifier := &emailMarketingEventVerifier{keys: map[marketing.DeliveryEventSource]emailMarketingEventKey{
		marketing.DeliveryEventProvider: {id: "provider-v1", value: deriveEmailMarketingKey(eventMasterKey, "provider")},
		marketing.DeliveryEventLocal:    {id: "local-v1", value: deriveEmailMarketingKey(eventMasterKey, "local")},
	}}
	now := func() time.Time { return time.Now().UTC() }
	operations := &EmailMarketingOperations{DB: db, Repository: repository, Identity: identityService, Audit: auditService, ArchiveRoot: archiveRoot, Now: now}
	operations.Events = marketing.DeliveryEventService{Repository: repository, Verifier: verifier, Policy: marketing.DeliveryEventPolicy{MaximumPayloadBytes: 1 << 20, MaximumClockSkew: 5 * time.Minute, ReplayWindow: 30 * 24 * time.Hour, DelayedAfter: 15 * time.Minute}, Now: now}
	operations.Metrics = marketing.CampaignMetricsService{Repository: repository, Now: now}
	operations.Policy = marketing.CampaignPolicyService{Repository: repository, Senders: &emailMarketingSenderVerifier{db: db, resolver: net.DefaultResolver, now: now}, Now: now}
	operations.Backup = marketing.CampaignBackupService{Now: now}
	operations.Restore = &emailMarketingRestoreActivation{live: db, root: archiveRoot, stages: make(map[string]*emailMarketingRestoreStage), now: now}
	return operations, nil
}

func bootstrapEmailMarketingArchiveJobs(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS email_marketing_archive_jobs_v1 (
		job_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('backup','restore','reconcile')),
		state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed')), generation INTEGER NOT NULL CHECK(generation>0),
		source_job_id TEXT NOT NULL, artifact_path TEXT NOT NULL, schema_digest TEXT NOT NULL, policy_digest TEXT NOT NULL, scope_digest TEXT NOT NULL,
		maximum_records INTEGER NOT NULL CHECK(maximum_records>0), maximum_bytes INTEGER NOT NULL CHECK(maximum_bytes>=1024),
		result TEXT NOT NULL, content_digest TEXT NOT NULL, error_code TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	) STRICT`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE email_marketing_archive_jobs_v1 SET state='failed',generation=generation+1,result='interrupted',error_code='interrupted',updated_at=? WHERE state IN ('queued','running')`, emailMarketingDBTime(time.Now().UTC()))
	return err
}

func (operations *EmailMarketingOperations) IngestDeliveryEvent(ctx context.Context, signed marketing.SignedDeliveryEvent) (marketing.DeliveryEventResult, error) {
	if operations == nil {
		return marketing.DeliveryEventResult{}, ErrOperationUnavailable
	}
	return operations.Events.Ingest(ctx, signed)
}

func (operations *EmailMarketingOperations) CampaignMetrics(ctx context.Context, invocation Invocation, campaign marketing.CampaignID, query marketing.CampaignMetricsQuery) (marketing.CampaignMetricsSnapshot, error) {
	service := operations.Metrics
	service.Authorizer = operations.authority(invocation, identity.AssurancePassword)
	service.Audit = operations.auditSink(invocation)
	return service.Read(ctx, marketingAccess(invocation), campaign, query)
}

func (operations *EmailMarketingOperations) PolicyStatus(ctx context.Context, invocation Invocation) (MarketingPolicyStatus, error) {
	authority := operations.authority(invocation, identity.AssurancePassword)
	request := marketing.AuthorizationRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.campaign.policy.status", Resource: invocation.Request.TenantID, DataClass: "campaign_safety_policy"}
	if err := authority.Authorize(ctx, request); err != nil {
		return MarketingPolicyStatus{}, marketing.ErrUnauthorized
	}
	status, err := operations.readPolicyStatus(ctx, invocation.Request.TenantID, "")
	if err != nil {
		return MarketingPolicyStatus{}, err
	}
	if err = operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: "read", EvidenceDigest: digestEmailMarketingValue(status), OccurredAt: operations.Now()}); err != nil {
		return MarketingPolicyStatus{}, err
	}
	return status, nil
}

func (operations *EmailMarketingOperations) AdmissionStatus(ctx context.Context, invocation Invocation, campaign marketing.CampaignID) (MarketingPolicyStatus, error) {
	authority := operations.authority(invocation, identity.AssurancePassword)
	request := marketing.AuthorizationRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.campaign.admission.status", Resource: string(campaign), DataClass: "campaign_safety_policy"}
	if err := authority.Authorize(ctx, request); err != nil {
		return MarketingPolicyStatus{}, marketing.ErrUnauthorized
	}
	status, err := operations.readPolicyStatus(ctx, invocation.Request.TenantID, campaign)
	if err != nil {
		return MarketingPolicyStatus{}, err
	}
	if err = operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: "read", EvidenceDigest: digestEmailMarketingValue(status), OccurredAt: operations.Now()}); err != nil {
		return MarketingPolicyStatus{}, err
	}
	return status, nil
}

func (operations *EmailMarketingOperations) PutPolicy(ctx context.Context, invocation Invocation, policy marketing.TenantCampaignPolicy, expected uint64) (MarketingPolicyStatus, error) {
	service := operations.Policy
	service.Authorizer = operations.authority(invocation, identity.AssurancePhishingResistant)
	service.StepUp = operations.authority(invocation, identity.AssurancePhishingResistant)
	service.Audit = operations.auditSink(invocation)
	if err := service.PutPolicy(ctx, marketingAccess(invocation), policy, expected, invocation.Request.RequestID); err != nil {
		return MarketingPolicyStatus{}, err
	}
	return operations.readPolicyStatus(ctx, invocation.Request.TenantID, "")
}

func (operations *EmailMarketingOperations) PutCapacity(ctx context.Context, invocation Invocation, capacity marketing.CampaignDeliveryCapacity, expected uint64) (MarketingPolicyStatus, error) {
	service := operations.Policy
	service.Authorizer = operations.authority(invocation, identity.AssuranceMFA)
	service.StepUp = operations.authority(invocation, identity.AssuranceMFA)
	service.Audit = operations.auditSink(invocation)
	if err := service.PutCapacity(ctx, marketingAccess(invocation), capacity, expected, invocation.Request.RequestID); err != nil {
		return MarketingPolicyStatus{}, err
	}
	return operations.readPolicyStatus(ctx, invocation.Request.TenantID, "")
}

func (operations *EmailMarketingOperations) RefreshSender(ctx context.Context, invocation Invocation, domain string, expected uint64) (MarketingPolicyStatus, error) {
	service := operations.Policy
	service.Authorizer = operations.authority(invocation, identity.AssurancePhishingResistant)
	service.StepUp = operations.authority(invocation, identity.AssurancePhishingResistant)
	service.Audit = operations.auditSink(invocation)
	if _, err := service.RefreshSender(ctx, marketingAccess(invocation), strings.ToLower(domain), expected, invocation.Request.RequestID); err != nil {
		return MarketingPolicyStatus{}, err
	}
	return operations.readPolicyStatus(ctx, invocation.Request.TenantID, "")
}

func (operations *EmailMarketingOperations) ReserveAdmission(ctx context.Context, invocation Invocation, request marketing.CampaignAdmissionRequest) (marketing.CampaignAdmissionResult, error) {
	authorization := operations.authority(invocation, identity.AssuranceMFA)
	authorizationRequest := marketing.AuthorizationRequest{TenantID: request.TenantID, ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.campaign.admission.reserve", Resource: string(request.CampaignID), DataClass: "campaign_safety_policy"}
	if err := authorization.Authorize(ctx, authorizationRequest); err != nil {
		return marketing.CampaignAdmissionResult{}, marketing.ErrUnauthorized
	}
	result, err := operations.Repository.ReserveCampaignAdmission(ctx, request, operations.Now())
	if errors.Is(err, marketing.ErrCampaignAdmissionWaiting) {
		err = nil
	}
	if err != nil {
		return marketing.CampaignAdmissionResult{}, err
	}
	outcome := "waiting"
	evidence := digestEmailMarketingValue(result)
	if result.Admitted {
		outcome = "committed"
		evidence = digestEmailMarketingValue(result.Reservation)
	}
	if auditErr := operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: request.TenantID, ActorID: authorizationRequest.ActorID, Action: authorizationRequest.Action, Resource: authorizationRequest.Resource, Outcome: outcome, EvidenceDigest: evidence, OccurredAt: operations.Now()}); auditErr != nil {
		return marketing.CampaignAdmissionResult{}, auditErr
	}
	return result, nil
}

func (operations *EmailMarketingOperations) StartBackup(ctx context.Context, invocation Invocation, retentionDays uint32, maximumRecords uint64, maximumBytes int64) (MarketingArchiveJob, error) {
	if retentionDays == 0 || retentionDays > 3650 || maximumRecords == 0 || maximumRecords > 100_000_000 || maximumBytes < 1024 || maximumBytes > 1<<40 {
		return MarketingArchiveJob{}, marketing.ErrInvalid
	}
	service := operations.Backup
	service.Authorizer = operations.authority(invocation, identity.AssurancePhishingResistant)
	service.StepUp = operations.authority(invocation, identity.AssurancePhishingResistant)
	service.Audit = operations.auditSink(invocation)
	service.Now = operations.Now
	request := marketing.AuthorizationRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.backup.export", Resource: "backup:" + invocation.Request.TenantID, DataClass: "contact_consent_and_delivery_backup"}
	if err := service.Authorizer.Authorize(ctx, request); err != nil {
		return MarketingArchiveJob{}, marketing.ErrUnauthorized
	}
	policyDigest, err := operations.policyDigest(ctx, invocation.Request.TenantID)
	if err != nil {
		return MarketingArchiveJob{}, err
	}
	now := operations.Now()
	jobID := effectID(invocation)
	path := filepath.Join(operations.ArchiveRoot, jobID+".jsonl")
	deadline := now.Add(time.Duration(retentionDays) * 24 * time.Hour)
	retention := make([]marketing.BackupRetentionRule, 0, 6)
	for _, class := range []marketing.BackupDataClass{marketing.BackupClassContact, marketing.BackupClassConsent, marketing.BackupClassSuppression, marketing.BackupClassContent, marketing.BackupClassDelivery, marketing.BackupClassProviderRef} {
		retention = append(retention, marketing.BackupRetentionRule{DataClass: class, RetainUntil: deadline})
	}
	sort.Slice(retention, func(i, j int) bool { return retention[i].DataClass < retention[j].DataClass })
	scope := marketing.CampaignBackupScope{TenantID: marketing.TenantID(invocation.Request.TenantID), SourceRevision: fmt.Sprintf("local_%d", now.UnixNano()), SchemaDigest: emailMarketingSchemaDigest(), PolicyDigest: policyDigest, Retention: retention, CreatedAt: now, MaximumRecords: maximumRecords, MaximumBytes: maximumBytes}
	job := marketingArchiveJobRecord{MarketingArchiveJob: MarketingArchiveJob{ID: jobID, TenantID: invocation.Request.TenantID, Kind: "backup", State: "queued", Generation: 1, CreatedAt: now, UpdatedAt: now}, ArtifactPath: path, SchemaDigest: scope.SchemaDigest, PolicyDigest: scope.PolicyDigest, ScopeDigest: digestEmailMarketingValue(scope), MaximumRecords: maximumRecords, MaximumBytes: maximumBytes}
	if err = operations.insertArchiveJob(ctx, job); err != nil {
		return MarketingArchiveJob{}, err
	}
	go operations.runBackup(invocation, job, service, scope)
	return job.MarketingArchiveJob, nil
}

func (operations *EmailMarketingOperations) StartRestore(ctx context.Context, invocation Invocation, sourceJobID string, expectedActivationGeneration uint64) (MarketingArchiveJob, error) {
	if expectedActivationGeneration != 0 {
		return MarketingArchiveJob{}, marketing.ErrConflict
	}
	if err := operations.authority(invocation, identity.AssurancePhishingResistant).Authorize(ctx, marketing.AuthorizationRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.backup.restore", Resource: "restore:" + invocation.Request.TenantID, DataClass: "contact_consent_and_delivery_backup"}); err != nil {
		return MarketingArchiveJob{}, marketing.ErrUnauthorized
	}
	source, err := operations.archiveJob(ctx, invocation.Request.TenantID, sourceJobID)
	if err != nil || source.Kind != "backup" || source.State != "succeeded" || source.ArtifactPath == "" {
		return MarketingArchiveJob{}, marketing.ErrNotFound
	}
	currentPolicyDigest, err := operations.policyDigest(ctx, invocation.Request.TenantID)
	if err != nil || currentPolicyDigest != source.PolicyDigest {
		return MarketingArchiveJob{}, marketing.ErrConflict
	}
	now := operations.Now()
	job := marketingArchiveJobRecord{MarketingArchiveJob: MarketingArchiveJob{ID: effectID(invocation), TenantID: invocation.Request.TenantID, Kind: "restore", State: "queued", Generation: 1, SourceJobID: source.ID, CreatedAt: now, UpdatedAt: now}, SchemaDigest: source.SchemaDigest, PolicyDigest: source.PolicyDigest, ScopeDigest: source.ScopeDigest, MaximumRecords: source.MaximumRecords, MaximumBytes: source.MaximumBytes}
	if err = operations.insertArchiveJob(ctx, job); err != nil {
		return MarketingArchiveJob{}, err
	}
	service := operations.Backup
	service.Authorizer = operations.authority(invocation, identity.AssurancePhishingResistant)
	service.StepUp = operations.authority(invocation, identity.AssurancePhishingResistant)
	service.Audit = operations.auditSink(invocation)
	go operations.runRestore(invocation, job, source, service, expectedActivationGeneration)
	return job.MarketingArchiveJob, nil
}

func (operations *EmailMarketingOperations) StartReconcile(ctx context.Context, invocation Invocation, sourceJobID string) (MarketingArchiveJob, error) {
	if err := operations.authority(invocation, identity.AssuranceMFA).Authorize(ctx, marketing.AuthorizationRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.backup.reconcile", Resource: sourceJobID, DataClass: "aggregate_delivery_metadata"}); err != nil {
		return MarketingArchiveJob{}, marketing.ErrUnauthorized
	}
	source, err := operations.archiveJob(ctx, invocation.Request.TenantID, sourceJobID)
	if err != nil || source.Kind != "backup" || source.State != "succeeded" || source.ArtifactPath == "" {
		return MarketingArchiveJob{}, marketing.ErrNotFound
	}
	now := operations.Now()
	job := marketingArchiveJobRecord{MarketingArchiveJob: MarketingArchiveJob{ID: effectID(invocation), TenantID: invocation.Request.TenantID, Kind: "reconcile", State: "queued", Generation: 1, SourceJobID: source.ID, CreatedAt: now, UpdatedAt: now}, SchemaDigest: source.SchemaDigest, PolicyDigest: source.PolicyDigest, ScopeDigest: source.ScopeDigest, MaximumRecords: source.MaximumRecords, MaximumBytes: source.MaximumBytes}
	if err = operations.insertArchiveJob(ctx, job); err != nil {
		return MarketingArchiveJob{}, err
	}
	go operations.runReconcile(invocation, job, source)
	return job.MarketingArchiveJob, nil
}

func (operations *EmailMarketingOperations) ArchiveJob(ctx context.Context, invocation Invocation, id string) (MarketingArchiveJob, error) {
	request := marketing.AuthorizationRequest{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.backup.status", Resource: id, DataClass: "aggregate_delivery_metadata"}
	if err := operations.authority(invocation, identity.AssurancePassword).Authorize(ctx, request); err != nil {
		return MarketingArchiveJob{}, marketing.ErrUnauthorized
	}
	job, err := operations.archiveJob(ctx, invocation.Request.TenantID, id)
	if err != nil {
		return MarketingArchiveJob{}, err
	}
	if err = operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: "read", EvidenceDigest: digestEmailMarketingValue(job.MarketingArchiveJob), OccurredAt: operations.Now()}); err != nil {
		return MarketingArchiveJob{}, err
	}
	return job.MarketingArchiveJob, nil
}

func (operations *EmailMarketingOperations) runBackup(invocation Invocation, job marketingArchiveJobRecord, service marketing.CampaignBackupService, scope marketing.CampaignBackupScope) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	if operations.transitionArchiveJob(ctx, job.TenantID, job.ID, "queued", "running", "", "", "") != nil {
		return
	}
	partial := job.ArtifactPath + ".partial"
	file, err := os.OpenFile(partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		var manifest marketing.CampaignBackupManifest
		manifest, err = service.Export(ctx, marketingAccess(invocation), invocation.Request.RequestID, operations.Repository, file, scope)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(partial, job.ArtifactPath)
		}
		if err == nil {
			_ = operations.transitionArchiveJob(ctx, job.TenantID, job.ID, "running", "succeeded", "exported", manifest.ContentDigest, "")
			return
		}
	}
	_ = os.Remove(partial)
	_ = os.Remove(job.ArtifactPath)
	_ = operations.transitionArchiveJob(context.Background(), job.TenantID, job.ID, "running", "failed", "export_failed", "", emailMarketingErrorCode(err))
}

func (operations *EmailMarketingOperations) runRestore(invocation Invocation, job, source marketingArchiveJobRecord, service marketing.CampaignBackupService, expected uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	if operations.transitionArchiveJob(ctx, job.TenantID, job.ID, "queued", "running", "", "", "") != nil {
		return
	}
	file, err := os.Open(source.ArtifactPath)
	if err == nil {
		activation := emailMarketingBoundRestoreActivation{activation: operations.Restore, expectedContentDigest: source.EvidenceDigest, expectedScopeDigest: source.ScopeDigest, maximumRecords: source.MaximumRecords, maximumBytes: source.MaximumBytes}
		validation, restoreErr := service.Restore(ctx, marketingAccess(invocation), invocation.Request.RequestID, file, activation, marketing.CampaignRestoreLimits{MaximumRecords: source.MaximumRecords, MaximumBytes: source.MaximumBytes, MaximumLineBytes: 16 << 20, ExpectedTenant: marketing.TenantID(job.TenantID), ExpectedSchemaDigest: source.SchemaDigest, ExpectedPolicyDigest: source.PolicyDigest, ExpectedActivationGeneration: expected})
		err = errors.Join(restoreErr, file.Close())
		if err == nil {
			_ = operations.transitionArchiveJob(ctx, job.TenantID, job.ID, "running", "succeeded", "activated_reauthorization_required", validation.ValidationDigest, "")
			return
		}
	}
	_ = operations.transitionArchiveJob(context.Background(), job.TenantID, job.ID, "running", "failed", "restore_failed", "", emailMarketingErrorCode(err))
}

func (operations *EmailMarketingOperations) runReconcile(invocation Invocation, job, source marketingArchiveJobRecord) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	if operations.transitionArchiveJob(ctx, job.TenantID, job.ID, "queued", "running", "", "", "") != nil {
		return
	}
	request := marketing.AuthorizationRequest{TenantID: marketing.TenantID(job.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String()), Action: "emailmarketing.backup.reconcile", Resource: source.ID, DataClass: "aggregate_delivery_metadata"}
	if err := operations.authority(invocation, identity.AssuranceMFA).Authorize(ctx, request); err != nil {
		_ = operations.transitionArchiveJob(context.Background(), job.TenantID, job.ID, "running", "failed", "reconcile_failed", "", "unauthorized")
		return
	}
	manifest, err := readEmailMarketingManifest(source.ArtifactPath, source.MaximumBytes)
	if err == nil && emailMarketingManifestScopeDigest(manifest, source.MaximumRecords, source.MaximumBytes) != source.ScopeDigest {
		err = marketing.ErrIntegrity
	}
	if err == nil {
		currentPolicyDigest, policyErr := operations.policyDigest(ctx, job.TenantID)
		if policyErr != nil {
			err = policyErr
		} else {
			current, exportErr := marketing.ExportCampaignBackup(ctx, operations.Repository, io.Discard, marketing.CampaignBackupScope{TenantID: marketing.TenantID(job.TenantID), SourceRevision: manifest.SourceRevision, SchemaDigest: manifest.SchemaDigest, PolicyDigest: currentPolicyDigest, Retention: manifest.Retention, CreatedAt: manifest.CreatedAt, MaximumRecords: source.MaximumRecords, MaximumBytes: source.MaximumBytes})
			err = exportErr
			if err == nil {
				result := "drift_detected"
				if current.ContentDigest == source.EvidenceDigest && currentPolicyDigest == source.PolicyDigest {
					result = "in_sync"
				}
				auditErr := operations.auditSink(invocation).RecordAudit(ctx, marketing.AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: "read", EvidenceDigest: current.ContentDigest, OccurredAt: operations.Now()})
				if auditErr == nil {
					_ = operations.transitionArchiveJob(ctx, job.TenantID, job.ID, "running", "succeeded", result, current.ContentDigest, "")
					return
				}
				err = auditErr
			}
		}
	}
	_ = operations.transitionArchiveJob(context.Background(), job.TenantID, job.ID, "running", "failed", "reconcile_failed", "", emailMarketingErrorCode(err))
}

func (operations *EmailMarketingOperations) readPolicyStatus(ctx context.Context, tenant string, campaign marketing.CampaignID) (MarketingPolicyStatus, error) {
	status := MarketingPolicyStatus{Senders: []MarketingSenderProjection{}, Capacities: []MarketingCapacityProjection{}, Reservations: []MarketingReservationProjection{}, AsOf: operations.Now()}
	var target *marketing.Campaign
	var document []byte
	if campaign != "" {
		var value marketing.Campaign
		if err := operations.DB.QueryRowContext(ctx, `SELECT document FROM email_marketing_campaigns_v1 WHERE tenant_id=? AND campaign_id=?`, tenant, campaign).Scan(&document); errors.Is(err, sql.ErrNoRows) {
			return MarketingPolicyStatus{}, marketing.ErrNotFound
		} else if err != nil {
			return MarketingPolicyStatus{}, err
		} else if json.Unmarshal(document, &value) != nil || value.TenantID != marketing.TenantID(tenant) || value.ID != campaign {
			return MarketingPolicyStatus{}, marketing.ErrIntegrity
		}
		target = &value
	}
	err := operations.DB.QueryRowContext(ctx, `SELECT document FROM email_marketing_tenant_policy_v1 WHERE tenant_id=?`, tenant).Scan(&document)
	if err == nil {
		var policy marketing.TenantCampaignPolicy
		if json.Unmarshal(document, &policy) != nil || string(policy.TenantID) != tenant {
			return MarketingPolicyStatus{}, marketing.ErrIntegrity
		}
		projection := projectMarketingPolicy(policy)
		status.Policy = &projection
	} else if !errors.Is(err, sql.ErrNoRows) {
		return MarketingPolicyStatus{}, err
	}
	rows, err := operations.DB.QueryContext(ctx, `SELECT document FROM email_marketing_sender_admission_v1 WHERE tenant_id=? ORDER BY domain`, tenant)
	if err != nil {
		return MarketingPolicyStatus{}, err
	}
	for rows.Next() {
		var sender marketing.SenderDomainAdmission
		if rows.Scan(&document) != nil || json.Unmarshal(document, &sender) != nil || string(sender.TenantID) != tenant {
			rows.Close()
			return MarketingPolicyStatus{}, marketing.ErrIntegrity
		}
		status.Senders = append(status.Senders, MarketingSenderProjection{Domain: sender.Domain, Generation: sender.Generation, EvidenceDigest: sender.EvidenceDigest, VerifiedAt: sender.VerifiedAt, ExpiresAt: sender.ExpiresAt, UpdatedAt: sender.UpdatedAt})
	}
	if err = rows.Close(); err != nil {
		return MarketingPolicyStatus{}, err
	}
	rows, err = operations.DB.QueryContext(ctx, `SELECT document FROM email_marketing_delivery_capacity_v1 WHERE tenant_id=? ORDER BY profile_ref`, tenant)
	if err != nil {
		return MarketingPolicyStatus{}, err
	}
	for rows.Next() {
		var capacity marketing.CampaignDeliveryCapacity
		if rows.Scan(&document) != nil || json.Unmarshal(document, &capacity) != nil || string(capacity.TenantID) != tenant {
			rows.Close()
			return MarketingPolicyStatus{}, marketing.ErrIntegrity
		}
		status.Capacities = append(status.Capacities, projectMarketingCapacity(capacity))
	}
	if err = rows.Close(); err != nil {
		return MarketingPolicyStatus{}, err
	}
	query := `SELECT document FROM email_marketing_campaign_reservations_v1 WHERE tenant_id=?`
	arguments := []any{tenant}
	if campaign != "" {
		query += ` AND campaign_id=?`
		arguments = append(arguments, campaign)
	}
	query += ` ORDER BY updated_at DESC LIMIT 100`
	rows, err = operations.DB.QueryContext(ctx, query, arguments...)
	if err != nil {
		return MarketingPolicyStatus{}, err
	}
	for rows.Next() {
		var reservation marketing.CampaignAdmissionReservation
		if rows.Scan(&document) != nil || json.Unmarshal(document, &reservation) != nil || string(reservation.TenantID) != tenant {
			rows.Close()
			return MarketingPolicyStatus{}, marketing.ErrIntegrity
		}
		status.Reservations = append(status.Reservations, projectMarketingReservation(reservation))
	}
	if err = rows.Close(); err != nil {
		return MarketingPolicyStatus{}, err
	}
	status.WaitReason = "policy_missing"
	if status.Policy != nil {
		senderReady := false
		for _, sender := range status.Senders {
			if sender.ExpiresAt.After(status.AsOf) && (target == nil || sender.Domain == target.VerifiedSenderDomain && sender.EvidenceDigest == target.SenderVerificationDigest) {
				senderReady = true
				break
			}
		}
		switch {
		case !status.Policy.LocalAuthorityReady:
			status.WaitReason = "local_authority_not_ready"
		case status.Policy.Abuse != string(marketing.AbuseClear):
			status.WaitReason = "abuse_" + status.Policy.Abuse
		case status.AsOf.Before(status.Policy.WarmupStartedAt):
			status.WaitReason = "warmup_not_started"
		case target != nil && target.RecipientCount > status.Policy.MaxRecipientsPerCampaign:
			status.WaitReason = "recipient_limit_exceeded"
		case target != nil && len(target.Approvals) < int(status.Policy.MinimumApprovals):
			status.WaitReason = "approvals_missing"
		case !senderReady:
			status.WaitReason = "sender_missing_or_expired"
		case len(status.Capacities) == 0:
			status.WaitReason = "capacity_missing"
		default:
			for _, capacity := range status.Capacities {
				if (target == nil || capacity.ProfileRef == target.DeliveryProfileRef) && capacity.Online && !capacity.ObservedAt.After(status.AsOf) && capacity.ObservedAt.Add(time.Duration(status.Policy.CapacityMaximumAgeSeconds)*time.Second).After(status.AsOf) {
					status.SafetyReady = true
					status.WaitReason = ""
					break
				}
			}
			if !status.SafetyReady {
				status.WaitReason = "capacity_offline_or_stale"
			}
		}
	}
	return status, nil
}

func (operations *EmailMarketingOperations) policyDigest(ctx context.Context, tenant string) (string, error) {
	var document []byte
	if err := operations.DB.QueryRowContext(ctx, `SELECT document FROM email_marketing_tenant_policy_v1 WHERE tenant_id=?`, tenant).Scan(&document); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", marketing.ErrNotFound
		}
		return "", err
	}
	var policy marketing.TenantCampaignPolicy
	if json.Unmarshal(document, &policy) != nil || string(policy.TenantID) != tenant {
		return "", marketing.ErrIntegrity
	}
	return marketing.DigestTenantCampaignPolicy(policy), nil
}

func (operations *EmailMarketingOperations) insertArchiveJob(ctx context.Context, job marketingArchiveJobRecord) error {
	_, err := operations.DB.ExecContext(ctx, `INSERT INTO email_marketing_archive_jobs_v1(job_id,tenant_id,kind,state,generation,source_job_id,artifact_path,schema_digest,policy_digest,scope_digest,maximum_records,maximum_bytes,result,content_digest,error_code,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, job.ID, job.TenantID, job.Kind, job.State, job.Generation, job.SourceJobID, job.ArtifactPath, job.SchemaDigest, job.PolicyDigest, job.ScopeDigest, job.MaximumRecords, job.MaximumBytes, job.Result, job.EvidenceDigest, job.ErrorCode, emailMarketingDBTime(job.CreatedAt), emailMarketingDBTime(job.UpdatedAt))
	if err != nil {
		return marketing.ErrConflict
	}
	return nil
}

func (operations *EmailMarketingOperations) archiveJob(ctx context.Context, tenant, id string) (marketingArchiveJobRecord, error) {
	var job marketingArchiveJobRecord
	var created, updated string
	err := operations.DB.QueryRowContext(ctx, `SELECT job_id,tenant_id,kind,state,generation,source_job_id,artifact_path,schema_digest,policy_digest,scope_digest,maximum_records,maximum_bytes,result,content_digest,error_code,created_at,updated_at FROM email_marketing_archive_jobs_v1 WHERE tenant_id=? AND job_id=?`, tenant, id).Scan(&job.ID, &job.TenantID, &job.Kind, &job.State, &job.Generation, &job.SourceJobID, &job.ArtifactPath, &job.SchemaDigest, &job.PolicyDigest, &job.ScopeDigest, &job.MaximumRecords, &job.MaximumBytes, &job.Result, &job.EvidenceDigest, &job.ErrorCode, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return marketingArchiveJobRecord{}, marketing.ErrNotFound
	}
	if err != nil {
		return marketingArchiveJobRecord{}, err
	}
	job.CreatedAt, err = parseEmailMarketingDBTime(created)
	if err == nil {
		job.UpdatedAt, err = parseEmailMarketingDBTime(updated)
	}
	if err != nil || job.ID != id || job.TenantID != tenant || !validMarketingDigest(job.SchemaDigest) || !validMarketingDigest(job.PolicyDigest) || !validMarketingDigest(job.ScopeDigest) || job.MaximumRecords == 0 || job.MaximumRecords > 100_000_000 || job.MaximumBytes < 1024 || job.MaximumBytes > 1<<40 || job.Kind == "backup" && job.ArtifactPath != filepath.Join(operations.ArchiveRoot, job.ID+".jsonl") || job.Kind == "backup" && job.State == "succeeded" && !validMarketingDigest(job.EvidenceDigest) {
		return marketingArchiveJobRecord{}, marketing.ErrIntegrity
	}
	return job, nil
}

func (operations *EmailMarketingOperations) transitionArchiveJob(ctx context.Context, tenant, id, expected, next, result, evidence, errorCode string) error {
	updated := operations.Now()
	change, err := operations.DB.ExecContext(ctx, `UPDATE email_marketing_archive_jobs_v1 SET state=?,generation=generation+1,result=?,content_digest=?,error_code=?,updated_at=? WHERE tenant_id=? AND job_id=? AND state=?`, next, result, evidence, errorCode, emailMarketingDBTime(updated), tenant, id, expected)
	if err != nil {
		return err
	}
	affected, _ := change.RowsAffected()
	if affected != 1 {
		return marketing.ErrStale
	}
	return nil
}

func (operations *EmailMarketingOperations) authority(invocation Invocation, assurance identity.AssuranceLevel) *emailMarketingAuthority {
	return &emailMarketingAuthority{operations: operations, invocation: invocation, assurance: assurance}
}

func (operations *EmailMarketingOperations) auditSink(invocation Invocation) marketing.AuditSink {
	return emailMarketingAuditSink{operations: operations, invocation: invocation}
}

type emailMarketingAuthority struct {
	operations *EmailMarketingOperations
	invocation Invocation
	assurance  identity.AssuranceLevel
}

func (authority *emailMarketingAuthority) Authorize(ctx context.Context, request marketing.AuthorizationRequest) error {
	if authority == nil || authority.operations == nil || authority.operations.Identity == nil || string(request.TenantID) != authority.invocation.Request.TenantID || string(request.ActorID) != authority.invocation.Actor.PrincipalID.String() {
		return marketing.ErrUnauthorized
	}
	tenant, err := identity.NewID(string(request.TenantID))
	if err != nil {
		return marketing.ErrUnauthorized
	}
	_, err = authority.operations.Identity.AuthorizeActor(ctx, authority.invocation.Actor.IdentityContext(), identity.MustPermission("mail:manage"), identity.Scope{Kind: identity.ScopeTenant, TenantID: tenant}, authority.assurance)
	if err != nil {
		return marketing.ErrUnauthorized
	}
	return nil
}

func (authority *emailMarketingAuthority) VerifyStepUp(ctx context.Context, request marketing.AuthorizationRequest, proof string) (string, error) {
	if proof == "" || proof != authority.invocation.Request.RequestID || authority.Authorize(ctx, request) != nil {
		return "", marketing.ErrUnauthorized
	}
	return digestEmailMarketingValue(struct{ RequestID, Action, Resource string }{proof, request.Action, request.Resource}), nil
}

type emailMarketingAuditSink struct {
	operations *EmailMarketingOperations
	invocation Invocation
}

func (sink emailMarketingAuditSink) RecordAudit(ctx context.Context, record marketing.AuditRecord) error {
	if sink.operations == nil || sink.operations.Audit == nil || sink.operations.Audit.Writer == nil || string(record.TenantID) != sink.invocation.Request.TenantID || string(record.ActorID) != sink.invocation.Actor.PrincipalID.String() {
		return marketing.ErrUnauthorized
	}
	class := audit.ClassMutation
	outcome := audit.OutcomeApplied
	if record.Outcome == "read" {
		class = audit.ClassSensitiveRead
		outcome = audit.OutcomeAllowed
	} else if record.Outcome == "waiting" {
		outcome = audit.OutcomeAmbiguous
	}
	requestDigest := digestEmailMarketingValue(struct{ Action, Resource, Evidence string }{record.Action, record.Resource, record.EvidenceDigest})
	id := "mkt_" + digestEmailMarketingValue(struct{ RequestID, Action, Resource, Outcome string }{sink.invocation.Request.RequestID, record.Action, record.Resource, record.Outcome})[:48]
	_, err := sink.operations.Audit.Writer.Append(ctx, audit.Event{ID: id, Class: class, Action: record.Action, Actor: audit.Actor{PrincipalID: sink.invocation.Actor.PrincipalID.String(), CredentialID: sink.invocation.Actor.CredentialID.String(), SessionID: sink.invocation.Actor.SessionID.String(), TenantID: sink.invocation.Request.TenantID, AuthzEpoch: sink.invocation.Actor.AuthzEpoch, Assurance: fmt.Sprint(sink.invocation.Actor.Assurance), Origin: sink.invocation.Meta.Origin}, Target: audit.Target{Kind: "emailmarketing", ID: record.Resource, TenantID: sink.invocation.Request.TenantID}, Outcome: outcome, RequestDigest: requestDigest, EffectID: effectID(sink.invocation), TraceID: sink.invocation.Request.RequestID, Attributes: map[string]string{"evidence_digest": record.EvidenceDigest}, OccurredAt: record.OccurredAt})
	return err
}

type emailMarketingEventKey struct {
	id    string
	value []byte
}

type emailMarketingTXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type emailMarketingSenderVerifier struct {
	db       *sql.DB
	resolver emailMarketingTXTResolver
	now      func() time.Time
}

func (verifier *emailMarketingSenderVerifier) ResolveVerifiedSender(ctx context.Context, tenant marketing.TenantID, domainName string) (marketing.VerifiedSender, error) {
	if verifier == nil || verifier.db == nil || verifier.resolver == nil || verifier.now == nil || domainName != strings.ToLower(domainName) {
		return marketing.VerifiedSender{}, marketing.ErrUnauthorized
	}
	rows, err := verifier.db.QueryContext(ctx, `SELECT resource_id,generation,state,resource_json FROM mail_resources_v2 WHERE tenant_id=? AND kind=? ORDER BY resource_id`, tenant, mail.ResourceDomain)
	if err != nil {
		return marketing.VerifiedSender{}, err
	}
	defer rows.Close()
	var matched *mail.ResourceEnvelope
	var configured mail.Domain
	for rows.Next() {
		var resourceID string
		var generation uint64
		var state mail.ResourceState
		var raw []byte
		var resource mail.ResourceEnvelope
		var candidate mail.Domain
		if rows.Scan(&resourceID, &generation, &state, &raw) != nil || json.Unmarshal(raw, &resource) != nil || json.Unmarshal(resource.Spec, &candidate) != nil || resource.TenantID != string(tenant) || resource.Kind != mail.ResourceDomain || resource.ID != resourceID || resource.ID != string(candidate.ID) || resource.Generation != generation || resource.State != state || candidate.Tenant != string(tenant) {
			return marketing.VerifiedSender{}, marketing.ErrIntegrity
		}
		if strings.ToLower(candidate.Name) != domainName {
			continue
		}
		if matched != nil || resource.State != mail.StateActive || !candidate.DKIM.Enabled || candidate.DKIM.Selector == "" || candidate.DKIM.PublicKey == "" {
			return marketing.VerifiedSender{}, marketing.ErrUnauthorized
		}
		copyResource := resource
		matched = &copyResource
		configured = candidate
	}
	if err = rows.Err(); err != nil {
		return marketing.VerifiedSender{}, err
	}
	if err = rows.Close(); err != nil {
		return marketing.VerifiedSender{}, err
	}
	if matched == nil {
		return marketing.VerifiedSender{}, marketing.ErrUnauthorized
	}
	records, err := verifier.resolver.LookupTXT(ctx, strings.ToLower(configured.DKIM.Selector)+"._domainkey."+domainName)
	if err != nil {
		return marketing.VerifiedSender{}, marketing.ErrUnauthorized
	}
	expectedKey := emailMarketingDKIMPublicKey(configured.DKIM.PublicKey)
	proofs := make([]string, 0, len(records))
	for _, record := range records {
		if expectedKey != "" && emailMarketingDKIMPublicKey(record) == expectedKey {
			proofs = append(proofs, strings.TrimSpace(record))
		}
	}
	if len(proofs) == 0 {
		return marketing.VerifiedSender{}, marketing.ErrUnauthorized
	}
	sort.Strings(proofs)
	now := verifier.now().UTC()
	evidence := digestEmailMarketingValue(struct {
		Tenant     marketing.TenantID
		Domain     string
		Generation uint64
		Selector   string
		Records    []string
	}{tenant, domainName, matched.Generation, strings.ToLower(configured.DKIM.Selector), proofs})
	return marketing.VerifiedSender{TenantID: tenant, Domain: domainName, EvidenceDigest: evidence, VerifiedAt: now, ExpiresAt: now.Add(24 * time.Hour)}, nil
}

func emailMarketingDKIMPublicKey(record string) string {
	values := make(map[string]string)
	for _, field := range strings.Split(record, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(field), "=")
		if found {
			values[strings.ToLower(strings.TrimSpace(key))] = strings.Join(strings.Fields(value), "")
		}
	}
	if !strings.EqualFold(values["v"], "DKIM1") || values["p"] == "" || values["k"] != "" && !strings.EqualFold(values["k"], "rsa") {
		return ""
	}
	return values["p"]
}

type emailMarketingEventVerifier struct {
	keys map[marketing.DeliveryEventSource]emailMarketingEventKey
}

type emailMarketingSignedEventDocument struct {
	Source            marketing.DeliveryEventSource `json:"source"`
	ProviderRef       string                        `json:"provider_ref"`
	EventID           string                        `json:"event_id"`
	TenantID          marketing.TenantID            `json:"tenant_id"`
	CampaignID        marketing.CampaignID          `json:"campaign_id"`
	AttemptID         marketing.AttemptID           `json:"attempt_id"`
	ProviderMessageID string                        `json:"provider_message_id"`
	Status            marketing.AttemptStatus       `json:"status"`
	Reason            string                        `json:"reason,omitempty"`
	OccurredAt        time.Time                     `json:"occurred_at"`
}

func (verifier *emailMarketingEventVerifier) VerifyDeliveryEvent(ctx context.Context, signed marketing.SignedDeliveryEvent, now time.Time) (marketing.VerifiedDeliveryEvent, error) {
	select {
	case <-ctx.Done():
		return marketing.VerifiedDeliveryEvent{}, ctx.Err()
	default:
	}
	key, found := verifier.keys[signed.Source]
	if !found || signed.KeyID != key.id || len(signed.Signature) != sha256.Size {
		return marketing.VerifiedDeliveryEvent{}, marketing.ErrDeliveryEventRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(signed.Payload))
	decoder.DisallowUnknownFields()
	var document emailMarketingSignedEventDocument
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Source != signed.Source || document.ProviderRef != signed.ProviderRef || document.EventID != signed.EventID {
		return marketing.VerifiedDeliveryEvent{}, marketing.ErrDeliveryEventRejected
	}
	scopedKey := deriveEmailMarketingScopedEventKey(key.value, document.TenantID, signed.ProviderRef)
	defer clearSecret(scopedKey)
	mac := hmac.New(sha256.New, scopedKey)
	mac.Write(emailMarketingEventSigningPayload(signed))
	if !hmac.Equal(mac.Sum(nil), signed.Signature) {
		return marketing.VerifiedDeliveryEvent{}, marketing.ErrDeliveryEventRejected
	}
	return marketing.VerifiedDeliveryEvent{Source: document.Source, ProviderRef: document.ProviderRef, EventID: document.EventID, NonceDigest: marketing.DigestEvidence([]byte(signed.Nonce)), TenantID: document.TenantID, CampaignID: document.CampaignID, AttemptID: document.AttemptID, ProviderMessageID: document.ProviderMessageID, Status: document.Status, Reason: document.Reason, OccurredAt: document.OccurredAt, VerifiedAt: now, SignatureDigest: marketing.DigestEvidence(signed.Signature), PayloadDigest: marketing.DigestEvidence(signed.Payload)}, nil
}

func emailMarketingEventSigningPayload(signed marketing.SignedDeliveryEvent) []byte {
	return []byte("cyberpanel-emailmarketing-event-v1\x00" + string(signed.Source) + "\x00" + signed.ProviderRef + "\x00" + signed.KeyID + "\x00" + signed.EventID + "\x00" + signed.Nonce + "\x00" + signed.SignedAt.UTC().Format(time.RFC3339Nano) + "\x00" + string(signed.Payload))
}

func deriveEmailMarketingKey(master []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("cyberpanel-emailmarketing-events-v1\x00" + purpose))
	return mac.Sum(nil)
}

func deriveEmailMarketingScopedEventKey(sourceKey []byte, tenant marketing.TenantID, providerRef string) []byte {
	mac := hmac.New(sha256.New, sourceKey)
	mac.Write([]byte("cyberpanel-emailmarketing-event-scope-v1\x00" + string(tenant) + "\x00" + providerRef))
	return mac.Sum(nil)
}

func marketingAccess(invocation Invocation) marketing.AdministrativeContext {
	return marketing.AdministrativeContext{TenantID: marketing.TenantID(invocation.Request.TenantID), ActorID: marketing.ActorID(invocation.Actor.PrincipalID.String())}
}

func projectMarketingPolicy(policy marketing.TenantCampaignPolicy) MarketingPolicyProjection {
	return MarketingPolicyProjection{Generation: policy.Generation, MaxRecipientsPerCampaign: policy.MaxRecipientsPerCampaign, MaxRecipientsPerHour: policy.MaxRecipientsPerHour, MaxRecipientsPerDay: policy.MaxRecipientsPerDay, MaxConcurrentCampaigns: policy.MaxConcurrentCampaigns, WarmupStartedAt: policy.WarmupStartedAt, WarmupInitialDailyLimit: policy.WarmupInitialDailyLimit, WarmupDoublingSeconds: uint64(policy.WarmupDoublingPeriod / time.Second), MinimumApprovals: policy.MinimumApprovals, CapacityMaximumAgeSeconds: uint64(policy.CapacityMaximumAge / time.Second), Abuse: string(policy.Abuse), AbuseEvidenceDigest: policy.AbuseEvidenceDigest, LocalAuthorityReady: policy.LocalAuthorityReady, UpdatedAt: policy.UpdatedAt}
}

func projectMarketingCapacity(capacity marketing.CampaignDeliveryCapacity) MarketingCapacityProjection {
	return MarketingCapacityProjection{ProfileRef: capacity.ProfileRef, Generation: capacity.Generation, Kind: string(capacity.Kind), Online: capacity.Online, MaximumConcurrency: capacity.MaximumConcurrency, MaximumRecipientsPerHour: capacity.MaximumRecipientsPerHour, ReservedTransactionalConcurrency: capacity.ReservedTransactionalConcurrency, ReservedTransactionalPerHour: capacity.ReservedTransactionalPerHour, ObservedAt: capacity.ObservedAt, UpdatedAt: capacity.UpdatedAt}
}

func projectMarketingReservation(reservation marketing.CampaignAdmissionReservation) MarketingReservationProjection {
	return MarketingReservationProjection{ID: reservation.ID, CampaignID: string(reservation.CampaignID), CampaignRevision: reservation.CampaignRevision, RecipientCount: reservation.RecipientCount, ProfileRef: reservation.ProfileRef, CapacityKind: string(reservation.CapacityKind), Status: reservation.Status, CreatedAt: reservation.CreatedAt, ExpiresAt: reservation.ExpiresAt, UpdatedAt: reservation.UpdatedAt}
}

func emailMarketingSchemaDigest() string {
	sum := sha256.Sum256([]byte(emailMarketingSchemaVersion))
	return hex.EncodeToString(sum[:])
}

func emailMarketingManifestScopeDigest(manifest marketing.CampaignBackupManifest, maximumRecords uint64, maximumBytes int64) string {
	expectedManifestID := "backup:" + marketing.DigestEvidence([]byte(string(manifest.TenantID)+":"+manifest.SourceRevision+":"+emailMarketingDBTime(manifest.CreatedAt)))[:40]
	if manifest.ManifestID != expectedManifestID {
		return ""
	}
	scope := marketing.CampaignBackupScope{TenantID: manifest.TenantID, SourceRevision: manifest.SourceRevision, SchemaDigest: manifest.SchemaDigest, PolicyDigest: manifest.PolicyDigest, Retention: append([]marketing.BackupRetentionRule(nil), manifest.Retention...), CreatedAt: manifest.CreatedAt, MaximumRecords: maximumRecords, MaximumBytes: maximumBytes}
	return digestEmailMarketingValue(scope)
}

func digestEmailMarketingValue(value any) string {
	raw, _ := json.Marshal(value)
	return marketing.DigestEvidence(raw)
}

func emailMarketingDBTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func parseEmailMarketingDBTime(value string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05.000000000Z", value)
}

func emailMarketingErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, marketing.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, marketing.ErrIntegrity):
		return "integrity"
	case errors.Is(err, marketing.ErrConflict), errors.Is(err, marketing.ErrStale):
		return "conflict"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "interrupted"
	default:
		return "unavailable"
	}
}

func readEmailMarketingManifest(path string, maximumBytes int64) (marketing.CampaignBackupManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return marketing.CampaignBackupManifest{}, err
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, maximumBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > 1<<20 {
		return marketing.CampaignBackupManifest{}, marketing.ErrIntegrity
	}
	var envelope struct {
		Kind     string
		Manifest *marketing.CampaignBackupManifest
	}
	if json.Unmarshal(bytes.TrimSpace(line), &envelope) != nil || envelope.Kind != "manifest" || envelope.Manifest == nil {
		return marketing.CampaignBackupManifest{}, marketing.ErrIntegrity
	}
	return *envelope.Manifest, nil
}

type emailMarketingRestoreActivation struct {
	live   *sql.DB
	root   string
	mu     sync.Mutex
	stages map[string]*emailMarketingRestoreStage
	now    func() time.Time
}

type emailMarketingRestoreStage struct {
	id       string
	path     string
	db       *sql.DB
	manifest marketing.CampaignBackupManifest
}

type emailMarketingBoundRestoreActivation struct {
	activation            *emailMarketingRestoreActivation
	expectedContentDigest string
	expectedScopeDigest   string
	maximumRecords        uint64
	maximumBytes          int64
}

func (bound emailMarketingBoundRestoreActivation) BeginIsolatedCampaignRestore(ctx context.Context, manifest marketing.CampaignBackupManifest) (string, error) {
	if emailMarketingManifestScopeDigest(manifest, bound.maximumRecords, bound.maximumBytes) != bound.expectedScopeDigest {
		return "", marketing.ErrIntegrity
	}
	return bound.activation.BeginIsolatedCampaignRestore(ctx, manifest)
}

func (bound emailMarketingBoundRestoreActivation) StageCampaignRestoreRecord(ctx context.Context, id string, record marketing.CampaignBackupRecord) error {
	return bound.activation.StageCampaignRestoreRecord(ctx, id, record)
}

func (bound emailMarketingBoundRestoreActivation) ValidateIsolatedCampaignRestore(ctx context.Context, id string, manifest marketing.CampaignBackupManifest) (marketing.CampaignRestoreValidation, error) {
	if manifest.ContentDigest != bound.expectedContentDigest {
		return marketing.CampaignRestoreValidation{}, marketing.ErrIntegrity
	}
	return bound.activation.ValidateIsolatedCampaignRestore(ctx, id, manifest)
}

func (bound emailMarketingBoundRestoreActivation) ActivateCampaignRestoreCAS(ctx context.Context, id string, expected uint64, validation marketing.CampaignRestoreValidation) error {
	return bound.activation.ActivateCampaignRestoreCAS(ctx, id, expected, validation)
}

func (bound emailMarketingBoundRestoreActivation) AbortCampaignRestore(ctx context.Context, id string) error {
	return bound.activation.AbortCampaignRestore(ctx, id)
}

func (activation *emailMarketingRestoreActivation) BeginIsolatedCampaignRestore(ctx context.Context, manifest marketing.CampaignBackupManifest) (string, error) {
	now := activation.now()
	for _, retention := range manifest.Retention {
		if !retention.RetainUntil.After(now) {
			return "", marketing.ErrConflict
		}
	}
	id := "restore_" + digestEmailMarketingValue(struct{ Manifest string; At int64 }{manifest.ManifestID, now.UnixNano()})[:40]
	path := filepath.Join(activation.root, id+".stage.sqlite")
	artifact, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	if err = artifact.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	db.SetMaxOpenConns(1)
	_, err = db.ExecContext(ctx, `CREATE TABLE records(sequence INTEGER PRIMARY KEY,record_type TEXT NOT NULL,data_class TEXT NOT NULL,resource_id TEXT NOT NULL,generation INTEGER NOT NULL,payload BLOB NOT NULL,payload_digest TEXT NOT NULL,retain_until TEXT NOT NULL,reauthorization_required INTEGER NOT NULL) STRICT`)
	if err != nil {
		db.Close()
		_ = os.Remove(path)
		return "", err
	}
	activation.mu.Lock()
	activation.stages[id] = &emailMarketingRestoreStage{id: id, path: path, db: db, manifest: manifest}
	activation.mu.Unlock()
	return id, nil
}

func (activation *emailMarketingRestoreActivation) StageCampaignRestoreRecord(ctx context.Context, id string, record marketing.CampaignBackupRecord) error {
	stage := activation.stage(id)
	if stage == nil {
		return marketing.ErrNotFound
	}
	_, err := stage.db.ExecContext(ctx, `INSERT INTO records(sequence,record_type,data_class,resource_id,generation,payload,payload_digest,retain_until,reauthorization_required) VALUES(?,?,?,?,?,?,?,?,?)`, record.Sequence, record.Type, record.DataClass, record.ResourceID, record.Generation, []byte(record.Payload), record.PayloadDigest, emailMarketingDBTime(record.RetainUntil), record.ReauthorizationRequired)
	return err
}

func (activation *emailMarketingRestoreActivation) ValidateIsolatedCampaignRestore(ctx context.Context, id string, manifest marketing.CampaignBackupManifest) (marketing.CampaignRestoreValidation, error) {
	stage := activation.stage(id)
	if stage == nil || stage.manifest.ManifestID != manifest.ManifestID || stage.manifest.TenantID != manifest.TenantID {
		return marketing.CampaignRestoreValidation{}, marketing.ErrIntegrity
	}
	rows, err := stage.db.QueryContext(ctx, `SELECT sequence,record_type,data_class,resource_id,generation,payload,payload_digest,retain_until,reauthorization_required FROM records ORDER BY sequence`)
	if err != nil {
		return marketing.CampaignRestoreValidation{}, err
	}
	defer rows.Close()
	hasher := sha256.New()
	var count uint64
	for rows.Next() {
		record, scanErr := scanEmailMarketingRestoreRecord(rows)
		if scanErr != nil || record.Sequence != count+1 || validateEmailMarketingRestoredRecord(record, manifest.TenantID) != nil {
			return marketing.CampaignRestoreValidation{}, marketing.ErrIntegrity
		}
		raw, _ := json.Marshal(record)
		_, _ = hasher.Write(raw)
		count++
	}
	if err = rows.Err(); err != nil || count != manifest.RecordCount {
		return marketing.CampaignRestoreValidation{}, marketing.ErrIntegrity
	}
	stage.manifest = manifest
	return marketing.CampaignRestoreValidation{ManifestID: manifest.ManifestID, RecordCount: count, ContentDigest: manifest.ContentDigest, ValidationDigest: hex.EncodeToString(hasher.Sum(nil)), ReauthorizationRequired: true}, nil
}

func (activation *emailMarketingRestoreActivation) ActivateCampaignRestoreCAS(ctx context.Context, id string, expected uint64, validation marketing.CampaignRestoreValidation) error {
	if expected != 0 {
		return marketing.ErrConflict
	}
	stage := activation.stage(id)
	if stage == nil || validation.ManifestID != stage.manifest.ManifestID || validation.RecordCount != stage.manifest.RecordCount || validation.ContentDigest != stage.manifest.ContentDigest || !validation.ReauthorizationRequired {
		return marketing.ErrIntegrity
	}
	tx, err := activation.live.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"email_marketing_lists_v1", "email_marketing_tags_v1", "email_marketing_subscribers_v1", "email_marketing_memberships_v1", "email_marketing_consents_v1", "email_marketing_suppression_history_v1", "email_marketing_suppression_state_v1", "email_marketing_tombstones_v1", "email_marketing_import_checkpoints_v1", "email_marketing_unsubscribe_uses_v1", "email_marketing_templates_v1", "email_marketing_template_versions_v1", "email_marketing_campaigns_v1", "email_marketing_campaign_recipients_v1", "email_marketing_campaign_attempts_v1", "email_marketing_campaign_receipts_v1", "email_marketing_campaign_dispatch_v1", "email_marketing_delivery_events_v1", "email_marketing_sender_admission_v1", "email_marketing_delivery_capacity_v1", "email_marketing_campaign_reservations_v1"} {
		var count uint64
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE tenant_id=?`, stage.manifest.TenantID).Scan(&count); err != nil || count != 0 {
			if err == nil {
				err = marketing.ErrConflict
			}
			return err
		}
	}
	rows, err := stage.db.QueryContext(ctx, `SELECT sequence,record_type,data_class,resource_id,generation,payload,payload_digest,retain_until,reauthorization_required FROM records ORDER BY sequence`)
	if err != nil {
		return err
	}
	for rows.Next() {
		record, scanErr := scanEmailMarketingRestoreRecord(rows)
		if scanErr != nil || insertEmailMarketingRestoredRecord(ctx, tx, stage.manifest.TenantID, record, activation.now()) != nil {
			rows.Close()
			return marketing.ErrIntegrity
		}
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_suppression_state_v1(scope,tenant_id,address_digest,record_id,reason,occurred_at) SELECT h.scope,h.tenant_id,h.address_digest,h.record_id,h.reason,h.occurred_at FROM email_marketing_suppression_history_v1 h WHERE h.tenant_id=? AND h.action='added' AND NOT EXISTS(SELECT 1 FROM email_marketing_suppression_history_v1 later WHERE later.scope=h.scope AND later.tenant_id=h.tenant_id AND later.address_digest=h.address_digest AND later.reason=h.reason AND (later.occurred_at>h.occurred_at OR (later.occurred_at=h.occurred_at AND later.record_id>h.record_id)))`, stage.manifest.TenantID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	activation.cleanup(id)
	return nil
}

func (activation *emailMarketingRestoreActivation) AbortCampaignRestore(_ context.Context, id string) error {
	activation.cleanup(id)
	return nil
}

func (activation *emailMarketingRestoreActivation) stage(id string) *emailMarketingRestoreStage {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	return activation.stages[id]
}

func (activation *emailMarketingRestoreActivation) cleanup(id string) {
	activation.mu.Lock()
	stage := activation.stages[id]
	delete(activation.stages, id)
	activation.mu.Unlock()
	if stage != nil {
		_ = stage.db.Close()
		_ = os.Remove(stage.path)
	}
}

type emailMarketingRowScanner interface {
	Scan(...any) error
}

func scanEmailMarketingRestoreRecord(row emailMarketingRowScanner) (marketing.CampaignBackupRecord, error) {
	var record marketing.CampaignBackupRecord
	var payload []byte
	var retainUntil string
	err := row.Scan(&record.Sequence, &record.Type, &record.DataClass, &record.ResourceID, &record.Generation, &payload, &record.PayloadDigest, &retainUntil, &record.ReauthorizationRequired)
	if err != nil {
		return marketing.CampaignBackupRecord{}, err
	}
	record.Payload = append(json.RawMessage(nil), payload...)
	record.RetainUntil, err = parseEmailMarketingDBTime(retainUntil)
	return record, err
}

func validateEmailMarketingRestoredRecord(record marketing.CampaignBackupRecord, tenant marketing.TenantID) error {
	check := func(expected string, _ any) error {
		if record.ResourceID != expected {
			return marketing.ErrIntegrity
		}
		return nil
	}
	switch {
	case strings.HasPrefix(record.ResourceID, "list:"):
		var value marketing.List
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("list:"+string(value.ID), value)
	case strings.HasPrefix(record.ResourceID, "tag:"):
		var value marketing.Tag
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("tag:"+string(value.ID), value)
	case strings.HasPrefix(record.ResourceID, "subscriber:"):
		var value marketing.Subscriber
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("subscriber:"+string(value.ID), value)
	case strings.HasPrefix(record.ResourceID, "membership:"):
		var value marketing.Membership
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("membership:"+string(value.ListID)+":"+string(value.SubscriberID), value)
	case strings.HasPrefix(record.ResourceID, "consent:"):
		var value marketing.ConsentRecord
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("consent:"+value.ID, value)
	case strings.HasPrefix(record.ResourceID, "suppression:"):
		var value marketing.SuppressionRecord
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("suppression:"+value.ID, value)
	case strings.HasPrefix(record.ResourceID, "template_version:"):
		var value marketing.MessageTemplateVersion
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check(fmt.Sprintf("template_version:%s:%d", value.TemplateID, value.Version), value)
	case strings.HasPrefix(record.ResourceID, "template:"):
		var value marketing.MessageTemplate
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("template:"+string(value.ID), value)
	case strings.HasPrefix(record.ResourceID, "recipient:"):
		var value marketing.FrozenRecipient
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check(fmt.Sprintf("recipient:%s:%d", value.CampaignID, value.Ordinal), value)
	case strings.HasPrefix(record.ResourceID, "campaign:"):
		var value marketing.Campaign
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("campaign:"+string(value.ID), value)
	case strings.HasPrefix(record.ResourceID, "attempt:"):
		var value marketing.QueueAttempt
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("attempt:"+string(value.ID), value)
	case strings.HasPrefix(record.ResourceID, "receipt:"):
		var value marketing.AttemptReceipt
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("receipt:"+value.ID, value)
	case strings.HasPrefix(record.ResourceID, "event:"):
		var value marketing.VerifiedDeliveryEvent
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant {
			return marketing.ErrIntegrity
		}
		return check("event:"+value.ProviderRef+":"+value.EventID, value)
	case strings.HasPrefix(record.ResourceID, "sender:"):
		var value marketing.SenderDomainAdmission
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant || !record.ReauthorizationRequired {
			return marketing.ErrIntegrity
		}
		return check("sender:"+value.Domain, value)
	case strings.HasPrefix(record.ResourceID, "capacity:"):
		var value marketing.CampaignDeliveryCapacity
		if json.Unmarshal(record.Payload, &value) != nil || value.TenantID != tenant || !record.ReauthorizationRequired {
			return marketing.ErrIntegrity
		}
		return check("capacity:"+value.ProfileRef, value)
	default:
		return marketing.ErrIntegrity
	}
}

func insertEmailMarketingRestoredRecord(ctx context.Context, tx *sql.Tx, tenant marketing.TenantID, record marketing.CampaignBackupRecord, now time.Time) error {
	if err := validateEmailMarketingRestoredRecord(record, tenant); err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(record.ResourceID, "list:"):
		var value marketing.List
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_lists_v1(tenant_id,list_id,generation,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?)`, value.TenantID, value.ID, value.Generation, value.Lifecycle, []byte(record.Payload), emailMarketingDBTime(value.UpdatedAt))
		return err
	case strings.HasPrefix(record.ResourceID, "tag:"):
		var value marketing.Tag
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_tags_v1(tenant_id,tag_id,generation,name,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?,?)`, value.TenantID, value.ID, value.Generation, value.Name, value.Lifecycle, []byte(record.Payload), emailMarketingDBTime(value.UpdatedAt))
		return err
	case strings.HasPrefix(record.ResourceID, "subscriber:"):
		var value marketing.Subscriber
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_subscribers_v1(tenant_id,subscriber_id,address,address_digest,generation,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?,?,?)`, value.TenantID, value.ID, value.Address.Normalized, value.Address.Digest, value.Generation, value.Lifecycle, []byte(record.Payload), emailMarketingDBTime(value.UpdatedAt))
		return err
	case strings.HasPrefix(record.ResourceID, "membership:"):
		var value marketing.Membership
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_memberships_v1(tenant_id,list_id,subscriber_id,status,generation,document,updated_at) VALUES(?,?,?,?,?,?,?)`, value.TenantID, value.ListID, value.SubscriberID, value.Status, value.Generation, []byte(record.Payload), emailMarketingDBTime(value.UpdatedAt))
		return err
	case strings.HasPrefix(record.ResourceID, "consent:"):
		var value marketing.ConsentRecord
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_consents_v1(consent_id,tenant_id,list_id,subscriber_id,captured_at,recorded_at,evidence_digest,document) VALUES(?,?,?,?,?,?,?,?)`, value.ID, value.TenantID, value.ListID, value.SubscriberID, emailMarketingDBTime(value.CapturedAt), emailMarketingDBTime(value.RecordedAt), value.EvidenceDigest, []byte(record.Payload))
		return err
	case strings.HasPrefix(record.ResourceID, "suppression:"):
		var value marketing.SuppressionRecord
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_suppression_history_v1(record_id,scope,tenant_id,list_id,subscriber_id,address_digest,reason,action,occurred_at,document) VALUES(?,?,?,?,?,?,?,?,?,?)`, value.ID, value.Scope, value.TenantID, value.ListID, value.SubscriberID, value.AddressDigest, value.Reason, value.Action, emailMarketingDBTime(value.OccurredAt), []byte(record.Payload))
		return err
	case strings.HasPrefix(record.ResourceID, "template_version:"):
		var value marketing.MessageTemplateVersion
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_template_versions_v1(tenant_id,template_id,version,digest,document,created_at) VALUES(?,?,?,?,?,?)`, value.TenantID, value.TemplateID, value.Version, value.Digest, []byte(record.Payload), emailMarketingDBTime(value.CreatedAt))
		return err
	case strings.HasPrefix(record.ResourceID, "template:"):
		var value marketing.MessageTemplate
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_templates_v1(tenant_id,template_id,generation,latest_version,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?,?)`, value.TenantID, value.ID, value.Generation, value.LatestVersion, value.Lifecycle, []byte(record.Payload), emailMarketingDBTime(value.UpdatedAt))
		return err
	case strings.HasPrefix(record.ResourceID, "recipient:"):
		var value marketing.FrozenRecipient
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_recipients_v1(tenant_id,campaign_id,campaign_revision,ordinal,subscriber_id,list_id,address,address_digest,consent_id,consent_digest,snapshot_digest,document) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, value.TenantID, value.CampaignID, value.CampaignRevision, value.Ordinal, value.SubscriberID, value.ListID, value.Address.Normalized, value.Address.Digest, value.ConsentID, value.ConsentDigest, value.SnapshotDigest, []byte(record.Payload))
		return err
	case strings.HasPrefix(record.ResourceID, "campaign:"):
		var value marketing.Campaign
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_campaigns_v1(tenant_id,campaign_id,generation,revision,state,document,updated_at) VALUES(?,?,?,?,?,?,?)`, value.TenantID, value.ID, value.Generation, value.Revision, value.State, []byte(record.Payload), emailMarketingDBTime(value.UpdatedAt))
		return err
	case strings.HasPrefix(record.ResourceID, "attempt:"):
		var value marketing.QueueAttempt
		_ = json.Unmarshal(record.Payload, &value)
		value.LeaseOwner = ""
		value.LeaseExpiresAt = time.Time{}
		document, _ := json.Marshal(value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_attempts_v1(attempt_id,tenant_id,campaign_id,campaign_revision,recipient_ordinal,status,attempt_number,next_attempt_at,lease_owner,lease_expires_at,fence,awaiting_receipt,document,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.ID, value.TenantID, value.CampaignID, value.CampaignRevision, value.RecipientOrdinal, value.Status, value.AttemptNumber, emailMarketingDBTime(value.NextAttemptAt), "", "", value.Fence, value.AwaitingReceipt, document, emailMarketingDBTime(value.UpdatedAt))
		return err
	case strings.HasPrefix(record.ResourceID, "receipt:"):
		var value marketing.AttemptReceipt
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_receipts_v1(receipt_id,tenant_id,campaign_id,attempt_id,status,provider_message_id,delayed_event,observed_at,document) VALUES(?,?,?,?,?,?,?,?,?)`, value.ID, value.TenantID, value.CampaignID, value.AttemptID, value.Status, value.ProviderMessageID, value.DelayedEvent, emailMarketingDBTime(value.ObservedAt), []byte(record.Payload))
		return err
	case strings.HasPrefix(record.ResourceID, "event:"):
		var value marketing.VerifiedDeliveryEvent
		_ = json.Unmarshal(record.Payload, &value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_delivery_events_v1(provider_ref,event_id,nonce_digest,tenant_id,campaign_id,attempt_id,provider_message_id,status,occurred_at,received_at,delayed,out_of_order,payload_digest,document) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, value.ProviderRef, value.EventID, value.NonceDigest, value.TenantID, value.CampaignID, value.AttemptID, value.ProviderMessageID, value.Status, emailMarketingDBTime(value.OccurredAt), emailMarketingDBTime(now), true, false, value.PayloadDigest, []byte(record.Payload))
		return err
	case strings.HasPrefix(record.ResourceID, "sender:"):
		var value marketing.SenderDomainAdmission
		_ = json.Unmarshal(record.Payload, &value)
		value.ExpiresAt = value.VerifiedAt
		value.UpdatedAt = now
		document, _ := json.Marshal(value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_sender_admission_v1(tenant_id,domain,generation,evidence_digest,expires_at,document,updated_at) VALUES(?,?,?,?,?,?,?)`, value.TenantID, value.Domain, value.Generation, value.EvidenceDigest, emailMarketingDBTime(value.ExpiresAt), document, emailMarketingDBTime(value.UpdatedAt))
		return err
	case strings.HasPrefix(record.ResourceID, "capacity:"):
		var value marketing.CampaignDeliveryCapacity
		_ = json.Unmarshal(record.Payload, &value)
		value.Online = false
		value.UpdatedAt = now
		document, _ := json.Marshal(value)
		_, err := tx.ExecContext(ctx, `INSERT INTO email_marketing_delivery_capacity_v1(tenant_id,profile_ref,generation,kind,online,document,updated_at) VALUES(?,?,?,?,?,?,?)`, value.TenantID, value.ProfileRef, value.Generation, value.Kind, false, document, emailMarketingDBTime(value.UpdatedAt))
		return err
	default:
		return marketing.ErrIntegrity
	}
}
