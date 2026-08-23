package mailtelemetry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type ExportState string

const (
	ExportPending  ExportState = "pending"
	ExportRunning  ExportState = "running"
	ExportComplete ExportState = "complete"
	ExportFailed   ExportState = "failed"
)

func (state ExportState) valid() bool { return state == ExportPending || state == ExportRunning || state == ExportComplete || state == ExportFailed }

type ExportJob struct {
	ID             ExportID   `json:"id"`
	TenantID       TenantID   `json:"tenant_id"`
	PolicyID       PolicyID   `json:"policy_id"`
	PolicyRevision uint64     `json:"policy_revision"`
	Format         string     `json:"format"`
	QueryDigest    string     `json:"query_digest"`
	State          ExportState `json:"state"`
	Rows           uint64     `json:"rows"`
	Bytes          int64      `json:"bytes"`
	ArtifactID     string     `json:"artifact_id,omitempty"`
	ArtifactDigest string     `json:"artifact_digest,omitempty"`
	FailureCode    string     `json:"failure_code,omitempty"`
	Revision       uint64     `json:"revision"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (job ExportJob) valid() bool {
	if !validID(string(job.ID)) || !validID(string(job.TenantID)) || !validID(string(job.PolicyID)) || job.PolicyRevision == 0 || job.Format != "jsonl-v1" || !validDigest(job.QueryDigest) || !job.State.valid() || job.Rows > MaximumExportRows || job.Bytes < 0 || job.Bytes > MaximumExportBytes || job.Revision == 0 || job.CreatedAt.IsZero() || job.UpdatedAt.Before(job.CreatedAt) || len(job.FailureCode) > 128 {
		return false
	}
	if job.State == ExportComplete {
		return validID(job.ArtifactID) && validDigest(job.ArtifactDigest) && job.FailureCode == ""
	}
	return job.ArtifactID == "" && job.ArtifactDigest == ""
}

func (repository *SQLiteRepository) putExportJob(ctx context.Context, job ExportJob, expectedRevision uint64) error {
	if repository == nil || ctx == nil || !job.valid() || job.Revision != expectedRevision+1 {
		return ErrInvalid
	}
	document, err := encodeDocument(job, 64<<10)
	if err != nil { return err }
	if expectedRevision == 0 {
		_, err = repository.db.ExecContext(ctx, `INSERT INTO mail_telemetry_export_jobs_v1(export_id,tenant_id,policy_id,revision,state,document,updated_at) VALUES(?,?,?,?,?,?,?)`, job.ID, job.TenantID, job.PolicyID, job.Revision, job.State, document, repositoryTime(job.UpdatedAt))
		if err != nil { return errors.Join(ErrConflict, err) }
		return nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE mail_telemetry_export_jobs_v1 SET revision=?,state=?,document=?,updated_at=? WHERE export_id=? AND tenant_id=? AND revision=?`, job.Revision, job.State, document, repositoryTime(job.UpdatedAt), job.ID, job.TenantID, expectedRevision)
	if err != nil { return err }
	return changedExactlyOne(result)
}

func (repository *SQLiteRepository) GetExportJob(ctx context.Context, actor Actor, tenant TenantID, exportID ExportID) (ExportJob, error) {
	if repository == nil || ctx == nil || !actor.valid() || !validID(string(exportID)) { return ExportJob{}, ErrInvalid }
	if actor.TenantID != tenant { return ExportJob{}, ErrNotFound }
	var document []byte
	var revision uint64
	err := repository.db.QueryRowContext(ctx, `SELECT revision,document FROM mail_telemetry_export_jobs_v1 WHERE tenant_id=? AND export_id=?`, tenant, exportID).Scan(&revision, &document)
	if errors.Is(err, sql.ErrNoRows) { return ExportJob{}, ErrNotFound }
	if err != nil { return ExportJob{}, err }
	var job ExportJob
	if decodeDocument(document, 64<<10, &job) != nil || !job.valid() || job.TenantID != tenant || job.ID != exportID || job.Revision != revision { return ExportJob{}, ErrIntegrity }
	policy, err := repository.GetPolicy(ctx, actor, tenant, job.PolicyID)
	if err != nil { return ExportJob{}, ErrNotFound }
	if repository.authorizer.AuthorizeExport(ctx, actor, policy, job.Format) != nil { return ExportJob{}, ErrNotFound }
	return job, nil
}

type ArtifactManifest struct {
	SchemaVersion  uint16    `json:"schema_version"`
	ExportID       ExportID  `json:"export_id"`
	TenantID       TenantID  `json:"tenant_id"`
	PolicyID       PolicyID  `json:"policy_id"`
	PolicyRevision uint64    `json:"policy_revision"`
	Format         string    `json:"format"`
	QueryDigest    string    `json:"query_digest"`
	ContentDigest  string    `json:"content_digest"`
	Rows           uint64    `json:"rows"`
	Bytes          int64     `json:"bytes"`
	MissingGapIDs  []string  `json:"missing_gap_ids"`
	GeneratedAt    time.Time `json:"generated_at"`
}

type ArtifactReceipt struct {
	ArtifactID     string
	ManifestDigest string
}

type ArtifactStream interface {
	WriteArtifactChunk(context.Context, []byte) error
	CommitArtifact(context.Context, ArtifactManifest) (ArtifactReceipt, error)
	AbortArtifact(context.Context) error
}

type ArtifactSink interface {
	OpenMailTelemetryArtifact(context.Context, TenantID, ExportID, string) (ArtifactStream, error)
}

type ExportRequest struct {
	ID       ExportID
	PolicyID PolicyID
	Format   string
	Query    EventQuery
}

type Exporter struct {
	repository *SQLiteRepository
	sink       ArtifactSink
	now        func() time.Time
}

func NewExporter(repository *SQLiteRepository, sink ArtifactSink) (*Exporter, error) {
	if repository == nil || sink == nil { return nil, ErrInvalid }
	return &Exporter{repository: repository, sink: sink, now: time.Now}, nil
}

func exportQueryDigest(request ExportRequest) (string, error) {
	encoded, err := encodeDocument(struct {
		PolicyID PolicyID `json:"policy_id"`
		Format string `json:"format"`
		TenantID TenantID `json:"tenant_id"`
		DomainID DomainID `json:"domain_id,omitempty"`
		MailboxID MailboxID `json:"mailbox_id,omitempty"`
		Categories []Category `json:"categories"`
		Start time.Time `json:"start"`
		End time.Time `json:"end"`
	}{request.PolicyID, request.Format, request.Query.TenantID, request.Query.DomainID, request.Query.MailboxID, request.Query.Categories, request.Query.Start.UTC(), request.Query.End.UTC()}, 32<<10)
	if err != nil { return "", err }
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func (exporter *Exporter) Export(ctx context.Context, actor Actor, request ExportRequest) (ExportJob, error) {
	if exporter == nil || ctx == nil || !actor.valid() || actor.TenantID != request.Query.TenantID || !validID(string(request.ID)) || !validID(string(request.PolicyID)) || request.Query.validate(actor) != nil || request.Query.AfterID != "" || request.Format != "jsonl-v1" {
		return ExportJob{}, ErrInvalid
	}
	policy, err := exporter.repository.GetPolicy(ctx, actor, actor.TenantID, request.PolicyID)
	if err != nil { return ExportJob{}, err }
	if !policy.Transfer.ExportAllowed || policy.Transfer.RequireStepUp && (actor.StepUpAt.IsZero() || exporter.now().UTC().Sub(actor.StepUpAt.UTC()) > 5*time.Minute || actor.StepUpAt.After(exporter.now().UTC().Add(time.Minute))) {
		return ExportJob{}, ErrUnauthorized
	}
	allowed := false
	for _, format := range policy.Transfer.AllowedExportFormats { if format == request.Format { allowed = true } }
	if !allowed || exporter.repository.authorizer.AuthorizeExport(ctx, actor, policy, request.Format) != nil { return ExportJob{}, ErrUnauthorized }
	if policy.DomainID != "" && request.Query.DomainID != policy.DomainID || policy.MailboxID != "" && request.Query.MailboxID != policy.MailboxID { return ExportJob{}, ErrUnauthorized }
	queryDigest, err := exportQueryDigest(request)
	if err != nil { return ExportJob{}, err }
	now := exporter.now().UTC()
	job := ExportJob{ID: request.ID, TenantID: actor.TenantID, PolicyID: policy.ID, PolicyRevision: policy.Revision, Format: request.Format, QueryDigest: queryDigest, State: ExportPending, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err = exporter.repository.putExportJob(ctx, job, 0); err != nil { return ExportJob{}, err }
	audit := AuditRecord{Action: "mail_telemetry.export", Actor: actor, TenantID: actor.TenantID, ResourceID: string(request.ID), At: now, RequestDigest: queryDigest, Outcome: "authorized", EvidenceDigest: digestParts(string(request.ID), queryDigest, actor.SubjectID)}
	if err = exporter.repository.auditor.RecordMailTelemetryAudit(ctx, audit); err != nil { return exporter.failJob(ctx, job, "audit_unavailable", err) }
	stream, err := exporter.sink.OpenMailTelemetryArtifact(ctx, actor.TenantID, request.ID, "application/x-ndjson")
	if err != nil { return exporter.failJob(ctx, job, "sink_open_failed", err) }
	committed := false
	defer func() { if !committed { _ = stream.AbortArtifact(context.Background()) } }()
	job.State, job.Revision, job.UpdatedAt = ExportRunning, 2, exporter.now().UTC()
	if err = exporter.repository.putExportJob(ctx, job, 1); err != nil { return ExportJob{}, err }
	hash := sha256.New()
	query := request.Query
	query.Limit = MaximumPageSize
	missing := make(map[string]struct{})
	for {
		page, searchErr := exporter.repository.SearchEvents(ctx, actor, query)
		if searchErr != nil { return exporter.failJob(ctx, job, "search_failed", searchErr) }
		for _, gap := range page.Missing { if len(missing) < 256 { missing[gap.ID] = struct{}{} } }
		for _, event := range page.Events {
			encoded, encodeErr := json.Marshal(event)
			if encodeErr != nil || len(encoded) > MaximumRecordBytes { return exporter.failJob(ctx, job, "encode_failed", ErrIntegrity) }
			encoded = append(encoded, '\n')
			if job.Rows == MaximumExportRows || job.Bytes+int64(len(encoded)) > MaximumExportBytes { return exporter.failJob(ctx, job, "export_limit", ErrLimit) }
			if _, err = hash.Write(encoded); err != nil { return exporter.failJob(ctx, job, "digest_failed", err) }
			if err = stream.WriteArtifactChunk(ctx, encoded); err != nil { return exporter.failJob(ctx, job, "sink_write_failed", err) }
			job.Rows++
			job.Bytes += int64(len(encoded))
		}
		if page.NextEventID == "" { break }
		query.AfterAt, query.AfterID = page.NextAt, page.NextEventID
	}
	gapIDs := make([]string, 0, len(missing))
	for id := range missing { gapIDs = append(gapIDs, id) }
	sortStrings(gapIDs)
	manifest := ArtifactManifest{SchemaVersion: 1, ExportID: request.ID, TenantID: actor.TenantID, PolicyID: policy.ID, PolicyRevision: policy.Revision, Format: request.Format, QueryDigest: queryDigest, ContentDigest: hex.EncodeToString(hash.Sum(nil)), Rows: job.Rows, Bytes: job.Bytes, MissingGapIDs: gapIDs, GeneratedAt: exporter.now().UTC()}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil { return exporter.failJob(ctx, job, "manifest_failed", err) }
	manifestSum := sha256.Sum256(manifestRaw)
	audit.At, audit.Outcome, audit.EvidenceDigest = manifest.GeneratedAt, "ready", hex.EncodeToString(manifestSum[:])
	if err = exporter.repository.auditor.RecordMailTelemetryAudit(ctx, audit); err != nil { return exporter.failJob(ctx, job, "audit_unavailable", err) }
	receipt, err := stream.CommitArtifact(ctx, manifest)
	if err != nil || !validID(receipt.ArtifactID) || receipt.ManifestDigest != hex.EncodeToString(manifestSum[:]) { return exporter.failJob(ctx, job, "sink_commit_failed", errors.Join(ErrIntegrity, err)) }
	committed = true
	job.State, job.ArtifactID, job.ArtifactDigest = ExportComplete, receipt.ArtifactID, manifest.ContentDigest
	job.Revision++
	job.UpdatedAt = exporter.now().UTC()
	if err = exporter.repository.putExportJob(ctx, job, job.Revision-1); err != nil { return ExportJob{}, err }
	return job, nil
}

func (exporter *Exporter) failJob(ctx context.Context, job ExportJob, code string, cause error) (ExportJob, error) {
	if job.State != ExportComplete {
		job.State, job.FailureCode = ExportFailed, code
		job.Revision++
		job.UpdatedAt = exporter.now().UTC()
		_ = exporter.repository.putExportJob(ctx, job, job.Revision-1)
	}
	return job, cause
}

func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- { values[cursor], values[cursor-1] = values[cursor-1], values[cursor] }
	}
}

type PolicyBundle struct {
	SchemaVersion uint16 `json:"schema_version"`
	Purpose string `json:"purpose"`
	Policy Policy `json:"policy"`
	HistorySelected bool `json:"history_selected"`
	History []Event `json:"history,omitempty"`
	HistoryExcludedReason string `json:"history_excluded_reason,omitempty"`
	SourceInstallation string `json:"source_installation"`
	CreatedAt time.Time `json:"created_at"`
	Digest string `json:"digest"`
}

func BuildPolicyBundle(policy Policy, purpose, sourceInstallation string, historySelected bool, history []Event, excludedReason string, createdAt time.Time) (PolicyBundle, error) {
	if policy.Validate() != nil || (purpose != "backup" && purpose != "migration") || !validID(sourceInstallation) || createdAt.IsZero() || len(history) > 10_000 || historySelected && excludedReason != "" || !historySelected && (len(history) != 0 || excludedReason == "" || len(excludedReason) > 256) { return PolicyBundle{}, ErrInvalid }
	if historySelected && (purpose == "backup" && !policy.Transfer.BackupHistory || purpose == "migration" && !policy.Transfer.MigrationHistory) { return PolicyBundle{}, ErrUnauthorized }
	for _, event := range history {
		if event.Validate() != nil || event.TenantID != policy.TenantID || policy.DomainID != "" && event.DomainID != policy.DomainID || policy.MailboxID != "" && event.MailboxID != policy.MailboxID { return PolicyBundle{}, ErrInvalid }
	}
	bundle := PolicyBundle{SchemaVersion: 1, Purpose: purpose, Policy: policy, HistorySelected: historySelected, History: append([]Event(nil), history...), HistoryExcludedReason: excludedReason, SourceInstallation: sourceInstallation, CreatedAt: createdAt.UTC()}
	payload, err := json.Marshal(bundle)
	if err != nil { return PolicyBundle{}, err }
	if len(payload) > 128<<20 { return PolicyBundle{}, ErrLimit }
	sum := sha256.Sum256(payload)
	bundle.Digest = hex.EncodeToString(sum[:])
	return bundle, nil
}

func (bundle PolicyBundle) Validate() error {
	if bundle.SchemaVersion != 1 || (bundle.Purpose != "backup" && bundle.Purpose != "migration") || bundle.Policy.Validate() != nil || !validID(bundle.SourceInstallation) || bundle.CreatedAt.IsZero() || !validDigest(bundle.Digest) || len(bundle.History) > 10_000 || bundle.HistorySelected && bundle.HistoryExcludedReason != "" || !bundle.HistorySelected && (len(bundle.History) != 0 || bundle.HistoryExcludedReason == "" || len(bundle.HistoryExcludedReason) > 256) { return ErrInvalid }
	if bundle.HistorySelected && (bundle.Purpose == "backup" && !bundle.Policy.Transfer.BackupHistory || bundle.Purpose == "migration" && !bundle.Policy.Transfer.MigrationHistory) { return ErrIntegrity }
	for _, event := range bundle.History {
		if event.Validate() != nil || event.TenantID != bundle.Policy.TenantID || bundle.Policy.DomainID != "" && event.DomainID != bundle.Policy.DomainID || bundle.Policy.MailboxID != "" && event.MailboxID != bundle.Policy.MailboxID { return ErrIntegrity }
	}
	digest := bundle.Digest
	bundle.Digest = ""
	payload, err := json.Marshal(bundle)
	if err != nil || len(payload) > 128<<20 { return ErrIntegrity }
	sum := sha256.Sum256(payload)
	if digest != hex.EncodeToString(sum[:]) { return ErrIntegrity }
	return nil
}

type RestoreOptions struct {
	ExpectedRevision uint64
	AllowEnabled bool
	DestinationTenant TenantID
	DestinationDomain DomainID
	DestinationMailbox MailboxID
	Now time.Time
}

func (repository *SQLiteRepository) RestorePolicyBundle(ctx context.Context, actor Actor, bundle PolicyBundle, options RestoreOptions) (Policy, error) {
	if repository == nil || ctx == nil || bundle.Validate() != nil || !options.Now.IsZero() && options.Now.Before(bundle.CreatedAt) || actor.TenantID != options.DestinationTenant || !validID(string(options.DestinationTenant)) || options.DestinationDomain != "" && !validID(string(options.DestinationDomain)) || options.DestinationMailbox != "" && !validID(string(options.DestinationMailbox)) { return Policy{}, ErrInvalid }
	policy := bundle.Policy
	policy.TenantID, policy.DomainID, policy.MailboxID = options.DestinationTenant, options.DestinationDomain, options.DestinationMailbox
	if policy.Enabled && !options.AllowEnabled { return Policy{}, ErrConflict }
	policy.Revision = options.ExpectedRevision + 1
	if options.ExpectedRevision == 0 { policy.CreatedAt = options.Now.UTC() }
	policy.UpdatedAt = options.Now.UTC()
	if policy.Validate() != nil { return Policy{}, ErrInvalid }
	if err := repository.PutPolicy(ctx, actor, policy, options.ExpectedRevision); err != nil { return Policy{}, err }
	for _, sourceEvent := range bundle.History {
		event := sourceEvent
		event.ID = EventID("event-" + digestParts(bundle.Digest, string(sourceEvent.ID), string(options.DestinationTenant))[:24])
		event.TenantID, event.DomainID, event.MailboxID = options.DestinationTenant, options.DestinationDomain, options.DestinationMailbox
		event.SourceID = SourceID("import-" + digestParts(bundle.Digest, string(options.DestinationTenant))[:24])
		event.SourceGeneration = 1
		event.SourceCursor = string(sourceEvent.ID)
		event.ObservedAt = options.Now.UTC()
		if event.ObservedAt.Before(event.OccurredAt.Add(-time.Minute)) { event.ObservedAt = event.OccurredAt }
		if event.Validate() != nil { return Policy{}, ErrIntegrity }
		if _, err := repository.PutEvent(ctx, event); err != nil { return Policy{}, err }
	}
	return policy, nil
}

func (job ExportJob) String() string { return fmt.Sprintf("%s/%s", job.TenantID, job.ID) }
