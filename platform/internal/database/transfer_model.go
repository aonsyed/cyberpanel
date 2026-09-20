package database

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

var (
	ErrTransferInvalid    = errors.New("invalid database transfer")
	ErrTransferStale      = errors.New("database transfer state is stale")
	ErrTransferLimit      = errors.New("database transfer limit exceeded")
	ErrTransferUnsafeSQL  = errors.New("database transfer contains unsafe SQL")
	ErrTransferCancelled  = errors.New("database transfer cancelled at a safe point")
)

const (
	MaximumTransferBytes      uint64 = 1 << 40
	MaximumTransferRows       uint64 = 1_000_000_000
	MaximumTransferDuration          = 24 * time.Hour
	MaximumTransferTables            = 2048
	MaximumTransferStderrBytes        = 64 << 10
	MaximumTransferStatementBytes     = 8 << 20
	MaximumTransferReceiptBytes       = 256 << 10
)

type TransferDirection string

const (
	TransferExport TransferDirection = "export"
	TransferImport TransferDirection = "import"
)

type TransferFormat string

const TransferFormatSQL TransferFormat = "mariadb_sql_v1"

type TransferCompression string

const (
	TransferCompressionNone TransferCompression = "none"
	TransferCompressionGzip TransferCompression = "gzip"
)

type TransferConflictPolicy string

const (
	TransferConflictFail    TransferConflictPolicy = "fail_if_not_empty"
	TransferConflictReplace TransferConflictPolicy = "replace"
)

type TransferSelection struct {
	Schema bool            `json:"schema"`
	Data   bool            `json:"data"`
	Tables []SQLIdentifier `json:"tables,omitempty"`
}

func (selection TransferSelection) Validate() error {
	if !selection.Schema && !selection.Data || len(selection.Tables) > MaximumTransferTables { return ErrTransferInvalid }
	previous := ""
	for _, table := range selection.Tables {
		if table.IsZero() || table.String() <= previous { return ErrTransferInvalid }
		previous = table.String()
	}
	return nil
}

type TransferLimits struct {
	MaximumBytes    uint64        `json:"maximum_bytes"`
	MaximumRows     uint64        `json:"maximum_rows"`
	MaximumDuration time.Duration `json:"maximum_duration"`
}

func (limits TransferLimits) Validate() error {
	if limits.MaximumBytes < 1024 || limits.MaximumBytes > MaximumTransferBytes || limits.MaximumRows < 1 || limits.MaximumRows > MaximumTransferRows ||
		limits.MaximumDuration < time.Second || limits.MaximumDuration > MaximumTransferDuration { return ErrTransferInvalid }
	return nil
}

type TransferArtifactIdentity struct {
	StoreID    ResourceID `json:"store_id"`
	ArtifactID ResourceID `json:"artifact_id"`
	Generation uint64     `json:"generation"`
}

func (identity TransferArtifactIdentity) Validate() error {
	if identity.StoreID.IsZero() || identity.ArtifactID.IsZero() || identity.Generation == 0 { return ErrTransferInvalid }
	return nil
}

type TransferArtifactDescriptor struct {
	Identity    TransferArtifactIdentity `json:"identity"`
	Format      TransferFormat           `json:"format"`
	Compression TransferCompression      `json:"compression"`
	Bytes       uint64                   `json:"bytes"`
	Rows        uint64                   `json:"rows"`
	Digest      string                   `json:"digest"`
	CreatedAt   time.Time                `json:"created_at"`
	ExpiresAt   time.Time                `json:"expires_at"`
}

func (descriptor TransferArtifactDescriptor) Validate() error {
	if descriptor.Identity.Validate() != nil || descriptor.Format != TransferFormatSQL || !validTransferCompression(descriptor.Compression) || descriptor.Bytes == 0 || descriptor.Bytes > MaximumTransferBytes ||
		descriptor.Rows > MaximumTransferRows || !validSHA256(descriptor.Digest) || descriptor.CreatedAt.IsZero() || !descriptor.ExpiresAt.After(descriptor.CreatedAt) { return ErrTransferInvalid }
	return nil
}

type TransferRetention struct {
	RetainUntil       time.Time `json:"retain_until"`
	DeleteAfterSuccess bool     `json:"delete_after_success"`
	LegalHold         bool      `json:"legal_hold"`
}

func (retention TransferRetention) Validate(createdAt time.Time) error {
	if retention.RetainUntil.Before(createdAt) || retention.RetainUntil.After(createdAt.AddDate(10, 0, 0)) || retention.LegalHold && retention.DeleteAfterSuccess { return ErrTransferInvalid }
	return nil
}

type TransferImpactPreview struct {
	DatabaseID         ResourceID `json:"database_id"`
	DatabaseGeneration uint64     `json:"database_generation"`
	SchemaObjects      uint64     `json:"schema_objects"`
	Rows               uint64     `json:"rows"`
	Bytes              uint64     `json:"bytes"`
	EstimatedDowntime  time.Duration `json:"estimated_downtime"`
	CapturedAt         time.Time  `json:"captured_at"`
	Digest             string     `json:"digest"`
}

func (preview TransferImpactPreview) Validate() error {
	if preview.DatabaseID.IsZero() || preview.DatabaseGeneration == 0 || preview.Rows > MaximumTransferRows || preview.Bytes > MaximumTransferBytes || preview.EstimatedDowntime < 0 ||
		preview.EstimatedDowntime > MaximumTransferDuration || preview.CapturedAt.IsZero() || !validSHA256(preview.Digest) || transferImpactDigest(preview) != preview.Digest { return ErrTransferInvalid }
	return nil
}

func transferImpactDigest(preview TransferImpactPreview) string {
	preview.Digest = ""
	encoded, _ := json.Marshal(preview)
	return transferDigest(encoded)
}

func SealTransferImpactPreview(preview TransferImpactPreview) TransferImpactPreview {
	preview.Digest = transferImpactDigest(preview)
	return preview
}

type TransferJob struct {
	// Panel-export imports retain their source authority in the immutable job
	// document so a worker can reconstruct execution after process restart.
	ExportSource *TransferJob `json:"export_source,omitempty"`
	UploadSource *TransferUploadIntent `json:"upload_source,omitempty"`
	ID                  ResourceID                  `json:"id"`
	IdempotencyKey      string                      `json:"idempotency_key"`
	TenantID            site.TenantID               `json:"tenant_id"`
	SiteID              site.SiteID                 `json:"site_id"`
	DatabaseID          ResourceID                  `json:"database_id"`
	DatabaseGeneration  uint64                      `json:"database_generation"`
	InstanceID          ResourceID                  `json:"instance_id"`
	Direction           TransferDirection           `json:"direction"`
	Format              TransferFormat              `json:"format"`
	Compression         TransferCompression         `json:"compression"`
	Source              *TransferArtifactDescriptor `json:"source,omitempty"`
	Destination         *TransferArtifactIdentity   `json:"destination,omitempty"`
	Selection           TransferSelection           `json:"selection"`
	Limits              TransferLimits              `json:"limits"`
	ConflictPolicy      TransferConflictPolicy      `json:"conflict_policy"`
	Impact              TransferImpactPreview       `json:"impact"`
	RestorePointRef     ResourceID                  `json:"restore_point_ref,omitempty"`
	RestorePointDigest  string                      `json:"restore_point_digest,omitempty"`
	RestorePointCreatedAt time.Time                 `json:"restore_point_created_at,omitempty"`
	Retention           TransferRetention           `json:"retention"`
	CreatedBy           string                      `json:"created_by"`
	CreatedAt           time.Time                   `json:"created_at"`
	Digest              string                      `json:"digest"`
}

func (job TransferJob) Validate() error {
	if job.UploadSource!=nil && (job.Direction!=TransferImport || job.ExportSource!=nil || !validTransferUploadSource(job)) { return ErrTransferInvalid }
	if job.ExportSource!=nil && (job.Direction!=TransferImport || job.ExportSource.Direction!=TransferExport || job.ExportSource.ExportSource!=nil) { return ErrTransferInvalid }
	if job.ID.IsZero() || !validTransferIdentifier(job.IdempotencyKey) || job.TenantID.String() == "" || job.SiteID.String() == "" || job.DatabaseID.IsZero() || job.DatabaseGeneration == 0 ||
		job.InstanceID.IsZero() || job.Format != TransferFormatSQL || !validTransferCompression(job.Compression) || job.Selection.Validate() != nil || job.Limits.Validate() != nil ||
		job.Impact.Validate() != nil || job.Impact.DatabaseID != job.DatabaseID || job.Impact.DatabaseGeneration != job.DatabaseGeneration || job.Retention.Validate(job.CreatedAt) != nil ||
		!validTransferIdentifier(job.CreatedBy) || job.CreatedAt.IsZero() || !validSHA256(job.Digest) || transferJobDigest(job) != job.Digest { return ErrTransferInvalid }
	switch job.Direction {
	case TransferExport:
		if job.Source != nil || job.Destination == nil || job.Destination.Validate() != nil || job.ConflictPolicy != TransferConflictFail || !job.RestorePointRef.IsZero() || job.RestorePointDigest != "" || !job.RestorePointCreatedAt.IsZero() { return ErrTransferInvalid }
	case TransferImport:
		if job.Source == nil || job.Source.Validate() != nil || job.Destination != nil || job.Source.Format != job.Format || job.Source.Compression != job.Compression ||
			job.Source.Bytes > job.Limits.MaximumBytes || job.Source.Rows > job.Limits.MaximumRows || !job.Source.ExpiresAt.After(job.CreatedAt) { return ErrTransferInvalid }
		if job.ConflictPolicy != TransferConflictFail && job.ConflictPolicy != TransferConflictReplace { return ErrTransferInvalid }
		if job.ConflictPolicy == TransferConflictReplace && (job.RestorePointRef.IsZero() || !validSHA256(job.RestorePointDigest) || job.RestorePointCreatedAt.IsZero()) ||
			job.ConflictPolicy == TransferConflictFail && (!job.RestorePointRef.IsZero() || job.RestorePointDigest != "" || !job.RestorePointCreatedAt.IsZero()) { return ErrTransferInvalid }
		if job.ExportSource!=nil && !validTransferExportSource(job,*job.ExportSource) { return ErrTransferInvalid }
	default:
		return ErrTransferInvalid
	}
	if job.Impact.Bytes > job.Limits.MaximumBytes || job.Impact.Rows > job.Limits.MaximumRows { return ErrTransferLimit }
	return nil
}

func SealTransferJob(job TransferJob) (TransferJob, error) {
	job.Digest = transferJobDigest(job)
	if job.Validate() != nil { return TransferJob{}, ErrTransferInvalid }
	return job, nil
}

func transferJobDigest(job TransferJob) string {
	job.Digest = ""
	encoded, _ := json.Marshal(job)
	return transferDigest(encoded)
}

type TransferStatus string

const (
	TransferQueued     TransferStatus = "queued"
	TransferRunning    TransferStatus = "running"
	TransferVerifying  TransferStatus = "verifying"
	TransferPromoting  TransferStatus = "promoting"
	TransferCompleted  TransferStatus = "completed"
	TransferFailed     TransferStatus = "failed"
	TransferCancelled  TransferStatus = "cancelled"
	TransferAmbiguous  TransferStatus = "ambiguous"
)

type TransferPhase string

const (
	TransferPhaseQueued      TransferPhase = "queued"
	TransferPhaseStreaming   TransferPhase = "streaming"
	TransferPhaseVerifying   TransferPhase = "verifying"
	TransferPhasePromoting   TransferPhase = "promoting"
	TransferPhaseCleanup     TransferPhase = "cleanup"
	TransferPhaseTerminal    TransferPhase = "terminal"
)

type TransferResumeClass string

const (
	TransferResumeRestartIsolated TransferResumeClass = "restart_isolated"
	TransferResumeRestartArtifact TransferResumeClass = "restart_artifact"
	TransferResumeNotSafe         TransferResumeClass = "not_safe"
)

type TransferProgress struct {
	JobID          ResourceID    `json:"job_id"`
	Generation     uint64        `json:"generation"`
	Phase          TransferPhase `json:"phase"`
	BytesProcessed uint64        `json:"bytes_processed"`
	RowsProcessed  uint64        `json:"rows_processed"`
	TablesProcessed uint32       `json:"tables_processed"`
	SafePoint      bool          `json:"safe_point"`
	UpdatedAt      time.Time     `json:"updated_at"`
	Digest         string        `json:"digest"`
}

func (progress TransferProgress) Validate(job TransferJob) error {
	if progress.JobID != job.ID || progress.Generation == 0 || progress.BytesProcessed > job.Limits.MaximumBytes || progress.RowsProcessed > job.Limits.MaximumRows ||
		progress.TablesProcessed > MaximumTransferTables || !validTransferPhase(progress.Phase) || progress.UpdatedAt.IsZero() || !validSHA256(progress.Digest) || transferProgressDigest(progress) != progress.Digest { return ErrTransferInvalid }
	return nil
}

func SealTransferProgress(progress TransferProgress) TransferProgress {
	progress.Digest = transferProgressDigest(progress)
	return progress
}

func transferProgressDigest(progress TransferProgress) string {
	progress.Digest = ""
	encoded, _ := json.Marshal(progress)
	return transferDigest(encoded)
}

type TransferLease struct {
	JobID       ResourceID `json:"job_id"`
	WorkerID    string     `json:"worker_id"`
	Generation  uint64     `json:"generation"`
	Attempt     uint32     `json:"attempt"`
	FenceDigest string     `json:"fence_digest"`
	AcquiredAt  time.Time  `json:"acquired_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Duration    time.Duration `json:"duration"`
	FenceToken  string     `json:"-"`
}

func (lease TransferLease) Validate() error {
	if lease.JobID.IsZero() || !validTransferIdentifier(lease.WorkerID) || lease.Generation == 0 || lease.Attempt == 0 || !validSHA256(lease.FenceDigest) ||
		len(lease.FenceToken) != 64 || transferDigest([]byte(lease.FenceToken)) != lease.FenceDigest || lease.AcquiredAt.IsZero() || lease.Duration < time.Second || lease.Duration > 5*time.Minute ||
		lease.ExpiresAt != lease.AcquiredAt.Add(lease.Duration) { return ErrTransferInvalid }
	return nil
}

type TransferProcessReceipt struct {
	ExitCode         int                         `json:"exit_code"`
	Partial          bool                        `json:"partial"`
	BytesProcessed   uint64                      `json:"bytes_processed"`
	RowsProcessed    uint64                      `json:"rows_processed"`
	StderrDigest     string                      `json:"stderr_digest"`
	StderrBytes      uint32                      `json:"stderr_bytes"`
	StderrTruncated  bool                        `json:"stderr_truncated"`
	Artifact         *TransferArtifactDescriptor `json:"artifact,omitempty"`
	InputVerified    bool                        `json:"input_verified"`
	CompletedAt      time.Time                   `json:"completed_at"`
	Digest           string                      `json:"digest"`
}

func (receipt TransferProcessReceipt) Validate(job TransferJob) error {
	if receipt.ExitCode < -1 || receipt.BytesProcessed > job.Limits.MaximumBytes || receipt.RowsProcessed > job.Limits.MaximumRows || !validSHA256(receipt.StderrDigest) ||
		receipt.StderrBytes > MaximumTransferStderrBytes || receipt.CompletedAt.IsZero() || !validSHA256(receipt.Digest) || transferProcessDigest(receipt) != receipt.Digest { return ErrTransferInvalid }
	if job.Direction == TransferExport {
		if receipt.Artifact == nil && receipt.ExitCode == 0 && !receipt.Partial || receipt.Artifact != nil && receipt.Artifact.Validate() != nil || receipt.InputVerified { return ErrTransferInvalid }
	} else if receipt.Artifact != nil { return ErrTransferInvalid }
	return nil
}

func SealTransferProcessReceipt(receipt TransferProcessReceipt) TransferProcessReceipt {
	receipt.Digest = transferProcessDigest(receipt)
	return receipt
}

func transferProcessDigest(receipt TransferProcessReceipt) string {
	receipt.Digest = ""
	encoded, _ := json.Marshal(receipt)
	return transferDigest(encoded)
}

type TransferReceipt struct {
	JobID             ResourceID              `json:"job_id"`
	JobDigest         string                  `json:"job_digest"`
	Attempt           uint32                  `json:"attempt"`
	Generation        uint64                  `json:"generation"`
	Status            TransferStatus          `json:"status"`
	ResumeClass       TransferResumeClass     `json:"resume_class"`
	Process           *TransferProcessReceipt `json:"process,omitempty"`
	VerificationDigest string                 `json:"verification_digest,omitempty"`
	PromotionDigest   string                  `json:"promotion_digest,omitempty"`
	FailureCode       string                  `json:"failure_code,omitempty"`
	SourcePreserved   bool                    `json:"source_preserved"`
	MutationPossible  bool                    `json:"mutation_possible"`
	OccurredAt        time.Time               `json:"occurred_at"`
	Digest            string                  `json:"digest"`
}

func (receipt TransferReceipt) Validate(job TransferJob) error {
	if receipt.JobID != job.ID || receipt.JobDigest != job.Digest || receipt.Attempt == 0 || receipt.Generation == 0 || !validTransferStatus(receipt.Status) || !validResumeClass(receipt.ResumeClass) ||
		receipt.Process != nil && receipt.Process.Validate(job) != nil || receipt.VerificationDigest != "" && !validSHA256(receipt.VerificationDigest) || receipt.PromotionDigest != "" && !validSHA256(receipt.PromotionDigest) ||
		receipt.FailureCode != "" && !validTransferCode(receipt.FailureCode) || receipt.OccurredAt.IsZero() || !validSHA256(receipt.Digest) || transferReceiptDigest(receipt) != receipt.Digest { return ErrTransferInvalid }
	if receipt.Status == TransferAmbiguous && !receipt.MutationPossible { return ErrTransferInvalid }
	if receipt.Status == TransferCompleted {
		if receipt.Process == nil || receipt.Process.ExitCode != 0 || receipt.Process.Partial || !receipt.SourcePreserved { return ErrTransferInvalid }
		if job.Direction == TransferExport && receipt.Process.Artifact == nil { return ErrTransferInvalid }
		if job.Direction == TransferImport && (!receipt.Process.InputVerified || receipt.VerificationDigest == "" || receipt.PromotionDigest == "") { return ErrTransferInvalid }
	}
	if job.Direction == TransferImport && (receipt.Status == TransferFailed || receipt.Status == TransferCancelled) && !receipt.SourcePreserved { return ErrTransferInvalid }
	return nil
}

func SealTransferReceipt(receipt TransferReceipt) TransferReceipt {
	receipt.Digest = transferReceiptDigest(receipt)
	return receipt
}

func transferReceiptDigest(receipt TransferReceipt) string {
	receipt.Digest = ""
	encoded, _ := json.Marshal(receipt)
	return transferDigest(encoded)
}

func validTransferCompression(value TransferCompression) bool { return value == TransferCompressionNone || value == TransferCompressionGzip }

func validTransferPhase(value TransferPhase) bool {
	return value == TransferPhaseQueued || value == TransferPhaseStreaming || value == TransferPhaseVerifying || value == TransferPhasePromoting || value == TransferPhaseCleanup || value == TransferPhaseTerminal
}

func validTransferStatus(value TransferStatus) bool {
	return value == TransferQueued || value == TransferRunning || value == TransferVerifying || value == TransferPromoting || value == TransferCompleted || value == TransferFailed || value == TransferCancelled || value == TransferAmbiguous
}

func validResumeClass(value TransferResumeClass) bool {
	return value == TransferResumeRestartIsolated || value == TransferResumeRestartArtifact || value == TransferResumeNotSafe
}

func validTransferIdentifier(value string) bool {
	if value == "" || len(value) > 128 || !asciiAlphaNumeric(value[0]) || !asciiAlphaNumeric(value[len(value)-1]) { return false }
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' { continue }
		return false
	}
	return true
}

func validTransferCode(value string) bool {
	if value == "" || len(value) > 96 || value[0] < 'a' || value[0] > 'z' { return false }
	for _, character := range value { if character < 'a' || character > 'z' { if character < '0' || character > '9' { if character != '_' { return false } } } }
	return true
}

func transferDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func sortTransferTables(tables []SQLIdentifier) []SQLIdentifier {
	result := append([]SQLIdentifier(nil), tables...)
	sort.Slice(result, func(left, right int) bool { return result[left].String() < result[right].String() })
	return result
}

func redactedTransferProjection(job TransferJob) string {
	projection := struct {
		ID ResourceID `json:"id"`; DatabaseID ResourceID `json:"database_id"`; Direction TransferDirection `json:"direction"`; Format TransferFormat `json:"format"`
		Compression TransferCompression `json:"compression"`; Selection TransferSelection `json:"selection"`; Limits TransferLimits `json:"limits"`; Conflict TransferConflictPolicy `json:"conflict"`
	}{job.ID, job.DatabaseID, job.Direction, job.Format, job.Compression, job.Selection, job.Limits, job.ConflictPolicy}
	encoded, _ := json.Marshal(projection)
	return transferDigest(encoded)
}
