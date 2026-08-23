package logworkspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sync"
	"time"
)

const (
	createSchema = `CREATE TABLE IF NOT EXISTS log_workspace_schema_v1 (
singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL CHECK (version = 1))`
	insertSchema = `INSERT OR IGNORE INTO log_workspace_schema_v1(singleton, version) VALUES (1, 1)`
	createSourceMetadata = `CREATE TABLE IF NOT EXISTS log_source_metadata_v1 (
source_id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK (revision > 0), generation INTEGER NOT NULL CHECK (generation > 0),
metadata_json BLOB NOT NULL, updated_at TEXT NOT NULL)`
	createSourceOrder = `CREATE INDEX IF NOT EXISTS log_source_metadata_order_v1 ON log_source_metadata_v1(source_id)`
	createExportJobs = `CREATE TABLE IF NOT EXISTS log_export_jobs_v1 (
tenant_id TEXT NOT NULL, job_id TEXT NOT NULL, source_id TEXT NOT NULL, source_generation INTEGER NOT NULL CHECK (source_generation > 0),
state TEXT NOT NULL, revision INTEGER NOT NULL CHECK (revision > 0), job_json BLOB NOT NULL, updated_at TEXT NOT NULL,
PRIMARY KEY (tenant_id, job_id))`
	createExportOrder = `CREATE INDEX IF NOT EXISTS log_export_jobs_order_v1 ON log_export_jobs_v1(tenant_id, job_id)`
	createReceipts = `CREATE TABLE IF NOT EXISTS log_lifecycle_receipts_v1 (
receipt_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, source_id TEXT NOT NULL, before_generation INTEGER NOT NULL,
status TEXT NOT NULL, receipt_json BLOB NOT NULL, completed_at TEXT NOT NULL)`
	repositoryTimeLayout      = "2006-01-02T15:04:05.000000000Z"
	maximumExportEntryOverhead = 64 << 10
)

type SourceMetadata struct {
	SourceID   SourceID    `json:"source_id"`
	Backend    BackendKind `json:"backend"`
	Generation uint64      `json:"generation"`
	Device     uint64      `json:"device,omitempty"`
	Inode      uint64      `json:"inode,omitempty"`
	Revision   uint64      `json:"revision"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

func (metadata SourceMetadata) valid() bool {
	if !opaquePattern.MatchString(string(metadata.SourceID)) || metadata.Generation == 0 || metadata.Generation > MaximumGeneration || metadata.Revision == 0 || metadata.Revision > uint64(math.MaxInt64) || metadata.UpdatedAt.IsZero() {
		return false
	}
	if metadata.Backend == BackendJournal {
		return metadata.Device == 0 && metadata.Inode == 0
	}
	return metadata.Backend == BackendFile && metadata.Device != 0 && metadata.Inode != 0
}

type SourceMetadataPage struct {
	Items  []SourceMetadata
	NextID SourceID
}

type ExportState string

const (
	ExportQueued    ExportState = "queued"
	ExportRunning   ExportState = "running"
	ExportSucceeded ExportState = "succeeded"
	ExportFailed    ExportState = "failed"
)

type ExportJob struct {
	TenantID        string      `json:"tenant_id"`
	ID              string      `json:"id"`
	SourceID        SourceID    `json:"source_id"`
	SourceGeneration uint64     `json:"source_generation"`
	Query           Query       `json:"query"`
	State           ExportState `json:"state"`
	Attempts        uint8       `json:"attempts"`
	ArtifactID      string      `json:"artifact_id,omitempty"`
	FailureCode     string      `json:"failure_code,omitempty"`
	Revision        uint64      `json:"revision"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

func (job ExportJob) valid() bool {
	if !opaquePattern.MatchString(job.TenantID) || !opaquePattern.MatchString(job.ID) || !opaquePattern.MatchString(string(job.SourceID)) || job.SourceGeneration == 0 || job.SourceGeneration > MaximumGeneration || job.Query.SourceID != job.SourceID || job.Query.Validate() != nil || job.Attempts > 10 || job.Revision == 0 || job.Revision > uint64(math.MaxInt64) || job.CreatedAt.IsZero() || job.UpdatedAt.Before(job.CreatedAt) {
		return false
	}
	switch job.State {
	case ExportQueued, ExportRunning:
		return job.ArtifactID == "" && job.FailureCode == ""
	case ExportSucceeded:
		return opaquePattern.MatchString(job.ArtifactID) && job.FailureCode == ""
	case ExportFailed:
		return job.ArtifactID == "" && opaquePattern.MatchString(job.FailureCode)
	default:
		return false
	}
}

func validExportTransition(previous, next ExportJob) bool {
	if previous.TenantID != next.TenantID || previous.ID != next.ID || previous.SourceID != next.SourceID || previous.SourceGeneration != next.SourceGeneration || previous.Query != next.Query || previous.CreatedAt != next.CreatedAt {
		return false
	}
	switch previous.State {
	case ExportQueued:
		return next.State == ExportRunning && next.Attempts == previous.Attempts+1 || next.State == ExportFailed && next.Attempts == previous.Attempts
	case ExportRunning:
		return (next.State == ExportSucceeded || next.State == ExportFailed) && next.Attempts == previous.Attempts
	case ExportFailed:
		return next.State == ExportQueued && next.Attempts == previous.Attempts
	default:
		return false
	}
}

type ExportJobPage struct {
	Jobs   []ExportJob
	NextID string
}

type SQLiteRepository struct {
	db     *sql.DB
	now    func() time.Time
	writer sync.Mutex
}

func NewSQLiteRepository(db *sql.DB) (*SQLiteRepository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &SQLiteRepository{db: db, now: time.Now}, nil
}

func (repository *SQLiteRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil || ctx == nil {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	transaction, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	for _, statement := range []string{createSchema, insertSchema, createSourceMetadata, createSourceOrder, createExportJobs, createExportOrder, createReceipts} {
		if _, err = transaction.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	var version uint8
	if err = transaction.QueryRowContext(ctx, `SELECT version FROM log_workspace_schema_v1 WHERE singleton = 1`).Scan(&version); err != nil || version != 1 {
		return errors.Join(ErrIntegrity, err)
	}
	return transaction.Commit()
}

func repositoryTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(repositoryTimeLayout)
}

func encodeRepositoryValue(value any, maximum int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maximum {
		return nil, ErrLimit
	}
	return encoded, nil
}

func decodeRepositoryValue(encoded []byte, maximum int, target any) error {
	if len(encoded) == 0 || len(encoded) > maximum {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrIntegrity
	}
	return nil
}

type rowScanner interface {
	Scan(...any) error
}

func changedExactlyOne(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func scanSourceMetadata(row rowScanner, sourceID SourceID) (SourceMetadata, error) {
	var revision, generation uint64
	var encoded []byte
	var updatedRaw string
	if err := row.Scan(&revision, &generation, &encoded, &updatedRaw); err != nil {
		return SourceMetadata{}, err
	}
	var metadata SourceMetadata
	if decodeRepositoryValue(encoded, MaximumSourceJSONBytes, &metadata) != nil || metadata.SourceID != sourceID || metadata.Revision != revision || metadata.Generation != generation || repositoryTime(metadata.UpdatedAt) != updatedRaw || !metadata.valid() {
		return SourceMetadata{}, ErrIntegrity
	}
	return metadata, nil
}

func (repository *SQLiteRepository) GetSourceMetadata(ctx context.Context, sourceID SourceID) (SourceMetadata, error) {
	if repository == nil || repository.db == nil || ctx == nil || !opaquePattern.MatchString(string(sourceID)) {
		return SourceMetadata{}, ErrInvalid
	}
	metadata, err := scanSourceMetadata(repository.db.QueryRowContext(ctx, `SELECT revision, generation, metadata_json, updated_at FROM log_source_metadata_v1 WHERE source_id = ?`, sourceID), sourceID)
	if errors.Is(err, sql.ErrNoRows) {
		return SourceMetadata{}, ErrNotFound
	}
	return metadata, err
}

func (repository *SQLiteRepository) ListSourceMetadata(ctx context.Context, after SourceID, limit uint16) (SourceMetadataPage, error) {
	if repository == nil || repository.db == nil || ctx == nil || limit == 0 || limit > MaximumPageSize || after != "" && !opaquePattern.MatchString(string(after)) {
		return SourceMetadataPage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT source_id, revision, generation, metadata_json, updated_at FROM log_source_metadata_v1 WHERE source_id > ? ORDER BY source_id ASC LIMIT ?`, after, int(limit)+1)
	if err != nil {
		return SourceMetadataPage{}, err
	}
	defer rows.Close()
	page := SourceMetadataPage{Items: make([]SourceMetadata, 0, limit)}
	for rows.Next() {
		var sourceID SourceID
		var revision, generation uint64
		var encoded []byte
		var updatedRaw string
		if err = rows.Scan(&sourceID, &revision, &generation, &encoded, &updatedRaw); err != nil {
			return SourceMetadataPage{}, err
		}
		if len(page.Items) == int(limit) {
			page.NextID = page.Items[len(page.Items)-1].SourceID
			return page, rows.Close()
		}
		var metadata SourceMetadata
		if decodeRepositoryValue(encoded, MaximumSourceJSONBytes, &metadata) != nil || metadata.SourceID != sourceID || metadata.Revision != revision || metadata.Generation != generation || repositoryTime(metadata.UpdatedAt) != updatedRaw || !metadata.valid() {
			return SourceMetadataPage{}, ErrIntegrity
		}
		page.Items = append(page.Items, metadata)
	}
	return page, rows.Err()
}

func (repository *SQLiteRepository) UpsertSourceMetadata(ctx context.Context, metadata SourceMetadata, expectedRevision uint64) (SourceMetadata, error) {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision >= uint64(math.MaxInt64) || !opaquePattern.MatchString(string(metadata.SourceID)) || metadata.Generation == 0 || metadata.Backend != BackendJournal && metadata.Backend != BackendFile {
		return SourceMetadata{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	metadata.Revision = expectedRevision + 1
	metadata.UpdatedAt = repository.now().UTC()
	if !metadata.valid() {
		return SourceMetadata{}, ErrInvalid
	}
	encoded, err := encodeRepositoryValue(metadata, MaximumSourceJSONBytes)
	if err != nil {
		return SourceMetadata{}, err
	}
	if expectedRevision == 0 {
		result, insertErr := repository.db.ExecContext(ctx, `INSERT INTO log_source_metadata_v1(source_id, revision, generation, metadata_json, updated_at)
SELECT ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM log_source_metadata_v1) < ?`, metadata.SourceID, metadata.Revision, metadata.Generation, encoded, repositoryTime(metadata.UpdatedAt), MaximumSources)
		if insertErr != nil {
			if _, getErr := repository.GetSourceMetadata(ctx, metadata.SourceID); getErr == nil {
				return SourceMetadata{}, ErrConflict
			}
			return SourceMetadata{}, insertErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return SourceMetadata{}, rowsErr
		}
		if rows == 0 {
			return SourceMetadata{}, ErrLimit
		}
		return metadata, nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE log_source_metadata_v1 SET revision = ?, generation = ?, metadata_json = ?, updated_at = ? WHERE source_id = ? AND revision = ?`, metadata.Revision, metadata.Generation, encoded, repositoryTime(metadata.UpdatedAt), metadata.SourceID, expectedRevision)
	if err != nil {
		return SourceMetadata{}, err
	}
	if err = changedExactlyOne(result); err != nil {
		return SourceMetadata{}, err
	}
	return metadata, nil
}

func (repository *SQLiteRepository) DeleteSourceMetadata(ctx context.Context, sourceID SourceID, expectedRevision uint64) error {
	if repository == nil || repository.db == nil || ctx == nil || !opaquePattern.MatchString(string(sourceID)) || expectedRevision == 0 || expectedRevision > uint64(math.MaxInt64) {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.db.ExecContext(ctx, `DELETE FROM log_source_metadata_v1 WHERE source_id = ? AND revision = ?`, sourceID, expectedRevision)
	if err != nil {
		return err
	}
	return changedExactlyOne(result)
}

func scanExportJob(row rowScanner, tenantID, jobID string) (ExportJob, error) {
	var sourceID SourceID
	var generation, revision uint64
	var state ExportState
	var encoded []byte
	var updatedRaw string
	if err := row.Scan(&sourceID, &generation, &state, &revision, &encoded, &updatedRaw); err != nil {
		return ExportJob{}, err
	}
	var job ExportJob
	if decodeRepositoryValue(encoded, MaximumExportJSONBytes, &job) != nil || job.TenantID != tenantID || job.ID != jobID || job.SourceID != sourceID || job.SourceGeneration != generation || job.State != state || job.Revision != revision || repositoryTime(job.UpdatedAt) != updatedRaw || !job.valid() {
		return ExportJob{}, ErrIntegrity
	}
	return job, nil
}

func (repository *SQLiteRepository) GetExportJob(ctx context.Context, tenantID, jobID string) (ExportJob, error) {
	if repository == nil || repository.db == nil || ctx == nil || !opaquePattern.MatchString(tenantID) || !opaquePattern.MatchString(jobID) {
		return ExportJob{}, ErrInvalid
	}
	job, err := scanExportJob(repository.db.QueryRowContext(ctx, `SELECT source_id, source_generation, state, revision, job_json, updated_at FROM log_export_jobs_v1 WHERE tenant_id = ? AND job_id = ?`, tenantID, jobID), tenantID, jobID)
	if errors.Is(err, sql.ErrNoRows) {
		return ExportJob{}, ErrNotFound
	}
	return job, err
}

func (repository *SQLiteRepository) ListExportJobs(ctx context.Context, tenantID, after string, limit uint16) (ExportJobPage, error) {
	if repository == nil || repository.db == nil || ctx == nil || !opaquePattern.MatchString(tenantID) || limit == 0 || limit > MaximumPageSize || after != "" && !opaquePattern.MatchString(after) {
		return ExportJobPage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT job_id, source_id, source_generation, state, revision, job_json, updated_at FROM log_export_jobs_v1 WHERE tenant_id = ? AND job_id > ? ORDER BY job_id ASC LIMIT ?`, tenantID, after, int(limit)+1)
	if err != nil {
		return ExportJobPage{}, err
	}
	defer rows.Close()
	page := ExportJobPage{Jobs: make([]ExportJob, 0, limit)}
	for rows.Next() {
		var jobID string
		var sourceID SourceID
		var generation, revision uint64
		var state ExportState
		var encoded []byte
		var updatedRaw string
		if err = rows.Scan(&jobID, &sourceID, &generation, &state, &revision, &encoded, &updatedRaw); err != nil {
			return ExportJobPage{}, err
		}
		if len(page.Jobs) == int(limit) {
			page.NextID = page.Jobs[len(page.Jobs)-1].ID
			return page, rows.Close()
		}
		var job ExportJob
		if decodeRepositoryValue(encoded, MaximumExportJSONBytes, &job) != nil || job.TenantID != tenantID || job.ID != jobID || job.SourceID != sourceID || job.SourceGeneration != generation || job.State != state || job.Revision != revision || repositoryTime(job.UpdatedAt) != updatedRaw || !job.valid() {
			return ExportJobPage{}, ErrIntegrity
		}
		page.Jobs = append(page.Jobs, job)
	}
	return page, rows.Err()
}

func (repository *SQLiteRepository) UpsertExportJob(ctx context.Context, job ExportJob, expectedRevision uint64) (ExportJob, error) {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision >= uint64(math.MaxInt64) || !opaquePattern.MatchString(job.TenantID) || !opaquePattern.MatchString(job.ID) || job.Attempts > 10 {
		return ExportJob{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	now := repository.now().UTC()
	if expectedRevision == 0 {
		if job.State != ExportQueued || job.Attempts != 0 || !job.CreatedAt.IsZero() && job.CreatedAt.After(now) {
			return ExportJob{}, ErrInvalid
		}
		if job.CreatedAt.IsZero() {
			job.CreatedAt = now
		}
	} else {
		previous, err := repository.GetExportJob(ctx, job.TenantID, job.ID)
		if err != nil {
			return ExportJob{}, err
		}
		if previous.Revision != expectedRevision || !validExportTransition(previous, job) {
			return ExportJob{}, ErrConflict
		}
	}
	job.Revision = expectedRevision + 1
	job.UpdatedAt = now
	if !job.valid() {
		return ExportJob{}, ErrInvalid
	}
	encoded, err := encodeRepositoryValue(job, MaximumExportJSONBytes)
	if err != nil {
		return ExportJob{}, err
	}
	if expectedRevision == 0 {
		result, insertErr := repository.db.ExecContext(ctx, `INSERT INTO log_export_jobs_v1(tenant_id, job_id, source_id, source_generation, state, revision, job_json, updated_at)
SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM log_export_jobs_v1 WHERE tenant_id = ?) < ?`, job.TenantID, job.ID, job.SourceID, job.SourceGeneration, job.State, job.Revision, encoded, repositoryTime(job.UpdatedAt), job.TenantID, MaximumExportsPerTenant)
		if insertErr != nil {
			if _, getErr := repository.GetExportJob(ctx, job.TenantID, job.ID); getErr == nil {
				return ExportJob{}, ErrConflict
			}
			return ExportJob{}, insertErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return ExportJob{}, rowsErr
		}
		if rows == 0 {
			return ExportJob{}, ErrLimit
		}
		return job, nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE log_export_jobs_v1 SET state = ?, revision = ?, job_json = ?, updated_at = ? WHERE tenant_id = ? AND job_id = ? AND revision = ?`, job.State, job.Revision, encoded, repositoryTime(job.UpdatedAt), job.TenantID, job.ID, expectedRevision)
	if err != nil {
		return ExportJob{}, err
	}
	if err = changedExactlyOne(result); err != nil {
		return ExportJob{}, err
	}
	return job, nil
}

func (repository *SQLiteRepository) DeleteExportJob(ctx context.Context, tenantID, jobID string, expectedRevision uint64) error {
	if repository == nil || repository.db == nil || ctx == nil || !opaquePattern.MatchString(tenantID) || !opaquePattern.MatchString(jobID) || expectedRevision == 0 || expectedRevision > uint64(math.MaxInt64) {
		return ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	result, err := repository.db.ExecContext(ctx, `DELETE FROM log_export_jobs_v1 WHERE tenant_id = ? AND job_id = ? AND revision = ? AND state IN ('succeeded','failed')`, tenantID, jobID, expectedRevision)
	if err != nil {
		return err
	}
	return changedExactlyOne(result)
}

func (repository *SQLiteRepository) InsertLifecycleReceipt(ctx context.Context, receipt LifecycleReceipt) error {
	if repository == nil || repository.db == nil || ctx == nil || !receipt.valid() {
		return ErrInvalid
	}
	encoded, err := encodeRepositoryValue(receipt, MaximumReceiptJSONBytes)
	if err != nil {
		return err
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	_, err = repository.db.ExecContext(ctx, `INSERT INTO log_lifecycle_receipts_v1(receipt_id, plan_id, source_id, before_generation, status, receipt_json, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, receipt.ID, receipt.PlanID, receipt.SourceID, receipt.BeforeGeneration, receipt.Status, encoded, repositoryTime(receipt.CompletedAt))
	if err != nil {
		if _, getErr := repository.GetLifecycleReceipt(ctx, receipt.ID); getErr == nil {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (repository *SQLiteRepository) GetLifecycleReceipt(ctx context.Context, receiptID string) (LifecycleReceipt, error) {
	if repository == nil || repository.db == nil || ctx == nil || !opaquePattern.MatchString(receiptID) {
		return LifecycleReceipt{}, ErrInvalid
	}
	var planID string
	var sourceID SourceID
	var beforeGeneration uint64
	var status ReceiptStatus
	var encoded []byte
	var completedRaw string
	err := repository.db.QueryRowContext(ctx, `SELECT plan_id, source_id, before_generation, status, receipt_json, completed_at FROM log_lifecycle_receipts_v1 WHERE receipt_id = ?`, receiptID).Scan(&planID, &sourceID, &beforeGeneration, &status, &encoded, &completedRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return LifecycleReceipt{}, ErrNotFound
	}
	if err != nil {
		return LifecycleReceipt{}, err
	}
	var receipt LifecycleReceipt
	if decodeRepositoryValue(encoded, MaximumReceiptJSONBytes, &receipt) != nil || receipt.ID != receiptID || receipt.PlanID != planID || receipt.SourceID != sourceID || receipt.BeforeGeneration != beforeGeneration || receipt.Status != status || repositoryTime(receipt.CompletedAt) != completedRaw || !receipt.valid() {
		return LifecycleReceipt{}, ErrIntegrity
	}
	return receipt, nil
}

type ArtifactWriter interface {
	WriteLogChunk(context.Context, []byte) error
	CommitLogArtifact(context.Context, ExportManifest) (ArtifactReceipt, error)
	AbortLogArtifact(context.Context) error
}

type ArtifactSink interface {
	BeginLogArtifact(context.Context, ExportJob) (ArtifactWriter, error)
}

type ExportManifest struct {
	Schema       string    `json:"schema"`
	TenantID     string    `json:"tenant_id"`
	JobID        string    `json:"job_id"`
	SourceID     SourceID  `json:"source_id"`
	Generation   uint64    `json:"generation"`
	Lines        uint32    `json:"lines"`
	Bytes        int64     `json:"bytes"`
	Conditions   uint32    `json:"conditions"`
	ContentDigest string   `json:"content_digest"`
	CreatedAt    time.Time `json:"created_at"`
}

type ArtifactReceipt struct {
	ArtifactID    string
	ContentDigest string
	Bytes         int64
}

type exportRecordSink struct {
	writer     ArtifactWriter
	hash       hashWriter
	bytes      int64
	conditions uint32
	summary    ProjectionSummary
}

type hashWriter struct {
	state interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
}

func newHashWriter() hashWriter {
	return hashWriter{state: sha256.New()}
}

func (sink *exportRecordSink) writeCanonical(ctx context.Context, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaximumRecordBytes+maximumExportEntryOverhead {
		return ErrLimit
	}
	encoded = append(encoded, '\n')
	if sink.bytes+int64(len(encoded)) > MaximumBytes {
		return ErrLimit
	}
	if err = sink.writer.WriteLogChunk(ctx, encoded); err != nil {
		return err
	}
	if _, err = sink.hash.state.Write(encoded); err != nil {
		return err
	}
	sink.bytes += int64(len(encoded))
	return nil
}

func (sink *exportRecordSink) WriteRecord(ctx context.Context, record LogRecord) error {
	entry := struct {
		Kind       string    `json:"kind"`
		SourceID   SourceID  `json:"source_id"`
		Generation uint64    `json:"generation"`
		Sequence   uint64    `json:"sequence"`
		Offset     int64     `json:"offset"`
		ObservedAt time.Time `json:"observed_at"`
		Text       string    `json:"text"`
		Redacted   bool      `json:"redacted"`
	}{"record", record.SourceID, record.Generation, record.Sequence, record.Offset, record.ObservedAt, string(record.Text), record.Redacted}
	return sink.writeCanonical(ctx, entry)
}

func (sink *exportRecordSink) WriteCondition(ctx context.Context, condition StreamCondition) error {
	sink.conditions++
	entry := struct {
		Kind       string        `json:"kind"`
		Code       ConditionCode `json:"code"`
		SourceID   SourceID      `json:"source_id"`
		Generation uint64        `json:"generation"`
		At         time.Time     `json:"at"`
	}{"condition", condition.Code, condition.SourceID, condition.Generation, condition.At}
	return sink.writeCanonical(ctx, entry)
}

func (sink *exportRecordSink) Close(_ context.Context, summary ProjectionSummary) error {
	sink.summary = summary
	return nil
}

func (sink *exportRecordSink) digest() string {
	return hex.EncodeToString(sink.hash.state.Sum(nil))
}

type ExportService struct {
	reader     Reader
	repository *SQLiteRepository
	artifacts  ArtifactSink
	now        func() time.Time
}

func NewExportService(reader Reader, repository *SQLiteRepository, artifacts ArtifactSink) (*ExportService, error) {
	if reader == nil || repository == nil || artifacts == nil {
		return nil, ErrInvalid
	}
	return &ExportService{reader: reader, repository: repository, artifacts: artifacts, now: time.Now}, nil
}

func (service *ExportService) failJob(ctx context.Context, job ExportJob, failureCode string) error {
	job.State = ExportFailed
	job.ArtifactID = ""
	job.FailureCode = failureCode
	_, err := service.repository.UpsertExportJob(ctx, job, job.Revision)
	return err
}

func (service *ExportService) Run(ctx context.Context, actor Actor, tenantID, jobID string, expectedRevision uint64) (ArtifactReceipt, error) {
	if service == nil || ctx == nil || !actor.valid() || actor.TenantID != tenantID || expectedRevision == 0 {
		return ArtifactReceipt{}, ErrInvalid
	}
	job, err := service.repository.GetExportJob(ctx, tenantID, jobID)
	if err != nil {
		return ArtifactReceipt{}, err
	}
	if job.Revision != expectedRevision || job.State != ExportQueued || job.Attempts == 10 {
		return ArtifactReceipt{}, ErrConflict
	}
	job.State = ExportRunning
	job.Attempts++
	job, err = service.repository.UpsertExportJob(ctx, job, expectedRevision)
	if err != nil {
		return ArtifactReceipt{}, err
	}
	writer, err := service.artifacts.BeginLogArtifact(ctx, job)
	if err != nil {
		return ArtifactReceipt{}, errors.Join(err, service.failJob(ctx, job, "artifact_unavailable"))
	}
	recordSink := &exportRecordSink{writer: writer, hash: newHashWriter()}
	summary, streamErr := service.reader.Stream(ctx, actor, job.Query, recordSink)
	if streamErr != nil {
		abortErr := writer.AbortLogArtifact(ctx)
		failErr := service.failJob(ctx, job, "stream_failed")
		return ArtifactReceipt{}, errors.Join(streamErr, abortErr, failErr)
	}
	if summary.SourceID != job.SourceID || summary.Generation != job.SourceGeneration || recordSink.summary != summary {
		abortErr := writer.AbortLogArtifact(ctx)
		failErr := service.failJob(ctx, job, "source_generation_changed")
		return ArtifactReceipt{}, errors.Join(ErrConflict, abortErr, failErr)
	}
	manifest := ExportManifest{
		Schema: "cyberpanel.log-export.v1", TenantID: tenantID, JobID: job.ID, SourceID: job.SourceID,
		Generation: job.SourceGeneration, Lines: summary.Lines, Bytes: recordSink.bytes,
		Conditions: recordSink.conditions, ContentDigest: recordSink.digest(), CreatedAt: service.now().UTC(),
	}
	receipt, err := writer.CommitLogArtifact(ctx, manifest)
	if err != nil || !opaquePattern.MatchString(receipt.ArtifactID) || receipt.ContentDigest != manifest.ContentDigest || receipt.Bytes != manifest.Bytes {
		abortErr := writer.AbortLogArtifact(ctx)
		failErr := service.failJob(ctx, job, "artifact_commit_failed")
		if err == nil {
			err = ErrIntegrity
		}
		return ArtifactReceipt{}, errors.Join(err, abortErr, failErr)
	}
	job.State = ExportSucceeded
	job.ArtifactID = receipt.ArtifactID
	job.FailureCode = ""
	if _, err = service.repository.UpsertExportJob(ctx, job, job.Revision); err != nil {
		return ArtifactReceipt{}, err
	}
	return receipt, nil
}
