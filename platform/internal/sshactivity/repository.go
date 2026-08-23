package sshactivity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	createSchema = `CREATE TABLE IF NOT EXISTS ssh_activity_schema_v1 (
singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL CHECK (version = 1))`
	insertSchema = `INSERT OR IGNORE INTO ssh_activity_schema_v1(singleton, version) VALUES (1, 1)`
	createMetadata = `CREATE TABLE IF NOT EXISTS ssh_observation_metadata_v1 (
source_id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK (revision > 0), boot_id TEXT NOT NULL,
metadata_json BLOB NOT NULL, updated_at TEXT NOT NULL)`
	createRisk = `CREATE TABLE IF NOT EXISTS ssh_risk_snapshots_v1 (
risk_id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK (revision > 0), window_start TEXT NOT NULL, window_end TEXT NOT NULL,
snapshot_json BLOB NOT NULL, updated_at TEXT NOT NULL)`
	createRiskOrder = `CREATE INDEX IF NOT EXISTS ssh_risk_snapshots_order_v1 ON ssh_risk_snapshots_v1(window_start, risk_id)`
	createPlans = `CREATE TABLE IF NOT EXISTS ssh_response_plans_v1 (
plan_id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK (revision > 0), status TEXT NOT NULL, body_digest TEXT NOT NULL,
plan_json BLOB NOT NULL, updated_at TEXT NOT NULL)`
	createPlanOrder = `CREATE INDEX IF NOT EXISTS ssh_response_plans_order_v1 ON ssh_response_plans_v1(status, plan_id)`
	createReceipts = `CREATE TABLE IF NOT EXISTS ssh_response_receipts_v1 (
plan_id TEXT PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_json BLOB NOT NULL, completed_at TEXT NOT NULL)`
	repositoryTimeLayout = "2006-01-02T15:04:05.000000000Z"
	MaximumRiskSnapshots = 2_048
	MaximumResponsePlans = 1_024
	MaximumMetadataSources = 16
)

type ObservationMetadata struct {
	SourceID            SourceID     `json:"source_id"`
	Boot                BootIdentity `json:"boot"`
	Cursor              string       `json:"cursor,omitempty"`
	LastObservedAt      time.Time    `json:"last_observed_at"`
	EvidenceChainDigest string       `json:"evidence_chain_digest"`
	GapCount            uint64       `json:"gap_count"`
	Revision            uint64       `json:"revision"`
	UpdatedAt           time.Time    `json:"updated_at"`
}

func (metadata ObservationMetadata) valid() bool {
	return validOpaque(string(metadata.SourceID)) && metadata.Boot.valid() && len(metadata.Cursor) <= MaximumCursorBytes && !metadata.LastObservedAt.IsZero() && validDigest(metadata.EvidenceChainDigest) &&
		metadata.Revision > 0 && metadata.Revision <= MaximumRevision && !metadata.UpdatedAt.Before(metadata.LastObservedAt)
}

type MetadataPage struct {
	Items  []ObservationMetadata
	NextID SourceID
}

type RiskSnapshot struct {
	ID          string         `json:"id"`
	WindowStart time.Time      `json:"window_start"`
	WindowEnd   time.Time      `json:"window_end"`
	Result      AnalysisResult `json:"result"`
	Revision    uint64         `json:"revision"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

func analysisResultValid(result AnalysisResult) bool {
	if result.Attribution != AttributionUndetermined || !validDigest(result.Digest) || len(result.Findings) > MaximumRiskFindings || len(result.Sources) > MaximumRiskFindings || len(result.Gaps) > MaximumRepositoryPage {
		return false
	}
	for _, finding := range result.Findings {
		if !finding.valid() {
			return false
		}
	}
	for _, source := range result.Sources {
		if !source.Source.IsValid() || source.Successes+source.Failures == 0 || source.DistinctUsers == 0 || source.FirstAt.IsZero() || source.LastAt.Before(source.FirstAt) {
			return false
		}
	}
	for _, gap := range result.Gaps {
		if !gap.valid() {
			return false
		}
	}
	encoded, err := json.Marshal(struct {
		Findings []RiskFinding `json:"findings"`
		Sources  []SourceAggregate `json:"sources"`
		Gaps     []ObservationGap `json:"gaps"`
	}{result.Findings, result.Sources, result.Gaps})
	if err != nil || len(encoded) > MaximumRiskJSON {
		return false
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]) == result.Digest
}

func (snapshot RiskSnapshot) valid() bool {
	return validOpaque(snapshot.ID) && !snapshot.WindowStart.IsZero() && snapshot.WindowEnd.After(snapshot.WindowStart) && snapshot.WindowEnd.Sub(snapshot.WindowStart) <= MaximumQueryWindow &&
		analysisResultValid(snapshot.Result) && snapshot.Revision > 0 && snapshot.Revision <= MaximumRevision && !snapshot.CreatedAt.IsZero() && !snapshot.UpdatedAt.Before(snapshot.CreatedAt)
}

type RiskPage struct {
	Items  []RiskSnapshot
	NextID string
}

type PlanPage struct {
	Items  []ResponsePlan
	NextID PlanID
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
	for _, statement := range []string{createSchema, insertSchema, createMetadata, createRisk, createRiskOrder, createPlans, createPlanOrder, createReceipts} {
		if _, err = transaction.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	var version uint8
	if err = transaction.QueryRowContext(ctx, `SELECT version FROM ssh_activity_schema_v1 WHERE singleton = 1`).Scan(&version); err != nil || version != 1 {
		return errors.Join(ErrIntegrity, err)
	}
	return transaction.Commit()
}

func storedTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(repositoryTimeLayout)
}

func encodeStored(value any, maximum int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maximum {
		return nil, ErrLimit
	}
	return encoded, nil
}

func decodeStored(encoded []byte, maximum int, target any) error {
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

type rowScanner interface { Scan(...any) error }

func changedOne(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func scanMetadata(row rowScanner, sourceID SourceID) (ObservationMetadata, error) {
	var revision uint64
	var bootID string
	var encoded []byte
	var updatedRaw string
	if err := row.Scan(&revision, &bootID, &encoded, &updatedRaw); err != nil {
		return ObservationMetadata{}, err
	}
	var metadata ObservationMetadata
	if decodeStored(encoded, MaximumMetadataJSON, &metadata) != nil || metadata.SourceID != sourceID || metadata.Revision != revision || metadata.Boot.BootID != bootID || storedTime(metadata.UpdatedAt) != updatedRaw || !metadata.valid() {
		return ObservationMetadata{}, ErrIntegrity
	}
	return metadata, nil
}

func (repository *SQLiteRepository) GetObservationMetadata(ctx context.Context, sourceID SourceID) (ObservationMetadata, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validOpaque(string(sourceID)) {
		return ObservationMetadata{}, ErrInvalid
	}
	metadata, err := scanMetadata(repository.db.QueryRowContext(ctx, `SELECT revision, boot_id, metadata_json, updated_at FROM ssh_observation_metadata_v1 WHERE source_id = ?`, sourceID), sourceID)
	if errors.Is(err, sql.ErrNoRows) {
		return ObservationMetadata{}, ErrNotFound
	}
	return metadata, err
}

func (repository *SQLiteRepository) ListObservationMetadata(ctx context.Context, after SourceID, limit uint16) (MetadataPage, error) {
	if repository == nil || repository.db == nil || ctx == nil || limit == 0 || limit > MaximumRepositoryPage || after != "" && !validOpaque(string(after)) {
		return MetadataPage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT source_id, revision, boot_id, metadata_json, updated_at FROM ssh_observation_metadata_v1 WHERE source_id > ? ORDER BY source_id ASC LIMIT ?`, after, int(limit)+1)
	if err != nil {
		return MetadataPage{}, err
	}
	defer rows.Close()
	page := MetadataPage{Items: make([]ObservationMetadata, 0, limit)}
	for rows.Next() {
		var sourceID SourceID
		var revision uint64
		var bootID string
		var encoded []byte
		var updatedRaw string
		if err = rows.Scan(&sourceID, &revision, &bootID, &encoded, &updatedRaw); err != nil {
			return MetadataPage{}, err
		}
		if len(page.Items) == int(limit) {
			page.NextID = page.Items[len(page.Items)-1].SourceID
			return page, rows.Close()
		}
		var metadata ObservationMetadata
		if decodeStored(encoded, MaximumMetadataJSON, &metadata) != nil || metadata.SourceID != sourceID || metadata.Revision != revision || metadata.Boot.BootID != bootID || storedTime(metadata.UpdatedAt) != updatedRaw || !metadata.valid() {
			return MetadataPage{}, ErrIntegrity
		}
		page.Items = append(page.Items, metadata)
	}
	return page, rows.Err()
}

func (repository *SQLiteRepository) UpsertObservationMetadata(ctx context.Context, metadata ObservationMetadata, expectedRevision uint64) (ObservationMetadata, error) {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision >= MaximumRevision || !validOpaque(string(metadata.SourceID)) || !metadata.Boot.valid() || !validDigest(metadata.EvidenceChainDigest) || metadata.LastObservedAt.IsZero() || len(metadata.Cursor) > MaximumCursorBytes {
		return ObservationMetadata{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	metadata.Revision = expectedRevision + 1
	metadata.UpdatedAt = repository.now().UTC()
	if !metadata.valid() {
		return ObservationMetadata{}, ErrInvalid
	}
	encoded, err := encodeStored(metadata, MaximumMetadataJSON)
	if err != nil {
		return ObservationMetadata{}, err
	}
	if expectedRevision == 0 {
		result, insertErr := repository.db.ExecContext(ctx, `INSERT INTO ssh_observation_metadata_v1(source_id, revision, boot_id, metadata_json, updated_at)
SELECT ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM ssh_observation_metadata_v1) < ?`, metadata.SourceID, metadata.Revision, metadata.Boot.BootID, encoded, storedTime(metadata.UpdatedAt), MaximumMetadataSources)
		if insertErr != nil {
			if _, getErr := repository.GetObservationMetadata(ctx, metadata.SourceID); getErr == nil {
				return ObservationMetadata{}, ErrConflict
			}
			return ObservationMetadata{}, insertErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return ObservationMetadata{}, rowsErr
		}
		if rows == 0 {
			return ObservationMetadata{}, ErrLimit
		}
		return metadata, nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE ssh_observation_metadata_v1 SET revision = ?, boot_id = ?, metadata_json = ?, updated_at = ? WHERE source_id = ? AND revision = ?`, metadata.Revision, metadata.Boot.BootID, encoded, storedTime(metadata.UpdatedAt), metadata.SourceID, expectedRevision)
	if err != nil {
		return ObservationMetadata{}, err
	}
	if err = changedOne(result); err != nil {
		return ObservationMetadata{}, err
	}
	return metadata, nil
}

func scanRisk(row rowScanner, riskID string) (RiskSnapshot, error) {
	var revision uint64
	var startRaw, endRaw string
	var encoded []byte
	var updatedRaw string
	if err := row.Scan(&revision, &startRaw, &endRaw, &encoded, &updatedRaw); err != nil {
		return RiskSnapshot{}, err
	}
	var snapshot RiskSnapshot
	if decodeStored(encoded, MaximumRiskJSON, &snapshot) != nil || snapshot.ID != riskID || snapshot.Revision != revision || storedTime(snapshot.WindowStart) != startRaw || storedTime(snapshot.WindowEnd) != endRaw || storedTime(snapshot.UpdatedAt) != updatedRaw || !snapshot.valid() {
		return RiskSnapshot{}, ErrIntegrity
	}
	return snapshot, nil
}

func (repository *SQLiteRepository) GetRiskSnapshot(ctx context.Context, riskID string) (RiskSnapshot, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validOpaque(riskID) {
		return RiskSnapshot{}, ErrInvalid
	}
	snapshot, err := scanRisk(repository.db.QueryRowContext(ctx, `SELECT revision, window_start, window_end, snapshot_json, updated_at FROM ssh_risk_snapshots_v1 WHERE risk_id = ?`, riskID), riskID)
	if errors.Is(err, sql.ErrNoRows) {
		return RiskSnapshot{}, ErrNotFound
	}
	return snapshot, err
}

func (repository *SQLiteRepository) ListRiskSnapshots(ctx context.Context, after string, limit uint16) (RiskPage, error) {
	if repository == nil || repository.db == nil || ctx == nil || limit == 0 || limit > MaximumRepositoryPage || after != "" && !validOpaque(after) {
		return RiskPage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT risk_id, revision, window_start, window_end, snapshot_json, updated_at FROM ssh_risk_snapshots_v1 WHERE risk_id > ? ORDER BY risk_id ASC LIMIT ?`, after, int(limit)+1)
	if err != nil {
		return RiskPage{}, err
	}
	defer rows.Close()
	page := RiskPage{Items: make([]RiskSnapshot, 0, limit)}
	for rows.Next() {
		var riskID string
		var revision uint64
		var startRaw, endRaw string
		var encoded []byte
		var updatedRaw string
		if err = rows.Scan(&riskID, &revision, &startRaw, &endRaw, &encoded, &updatedRaw); err != nil {
			return RiskPage{}, err
		}
		if len(page.Items) == int(limit) {
			page.NextID = page.Items[len(page.Items)-1].ID
			return page, rows.Close()
		}
		var snapshot RiskSnapshot
		if decodeStored(encoded, MaximumRiskJSON, &snapshot) != nil || snapshot.ID != riskID || snapshot.Revision != revision || storedTime(snapshot.WindowStart) != startRaw || storedTime(snapshot.WindowEnd) != endRaw || storedTime(snapshot.UpdatedAt) != updatedRaw || !snapshot.valid() {
			return RiskPage{}, ErrIntegrity
		}
		page.Items = append(page.Items, snapshot)
	}
	return page, rows.Err()
}

func (repository *SQLiteRepository) UpsertRiskSnapshot(ctx context.Context, snapshot RiskSnapshot, expectedRevision uint64) (RiskSnapshot, error) {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision >= MaximumRevision || !validOpaque(snapshot.ID) || snapshot.WindowStart.IsZero() || !snapshot.WindowEnd.After(snapshot.WindowStart) || !analysisResultValid(snapshot.Result) {
		return RiskSnapshot{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	now := repository.now().UTC()
	if expectedRevision == 0 {
		if snapshot.CreatedAt.IsZero() {
			snapshot.CreatedAt = now
		}
	} else {
		previous, err := repository.GetRiskSnapshot(ctx, snapshot.ID)
		if err != nil || previous.Revision != expectedRevision || !previous.WindowStart.Equal(snapshot.WindowStart) || !previous.WindowEnd.Equal(snapshot.WindowEnd) {
			return RiskSnapshot{}, ErrConflict
		}
		snapshot.CreatedAt = previous.CreatedAt
	}
	snapshot.Revision = expectedRevision + 1
	snapshot.UpdatedAt = now
	if !snapshot.valid() {
		return RiskSnapshot{}, ErrInvalid
	}
	encoded, err := encodeStored(snapshot, MaximumRiskJSON)
	if err != nil {
		return RiskSnapshot{}, err
	}
	if expectedRevision == 0 {
		result, insertErr := repository.db.ExecContext(ctx, `INSERT INTO ssh_risk_snapshots_v1(risk_id, revision, window_start, window_end, snapshot_json, updated_at)
SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM ssh_risk_snapshots_v1) < ?`, snapshot.ID, snapshot.Revision, storedTime(snapshot.WindowStart), storedTime(snapshot.WindowEnd), encoded, storedTime(snapshot.UpdatedAt), MaximumRiskSnapshots)
		if insertErr != nil {
			if _, getErr := repository.GetRiskSnapshot(ctx, snapshot.ID); getErr == nil {
				return RiskSnapshot{}, ErrConflict
			}
			return RiskSnapshot{}, insertErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return RiskSnapshot{}, rowsErr
		}
		if rows == 0 {
			return RiskSnapshot{}, ErrLimit
		}
		return snapshot, nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE ssh_risk_snapshots_v1 SET revision = ?, snapshot_json = ?, updated_at = ? WHERE risk_id = ? AND revision = ?`, snapshot.Revision, encoded, storedTime(snapshot.UpdatedAt), snapshot.ID, expectedRevision)
	if err != nil {
		return RiskSnapshot{}, err
	}
	if err = changedOne(result); err != nil {
		return RiskSnapshot{}, err
	}
	return snapshot, nil
}

func validPlanTransition(previous, next ResponsePlan) bool {
	if previous.ID != next.ID || previous.BodyDigest != next.BodyDigest || previous.CreatedAt != next.CreatedAt || previous.ExpiresAt != next.ExpiresAt {
		return false
	}
	switch previous.Status {
	case PlanProposed:
		return next.Status == PlanApproved && previous.Approval == nil && next.Approval != nil
	case PlanApproved:
		return next.Status == PlanExecuting && previous.Approval != nil && next.Approval != nil && *previous.Approval == *next.Approval
	case PlanExecuting:
		return (next.Status == PlanSucceeded || next.Status == PlanFailed) && previous.Approval != nil && next.Approval != nil && *previous.Approval == *next.Approval
	default:
		return false
	}
}

func scanPlan(row rowScanner, planID PlanID, now time.Time) (ResponsePlan, error) {
	var revision uint64
	var status ResponsePlanStatus
	var bodyDigest string
	var encoded []byte
	var updatedRaw string
	if err := row.Scan(&revision, &status, &bodyDigest, &encoded, &updatedRaw); err != nil {
		return ResponsePlan{}, err
	}
	var plan ResponsePlan
	if decodeStored(encoded, MaximumPlanJSON, &plan) != nil || plan.ID != planID || plan.Revision != revision || plan.Status != status || plan.BodyDigest != bodyDigest || !plan.valid(now) {
		return ResponsePlan{}, ErrIntegrity
	}
	return plan, nil
}

func (repository *SQLiteRepository) GetResponsePlan(ctx context.Context, planID PlanID) (ResponsePlan, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validOpaque(string(planID)) {
		return ResponsePlan{}, ErrInvalid
	}
	plan, err := scanPlan(repository.db.QueryRowContext(ctx, `SELECT revision, status, body_digest, plan_json, updated_at FROM ssh_response_plans_v1 WHERE plan_id = ?`, planID), planID, repository.now().UTC())
	if errors.Is(err, sql.ErrNoRows) {
		return ResponsePlan{}, ErrNotFound
	}
	return plan, err
}

func (repository *SQLiteRepository) ListResponsePlans(ctx context.Context, after PlanID, limit uint16) (PlanPage, error) {
	if repository == nil || repository.db == nil || ctx == nil || limit == 0 || limit > MaximumRepositoryPage || after != "" && !validOpaque(string(after)) {
		return PlanPage{}, ErrInvalid
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT plan_id, revision, status, body_digest, plan_json, updated_at FROM ssh_response_plans_v1 WHERE plan_id > ? ORDER BY plan_id ASC LIMIT ?`, after, int(limit)+1)
	if err != nil {
		return PlanPage{}, err
	}
	defer rows.Close()
	now := repository.now().UTC()
	page := PlanPage{Items: make([]ResponsePlan, 0, limit)}
	for rows.Next() {
		var planID PlanID
		var revision uint64
		var status ResponsePlanStatus
		var bodyDigest string
		var encoded []byte
		var updatedRaw string
		if err = rows.Scan(&planID, &revision, &status, &bodyDigest, &encoded, &updatedRaw); err != nil {
			return PlanPage{}, err
		}
		if len(page.Items) == int(limit) {
			page.NextID = page.Items[len(page.Items)-1].ID
			return page, rows.Close()
		}
		var plan ResponsePlan
		if decodeStored(encoded, MaximumPlanJSON, &plan) != nil || plan.ID != planID || plan.Revision != revision || plan.Status != status || plan.BodyDigest != bodyDigest || !plan.valid(now) {
			return PlanPage{}, ErrIntegrity
		}
		page.Items = append(page.Items, plan)
	}
	return page, rows.Err()
}

func (repository *SQLiteRepository) UpsertResponsePlan(ctx context.Context, plan ResponsePlan, expectedRevision uint64) (ResponsePlan, error) {
	if repository == nil || repository.db == nil || ctx == nil || expectedRevision >= MaximumRevision || !validOpaque(string(plan.ID)) {
		return ResponsePlan{}, ErrInvalid
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	if expectedRevision == 0 {
		if plan.Status != PlanProposed || plan.Revision != 1 {
			return ResponsePlan{}, ErrInvalid
		}
	} else {
		previous, err := repository.GetResponsePlan(ctx, plan.ID)
		if err != nil || previous.Revision != expectedRevision || !validPlanTransition(previous, plan) {
			return ResponsePlan{}, ErrConflict
		}
	}
	plan.Revision = expectedRevision + 1
	if !plan.valid(repository.now().UTC()) {
		return ResponsePlan{}, ErrInvalid
	}
	encoded, err := encodeStored(plan, MaximumPlanJSON)
	if err != nil {
		return ResponsePlan{}, err
	}
	if expectedRevision == 0 {
		result, insertErr := repository.db.ExecContext(ctx, `INSERT INTO ssh_response_plans_v1(plan_id, revision, status, body_digest, plan_json, updated_at)
SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM ssh_response_plans_v1) < ?`, plan.ID, plan.Revision, plan.Status, plan.BodyDigest, encoded, storedTime(repository.now().UTC()), MaximumResponsePlans)
		if insertErr != nil {
			if _, getErr := repository.GetResponsePlan(ctx, plan.ID); getErr == nil {
				return ResponsePlan{}, ErrConflict
			}
			return ResponsePlan{}, insertErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return ResponsePlan{}, rowsErr
		}
		if rows == 0 {
			return ResponsePlan{}, ErrLimit
		}
		return plan, nil
	}
	result, err := repository.db.ExecContext(ctx, `UPDATE ssh_response_plans_v1 SET revision = ?, status = ?, plan_json = ?, updated_at = ? WHERE plan_id = ? AND revision = ?`, plan.Revision, plan.Status, encoded, storedTime(repository.now().UTC()), plan.ID, expectedRevision)
	if err != nil {
		return ResponsePlan{}, err
	}
	if err = changedOne(result); err != nil {
		return ResponsePlan{}, err
	}
	return plan, nil
}

func (repository *SQLiteRepository) GetResponseReceipt(ctx context.Context, planID PlanID) (ResponseReceipt, error) {
	if repository == nil || repository.db == nil || ctx == nil || !validOpaque(string(planID)) {
		return ResponseReceipt{}, ErrInvalid
	}
	var receiptID string
	var encoded []byte
	var completedRaw string
	err := repository.db.QueryRowContext(ctx, `SELECT receipt_id, receipt_json, completed_at FROM ssh_response_receipts_v1 WHERE plan_id = ?`, planID).Scan(&receiptID, &encoded, &completedRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return ResponseReceipt{}, ErrNotFound
	}
	if err != nil {
		return ResponseReceipt{}, err
	}
	var receipt ResponseReceipt
	if decodeStored(encoded, MaximumReceiptJSON, &receipt) != nil || receipt.PlanID != planID || receipt.ID != receiptID || storedTime(receipt.CompletedAt) != completedRaw || !receipt.valid() {
		return ResponseReceipt{}, ErrIntegrity
	}
	return receipt, nil
}

func (repository *SQLiteRepository) InsertResponseReceipt(ctx context.Context, receipt ResponseReceipt) error {
	if repository == nil || repository.db == nil || ctx == nil || !receipt.valid() {
		return ErrInvalid
	}
	encoded, err := encodeStored(receipt, MaximumReceiptJSON)
	if err != nil {
		return err
	}
	plan, err := repository.GetResponsePlan(ctx, receipt.PlanID)
	if err != nil || plan.BodyDigest != receipt.PlanDigest || plan.IncidentID != receipt.IncidentID || plan.Action != receipt.Action || plan.Status != PlanExecuting && plan.Status != PlanSucceeded && plan.Status != PlanFailed {
		return ErrConflict
	}
	repository.writer.Lock()
	defer repository.writer.Unlock()
	_, err = repository.db.ExecContext(ctx, `INSERT INTO ssh_response_receipts_v1(plan_id, receipt_id, receipt_json, completed_at) VALUES (?, ?, ?, ?)`, receipt.PlanID, receipt.ID, encoded, storedTime(receipt.CompletedAt))
	if err != nil {
		if existing, getErr := repository.GetResponseReceipt(ctx, receipt.PlanID); getErr == nil && existing.Digest == receipt.Digest {
			return nil
		}
		return ErrConflict
	}
	return nil
}

var _ ResponseRepository = (*SQLiteRepository)(nil)
