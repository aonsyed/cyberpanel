package incidents

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const Schema = `
CREATE TABLE IF NOT EXISTS incident_cases_v1 (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    assignee_id TEXT NOT NULL,
    case_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, case_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS incident_evidence_v1 (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_tenant_id TEXT NOT NULL CHECK (source_tenant_id = tenant_id),
    source_id TEXT NOT NULL,
    source_generation INTEGER NOT NULL CHECK (source_generation > 0),
    source_digest TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    evidence_json BLOB NOT NULL,
    PRIMARY KEY (tenant_id, case_id, evidence_id),
    UNIQUE (tenant_id, case_id, kind, source_id, source_generation),
    FOREIGN KEY (tenant_id, case_id) REFERENCES incident_cases_v1 (tenant_id, case_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS incident_timeline_v1 (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    timeline_id TEXT NOT NULL,
    case_generation INTEGER NOT NULL CHECK (case_generation > 0),
    kind TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    entry_json BLOB NOT NULL,
    PRIMARY KEY (tenant_id, case_id, timeline_id),
    UNIQUE (tenant_id, case_id, case_generation),
    FOREIGN KEY (tenant_id, case_id) REFERENCES incident_cases_v1 (tenant_id, case_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS incident_cases_tenant_id_v1
    ON incident_cases_v1 (tenant_id, case_id);
CREATE INDEX IF NOT EXISTS incident_evidence_order_v1
    ON incident_evidence_v1 (tenant_id, case_id, linked_at, evidence_id);
CREATE INDEX IF NOT EXISTS incident_timeline_order_v1
    ON incident_timeline_v1 (tenant_id, case_id, case_generation, timeline_id);
CREATE TRIGGER IF NOT EXISTS incident_evidence_no_update_v1
    BEFORE UPDATE ON incident_evidence_v1
    BEGIN SELECT RAISE(ABORT, 'incident evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS incident_evidence_no_delete_v1
    BEFORE DELETE ON incident_evidence_v1
    BEGIN SELECT RAISE(ABORT, 'incident evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS incident_timeline_no_update_v1
    BEFORE UPDATE ON incident_timeline_v1
    BEGIN SELECT RAISE(ABORT, 'incident timeline is append-only'); END;
CREATE TRIGGER IF NOT EXISTS incident_timeline_no_delete_v1
    BEFORE DELETE ON incident_timeline_v1
    BEGIN SELECT RAISE(ABORT, 'incident timeline is append-only'); END;
`

const (
	maximumCaseJSON     = 32 * 1024
	maximumEvidenceJSON = 8 * 1024
	maximumTimelineJSON = 16 * 1024
	defaultListLimit    = 50
)

type CaseRepository interface {
	Create(context.Context, IncidentCase, TimelineEntry) (IncidentCase, error)
	Get(context.Context, TenantID, CaseID) (IncidentCase, error)
	List(context.Context, TenantID, CaseID, uint32) ([]IncidentCase, CaseID, error)
	AppendEvidence(context.Context, TenantID, CaseID, uint64, EvidenceLink, TimelineEntry) (IncidentCase, error)
	AppendTimeline(context.Context, TenantID, CaseID, uint64, TimelineEntry) (IncidentCase, error)
	Assign(context.Context, TenantID, CaseID, uint64, PrincipalID, TimelineEntry) (IncidentCase, error)
	Transition(context.Context, TenantID, CaseID, uint64, Status, *ClassifiedText, *ClassifiedText, TimelineEntry) (IncidentCase, error)
}

type SQLRepository struct {
	db     *sql.DB
	writer sync.Mutex
}

func NewSQLRepository(db *sql.DB) (*SQLRepository, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &SQLRepository{db: db}, nil
}

func (repository *SQLRepository) Bootstrap(ctx context.Context) error {
	if repository == nil || repository.db == nil {
		return ErrInvalid
	}
	_, err := repository.db.ExecContext(ctx, Schema)
	return err
}

func (repository *SQLRepository) Create(ctx context.Context, incident IncidentCase, entry TimelineEntry) (IncidentCase, error) {
	if repository == nil || repository.db == nil || incident.Generation != 1 || incident.Status != StatusOpen || len(incident.Evidence) != 0 || len(incident.Timeline) != 0 || incident.ClosedAt != nil {
		return IncidentCase{}, ErrInvalid
	}
	if err := incident.Validate(); err != nil {
		return IncidentCase{}, err
	}
	if entry.Kind != TimelineCreated || entry.CaseGeneration != 1 || entry.TenantID != incident.TenantID || entry.CaseID != incident.ID || !entry.OccurredAt.Equal(incident.CreatedAt) || !entry.OccurredAt.Equal(incident.UpdatedAt) {
		return IncidentCase{}, ErrInvalid
	}
	if err := entry.Validate(incident.TenantID, incident.ID); err != nil {
		return IncidentCase{}, err
	}

	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return IncidentCase{}, err
	}
	defer tx.Rollback()
	caseJSON, err := marshalCore(incident)
	if err != nil {
		return IncidentCase{}, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO incident_cases_v1
        (tenant_id,case_id,generation,severity,status,assignee_id,case_json,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT (tenant_id,case_id) DO NOTHING`, incident.TenantID, incident.ID, incident.Generation, incident.Severity, incident.Status, incident.AssigneeID, caseJSON, timestamp(incident.CreatedAt), timestamp(incident.UpdatedAt))
	if err != nil {
		return IncidentCase{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return IncidentCase{}, err
	}
	if inserted != 1 {
		return IncidentCase{}, ErrConflict
	}
	if err = insertTimeline(ctx, tx, entry); err != nil {
		return IncidentCase{}, err
	}
	if err = tx.Commit(); err != nil {
		return IncidentCase{}, err
	}
	incident.Timeline = []TimelineEntry{entry}
	return incident, incident.Validate()
}

func (repository *SQLRepository) Get(ctx context.Context, tenantID TenantID, caseID CaseID) (IncidentCase, error) {
	if repository == nil || repository.db == nil || !validStableID(string(tenantID)) || !validStableID(string(caseID)) {
		return IncidentCase{}, ErrInvalid
	}
	return loadAggregate(ctx, repository.db, tenantID, caseID)
}

func (repository *SQLRepository) List(ctx context.Context, tenantID TenantID, after CaseID, limit uint32) ([]IncidentCase, CaseID, error) {
	if repository == nil || repository.db == nil || !validStableID(string(tenantID)) || after != "" && !validStableID(string(after)) || limit > MaximumListLimit {
		return nil, "", ErrInvalid
	}
	if limit == 0 {
		limit = defaultListLimit
	}
	rows, err := repository.db.QueryContext(ctx, `SELECT case_id,case_json FROM incident_cases_v1
        WHERE tenant_id=? AND case_id>? ORDER BY case_id ASC LIMIT ?`, tenantID, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	cases := make([]IncidentCase, 0, limit)
	for rows.Next() {
		var storedID CaseID
		var raw []byte
		if err = rows.Scan(&storedID, &raw); err != nil {
			return nil, "", err
		}
		var incident IncidentCase
		if err = decodeStrict(raw, maximumCaseJSON, &incident); err != nil || incident.ID != storedID || incident.TenantID != tenantID {
			return nil, "", ErrIntegrity
		}
		if err = incident.Validate(); err != nil {
			return nil, "", fmt.Errorf("%w: list case %s", ErrIntegrity, storedID)
		}
		cases = append(cases, incident)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	var next CaseID
	if len(cases) > int(limit) {
		cases = cases[:limit]
		next = cases[len(cases)-1].ID
	}
	return cases, next, nil
}

func (repository *SQLRepository) AppendEvidence(ctx context.Context, tenantID TenantID, caseID CaseID, expected uint64, link EvidenceLink, entry TimelineEntry) (IncidentCase, error) {
	if link.Validate(tenantID, caseID) != nil || entry.Kind != TimelineEvidenceLinked || !link.LinkedAt.Equal(entry.OccurredAt) {
		return IncidentCase{}, ErrInvalid
	}
	return repository.mutate(ctx, tenantID, caseID, expected, entry, &link, func(incident *IncidentCase) error {
		return nil
	})
}

func (repository *SQLRepository) AppendTimeline(ctx context.Context, tenantID TenantID, caseID CaseID, expected uint64, entry TimelineEntry) (IncidentCase, error) {
	if entry.Kind != TimelineNote {
		return IncidentCase{}, ErrInvalid
	}
	return repository.mutate(ctx, tenantID, caseID, expected, entry, nil, func(incident *IncidentCase) error {
		return nil
	})
}

func (repository *SQLRepository) Assign(ctx context.Context, tenantID TenantID, caseID CaseID, expected uint64, assigneeID PrincipalID, entry TimelineEntry) (IncidentCase, error) {
	if !assigneeID.validOptional() || entry.Kind != TimelineAssigned {
		return IncidentCase{}, ErrInvalid
	}
	return repository.mutate(ctx, tenantID, caseID, expected, entry, nil, func(incident *IncidentCase) error {
		if incident.AssigneeID == assigneeID {
			return ErrInvalid
		}
		incident.AssigneeID = assigneeID
		return nil
	})
}

func (repository *SQLRepository) Transition(ctx context.Context, tenantID TenantID, caseID CaseID, expected uint64, target Status, containment, recovery *ClassifiedText, entry TimelineEntry) (IncidentCase, error) {
	if !validStatus(target) || entry.Kind != TimelineTransitioned || entry.ToStatus != target {
		return IncidentCase{}, ErrInvalid
	}
	if containment != nil && !validClassifiedText(*containment, 0, 8192) || recovery != nil && !validClassifiedText(*recovery, 0, 8192) {
		return IncidentCase{}, ErrInvalid
	}
	return repository.mutate(ctx, tenantID, caseID, expected, entry, nil, func(incident *IncidentCase) error {
		if entry.FromStatus != incident.Status || !CanTransition(incident.Status, target) {
			return ErrInvalid
		}
		if containment != nil {
			incident.ContainmentSummary = *containment
		}
		if recovery != nil {
			incident.RecoverySummary = *recovery
		}
		incident.Status = target
		if target == StatusClosed {
			closedAt := entry.OccurredAt
			incident.ClosedAt = &closedAt
		}
		return nil
	})
}

func (repository *SQLRepository) mutate(ctx context.Context, tenantID TenantID, caseID CaseID, expected uint64, entry TimelineEntry, link *EvidenceLink, apply func(*IncidentCase) error) (IncidentCase, error) {
	if repository == nil || repository.db == nil || !validStableID(string(tenantID)) || !validStableID(string(caseID)) || expected == 0 || entry.TenantID != tenantID || entry.CaseID != caseID {
		return IncidentCase{}, ErrInvalid
	}
	if expected >= MaximumTimelineEntries {
		return IncidentCase{}, ErrCapacity
	}
	if entry.CaseGeneration != expected+1 {
		return IncidentCase{}, ErrInvalid
	}
	if err := entry.Validate(tenantID, caseID); err != nil {
		return IncidentCase{}, err
	}

	repository.writer.Lock()
	defer repository.writer.Unlock()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return IncidentCase{}, err
	}
	defer tx.Rollback()
	incident, err := loadCore(ctx, tx, tenantID, caseID)
	if err != nil {
		return IncidentCase{}, err
	}
	if incident.Generation != expected {
		return IncidentCase{}, ErrConflict
	}
	if incident.Status == StatusClosed || entry.OccurredAt.Before(incident.UpdatedAt) {
		return IncidentCase{}, ErrInvalid
	}
	var timelineCount uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_timeline_v1 WHERE tenant_id=? AND case_id=?`, tenantID, caseID).Scan(&timelineCount); err != nil {
		return IncidentCase{}, err
	}
	if timelineCount >= MaximumTimelineEntries {
		return IncidentCase{}, ErrCapacity
	}
	if link != nil {
		var evidenceCount uint64
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_evidence_v1 WHERE tenant_id=? AND case_id=?`, tenantID, caseID).Scan(&evidenceCount); err != nil {
			return IncidentCase{}, err
		}
		if evidenceCount >= MaximumEvidenceLinks {
			return IncidentCase{}, ErrCapacity
		}
	}
	if err = apply(&incident); err != nil {
		return IncidentCase{}, err
	}
	incident.Generation = expected + 1
	incident.UpdatedAt = entry.OccurredAt
	if err = incident.Validate(); err != nil {
		return IncidentCase{}, err
	}
	caseJSON, err := marshalCore(incident)
	if err != nil {
		return IncidentCase{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE incident_cases_v1 SET
        generation=?,severity=?,status=?,assignee_id=?,case_json=?,updated_at=?
        WHERE tenant_id=? AND case_id=? AND generation=?`, incident.Generation, incident.Severity, incident.Status, incident.AssigneeID, caseJSON, timestamp(incident.UpdatedAt), tenantID, caseID, expected)
	if err != nil {
		return IncidentCase{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return IncidentCase{}, err
	}
	if changed != 1 {
		return IncidentCase{}, ErrConflict
	}
	if link != nil {
		if err = insertEvidence(ctx, tx, *link); err != nil {
			return IncidentCase{}, err
		}
	}
	if err = insertTimeline(ctx, tx, entry); err != nil {
		return IncidentCase{}, err
	}
	if err = tx.Commit(); err != nil {
		return IncidentCase{}, err
	}
	return repository.Get(ctx, tenantID, caseID)
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadCore(ctx context.Context, source queryer, tenantID TenantID, caseID CaseID) (IncidentCase, error) {
	var raw []byte
	if err := source.QueryRowContext(ctx, `SELECT case_json FROM incident_cases_v1 WHERE tenant_id=? AND case_id=?`, tenantID, caseID).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IncidentCase{}, ErrNotFound
		}
		return IncidentCase{}, err
	}
	var incident IncidentCase
	if err := decodeStrict(raw, maximumCaseJSON, &incident); err != nil || incident.TenantID != tenantID || incident.ID != caseID || len(incident.Evidence) != 0 || len(incident.Timeline) != 0 {
		return IncidentCase{}, ErrIntegrity
	}
	if err := incident.Validate(); err != nil {
		return IncidentCase{}, fmt.Errorf("%w: invalid case core", ErrIntegrity)
	}
	return incident, nil
}

func loadAggregate(ctx context.Context, source queryer, tenantID TenantID, caseID CaseID) (IncidentCase, error) {
	incident, err := loadCore(ctx, source, tenantID, caseID)
	if err != nil {
		return IncidentCase{}, err
	}
	evidenceRows, err := source.QueryContext(ctx, `SELECT evidence_json FROM incident_evidence_v1
        WHERE tenant_id=? AND case_id=? ORDER BY linked_at ASC,evidence_id ASC LIMIT ?`, tenantID, caseID, MaximumEvidenceLinks+1)
	if err != nil {
		return IncidentCase{}, err
	}
	for evidenceRows.Next() {
		var raw []byte
		var link EvidenceLink
		if err = evidenceRows.Scan(&raw); err != nil {
			evidenceRows.Close()
			return IncidentCase{}, err
		}
		if err = decodeStrict(raw, maximumEvidenceJSON, &link); err != nil {
			evidenceRows.Close()
			return IncidentCase{}, ErrIntegrity
		}
		incident.Evidence = append(incident.Evidence, link)
	}
	if err = evidenceRows.Err(); err != nil {
		evidenceRows.Close()
		return IncidentCase{}, err
	}
	evidenceRows.Close()
	if len(incident.Evidence) > MaximumEvidenceLinks {
		return IncidentCase{}, ErrIntegrity
	}
	timelineRows, err := source.QueryContext(ctx, `SELECT entry_json FROM incident_timeline_v1
        WHERE tenant_id=? AND case_id=? ORDER BY case_generation ASC,timeline_id ASC LIMIT ?`, tenantID, caseID, MaximumTimelineEntries+1)
	if err != nil {
		return IncidentCase{}, err
	}
	for timelineRows.Next() {
		var raw []byte
		var entry TimelineEntry
		if err = timelineRows.Scan(&raw); err != nil {
			timelineRows.Close()
			return IncidentCase{}, err
		}
		if err = decodeStrict(raw, maximumTimelineJSON, &entry); err != nil {
			timelineRows.Close()
			return IncidentCase{}, ErrIntegrity
		}
		incident.Timeline = append(incident.Timeline, entry)
	}
	if err = timelineRows.Err(); err != nil {
		timelineRows.Close()
		return IncidentCase{}, err
	}
	timelineRows.Close()
	if len(incident.Timeline) > MaximumTimelineEntries {
		return IncidentCase{}, ErrIntegrity
	}
	if err = incident.Validate(); err != nil {
		return IncidentCase{}, fmt.Errorf("%w: invalid case aggregate", ErrIntegrity)
	}
	return incident, nil
}

func insertEvidence(ctx context.Context, tx *sql.Tx, link EvidenceLink) error {
	raw, err := json.Marshal(link)
	if err != nil || len(raw) > maximumEvidenceJSON {
		return ErrInvalid
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO incident_evidence_v1
        (tenant_id,case_id,evidence_id,kind,source_tenant_id,source_id,source_generation,source_digest,linked_at,evidence_json)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, link.TenantID, link.CaseID, link.ID, link.Kind, link.SourceTenantID, link.SourceID, link.SourceGeneration, link.SourceDigest, timestamp(link.LinkedAt), raw)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted != 1 {
		return ErrConflict
	}
	return nil
}

func insertTimeline(ctx context.Context, tx *sql.Tx, entry TimelineEntry) error {
	raw, err := json.Marshal(entry)
	if err != nil || len(raw) > maximumTimelineJSON {
		return ErrInvalid
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO incident_timeline_v1
        (tenant_id,case_id,timeline_id,case_generation,kind,occurred_at,entry_json)
		VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, entry.TenantID, entry.CaseID, entry.ID, entry.CaseGeneration, entry.Kind, timestamp(entry.OccurredAt), raw)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted != 1 {
		return ErrConflict
	}
	return nil
}

func marshalCore(incident IncidentCase) ([]byte, error) {
	incident.Evidence = nil
	incident.Timeline = nil
	raw, err := json.Marshal(incident)
	if err != nil || len(raw) > maximumCaseJSON {
		return nil, ErrInvalid
	}
	return raw, nil
}

func decodeStrict(raw []byte, maximum int, target any) error {
	if len(raw) == 0 || len(raw) > maximum {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrIntegrity
	}
	return nil
}

func timestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
