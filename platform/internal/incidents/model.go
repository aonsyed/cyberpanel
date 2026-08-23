package incidents

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid      = errors.New("incidents: invalid value")
	ErrNotFound     = errors.New("incidents: not found")
	ErrConflict     = errors.New("incidents: conflict")
	ErrUnauthorized = errors.New("incidents: unauthorized")
	ErrCapacity     = errors.New("incidents: capacity exceeded")
	ErrIntegrity    = errors.New("incidents: integrity failure")
)

const (
	MaximumEvidenceLinks    = 4096
	MaximumTimelineEntries  = 10000
	MaximumListLimit        = 200
	MaximumSourceGeneration = uint64(1<<63 - 1)
)

var stableIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,191}$`)

type CaseID string
type EvidenceID string
type TimelineID string
type TenantID string
type PrincipalID string

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Status string

const (
	StatusOpen       Status = "open"
	StatusTriaged    Status = "triaged"
	StatusContained  Status = "contained"
	StatusRecovering Status = "recovering"
	StatusResolved   Status = "resolved"
	StatusClosed     Status = "closed"
)

type RedactionClass string

const (
	RedactionPublic     RedactionClass = "public"
	RedactionInternal   RedactionClass = "internal"
	RedactionSensitive  RedactionClass = "sensitive"
	RedactionRestricted RedactionClass = "restricted"
)

type ClassifiedText struct {
	Text      string         `json:"text"`
	Redaction RedactionClass `json:"redaction"`
}

type EvidenceKind string

const (
	EvidenceFinding    EvidenceKind = "finding"
	EvidenceLog        EvidenceKind = "log"
	EvidenceSession    EvidenceKind = "session"
	EvidenceProcess    EvidenceKind = "process"
	EvidenceBan        EvidenceKind = "ban"
	EvidenceQuarantine EvidenceKind = "quarantine"
	EvidenceAction     EvidenceKind = "action"
	EvidenceArtifact   EvidenceKind = "artifact"
	EvidenceAudit      EvidenceKind = "audit"
)

// EvidenceLink is an immutable pointer to source material. The source tenant,
// generation, and digest bind the link to one exact source object version.
type EvidenceLink struct {
	ID               EvidenceID    `json:"id"`
	TenantID         TenantID      `json:"tenant_id"`
	CaseID           CaseID        `json:"case_id"`
	Kind             EvidenceKind  `json:"kind"`
	SourceTenantID   TenantID      `json:"source_tenant_id"`
	SourceID         string        `json:"source_id"`
	SourceGeneration uint64         `json:"source_generation"`
	SourceDigest     string         `json:"source_digest"`
	Redaction        RedactionClass `json:"redaction"`
	LinkedBy         PrincipalID    `json:"linked_by"`
	LinkedAt         time.Time      `json:"linked_at"`
}

type TimelineKind string

const (
	TimelineCreated        TimelineKind = "created"
	TimelineEvidenceLinked TimelineKind = "evidence_linked"
	TimelineNote           TimelineKind = "note"
	TimelineAssigned       TimelineKind = "assigned"
	TimelineTransitioned TimelineKind = "transitioned"
)

// TimelineEntry is append-only and bound to the case generation created by
// the same transaction.
type TimelineEntry struct {
	ID             TimelineID    `json:"id"`
	TenantID       TenantID      `json:"tenant_id"`
	CaseID         CaseID        `json:"case_id"`
	CaseGeneration uint64         `json:"case_generation"`
	Kind           TimelineKind  `json:"kind"`
	ActorID        PrincipalID   `json:"actor_id"`
	FromStatus     Status        `json:"from_status,omitempty"`
	ToStatus       Status        `json:"to_status,omitempty"`
	Summary        ClassifiedText `json:"summary"`
	OccurredAt     time.Time      `json:"occurred_at"`
}

type IncidentCase struct {
	ID                 CaseID         `json:"id"`
	TenantID           TenantID       `json:"tenant_id"`
	Title              ClassifiedText `json:"title"`
	Description        ClassifiedText `json:"description"`
	Severity           Severity       `json:"severity"`
	Status             Status         `json:"status"`
	AssigneeID         PrincipalID    `json:"assignee_id,omitempty"`
	ContainmentSummary ClassifiedText `json:"containment_summary"`
	RecoverySummary    ClassifiedText `json:"recovery_summary"`
	Generation         uint64         `json:"generation"`
	Evidence           []EvidenceLink `json:"evidence"`
	Timeline           []TimelineEntry `json:"timeline"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
	ClosedAt           *time.Time      `json:"closed_at,omitempty"`
}

func (incident IncidentCase) Validate() error {
	if !validStableID(string(incident.ID)) || !validStableID(string(incident.TenantID)) || incident.Generation == 0 || incident.Generation > MaximumTimelineEntries || !validSeverity(incident.Severity) || !validStatus(incident.Status) || !validClassifiedText(incident.Title, 1, 256) || !validClassifiedText(incident.Description, 0, 8192) || !validClassifiedText(incident.ContainmentSummary, 0, 8192) || !validClassifiedText(incident.RecoverySummary, 0, 8192) || !incident.AssigneeID.validOptional() || incident.CreatedAt.IsZero() || incident.UpdatedAt.Before(incident.CreatedAt) || len(incident.Evidence) > MaximumEvidenceLinks || len(incident.Timeline) > MaximumTimelineEntries {
		return ErrInvalid
	}
	if requiresContainment(incident.Status) && strings.TrimSpace(incident.ContainmentSummary.Text) == "" {
		return ErrInvalid
	}
	if requiresRecovery(incident.Status) && strings.TrimSpace(incident.RecoverySummary.Text) == "" {
		return ErrInvalid
	}
	if incident.Status == StatusClosed {
		if incident.ClosedAt == nil || !incident.ClosedAt.Equal(incident.UpdatedAt) {
			return ErrInvalid
		}
	} else if incident.ClosedAt != nil {
		return ErrInvalid
	}

	evidenceIDs := make(map[EvidenceID]bool, len(incident.Evidence))
	evidenceTimes := make(map[string]uint64)
	for _, link := range incident.Evidence {
		if link.Validate(incident.TenantID, incident.ID) != nil || evidenceIDs[link.ID] || link.LinkedAt.Before(incident.CreatedAt) || link.LinkedAt.After(incident.UpdatedAt) {
			return ErrIntegrity
		}
		evidenceIDs[link.ID] = true
		evidenceTimes[timeKey(link.LinkedAt)]++
	}
	if len(incident.Timeline) == 0 {
		return nil
	}
	if uint64(len(incident.Timeline)) != incident.Generation {
		return ErrIntegrity
	}

	timelineIDs := make(map[TimelineID]bool, len(incident.Timeline))
	currentStatus := StatusOpen
	var lastAt time.Time
	for index, entry := range incident.Timeline {
		if entry.Validate(incident.TenantID, incident.ID) != nil || timelineIDs[entry.ID] || entry.CaseGeneration != uint64(index+1) || !lastAt.IsZero() && entry.OccurredAt.Before(lastAt) {
			return ErrIntegrity
		}
		if index == 0 {
			if entry.Kind != TimelineCreated || !entry.OccurredAt.Equal(incident.CreatedAt) {
				return ErrIntegrity
			}
		} else if entry.Kind == TimelineCreated {
			return ErrIntegrity
		}
		if entry.Kind == TimelineTransitioned {
			if entry.FromStatus != currentStatus {
				return ErrIntegrity
			}
			currentStatus = entry.ToStatus
		}
		if entry.Kind == TimelineEvidenceLinked {
			key := timeKey(entry.OccurredAt)
			if evidenceTimes[key] == 0 {
				return ErrIntegrity
			}
			evidenceTimes[key]--
		}
		timelineIDs[entry.ID] = true
		lastAt = entry.OccurredAt
	}
	if currentStatus != incident.Status || !lastAt.Equal(incident.UpdatedAt) {
		return ErrIntegrity
	}
	for _, unmatched := range evidenceTimes {
		if unmatched != 0 {
			return ErrIntegrity
		}
	}
	return nil
}

func (link EvidenceLink) Validate(tenant TenantID, caseID CaseID) error {
	if !validStableID(string(link.ID)) || link.TenantID != tenant || link.CaseID != caseID || link.SourceTenantID != tenant || !validEvidenceKind(link.Kind) || !validReference(link.SourceID, 512) || link.SourceGeneration == 0 || link.SourceGeneration > MaximumSourceGeneration || !validDigest(link.SourceDigest) || !validRedaction(link.Redaction) || !validStableID(string(link.LinkedBy)) || link.LinkedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

func (entry TimelineEntry) Validate(tenant TenantID, caseID CaseID) error {
	if !validStableID(string(entry.ID)) || entry.TenantID != tenant || entry.CaseID != caseID || entry.CaseGeneration == 0 || entry.CaseGeneration > MaximumTimelineEntries || !validTimelineKind(entry.Kind) || !validStableID(string(entry.ActorID)) || !validClassifiedText(entry.Summary, 1, 8192) || entry.OccurredAt.IsZero() {
		return ErrInvalid
	}
	if entry.Kind == TimelineTransitioned {
		if !validStatus(entry.FromStatus) || !validStatus(entry.ToStatus) || !CanTransition(entry.FromStatus, entry.ToStatus) {
			return ErrInvalid
		}
	} else if entry.FromStatus != "" || entry.ToStatus != "" {
		return ErrInvalid
	}
	return nil
}

func CanTransition(from, to Status) bool {
	switch from {
	case StatusOpen:
		return to == StatusTriaged || to == StatusContained
	case StatusTriaged:
		return to == StatusContained
	case StatusContained:
		return to == StatusRecovering || to == StatusResolved
	case StatusRecovering:
		return to == StatusContained || to == StatusResolved
	case StatusResolved:
		return to == StatusRecovering || to == StatusClosed
	case StatusClosed:
		return false
	default:
		return false
	}
}

func validStableID(value string) bool {
	return stableIDPattern.MatchString(value)
}

func (id PrincipalID) validOptional() bool {
	return id == "" || validStableID(string(id))
}

func validReference(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func validClassifiedText(value ClassifiedText, minimum, maximum int) bool {
	length := len(value.Text)
	return length >= minimum && length <= maximum && (minimum == 0 || strings.TrimSpace(value.Text) != "") && !strings.ContainsRune(value.Text, 0) && validRedaction(value.Redaction)
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validSeverity(value Severity) bool {
	switch value {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func validStatus(value Status) bool {
	switch value {
	case StatusOpen, StatusTriaged, StatusContained, StatusRecovering, StatusResolved, StatusClosed:
		return true
	default:
		return false
	}
}

func validRedaction(value RedactionClass) bool {
	switch value {
	case RedactionPublic, RedactionInternal, RedactionSensitive, RedactionRestricted:
		return true
	default:
		return false
	}
}

func validEvidenceKind(value EvidenceKind) bool {
	switch value {
	case EvidenceFinding, EvidenceLog, EvidenceSession, EvidenceProcess, EvidenceBan, EvidenceQuarantine, EvidenceAction, EvidenceArtifact, EvidenceAudit:
		return true
	default:
		return false
	}
}

func validTimelineKind(value TimelineKind) bool {
	switch value {
	case TimelineCreated, TimelineEvidenceLinked, TimelineNote, TimelineAssigned, TimelineTransitioned:
		return true
	default:
		return false
	}
}

func requiresContainment(status Status) bool {
	return status == StatusContained || status == StatusRecovering || status == StatusResolved || status == StatusClosed
}

func requiresRecovery(status Status) bool {
	return status == StatusResolved || status == StatusClosed
}

func timeKey(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
