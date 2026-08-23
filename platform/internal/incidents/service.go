package incidents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type Action string

const (
	ActionCreate          Action = "incident.create"
	ActionRead            Action = "incident.read"
	ActionList            Action = "incident.list"
	ActionLinkEvidence    Action = "incident.evidence.link"
	ActionAppendTimeline  Action = "incident.timeline.append"
	ActionAssign          Action = "incident.assign"
	ActionTransition      Action = "incident.transition"
)

type AuthorizationRequest struct {
	TenantID TenantID
	ActorID  PrincipalID
	Action   Action
	CaseID   CaseID
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) error
}

type MutationID string

// AuditMutation contains only stable identifiers and a digest of the request;
// classified case and evidence content never enters the audit envelope.
type AuditMutation struct {
	ID                 MutationID
	TenantID           TenantID
	CaseID             CaseID
	ActorID            PrincipalID
	Action             Action
	ExpectedGeneration uint64
	NextGeneration     uint64
	RequestDigest      string
	Redaction          RedactionClass
	RecordedAt         time.Time
}

type AuditSink interface {
	RecordMutation(context.Context, AuditMutation) error
}

type Service struct {
	Repository CaseRepository
	Authorizer Authorizer
	Audit      AuditSink
	Now        func() time.Time
}

func NewService(repository CaseRepository, authorizer Authorizer, audit AuditSink) (*Service, error) {
	if repository == nil || authorizer == nil || audit == nil {
		return nil, ErrInvalid
	}
	return &Service{
		Repository: repository,
		Authorizer: authorizer,
		Audit:      audit,
		Now:        time.Now,
	}, nil
}

type CreateRequest struct {
	MutationID        MutationID
	TenantID          TenantID
	ActorID           PrincipalID
	CaseID            CaseID
	Title             ClassifiedText
	Description       ClassifiedText
	Severity          Severity
	AssigneeID        PrincipalID
	ContainmentSummary ClassifiedText
	RecoverySummary   ClassifiedText
	TimelineSummary   ClassifiedText
}

func (service *Service) Create(ctx context.Context, request CreateRequest) (IncidentCase, error) {
	now, err := service.mutationTime(request.MutationID, request.TenantID, request.ActorID, request.CaseID, 0, true)
	if err != nil {
		return IncidentCase{}, err
	}
	incident := IncidentCase{
		ID:                 request.CaseID,
		TenantID:           request.TenantID,
		Title:              request.Title,
		Description:        request.Description,
		Severity:           request.Severity,
		Status:             StatusOpen,
		AssigneeID:         request.AssigneeID,
		ContainmentSummary: request.ContainmentSummary,
		RecoverySummary:    request.RecoverySummary,
		Generation:         1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	entry := TimelineEntry{
		ID:             timelineID(request.MutationID),
		TenantID:       request.TenantID,
		CaseID:         request.CaseID,
		CaseGeneration: 1,
		Kind:           TimelineCreated,
		ActorID:        request.ActorID,
		Summary:        request.TimelineSummary,
		OccurredAt:     now,
	}
	if err = incident.Validate(); err != nil {
		return IncidentCase{}, err
	}
	if err = entry.Validate(request.TenantID, request.CaseID); err != nil {
		return IncidentCase{}, err
	}
	if err = service.authorize(ctx, AuthorizationRequest{request.TenantID, request.ActorID, ActionCreate, request.CaseID}); err != nil {
		return IncidentCase{}, err
	}
	redaction := strictestRedaction(request.Title.Redaction, request.Description.Redaction, request.ContainmentSummary.Redaction, request.RecoverySummary.Redaction, request.TimelineSummary.Redaction)
	if err = service.audit(ctx, request.MutationID, request.TenantID, request.CaseID, request.ActorID, ActionCreate, 0, 1, redaction, request, now); err != nil {
		return IncidentCase{}, err
	}
	return service.Repository.Create(ctx, incident, entry)
}

type GetRequest struct {
	TenantID TenantID
	ActorID  PrincipalID
	CaseID   CaseID
}

func (service *Service) Get(ctx context.Context, request GetRequest) (IncidentCase, error) {
	if err := service.readReady(request.TenantID, request.ActorID, request.CaseID); err != nil {
		return IncidentCase{}, err
	}
	if err := service.authorize(ctx, AuthorizationRequest{request.TenantID, request.ActorID, ActionRead, request.CaseID}); err != nil {
		return IncidentCase{}, err
	}
	return service.Repository.Get(ctx, request.TenantID, request.CaseID)
}

type ListRequest struct {
	TenantID TenantID
	ActorID  PrincipalID
	After    CaseID
	Limit    uint32
}

func (service *Service) List(ctx context.Context, request ListRequest) ([]IncidentCase, CaseID, error) {
	if service == nil || service.Repository == nil || service.Authorizer == nil || !validStableID(string(request.TenantID)) || !validStableID(string(request.ActorID)) || request.After != "" && !validStableID(string(request.After)) || request.Limit > MaximumListLimit {
		return nil, "", ErrInvalid
	}
	if err := service.authorize(ctx, AuthorizationRequest{request.TenantID, request.ActorID, ActionList, "incident:list"}); err != nil {
		return nil, "", err
	}
	return service.Repository.List(ctx, request.TenantID, request.After, request.Limit)
}

type AppendEvidenceRequest struct {
	MutationID        MutationID
	TenantID          TenantID
	ActorID           PrincipalID
	CaseID            CaseID
	ExpectedGeneration uint64
	Evidence          EvidenceLink
	TimelineSummary   ClassifiedText
}

func (service *Service) AppendEvidence(ctx context.Context, request AppendEvidenceRequest) (IncidentCase, error) {
	now, err := service.mutationTime(request.MutationID, request.TenantID, request.ActorID, request.CaseID, request.ExpectedGeneration, false)
	if err != nil {
		return IncidentCase{}, err
	}
	link := request.Evidence
	link.TenantID = request.TenantID
	link.CaseID = request.CaseID
	link.LinkedBy = request.ActorID
	link.LinkedAt = now
	entry := TimelineEntry{
		ID:             timelineID(request.MutationID),
		TenantID:       request.TenantID,
		CaseID:         request.CaseID,
		CaseGeneration: request.ExpectedGeneration + 1,
		Kind:           TimelineEvidenceLinked,
		ActorID:        request.ActorID,
		Summary:        request.TimelineSummary,
		OccurredAt:     now,
	}
	if err = link.Validate(request.TenantID, request.CaseID); err != nil {
		return IncidentCase{}, err
	}
	if err = entry.Validate(request.TenantID, request.CaseID); err != nil {
		return IncidentCase{}, err
	}
	if err = service.authorize(ctx, AuthorizationRequest{request.TenantID, request.ActorID, ActionLinkEvidence, request.CaseID}); err != nil {
		return IncidentCase{}, err
	}
	redaction := strictestRedaction(link.Redaction, request.TimelineSummary.Redaction)
	digestInput := struct {
		Expected uint64
		Evidence EvidenceLink
		Summary  ClassifiedText
	}{request.ExpectedGeneration, link, request.TimelineSummary}
	if err = service.audit(ctx, request.MutationID, request.TenantID, request.CaseID, request.ActorID, ActionLinkEvidence, request.ExpectedGeneration, request.ExpectedGeneration+1, redaction, digestInput, now); err != nil {
		return IncidentCase{}, err
	}
	return service.Repository.AppendEvidence(ctx, request.TenantID, request.CaseID, request.ExpectedGeneration, link, entry)
}

type AppendTimelineRequest struct {
	MutationID        MutationID
	TenantID          TenantID
	ActorID           PrincipalID
	CaseID            CaseID
	ExpectedGeneration uint64
	Summary           ClassifiedText
}

func (service *Service) AppendTimeline(ctx context.Context, request AppendTimelineRequest) (IncidentCase, error) {
	now, err := service.mutationTime(request.MutationID, request.TenantID, request.ActorID, request.CaseID, request.ExpectedGeneration, false)
	if err != nil {
		return IncidentCase{}, err
	}
	entry := TimelineEntry{
		ID:             timelineID(request.MutationID),
		TenantID:       request.TenantID,
		CaseID:         request.CaseID,
		CaseGeneration: request.ExpectedGeneration + 1,
		Kind:           TimelineNote,
		ActorID:        request.ActorID,
		Summary:        request.Summary,
		OccurredAt:     now,
	}
	if err = entry.Validate(request.TenantID, request.CaseID); err != nil {
		return IncidentCase{}, err
	}
	if err = service.authorize(ctx, AuthorizationRequest{request.TenantID, request.ActorID, ActionAppendTimeline, request.CaseID}); err != nil {
		return IncidentCase{}, err
	}
	if err = service.audit(ctx, request.MutationID, request.TenantID, request.CaseID, request.ActorID, ActionAppendTimeline, request.ExpectedGeneration, request.ExpectedGeneration+1, request.Summary.Redaction, request, now); err != nil {
		return IncidentCase{}, err
	}
	return service.Repository.AppendTimeline(ctx, request.TenantID, request.CaseID, request.ExpectedGeneration, entry)
}

type AssignRequest struct {
	MutationID        MutationID
	TenantID          TenantID
	ActorID           PrincipalID
	CaseID            CaseID
	ExpectedGeneration uint64
	AssigneeID        PrincipalID
	TimelineSummary   ClassifiedText
}

func (service *Service) Assign(ctx context.Context, request AssignRequest) (IncidentCase, error) {
	now, err := service.mutationTime(request.MutationID, request.TenantID, request.ActorID, request.CaseID, request.ExpectedGeneration, false)
	if err != nil || !request.AssigneeID.validOptional() {
		if err != nil {
			return IncidentCase{}, err
		}
		return IncidentCase{}, ErrInvalid
	}
	entry := TimelineEntry{
		ID:             timelineID(request.MutationID),
		TenantID:       request.TenantID,
		CaseID:         request.CaseID,
		CaseGeneration: request.ExpectedGeneration + 1,
		Kind:           TimelineAssigned,
		ActorID:        request.ActorID,
		Summary:        request.TimelineSummary,
		OccurredAt:     now,
	}
	if err = entry.Validate(request.TenantID, request.CaseID); err != nil {
		return IncidentCase{}, err
	}
	if err = service.authorize(ctx, AuthorizationRequest{request.TenantID, request.ActorID, ActionAssign, request.CaseID}); err != nil {
		return IncidentCase{}, err
	}
	if err = service.audit(ctx, request.MutationID, request.TenantID, request.CaseID, request.ActorID, ActionAssign, request.ExpectedGeneration, request.ExpectedGeneration+1, request.TimelineSummary.Redaction, request, now); err != nil {
		return IncidentCase{}, err
	}
	return service.Repository.Assign(ctx, request.TenantID, request.CaseID, request.ExpectedGeneration, request.AssigneeID, entry)
}

type TransitionRequest struct {
	MutationID        MutationID
	TenantID          TenantID
	ActorID           PrincipalID
	CaseID            CaseID
	ExpectedGeneration uint64
	Target            Status
	ContainmentSummary *ClassifiedText
	RecoverySummary   *ClassifiedText
	TimelineSummary   ClassifiedText
}

func (service *Service) Transition(ctx context.Context, request TransitionRequest) (IncidentCase, error) {
	now, err := service.mutationTime(request.MutationID, request.TenantID, request.ActorID, request.CaseID, request.ExpectedGeneration, false)
	if err != nil || !validStatus(request.Target) {
		if err != nil {
			return IncidentCase{}, err
		}
		return IncidentCase{}, ErrInvalid
	}
	if request.ContainmentSummary != nil && !validClassifiedText(*request.ContainmentSummary, 0, 8192) || request.RecoverySummary != nil && !validClassifiedText(*request.RecoverySummary, 0, 8192) {
		return IncidentCase{}, ErrInvalid
	}
	if err = service.authorize(ctx, AuthorizationRequest{request.TenantID, request.ActorID, ActionTransition, request.CaseID}); err != nil {
		return IncidentCase{}, err
	}
	current, err := service.Repository.Get(ctx, request.TenantID, request.CaseID)
	if err != nil {
		return IncidentCase{}, err
	}
	if current.Generation != request.ExpectedGeneration {
		return IncidentCase{}, ErrConflict
	}
	if !CanTransition(current.Status, request.Target) {
		return IncidentCase{}, ErrInvalid
	}
	entry := TimelineEntry{
		ID:             timelineID(request.MutationID),
		TenantID:       request.TenantID,
		CaseID:         request.CaseID,
		CaseGeneration: request.ExpectedGeneration + 1,
		Kind:           TimelineTransitioned,
		ActorID:        request.ActorID,
		FromStatus:     current.Status,
		ToStatus:       request.Target,
		Summary:        request.TimelineSummary,
		OccurredAt:     now,
	}
	if err = entry.Validate(request.TenantID, request.CaseID); err != nil {
		return IncidentCase{}, err
	}
	redactions := []RedactionClass{request.TimelineSummary.Redaction}
	if request.ContainmentSummary != nil {
		redactions = append(redactions, request.ContainmentSummary.Redaction)
	}
	if request.RecoverySummary != nil {
		redactions = append(redactions, request.RecoverySummary.Redaction)
	}
	if err = service.audit(ctx, request.MutationID, request.TenantID, request.CaseID, request.ActorID, ActionTransition, request.ExpectedGeneration, request.ExpectedGeneration+1, strictestRedaction(redactions...), request, now); err != nil {
		return IncidentCase{}, err
	}
	return service.Repository.Transition(ctx, request.TenantID, request.CaseID, request.ExpectedGeneration, request.Target, request.ContainmentSummary, request.RecoverySummary, entry)
}

func (service *Service) mutationTime(mutationID MutationID, tenantID TenantID, actorID PrincipalID, caseID CaseID, expected uint64, allowCreate bool) (time.Time, error) {
	if service == nil || service.Repository == nil || service.Authorizer == nil || service.Audit == nil || service.Now == nil || !validMutationID(mutationID) || !validStableID(string(tenantID)) || !validStableID(string(actorID)) || !validStableID(string(caseID)) {
		return time.Time{}, ErrInvalid
	}
	if allowCreate {
		if expected != 0 {
			return time.Time{}, ErrInvalid
		}
	} else {
		if expected == 0 {
			return time.Time{}, ErrInvalid
		}
		if expected >= MaximumTimelineEntries {
			return time.Time{}, ErrCapacity
		}
	}
	return service.Now().UTC(), nil
}

func (service *Service) readReady(tenantID TenantID, actorID PrincipalID, caseID CaseID) error {
	if service == nil || service.Repository == nil || service.Authorizer == nil || !validStableID(string(tenantID)) || !validStableID(string(actorID)) || !validStableID(string(caseID)) {
		return ErrInvalid
	}
	return nil
}

func (service *Service) authorize(ctx context.Context, request AuthorizationRequest) error {
	if err := service.Authorizer.Authorize(ctx, request); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

// audit runs before persistence so no case mutation can succeed unless its
// immutable request digest has first been accepted by the audit sink.
func (service *Service) audit(ctx context.Context, mutationID MutationID, tenantID TenantID, caseID CaseID, actorID PrincipalID, action Action, expected, next uint64, redaction RedactionClass, request any, recordedAt time.Time) error {
	digest, err := requestDigest(request)
	if err != nil {
		return err
	}
	event := AuditMutation{
		ID:                 mutationID,
		TenantID:           tenantID,
		CaseID:             caseID,
		ActorID:            actorID,
		Action:             action,
		ExpectedGeneration: expected,
		NextGeneration:     next,
		RequestDigest:      digest,
		Redaction:          redaction,
		RecordedAt:         recordedAt,
	}
	if !validMutationID(event.ID) || !validDigest(event.RequestDigest) || !validRedaction(event.Redaction) || event.RecordedAt.IsZero() || event.NextGeneration != event.ExpectedGeneration+1 {
		return ErrInvalid
	}
	return service.Audit.RecordMutation(ctx, event)
}

func requestDigest(request any) (string, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validMutationID(id MutationID) bool {
	return len(id) <= 182 && validStableID(string(id))
}

func timelineID(mutationID MutationID) TimelineID {
	return TimelineID("timeline:" + string(mutationID))
}

func strictestRedaction(classes ...RedactionClass) RedactionClass {
	strictest := RedactionPublic
	for _, class := range classes {
		if redactionRank(class) > redactionRank(strictest) {
			strictest = class
		}
	}
	return strictest
}

func redactionRank(class RedactionClass) int {
	switch class {
	case RedactionPublic:
		return 1
	case RedactionInternal:
		return 2
	case RedactionSensitive:
		return 3
	case RedactionRestricted:
		return 4
	default:
		return 0
	}
}
