package emailmarketing

import (
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type TemplateID string
type CampaignID string
type AttemptID string

type TemplateLifecycle string

const (
	TemplateActive   TemplateLifecycle = "active"
	TemplateArchived TemplateLifecycle = "archived"
	TemplateDeleted  TemplateLifecycle = "deleted"
)

// MessageTemplate is the mutable identity of a template. Its versions are
// immutable and independently addressable.
type MessageTemplate struct {
	TenantID      TenantID
	ID            TemplateID
	Name          string
	Lifecycle     TemplateLifecycle
	LatestVersion uint64
	Generation    uint64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ArchivedAt    *time.Time
	DeleteAfter   *time.Time
}

type MessageTemplateVersion struct {
	TenantID    TenantID
	TemplateID  TemplateID
	Version     uint64
	Subject     string
	From        string
	ReplyTo     string
	TextBody    string
	HTMLBody    string
	Variables   []string
	Digest      string
	CreatedBy   ActorID
	CreatedAt   time.Time
}

type TemplateRenderRequest struct {
	TenantID       TenantID
	TemplateID     TemplateID
	TemplateVersion uint64
	Variables      map[string]string
	RequestedBy    ActorID
	RequestedAt    time.Time
	Purpose        string
}

type TemplatePreview struct {
	RequestDigest string
	Subject       string
	From          string
	ReplyTo       string
	TextBody      string
	HTMLBody      string
	TemplateDigest string
	RenderedAt    time.Time
}

type TestSendRequest struct {
	RenderRequest TemplateRenderRequest
	Recipient     string
	ProviderRef   string
	VerifiedSenderDomain string
	SenderVerificationDigest string
	Reason        string
	StepUpProof   string
}

type CampaignState string

const (
	CampaignDraft     CampaignState = "draft"
	CampaignApproval  CampaignState = "approval"
	CampaignScheduled CampaignState = "scheduled"
	CampaignRunning   CampaignState = "running"
	CampaignPaused    CampaignState = "paused"
	CampaignCancelled CampaignState = "cancelled"
	CampaignCompleted CampaignState = "completed"
	CampaignArchived  CampaignState = "archived"
)

type TrackingPolicy string

const (
	TrackingNone       TrackingPolicy = "none"
	TrackingAggregate  TrackingPolicy = "aggregate"
	TrackingIndividual TrackingPolicy = "individual_with_consent"
)

type ConsentPolicy struct {
	Purpose                  string
	RequireAffirmative       bool
	RequireExactEvidence     bool
	AllowIndividualTracking  bool
}

type ListSegment struct {
	ListID          ListID
	RequireTagIDs   []TagID
	ExcludeTagIDs   []TagID
}

type CampaignApprovalRecord struct {
	Approver       ActorID
	StepUpReceipt  string
	EvidenceDigest string
	ApprovedAt     time.Time
}

type Campaign struct {
	TenantID             TenantID
	ID                   CampaignID
	Name                 string
	State                CampaignState
	Generation           uint64
	Revision             uint64
	Segments             []ListSegment
	TemplateID           TemplateID
	TemplateVersion      uint64
	TemplateVariables    map[string]string
	SubjectOverride      string
	From                  string
	ReplyTo               string
	VerifiedSenderDomain  string
	SenderVerificationDigest string
	DeliveryProfileRef   string
	ScheduleAt           *time.Time
	Timezone             string
	RatePerMinute         uint32
	Concurrency           uint16
	Tracking              TrackingPolicy
	Consent               ConsentPolicy
	PolicyDigest          string
	TemplateDigest        string
	SnapshotDigest        string
	RecipientCount        uint64
	Approvals             []CampaignApprovalRecord
	CreatedBy             ActorID
	CreatedAt             time.Time
	UpdatedAt             time.Time
	ArchivedAt            *time.Time
	ClonedFrom            CampaignID
}

type FrozenRecipient struct {
	TenantID       TenantID
	CampaignID     CampaignID
	CampaignRevision uint64
	Ordinal        uint64
	SubscriberID   SubscriberID
	ListID         ListID
	Address        AddressIdentity
	ConsentID      string
	ConsentDigest  string
	SnapshotDigest string
}

type AttemptStatus string

const (
	AttemptQueued     AttemptStatus = "queued"
	AttemptSent       AttemptStatus = "sent"
	AttemptDelivered  AttemptStatus = "delivered"
	AttemptDeferred   AttemptStatus = "deferred"
	AttemptBounced    AttemptStatus = "bounced"
	AttemptComplained AttemptStatus = "complained"
	AttemptSuppressed AttemptStatus = "suppressed"
	AttemptFailed     AttemptStatus = "failed"
)

type QueueAttempt struct {
	TenantID          TenantID
	CampaignID        CampaignID
	CampaignRevision  uint64
	ID                AttemptID
	RecipientOrdinal  uint64
	Status            AttemptStatus
	AttemptNumber     uint32
	NextAttemptAt     time.Time
	LeaseOwner        string
	LeaseExpiresAt    time.Time
	Fence              uint64
	ProviderRef       string
	ProviderMessageID string
	Reason             string
	AwaitingReceipt    bool
	UpdatedAt          time.Time
}

type AttemptReceipt struct {
	ID                string
	TenantID          TenantID
	CampaignID        CampaignID
	AttemptID         AttemptID
	Status            AttemptStatus
	ProviderRef       string
	ProviderMessageID string
	Provenance        string
	Reason            string
	DelayedEvent      bool
	ObservedAt        time.Time
}

type CampaignStatistics struct {
	CampaignID      CampaignID
	Denominator     uint64
	Queued          uint64
	Sent            uint64
	Delivered       uint64
	Deferred        uint64
	Bounced         uint64
	Complained      uint64
	Suppressed      uint64
	Failed          uint64
	DelayedEvents   uint64
	AwaitingReceipts uint64
	SmallCohort     bool
	AsOf            time.Time
}

type CampaignLimits struct {
	MaxRecipientsPerCampaign uint64
	MaxQueuedPerTenant        uint64
	MaxRatePerMinute          uint32
	MaxConcurrency            uint16
	MinimumApprovals          uint8
	MinimumReportPopulation   uint64
}

func (limits CampaignLimits) validate() error {
	if limits.MaxRecipientsPerCampaign == 0 || limits.MaxQueuedPerTenant < limits.MaxRecipientsPerCampaign ||
		limits.MaxRatePerMinute == 0 || limits.MaxConcurrency == 0 || limits.MinimumApprovals == 0 || limits.MinimumApprovals > 8 || limits.MinimumReportPopulation == 0 {
		return ErrInvalid
	}
	return nil
}

func validateCampaign(c Campaign, expected uint64) error {
	if validateIdentifier(string(c.TenantID)) != nil || validateIdentifier(string(c.ID)) != nil || validateIdentifier(string(c.CreatedBy)) != nil ||
		c.Name == "" || len(c.Name) > maxNameBytes || c.Generation != expected+1 || c.Revision == 0 || c.CreatedAt.IsZero() || c.UpdatedAt.Before(c.CreatedAt) ||
		validateIdentifier(string(c.TemplateID)) != nil || c.TemplateVersion == 0 || len(c.Segments) == 0 || len(c.Segments) > 64 ||
		validateHeaderValue(c.From, 320) != nil || (c.ReplyTo != "" && validateHeaderValue(c.ReplyTo, 320) != nil) ||
		validateIdentifier(c.DeliveryProfileRef) != nil || validateIdentifier(c.VerifiedSenderDomain) != nil || !validDigest(c.SenderVerificationDigest) ||
		c.Timezone == "" || len(c.Timezone) > 128 || c.RatePerMinute == 0 || c.Concurrency == 0 || validateCampaignState(c.State) != nil ||
		validateConsentPolicy(c.Consent) != nil {
		return ErrInvalid
	}
	if c.SubjectOverride != "" && validateHeaderValue(c.SubjectOverride, 998) != nil {
		return ErrInvalid
	}
	if len(c.TemplateVariables) > maxTemplateVariables {
		return ErrInvalid
	}
	for name, value := range c.TemplateVariables {
		if !variableNamePattern.MatchString(name) || secretLikeVariable(name) || name == "recipient_email" || len(value) > 64*1024 || !utf8.ValidString(value) || hasForbiddenControl(value) {
			return ErrInvalid
		}
	}
	if c.Tracking != TrackingNone && c.Tracking != TrackingAggregate && c.Tracking != TrackingIndividual {
		return ErrInvalid
	}
	if c.Tracking == TrackingIndividual && (!c.Consent.AllowIndividualTracking || !c.Consent.RequireAffirmative) {
		return ErrInvalid
	}
	if c.ScheduleAt != nil && c.ScheduleAt.IsZero() {
		return ErrInvalid
	}
	seen := make(map[ListID]struct{}, len(c.Segments))
	for i := range c.Segments {
		segment := &c.Segments[i]
		if validateIdentifier(string(segment.ListID)) != nil {
			return ErrInvalid
		}
		if _, duplicate := seen[segment.ListID]; duplicate {
			return ErrInvalid
		}
		seen[segment.ListID] = struct{}{}
		var err error
		segment.RequireTagIDs, err = normalizeTags(segment.RequireTagIDs)
		if err != nil {
			return ErrInvalid
		}
		segment.ExcludeTagIDs, err = normalizeTags(segment.ExcludeTagIDs)
		if err != nil || intersectsTags(segment.RequireTagIDs, segment.ExcludeTagIDs) {
			return ErrInvalid
		}
	}
	if c.State == CampaignDraft {
		if c.PolicyDigest != "" || c.TemplateDigest != "" || c.SnapshotDigest != "" || c.RecipientCount != 0 || len(c.Approvals) != 0 {
			return ErrInvalid
		}
	} else if !validDigest(c.PolicyDigest) || !validDigest(c.TemplateDigest) || !validDigest(c.SnapshotDigest) || !approvalAppendOnly(nil, c.Approvals) {
		return ErrInvalid
	}
	if c.State == CampaignArchived && c.ArchivedAt == nil {
		return ErrInvalid
	}
	return nil
}

func validateCampaignState(state CampaignState) error {
	switch state {
	case CampaignDraft, CampaignApproval, CampaignScheduled, CampaignRunning, CampaignPaused, CampaignCancelled, CampaignCompleted, CampaignArchived:
		return nil
	default:
		return ErrInvalid
	}
}

func validateConsentPolicy(policy ConsentPolicy) error {
	if strings.TrimSpace(policy.Purpose) == "" || len(policy.Purpose) > maxPurposeBytes {
		return ErrInvalid
	}
	return nil
}

func intersectsTags(left, right []TagID) bool {
	seen := make(map[TagID]struct{}, len(left))
	for _, id := range left {
		seen[id] = struct{}{}
	}
	for _, id := range right {
		if _, ok := seen[id]; ok {
			return true
		}
	}
	return false
}

func normalizeSegments(segments []ListSegment) ([]ListSegment, error) {
	result := append([]ListSegment(nil), segments...)
	for i := range result {
		var err error
		result[i].RequireTagIDs, err = normalizeTags(result[i].RequireTagIDs)
		if err != nil {
			return nil, err
		}
		result[i].ExcludeTagIDs, err = normalizeTags(result[i].ExcludeTagIDs)
		if err != nil || intersectsTags(result[i].RequireTagIDs, result[i].ExcludeTagIDs) {
			return nil, errors.New("emailmarketing: invalid segment")
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ListID < result[j].ListID })
	return result, nil
}
