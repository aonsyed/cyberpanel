package emailmarketing

import (
	"context"
	"strings"
	"time"
)

type CampaignRepository interface {
	PutMessageTemplate(context.Context, MessageTemplate, uint64, *MessageTemplateVersion) error
	GetMessageTemplate(context.Context, TenantID, TemplateID) (MessageTemplate, error)
	GetMessageTemplateVersion(context.Context, TenantID, TemplateID, uint64) (MessageTemplateVersion, error)
	ListMessageTemplates(context.Context, TenantID, TemplateID, int) ([]MessageTemplate, error)
	PutCampaign(context.Context, Campaign, uint64) error
	GetCampaign(context.Context, TenantID, CampaignID) (Campaign, error)
	ListCampaigns(context.Context, TenantID, CampaignID, int) ([]Campaign, error)
	FreezeCampaign(context.Context, Campaign, uint64, CampaignLimits) (Campaign, error)
	ActiveSuppressions(context.Context, TenantID, string) ([]SuppressionRecord, error)
	ListCampaignAttempts(context.Context, TenantID, CampaignID, AttemptID, int) ([]QueueAttempt, error)
	ListCampaignReceipts(context.Context, TenantID, CampaignID, string, int) ([]AttemptReceipt, error)
	CampaignStatistics(context.Context, TenantID, CampaignID, uint64, time.Time) (CampaignStatistics, error)
	CancelCampaignPendingAttempts(context.Context, TenantID, CampaignID, time.Time) error
}

type VerifiedSender struct {
	TenantID       TenantID
	Domain         string
	EvidenceDigest string
	VerifiedAt     time.Time
	ExpiresAt      time.Time
}

type SenderDomainVerifier interface {
	ResolveVerifiedSender(context.Context, TenantID, string) (VerifiedSender, error)
}

type DeliveryProfilePolicy interface {
	AuthorizeCampaignProfile(context.Context, TenantID, string) error
}

type CampaignService struct {
	Repository CampaignRepository
	Authorizer Authorizer
	StepUp     StepUpVerifier
	Audit      AuditSink
	Senders    SenderDomainVerifier
	Profiles   DeliveryProfilePolicy
	Limits     CampaignLimits
	Now        func() time.Time
}

func (service CampaignService) PutTemplate(ctx context.Context, access AdministrativeContext, template MessageTemplate, expected uint64, version *MessageTemplateVersion) error {
	request, err := service.authorize(ctx, access, "emailmarketing.template.write", string(template.ID), "message_content")
	if err != nil || template.TenantID != access.TenantID {
		return unauthorizedOr(err)
	}
	if expected > 0 {
		current, getErr := service.Repository.GetMessageTemplate(ctx, access.TenantID, template.ID)
		if getErr != nil || current.Generation != expected || current.Lifecycle != TemplateActive || template.Lifecycle != TemplateActive || template.LatestVersion < current.LatestVersion || template.LatestVersion > current.LatestVersion+1 {
			return staleOr(getErr)
		}
		if template.LatestVersion == current.LatestVersion && version != nil || template.LatestVersion == current.LatestVersion+1 && version == nil {
			return ErrInvalid
		}
	} else if template.Lifecycle != TemplateActive || template.LatestVersion != 1 {
		return ErrInvalid
	}
	if version != nil {
		version.TenantID, version.TemplateID, version.CreatedBy = template.TenantID, template.ID, access.ActorID
		sealed, sealErr := SealTemplateVersion(*version)
		if sealErr != nil {
			return sealErr
		}
		*version = sealed
	}
	if err = service.Repository.PutMessageTemplate(ctx, template, expected, version); err != nil {
		return err
	}
	return service.audit(ctx, request, "committed", digestObject(template))
}

func (service CampaignService) ListTemplates(ctx context.Context, access AdministrativeContext, after TemplateID, limit int) ([]MessageTemplate, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.template.read", string(access.TenantID), "message_content")
	if err != nil {
		return nil, err
	}
	result, err := service.Repository.ListMessageTemplates(ctx, access.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	err = service.audit(ctx, request, "read", DigestEvidence([]byte(after)))
	return result, err
}

func (service CampaignService) InspectTemplate(ctx context.Context, access AdministrativeContext, id TemplateID, version uint64) (MessageTemplate, MessageTemplateVersion, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.template.read", string(id), "message_content")
	if err != nil {
		return MessageTemplate{}, MessageTemplateVersion{}, err
	}
	template, err := service.Repository.GetMessageTemplate(ctx, access.TenantID, id)
	if err != nil {
		return MessageTemplate{}, MessageTemplateVersion{}, err
	}
	if version == 0 {
		version = template.LatestVersion
	}
	templateVersion, err := service.Repository.GetMessageTemplateVersion(ctx, access.TenantID, id, version)
	if err != nil {
		return MessageTemplate{}, MessageTemplateVersion{}, err
	}
	if err = service.audit(ctx, request, "read", templateVersion.Digest); err != nil {
		return MessageTemplate{}, MessageTemplateVersion{}, err
	}
	return template, templateVersion, nil
}

func (service CampaignService) PreviewTemplate(ctx context.Context, access AdministrativeContext, input TemplateRenderRequest) (TemplatePreview, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.template.preview", string(input.TemplateID), "message_content")
	if err != nil || input.TenantID != access.TenantID || input.RequestedBy != access.ActorID {
		return TemplatePreview{}, unauthorizedOr(err)
	}
	version, err := service.Repository.GetMessageTemplateVersion(ctx, input.TenantID, input.TemplateID, input.TemplateVersion)
	if err != nil {
		return TemplatePreview{}, err
	}
	preview, err := RenderTemplate(version, input, service.Now().UTC())
	if err != nil {
		return TemplatePreview{}, err
	}
	if err = service.audit(ctx, request, "rendered", preview.RequestDigest); err != nil {
		return TemplatePreview{}, err
	}
	return preview, nil
}

func (service CampaignService) SetTemplateLifecycle(ctx context.Context, access AdministrativeContext, id TemplateID, expected uint64, lifecycle TemplateLifecycle, deleteAfter *time.Time, stepUpProof string) error {
	if lifecycle != TemplateArchived && lifecycle != TemplateDeleted {
		return ErrInvalid
	}
	request, err := service.authorize(ctx, access, "emailmarketing.template.lifecycle", string(id), "message_content")
	if err != nil {
		return err
	}
	if _, err = service.requireStepUp(ctx, request, stepUpProof); err != nil {
		return err
	}
	template, err := service.Repository.GetMessageTemplate(ctx, access.TenantID, id)
	if err != nil || template.Generation != expected {
		return staleOr(err)
	}
	if template.Lifecycle == TemplateDeleted || lifecycle == TemplateArchived && template.Lifecycle != TemplateActive {
		return ErrInvalid
	}
	now := service.Now().UTC()
	template.Generation, template.Lifecycle, template.UpdatedAt = expected+1, lifecycle, now
	if lifecycle == TemplateArchived {
		template.ArchivedAt, template.DeleteAfter = timePointer(now), nil
	} else {
		if deleteAfter == nil || !deleteAfter.After(now) {
			return ErrInvalid
		}
		template.DeleteAfter = timePointer(deleteAfter.UTC())
		if template.ArchivedAt == nil {
			template.ArchivedAt = timePointer(now)
		}
	}
	if err = service.Repository.PutMessageTemplate(ctx, template, expected, nil); err != nil {
		return err
	}
	return service.audit(ctx, request, string(lifecycle), digestObject(template))
}

func (service CampaignService) PutCampaign(ctx context.Context, access AdministrativeContext, campaign Campaign, expected uint64) error {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.write", string(campaign.ID), "campaign_policy")
	if err != nil || campaign.TenantID != access.TenantID || campaign.CreatedBy != access.ActorID || service.Limits.validate() != nil {
		return unauthorizedOr(err)
	}
	now := service.Now().UTC()
	if expected == 0 {
		if campaign.State != CampaignDraft || campaign.Generation != 1 || campaign.Revision != 1 || campaign.CreatedAt.IsZero() || campaign.UpdatedAt.Before(campaign.CreatedAt) {
			return ErrInvalid
		}
	} else {
		current, getErr := service.Repository.GetCampaign(ctx, access.TenantID, campaign.ID)
		if getErr != nil || current.Generation != expected || current.State != CampaignDraft || campaign.State != CampaignDraft || campaign.Revision != current.Revision+1 || campaign.CreatedBy != current.CreatedBy || campaign.CreatedAt != current.CreatedAt {
			return staleOr(getErr)
		}
		campaign.Generation = expected + 1
		campaign.UpdatedAt = now
	}
	if err = service.validateCampaignBindings(ctx, campaign, now); err != nil {
		return err
	}
	if err = service.Repository.PutCampaign(ctx, campaign, expected); err != nil {
		return err
	}
	return service.audit(ctx, request, "committed", digestObject(campaign))
}

func (service CampaignService) ApproveCampaign(ctx context.Context, access AdministrativeContext, id CampaignID, expected uint64, stepUpProof string) (Campaign, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.approve", string(id), "contact_and_campaign")
	if err != nil {
		return Campaign{}, err
	}
	receipt, err := service.requireStepUp(ctx, request, stepUpProof)
	if err != nil {
		return Campaign{}, err
	}
	campaign, err := service.Repository.GetCampaign(ctx, access.TenantID, id)
	if err != nil || campaign.Generation != expected || campaign.State != CampaignDraft || campaign.CreatedBy == access.ActorID {
		return Campaign{}, staleOr(err)
	}
	if err = service.validateCampaignBindings(ctx, campaign, service.Now().UTC()); err != nil {
		return Campaign{}, err
	}
	for _, approval := range campaign.Approvals {
		if approval.Approver == access.ActorID {
			return Campaign{}, ErrConflict
		}
	}
	now := service.Now().UTC()
	campaign.Approvals = []CampaignApprovalRecord{{Approver: access.ActorID, StepUpReceipt: receipt, EvidenceDigest: digestObject(struct {
		Campaign CampaignID
		Revision uint64
		Actor ActorID
	}{campaign.ID, campaign.Revision, access.ActorID}), ApprovedAt: now}}
	campaign.UpdatedAt = now
	frozen, err := service.Repository.FreezeCampaign(ctx, campaign, expected, service.Limits)
	if err != nil {
		return Campaign{}, err
	}
	if err = service.audit(ctx, request, "snapshot_frozen", frozen.SnapshotDigest); err != nil {
		return Campaign{}, err
	}
	return frozen, nil
}

func (service CampaignService) AddCampaignApproval(ctx context.Context, access AdministrativeContext, id CampaignID, expected uint64, stepUpProof string) (Campaign, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.approve", string(id), "contact_and_campaign")
	if err != nil {
		return Campaign{}, err
	}
	receipt, err := service.requireStepUp(ctx, request, stepUpProof)
	if err != nil {
		return Campaign{}, err
	}
	campaign, err := service.Repository.GetCampaign(ctx, access.TenantID, id)
	if err != nil || campaign.Generation != expected || campaign.State != CampaignApproval || campaign.CreatedBy == access.ActorID {
		return Campaign{}, staleOr(err)
	}
	for _, approval := range campaign.Approvals {
		if approval.Approver == access.ActorID {
			return Campaign{}, ErrConflict
		}
	}
	now := service.Now().UTC()
	campaign.Approvals = append(campaign.Approvals, CampaignApprovalRecord{Approver: access.ActorID, StepUpReceipt: receipt, EvidenceDigest: DigestEvidence([]byte(receipt)), ApprovedAt: now})
	campaign.Generation, campaign.UpdatedAt = expected+1, now
	if err = service.Repository.PutCampaign(ctx, campaign, expected); err != nil {
		return Campaign{}, err
	}
	err = service.audit(ctx, request, "approved", campaign.SnapshotDigest)
	return campaign, err
}

func (service CampaignService) SetCampaignState(ctx context.Context, access AdministrativeContext, id CampaignID, expected uint64, target CampaignState, scheduleAt *time.Time, stepUpProof string) (Campaign, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.lifecycle", string(id), "contact_and_campaign")
	if err != nil {
		return Campaign{}, err
	}
	if target == CampaignCancelled || target == CampaignArchived || target == CampaignRunning {
		if _, err = service.requireStepUp(ctx, request, stepUpProof); err != nil {
			return Campaign{}, err
		}
	}
	campaign, err := service.Repository.GetCampaign(ctx, access.TenantID, id)
	if err != nil || campaign.Generation != expected || !campaignTransitionAllowed(campaign.State, target) {
		return Campaign{}, staleOr(err)
	}
	now := service.Now().UTC()
	if target == CampaignScheduled {
		if scheduleAt == nil || !scheduleAt.After(now) || len(campaign.Approvals) < int(service.Limits.MinimumApprovals) {
			return Campaign{}, ErrInvalid
		}
		campaign.ScheduleAt = timePointer(scheduleAt.UTC())
	}
	if target == CampaignRunning {
		if len(campaign.Approvals) < int(service.Limits.MinimumApprovals) || campaign.ScheduleAt != nil && campaign.ScheduleAt.After(now) {
			return Campaign{}, ErrUnauthorized
		}
	}
	if target == CampaignArchived {
		campaign.ArchivedAt = timePointer(now)
	}
	campaign.State, campaign.Generation, campaign.UpdatedAt = target, expected+1, now
	if err = service.Repository.PutCampaign(ctx, campaign, expected); err != nil {
		return Campaign{}, err
	}
	if target == CampaignCancelled {
		if err = service.Repository.CancelCampaignPendingAttempts(ctx, campaign.TenantID, campaign.ID, now); err != nil {
			return Campaign{}, err
		}
	}
	err = service.audit(ctx, request, string(target), campaign.SnapshotDigest)
	return campaign, err
}

func (service CampaignService) CloneCampaign(ctx context.Context, access AdministrativeContext, sourceID, newID CampaignID) (Campaign, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.clone", string(sourceID), "campaign_policy")
	if err != nil {
		return Campaign{}, err
	}
	source, err := service.Repository.GetCampaign(ctx, access.TenantID, sourceID)
	if err != nil {
		return Campaign{}, err
	}
	if validateIdentifier(string(newID)) != nil {
		return Campaign{}, ErrInvalid
	}
	now := service.Now().UTC()
	clone := source
	clone.ID, clone.State, clone.Generation, clone.Revision = newID, CampaignDraft, 1, 1
	clone.PolicyDigest, clone.TemplateDigest, clone.SnapshotDigest, clone.RecipientCount = "", "", "", 0
	clone.Approvals, clone.ScheduleAt, clone.ArchivedAt = nil, nil, nil
	clone.CreatedBy, clone.CreatedAt, clone.UpdatedAt, clone.ClonedFrom = access.ActorID, now, now, source.ID
	if err = service.validateCampaignBindings(ctx, clone, now); err != nil {
		return Campaign{}, err
	}
	if err = service.Repository.PutCampaign(ctx, clone, 0); err != nil {
		return Campaign{}, err
	}
	err = service.audit(ctx, request, "cloned", digestObject(clone))
	return clone, err
}

func (service CampaignService) ListCampaigns(ctx context.Context, access AdministrativeContext, after CampaignID, limit int) ([]Campaign, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.read", string(access.TenantID), "campaign_policy")
	if err != nil {
		return nil, err
	}
	result, err := service.Repository.ListCampaigns(ctx, access.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	err = service.audit(ctx, request, "read", DigestEvidence([]byte(after)))
	return result, err
}

func (service CampaignService) InspectCampaign(ctx context.Context, access AdministrativeContext, id CampaignID) (Campaign, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.read", string(id), "campaign_policy")
	if err != nil {
		return Campaign{}, err
	}
	campaign, err := service.Repository.GetCampaign(ctx, access.TenantID, id)
	if err != nil {
		return Campaign{}, err
	}
	if err = service.audit(ctx, request, "read", digestObject(struct {
		ID CampaignID
		Generation uint64
		Revision uint64
	}{id, campaign.Generation, campaign.Revision})); err != nil {
		return Campaign{}, err
	}
	return campaign, nil
}

func (service CampaignService) ListAttempts(ctx context.Context, access AdministrativeContext, campaign CampaignID, after AttemptID, limit int) ([]QueueAttempt, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.attempts", string(campaign), "delivery_metadata")
	if err != nil {
		return nil, err
	}
	result, err := service.Repository.ListCampaignAttempts(ctx, access.TenantID, campaign, after, limit)
	if err != nil {
		return nil, err
	}
	err = service.audit(ctx, request, "read", DigestEvidence([]byte(after)))
	return result, err
}

func (service CampaignService) ListReceipts(ctx context.Context, access AdministrativeContext, campaign CampaignID, after string, limit int) ([]AttemptReceipt, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.receipts", string(campaign), "delivery_metadata")
	if err != nil {
		return nil, err
	}
	result, err := service.Repository.ListCampaignReceipts(ctx, access.TenantID, campaign, after, limit)
	if err != nil {
		return nil, err
	}
	err = service.audit(ctx, request, "read", DigestEvidence([]byte(after)))
	return result, err
}

func (service CampaignService) Statistics(ctx context.Context, access AdministrativeContext, campaign CampaignID) (CampaignStatistics, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.statistics", string(campaign), "aggregate_delivery_metadata")
	if err != nil {
		return CampaignStatistics{}, err
	}
	statistics, err := service.Repository.CampaignStatistics(ctx, access.TenantID, campaign, service.Limits.MinimumReportPopulation, service.Now().UTC())
	if err != nil {
		return CampaignStatistics{}, err
	}
	err = service.audit(ctx, request, "read", digestObject(struct {
		Campaign CampaignID
		Denominator uint64
		AsOf time.Time
	}{campaign, statistics.Denominator, statistics.AsOf}))
	return statistics, err
}

func (service CampaignService) TestSend(ctx context.Context, access AdministrativeContext, input TestSendRequest, provider DeliveryProvider) (ProviderResult, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.template.test_send", string(input.RenderRequest.TemplateID), "message_content")
	if err != nil || provider == nil || input.RenderRequest.TenantID != access.TenantID || input.RenderRequest.RequestedBy != access.ActorID || strings.TrimSpace(input.Reason) == "" {
		return ProviderResult{}, unauthorizedOr(err)
	}
	if _, err = service.requireStepUp(ctx, request, input.StepUpProof); err != nil {
		return ProviderResult{}, err
	}
	recipient, err := NormalizeAddress(input.Recipient)
	if err != nil {
		return ProviderResult{}, ErrInvalid
	}
	suppressions, err := service.Repository.ActiveSuppressions(ctx, access.TenantID, recipient.Digest)
	if err != nil || len(suppressions) != 0 {
		if err != nil {
			return ProviderResult{}, err
		}
		return ProviderResult{}, ErrSuppressed
	}
	version, err := service.Repository.GetMessageTemplateVersion(ctx, access.TenantID, input.RenderRequest.TemplateID, input.RenderRequest.TemplateVersion)
	if err != nil {
		return ProviderResult{}, err
	}
	preview, err := RenderTemplate(version, input.RenderRequest, service.Now().UTC())
	if err != nil {
		return ProviderResult{}, err
	}
	if validateIdentifier(input.ProviderRef) != nil || service.Profiles == nil || service.Senders == nil || service.Profiles.AuthorizeCampaignProfile(ctx, access.TenantID, input.ProviderRef) != nil {
		return ProviderResult{}, ErrUnauthorized
	}
	domain, err := mailboxDomain(preview.From)
	if err != nil || domain != strings.ToLower(input.VerifiedSenderDomain) {
		return ProviderResult{}, ErrInvalid
	}
	verified, err := service.Senders.ResolveVerifiedSender(ctx, access.TenantID, domain)
	if err != nil || verified.TenantID != access.TenantID || verified.Domain != domain || !validDigest(verified.EvidenceDigest) || verified.EvidenceDigest != input.SenderVerificationDigest || verified.VerifiedAt.IsZero() || !verified.ExpiresAt.After(service.Now()) {
		return ProviderResult{}, ErrUnauthorized
	}
	idempotencyKey := "test:" + preview.RequestDigest[:40]
	result, sendErr := provider.Send(ctx, DeliveryEnvelope{TenantID: access.TenantID, IdempotencyKey: idempotencyKey, Recipient: recipient.Normalized, Subject: preview.Subject, From: preview.From, ReplyTo: preview.ReplyTo, TextBody: preview.TextBody, HTMLBody: preview.HTMLBody, ProviderRef: input.ProviderRef, Test: true})
	outcome := "provider_result"
	if sendErr != nil {
		outcome = "provider_error"
	}
	if auditErr := service.audit(ctx, request, outcome, preview.RequestDigest); auditErr != nil {
		return ProviderResult{}, auditErr
	}
	return result, sendErr
}

func (service CampaignService) validateCampaignBindings(ctx context.Context, campaign Campaign, now time.Time) error {
	if campaign.RatePerMinute > service.Limits.MaxRatePerMinute || campaign.Concurrency > service.Limits.MaxConcurrency || service.Senders == nil || service.Profiles == nil {
		return ErrInvalid
	}
	version, err := service.Repository.GetMessageTemplateVersion(ctx, campaign.TenantID, campaign.TemplateID, campaign.TemplateVersion)
	if err != nil {
		return err
	}
	template, err := service.Repository.GetMessageTemplate(ctx, campaign.TenantID, campaign.TemplateID)
	if err != nil || template.Lifecycle != TemplateActive || template.LatestVersion < campaign.TemplateVersion {
		return ErrInvalid
	}
	variables := make(map[string]string, len(campaign.TemplateVariables)+1)
	for name, value := range campaign.TemplateVariables {
		variables[name] = value
	}
	for _, name := range version.Variables {
		if name == "recipient_email" {
			variables[name] = "recipient@example.invalid"
		}
	}
	if _, err = RenderTemplate(version, TemplateRenderRequest{TenantID: campaign.TenantID, TemplateID: campaign.TemplateID, TemplateVersion: campaign.TemplateVersion, Variables: variables, RequestedBy: "campaign_validator", RequestedAt: now, Purpose: campaign.Consent.Purpose}, now); err != nil {
		return ErrInvalid
	}
	if campaign.SubjectOverride != "" {
		if validateTemplateTokens(campaign.SubjectOverride, version.Variables) != nil || validateHeaderValue(renderClosed(campaign.SubjectOverride, variables, false), 998) != nil {
			return ErrInvalid
		}
	}
	if _, err = time.LoadLocation(campaign.Timezone); err != nil {
		return ErrInvalid
	}
	from := campaign.From
	if from == "" {
		from = version.From
		campaign.From = from
	}
	domain, err := mailboxDomain(from)
	if err != nil || domain != strings.ToLower(campaign.VerifiedSenderDomain) {
		return ErrInvalid
	}
	if campaign.ReplyTo != "" && validateMailbox(campaign.ReplyTo) != nil {
		return ErrInvalid
	}
	verified, err := service.Senders.ResolveVerifiedSender(ctx, campaign.TenantID, domain)
	if err != nil || verified.TenantID != campaign.TenantID || verified.Domain != domain || !validDigest(verified.EvidenceDigest) || verified.VerifiedAt.IsZero() || !verified.ExpiresAt.After(now) || verified.EvidenceDigest != campaign.SenderVerificationDigest {
		return ErrUnauthorized
	}
	if err = service.Profiles.AuthorizeCampaignProfile(ctx, campaign.TenantID, campaign.DeliveryProfileRef); err != nil {
		return ErrUnauthorized
	}
	return nil
}

func (service CampaignService) authorize(ctx context.Context, access AdministrativeContext, action, resource, dataClass string) (AuthorizationRequest, error) {
	request := AuthorizationRequest{TenantID: access.TenantID, ActorID: access.ActorID, Action: action, Resource: resource, DataClass: dataClass}
	if service.Repository == nil || service.Authorizer == nil || service.Audit == nil || service.Now == nil || service.Limits.validate() != nil || validateIdentifier(string(access.TenantID)) != nil || validateIdentifier(string(access.ActorID)) != nil || resource == "" {
		return request, ErrUnauthorized
	}
	if err := service.Authorizer.Authorize(ctx, request); err != nil {
		return request, ErrUnauthorized
	}
	return request, nil
}

func (service CampaignService) requireStepUp(ctx context.Context, request AuthorizationRequest, proof string) (string, error) {
	if service.StepUp == nil || proof == "" {
		return "", ErrUnauthorized
	}
	receipt, err := service.StepUp.VerifyStepUp(ctx, request, proof)
	if err != nil || receipt == "" {
		return "", ErrUnauthorized
	}
	return receipt, nil
}

func (service CampaignService) audit(ctx context.Context, request AuthorizationRequest, outcome, evidence string) error {
	return service.Audit.RecordAudit(ctx, AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: outcome, EvidenceDigest: evidence, OccurredAt: service.Now().UTC()})
}

func campaignTransitionAllowed(from, to CampaignState) bool {
	switch from {
	case CampaignApproval:
		return to == CampaignScheduled || to == CampaignRunning || to == CampaignCancelled
	case CampaignScheduled:
		return to == CampaignRunning || to == CampaignCancelled
	case CampaignRunning:
		return to == CampaignPaused || to == CampaignCancelled
	case CampaignPaused:
		return to == CampaignRunning || to == CampaignCancelled
	case CampaignCancelled, CampaignCompleted:
		return to == CampaignArchived
	default:
		return false
	}
}
