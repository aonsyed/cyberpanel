package emailmarketing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type ProviderAvailability struct {
	Online        bool
	RetryAfter    time.Duration
	EvidenceDigest string
}

type ProviderDisposition string

const (
	ProviderAccepted  ProviderDisposition = "accepted"
	ProviderDelivered ProviderDisposition = "delivered"
	ProviderDeferred  ProviderDisposition = "deferred"
	ProviderRejected  ProviderDisposition = "rejected"
	ProviderUnknown   ProviderDisposition = "unknown"
)

type ProviderResult struct {
	Disposition      ProviderDisposition
	ProviderMessageID string
	Reason           string
	RetryAfter       time.Duration
	Definitive       bool
}

type DeliveryEnvelope struct {
	TenantID      TenantID
	CampaignID    CampaignID
	AttemptID     AttemptID
	IdempotencyKey string
	Recipient     string
	Subject       string
	From          string
	ReplyTo       string
	TextBody      string
	HTMLBody      string
	ProviderRef   string
	Test          bool
}

// DeliveryProvider is the only delivery seam. Implementations must bind the
// supplied idempotency key to at most one provider submission.
type DeliveryProvider interface {
	Availability(context.Context, TenantID, string) (ProviderAvailability, error)
	Send(context.Context, DeliveryEnvelope) (ProviderResult, error)
}

type QueueLimits struct {
	TotalDeliveryConcurrency   uint32
	ReservedTransactionalSlots uint32
	MaxCampaignConcurrency     uint32
	MaxTenantConcurrency       uint32
	LeaseDuration              time.Duration
	ProviderOfflineDelay       time.Duration
	RetryBase                  time.Duration
	RetryMaximum               time.Duration
	MaxAttempts                uint32
}

func (limits QueueLimits) validate() error {
	available := limits.TotalDeliveryConcurrency - limits.ReservedTransactionalSlots
	if limits.TotalDeliveryConcurrency == 0 || limits.ReservedTransactionalSlots == 0 || limits.ReservedTransactionalSlots >= limits.TotalDeliveryConcurrency ||
		limits.MaxCampaignConcurrency == 0 || limits.MaxCampaignConcurrency > available || limits.MaxTenantConcurrency == 0 || limits.MaxTenantConcurrency > limits.MaxCampaignConcurrency ||
		limits.LeaseDuration < time.Second || limits.LeaseDuration > 15*time.Minute || limits.ProviderOfflineDelay < time.Second || limits.RetryBase < time.Second ||
		limits.RetryMaximum < limits.RetryBase || limits.MaxAttempts == 0 || limits.MaxAttempts > 32 {
		return ErrInvalid
	}
	return nil
}

type CampaignDispatch struct {
	Attempt   QueueAttempt
	Campaign  Campaign
	Recipient FrozenRecipient
	Template  MessageTemplateVersion
}

type CampaignQueueRepository interface {
	LeaseCampaignAttempt(context.Context, string, time.Time, QueueLimits) (QueueAttempt, error)
	PrepareCampaignDelivery(context.Context, QueueAttempt, time.Time) (CampaignDispatch, error)
	CompleteCampaignAttempt(context.Context, QueueAttempt, AttemptReceipt, time.Time) error
	RecordCampaignProviderReceipt(context.Context, TenantID, AttemptID, AttemptReceipt) error
}

type CampaignQueue struct {
	Repository CampaignQueueRepository
	Provider   DeliveryProvider
	Limits     QueueLimits
	WorkerID   string
	Now        func() time.Time
}

// ProcessOne processes at most one campaign attempt. It never borrows from the
// capacity explicitly reserved for transactional delivery.
func (queue CampaignQueue) ProcessOne(ctx context.Context) (bool, error) {
	if queue.Repository == nil || queue.Provider == nil || queue.Now == nil || validateIdentifier(queue.WorkerID) != nil || queue.Limits.validate() != nil {
		return false, ErrInvalid
	}
	now := queue.Now().UTC()
	attempt, err := queue.Repository.LeaseCampaignAttempt(ctx, queue.WorkerID, now, queue.Limits)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	dispatch, err := queue.Repository.PrepareCampaignDelivery(ctx, attempt, queue.Now().UTC())
	if errors.Is(err, ErrSuppressed) || errors.Is(err, ErrStale) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	availability, availabilityErr := queue.Provider.Availability(ctx, dispatch.Campaign.TenantID, dispatch.Campaign.DeliveryProfileRef)
	if availabilityErr != nil || !availability.Online {
		delay := availability.RetryAfter
		if delay <= 0 {
			delay = queue.Limits.ProviderOfflineDelay
		}
		receipt := queue.receipt(dispatch, AttemptDeferred, "provider_offline", "provider_availability", "", false, queue.Now().UTC())
		dispatch.Attempt.AttemptNumber--
		dispatch.Attempt.Status, dispatch.Attempt.Reason, dispatch.Attempt.NextAttemptAt = AttemptDeferred, "provider_offline", queue.Now().UTC().Add(delay)
		return true, queue.Repository.CompleteCampaignAttempt(ctx, dispatch.Attempt, receipt, queue.Now().UTC())
	}
	variables := make(map[string]string, len(dispatch.Campaign.TemplateVariables)+1)
	for name, value := range dispatch.Campaign.TemplateVariables {
		variables[name] = value
	}
	for _, name := range dispatch.Template.Variables {
		if name == "recipient_email" {
			variables[name] = dispatch.Recipient.Address.Normalized
		}
	}
	preview, err := RenderTemplate(dispatch.Template, TemplateRenderRequest{TenantID: dispatch.Campaign.TenantID, TemplateID: dispatch.Template.TemplateID, TemplateVersion: dispatch.Template.Version, Variables: variables, RequestedBy: "campaign_queue", RequestedAt: queue.Now().UTC(), Purpose: dispatch.Campaign.Consent.Purpose}, queue.Now().UTC())
	if err != nil {
		receipt := queue.receipt(dispatch, AttemptFailed, "template_render_failed", "local", "", false, queue.Now().UTC())
		dispatch.Attempt.Status, dispatch.Attempt.Reason = AttemptFailed, "template_render_failed"
		return true, queue.Repository.CompleteCampaignAttempt(ctx, dispatch.Attempt, receipt, queue.Now().UTC())
	}
	subject := preview.Subject
	if dispatch.Campaign.SubjectOverride != "" {
		subject = renderClosed(dispatch.Campaign.SubjectOverride, variables, false)
		if validateHeaderValue(subject, 998) != nil {
			return true, ErrIntegrity
		}
	}
	from := dispatch.Campaign.From
	if from == "" {
		from = preview.From
	}
	replyTo := dispatch.Campaign.ReplyTo
	if replyTo == "" {
		replyTo = preview.ReplyTo
	}
	envelope := DeliveryEnvelope{TenantID: dispatch.Campaign.TenantID, CampaignID: dispatch.Campaign.ID, AttemptID: dispatch.Attempt.ID, IdempotencyKey: string(dispatch.Attempt.ID), Recipient: dispatch.Recipient.Address.Normalized, Subject: subject, From: from, ReplyTo: replyTo, TextBody: preview.TextBody, HTMLBody: preview.HTMLBody, ProviderRef: dispatch.Campaign.DeliveryProfileRef}
	result, sendErr := queue.Provider.Send(ctx, envelope)
	finishedAt := queue.Now().UTC()
	return true, queue.finishProviderResult(ctx, dispatch, result, sendErr, finishedAt)
}

func (queue CampaignQueue) finishProviderResult(ctx context.Context, dispatch CampaignDispatch, result ProviderResult, sendErr error, now time.Time) error {
	if (result.Disposition == ProviderAccepted || result.Disposition == ProviderDelivered) && result.ProviderMessageID == "" {
		result.Disposition, result.Reason, result.Definitive = ProviderRejected, "provider_message_id_missing", true
	}
	status, reason, delayed := AttemptFailed, result.Reason, false
	next := time.Time{}
	awaiting := false
	if sendErr != nil && !result.Definitive || result.Disposition == ProviderUnknown {
		status, reason, awaiting, delayed = AttemptDeferred, "uncertain_submission_outcome", true, true
	} else {
		switch result.Disposition {
		case ProviderAccepted:
			status, awaiting = AttemptSent, true
		case ProviderDelivered:
			status = AttemptDelivered
		case ProviderDeferred:
			status = AttemptDeferred
			delay := result.RetryAfter
			if delay <= 0 {
				delay = queue.retryDelay(dispatch.Attempt.AttemptNumber)
			}
			if dispatch.Attempt.AttemptNumber >= queue.Limits.MaxAttempts {
				status, reason = AttemptFailed, "retry_limit_exhausted"
			} else {
				next = now.Add(delay)
			}
		case ProviderRejected:
			status = AttemptFailed
		default:
			if sendErr != nil && result.Definitive && dispatch.Attempt.AttemptNumber < queue.Limits.MaxAttempts {
				status, reason, next = AttemptDeferred, "definitive_pre_submission_failure", now.Add(queue.retryDelay(dispatch.Attempt.AttemptNumber))
			} else {
				reason = "invalid_provider_result"
			}
		}
	}
	dispatch.Attempt.Status, dispatch.Attempt.Reason, dispatch.Attempt.NextAttemptAt, dispatch.Attempt.AwaitingReceipt = status, reason, next, awaiting
	dispatch.Attempt.ProviderRef, dispatch.Attempt.ProviderMessageID = dispatch.Campaign.DeliveryProfileRef, result.ProviderMessageID
	receipt := queue.receipt(dispatch, status, reason, "provider", result.ProviderMessageID, delayed, now)
	return queue.Repository.CompleteCampaignAttempt(ctx, dispatch.Attempt, receipt, now)
}

func (queue CampaignQueue) retryDelay(attempt uint32) time.Duration {
	delay := queue.Limits.RetryBase
	for i := uint32(1); i < attempt && delay < queue.Limits.RetryMaximum/2; i++ {
		delay *= 2
	}
	if delay > queue.Limits.RetryMaximum {
		return queue.Limits.RetryMaximum
	}
	return delay
}

func (queue CampaignQueue) receipt(dispatch CampaignDispatch, status AttemptStatus, reason, provenance, providerMessageID string, delayed bool, now time.Time) AttemptReceipt {
	material := fmt.Sprintf("%s:%d:%s:%s:%s", dispatch.Attempt.ID, dispatch.Attempt.Fence, status, providerMessageID, dbTime(now))
	return AttemptReceipt{ID: "receipt:" + DigestEvidence([]byte(material))[:40], TenantID: dispatch.Attempt.TenantID, CampaignID: dispatch.Attempt.CampaignID, AttemptID: dispatch.Attempt.ID, Status: status, ProviderRef: dispatch.Campaign.DeliveryProfileRef, ProviderMessageID: providerMessageID, Provenance: provenance, Reason: reason, DelayedEvent: delayed, ObservedAt: now}
}

func (r *SQLiteRepository) LeaseCampaignAttempt(ctx context.Context, worker string, now time.Time, limits QueueLimits) (QueueAttempt, error) {
	if validateIdentifier(worker) != nil || now.IsZero() || limits.validate() != nil {
		return QueueAttempt{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return QueueAttempt{}, err
	}
	defer tx.Rollback()
	var leased uint32
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_marketing_campaign_attempts_v1 WHERE lease_owner<>'' AND lease_expires_at>?`, dbTime(now)).Scan(&leased); err != nil {
		return QueueAttempt{}, err
	}
	if leased >= limits.MaxCampaignConcurrency {
		return QueueAttempt{}, ErrNotFound
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.document FROM email_marketing_campaign_attempts_v1 a JOIN email_marketing_campaigns_v1 c ON c.tenant_id=a.tenant_id AND c.campaign_id=a.campaign_id LEFT JOIN email_marketing_campaign_dispatch_v1 d ON d.tenant_id=a.tenant_id WHERE c.state='running' AND a.status IN ('queued','deferred') AND a.awaiting_receipt=0 AND a.next_attempt_at<=? AND (a.lease_owner='' OR a.lease_expires_at<=?) ORDER BY COALESCE(d.dispatch_sequence,0),a.next_attempt_at,a.attempt_id LIMIT 64`, dbTime(now), dbTime(now))
	if err != nil {
		return QueueAttempt{}, err
	}
	var candidates []QueueAttempt
	for rows.Next() {
		var document []byte
		var attempt QueueAttempt
		if rows.Scan(&document) != nil || json.Unmarshal(document, &attempt) != nil {
			rows.Close()
			return QueueAttempt{}, ErrIntegrity
		}
		candidates = append(candidates, attempt)
	}
	if err = rows.Close(); err != nil {
		return QueueAttempt{}, err
	}
	for _, attempt := range candidates {
		var tenantLeased, campaignLeased, recent uint32
		var campaignDocument []byte
		if err = tx.QueryRowContext(ctx, `SELECT document FROM email_marketing_campaigns_v1 WHERE tenant_id=? AND campaign_id=? AND state='running'`, attempt.TenantID, attempt.CampaignID).Scan(&campaignDocument); err != nil {
			continue
		}
		var campaign Campaign
		if json.Unmarshal(campaignDocument, &campaign) != nil {
			return QueueAttempt{}, ErrIntegrity
		}
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND lease_owner<>'' AND lease_expires_at>?`, attempt.TenantID, dbTime(now)).Scan(&tenantLeased); err != nil {
			return QueueAttempt{}, err
		}
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND campaign_id=? AND lease_owner<>'' AND lease_expires_at>?`, attempt.TenantID, attempt.CampaignID, dbTime(now)).Scan(&campaignLeased); err != nil {
			return QueueAttempt{}, err
		}
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_marketing_campaign_receipts_v1 WHERE tenant_id=? AND campaign_id=? AND status NOT IN ('queued','suppressed') AND observed_at>?`, attempt.TenantID, attempt.CampaignID, dbTime(now.Add(-time.Minute))).Scan(&recent); err != nil {
			return QueueAttempt{}, err
		}
		if tenantLeased >= limits.MaxTenantConcurrency || campaignLeased >= uint32(campaign.Concurrency) || recent >= campaign.RatePerMinute {
			continue
		}
		attempt.LeaseOwner, attempt.LeaseExpiresAt, attempt.Fence = worker, now.Add(limits.LeaseDuration), attempt.Fence+1
		attempt.AttemptNumber++
		attempt.UpdatedAt = now
		document, _ := json.Marshal(attempt)
		result, updateErr := tx.ExecContext(ctx, `UPDATE email_marketing_campaign_attempts_v1 SET attempt_number=?,lease_owner=?,lease_expires_at=?,fence=?,document=?,updated_at=? WHERE attempt_id=? AND fence=? AND (lease_owner='' OR lease_expires_at<=?)`, attempt.AttemptNumber, worker, dbTime(attempt.LeaseExpiresAt), attempt.Fence, document, dbTime(now), attempt.ID, attempt.Fence-1, dbTime(now))
		if updateErr != nil {
			return QueueAttempt{}, updateErr
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			continue
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_dispatch_v1(tenant_id,dispatch_sequence,updated_at) VALUES(?,1,?) ON CONFLICT(tenant_id) DO UPDATE SET dispatch_sequence=(SELECT COALESCE(MAX(dispatch_sequence),0)+1 FROM email_marketing_campaign_dispatch_v1),updated_at=excluded.updated_at`, attempt.TenantID, dbTime(now))
		if err != nil {
			return QueueAttempt{}, err
		}
		if err = tx.Commit(); err != nil {
			return QueueAttempt{}, err
		}
		return attempt, nil
	}
	return QueueAttempt{}, ErrNotFound
}

func (r *SQLiteRepository) PrepareCampaignDelivery(ctx context.Context, lease QueueAttempt, now time.Time) (CampaignDispatch, error) {
	if lease.LeaseOwner == "" || lease.Fence == 0 || now.IsZero() {
		return CampaignDispatch{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return CampaignDispatch{}, err
	}
	defer tx.Rollback()
	var attemptDocument, campaignDocument, recipientDocument []byte
	var owner, expires string
	var fence uint64
	if err = tx.QueryRowContext(ctx, `SELECT document,lease_owner,lease_expires_at,fence FROM email_marketing_campaign_attempts_v1 WHERE attempt_id=?`, lease.ID).Scan(&attemptDocument, &owner, &expires, &fence); err != nil {
		return CampaignDispatch{}, err
	}
	expiresAt, parseErr := parseDBTime(expires)
	if parseErr != nil || owner != lease.LeaseOwner || fence != lease.Fence || !expiresAt.After(now) {
		return CampaignDispatch{}, ErrStale
	}
	var attempt QueueAttempt
	if json.Unmarshal(attemptDocument, &attempt) != nil || attempt.ID != lease.ID {
		return CampaignDispatch{}, ErrIntegrity
	}
	if err = tx.QueryRowContext(ctx, `SELECT document FROM email_marketing_campaigns_v1 WHERE tenant_id=? AND campaign_id=?`, attempt.TenantID, attempt.CampaignID).Scan(&campaignDocument); err != nil {
		return CampaignDispatch{}, err
	}
	var campaign Campaign
	if json.Unmarshal(campaignDocument, &campaign) != nil || campaign.Revision != attempt.CampaignRevision {
		return CampaignDispatch{}, ErrIntegrity
	}
	if campaign.State != CampaignRunning {
		attempt.AttemptNumber--
		if campaign.State == CampaignCancelled {
			attempt.Status, attempt.Reason, attempt.NextAttemptAt, attempt.UpdatedAt = AttemptFailed, "cancelled_before_submission", time.Time{}, now
			receipt := AttemptReceipt{ID: "receipt:" + DigestEvidence([]byte(fmt.Sprintf("%s:%d:cancelled", attempt.ID, attempt.Fence)))[:40], TenantID: attempt.TenantID, CampaignID: attempt.CampaignID, AttemptID: attempt.ID, Status: AttemptFailed, Provenance: "campaign_cancellation", Reason: attempt.Reason, ObservedAt: now}
			if err = finishAttemptTx(ctx, tx, attempt, receipt, now); err != nil {
				return CampaignDispatch{}, err
			}
		} else {
			attempt.LeaseOwner, attempt.LeaseExpiresAt, attempt.UpdatedAt = "", time.Time{}, now
			document, _ := json.Marshal(attempt)
			result, updateErr := tx.ExecContext(ctx, `UPDATE email_marketing_campaign_attempts_v1 SET attempt_number=?,lease_owner='',lease_expires_at='',document=?,updated_at=? WHERE attempt_id=? AND lease_owner=? AND fence=?`, attempt.AttemptNumber, document, dbTime(now), attempt.ID, lease.LeaseOwner, attempt.Fence)
			if updateErr != nil {
				return CampaignDispatch{}, updateErr
			}
			affected, _ := result.RowsAffected()
			if affected != 1 {
				return CampaignDispatch{}, ErrStale
			}
		}
		if err = tx.Commit(); err != nil {
			return CampaignDispatch{}, err
		}
		return CampaignDispatch{}, ErrStale
	}
	if err = tx.QueryRowContext(ctx, `SELECT document FROM email_marketing_campaign_recipients_v1 WHERE tenant_id=? AND campaign_id=? AND campaign_revision=? AND ordinal=?`, attempt.TenantID, attempt.CampaignID, attempt.CampaignRevision, attempt.RecipientOrdinal).Scan(&recipientDocument); err != nil {
		return CampaignDispatch{}, err
	}
	var recipient FrozenRecipient
	if json.Unmarshal(recipientDocument, &recipient) != nil || recipient.SnapshotDigest != campaign.SnapshotDigest {
		return CampaignDispatch{}, ErrIntegrity
	}
	identity, identityErr := NormalizeAddress(recipient.Address.Normalized)
	if identityErr != nil || identity != recipient.Address {
		return CampaignDispatch{}, ErrIntegrity
	}
	suppressed, err := activeSuppressionTx(ctx, tx, attempt.TenantID, recipient.Address.Digest)
	if err != nil {
		return CampaignDispatch{}, err
	}
	consent, consentErr := latestConsentTx(ctx, tx, attempt.TenantID, recipient.ListID, recipient.SubscriberID)
	if consentErr != nil && !errors.Is(consentErr, ErrNotFound) {
		return CampaignDispatch{}, consentErr
	}
	if suppressed || errors.Is(consentErr, ErrNotFound) || consent.ID != recipient.ConsentID || !consentEligible(consent, campaign.Consent) || digestObject(consent) != recipient.ConsentDigest {
		attempt.Status, attempt.Reason, attempt.UpdatedAt = AttemptSuppressed, "current_suppression_or_consent", now
		receipt := AttemptReceipt{ID: "receipt:" + DigestEvidence([]byte(fmt.Sprintf("%s:%d:suppressed", attempt.ID, attempt.Fence)))[:40], TenantID: attempt.TenantID, CampaignID: attempt.CampaignID, AttemptID: attempt.ID, Status: AttemptSuppressed, Provenance: "atomic_pre_submission_check", Reason: attempt.Reason, ObservedAt: now}
		if err = finishAttemptTx(ctx, tx, attempt, receipt, now); err != nil {
			return CampaignDispatch{}, err
		}
		if err = tx.Commit(); err != nil {
			return CampaignDispatch{}, err
		}
		return CampaignDispatch{}, ErrSuppressed
	}
	version, err := templateVersionTx(ctx, tx, campaign.TenantID, campaign.TemplateID, campaign.TemplateVersion)
	if err != nil || version.Digest != campaign.TemplateDigest {
		return CampaignDispatch{}, ErrIntegrity
	}
	return CampaignDispatch{Attempt: attempt, Campaign: campaign, Recipient: recipient, Template: version}, tx.Commit()
}

func (r *SQLiteRepository) CompleteCampaignAttempt(ctx context.Context, attempt QueueAttempt, receipt AttemptReceipt, now time.Time) error {
	if now.IsZero() || validateIdentifier(receipt.ID) != nil || receipt.ObservedAt.IsZero() || receipt.ObservedAt.After(now.Add(time.Minute)) || receipt.AttemptID != attempt.ID || receipt.TenantID != attempt.TenantID || receipt.CampaignID != attempt.CampaignID || receipt.Status != attempt.Status || validateAttemptStatus(attempt.Status) != nil {
		return ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = finishAttemptTx(ctx, tx, attempt, receipt, now); err != nil {
		return err
	}
	return tx.Commit()
}

func finishAttemptTx(ctx context.Context, tx *sql.Tx, attempt QueueAttempt, receipt AttemptReceipt, now time.Time) error {
	leaseOwner := attempt.LeaseOwner
	attempt.LeaseOwner, attempt.LeaseExpiresAt, attempt.UpdatedAt = "", time.Time{}, now
	document, _ := json.Marshal(attempt)
	result, err := tx.ExecContext(ctx, `UPDATE email_marketing_campaign_attempts_v1 SET status=?,attempt_number=?,next_attempt_at=?,lease_owner='',lease_expires_at='',awaiting_receipt=?,document=?,updated_at=? WHERE attempt_id=? AND lease_owner=? AND fence=?`, attempt.Status, attempt.AttemptNumber, dbTime(attempt.NextAttemptAt), attempt.AwaitingReceipt, document, dbTime(now), attempt.ID, leaseOwner, attempt.Fence)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrStale
	}
	receiptDocument, _ := json.Marshal(receipt)
	_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_receipts_v1(receipt_id,tenant_id,campaign_id,attempt_id,status,provider_message_id,delayed_event,observed_at,document) VALUES(?,?,?,?,?,?,?,?,?)`, receipt.ID, receipt.TenantID, receipt.CampaignID, receipt.AttemptID, receipt.Status, receipt.ProviderMessageID, receipt.DelayedEvent, dbTime(receipt.ObservedAt), receiptDocument)
	if err != nil {
		return ErrConflict
	}
	if err = completeCampaignIfFinishedTx(ctx, tx, attempt, now); err != nil {
		return err
	}
	return nil
}

func (r *SQLiteRepository) RecordCampaignProviderReceipt(ctx context.Context, tenant TenantID, id AttemptID, receipt AttemptReceipt) error {
	if validateIdentifier(receipt.ID) != nil || receipt.TenantID != tenant || receipt.AttemptID != id || receipt.ProviderMessageID == "" || receipt.ProviderRef == "" || receipt.Provenance == "" || receipt.ObservedAt.IsZero() || !providerReceiptStatus(receipt.Status) {
		return ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var document []byte
	if err = tx.QueryRowContext(ctx, `SELECT document FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND attempt_id=?`, tenant, id).Scan(&document); err != nil {
		return err
	}
	var attempt QueueAttempt
	if json.Unmarshal(document, &attempt) != nil || receipt.CampaignID != attempt.CampaignID || attempt.Status != AttemptSent && !(attempt.Status == AttemptDeferred && attempt.AwaitingReceipt) {
		return ErrStale
	}
	if attempt.ProviderRef != receipt.ProviderRef || attempt.ProviderMessageID != "" && attempt.ProviderMessageID != receipt.ProviderMessageID {
		return ErrIntegrity
	}
	attempt.Status, attempt.ProviderMessageID, attempt.Reason, attempt.AwaitingReceipt, attempt.UpdatedAt = receipt.Status, receipt.ProviderMessageID, receipt.Reason, receipt.Status == AttemptDeferred, receipt.ObservedAt
	attemptDocument, _ := json.Marshal(attempt)
	result, err := tx.ExecContext(ctx, `UPDATE email_marketing_campaign_attempts_v1 SET status=?,awaiting_receipt=?,document=?,updated_at=? WHERE attempt_id=? AND status=?`, attempt.Status, attempt.AwaitingReceipt, attemptDocument, dbTime(receipt.ObservedAt), attempt.ID, string(AttemptSent))
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		result, err = tx.ExecContext(ctx, `UPDATE email_marketing_campaign_attempts_v1 SET status=?,awaiting_receipt=?,document=?,updated_at=? WHERE attempt_id=? AND status='deferred' AND awaiting_receipt=1`, attempt.Status, attempt.AwaitingReceipt, attemptDocument, dbTime(receipt.ObservedAt), attempt.ID)
		if err != nil {
			return err
		}
		affected, _ = result.RowsAffected()
		if affected != 1 {
			return ErrStale
		}
	}
	if receipt.Status == AttemptComplained || receipt.Status == AttemptBounced {
		var recipientDocument []byte
		if err = tx.QueryRowContext(ctx, `SELECT r.document FROM email_marketing_campaign_recipients_v1 r JOIN email_marketing_campaign_attempts_v1 a ON a.tenant_id=r.tenant_id AND a.campaign_id=r.campaign_id AND a.campaign_revision=r.campaign_revision AND a.recipient_ordinal=r.ordinal WHERE a.attempt_id=?`, attempt.ID).Scan(&recipientDocument); err != nil {
			return err
		}
		var recipient FrozenRecipient
		if json.Unmarshal(recipientDocument, &recipient) != nil {
			return ErrIntegrity
		}
		reason, scope, suppressionTenant := SuppressionHardBounce, SuppressionTenant, tenant
		if receipt.Status == AttemptComplained {
			reason, scope, suppressionTenant = SuppressionComplaint, SuppressionGlobal, ""
		}
		record := SuppressionRecord{ID: "delivery:" + DigestEvidence([]byte(receipt.ID+":"+string(reason)))[:40], Scope: scope, TenantID: suppressionTenant, ListID: recipient.ListID, SubscriberID: recipient.SubscriberID, AddressDigest: recipient.Address.Digest, Reason: reason, Action: SuppressionAdded, OccurredAt: receipt.ObservedAt, EvidenceDigest: digestObject(receipt), ActorID: "provider_receipt"}
		if err = insertSuppression(ctx, tx, record); err != nil {
			return err
		}
		if err = setSuppressionState(ctx, tx, record); err != nil {
			return err
		}
	}
	receipt.DelayedEvent = true
	receiptDocument, _ := json.Marshal(receipt)
	if _, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_receipts_v1(receipt_id,tenant_id,campaign_id,attempt_id,status,provider_message_id,delayed_event,observed_at,document) VALUES(?,?,?,?,?,?,?,?,?)`, receipt.ID, receipt.TenantID, receipt.CampaignID, receipt.AttemptID, receipt.Status, receipt.ProviderMessageID, 1, dbTime(receipt.ObservedAt), receiptDocument); err != nil {
		return ErrConflict
	}
	if err = completeCampaignIfFinishedTx(ctx, tx, attempt, receipt.ObservedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func completeCampaignIfFinishedTx(ctx context.Context, tx *sql.Tx, attempt QueueAttempt, now time.Time) error {
	if attempt.Status == AttemptQueued || attempt.Status == AttemptDeferred || attempt.Status == AttemptSent {
		return nil
	}
	var remaining uint64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND campaign_id=? AND campaign_revision=? AND status IN ('queued','deferred','sent')`, attempt.TenantID, attempt.CampaignID, attempt.CampaignRevision).Scan(&remaining); err != nil || remaining != 0 {
		return err
	}
	var campaignDocument []byte
	var generation uint64
	err := tx.QueryRowContext(ctx, `SELECT generation,document FROM email_marketing_campaigns_v1 WHERE tenant_id=? AND campaign_id=? AND state='running'`, attempt.TenantID, attempt.CampaignID).Scan(&generation, &campaignDocument)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var campaign Campaign
	if json.Unmarshal(campaignDocument, &campaign) != nil {
		return ErrIntegrity
	}
	campaign.State, campaign.Generation, campaign.UpdatedAt = CampaignCompleted, generation+1, now
	campaignDocument, _ = json.Marshal(campaign)
	result, err := tx.ExecContext(ctx, `UPDATE email_marketing_campaigns_v1 SET generation=?,state='completed',document=?,updated_at=? WHERE tenant_id=? AND campaign_id=? AND generation=? AND state='running'`, campaign.Generation, campaignDocument, dbTime(now), campaign.TenantID, campaign.ID, generation)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrStale
	}
	return nil
}

func validateAttemptStatus(status AttemptStatus) error {
	switch status {
	case AttemptQueued, AttemptSent, AttemptDelivered, AttemptDeferred, AttemptBounced, AttemptComplained, AttemptSuppressed, AttemptFailed:
		return nil
	default:
		return ErrInvalid
	}
}

func providerReceiptStatus(status AttemptStatus) bool {
	return status == AttemptDelivered || status == AttemptDeferred || status == AttemptBounced || status == AttemptComplained || status == AttemptFailed
}
