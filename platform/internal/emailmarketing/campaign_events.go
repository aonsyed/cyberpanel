package emailmarketing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrDeliveryEventRejected = errors.New("emailmarketing: delivery event rejected")

type DeliveryEventSource string

const (
	DeliveryEventProvider DeliveryEventSource = "provider"
	DeliveryEventLocal    DeliveryEventSource = "local"
)

type SignedDeliveryEvent struct {
	Source        DeliveryEventSource
	ProviderRef   string
	KeyID         string
	EventID       string
	Nonce         string
	SignedAt      time.Time
	Payload       []byte
	Signature     []byte
}

type VerifiedDeliveryEvent struct {
	Source            DeliveryEventSource
	ProviderRef       string
	EventID           string
	NonceDigest       string
	TenantID          TenantID
	CampaignID        CampaignID
	AttemptID         AttemptID
	ProviderMessageID string
	Status            AttemptStatus
	Reason            string
	OccurredAt        time.Time
	VerifiedAt        time.Time
	SignatureDigest   string
	PayloadDigest     string
}

// DeliveryEventVerifier owns signature/key validation and strict payload
// decoding. The core never accepts an unverified event document.
type DeliveryEventVerifier interface {
	VerifyDeliveryEvent(context.Context, SignedDeliveryEvent, time.Time) (VerifiedDeliveryEvent, error)
}

type DeliveryEventPolicy struct {
	MaximumPayloadBytes int
	MaximumClockSkew    time.Duration
	ReplayWindow        time.Duration
	DelayedAfter        time.Duration
}

func (policy DeliveryEventPolicy) validate() error {
	if policy.MaximumPayloadBytes < 1 || policy.MaximumPayloadBytes > 1<<20 || policy.MaximumClockSkew < 0 ||
		policy.MaximumClockSkew > 15*time.Minute || policy.ReplayWindow < time.Minute || policy.ReplayWindow > 30*24*time.Hour ||
		policy.DelayedAfter < time.Minute || policy.DelayedAfter > 7*24*time.Hour {
		return ErrInvalid
	}
	return nil
}

type DeliveryEventResult struct {
	Accepted   bool
	Duplicate  bool
	Delayed    bool
	OutOfOrder bool
	ReceiptID  string
}

type DeliveryEventRepository interface {
	ApplyVerifiedDeliveryEvent(context.Context, VerifiedDeliveryEvent, DeliveryEventPolicy, time.Time) (DeliveryEventResult, error)
}

type DeliveryEventService struct {
	Repository DeliveryEventRepository
	Verifier   DeliveryEventVerifier
	Policy     DeliveryEventPolicy
	Now        func() time.Time
}

// Ingest deliberately returns one generic rejection error for correlation,
// signature, replay, and authorization failures to prevent recipient probing.
func (service DeliveryEventService) Ingest(ctx context.Context, signed SignedDeliveryEvent) (DeliveryEventResult, error) {
	if service.Repository == nil || service.Verifier == nil || service.Now == nil || service.Policy.validate() != nil ||
		len(signed.Payload) == 0 || len(signed.Payload) > service.Policy.MaximumPayloadBytes || len(signed.Signature) == 0 ||
		validateIdentifier(signed.EventID) != nil || validateIdentifier(signed.KeyID) != nil || validateIdentifier(signed.ProviderRef) != nil ||
		len(signed.Nonce) < 16 || len(signed.Nonce) > 256 || signed.SignedAt.IsZero() {
		return DeliveryEventResult{}, ErrDeliveryEventRejected
	}
	now := service.Now().UTC()
	if signed.SignedAt.Before(now.Add(-service.Policy.ReplayWindow)) || signed.SignedAt.After(now.Add(service.Policy.MaximumClockSkew)) {
		return DeliveryEventResult{}, ErrDeliveryEventRejected
	}
	event, err := service.Verifier.VerifyDeliveryEvent(ctx, signed, now)
	if err != nil || validateVerifiedDeliveryEvent(event, signed, service.Policy, now) != nil {
		return DeliveryEventResult{}, ErrDeliveryEventRejected
	}
	result, err := service.Repository.ApplyVerifiedDeliveryEvent(ctx, event, service.Policy, now)
	if err != nil {
		return DeliveryEventResult{}, ErrDeliveryEventRejected
	}
	return result, nil
}

func validateVerifiedDeliveryEvent(event VerifiedDeliveryEvent, signed SignedDeliveryEvent, policy DeliveryEventPolicy, now time.Time) error {
	if event.Source != signed.Source || event.ProviderRef != signed.ProviderRef || event.EventID != signed.EventID ||
		validateIdentifier(string(event.TenantID)) != nil || validateIdentifier(string(event.CampaignID)) != nil ||
		validateIdentifier(string(event.AttemptID)) != nil || validateOpaqueEventID(event.ProviderMessageID) != nil ||
		!validDigest(event.NonceDigest) || event.NonceDigest != DigestEvidence([]byte(signed.Nonce)) || !validDigest(event.SignatureDigest) ||
		event.SignatureDigest != DigestEvidence(signed.Signature) || !validDigest(event.PayloadDigest) || event.PayloadDigest != DigestEvidence(signed.Payload) || event.OccurredAt.IsZero() ||
		event.VerifiedAt.IsZero() || event.VerifiedAt.Before(signed.SignedAt.Add(-policy.MaximumClockSkew)) || event.VerifiedAt.After(now.Add(policy.MaximumClockSkew)) ||
		event.OccurredAt.After(now.Add(policy.MaximumClockSkew)) || event.OccurredAt.Before(now.Add(-policy.ReplayWindow)) || len(event.Reason) > 1024 || hasForbiddenControl(event.Reason) {
		return ErrInvalid
	}
	if event.Source != DeliveryEventProvider && event.Source != DeliveryEventLocal || !providerEventStatus(event.Status) {
		return ErrInvalid
	}
	return nil
}

func providerEventStatus(status AttemptStatus) bool {
	return status == AttemptDelivered || status == AttemptDeferred || status == AttemptBounced || status == AttemptComplained || status == AttemptFailed
}

func (r *SQLiteRepository) BootstrapCampaignEvents(ctx context.Context) error {
	if r == nil || r.db == nil {
		return ErrInvalid
	}
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE IF NOT EXISTS email_marketing_delivery_events_v1 (
			provider_ref TEXT NOT NULL, event_id TEXT NOT NULL, nonce_digest TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL,
			campaign_id TEXT NOT NULL, attempt_id TEXT NOT NULL, provider_message_id TEXT NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('delivered','deferred','bounced','complained','failed')),
			occurred_at TEXT NOT NULL, received_at TEXT NOT NULL, delayed INTEGER NOT NULL CHECK(delayed IN (0,1)),
			out_of_order INTEGER NOT NULL CHECK(out_of_order IN (0,1)), payload_digest TEXT NOT NULL, document BLOB NOT NULL,
			PRIMARY KEY(provider_ref,event_id), FOREIGN KEY(attempt_id) REFERENCES email_marketing_campaign_attempts_v1(attempt_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_delivery_events_attempt_v1 ON email_marketing_delivery_events_v1(tenant_id,campaign_id,attempt_id,occurred_at,event_id)`,
		`CREATE INDEX IF NOT EXISTS email_marketing_delivery_events_time_v1 ON email_marketing_delivery_events_v1(tenant_id,campaign_id,received_at,status)`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_delivery_events_no_update_v1 BEFORE UPDATE ON email_marketing_delivery_events_v1 BEGIN SELECT RAISE(ABORT,'delivery events are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_delivery_events_no_delete_v1 BEFORE DELETE ON email_marketing_delivery_events_v1 BEGIN SELECT RAISE(ABORT,'delivery events are immutable'); END`,
	}
	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) ApplyVerifiedDeliveryEvent(ctx context.Context, event VerifiedDeliveryEvent, policy DeliveryEventPolicy, now time.Time) (DeliveryEventResult, error) {
	if policy.validate() != nil || now.IsZero() || validateIdentifier(string(event.TenantID)) != nil || validateIdentifier(string(event.CampaignID)) != nil || validateIdentifier(string(event.AttemptID)) != nil ||
		validateIdentifier(event.ProviderRef) != nil || validateIdentifier(event.EventID) != nil || validateOpaqueEventID(event.ProviderMessageID) != nil ||
		!validDigest(event.NonceDigest) || !validDigest(event.SignatureDigest) || !validDigest(event.PayloadDigest) || !providerEventStatus(event.Status) ||
		event.OccurredAt.IsZero() || event.VerifiedAt.IsZero() || event.OccurredAt.Before(now.Add(-policy.ReplayWindow)) || event.OccurredAt.After(now.Add(policy.MaximumClockSkew)) || event.VerifiedAt.After(now.Add(policy.MaximumClockSkew)) || len(event.Reason) > 1024 || hasForbiddenControl(event.Reason) {
		return DeliveryEventResult{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return DeliveryEventResult{}, err
	}
	defer tx.Rollback()
	var priorDigest string
	err = tx.QueryRowContext(ctx, `SELECT payload_digest FROM email_marketing_delivery_events_v1 WHERE provider_ref=? AND event_id=?`, event.ProviderRef, event.EventID).Scan(&priorDigest)
	if err == nil {
		if priorDigest != event.PayloadDigest {
			return DeliveryEventResult{}, ErrIntegrity
		}
		return DeliveryEventResult{Accepted: true, Duplicate: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DeliveryEventResult{}, err
	}
	var attemptDocument, recipientDocument []byte
	var attemptStatus AttemptStatus
	var updatedAt string
	err = tx.QueryRowContext(ctx, `SELECT document,status,updated_at FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND campaign_id=? AND attempt_id=?`, event.TenantID, event.CampaignID, event.AttemptID).Scan(&attemptDocument, &attemptStatus, &updatedAt)
	if err != nil {
		return DeliveryEventResult{}, ErrNotFound
	}
	var attempt QueueAttempt
	if json.Unmarshal(attemptDocument, &attempt) != nil || attempt.TenantID != event.TenantID || attempt.CampaignID != event.CampaignID || attempt.ID != event.AttemptID || attempt.Status != attemptStatus || attempt.ProviderRef != event.ProviderRef ||
		attempt.ProviderMessageID != "" && attempt.ProviderMessageID != event.ProviderMessageID {
		return DeliveryEventResult{}, ErrIntegrity
	}
	if attempt.Status == AttemptQueued || attempt.Status == AttemptSuppressed {
		return DeliveryEventResult{}, ErrIntegrity
	}
	var lastOccurred string
	var lastStatus AttemptStatus
	err = tx.QueryRowContext(ctx, `SELECT occurred_at,status FROM email_marketing_delivery_events_v1 WHERE tenant_id=? AND campaign_id=? AND attempt_id=? ORDER BY occurred_at DESC,event_id DESC LIMIT 1`, event.TenantID, event.CampaignID, event.AttemptID).Scan(&lastOccurred, &lastStatus)
	outOfOrder := false
	if err == nil {
		watermark, parseErr := parseDBTime(lastOccurred)
		if parseErr != nil {
			return DeliveryEventResult{}, ErrIntegrity
		}
		outOfOrder = event.OccurredAt.Before(watermark)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return DeliveryEventResult{}, err
	}
	delayed := now.Sub(event.OccurredAt) > policy.DelayedAfter
	applyState := deliveryEventAdvances(attempt.Status, lastStatus, event.Status, outOfOrder)
	eventDocument, _ := json.Marshal(event)
	_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_delivery_events_v1(provider_ref,event_id,nonce_digest,tenant_id,campaign_id,attempt_id,provider_message_id,status,occurred_at,received_at,delayed,out_of_order,payload_digest,document) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, event.ProviderRef, event.EventID, event.NonceDigest, event.TenantID, event.CampaignID, event.AttemptID, event.ProviderMessageID, event.Status, dbTime(event.OccurredAt), dbTime(now), delayed, outOfOrder, event.PayloadDigest, eventDocument)
	if err != nil {
		return DeliveryEventResult{}, ErrConflict
	}
	receiptID := "receipt:" + DigestEvidence([]byte(fmt.Sprintf("event:%s:%s", event.ProviderRef, event.EventID)))[:40]
	if applyState {
		attempt.Status, attempt.ProviderMessageID, attempt.Reason, attempt.UpdatedAt = event.Status, event.ProviderMessageID, event.Reason, now
		attempt.AwaitingReceipt = event.Status == AttemptDeferred
		attemptDocument, _ = json.Marshal(attempt)
		result, updateErr := tx.ExecContext(ctx, `UPDATE email_marketing_campaign_attempts_v1 SET status=?,awaiting_receipt=?,document=?,updated_at=? WHERE tenant_id=? AND campaign_id=? AND attempt_id=? AND status=? AND updated_at=?`, attempt.Status, attempt.AwaitingReceipt, attemptDocument, dbTime(now), event.TenantID, event.CampaignID, event.AttemptID, attemptStatus, updatedAt)
		if updateErr != nil {
			return DeliveryEventResult{}, updateErr
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			return DeliveryEventResult{}, ErrStale
		}
		if event.Status == AttemptComplained || event.Status == AttemptBounced {
			if err = tx.QueryRowContext(ctx, `SELECT r.document FROM email_marketing_campaign_recipients_v1 r JOIN email_marketing_campaign_attempts_v1 a ON a.tenant_id=r.tenant_id AND a.campaign_id=r.campaign_id AND a.campaign_revision=r.campaign_revision AND a.recipient_ordinal=r.ordinal WHERE a.attempt_id=?`, attempt.ID).Scan(&recipientDocument); err != nil {
				return DeliveryEventResult{}, err
			}
			var recipient FrozenRecipient
			if json.Unmarshal(recipientDocument, &recipient) != nil || recipient.TenantID != event.TenantID || recipient.CampaignID != event.CampaignID {
				return DeliveryEventResult{}, ErrIntegrity
			}
			reason, scope, suppressionTenant := SuppressionHardBounce, SuppressionTenant, event.TenantID
			if event.Status == AttemptComplained {
				reason, scope, suppressionTenant = SuppressionComplaint, SuppressionGlobal, ""
			}
			suppression := SuppressionRecord{ID: "event:" + DigestEvidence([]byte(event.ProviderRef+":"+event.EventID+":"+string(reason)))[:40], Scope: scope, TenantID: suppressionTenant, ListID: recipient.ListID, SubscriberID: recipient.SubscriberID, AddressDigest: recipient.Address.Digest, Reason: reason, Action: SuppressionAdded, OccurredAt: event.OccurredAt, EvidenceDigest: event.PayloadDigest, ActorID: "delivery_event"}
			if err = insertSuppression(ctx, tx, suppression); err != nil {
				return DeliveryEventResult{}, err
			}
			if err = setSuppressionState(ctx, tx, suppression); err != nil && !errors.Is(err, ErrStale) {
				return DeliveryEventResult{}, err
			}
		}
	}
	receipt := AttemptReceipt{ID: receiptID, TenantID: event.TenantID, CampaignID: event.CampaignID, AttemptID: event.AttemptID, Status: event.Status, ProviderRef: event.ProviderRef, ProviderMessageID: event.ProviderMessageID, Provenance: string(event.Source) + "_signed_event", Reason: event.Reason, DelayedEvent: delayed || outOfOrder, ObservedAt: now}
	receiptDocument, _ := json.Marshal(receipt)
	receiptResult, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO email_marketing_campaign_receipts_v1(receipt_id,tenant_id,campaign_id,attempt_id,status,provider_message_id,delayed_event,observed_at,document) VALUES(?,?,?,?,?,?,?,?,?)`, receipt.ID, receipt.TenantID, receipt.CampaignID, receipt.AttemptID, receipt.Status, receipt.ProviderMessageID, receipt.DelayedEvent, dbTime(receipt.ObservedAt), receiptDocument)
	if err != nil {
		return DeliveryEventResult{}, err
	}
	receiptInserted, _ := receiptResult.RowsAffected()
	if receiptInserted != 1 {
		receiptID = ""
	}
	if applyState {
		if err = completeCampaignIfFinishedTx(ctx, tx, attempt, now); err != nil {
			return DeliveryEventResult{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return DeliveryEventResult{}, err
	}
	return DeliveryEventResult{Accepted: true, Delayed: delayed, OutOfOrder: outOfOrder, ReceiptID: receiptID}, nil
}

func deliveryEventAdvances(current, previous, next AttemptStatus, outOfOrder bool) bool {
	if next == AttemptComplained {
		return current != AttemptComplained
	}
	if outOfOrder || current == AttemptComplained || current == AttemptBounced || current == AttemptDelivered || current == AttemptFailed || current == AttemptSuppressed {
		return false
	}
	if next == AttemptDeferred {
		return current == AttemptSent || current == AttemptDeferred
	}
	if next == AttemptDelivered {
		return current == AttemptSent || current == AttemptDeferred || previous == AttemptDeferred
	}
	return next == AttemptBounced || next == AttemptFailed
}

func validateOpaqueEventID(value string) error {
	if value == "" || len(value) > 512 {
		return ErrInvalid
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return ErrInvalid
		}
	}
	return nil
}
