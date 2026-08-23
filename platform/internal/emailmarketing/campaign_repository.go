package emailmarketing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// BootstrapCampaignCore installs only the marketing campaign extension. It is
// separate from Bootstrap so callers can migrate the existing subscriber core
// and this schema under their normal migration coordinator.
func (r *SQLiteRepository) BootstrapCampaignCore(ctx context.Context) error {
	if r == nil || r.db == nil {
		return ErrInvalid
	}
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS email_marketing_templates_v1 (
			tenant_id TEXT NOT NULL, template_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0),
			latest_version INTEGER NOT NULL CHECK(latest_version>0), lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','archived','deleted')),
			document BLOB NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(tenant_id,template_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_templates_page_v1 ON email_marketing_templates_v1(tenant_id,template_id)`,
		`CREATE TABLE IF NOT EXISTS email_marketing_template_versions_v1 (
			tenant_id TEXT NOT NULL, template_id TEXT NOT NULL, version INTEGER NOT NULL CHECK(version>0), digest TEXT NOT NULL,
			document BLOB NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,template_id,version), UNIQUE(tenant_id,digest),
			FOREIGN KEY(tenant_id,template_id) REFERENCES email_marketing_templates_v1(tenant_id,template_id)
		) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_template_versions_no_update_v1 BEFORE UPDATE ON email_marketing_template_versions_v1 BEGIN SELECT RAISE(ABORT,'template versions are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_template_versions_no_delete_v1 BEFORE DELETE ON email_marketing_template_versions_v1 BEGIN SELECT RAISE(ABORT,'template versions are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS email_marketing_campaigns_v1 (
			tenant_id TEXT NOT NULL, campaign_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0), revision INTEGER NOT NULL CHECK(revision>0),
			state TEXT NOT NULL CHECK(state IN ('draft','approval','scheduled','running','paused','cancelled','completed','archived')),
			document BLOB NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(tenant_id,campaign_id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_campaigns_page_v1 ON email_marketing_campaigns_v1(tenant_id,campaign_id)`,
		`CREATE TABLE IF NOT EXISTS email_marketing_campaign_recipients_v1 (
			tenant_id TEXT NOT NULL, campaign_id TEXT NOT NULL, campaign_revision INTEGER NOT NULL, ordinal INTEGER NOT NULL,
			subscriber_id TEXT NOT NULL, list_id TEXT NOT NULL, address TEXT NOT NULL, address_digest TEXT NOT NULL,
			consent_id TEXT NOT NULL, consent_digest TEXT NOT NULL, snapshot_digest TEXT NOT NULL, document BLOB NOT NULL,
			PRIMARY KEY(tenant_id,campaign_id,campaign_revision,ordinal), UNIQUE(tenant_id,campaign_id,campaign_revision,address_digest)
		) STRICT`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_campaign_recipients_no_update_v1 BEFORE UPDATE ON email_marketing_campaign_recipients_v1 BEGIN SELECT RAISE(ABORT,'campaign recipients are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_campaign_recipients_no_delete_v1 BEFORE DELETE ON email_marketing_campaign_recipients_v1 BEGIN SELECT RAISE(ABORT,'campaign recipients are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS email_marketing_campaign_attempts_v1 (
			attempt_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, campaign_id TEXT NOT NULL, campaign_revision INTEGER NOT NULL,
			recipient_ordinal INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('queued','sent','delivered','deferred','bounced','complained','suppressed','failed')),
			attempt_number INTEGER NOT NULL CHECK(attempt_number>=0), next_attempt_at TEXT NOT NULL, lease_owner TEXT NOT NULL,
			lease_expires_at TEXT NOT NULL, fence INTEGER NOT NULL CHECK(fence>=0), awaiting_receipt INTEGER NOT NULL CHECK(awaiting_receipt IN (0,1)),
			document BLOB NOT NULL, updated_at TEXT NOT NULL, UNIQUE(tenant_id,campaign_id,campaign_revision,recipient_ordinal)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_campaign_attempts_queue_v1 ON email_marketing_campaign_attempts_v1(status,next_attempt_at,tenant_id,attempt_id)`,
		`CREATE TABLE IF NOT EXISTS email_marketing_campaign_receipts_v1 (
			receipt_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, campaign_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('queued','sent','delivered','deferred','bounced','complained','suppressed','failed')),
			provider_message_id TEXT NOT NULL, delayed_event INTEGER NOT NULL CHECK(delayed_event IN (0,1)), observed_at TEXT NOT NULL, document BLOB NOT NULL,
			FOREIGN KEY(attempt_id) REFERENCES email_marketing_campaign_attempts_v1(attempt_id)
		) STRICT`,
		`CREATE UNIQUE INDEX IF NOT EXISTS email_marketing_campaign_provider_receipt_v1 ON email_marketing_campaign_receipts_v1(attempt_id,provider_message_id,status) WHERE provider_message_id<>''`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_campaign_receipts_no_update_v1 BEFORE UPDATE ON email_marketing_campaign_receipts_v1 BEGIN SELECT RAISE(ABORT,'attempt receipts are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS email_marketing_campaign_receipts_no_delete_v1 BEFORE DELETE ON email_marketing_campaign_receipts_v1 BEGIN SELECT RAISE(ABORT,'attempt receipts are immutable'); END`,
		`CREATE TABLE IF NOT EXISTS email_marketing_campaign_dispatch_v1 (
			tenant_id TEXT PRIMARY KEY, dispatch_sequence INTEGER NOT NULL CHECK(dispatch_sequence>=0), updated_at TEXT NOT NULL
		) STRICT`,
	}
	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) PutMessageTemplate(ctx context.Context, template MessageTemplate, expected uint64, version *MessageTemplateVersion) error {
	if validateMessageTemplate(template, expected) != nil {
		return ErrInvalid
	}
	var sealed MessageTemplateVersion
	var err error
	if version != nil {
		sealed, err = SealTemplateVersion(*version)
		if err != nil || sealed.TenantID != template.TenantID || sealed.TemplateID != template.ID || sealed.Version != template.LatestVersion {
			return ErrInvalid
		}
	} else if expected == 0 {
		return ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	document, _ := json.Marshal(template)
	if expected == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_templates_v1(tenant_id,template_id,generation,latest_version,lifecycle,document,updated_at) VALUES(?,?,?,?,?,?,?)`, template.TenantID, template.ID, template.Generation, template.LatestVersion, template.Lifecycle, document, dbTime(template.UpdatedAt))
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE email_marketing_templates_v1 SET generation=?,latest_version=?,lifecycle=?,document=?,updated_at=? WHERE tenant_id=? AND template_id=? AND generation=?`, template.Generation, template.LatestVersion, template.Lifecycle, document, dbTime(template.UpdatedAt), template.TenantID, template.ID, expected)
		if err == nil {
			affected, _ := result.RowsAffected()
			if affected != 1 {
				return ErrStale
			}
		}
	}
	if err != nil {
		return ErrConflict
	}
	if version != nil {
		versionDocument, _ := json.Marshal(sealed)
		if _, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_template_versions_v1(tenant_id,template_id,version,digest,document,created_at) VALUES(?,?,?,?,?,?)`, sealed.TenantID, sealed.TemplateID, sealed.Version, sealed.Digest, versionDocument, dbTime(sealed.CreatedAt)); err != nil {
			return ErrConflict
		}
	}
	return tx.Commit()
}

func (r *SQLiteRepository) GetMessageTemplate(ctx context.Context, tenant TenantID, id TemplateID) (MessageTemplate, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(id)) != nil {
		return MessageTemplate{}, ErrInvalid
	}
	var document []byte
	var generation uint64
	err := r.db.QueryRowContext(ctx, `SELECT generation,document FROM email_marketing_templates_v1 WHERE tenant_id=? AND template_id=?`, tenant, id).Scan(&generation, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return MessageTemplate{}, ErrNotFound
	}
	var template MessageTemplate
	if err != nil || json.Unmarshal(document, &template) != nil || template.TenantID != tenant || template.ID != id || template.Generation != generation {
		if err != nil {
			return MessageTemplate{}, err
		}
		return MessageTemplate{}, ErrIntegrity
	}
	return template, nil
}

func (r *SQLiteRepository) GetMessageTemplateVersion(ctx context.Context, tenant TenantID, id TemplateID, version uint64) (MessageTemplateVersion, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(id)) != nil || version == 0 {
		return MessageTemplateVersion{}, ErrInvalid
	}
	var document []byte
	var digest string
	err := r.db.QueryRowContext(ctx, `SELECT digest,document FROM email_marketing_template_versions_v1 WHERE tenant_id=? AND template_id=? AND version=?`, tenant, id, version).Scan(&digest, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return MessageTemplateVersion{}, ErrNotFound
	}
	var result MessageTemplateVersion
	if err != nil || json.Unmarshal(document, &result) != nil || result.TenantID != tenant || result.TemplateID != id || result.Version != version || result.Digest != digest {
		if err != nil {
			return MessageTemplateVersion{}, err
		}
		return MessageTemplateVersion{}, ErrIntegrity
	}
	sealed, sealErr := SealTemplateVersion(result)
	if sealErr != nil || sealed.Digest != digest {
		return MessageTemplateVersion{}, ErrIntegrity
	}
	return result, nil
}

func (r *SQLiteRepository) ListMessageTemplates(ctx context.Context, tenant TenantID, after TemplateID, limit int) ([]MessageTemplate, error) {
	if validateIdentifier(string(tenant)) != nil || (after != "" && validateIdentifier(string(after)) != nil) || limit < 1 || limit > maxPageSize {
		return nil, ErrInvalid
	}
	rows, err := r.db.QueryContext(ctx, `SELECT document FROM email_marketing_templates_v1 WHERE tenant_id=? AND template_id>? ORDER BY template_id LIMIT ?`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]MessageTemplate, 0, limit)
	for rows.Next() {
		var document []byte
		var template MessageTemplate
		if rows.Scan(&document) != nil || json.Unmarshal(document, &template) != nil || template.TenantID != tenant {
			return nil, ErrIntegrity
		}
		result = append(result, template)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) PutCampaign(ctx context.Context, campaign Campaign, expected uint64) error {
	campaign.Segments, _ = normalizeSegments(campaign.Segments)
	if validateCampaign(campaign, expected) != nil {
		return ErrInvalid
	}
	if expected > 0 {
		current, err := r.GetCampaign(ctx, campaign.TenantID, campaign.ID)
		if err != nil || current.Generation != expected {
			return staleOr(err)
		}
		if current.State != CampaignDraft {
			if approvedCampaignDigest(current) != approvedCampaignDigest(campaign) || !approvalAppendOnly(current.Approvals, campaign.Approvals) ||
				(current.State != campaign.State && !campaignTransitionAllowed(current.State, campaign.State)) {
				return ErrInvalid
			}
		}
	}
	document, _ := json.Marshal(campaign)
	return putCAS(ctx, r.db,
		`INSERT INTO email_marketing_campaigns_v1(tenant_id,campaign_id,generation,revision,state,document,updated_at) VALUES(?,?,?,?,?,?,?)`,
		`UPDATE email_marketing_campaigns_v1 SET generation=?,revision=?,state=?,document=?,updated_at=? WHERE tenant_id=? AND campaign_id=? AND generation=?`, expected,
		[]any{campaign.TenantID, campaign.ID, campaign.Generation, campaign.Revision, campaign.State, document, dbTime(campaign.UpdatedAt)},
		[]any{campaign.Generation, campaign.Revision, campaign.State, document, dbTime(campaign.UpdatedAt), campaign.TenantID, campaign.ID, expected})
}

func (r *SQLiteRepository) GetCampaign(ctx context.Context, tenant TenantID, id CampaignID) (Campaign, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(id)) != nil {
		return Campaign{}, ErrInvalid
	}
	var document []byte
	var generation, revision uint64
	var state CampaignState
	err := r.db.QueryRowContext(ctx, `SELECT generation,revision,state,document FROM email_marketing_campaigns_v1 WHERE tenant_id=? AND campaign_id=?`, tenant, id).Scan(&generation, &revision, &state, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return Campaign{}, ErrNotFound
	}
	var campaign Campaign
	if err != nil || json.Unmarshal(document, &campaign) != nil || campaign.TenantID != tenant || campaign.ID != id || campaign.Generation != generation || campaign.Revision != revision || campaign.State != state {
		if err != nil {
			return Campaign{}, err
		}
		return Campaign{}, ErrIntegrity
	}
	return campaign, nil
}

func (r *SQLiteRepository) ListCampaigns(ctx context.Context, tenant TenantID, after CampaignID, limit int) ([]Campaign, error) {
	if validateIdentifier(string(tenant)) != nil || (after != "" && validateIdentifier(string(after)) != nil) || limit < 1 || limit > maxPageSize {
		return nil, ErrInvalid
	}
	rows, err := r.db.QueryContext(ctx, `SELECT document FROM email_marketing_campaigns_v1 WHERE tenant_id=? AND campaign_id>? ORDER BY campaign_id LIMIT ?`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Campaign, 0, limit)
	for rows.Next() {
		var document []byte
		var campaign Campaign
		if rows.Scan(&document) != nil || json.Unmarshal(document, &campaign) != nil || campaign.TenantID != tenant {
			return nil, ErrIntegrity
		}
		result = append(result, campaign)
	}
	return result, rows.Err()
}

// FreezeCampaign atomically freezes the first approved revision and creates
// one stable, idempotent attempt per normalized address.
func (r *SQLiteRepository) FreezeCampaign(ctx context.Context, campaign Campaign, expected uint64, limits CampaignLimits) (Campaign, error) {
	if limits.validate() != nil || campaign.State != CampaignDraft || campaign.Generation != expected || len(campaign.Approvals) != 1 || !approvalAppendOnly(nil, campaign.Approvals) {
		return Campaign{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Campaign{}, err
	}
	defer tx.Rollback()
	var currentDocument []byte
	var currentGeneration uint64
	if err = tx.QueryRowContext(ctx, `SELECT generation,document FROM email_marketing_campaigns_v1 WHERE tenant_id=? AND campaign_id=?`, campaign.TenantID, campaign.ID).Scan(&currentGeneration, &currentDocument); err != nil || currentGeneration != expected {
		return Campaign{}, staleOr(err)
	}
	var current Campaign
	if json.Unmarshal(currentDocument, &current) != nil || current.State != CampaignDraft || current.Revision != campaign.Revision {
		return Campaign{}, ErrStale
	}
	if campaignDraftDigest(current) != campaignDraftDigest(campaign) {
		return Campaign{}, ErrStale
	}
	version, err := templateVersionTx(ctx, tx, campaign.TenantID, campaign.TemplateID, campaign.TemplateVersion)
	if err != nil {
		return Campaign{}, err
	}
	var lifecycle TemplateLifecycle
	if err = tx.QueryRowContext(ctx, `SELECT lifecycle FROM email_marketing_templates_v1 WHERE tenant_id=? AND template_id=?`, campaign.TenantID, campaign.TemplateID).Scan(&lifecycle); err != nil || lifecycle != TemplateActive {
		return Campaign{}, ErrInvalid
	}
	recipients, err := freezeRecipientsTx(ctx, tx, campaign)
	if err != nil {
		return Campaign{}, err
	}
	if len(recipients) == 0 || uint64(len(recipients)) > limits.MaxRecipientsPerCampaign {
		return Campaign{}, ErrConflict
	}
	var queued uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND status IN ('queued','deferred','sent')`, campaign.TenantID).Scan(&queued); err != nil || queued+uint64(len(recipients)) > limits.MaxQueuedPerTenant {
		if err != nil {
			return Campaign{}, err
		}
		return Campaign{}, ErrConflict
	}
	campaign.TemplateDigest = version.Digest
	campaign.PolicyDigest = digestObject(struct {
		Segments []ListSegment
		Subject string
		From string
		ReplyTo string
		Variables map[string]string
		Sender string
		SenderProof string
		Profile string
		Rate uint32
		Concurrency uint16
		Tracking TrackingPolicy
		Consent ConsentPolicy
	}{campaign.Segments, campaign.SubjectOverride, campaign.From, campaign.ReplyTo, campaign.TemplateVariables, campaign.VerifiedSenderDomain, campaign.SenderVerificationDigest, campaign.DeliveryProfileRef, campaign.RatePerMinute, campaign.Concurrency, campaign.Tracking, campaign.Consent})
	campaign.SnapshotDigest = digestObject(recipients)
	campaign.RecipientCount = uint64(len(recipients))
	campaign.State = CampaignApproval
	campaign.Generation = expected + 1
	for i := range recipients {
		recipients[i].Ordinal = uint64(i + 1)
		recipients[i].SnapshotDigest = campaign.SnapshotDigest
		document, _ := json.Marshal(recipients[i])
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_recipients_v1(tenant_id,campaign_id,campaign_revision,ordinal,subscriber_id,list_id,address,address_digest,consent_id,consent_digest,snapshot_digest,document) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, recipients[i].TenantID, recipients[i].CampaignID, recipients[i].CampaignRevision, recipients[i].Ordinal, recipients[i].SubscriberID, recipients[i].ListID, recipients[i].Address.Normalized, recipients[i].Address.Digest, recipients[i].ConsentID, recipients[i].ConsentDigest, recipients[i].SnapshotDigest, document)
		if err != nil {
			return Campaign{}, ErrConflict
		}
		attemptID := AttemptID("attempt:" + DigestEvidence([]byte(fmt.Sprintf("%s:%s:%d:%s", campaign.TenantID, campaign.ID, campaign.Revision, recipients[i].Address.Digest)))[:40])
		attempt := QueueAttempt{TenantID: campaign.TenantID, CampaignID: campaign.ID, CampaignRevision: campaign.Revision, ID: attemptID, RecipientOrdinal: recipients[i].Ordinal, Status: AttemptQueued, NextAttemptAt: campaign.CreatedAt.UTC(), ProviderRef: campaign.DeliveryProfileRef, UpdatedAt: campaign.UpdatedAt.UTC()}
		attemptDocument, _ := json.Marshal(attempt)
		_, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_attempts_v1(attempt_id,tenant_id,campaign_id,campaign_revision,recipient_ordinal,status,attempt_number,next_attempt_at,lease_owner,lease_expires_at,fence,awaiting_receipt,document,updated_at) VALUES(?,?,?,?,?, 'queued',0,?,'','',0,0,?,?)`, attempt.ID, attempt.TenantID, attempt.CampaignID, attempt.CampaignRevision, attempt.RecipientOrdinal, dbTime(attempt.NextAttemptAt), attemptDocument, dbTime(attempt.UpdatedAt))
		if err != nil {
			return Campaign{}, ErrConflict
		}
		queuedReceipt := AttemptReceipt{ID: "receipt:" + DigestEvidence([]byte(string(attempt.ID)+":queued"))[:40], TenantID: attempt.TenantID, CampaignID: attempt.CampaignID, AttemptID: attempt.ID, Status: AttemptQueued, ProviderRef: campaign.DeliveryProfileRef, Provenance: "approval_snapshot", Reason: "eligible_at_approval", ObservedAt: campaign.UpdatedAt}
		receiptDocument, _ := json.Marshal(queuedReceipt)
		if _, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_receipts_v1(receipt_id,tenant_id,campaign_id,attempt_id,status,provider_message_id,delayed_event,observed_at,document) VALUES(?,?,?,?,?,'',0,?,?)`, queuedReceipt.ID, queuedReceipt.TenantID, queuedReceipt.CampaignID, queuedReceipt.AttemptID, queuedReceipt.Status, dbTime(queuedReceipt.ObservedAt), receiptDocument); err != nil {
			return Campaign{}, ErrConflict
		}
	}
	campaignDocument, _ := json.Marshal(campaign)
	result, err := tx.ExecContext(ctx, `UPDATE email_marketing_campaigns_v1 SET generation=?,state='approval',document=?,updated_at=? WHERE tenant_id=? AND campaign_id=? AND generation=? AND state='draft'`, campaign.Generation, campaignDocument, dbTime(campaign.UpdatedAt), campaign.TenantID, campaign.ID, expected)
	if err != nil {
		return Campaign{}, err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return Campaign{}, ErrStale
	}
	if err = tx.Commit(); err != nil {
		return Campaign{}, err
	}
	return campaign, nil
}

func templateVersionTx(ctx context.Context, tx *sql.Tx, tenant TenantID, id TemplateID, version uint64) (MessageTemplateVersion, error) {
	var document []byte
	var digest string
	err := tx.QueryRowContext(ctx, `SELECT digest,document FROM email_marketing_template_versions_v1 WHERE tenant_id=? AND template_id=? AND version=?`, tenant, id, version).Scan(&digest, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return MessageTemplateVersion{}, ErrNotFound
	}
	var result MessageTemplateVersion
	if err != nil || json.Unmarshal(document, &result) != nil || result.TenantID != tenant || result.TemplateID != id || result.Version != version || result.Digest != digest {
		if err != nil {
			return MessageTemplateVersion{}, err
		}
		return MessageTemplateVersion{}, ErrIntegrity
	}
	sealed, sealErr := SealTemplateVersion(result)
	if sealErr != nil || sealed.Digest != digest {
		return MessageTemplateVersion{}, ErrIntegrity
	}
	return result, nil
}

func freezeRecipientsTx(ctx context.Context, tx *sql.Tx, campaign Campaign) ([]FrozenRecipient, error) {
	byDigest := make(map[string]FrozenRecipient)
	for _, segment := range campaign.Segments {
		rows, err := tx.QueryContext(ctx, `SELECT s.document FROM email_marketing_memberships_v1 m JOIN email_marketing_subscribers_v1 s ON s.tenant_id=m.tenant_id AND s.subscriber_id=m.subscriber_id WHERE m.tenant_id=? AND m.list_id=? AND m.status='subscribed' AND s.lifecycle='active' ORDER BY s.address_digest,s.subscriber_id`, campaign.TenantID, segment.ListID)
		if err != nil {
			return nil, err
		}
		var subscribers []Subscriber
		for rows.Next() {
			var document []byte
			var subscriber Subscriber
			if rows.Scan(&document) != nil || json.Unmarshal(document, &subscriber) != nil {
				rows.Close()
				return nil, ErrIntegrity
			}
			if segmentMatches(subscriber.TagIDs, segment) {
				subscribers = append(subscribers, subscriber)
			}
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
		for _, subscriber := range subscribers {
			consent, consentErr := latestConsentTx(ctx, tx, campaign.TenantID, segment.ListID, subscriber.ID)
			if errors.Is(consentErr, ErrNotFound) || consentErr == nil && !consentEligible(consent, campaign.Consent) {
				continue
			}
			if consentErr != nil {
				return nil, consentErr
			}
			candidate := FrozenRecipient{TenantID: campaign.TenantID, CampaignID: campaign.ID, CampaignRevision: campaign.Revision, SubscriberID: subscriber.ID, ListID: segment.ListID, Address: subscriber.Address, ConsentID: consent.ID, ConsentDigest: digestObject(consent)}
			if prior, exists := byDigest[subscriber.Address.Digest]; !exists || candidate.ListID < prior.ListID || candidate.ListID == prior.ListID && candidate.SubscriberID < prior.SubscriberID {
				byDigest[subscriber.Address.Digest] = candidate
			}
		}
	}
	result := make([]FrozenRecipient, 0, len(byDigest))
	for _, recipient := range byDigest {
		result = append(result, recipient)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Address.Digest < result[j].Address.Digest })
	return result, nil
}

func latestConsentTx(ctx context.Context, tx *sql.Tx, tenant TenantID, list ListID, subscriber SubscriberID) (ConsentRecord, error) {
	var document []byte
	err := tx.QueryRowContext(ctx, `SELECT document FROM email_marketing_consents_v1 WHERE tenant_id=? AND list_id=? AND subscriber_id=? ORDER BY captured_at DESC,consent_id DESC LIMIT 1`, tenant, list, subscriber).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return ConsentRecord{}, ErrNotFound
	}
	var consent ConsentRecord
	if err != nil || json.Unmarshal(document, &consent) != nil {
		if err != nil {
			return ConsentRecord{}, err
		}
		return ConsentRecord{}, ErrIntegrity
	}
	return consent, nil
}

func consentEligible(consent ConsentRecord, policy ConsentPolicy) bool {
	if consent.ID == "" || consent.Purpose != policy.Purpose || policy.RequireAffirmative && !consent.Affirmative {
		return false
	}
	return !policy.RequireExactEvidence || consent.Verification.Certainty == CertaintyExact
}

func segmentMatches(tags []TagID, segment ListSegment) bool {
	present := make(map[TagID]struct{}, len(tags))
	for _, tag := range tags {
		present[tag] = struct{}{}
	}
	for _, required := range segment.RequireTagIDs {
		if _, ok := present[required]; !ok {
			return false
		}
	}
	for _, excluded := range segment.ExcludeTagIDs {
		if _, ok := present[excluded]; ok {
			return false
		}
	}
	return true
}

func validateMessageTemplate(template MessageTemplate, expected uint64) error {
	if validateIdentifier(string(template.TenantID)) != nil || validateIdentifier(string(template.ID)) != nil || template.Name == "" || len(template.Name) > maxNameBytes ||
		template.Generation != expected+1 || template.LatestVersion == 0 || template.CreatedAt.IsZero() || template.UpdatedAt.Before(template.CreatedAt) {
		return ErrInvalid
	}
	switch template.Lifecycle {
	case TemplateActive:
		if template.ArchivedAt != nil || template.DeleteAfter != nil {
			return ErrInvalid
		}
	case TemplateArchived:
		if template.ArchivedAt == nil {
			return ErrInvalid
		}
	case TemplateDeleted:
		if template.DeleteAfter == nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func campaignDraftDigest(campaign Campaign) string {
	return digestObject(struct {
		TenantID TenantID
		ID CampaignID
		Revision uint64
		Segments []ListSegment
		TemplateID TemplateID
		TemplateVersion uint64
		TemplateVariables map[string]string
		Subject string
		From string
		ReplyTo string
		SenderDomain string
		SenderDigest string
		Profile string
		ScheduleAt *time.Time
		Timezone string
		Rate uint32
		Concurrency uint16
		Tracking TrackingPolicy
		Consent ConsentPolicy
		CreatedBy ActorID
		CreatedAt time.Time
	}{campaign.TenantID, campaign.ID, campaign.Revision, campaign.Segments, campaign.TemplateID, campaign.TemplateVersion, campaign.TemplateVariables, campaign.SubjectOverride, campaign.From, campaign.ReplyTo, campaign.VerifiedSenderDomain, campaign.SenderVerificationDigest, campaign.DeliveryProfileRef, campaign.ScheduleAt, campaign.Timezone, campaign.RatePerMinute, campaign.Concurrency, campaign.Tracking, campaign.Consent, campaign.CreatedBy, campaign.CreatedAt})
}

func approvedCampaignDigest(campaign Campaign) string {
	return digestObject(struct {
		TenantID TenantID
		ID CampaignID
		Revision uint64
		Segments []ListSegment
		TemplateID TemplateID
		TemplateVersion uint64
		TemplateVariables map[string]string
		Subject string
		From string
		ReplyTo string
		SenderDomain string
		SenderDigest string
		Profile string
		Timezone string
		Rate uint32
		Concurrency uint16
		Tracking TrackingPolicy
		Consent ConsentPolicy
		PolicyDigest string
		TemplateDigest string
		SnapshotDigest string
		RecipientCount uint64
		CreatedBy ActorID
		CreatedAt time.Time
	}{campaign.TenantID, campaign.ID, campaign.Revision, campaign.Segments, campaign.TemplateID, campaign.TemplateVersion, campaign.TemplateVariables, campaign.SubjectOverride, campaign.From, campaign.ReplyTo, campaign.VerifiedSenderDomain, campaign.SenderVerificationDigest, campaign.DeliveryProfileRef, campaign.Timezone, campaign.RatePerMinute, campaign.Concurrency, campaign.Tracking, campaign.Consent, campaign.PolicyDigest, campaign.TemplateDigest, campaign.SnapshotDigest, campaign.RecipientCount, campaign.CreatedBy, campaign.CreatedAt})
}

func approvalAppendOnly(current, next []CampaignApprovalRecord) bool {
	if len(next) < len(current) {
		return false
	}
	for index := range current {
		if digestObject(current[index]) != digestObject(next[index]) {
			return false
		}
	}
	seen := make(map[ActorID]struct{}, len(next))
	for _, approval := range next {
		if validateIdentifier(string(approval.Approver)) != nil || approval.StepUpReceipt == "" || !validDigest(approval.EvidenceDigest) || approval.ApprovedAt.IsZero() {
			return false
		}
		if _, duplicate := seen[approval.Approver]; duplicate {
			return false
		}
		seen[approval.Approver] = struct{}{}
	}
	return true
}

func (r *SQLiteRepository) ListCampaignAttempts(ctx context.Context, tenant TenantID, campaign CampaignID, after AttemptID, limit int) ([]QueueAttempt, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(campaign)) != nil || (after != "" && validateIdentifier(string(after)) != nil) || limit < 1 || limit > maxPageSize {
		return nil, ErrInvalid
	}
	rows, err := r.db.QueryContext(ctx, `SELECT document FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND campaign_id=? AND attempt_id>? ORDER BY attempt_id LIMIT ?`, tenant, campaign, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]QueueAttempt, 0, limit)
	for rows.Next() {
		var document []byte
		var attempt QueueAttempt
		if rows.Scan(&document) != nil || json.Unmarshal(document, &attempt) != nil || attempt.TenantID != tenant || attempt.CampaignID != campaign {
			return nil, ErrIntegrity
		}
		result = append(result, attempt)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) CampaignStatistics(ctx context.Context, tenant TenantID, campaign CampaignID, minimumPopulation uint64, now time.Time) (CampaignStatistics, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(campaign)) != nil || now.IsZero() {
		return CampaignStatistics{}, ErrInvalid
	}
	statistics := CampaignStatistics{CampaignID: campaign, AsOf: now.UTC()}
	rows, err := r.db.QueryContext(ctx, `SELECT status,COUNT(*),SUM(awaiting_receipt) FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND campaign_id=? GROUP BY status`, tenant, campaign)
	if err != nil {
		return statistics, err
	}
	defer rows.Close()
	for rows.Next() {
		var status AttemptStatus
		var count, awaiting uint64
		if err = rows.Scan(&status, &count, &awaiting); err != nil {
			return CampaignStatistics{}, err
		}
		statistics.Denominator += count
		statistics.AwaitingReceipts += awaiting
		switch status {
		case AttemptQueued:
			statistics.Queued = count
		case AttemptSent:
			statistics.Sent = count
		case AttemptDelivered:
			statistics.Delivered = count
		case AttemptDeferred:
			statistics.Deferred = count
		case AttemptBounced:
			statistics.Bounced = count
		case AttemptComplained:
			statistics.Complained = count
		case AttemptSuppressed:
			statistics.Suppressed = count
		case AttemptFailed:
			statistics.Failed = count
		default:
			return CampaignStatistics{}, ErrIntegrity
		}
	}
	if err = rows.Err(); err != nil {
		return CampaignStatistics{}, err
	}
	if err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_marketing_campaign_receipts_v1 WHERE tenant_id=? AND campaign_id=? AND delayed_event=1`, tenant, campaign).Scan(&statistics.DelayedEvents); err != nil {
		return CampaignStatistics{}, err
	}
	statistics.SmallCohort = statistics.Denominator < minimumPopulation
	return statistics, nil
}

func (r *SQLiteRepository) ListCampaignReceipts(ctx context.Context, tenant TenantID, campaign CampaignID, after string, limit int) ([]AttemptReceipt, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(campaign)) != nil || (after != "" && validateIdentifier(after) != nil) || limit < 1 || limit > maxPageSize {
		return nil, ErrInvalid
	}
	rows, err := r.db.QueryContext(ctx, `SELECT document FROM email_marketing_campaign_receipts_v1 WHERE tenant_id=? AND campaign_id=? AND receipt_id>? ORDER BY receipt_id LIMIT ?`, tenant, campaign, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AttemptReceipt, 0, limit)
	for rows.Next() {
		var document []byte
		var receipt AttemptReceipt
		if rows.Scan(&document) != nil || json.Unmarshal(document, &receipt) != nil || receipt.TenantID != tenant || receipt.CampaignID != campaign {
			return nil, ErrIntegrity
		}
		result = append(result, receipt)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) CancelCampaignPendingAttempts(ctx context.Context, tenant TenantID, campaign CampaignID, now time.Time) error {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(campaign)) != nil || now.IsZero() {
		return ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT document FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND campaign_id=? AND status IN ('queued','deferred') AND awaiting_receipt=0 AND lease_owner='' ORDER BY attempt_id`, tenant, campaign)
	if err != nil {
		return err
	}
	var attempts []QueueAttempt
	for rows.Next() {
		var document []byte
		var attempt QueueAttempt
		if rows.Scan(&document) != nil || json.Unmarshal(document, &attempt) != nil {
			rows.Close()
			return ErrIntegrity
		}
		attempts = append(attempts, attempt)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, attempt := range attempts {
		attempt.Status, attempt.Reason, attempt.NextAttemptAt, attempt.UpdatedAt = AttemptFailed, "cancelled_before_submission", time.Time{}, now
		receipt := AttemptReceipt{ID: "receipt:" + DigestEvidence([]byte(string(attempt.ID)+":cancelled"))[:40], TenantID: tenant, CampaignID: campaign, AttemptID: attempt.ID, Status: AttemptFailed, Provenance: "campaign_cancellation", Reason: attempt.Reason, ObservedAt: now}
		if err = finishAttemptTx(ctx, tx, attempt, receipt, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
