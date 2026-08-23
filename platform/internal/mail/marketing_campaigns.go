package mail

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

func (s MarketingStore) ApproveCampaign(ctx context.Context, tenant string, id CampaignID, expected uint64, approvedBy string) (Campaign, CampaignSnapshot, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(id)) || expected == 0 || !validOpaque(approvedBy) {
		return Campaign{}, CampaignSnapshot{}, ErrInvalidCommand
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	defer tx.Rollback()
	var campaignRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT campaign_json FROM marketing_campaigns_v2 WHERE tenant_id=? AND id=?`, tenant, id).Scan(&campaignRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Campaign{}, CampaignSnapshot{}, ErrNotFound
		}
		return Campaign{}, CampaignSnapshot{}, err
	}
	var campaign Campaign
	if err = strictJSON(campaignRaw, &campaign); err != nil || campaign.ID != id || validateCampaignRecord(tenant, campaign) != nil {
		return Campaign{}, CampaignSnapshot{}, errors.Join(ErrInvalidReceipt, err)
	}
	if campaign.Generation != expected || campaign.State != "draft" {
		return Campaign{}, CampaignSnapshot{}, ErrConflict
	}
	if err = approvedTemplateAvailableTx(ctx, tx, tenant, campaign.TemplateRef); err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	var listRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT list_json FROM marketing_lists_v2 WHERE tenant_id=? AND id=?`, tenant, campaign.List).Scan(&listRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Campaign{}, CampaignSnapshot{}, ErrNotFound
		}
		return Campaign{}, CampaignSnapshot{}, err
	}
	var list List
	if err = strictJSON(listRaw, &list); err != nil || list.ID != campaign.List {
		return Campaign{}, CampaignSnapshot{}, errors.Join(ErrInvalidReceipt, err)
	}
	recipients, excluded, err := campaignRecipientsTx(ctx, tx, tenant, list.Contacts)
	if err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	if len(recipients) == 0 {
		return Campaign{}, CampaignSnapshot{}, ErrConflict
	}
	listSum := sha256.Sum256(listRaw)
	recipientRaw, err := json.Marshal(recipients)
	if err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	recipientSum := sha256.Sum256(recipientRaw)
	snapshotSum := sha256.Sum256([]byte("cyberpanel-campaign-snapshot-v1\x00" + tenant + "\x00" + string(id) + "\x00" + hex.EncodeToString(listSum[:]) + "\x00" + hex.EncodeToString(recipientSum[:])))
	now := time.Now().UTC()
	snapshot := CampaignSnapshot{
		ID:"snapshot_" + hex.EncodeToString(snapshotSum[:24]), CampaignID:id, ListID:list.ID,
		ListDigest:hex.EncodeToString(listSum[:]), RecipientDigest:hex.EncodeToString(recipientSum[:]),
		Requested:uint64(len(list.Contacts)), Eligible:uint64(len(recipients)), Excluded:excluded,
		CreatedAt:now, ApprovedBy:approvedBy,
	}
	if err = validateCampaignSnapshot(snapshot); err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	snapshotRaw, err := json.Marshal(snapshot)
	if err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO marketing_campaign_snapshots_v2(id,tenant_id,campaign_id,snapshot_json,created_at) VALUES(?,?,?,?,?)`, snapshot.ID, tenant, id, snapshotRaw, snapshot.CreatedAt); err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	for _, recipient := range recipients {
		raw, marshalErr := json.Marshal(recipient)
		if marshalErr != nil {
			return Campaign{}, CampaignSnapshot{}, marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO marketing_campaign_snapshot_recipients_v2(snapshot_id,tenant_id,campaign_id,contact_id,address,recipient_json) VALUES(?,?,?,?,?,?)`, snapshot.ID, tenant, id, recipient.ContactID, recipient.Address, raw); err != nil {
			return Campaign{}, CampaignSnapshot{}, err
		}
	}
	campaign.State = "approved"
	campaign.SnapshotRef = snapshot.ID
	campaign.RecipientCount = snapshot.Eligible
	campaign.ApprovedAt = &now
	campaign.ApprovedBy = approvedBy
	campaign.Generation++
	if err = validateCampaignRecord(tenant, campaign); err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	updatedRaw, err := json.Marshal(campaign)
	if err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE marketing_campaigns_v2 SET state=?,campaign_json=? WHERE tenant_id=? AND id=? AND campaign_json=?`, campaign.State, updatedRaw, tenant, id, campaignRaw)
	if err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	if affected != 1 {
		return Campaign{}, CampaignSnapshot{}, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return Campaign{}, CampaignSnapshot{}, err
	}
	return campaign, snapshot, nil
}

func (s MarketingStore) CampaignSnapshot(ctx context.Context, tenant string, campaign Campaign) (CampaignSnapshot, bool, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(campaign.ID)) || !validOpaque(campaign.SnapshotRef) {
		return CampaignSnapshot{}, false, ErrInvalidCommand
	}
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM marketing_campaign_snapshots_v2 WHERE tenant_id=? AND campaign_id=? AND id=?`, tenant, campaign.ID, campaign.SnapshotRef).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return CampaignSnapshot{}, false, nil
	}
	if err != nil {
		return CampaignSnapshot{}, false, err
	}
	var value CampaignSnapshot
	if err = strictJSON(raw, &value); err != nil || value.ID != campaign.SnapshotRef || value.CampaignID != campaign.ID || validateCampaignSnapshot(value) != nil {
		return CampaignSnapshot{}, false, errors.Join(ErrInvalidReceipt, err)
	}
	return value, true, nil
}

func (s MarketingStore) CampaignRecipient(ctx context.Context, tenant string, campaign Campaign, contact ContactID) (CampaignRecipient, bool, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || !validOpaque(string(campaign.ID)) || !validOpaque(campaign.SnapshotRef) || !validOpaque(string(contact)) {
		return CampaignRecipient{}, false, ErrInvalidCommand
	}
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT recipient_json FROM marketing_campaign_snapshot_recipients_v2 WHERE tenant_id=? AND campaign_id=? AND snapshot_id=? AND contact_id=?`, tenant, campaign.ID, campaign.SnapshotRef, contact).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return CampaignRecipient{}, false, nil
	}
	if err != nil {
		return CampaignRecipient{}, false, err
	}
	var value CampaignRecipient
	if err = strictJSON(raw, &value); err != nil || value.ContactID != contact || validateCampaignRecipient(value) != nil {
		return CampaignRecipient{}, false, errors.Join(ErrInvalidReceipt, err)
	}
	return value, true, nil
}

func approvedTemplateAvailableTx(ctx context.Context, tx *sql.Tx, tenant, reference string) error {
	id, generation, err := parseCampaignTemplateReference(reference)
	if err != nil {
		return err
	}
	var selectedRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT template_json FROM marketing_templates_v2 WHERE tenant_id=? AND id=? AND generation=?`, tenant, id, generation).Scan(&selectedRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	var selected CampaignTemplate
	if err = strictJSON(selectedRaw, &selected); err != nil || selected.ID != id || selected.Generation != generation {
		return errors.Join(ErrInvalidReceipt, err)
	}
	var latestRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT template_json FROM marketing_templates_v2 WHERE tenant_id=? AND id=? ORDER BY generation DESC LIMIT 1`, tenant, id).Scan(&latestRaw); err != nil {
		return err
	}
	var latest CampaignTemplate
	if err = strictJSON(latestRaw, &latest); err != nil || latest.ID != id {
		return errors.Join(ErrInvalidReceipt, err)
	}
	if selected.State != "approved" || latest.State == "archived" {
		return ErrConflict
	}
	return nil
}

func campaignRecipientsTx(ctx context.Context, tx *sql.Tx, tenant string, contacts []ContactID) ([]CampaignRecipient, map[string]uint64, error) {
	requested := make(map[ContactID]struct{}, len(contacts))
	for _, contact := range contacts {
		if !validOpaque(string(contact)) {
			return nil, nil, ErrInvalidCommand
		}
		requested[contact] = struct{}{}
	}
	available := make(map[ContactID]struct{}, len(contacts))
	recipients := make([]CampaignRecipient, 0, len(contacts))
	excluded := map[string]uint64{}
	for start := 0; start < len(contacts); start += 200 {
		end := start + 200
		if end > len(contacts) {
			end = len(contacts)
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", end-start), ",")
		arguments := make([]any, 0, end-start+1)
		arguments = append(arguments, tenant)
		for _, contact := range contacts[start:end] {
			arguments = append(arguments, contact)
		}
		query := `SELECT subscriber.id,subscriber.subscriber_json,(SELECT consent.event_json FROM marketing_consent_events_v2 AS consent WHERE consent.tenant_id=subscriber.tenant_id AND consent.address=subscriber.address ORDER BY consent.occurred_at DESC,consent.id DESC LIMIT 1) FROM marketing_subscribers_v2 AS subscriber WHERE subscriber.tenant_id=? AND subscriber.id IN (` + placeholders + `)`
		rows, err := tx.QueryContext(ctx, query, arguments...)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var id string
			var subscriberRaw, consentRaw []byte
			if err = rows.Scan(&id, &subscriberRaw, &consentRaw); err != nil {
				rows.Close()
				return nil, nil, err
			}
			contact := ContactID(id)
			available[contact] = struct{}{}
			var subscriber Subscriber
			if err = strictJSON(subscriberRaw, &subscriber); err != nil || subscriber.ID != contact || validateSubscriber(subscriber) != nil {
				rows.Close()
				return nil, nil, errors.Join(ErrInvalidReceipt, err)
			}
			if subscriber.State != SubscriberActive {
				excluded["archived"]++
				continue
			}
			if subscriber.Verification != VerificationVerified {
				excluded["not_verified"]++
				continue
			}
			if len(consentRaw) == 0 {
				excluded["no_consent"]++
				continue
			}
			var consent ConsentEvent
			if err = strictJSON(consentRaw, &consent); err != nil || consent.TenantID != tenant || consent.Address != subscriber.Address {
				rows.Close()
				return nil, nil, errors.Join(ErrInvalidReceipt, err)
			}
			if consent.State != Consented || consent.ContactID != subscriber.ID {
				reason := "no_consent"
				if consent.State == Suppressed {
					reason = "suppressed_" + string(consent.SuppressionReason)
				}
				excluded[reason]++
				continue
			}
			recipients = append(recipients, CampaignRecipient{ContactID:subscriber.ID, Address:subscriber.Address, SubscriberGeneration:subscriber.Generation, ConsentEventID:consent.ID})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, nil, err
		}
		rows.Close()
	}
	for contact := range requested {
		if _, found := available[contact]; !found {
			excluded["missing_subscriber"]++
		}
	}
	sort.Slice(recipients, func(left, right int) bool {
		if recipients[left].Address == recipients[right].Address {
			return recipients[left].ContactID < recipients[right].ContactID
		}
		return recipients[left].Address < recipients[right].Address
	})
	return recipients, excluded, nil
}

func validateCampaignRecipient(value CampaignRecipient) error {
	if !validOpaque(string(value.ContactID)) || ValidateAddress(value.Address) != nil || value.Address != canonicalMarketingAddress(value.Address) || value.SubscriberGeneration == 0 || !validOpaque(value.ConsentEventID) {
		return ErrInvalidCommand
	}
	return nil
}

func validateCampaignSnapshot(value CampaignSnapshot) error {
	if !validOpaque(value.ID) || !validOpaque(string(value.CampaignID)) || !validOpaque(string(value.ListID)) || !validMailEvidenceDigest(value.ListDigest) || !validMailEvidenceDigest(value.RecipientDigest) || value.Requested == 0 || value.Eligible == 0 || value.Eligible > value.Requested || value.CreatedAt.IsZero() || !validOpaque(value.ApprovedBy) {
		return ErrInvalidCommand
	}
	var excluded uint64
	for reason, count := range value.Excluded {
		if !validOpaque(reason) || count == 0 {
			return ErrInvalidCommand
		}
		excluded += count
	}
	if value.Eligible+excluded != value.Requested {
		return ErrInvalidCommand
	}
	return nil
}
