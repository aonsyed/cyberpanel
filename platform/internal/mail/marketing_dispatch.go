package mail

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

type campaignDispatchCandidate struct {
	TenantID string
	Campaign Campaign
}

// RunDispatchQueue operates the campaign-only queue. It never runs in paneld,
// and its additional broker semaphore keeps campaign SMTP capacity separate
// from transactional and interactive mail submission.
func (c *CampaignCoordinator) RunDispatchQueue(ctx context.Context, interval time.Duration, maximumConcurrent uint32) {
	if c == nil || c.Sender == nil || c.Store.DB == nil || ctx == nil {
		return
	}
	if interval < 250*time.Millisecond {
		interval = time.Second
	}
	if maximumConcurrent == 0 {
		maximumConcurrent = 4
	}
	if maximumConcurrent > 8 {
		maximumConcurrent = 8
	}
	c.dispatchRound(ctx, maximumConcurrent)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.dispatchRound(ctx, maximumConcurrent)
		}
	}
}

func (c *CampaignCoordinator) dispatchRound(ctx context.Context, maximum uint32) {
	_ = c.Store.markStaleCampaignAttemptsAmbiguous(ctx, c.now().Add(-5*time.Minute))
	var workers sync.WaitGroup
	for index := uint32(0); index < maximum; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_ = c.dispatchOne(ctx)
		}()
	}
	workers.Wait()
}

func (c *CampaignCoordinator) dispatchOne(ctx context.Context) error {
	for scan := 0; scan < 128; scan++ {
		candidates, err := c.Store.dispatchCampaigns(ctx, 128)
		if err != nil {
			return err
		}
		if len(candidates) == 0 {
			return nil
		}
		progressed := false
		for _, candidate := range candidates {
			campaign := candidate.Campaign
			if campaign.State == "scheduled" {
				when, parseErr := CampaignScheduleTime(campaign.Schedule)
				if parseErr != nil {
					return parseErr
				}
				if when.After(c.now()) {
					continue
				}
				campaign.State = "running"
				campaign.Generation++
				if err = c.Store.AdvanceCampaign(ctx, candidate.TenantID, campaign, candidate.Campaign.Generation); err != nil {
					if errors.Is(err, ErrConflict) {
						continue
					}
					return err
				}
				progressed = true
			}
			if campaign.State != "running" {
				continue
			}
			recipient, found, err := c.Store.nextCampaignRecipient(ctx, candidate.TenantID, campaign, c.now())
			if err != nil {
				return err
			}
			if !found {
				completed, completeErr := c.Store.completeCampaignIfDrained(ctx, candidate.TenantID, campaign)
				if completeErr != nil && !errors.Is(completeErr, ErrConflict) {
					return completeErr
				}
				progressed = progressed || completed
				continue
			}
			attempt := campaignAttemptFor(candidate.TenantID, campaign, recipient)
			result, sendErr := c.SendOne(ctx, candidate.TenantID, campaign, recipient, attempt)
			if sendErr != nil {
				return sendErr
			}
			if result.State == "reserved" {
				progressed = true
				continue
			}
			return nil
		}
		if !progressed {
			return nil
		}
	}
	return nil
}

func (s MarketingStore) dispatchCampaigns(ctx context.Context, limit int) ([]campaignDispatchCandidate, error) {
	if s.DB == nil || ctx == nil {
		return nil, ErrInvalidCommand
	}
	if limit < 1 || limit > 512 {
		limit = 128
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT tenant_id,campaign_json FROM marketing_campaigns_v2 WHERE state IN ('scheduled','running') ORDER BY tenant_id,id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]campaignDispatchCandidate, 0, limit)
	for rows.Next() {
		var tenant string
		var raw []byte
		if err = rows.Scan(&tenant, &raw); err != nil {
			return nil, err
		}
		var campaign Campaign
		if err = strictJSON(raw, &campaign); err != nil || validateCampaignRecord(tenant, campaign) != nil {
			return nil, errors.Join(ErrInvalidReceipt, err)
		}
		items = append(items, campaignDispatchCandidate{TenantID:tenant, Campaign:campaign})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s MarketingStore) nextCampaignRecipient(ctx context.Context, tenant string, campaign Campaign, now time.Time) (CampaignRecipient, bool, error) {
	if s.DB == nil || ctx == nil || !validOpaque(tenant) || campaign.State != "running" || !validOpaque(campaign.SnapshotRef) {
		return CampaignRecipient{}, false, ErrInvalidCommand
	}
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT recipient.recipient_json FROM marketing_campaign_snapshot_recipients_v2 AS recipient LEFT JOIN marketing_attempts_v2 AS attempt ON attempt.tenant_id=recipient.tenant_id AND attempt.campaign_id=recipient.campaign_id AND attempt.contact_id=recipient.contact_id WHERE recipient.tenant_id=? AND recipient.campaign_id=? AND recipient.snapshot_id=? AND (attempt.id IS NULL OR attempt.state='deferred' AND attempt.next_attempt<=?) ORDER BY recipient.contact_id LIMIT 1`, tenant, campaign.ID, campaign.SnapshotRef, now.UTC()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return CampaignRecipient{}, false, nil
	}
	if err != nil {
		return CampaignRecipient{}, false, err
	}
	var value CampaignRecipient
	if err = strictJSON(raw, &value); err != nil || validateCampaignRecipient(value) != nil {
		return CampaignRecipient{}, false, errors.Join(ErrInvalidReceipt, err)
	}
	return value, true, nil
}

func (s MarketingStore) completeCampaignIfDrained(ctx context.Context, tenant string, campaign Campaign) (bool, error) {
	if campaign.State != "running" {
		return false, nil
	}
	var outstanding uint64
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM marketing_campaign_snapshot_recipients_v2 AS recipient LEFT JOIN marketing_attempts_v2 AS attempt ON attempt.tenant_id=recipient.tenant_id AND attempt.campaign_id=recipient.campaign_id AND attempt.contact_id=recipient.contact_id WHERE recipient.tenant_id=? AND recipient.campaign_id=? AND recipient.snapshot_id=? AND (attempt.id IS NULL OR attempt.state IN ('reserved','deferred'))`, tenant, campaign.ID, campaign.SnapshotRef).Scan(&outstanding)
	if err != nil {
		return false, err
	}
	if outstanding != 0 {
		return false, nil
	}
	campaign.State = "completed"
	campaign.Generation++
	if err = s.AdvanceCampaign(ctx, tenant, campaign, campaign.Generation-1); err != nil {
		return false, err
	}
	return true, nil
}

func (s MarketingStore) markStaleCampaignAttemptsAmbiguous(ctx context.Context, cutoff time.Time) error {
	rows, err := s.DB.QueryContext(ctx, `SELECT tenant_id,id,attempt_json FROM marketing_attempts_v2 WHERE state='reserved' AND updated_at<=? ORDER BY tenant_id,id LIMIT 512`, cutoff.UTC())
	if err != nil {
		return err
	}
	type staleAttempt struct{ tenant string; id AttemptID; raw []byte; value CampaignAttempt }
	items := make([]staleAttempt, 0, 64)
	for rows.Next() {
		var item staleAttempt
		if err = rows.Scan(&item.tenant, &item.id, &item.raw); err != nil {
			rows.Close()
			return err
		}
		if err = strictJSON(item.raw, &item.value); err != nil || item.value.TenantID != item.tenant || item.value.ID != item.id || item.value.State != "reserved" {
			rows.Close()
			return errors.Join(ErrInvalidReceipt, err)
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, item := range items {
		item.value.State = "ambiguous"
		item.value.Detail = "campaign worker lease expired; submission outcome requires reconciliation"
		item.value.NextAttempt = time.Time{}
		item.value.UpdatedAt = time.Now().UTC()
		raw, marshalErr := json.Marshal(item.value)
		if marshalErr != nil {
			return marshalErr
		}
		result, updateErr := s.DB.ExecContext(ctx, `UPDATE marketing_attempts_v2 SET state='ambiguous',next_attempt=NULL,attempt_json=?,updated_at=? WHERE tenant_id=? AND id=? AND state='reserved' AND attempt_json=?`, raw, item.value.UpdatedAt, item.tenant, item.id, item.raw)
		if updateErr != nil {
			return updateErr
		}
		if _, updateErr = result.RowsAffected(); updateErr != nil {
			return updateErr
		}
	}
	return nil
}

func campaignAttemptFor(tenant string, campaign Campaign, recipient CampaignRecipient) CampaignAttempt {
	sum := sha256.Sum256([]byte("cyberpanel-campaign-attempt-v1\x00" + tenant + "\x00" + string(campaign.ID) + "\x00" + campaign.SnapshotRef + "\x00" + string(recipient.ContactID)))
	digest := hex.EncodeToString(sum[:])
	return CampaignAttempt{ID:AttemptID("attempt_" + digest[:48]), TenantID:tenant, CampaignID:campaign.ID, ContactID:recipient.ContactID, Address:recipient.Address, IdempotencyKey:"campaign_" + digest}
}

func NormalizeCampaignSchedule(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Year() < 2020 || parsed.Year() > 2200 {
		return "", ErrInvalidCommand
	}
	return parsed.UTC().Format(time.RFC3339), nil
}

func CampaignScheduleTime(value string) (time.Time, error) {
	normalized, err := NormalizeCampaignSchedule(value)
	if err != nil || normalized == "" {
		return time.Time{}, ErrInvalidCommand
	}
	parsed, err := time.Parse(time.RFC3339, normalized)
	if err != nil {
		return time.Time{}, ErrInvalidCommand
	}
	return parsed.UTC(), nil
}
