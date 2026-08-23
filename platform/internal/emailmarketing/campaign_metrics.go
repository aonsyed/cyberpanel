package emailmarketing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

type DeliveryStateCounts struct {
	Denominator uint64
	Queued      uint64
	Sent        uint64
	Delivered   uint64
	Deferred    uint64
	Bounced     uint64
	Complained  uint64
	Suppressed  uint64
	Failed      uint64
}

type ProviderMetric struct {
	ProviderRef string
	Attempts    uint64
	Events      uint64
	Queued      uint64
	Sent        uint64
	Delivered   uint64
	Deferred    uint64
	Bounced     uint64
	Complained  uint64
	Suppressed  uint64
	Failed      uint64
}

type CampaignMetricBucket struct {
	Start      time.Time
	End        time.Time
	Delivered uint64
	Deferred  uint64
	Bounced   uint64
	Complained uint64
	Failed    uint64
}

type ListCampaignMetric struct {
	ListID      ListID
	Counts      DeliveryStateCounts
	SmallCohort bool
}

type CampaignMetricQuality struct {
	EventWatermark    *time.Time
	LatestReceivedAt  *time.Time
	WatermarkLag      time.Duration
	DelayedEvents     uint64
	OutOfOrderEvents  uint64
	AwaitingReceipts  uint64
	MissingProviderData bool
	ProviderCardinalityTruncated bool
}

type CampaignMetricsSnapshot struct {
	TenantID     TenantID
	CampaignID   CampaignID
	Counts       DeliveryStateCounts
	Lists        []ListCampaignMetric
	Providers    []ProviderMetric
	TimeSeries   []CampaignMetricBucket
	Quality      CampaignMetricQuality
	SmallCohort  bool
	AsOf         time.Time
}

type CampaignMetricsQuery struct {
	Start                 time.Time
	End                   time.Time
	BucketWidth           time.Duration
	MaximumBuckets        int
	MaximumProviders      int
	MinimumReportPopulation uint64
}

func (query CampaignMetricsQuery) validate(now time.Time) error {
	if query.Start.IsZero() || query.End.IsZero() || !query.End.After(query.Start) || query.End.After(now.Add(time.Minute)) ||
		query.BucketWidth < time.Hour || query.BucketWidth > 24*time.Hour || query.MaximumBuckets < 1 || query.MaximumBuckets > 168 ||
		query.MaximumProviders < 1 || query.MaximumProviders > 32 || query.MinimumReportPopulation == 0 ||
		query.End.Sub(query.Start) > time.Duration(query.MaximumBuckets)*query.BucketWidth {
		return ErrInvalid
	}
	return nil
}

type CampaignMetricsRepository interface {
	ReadCampaignMetrics(context.Context, TenantID, CampaignID, CampaignMetricsQuery, time.Time) (CampaignMetricsSnapshot, error)
}

type CampaignMetricsService struct {
	Repository CampaignMetricsRepository
	Authorizer Authorizer
	Audit      AuditSink
	Now        func() time.Time
}

func (service CampaignMetricsService) Read(ctx context.Context, access AdministrativeContext, campaign CampaignID, query CampaignMetricsQuery) (CampaignMetricsSnapshot, error) {
	request := AuthorizationRequest{TenantID: access.TenantID, ActorID: access.ActorID, Action: "emailmarketing.campaign.metrics", Resource: string(campaign), DataClass: "aggregate_delivery_metadata"}
	if service.Repository == nil || service.Authorizer == nil || service.Audit == nil || service.Now == nil ||
		validateIdentifier(string(access.TenantID)) != nil || validateIdentifier(string(access.ActorID)) != nil || validateIdentifier(string(campaign)) != nil ||
		query.validate(service.Now().UTC()) != nil || service.Authorizer.Authorize(ctx, request) != nil {
		return CampaignMetricsSnapshot{}, ErrUnauthorized
	}
	snapshot, err := service.Repository.ReadCampaignMetrics(ctx, access.TenantID, campaign, query, service.Now().UTC())
	if err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	evidence := digestObject(struct {
		Campaign CampaignID
		AsOf time.Time
		Denominator uint64
	}{campaign, snapshot.AsOf, snapshot.Counts.Denominator})
	if err = service.Audit.RecordAudit(ctx, AuditRecord{TenantID: access.TenantID, ActorID: access.ActorID, Action: request.Action, Resource: request.Resource, Outcome: "read", EvidenceDigest: evidence, OccurredAt: service.Now().UTC()}); err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	return snapshot, nil
}

func (r *SQLiteRepository) ReadCampaignMetrics(ctx context.Context, tenant TenantID, campaign CampaignID, query CampaignMetricsQuery, now time.Time) (CampaignMetricsSnapshot, error) {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(string(campaign)) != nil || query.validate(now) != nil {
		return CampaignMetricsSnapshot{}, ErrInvalid
	}
	snapshot := CampaignMetricsSnapshot{TenantID: tenant, CampaignID: campaign, AsOf: now.UTC()}
	var campaignDocument []byte
	if err := r.db.QueryRowContext(ctx, `SELECT document FROM email_marketing_campaigns_v1 WHERE tenant_id=? AND campaign_id=?`, tenant, campaign).Scan(&campaignDocument); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CampaignMetricsSnapshot{}, ErrNotFound
		}
		return CampaignMetricsSnapshot{}, err
	}
	var campaignModel Campaign
	if json.Unmarshal(campaignDocument, &campaignModel) != nil || campaignModel.TenantID != tenant || campaignModel.ID != campaign {
		return CampaignMetricsSnapshot{}, ErrIntegrity
	}
	frozen := campaignModel.RecipientCount
	snapshot.Counts.Denominator = frozen
	rows, err := r.db.QueryContext(ctx, `SELECT status,COUNT(*) FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND campaign_id=? GROUP BY status`, tenant, campaign)
	if err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	for rows.Next() {
		var status AttemptStatus
		var count uint64
		if rows.Scan(&status, &count) != nil || addDeliveryCount(&snapshot.Counts, status, count) != nil {
			rows.Close()
			return CampaignMetricsSnapshot{}, ErrIntegrity
		}
	}
	if err = rows.Close(); err != nil || deliveryCountTotal(snapshot.Counts) != frozen {
		return CampaignMetricsSnapshot{}, ErrIntegrity
	}
	snapshot.SmallCohort = frozen < query.MinimumReportPopulation
	listRows, err := r.db.QueryContext(ctx, `SELECT r.list_id,a.status,COUNT(*) FROM email_marketing_campaign_recipients_v1 r JOIN email_marketing_campaign_attempts_v1 a ON a.tenant_id=r.tenant_id AND a.campaign_id=r.campaign_id AND a.campaign_revision=r.campaign_revision AND a.recipient_ordinal=r.ordinal WHERE r.tenant_id=? AND r.campaign_id=? GROUP BY r.list_id,a.status ORDER BY r.list_id,a.status`, tenant, campaign)
	if err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	byList := make(map[ListID]*ListCampaignMetric)
	for listRows.Next() {
		var list ListID
		var status AttemptStatus
		var count uint64
		if listRows.Scan(&list, &status, &count) != nil {
			listRows.Close()
			return CampaignMetricsSnapshot{}, ErrIntegrity
		}
		metric := byList[list]
		if metric == nil {
			metric = &ListCampaignMetric{ListID: list}
			byList[list] = metric
		}
		metric.Counts.Denominator += count
		if addDeliveryCount(&metric.Counts, status, count) != nil {
			listRows.Close()
			return CampaignMetricsSnapshot{}, ErrIntegrity
		}
	}
	if err = listRows.Close(); err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	for _, metric := range byList {
		metric.SmallCohort = metric.Counts.Denominator < query.MinimumReportPopulation
		snapshot.Lists = append(snapshot.Lists, *metric)
	}
	sort.Slice(snapshot.Lists, func(i, j int) bool { return snapshot.Lists[i].ListID < snapshot.Lists[j].ListID })
	var listDenominator uint64
	for _, metric := range snapshot.Lists {
		listDenominator += metric.Counts.Denominator
	}
	if listDenominator != frozen {
		return CampaignMetricsSnapshot{}, ErrIntegrity
	}
	providerRows, err := r.db.QueryContext(ctx, `SELECT document FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND campaign_id=? ORDER BY attempt_id`, tenant, campaign)
	if err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	providers := make(map[string]*ProviderMetric)
	for providerRows.Next() {
		var document []byte
		var attempt QueueAttempt
		if providerRows.Scan(&document) != nil || json.Unmarshal(document, &attempt) != nil || attempt.ProviderRef == "" {
			providerRows.Close()
			return CampaignMetricsSnapshot{}, ErrIntegrity
		}
		provider := attempt.ProviderRef
		metric := providers[provider]
		if metric == nil {
			if len(providers) >= query.MaximumProviders {
				snapshot.Quality.ProviderCardinalityTruncated = true
				continue
			}
			metric = &ProviderMetric{ProviderRef: provider}
			providers[provider] = metric
		}
		metric.Attempts++
		addProviderCount(metric, attempt.Status, 1)
	}
	if err = providerRows.Close(); err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	eventProviderRows, err := r.db.QueryContext(ctx, `SELECT provider_ref,COUNT(*) FROM email_marketing_delivery_events_v1 WHERE tenant_id=? AND campaign_id=? AND occurred_at>=? AND occurred_at<? GROUP BY provider_ref ORDER BY provider_ref`, tenant, campaign, dbTime(query.Start), dbTime(query.End))
	if err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	for eventProviderRows.Next() {
		var provider string
		var count uint64
		if eventProviderRows.Scan(&provider, &count) != nil {
			eventProviderRows.Close()
			return CampaignMetricsSnapshot{}, ErrIntegrity
		}
		metric := providers[provider]
		if metric == nil {
			if len(providers) >= query.MaximumProviders {
				snapshot.Quality.ProviderCardinalityTruncated = true
				continue
			}
			metric = &ProviderMetric{ProviderRef: provider}
			providers[provider] = metric
		}
		metric.Events = count
	}
	if err = eventProviderRows.Close(); err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	for _, metric := range providers {
		snapshot.Providers = append(snapshot.Providers, *metric)
	}
	sort.Slice(snapshot.Providers, func(i, j int) bool { return snapshot.Providers[i].ProviderRef < snapshot.Providers[j].ProviderRef })
	if !snapshot.SmallCohort {
		snapshot.TimeSeries = makeMetricBuckets(query)
		eventRows, eventErr := r.db.QueryContext(ctx, `SELECT status,occurred_at FROM email_marketing_delivery_events_v1 WHERE tenant_id=? AND campaign_id=? AND occurred_at>=? AND occurred_at<? ORDER BY occurred_at,event_id`, tenant, campaign, dbTime(query.Start), dbTime(query.End))
		if eventErr != nil {
			return CampaignMetricsSnapshot{}, eventErr
		}
		for eventRows.Next() {
			var status AttemptStatus
			var occurred string
			if eventRows.Scan(&status, &occurred) != nil {
				eventRows.Close()
				return CampaignMetricsSnapshot{}, ErrIntegrity
			}
			at, parseErr := parseDBTime(occurred)
			if parseErr != nil {
				eventRows.Close()
				return CampaignMetricsSnapshot{}, ErrIntegrity
			}
			index := int(at.Sub(query.Start) / query.BucketWidth)
			if index >= 0 && index < len(snapshot.TimeSeries) {
				addBucketCount(&snapshot.TimeSeries[index], status)
			}
		}
		if err = eventRows.Close(); err != nil {
			return CampaignMetricsSnapshot{}, err
		}
	}
	var watermark, received sql.NullString
	if err = r.db.QueryRowContext(ctx, `SELECT MAX(occurred_at),MAX(received_at),COALESCE(SUM(delayed),0),COALESCE(SUM(out_of_order),0) FROM email_marketing_delivery_events_v1 WHERE tenant_id=? AND campaign_id=?`, tenant, campaign).Scan(&watermark, &received, &snapshot.Quality.DelayedEvents, &snapshot.Quality.OutOfOrderEvents); err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	if watermark.Valid {
		parsed, parseErr := parseDBTime(watermark.String)
		if parseErr != nil {
			return CampaignMetricsSnapshot{}, ErrIntegrity
		}
		snapshot.Quality.EventWatermark = &parsed
		snapshot.Quality.WatermarkLag = now.Sub(parsed)
		if snapshot.Quality.WatermarkLag < 0 {
			snapshot.Quality.WatermarkLag = 0
		}
	}
	if received.Valid {
		parsed, parseErr := parseDBTime(received.String)
		if parseErr != nil {
			return CampaignMetricsSnapshot{}, ErrIntegrity
		}
		snapshot.Quality.LatestReceivedAt = &parsed
	}
	if err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_marketing_campaign_attempts_v1 WHERE tenant_id=? AND campaign_id=? AND awaiting_receipt=1`, tenant, campaign).Scan(&snapshot.Quality.AwaitingReceipts); err != nil {
		return CampaignMetricsSnapshot{}, err
	}
	snapshot.Quality.MissingProviderData = snapshot.Quality.AwaitingReceipts > 0 || snapshot.Counts.Sent > 0 && snapshot.Quality.EventWatermark == nil
	return snapshot, nil
}

func addDeliveryCount(counts *DeliveryStateCounts, status AttemptStatus, count uint64) error {
	switch status {
	case AttemptQueued:
		counts.Queued += count
	case AttemptSent:
		counts.Sent += count
	case AttemptDelivered:
		counts.Delivered += count
	case AttemptDeferred:
		counts.Deferred += count
	case AttemptBounced:
		counts.Bounced += count
	case AttemptComplained:
		counts.Complained += count
	case AttemptSuppressed:
		counts.Suppressed += count
	case AttemptFailed:
		counts.Failed += count
	default:
		return ErrIntegrity
	}
	return nil
}

func deliveryCountTotal(counts DeliveryStateCounts) uint64 {
	return counts.Queued + counts.Sent + counts.Delivered + counts.Deferred + counts.Bounced + counts.Complained + counts.Suppressed + counts.Failed
}

func addProviderCount(metric *ProviderMetric, status AttemptStatus, count uint64) {
	switch status {
	case AttemptQueued:
		metric.Queued += count
	case AttemptSent:
		metric.Sent += count
	case AttemptDelivered:
		metric.Delivered += count
	case AttemptDeferred:
		metric.Deferred += count
	case AttemptBounced:
		metric.Bounced += count
	case AttemptComplained:
		metric.Complained += count
	case AttemptSuppressed:
		metric.Suppressed += count
	case AttemptFailed:
		metric.Failed += count
	}
}

func makeMetricBuckets(query CampaignMetricsQuery) []CampaignMetricBucket {
	count := int((query.End.Sub(query.Start) + query.BucketWidth - 1) / query.BucketWidth)
	if count > query.MaximumBuckets {
		count = query.MaximumBuckets
	}
	buckets := make([]CampaignMetricBucket, count)
	for index := range buckets {
		buckets[index].Start = query.Start.Add(time.Duration(index) * query.BucketWidth)
		buckets[index].End = buckets[index].Start.Add(query.BucketWidth)
		if buckets[index].End.After(query.End) {
			buckets[index].End = query.End
		}
	}
	return buckets
}

func addBucketCount(bucket *CampaignMetricBucket, status AttemptStatus) {
	switch status {
	case AttemptDelivered:
		bucket.Delivered++
	case AttemptDeferred:
		bucket.Deferred++
	case AttemptBounced:
		bucket.Bounced++
	case AttemptComplained:
		bucket.Complained++
	case AttemptFailed:
		bucket.Failed++
	}
}
