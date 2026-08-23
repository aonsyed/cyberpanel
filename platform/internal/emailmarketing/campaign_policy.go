package emailmarketing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrCampaignAdmissionWaiting = errors.New("emailmarketing: campaign admission waiting")
	ErrCampaignAbuseBlocked    = errors.New("emailmarketing: campaign blocked by abuse policy")
)

const (
	maximumAdmissionCampaignRecipients = uint64(100_000_000)
	maximumAdmissionHourlyRecipients   = uint64(1_000_000_000)
	maximumAdmissionDailyRecipients    = uint64(10_000_000_000)
	maximumAdmissionConcurrency        = uint32(100_000)
)

type AbuseDisposition string

const (
	AbuseClear  AbuseDisposition = "clear"
	AbuseReview AbuseDisposition = "review"
	AbuseBlock  AbuseDisposition = "block"
)

type TenantCampaignPolicy struct {
	TenantID                 TenantID
	Generation               uint64
	MaxRecipientsPerCampaign uint64
	MaxRecipientsPerHour     uint64
	MaxRecipientsPerDay      uint64
	MaxConcurrentCampaigns   uint32
	WarmupStartedAt          time.Time
	WarmupInitialDailyLimit  uint64
	WarmupDoublingPeriod     time.Duration
	MinimumApprovals         uint8
	CapacityMaximumAge       time.Duration
	Abuse                    AbuseDisposition
	AbuseEvidenceDigest      string
	LocalAuthorityReady      bool
	UpdatedAt                time.Time
}

type SenderDomainAdmission struct {
	TenantID       TenantID
	Domain         string
	Generation     uint64
	EvidenceDigest string
	VerifiedAt     time.Time
	ExpiresAt      time.Time
	UpdatedAt      time.Time
}

type DeliveryCapacityKind string

const (
	CapacityLocal    DeliveryCapacityKind = "local"
	CapacityProvider DeliveryCapacityKind = "provider"
)

type CampaignDeliveryCapacity struct {
	TenantID                        TenantID
	ProfileRef                      string
	Generation                      uint64
	Kind                            DeliveryCapacityKind
	Online                          bool
	MaximumConcurrency              uint32
	MaximumRecipientsPerHour        uint64
	ReservedTransactionalConcurrency uint32
	ReservedTransactionalPerHour    uint64
	ObservedAt                      time.Time
	UpdatedAt                       time.Time
}

type CampaignAdmissionRequest struct {
	TenantID             TenantID
	CampaignID           CampaignID
	CampaignRevision     uint64
	ReservationID        string
	RecipientCount       uint64
	DeliveryProfileRef   string
	VerifiedSenderDomain string
	SenderEvidenceDigest string
	PolicyGeneration     uint64
	TenantPolicyDigest   string
	SenderGeneration     uint64
	CapacityGeneration   uint64
	AllowFallback        bool
	RequestedAt          time.Time
	ExpiresAt            time.Time
}

type CampaignAdmissionReservation struct {
	ID               string
	TenantID         TenantID
	CampaignID       CampaignID
	CampaignRevision uint64
	RecipientCount   uint64
	ProfileRef       string
	CapacityKind     DeliveryCapacityKind
	Status           string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	UpdatedAt        time.Time
}

type CampaignAdmissionResult struct {
	Admitted    bool
	Waiting     bool
	WaitReason  string
	Reservation CampaignAdmissionReservation
}

type CampaignAdmissionRepository interface {
	PutTenantCampaignPolicy(context.Context, TenantCampaignPolicy, uint64) error
	PutSenderDomainAdmission(context.Context, SenderDomainAdmission, uint64) error
	PutCampaignDeliveryCapacity(context.Context, CampaignDeliveryCapacity, uint64) error
	ReserveCampaignAdmission(context.Context, CampaignAdmissionRequest, time.Time) (CampaignAdmissionResult, error)
	SetCampaignReservationStatus(context.Context, TenantID, string, string, string, time.Time) error
}

type CampaignPolicyService struct {
	Repository CampaignAdmissionRepository
	Authorizer Authorizer
	StepUp     StepUpVerifier
	Audit      AuditSink
	Senders    SenderDomainVerifier
	Now        func() time.Time
}

func (service CampaignPolicyService) PutPolicy(ctx context.Context, access AdministrativeContext, policy TenantCampaignPolicy, expected uint64, stepUpProof string) error {
	request, err := service.authorize(ctx, access, "emailmarketing.campaign.policy", string(access.TenantID))
	if err != nil || policy.TenantID != access.TenantID {
		return ErrUnauthorized
	}
	if _, err = service.stepUp(ctx, request, stepUpProof); err != nil {
		return err
	}
	if err = service.Repository.PutTenantCampaignPolicy(ctx, policy, expected); err != nil {
		return err
	}
	return service.audit(ctx, request, "committed", digestObject(policy))
}

func (service CampaignPolicyService) RefreshSender(ctx context.Context, access AdministrativeContext, domain string, expected uint64, stepUpProof string) (SenderDomainAdmission, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.sender.admission", domain)
	if err != nil || service.Senders == nil {
		return SenderDomainAdmission{}, ErrUnauthorized
	}
	if _, err = service.stepUp(ctx, request, stepUpProof); err != nil {
		return SenderDomainAdmission{}, err
	}
	verified, err := service.Senders.ResolveVerifiedSender(ctx, access.TenantID, strings.ToLower(domain))
	if err != nil || verified.TenantID != access.TenantID || verified.Domain != strings.ToLower(domain) || !validDigest(verified.EvidenceDigest) || !verified.ExpiresAt.After(service.Now()) {
		return SenderDomainAdmission{}, ErrUnauthorized
	}
	now := service.Now().UTC()
	admission := SenderDomainAdmission{TenantID: access.TenantID, Domain: verified.Domain, Generation: expected + 1, EvidenceDigest: verified.EvidenceDigest, VerifiedAt: verified.VerifiedAt, ExpiresAt: verified.ExpiresAt, UpdatedAt: now}
	if err = service.Repository.PutSenderDomainAdmission(ctx, admission, expected); err != nil {
		return SenderDomainAdmission{}, err
	}
	err = service.audit(ctx, request, "verified", admission.EvidenceDigest)
	return admission, err
}

func (service CampaignPolicyService) PutCapacity(ctx context.Context, access AdministrativeContext, capacity CampaignDeliveryCapacity, expected uint64, stepUpProof string) error {
	request, err := service.authorize(ctx, access, "emailmarketing.delivery.capacity", capacity.ProfileRef)
	if err != nil || capacity.TenantID != access.TenantID {
		return ErrUnauthorized
	}
	if _, err = service.stepUp(ctx, request, stepUpProof); err != nil {
		return err
	}
	if err = service.Repository.PutCampaignDeliveryCapacity(ctx, capacity, expected); err != nil {
		return err
	}
	return service.audit(ctx, request, "committed", digestObject(capacity))
}

func (service CampaignPolicyService) authorize(ctx context.Context, access AdministrativeContext, action, resource string) (AuthorizationRequest, error) {
	request := AuthorizationRequest{TenantID: access.TenantID, ActorID: access.ActorID, Action: action, Resource: resource, DataClass: "campaign_safety_policy"}
	if service.Repository == nil || service.Authorizer == nil || service.Audit == nil || service.Now == nil || validateIdentifier(string(access.TenantID)) != nil || validateIdentifier(string(access.ActorID)) != nil || resource == "" || service.Authorizer.Authorize(ctx, request) != nil {
		return request, ErrUnauthorized
	}
	return request, nil
}

func (service CampaignPolicyService) stepUp(ctx context.Context, request AuthorizationRequest, proof string) (string, error) {
	if service.StepUp == nil || proof == "" {
		return "", ErrUnauthorized
	}
	receipt, err := service.StepUp.VerifyStepUp(ctx, request, proof)
	if err != nil || receipt == "" {
		return "", ErrUnauthorized
	}
	return receipt, nil
}

func (service CampaignPolicyService) audit(ctx context.Context, request AuthorizationRequest, outcome, evidence string) error {
	return service.Audit.RecordAudit(ctx, AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: outcome, EvidenceDigest: evidence, OccurredAt: service.Now().UTC()})
}

func (r *SQLiteRepository) BootstrapCampaignPolicy(ctx context.Context) error {
	if r == nil || r.db == nil {
		return ErrInvalid
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS email_marketing_tenant_policy_v1 (
			tenant_id TEXT PRIMARY KEY, generation INTEGER NOT NULL CHECK(generation>0), document BLOB NOT NULL, updated_at TEXT NOT NULL
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS email_marketing_sender_admission_v1 (
			tenant_id TEXT NOT NULL, domain TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0), evidence_digest TEXT NOT NULL,
			expires_at TEXT NOT NULL, document BLOB NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(tenant_id,domain)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS email_marketing_delivery_capacity_v1 (
			tenant_id TEXT NOT NULL, profile_ref TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0), kind TEXT NOT NULL CHECK(kind IN ('local','provider')),
			online INTEGER NOT NULL CHECK(online IN (0,1)), document BLOB NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(tenant_id,profile_ref)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS email_marketing_campaign_reservations_v1 (
			reservation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, campaign_id TEXT NOT NULL, campaign_revision INTEGER NOT NULL,
			recipient_count INTEGER NOT NULL CHECK(recipient_count>0), profile_ref TEXT NOT NULL, capacity_kind TEXT NOT NULL CHECK(capacity_kind IN ('local','provider')),
			status TEXT NOT NULL CHECK(status IN ('reserved','consumed','released','expired')), created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
			document BLOB NOT NULL, updated_at TEXT NOT NULL, UNIQUE(tenant_id,campaign_id,campaign_revision)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS email_marketing_campaign_reservations_usage_v1 ON email_marketing_campaign_reservations_v1(tenant_id,status,created_at,profile_ref)`,
	}
	for _, statement := range statements {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) PutTenantCampaignPolicy(ctx context.Context, policy TenantCampaignPolicy, expected uint64) error {
	if validateTenantCampaignPolicy(policy, expected) != nil {
		return ErrInvalid
	}
	document, _ := json.Marshal(policy)
	return putCAS(ctx, r.db, `INSERT INTO email_marketing_tenant_policy_v1(tenant_id,generation,document,updated_at) VALUES(?,?,?,?)`, `UPDATE email_marketing_tenant_policy_v1 SET generation=?,document=?,updated_at=? WHERE tenant_id=? AND generation=?`, expected,
		[]any{policy.TenantID, policy.Generation, document, dbTime(policy.UpdatedAt)}, []any{policy.Generation, document, dbTime(policy.UpdatedAt), policy.TenantID, expected})
}

func (r *SQLiteRepository) PutSenderDomainAdmission(ctx context.Context, sender SenderDomainAdmission, expected uint64) error {
	if validateIdentifier(string(sender.TenantID)) != nil || validateIdentifier(sender.Domain) != nil || sender.Domain != strings.ToLower(sender.Domain) || sender.Generation != expected+1 || !validDigest(sender.EvidenceDigest) || sender.VerifiedAt.IsZero() || !sender.ExpiresAt.After(sender.VerifiedAt) || sender.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	document, _ := json.Marshal(sender)
	return putCAS(ctx, r.db, `INSERT INTO email_marketing_sender_admission_v1(tenant_id,domain,generation,evidence_digest,expires_at,document,updated_at) VALUES(?,?,?,?,?,?,?)`, `UPDATE email_marketing_sender_admission_v1 SET generation=?,evidence_digest=?,expires_at=?,document=?,updated_at=? WHERE tenant_id=? AND domain=? AND generation=?`, expected,
		[]any{sender.TenantID, sender.Domain, sender.Generation, sender.EvidenceDigest, dbTime(sender.ExpiresAt), document, dbTime(sender.UpdatedAt)}, []any{sender.Generation, sender.EvidenceDigest, dbTime(sender.ExpiresAt), document, dbTime(sender.UpdatedAt), sender.TenantID, sender.Domain, expected})
}

func (r *SQLiteRepository) PutCampaignDeliveryCapacity(ctx context.Context, capacity CampaignDeliveryCapacity, expected uint64) error {
	if validateDeliveryCapacity(capacity, expected) != nil {
		return ErrInvalid
	}
	document, _ := json.Marshal(capacity)
	return putCAS(ctx, r.db, `INSERT INTO email_marketing_delivery_capacity_v1(tenant_id,profile_ref,generation,kind,online,document,updated_at) VALUES(?,?,?,?,?,?,?)`, `UPDATE email_marketing_delivery_capacity_v1 SET generation=?,kind=?,online=?,document=?,updated_at=? WHERE tenant_id=? AND profile_ref=? AND generation=?`, expected,
		[]any{capacity.TenantID, capacity.ProfileRef, capacity.Generation, capacity.Kind, capacity.Online, document, dbTime(capacity.UpdatedAt)}, []any{capacity.Generation, capacity.Kind, capacity.Online, document, dbTime(capacity.UpdatedAt), capacity.TenantID, capacity.ProfileRef, expected})
}

func (r *SQLiteRepository) ReserveCampaignAdmission(ctx context.Context, request CampaignAdmissionRequest, now time.Time) (CampaignAdmissionResult, error) {
	if validateAdmissionRequest(request, now) != nil {
		return CampaignAdmissionResult{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return CampaignAdmissionResult{}, err
	}
	defer tx.Rollback()
	var existingDocument []byte
	err = tx.QueryRowContext(ctx, `SELECT document FROM email_marketing_campaign_reservations_v1 WHERE reservation_id=?`, request.ReservationID).Scan(&existingDocument)
	if err == nil {
		var existing CampaignAdmissionReservation
		if json.Unmarshal(existingDocument, &existing) != nil || existing.TenantID != request.TenantID || existing.CampaignID != request.CampaignID || existing.CampaignRevision != request.CampaignRevision || existing.RecipientCount != request.RecipientCount || existing.ProfileRef != request.DeliveryProfileRef {
			return CampaignAdmissionResult{}, ErrIntegrity
		}
		return CampaignAdmissionResult{Admitted: existing.Status == "reserved" || existing.Status == "consumed", Reservation: existing}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CampaignAdmissionResult{}, err
	}
	var campaignDocument, policyDocument, senderDocument, capacityDocument []byte
	var policyGeneration, senderGeneration, capacityGeneration uint64
	if err = tx.QueryRowContext(ctx, `SELECT document FROM email_marketing_campaigns_v1 WHERE tenant_id=? AND campaign_id=? AND revision=? AND state IN ('approval','scheduled','running')`, request.TenantID, request.CampaignID, request.CampaignRevision).Scan(&campaignDocument); err != nil {
		return CampaignAdmissionResult{}, ErrNotFound
	}
	if err = tx.QueryRowContext(ctx, `SELECT generation,document FROM email_marketing_tenant_policy_v1 WHERE tenant_id=?`, request.TenantID).Scan(&policyGeneration, &policyDocument); err != nil || policyGeneration != request.PolicyGeneration {
		return CampaignAdmissionResult{}, staleOr(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT generation,document FROM email_marketing_sender_admission_v1 WHERE tenant_id=? AND domain=?`, request.TenantID, request.VerifiedSenderDomain).Scan(&senderGeneration, &senderDocument); err != nil || senderGeneration != request.SenderGeneration {
		return CampaignAdmissionResult{}, staleOr(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT generation,document FROM email_marketing_delivery_capacity_v1 WHERE tenant_id=? AND profile_ref=?`, request.TenantID, request.DeliveryProfileRef).Scan(&capacityGeneration, &capacityDocument); err != nil || capacityGeneration != request.CapacityGeneration {
		return CampaignAdmissionResult{}, staleOr(err)
	}
	var campaign Campaign
	var policy TenantCampaignPolicy
	var sender SenderDomainAdmission
	var capacity CampaignDeliveryCapacity
	if json.Unmarshal(campaignDocument, &campaign) != nil || json.Unmarshal(policyDocument, &policy) != nil || json.Unmarshal(senderDocument, &sender) != nil || json.Unmarshal(capacityDocument, &capacity) != nil || digestObject(policy) != request.TenantPolicyDigest {
		return CampaignAdmissionResult{}, ErrIntegrity
	}
	if campaign.Generation == 0 || validateCampaign(campaign, campaign.Generation-1) != nil || campaign.TenantID != request.TenantID || campaign.ID != request.CampaignID || campaign.Revision != request.CampaignRevision ||
		policy.Generation == 0 || validateTenantCampaignPolicy(policy, policy.Generation-1) != nil || policy.TenantID != request.TenantID || policy.Generation != policyGeneration || sender.TenantID != request.TenantID || sender.Domain != request.VerifiedSenderDomain || sender.Generation != senderGeneration ||
		capacity.TenantID != request.TenantID || capacity.ProfileRef != request.DeliveryProfileRef || capacity.Generation != capacityGeneration || validateDeliveryCapacity(capacity, capacity.Generation-1) != nil {
		return CampaignAdmissionResult{}, ErrIntegrity
	}
	// No central reachability input is consulted: locally durable safety policy
	// remains authoritative during a partition.
	if !policy.LocalAuthorityReady {
		return CampaignAdmissionResult{Waiting: true, WaitReason: "local_authority_not_ready"}, ErrCampaignAdmissionWaiting
	}
	if policy.Abuse == AbuseBlock || policy.Abuse == AbuseReview {
		return CampaignAdmissionResult{}, ErrCampaignAbuseBlocked
	}
	if campaign.RecipientCount != request.RecipientCount || campaign.DeliveryProfileRef != request.DeliveryProfileRef || campaign.VerifiedSenderDomain != request.VerifiedSenderDomain ||
		campaign.SenderVerificationDigest != request.SenderEvidenceDigest || len(campaign.Approvals) < int(policy.MinimumApprovals) ||
		sender.EvidenceDigest != request.SenderEvidenceDigest || !sender.ExpiresAt.After(now) || capacity.ProfileRef != request.DeliveryProfileRef {
		return CampaignAdmissionResult{}, ErrUnauthorized
	}
	if !capacity.Online {
		reason := "local_capacity_offline"
		if capacity.Kind == CapacityProvider {
			reason = "provider_offline"
		}
		return CampaignAdmissionResult{Waiting: true, WaitReason: reason}, ErrCampaignAdmissionWaiting
	}
	if capacity.ObservedAt.After(now.Add(time.Minute)) || !capacity.ObservedAt.Add(policy.CapacityMaximumAge).After(now) {
		return CampaignAdmissionResult{Waiting: true, WaitReason: "capacity_state_stale"}, ErrCampaignAdmissionWaiting
	}
	warmupLimit := warmupDailyLimit(policy, now)
	if request.RecipientCount > policy.MaxRecipientsPerCampaign || request.RecipientCount > warmupLimit {
		return CampaignAdmissionResult{}, ErrConflict
	}
	var active, profileActive uint32
	var hourly, daily, profileHourly uint64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT campaign_id),COALESCE(SUM(CASE WHEN created_at>=? THEN recipient_count ELSE 0 END),0),COALESCE(SUM(CASE WHEN created_at>=? THEN recipient_count ELSE 0 END),0) FROM email_marketing_campaign_reservations_v1 WHERE tenant_id=? AND status IN ('reserved','consumed')`, dbTime(now.Add(-time.Hour)), dbTime(now.Add(-24*time.Hour)), request.TenantID).Scan(&active, &hourly, &daily); err != nil {
		return CampaignAdmissionResult{}, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(recipient_count),0) FROM email_marketing_campaign_reservations_v1 WHERE tenant_id=? AND profile_ref=? AND status IN ('reserved','consumed') AND created_at>=?`, request.TenantID, request.DeliveryProfileRef, dbTime(now.Add(-time.Hour))).Scan(&profileHourly); err != nil {
		return CampaignAdmissionResult{}, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT campaign_id) FROM email_marketing_campaign_reservations_v1 WHERE tenant_id=? AND profile_ref=? AND status IN ('reserved','consumed')`, request.TenantID, request.DeliveryProfileRef).Scan(&profileActive); err != nil {
		return CampaignAdmissionResult{}, err
	}
	availableConcurrency := capacity.MaximumConcurrency
	availableHourly := capacity.MaximumRecipientsPerHour
	if capacity.ReservedTransactionalConcurrency >= availableConcurrency || capacity.ReservedTransactionalPerHour >= availableHourly {
		return CampaignAdmissionResult{Waiting: true, WaitReason: "transactional_reserve"}, ErrCampaignAdmissionWaiting
	}
	availableConcurrency -= capacity.ReservedTransactionalConcurrency
	availableHourly -= capacity.ReservedTransactionalPerHour
	if active >= policy.MaxConcurrentCampaigns || profileActive >= availableConcurrency || hourly+request.RecipientCount > policy.MaxRecipientsPerHour || daily+request.RecipientCount > policy.MaxRecipientsPerDay || daily+request.RecipientCount > warmupLimit || profileHourly+request.RecipientCount > availableHourly {
		return CampaignAdmissionResult{Waiting: true, WaitReason: "bounded_capacity"}, ErrCampaignAdmissionWaiting
	}
	reservation := CampaignAdmissionReservation{ID: request.ReservationID, TenantID: request.TenantID, CampaignID: request.CampaignID, CampaignRevision: request.CampaignRevision, RecipientCount: request.RecipientCount, ProfileRef: request.DeliveryProfileRef, CapacityKind: capacity.Kind, Status: "reserved", CreatedAt: now, ExpiresAt: request.ExpiresAt, UpdatedAt: now}
	document, _ := json.Marshal(reservation)
	if _, err = tx.ExecContext(ctx, `INSERT INTO email_marketing_campaign_reservations_v1(reservation_id,tenant_id,campaign_id,campaign_revision,recipient_count,profile_ref,capacity_kind,status,created_at,expires_at,document,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, reservation.ID, reservation.TenantID, reservation.CampaignID, reservation.CampaignRevision, reservation.RecipientCount, reservation.ProfileRef, reservation.CapacityKind, reservation.Status, dbTime(reservation.CreatedAt), dbTime(reservation.ExpiresAt), document, dbTime(reservation.UpdatedAt)); err != nil {
		return CampaignAdmissionResult{}, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return CampaignAdmissionResult{}, err
	}
	return CampaignAdmissionResult{Admitted: true, Reservation: reservation}, nil
}

func (r *SQLiteRepository) SetCampaignReservationStatus(ctx context.Context, tenant TenantID, id, expected, next string, now time.Time) error {
	if validateIdentifier(string(tenant)) != nil || validateIdentifier(id) != nil || now.IsZero() || !reservationTransition(expected, next) {
		return ErrInvalid
	}
	var document []byte
	err := r.db.QueryRowContext(ctx, `SELECT document FROM email_marketing_campaign_reservations_v1 WHERE tenant_id=? AND reservation_id=? AND status=?`, tenant, id, expected).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStale
	}
	var reservation CampaignAdmissionReservation
	if err != nil || json.Unmarshal(document, &reservation) != nil {
		return ErrIntegrity
	}
	reservation.Status, reservation.UpdatedAt = next, now
	document, _ = json.Marshal(reservation)
	result, err := r.db.ExecContext(ctx, `UPDATE email_marketing_campaign_reservations_v1 SET status=?,document=?,updated_at=? WHERE tenant_id=? AND reservation_id=? AND status=?`, next, document, dbTime(now), tenant, id, expected)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return ErrStale
	}
	return nil
}

func validateTenantCampaignPolicy(policy TenantCampaignPolicy, expected uint64) error {
	if validateIdentifier(string(policy.TenantID)) != nil || policy.Generation != expected+1 || policy.MaxRecipientsPerCampaign == 0 || policy.MaxRecipientsPerCampaign > maximumAdmissionCampaignRecipients ||
		policy.MaxRecipientsPerHour < policy.MaxRecipientsPerCampaign || policy.MaxRecipientsPerHour > maximumAdmissionHourlyRecipients || policy.MaxRecipientsPerDay < policy.MaxRecipientsPerHour || policy.MaxRecipientsPerDay > maximumAdmissionDailyRecipients ||
		policy.MaxConcurrentCampaigns == 0 || policy.MaxConcurrentCampaigns > maximumAdmissionConcurrency || policy.WarmupStartedAt.IsZero() || policy.WarmupInitialDailyLimit == 0 || policy.WarmupInitialDailyLimit > policy.MaxRecipientsPerDay ||
		policy.WarmupDoublingPeriod < 24*time.Hour || policy.WarmupDoublingPeriod > 30*24*time.Hour || policy.MinimumApprovals == 0 || policy.CapacityMaximumAge < time.Minute || policy.CapacityMaximumAge > 24*time.Hour ||
		policy.MinimumApprovals > 8 || policy.UpdatedAt.IsZero() || !validDigest(policy.AbuseEvidenceDigest) {
		return ErrInvalid
	}
	if policy.Abuse != AbuseClear && policy.Abuse != AbuseReview && policy.Abuse != AbuseBlock {
		return ErrInvalid
	}
	return nil
}

func validateDeliveryCapacity(capacity CampaignDeliveryCapacity, expected uint64) error {
	if validateIdentifier(string(capacity.TenantID)) != nil || validateIdentifier(capacity.ProfileRef) != nil || capacity.Generation != expected+1 ||
		(capacity.Kind != CapacityLocal && capacity.Kind != CapacityProvider) || capacity.MaximumConcurrency == 0 || capacity.MaximumConcurrency > maximumAdmissionConcurrency || capacity.MaximumRecipientsPerHour == 0 || capacity.MaximumRecipientsPerHour > maximumAdmissionHourlyRecipients ||
		capacity.ReservedTransactionalConcurrency >= capacity.MaximumConcurrency || capacity.ReservedTransactionalPerHour >= capacity.MaximumRecipientsPerHour ||
		capacity.ObservedAt.IsZero() || capacity.UpdatedAt.Before(capacity.ObservedAt) {
		return ErrInvalid
	}
	return nil
}

func DigestTenantCampaignPolicy(policy TenantCampaignPolicy) string { return digestObject(policy) }

func validateAdmissionRequest(request CampaignAdmissionRequest, now time.Time) error {
	if validateIdentifier(string(request.TenantID)) != nil || validateIdentifier(string(request.CampaignID)) != nil || validateIdentifier(request.ReservationID) != nil ||
		validateIdentifier(request.DeliveryProfileRef) != nil || validateIdentifier(request.VerifiedSenderDomain) != nil || request.VerifiedSenderDomain != strings.ToLower(request.VerifiedSenderDomain) || !validDigest(request.SenderEvidenceDigest) ||
		request.CampaignRevision == 0 || request.RecipientCount == 0 || request.RecipientCount > maximumAdmissionCampaignRecipients || request.PolicyGeneration == 0 || !validDigest(request.TenantPolicyDigest) || request.SenderGeneration == 0 || request.CapacityGeneration == 0 ||
		request.AllowFallback || request.RequestedAt.IsZero() || request.RequestedAt.After(now.Add(time.Minute)) || !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(24*time.Hour)) {
		return ErrInvalid
	}
	return nil
}

func warmupDailyLimit(policy TenantCampaignPolicy, now time.Time) uint64 {
	if now.Before(policy.WarmupStartedAt) {
		return 0
	}
	periods := uint64(now.Sub(policy.WarmupStartedAt) / policy.WarmupDoublingPeriod)
	limit := policy.WarmupInitialDailyLimit
	for index := uint64(0); index < periods && limit < policy.MaxRecipientsPerDay; index++ {
		if limit > ^uint64(0)/2 {
			return policy.MaxRecipientsPerDay
		}
		limit *= 2
	}
	if limit > policy.MaxRecipientsPerDay {
		return policy.MaxRecipientsPerDay
	}
	return limit
}

func reservationTransition(current, next string) bool {
	return current == "reserved" && (next == "consumed" || next == "released" || next == "expired") || current == "consumed" && next == "released"
}
