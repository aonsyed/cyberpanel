package emailmarketing

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type AdministrativeContext struct {
	TenantID TenantID
	ActorID  ActorID
}

type AuthorizationRequest struct {
	TenantID TenantID
	ActorID  ActorID
	Action   string
	Resource string
	DataClass string
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) error
}

type StepUpVerifier interface {
	VerifyStepUp(context.Context, AuthorizationRequest, string) (string, error)
}

type AuditRecord struct {
	TenantID      TenantID
	ActorID       ActorID
	Action        string
	Resource      string
	Outcome       string
	EvidenceDigest string
	OccurredAt    time.Time
}

type AuditSink interface {
	RecordAudit(context.Context, AuditRecord) error
}

// ProviderConsentVerifier is an adapter contract for optional attestations. The
// core has no provider transport and never sends subscriber data itself.
type ProviderConsentVerifier interface {
	VerifyProviderConsent(context.Context, ProviderConsentAttestation) (Verification, error)
}

type ProviderConsentAttestation struct {
	TenantID         TenantID
	ListID           ListID
	SubscriberID     SubscriberID
	ProviderBinding  string
	Purpose          string
	CapturedAt       time.Time
	ObservedAt       time.Time
	EvidenceDigest   string
	EvidenceCertainty EvidenceCertainty
}

func (attestation ProviderConsentAttestation) Validate() error {
	if validateIdentifier(string(attestation.TenantID)) != nil || validateIdentifier(string(attestation.ListID)) != nil ||
		validateIdentifier(string(attestation.SubscriberID)) != nil || validateIdentifier(attestation.ProviderBinding) != nil ||
		attestation.Purpose == "" || len(attestation.Purpose) > maxPurposeBytes || attestation.CapturedAt.IsZero() ||
		attestation.ObservedAt.Before(attestation.CapturedAt) || !validDigest(attestation.EvidenceDigest) {
		return ErrInvalid
	}
	if attestation.EvidenceCertainty != CertaintyExact && attestation.EvidenceCertainty != CertaintyInferred && attestation.EvidenceCertainty != CertaintyUnknown {
		return ErrInvalid
	}
	return nil
}

type AdministrativeRepository interface {
	PutList(context.Context, List, uint64) error
	GetList(context.Context, TenantID, ListID) (List, error)
	ListLists(context.Context, TenantID, ListID, int) ([]List, error)
	PutTag(context.Context, Tag, uint64) error
	FindSubscriber(context.Context, TenantID, AddressIdentity) (Subscriber, error)
	GetSubscriber(context.Context, TenantID, SubscriberID) (Subscriber, error)
	ListSubscribers(context.Context, TenantID, ListID, string, int) (SubscriberPage, error)
	SearchSubscribers(context.Context, TenantID, string, int) ([]Subscriber, error)
	EnrollSubscriber(context.Context, Subscriber, uint64, Membership, uint64, *ConsentRecord) error
	RecordConsent(context.Context, ConsentRecord) error
	LatestConsent(context.Context, TenantID, ListID, SubscriberID) (ConsentRecord, error)
	Suppress(context.Context, SuppressionRecord) error
	ActiveSuppressions(context.Context, TenantID, string) ([]SuppressionRecord, error)
	ReleaseSuppression(context.Context, SuppressionRecord, SuppressionRecord, ResubscribeProof) error
	PutSubscriber(context.Context, Subscriber, uint64) error
	EraseSubscriber(context.Context, TenantID, SubscriberID, RetentionPolicy, time.Time) (Tombstone, error)
}

type Service struct {
	Repository AdministrativeRepository
	Authorizer Authorizer
	StepUp     StepUpVerifier
	Audit      AuditSink
	Now        func() time.Time
}

func (service Service) PutList(ctx context.Context, access AdministrativeContext, list List, expected uint64) error {
	request, err := service.authorize(ctx, access, "emailmarketing.list.write", string(list.ID), "subscriber_metadata")
	if err != nil || list.TenantID != access.TenantID {
		return unauthorizedOr(err)
	}
	if err = service.Repository.PutList(ctx, list, expected); err != nil {
		return err
	}
	return service.audit(ctx, request, "committed", digestObject(list))
}

func (service Service) PutTag(ctx context.Context, access AdministrativeContext, tag Tag, expected uint64) error {
	request, err := service.authorize(ctx, access, "emailmarketing.tag.write", string(tag.ID), "subscriber_metadata")
	if err != nil || tag.TenantID != access.TenantID {
		return unauthorizedOr(err)
	}
	if err = service.Repository.PutTag(ctx, tag, expected); err != nil {
		return err
	}
	return service.audit(ctx, request, "committed", digestObject(tag))
}

func (service Service) ListLists(ctx context.Context, access AdministrativeContext, after ListID, limit int) ([]List, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.list.read", string(access.TenantID), "subscriber_metadata")
	if err != nil {
		return nil, err
	}
	lists, err := service.Repository.ListLists(ctx, access.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	if err = service.audit(ctx, request, "read", DigestEvidence([]byte(string(after)))); err != nil {
		return nil, err
	}
	return lists, nil
}

func (service Service) ListSubscribers(ctx context.Context, access AdministrativeContext, list ListID, afterDigest string, limit int) (SubscriberPage, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.subscriber.read", string(list), "contact_and_consent")
	if err != nil {
		return SubscriberPage{}, err
	}
	page, err := service.Repository.ListSubscribers(ctx, access.TenantID, list, afterDigest, limit)
	if err != nil {
		return SubscriberPage{}, err
	}
	evidence := afterDigest
	if evidence == "" {
		evidence = DigestEvidence(nil)
	}
	if err = service.audit(ctx, request, "read", evidence); err != nil {
		return SubscriberPage{}, err
	}
	return page, nil
}

func (service Service) SearchSubscribers(ctx context.Context, access AdministrativeContext, prefix string, limit int) ([]Subscriber, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.subscriber.search", string(access.TenantID), "contact_and_consent")
	if err != nil {
		return nil, err
	}
	result, err := service.Repository.SearchSubscribers(ctx, access.TenantID, prefix, limit)
	if err != nil {
		return nil, err
	}
	if err = service.audit(ctx, request, "read", DigestEvidence([]byte(prefix))); err != nil {
		return nil, err
	}
	return result, nil
}

type EnrollmentRequest struct {
	TenantID             TenantID
	ListID               ListID
	SubscriberID         SubscriberID
	Address              string
	TagIDs               []TagID
	Verification         Verification
	SubscriberGeneration uint64
	MembershipGeneration uint64
	Consent              *ConsentRecord
}

func (service Service) Enroll(ctx context.Context, access AdministrativeContext, input EnrollmentRequest) (Subscriber, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.subscriber.enroll", string(input.ListID), "contact_and_consent")
	if err != nil || input.TenantID != access.TenantID {
		return Subscriber{}, unauthorizedOr(err)
	}
	identity, err := NormalizeAddress(input.Address)
	if err != nil {
		return Subscriber{}, ErrInvalid
	}
	if validateVerification(input.Verification) != nil {
		return Subscriber{}, ErrInvalid
	}
	now := service.Now().UTC()
	existing, findErr := service.Repository.FindSubscriber(ctx, input.TenantID, identity)
	var subscriber Subscriber
	if findErr == nil {
		if existing.Lifecycle != LifecycleActive || input.SubscriberGeneration != existing.Generation || (input.SubscriberID != "" && input.SubscriberID != existing.ID) {
			return Subscriber{}, ErrStale
		}
		tags, tagErr := mergeTags(existing.TagIDs, input.TagIDs)
		if tagErr != nil {
			return Subscriber{}, tagErr
		}
		verification := existing.Verification
		if verificationRank(input.Verification) > verificationRank(existing.Verification) {
			verification = input.Verification
		}
		subscriber = existing
		subscriber.TagIDs, subscriber.Verification = tags, verification
		subscriber.Generation, subscriber.UpdatedAt = existing.Generation+1, now
	} else if errors.Is(findErr, ErrNotFound) {
		if input.SubscriberGeneration != 0 || validateIdentifier(string(input.SubscriberID)) != nil {
			return Subscriber{}, ErrInvalid
		}
		tags, tagErr := normalizeTags(input.TagIDs)
		if tagErr != nil || validateVerification(input.Verification) != nil {
			return Subscriber{}, ErrInvalid
		}
		subscriber = Subscriber{TenantID: input.TenantID, ID: input.SubscriberID, Address: identity, Verification: input.Verification, TagIDs: tags, Lifecycle: LifecycleActive, Generation: 1, CreatedAt: now, UpdatedAt: now}
	} else {
		return Subscriber{}, findErr
	}
	membership := Membership{TenantID: input.TenantID, ListID: input.ListID, SubscriberID: subscriber.ID, Status: MembershipSubscribed, Generation: input.MembershipGeneration + 1, CreatedAt: now, UpdatedAt: now}
	if input.MembershipGeneration > 0 {
		membership.CreatedAt = subscriber.CreatedAt
	}
	if input.Consent != nil {
		input.Consent.TenantID, input.Consent.ListID, input.Consent.SubscriberID = input.TenantID, input.ListID, subscriber.ID
		if input.Consent.ActorID != access.ActorID {
			return Subscriber{}, ErrInvalid
		}
	}
	if err = service.Repository.EnrollSubscriber(ctx, subscriber, input.SubscriberGeneration, membership, input.MembershipGeneration, input.Consent); err != nil {
		return Subscriber{}, err
	}
	if err = service.audit(ctx, request, "committed", identity.Digest); err != nil {
		return Subscriber{}, err
	}
	return subscriber, nil
}

func (service Service) RecordConsent(ctx context.Context, access AdministrativeContext, consent ConsentRecord) error {
	request, err := service.authorize(ctx, access, "emailmarketing.consent.record", string(consent.ListID)+":"+string(consent.SubscriberID), "consent_evidence")
	if err != nil || consent.TenantID != access.TenantID || consent.ActorID != access.ActorID {
		return unauthorizedOr(err)
	}
	if err = service.Repository.RecordConsent(ctx, consent); err != nil {
		return err
	}
	return service.audit(ctx, request, "committed", consent.EvidenceDigest)
}

type SuppressRequest struct {
	TenantID       TenantID
	ListID         ListID
	SubscriberID   SubscriberID
	Scope          SuppressionScope
	Reason         SuppressionReason
	RecordID       string
	EvidenceDigest string
	StepUpProof    string
}

func (service Service) Suppress(ctx context.Context, access AdministrativeContext, input SuppressRequest) error {
	action := "emailmarketing.suppression.tenant"
	if input.Scope == SuppressionGlobal {
		action = "emailmarketing.suppression.global"
	}
	request, err := service.authorize(ctx, access, action, string(input.SubscriberID), "contact_suppression")
	if err != nil || input.TenantID != access.TenantID {
		return unauthorizedOr(err)
	}
	if _, err = service.requireStepUp(ctx, request, input.StepUpProof); err != nil {
		return err
	}
	subscriber, err := service.Repository.GetSubscriber(ctx, input.TenantID, input.SubscriberID)
	if err != nil {
		return err
	}
	recordTenant := input.TenantID
	if input.Scope == SuppressionGlobal {
		recordTenant = ""
	}
	record := SuppressionRecord{ID: input.RecordID, Scope: input.Scope, TenantID: recordTenant, ListID: input.ListID, SubscriberID: input.SubscriberID, AddressDigest: subscriber.Address.Digest, Reason: input.Reason, Action: SuppressionAdded, OccurredAt: service.Now().UTC(), EvidenceDigest: input.EvidenceDigest, ActorID: access.ActorID}
	if err = service.Repository.Suppress(ctx, record); err != nil {
		return err
	}
	return service.audit(ctx, request, "suppressed", digestObject(record))
}

type ResubscribeRequest struct {
	TenantID       TenantID
	SubscriberID   SubscriberID
	ActiveRecordID string
	ReleaseRecordID string
	Proof          ResubscribeProof
	StepUpProof    string
}

func (service Service) Resubscribe(ctx context.Context, access AdministrativeContext, input ResubscribeRequest) error {
	request, err := service.authorize(ctx, access, "emailmarketing.suppression.release", string(input.SubscriberID), "contact_suppression")
	if err != nil || input.TenantID != access.TenantID {
		return unauthorizedOr(err)
	}
	receipt, err := service.requireStepUp(ctx, request, input.StepUpProof)
	if err != nil {
		return err
	}
	input.Proof.StepUpReceipt = receipt
	subscriber, err := service.Repository.GetSubscriber(ctx, input.TenantID, input.SubscriberID)
	if err != nil {
		return err
	}
	records, err := service.Repository.ActiveSuppressions(ctx, input.TenantID, subscriber.Address.Digest)
	if err != nil {
		return err
	}
	var active SuppressionRecord
	for _, record := range records {
		if record.ID == input.ActiveRecordID {
			active = record
			break
		}
	}
	if active.ID == "" {
		return ErrNotFound
	}
	if input.Proof.Consent.TenantID != access.TenantID || input.Proof.Consent.ListID != active.ListID {
		return ErrInvalid
	}
	consent, err := service.Repository.LatestConsent(ctx, access.TenantID, input.Proof.Consent.ListID, input.SubscriberID)
	if err != nil || consent.ID != input.Proof.Consent.ID {
		return ErrIntegrity
	}
	input.Proof.Consent = consent
	release := SuppressionRecord{ID: input.ReleaseRecordID, Scope: active.Scope, TenantID: active.TenantID, ListID: active.ListID, SubscriberID: active.SubscriberID, AddressDigest: active.AddressDigest, Reason: active.Reason, Action: SuppressionReleased, OccurredAt: service.Now().UTC(), EvidenceDigest: consent.EvidenceDigest, ActorID: access.ActorID, PriorRecordID: active.ID, ConsentRecordID: consent.ID}
	if err = service.Repository.ReleaseSuppression(ctx, active, release, input.Proof); err != nil {
		return err
	}
	return service.audit(ctx, request, "released", digestObject(release))
}

func (service Service) SetListLifecycle(ctx context.Context, access AdministrativeContext, id ListID, expected uint64, lifecycle Lifecycle, stepUpProof string) error {
	if lifecycle != LifecycleArchived && lifecycle != LifecycleDeleted {
		return ErrInvalid
	}
	request, err := service.authorize(ctx, access, "emailmarketing.list.lifecycle", string(id), "subscriber_metadata")
	if err != nil {
		return err
	}
	if _, err = service.requireStepUp(ctx, request, stepUpProof); err != nil {
		return err
	}
	list, err := service.Repository.GetList(ctx, access.TenantID, id)
	if err != nil || list.Generation != expected {
		return staleOr(err)
	}
	now := service.Now().UTC()
	list.Generation, list.Lifecycle, list.UpdatedAt = expected+1, lifecycle, now
	if lifecycle == LifecycleArchived {
		list.ArchivedAt = &now
	}
	if err = service.Repository.PutList(ctx, list, expected); err != nil {
		return err
	}
	return service.audit(ctx, request, string(lifecycle), digestObject(list))
}

func (service Service) MarkSubscriberDeleted(ctx context.Context, access AdministrativeContext, id SubscriberID, expected uint64, deleteAfter time.Time, stepUpProof string) error {
	request, err := service.authorize(ctx, access, "emailmarketing.subscriber.delete", string(id), "contact_and_consent")
	if err != nil {
		return err
	}
	if _, err = service.requireStepUp(ctx, request, stepUpProof); err != nil {
		return err
	}
	subscriber, err := service.Repository.GetSubscriber(ctx, access.TenantID, id)
	if err != nil || subscriber.Generation != expected || !deleteAfter.After(service.Now()) {
		return staleOr(err)
	}
	now := service.Now().UTC()
	subscriber.Generation, subscriber.Lifecycle, subscriber.UpdatedAt, subscriber.DeleteAfter = expected+1, LifecycleDeleted, now, timePointer(deleteAfter.UTC())
	if err = service.Repository.PutSubscriber(ctx, subscriber, expected); err != nil {
		return err
	}
	return service.audit(ctx, request, "marked_deleted", subscriber.Address.Digest)
}

func (service Service) EraseSubscriber(ctx context.Context, access AdministrativeContext, id SubscriberID, policy RetentionPolicy, stepUpProof string) (Tombstone, error) {
	request, err := service.authorize(ctx, access, "emailmarketing.subscriber.erase", string(id), "contact_and_consent")
	if err != nil {
		return Tombstone{}, err
	}
	if _, err = service.requireStepUp(ctx, request, stepUpProof); err != nil {
		return Tombstone{}, err
	}
	tombstone, err := service.Repository.EraseSubscriber(ctx, access.TenantID, id, policy, service.Now().UTC())
	if err != nil {
		return Tombstone{}, err
	}
	if err = service.audit(ctx, request, "erased", tombstone.AddressDigest); err != nil {
		return Tombstone{}, err
	}
	return tombstone, nil
}

func (service Service) ImportCSV(ctx context.Context, access AdministrativeContext, stepUpProof string, input io.Reader, request CSVImportRequest, repository CSVImportRepository) (CSVImportSummary, error) {
	authorization, err := service.authorize(ctx, access, "emailmarketing.csv.import", string(request.ListID), "contact_and_consent")
	if err != nil || request.TenantID != access.TenantID {
		return CSVImportSummary{}, unauthorizedOr(err)
	}
	if _, err = service.requireStepUp(ctx, authorization, stepUpProof); err != nil {
		return CSVImportSummary{}, err
	}
	request.ActorID = access.ActorID
	summary, err := (CSVImporter{Repository: repository, Now: service.Now}).Import(ctx, input, request)
	if err != nil {
		return summary, err
	}
	err = service.audit(ctx, authorization, "completed", summary.HeaderDigest)
	return summary, err
}

func (service Service) ExportCSV(ctx context.Context, access AdministrativeContext, stepUpProof string, output io.Writer, request CSVExportRequest, repository CSVExportRepository) (CSVExportSummary, error) {
	authorization, err := service.authorize(ctx, access, "emailmarketing.csv.export", string(request.ListID), "contact_and_consent")
	if err != nil || request.TenantID != access.TenantID {
		return CSVExportSummary{}, unauthorizedOr(err)
	}
	if _, err = service.requireStepUp(ctx, authorization, stepUpProof); err != nil {
		return CSVExportSummary{}, err
	}
	summary, err := (CSVExporter{Repository: repository}).Export(ctx, output, request)
	if err != nil {
		return summary, err
	}
	err = service.audit(ctx, authorization, "completed", digestObject(summary))
	return summary, err
}

func (service Service) authorize(ctx context.Context, access AdministrativeContext, action, resource, dataClass string) (AuthorizationRequest, error) {
	request := AuthorizationRequest{TenantID: access.TenantID, ActorID: access.ActorID, Action: action, Resource: resource, DataClass: dataClass}
	if service.Repository == nil || service.Authorizer == nil || service.Audit == nil || service.Now == nil || validateIdentifier(string(access.TenantID)) != nil || validateIdentifier(string(access.ActorID)) != nil || action == "" || resource == "" {
		return request, ErrUnauthorized
	}
	if err := service.Authorizer.Authorize(ctx, request); err != nil {
		return request, ErrUnauthorized
	}
	return request, nil
}

func (service Service) requireStepUp(ctx context.Context, request AuthorizationRequest, proof string) (string, error) {
	if service.StepUp == nil || proof == "" {
		return "", ErrUnauthorized
	}
	receipt, err := service.StepUp.VerifyStepUp(ctx, request, proof)
	if err != nil || receipt == "" {
		return "", ErrUnauthorized
	}
	return receipt, nil
}

func (service Service) audit(ctx context.Context, request AuthorizationRequest, outcome, evidence string) error {
	return service.Audit.RecordAudit(ctx, AuditRecord{TenantID: request.TenantID, ActorID: request.ActorID, Action: request.Action, Resource: request.Resource, Outcome: outcome, EvidenceDigest: evidence, OccurredAt: service.Now().UTC()})
}

func mergeTags(left, right []TagID) ([]TagID, error) {
	combined := append(append([]TagID(nil), left...), right...)
	return normalizeTags(combined)
}

func verificationRank(verification Verification) int {
	if validateVerification(verification) != nil {
		return -1
	}
	rank := map[VerificationProvenance]int{VerificationUnverified: 0, VerificationMigrated: 1, VerificationSelfAsserted: 2, VerificationProvider: 3, VerificationDoubleOptIn: 4}[verification.Provenance]
	if verification.Certainty == CertaintyExact {
		rank += 10
	}
	return rank
}

func digestObject(value any) string {
	encoded, _ := json.Marshal(value)
	return DigestEvidence(encoded)
}

func unauthorizedOr(err error) error {
	if err != nil {
		return err
	}
	return ErrUnauthorized
}

func staleOr(err error) error {
	if err != nil {
		return err
	}
	return ErrStale
}

func timePointer(value time.Time) *time.Time { return &value }
