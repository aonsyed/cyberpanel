package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type QueueBackendRecipient struct {
	Address     Address
	DelayReason string
}

type QueueBackendRecord struct {
	QueueID     QueueID
	QueueName   string
	Sender      Address
	Recipients  []QueueBackendRecipient
	MessageBytes uint64
	ArrivedAt   time.Time
}

type QueueBackendSnapshot struct {
	Records        []QueueBackendRecord
	EvidenceDigest string
	ObservedAt     time.Time
}

type QueueBackendHeaders struct {
	QueueID        QueueID
	Headers        []QueueHeaderProjection
	EvidenceDigest string
	ObservedAt     time.Time
}

type QueueBackendBody struct {
	QueueID        QueueID
	Content        []byte
	ContentDigest  string
	ObservedAt     time.Time
}

type QueueBackendActionResult struct {
	QueueID        QueueID
	Outcome        QueueActionOutcome
	EvidenceDigest string
	ObservedAt     time.Time
}

type QueueAdminBackend interface {
	Snapshot(context.Context) (QueueBackendSnapshot, error)
	Headers(context.Context, QueueID) (QueueBackendHeaders, error)
	Body(context.Context, QueueID, uint32) (QueueBackendBody, error)
	Apply(context.Context, QueueAdminAction, QueueID) (QueueBackendActionResult, error)
	Flush(context.Context) (QueueBackendActionResult, error)
}

type QueueOwnershipBinding struct {
	TenantID         string
	DomainID         DomainID
	MailboxID        MailboxID
	DomainGeneration uint64
	MailboxGeneration uint64
}

type QueueOwnershipQuery struct {
	QueueID       QueueID
	Sender        Address
	Recipients    []Address
	MessageDigest string
	ObservedAt    time.Time
}

type QueueCanonicalOwnership struct {
	MessageDigest    string
	Bindings         []QueueOwnershipBinding
	Ambiguous        bool
	SourceGeneration uint64
	EvidenceDigest   string
	ResolvedAt       time.Time
}

// QueueCanonicalResolver must resolve envelope addresses against the current
// authoritative mail-domain and mailbox registry on every invocation.
type QueueCanonicalResolver interface {
	ResolveQueueOwnership(context.Context, QueueOwnershipQuery) (QueueCanonicalOwnership, error)
}

type QueueAuthorizationRequest struct {
	ActorID  string
	Action   QueueAdminAction
	Risk     QueueAdminRisk
	Scope    QueueAdminScope
	HostID   string
	QueueIDs []QueueID
	StepUp   *QueueStepUpProof
}

type QueueAdminAuthorizer interface {
	AuthorizeQueueAdmin(context.Context, QueueAuthorizationRequest) error
}

type QueueAuditEvent struct {
	RequestID     string
	ActorID       string
	Action        QueueAdminAction
	Risk          QueueAdminRisk
	Scope         QueueAdminScope
	HostID        string
	QueueIDs      []QueueID
	RequestDigest string
	OccurredAt    time.Time
}

// QueueAuditEvent intentionally has no address, header, or body field.
type QueueAdminAuditSink interface {
	RecordQueueAdmin(context.Context, QueueAuditEvent) error
}

type QueueAdminService struct {
	Operations QueueOperationRepository
	Ownership  QueueCanonicalResolver
	Authorizer QueueAdminAuthorizer
	Backend    QueueAdminBackend
	Audit      QueueAdminAuditSink
	Now        func() time.Time
}

func NewQueueAdminService(operations QueueOperationRepository, ownership QueueCanonicalResolver, authorizer QueueAdminAuthorizer, backend QueueAdminBackend, audit QueueAdminAuditSink, now func() time.Time) (*QueueAdminService, error) {
	if operations == nil || ownership == nil || authorizer == nil || backend == nil || audit == nil {
		return nil, ErrInvalidCommand
	}
	if now == nil {
		now = time.Now
	}
	return &QueueAdminService{Operations: operations, Ownership: ownership, Authorizer: authorizer, Backend: backend, Audit: audit, Now: now}, nil
}

func (service *QueueAdminService) Summary(ctx context.Context, request QueueReadRequest) (QueueSummary, error) {
	if err := service.validateRead(ctx, request, false); err != nil || request.Cursor != "" || request.Limit != 0 {
		if err != nil {
			return QueueSummary{}, err
		}
		return QueueSummary{}, ErrInvalidCommand
	}
	requestDigest, err := queueRequestDigest(request.Scope, request.Filter, false)
	if err != nil {
		return QueueSummary{}, err
	}
	if err = service.authorize(ctx, request.ActorID, QueueAdminSummarize, QueueRiskNormal, request.Scope, "", nil, nil); err != nil {
		return QueueSummary{}, err
	}
	snapshot, err := service.snapshot(ctx)
	if err != nil {
		return QueueSummary{}, err
	}
	projections, err := service.scopedProjections(ctx, snapshot, request.Scope, request.Filter, queueCursor{}, 0)
	if err != nil {
		return QueueSummary{}, err
	}
	if err = service.audit(ctx, request.RequestID, request.ActorID, QueueAdminSummarize, QueueRiskNormal, request.Scope, "", nil, requestDigest); err != nil {
		return QueueSummary{}, err
	}
	summary := QueueSummary{Total: uint32(len(projections)), ByState: map[QueueMessageState]uint32{}, ObservedAt: snapshot.ObservedAt}
	digests := make([]string, 0, len(projections))
	for _, projection := range projections {
		summary.TotalBytes += projection.MessageBytes
		summary.ByState[projection.State]++
		if summary.OldestArrivedAt == nil || projection.ArrivedAt.Before(*summary.OldestArrivedAt) {
			value := projection.ArrivedAt
			summary.OldestArrivedAt = &value
		}
		digests = append(digests, projection.MessageDigest)
	}
	summary.ScopeDigest, err = queueDigest("mail-queue-summary-v1", digests)
	if err != nil {
		return QueueSummary{}, err
	}
	return summary, nil
}

func (service *QueueAdminService) List(ctx context.Context, request QueueReadRequest) (QueuePage, error) {
	return service.page(ctx, request, false)
}

func (service *QueueAdminService) Search(ctx context.Context, request QueueReadRequest) (QueuePage, error) {
	return service.page(ctx, request, true)
}

func (service *QueueAdminService) page(ctx context.Context, request QueueReadRequest, search bool) (QueuePage, error) {
	if err := service.validateRead(ctx, request, search); err != nil {
		return QueuePage{}, err
	}
	requestDigest, err := queueRequestDigest(request.Scope, request.Filter, search)
	if err != nil {
		return QueuePage{}, err
	}
	cursor, err := decodeQueueCursor(request.Cursor, requestDigest)
	if err != nil {
		return QueuePage{}, err
	}
	limit := request.Limit
	if limit == 0 {
		limit = QueueAdminDefaultLimit
	}
	action := QueueAdminList
	if search {
		action = QueueAdminSearch
	}
	if err = service.authorize(ctx, request.ActorID, action, QueueRiskNormal, request.Scope, "", nil, nil); err != nil {
		return QueuePage{}, err
	}
	snapshot, err := service.snapshot(ctx)
	if err != nil {
		return QueuePage{}, err
	}
	items, err := service.scopedProjections(ctx, snapshot, request.Scope, request.Filter, cursor, limit+1)
	if err != nil {
		return QueuePage{}, err
	}
	page := QueuePage{Items: items, ObservedAt: snapshot.ObservedAt}
	if len(page.Items) > int(limit) {
		page.Items = page.Items[:limit]
		page.NextCursor, err = encodeQueueCursor(page.Items[len(page.Items)-1], requestDigest)
		if err != nil {
			return QueuePage{}, err
		}
	}
	digests := make([]string, 0, len(page.Items))
	for _, item := range page.Items {
		digests = append(digests, item.MessageDigest)
	}
	page.ScopeDigest, err = queueDigest("mail-queue-page-result-v1", digests)
	if err != nil {
		return QueuePage{}, err
	}
	if err = service.audit(ctx, request.RequestID, request.ActorID, action, QueueRiskNormal, request.Scope, "", nil, requestDigest); err != nil {
		return QueuePage{}, err
	}
	return page, nil
}

func (service *QueueAdminService) Detail(ctx context.Context, request QueueMessageRequest) (QueueMessageDetail, error) {
	if err := service.validateMessage(ctx, request, false); err != nil {
		return QueueMessageDetail{}, err
	}
	requestDigest, err := queueDigest("mail-queue-detail-v1", request)
	if err != nil {
		return QueueMessageDetail{}, err
	}
	if err = service.authorize(ctx, request.ActorID, QueueAdminInspect, QueueRiskNormal, request.Scope, "", []QueueID{request.QueueID}, nil); err != nil {
		return QueueMessageDetail{}, err
	}
	snapshot, err := service.snapshot(ctx)
	if err != nil {
		return QueueMessageDetail{}, err
	}
	record, found := findQueueRecord(snapshot.Records, request.QueueID)
	if !found {
		return QueueMessageDetail{}, ErrNotFound
	}
	messageDigest, err := queueRecordDigest(record)
	if err != nil {
		return QueueMessageDetail{}, err
	}
	if request.ExpectedMessageDigest != "" && request.ExpectedMessageDigest != messageDigest {
		return QueueMessageDetail{}, ErrConflict
	}
	owned, err := service.scopeOwns(ctx, request.Scope, record, messageDigest, snapshot.ObservedAt)
	if err != nil {
		return QueueMessageDetail{}, err
	}
	if !owned {
		return QueueMessageDetail{}, ErrUnauthorized
	}
	if err = service.audit(ctx, request.RequestID, request.ActorID, QueueAdminInspect, QueueRiskNormal, request.Scope, "", []QueueID{request.QueueID}, requestDigest); err != nil {
		return QueueMessageDetail{}, err
	}
	headers, err := service.Backend.Headers(ctx, request.QueueID)
	if err != nil {
		return QueueMessageDetail{}, err
	}
	if err = validateBackendHeaders(headers, request.QueueID, service.now()); err != nil {
		return QueueMessageDetail{}, err
	}
	projection, err := projectQueueRecord(record, request.Scope, snapshot.ObservedAt, messageDigest)
	if err != nil {
		return QueueMessageDetail{}, err
	}
	detail := QueueMessageDetail{Message: projection, Headers: append([]QueueHeaderProjection(nil), headers.Headers...), HeaderEvidenceDigest: headers.EvidenceDigest, InspectedAt: headers.ObservedAt}
	maximum := len(record.Recipients)
	if maximum > int(QueueAdminMaximumRecipients) {
		maximum = int(QueueAdminMaximumRecipients)
		detail.RecipientsTruncated = true
	}
	for _, recipient := range record.Recipients[:maximum] {
		detail.Recipients = append(detail.Recipients, QueueRecipientProjection{Address: projectQueueAddress(recipient.Address), Deferred: recipient.DelayReason != ""})
	}
	return detail, nil
}

func (service *QueueAdminService) Body(ctx context.Context, request QueueBodyRequest) (QueueBody, error) {
	if err := service.validateMessage(ctx, request.Message, true); err != nil {
		return QueueBody{}, err
	}
	maximum := request.MaximumBytes
	if maximum == 0 {
		maximum = QueueAdminMaximumBodyBytes
	}
	now := service.now()
	if maximum > QueueAdminMaximumBodyBytes || !validQueueStepUp(request.StepUp, now) {
		return QueueBody{}, ErrInvalidCommand
	}
	requestDigest, err := queueDigest("mail-queue-body-v1", struct {
		Message      QueueMessageRequest `json:"message"`
		ProofID      string              `json:"proof_id"`
		MaximumBytes uint32              `json:"maximum_bytes"`
	}{Message: request.Message, ProofID: request.StepUp.ProofID, MaximumBytes: maximum})
	if err != nil {
		return QueueBody{}, err
	}
	if err = service.authorize(ctx, request.Message.ActorID, QueueAdminReadBody, QueueRiskStepUp, request.Message.Scope, "", []QueueID{request.Message.QueueID}, &request.StepUp); err != nil {
		return QueueBody{}, err
	}
	snapshot, err := service.snapshot(ctx)
	if err != nil {
		return QueueBody{}, err
	}
	record, found := findQueueRecord(snapshot.Records, request.Message.QueueID)
	if !found {
		return QueueBody{}, ErrNotFound
	}
	messageDigest, err := queueRecordDigest(record)
	if err != nil {
		return QueueBody{}, err
	}
	if request.Message.ExpectedMessageDigest != messageDigest {
		return QueueBody{}, ErrConflict
	}
	owned, err := service.scopeOwns(ctx, request.Message.Scope, record, messageDigest, snapshot.ObservedAt)
	if err != nil {
		return QueueBody{}, err
	}
	if !owned {
		return QueueBody{}, ErrUnauthorized
	}
	if err = service.audit(ctx, request.Message.RequestID, request.Message.ActorID, QueueAdminReadBody, QueueRiskStepUp, request.Message.Scope, "", []QueueID{request.Message.QueueID}, requestDigest); err != nil {
		return QueueBody{}, err
	}
	material, err := service.Backend.Body(ctx, request.Message.QueueID, maximum)
	if err != nil {
		wipeQueueBytes(material.Content)
		return QueueBody{}, err
	}
	if material.QueueID != request.Message.QueueID || uint32(len(material.Content)) > maximum || !validQueueDigest(material.ContentDigest) || !canonicalQueueTime(material.ObservedAt) || material.ObservedAt.After(service.now().Add(time.Minute)) {
		wipeQueueBytes(material.Content)
		return QueueBody{}, ErrInvalidReceipt
	}
	digest := sha256.Sum256(material.Content)
	if hex.EncodeToString(digest[:]) != material.ContentDigest {
		wipeQueueBytes(material.Content)
		return QueueBody{}, ErrInvalidReceipt
	}
	return QueueBody{QueueID: material.QueueID, Content: material.Content, ContentBytes: uint32(len(material.Content)), ContentDigest: material.ContentDigest, ObservedAt: material.ObservedAt}, nil
}

func (service *QueueAdminService) Act(ctx context.Context, request QueueActionRequest) (QueueActionReceipt, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(request.OperationID) || !validOpaque(request.ActorID) || request.Scope.Validate() != nil || !validQueueAdminAction(request.Action) {
		if err != nil {
			return QueueActionReceipt{}, err
		}
		return QueueActionReceipt{}, ErrInvalidCommand
	}
	now := service.now()
	targets, err := normalizeQueueTargets(request.Targets, now)
	if err != nil {
		return QueueActionReceipt{}, err
	}
	canonicalRequest := request
	canonicalRequest.Targets = targets
	requestDigest, err := queueDigest("mail-queue-action-v1", canonicalRequest)
	if err != nil {
		return QueueActionReceipt{}, err
	}
	risk := QueueRiskElevated
	if request.Action == QueueAdminDelete {
		risk = QueueRiskHigh
	}
	queueIDs := targetQueueIDs(targets)
	if err = service.authorize(ctx, request.ActorID, request.Action, risk, request.Scope, "", queueIDs, nil); err != nil {
		return QueueActionReceipt{}, err
	}
	partition := queueOperationPartition("tenant", request.Scope.TenantID)
	if prior, found, lookupErr := service.Operations.Lookup(ctx, partition, request.OperationID, requestDigest); lookupErr != nil {
		return QueueActionReceipt{}, lookupErr
	} else if found {
		if auditErr := service.audit(ctx, request.OperationID, request.ActorID, request.Action, risk, request.Scope, "", queueIDs, requestDigest); auditErr != nil {
			return QueueActionReceipt{}, auditErr
		}
		return receiptResult(prior)
	}
	snapshot, err := service.snapshot(ctx)
	if err != nil {
		return QueueActionReceipt{}, err
	}
	for _, target := range targets {
		record, found := findQueueRecord(snapshot.Records, target.QueueID)
		if !found {
			return QueueActionReceipt{}, ErrConflict
		}
		messageDigest, digestErr := queueRecordDigest(record)
		if digestErr != nil {
			return QueueActionReceipt{}, digestErr
		}
		if target.ExpectedMessageDigest != messageDigest {
			return QueueActionReceipt{}, ErrConflict
		}
		owned, ownershipErr := service.scopeOwns(ctx, request.Scope, record, messageDigest, snapshot.ObservedAt)
		if ownershipErr != nil {
			return QueueActionReceipt{}, ownershipErr
		}
		if !owned {
			return QueueActionReceipt{}, ErrUnauthorized
		}
	}
	if err = service.audit(ctx, request.OperationID, request.ActorID, request.Action, risk, request.Scope, "", queueIDs, requestDigest); err != nil {
		return QueueActionReceipt{}, err
	}
	claim, err := service.Operations.Claim(ctx, partition, request.OperationID, request.Action, requestDigest, now)
	if err != nil {
		return QueueActionReceipt{}, err
	}
	if claim.Receipt != nil {
		return receiptResult(*claim.Receipt)
	}
	receipt := QueueActionReceipt{OperationID: request.OperationID, RequestDigest: requestDigest, Action: request.Action, Scope: request.Scope, Status: QueueOperationApplied, CompletedAt: service.now()}
	for _, target := range targets {
		result, applyErr := service.Backend.Apply(ctx, request.Action, target.QueueID)
		if validationErr := validateBackendAction(result, target.QueueID, service.now()); validationErr != nil {
			result = QueueBackendActionResult{QueueID: target.QueueID, Outcome: QueueActionAmbiguous, EvidenceDigest: emptyQueueEvidenceDigest(), ObservedAt: service.now()}
			applyErr = errors.Join(applyErr, validationErr)
		}
		if applyErr != nil {
			result.Outcome = QueueActionAmbiguous
		}
		receipt.Targets = append(receipt.Targets, QueueTargetReceipt{QueueID: result.QueueID, Outcome: result.Outcome, EvidenceDigest: result.EvidenceDigest, ObservedAt: result.ObservedAt})
		if result.Outcome == QueueActionAmbiguous || applyErr != nil {
			receipt.Status = QueueOperationAmbiguous
			break
		}
		if result.Outcome == QueueActionNotFound {
			receipt.Status = QueueOperationCompleted
		}
	}
	receipt.CompletedAt = service.now()
	receipt.EvidenceDigest, err = queueDigest("mail-queue-action-receipt-v1", receipt.Targets)
	if err != nil {
		return QueueActionReceipt{}, errors.Join(ErrAmbiguous, err)
	}
	if err = service.Operations.Complete(ctx, partition, request.OperationID, requestDigest, claim.Token, receipt); err != nil {
		return QueueActionReceipt{}, errors.Join(ErrAmbiguous, err)
	}
	return receiptResult(receipt)
}

func (service *QueueAdminService) Flush(ctx context.Context, request QueueFlushRequest) (QueueActionReceipt, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(request.OperationID) || !validOpaque(request.ActorID) || !validOpaque(request.HostID) || len(request.HostID) > 120 {
		if err != nil {
			return QueueActionReceipt{}, err
		}
		return QueueActionReceipt{}, ErrInvalidCommand
	}
	requestDigest, err := queueDigest("mail-queue-flush-v1", request)
	if err != nil {
		return QueueActionReceipt{}, err
	}
	if err = service.authorize(ctx, request.ActorID, QueueAdminFlush, QueueRiskHostAdmin, QueueAdminScope{}, request.HostID, nil, nil); err != nil {
		return QueueActionReceipt{}, err
	}
	partition := queueOperationPartition("host", request.HostID)
	if prior, found, lookupErr := service.Operations.Lookup(ctx, partition, request.OperationID, requestDigest); lookupErr != nil {
		return QueueActionReceipt{}, lookupErr
	} else if found {
		if auditErr := service.audit(ctx, request.OperationID, request.ActorID, QueueAdminFlush, QueueRiskHostAdmin, QueueAdminScope{}, request.HostID, nil, requestDigest); auditErr != nil {
			return QueueActionReceipt{}, auditErr
		}
		return receiptResult(prior)
	}
	if err = service.audit(ctx, request.OperationID, request.ActorID, QueueAdminFlush, QueueRiskHostAdmin, QueueAdminScope{}, request.HostID, nil, requestDigest); err != nil {
		return QueueActionReceipt{}, err
	}
	claim, err := service.Operations.Claim(ctx, partition, request.OperationID, QueueAdminFlush, requestDigest, service.now())
	if err != nil {
		return QueueActionReceipt{}, err
	}
	if claim.Receipt != nil {
		return receiptResult(*claim.Receipt)
	}
	result, applyErr := service.Backend.Flush(ctx)
	if validationErr := validateBackendAction(result, "", service.now()); validationErr != nil {
		result = QueueBackendActionResult{Outcome: QueueActionAmbiguous, EvidenceDigest: emptyQueueEvidenceDigest(), ObservedAt: service.now()}
		applyErr = errors.Join(applyErr, validationErr)
	}
	status := QueueOperationApplied
	if result.Outcome == QueueActionAmbiguous || applyErr != nil {
		status = QueueOperationAmbiguous
	}
	receipt := QueueActionReceipt{OperationID: request.OperationID, RequestDigest: requestDigest, Action: QueueAdminFlush, HostID: request.HostID, Status: status, EvidenceDigest: result.EvidenceDigest, CompletedAt: service.now()}
	if err = service.Operations.Complete(ctx, partition, request.OperationID, requestDigest, claim.Token, receipt); err != nil {
		return QueueActionReceipt{}, errors.Join(ErrAmbiguous, err)
	}
	return receiptResult(receipt)
}

func (service *QueueAdminService) scopedProjections(ctx context.Context, snapshot QueueBackendSnapshot, scope QueueAdminScope, filter QueueFilter, cursor queueCursor, maximum uint32) ([]QueueMessageProjection, error) {
	result := make([]QueueMessageProjection, 0)
	for _, record := range snapshot.Records {
		if !queueFilterMatches(filter, record) || !queueRecordAfterCursor(record, cursor) {
			continue
		}
		messageDigest, err := queueRecordDigest(record)
		if err != nil {
			return nil, err
		}
		owned, err := service.scopeOwns(ctx, scope, record, messageDigest, snapshot.ObservedAt)
		if err != nil {
			return nil, err
		}
		if !owned {
			continue
		}
		projection, err := projectQueueRecord(record, scope, snapshot.ObservedAt, messageDigest)
		if err != nil {
			return nil, err
		}
		result = append(result, projection)
		if maximum != 0 && uint32(len(result)) >= maximum {
			break
		}
	}
	return result, nil
}

func (service *QueueAdminService) scopeOwns(ctx context.Context, scope QueueAdminScope, record QueueBackendRecord, messageDigest string, observedAt time.Time) (bool, error) {
	recipients := make([]Address, 0, len(record.Recipients))
	for _, recipient := range record.Recipients {
		recipients = append(recipients, recipient.Address)
	}
	resolved, err := service.Ownership.ResolveQueueOwnership(ctx, QueueOwnershipQuery{QueueID: record.QueueID, Sender: record.Sender, Recipients: recipients, MessageDigest: messageDigest, ObservedAt: observedAt})
	if err != nil {
		return false, err
	}
	if err = validateCanonicalOwnership(resolved, messageDigest, service.now()); err != nil {
		return false, err
	}
	if resolved.Ambiguous {
		return false, ErrAmbiguous
	}
	if len(resolved.Bindings) == 0 {
		return false, nil
	}
	matched := false
	unmatched := false
	for _, binding := range resolved.Bindings {
		bindingMatches := binding.TenantID == scope.TenantID
		if scope.DomainID != "" {
			bindingMatches = bindingMatches && binding.DomainID == scope.DomainID
			if binding.TenantID == scope.TenantID && binding.DomainID == scope.DomainID && binding.DomainGeneration != scope.ExpectedDomainGeneration {
				return false, ErrConflict
			}
		}
		if scope.MailboxID != "" {
			bindingMatches = bindingMatches && binding.MailboxID == scope.MailboxID
			if binding.TenantID == scope.TenantID && binding.DomainID == scope.DomainID && binding.MailboxID == scope.MailboxID && binding.MailboxGeneration != scope.ExpectedMailboxGeneration {
				return false, ErrConflict
			}
		}
		if bindingMatches {
			matched = true
		} else {
			unmatched = true
		}
	}
	if matched && unmatched {
		return false, ErrAmbiguous
	}
	return matched, nil
}

func (service *QueueAdminService) snapshot(ctx context.Context) (QueueBackendSnapshot, error) {
	snapshot, err := service.Backend.Snapshot(ctx)
	if err != nil {
		return QueueBackendSnapshot{}, err
	}
	if err = validateBackendSnapshot(snapshot, service.now()); err != nil {
		return QueueBackendSnapshot{}, err
	}
	sort.Slice(snapshot.Records, func(left, right int) bool {
		if snapshot.Records[left].ArrivedAt.Equal(snapshot.Records[right].ArrivedAt) {
			return snapshot.Records[left].QueueID < snapshot.Records[right].QueueID
		}
		return snapshot.Records[left].ArrivedAt.After(snapshot.Records[right].ArrivedAt)
	})
	return snapshot, nil
}

func (service *QueueAdminService) validateRead(ctx context.Context, request QueueReadRequest, search bool) error {
	if err := service.ready(ctx); err != nil {
		return err
	}
	if !validOpaque(request.RequestID) || !validOpaque(request.ActorID) || request.Scope.Validate() != nil || request.Limit > QueueAdminMaximumLimit {
		return ErrInvalidCommand
	}
	return request.Filter.Validate(search)
}

func (service *QueueAdminService) validateMessage(ctx context.Context, request QueueMessageRequest, requireProof bool) error {
	if err := service.ready(ctx); err != nil {
		return err
	}
	if !validOpaque(request.RequestID) || !validOpaque(request.ActorID) || request.Scope.Validate() != nil || !validQueueAdminID(request.QueueID) {
		return ErrInvalidCommand
	}
	if request.ExpectedMessageDigest == "" {
		if requireProof || !request.ObservedAt.IsZero() {
			return ErrInvalidCommand
		}
		return nil
	}
	now := service.now()
	if !validQueueDigest(request.ExpectedMessageDigest) || !canonicalQueueTime(request.ObservedAt) || request.ObservedAt.After(now) || now.Sub(request.ObservedAt) > queueAdminMaximumProofAge {
		return ErrInvalidCommand
	}
	return nil
}

func (service *QueueAdminService) authorize(ctx context.Context, actor string, action QueueAdminAction, risk QueueAdminRisk, scope QueueAdminScope, host string, ids []QueueID, stepUp *QueueStepUpProof) error {
	request := QueueAuthorizationRequest{ActorID: actor, Action: action, Risk: risk, Scope: scope, HostID: host, QueueIDs: append([]QueueID(nil), ids...), StepUp: stepUp}
	if err := service.Authorizer.AuthorizeQueueAdmin(ctx, request); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

func (service *QueueAdminService) audit(ctx context.Context, requestID, actor string, action QueueAdminAction, risk QueueAdminRisk, scope QueueAdminScope, host string, ids []QueueID, requestDigest string) error {
	event := QueueAuditEvent{RequestID: requestID, ActorID: actor, Action: action, Risk: risk, Scope: scope, HostID: host, QueueIDs: append([]QueueID(nil), ids...), RequestDigest: requestDigest, OccurredAt: service.now()}
	if !validOpaque(event.RequestID) || !validOpaque(event.ActorID) || !validQueueDigest(event.RequestDigest) || !canonicalQueueTime(event.OccurredAt) || len(event.QueueIDs) > int(QueueAdminMaximumBatch) {
		return ErrInvalidCommand
	}
	for _, id := range event.QueueIDs {
		if !validQueueAdminID(id) {
			return ErrInvalidCommand
		}
	}
	if action == QueueAdminFlush {
		if risk != QueueRiskHostAdmin || !validOpaque(host) || scope.TenantID != "" {
			return ErrInvalidCommand
		}
	} else if scope.Validate() != nil || host != "" {
		return ErrInvalidCommand
	}
	return service.Audit.RecordQueueAdmin(ctx, event)
}

func (service *QueueAdminService) ready(ctx context.Context) error {
	if service == nil || ctx == nil || service.Operations == nil || service.Ownership == nil || service.Authorizer == nil || service.Backend == nil || service.Audit == nil || service.Now == nil {
		return ErrInvalidCommand
	}
	return nil
}

func (service *QueueAdminService) now() time.Time {
	return service.Now().UTC().Truncate(time.Second)
}

func validateBackendSnapshot(snapshot QueueBackendSnapshot, now time.Time) error {
	if !canonicalQueueTime(snapshot.ObservedAt) || snapshot.ObservedAt.After(now.Add(time.Minute)) || !validQueueDigest(snapshot.EvidenceDigest) || len(snapshot.Records) > int(QueueAdminMaximumBackendRecords) {
		return ErrInvalidReceipt
	}
	seen := make(map[QueueID]struct{}, len(snapshot.Records))
	for _, record := range snapshot.Records {
		if !validQueueAdminID(record.QueueID) || !validQueueName(record.QueueName) || !canonicalQueueAddress(record.Sender, true) || record.MessageBytes > queueAdminMaximumMessageBytes || !canonicalQueueTime(record.ArrivedAt) || record.ArrivedAt.After(now.Add(time.Minute)) || len(record.Recipients) == 0 || len(record.Recipients) > int(QueueAdminMaximumBackendRecords) {
			return ErrInvalidReceipt
		}
		if _, found := seen[record.QueueID]; found {
			return ErrAmbiguous
		}
		seen[record.QueueID] = struct{}{}
		for _, recipient := range record.Recipients {
			if !canonicalQueueAddress(recipient.Address, false) || len(recipient.DelayReason) > 4096 || strings.ContainsRune(recipient.DelayReason, '\x00') {
				return ErrInvalidReceipt
			}
		}
	}
	return nil
}

func validateBackendHeaders(headers QueueBackendHeaders, id QueueID, now time.Time) error {
	if headers.QueueID != id || !validQueueDigest(headers.EvidenceDigest) || !canonicalQueueTime(headers.ObservedAt) || headers.ObservedAt.After(now.Add(time.Minute)) || len(headers.Headers) > int(QueueAdminMaximumRecipients) {
		return ErrInvalidReceipt
	}
	for _, header := range headers.Headers {
		if !validQueueHeaderName(header.Name) || header.ValueClass != "redacted" {
			return ErrInvalidReceipt
		}
	}
	return nil
}

func validateBackendAction(result QueueBackendActionResult, expected QueueID, now time.Time) error {
	if result.QueueID != expected || !validQueueDigest(result.EvidenceDigest) || !canonicalQueueTime(result.ObservedAt) || result.ObservedAt.After(now.Add(time.Minute)) {
		return ErrInvalidReceipt
	}
	switch result.Outcome {
	case QueueActionApplied, QueueActionAlreadySatisfied, QueueActionNotFound, QueueActionAmbiguous:
		return nil
	default:
		return ErrInvalidReceipt
	}
}

func validateCanonicalOwnership(result QueueCanonicalOwnership, messageDigest string, now time.Time) error {
	if result.MessageDigest != messageDigest || !validQueueDigest(result.EvidenceDigest) || result.SourceGeneration == 0 || !canonicalQueueTime(result.ResolvedAt) || result.ResolvedAt.After(now.Add(time.Minute)) || now.Sub(result.ResolvedAt) > queueAdminMaximumProofAge || len(result.Bindings) > int(QueueAdminMaximumRecipients) {
		return ErrInvalidReceipt
	}
	seen := make(map[string]struct{}, len(result.Bindings))
	for _, binding := range result.Bindings {
		if !validOpaque(binding.TenantID) {
			return ErrInvalidReceipt
		}
		if binding.DomainID == "" {
			if binding.MailboxID != "" || binding.DomainGeneration != 0 || binding.MailboxGeneration != 0 {
				return ErrInvalidReceipt
			}
		} else if !validOpaque(string(binding.DomainID)) || binding.DomainGeneration == 0 || binding.MailboxID == "" && binding.MailboxGeneration != 0 || binding.MailboxID != "" && (!validOpaque(string(binding.MailboxID)) || binding.MailboxGeneration == 0) {
			return ErrInvalidReceipt
		}
		key := binding.TenantID + "\x00" + string(binding.DomainID) + "\x00" + string(binding.MailboxID)
		if _, found := seen[key]; found {
			return ErrInvalidReceipt
		}
		seen[key] = struct{}{}
	}
	return nil
}

func queueRecordDigest(record QueueBackendRecord) (string, error) {
	copyRecord := record
	copyRecord.Recipients = append([]QueueBackendRecipient(nil), record.Recipients...)
	sort.Slice(copyRecord.Recipients, func(left, right int) bool {
		if copyRecord.Recipients[left].Address == copyRecord.Recipients[right].Address {
			return copyRecord.Recipients[left].DelayReason < copyRecord.Recipients[right].DelayReason
		}
		return copyRecord.Recipients[left].Address < copyRecord.Recipients[right].Address
	})
	return queueDigest("mail-queue-message-v1", copyRecord)
}

func projectQueueRecord(record QueueBackendRecord, scope QueueAdminScope, observedAt time.Time, messageDigest string) (QueueMessageProjection, error) {
	if !validQueueDigest(messageDigest) {
		return QueueMessageProjection{}, ErrInvalidCommand
	}
	domainSet := make(map[string]struct{})
	deferred := false
	for _, recipient := range record.Recipients {
		parts := strings.SplitN(string(recipient.Address), "@", 2)
		if len(parts) != 2 {
			return QueueMessageProjection{}, ErrInvalidReceipt
		}
		domainSet[parts[1]] = struct{}{}
		deferred = deferred || recipient.DelayReason != ""
	}
	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	truncated := false
	if len(domains) > 32 {
		domains = domains[:32]
		truncated = true
	}
	return QueueMessageProjection{QueueID: record.QueueID, QueueName: record.QueueName, State: queueState(record.QueueName), Sender: projectQueueAddress(record.Sender), RecipientCount: uint32(len(record.Recipients)), RecipientDomains: domains, RecipientDomainsTruncated: truncated, Deferred: deferred, MessageBytes: record.MessageBytes, ArrivedAt: record.ArrivedAt, MessageDigest: messageDigest, Scope: scope, ObservedAt: observedAt}, nil
}

func projectQueueAddress(address Address) QueueAddressProjection {
	if address == "<>" {
		return QueueAddressProjection{NullSender: true}
	}
	parts := strings.SplitN(string(address), "@", 2)
	digest := sha256.Sum256([]byte("mail-queue-local-v1\x00" + parts[0]))
	return QueueAddressProjection{Domain: parts[1], LocalHash: hex.EncodeToString(digest[:8])}
}

func queueFilterMatches(filter QueueFilter, record QueueBackendRecord) bool {
	if filter.QueueID != "" && record.QueueID != filter.QueueID || filter.QueueName != "" && record.QueueName != filter.QueueName || filter.State != "" && queueState(record.QueueName) != filter.State || filter.Sender != "" && record.Sender != filter.Sender || filter.MinimumBytes != 0 && record.MessageBytes < filter.MinimumBytes || filter.MaximumBytes != 0 && record.MessageBytes > filter.MaximumBytes || filter.ArrivedAfter != nil && record.ArrivedAt.Before(*filter.ArrivedAfter) || filter.ArrivedBefore != nil && !record.ArrivedAt.Before(*filter.ArrivedBefore) {
		return false
	}
	if filter.Recipient != "" {
		for _, recipient := range record.Recipients {
			if recipient.Address == filter.Recipient {
				return true
			}
		}
		return false
	}
	return true
}

func queueRecordAfterCursor(record QueueBackendRecord, cursor queueCursor) bool {
	if cursor.Version == 0 {
		return true
	}
	arrived := time.Unix(cursor.ArrivedUnix, 0).UTC()
	return record.ArrivedAt.Before(arrived) || record.ArrivedAt.Equal(arrived) && record.QueueID > cursor.QueueID
}

func findQueueRecord(records []QueueBackendRecord, id QueueID) (QueueBackendRecord, bool) {
	for _, record := range records {
		if record.QueueID == id {
			return record, true
		}
	}
	return QueueBackendRecord{}, false
}

func targetQueueIDs(targets []QueueActionTarget) []QueueID {
	result := make([]QueueID, 0, len(targets))
	for _, target := range targets {
		result = append(result, target.QueueID)
	}
	return result
}

func validQueueStepUp(proof QueueStepUpProof, now time.Time) bool {
	return validOpaque(proof.ProofID) && canonicalQueueTime(proof.VerifiedAt) && canonicalQueueTime(proof.ExpiresAt) && !proof.VerifiedAt.After(now) && proof.ExpiresAt.After(now) && proof.ExpiresAt.After(proof.VerifiedAt) && proof.ExpiresAt.Sub(proof.VerifiedAt) <= 15*time.Minute
}

func validQueueHeaderName(name string) bool {
	if len(name) == 0 || len(name) > 78 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for _, character := range name {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
}

func receiptResult(receipt QueueActionReceipt) (QueueActionReceipt, error) {
	if err := validateQueueActionReceipt(receipt); err != nil {
		return QueueActionReceipt{}, err
	}
	if receipt.Status == QueueOperationAmbiguous {
		return receipt, ErrAmbiguous
	}
	if receipt.Status == QueueOperationCompleted {
		return receipt, ErrConflict
	}
	return receipt, nil
}

func emptyQueueEvidenceDigest() string {
	digest := sha256.Sum256([]byte("mail-queue-empty-evidence-v1"))
	return hex.EncodeToString(digest[:])
}

func queueOperationPartition(kind, id string) string {
	digest := sha256.Sum256([]byte("mail-queue-operation-partition-v1\x00" + kind + "\x00" + id))
	return kind + "_" + hex.EncodeToString(digest[:])
}

func wipeQueueBytes(content []byte) {
	for index := range content {
		content[index] = 0
	}
}
