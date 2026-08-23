package mail

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	QueueAdminDefaultLimit          uint32 = 50
	QueueAdminMaximumLimit          uint32 = 200
	QueueAdminMaximumBatch          uint32 = 100
	QueueAdminMaximumRecipients     uint32 = 200
	QueueAdminMaximumBackendRecords uint32 = 10000
	QueueAdminMaximumBodyBytes      uint32 = 64 << 10
	queueAdminMaximumCursorBytes           = 512
	queueAdminMaximumMessageBytes   uint64 = 2 << 30
	queueAdminMaximumProofAge              = 5 * time.Minute
)

type QueueAdminAction string

const (
	QueueAdminSummarize QueueAdminAction = "queue.summary"
	QueueAdminList      QueueAdminAction = "queue.list"
	QueueAdminSearch    QueueAdminAction = "queue.search"
	QueueAdminInspect   QueueAdminAction = "queue.detail"
	QueueAdminReadBody  QueueAdminAction = "queue.body.read"
	QueueAdminRetry     QueueAdminAction = "queue.retry"
	QueueAdminHold      QueueAdminAction = "queue.hold"
	QueueAdminRelease   QueueAdminAction = "queue.release"
	QueueAdminDelete    QueueAdminAction = "queue.delete"
	QueueAdminFlush     QueueAdminAction = "queue.flush"
)

type QueueAdminRisk string

const (
	QueueRiskNormal    QueueAdminRisk = "normal"
	QueueRiskElevated  QueueAdminRisk = "elevated"
	QueueRiskStepUp    QueueAdminRisk = "step_up"
	QueueRiskHigh      QueueAdminRisk = "high"
	QueueRiskHostAdmin QueueAdminRisk = "host_admin"
)

type QueueMessageState string

const (
	QueueMessageActive   QueueMessageState = "active"
	QueueMessageDeferred QueueMessageState = "deferred"
	QueueMessageHeld     QueueMessageState = "held"
	QueueMessagePending  QueueMessageState = "pending"
)

type QueueAdminScope struct {
	TenantID                 string    `json:"tenant_id"`
	DomainID                 DomainID  `json:"domain_id,omitempty"`
	MailboxID                MailboxID `json:"mailbox_id,omitempty"`
	ExpectedDomainGeneration uint64    `json:"expected_domain_generation,omitempty"`
	ExpectedMailboxGeneration uint64   `json:"expected_mailbox_generation,omitempty"`
}

func (scope QueueAdminScope) Validate() error {
	if !validOpaque(scope.TenantID) {
		return ErrInvalidCommand
	}
	if scope.DomainID == "" {
		if scope.MailboxID != "" || scope.ExpectedDomainGeneration != 0 || scope.ExpectedMailboxGeneration != 0 {
			return ErrInvalidCommand
		}
		return nil
	}
	if !validOpaque(string(scope.DomainID)) || scope.ExpectedDomainGeneration == 0 {
		return ErrInvalidCommand
	}
	if scope.MailboxID == "" {
		if scope.ExpectedMailboxGeneration != 0 {
			return ErrInvalidCommand
		}
		return nil
	}
	if !validOpaque(string(scope.MailboxID)) || scope.ExpectedMailboxGeneration == 0 {
		return ErrInvalidCommand
	}
	return nil
}

type QueueFilter struct {
	QueueID      QueueID           `json:"queue_id,omitempty"`
	QueueName    string            `json:"queue_name,omitempty"`
	State        QueueMessageState `json:"state,omitempty"`
	Sender       Address           `json:"sender,omitempty"`
	Recipient    Address           `json:"recipient,omitempty"`
	ArrivedAfter *time.Time        `json:"arrived_after,omitempty"`
	ArrivedBefore *time.Time       `json:"arrived_before,omitempty"`
	MinimumBytes uint64            `json:"minimum_bytes,omitempty"`
	MaximumBytes uint64            `json:"maximum_bytes,omitempty"`
}

func (filter QueueFilter) Validate(search bool) error {
	if filter.QueueID != "" && !validQueueAdminID(filter.QueueID) {
		return ErrInvalidCommand
	}
	if filter.QueueName != "" && !validQueueName(filter.QueueName) {
		return ErrInvalidCommand
	}
	if filter.State != "" && !validQueueState(filter.State) {
		return ErrInvalidCommand
	}
	if filter.Sender != "" && !canonicalQueueAddress(filter.Sender, true) {
		return ErrInvalidCommand
	}
	if filter.Recipient != "" && !canonicalQueueAddress(filter.Recipient, false) {
		return ErrInvalidCommand
	}
	if filter.ArrivedAfter != nil && !canonicalQueueTime(*filter.ArrivedAfter) || filter.ArrivedBefore != nil && !canonicalQueueTime(*filter.ArrivedBefore) {
		return ErrInvalidCommand
	}
	if filter.ArrivedAfter != nil && filter.ArrivedBefore != nil && !filter.ArrivedAfter.Before(*filter.ArrivedBefore) {
		return ErrInvalidCommand
	}
	if filter.MaximumBytes > queueAdminMaximumMessageBytes || filter.MinimumBytes > filter.MaximumBytes && filter.MaximumBytes != 0 {
		return ErrInvalidCommand
	}
	if search && filter.QueueID == "" && filter.Sender == "" && filter.Recipient == "" {
		return ErrInvalidCommand
	}
	return nil
}

type QueueReadRequest struct {
	RequestID string          `json:"request_id"`
	ActorID   string          `json:"actor_id"`
	Scope     QueueAdminScope `json:"scope"`
	Filter    QueueFilter     `json:"filter,omitempty"`
	Cursor    string          `json:"cursor,omitempty"`
	Limit     uint32          `json:"limit,omitempty"`
}

type QueueMessageRequest struct {
	RequestID             string          `json:"request_id"`
	ActorID               string          `json:"actor_id"`
	Scope                 QueueAdminScope `json:"scope"`
	QueueID               QueueID         `json:"queue_id"`
	ExpectedMessageDigest string          `json:"expected_message_digest,omitempty"`
	ObservedAt            time.Time       `json:"observed_at,omitempty"`
}

type QueueStepUpProof struct {
	ProofID    string    `json:"proof_id"`
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type QueueBodyRequest struct {
	Message      QueueMessageRequest `json:"message"`
	StepUp       QueueStepUpProof     `json:"step_up"`
	MaximumBytes uint32               `json:"maximum_bytes,omitempty"`
}

type QueueActionTarget struct {
	QueueID               QueueID   `json:"queue_id"`
	ExpectedMessageDigest string    `json:"expected_message_digest"`
	ObservedAt            time.Time `json:"observed_at"`
}

type QueueActionRequest struct {
	OperationID string              `json:"operation_id"`
	ActorID     string              `json:"actor_id"`
	Scope       QueueAdminScope     `json:"scope"`
	Action      QueueAdminAction    `json:"action"`
	Targets     []QueueActionTarget `json:"targets"`
}

type QueueFlushRequest struct {
	OperationID string `json:"operation_id"`
	ActorID     string `json:"actor_id"`
	HostID      string `json:"host_id"`
}

type QueueAddressProjection struct {
	Domain     string `json:"domain,omitempty"`
	LocalHash  string `json:"local_hash,omitempty"`
	NullSender bool   `json:"null_sender,omitempty"`
}

type QueueMessageProjection struct {
	QueueID                  QueueID                 `json:"queue_id"`
	QueueName                string                  `json:"queue_name"`
	State                    QueueMessageState       `json:"state"`
	Sender                   QueueAddressProjection  `json:"sender"`
	RecipientCount           uint32                  `json:"recipient_count"`
	RecipientDomains         []string                `json:"recipient_domains,omitempty"`
	RecipientDomainsTruncated bool                   `json:"recipient_domains_truncated,omitempty"`
	Deferred                 bool                    `json:"deferred"`
	MessageBytes             uint64                  `json:"message_bytes"`
	ArrivedAt                time.Time               `json:"arrived_at"`
	MessageDigest            string                  `json:"message_digest"`
	Scope                    QueueAdminScope         `json:"scope"`
	ObservedAt               time.Time               `json:"observed_at"`
}

type QueueRecipientProjection struct {
	Address  QueueAddressProjection `json:"address"`
	Deferred bool                   `json:"deferred"`
}

type QueueHeaderProjection struct {
	Name       string `json:"name"`
	ValueClass string `json:"value_class"`
}

type QueueMessageDetail struct {
	Message             QueueMessageProjection   `json:"message"`
	Recipients          []QueueRecipientProjection `json:"recipients"`
	RecipientsTruncated bool                     `json:"recipients_truncated,omitempty"`
	Headers             []QueueHeaderProjection  `json:"headers"`
	HeaderEvidenceDigest string                  `json:"header_evidence_digest"`
	InspectedAt         time.Time                `json:"inspected_at"`
}

// Content is deliberately excluded from JSON so audit and generic structured
// logging cannot accidentally serialize message bodies.
type QueueBody struct {
	QueueID      QueueID   `json:"queue_id"`
	Content      []byte    `json:"-"`
	ContentBytes uint32    `json:"content_bytes"`
	ContentDigest string   `json:"content_digest"`
	ObservedAt   time.Time `json:"observed_at"`
}

func (body *QueueBody) Wipe() {
	if body == nil {
		return
	}
	for index := range body.Content {
		body.Content[index] = 0
	}
	body.Content = nil
	body.ContentBytes = 0
}

type QueueSummary struct {
	Total          uint32                       `json:"total"`
	TotalBytes     uint64                       `json:"total_bytes"`
	ByState        map[QueueMessageState]uint32 `json:"by_state"`
	OldestArrivedAt *time.Time                  `json:"oldest_arrived_at,omitempty"`
	ScopeDigest    string                       `json:"scope_digest"`
	ObservedAt     time.Time                    `json:"observed_at"`
}

type QueuePage struct {
	Items       []QueueMessageProjection `json:"items"`
	NextCursor  string                   `json:"next_cursor,omitempty"`
	ScopeDigest string                   `json:"scope_digest"`
	ObservedAt  time.Time                `json:"observed_at"`
}

type QueueActionOutcome string

const (
	QueueActionApplied          QueueActionOutcome = "applied"
	QueueActionAlreadySatisfied QueueActionOutcome = "already_satisfied"
	QueueActionNotFound         QueueActionOutcome = "not_found"
	QueueActionAmbiguous        QueueActionOutcome = "ambiguous"
)

type QueueTargetReceipt struct {
	QueueID        QueueID            `json:"queue_id"`
	Outcome        QueueActionOutcome `json:"outcome"`
	EvidenceDigest string             `json:"evidence_digest"`
	ObservedAt     time.Time          `json:"observed_at"`
}

type QueueOperationStatus string

const (
	QueueOperationApplied   QueueOperationStatus = "applied"
	QueueOperationCompleted QueueOperationStatus = "completed"
	QueueOperationAmbiguous QueueOperationStatus = "ambiguous"
)

type QueueActionReceipt struct {
	OperationID  string               `json:"operation_id"`
	RequestDigest string              `json:"request_digest"`
	Action       QueueAdminAction     `json:"action"`
	Scope        QueueAdminScope      `json:"scope,omitempty"`
	HostID       string               `json:"host_id,omitempty"`
	Status       QueueOperationStatus `json:"status"`
	Targets      []QueueTargetReceipt `json:"targets,omitempty"`
	EvidenceDigest string             `json:"evidence_digest"`
	CompletedAt  time.Time            `json:"completed_at"`
}

type queueCursor struct {
	Version      uint8   `json:"version"`
	ArrivedUnix  int64   `json:"arrived_unix"`
	QueueID      QueueID `json:"queue_id"`
	RequestDigest string `json:"request_digest"`
}

func validQueueAdminID(id QueueID) bool {
	if len(id) < 5 || len(id) > 32 {
		return false
	}
	for _, character := range id {
		if !(character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z') {
			return false
		}
	}
	return true
}

func validQueueAdminAction(action QueueAdminAction) bool {
	switch action {
	case QueueAdminRetry, QueueAdminHold, QueueAdminRelease, QueueAdminDelete:
		return true
	default:
		return false
	}
}

func validQueueState(state QueueMessageState) bool {
	switch state {
	case QueueMessageActive, QueueMessageDeferred, QueueMessageHeld, QueueMessagePending:
		return true
	default:
		return false
	}
}

func validQueueName(name string) bool {
	switch name {
	case "active", "deferred", "hold", "incoming", "maildrop":
		return true
	default:
		return false
	}
}

func queueState(name string) QueueMessageState {
	switch name {
	case "active":
		return QueueMessageActive
	case "deferred":
		return QueueMessageDeferred
	case "hold":
		return QueueMessageHeld
	default:
		return QueueMessagePending
	}
}

func canonicalQueueAddress(address Address, allowNull bool) bool {
	if allowNull && address == "<>" {
		return true
	}
	return ValidateAddress(address) == nil && string(address) == strings.ToLower(strings.TrimSpace(string(address)))
}

func canonicalQueueTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func validQueueDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func queueDigest(label string, value any) (string, error) {
	raw, err := json.Marshal(struct {
		Version uint8 `json:"version"`
		Label   string `json:"label"`
		Value   any    `json:"value"`
	}{Version: 1, Label: label, Value: value})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func queueRequestDigest(scope QueueAdminScope, filter QueueFilter, search bool) (string, error) {
	return queueDigest("mail-queue-page-v1", struct {
		Scope  QueueAdminScope `json:"scope"`
		Filter QueueFilter     `json:"filter"`
		Search bool            `json:"search"`
	}{Scope: scope, Filter: filter, Search: search})
}

func encodeQueueCursor(item QueueMessageProjection, requestDigest string) (string, error) {
	if !validQueueAdminID(item.QueueID) || !canonicalQueueTime(item.ArrivedAt) || !validQueueDigest(requestDigest) {
		return "", ErrInvalidCommand
	}
	raw, err := json.Marshal(queueCursor{Version: 1, ArrivedUnix: item.ArrivedAt.Unix(), QueueID: item.QueueID, RequestDigest: requestDigest})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeQueueCursor(encoded, requestDigest string) (queueCursor, error) {
	if encoded == "" {
		return queueCursor{}, nil
	}
	if len(encoded) > queueAdminMaximumCursorBytes || !validQueueDigest(requestDigest) {
		return queueCursor{}, ErrInvalidCommand
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > queueAdminMaximumCursorBytes || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return queueCursor{}, ErrInvalidCommand
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cursor queueCursor
	if err = decoder.Decode(&cursor); err != nil || decoder.Decode(&struct{}{}) != io.EOF || cursor.Version != 1 || !validQueueAdminID(cursor.QueueID) || cursor.ArrivedUnix <= 0 || cursor.RequestDigest != requestDigest {
		return queueCursor{}, ErrInvalidCommand
	}
	canonical, err := json.Marshal(cursor)
	if err != nil || !bytes.Equal(canonical, raw) {
		return queueCursor{}, ErrInvalidCommand
	}
	return cursor, nil
}

func normalizeQueueTargets(targets []QueueActionTarget, now time.Time) ([]QueueActionTarget, error) {
	if len(targets) == 0 || len(targets) > int(QueueAdminMaximumBatch) {
		return nil, ErrInvalidCommand
	}
	result := append([]QueueActionTarget(nil), targets...)
	sort.Slice(result, func(left, right int) bool { return result[left].QueueID < result[right].QueueID })
	for index, target := range result {
		if !validQueueAdminID(target.QueueID) || !validQueueDigest(target.ExpectedMessageDigest) || !canonicalQueueTime(target.ObservedAt) || target.ObservedAt.After(now) || now.Sub(target.ObservedAt) > queueAdminMaximumProofAge {
			return nil, ErrInvalidCommand
		}
		if index > 0 && result[index-1].QueueID == target.QueueID {
			return nil, ErrInvalidCommand
		}
	}
	return result, nil
}

func validateQueueActionReceipt(receipt QueueActionReceipt) error {
	if !validOpaque(receipt.OperationID) || !validQueueDigest(receipt.RequestDigest) || !canonicalQueueTime(receipt.CompletedAt) || !validQueueDigest(receipt.EvidenceDigest) {
		return ErrInvalidReceipt
	}
	if receipt.Action == QueueAdminFlush {
		if !validOpaque(receipt.HostID) || receipt.Scope.TenantID != "" || len(receipt.Targets) != 0 || receipt.Status == QueueOperationCompleted {
			return ErrInvalidReceipt
		}
	} else if !validQueueAdminAction(receipt.Action) || receipt.Scope.Validate() != nil || receipt.HostID != "" || len(receipt.Targets) == 0 || len(receipt.Targets) > int(QueueAdminMaximumBatch) {
		return ErrInvalidReceipt
	}
	switch receipt.Status {
	case QueueOperationApplied, QueueOperationCompleted, QueueOperationAmbiguous:
	default:
		return ErrInvalidReceipt
	}
	hasNotFound := false
	hasAmbiguous := false
	var previous QueueID
	for index, target := range receipt.Targets {
		if !validQueueAdminID(target.QueueID) || !validQueueDigest(target.EvidenceDigest) || !canonicalQueueTime(target.ObservedAt) || target.ObservedAt.After(receipt.CompletedAt) {
			return ErrInvalidReceipt
		}
		switch target.Outcome {
		case QueueActionApplied, QueueActionAlreadySatisfied:
		case QueueActionNotFound:
			hasNotFound = true
		case QueueActionAmbiguous:
			hasAmbiguous = true
		default:
			return ErrInvalidReceipt
		}
		if index > 0 && target.QueueID <= previous {
			return ErrInvalidReceipt
		}
		previous = target.QueueID
	}
	if receipt.Action != QueueAdminFlush {
		evidence, err := queueDigest("mail-queue-action-receipt-v1", receipt.Targets)
		if err != nil || evidence != receipt.EvidenceDigest {
			return ErrInvalidReceipt
		}
	}
	switch receipt.Status {
	case QueueOperationApplied:
		if hasNotFound || hasAmbiguous {
			return ErrInvalidReceipt
		}
	case QueueOperationCompleted:
		if !hasNotFound || hasAmbiguous {
			return ErrInvalidReceipt
		}
	case QueueOperationAmbiguous:
		if receipt.Action != QueueAdminFlush && !hasAmbiguous {
			return ErrInvalidReceipt
		}
	}
	return nil
}

func decodeQueueReceipt(raw []byte) (QueueActionReceipt, error) {
	if len(raw) == 0 || len(raw) > 128<<10 {
		return QueueActionReceipt{}, ErrInvalidReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt QueueActionReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return QueueActionReceipt{}, errors.Join(ErrInvalidReceipt, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return QueueActionReceipt{}, ErrInvalidReceipt
	}
	if err := validateQueueActionReceipt(receipt); err != nil {
		return QueueActionReceipt{}, err
	}
	return receipt, nil
}
