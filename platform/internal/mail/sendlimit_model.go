package mail

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	SendLimitMaximumList       uint32 = 200
	SendLimitMaximumScavenge   uint32 = 500
	SendLimitMaximumRecipients uint32 = 10000
	SendLimitMaximumMessageBytes uint64 = 2 << 30
	SendLimitMaximumRevision uint64 = 1<<63 - 1
	SendLimitDefaultReservationTTL = 10 * time.Minute
	SendLimitMaximumReservationTTL = 30 * time.Minute
)

type SendLimitScopeKind string

const (
	SendLimitTenantScope  SendLimitScopeKind = "tenant"
	SendLimitDomainScope  SendLimitScopeKind = "domain"
	SendLimitMailboxScope SendLimitScopeKind = "mailbox"
)

type SendLimitScope struct {
	TenantID  string             `json:"tenant_id"`
	Kind      SendLimitScopeKind `json:"kind"`
	DomainID  DomainID           `json:"domain_id,omitempty"`
	MailboxID MailboxID          `json:"mailbox_id,omitempty"`
}

func (scope SendLimitScope) Validate() error {
	if !validOpaque(scope.TenantID) {
		return ErrInvalidCommand
	}
	switch scope.Kind {
	case SendLimitTenantScope:
		if scope.DomainID != "" || scope.MailboxID != "" {
			return ErrInvalidCommand
		}
	case SendLimitDomainScope:
		if !validOpaque(string(scope.DomainID)) || scope.MailboxID != "" {
			return ErrInvalidCommand
		}
	case SendLimitMailboxScope:
		if !validOpaque(string(scope.DomainID)) || !validOpaque(string(scope.MailboxID)) {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func (scope SendLimitScope) ID() string {
	switch scope.Kind {
	case SendLimitTenantScope:
		return scope.TenantID
	case SendLimitDomainScope:
		return string(scope.DomainID)
	case SendLimitMailboxScope:
		return string(scope.MailboxID)
	default:
		return ""
	}
}

type SendLimitAmount struct {
	Messages   uint64 `json:"messages"`
	Recipients uint64 `json:"recipients"`
	Bytes      uint64 `json:"bytes"`
}

func (amount SendLimitAmount) Add(other SendLimitAmount) (SendLimitAmount, error) {
	result := SendLimitAmount{Messages: amount.Messages + other.Messages, Recipients: amount.Recipients + other.Recipients, Bytes: amount.Bytes + other.Bytes}
	if result.Messages < amount.Messages || result.Recipients < amount.Recipients || result.Bytes < amount.Bytes || !validSendLimitAmount(result) {
		return SendLimitAmount{}, ErrInvalidReceipt
	}
	return result, nil
}

func (amount SendLimitAmount) Empty() bool {
	return amount.Messages == 0 && amount.Recipients == 0 && amount.Bytes == 0
}

type SendLimitDependencyMode string

const (
	SendLimitFailClosed         SendLimitDependencyMode = "fail_closed"
	SendLimitEmergencyAllowance SendLimitDependencyMode = "emergency_allowance"
)

type SendLimitDependencyBehavior struct {
	Mode             SendLimitDependencyMode `json:"mode"`
	EmergencyHourly  SendLimitAmount         `json:"emergency_hourly,omitempty"`
	EmergencyMonthly SendLimitAmount         `json:"emergency_monthly,omitempty"`
}

type SendLimitWarningThresholds struct {
	HourlyBasisPoints  uint16 `json:"hourly_basis_points"`
	MonthlyBasisPoints uint16 `json:"monthly_basis_points"`
}

type SendLimitPolicy struct {
	Scope       SendLimitScope              `json:"scope"`
	Revision    uint64                      `json:"revision"`
	Enabled     bool                        `json:"enabled"`
	Hourly      SendLimitAmount             `json:"hourly"`
	Monthly     SendLimitAmount             `json:"monthly"`
	Warnings    SendLimitWarningThresholds  `json:"warnings"`
	Dependency SendLimitDependencyBehavior  `json:"dependency"`
	EffectiveAt time.Time                   `json:"effective_at"`
	CreatedAt   time.Time                   `json:"created_at"`
}

func (policy SendLimitPolicy) Validate() error {
	if policy.Scope.Validate() != nil || policy.Revision == 0 || policy.Revision > SendLimitMaximumRevision || !sendLimitCanonicalTime(policy.EffectiveAt) || !sendLimitCanonicalTime(policy.CreatedAt) || policy.EffectiveAt.Before(policy.CreatedAt) {
		return ErrInvalidCommand
	}
	if !validSendLimitAmount(policy.Hourly) || !validSendLimitAmount(policy.Monthly) || policy.Enabled && (policy.Hourly.Empty() || policy.Monthly.Empty()) {
		return ErrInvalidCommand
	}
	if policy.Warnings.HourlyBasisPoints == 0 || policy.Warnings.HourlyBasisPoints > 10000 || policy.Warnings.MonthlyBasisPoints == 0 || policy.Warnings.MonthlyBasisPoints > 10000 {
		return ErrInvalidCommand
	}
	switch policy.Dependency.Mode {
	case SendLimitFailClosed:
		if !policy.Dependency.EmergencyHourly.Empty() || !policy.Dependency.EmergencyMonthly.Empty() {
			return ErrInvalidCommand
		}
	case SendLimitEmergencyAllowance:
		if policy.Dependency.EmergencyHourly.Empty() || policy.Dependency.EmergencyMonthly.Empty() || !validEmergencyAmount(policy.Dependency.EmergencyHourly, true) || !validEmergencyAmount(policy.Dependency.EmergencyMonthly, false) || !sendLimitWithin(policy.Dependency.EmergencyHourly, policy.Hourly) || !sendLimitWithin(policy.Dependency.EmergencyMonthly, policy.Monthly) {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}

func (policy SendLimitPolicy) Digest() (string, error) {
	if err := policy.Validate(); err != nil {
		return "", err
	}
	return sendLimitDigest("mail-send-limit-policy-v1", policy)
}

type SendLimitIdentity struct {
	TenantID          string    `json:"tenant_id"`
	DomainID          DomainID  `json:"domain_id"`
	MailboxID         MailboxID `json:"mailbox_id"`
	MailboxAddress    Address   `json:"mailbox_address"`
	DirectoryGeneration uint64  `json:"directory_generation"`
	DomainGeneration  uint64    `json:"domain_generation"`
	MailboxGeneration uint64    `json:"mailbox_generation"`
	DependenciesAvailable bool  `json:"dependencies_available"`
}

func (identity SendLimitIdentity) Validate() error {
	if !validOpaque(identity.TenantID) || !validOpaque(string(identity.DomainID)) || !validOpaque(string(identity.MailboxID)) || identity.DirectoryGeneration == 0 || identity.DomainGeneration == 0 || identity.MailboxGeneration == 0 || !sendLimitCanonicalAddress(identity.MailboxAddress) {
		return ErrInvalidCommand
	}
	return nil
}

func (identity SendLimitIdentity) Scopes() []SendLimitScope {
	return []SendLimitScope{
		{TenantID: identity.TenantID, Kind: SendLimitTenantScope},
		{TenantID: identity.TenantID, Kind: SendLimitDomainScope, DomainID: identity.DomainID},
		{TenantID: identity.TenantID, Kind: SendLimitMailboxScope, DomainID: identity.DomainID, MailboxID: identity.MailboxID},
	}
}

type SendLimitReservationRequest struct {
	MessageKey     string            `json:"message_key"`
	EffectKey      string            `json:"effect_key"`
	Identity       SendLimitIdentity `json:"identity"`
	Recipients     uint32            `json:"recipients"`
	MessageBytes   uint64            `json:"message_bytes"`
	At             time.Time         `json:"at"`
	ReservationTTL time.Duration     `json:"reservation_ttl"`
}

func (request SendLimitReservationRequest) Validate() error {
	if !validSendLimitKey(request.MessageKey, "slmsg_") || !validSendLimitKey(request.EffectKey, "sleff_") || request.Identity.Validate() != nil || request.Recipients == 0 || request.Recipients > SendLimitMaximumRecipients || request.MessageBytes == 0 || request.MessageBytes > SendLimitMaximumMessageBytes || !sendLimitCanonicalTime(request.At) || request.ReservationTTL < time.Minute || request.ReservationTTL > SendLimitMaximumReservationTTL {
		return ErrInvalidCommand
	}
	return nil
}

func (request SendLimitReservationRequest) Amount() SendLimitAmount {
	return SendLimitAmount{Messages: 1, Recipients: uint64(request.Recipients), Bytes: request.MessageBytes}
}

type SendLimitDecision string

const (
	SendLimitPermit SendLimitDecision = "permit"
	SendLimitDefer  SendLimitDecision = "defer"
	SendLimitReject SendLimitDecision = "reject"
)

type SendLimitDecisionCode string

const (
	SendLimitCodePermit                  SendLimitDecisionCode = "permit"
	SendLimitCodePermitWarning           SendLimitDecisionCode = "permit_warning"
	SendLimitCodePermitEmergency         SendLimitDecisionCode = "permit_emergency"
	SendLimitCodePermitEmergencyWarning  SendLimitDecisionCode = "permit_emergency_warning"
	SendLimitCodeDependencyUnavailable   SendLimitDecisionCode = "dependency_unavailable"
	SendLimitCodePolicyUnavailable       SendLimitDecisionCode = "policy_unavailable"
	SendLimitCodeIdentityUnresolved      SendLimitDecisionCode = "identity_unresolved"
)

type SendLimitWindowKind string

const (
	SendLimitHour  SendLimitWindowKind = "utc_hour"
	SendLimitMonth SendLimitWindowKind = "utc_calendar_month"
)

type SendLimitUsageProjection struct {
	Scope      SendLimitScope      `json:"scope"`
	Window     SendLimitWindowKind `json:"window"`
	BucketStart time.Time          `json:"bucket_start"`
	ResetsAt   time.Time           `json:"resets_at"`
	Limit      SendLimitAmount     `json:"limit"`
	Reserved   SendLimitAmount     `json:"reserved"`
	Committed  SendLimitAmount     `json:"committed"`
	Projected  SendLimitAmount     `json:"projected"`
	Warning    bool                `json:"warning"`
}

type SendLimitPolicyBinding struct {
	Scope    SendLimitScope `json:"scope"`
	Revision uint64         `json:"revision"`
	Digest   string         `json:"digest"`
}

type SendLimitDecisionReceipt struct {
	MessageKey       string                   `json:"message_key"`
	EffectKey        string                   `json:"effect_key"`
	RequestDigest    string                   `json:"request_digest"`
	ReservationID   string                   `json:"reservation_id,omitempty"`
	Decision        SendLimitDecision        `json:"decision"`
	Code            SendLimitDecisionCode    `json:"code"`
	Emergency       bool                     `json:"emergency"`
	Policies        []SendLimitPolicyBinding `json:"policies"`
	Usage           []SendLimitUsageProjection `json:"usage"`
	ReservedAt      time.Time                `json:"reserved_at"`
	ExpiresAt       *time.Time               `json:"expires_at,omitempty"`
	ReceiptDigest   string                   `json:"receipt_digest"`
}

func (receipt SendLimitDecisionReceipt) Validate() error {
	if !validSendLimitKey(receipt.MessageKey, "slmsg_") || !validSendLimitKey(receipt.EffectKey, "sleff_") || !validSendLimitDigest(receipt.RequestDigest) || !sendLimitCanonicalTime(receipt.ReservedAt) || len(receipt.Policies) > 3 || len(receipt.Usage) > 6 || !validSendLimitDecisionCode(receipt.Decision, receipt.Code) {
		return ErrInvalidReceipt
	}
	if len(receipt.Policies) == 0 && receipt.Code != SendLimitCodePolicyUnavailable {
		return ErrInvalidReceipt
	}
	if receipt.Emergency && receipt.Code == SendLimitCodeDependencyUnavailable || !receipt.Emergency && (receipt.Code == SendLimitCodePermitEmergency || receipt.Code == SendLimitCodePermitEmergencyWarning) {
		return ErrInvalidReceipt
	}
	if receipt.Decision == SendLimitPermit {
		if !validSendLimitKey(receipt.ReservationID, "slres_") || receipt.ExpiresAt == nil || !sendLimitCanonicalTime(*receipt.ExpiresAt) || !receipt.ExpiresAt.After(receipt.ReservedAt) {
			return ErrInvalidReceipt
		}
	} else if receipt.ReservationID != "" || receipt.ExpiresAt != nil {
		return ErrInvalidReceipt
	}
	for _, binding := range receipt.Policies {
		if binding.Scope.Validate() != nil || binding.Revision == 0 || !validSendLimitDigest(binding.Digest) {
			return ErrInvalidReceipt
		}
	}
	for _, usage := range receipt.Usage {
		if usage.Scope.Validate() != nil || usage.Window != SendLimitHour && usage.Window != SendLimitMonth || !sendLimitCanonicalTime(usage.BucketStart) || !sendLimitCanonicalTime(usage.ResetsAt) || !usage.ResetsAt.After(usage.BucketStart) || !validSendLimitAmount(usage.Limit) || !validSendLimitAmount(usage.Reserved) || !validSendLimitAmount(usage.Committed) || !validSendLimitAmount(usage.Projected) {
			return ErrInvalidReceipt
		}
	}
	if !validSendLimitDigest(receipt.ReceiptDigest) {
		return ErrInvalidReceipt
	}
	copyReceipt := receipt
	copyReceipt.ReceiptDigest = ""
	digest, err := sendLimitDigest("mail-send-limit-decision-v1", copyReceipt)
	if err != nil || digest != receipt.ReceiptDigest {
		return ErrInvalidReceipt
	}
	return nil
}

type SendLimitReservationState string

const (
	SendLimitReserved  SendLimitReservationState = "reserved"
	SendLimitCommitted SendLimitReservationState = "committed"
	SendLimitReleased  SendLimitReservationState = "released"
	SendLimitExpired   SendLimitReservationState = "expired"
)

type SendLimitFinalizeRequest struct {
	ReservationID string    `json:"reservation_id"`
	MessageKey    string    `json:"message_key"`
	EffectKey     string    `json:"effect_key"`
	ReceiptDigest string    `json:"receipt_digest"`
	At            time.Time `json:"at"`
}

type SendLimitLifecycleReceipt struct {
	ReservationID string                    `json:"reservation_id"`
	State         SendLimitReservationState `json:"state"`
	DecisionDigest string                   `json:"decision_digest"`
	OccurredAt    time.Time                 `json:"occurred_at"`
	ReceiptDigest string                    `json:"receipt_digest"`
}

func (receipt SendLimitLifecycleReceipt) Validate() error {
	if !validSendLimitKey(receipt.ReservationID, "slres_") || !validSendLimitDigest(receipt.DecisionDigest) || !sendLimitCanonicalTime(receipt.OccurredAt) || !validSendLimitDigest(receipt.ReceiptDigest) {
		return ErrInvalidReceipt
	}
	switch receipt.State {
	case SendLimitCommitted, SendLimitReleased, SendLimitExpired:
	default:
		return ErrInvalidReceipt
	}
	copyReceipt := receipt
	copyReceipt.ReceiptDigest = ""
	digest, err := sendLimitDigest("mail-send-limit-lifecycle-v1", copyReceipt)
	if err != nil || digest != receipt.ReceiptDigest {
		return ErrInvalidReceipt
	}
	return nil
}

func sendLimitHourBounds(at time.Time) (time.Time, time.Time) {
	start := at.UTC().Truncate(time.Hour)
	return start, start.Add(time.Hour)
}

func sendLimitMonthBounds(at time.Time) (time.Time, time.Time) {
	at = at.UTC()
	start := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
}

func sendLimitExceededCode(scope SendLimitScopeKind, window SendLimitWindowKind, dimension string) SendLimitDecisionCode {
	return SendLimitDecisionCode(string(scope) + "_" + string(window) + "_" + dimension + "_limit")
}

func validSendLimitDecisionCode(decision SendLimitDecision, code SendLimitDecisionCode) bool {
	switch decision {
	case SendLimitPermit:
		return code == SendLimitCodePermit || code == SendLimitCodePermitWarning || code == SendLimitCodePermitEmergency || code == SendLimitCodePermitEmergencyWarning
	case SendLimitDefer:
		if code == SendLimitCodeDependencyUnavailable || code == SendLimitCodePolicyUnavailable || code == SendLimitCodeIdentityUnresolved {
			return true
		}
		parts := strings.Split(string(code), "_")
		if len(parts) < 5 || parts[len(parts)-1] != "limit" {
			return false
		}
		for _, scope := range []SendLimitScopeKind{SendLimitTenantScope, SendLimitDomainScope, SendLimitMailboxScope} {
			for _, window := range []SendLimitWindowKind{SendLimitHour, SendLimitMonth} {
				for _, dimension := range []string{"messages", "recipients", "bytes"} {
					if code == sendLimitExceededCode(scope, window, dimension) {
						return true
					}
				}
			}
		}
		return false
	case SendLimitReject:
		return code == SendLimitCodeIdentityUnresolved
	default:
		return false
	}
}

func sendLimitDigest(label string, value any) (string, error) {
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

func validSendLimitDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validSendLimitKey(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && len(value) >= len(prefix)+32 && len(value) <= 96 && validOpaque(value)
}

func sendLimitCanonicalAddress(address Address) bool {
	return ValidateAddress(address) == nil && string(address) == strings.ToLower(strings.TrimSpace(string(address)))
}

func sendLimitCanonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func validSendLimitAmount(amount SendLimitAmount) bool {
	return amount.Messages <= 1_000_000_000 && amount.Recipients <= 10_000_000_000 && amount.Bytes <= 1<<60
}

func validEmergencyAmount(amount SendLimitAmount, hourly bool) bool {
	if !validSendLimitAmount(amount) {
		return false
	}
	if hourly {
		return amount.Messages <= 100 && amount.Recipients <= 10_000 && amount.Bytes <= 1<<30
	}
	return amount.Messages <= 1000 && amount.Recipients <= 100_000 && amount.Bytes <= 10<<30
}

func sendLimitWithin(value, ceiling SendLimitAmount) bool {
	return (ceiling.Messages == 0 || value.Messages <= ceiling.Messages) && (ceiling.Recipients == 0 || value.Recipients <= ceiling.Recipients) && (ceiling.Bytes == 0 || value.Bytes <= ceiling.Bytes)
}

func encodeSendLimitPolicy(policy SendLimitPolicy) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(policy)
	if err != nil || len(raw) == 0 || len(raw) > 32<<10 {
		return nil, errors.Join(ErrInvalidCommand, err)
	}
	return raw, nil
}

func decodeSendLimitPolicy(raw []byte) (SendLimitPolicy, error) {
	if len(raw) == 0 || len(raw) > 32<<10 {
		return SendLimitPolicy{}, ErrInvalidReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy SendLimitPolicy
	if err := decoder.Decode(&policy); err != nil || decoder.Decode(&struct{}{}) != io.EOF || policy.Validate() != nil {
		return SendLimitPolicy{}, ErrInvalidReceipt
	}
	return policy, nil
}
