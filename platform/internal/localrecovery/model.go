package localrecovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid          = errors.New("invalid local recovery request")
	ErrUnauthorized     = errors.New("unauthorized local recovery peer")
	ErrRateLimited      = errors.New("local recovery rate limited")
	ErrAuthorityDenied  = errors.New("local recovery authority denied proof")
	ErrAuditUnavailable = errors.New("local recovery audit unavailable")
	ErrConflict         = errors.New("local recovery generation conflict")
	ErrRecoveryFailed   = errors.New("local identity recovery failed")
)

const (
	ProtocolVersion          = uint16(1)
	MaximumFrameBytes        = 16 << 10
	MaximumRequestLifetime   = 2 * time.Minute
	MaximumChallengeLifetime = 2 * time.Minute
)

type Action string
type CredentialReference string
type AuthorityReference string

const (
	ActionStatus                    Action = "status"
	ActionBeginChallenge            Action = "begin_challenge"
	ActionResetOwnerPassword        Action = "reset_owner_password_credential_ref"
	ActionResetOwnerMFA             Action = "reset_owner_mfa"
	ActionRevokeOwnerAccess         Action = "revoke_owner_sessions_api_credentials"
	ActionRotateRecoveryAuthority Action = "rotate_recovery_authority"
)

func (action Action) protected() bool {
	switch action {
	case ActionStatus, ActionResetOwnerPassword, ActionResetOwnerMFA, ActionRevokeOwnerAccess, ActionRotateRecoveryAuthority:
		return true
	default:
		return false
	}
}

func NewCredentialReference(value string) (CredentialReference, error) {
	if !validReference(value) {
		return "", ErrInvalid
	}
	return CredentialReference(value), nil
}

func NewAuthorityReference(value string) (AuthorityReference, error) {
	if !validReference(value) {
		return "", ErrInvalid
	}
	return AuthorityReference(value), nil
}

type HostIdentity struct {
	BootID    string `json:"boot_id"`
	MachineID string `json:"machine_id"`
}

func (identity HostIdentity) Validate() error {
	if !validHostID(identity.BootID, 16, 64) || !validHostID(identity.MachineID, 16, 128) {
		return ErrInvalid
	}
	return nil
}

type ChallengeBinding struct {
	RequestID     string       `json:"request_id"`
	Action        Action       `json:"action"`
	Reason        string       `json:"reason"`
	Host          HostIdentity `json:"host"`
	RequestDigest string       `json:"request_digest"`
	Deadline      time.Time    `json:"deadline"`
}

func (binding ChallengeBinding) Validate(now time.Time) error {
	if !validRequestID(binding.RequestID) || !binding.Action.protected() || !validReason(binding.Reason) || binding.Host.Validate() != nil || !validDigest(binding.RequestDigest) || !validDeadline(binding.Deadline, now) {
		return ErrInvalid
	}
	return nil
}

func (binding ChallengeBinding) Digest() string {
	encoded, err := json.Marshal(binding)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("cyberpanel:local-recovery:binding:v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

type Challenge struct {
	ID            string    `json:"id"`
	Nonce         []byte    `json:"nonce"`
	ExpiresAt     time.Time `json:"expires_at"`
	BindingDigest string    `json:"binding_digest"`
}

func (challenge Challenge) Validate(binding ChallengeBinding, now time.Time) error {
	if !validOpaqueID(challenge.ID, 8, 128) || len(challenge.Nonce) < 24 || len(challenge.Nonce) > 64 || !nonZeroBytes(challenge.Nonce) || challenge.BindingDigest != binding.Digest() || challenge.ExpiresAt.Location() != time.UTC || !challenge.ExpiresAt.After(now) || challenge.ExpiresAt.After(now.Add(MaximumChallengeLifetime)) || challenge.ExpiresAt.After(binding.Deadline) {
		return ErrInvalid
	}
	return nil
}

type Authorization struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       []byte `json:"nonce"`
	Proof       []byte `json:"proof"`
}

func (authorization Authorization) Validate() error {
	if !validOpaqueID(authorization.ChallengeID, 8, 128) || len(authorization.Nonce) < 24 || len(authorization.Nonce) > 64 || !nonZeroBytes(authorization.Nonce) || len(authorization.Proof) < 32 || len(authorization.Proof) > 4096 || !nonZeroBytes(authorization.Proof) {
		return ErrInvalid
	}
	return nil
}

type ProofClaim struct {
	Binding     ChallengeBinding
	ChallengeID string
	Nonce       []byte
	Proof       []byte
}

// RecoveryAuthority owns nonce persistence. VerifyAndConsume must atomically
// make the challenge unusable on its first call, even when proof verification
// fails, and must not retain Proof.
type RecoveryAuthority interface {
	Begin(context.Context, ChallengeBinding) (Challenge, error)
	VerifyAndConsume(context.Context, ProofClaim) error
}

// ProofProvider returns a fresh mutable proof buffer. Client wipes it after
// the single request completes.
type ProofProvider interface {
	Prove(context.Context, ChallengeBinding, Challenge) ([]byte, error)
}

type Request struct {
	Version              uint16            `json:"version"`
	RequestID            string            `json:"request_id"`
	Action               Action            `json:"action"`
	Deadline             time.Time         `json:"deadline"`
	Reason               string            `json:"reason,omitempty"`
	Host                 HostIdentity      `json:"host,omitempty"`
	ExpectedGeneration   uint64            `json:"expected_generation,omitempty"`
	CredentialRef        CredentialReference `json:"credential_ref,omitempty"`
	RecoveryAuthorityRef AuthorityReference  `json:"recovery_authority_ref,omitempty"`
	RequestDigest        string            `json:"request_digest,omitempty"`
	Binding              *ChallengeBinding `json:"binding,omitempty"`
	Authorization        *Authorization    `json:"authorization,omitempty"`
}

func (request Request) Validate(now time.Time) error {
	if request.Version != ProtocolVersion || !validRequestID(request.RequestID) || !validDeadline(request.Deadline, now) {
		return ErrInvalid
	}
	if request.Action == ActionBeginChallenge {
		if request.Binding == nil || request.Binding.Validate(now) != nil || request.Authorization != nil || request.Reason != "" || request.Host != (HostIdentity{}) || request.ExpectedGeneration != 0 || request.CredentialRef != "" || request.RecoveryAuthorityRef != "" || request.RequestDigest != "" || request.Deadline.After(request.Binding.Deadline) {
			return ErrInvalid
		}
		return nil
	}
	if request.validateProtectedIntent(now) != nil || request.Authorization == nil || request.Authorization.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func (request Request) validateProtectedIntent(now time.Time) error {
	if request.Version != ProtocolVersion || !validRequestID(request.RequestID) || !validDeadline(request.Deadline, now) || !request.Action.protected() || request.Binding != nil || !validReason(request.Reason) || request.Host.Validate() != nil || !validDigest(request.RequestDigest) || request.RequestDigest != request.digest() {
		return ErrInvalid
	}
	switch request.Action {
	case ActionStatus:
		if request.ExpectedGeneration != 0 || request.CredentialRef != "" || request.RecoveryAuthorityRef != "" {
			return ErrInvalid
		}
	case ActionResetOwnerPassword:
		if request.ExpectedGeneration == 0 || request.ExpectedGeneration == ^uint64(0) || !validReference(string(request.CredentialRef)) || request.RecoveryAuthorityRef != "" {
			return ErrInvalid
		}
	case ActionResetOwnerMFA, ActionRevokeOwnerAccess:
		if request.ExpectedGeneration == 0 || request.ExpectedGeneration == ^uint64(0) || request.CredentialRef != "" || request.RecoveryAuthorityRef != "" {
			return ErrInvalid
		}
	case ActionRotateRecoveryAuthority:
		if request.ExpectedGeneration == 0 || request.ExpectedGeneration == ^uint64(0) || request.CredentialRef != "" || !validReference(string(request.RecoveryAuthorityRef)) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (request Request) binding() ChallengeBinding {
	return ChallengeBinding{RequestID: request.RequestID, Action: request.Action, Reason: request.Reason, Host: request.Host, RequestDigest: request.RequestDigest, Deadline: request.Deadline}
}

func (request Request) digest() string {
	type intent struct {
		Version              uint16       `json:"version"`
		RequestID            string       `json:"request_id"`
		Action               Action       `json:"action"`
		Deadline             time.Time    `json:"deadline"`
		Reason               string       `json:"reason"`
		Host                 HostIdentity `json:"host"`
		ExpectedGeneration   uint64       `json:"expected_generation"`
		CredentialRef        CredentialReference `json:"credential_ref"`
		RecoveryAuthorityRef AuthorityReference  `json:"recovery_authority_ref"`
	}
	encoded, err := json.Marshal(intent{request.Version, request.RequestID, request.Action, request.Deadline, request.Reason, request.Host, request.ExpectedGeneration, request.CredentialRef, request.RecoveryAuthorityRef})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("cyberpanel:local-recovery:request:v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

// RecoveryContext uses ExpectedGeneration for the owner on owner mutations
// and for the recovery authority on rotation.
type RecoveryContext struct {
	RequestID          string
	Reason             string
	Host               HostIdentity
	RequestDigest      string
	ExpectedGeneration uint64
}

type RecoveryStatus struct {
	OwnerGeneration               uint64    `json:"owner_generation"`
	RecoveryAuthorityGeneration   uint64    `json:"recovery_authority_generation"`
	PasswordCredentialConfigured  bool      `json:"password_credential_configured"`
	MFAConfigured                 bool      `json:"mfa_configured"`
	ActiveSessions                uint32    `json:"active_sessions"`
	ActiveAPICredentials          uint32    `json:"active_api_credentials"`
	ObservedAt                    time.Time `json:"observed_at"`
}

func (status RecoveryStatus) Validate(now time.Time) error {
	if status.OwnerGeneration == 0 || status.RecoveryAuthorityGeneration == 0 || status.ObservedAt.Location() != time.UTC || status.ObservedAt.After(now) || status.ObservedAt.Before(now.Add(-MaximumRequestLifetime)) {
		return ErrInvalid
	}
	return nil
}

type RecoveryReceipt struct {
	RequestID          string    `json:"request_id"`
	Action             Action    `json:"action"`
	RequestDigest      string    `json:"request_digest"`
	PreviousGeneration uint64    `json:"previous_generation"`
	Generation         uint64    `json:"generation"`
	CompletedAt        time.Time `json:"completed_at"`
}

func (receipt RecoveryReceipt) Validate(request Request, now time.Time) error {
	if receipt.RequestID != request.RequestID || receipt.Action != request.Action || receipt.RequestDigest != request.RequestDigest || receipt.PreviousGeneration != request.ExpectedGeneration || receipt.Generation != request.ExpectedGeneration+1 || receipt.CompletedAt.Location() != time.UTC || receipt.CompletedAt.After(now) || receipt.CompletedAt.Before(now.Add(-MaximumRequestLifetime)) {
		return ErrInvalid
	}
	return nil
}

// IdentityRecovery deliberately exposes only owner break-glass operations.
// Implementations must apply ExpectedGeneration as a compare-and-swap.
type IdentityRecovery interface {
	Status(context.Context, RecoveryContext) (RecoveryStatus, error)
	ResetOwnerPasswordCredentialRef(context.Context, RecoveryContext, CredentialReference) (RecoveryReceipt, error)
	ResetOwnerMFA(context.Context, RecoveryContext) (RecoveryReceipt, error)
	RevokeOwnerSessionsAndAPICredentials(context.Context, RecoveryContext) (RecoveryReceipt, error)
	RotateRecoveryAuthority(context.Context, RecoveryContext, AuthorityReference) (RecoveryReceipt, error)
}

type AuditPhase string
type AuditOutcome string

const (
	AuditAttempt AuditPhase = "attempt"
	AuditResult  AuditPhase = "result"

	AuditStarted AuditOutcome = "started"
	AuditApplied AuditOutcome = "applied"
	AuditDenied  AuditOutcome = "denied"
	AuditFailed  AuditOutcome = "failed"
)

type AuditRecord struct {
	ID             string       `json:"id"`
	RequestID      string       `json:"request_id"`
	Action         Action       `json:"action"`
	ChallengeFor   Action       `json:"challenge_for,omitempty"`
	Phase          AuditPhase   `json:"phase"`
	Outcome        AuditOutcome `json:"outcome"`
	Reason         string       `json:"reason"`
	Host           HostIdentity `json:"host"`
	RequestDigest  string       `json:"request_digest"`
	PeerUID        uint32       `json:"peer_uid"`
	Generation     uint64       `json:"generation,omitempty"`
	ErrorCode      string       `json:"error_code,omitempty"`
	OccurredAt     time.Time    `json:"occurred_at"`
}

func (record AuditRecord) Validate() error {
	if !validOpaqueID(record.ID, 16, 160) || !validRequestID(record.RequestID) || (!record.Action.protected() && record.Action != ActionBeginChallenge) || (record.Phase != AuditAttempt && record.Phase != AuditResult) || record.PeerUID != 0 || record.OccurredAt.Location() != time.UTC {
		return ErrInvalid
	}
	if record.Phase == AuditAttempt && (record.Outcome != AuditStarted || record.ErrorCode != "" || record.Generation != 0) {
		return ErrInvalid
	}
	if record.Phase == AuditResult && record.Outcome != AuditApplied && record.Outcome != AuditDenied && record.Outcome != AuditFailed {
		return ErrInvalid
	}
	if record.Phase == AuditResult && (record.Outcome == AuditApplied && record.ErrorCode != "" || record.Outcome != AuditApplied && !ErrorCode(record.ErrorCode).valid()) {
		return ErrInvalid
	}
	if record.Phase == AuditResult && (record.Outcome != AuditApplied && record.Generation != 0 || record.Outcome == AuditApplied && record.Action == ActionBeginChallenge && record.Generation != 0 || record.Outcome == AuditApplied && record.Action != ActionBeginChallenge && record.Generation == 0) {
		return ErrInvalid
	}
	if record.Action == ActionBeginChallenge {
		if !record.ChallengeFor.protected() || !validReason(record.Reason) || record.Host.Validate() != nil || !validDigest(record.RequestDigest) {
			return ErrInvalid
		}
	} else if record.ChallengeFor != "" || !validReason(record.Reason) || record.Host.Validate() != nil || !validDigest(record.RequestDigest) {
		return ErrInvalid
	}
	return nil
}

// AuditSink returns nil only after the record is durably appended.
type AuditSink interface {
	Append(context.Context, AuditRecord) error
}

func validDeadline(deadline, now time.Time) bool {
	return deadline.Location() == time.UTC && deadline.After(now) && !deadline.After(now.Add(MaximumRequestLifetime))
}

func validRequestID(value string) bool {
	return strings.HasPrefix(value, "lrr-") && len(value) == 36 && validLowerHex(value[4:])
}

func validDigest(value string) bool {
	return len(value) == sha256.Size*2 && validLowerHex(value)
}

func validLowerHex(value string) bool {
	for index := range value {
		if value[index] < '0' || value[index] > '9' && value[index] < 'a' || value[index] > 'f' {
			return false
		}
	}
	return value != ""
}

func validHostID(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || strings.ToLower(value) != value {
		return false
	}
	for index := range value {
		if value[index] >= '0' && value[index] <= '9' || value[index] >= 'a' && value[index] <= 'f' || value[index] == '-' {
			continue
		}
		return false
	}
	return true
}

func validReason(value string) bool {
	if len(value) < 8 || len(value) > 512 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validReference(value string) bool {
	if len(value) < 3 || len(value) > 128 || !alphaNumeric(value[0]) || !alphaNumeric(value[len(value)-1]) || strings.Contains(value, "..") {
		return false
	}
	for index := range value {
		character := value[index]
		if alphaNumeric(character) || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func alphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func validOpaqueID(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == ':' || character == '/' {
			continue
		}
		return false
	}
	return true
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func nonZeroBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined != 0
}
