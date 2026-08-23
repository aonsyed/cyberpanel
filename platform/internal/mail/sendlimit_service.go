package mail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type SendLimitAdminAction string

const (
	SendLimitPolicyMutate SendLimitAdminAction = "send_limit.policy.mutate"
	SendLimitPolicyExport SendLimitAdminAction = "send_limit.policy.export"
)

type SendLimitStepUpProof struct {
	ProofID    string    `json:"proof_id"`
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type SendLimitAuthorizationRequest struct {
	ActorID string
	Action  SendLimitAdminAction
	Scope   SendLimitScope
	StepUp  SendLimitStepUpProof
}

type SendLimitAuthorizer interface {
	AuthorizeSendLimit(context.Context, SendLimitAuthorizationRequest) error
}

type SendLimitAuditEvent struct {
	RequestID          string
	ActorID            string
	Action             SendLimitAdminAction
	Scope              SendLimitScope
	ExpectedRevision   uint64
	ResultingRevision  uint64
	RequestDigest      string
	OccurredAt         time.Time
}

// Audit events contain only stable identifiers and a request digest; policy
// exports and runtime submission metadata are never copied into the event.
type SendLimitAuditSink interface {
	RecordSendLimitAdmin(context.Context, SendLimitAuditEvent) error
}

type SendLimitAdminService struct {
	Repository SendLimitRepository
	Authorizer SendLimitAuthorizer
	Audit      SendLimitAuditSink
	Now        func() time.Time
}

func NewSendLimitAdminService(repository SendLimitRepository, authorizer SendLimitAuthorizer, audit SendLimitAuditSink, now func() time.Time) (*SendLimitAdminService, error) {
	if repository == nil || authorizer == nil || audit == nil {
		return nil, ErrInvalidCommand
	}
	if now == nil {
		now = time.Now
	}
	return &SendLimitAdminService{Repository: repository, Authorizer: authorizer, Audit: audit, Now: now}, nil
}

type SendLimitPolicyMutationRequest struct {
	RequestID        string
	ActorID          string
	ExpectedRevision uint64
	Policy           SendLimitPolicy
	StepUp           SendLimitStepUpProof
}

func (service *SendLimitAdminService) PutPolicy(ctx context.Context, request SendLimitPolicyMutationRequest) (SendLimitPolicy, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(request.RequestID) || !validOpaque(request.ActorID) || request.Policy.Scope.Validate() != nil || request.Policy.Revision != request.ExpectedRevision+1 {
		if err != nil {
			return SendLimitPolicy{}, err
		}
		return SendLimitPolicy{}, ErrInvalidCommand
	}
	now := service.now()
	if !validSendLimitStepUp(request.StepUp, now) {
		return SendLimitPolicy{}, ErrInvalidCommand
	}
	policy := request.Policy
	policy.CreatedAt = now
	if policy.EffectiveAt.IsZero() {
		policy.EffectiveAt = now
	}
	if err := policy.Validate(); err != nil {
		return SendLimitPolicy{}, err
	}
	digestInput := struct {
		Expected uint64          `json:"expected_revision"`
		Policy   SendLimitPolicy `json:"policy"`
	}{Expected: request.ExpectedRevision, Policy: policy}
	requestDigest, err := sendLimitDigest("mail-send-limit-policy-mutation-v1", digestInput)
	if err != nil {
		return SendLimitPolicy{}, err
	}
	if err = service.authorize(ctx, request.ActorID, SendLimitPolicyMutate, policy.Scope, request.StepUp); err != nil {
		return SendLimitPolicy{}, err
	}
	if err = service.audit(ctx, request.RequestID, request.ActorID, SendLimitPolicyMutate, policy.Scope, request.ExpectedRevision, policy.Revision, requestDigest); err != nil {
		return SendLimitPolicy{}, err
	}
	return service.Repository.PutPolicy(ctx, policy, request.ExpectedRevision)
}

type SendLimitExportRequest struct {
	RequestID    string
	ActorID      string
	TenantID     string
	AfterKind    SendLimitScopeKind
	AfterDomain  DomainID
	AfterMailbox MailboxID
	Limit        uint32
	At           time.Time
	StepUp       SendLimitStepUpProof
}

type SendLimitExport struct {
	Policies    []SendLimitPolicy          `json:"policies"`
	Usage       []SendLimitUsageProjection `json:"usage"`
	GeneratedAt time.Time                  `json:"generated_at"`
}

func (service *SendLimitAdminService) Export(ctx context.Context, request SendLimitExportRequest) (SendLimitExport, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(request.RequestID) || !validOpaque(request.ActorID) || !validOpaque(request.TenantID) || request.Limit == 0 || request.Limit > SendLimitMaximumList || !validSendLimitAfter(request.AfterKind, request.AfterDomain, request.AfterMailbox) {
		if err != nil {
			return SendLimitExport{}, err
		}
		return SendLimitExport{}, ErrInvalidCommand
	}
	now := service.now()
	if request.At.IsZero() {
		request.At = now
	}
	if !sendLimitCanonicalTime(request.At) || request.At.After(now.Add(time.Minute)) || !validSendLimitStepUp(request.StepUp, now) {
		return SendLimitExport{}, ErrInvalidCommand
	}
	scope := SendLimitScope{TenantID: request.TenantID, Kind: SendLimitTenantScope}
	digestInput := struct {
		Tenant       string             `json:"tenant"`
		AfterKind    SendLimitScopeKind `json:"after_kind"`
		AfterDomain  DomainID           `json:"after_domain"`
		AfterMailbox MailboxID          `json:"after_mailbox"`
		Limit        uint32             `json:"limit"`
		At           time.Time          `json:"at"`
	}{Tenant: request.TenantID, AfterKind: request.AfterKind, AfterDomain: request.AfterDomain, AfterMailbox: request.AfterMailbox, Limit: request.Limit, At: request.At}
	requestDigest, err := sendLimitDigest("mail-send-limit-export-v1", digestInput)
	if err != nil {
		return SendLimitExport{}, err
	}
	if err = service.authorize(ctx, request.ActorID, SendLimitPolicyExport, scope, request.StepUp); err != nil {
		return SendLimitExport{}, err
	}
	if err = service.audit(ctx, request.RequestID, request.ActorID, SendLimitPolicyExport, scope, 0, 0, requestDigest); err != nil {
		return SendLimitExport{}, err
	}
	policies, err := service.Repository.ListPolicies(ctx, request.TenantID, request.AfterKind, request.AfterDomain, request.AfterMailbox, request.Limit)
	if err != nil {
		return SendLimitExport{}, err
	}
	usage, err := service.Repository.Usage(ctx, request.TenantID, request.At, request.Limit)
	if err != nil {
		return SendLimitExport{}, err
	}
	return SendLimitExport{Policies: policies, Usage: usage, GeneratedAt: now}, nil
}

func (service *SendLimitAdminService) authorize(ctx context.Context, actor string, action SendLimitAdminAction, scope SendLimitScope, proof SendLimitStepUpProof) error {
	if err := service.Authorizer.AuthorizeSendLimit(ctx, SendLimitAuthorizationRequest{ActorID: actor, Action: action, Scope: scope, StepUp: proof}); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

func (service *SendLimitAdminService) audit(ctx context.Context, requestID, actor string, action SendLimitAdminAction, scope SendLimitScope, expected, resulting uint64, requestDigest string) error {
	event := SendLimitAuditEvent{RequestID: requestID, ActorID: actor, Action: action, Scope: scope, ExpectedRevision: expected, ResultingRevision: resulting, RequestDigest: requestDigest, OccurredAt: service.now()}
	if !validOpaque(event.RequestID) || !validOpaque(event.ActorID) || event.Scope.Validate() != nil || !validSendLimitDigest(event.RequestDigest) || !sendLimitCanonicalTime(event.OccurredAt) || action == SendLimitPolicyMutate && resulting != expected+1 || action == SendLimitPolicyExport && (expected != 0 || resulting != 0) {
		return ErrInvalidCommand
	}
	return service.Audit.RecordSendLimitAdmin(ctx, event)
}

func (service *SendLimitAdminService) ready(ctx context.Context) error {
	if service == nil || ctx == nil || service.Repository == nil || service.Authorizer == nil || service.Audit == nil || service.Now == nil {
		return ErrInvalidCommand
	}
	return nil
}

func (service *SendLimitAdminService) now() time.Time {
	return service.Now().UTC().Truncate(time.Second)
}

func validSendLimitStepUp(proof SendLimitStepUpProof, now time.Time) bool {
	return validOpaque(proof.ProofID) && sendLimitCanonicalTime(proof.VerifiedAt) && sendLimitCanonicalTime(proof.ExpiresAt) && !proof.VerifiedAt.After(now) && proof.ExpiresAt.After(now) && proof.ExpiresAt.After(proof.VerifiedAt) && proof.ExpiresAt.Sub(proof.VerifiedAt) <= 15*time.Minute
}

// LocalSendLimitDirectory must use only the host's canonical mail registry. It
// must not perform network or remote-control-plane calls on the SMTP path.
type LocalSendLimitDirectory interface {
	ResolveLocalSendLimitIdentity(context.Context, Address, Address) (SendLimitIdentity, error)
}

type SendLimitRuntime struct {
	Repository SendLimitRepository
	Directory  LocalSendLimitDirectory
	Now        func() time.Time
	ReservationTTL time.Duration
}

func NewSendLimitRuntime(repository SendLimitRepository, directory LocalSendLimitDirectory, now func() time.Time) (*SendLimitRuntime, error) {
	if repository == nil || directory == nil {
		return nil, ErrInvalidCommand
	}
	if now == nil {
		now = time.Now
	}
	return &SendLimitRuntime{Repository: repository, Directory: directory, Now: now, ReservationTTL: SendLimitDefaultReservationTTL}, nil
}

type SendLimitRuntimeRequest struct {
	MessageKey   string
	EffectKey    string
	SASLUsername Address
	Sender       Address
	Recipients   uint32
	MessageBytes uint64
}

func (runtime *SendLimitRuntime) Decide(ctx context.Context, request SendLimitRuntimeRequest) (SendLimitDecisionReceipt, error) {
	if runtime == nil || ctx == nil || runtime.Repository == nil || runtime.Directory == nil || runtime.Now == nil || !validSendLimitKey(request.MessageKey, "slmsg_") || !validSendLimitKey(request.EffectKey, "sleff_") || request.Recipients == 0 || request.Recipients > SendLimitMaximumRecipients || request.MessageBytes == 0 || request.MessageBytes > SendLimitMaximumMessageBytes {
		return SendLimitDecisionReceipt{}, ErrInvalidCommand
	}
	sasl := Address(strings.ToLower(strings.TrimSpace(string(request.SASLUsername))))
	sender := Address(strings.ToLower(strings.TrimSpace(string(request.Sender))))
	if !sendLimitCanonicalAddress(sasl) || !sendLimitCanonicalAddress(sender) {
		return SendLimitDecisionReceipt{}, ErrInvalidCommand
	}
	identity, err := runtime.Directory.ResolveLocalSendLimitIdentity(ctx, sasl, sender)
	if err != nil {
		return SendLimitDecisionReceipt{}, err
	}
	if err = identity.Validate(); err != nil || identity.MailboxAddress != sasl || identity.MailboxAddress != sender {
		return SendLimitDecisionReceipt{}, errors.Join(ErrUnauthorized, err)
	}
	ttl := runtime.ReservationTTL
	if ttl == 0 {
		ttl = SendLimitDefaultReservationTTL
	}
	at := runtime.Now().UTC().Truncate(time.Second)
	reservation := SendLimitReservationRequest{MessageKey: request.MessageKey, EffectKey: request.EffectKey, Identity: identity, Recipients: request.Recipients, MessageBytes: request.MessageBytes, At: at, ReservationTTL: ttl}
	if err = reservation.Validate(); err != nil {
		return SendLimitDecisionReceipt{}, err
	}
	return runtime.Repository.Reserve(ctx, reservation)
}

func (runtime *SendLimitRuntime) Commit(ctx context.Context, request SendLimitFinalizeRequest) (SendLimitLifecycleReceipt, error) {
	if runtime == nil || runtime.Repository == nil || runtime.Now == nil || ctx == nil {
		return SendLimitLifecycleReceipt{}, ErrInvalidCommand
	}
	if request.At.IsZero() {
		request.At = runtime.Now().UTC().Truncate(time.Second)
	}
	return runtime.Repository.Commit(ctx, request)
}

func (runtime *SendLimitRuntime) Release(ctx context.Context, request SendLimitFinalizeRequest) (SendLimitLifecycleReceipt, error) {
	if runtime == nil || runtime.Repository == nil || runtime.Now == nil || ctx == nil {
		return SendLimitLifecycleReceipt{}, ErrInvalidCommand
	}
	if request.At.IsZero() {
		request.At = runtime.Now().UTC().Truncate(time.Second)
	}
	return runtime.Repository.Release(ctx, request)
}

func (runtime *SendLimitRuntime) Scavenge(ctx context.Context, limit uint32) (uint32, error) {
	if runtime == nil || runtime.Repository == nil || runtime.Now == nil || ctx == nil {
		return 0, ErrInvalidCommand
	}
	return runtime.Repository.Scavenge(ctx, runtime.Now().UTC().Truncate(time.Second), limit)
}
