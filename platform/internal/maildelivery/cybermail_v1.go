package maildelivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	CyberMailAdapterKind              = "cybermail"
	CyberMailAdapterVersionV1         = "cybermail-cp-v1"
	CyberMailAPIBaseURL               = "https://platform.cyberpersons.com/email/cp/"
	CyberMailSMTPHost                 = "mail.cyberpersons.com"
	CyberMailSMTPPort          uint16 = 587
	CyberMailMaximumRequestBytes      = 64 << 10
	CyberMailMaximumResponseBytes     = 1 << 20
)

var (
	ErrUnsupported = errors.New("maildelivery: provider operation unsupported")
	ErrIntegrity   = errors.New("maildelivery: provider response failed integrity checks")
	ErrRateLimited = errors.New("maildelivery: provider rate limited")
	ErrPartial     = errors.New("maildelivery: provider operation partially applied")
)

var cyberMailReferenceV1 = ProviderAdapterRef{
	Kind:            CyberMailAdapterKind,
	ContractVersion: AdapterContractVersion,
	AdapterVersion:  CyberMailAdapterVersionV1,
}

func CyberMailProviderReferenceV1() ProviderAdapterRef {
	return cyberMailReferenceV1
}

type ProviderCircuitHint string

const (
	CircuitHintNone      ProviderCircuitHint = "none"
	CircuitHintFailure   ProviderCircuitHint = "record_failure"
	CircuitHintThrottle  ProviderCircuitHint = "rate_limited"
	CircuitHintReconcile ProviderCircuitHint = "reconcile"
)

// ProviderOperationError exposes only normalized, content-free provider data.
// In particular, it never includes provider response text, credentials, or mail.
type ProviderOperationError struct {
	provider     string
	operation    string
	code         string
	cause        error
	hint         ProviderCircuitHint
	retryAfter   time.Duration
	mayHaveWrite bool
}

func (failure *ProviderOperationError) Error() string {
	if failure == nil {
		return "maildelivery: provider operation failed"
	}
	return fmt.Sprintf("maildelivery: %s %s failed (%s)", failure.provider, failure.operation, failure.code)
}

func (failure *ProviderOperationError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (failure *ProviderOperationError) Provider() string {
	if failure == nil {
		return ""
	}
	return failure.provider
}

func (failure *ProviderOperationError) Operation() string {
	if failure == nil {
		return ""
	}
	return failure.operation
}

func (failure *ProviderOperationError) Code() string {
	if failure == nil {
		return ""
	}
	return failure.code
}

func (failure *ProviderOperationError) MayHaveSubmitted() bool {
	return failure != nil && failure.mayHaveWrite
}

func (failure *ProviderOperationError) CircuitHint() ProviderCircuitHint {
	if failure == nil {
		return CircuitHintNone
	}
	return failure.hint
}

func (failure *ProviderOperationError) RetryAfter() time.Duration {
	if failure == nil {
		return 0
	}
	return failure.retryAfter
}

func cyberMailFailure(operation, code string, cause error, hint ProviderCircuitHint, retryAfter time.Duration, mayHaveWrite bool) error {
	return &ProviderOperationError{provider: CyberMailAdapterKind, operation: operation, code: code, cause: cause,
		hint: hint, retryAfter: retryAfter, mayHaveWrite: mayHaveWrite}
}

type CyberMailCredential struct {
	TenantID          TenantID
	BindingID         BindingID
	CredentialVersion uint64
	AccountEmail      string
	APIKey            []byte `json:"-"`
	SMTPCredentialID  string
	SMTPUsername      string
	Cleanup           func() `json:"-"`
}

func (credential CyberMailCredential) validate(binding ProviderBinding, version uint64) error {
	if credential.TenantID != binding.TenantID || credential.BindingID != binding.ID || credential.CredentialVersion != version ||
		version == 0 || credential.Cleanup == nil || !validMailbox(credential.AccountEmail) || len(credential.APIKey) == 0 ||
		len(credential.APIKey) > 4096 ||
		len(credential.SMTPCredentialID) > 256 || strings.ContainsAny(credential.SMTPCredentialID, "\x00\r\n") ||
		len(credential.SMTPUsername) > 512 || strings.ContainsAny(credential.SMTPUsername, "\x00\r\n") {
		return ErrInvalid
	}
	for _, character := range credential.APIKey {
		if character == 0 || character == '\r' || character == '\n' || character == '\t' || character == ' ' {
			return ErrInvalid
		}
	}
	return nil
}

func (credential *CyberMailCredential) clear() {
	if credential == nil {
		return
	}
	clearBytes(credential.APIKey)
	credential.APIKey = nil
	if credential.Cleanup != nil {
		credential.Cleanup()
		credential.Cleanup = nil
	}
}

type CyberMailCredentialResolver interface {
	ResolveCyberMailCredential(context.Context, ProviderBinding, uint64) (CyberMailCredential, error)
}

type CyberMailBindingResolver interface {
	ResolveCyberMailBinding(context.Context, TenantID, DomainID) (ProviderBinding, error)
}

type CyberMailRelay interface {
	SubmitCyberMail(context.Context, ProviderBinding, SubmitRequest) (SubmitResult, error)
	QueryCyberMailByIdempotency(context.Context, ProviderBinding, string) (QueryResult, error)
}

type CyberMailRotatedCredential struct {
	TenantID          TenantID
	BindingID         BindingID
	OldVersion        uint64
	NewVersion        uint64
	SMTPCredentialID  string
	SMTPUsername      string
	SMTPPassword      []byte `json:"-"`
}

type CyberMailCredentialActivator interface {
	ActivateCyberMailRotatedCredential(context.Context, CyberMailRotatedCredential) (string, error)
}

type CyberMailAdapterV1Options struct {
	Credentials         CyberMailCredentialResolver
	Bindings            CyberMailBindingResolver
	Relay               CyberMailRelay
	CredentialActivator CyberMailCredentialActivator
	HTTPTransport       http.RoundTripper
	RequestTimeout      time.Duration
	MaximumRequestBytes int
	MaximumResponseBytes int64
	Now                 func() time.Time
}

type CyberMailAdapterV1 struct {
	credentials         CyberMailCredentialResolver
	bindings            CyberMailBindingResolver
	relay               CyberMailRelay
	credentialActivator CyberMailCredentialActivator
	client              *http.Client
	requestTimeout      time.Duration
	maximumRequestBytes int
	maximumResponseBytes int64
	now                 func() time.Time
}

func NewCyberMailAdapterV1(options CyberMailAdapterV1Options) (*CyberMailAdapterV1, error) {
	if options.Credentials == nil || options.Bindings == nil || options.Relay == nil {
		return nil, ErrInvalid
	}
	if options.RequestTimeout == 0 {
		options.RequestTimeout = 30 * time.Second
	}
	if options.MaximumRequestBytes == 0 {
		options.MaximumRequestBytes = CyberMailMaximumRequestBytes
	}
	if options.MaximumResponseBytes == 0 {
		options.MaximumResponseBytes = CyberMailMaximumResponseBytes
	}
	if options.RequestTimeout < time.Second || options.RequestTimeout > 30*time.Second ||
		options.MaximumRequestBytes < 1024 || options.MaximumRequestBytes > CyberMailMaximumRequestBytes ||
		options.MaximumResponseBytes < 1024 || options.MaximumResponseBytes > CyberMailMaximumResponseBytes {
		return nil, ErrInvalid
	}
	transport := options.HTTPTransport
	if transport == nil {
		transport = newCyberMailHTTPTransport()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   options.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &CyberMailAdapterV1{credentials: options.Credentials, bindings: options.Bindings, relay: options.Relay,
		credentialActivator: options.CredentialActivator, client: client, requestTimeout: options.RequestTimeout,
		maximumRequestBytes: options.MaximumRequestBytes, maximumResponseBytes: options.MaximumResponseBytes,
		now: options.Now}, nil
}

func (adapter *CyberMailAdapterV1) Reference() ProviderAdapterRef {
	return CyberMailProviderReferenceV1()
}

func (adapter *CyberMailAdapterV1) Submit(ctx context.Context, request SubmitRequest) (SubmitResult, error) {
	if adapter == nil || validateSubmitRequest(request) != nil {
		return SubmitResult{}, cyberMailFailure("relay.submit", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	binding, err := adapter.bindings.ResolveCyberMailBinding(ctx, request.Envelope.TenantID, request.Envelope.DomainID)
	if err != nil {
		return SubmitResult{}, cyberMailFailure("relay.submit", "binding_unavailable", ErrUnavailable, CircuitHintFailure, 0, false)
	}
	if validateCyberMailBinding(binding) != nil || binding.TenantID != request.Envelope.TenantID ||
		binding.Lifecycle != BindingEnabled || !cyberMailDomainMatches(binding, request.Envelope.DomainID, request.Envelope.MailFrom, true) {
		return SubmitResult{}, cyberMailFailure("relay.submit", "binding_mismatch", ErrDenied, CircuitHintNone, 0, false)
	}
	result, err := adapter.relay.SubmitCyberMail(ctx, binding, request)
	if err != nil {
		mayHaveSubmitted := false
		var submissionFailure ProviderSubmissionError
		if errors.As(err, &submissionFailure) {
			mayHaveSubmitted = submissionFailure.MayHaveSubmitted()
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			mayHaveSubmitted = true
		}
		if mayHaveSubmitted {
			return result, cyberMailFailure("relay.submit", "ambiguous", errors.Join(ErrAmbiguous, err), CircuitHintReconcile, 0, true)
		}
		return result, cyberMailFailure("relay.submit", "rejected", errors.Join(ErrUnavailable, err), CircuitHintFailure, 0, false)
	}
	if result.State != SubmissionAccepted || result.ProviderMessageID == "" || len(result.ProviderMessageID) > 256 ||
		result.AcceptedAt.IsZero() || result.MayHaveSubmitted || result.RetryAfter < 0 || len(result.Code) > 128 {
		return SubmitResult{State: SubmissionAmbiguous, Code: "invalid_provider_receipt", MayHaveSubmitted: true},
			cyberMailFailure("relay.submit", "invalid_receipt", ErrAmbiguous, CircuitHintReconcile, 0, true)
	}
	return result, nil
}

func (adapter *CyberMailAdapterV1) QueryByIdempotency(ctx context.Context, binding ProviderBinding, idempotencyKey string) (QueryResult, error) {
	if adapter == nil || validateCyberMailBinding(binding) != nil || !validID(idempotencyKey) {
		return QueryResult{}, cyberMailFailure("relay.query", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	result, err := adapter.relay.QueryCyberMailByIdempotency(ctx, binding, idempotencyKey)
	if err != nil {
		return QueryResult{}, cyberMailFailure("relay.query", "unavailable", ErrUnavailable, CircuitHintFailure, 0, false)
	}
	if result.ObservedAt.IsZero() || len(result.ProviderMessageID) > 256 ||
		result.State != SubmissionAccepted && result.State != SubmissionAbsent && result.State != SubmissionAmbiguous && result.State != SubmissionFailed ||
		result.State == SubmissionAccepted && result.ProviderMessageID == "" ||
		result.AuthoritativeAbsence && result.State != SubmissionAbsent {
		return QueryResult{}, cyberMailFailure("relay.query", "invalid_response", ErrIntegrity, CircuitHintFailure, 0, false)
	}
	return result, nil
}

func (adapter *CyberMailAdapterV1) VerifyDomain(ctx context.Context, request DomainVerificationRequest) (DomainVerificationResult, error) {
	if adapter == nil || validateCyberMailBinding(request.Binding) != nil || request.Domain.Validate() != nil || request.Plan.Validate() != nil ||
		request.Plan.BindingID != request.Binding.ID || request.Plan.BindingGeneration != request.Binding.Generation ||
		request.Plan.TenantID != request.Binding.TenantID || request.Plan.DomainID != request.Domain.ID || request.Plan.Domain != request.Domain.Name ||
		!cyberMailHasDomain(request.Binding, request.Domain.ID, request.Domain.Name) {
		return DomainVerificationResult{}, cyberMailFailure("domain.verify", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	var data cyberMailVerificationData
	err := adapter.api(ctx, request.Binding, request.Binding.Credential.Version, "domain.verify", "api/domains/verify/", map[string]any{
		"domain": request.Domain.Name,
	}, &data, false)
	if err != nil {
		return DomainVerificationResult{}, err
	}
	observedAt := adapter.currentTime()
	state := VerificationPending
	if data.AllVerified {
		if !data.SPF || !data.DKIM || !data.DMARC {
			return DomainVerificationResult{}, cyberMailFailure("domain.verify", "inconsistent_response", ErrIntegrity, CircuitHintFailure, 0, false)
		}
		state = VerificationVerified
	} else if request.Plan.State == VerificationVerified {
		state = VerificationDrifted
	}
	result := DomainVerificationResult{State: state, ObservedAt: observedAt}
	if state == VerificationVerified {
		result.EvidenceDigest = cyberMailEvidenceDigest("domain.verify", string(request.Binding.TenantID), string(request.Binding.ID),
			string(request.Domain.ID), request.Domain.Name, strconv.FormatBool(data.SPF), strconv.FormatBool(data.DKIM),
			strconv.FormatBool(data.DMARC), strconv.FormatBool(data.AllVerified), request.Plan.ProviderVersion)
	}
	return result, nil
}

func (adapter *CyberMailAdapterV1) ObserveHealthAndLimits(ctx context.Context, binding ProviderBinding) (ProviderObservation, error) {
	if adapter == nil || validateCyberMailBinding(binding) != nil {
		return ProviderObservation{}, cyberMailFailure("account.observe", "invalid_binding", ErrInvalid, CircuitHintNone, 0, false)
	}
	var data cyberMailAccountData
	if err := adapter.api(ctx, binding, binding.Credential.Version, "account.observe", "api/account/", nil, &data, false); err != nil {
		return ProviderObservation{}, err
	}
	if data.Plan.EmailsPerMonth != 0 && data.EmailsSentThisMonth > data.Plan.EmailsPerMonth {
		return ProviderObservation{}, cyberMailFailure("account.observe", "invalid_quota", ErrIntegrity, CircuitHintFailure, 0, false)
	}
	observedAt := adapter.currentTime()
	observation := ProviderObservation{
		Health:          ProviderHealthy,
		CredentialState: "active",
		QuotaLimit:      data.Plan.EmailsPerMonth,
		QuotaUsed:       data.EmailsSentThisMonth,
		UsageCount:      data.EmailsSentThisMonth,
		ObservedAt:      observedAt,
		StaleAfter:      observedAt.Add(5 * time.Minute),
		EvidenceDigest: cyberMailEvidenceDigest("account.observe", string(binding.TenantID), string(binding.ID),
			strconv.FormatUint(binding.Credential.Version, 10), strconv.FormatUint(data.Plan.EmailsPerMonth, 10),
			strconv.FormatUint(data.EmailsSentThisMonth, 10)),
	}
	if observation.Validate() != nil {
		return ProviderObservation{}, cyberMailFailure("account.observe", "invalid_response", ErrIntegrity, CircuitHintFailure, 0, false)
	}
	return observation, nil
}

func (adapter *CyberMailAdapterV1) RotateCredential(ctx context.Context, request CredentialRotationRequest) (CredentialRotation, error) {
	if adapter == nil || validateCyberMailBinding(request.Binding) != nil || request.Rotation.Validate() != nil ||
		request.Rotation.BindingID != request.Binding.ID || request.Rotation.TenantID != request.Binding.TenantID ||
		request.Rotation.OldVersion != request.Binding.Credential.Version || request.Rotation.State != RotationPrepared {
		return CredentialRotation{}, cyberMailFailure("smtp.rotate", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	if adapter.credentialActivator == nil {
		return CredentialRotation{}, cyberMailFailure("smtp.rotate", "activation_unsupported", ErrUnsupported, CircuitHintNone, 0, false)
	}
	credential, err := adapter.resolveCredential(ctx, request.Binding, request.Rotation.OldVersion, "smtp.rotate")
	if err != nil {
		return CredentialRotation{}, err
	}
	defer credential.clear()
	if credential.SMTPCredentialID == "" || credential.SMTPUsername == "" {
		return CredentialRotation{}, cyberMailFailure("smtp.rotate", "smtp_credential_missing", ErrUnsupported, CircuitHintNone, 0, false)
	}
	var data cyberMailRotateData
	err = adapter.apiWithCredential(ctx, credential, "smtp.rotate", "api/smtp/rotate/", map[string]any{
		"credential_id": credential.SMTPCredentialID,
	}, &data, true)
	if err != nil {
		return CredentialRotation{}, err
	}
	defer data.NewPassword.clear()
	if len(data.NewPassword) == 0 || len(data.NewPassword) > 4096 || bytes.IndexByte(data.NewPassword, 0) >= 0 {
		return CredentialRotation{}, cyberMailFailure("smtp.rotate", "invalid_secret_response", ErrIntegrity, CircuitHintReconcile, 0, true)
	}
	activation := CyberMailRotatedCredential{TenantID: request.Binding.TenantID, BindingID: request.Binding.ID,
		OldVersion: request.Rotation.OldVersion, NewVersion: request.Rotation.NewVersion,
		SMTPCredentialID: credential.SMTPCredentialID, SMTPUsername: credential.SMTPUsername,
		SMTPPassword: data.NewPassword}
	reloadDigest, activationErr := adapter.credentialActivator.ActivateCyberMailRotatedCredential(ctx, activation)
	if activationErr != nil || !validDigest(reloadDigest) {
		return CredentialRotation{}, cyberMailFailure("smtp.rotate", "activation_ambiguous", ErrAmbiguous, CircuitHintReconcile, 0, true)
	}
	rotated := request.Rotation
	rotated.State = RotationRevoked
	rotated.ReloadReceiptDigest = reloadDigest
	rotated.ProviderReceiptDigest = cyberMailEvidenceDigest("smtp.rotate", string(request.Binding.TenantID), string(request.Binding.ID),
		credential.SMTPCredentialID, strconv.FormatUint(rotated.OldVersion, 10), strconv.FormatUint(rotated.NewVersion, 10))
	rotated.OccurredAt = adapter.currentTime()
	if rotated.Validate() != nil {
		return CredentialRotation{}, cyberMailFailure("smtp.rotate", "invalid_receipt", ErrIntegrity, CircuitHintReconcile, 0, true)
	}
	return rotated, nil
}

func (adapter *CyberMailAdapterV1) RevokeCredential(ctx context.Context, binding ProviderBinding, credentialVersion uint64) (CredentialRevocation, error) {
	if adapter == nil || validateCyberMailBinding(binding) != nil || credentialVersion == 0 || credentialVersion > binding.Credential.Version {
		return CredentialRevocation{}, cyberMailFailure("smtp.revoke", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	credential, err := adapter.resolveCredential(ctx, binding, credentialVersion, "smtp.revoke")
	if err != nil {
		return CredentialRevocation{}, err
	}
	defer credential.clear()
	if credential.SMTPCredentialID == "" {
		return CredentialRevocation{}, cyberMailFailure("smtp.revoke", "smtp_credential_missing", ErrUnsupported, CircuitHintNone, 0, false)
	}
	err = adapter.apiWithCredential(ctx, credential, "smtp.revoke", "api/smtp/delete/", map[string]any{
		"credential_id": credential.SMTPCredentialID,
	}, nil, true)
	if err != nil {
		return CredentialRevocation{}, err
	}
	revokedAt := adapter.currentTime()
	revocation := CredentialRevocation{
		ID:                derivedID("revocation", string(binding.ID), strconv.FormatUint(credentialVersion, 10), credential.SMTPCredentialID),
		BindingID:         binding.ID,
		TenantID:          binding.TenantID,
		CredentialVersion: credentialVersion,
		ProviderReceiptDigest: cyberMailEvidenceDigest("smtp.revoke", string(binding.TenantID), string(binding.ID),
			credential.SMTPCredentialID, strconv.FormatUint(credentialVersion, 10)),
		RevokedAt: revokedAt,
	}
	if revocation.Validate() != nil {
		return CredentialRevocation{}, cyberMailFailure("smtp.revoke", "invalid_receipt", ErrIntegrity, CircuitHintFailure, 0, false)
	}
	return revocation, nil
}

// CyberMail's local reference documents webhook availability by plan, but do
// not define a signature scheme or event payload. Accepting one here would
// invent a security contract, so the v1 adapter rejects every provider event.
func (adapter *CyberMailAdapterV1) NormalizeEvent(context.Context, RawProviderEvent) (NormalizedProviderEvent, error) {
	return NormalizedProviderEvent{}, errors.Join(ErrWebhookRejected, ErrUnsupported)
}

type CyberMailDNSPlanRequest struct {
	Binding   ProviderBinding
	Domain    SendingDomain
	PlanID    PlanID
	Revision  uint64
	CreatedAt time.Time
}

func (request CyberMailDNSPlanRequest) validate() error {
	if validateCyberMailBinding(request.Binding) != nil || request.Domain.Validate() != nil ||
		!cyberMailHasDomain(request.Binding, request.Domain.ID, request.Domain.Name) || !validID(string(request.PlanID)) ||
		request.Revision == 0 || request.CreatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type CyberMailDomainEnrollment struct {
	TenantID        TenantID       `json:"tenant_id"`
	BindingID       BindingID      `json:"binding_id"`
	DomainID        DomainID       `json:"domain_id"`
	ProviderDomainID string        `json:"provider_domain_id"`
	DNSPlan         DNSPlan        `json:"dns_plan"`
}

func (adapter *CyberMailAdapterV1) EnrollDomain(ctx context.Context, request CyberMailDNSPlanRequest) (CyberMailDomainEnrollment, error) {
	var enrollment CyberMailDomainEnrollment
	if adapter == nil || request.validate() != nil {
		return enrollment, cyberMailFailure("domain.enroll", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	var added cyberMailDomainData
	if err := adapter.api(ctx, request.Binding, request.Binding.Credential.Version, "domain.enroll", "api/domains/add/", map[string]any{
		"domain": request.Domain.Name,
	}, &added, true); err != nil {
		return enrollment, err
	}
	providerDomainID, err := cyberMailProviderID(added.ID, added.DomainID)
	if err != nil {
		return enrollment, cyberMailFailure("domain.enroll", "invalid_domain_receipt", ErrIntegrity, CircuitHintReconcile, 0, true)
	}
	enrollment = CyberMailDomainEnrollment{TenantID: request.Binding.TenantID, BindingID: request.Binding.ID,
		DomainID: request.Domain.ID, ProviderDomainID: providerDomainID}
	plan, err := adapter.FetchDNSPlan(ctx, request)
	if err != nil {
		return enrollment, cyberMailFailure("domain.enroll", "dns_plan_incomplete", errors.Join(ErrPartial, err), CircuitHintReconcile, 0, true)
	}
	enrollment.DNSPlan = plan
	return enrollment, nil
}

func (adapter *CyberMailAdapterV1) FetchDNSPlan(ctx context.Context, request CyberMailDNSPlanRequest) (DNSPlan, error) {
	if adapter == nil || request.validate() != nil {
		return DNSPlan{}, cyberMailFailure("domain.dns_plan", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	var data cyberMailDNSData
	if err := adapter.api(ctx, request.Binding, request.Binding.Credential.Version, "domain.dns_plan", "api/domains/dns-records/", map[string]any{
		"domain": request.Domain.Name,
	}, &data, false); err != nil {
		return DNSPlan{}, err
	}
	plan, err := normalizeCyberMailDNSPlan(request, data.Records)
	if err != nil {
		return DNSPlan{}, cyberMailFailure("domain.dns_plan", "unsupported_record_plan", err, CircuitHintNone, 0, false)
	}
	return plan, nil
}

func (adapter *CyberMailAdapterV1) RemoveDomain(ctx context.Context, binding ProviderBinding, domainID DomainID) error {
	domain, ok := cyberMailBoundDomain(binding, domainID)
	if adapter == nil || validateCyberMailBinding(binding) != nil || !ok {
		return cyberMailFailure("domain.remove", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	return adapter.api(ctx, binding, binding.Credential.Version, "domain.remove", "api/domains/remove/", map[string]any{
		"domain": domain.Name,
	}, nil, true)
}

type CyberMailPageRequest struct {
	Page    uint32 `json:"page"`
	PerPage uint16 `json:"per_page"`
}

func (request CyberMailPageRequest) validate() error {
	if request.Page == 0 || request.PerPage == 0 || request.PerPage > 100 {
		return ErrInvalid
	}
	return nil
}

type CyberMailDomainStatus struct {
	DomainID         DomainID          `json:"domain_id"`
	Domain           string            `json:"domain"`
	ProviderDomainID string            `json:"provider_domain_id"`
	Verification     VerificationState `json:"verification"`
	SPFVerified      bool              `json:"spf_verified"`
	DKIMVerified     bool              `json:"dkim_verified"`
	DMARCVerified    bool              `json:"dmarc_verified"`
}

type CyberMailDomainPage struct {
	Items      []CyberMailDomainStatus `json:"items"`
	Page       uint32                  `json:"page"`
	TotalPages uint32                  `json:"total_pages"`
	TotalItems uint32                  `json:"total_items"`
	NextPage   uint32                  `json:"next_page,omitempty"`
}

func (adapter *CyberMailAdapterV1) ListDomains(ctx context.Context, binding ProviderBinding, page CyberMailPageRequest) (CyberMailDomainPage, error) {
	if adapter == nil || validateCyberMailBinding(binding) != nil || page.validate() != nil {
		return CyberMailDomainPage{}, cyberMailFailure("domain.list", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	var data cyberMailDomainsData
	if err := adapter.api(ctx, binding, binding.Credential.Version, "domain.list", "api/domains/list/", nil, &data, false); err != nil {
		return CyberMailDomainPage{}, err
	}
	items := make([]CyberMailDomainStatus, 0, len(binding.Domains))
	seen := make(map[string]struct{}, len(data.Domains))
	for _, remote := range data.Domains {
		name := strings.ToLower(strings.TrimSuffix(remote.Domain, "."))
		bound, ok := cyberMailBoundDomainByName(binding, name)
		if !ok {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			return CyberMailDomainPage{}, cyberMailFailure("domain.list", "duplicate_domain", ErrIntegrity, CircuitHintFailure, 0, false)
		}
		seen[name] = struct{}{}
		providerID, err := cyberMailProviderID(remote.ID, nil)
		if err != nil {
			return CyberMailDomainPage{}, cyberMailFailure("domain.list", "invalid_domain_id", ErrIntegrity, CircuitHintFailure, 0, false)
		}
		verification := VerificationPending
		if remote.Status == "verified" && remote.SPFVerified && remote.DKIMVerified && remote.DMARCVerified {
			verification = VerificationVerified
		}
		items = append(items, CyberMailDomainStatus{DomainID: bound.ID, Domain: bound.Name, ProviderDomainID: providerID,
			Verification: verification, SPFVerified: remote.SPFVerified, DKIMVerified: remote.DKIMVerified,
			DMARCVerified: remote.DMARCVerified})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].DomainID < items[right].DomainID })
	start, end, totalPages, err := cyberMailPageBounds(len(items), page)
	if err != nil {
		return CyberMailDomainPage{}, err
	}
	result := CyberMailDomainPage{Items: append([]CyberMailDomainStatus(nil), items[start:end]...), Page: page.Page,
		TotalPages: totalPages, TotalItems: uint32(len(items))}
	if page.Page < totalPages {
		result.NextPage = page.Page + 1
	}
	return result, nil
}

type CyberMailSMTPCredential struct {
	CredentialID string `json:"credential_id"`
}

type CyberMailSMTPCredentialPage struct {
	Items      []CyberMailSMTPCredential `json:"items"`
	Page       uint32                    `json:"page"`
	TotalPages uint32                    `json:"total_pages"`
	TotalItems uint32                    `json:"total_items"`
	NextPage   uint32                    `json:"next_page,omitempty"`
}

func (adapter *CyberMailAdapterV1) ListSMTPCredentials(ctx context.Context, binding ProviderBinding, page CyberMailPageRequest) (CyberMailSMTPCredentialPage, error) {
	if adapter == nil || validateCyberMailBinding(binding) != nil || page.validate() != nil {
		return CyberMailSMTPCredentialPage{}, cyberMailFailure("smtp.list", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	var data cyberMailCredentialsData
	if err := adapter.api(ctx, binding, binding.Credential.Version, "smtp.list", "api/smtp/list/", nil, &data, false); err != nil {
		return CyberMailSMTPCredentialPage{}, err
	}
	items := make([]CyberMailSMTPCredential, 0, len(data.Credentials))
	seen := make(map[string]struct{}, len(data.Credentials))
	for _, remote := range data.Credentials {
		identifier, err := cyberMailProviderID(remote.CredentialID, remote.ID)
		if err != nil {
			return CyberMailSMTPCredentialPage{}, cyberMailFailure("smtp.list", "invalid_credential_id", ErrIntegrity, CircuitHintFailure, 0, false)
		}
		if _, duplicate := seen[identifier]; duplicate {
			return CyberMailSMTPCredentialPage{}, cyberMailFailure("smtp.list", "duplicate_credential", ErrIntegrity, CircuitHintFailure, 0, false)
		}
		seen[identifier] = struct{}{}
		items = append(items, CyberMailSMTPCredential{CredentialID: identifier})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].CredentialID < items[right].CredentialID })
	start, end, totalPages, err := cyberMailPageBounds(len(items), page)
	if err != nil {
		return CyberMailSMTPCredentialPage{}, err
	}
	result := CyberMailSMTPCredentialPage{Items: append([]CyberMailSMTPCredential(nil), items[start:end]...), Page: page.Page,
		TotalPages: totalPages, TotalItems: uint32(len(items))}
	if page.Page < totalPages {
		result.NextPage = page.Page + 1
	}
	return result, nil
}

type CyberMailStatistics struct {
	TotalSent    uint64  `json:"total_sent"`
	Delivered    uint64  `json:"delivered"`
	Bounced      uint64  `json:"bounced"`
	Failed       uint64  `json:"failed"`
	DeliveryRate float64 `json:"delivery_rate"`
}

func (statistics CyberMailStatistics) validate() error {
	if statistics.DeliveryRate < 0 || statistics.DeliveryRate > 100 ||
		statistics.Delivered > statistics.TotalSent || statistics.Bounced > statistics.TotalSent || statistics.Failed > statistics.TotalSent {
		return ErrIntegrity
	}
	return nil
}

func (adapter *CyberMailAdapterV1) Statistics(ctx context.Context, binding ProviderBinding) (CyberMailStatistics, error) {
	if adapter == nil || validateCyberMailBinding(binding) != nil {
		return CyberMailStatistics{}, cyberMailFailure("stats.account", "invalid_binding", ErrInvalid, CircuitHintNone, 0, false)
	}
	var data cyberMailStatisticsData
	if err := adapter.api(ctx, binding, binding.Credential.Version, "stats.account", "api/stats/", nil, &data, false); err != nil {
		return CyberMailStatistics{}, err
	}
	statistics := data.statistics()
	if statistics.validate() != nil {
		return CyberMailStatistics{}, cyberMailFailure("stats.account", "invalid_response", ErrIntegrity, CircuitHintFailure, 0, false)
	}
	return statistics, nil
}

type CyberMailDomainStatistics struct {
	DomainID DomainID `json:"domain_id"`
	Domain   string   `json:"domain"`
	CyberMailStatistics
}

type CyberMailDomainStatisticsPage struct {
	Items      []CyberMailDomainStatistics `json:"items"`
	Page       uint32                      `json:"page"`
	TotalPages uint32                      `json:"total_pages"`
	TotalItems uint32                      `json:"total_items"`
	NextPage   uint32                      `json:"next_page,omitempty"`
}

func (adapter *CyberMailAdapterV1) ListDomainStatistics(ctx context.Context, binding ProviderBinding, page CyberMailPageRequest) (CyberMailDomainStatisticsPage, error) {
	if adapter == nil || validateCyberMailBinding(binding) != nil || page.validate() != nil {
		return CyberMailDomainStatisticsPage{}, cyberMailFailure("stats.domains", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	var data cyberMailDomainStatisticsData
	if err := adapter.api(ctx, binding, binding.Credential.Version, "stats.domains", "api/stats/domains/", nil, &data, false); err != nil {
		return CyberMailDomainStatisticsPage{}, err
	}
	items := make([]CyberMailDomainStatistics, 0, len(binding.Domains))
	for name, remote := range data.Domains {
		normalizedName := strings.ToLower(strings.TrimSuffix(name, "."))
		bound, ok := cyberMailBoundDomainByName(binding, normalizedName)
		if !ok {
			continue
		}
		statistics := remote.statistics()
		if statistics.validate() != nil {
			return CyberMailDomainStatisticsPage{}, cyberMailFailure("stats.domains", "invalid_response", ErrIntegrity, CircuitHintFailure, 0, false)
		}
		items = append(items, CyberMailDomainStatistics{DomainID: bound.ID, Domain: bound.Name, CyberMailStatistics: statistics})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].DomainID < items[right].DomainID })
	start, end, totalPages, err := cyberMailPageBounds(len(items), page)
	if err != nil {
		return CyberMailDomainStatisticsPage{}, err
	}
	result := CyberMailDomainStatisticsPage{Items: append([]CyberMailDomainStatistics(nil), items[start:end]...), Page: page.Page,
		TotalPages: totalPages, TotalItems: uint32(len(items))}
	if page.Page < totalPages {
		result.NextPage = page.Page + 1
	}
	return result, nil
}

type CyberMailDeliveryLogRequest struct {
	DomainID DomainID
	Page     uint32
	PerPage  uint16
	Status   string
	Days     uint8
}

func (request CyberMailDeliveryLogRequest) validate(binding ProviderBinding) (SendingDomain, error) {
	domain, ok := cyberMailBoundDomain(binding, request.DomainID)
	if !ok || request.Page == 0 || request.PerPage == 0 || request.PerPage > 100 || request.Days == 0 || request.Days > 30 {
		return SendingDomain{}, ErrInvalid
	}
	if request.Status != "" && request.Status != "delivered" && request.Status != "bounced" && request.Status != "failed" {
		return SendingDomain{}, ErrInvalid
	}
	return domain, nil
}

// CyberMailDeliveryLog intentionally omits subject, local-parts, recipients,
// headers, and message bodies even though the legacy endpoint returns some of
// them. Only binding-safe delivery metadata crosses this adapter boundary.
type CyberMailDeliveryLog struct {
	DomainID DomainID `json:"domain_id"`
	Domain   string   `json:"domain"`
	QueuedAt string   `json:"queued_at"`
	Status   string   `json:"status"`
}

type CyberMailDeliveryLogPage struct {
	Items      []CyberMailDeliveryLog `json:"items"`
	Page       uint32                 `json:"page"`
	TotalPages uint32                 `json:"total_pages"`
	NextPage   uint32                 `json:"next_page,omitempty"`
}

func (adapter *CyberMailAdapterV1) ListDeliveryLogs(ctx context.Context, binding ProviderBinding, request CyberMailDeliveryLogRequest) (CyberMailDeliveryLogPage, error) {
	if adapter == nil || validateCyberMailBinding(binding) != nil {
		return CyberMailDeliveryLogPage{}, cyberMailFailure("delivery.logs", "invalid_binding", ErrInvalid, CircuitHintNone, 0, false)
	}
	domain, err := request.validate(binding)
	if err != nil {
		return CyberMailDeliveryLogPage{}, cyberMailFailure("delivery.logs", "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
	}
	var data cyberMailLogsData
	err = adapter.api(ctx, binding, binding.Credential.Version, "delivery.logs", "api/logs/", map[string]any{
		"page":        request.Page,
		"per_page":    request.PerPage,
		"status":      request.Status,
		"from_domain": domain.Name,
		"days":        request.Days,
	}, &data, false)
	if err != nil {
		return CyberMailDeliveryLogPage{}, err
	}
	if data.Pagination.Page != request.Page || data.Pagination.TotalPages == 0 || data.Pagination.Page > data.Pagination.TotalPages ||
		len(data.Logs) > int(request.PerPage) {
		return CyberMailDeliveryLogPage{}, cyberMailFailure("delivery.logs", "invalid_pagination", ErrIntegrity, CircuitHintFailure, 0, false)
	}
	items := make([]CyberMailDeliveryLog, 0, len(data.Logs))
	for _, remote := range data.Logs {
		if !validCyberMailLogStatus(remote.Status) || len(remote.QueuedAt) == 0 || len(remote.QueuedAt) > 64 ||
			strings.ContainsAny(remote.QueuedAt, "\x00\r\n") || !mailboxBelongsToDomain(remote.FromEmail, domain.Name) {
			return CyberMailDeliveryLogPage{}, cyberMailFailure("delivery.logs", "invalid_log_entry", ErrIntegrity, CircuitHintFailure, 0, false)
		}
		items = append(items, CyberMailDeliveryLog{DomainID: domain.ID, Domain: domain.Name, QueuedAt: remote.QueuedAt, Status: remote.Status})
	}
	result := CyberMailDeliveryLogPage{Items: items, Page: data.Pagination.Page, TotalPages: data.Pagination.TotalPages}
	if result.Page < result.TotalPages {
		result.NextPage = result.Page + 1
	}
	return result, nil
}

func (adapter *CyberMailAdapterV1) currentTime() time.Time {
	if adapter == nil || adapter.now == nil {
		return time.Now().UTC()
	}
	return adapter.now().UTC()
}

func (adapter *CyberMailAdapterV1) resolveCredential(ctx context.Context, binding ProviderBinding, version uint64, operation string) (CyberMailCredential, error) {
	credential, err := adapter.credentials.ResolveCyberMailCredential(ctx, binding, version)
	if err != nil {
		return CyberMailCredential{}, cyberMailFailure(operation, "credential_unavailable", ErrDenied, CircuitHintFailure, 0, false)
	}
	if credential.validate(binding, version) != nil {
		credential.clear()
		return CyberMailCredential{}, cyberMailFailure(operation, "credential_invalid", ErrDenied, CircuitHintFailure, 0, false)
	}
	return credential, nil
}

func (adapter *CyberMailAdapterV1) api(ctx context.Context, binding ProviderBinding, version uint64, operation, path string, fields map[string]any, target any, mutation bool) error {
	credential, err := adapter.resolveCredential(ctx, binding, version, operation)
	if err != nil {
		return err
	}
	defer credential.clear()
	return adapter.apiWithCredential(ctx, credential, operation, path, fields, target, mutation)
}

func (adapter *CyberMailAdapterV1) apiWithCredential(ctx context.Context, credential CyberMailCredential, operation, path string, fields map[string]any, target any, mutation bool) error {
	if adapter == nil || adapter.client == nil || !strings.HasPrefix(path, "api/") || strings.ContainsAny(path, "?#\\") {
		return cyberMailFailure(operation, "invalid_endpoint", ErrInvalid, CircuitHintNone, 0, false)
	}
	document := make(map[string]any, len(fields)+1)
	document["email"] = credential.AccountEmail
	for name, value := range fields {
		if name == "email" || !validID(name) {
			return cyberMailFailure(operation, "invalid_request", ErrInvalid, CircuitHintNone, 0, false)
		}
		document[name] = value
	}
	body, err := json.Marshal(document)
	if err != nil || len(body) == 0 || len(body) > adapter.maximumRequestBytes {
		clearBytes(body)
		return cyberMailFailure(operation, "request_too_large", ErrInvalid, CircuitHintNone, 0, false)
	}
	defer clearBytes(body)
	requestContext, cancel := context.WithTimeout(ctx, adapter.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, CyberMailAPIBaseURL+path, bytes.NewReader(body))
	if err != nil {
		return cyberMailFailure(operation, "request_invalid", ErrInvalid, CircuitHintNone, 0, false)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(credential.APIKey))
	response, err := adapter.client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		mayHaveWrite := mutation
		cause := ErrUnavailable
		if requestContext.Err() != nil {
			cause = errors.Join(ErrUnavailable, requestContext.Err())
		}
		hint := CircuitHintFailure
		if mayHaveWrite {
			hint = CircuitHintReconcile
		}
		return cyberMailFailure(operation, "transport_failure", cause, hint, 0, mayHaveWrite)
	}
	defer response.Body.Close()
	if response.ContentLength > adapter.maximumResponseBytes {
		return cyberMailFailure(operation, "response_too_large", ErrIntegrity, CircuitHintFailure, 0, mutation)
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, adapter.maximumResponseBytes+1))
	defer clearBytes(raw)
	if readErr != nil || int64(len(raw)) > adapter.maximumResponseBytes {
		return cyberMailFailure(operation, "response_too_large", ErrIntegrity, CircuitHintFailure, 0, mutation)
	}
	retryAfter := cyberMailRetryAfter(response.Header.Get("Retry-After"), adapter.currentTime())
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return cyberMailHTTPFailure(operation, response.StatusCode, retryAfter, mutation)
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" || len(raw) == 0 {
		return cyberMailFailure(operation, "invalid_content_type", ErrIntegrity, CircuitHintFailure, 0, mutation)
	}
	var envelope cyberMailEnvelope
	if decodeCyberMailJSON(raw, &envelope) != nil {
		return cyberMailFailure(operation, "invalid_json", ErrIntegrity, CircuitHintFailure, 0, mutation)
	}
	defer clearBytes(envelope.Data)
	defer clearBytes(envelope.Error)
	if !envelope.Success {
		return cyberMailFailure(operation, "provider_rejected", ErrUnavailable, CircuitHintFailure, retryAfter, false)
	}
	if target != nil {
		if len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) || decodeCyberMailJSON(envelope.Data, target) != nil {
			return cyberMailFailure(operation, "invalid_data", ErrIntegrity, CircuitHintFailure, 0, mutation)
		}
	}
	return nil
}

func cyberMailHTTPFailure(operation string, status int, retryAfter time.Duration, mutation bool) error {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return cyberMailFailure(operation, "request_rejected", ErrInvalid, CircuitHintNone, 0, false)
	case http.StatusUnauthorized, http.StatusForbidden:
		return cyberMailFailure(operation, "credential_rejected", ErrDenied, CircuitHintFailure, 0, false)
	case http.StatusNotFound:
		return cyberMailFailure(operation, "not_found", ErrNotFound, CircuitHintNone, 0, false)
	case http.StatusConflict:
		return cyberMailFailure(operation, "conflict", ErrConflict, CircuitHintNone, 0, false)
	case http.StatusTooManyRequests:
		return cyberMailFailure(operation, "rate_limited", errors.Join(ErrBackpressure, ErrRateLimited), CircuitHintThrottle, retryAfter, false)
	case http.StatusRequestTimeout, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return cyberMailFailure(operation, "provider_unavailable", ErrUnavailable, CircuitHintFailure, retryAfter, mutation)
	default:
		if status >= 300 && status < 400 {
			return cyberMailFailure(operation, "redirect_rejected", ErrDenied, CircuitHintFailure, 0, mutation)
		}
		return cyberMailFailure(operation, "provider_failure", ErrUnavailable, CircuitHintFailure, retryAfter, mutation)
	}
}

func newCyberMailHTTPTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, Renegotiation: tls.RenegotiateNever},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(host, "platform.cyberpersons.com") || port != "443" {
				return nil, ErrDenied
			}
			addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(addresses) == 0 || len(addresses) > 32 {
				return nil, ErrUnavailable
			}
			for _, candidate := range addresses {
				if !publicRelayIP(candidate) {
					continue
				}
				connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
				if dialErr == nil {
					return connection, nil
				}
			}
			return nil, ErrUnavailable
		},
	}
}

type CyberMailSMTPRelayOptions struct {
	HelloName             string
	Secrets               SMTPSecretResolver
	Resolver              SMTPDNSResolver
	Dialer                SMTPDialer
	Observer              SMTPQueueObserver
	TLSConfig             *tls.Config
	DialTimeout           time.Duration
	CommandTimeout        time.Duration
	MaximumResponseBytes  int
	MaximumMessageBytes   int64
	Now                   func() time.Time
}

type CyberMailSMTPRelay struct {
	options CyberMailSMTPRelayOptions
}

func NewCyberMailSMTPRelay(options CyberMailSMTPRelayOptions) (*CyberMailSMTPRelay, error) {
	if !validHostname(options.HelloName) || options.Secrets == nil || options.Observer == nil {
		return nil, ErrInvalid
	}
	probeReference := EncryptedCredentialReference{Reference: "cybermail-probe", Version: 1,
		EncryptionContextDigest: strings.Repeat("0", 64), Purpose: "maildelivery_provider"}
	_, err := NewSMTPRelay(SMTPRelayOptions{Origin: cyberMailSMTPOrigin(options.HelloName), Credential: probeReference,
		Secrets: options.Secrets, Resolver: options.Resolver, Dialer: options.Dialer, Observer: options.Observer,
		TLSConfig: options.TLSConfig, DialTimeout: options.DialTimeout, CommandTimeout: options.CommandTimeout,
		MaximumResponseBytes: options.MaximumResponseBytes, MaximumMessageBytes: options.MaximumMessageBytes, Now: options.Now})
	if err != nil {
		return nil, err
	}
	return &CyberMailSMTPRelay{options: options}, nil
}

func (relay *CyberMailSMTPRelay) SubmitCyberMail(ctx context.Context, binding ProviderBinding, request SubmitRequest) (SubmitResult, error) {
	resolved, err := relay.forBinding(binding)
	if err != nil {
		return SubmitResult{}, err
	}
	return resolved.Submit(ctx, request)
}

func (relay *CyberMailSMTPRelay) QueryCyberMailByIdempotency(ctx context.Context, binding ProviderBinding, idempotencyKey string) (QueryResult, error) {
	resolved, err := relay.forBinding(binding)
	if err != nil {
		return QueryResult{}, err
	}
	return resolved.QueryByIdempotency(ctx, binding, idempotencyKey)
}

func (relay *CyberMailSMTPRelay) forBinding(binding ProviderBinding) (*SMTPRelay, error) {
	if relay == nil || validateCyberMailBinding(binding) != nil {
		return nil, ErrInvalid
	}
	options := relay.options
	return NewSMTPRelay(SMTPRelayOptions{Origin: cyberMailSMTPOrigin(options.HelloName), Credential: binding.Credential,
		Secrets: options.Secrets, Resolver: options.Resolver, Dialer: options.Dialer, Observer: options.Observer,
		TLSConfig: options.TLSConfig, DialTimeout: options.DialTimeout, CommandTimeout: options.CommandTimeout,
		MaximumResponseBytes: options.MaximumResponseBytes, MaximumMessageBytes: options.MaximumMessageBytes, Now: options.Now})
}

func cyberMailSMTPOrigin(helloName string) SMTPRelayOrigin {
	return SMTPRelayOrigin{Host: CyberMailSMTPHost, Port: CyberMailSMTPPort, ServerName: CyberMailSMTPHost,
		HelloName: helloName, TLSMode: SMTPSTARTTLS}
}

func normalizeCyberMailDNSPlan(request CyberMailDNSPlanRequest, records []cyberMailDNSRecord) (DNSPlan, error) {
	if request.validate() != nil || len(records) == 0 || len(records) > 64 {
		return DNSPlan{}, ErrInvalid
	}
	normalized := make([]DNSRecordPlan, 0, len(records))
	for _, remote := range records {
		record := DNSRecordPlan{Name: remote.Host, Type: strings.ToUpper(remote.Type), Value: remote.Value, Required: true}
		value := strings.ToLower(strings.TrimSpace(remote.Value))
		switch {
		case strings.HasPrefix(value, "v=spf1"):
			record.Kind = DNSRecordSPF
		case strings.HasPrefix(value, "v=dkim1"):
			record.Kind = DNSRecordDKIM
		default:
			record.Kind = DNSRecordProvider
		}
		if record.Validate() != nil {
			return DNSPlan{}, ErrIntegrity
		}
		normalized = append(normalized, record)
	}
	sort.Slice(normalized, func(left, right int) bool {
		leftKey := string(normalized[left].Kind) + "\x00" + normalized[left].Name + "\x00" + normalized[left].Type + "\x00" + normalized[left].Value
		rightKey := string(normalized[right].Kind) + "\x00" + normalized[right].Name + "\x00" + normalized[right].Type + "\x00" + normalized[right].Value
		return leftKey < rightKey
	})
	required := map[DNSRecordKind]bool{DNSRecordSPF: false, DNSRecordDKIM: false, DNSRecordReturnPath: false, DNSRecordTracking: false}
	seen := make(map[string]struct{}, len(normalized))
	for _, record := range normalized {
		key := string(record.Kind) + "\x00" + record.Name + "\x00" + record.Type
		if _, duplicate := seen[key]; duplicate {
			return DNSPlan{}, ErrIntegrity
		}
		seen[key] = struct{}{}
		if record.Required {
			required[record.Kind] = true
		}
	}
	if !required[DNSRecordSPF] || !required[DNSRecordDKIM] || !required[DNSRecordReturnPath] || !required[DNSRecordTracking] {
		// The documented CyberMail response contains SPF, DKIM, and DMARC.
		// The provider-neutral v1 plan additionally mandates return-path and
		// tracking records; those must be documented by the provider before
		// this adapter can assign those semantic kinds.
		return DNSPlan{}, ErrUnsupported
	}
	plan := DNSPlan{ID: request.PlanID, BindingID: request.Binding.ID, BindingGeneration: request.Binding.Generation,
		TenantID: request.Binding.TenantID, DomainID: request.Domain.ID, Domain: request.Domain.Name, Revision: request.Revision,
		ProviderVersion: CyberMailAdapterVersionV1, Records: normalized, State: VerificationPending, CreatedAt: request.CreatedAt.UTC()}
	if plan.Validate() != nil {
		return DNSPlan{}, ErrIntegrity
	}
	return plan, nil
}

func validateCyberMailBinding(binding ProviderBinding) error {
	if binding.Validate() != nil || binding.Adapter != CyberMailProviderReferenceV1() || binding.Credential.Purpose != "maildelivery_provider" {
		return ErrInvalid
	}
	return nil
}

func cyberMailHasDomain(binding ProviderBinding, domainID DomainID, name string) bool {
	domain, ok := cyberMailBoundDomain(binding, domainID)
	return ok && domain.Name == name
}

func cyberMailBoundDomain(binding ProviderBinding, domainID DomainID) (SendingDomain, bool) {
	for _, domain := range binding.Domains {
		if domain.ID == domainID {
			return domain, true
		}
	}
	return SendingDomain{}, false
}

func cyberMailBoundDomainByName(binding ProviderBinding, name string) (SendingDomain, bool) {
	for _, domain := range binding.Domains {
		if domain.Name == name {
			return domain, true
		}
	}
	return SendingDomain{}, false
}

func cyberMailDomainMatches(binding ProviderBinding, domainID DomainID, mailbox string, requireVerified bool) bool {
	domain, ok := cyberMailBoundDomain(binding, domainID)
	if !ok || requireVerified && domain.Verification != VerificationVerified {
		return false
	}
	return mailboxBelongsToDomain(mailbox, domain.Name)
}

func validMailbox(value string) bool {
	if len(value) == 0 || len(value) > 320 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Name == "" && parsed.Address == value && strings.Count(value, "@") == 1
}

func mailboxBelongsToDomain(value, domain string) bool {
	if !validMailbox(value) {
		return false
	}
	separator := strings.LastIndexByte(value, '@')
	return separator > 0 && strings.EqualFold(value[separator+1:], domain)
}

func validCyberMailLogStatus(status string) bool {
	return status == "delivered" || status == "bounced" || status == "failed"
}

func cyberMailPageBounds(length int, request CyberMailPageRequest) (int, int, uint32, error) {
	if request.validate() != nil || length < 0 {
		return 0, 0, 0, ErrInvalid
	}
	totalPages := uint32(1)
	if length > 0 {
		totalPages = uint32((length + int(request.PerPage) - 1) / int(request.PerPage))
	}
	if request.Page > totalPages {
		return 0, 0, 0, ErrNotFound
	}
	start64 := uint64(request.Page-1) * uint64(request.PerPage)
	if start64 > uint64(length) {
		return 0, 0, 0, ErrNotFound
	}
	start := int(start64)
	end := start + int(request.PerPage)
	if end > length {
		end = length
	}
	return start, end, totalPages, nil
}

func cyberMailProviderID(primary, fallback json.RawMessage) (string, error) {
	value := bytes.TrimSpace(primary)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		value = bytes.TrimSpace(fallback)
	}
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return "", ErrIntegrity
	}
	var identifier string
	if value[0] == '"' {
		if json.Unmarshal(value, &identifier) != nil {
			return "", ErrIntegrity
		}
	} else {
		for _, character := range value {
			if character < '0' || character > '9' {
				return "", ErrIntegrity
			}
		}
		identifier = string(value)
	}
	if len(identifier) == 0 || len(identifier) > 256 || strings.ContainsAny(identifier, "\x00\r\n") {
		return "", ErrIntegrity
	}
	return identifier, nil
}

func cyberMailEvidenceDigest(parts ...string) string {
	digest := sha256.New()
	for _, part := range parts {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(part))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func cyberMailRetryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		duration := time.Duration(seconds) * time.Second
		if duration <= 24*time.Hour {
			return duration
		}
		return 24 * time.Hour
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	duration := when.Sub(now)
	if duration > 24*time.Hour {
		return 24 * time.Hour
	}
	return duration
}

func decodeCyberMailJSON(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

type cyberMailEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   json.RawMessage `json:"error"`
}

type cyberMailAccountData struct {
	EmailsSentThisMonth uint64 `json:"emails_sent_this_month"`
	Plan struct {
		EmailsPerMonth uint64 `json:"emails_per_month"`
	} `json:"plan"`
}

type cyberMailVerificationData struct {
	SPF         bool `json:"spf"`
	DKIM        bool `json:"dkim"`
	DMARC       bool `json:"dmarc"`
	AllVerified bool `json:"all_verified"`
}

type cyberMailDomainData struct {
	ID       json.RawMessage `json:"id"`
	DomainID json.RawMessage `json:"domain_id"`
}

type cyberMailDNSRecord struct {
	Host     string `json:"host"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Priority int    `json:"priority"`
	TTL      int    `json:"ttl"`
}

type cyberMailDNSData struct {
	Records []cyberMailDNSRecord `json:"records"`
}

type cyberMailRemoteDomain struct {
	ID            json.RawMessage `json:"id"`
	Domain        string          `json:"domain"`
	Status        string          `json:"status"`
	SPFVerified   bool            `json:"spf_verified"`
	DKIMVerified  bool            `json:"dkim_verified"`
	DMARCVerified bool            `json:"dmarc_verified"`
}

type cyberMailDomainsData struct {
	Domains []cyberMailRemoteDomain `json:"domains"`
}

type cyberMailRemoteCredential struct {
	ID           json.RawMessage `json:"id"`
	CredentialID json.RawMessage `json:"credential_id"`
}

type cyberMailCredentialsData struct {
	Credentials []cyberMailRemoteCredential `json:"credentials"`
}

type secretJSONBytes []byte

func (secret *secretJSONBytes) UnmarshalJSON(encoded []byte) error {
	var value string
	if json.Unmarshal(encoded, &value) != nil {
		return ErrInvalid
	}
	*secret = append((*secret)[:0], value...)
	return nil
}

func (secret *secretJSONBytes) clear() {
	if secret == nil {
		return
	}
	clearBytes(*secret)
	*secret = nil
}

type cyberMailRotateData struct {
	NewPassword secretJSONBytes `json:"new_password"`
}

type cyberMailStatisticsData struct {
	TotalSent    uint64  `json:"total_sent"`
	Delivered    uint64  `json:"delivered"`
	Bounced      uint64  `json:"bounced"`
	Failed       uint64  `json:"failed"`
	DeliveryRate float64 `json:"delivery_rate"`
}

func (data cyberMailStatisticsData) statistics() CyberMailStatistics {
	return CyberMailStatistics{TotalSent: data.TotalSent, Delivered: data.Delivered, Bounced: data.Bounced,
		Failed: data.Failed, DeliveryRate: data.DeliveryRate}
}

type cyberMailDomainStatisticsData struct {
	Domains map[string]cyberMailStatisticsData `json:"domains"`
}

type cyberMailRemoteLog struct {
	QueuedAt  string `json:"queued_at"`
	FromEmail string `json:"from_email"`
	Status    string `json:"status"`
}

type cyberMailLogsData struct {
	Logs []cyberMailRemoteLog `json:"logs"`
	Pagination struct {
		Page       uint32 `json:"page"`
		TotalPages uint32 `json:"total_pages"`
	} `json:"pagination"`
}

var _ ProviderAdapterV1 = (*CyberMailAdapterV1)(nil)
var _ CyberMailRelay = (*CyberMailSMTPRelay)(nil)
