package sshactivity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

const (
	MaximumPlanLifetime = 15 * time.Minute
	MaximumStepUpAge    = 10 * time.Minute
	MaximumBlockLifetime = 24 * time.Hour
	MaximumProcessGrace = 10 * time.Second
)

type ResponseAction string

const (
	ActionRevokeSession       ResponseAction = "revoke_session"
	ActionTerminateProcess    ResponseAction = "terminate_process"
	ActionExpireKey           ResponseAction = "expire_key"
	ActionExpireGrant         ResponseAction = "expire_grant"
	ActionRequestFirewallBlock ResponseAction = "request_firewall_block"
)

func (action ResponseAction) valid() bool {
	switch action {
	case ActionRevokeSession, ActionTerminateProcess, ActionExpireKey, ActionExpireGrant, ActionRequestFirewallBlock:
		return true
	default:
		return false
	}
}

type SessionTarget struct {
	Identity SessionIdentity `json:"identity"`
	UserID   UserID          `json:"user_id"`
	Source   netip.Addr      `json:"source"`
}

func (target SessionTarget) valid() bool {
	return target.Identity.valid() && validOpaque(string(target.UserID)) && target.Source.IsValid() && !target.Source.IsUnspecified()
}

type ProcessTarget struct {
	Identity       ProcessIdentity `json:"identity"`
	SnapshotDigest string          `json:"snapshot_digest"`
	ExpectedUID    uint32          `json:"expected_uid"`
	ExpectedCommand string         `json:"expected_command"`
}

func (target ProcessTarget) valid() bool {
	return target.Identity.valid() && validDigest(target.SnapshotDigest) && len(target.ExpectedCommand) > 0 && len(target.ExpectedCommand) <= 128
}

type CredentialKind string

const (
	CredentialKey   CredentialKind = "key"
	CredentialGrant CredentialKind = "grant"
)

type CredentialTarget struct {
	Kind        CredentialKind `json:"kind"`
	ID          string         `json:"id"`
	UserID      UserID         `json:"user_id"`
	Generation  uint64         `json:"generation"`
	Fingerprint string         `json:"fingerprint,omitempty"`
}

func (target CredentialTarget) valid() bool {
	if (target.Kind != CredentialKey && target.Kind != CredentialGrant) || !validOpaque(target.ID) || !validOpaque(string(target.UserID)) || target.Generation == 0 || target.Generation >= MaximumRevision {
		return false
	}
	return target.Kind == CredentialKey && fingerprintPattern.MatchString(target.Fingerprint) || target.Kind == CredentialGrant && target.Fingerprint == ""
}

type FirewallBlockTarget struct {
	Prefix    netip.Prefix `json:"prefix"`
	ExpiresAt time.Time    `json:"expires_at"`
	ReasonCode string      `json:"reason_code"`
}

func (target FirewallBlockTarget) valid(now time.Time) bool {
	minimumBits := 8
	if target.Prefix.Addr().Is6() {
		minimumBits = 64
	}
	return target.Prefix.IsValid() && target.Prefix.Bits() >= minimumBits && target.Prefix.Bits() <= target.Prefix.Addr().BitLen() && target.ExpiresAt.After(now) && target.ExpiresAt.Sub(now) <= MaximumBlockLifetime && validOpaque(target.ReasonCode)
}

type DryRunImpact struct {
	Sessions              uint16 `json:"sessions"`
	Processes             uint16 `json:"processes"`
	Credentials           uint16 `json:"credentials"`
	EstimatedAddresses    uint64 `json:"estimated_addresses"`
	OperatorRecoveryAffected bool `json:"operator_recovery_affected"`
	ProtectedTarget       bool   `json:"protected_target"`
	Reversible            bool   `json:"reversible"`
	EvidenceDigest        string `json:"evidence_digest"`
}

func (impact DryRunImpact) valid(action ResponseAction) bool {
	if impact.OperatorRecoveryAffected || impact.ProtectedTarget || !validDigest(impact.EvidenceDigest) {
		return false
	}
	switch action {
	case ActionRevokeSession:
		return impact.Sessions == 1 && impact.Processes == 0 && impact.Credentials == 0 && impact.EstimatedAddresses == 0
	case ActionTerminateProcess:
		return impact.Sessions == 0 && impact.Processes == 1 && impact.Credentials == 0 && impact.EstimatedAddresses == 0
	case ActionExpireKey, ActionExpireGrant:
		return impact.Sessions == 0 && impact.Processes == 0 && impact.Credentials == 1 && impact.EstimatedAddresses == 0
	case ActionRequestFirewallBlock:
		return impact.Sessions == 0 && impact.Processes == 0 && impact.Credentials == 0 && impact.EstimatedAddresses > 0
	default:
		return false
	}
}

type ResponsePlanStatus string

const (
	PlanProposed  ResponsePlanStatus = "proposed"
	PlanApproved  ResponsePlanStatus = "approved"
	PlanExecuting ResponsePlanStatus = "executing"
	PlanSucceeded ResponsePlanStatus = "succeeded"
	PlanFailed    ResponsePlanStatus = "failed"
)

type ApprovalEvidence struct {
	ID             string    `json:"id"`
	ReviewerID     string    `json:"reviewer_id"`
	ApprovedDigest string    `json:"approved_digest"`
	EvidenceRef    string    `json:"evidence_ref"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (approval ApprovalEvidence) structurallyValid(plan ResponsePlan) bool {
	return validOpaque(approval.ID) && validOpaque(approval.ReviewerID) && approval.ReviewerID != plan.CreatedBy && approval.ApprovedDigest == plan.BodyDigest && validOpaque(approval.EvidenceRef) &&
		!approval.IssuedAt.IsZero() && approval.ExpiresAt.After(approval.IssuedAt) && approval.ExpiresAt.Sub(approval.IssuedAt) <= MaximumPlanLifetime
}

func (approval ApprovalEvidence) valid(plan ResponsePlan, now time.Time) bool {
	return approval.structurallyValid(plan) && !now.Before(approval.IssuedAt.Add(-time.Minute)) && now.Before(approval.ExpiresAt)
}

type ResponsePlan struct {
	ID          PlanID               `json:"id"`
	Action      ResponseAction       `json:"action"`
	Session     *SessionTarget       `json:"session,omitempty"`
	Process     *ProcessTarget       `json:"process,omitempty"`
	Credential  *CredentialTarget    `json:"credential,omitempty"`
	Firewall    *FirewallBlockTarget `json:"firewall,omitempty"`
	Grace       time.Duration        `json:"grace,omitempty"`
	IncidentID  IncidentID           `json:"incident_id"`
	CreatedBy   string               `json:"created_by"`
	CreatedAt   time.Time            `json:"created_at"`
	ExpiresAt   time.Time            `json:"expires_at"`
	Impact      DryRunImpact         `json:"impact"`
	BodyDigest  string               `json:"body_digest"`
	Approval    *ApprovalEvidence    `json:"approval,omitempty"`
	Status      ResponsePlanStatus   `json:"status"`
	Revision    uint64               `json:"revision"`
}

type responsePlanBody struct {
	ID         PlanID               `json:"id"`
	Action     ResponseAction       `json:"action"`
	Session    *SessionTarget       `json:"session,omitempty"`
	Process    *ProcessTarget       `json:"process,omitempty"`
	Credential *CredentialTarget    `json:"credential,omitempty"`
	Firewall   *FirewallBlockTarget `json:"firewall,omitempty"`
	Grace      time.Duration        `json:"grace,omitempty"`
	IncidentID IncidentID           `json:"incident_id"`
	CreatedBy  string               `json:"created_by"`
	CreatedAt  time.Time            `json:"created_at"`
	ExpiresAt  time.Time            `json:"expires_at"`
	Impact     DryRunImpact         `json:"impact"`
}

func responsePlanDigest(plan ResponsePlan) (string, error) {
	body := responsePlanBody{plan.ID, plan.Action, plan.Session, plan.Process, plan.Credential, plan.Firewall, plan.Grace, plan.IncidentID, plan.CreatedBy, plan.CreatedAt, plan.ExpiresAt, plan.Impact}
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > MaximumPlanJSON {
		return "", ErrLimit
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (plan ResponsePlan) targetValid(now time.Time) bool {
	count := 0
	if plan.Session != nil { count++ }
	if plan.Process != nil { count++ }
	if plan.Credential != nil { count++ }
	if plan.Firewall != nil { count++ }
	if count != 1 {
		return false
	}
	switch plan.Action {
	case ActionRevokeSession:
		return plan.Session != nil && plan.Session.valid() && plan.Grace == 0
	case ActionTerminateProcess:
		return plan.Process != nil && plan.Process.valid() && plan.Grace > 0 && plan.Grace <= MaximumProcessGrace
	case ActionExpireKey:
		return plan.Credential != nil && plan.Credential.Kind == CredentialKey && plan.Credential.valid() && plan.Grace == 0
	case ActionExpireGrant:
		return plan.Credential != nil && plan.Credential.Kind == CredentialGrant && plan.Credential.valid() && plan.Grace == 0
	case ActionRequestFirewallBlock:
		return plan.Firewall != nil && plan.Firewall.valid(now) && plan.Grace == 0
	default:
		return false
	}
}

func (plan ResponsePlan) valid(now time.Time) bool {
	if !validOpaque(string(plan.ID)) || !plan.Action.valid() || !validOpaque(string(plan.IncidentID)) || !validOpaque(plan.CreatedBy) || plan.CreatedAt.IsZero() || !plan.ExpiresAt.After(plan.CreatedAt) || plan.ExpiresAt.Sub(plan.CreatedAt) > MaximumPlanLifetime || now.Before(plan.CreatedAt.Add(-time.Minute)) || !plan.Impact.valid(plan.Action) || plan.Revision == 0 || plan.Revision > MaximumRevision || !plan.targetValid(plan.CreatedAt) {
		return false
	}
	digest, err := responsePlanDigest(plan)
	if err != nil || digest != plan.BodyDigest {
		return false
	}
	switch plan.Status {
	case PlanProposed:
		return plan.Approval == nil
	case PlanApproved, PlanExecuting, PlanSucceeded, PlanFailed:
		return plan.Approval != nil && plan.Approval.structurallyValid(plan)
	default:
		return false
	}
}

type StepUpGrant struct {
	ID         string
	SessionID  string
	VerifiedAt time.Time
	ExpiresAt  time.Time
	AuthzEpoch uint64
}

func (grant StepUpGrant) valid(actor Actor, now time.Time) bool {
	return validOpaque(grant.ID) && grant.SessionID == actor.SessionID && grant.AuthzEpoch == actor.AuthzEpoch && !grant.VerifiedAt.IsZero() && !grant.ExpiresAt.IsZero() &&
		!now.Before(grant.VerifiedAt) && now.Sub(grant.VerifiedAt) <= MaximumStepUpAge && now.Before(grant.ExpiresAt)
}

type ResponseRequest struct {
	ID         PlanID
	Action     ResponseAction
	Session    *SessionTarget
	Process    *ProcessTarget
	Credential *CredentialTarget
	Firewall   *FirewallBlockTarget
	Grace      time.Duration
	IncidentID IncidentID
}

type ResponseImpactAssessor interface {
	PreviewSSHResponse(context.Context, Actor, ResponseRequest) (DryRunImpact, error)
	VerifySSHResponsePreconditions(context.Context, ResponsePlan) error
}

type LockoutSafetyChecker interface {
	CheckSSHResponseLockout(context.Context, Actor, ResponsePlan) error
}

type ResponseAuthorizer interface {
	AuthorizeSSHResponse(context.Context, Actor, ResponsePlan, StepUpGrant) error
}

type ApprovalVerifier interface {
	VerifySSHResponseApproval(context.Context, ResponsePlan, ApprovalEvidence) error
}

type SessionRevoker interface {
	RevokeSSHSession(context.Context, PlanID, SessionTarget) (ResponseEffect, error)
}

type ProcessTerminator interface {
	TerminateSSHProcess(context.Context, PlanID, ProcessTarget, time.Duration) (ResponseEffect, error)
}

type CredentialExpirer interface {
	ExpireSSHCredential(context.Context, PlanID, CredentialTarget) (ResponseEffect, error)
}

// FirewallBlockRequester requests a lease from the existing firewall owner. It
// cannot mutate rules or become a second source of firewall truth.
type FirewallBlockRequester interface {
	RequestSSHFirewallBlock(context.Context, PlanID, FirewallBlockTarget) (ResponseEffect, error)
}

type ResponseEffect struct {
	Changed        bool   `json:"changed"`
	AlreadyApplied bool   `json:"already_applied"`
	TermSent       bool   `json:"term_sent,omitempty"`
	KillSent       bool   `json:"kill_sent,omitempty"`
	Exited         bool   `json:"exited,omitempty"`
	OwnerReceiptID string `json:"owner_receipt_id,omitempty"`
	EvidenceDigest string `json:"evidence_digest"`
}

func (effect ResponseEffect) structuralValid() bool {
	return !(effect.Changed && effect.AlreadyApplied) && validDigest(effect.EvidenceDigest) && (effect.OwnerReceiptID == "" || validOpaque(effect.OwnerReceiptID))
}

func (effect ResponseEffect) successValid() bool {
	return effect.structuralValid() && (effect.Changed || effect.AlreadyApplied)
}

type ReceiptStatus string

const (
	ReceiptSucceeded ReceiptStatus = "succeeded"
	ReceiptFailed    ReceiptStatus = "failed"
)

type ResponseReceipt struct {
	ID             string         `json:"id"`
	PlanID         PlanID         `json:"plan_id"`
	PlanDigest     string         `json:"plan_digest"`
	IncidentID     IncidentID     `json:"incident_id"`
	Action         ResponseAction `json:"action"`
	ActorID        string         `json:"actor_id"`
	ApprovalID     string         `json:"approval_id"`
	Status         ReceiptStatus  `json:"status"`
	ReasonCode     string         `json:"reason_code"`
	Effect         ResponseEffect `json:"effect"`
	CompletedAt    time.Time      `json:"completed_at"`
	Digest         string         `json:"digest"`
}

func responseReceiptDigest(receipt ResponseReceipt) (string, error) {
	receipt.Digest = ""
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaximumReceiptJSON {
		return "", ErrLimit
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (receipt ResponseReceipt) valid() bool {
	if !validOpaque(receipt.ID) || !validOpaque(string(receipt.PlanID)) || !validDigest(receipt.PlanDigest) || !validOpaque(string(receipt.IncidentID)) || !receipt.Action.valid() || !validOpaque(receipt.ActorID) || !validOpaque(receipt.ApprovalID) || !validOpaque(receipt.ReasonCode) || !receipt.Effect.structuralValid() || receipt.CompletedAt.IsZero() || receipt.Status != ReceiptSucceeded && receipt.Status != ReceiptFailed {
		return false
	}
	if receipt.Status == ReceiptSucceeded && !receipt.Effect.successValid() {
		return false
	}
	digest, err := responseReceiptDigest(receipt)
	return err == nil && digest == receipt.Digest
}

type ResponseRepository interface {
	GetResponsePlan(context.Context, PlanID) (ResponsePlan, error)
	UpsertResponsePlan(context.Context, ResponsePlan, uint64) (ResponsePlan, error)
	GetResponseReceipt(context.Context, PlanID) (ResponseReceipt, error)
	InsertResponseReceipt(context.Context, ResponseReceipt) error
}

type IncidentEvidenceRecorder interface {
	RecordSSHIncidentEvidence(context.Context, IncidentID, ResponseReceipt) error
}

type ResponseAuditor interface {
	RecordSSHResponseAudit(context.Context, ResponseAuditRecord) error
}

type ResponseAuditRecord struct {
	PlanID       PlanID
	PlanDigest   string
	IncidentID   IncidentID
	Action       ResponseAction
	ActorID      string
	ApprovalID   string
	Outcome      string
	ReasonCode   string
	ReceiptDigest string
	RecordedAt   time.Time
}

type ResponseManager struct {
	impact      ResponseImpactAssessor
	safety      LockoutSafetyChecker
	authorizer  ResponseAuthorizer
	approvals   ApprovalVerifier
	sessions    SessionRevoker
	processes   ProcessTerminator
	credentials CredentialExpirer
	firewall    FirewallBlockRequester
	repository  ResponseRepository
	incidents   IncidentEvidenceRecorder
	auditor     ResponseAuditor
	now         func() time.Time
}

func NewResponseManager(impact ResponseImpactAssessor, safety LockoutSafetyChecker, authorizer ResponseAuthorizer, approvals ApprovalVerifier, sessions SessionRevoker, processes ProcessTerminator, credentials CredentialExpirer, firewall FirewallBlockRequester, repository ResponseRepository, incidents IncidentEvidenceRecorder, auditor ResponseAuditor) (*ResponseManager, error) {
	if impact == nil || safety == nil || authorizer == nil || approvals == nil || sessions == nil || processes == nil || credentials == nil || firewall == nil || repository == nil || incidents == nil || auditor == nil {
		return nil, ErrInvalid
	}
	return &ResponseManager{impact: impact, safety: safety, authorizer: authorizer, approvals: approvals, sessions: sessions, processes: processes, credentials: credentials, firewall: firewall, repository: repository, incidents: incidents, auditor: auditor, now: time.Now}, nil
}

func sameProcess(left, right *ProcessIdentity) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameSessionIdentity(left, right SessionIdentity) bool {
	return left.ID == right.ID && left.Boot == right.Boot && left.StartedAt.Equal(right.StartedAt) && sameProcess(left.Leader, right.Leader)
}

func directRecoveryConflict(actor Actor, plan ResponsePlan) bool {
	if plan.Session != nil && actor.RecoverySession != "" && plan.Session.Identity.ID == actor.RecoverySession {
		return true
	}
	return plan.Process != nil && actor.RecoveryProcess != nil && plan.Process.Identity == *actor.RecoveryProcess
}

func (manager *ResponseManager) Build(ctx context.Context, actor Actor, request ResponseRequest) (ResponsePlan, error) {
	if manager == nil || ctx == nil || !actor.valid() || !validOpaque(string(request.ID)) || !request.Action.valid() || !validOpaque(string(request.IncidentID)) {
		return ResponsePlan{}, ErrInvalid
	}
	now := manager.now().UTC()
	plan := ResponsePlan{ID: request.ID, Action: request.Action, Session: request.Session, Process: request.Process, Credential: request.Credential, Firewall: request.Firewall, Grace: request.Grace, IncidentID: request.IncidentID, CreatedBy: actor.SubjectID, CreatedAt: now, ExpiresAt: now.Add(MaximumPlanLifetime), Status: PlanProposed}
	if !plan.targetValid(now) || directRecoveryConflict(actor, plan) {
		return ResponsePlan{}, ErrProtected
	}
	impact, err := manager.impact.PreviewSSHResponse(ctx, actor, request)
	if err != nil {
		return ResponsePlan{}, err
	}
	if !impact.valid(plan.Action) {
		return ResponsePlan{}, ErrProtected
	}
	plan.Impact = impact
	plan.BodyDigest, err = responsePlanDigest(plan)
	if err != nil {
		return ResponsePlan{}, err
	}
	plan.Revision = 1
	if err = manager.safety.CheckSSHResponseLockout(ctx, actor, plan); err != nil {
		return ResponsePlan{}, ErrProtected
	}
	return manager.repository.UpsertResponsePlan(ctx, plan, 0)
}

func (manager *ResponseManager) Approve(ctx context.Context, reviewer Actor, id PlanID, expectedRevision uint64, approval ApprovalEvidence, grant StepUpGrant) (ResponsePlan, error) {
	if manager == nil || ctx == nil || !reviewer.valid() || !validOpaque(string(id)) || expectedRevision == 0 {
		return ResponsePlan{}, ErrInvalid
	}
	plan, err := manager.repository.GetResponsePlan(ctx, id)
	if err != nil {
		return ResponsePlan{}, err
	}
	now := manager.now().UTC()
	if plan.Revision != expectedRevision || plan.Status != PlanProposed || !now.Before(plan.ExpiresAt) {
		return ResponsePlan{}, ErrConflict
	}
	if !grant.valid(reviewer, now) || !approval.valid(plan, now) || approval.ReviewerID != reviewer.SubjectID || manager.approvals.VerifySSHResponseApproval(ctx, plan, approval) != nil || manager.authorizer.AuthorizeSSHResponse(ctx, reviewer, plan, grant) != nil {
		return ResponsePlan{}, ErrUnauthorized
	}
	if directRecoveryConflict(reviewer, plan) || manager.safety.CheckSSHResponseLockout(ctx, reviewer, plan) != nil || manager.impact.VerifySSHResponsePreconditions(ctx, plan) != nil {
		return ResponsePlan{}, ErrProtected
	}
	plan.Approval = &approval
	plan.Status = PlanApproved
	return manager.repository.UpsertResponsePlan(ctx, plan, expectedRevision)
}

func (manager *ResponseManager) dispatch(ctx context.Context, plan ResponsePlan) (ResponseEffect, error) {
	switch plan.Action {
	case ActionRevokeSession:
		return manager.sessions.RevokeSSHSession(ctx, plan.ID, *plan.Session)
	case ActionTerminateProcess:
		return manager.processes.TerminateSSHProcess(ctx, plan.ID, *plan.Process, plan.Grace)
	case ActionExpireKey, ActionExpireGrant:
		return manager.credentials.ExpireSSHCredential(ctx, plan.ID, *plan.Credential)
	case ActionRequestFirewallBlock:
		return manager.firewall.RequestSSHFirewallBlock(ctx, plan.ID, *plan.Firewall)
	default:
		return ResponseEffect{}, ErrInvalid
	}
}

func (manager *ResponseManager) Execute(ctx context.Context, actor Actor, id PlanID, expectedRevision uint64, grant StepUpGrant) (ResponseReceipt, error) {
	if manager == nil || ctx == nil || !actor.valid() || !validOpaque(string(id)) || expectedRevision == 0 {
		return ResponseReceipt{}, ErrInvalid
	}
	if receipt, err := manager.repository.GetResponseReceipt(ctx, id); err == nil {
		return receipt, nil
	} else if !errors.Is(err, ErrNotFound) {
		return ResponseReceipt{}, err
	}
	plan, err := manager.repository.GetResponsePlan(ctx, id)
	if err != nil {
		return ResponseReceipt{}, err
	}
	now := manager.now().UTC()
	if plan.Revision != expectedRevision || plan.Status != PlanApproved && plan.Status != PlanExecuting || !now.Before(plan.ExpiresAt) || plan.Approval == nil || !plan.Approval.valid(plan, now) || plan.Firewall != nil && !plan.Firewall.ExpiresAt.After(now) {
		return ResponseReceipt{}, ErrConflict
	}
	if !grant.valid(actor, now) || manager.approvals.VerifySSHResponseApproval(ctx, plan, *plan.Approval) != nil || manager.authorizer.AuthorizeSSHResponse(ctx, actor, plan, grant) != nil {
		return ResponseReceipt{}, ErrUnauthorized
	}
	if directRecoveryConflict(actor, plan) || manager.safety.CheckSSHResponseLockout(ctx, actor, plan) != nil || manager.impact.VerifySSHResponsePreconditions(ctx, plan) != nil {
		return ResponseReceipt{}, ErrProtected
	}
	if plan.Status == PlanApproved {
		plan.Status = PlanExecuting
		plan, err = manager.repository.UpsertResponsePlan(ctx, plan, expectedRevision)
		if err != nil {
			return ResponseReceipt{}, err
		}
	}
	started := ResponseAuditRecord{PlanID: plan.ID, PlanDigest: plan.BodyDigest, IncidentID: plan.IncidentID, Action: plan.Action, ActorID: actor.SubjectID, ApprovalID: plan.Approval.ID, Outcome: "started", ReasonCode: "authorized", RecordedAt: now}
	if err = manager.auditor.RecordSSHResponseAudit(ctx, started); err != nil {
		return ResponseReceipt{}, err
	}
	effect, actionErr := manager.dispatch(ctx, plan)
	status, reason := ReceiptSucceeded, "completed"
	if actionErr != nil || !effect.successValid() {
		status, reason = ReceiptFailed, "owner_failed"
		if !effect.structuralValid() {
			effect = ResponseEffect{EvidenceDigest: digestParts("owner-failure", string(plan.ID), string(plan.Action))}
		}
		if actionErr == nil {
			actionErr = ErrIntegrity
		}
	}
	receipt := ResponseReceipt{
		ID: "receipt-" + digestParts(string(plan.ID))[:24], PlanID: plan.ID, PlanDigest: plan.BodyDigest, IncidentID: plan.IncidentID,
		Action: plan.Action, ActorID: actor.SubjectID, ApprovalID: plan.Approval.ID, Status: status, ReasonCode: reason, Effect: effect, CompletedAt: manager.now().UTC(),
	}
	receipt.Digest, err = responseReceiptDigest(receipt)
	if err != nil {
		return ResponseReceipt{}, err
	}
	if err = manager.repository.InsertResponseReceipt(ctx, receipt); err != nil {
		if existing, getErr := manager.repository.GetResponseReceipt(ctx, plan.ID); getErr == nil {
			return existing, nil
		}
		return ResponseReceipt{}, err
	}
	plan.Status = PlanSucceeded
	if status == ReceiptFailed {
		plan.Status = PlanFailed
	}
	_, planErr := manager.repository.UpsertResponsePlan(ctx, plan, plan.Revision)
	incidentErr := manager.incidents.RecordSSHIncidentEvidence(ctx, plan.IncidentID, receipt)
	auditErr := manager.auditor.RecordSSHResponseAudit(ctx, ResponseAuditRecord{
		PlanID: plan.ID, PlanDigest: plan.BodyDigest, IncidentID: plan.IncidentID, Action: plan.Action, ActorID: actor.SubjectID,
		ApprovalID: plan.Approval.ID, Outcome: string(status), ReasonCode: reason, ReceiptDigest: receipt.Digest, RecordedAt: receipt.CompletedAt,
	})
	if actionErr != nil {
		return receipt, errors.Join(actionErr, planErr, incidentErr, auditErr)
	}
	if err = errors.Join(planErr, incidentErr, auditErr); err != nil {
		return receipt, err
	}
	return receipt, nil
}
