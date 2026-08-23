package onboarding

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

const auditWriteLimit = 2 * time.Second

type Permission string

const (
	PermissionStart      Permission = "onboarding.start"
	PermissionRead       Permission = "onboarding.read"
	PermissionAnswer     Permission = "onboarding.answer"
	PermissionPlan       Permission = "onboarding.plan"
	PermissionApply      Permission = "onboarding.apply"
	PermissionCompensate Permission = "onboarding.compensate"
	PermissionFinalize   Permission = "onboarding.finalize"
)

type Authorizer interface {
	Authorize(context.Context, Actor, Scope, Permission) error
}

type StepUpObservation struct {
	PrincipalID PrincipalID `json:"principal_id"`
	SessionID   string      `json:"session_id"`
	VerifiedAt  time.Time   `json:"verified_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	Method      string      `json:"method"`
}

func (observation StepUpObservation) Validate(actor Actor, now time.Time) error {
	if observation.PrincipalID != actor.PrincipalID || observation.SessionID != actor.SessionID || observation.VerifiedAt.Location() != time.UTC || observation.ExpiresAt.Location() != time.UTC || observation.VerifiedAt.After(now) || now.Sub(observation.VerifiedAt) > MaximumStepUpAge || !observation.ExpiresAt.After(now) || observation.ExpiresAt.After(observation.VerifiedAt.Add(MaximumStepUpAge)) || !validID(observation.Method) {
		return ErrStepUpRequired
	}
	return nil
}

type RecentStepUp interface {
	Observe(context.Context, Actor) (StepUpObservation, error)
}

type PrerequisiteSource interface {
	Observe(context.Context, Scope) (PrerequisiteObservation, error)
}

type SecretPurpose string

const (
	SecretOwnerPassword    SecretPurpose = "owner_password"
	SecretRecoveryAuthority SecretPurpose = "recovery_authority"
)

// SecretReferences validates scope and purpose without returning secret bytes.
type SecretReferences interface {
	Validate(context.Context, Scope, SecretRef, SecretPurpose) error
}

type FrontierDecision string

const (
	StopBeforeIrreversible FrontierDecision = "stop_before_irreversible"
	CrossIrreversible      FrontierDecision = "cross_irreversible"
)

type DispatchRequest struct {
	PlanDigest string          `json:"plan_digest"`
	Intent     OperationIntent `json:"intent"`
	Fence      uint64          `json:"fence"`
	LeaseUntil time.Time       `json:"lease_until"`
}

func (request DispatchRequest) Validate(plan ReviewPlan, lease IntentLease, now time.Time) error {
	if plan.Validate() != nil || request.PlanDigest != plan.Digest || request.Intent.ID != lease.Record.Intent.ID || request.Intent.Validate() != nil || request.Fence != lease.Fence || request.Fence == 0 || !request.LeaseUntil.Equal(lease.Until) || !request.LeaseUntil.After(now) {
		return ErrInvalid
	}
	return nil
}

type CompensationRequest struct {
	PlanDigest string           `json:"plan_digest"`
	Intent     OperationIntent  `json:"intent"`
	Receipt    OperationReceipt `json:"receipt"`
	Fence      uint64           `json:"fence"`
	LeaseUntil time.Time        `json:"lease_until"`
}

func (request CompensationRequest) Validate(plan ReviewPlan, lease IntentLease, now time.Time) error {
	if request.PlanDigest != plan.Digest || request.Intent.ID != lease.Record.Intent.ID || lease.Record.Receipt == nil || request.Receipt.Digest != lease.Record.Receipt.Digest || request.Fence != lease.Fence || request.Fence == 0 || !request.LeaseUntil.Equal(lease.Until) || !request.LeaseUntil.After(now) || request.Receipt.Validate(plan, request.Intent, now) != nil {
		return ErrInvalid
	}
	return nil
}

// OperationDispatcher must enforce Intent.IdempotencyKey and reject a fence
// lower than the highest fence it has observed for the intent.
type OperationDispatcher interface {
	Dispatch(context.Context, DispatchRequest) (OperationReceipt, error)
	Compensate(context.Context, CompensationRequest) (CompensationReceipt, error)
}

type ManifestSigningRequest struct {
	WizardID      WizardID `json:"wizard_id"`
	Scope         Scope    `json:"scope"`
	PlanGeneration uint64  `json:"plan_generation"`
	ManifestDigest string  `json:"manifest_digest"`
	CompletedAt    time.Time `json:"completed_at"`
}

type ManifestSigner interface {
	Sign(context.Context, ManifestSigningRequest) (ManifestSignature, error)
}

type AuditAction string
type AuditPhase string
type AuditOutcome string

const (
	AuditStart      AuditAction = "start"
	AuditAnswer     AuditAction = "answer"
	AuditPlan       AuditAction = "plan"
	AuditDispatch   AuditAction = "dispatch"
	AuditCompensate AuditAction = "compensate"
	AuditFinalize   AuditAction = "finalize"

	AuditAttempt AuditPhase = "attempt"
	AuditResult  AuditPhase = "result"

	AuditStarted AuditOutcome = "started"
	AuditApplied AuditOutcome = "applied"
	AuditDenied  AuditOutcome = "denied"
	AuditFailed  AuditOutcome = "failed"
)

type AuditEvent struct {
	ID             string       `json:"id"`
	WizardID       WizardID     `json:"wizard_id"`
	Scope          Scope        `json:"scope"`
	Actor          Actor        `json:"actor"`
	Action         AuditAction  `json:"action"`
	Phase          AuditPhase   `json:"phase"`
	Outcome        AuditOutcome `json:"outcome"`
	RequestDigest  string       `json:"request_digest"`
	Revision       uint64       `json:"revision"`
	PlanGeneration uint64       `json:"plan_generation"`
	ErrorCode      string       `json:"error_code,omitempty"`
	OccurredAt     time.Time    `json:"occurred_at"`
}

func (event AuditEvent) Validate() error {
	if !validID(event.ID) || !validID(string(event.WizardID)) || event.Scope.Validate() != nil || event.Actor.Validate() != nil || !validDigest(event.RequestDigest) || event.OccurredAt.Location() != time.UTC || event.Revision == 0 {
		return ErrInvalid
	}
	switch event.Action {
	case AuditStart, AuditAnswer, AuditPlan, AuditDispatch, AuditCompensate, AuditFinalize:
	default:
		return ErrInvalid
	}
	if event.Phase == AuditAttempt {
		if event.Outcome != AuditStarted || event.ErrorCode != "" {
			return ErrInvalid
		}
	} else if event.Phase == AuditResult {
		if event.Outcome != AuditApplied && event.Outcome != AuditDenied && event.Outcome != AuditFailed || event.Outcome == AuditApplied && event.ErrorCode != "" || event.Outcome != AuditApplied && !validAuditCode(event.ErrorCode) {
			return ErrInvalid
		}
	} else {
		return ErrInvalid
	}
	return nil
}

// AuditSink returns nil only after the event is durably appended.
type AuditSink interface {
	Append(context.Context, AuditEvent) error
}

type Snapshot struct {
	Wizard Wizard                    `json:"wizard"`
	Answers map[Step]AnswerRecord     `json:"answers"`
	Plan    *ReviewPlan               `json:"plan,omitempty"`
	Intents []IntentRecord            `json:"intents,omitempty"`
}

type Service struct {
	Repository    Repository
	Authorization Authorizer
	StepUp        RecentStepUp
	Prerequisites PrerequisiteSource
	Secrets       SecretReferences
	Dispatcher    OperationDispatcher
	Signer        ManifestSigner
	Audit         AuditSink
	Now           func() time.Time
}

func (service *Service) Start(ctx context.Context, actor Actor, id WizardID, scope Scope) (Wizard, error) {
	if service.invalid() || ctx == nil || !validID(string(id)) || actor.Validate() != nil || scope.Validate() != nil {
		return Wizard{}, ErrInvalid
	}
	if service.authorize(ctx, actor, scope, PermissionStart) != nil {
		return Wizard{}, ErrUnauthorized
	}
	if service.requireStepUp(ctx, actor) != nil {
		return Wizard{}, ErrStepUpRequired
	}
	now := service.currentTime()
	observation, err := service.observe(ctx, scope, now)
	if err != nil {
		return Wizard{}, err
	}
	requestDigest, err := digestValue("start", struct {
		ID WizardID `json:"id"`; Scope Scope `json:"scope"`; PrerequisiteDigest string `json:"prerequisite_digest"`
	}{id, scope, observation.Digest})
	if err != nil {
		return Wizard{}, err
	}
	wizard := Wizard{ID: id, Scope: scope, State: StateCollecting, Revision: 1, CurrentStep: StepHostname, IrreversibleStep: StepFinalClaim, CreatedAt: now, UpdatedAt: now}
	if service.audit(ctx, wizard, actor, AuditStart, AuditAttempt, AuditStarted, requestDigest, "", now) != nil {
		return Wizard{}, ErrAuditUnavailable
	}
	err = service.Repository.Create(ctx, wizard)
	if auditErr := service.auditResult(ctx, wizard, actor, AuditStart, requestDigest, err); auditErr != nil {
		return Wizard{}, auditErr
	}
	return wizard, err
}

func (service *Service) Snapshot(ctx context.Context, actor Actor, id WizardID) (Snapshot, error) {
	if service.invalid() || ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	wizard, err := service.Repository.Wizard(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	if service.authorize(ctx, actor, wizard.Scope, PermissionRead) != nil {
		return Snapshot{}, ErrUnauthorized
	}
	answers, err := service.Repository.Answers(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{Wizard: wizard, Answers: answers}
	if wizard.PlanGeneration > 0 {
		_, plan, intents, bundleErr := service.Repository.Bundle(ctx, id, wizard.PlanGeneration, service.currentTime())
		if bundleErr != nil {
			return Snapshot{}, bundleErr
		}
		snapshot.Plan, snapshot.Intents = &plan, intents
	}
	return snapshot, nil
}

func (service *Service) SubmitAnswer(ctx context.Context, actor Actor, id WizardID, expectedRevision uint64, answer StepAnswer) (Wizard, error) {
	if service.invalid() || ctx == nil || answer.Validate() != nil {
		return Wizard{}, ErrInvalid
	}
	wizard, err := service.Repository.Wizard(ctx, id)
	if err != nil {
		return Wizard{}, err
	}
	if wizard.Revision != expectedRevision {
		return Wizard{}, ErrStale
	}
	if service.authorize(ctx, actor, wizard.Scope, PermissionAnswer) != nil {
		return Wizard{}, ErrUnauthorized
	}
	step, _ := answer.Step()
	if step == StepOwnerContact || step == StepRecoveryEnrollment || step == StepFinalClaim {
		if service.requireStepUp(ctx, actor) != nil {
			return Wizard{}, ErrStepUpRequired
		}
	}
	now := service.currentTime()
	observation, err := service.observe(ctx, wizard.Scope, now)
	if err != nil {
		return Wizard{}, err
	}
	if err = validateAnswerCapability(answer, observation); err != nil {
		return Wizard{}, err
	}
	if step == StepFinalClaim {
		plan, planErr := service.Repository.Plan(ctx, id, wizard.PlanGeneration)
		if planErr != nil {
			return Wizard{}, planErr
		}
		if exactObservation(plan, observation) != nil {
			return Wizard{}, ErrStale
		}
	}
	if step == StepOwnerContact && service.Secrets.Validate(ctx, wizard.Scope, answer.OwnerContact.PasswordCredentialRef, SecretOwnerPassword) != nil {
		return Wizard{}, ErrInvalid
	}
	if step == StepRecoveryEnrollment && service.Secrets.Validate(ctx, wizard.Scope, answer.RecoveryEnrollment.AuthorityCredentialRef, SecretRecoveryAuthority) != nil {
		return Wizard{}, ErrInvalid
	}
	record, err := NewAnswerRecord(id, expectedRevision+1, answer, actor.PrincipalID, now)
	if err != nil {
		return Wizard{}, err
	}
	if service.audit(ctx, wizard, actor, AuditAnswer, AuditAttempt, AuditStarted, record.Digest, "", now) != nil {
		return Wizard{}, ErrAuditUnavailable
	}
	updated, err := service.Repository.AppendAnswer(ctx, id, expectedRevision, record)
	auditWizard := wizard
	if err == nil {
		auditWizard = updated
	}
	if auditErr := service.auditResult(ctx, auditWizard, actor, AuditAnswer, record.Digest, err); auditErr != nil {
		return Wizard{}, auditErr
	}
	return updated, err
}

func (service *Service) BuildPlan(ctx context.Context, actor Actor, id WizardID, expectedRevision uint64) (Wizard, ReviewPlan, error) {
	if service.invalid() || ctx == nil {
		return Wizard{}, ReviewPlan{}, ErrInvalid
	}
	wizard, err := service.Repository.Wizard(ctx, id)
	if err != nil {
		return Wizard{}, ReviewPlan{}, err
	}
	if wizard.Revision != expectedRevision {
		return Wizard{}, ReviewPlan{}, ErrStale
	}
	if service.authorize(ctx, actor, wizard.Scope, PermissionPlan) != nil {
		return Wizard{}, ReviewPlan{}, ErrUnauthorized
	}
	if service.requireStepUp(ctx, actor) != nil {
		return Wizard{}, ReviewPlan{}, ErrStepUpRequired
	}
	now := service.currentTime()
	observation, err := service.observe(ctx, wizard.Scope, now)
	if err != nil {
		return Wizard{}, ReviewPlan{}, err
	}
	answers, err := service.Repository.Answers(ctx, id)
	if err != nil {
		return Wizard{}, ReviewPlan{}, err
	}
	plan, err := BuildReviewPlan(wizard, answers, observation, now)
	if err != nil {
		return Wizard{}, ReviewPlan{}, err
	}
	if service.audit(ctx, wizard, actor, AuditPlan, AuditAttempt, AuditStarted, plan.Digest, "", now) != nil {
		return Wizard{}, ReviewPlan{}, ErrAuditUnavailable
	}
	updated, err := service.Repository.SavePlan(ctx, id, expectedRevision, plan, now)
	auditWizard := wizard
	if err == nil {
		auditWizard = updated
	}
	if auditErr := service.auditResult(ctx, auditWizard, actor, AuditPlan, plan.Digest, err); auditErr != nil {
		return Wizard{}, ReviewPlan{}, auditErr
	}
	return updated, plan, err
}

func (service *Service) Resume(ctx context.Context, actor Actor, id WizardID, worker string, leaseDuration time.Duration, frontier FrontierDecision) (OperationReceipt, bool, error) {
	if service.invalid() || ctx == nil || !validID(worker) || frontier != StopBeforeIrreversible && frontier != CrossIrreversible {
		return OperationReceipt{}, false, ErrInvalid
	}
	wizard, err := service.Repository.Wizard(ctx, id)
	if err != nil {
		return OperationReceipt{}, false, err
	}
	if service.authorize(ctx, actor, wizard.Scope, PermissionApply) != nil {
		return OperationReceipt{}, false, ErrUnauthorized
	}
	if service.requireStepUp(ctx, actor) != nil {
		return OperationReceipt{}, false, ErrStepUpRequired
	}
	now := service.currentTime()
	plan, err := service.Repository.Plan(ctx, id, wizard.PlanGeneration)
	if err != nil {
		return OperationReceipt{}, false, err
	}
	observation, err := service.observe(ctx, wizard.Scope, now)
	if err != nil {
		return OperationReceipt{}, false, err
	}
	if exactObservation(plan, observation) != nil {
		return OperationReceipt{}, false, ErrStale
	}
	claimedWizard, lease, claimed, err := service.Repository.ClaimNext(ctx, id, plan.Generation, worker, leaseDuration, frontier == CrossIrreversible, now)
	if err != nil || !claimed {
		return OperationReceipt{}, false, err
	}
	request := DispatchRequest{PlanDigest: plan.Digest, Intent: lease.Record.Intent, Fence: lease.Fence, LeaseUntil: lease.Until}
	if request.Validate(plan, lease, now) != nil {
		_ = service.Repository.ReleaseDispatch(ctx, lease, service.currentTime())
		return OperationReceipt{}, false, ErrInvalid
	}
	if service.audit(ctx, claimedWizard, actor, AuditDispatch, AuditAttempt, AuditStarted, lease.Record.Intent.InputDigest, "", now) != nil {
		_ = service.Repository.ReleaseDispatch(ctx, lease, service.currentTime())
		return OperationReceipt{}, false, ErrAuditUnavailable
	}
	dispatchContext, cancel := context.WithDeadline(ctx, lease.Until)
	receipt, dispatchErr := service.Dispatcher.Dispatch(dispatchContext, request)
	cancel()
	finished := service.currentTime()
	if dispatchErr != nil || receipt.Validate(plan, lease.Record.Intent, finished) != nil || receipt.Fence != lease.Fence {
		if dispatchErr == nil {
			dispatchErr = ErrStale
		}
		if auditErr := service.auditResult(ctx, claimedWizard, actor, AuditDispatch, lease.Record.Intent.InputDigest, dispatchErr); auditErr != nil {
			return OperationReceipt{}, false, auditErr
		}
		_ = service.Repository.ReleaseDispatch(ctx, lease, finished)
		return OperationReceipt{}, false, dispatchErr
	}
	if auditErr := service.auditResult(ctx, claimedWizard, actor, AuditDispatch, lease.Record.Intent.InputDigest, nil); auditErr != nil {
		_ = service.Repository.ReleaseDispatch(ctx, lease, finished)
		return OperationReceipt{}, false, auditErr
	}
	if err = service.Repository.RecordReceipt(ctx, plan, lease, receipt, finished); err != nil {
		return OperationReceipt{}, false, err
	}
	return receipt, true, nil
}

func (service *Service) Compensate(ctx context.Context, actor Actor, id WizardID, worker string, leaseDuration time.Duration) (CompensationReceipt, bool, error) {
	if service.invalid() || ctx == nil || !validID(worker) {
		return CompensationReceipt{}, false, ErrInvalid
	}
	wizard, err := service.Repository.Wizard(ctx, id)
	if err != nil {
		return CompensationReceipt{}, false, err
	}
	if service.authorize(ctx, actor, wizard.Scope, PermissionCompensate) != nil {
		return CompensationReceipt{}, false, ErrUnauthorized
	}
	if service.requireStepUp(ctx, actor) != nil {
		return CompensationReceipt{}, false, ErrStepUpRequired
	}
	now := service.currentTime()
	plan, err := service.Repository.Plan(ctx, id, wizard.PlanGeneration)
	if err != nil {
		return CompensationReceipt{}, false, err
	}
	observation, err := service.observe(ctx, wizard.Scope, now)
	if err != nil {
		return CompensationReceipt{}, false, err
	}
	if exactObservation(plan, observation) != nil {
		return CompensationReceipt{}, false, ErrStale
	}
	claimedWizard, lease, claimed, err := service.Repository.ClaimCompensation(ctx, id, plan.Generation, worker, leaseDuration, now)
	if err != nil || !claimed {
		return CompensationReceipt{}, false, err
	}
	request := CompensationRequest{PlanDigest: plan.Digest, Intent: lease.Record.Intent, Receipt: *lease.Record.Receipt, Fence: lease.Fence, LeaseUntil: lease.Until}
	if request.Validate(plan, lease, now) != nil {
		_ = service.Repository.ReleaseCompensation(ctx, lease, service.currentTime())
		return CompensationReceipt{}, false, ErrInvalid
	}
	if service.audit(ctx, claimedWizard, actor, AuditCompensate, AuditAttempt, AuditStarted, lease.Record.Intent.InputDigest, "", now) != nil {
		_ = service.Repository.ReleaseCompensation(ctx, lease, service.currentTime())
		return CompensationReceipt{}, false, ErrAuditUnavailable
	}
	dispatchContext, cancel := context.WithDeadline(ctx, lease.Until)
	receipt, compensationErr := service.Dispatcher.Compensate(dispatchContext, request)
	cancel()
	finished := service.currentTime()
	if compensationErr != nil || receipt.Validate(plan, lease.Record.Intent, *lease.Record.Receipt, finished) != nil || receipt.Fence != lease.Fence {
		if compensationErr == nil {
			compensationErr = ErrStale
		}
		if auditErr := service.auditResult(ctx, claimedWizard, actor, AuditCompensate, lease.Record.Intent.InputDigest, compensationErr); auditErr != nil {
			return CompensationReceipt{}, false, auditErr
		}
		_ = service.Repository.ReleaseCompensation(ctx, lease, finished)
		return CompensationReceipt{}, false, compensationErr
	}
	if auditErr := service.auditResult(ctx, claimedWizard, actor, AuditCompensate, lease.Record.Intent.InputDigest, nil); auditErr != nil {
		_ = service.Repository.ReleaseCompensation(ctx, lease, finished)
		return CompensationReceipt{}, false, auditErr
	}
	if err = service.Repository.RecordCompensation(ctx, plan, lease, receipt, finished); err != nil {
		return CompensationReceipt{}, false, err
	}
	return receipt, true, nil
}

func (service *Service) Finalize(ctx context.Context, actor Actor, id WizardID) (Wizard, CompletionManifest, error) {
	if service.invalid() || ctx == nil {
		return Wizard{}, CompletionManifest{}, ErrInvalid
	}
	wizard, err := service.Repository.Wizard(ctx, id)
	if err != nil {
		return Wizard{}, CompletionManifest{}, err
	}
	if service.authorize(ctx, actor, wizard.Scope, PermissionFinalize) != nil {
		return Wizard{}, CompletionManifest{}, ErrUnauthorized
	}
	if service.requireStepUp(ctx, actor) != nil {
		return Wizard{}, CompletionManifest{}, ErrStepUpRequired
	}
	now := service.currentTime()
	wizard, plan, records, err := service.Repository.Bundle(ctx, id, wizard.PlanGeneration, now)
	if err != nil {
		return Wizard{}, CompletionManifest{}, err
	}
	observation, err := service.observe(ctx, wizard.Scope, now)
	if err != nil {
		return Wizard{}, CompletionManifest{}, err
	}
	if exactObservation(plan, observation) != nil || wizard.State != StateApplying || !wizard.IrreversibleCrossed {
		return Wizard{}, CompletionManifest{}, ErrStale
	}
	receipts := make([]ManifestReceipt, 0, len(records))
	for index, record := range records {
		if !plan.Intents[index].Mandatory || record.State != IntentObserved || record.Receipt == nil || record.Receipt.Validate(plan, record.Intent, now) != nil {
			return Wizard{}, CompletionManifest{}, ErrIncomplete
		}
		receipts = append(receipts, ManifestReceipt{Step: record.Intent.Step, IntentID: record.Intent.ID, ReceiptDigest: record.Receipt.Digest, ObservedGeneration: record.Receipt.ObservedGeneration})
	}
	manifest := CompletionManifest{
		WizardID: id, Scope: wizard.Scope, PlanGeneration: plan.Generation, PlanDigest: plan.Digest,
		PrerequisiteGeneration: plan.PrerequisiteGeneration, PrerequisiteDigest: plan.PrerequisiteDigest,
		Answers: append([]AnswerBinding(nil), plan.Answers...), Receipts: receipts,
		IrreversibleFrontier: StepFinalClaim, FrontierCrossedAt: wizard.IrreversibleCrossedAt, CompletedAt: now,
	}
	manifest.Digest, err = manifest.UnsignedDigest()
	if err != nil {
		return Wizard{}, CompletionManifest{}, err
	}
	if service.audit(ctx, wizard, actor, AuditFinalize, AuditAttempt, AuditStarted, manifest.Digest, "", now) != nil {
		return Wizard{}, CompletionManifest{}, ErrAuditUnavailable
	}
	manifest.Signature, err = service.Signer.Sign(ctx, ManifestSigningRequest{WizardID: id, Scope: wizard.Scope, PlanGeneration: plan.Generation, ManifestDigest: manifest.Digest, CompletedAt: manifest.CompletedAt})
	if err != nil || manifest.Validate(plan) != nil {
		if err == nil {
			err = ErrInvalid
		}
		if auditErr := service.auditResult(ctx, wizard, actor, AuditFinalize, manifest.Digest, err); auditErr != nil {
			return Wizard{}, CompletionManifest{}, auditErr
		}
		return Wizard{}, CompletionManifest{}, err
	}
	updated, err := service.Repository.CommitManifest(ctx, wizard.Revision, manifest)
	auditWizard := wizard
	if err == nil {
		auditWizard = updated
	}
	if auditErr := service.auditResult(ctx, auditWizard, actor, AuditFinalize, manifest.Digest, err); auditErr != nil {
		return Wizard{}, CompletionManifest{}, auditErr
	}
	return updated, manifest, err
}

func (service *Service) invalid() bool {
	return service == nil || service.Repository.DB == nil || nilInterface(service.Authorization) || nilInterface(service.StepUp) || nilInterface(service.Prerequisites) || nilInterface(service.Secrets) || nilInterface(service.Dispatcher) || nilInterface(service.Signer) || nilInterface(service.Audit)
}

func (service *Service) authorize(ctx context.Context, actor Actor, scope Scope, permission Permission) error {
	if actor.Validate() != nil || scope.Validate() != nil || actor.TenantID != scope.TenantID || service.Authorization.Authorize(ctx, actor, scope, permission) != nil {
		return ErrUnauthorized
	}
	return nil
}

func (service *Service) requireStepUp(ctx context.Context, actor Actor) error {
	observation, err := service.StepUp.Observe(ctx, actor)
	if err != nil || observation.Validate(actor, service.currentTime()) != nil {
		return ErrStepUpRequired
	}
	return nil
}

func (service *Service) observe(ctx context.Context, scope Scope, now time.Time) (PrerequisiteObservation, error) {
	observation, err := service.Prerequisites.Observe(ctx, scope)
	if err != nil {
		return PrerequisiteObservation{}, err
	}
	if err = observation.Validate(scope.NodeID, now); err != nil {
		return PrerequisiteObservation{}, err
	}
	return observation, nil
}

func exactObservation(plan ReviewPlan, observation PrerequisiteObservation) error {
	if observation.Generation != plan.PrerequisiteGeneration || observation.Digest != plan.PrerequisiteDigest || observation.Tuple != plan.Tuple {
		return ErrStale
	}
	return nil
}

func (service *Service) audit(ctx context.Context, wizard Wizard, actor Actor, action AuditAction, phase AuditPhase, outcome AuditOutcome, requestDigest, code string, at time.Time) error {
	event := AuditEvent{WizardID: wizard.ID, Scope: wizard.Scope, Actor: actor, Action: action, Phase: phase, Outcome: outcome, RequestDigest: requestDigest, Revision: wizard.Revision, PlanGeneration: wizard.PlanGeneration, ErrorCode: code, OccurredAt: at.UTC()}
	encoded, err := json.Marshal(event)
	if err != nil {
		return ErrAuditUnavailable
	}
	event.ID = "audit-" + domainDigest("audit-event", encoded)[:40]
	if event.Validate() != nil || service.Audit.Append(ctx, event) != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (service *Service) auditResult(ctx context.Context, wizard Wizard, actor Actor, action AuditAction, requestDigest string, operationErr error) error {
	outcome, code := AuditApplied, ""
	if operationErr != nil {
		outcome, code = AuditFailed, errorCode(operationErr)
		if errors.Is(operationErr, ErrUnauthorized) || errors.Is(operationErr, ErrStepUpRequired) || errors.Is(operationErr, ErrIrreversible) {
			outcome = AuditDenied
		}
	}
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteLimit)
	defer cancel()
	return service.audit(auditContext, wizard, actor, action, AuditResult, outcome, requestDigest, code, service.currentTime())
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrStepUpRequired):
		return "step_up_required"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrStale):
		return "stale"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrIncomplete):
		return "incomplete"
	case errors.Is(err, ErrIrreversible):
		return "irreversible"
	default:
		return "failed"
	}
}

func validAuditCode(code string) bool {
	switch code {
	case "unauthorized", "step_up_required", "unsupported", "stale", "conflict", "incomplete", "irreversible", "failed":
		return true
	default:
		return false
	}
}

func digestValue(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return domainDigest(domain, encoded), nil
}

func (service *Service) currentTime() time.Time {
	if service != nil && service.Now != nil {
		return service.Now().UTC()
	}
	return time.Now().UTC()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
