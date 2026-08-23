package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

type SpamCapability string

const (
	SpamCapabilityPolicyMutate       SpamCapability = "spam.policy.mutate"
	SpamCapabilityPolicyInspect      SpamCapability = "spam.policy.inspect"
	SpamCapabilityPolicyActivate     SpamCapability = "spam.policy.activate"
	SpamCapabilityQuarantineIngest   SpamCapability = "spam.quarantine.ingest"
	SpamCapabilityQuarantineInspect  SpamCapability = "spam.quarantine.inspect"
	SpamCapabilityQuarantineBody     SpamCapability = "spam.quarantine.body"
	SpamCapabilityQuarantineRelease  SpamCapability = "spam.quarantine.release"
	SpamCapabilityQuarantineDeliver  SpamCapability = "spam.quarantine.deliver"
	SpamCapabilityQuarantineDelete   SpamCapability = "spam.quarantine.delete"
	SpamCapabilityFalsePositive      SpamCapability = "spam.quarantine.false_positive"
	SpamCapabilityHealth             SpamCapability = "spam.health.inspect"
)

type SpamStepUpProof struct {
	ProofID    string
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

type SpamAuthorizationRequest struct {
	ActorID    string
	Capability SpamCapability
	Scope      SpamScope
	ItemID     SpamQuarantineID
	StepUp     *SpamStepUpProof
}

type SpamAuthorizer interface {
	AuthorizeSpam(context.Context, SpamAuthorizationRequest) error
}

type SpamDomainBinding struct {
	TenantID   string
	DomainID   DomainID
	DomainName string
	Generation uint64
	Enabled    bool
}

type SpamMailboxBinding struct {
	TenantID   string
	DomainID   DomainID
	MailboxID  MailboxID
	Address    Address
	Generation uint64
	Enabled    bool
}

// SpamDirectory is the canonical ownership authority. Ambiguous results must
// return an error rather than selecting one owner.
type SpamDirectory interface {
	ResolveSpamDomain(context.Context, string, DomainID) (SpamDomainBinding, error)
	ResolveSpamMailbox(context.Context, string, DomainID, MailboxID) (SpamMailboxBinding, error)
}

type SpamActivationReceipt struct {
	GenerationID      string
	PolicyGeneration  uint64
	SnapshotDigest    string
	ArtifactDigest    string
	PreviousID        string
	ValidationDigest  string
	ReloadDigest      string
	ProbeDigest       string
	RolledBack        bool
	RollbackDigest    string
	ObservedAt        time.Time
}

type SpamRuntime interface {
	ApplySpamGeneration(context.Context, SpamConfigGeneration) (SpamActivationReceipt, error)
	SpamStatus(context.Context, SpamConfigGeneration) (SpamHealthStatus, error)
}

type SpamAuditEvent struct {
	OperationID        string
	ActorID            string
	Capability         SpamCapability
	Scope              SpamScope
	ItemID             SpamQuarantineID
	ObjectID           SpamObjectID
	ExpectedGeneration uint64
	ResultGeneration   uint64
	RequestDigest      string
	ResultDigest       string
	Outcome            string
	OccurredAt         time.Time
}

type SpamAuditSink interface {
	RecordSpamEvent(context.Context, SpamAuditEvent) error
}

type SpamService struct {
	Repository SpamRepository
	Directory  SpamDirectory
	Authorizer SpamAuthorizer
	Audit      SpamAuditSink
	Runtime    SpamRuntime
	Artifacts  SpamQuarantineArtifactStore
	Delivery   SpamQuarantineDelivery
	Learner    SpamLocalLearner
	Now        func() time.Time
}

func NewSpamService(repository SpamRepository, directory SpamDirectory, authorizer SpamAuthorizer, audit SpamAuditSink, runtime SpamRuntime, artifacts SpamQuarantineArtifactStore, delivery SpamQuarantineDelivery, learner SpamLocalLearner, now func() time.Time) (*SpamService, error) {
	if repository == nil || directory == nil || authorizer == nil || audit == nil || runtime == nil || artifacts == nil || delivery == nil || learner == nil {
		return nil, ErrInvalidCommand
	}
	if now == nil {
		now = time.Now
	}
	return &SpamService{Repository: repository, Directory: directory, Authorizer: authorizer, Audit: audit, Runtime: runtime, Artifacts: artifacts, Delivery: delivery, Learner: learner, Now: now}, nil
}

type SpamPolicyChangeRequest struct {
	OperationID       string
	ActorID           string
	Scope             SpamScope
	DomainGeneration  uint64
	MailboxGeneration uint64
	ExpectedGeneration uint64
	ExpectedRevision  uint64
	Thresholds        SpamThresholds
	Allow             []SpamIdentity
	Deny              []SpamIdentity
	SecurityControls  SpamSecurityControl
	Learning          SpamLearningPolicy
	RetentionDays     uint16
	EffectiveAt       time.Time
}

func (service *SpamService) PutPolicy(ctx context.Context, request SpamPolicyChangeRequest) (SpamPolicyCASReceipt, SpamActivationReceipt, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(request.OperationID) || !validOpaque(request.ActorID) || request.Scope.Validate() != nil || request.Scope.Kind == SpamScopeGlobal && (request.DomainGeneration != 0 || request.MailboxGeneration != 0) || request.Scope.Kind == SpamScopeDomain && (request.DomainGeneration == 0 || request.MailboxGeneration != 0) || request.Scope.Kind == SpamScopeMailbox && (request.DomainGeneration == 0 || request.MailboxGeneration == 0) || request.EffectiveAt.IsZero() == false && !canonicalSpamTime(request.EffectiveAt) {
		if err != nil {
			return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, err
		}
		return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, ErrInvalidCommand
	}
	if err := service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: request.ActorID, Capability: SpamCapabilityPolicyMutate, Scope: request.Scope}); err != nil {
		return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, err
	}
	if err := service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: request.ActorID, Capability: SpamCapabilityPolicyActivate, Scope: request.Scope}); err != nil {
		return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, err
	}
	now := service.now()
	if request.EffectiveAt.IsZero() {
		request.EffectiveAt = now
	} else if request.EffectiveAt.After(now) {
		return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, ErrInvalidCommand
	}
	policy := SpamPolicy{Scope: request.Scope, Revision: request.ExpectedRevision + 1, Generation: request.ExpectedGeneration + 1, Thresholds: request.Thresholds, Allow: request.Allow, Deny: request.Deny, SecurityControls: request.SecurityControls, Learning: request.Learning, RetentionDays: request.RetentionDays, EffectiveAt: request.EffectiveAt, CreatedAt: now, UpdatedAt: now}
	var current SpamPolicySnapshot
	if request.ExpectedGeneration != 0 {
		var err error
		current, err = service.Repository.SpamSnapshot(ctx, request.Scope.TenantID)
		if err != nil {
			return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, err
		}
		if current.Generation != request.ExpectedGeneration {
			return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, ErrConflict
		}
		for _, existing := range current.Policies {
			if existing.Scope == request.Scope {
				if existing.Revision != request.ExpectedRevision {
					return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, ErrConflict
				}
				policy.CreatedAt = existing.CreatedAt
				break
			}
		}
	}
	if err := service.bindPolicy(ctx, &policy, current, request.DomainGeneration, request.MailboxGeneration); err != nil {
		return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, err
	}
	requestDigest := spamRequestDigest(struct {
		OperationID string
		ActorID     string
		Policy      SpamPolicy
	}{request.OperationID, request.ActorID, policy})
	snapshot, policyReceipt, err := service.Repository.PutSpamPolicy(ctx, policy, request.ExpectedGeneration, request.ExpectedRevision)
	if err != nil {
		return SpamPolicyCASReceipt{}, SpamActivationReceipt{}, err
	}
	generation, err := CompileSpamGeneration(snapshot)
	if err != nil {
		auditErr := service.audit(ctx, SpamAuditEvent{OperationID: request.OperationID, ActorID: request.ActorID, Capability: SpamCapabilityPolicyMutate, Scope: request.Scope, ExpectedGeneration: request.ExpectedGeneration, ResultGeneration: policyReceipt.ResultGeneration, RequestDigest: requestDigest, ResultDigest: policyReceipt.SnapshotDigest, Outcome: "compile_failed", OccurredAt: now})
		return policyReceipt, SpamActivationReceipt{}, errors.Join(err, auditErr)
	}
	activation, applyErr := service.Runtime.ApplySpamGeneration(ctx, generation)
	outcome := "activated"
	if applyErr != nil {
		outcome = "stored_runtime_preserved"
	}
	auditErr := service.audit(ctx, SpamAuditEvent{OperationID: request.OperationID, ActorID: request.ActorID, Capability: SpamCapabilityPolicyMutate, Scope: request.Scope, ExpectedGeneration: request.ExpectedGeneration, ResultGeneration: policyReceipt.ResultGeneration, RequestDigest: requestDigest, ResultDigest: generation.ArtifactDigest, Outcome: outcome, OccurredAt: now})
	return policyReceipt, activation, errors.Join(applyErr, auditErr)
}

func (service *SpamService) InspectPolicy(ctx context.Context, actorID string, scope SpamScope) (SpamPolicy, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(actorID) || scope.Validate() != nil {
		if err != nil {
			return SpamPolicy{}, err
		}
		return SpamPolicy{}, ErrInvalidCommand
	}
	if err := service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityPolicyInspect, Scope: scope}); err != nil {
		return SpamPolicy{}, err
	}
	snapshot, err := service.Repository.SpamSnapshot(ctx, scope.TenantID)
	if err != nil {
		return SpamPolicy{}, err
	}
	for _, policy := range snapshot.Policies {
		if policy.Scope == scope {
			if err = service.verifyPolicyOwnership(ctx, policy); err != nil {
				return SpamPolicy{}, err
			}
			return policy, nil
		}
	}
	return SpamPolicy{}, ErrNotFound
}

func (service *SpamService) ListPolicies(ctx context.Context, actorID string, filter SpamPolicyListFilter) ([]SpamPolicy, SpamScope, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(actorID) || !validOpaque(filter.TenantID) {
		if err != nil {
			return nil, SpamScope{}, err
		}
		return nil, SpamScope{}, ErrInvalidCommand
	}
	scope := SpamScope{TenantID: filter.TenantID, Kind: SpamScopeGlobal}
	if err := service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityPolicyInspect, Scope: scope}); err != nil {
		return nil, SpamScope{}, err
	}
	policies, cursor, err := service.Repository.ListSpamPolicies(ctx, filter)
	if err != nil {
		return nil, SpamScope{}, err
	}
	for _, policy := range policies {
		if err = service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityPolicyInspect, Scope: policy.Scope}); err != nil {
			return nil, SpamScope{}, err
		}
		if err = service.verifyPolicyOwnership(ctx, policy); err != nil {
			return nil, SpamScope{}, err
		}
	}
	return policies, cursor, nil
}

func (service *SpamService) ActivatePolicyGeneration(ctx context.Context, operationID, actorID, tenantID string, generation uint64) (SpamActivationReceipt, error) {
	scope := SpamScope{TenantID: tenantID, Kind: SpamScopeGlobal}
	if err := service.ready(ctx); err != nil || !validOpaque(operationID) || !validOpaque(actorID) || scope.Validate() != nil || generation == 0 {
		if err != nil {
			return SpamActivationReceipt{}, err
		}
		return SpamActivationReceipt{}, ErrInvalidCommand
	}
	if err := service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityPolicyActivate, Scope: scope}); err != nil {
		return SpamActivationReceipt{}, err
	}
	snapshot, err := service.Repository.SpamSnapshotGeneration(ctx, tenantID, generation)
	if err != nil {
		return SpamActivationReceipt{}, err
	}
	compiled, err := CompileSpamGeneration(snapshot)
	if err != nil {
		return SpamActivationReceipt{}, err
	}
	requestDigest := spamRequestDigest(struct {
		OperationID string
		ActorID     string
		TenantID    string
		Generation  uint64
	}{operationID, actorID, tenantID, generation})
	receipt, applyErr := service.Runtime.ApplySpamGeneration(ctx, compiled)
	outcome := "activated"
	if applyErr != nil {
		outcome = "runtime_preserved"
	}
	auditErr := service.audit(ctx, SpamAuditEvent{OperationID: operationID, ActorID: actorID, Capability: SpamCapabilityPolicyActivate, Scope: scope, ExpectedGeneration: generation, ResultGeneration: generation, RequestDigest: requestDigest, ResultDigest: compiled.ArtifactDigest, Outcome: outcome, OccurredAt: service.now()})
	return receipt, errors.Join(applyErr, auditErr)
}

func (service *SpamService) Health(ctx context.Context, actorID, tenantID string) (SpamHealthStatus, error) {
	scope := SpamScope{TenantID: tenantID, Kind: SpamScopeGlobal}
	if err := service.ready(ctx); err != nil || !validOpaque(actorID) || scope.Validate() != nil {
		if err != nil {
			return SpamHealthStatus{}, err
		}
		return SpamHealthStatus{}, ErrInvalidCommand
	}
	if err := service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityHealth, Scope: scope}); err != nil {
		return SpamHealthStatus{}, err
	}
	snapshot, err := service.Repository.SpamSnapshot(ctx, tenantID)
	if err != nil {
		return SpamHealthStatus{}, err
	}
	generation, err := CompileSpamGeneration(snapshot)
	if err != nil {
		return SpamHealthStatus{}, err
	}
	return service.Runtime.SpamStatus(ctx, generation)
}

type SpamQuarantineCall struct {
	OperationID        string
	ActorID            string
	TenantID           string
	DomainID           DomainID
	MailboxID          MailboxID
	ItemID             SpamQuarantineID
	ObjectID           SpamObjectID
	ExpectedGeneration uint64
	EffectKey          string
	StepUp             *SpamStepUpProof
	ReasonCode         string
}

func (service *SpamService) RegisterQuarantine(ctx context.Context, operationID, actorID string, item SpamQuarantineItem) error {
	if err := service.ready(ctx); err != nil || !validOpaque(operationID) || !validOpaque(actorID) || item.Validate() != nil {
		if err != nil {
			return err
		}
		return ErrInvalidCommand
	}
	scope := SpamScope{TenantID: item.TenantID, Kind: SpamScopeMailbox, DomainID: item.DomainID, MailboxID: item.MailboxID}
	if err := service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityQuarantineIngest, Scope: scope, ItemID: item.ID}); err != nil {
		return err
	}
	if err := service.verifyQuarantineOwnership(ctx, item); err != nil {
		return err
	}
	snapshot, err := service.Repository.SpamSnapshot(ctx, item.TenantID)
	if err != nil {
		return err
	}
	policy, err := spamEffectivePolicy(snapshot, item)
	if err != nil {
		return err
	}
	maximumRetention := item.CreatedAt.Add(time.Duration(policy.RetentionDays) * 24 * time.Hour)
	if item.PolicyGeneration != snapshot.Generation || item.UpdatedAt != item.CreatedAt || item.CreatedAt.After(service.now()) || item.RetainUntil.After(maximumRetention) {
		return ErrConflict
	}
	if err := service.Repository.RegisterSpamQuarantine(ctx, item); err != nil {
		return err
	}
	return service.audit(ctx, SpamAuditEvent{OperationID: operationID, ActorID: actorID, Capability: SpamCapabilityQuarantineIngest, Scope: scope, ItemID: item.ID, ObjectID: item.ObjectID, ResultGeneration: item.Generation, RequestDigest: item.ObjectDigest, ResultDigest: item.ObjectDigest, Outcome: "held", OccurredAt: service.now()})
}

func (service *SpamService) InspectQuarantine(ctx context.Context, actorID, tenantID string, itemID SpamQuarantineID) (SpamQuarantineItem, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(actorID) || !validOpaque(tenantID) || !validSpamID(string(itemID), "spamq_") {
		if err != nil {
			return SpamQuarantineItem{}, err
		}
		return SpamQuarantineItem{}, ErrInvalidCommand
	}
	scope := SpamScope{TenantID: tenantID, Kind: SpamScopeGlobal}
	if err := service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityQuarantineInspect, Scope: scope, ItemID: itemID}); err != nil {
		return SpamQuarantineItem{}, err
	}
	item, err := service.Repository.SpamQuarantine(ctx, tenantID, itemID)
	if err != nil {
		return SpamQuarantineItem{}, err
	}
	itemScope := SpamScope{TenantID: item.TenantID, Kind: SpamScopeMailbox, DomainID: item.DomainID, MailboxID: item.MailboxID}
	if err = service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityQuarantineInspect, Scope: itemScope, ItemID: item.ID}); err != nil {
		return SpamQuarantineItem{}, err
	}
	if err = service.verifyQuarantineOwnership(ctx, item); err != nil {
		return SpamQuarantineItem{}, err
	}
	return item, nil
}

func (service *SpamService) ListQuarantine(ctx context.Context, actorID string, filter SpamQuarantineFilter) ([]SpamQuarantineItem, SpamQuarantineID, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(actorID) || !validOpaque(filter.TenantID) {
		if err != nil {
			return nil, "", err
		}
		return nil, "", ErrInvalidCommand
	}
	scope := SpamScope{TenantID: filter.TenantID, Kind: SpamScopeGlobal}
	if err := service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityQuarantineInspect, Scope: scope}); err != nil {
		return nil, "", err
	}
	items, cursor, err := service.Repository.ListSpamQuarantine(ctx, filter)
	if err != nil {
		return nil, "", err
	}
	for _, item := range items {
		itemScope := SpamScope{TenantID: item.TenantID, Kind: SpamScopeMailbox, DomainID: item.DomainID, MailboxID: item.MailboxID}
		if err = service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: actorID, Capability: SpamCapabilityQuarantineInspect, Scope: itemScope, ItemID: item.ID}); err != nil {
			return nil, "", err
		}
		if err = service.verifyQuarantineOwnership(ctx, item); err != nil {
			return nil, "", err
		}
	}
	return items, cursor, nil
}

func (service *SpamService) AccessQuarantine(ctx context.Context, call SpamQuarantineCall, destination io.Writer) (SpamQuarantineReceipt, error) {
	if destination == nil {
		return SpamQuarantineReceipt{}, ErrInvalidCommand
	}
	item, claim, err := service.prepareQuarantine(ctx, call, SpamQuarantineAccess, SpamCapabilityQuarantineBody, true, 0)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if claim.Completed {
		return claim, nil
	}
	handle, err := openSpamArtifact(ctx, service.Artifacts, item)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	defer handle.Close()
	_, digest, err := streamSpamArtifact(ctx, handle, destination, spamArtifactIdentity(item))
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	effectDigest := spamRequestDigest(struct{ OperationID, Digest string }{call.OperationID, digest})
	return service.finishQuarantine(ctx, call, item, claim, digest, effectDigest, SpamCapabilityQuarantineBody)
}

func (service *SpamService) ReleaseQuarantine(ctx context.Context, call SpamQuarantineCall) (SpamQuarantineReceipt, error) {
	return service.deliverQuarantine(ctx, call, SpamQuarantineRelease, SpamCapabilityQuarantineRelease)
}

func (service *SpamService) DeliverQuarantine(ctx context.Context, call SpamQuarantineCall) (SpamQuarantineReceipt, error) {
	return service.deliverQuarantine(ctx, call, SpamQuarantineDeliver, SpamCapabilityQuarantineDeliver)
}

func (service *SpamService) DeleteQuarantine(ctx context.Context, call SpamQuarantineCall) (SpamQuarantineReceipt, error) {
	item, claim, err := service.prepareQuarantine(ctx, call, SpamQuarantineDelete, SpamCapabilityQuarantineDelete, true, 0)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if claim.Completed {
		return claim, nil
	}
	effect, err := service.Artifacts.TombstoneExact(ctx, spamArtifactIdentity(item), call.EffectKey, item.EvidenceHold)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if effect.ObjectID != item.ObjectID || effect.EffectKey != call.EffectKey || effect.ObjectDigest != item.ObjectDigest || !validSpamDigest(effect.EffectDigest) || item.EvidenceHold && !effect.EvidencePreserved {
		return SpamQuarantineReceipt{}, ErrInvalidReceipt
	}
	return service.finishQuarantine(ctx, call, item, claim, item.ObjectDigest, effect.EffectDigest, SpamCapabilityQuarantineDelete)
}

func (service *SpamService) FalsePositive(ctx context.Context, call SpamQuarantineCall) (SpamQuarantineReceipt, error) {
	if !validSpamFeedbackReason(call.ReasonCode) {
		return SpamQuarantineReceipt{}, ErrInvalidCommand
	}
	if err := service.authorizeQuarantineCall(ctx, call, SpamCapabilityFalsePositive, false); err != nil {
		return SpamQuarantineReceipt{}, err
	}
	item, err := service.loadScopedQuarantine(ctx, call)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if item.Malware {
		return SpamQuarantineReceipt{}, ErrUnauthorized
	}
	policy, err := service.effectivePolicy(ctx, item)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	item, claim, err := service.beginLoadedQuarantine(ctx, call, item, SpamQuarantineFalsePositive, SpamCapabilityFalsePositive, policy.Learning.MaxFeedbackPerHour)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if claim.Completed {
		return claim, nil
	}
	handle, err := openSpamArtifact(ctx, service.Artifacts, item)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	defer handle.Close()
	request := SpamBodyEffectRequest{EffectKey: call.EffectKey, ActorID: call.ActorID, Action: SpamQuarantineFalsePositive, Identity: spamArtifactIdentity(item)}
	stage, err := service.Learner.BeginFalsePositive(ctx, request, SpamLearningAttribution{ActorID: call.ActorID, OperationID: call.OperationID, ReasonCode: call.ReasonCode, PolicyGeneration: item.PolicyGeneration})
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	effect, err := stageSpamArtifact(ctx, handle, stage, request.Identity)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if effect.EffectKey != call.EffectKey || effect.Action != SpamQuarantineFalsePositive {
		return SpamQuarantineReceipt{}, ErrInvalidReceipt
	}
	return service.finishQuarantine(ctx, call, item, claim, effect.ArtifactDigest, effect.EffectDigest, SpamCapabilityFalsePositive)
}

func (service *SpamService) deliverQuarantine(ctx context.Context, call SpamQuarantineCall, action SpamQuarantineAction, capability SpamCapability) (SpamQuarantineReceipt, error) {
	item, claim, err := service.prepareQuarantine(ctx, call, action, capability, true, 0)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if claim.Completed {
		return claim, nil
	}
	handle, err := openSpamArtifact(ctx, service.Artifacts, item)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	defer handle.Close()
	request := SpamBodyEffectRequest{EffectKey: call.EffectKey, ActorID: call.ActorID, Action: action, Identity: spamArtifactIdentity(item)}
	stage, err := service.Delivery.BeginDelivery(ctx, request)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	effect, err := stageSpamArtifact(ctx, handle, stage, request.Identity)
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	if effect.EffectKey != call.EffectKey || effect.Action != action {
		return SpamQuarantineReceipt{}, ErrInvalidReceipt
	}
	return service.finishQuarantine(ctx, call, item, claim, effect.ArtifactDigest, effect.EffectDigest, capability)
}

func (service *SpamService) prepareQuarantine(ctx context.Context, call SpamQuarantineCall, action SpamQuarantineAction, capability SpamCapability, stepUp bool, maxFeedback uint16) (SpamQuarantineItem, SpamQuarantineReceipt, error) {
	if err := service.authorizeQuarantineCall(ctx, call, capability, stepUp); err != nil {
		return SpamQuarantineItem{}, SpamQuarantineReceipt{}, err
	}
	item, err := service.loadScopedQuarantine(ctx, call)
	if err != nil {
		return SpamQuarantineItem{}, SpamQuarantineReceipt{}, err
	}
	return service.beginLoadedQuarantine(ctx, call, item, action, capability, maxFeedback)
}

func (service *SpamService) beginLoadedQuarantine(ctx context.Context, call SpamQuarantineCall, item SpamQuarantineItem, action SpamQuarantineAction, capability SpamCapability, maxFeedback uint16) (SpamQuarantineItem, SpamQuarantineReceipt, error) {
	scope := SpamScope{TenantID: call.TenantID, Kind: SpamScopeMailbox, DomainID: call.DomainID, MailboxID: call.MailboxID}
	if service.now().After(item.RetainUntil) && action != SpamQuarantineDelete {
		return SpamQuarantineItem{}, SpamQuarantineReceipt{}, ErrNotFound
	}
	requestDigest := spamRequestDigest(struct {
		Call   SpamQuarantineCall
		Action SpamQuarantineAction
	}{call, action})
	claim := SpamQuarantineClaim{OperationID: call.OperationID, RequestDigest: requestDigest, ActorID: call.ActorID, TenantID: call.TenantID, DomainID: call.DomainID, MailboxID: call.MailboxID, ItemID: call.ItemID, ObjectID: call.ObjectID, Action: action, EffectKey: call.EffectKey, ExpectedGeneration: call.ExpectedGeneration, MaxFeedbackPerHour: maxFeedback, OccurredAt: service.now()}
	receipt, _, err := service.Repository.BeginSpamQuarantine(ctx, claim)
	if err != nil {
		return SpamQuarantineItem{}, SpamQuarantineReceipt{}, err
	}
	if !receipt.Completed {
		if auditErr := service.audit(ctx, SpamAuditEvent{OperationID: call.OperationID, ActorID: call.ActorID, Capability: capability, Scope: scope, ItemID: item.ID, ObjectID: item.ObjectID, ExpectedGeneration: call.ExpectedGeneration, ResultGeneration: receipt.ResultGeneration, RequestDigest: requestDigest, Outcome: "effect_pending", OccurredAt: service.now()}); auditErr != nil {
			return SpamQuarantineItem{}, SpamQuarantineReceipt{}, auditErr
		}
	}
	return item, receipt, nil
}

func (service *SpamService) finishQuarantine(ctx context.Context, call SpamQuarantineCall, item SpamQuarantineItem, pending SpamQuarantineReceipt, artifactDigest, effectDigest string, capability SpamCapability) (SpamQuarantineReceipt, error) {
	receipt, err := service.Repository.CompleteSpamQuarantine(ctx, SpamQuarantineCompletion{OperationID: call.OperationID, RequestDigest: pending.RequestDigest, TenantID: call.TenantID, ArtifactDigest: artifactDigest, EffectDigest: effectDigest, CompletedAt: service.now()})
	if err != nil {
		return SpamQuarantineReceipt{}, err
	}
	scope := SpamScope{TenantID: item.TenantID, Kind: SpamScopeMailbox, DomainID: item.DomainID, MailboxID: item.MailboxID}
	auditErr := service.audit(ctx, SpamAuditEvent{OperationID: call.OperationID, ActorID: call.ActorID, Capability: capability, Scope: scope, ItemID: item.ID, ObjectID: item.ObjectID, ExpectedGeneration: pending.PreviousGeneration, ResultGeneration: receipt.ResultGeneration, RequestDigest: pending.RequestDigest, ResultDigest: effectDigest, Outcome: string(receipt.State), OccurredAt: receipt.OccurredAt})
	return receipt, auditErr
}

func (service *SpamService) loadScopedQuarantine(ctx context.Context, call SpamQuarantineCall) (SpamQuarantineItem, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(call.OperationID) || !validOpaque(call.ActorID) || !validOpaque(call.TenantID) || !validOpaque(string(call.DomainID)) || !validOpaque(string(call.MailboxID)) || !validSpamID(string(call.ItemID), "spamq_") || !validSpamID(string(call.ObjectID), "spamobj_") || call.ExpectedGeneration == 0 {
		if err != nil {
			return SpamQuarantineItem{}, err
		}
		return SpamQuarantineItem{}, ErrInvalidCommand
	}
	item, err := service.Repository.SpamQuarantine(ctx, call.TenantID, call.ItemID)
	if err != nil {
		return SpamQuarantineItem{}, err
	}
	if item.DomainID != call.DomainID || item.MailboxID != call.MailboxID || item.ObjectID != call.ObjectID || item.Generation != call.ExpectedGeneration {
		return SpamQuarantineItem{}, ErrConflict
	}
	if err = service.verifyQuarantineOwnership(ctx, item); err != nil {
		return SpamQuarantineItem{}, err
	}
	return item, nil
}

func (service *SpamService) authorizeQuarantineCall(ctx context.Context, call SpamQuarantineCall, capability SpamCapability, stepUp bool) error {
	if err := service.ready(ctx); err != nil || !validOpaque(call.OperationID) || !validOpaque(call.ActorID) || !validOpaque(call.TenantID) || !validOpaque(string(call.DomainID)) || !validOpaque(string(call.MailboxID)) || !validSpamID(string(call.ItemID), "spamq_") || !validSpamID(string(call.ObjectID), "spamobj_") || call.ExpectedGeneration == 0 {
		if err != nil {
			return err
		}
		return ErrInvalidCommand
	}
	if stepUp && !service.validStepUp(call.StepUp) {
		return ErrUnauthorized
	}
	scope := SpamScope{TenantID: call.TenantID, Kind: SpamScopeMailbox, DomainID: call.DomainID, MailboxID: call.MailboxID}
	return service.Authorizer.AuthorizeSpam(ctx, SpamAuthorizationRequest{ActorID: call.ActorID, Capability: capability, Scope: scope, ItemID: call.ItemID, StepUp: call.StepUp})
}

func (service *SpamService) effectivePolicy(ctx context.Context, item SpamQuarantineItem) (SpamPolicy, error) {
	snapshot, err := service.Repository.SpamSnapshot(ctx, item.TenantID)
	if err != nil {
		return SpamPolicy{}, err
	}
	return spamEffectivePolicy(snapshot, item)
}

func spamEffectivePolicy(snapshot SpamPolicySnapshot, item SpamQuarantineItem) (SpamPolicy, error) {
	var global SpamPolicy
	for _, policy := range snapshot.Policies {
		if policy.Scope.Kind == SpamScopeGlobal {
			global = policy
		}
		if policy.Scope.Kind == SpamScopeMailbox && policy.Scope.DomainID == item.DomainID && policy.Scope.MailboxID == item.MailboxID {
			return policy, nil
		}
	}
	for _, policy := range snapshot.Policies {
		if policy.Scope.Kind == SpamScopeDomain && policy.Scope.DomainID == item.DomainID {
			return policy, nil
		}
	}
	if global.Scope.Kind != SpamScopeGlobal {
		return SpamPolicy{}, ErrInvalidReceipt
	}
	return global, nil
}

func (service *SpamService) bindPolicy(ctx context.Context, policy *SpamPolicy, snapshot SpamPolicySnapshot, domainGeneration, mailboxGeneration uint64) error {
	if policy.Scope.Kind == SpamScopeGlobal {
		return nil
	}
	domain, err := service.Directory.ResolveSpamDomain(ctx, policy.Scope.TenantID, policy.Scope.DomainID)
	if err != nil {
		return err
	}
	if domain.TenantID != policy.Scope.TenantID || domain.DomainID != policy.Scope.DomainID || domain.Generation != domainGeneration || !domain.Enabled || domain.DomainName != canonicalRoutingDomain(domain.DomainName) {
		return ErrUnauthorized
	}
	policy.DomainName = domain.DomainName
	if policy.Scope.Kind == SpamScopeMailbox {
		mailbox, mailboxErr := service.Directory.ResolveSpamMailbox(ctx, policy.Scope.TenantID, policy.Scope.DomainID, policy.Scope.MailboxID)
		if mailboxErr != nil {
			return mailboxErr
		}
		if mailbox.TenantID != policy.Scope.TenantID || mailbox.DomainID != policy.Scope.DomainID || mailbox.MailboxID != policy.Scope.MailboxID || mailbox.Generation != mailboxGeneration || !mailbox.Enabled || ValidateAddress(mailbox.Address) != nil || string(mailbox.Address) != strings.ToLower(strings.TrimSpace(string(mailbox.Address))) || !strings.HasSuffix(string(mailbox.Address), "@"+domain.DomainName) {
			return ErrUnauthorized
		}
		policy.MailboxAddress = mailbox.Address
	}
	parent, found := spamParentFromSnapshot(snapshot, policy.Scope)
	if !found {
		return ErrConflict
	}
	parentDigest, err := SpamPolicyDigest(parent)
	if err != nil {
		return err
	}
	policy.ParentRevision = parent.Revision
	policy.ParentDigest = parentDigest
	return ValidateSpamChild(parent, *policy)
}

func (service *SpamService) verifyPolicyOwnership(ctx context.Context, policy SpamPolicy) error {
	if policy.Scope.Kind == SpamScopeGlobal {
		return nil
	}
	domain, err := service.Directory.ResolveSpamDomain(ctx, policy.Scope.TenantID, policy.Scope.DomainID)
	if err != nil {
		return err
	}
	if domain.TenantID != policy.Scope.TenantID || domain.DomainID != policy.Scope.DomainID || domain.DomainName != policy.DomainName || !domain.Enabled {
		return ErrUnauthorized
	}
	if policy.Scope.Kind == SpamScopeMailbox {
		mailbox, mailboxErr := service.Directory.ResolveSpamMailbox(ctx, policy.Scope.TenantID, policy.Scope.DomainID, policy.Scope.MailboxID)
		if mailboxErr != nil {
			return mailboxErr
		}
		if mailbox.TenantID != policy.Scope.TenantID || mailbox.DomainID != policy.Scope.DomainID || mailbox.MailboxID != policy.Scope.MailboxID || mailbox.Address != policy.MailboxAddress || !mailbox.Enabled {
			return ErrUnauthorized
		}
	}
	return nil
}

func (service *SpamService) verifyQuarantineOwnership(ctx context.Context, item SpamQuarantineItem) error {
	domain, err := service.Directory.ResolveSpamDomain(ctx, item.TenantID, item.DomainID)
	if err != nil {
		return err
	}
	mailbox, err := service.Directory.ResolveSpamMailbox(ctx, item.TenantID, item.DomainID, item.MailboxID)
	if err != nil {
		return err
	}
	if domain.TenantID != item.TenantID || domain.DomainID != item.DomainID || !domain.Enabled || domain.DomainName != canonicalRoutingDomain(domain.DomainName) || mailbox.TenantID != item.TenantID || mailbox.DomainID != item.DomainID || mailbox.MailboxID != item.MailboxID || !mailbox.Enabled || ValidateAddress(mailbox.Address) != nil || string(mailbox.Address) != strings.ToLower(strings.TrimSpace(string(mailbox.Address))) || !strings.HasSuffix(string(mailbox.Address), "@"+domain.DomainName) {
		return ErrUnauthorized
	}
	return nil
}

func spamParentFromSnapshot(snapshot SpamPolicySnapshot, scope SpamScope) (SpamPolicy, bool) {
	var global SpamPolicy
	for _, policy := range snapshot.Policies {
		if policy.Scope.Kind == SpamScopeGlobal {
			global = policy
		}
		if scope.Kind == SpamScopeMailbox && policy.Scope.Kind == SpamScopeDomain && policy.Scope.DomainID == scope.DomainID {
			return policy, true
		}
	}
	return global, global.Scope.Kind == SpamScopeGlobal
}

func (service *SpamService) validStepUp(proof *SpamStepUpProof) bool {
	if proof == nil || !validOpaque(proof.ProofID) || !canonicalSpamTime(proof.VerifiedAt) || !canonicalSpamTime(proof.ExpiresAt) {
		return false
	}
	now := service.now()
	return !proof.VerifiedAt.After(now) && proof.ExpiresAt.After(now) && proof.ExpiresAt.Sub(proof.VerifiedAt) <= 15*time.Minute
}

func (service *SpamService) ready(ctx context.Context) error {
	if service == nil || service.Repository == nil || service.Directory == nil || service.Authorizer == nil || service.Audit == nil || service.Runtime == nil || service.Artifacts == nil || service.Delivery == nil || service.Learner == nil || service.Now == nil || ctx == nil {
		return ErrInvalidCommand
	}
	return ctx.Err()
}

func (service *SpamService) now() time.Time { return service.Now().UTC().Truncate(time.Second) }

func (service *SpamService) audit(ctx context.Context, event SpamAuditEvent) error {
	if !validOpaque(event.OperationID) || !validOpaque(event.ActorID) || event.Scope.Validate() != nil || !validSpamDigest(event.RequestDigest) || event.ResultDigest != "" && !validSpamDigest(event.ResultDigest) || len(event.Outcome) == 0 || len(event.Outcome) > 80 || strings.ContainsAny(event.Outcome, "\r\n\x00") || !canonicalSpamTime(event.OccurredAt) {
		return ErrInvalidCommand
	}
	return service.Audit.RecordSpamEvent(ctx, event)
}

func spamRequestDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validSpamFeedbackReason(reason string) bool {
	switch reason {
	case "classification_error", "trusted_correspondent", "bulk_misclassified":
		return true
	default:
		return false
	}
}
