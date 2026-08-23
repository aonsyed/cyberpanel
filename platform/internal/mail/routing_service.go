package mail

import (
	"context"
	"fmt"
	"time"
)

type RoutingAction string

const (
	RoutingPolicyMutateAction RoutingAction = "routing.policy.mutate"
	RoutingRuleMutateAction   RoutingAction = "routing.rule.mutate"
	RoutingInspectAction      RoutingAction = "routing.inspect"
	RoutingDecideAction       RoutingAction = "routing.decide"
	RoutingActivateAction     RoutingAction = "routing.activate"
)

type RoutingScope struct {
	TenantID string
	DomainID DomainID
	RuleID   RoutingRuleID
}

type RoutingStepUpProof struct {
	ProofID    string
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

type RoutingAuthorizationRequest struct {
	ActorID string
	Action  RoutingAction
	Scope   RoutingScope
	StepUp  *RoutingStepUpProof
}

type RoutingAuthorizer interface {
	AuthorizeRouting(context.Context, RoutingAuthorizationRequest) error
}

type RoutingAuditEvent struct {
	OperationID        string
	ActorID            string
	Action             RoutingAction
	Scope              RoutingScope
	ExpectedGeneration uint64
	ResultGeneration   uint64
	ExpectedRevision   uint64
	ResultRevision     uint64
	RequestDigest      string
	OccurredAt         time.Time
}

type RoutingAuditSink interface {
	RecordRoutingEvent(context.Context, RoutingAuditEvent) error
}

type RoutingDomainBinding struct {
	TenantID  string
	DomainID  DomainID
	Name      string
	Generation uint64
}

type RoutingMailboxBinding struct {
	TenantID   string
	DomainID   DomainID
	MailboxID  MailboxID
	Address    Address
	Generation uint64
	Enabled    bool
}

// RoutingDirectory is the canonical ownership authority. Implementations must
// fail closed on ambiguous ownership and return at most one mailbox binding.
type RoutingDirectory interface {
	ResolveRoutingDomain(context.Context, string, DomainID) (RoutingDomainBinding, error)
	ResolveRoutingAddressDomain(context.Context, string) (RoutingDomainBinding, bool, error)
	ResolveRoutingMailbox(context.Context, Address) (RoutingMailboxBinding, bool, error)
}

type RoutingActivationReceipt struct {
	GenerationID    string
	SnapshotDigest  string
	SourceDigest    string
	ArtifactDigest  string
	PreviousID      string
	ValidationDigest string
	ReloadDigest    string
	ProbeDigest     string
	RolledBack      bool
	RollbackDigest  string
	ObservedAt      time.Time
}

type RoutingRuntime interface {
	ApplyRoutingGeneration(context.Context, RoutingMapGeneration) (RoutingActivationReceipt, error)
}

type RoutingService struct {
	Repository RoutingRepository
	Directory  RoutingDirectory
	Authorizer RoutingAuthorizer
	Audit      RoutingAuditSink
	Runtime    RoutingRuntime
	Now        func() time.Time
}

func NewRoutingService(repository RoutingRepository, directory RoutingDirectory, authorizer RoutingAuthorizer, audit RoutingAuditSink, runtime RoutingRuntime, now func() time.Time) (*RoutingService, error) {
	if repository == nil || directory == nil || authorizer == nil || audit == nil {
		return nil, ErrInvalidCommand
	}
	if now == nil {
		now = time.Now
	}
	return &RoutingService{Repository: repository, Directory: directory, Authorizer: authorizer, Audit: audit, Runtime: runtime, Now: now}, nil
}

type RoutingPolicyChangeRequest struct {
	OperationID            string
	ActorID                string
	TenantID               string
	DomainID               DomainID
	DirectoryGeneration    uint64
	ExpectedGeneration     uint64
	ExpectedPolicyRevision uint64
	PlusMode               RoutingPlusMode
	PlusDelimiter          string
	MaximumTagBytes        uint16
	CatchAll               RoutingCatchAllAction
	CatchAllTarget         *RoutingTarget
	StepUp                 RoutingStepUpProof
}

func (service *RoutingService) PutPolicy(ctx context.Context, request RoutingPolicyChangeRequest) (RoutingGenerationReceipt, error) {
	if err := service.ready(ctx, false); err != nil || !validRoutingCall(request.OperationID, request.ActorID, request.TenantID, request.DomainID) || request.DirectoryGeneration == 0 || request.ExpectedGeneration > RoutingMaximumGeneration-1 || request.ExpectedPolicyRevision > RoutingMaximumGeneration-1 {
		if err != nil {
			return RoutingGenerationReceipt{}, err
		}
		return RoutingGenerationReceipt{}, ErrInvalidCommand
	}
	now := service.now()
	if !validRoutingStepUp(request.StepUp, now) {
		return RoutingGenerationReceipt{}, ErrInvalidCommand
	}
	scope := RoutingScope{TenantID: request.TenantID, DomainID: request.DomainID}
	proof := request.StepUp
	if err := service.authorize(ctx, request.ActorID, RoutingPolicyMutateAction, scope, &proof); err != nil {
		return RoutingGenerationReceipt{}, err
	}
	domain, err := service.resolveDomain(ctx, request.TenantID, request.DomainID, request.DirectoryGeneration)
	if err != nil {
		return RoutingGenerationReceipt{}, err
	}
	createdAt := now
	var current RoutingSnapshot
	if request.ExpectedGeneration != 0 {
		var loadErr error
		current, loadErr = service.Repository.RoutingSnapshot(ctx, request.TenantID, request.DomainID)
		if loadErr != nil {
			return RoutingGenerationReceipt{}, loadErr
		}
		if current.Policy.Generation != request.ExpectedGeneration || current.Policy.Revision != request.ExpectedPolicyRevision || now.Before(current.Policy.UpdatedAt) {
			return RoutingGenerationReceipt{}, ErrConflict
		}
		createdAt = current.Policy.CreatedAt
	}
	policy := RoutingDomainPolicy{TenantID: request.TenantID, DomainID: request.DomainID, DomainName: domain.Name, DirectoryGeneration: request.DirectoryGeneration, Revision: request.ExpectedPolicyRevision + 1, Generation: request.ExpectedGeneration + 1, PlusMode: request.PlusMode, PlusDelimiter: request.PlusDelimiter, MaximumTagBytes: request.MaximumTagBytes, CatchAll: request.CatchAll, CatchAllTarget: request.CatchAllTarget, CreatedAt: createdAt, UpdatedAt: now}
	policy, err = NormalizeRoutingDomainPolicy(policy)
	if err != nil {
		return RoutingGenerationReceipt{}, err
	}
	if policy.CatchAllTarget != nil {
		if err = service.validateTarget(ctx, policy.TenantID, policy.DomainID, policy.DomainName, policy.DirectoryGeneration, *policy.CatchAllTarget); err != nil {
			return RoutingGenerationReceipt{}, err
		}
	}
	if request.ExpectedGeneration != 0 {
		resulting, snapshotErr := NewRoutingSnapshot(policy, current.Rules)
		if snapshotErr != nil {
			return RoutingGenerationReceipt{}, snapshotErr
		}
		if err = service.validateSnapshotTargets(ctx, resulting); err != nil {
			return RoutingGenerationReceipt{}, err
		}
	}
	digest, err := routingDigest("mail-routing-policy-change-v1", struct {
		ExpectedGeneration uint64              `json:"expected_generation"`
		ExpectedRevision   uint64              `json:"expected_revision"`
		Policy             RoutingDomainPolicy `json:"policy"`
	}{request.ExpectedGeneration, request.ExpectedPolicyRevision, policy})
	if err != nil {
		return RoutingGenerationReceipt{}, err
	}
	if err = service.audit(ctx, RoutingAuditEvent{OperationID: request.OperationID, ActorID: request.ActorID, Action: RoutingPolicyMutateAction, Scope: scope, ExpectedGeneration: request.ExpectedGeneration, ResultGeneration: policy.Generation, ExpectedRevision: request.ExpectedPolicyRevision, ResultRevision: policy.Revision, RequestDigest: digest, OccurredAt: now}); err != nil {
		return RoutingGenerationReceipt{}, err
	}
	return service.Repository.PutRoutingPolicy(ctx, RoutingPolicyMutation{OperationID: request.OperationID, ExpectedGeneration: request.ExpectedGeneration, ExpectedPolicyRevision: request.ExpectedPolicyRevision, Policy: policy})
}

type RoutingRuleChangeRequest struct {
	OperationID         string
	ActorID             string
	TenantID            string
	DomainID            DomainID
	DirectoryGeneration uint64
	ExpectedGeneration  uint64
	ExpectedRevision    uint64
	RuleID              RoutingRuleID
	Kind                RoutingRuleKind
	Source              Address
	Pattern             RoutingPatternSpec
	Priority            uint16
	Targets             []RoutingTarget
	State               RoutingRuleState
	StepUp              *RoutingStepUpProof
}

func (service *RoutingService) MutateRule(ctx context.Context, request RoutingRuleChangeRequest) (RoutingGenerationReceipt, error) {
	if err := service.ready(ctx, false); err != nil || !validRoutingCall(request.OperationID, request.ActorID, request.TenantID, request.DomainID) || !validOpaque(string(request.RuleID)) || request.DirectoryGeneration == 0 || request.ExpectedGeneration == 0 || request.ExpectedGeneration > RoutingMaximumGeneration-1 || request.ExpectedRevision > RoutingMaximumGeneration-1 {
		if err != nil {
			return RoutingGenerationReceipt{}, err
		}
		return RoutingGenerationReceipt{}, ErrInvalidCommand
	}
	now := service.now()
	stepUpRequired := false
	if request.State == RoutingRuleEnabled {
		for _, target := range request.Targets {
			stepUpRequired = stepUpRequired || target.Kind == RoutingExternal
		}
	}
	if stepUpRequired && (request.StepUp == nil || !validRoutingStepUp(*request.StepUp, now)) {
		return RoutingGenerationReceipt{}, ErrUnauthorized
	}
	scope := RoutingScope{TenantID: request.TenantID, DomainID: request.DomainID, RuleID: request.RuleID}
	if err := service.authorize(ctx, request.ActorID, RoutingRuleMutateAction, scope, request.StepUp); err != nil {
		return RoutingGenerationReceipt{}, err
	}
	domain, err := service.resolveDomain(ctx, request.TenantID, request.DomainID, request.DirectoryGeneration)
	if err != nil {
		return RoutingGenerationReceipt{}, err
	}
	snapshot, err := service.Repository.RoutingSnapshot(ctx, request.TenantID, request.DomainID)
	if err != nil {
		return RoutingGenerationReceipt{}, err
	}
	if snapshot.Policy.Generation != request.ExpectedGeneration || snapshot.Policy.DirectoryGeneration != request.DirectoryGeneration || snapshot.Policy.DomainName != domain.Name || now.Before(snapshot.Policy.UpdatedAt) {
		return RoutingGenerationReceipt{}, ErrConflict
	}
	createdAt := now
	if request.ExpectedRevision != 0 {
		previous, found, loadErr := service.Repository.GetRoutingRule(ctx, request.TenantID, request.DomainID, request.RuleID)
		if loadErr != nil {
			return RoutingGenerationReceipt{}, loadErr
		}
		if !found || previous.Revision != request.ExpectedRevision {
			return RoutingGenerationReceipt{}, ErrConflict
		}
		createdAt = previous.CreatedAt
	}
	rule := RoutingRule{ID: request.RuleID, TenantID: request.TenantID, DomainID: request.DomainID, DomainName: domain.Name, Kind: request.Kind, Source: request.Source, Pattern: request.Pattern, Priority: request.Priority, Targets: append([]RoutingTarget(nil), request.Targets...), State: request.State, Revision: request.ExpectedRevision + 1, DomainGeneration: request.ExpectedGeneration + 1, CreatedAt: createdAt, UpdatedAt: now}
	rule, err = NormalizeRoutingRule(rule)
	if err != nil {
		return RoutingGenerationReceipt{}, err
	}
	if rule.State == RoutingRuleEnabled {
		for _, target := range rule.Targets {
			if err = service.validateTarget(ctx, rule.TenantID, rule.DomainID, rule.DomainName, request.DirectoryGeneration, target); err != nil {
				return RoutingGenerationReceipt{}, err
			}
			stepUpRequired = stepUpRequired || target.Kind == RoutingExternal
		}
	}
	if stepUpRequired && (request.StepUp == nil || !validRoutingStepUp(*request.StepUp, now)) {
		return RoutingGenerationReceipt{}, ErrUnauthorized
	}
	nextPolicy := snapshot.Policy
	nextPolicy.Generation = request.ExpectedGeneration + 1
	nextPolicy.UpdatedAt = now
	rules := append([]RoutingRule(nil), snapshot.Rules...)
	replaced := false
	for index := range rules {
		if rules[index].ID == rule.ID {
			rules[index] = rule
			replaced = true
			break
		}
	}
	if !replaced {
		rules = append(rules, rule)
	}
	resulting, snapshotErr := NewRoutingSnapshot(nextPolicy, rules)
	if snapshotErr != nil {
		return RoutingGenerationReceipt{}, snapshotErr
	}
	if err = service.validateSnapshotTargets(ctx, resulting); err != nil {
		return RoutingGenerationReceipt{}, err
	}
	digest, err := routingDigest("mail-routing-rule-change-v1", struct {
		ExpectedGeneration uint64      `json:"expected_generation"`
		ExpectedRevision   uint64      `json:"expected_revision"`
		Rule               RoutingRule `json:"rule"`
	}{request.ExpectedGeneration, request.ExpectedRevision, rule})
	if err != nil {
		return RoutingGenerationReceipt{}, err
	}
	if err = service.audit(ctx, RoutingAuditEvent{OperationID: request.OperationID, ActorID: request.ActorID, Action: RoutingRuleMutateAction, Scope: scope, ExpectedGeneration: request.ExpectedGeneration, ResultGeneration: rule.DomainGeneration, ExpectedRevision: request.ExpectedRevision, ResultRevision: rule.Revision, RequestDigest: digest, OccurredAt: now}); err != nil {
		return RoutingGenerationReceipt{}, err
	}
	return service.Repository.MutateRoutingRule(ctx, RoutingRuleMutation{OperationID: request.OperationID, ExpectedGeneration: request.ExpectedGeneration, ExpectedRevision: request.ExpectedRevision, Rule: rule})
}

type RoutingInspectRequest struct {
	ActorID             string
	TenantID            string
	DomainID            DomainID
	DirectoryGeneration uint64
	After                RoutingRuleID
	Search               string
	Limit                uint32
}

func (service *RoutingService) ListRules(ctx context.Context, request RoutingInspectRequest) ([]RoutingRule, error) {
	if err := service.ready(ctx, false); err != nil || !validOpaque(request.ActorID) || !validOpaque(request.TenantID) || !validOpaque(string(request.DomainID)) || request.DirectoryGeneration == 0 {
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalidCommand
	}
	scope := RoutingScope{TenantID: request.TenantID, DomainID: request.DomainID}
	if err := service.authorize(ctx, request.ActorID, RoutingInspectAction, scope, nil); err != nil {
		return nil, err
	}
	if _, err := service.resolveDomain(ctx, request.TenantID, request.DomainID, request.DirectoryGeneration); err != nil {
		return nil, err
	}
	return service.Repository.ListRoutingRules(ctx, request.TenantID, request.DomainID, request.After, request.Search, request.Limit)
}

type RoutingDecisionRequest struct {
	ActorID             string
	TenantID            string
	DomainID            DomainID
	DirectoryGeneration uint64
	Recipient           Address
}

func (service *RoutingService) Decide(ctx context.Context, request RoutingDecisionRequest) (RoutingDecision, error) {
	if err := service.ready(ctx, false); err != nil || !validOpaque(request.ActorID) || !validOpaque(request.TenantID) || !validOpaque(string(request.DomainID)) || request.DirectoryGeneration == 0 {
		if err != nil {
			return RoutingDecision{}, err
		}
		return RoutingDecision{}, ErrInvalidCommand
	}
	scope := RoutingScope{TenantID: request.TenantID, DomainID: request.DomainID}
	if err := service.authorize(ctx, request.ActorID, RoutingDecideAction, scope, nil); err != nil {
		return RoutingDecision{}, err
	}
	domain, err := service.resolveDomain(ctx, request.TenantID, request.DomainID, request.DirectoryGeneration)
	if err != nil {
		return RoutingDecision{}, err
	}
	recipient, err := CanonicalRoutingAddress(request.Recipient)
	if err != nil || routingAddressDomain(recipient) != domain.Name {
		return RoutingDecision{}, ErrInvalidCommand
	}
	snapshot, err := service.Repository.RoutingSnapshot(ctx, request.TenantID, request.DomainID)
	if err != nil {
		return RoutingDecision{}, err
	}
	if snapshot.Policy.DirectoryGeneration != request.DirectoryGeneration || snapshot.Policy.DomainName != domain.Name {
		return RoutingDecision{}, ErrConflict
	}
	input := RoutingResolutionInput{Recipient: recipient}
	if direct, found, resolveErr := service.resolveMailboxTarget(ctx, recipient, snapshot.Policy); resolveErr != nil {
		return RoutingDecision{}, resolveErr
	} else if found {
		input.Direct = &direct
	}
	if snapshot.Policy.PlusMode == RoutingPlusStripTag {
		base, tagged := stripRoutingTag(recipient, snapshot.Policy)
		if tagged {
			if target, found, resolveErr := service.resolveMailboxTarget(ctx, base, snapshot.Policy); resolveErr != nil {
				return RoutingDecision{}, resolveErr
			} else if found {
				input.PlusBase = &target
			}
		}
	}
	decision, err := ResolveRouting(snapshot, input)
	if err != nil {
		return RoutingDecision{}, err
	}
	for _, target := range decision.Targets {
		if err = service.validateTarget(ctx, snapshot.Policy.TenantID, snapshot.Policy.DomainID, snapshot.Policy.DomainName, snapshot.Policy.DirectoryGeneration, target); err != nil {
			return RoutingDecision{}, err
		}
	}
	return decision, nil
}

type RoutingActivationRequest struct {
	OperationID         string
	ActorID             string
	TenantID            string
	DomainID            DomainID
	DirectoryGeneration uint64
	ExpectedGeneration  uint64
}

func (service *RoutingService) Activate(ctx context.Context, request RoutingActivationRequest) (RoutingActivationReceipt, error) {
	if err := service.ready(ctx, true); err != nil || !validRoutingCall(request.OperationID, request.ActorID, request.TenantID, request.DomainID) || request.DirectoryGeneration == 0 || request.ExpectedGeneration == 0 {
		if err != nil {
			return RoutingActivationReceipt{}, err
		}
		return RoutingActivationReceipt{}, ErrInvalidCommand
	}
	scope := RoutingScope{TenantID: request.TenantID, DomainID: request.DomainID}
	if err := service.authorize(ctx, request.ActorID, RoutingActivateAction, scope, nil); err != nil {
		return RoutingActivationReceipt{}, err
	}
	domain, err := service.resolveDomain(ctx, request.TenantID, request.DomainID, request.DirectoryGeneration)
	if err != nil {
		return RoutingActivationReceipt{}, err
	}
	snapshot, err := service.Repository.RoutingSnapshot(ctx, request.TenantID, request.DomainID)
	if err != nil {
		return RoutingActivationReceipt{}, err
	}
	if snapshot.Policy.Generation != request.ExpectedGeneration || snapshot.Policy.DirectoryGeneration != request.DirectoryGeneration || snapshot.Policy.DomainName != domain.Name {
		return RoutingActivationReceipt{}, ErrConflict
	}
	if err = service.validateSnapshotTargets(ctx, snapshot); err != nil {
		return RoutingActivationReceipt{}, err
	}
	generation, err := CompileRoutingMapGeneration(snapshot)
	if err != nil {
		return RoutingActivationReceipt{}, err
	}
	now := service.now()
	digest, err := routingDigest("mail-routing-activation-v1", struct {
		ID         string `json:"id"`
		Generation uint64 `json:"generation"`
		Digest     string `json:"digest"`
	}{generation.ID, generation.Generation, generation.SourceDigest})
	if err != nil {
		return RoutingActivationReceipt{}, err
	}
	if err = service.audit(ctx, RoutingAuditEvent{OperationID: request.OperationID, ActorID: request.ActorID, Action: RoutingActivateAction, Scope: scope, ExpectedGeneration: request.ExpectedGeneration, ResultGeneration: request.ExpectedGeneration, RequestDigest: digest, OccurredAt: now}); err != nil {
		return RoutingActivationReceipt{}, err
	}
	return service.Runtime.ApplyRoutingGeneration(ctx, generation)
}

func (service *RoutingService) validateTarget(ctx context.Context, tenant string, domain DomainID, domainName string, directoryGeneration uint64, target RoutingTarget) error {
	if target.Validate(tenant, domain, domainName) != nil {
		return ErrInvalidCommand
	}
	domainBinding, domainFound, err := service.Directory.ResolveRoutingAddressDomain(ctx, routingAddressDomain(target.Address))
	if err != nil {
		return err
	}
	if target.Kind == RoutingExternal && domainFound {
		return ErrUnauthorized
	}
	if target.Kind == RoutingLocalMailbox && (!domainFound || domainBinding.TenantID != tenant || domainBinding.DomainID != domain || domainBinding.Generation != directoryGeneration || canonicalRoutingDomain(domainBinding.Name) != domainName || domainBinding.Name != domainName) {
		return ErrUnauthorized
	}
	binding, found, err := service.Directory.ResolveRoutingMailbox(ctx, target.Address)
	if err != nil {
		return err
	}
	if target.Kind == RoutingExternal {
		if found {
			return ErrUnauthorized
		}
		return nil
	}
	if !found || !binding.Enabled || binding.TenantID != tenant || binding.DomainID != domain || binding.MailboxID != target.MailboxID || binding.Generation != target.MailboxGeneration {
		return ErrUnauthorized
	}
	address, canonicalErr := CanonicalRoutingAddress(binding.Address)
	if canonicalErr != nil || address != target.Address || binding.Address != address {
		return ErrInvalidReceipt
	}
	return nil
}

func (service *RoutingService) validateSnapshotTargets(ctx context.Context, snapshot RoutingSnapshot) error {
	if snapshot.Validate() != nil {
		return ErrInvalidReceipt
	}
	if snapshot.Policy.CatchAllTarget != nil {
		if err := service.validateTarget(ctx, snapshot.Policy.TenantID, snapshot.Policy.DomainID, snapshot.Policy.DomainName, snapshot.Policy.DirectoryGeneration, *snapshot.Policy.CatchAllTarget); err != nil {
			return err
		}
	}
	for _, rule := range snapshot.Rules {
		if rule.State != RoutingRuleEnabled {
			continue
		}
		for _, target := range rule.Targets {
			if err := service.validateTarget(ctx, snapshot.Policy.TenantID, snapshot.Policy.DomainID, snapshot.Policy.DomainName, snapshot.Policy.DirectoryGeneration, target); err != nil {
				return err
			}
		}
	}
	return nil
}

func (service *RoutingService) resolveMailboxTarget(ctx context.Context, address Address, policy RoutingDomainPolicy) (RoutingTarget, bool, error) {
	binding, found, err := service.Directory.ResolveRoutingMailbox(ctx, address)
	if err != nil || !found {
		return RoutingTarget{}, found, err
	}
	canonical, canonicalErr := CanonicalRoutingAddress(binding.Address)
	if canonicalErr != nil || canonical != address || binding.Address != canonical || !binding.Enabled || binding.TenantID != policy.TenantID || binding.DomainID != policy.DomainID || !validOpaque(string(binding.MailboxID)) || binding.Generation == 0 || binding.Generation > RoutingMaximumGeneration {
		return RoutingTarget{}, false, ErrUnauthorized
	}
	return RoutingTarget{Kind: RoutingLocalMailbox, Address: address, TenantID: binding.TenantID, DomainID: binding.DomainID, MailboxID: binding.MailboxID, MailboxGeneration: binding.Generation}, true, nil
}

func (service *RoutingService) resolveDomain(ctx context.Context, tenant string, domain DomainID, generation uint64) (RoutingDomainBinding, error) {
	binding, err := service.Directory.ResolveRoutingDomain(ctx, tenant, domain)
	if err != nil {
		return RoutingDomainBinding{}, err
	}
	name := canonicalRoutingDomain(binding.Name)
	if binding.TenantID != tenant || binding.DomainID != domain || binding.Generation != generation || generation == 0 || name == "" || binding.Name != name {
		return RoutingDomainBinding{}, ErrUnauthorized
	}
	return binding, nil
}

func (service *RoutingService) authorize(ctx context.Context, actor string, action RoutingAction, scope RoutingScope, proof *RoutingStepUpProof) error {
	if err := service.Authorizer.AuthorizeRouting(ctx, RoutingAuthorizationRequest{ActorID: actor, Action: action, Scope: scope, StepUp: proof}); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

func (service *RoutingService) audit(ctx context.Context, event RoutingAuditEvent) error {
	if !validOpaque(event.OperationID) || !validOpaque(event.ActorID) || !validOpaque(event.Scope.TenantID) || !validOpaque(string(event.Scope.DomainID)) || event.Scope.RuleID != "" && !validOpaque(string(event.Scope.RuleID)) || event.ExpectedGeneration > RoutingMaximumGeneration || event.ResultGeneration == 0 || event.ResultGeneration > RoutingMaximumGeneration || !validRoutingDigest(event.RequestDigest) || !routingCanonicalTime(event.OccurredAt) {
		return ErrInvalidCommand
	}
	if event.Action == RoutingPolicyMutateAction || event.Action == RoutingRuleMutateAction {
		if event.ResultGeneration != event.ExpectedGeneration+1 || event.ResultRevision != event.ExpectedRevision+1 {
			return ErrInvalidCommand
		}
	} else if event.Action != RoutingActivateAction || event.ResultGeneration != event.ExpectedGeneration || event.ExpectedRevision != 0 || event.ResultRevision != 0 {
		return ErrInvalidCommand
	}
	return service.Audit.RecordRoutingEvent(ctx, event)
}

func (service *RoutingService) ready(ctx context.Context, requireRuntime bool) error {
	if service == nil || ctx == nil || service.Repository == nil || service.Directory == nil || service.Authorizer == nil || service.Audit == nil || service.Now == nil || requireRuntime && service.Runtime == nil {
		return ErrInvalidCommand
	}
	return nil
}

func (service *RoutingService) now() time.Time {
	return service.Now().UTC().Truncate(time.Second)
}

func validRoutingCall(operation, actor, tenant string, domain DomainID) bool {
	return validOpaque(operation) && validOpaque(actor) && validOpaque(tenant) && validOpaque(string(domain))
}

func validRoutingStepUp(proof RoutingStepUpProof, now time.Time) bool {
	return validOpaque(proof.ProofID) && routingCanonicalTime(proof.VerifiedAt) && routingCanonicalTime(proof.ExpiresAt) && !proof.VerifiedAt.After(now) && proof.ExpiresAt.After(now) && proof.ExpiresAt.After(proof.VerifiedAt) && proof.ExpiresAt.Sub(proof.VerifiedAt) <= 15*time.Minute
}
