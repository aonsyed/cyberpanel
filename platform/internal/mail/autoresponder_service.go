package mail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type AutoresponderAction string

const (
	AutoresponderCreate AutoresponderAction = "autoresponder.create"
	AutoresponderInspect AutoresponderAction = "autoresponder.inspect"
	AutoresponderList AutoresponderAction = "autoresponder.list"
	AutoresponderEnable AutoresponderAction = "autoresponder.enable"
	AutoresponderSchedule AutoresponderAction = "autoresponder.schedule"
	AutoresponderSuspend AutoresponderAction = "autoresponder.suspend"
	AutoresponderUpdate AutoresponderAction = "autoresponder.update"
	AutoresponderDelete AutoresponderAction = "autoresponder.delete"
	AutoresponderReplyClaim AutoresponderAction = "autoresponder.reply.claim"
)

type AutoresponderScope struct {
	TenantID string
	DomainID DomainID
	MailboxID MailboxID
	RuleID AutoresponderID
}

type AutoresponderAuthorizationRequest struct {
	ActorID string
	Action AutoresponderAction
	Scope AutoresponderScope
}

type AutoresponderAuthorizer interface {
	AuthorizeAutoresponder(context.Context, AutoresponderAuthorizationRequest) error
}

type AutoresponderMailboxStore interface {
	Load(context.Context, string, ResourceKind, string) (ResourceEnvelope, bool, error)
}

type AutoresponderAuditTransition struct {
	OperationID string
	ActorID string
	Action AutoresponderAction
	Scope AutoresponderScope
	MailboxGeneration uint64
	ExpectedGeneration uint64
	NextGeneration uint64
	FromState AutoresponderState
	ToState AutoresponderState
	PreviousDigest string
	DesiredDigest string
	OccurredAt time.Time
}

type AutoresponderAuditSink interface {
	RecordAutoresponderTransition(context.Context, AutoresponderAuditTransition) error
}

type AutoresponderService struct {
	Repository AutoresponderRepository
	Mailboxes AutoresponderMailboxStore
	Authorizer AutoresponderAuthorizer
	Runtime AutoresponderSieveRuntime
	Audit AutoresponderAuditSink
	Now func() time.Time
	mu sync.Mutex
}

func NewAutoresponderService(repository AutoresponderRepository, mailboxes AutoresponderMailboxStore, authorizer AutoresponderAuthorizer, runtime AutoresponderSieveRuntime, audit AutoresponderAuditSink, now func() time.Time) (*AutoresponderService, error) {
	if repository == nil || mailboxes == nil || authorizer == nil || runtime == nil || audit == nil {
		return nil, ErrInvalidCommand
	}
	if now == nil {
		now = time.Now
	}
	return &AutoresponderService{Repository: repository, Mailboxes: mailboxes, Authorizer: authorizer, Runtime: runtime, Audit: audit, Now: now}, nil
}

type AutoresponderCreateRequest struct {
	OperationID string
	ActorID string
	Scope AutoresponderScope
	MailboxGeneration uint64
	Settings AutoresponderSettings
}

type AutoresponderCall struct {
	OperationID string
	ActorID string
	Scope AutoresponderScope
	ExpectedGeneration uint64
	MailboxGeneration uint64
}

type AutoresponderScheduleRequest struct {
	Call AutoresponderCall
	StartAt *time.Time
	EndAt *time.Time
	Timezone string
}

type AutoresponderUpdateRequest struct {
	Call AutoresponderCall
	Settings AutoresponderSettings
}

type AutoresponderListRequest struct {
	ActorID string
	TenantID string
	DomainID DomainID
	MailboxID MailboxID
	MailboxGeneration uint64
	After AutoresponderID
	Limit uint32
}

type AutoresponderReplyRequest struct {
	ActorID string
	Scope AutoresponderScope
	ExpectedGeneration uint64
	MailboxGeneration uint64
	Sender Address
}

func (service *AutoresponderService) Create(ctx context.Context, request AutoresponderCreateRequest) (AutoresponderRule, error) {
	if err := service.ready(ctx); err != nil || !validAutoresponderScope(request.Scope) || !validAutoresponderOperationID(request.OperationID) || !validOpaque(request.ActorID) || request.MailboxGeneration == 0 || request.MailboxGeneration > AutoresponderMaximumGeneration {
		if err != nil {
			return AutoresponderRule{}, err
		}
		return AutoresponderRule{}, ErrInvalidCommand
	}
	if request.Settings.RepeatInterval == 0 {
		request.Settings.RepeatInterval = AutoresponderDefaultRepeatInterval
	}
	if request.Settings.Timezone == "" {
		request.Settings.Timezone = "UTC"
	}
	settings, err := NormalizeAutoresponderSettings(request.Settings)
	if err != nil {
		return AutoresponderRule{}, err
	}
	if err = service.authorize(ctx, request.ActorID, AutoresponderCreate, request.Scope); err != nil {
		return AutoresponderRule{}, err
	}
	binding, err := service.resolveMailbox(ctx, request.Scope, request.MailboxGeneration)
	if err != nil {
		return AutoresponderRule{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if _, found, loadErr := service.Repository.Get(ctx, request.Scope.TenantID, request.Scope.RuleID); loadErr != nil {
		return AutoresponderRule{}, loadErr
	} else if found {
		return AutoresponderRule{}, ErrConflict
	}
	now := service.now()
	rule := AutoresponderRule{
		ID: request.Scope.RuleID,
		TenantID: request.Scope.TenantID,
		DomainID: request.Scope.DomainID,
		MailboxID: request.Scope.MailboxID,
		MailboxAddress: binding.Address,
		MailboxGeneration: request.MailboxGeneration,
		Settings: settings,
		State: AutoresponderSuspended,
		Generation: 1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	desired, err := CompileAutoresponderSieve(rule)
	if err != nil {
		return AutoresponderRule{}, err
	}
	rule.AppliedDigest = desired.Digest
	if err = rule.Validate(); err != nil {
		return AutoresponderRule{}, err
	}
	previous, err := RemovedAutoresponderSieveProgram(rule.TenantID, rule.DomainID, rule.MailboxID, rule.ID, 0)
	if err != nil {
		return AutoresponderRule{}, err
	}
	if err = service.auditTransition(ctx, request.OperationID, request.ActorID, AutoresponderCreate, request.Scope, request.MailboxGeneration, 0, AutoresponderState(""), rule.State, previous.Digest, desired.Digest, now); err != nil {
		return AutoresponderRule{}, err
	}
	if err = service.applyWithRollback(ctx, request.OperationID, request.Scope, request.MailboxGeneration, desired, previous); err != nil {
		return AutoresponderRule{}, err
	}
	created, err := service.Repository.Create(ctx, rule)
	if err != nil {
		return AutoresponderRule{}, service.restoreAfterPersistenceFailure(ctx, request.OperationID, request.Scope, request.MailboxGeneration, previous, desired.Digest, err)
	}
	return created, nil
}

func (service *AutoresponderService) Inspect(ctx context.Context, call AutoresponderCall) (AutoresponderRule, error) {
	if err := service.validateCall(ctx, call, false); err != nil {
		return AutoresponderRule{}, err
	}
	if err := service.authorize(ctx, call.ActorID, AutoresponderInspect, call.Scope); err != nil {
		return AutoresponderRule{}, err
	}
	if _, err := service.resolveMailbox(ctx, call.Scope, call.MailboxGeneration); err != nil {
		return AutoresponderRule{}, err
	}
	rule, err := service.currentRule(ctx, call.Scope, call.ExpectedGeneration)
	if err != nil {
		return AutoresponderRule{}, err
	}
	program, err := CompileAutoresponderSieve(rule)
	if err != nil || program.Digest != rule.AppliedDigest {
		return AutoresponderRule{}, errors.Join(ErrInvalidReceipt, err)
	}
	rule.State = rule.EffectiveState(service.now())
	return rule, nil
}

func (service *AutoresponderService) List(ctx context.Context, request AutoresponderListRequest) ([]AutoresponderRule, AutoresponderID, error) {
	if err := service.ready(ctx); err != nil || !validOpaque(request.ActorID) || !validOpaque(request.TenantID) || !validOpaque(string(request.DomainID)) || !validOpaque(string(request.MailboxID)) || request.MailboxGeneration == 0 || request.Limit > AutoresponderMaximumListLimit || request.After != "" && !validOpaque(string(request.After)) {
		if err != nil {
			return nil, "", err
		}
		return nil, "", ErrInvalidCommand
	}
	scope := AutoresponderScope{TenantID: request.TenantID, DomainID: request.DomainID, MailboxID: request.MailboxID, RuleID: AutoresponderID("list")}
	if err := service.authorize(ctx, request.ActorID, AutoresponderList, scope); err != nil {
		return nil, "", err
	}
	if _, err := service.resolveMailbox(ctx, scope, request.MailboxGeneration); err != nil {
		return nil, "", err
	}
	rules, next, err := service.Repository.List(ctx, request.TenantID, request.DomainID, request.MailboxID, request.After, request.Limit)
	if err != nil {
		return nil, "", err
	}
	now := service.now()
	for index := range rules {
		program, compileErr := CompileAutoresponderSieve(rules[index])
		if compileErr != nil || program.Digest != rules[index].AppliedDigest {
			return nil, "", errors.Join(ErrInvalidReceipt, compileErr)
		}
		rules[index].State = rules[index].EffectiveState(now)
	}
	return rules, next, nil
}

func (service *AutoresponderService) Enable(ctx context.Context, call AutoresponderCall) (AutoresponderRule, error) {
	return service.transition(ctx, call, AutoresponderEnable, func(rule *AutoresponderRule, now time.Time) error {
		if rule.Enabled || rule.Settings.EndAt != nil && !now.Before(*rule.Settings.EndAt) {
			return ErrConflict
		}
		rule.Enabled = true
		return nil
	})
}

func (service *AutoresponderService) Schedule(ctx context.Context, request AutoresponderScheduleRequest) (AutoresponderRule, error) {
	return service.transition(ctx, request.Call, AutoresponderSchedule, func(rule *AutoresponderRule, now time.Time) error {
		if request.StartAt == nil && request.EndAt == nil || request.Timezone == "" {
			return ErrInvalidCommand
		}
		settings := rule.Settings
		settings.StartAt = request.StartAt
		settings.EndAt = request.EndAt
		settings.Timezone = request.Timezone
		normalized, err := NormalizeAutoresponderSettings(settings)
		if err != nil {
			return err
		}
		if normalized.EndAt != nil && !now.Before(*normalized.EndAt) {
			return ErrConflict
		}
		rule.Settings = normalized
		rule.Enabled = true
		return nil
	})
}

func (service *AutoresponderService) Suspend(ctx context.Context, call AutoresponderCall) (AutoresponderRule, error) {
	return service.transition(ctx, call, AutoresponderSuspend, func(rule *AutoresponderRule, now time.Time) error {
		if !rule.Enabled {
			return ErrConflict
		}
		rule.Enabled = false
		return nil
	})
}

func (service *AutoresponderService) Update(ctx context.Context, request AutoresponderUpdateRequest) (AutoresponderRule, error) {
	settings := request.Settings
	if settings.RepeatInterval == 0 {
		settings.RepeatInterval = AutoresponderDefaultRepeatInterval
	}
	if settings.Timezone == "" {
		settings.Timezone = "UTC"
	}
	normalized, err := NormalizeAutoresponderSettings(settings)
	if err != nil {
		return AutoresponderRule{}, err
	}
	return service.transition(ctx, request.Call, AutoresponderUpdate, func(rule *AutoresponderRule, now time.Time) error {
		rule.Settings = normalized
		return nil
	})
}

func (service *AutoresponderService) Delete(ctx context.Context, call AutoresponderCall) error {
	if err := service.validateCall(ctx, call, true); err != nil {
		return err
	}
	if err := service.authorize(ctx, call.ActorID, AutoresponderDelete, call.Scope); err != nil {
		return err
	}
	if _, err := service.resolveMailbox(ctx, call.Scope, call.MailboxGeneration); err != nil {
		return err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	current, err := service.currentRule(ctx, call.Scope, call.ExpectedGeneration)
	if err != nil {
		return err
	}
	previous, err := service.provenProgram(current)
	if err != nil {
		return err
	}
	desired, err := RemovedAutoresponderSieveProgram(current.TenantID, current.DomainID, current.MailboxID, current.ID, current.Generation+1)
	if err != nil {
		return err
	}
	now := service.now()
	if err = service.auditTransition(ctx, call.OperationID, call.ActorID, AutoresponderDelete, call.Scope, call.MailboxGeneration, current.Generation, current.EffectiveState(now), AutoresponderDeleted, previous.Digest, desired.Digest, now); err != nil {
		return err
	}
	if err = service.applyWithRollback(ctx, call.OperationID, call.Scope, call.MailboxGeneration, desired, previous); err != nil {
		return err
	}
	if err = service.Repository.Delete(ctx, call.Scope.TenantID, call.Scope.RuleID, call.ExpectedGeneration); err != nil {
		return service.restoreAfterPersistenceFailure(ctx, call.OperationID, call.Scope, call.MailboxGeneration, previous, desired.Digest, err)
	}
	return nil
}

func (service *AutoresponderService) ClaimReply(ctx context.Context, request AutoresponderReplyRequest) (bool, error) {
	call := AutoresponderCall{ActorID: request.ActorID, Scope: request.Scope, ExpectedGeneration: request.ExpectedGeneration, MailboxGeneration: request.MailboxGeneration}
	if err := service.validateCall(ctx, call, false); err != nil {
		return false, err
	}
	if err := service.authorize(ctx, request.ActorID, AutoresponderReplyClaim, request.Scope); err != nil {
		return false, err
	}
	if _, err := service.resolveMailbox(ctx, request.Scope, request.MailboxGeneration); err != nil {
		return false, err
	}
	if _, err := service.currentRule(ctx, request.Scope, request.ExpectedGeneration); err != nil {
		return false, err
	}
	return service.Repository.ClaimReply(ctx, request.Scope.TenantID, request.Scope.RuleID, request.ExpectedGeneration, request.Sender, service.now())
}

func (service *AutoresponderService) transition(ctx context.Context, call AutoresponderCall, action AutoresponderAction, change func(*AutoresponderRule, time.Time) error) (AutoresponderRule, error) {
	if err := service.validateCall(ctx, call, true); err != nil {
		return AutoresponderRule{}, err
	}
	if err := service.authorize(ctx, call.ActorID, action, call.Scope); err != nil {
		return AutoresponderRule{}, err
	}
	binding, err := service.resolveMailbox(ctx, call.Scope, call.MailboxGeneration)
	if err != nil {
		return AutoresponderRule{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	current, err := service.currentRule(ctx, call.Scope, call.ExpectedGeneration)
	if err != nil {
		return AutoresponderRule{}, err
	}
	previous, err := service.provenProgram(current)
	if err != nil {
		return AutoresponderRule{}, err
	}
	now := service.now()
	next := current
	if err = change(&next, now); err != nil {
		return AutoresponderRule{}, err
	}
	next.MailboxAddress = binding.Address
	next.MailboxGeneration = call.MailboxGeneration
	next.Generation = current.Generation + 1
	next.UpdatedAt = now
	next.State = next.EffectiveState(now)
	desired, err := CompileAutoresponderSieve(next)
	if err != nil {
		return AutoresponderRule{}, err
	}
	next.AppliedDigest = desired.Digest
	if err = next.Validate(); err != nil {
		return AutoresponderRule{}, err
	}
	if err = service.auditTransition(ctx, call.OperationID, call.ActorID, action, call.Scope, call.MailboxGeneration, current.Generation, current.EffectiveState(now), next.State, previous.Digest, desired.Digest, now); err != nil {
		return AutoresponderRule{}, err
	}
	if err = service.applyWithRollback(ctx, call.OperationID, call.Scope, call.MailboxGeneration, desired, previous); err != nil {
		return AutoresponderRule{}, err
	}
	updated, err := service.Repository.Update(ctx, next, current.Generation)
	if err != nil {
		return AutoresponderRule{}, service.restoreAfterPersistenceFailure(ctx, call.OperationID, call.Scope, call.MailboxGeneration, previous, desired.Digest, err)
	}
	return updated, nil
}

func (service *AutoresponderService) currentRule(ctx context.Context, scope AutoresponderScope, expected uint64) (AutoresponderRule, error) {
	rule, found, err := service.Repository.Get(ctx, scope.TenantID, scope.RuleID)
	if err != nil {
		return AutoresponderRule{}, err
	}
	if !found {
		return AutoresponderRule{}, ErrNotFound
	}
	if rule.TenantID != scope.TenantID || rule.DomainID != scope.DomainID || rule.MailboxID != scope.MailboxID {
		return AutoresponderRule{}, ErrUnauthorized
	}
	if rule.Generation != expected {
		return AutoresponderRule{}, ErrConflict
	}
	return rule, nil
}

func (service *AutoresponderService) provenProgram(rule AutoresponderRule) (AutoresponderSieveProgram, error) {
	program, err := CompileAutoresponderSieve(rule)
	if err != nil || program.Digest != rule.AppliedDigest {
		return AutoresponderSieveProgram{}, errors.Join(ErrInvalidReceipt, err)
	}
	return program, nil
}

func (service *AutoresponderService) applyWithRollback(ctx context.Context, operationID string, scope AutoresponderScope, mailboxGeneration uint64, desired, previous AutoresponderSieveProgram) error {
	request := AutoresponderSieveRequest{OperationID: operationID, TenantID: scope.TenantID, DomainID: scope.DomainID, MailboxID: scope.MailboxID, MailboxGeneration: mailboxGeneration, ExpectedDigest: previous.Digest, Program: desired}
	receipt, err := service.Runtime.ApplyAutoresponder(ctx, request)
	if err == nil && validAutoresponderSieveReceipt(receipt, request) {
		return nil
	}
	if errors.Is(err, ErrConflict) {
		return err
	}
	cause := err
	if !validAutoresponderSieveReceipt(receipt, request) {
		cause = errors.Join(cause, ErrInvalidReceipt)
	}
	if restoreErr := service.restoreProgram(ctx, operationID, scope, mailboxGeneration, previous, desired.Digest); restoreErr != nil {
		return errors.Join(ErrAmbiguous, cause, restoreErr)
	}
	return cause
}

func (service *AutoresponderService) restoreAfterPersistenceFailure(ctx context.Context, operationID string, scope AutoresponderScope, mailboxGeneration uint64, previous AutoresponderSieveProgram, expectedDigest string, cause error) error {
	if restoreErr := service.restoreProgram(ctx, operationID, scope, mailboxGeneration, previous, expectedDigest); restoreErr != nil {
		return errors.Join(ErrAmbiguous, cause, restoreErr)
	}
	return cause
}

func (service *AutoresponderService) restoreProgram(ctx context.Context, operationID string, scope AutoresponderScope, mailboxGeneration uint64, program AutoresponderSieveProgram, expectedDigest string) error {
	if expectedDigest == "" {
		expectedDigest = program.Digest
	}
	request := AutoresponderSieveRequest{OperationID: operationID + ".rollback", TenantID: scope.TenantID, DomainID: scope.DomainID, MailboxID: scope.MailboxID, MailboxGeneration: mailboxGeneration, ExpectedDigest: expectedDigest, Program: program, Rollback: true}
	receipt, err := service.Runtime.ApplyAutoresponder(ctx, request)
	if err != nil || !validAutoresponderSieveReceipt(receipt, request) {
		return errors.Join(err, ErrInvalidReceipt)
	}
	return nil
}

func (service *AutoresponderService) auditTransition(ctx context.Context, operationID, actorID string, action AutoresponderAction, scope AutoresponderScope, mailboxGeneration, expected uint64, from, to AutoresponderState, previousDigest, desiredDigest string, at time.Time) error {
	event := AutoresponderAuditTransition{OperationID: operationID, ActorID: actorID, Action: action, Scope: scope, MailboxGeneration: mailboxGeneration, ExpectedGeneration: expected, NextGeneration: expected + 1, FromState: from, ToState: to, PreviousDigest: previousDigest, DesiredDigest: desiredDigest, OccurredAt: at}
	if !validAutoresponderOperationID(event.OperationID) || !validOpaque(event.ActorID) || !validAutoresponderScope(event.Scope) || event.MailboxGeneration == 0 || event.NextGeneration == 0 || !validAutoresponderDigest(event.PreviousDigest) || !validAutoresponderDigest(event.DesiredDigest) || event.OccurredAt.IsZero() {
		return ErrInvalidCommand
	}
	return service.Audit.RecordAutoresponderTransition(ctx, event)
}

type autoresponderMailboxBinding struct {
	Address Address
}

func (service *AutoresponderService) resolveMailbox(ctx context.Context, scope AutoresponderScope, expected uint64) (autoresponderMailboxBinding, error) {
	if expected == 0 || expected > AutoresponderMaximumGeneration {
		return autoresponderMailboxBinding{}, ErrInvalidCommand
	}
	resource, found, err := service.Mailboxes.Load(ctx, scope.TenantID, ResourceMailbox, string(scope.MailboxID))
	if err != nil {
		return autoresponderMailboxBinding{}, err
	}
	if !found || resource.State != StateActive {
		return autoresponderMailboxBinding{}, ErrNotFound
	}
	if resource.TenantID != scope.TenantID || resource.Kind != ResourceMailbox || resource.ID != string(scope.MailboxID) {
		return autoresponderMailboxBinding{}, ErrInvalidReceipt
	}
	if resource.Generation != expected {
		return autoresponderMailboxBinding{}, ErrConflict
	}
	var mailbox Mailbox
	if err = strictJSON(resource.Spec, &mailbox); err != nil || mailbox.ID != scope.MailboxID || mailbox.Domain != scope.DomainID || !mailbox.Enabled || mailbox.Local == "" || strings.ContainsAny(mailbox.Local, "@\x00\r\n") {
		return autoresponderMailboxBinding{}, errors.Join(ErrInvalidReceipt, err)
	}
	domainResource, found, err := service.Mailboxes.Load(ctx, scope.TenantID, ResourceDomain, string(scope.DomainID))
	if err != nil {
		return autoresponderMailboxBinding{}, err
	}
	if !found || domainResource.State != StateActive {
		return autoresponderMailboxBinding{}, ErrNotFound
	}
	if domainResource.TenantID != scope.TenantID || domainResource.Kind != ResourceDomain || domainResource.ID != string(scope.DomainID) {
		return autoresponderMailboxBinding{}, ErrInvalidReceipt
	}
	var domain Domain
	if err = strictJSON(domainResource.Spec, &domain); err != nil || domain.ID != scope.DomainID || domain.Tenant != scope.TenantID || !validHostname(domain.Name) {
		return autoresponderMailboxBinding{}, errors.Join(ErrInvalidReceipt, err)
	}
	address := Address(strings.ToLower(strings.TrimSpace(mailbox.Local + "@" + domain.Name)))
	if ValidateAddress(address) != nil {
		return autoresponderMailboxBinding{}, ErrInvalidReceipt
	}
	return autoresponderMailboxBinding{Address: address}, nil
}

func (service *AutoresponderService) validateCall(ctx context.Context, call AutoresponderCall, requireOperation bool) error {
	if err := service.ready(ctx); err != nil {
		return err
	}
	if !validAutoresponderScope(call.Scope) || !validOpaque(call.ActorID) || call.ExpectedGeneration == 0 || call.ExpectedGeneration >= AutoresponderMaximumGeneration || call.MailboxGeneration == 0 || call.MailboxGeneration > AutoresponderMaximumGeneration || requireOperation && !validAutoresponderOperationID(call.OperationID) || !requireOperation && call.OperationID != "" && !validAutoresponderOperationID(call.OperationID) {
		return ErrInvalidCommand
	}
	return nil
}

func (service *AutoresponderService) authorize(ctx context.Context, actorID string, action AutoresponderAction, scope AutoresponderScope) error {
	if err := service.Authorizer.AuthorizeAutoresponder(ctx, AutoresponderAuthorizationRequest{ActorID: actorID, Action: action, Scope: scope}); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

func (service *AutoresponderService) ready(ctx context.Context) error {
	if service == nil || ctx == nil || service.Repository == nil || service.Mailboxes == nil || service.Authorizer == nil || service.Runtime == nil || service.Audit == nil || service.Now == nil {
		return ErrInvalidCommand
	}
	return nil
}

func (service *AutoresponderService) now() time.Time {
	return service.Now().UTC().Truncate(time.Second)
}

func validAutoresponderScope(scope AutoresponderScope) bool {
	return validOpaque(scope.TenantID) && validOpaque(string(scope.DomainID)) && validOpaque(string(scope.MailboxID)) && validOpaque(string(scope.RuleID))
}

func validAutoresponderOperationID(operationID string) bool {
	return len(operationID) <= 140 && validOpaque(operationID)
}
