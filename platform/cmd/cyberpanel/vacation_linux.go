//go:build linux

package main

import (
	"context"
	"errors"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/webmaildata"
	"sync"
)

type localVacationLifecycle struct {
	mu         sync.Mutex
	repository *mail.SQLAutoresponderRepository
	store      mail.SQLControlRepository
	authority  webmailDataAuthority
	audit      webmailDataAudit
	data       *webmaildata.Service
	native     *webmaildata.LocalManageSieveAdapter
}

func (runtime *localVacationLifecycle) with(actor string, run func(*mail.AutoresponderService) error) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	service, err := mail.NewAutoresponderService(runtime.repository, runtime.store, runtime, webmaildata.VacationRuntime{Service: runtime.data, Native: runtime.native, ActorID: actor}, runtime, runtime.authority.now)
	if err != nil {
		return err
	}
	return run(service)
}
func (runtime *localVacationLifecycle) Create(ctx context.Context, r mail.AutoresponderCreateRequest) (v mail.AutoresponderRule, e error) {
	e = runtime.mutate(ctx, r.ActorID, r.Scope, func(s *mail.AutoresponderService) error { v, e = s.Create(ctx, r); return e })
	return
}
func (runtime *localVacationLifecycle) Inspect(ctx context.Context, r mail.AutoresponderCall) (v mail.AutoresponderRule, e error) {
	e = runtime.with(r.ActorID, func(s *mail.AutoresponderService) error { v, e = s.Inspect(ctx, r); return e })
	return
}
func (runtime *localVacationLifecycle) Enable(ctx context.Context, r mail.AutoresponderCall) (v mail.AutoresponderRule, e error) {
	e = runtime.mutate(ctx, r.ActorID, r.Scope, func(s *mail.AutoresponderService) error { v, e = s.Enable(ctx, r); return e })
	return
}
func (runtime *localVacationLifecycle) Suspend(ctx context.Context, r mail.AutoresponderCall) (v mail.AutoresponderRule, e error) {
	e = runtime.mutate(ctx, r.ActorID, r.Scope, func(s *mail.AutoresponderService) error { v, e = s.Suspend(ctx, r); return e })
	return
}
func (runtime *localVacationLifecycle) Update(ctx context.Context, r mail.AutoresponderUpdateRequest) (v mail.AutoresponderRule, e error) {
	e = runtime.mutate(ctx, r.Call.ActorID, r.Call.Scope, func(s *mail.AutoresponderService) error { v, e = s.Update(ctx, r); return e })
	return
}
func (runtime *localVacationLifecycle) Delete(ctx context.Context, r mail.AutoresponderCall) error {
	return runtime.mutate(ctx, r.ActorID, r.Scope, func(s *mail.AutoresponderService) error { return s.Delete(ctx, r) })
}

func (runtime *localVacationLifecycle) mutate(ctx context.Context, actor string, scope mail.AutoresponderScope, run func(*mail.AutoresponderService) error) error {
	unlock := runtime.data.LockSieveMailbox(webmaildata.Scope{TenantID: scope.TenantID, UserID: actor, MailboxID: string(scope.MailboxID)})
	defer unlock()
	return runtime.with(actor, func(service *mail.AutoresponderService) error {
		previous, wasPresent, err := runtime.repository.Get(ctx, scope.TenantID, scope.RuleID)
		if err != nil {
			return err
		}
		if err = run(service); err != nil {
			return err
		}
		current, present, err := runtime.repository.Get(ctx, scope.TenantID, scope.RuleID)
		if err != nil {
			return errors.Join(mail.ErrAmbiguous, err)
		}
		var keep []webmaildata.CanonicalVacationReference
		if present {
			keep = append(keep, webmaildata.CanonicalVacationReference{RuleID: current.ID, Generation: current.Generation, ProgramDigest: current.AppliedDigest})
			if wasPresent {
				keep = append(keep, webmaildata.CanonicalVacationReference{RuleID: previous.ID, Generation: previous.Generation, ProgramDigest: previous.AppliedDigest})
			}
		}
		adapter := webmaildata.VacationRuntime{Service: runtime.data, Native: runtime.native, ActorID: actor}
		if err = adapter.Retire(ctx, webmaildata.Scope{TenantID: scope.TenantID, UserID: actor, MailboxID: string(scope.MailboxID)}, scope.RuleID, keep); err != nil {
			return errors.Join(mail.ErrAmbiguous, err)
		}
		return nil
	})
}

func (runtime *localVacationLifecycle) AuthorizeAutoresponder(ctx context.Context, r mail.AutoresponderAuthorizationRequest) error {
	assurance := identity.AssuranceMFA
	if r.Action == mail.AutoresponderInspect || r.Action == mail.AutoresponderList {
		assurance = identity.AssurancePassword
	}
	return runtime.authority.authorize(ctx, r.ActorID, webmaildata.Scope{TenantID: r.Scope.TenantID, UserID: r.ActorID, MailboxID: string(r.Scope.MailboxID)}, assurance)
}
func (runtime *localVacationLifecycle) RecordAutoresponderTransition(ctx context.Context, r mail.AutoresponderAuditTransition) error {
	return runtime.audit.RecordWebmailData(ctx, webmaildata.AuditEvent{OperationID: r.OperationID, ActorID: r.ActorID, Operation: webmaildata.Operation(r.Action), Scope: webmaildata.Scope{TenantID: r.Scope.TenantID, UserID: r.ActorID, MailboxID: string(r.Scope.MailboxID)}, ResourceID: string(r.Scope.RuleID), Before: r.ExpectedGeneration, After: r.NextGeneration, Digest: r.DesiredDigest, OccurredAt: r.OccurredAt})
}
func (runtime *localVacationLifecycle) ResolveAutoresponder(ctx context.Context, scope webmaildata.Scope, id mail.AutoresponderID, generation uint64) (mail.AutoresponderRule, error) {
	if err := runtime.authority.authorize(ctx, scope.UserID, scope, identity.AssurancePassword); err != nil {
		return mail.AutoresponderRule{}, err
	}
	rule, found, err := runtime.repository.Get(ctx, scope.TenantID, id)
	if err != nil {
		return rule, err
	}
	if !found || string(rule.MailboxID) != scope.MailboxID || rule.Generation != generation || rule.State == mail.AutoresponderDeleted {
		return mail.AutoresponderRule{}, webmaildata.ErrNotFound
	}
	return rule, nil
}
