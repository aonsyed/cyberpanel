//go:build linux

package main

import (
	"context"
	"encoding/json"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/webmaildata"
)

func (runtime *localVacationLifecycle) Discover(ctx context.Context, scope webmaildata.Scope, cursor string) (result webmaildata.VacationDiscovery, err error) {
	err = runtime.with(scope.UserID, func(service *mail.AutoresponderService) error {
		var e error
		result, e = discoverMailboxVacation(ctx, runtime.store, service, scope, cursor)
		return e
	})
	return
}

func discoverMailboxVacation(ctx context.Context, store mail.SQLControlRepository, service *mail.AutoresponderService, scope webmaildata.Scope, cursor string) (webmaildata.VacationDiscovery, error) {
	result := webmaildata.VacationDiscovery{}
	if ctx == nil || !scope.Valid() || service == nil {
		return result, webmaildata.ErrInvalid
	}
	resource, found, err := store.Load(ctx, scope.TenantID, mail.ResourceMailbox, scope.MailboxID)
	if err != nil {
		return result, err
	}
	if !found || resource.State != mail.StateActive {
		return result, webmaildata.ErrNotFound
	}
	var mailbox mail.Mailbox
	if json.Unmarshal(resource.Spec, &mailbox) != nil || string(mailbox.ID) != scope.MailboxID || !mailbox.Enabled {
		return result, webmaildata.ErrNotFound
	}
	// The canonical list re-authorizes actor/scope and validates the live mailbox,
	// domain and generation before returning any rule or discovery metadata.
	rules, next, err := service.List(ctx, mail.AutoresponderListRequest{ActorID: scope.UserID, TenantID: scope.TenantID, DomainID: mailbox.Domain, MailboxID: mailbox.ID, MailboxGeneration: resource.Generation, After: mail.AutoresponderID(cursor), Limit: 100})
	if err != nil {
		return result, err
	}
	if rules == nil {
		rules = []mail.AutoresponderRule{}
	}
	return webmaildata.VacationDiscovery{MailboxID: scope.MailboxID, DomainID: mailbox.Domain, MailboxGeneration: resource.Generation, Rules: rules, NextCursor: string(next)}, nil
}
