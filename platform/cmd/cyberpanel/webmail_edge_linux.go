//go:build linux

package main

import (
	"context"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
)

type webmailEdge struct {
	service *mail.WebmailService
	store   *mail.WebmailStore
}

func newWebmailEdge(service *mail.WebmailService, store *mail.WebmailStore) (*webmailEdge, error) {
	if service == nil || store == nil || store.DB == nil { return nil, mail.ErrInvalidCommand }
	return &webmailEdge{service: service, store: store}, nil
}

func (edge *webmailEdge) ListContacts(ctx context.Context, call apiserver.EdgeCall, session mail.MailSession, page apiserver.EdgePagePayload) (apiserver.EdgePage[mail.Contact], error) {
	verified, err := edge.verify(ctx, call, session)
	if err != nil { return apiserver.EdgePage[mail.Contact]{}, err }
	items, next, err := edge.store.ListContacts(ctx, verified.TenantID, verified.MailboxID, int(page.Limit), page.Cursor)
	if err != nil { return apiserver.EdgePage[mail.Contact]{}, err }
	return apiserver.EdgePage[mail.Contact]{Items: items, NextCursor: next}, nil
}

func (edge *webmailEdge) ListSieveRules(ctx context.Context, call apiserver.EdgeCall, session mail.MailSession, page apiserver.EdgePagePayload) (apiserver.EdgePage[mail.SieveRule], error) {
	verified, err := edge.verify(ctx, call, session)
	if err != nil { return apiserver.EdgePage[mail.SieveRule]{}, err }
	items, next, err := edge.store.ListSieveRules(ctx, verified.TenantID, verified.MailboxID, int(page.Limit), page.Cursor)
	if err != nil { return apiserver.EdgePage[mail.SieveRule]{}, err }
	return apiserver.EdgePage[mail.SieveRule]{Items: items, NextCursor: next}, nil
}

func (edge *webmailEdge) verify(ctx context.Context, call apiserver.EdgeCall, session mail.MailSession) (mail.MailSession, error) {
	if edge == nil || edge.service == nil || edge.store == nil || ctx == nil || call.TenantID == "" || call.PrincipalID == "" {
		return mail.MailSession{}, mail.ErrInvalidCommand
	}
	verified, err := edge.service.ResolveSession(ctx, session)
	if err != nil { return mail.MailSession{}, err }
	if verified.TenantID != call.TenantID || verified.PrincipalID != call.PrincipalID {
		return mail.MailSession{}, mail.ErrUnauthorized
	}
	return verified, nil
}
