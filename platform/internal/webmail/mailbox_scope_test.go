package webmail

import (
	"context"
	"testing"
	"time"
)

type scopeAuthority struct{ Authorizer }

func (scopeAuthority) AuthorizeMailbox(_ context.Context, p Principal, tenant, mailbox string) (AuthorizedMailAccount, error) {
	if p.UserID != "owner" || tenant != "tenant" || mailbox != "mailbox" {
		return AuthorizedMailAccount{}, ErrNotFound
	}
	return AuthorizedMailAccount{TenantID: tenant, MailboxID: mailbox, DisplayLabel: "QA", AddressLabel: "qa@example.invalid", AuthorizationEpoch: 3, Enabled: true}, nil
}

type scopeRepository struct{ Repository }
type scopeAuditor struct{ Auditor }
type scopeBackend struct{ Backend }

func TestMailboxSettingsAuthorizationUsesLiveEpoch(t *testing.T) {
	service, err := NewService(scopeRepository{}, scopeAuthority{}, scopeAuditor{}, scopeBackend{}, "cyberpanel-webmail", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{UserID: "owner", SessionID: "session"}
	if err = service.AuthorizeMailboxScope(context.Background(), principal, "tenant", "mailbox", 3); err != nil {
		t.Fatal(err)
	}
	for _, epoch := range []uint64{0, 2, 4} {
		if err = service.AuthorizeMailboxScope(context.Background(), principal, "tenant", "mailbox", epoch); err == nil {
			t.Fatal("stale epoch accepted")
		}
	}
	if err = service.AuthorizeMailboxScope(context.Background(), principal, "foreign", "mailbox", 3); err == nil {
		t.Fatal("foreign tenant accepted")
	}
}
