package apiserver

import (
	"context"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	securewebmail "github.com/aonsyed/cyberpanel/platform/internal/webmail"
	"testing"
)

type dataMailboxAuthority struct{ calls int }

func (authority *dataMailboxAuthority) AuthorizeMailboxScope(_ context.Context, p securewebmail.Principal, tenant, mailbox string, epoch uint64) error {
	authority.calls++
	if p.UserID != "owner" || p.SessionID != "session" || tenant != "tenant" || mailbox != "mailbox" || epoch != 3 {
		return securewebmail.ErrNotFound
	}
	return nil
}
func TestWebmailDataUsesCurrentSecureMailboxContext(t *testing.T) {
	owner, _ := identity.NewID("owner")
	session, _ := identity.NewID("session")
	credential, _ := identity.NewID("credential")
	inv := Invocation{Actor: Actor{PrincipalID: owner, SessionID: session, CredentialID: credential}, Request: RequestEnvelope{TenantID: "tenant", ResourceID: "vacation_rule", RequestID: "request"}, IdempotencyKey: "vacation_create"}
	payload := WebmailDataSessionPayload{WebmailEpochPayload: WebmailEpochPayload{AuthorizationEpoch: 3}, MailboxID: "mailbox"}
	authority := &dataMailboxAuthority{}
	if err := validateWebmailDataPayload(&WebmailDataVacationPayload{WebmailDataSessionPayload: payload}); err != nil {
		t.Fatal("legacy session still required", err)
	}
	call, err := secureWebmailDataCall(context.Background(), authority, inv, payload)
	if err != nil || call.ActorID != "owner" || call.Scope.TenantID != "tenant" || call.Scope.UserID != "owner" || call.Scope.MailboxID != "mailbox" || call.StepUpProof != "credential" {
		t.Fatalf("secure binding lost: %+v %v", call, err)
	}
	for _, variant := range []string{"tenant", "mailbox", "epoch", "user", "session"} {
		other, changed := inv, payload
		switch variant {
		case "tenant":
			other.Request.TenantID = "foreign"
		case "mailbox":
			changed.MailboxID = "foreign"
		case "epoch":
			changed.AuthorizationEpoch = 2
		case "user":
			other.Actor.PrincipalID, _ = identity.NewID("foreign")
		case "session":
			other.Actor.SessionID = ""
			other.Actor.CredentialID = ""
		}
		if _, err = secureWebmailDataCall(context.Background(), authority, other, changed); err == nil {
			t.Fatalf("%s scope accepted", variant)
		}
	}
}
