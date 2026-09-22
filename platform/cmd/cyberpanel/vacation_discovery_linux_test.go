//go:build linux

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/webmaildata"
	"path/filepath"
	"testing"
	"time"
)

type discoveryAuthorizer struct{}

func (discoveryAuthorizer) AuthorizeAutoresponder(_ context.Context, r mail.AutoresponderAuthorizationRequest) error {
	if r.ActorID != "owner" || r.Scope.TenantID != "tenant" || r.Scope.MailboxID != "mailbox" {
		return mail.ErrUnauthorized
	}
	return nil
}

type discoveryUnusedRuntime struct{ mail.AutoresponderSieveRuntime }
type discoveryUnusedAudit struct{ mail.AutoresponderAuditSink }

func TestVacationDiscoveryEmptyPopulatedAndScoped(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := mail.SQLControlRepository{DB: db}
	if err = store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	repository, err := mail.NewSQLAutoresponderRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = repository.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		kind mail.ResourceKind
		id   string
		spec any
	}{{mail.ResourceDomain, "domain", mail.Domain{ID: "domain", Tenant: "tenant", Name: "example.invalid"}}, {mail.ResourceMailbox, "mailbox", mail.Mailbox{ID: "mailbox", Domain: "domain", Local: "qa", Enabled: true}}} {
		spec, _ := json.Marshal(r.spec)
		raw, _ := json.Marshal(mail.ResourceEnvelope{Kind: r.kind, ID: r.id, TenantID: "tenant", Generation: 3, State: mail.StateActive, Spec: spec})
		if _, err = db.Exec(`INSERT INTO mail_resources_v2 VALUES(?,?,?,?,?,?,?)`, "tenant", r.kind, r.id, 3, mail.StateActive, raw, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	service, err := mail.NewAutoresponderService(repository, store, discoveryAuthorizer{}, discoveryUnusedRuntime{}, discoveryUnusedAudit{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scope := webmaildata.Scope{TenantID: "tenant", UserID: "owner", MailboxID: "mailbox"}
	empty, err := discoverMailboxVacation(ctx, store, service, scope, "")
	if err != nil || empty.DomainID != "domain" || empty.MailboxGeneration != 3 || empty.Rules == nil || len(empty.Rules) != 0 {
		t.Fatalf("empty discovery: %+v %v", empty, err)
	}
	rule := mail.AutoresponderRule{ID: "vacation", TenantID: "tenant", DomainID: "domain", MailboxID: "mailbox", MailboxAddress: "qa@example.invalid", MailboxGeneration: 3, Generation: 1, State: mail.AutoresponderSuspended, Settings: mail.AutoresponderSettings{Subject: "Away", Body: "Reply", Timezone: "UTC", RepeatInterval: time.Hour}, CreatedAt: now, UpdatedAt: now}
	program, err := mail.CompileAutoresponderSieve(rule)
	if err != nil {
		t.Fatal(err)
	}
	rule.AppliedDigest = program.Digest
	if _, err = repository.Create(ctx, rule); err != nil {
		t.Fatal(err)
	}
	populated, err := discoverMailboxVacation(ctx, store, service, scope, "")
	if err != nil || len(populated.Rules) != 1 || populated.Rules[0].ID != "vacation" || populated.Rules[0].Generation != 1 {
		t.Fatal("existing rule not discoverable", err)
	}
	for _, foreign := range []webmaildata.Scope{{TenantID: "other", UserID: "owner", MailboxID: "mailbox"}, {TenantID: "tenant", UserID: "owner", MailboxID: "other"}, {TenantID: "tenant", UserID: "other", MailboxID: "mailbox"}} {
		result, e := discoverMailboxVacation(ctx, store, service, foreign, "")
		if e == nil || result.DomainID != "" || len(result.Rules) > 0 {
			t.Fatal("foreign discovery leaked metadata")
		}
	}
	if err = repository.Delete(ctx, "tenant", "vacation", 1); err != nil {
		t.Fatal(err)
	}
	deleted, err := discoverMailboxVacation(ctx, store, service, scope, "")
	if err != nil || len(deleted.Rules) != 0 {
		t.Fatal("deleted rule discovered", err)
	}
}
