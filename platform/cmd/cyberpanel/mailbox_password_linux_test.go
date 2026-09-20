//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
	_ "modernc.org/sqlite"
)

type mailboxCredentialConsumers struct{}

func (mailboxCredentialConsumers) Verify(context.Context, secrets.ConsumerIdentity) (bool, error) {
	return true, nil
}

type mailboxCredentialTransport struct {
	broker *secrets.Broker
	calls  int
}

func (transport *mailboxCredentialTransport) RoundTrip(ctx context.Context, request secrets.ManagementRequest) (secrets.ManagementResponse, error) {
	transport.calls++
	metadata, err := transport.broker.EnrollExact(ctx, secrets.PutRequest{ID: request.SecretID, OwnerTenantID: request.OwnerTenantID, Purpose: request.Purpose, Audience: request.Audience, Plaintext: request.Material})
	return secrets.ManagementResponse{Version: secrets.ManagementProtocolVersion, RequestID: request.RequestID, SecretID: request.SecretID, Metadata: metadata}, err
}

func TestMailboxPasswordEnrollmentAuthorityAndReplay(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	repository := mail.SQLControlRepository{DB: db}
	if err := repository.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := secrets.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "key")
	if err = os.WriteFile(keyPath, key, 0400); err != nil {
		t.Fatal(err)
	}
	wipeBytes(key)
	kek, err := secrets.NewFileKEK(keyPath, 1, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secrets.NewBroker(store, kek, mailboxCredentialConsumers{})
	if err != nil {
		t.Fatal(err)
	}
	transport := &mailboxCredentialTransport{broker: broker}
	client, err := secrets.NewManagementClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	for kind, spec := range map[mail.ResourceKind]any{mail.ResourceDomain: mail.Domain{ID: "domain", Tenant: "tenant", Name: "example.invalid"}, mail.ResourceMailbox: mail.Mailbox{ID: "mailbox", Domain: "domain", Local: "owner", SiteID: "site", QuotaBytes: 1024}} {
		id := "domain"
		if kind == mail.ResourceMailbox {
			id = "mailbox"
		}
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		envelope := mail.ResourceEnvelope{ID: id, Kind: kind, TenantID: "tenant", Generation: 1, State: mail.StateActive, Spec: raw, UpdatedAt: time.Now()}
		body, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`INSERT INTO mail_resources_v2(tenant_id,kind,resource_id,generation,state,resource_json,updated_at) VALUES(?,?,?,?,?,?,?)`, "tenant", kind, id, 1, mail.StateActive, body, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	service := &mailboxPasswordEnrollment{store: repository, broker: client, release: strings.Repeat("a", 64), slots: make(chan struct{}, 2)}
	call := apiserver.EdgeCall{TenantID: "tenant", ResourceID: "mailbox", ExpectedGeneration: 1, CommandID: "command", PrincipalID: "owner", Assurance: identity.AssuranceMFA}
	password := []byte("qemu-public-password-fixture")
	reference, err := service.EnrollMailboxPassword(ctx, call, password)
	if err != nil || reference.ID == "" {
		t.Fatal("enroll", err)
	}
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("caller password not wiped")
	}
	replay, err := service.EnrollMailboxPassword(ctx, call, []byte("qemu-public-password-fixture"))
	if err != nil || replay.ID != reference.ID || replay.BindingDigest != reference.BindingDigest || replay.Version != 1 {
		t.Fatal("exact replay", err)
	}
	if _, err := service.EnrollMailboxPassword(ctx, call, []byte("qemu-other-password-fixture")); err == nil {
		t.Fatal("changed password replay accepted")
	}
	calls := transport.calls
	for _, variant := range []string{"tenant", "mailbox", "generation", "assurance", "principal"} {
		denied := call
		switch variant {
		case "tenant":
			denied.TenantID = "other"
		case "mailbox":
			denied.ResourceID = "other"
		case "generation":
			denied.ExpectedGeneration = 2
		case "assurance":
			denied.Assurance = identity.AssurancePassword
		case "principal":
			denied.PrincipalID = ""
		}
		if _, err := service.EnrollMailboxPassword(ctx, denied, []byte("qemu-public-password-fixture")); err == nil {
			t.Fatal("authority accepted", variant)
		}
	}
	if transport.calls != calls {
		t.Fatal("denied request reached secret broker")
	}
}
