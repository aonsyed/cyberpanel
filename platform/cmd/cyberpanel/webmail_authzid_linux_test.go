//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	securewebmail "github.com/aonsyed/cyberpanel/platform/internal/webmail"
)

func TestWebmailAuthzIDUsesLiveConsumedGrant(t *testing.T) {
	for _, variant := range []string{"valid", "expired", "revoked", "unconsumed", "wrong tenant", "stale epoch", "wrong token"} {
		t.Run(variant, func(t *testing.T) {
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
			repository, err := securewebmail.NewSQLiteRepository(db)
			if err != nil {
				t.Fatal(err)
			}
			if err = repository.Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			if err = bootstrapWebmailDovecotTokens(ctx, db); err != nil {
				t.Fatal(err)
			}
			for _, resource := range []struct {
				kind mail.ResourceKind
				id   string
				spec any
			}{
				{mail.ResourceDomain, "domain", mail.Domain{ID: "domain", Tenant: "tenant", Name: "example.invalid"}},
				{mail.ResourceMailbox, "mailbox", mail.Mailbox{ID: "mailbox", Domain: "domain", Local: "qa", Enabled: true}},
			} {
				spec, _ := json.Marshal(resource.spec)
				generation := uint64(1)
				if variant == "stale epoch" && resource.kind == mail.ResourceMailbox {
					generation = 2
				}
				raw, _ := json.Marshal(mail.ResourceEnvelope{Kind: resource.kind, ID: resource.id, TenantID: "tenant", Generation: generation, State: mail.StateActive, Spec: spec})
				if _, err = db.Exec(`INSERT INTO mail_resources_v2 VALUES(?,?,?,?,?,?,?)`, "tenant", resource.kind, resource.id, generation, mail.StateActive, raw, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			token := strings.Repeat("x", 64)
			sum := sha256.Sum256([]byte(token))
			digest := hex.EncodeToString(sum[:])
			now := time.Now().UnixNano()
			expires := time.Now().Add(time.Minute).UnixNano()
			if _, err = db.Exec(`INSERT INTO webmail_grants_v1 VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL)`, digest, "tenant", "owner", "session", "mailbox", "cyberpanel-webmail", 1, now, expires); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE webmail_grants_v1 SET consumed_at=? WHERE token_digest=?`, now, digest); err != nil {
				t.Fatal(err)
			}
			mutations := map[string]string{"expired": "UPDATE webmail_dovecot_tokens_v1 SET expires_at=1", "revoked": "UPDATE webmail_grants_v1 SET revoked_at=1", "unconsumed": "UPDATE webmail_grants_v1 SET consumed_at=NULL", "wrong tenant": "UPDATE webmail_grants_v1 SET tenant_id='other'"}
			if statement := mutations[variant]; statement != "" {
				if _, err = db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "wrong token" {
				token = strings.Repeat("z", 64)
			}
			handler := webmailTokenInfo{database: db, directory: secureWebmailDirectory{store: store}}
			address, err := handler.AuthzID(ctx, token)
			if variant != "valid" {
				if err == nil {
					t.Fatal("invalid grant returned authzid")
				}
				return
			}
			if err != nil || address != "qa@example.invalid" {
				t.Fatal("canonical authzid", err)
			}
			request := httptest.NewRequest("GET", "http://127.0.0.1:18090/tokeninfo", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 200 {
				t.Fatal("authzid lookup prematurely consumed native introspection token")
			}
			if _, err = handler.AuthzID(ctx, token); err == nil {
				t.Fatal("replayed native token accepted")
			}
		})
	}
}
