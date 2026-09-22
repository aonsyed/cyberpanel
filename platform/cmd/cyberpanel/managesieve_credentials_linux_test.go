//go:build linux

package main

import (
	"context"
	"database/sql"
	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	securewebmail "github.com/aonsyed/cyberpanel/platform/internal/webmail"
	"github.com/aonsyed/cyberpanel/platform/internal/webmaildata"
	"path/filepath"
	"testing"
)

func TestManageSieveDeniedConsumerCannotIssueCredential(t *testing.T) {
	provider := localManageSieveCredentials{service: &securewebmail.Service{}, repository: &securewebmail.SQLiteRepository{}}
	for _, scope := range []webmaildata.Scope{{}, {TenantID: "foreign", UserID: "user", MailboxID: "mailbox"}} {
		credentials, err := provider.CredentialsForManageSieve(context.Background(), scope)
		if err == nil || credentials.Username != "" || len(credentials.Secret) != 0 {
			t.Fatal("unauthorized consumer received credential")
		}
	}
}

func TestWebmailDataAssemblyWiresCanonicalVacation(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := securewebmail.NewSQLiteRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	service, err := assembleWebmailDataService(context.Background(), db, mail.SQLControlRepository{DB: db}, store, &audit.Service{}, "mail.example.invalid", &securewebmail.Service{}, repository)
	if err != nil {
		t.Fatal(err)
	}
	if service.Vacations == nil || service.Autoresponders == nil {
		t.Fatal("canonical vacation service missing")
	}
	native, ok := service.SieveRuntime.(*webmaildata.LocalManageSieveAdapter)
	if !ok {
		t.Fatal("native adapter missing")
	}
	provider, ok := native.Credentials.(localManageSieveCredentials)
	if !ok || provider.repository != repository || provider.service == nil {
		t.Fatal("authorized one-use grant provider missing")
	}
}
