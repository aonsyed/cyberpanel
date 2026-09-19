//go:build linux

package apps

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

func TestQEMULiveApplicationSecretLease(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_APP_SECRETS") != "1" {
		t.Skip("requires installed QEMU secret-management broker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := secrets.NewLocalManagementClient()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := SQLRepository{DB: db}
	if err := store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	issuer, err := NewApplicationSecretIssuer(client, store, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	installation := InstallationID(fmt.Sprintf("qemu-app-%x", time.Now().UnixNano()))
	ref, err := issuer.IssueApplicationSecret(ctx, "qemu-tenant", "qemu-site", installation, "configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := issuer.RevokeApplicationSecret(cleanup, ref); err != nil {
			t.Errorf("revoke fixture: %v", err)
		}
	}()
	id, err := secrets.NewID(string(ref))
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.LoadApplicationSecretLease(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if before.Metadata.State != secrets.StateActive {
		t.Fatal("issued lease not active")
	}
	replay, err := issuer.IssueApplicationSecret(ctx, "qemu-tenant", "qemu-site", installation, "configuration")
	if err != nil || replay != ref {
		t.Fatalf("replay: %v", err)
	}
	after, err := store.LoadApplicationSecretLease(ctx, id)
	if err != nil || after.Metadata.Version != before.Metadata.Version || after.Metadata.BindingDigest != before.Metadata.BindingDigest {
		t.Fatalf("replay changed lease: %v", err)
	}
	if _, err := issuer.IssueApplicationSecret(ctx, "other-tenant", "qemu-site", installation, "configuration"); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("cross-tenant cached lease accepted: %v", err)
	}
	otherRelease, err := NewApplicationSecretIssuer(client, store, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherRelease.IssueApplicationSecret(ctx, "qemu-tenant", "qemu-site", installation, "configuration"); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("changed consumer release accepted cached lease: %v", err)
	}
	if err := issuer.RevokeApplicationSecret(ctx, ref); err != nil {
		t.Fatal(err)
	}
	lease, err := store.LoadApplicationSecretLease(ctx, id)
	if err != nil || lease.Metadata.State != secrets.StateRevoked {
		t.Fatalf("broker revocation not persisted: %v", err)
	}
	if err := issuer.RevokeApplicationSecret(ctx, ref); err != nil {
		t.Fatalf("revocation replay: %v", err)
	}
	adminRef, err := issuer.IssueApplicationSecret(ctx, "qemu-tenant", "qemu-site", installation, "administrator")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := issuer.RevokeApplicationSecret(cleanup, adminRef); err != nil {
			t.Errorf("revoke administrator fixture: %v", err)
		}
	}()
	if _, err := issuer.IssueApplicationSecret(ctx, "qemu-tenant", "other-site", installation, "administrator"); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("administrator lease reused across sites: %v", err)
	}
	if replay, err := issuer.IssueApplicationSecret(ctx, "qemu-tenant", "qemu-site", installation, "administrator"); err != nil || replay != adminRef {
		t.Fatalf("administrator replay: %v", err)
	}
	t.Log("actual broker issuance, exact cached replay, tenant/release binding rejection, revocation and durable lease verified")
}
