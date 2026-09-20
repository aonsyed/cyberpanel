package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	_ "modernc.org/sqlite"
)

func TestIdentityPreparedIntentIsNotReportedApplied(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	index, err := NewSQLIndex(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = index.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer("test", private, map[string]ed25519.PublicKey{"test": public})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewWriter(root, index, signer)
	if err != nil {
		t.Fatal(err)
	}
	sink := IdentitySink{Service: &Service{Writer: writer}}
	if err = sink.Record(ctx, identity.AuditEvent{ID: "tenant-create-intent", ActorID: "owner", TenantID: "customer", Action: "tenant.create", TargetKind: "tenant", TargetID: "customer", Outcome: "prepared", RequestHash: strings.Repeat("a", 64), At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	records, err := index.Query(ctx, Query{Action: "tenant.create"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || string(records[0].Event.Outcome) != "prepared" {
		t.Fatal("prepared intent was missing or misreported as completion")
	}
}
