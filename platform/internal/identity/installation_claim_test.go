package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

type claimVerifier struct {
	AuthVerifier
	revoked, enrolled int
}

func (v *claimVerifier) EnrollPassword(context.Context, ID, []byte) (ID, error) {
	v.enrolled++
	return ID(fmt.Sprintf("claim_verifier_%d", v.enrolled)), nil
}
func (v *claimVerifier) Revoke(context.Context, ID) error { v.revoked++; return nil }

type claimAudit struct{}

func (claimAudit) Record(context.Context, AuditEvent) error { return nil }

func TestInstallationCanOnlyBeClaimedOnce(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	verifier := &claimVerifier{}
	service, err := NewService(store, verifier, claimAudit{})
	if err != nil {
		t.Fatal(err)
	}
	claim := func(suffix string) InstallationClaim {
		return InstallationClaim{PrincipalID: ID("owner_" + suffix), TenantID: ID("tenant_" + suffix), MembershipID: ID("member_" + suffix), RoleID: ID("role_" + suffix), BindingID: ID("binding_" + suffix), PlanID: ID("plan_" + suffix), Username: "owner_" + suffix, Email: "owner@example.invalid", DisplayName: "QEMU owner", Password: []byte("qemu-only-test-password"), Quota: ResourceQuota{Sites: 1, Domains: 1, DiskBytes: 1 << 30, Inodes: 1000, MemoryBytes: 1 << 28, PIDs: 32, PHPConcurrency: 2}}
	}
	if _, err := service.ClaimInstallation(ctx, claim("first")); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"second", "first"} {
		if _, err := service.ClaimInstallation(ctx, claim(suffix)); !errors.Is(err, ErrConflict) {
			t.Fatalf("second installation claim %s accepted or wrong error: %v", suffix, err)
		}
	}
	var owners int
	if err := db.QueryRow("SELECT COUNT(*) FROM identity_tenants WHERE kind='owner'").Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Fatalf("installation has %d owners", owners)
	}
	if verifier.revoked != 2 {
		t.Fatalf("rejected claims leaked enrolled verifiers: revoked %d", verifier.revoked)
	}
	// Existing installations predate the singleton row. Existing authority must
	// still prevent a fresh claim when the new table has no marker yet.
	if _, err := db.Exec("DELETE FROM identity_installation_claim"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ClaimInstallation(ctx, claim("older_install")); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted claim over existing authority without marker: %v", err)
	}
	var kind string
	var length int
	if err := db.QueryRow("SELECT typeof(public_data),length(public_data) FROM identity_credentials LIMIT 1").Scan(&kind, &length); err != nil {
		t.Fatal(err)
	}
	if kind != "blob" || length != 0 {
		t.Fatalf("password metadata = %s/%d, want empty blob", kind, length)
	}
}

func TestClaimReservationRollsBackAndRejectsDuplicate(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "reservation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	for _, commit := range []bool{false, true} {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := reserveInstallationClaim(ctx, tx, "first_owner"); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if commit {
			err = tx.Commit()
		} else {
			err = tx.Rollback()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := reserveInstallationClaim(ctx, tx, "second_owner"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate claim reservation: %v", err)
	}
}
