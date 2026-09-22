//go:build linux

package dns

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestRecordReplacementPreservesSOAAndAuthority(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(powerDNSSQLiteSchema); err != nil {
		t.Fatal(err)
	}
	bound, err := newPowerDNSAuthoritativeDatabase(db, LocalPowerDNSDatabaseBinding().AuthoritativeIdentity(), LocalPowerDNSControlFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewSecuredPowerDNSAuthority(bound, nil)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := ParseName("records.invalid")
	ns, _ := ParseName("ns.records.invalid")
	mail, _ := ParseName("hostmaster.records.invalid")
	zone := ZoneSpec{ID: "zone_records", TenantID: "tenant_records", Name: name, Mode: ZoneNative, Account: "tenant_records", Generation: 1, SOA: SOAConfig{Primary: ns, Hostmaster: mail, Refresh: 3600, Retry: 600, Expire: 1209600, Minimum: 300, DefaultTTL: 3600}}
	sets := []RecordSet{{ZoneID: zone.ID, Owner: name, Kind: RR_A, TTL: 60, Records: []string{"192.0.2.1"}}, {ZoneID: zone.ID, Owner: name, Kind: RR_TXT, TTL: 60, Records: []string{"first"}}}
	if _, err = authority.ApplyZone(ctx, "records_create", zone, sets, nil); err != nil {
		t.Fatal(err)
	}
	zone.Generation++
	sets[0].Records = []string{"192.0.2.2"}
	if _, err = authority.ImportRecordSets(ctx, "records_update", zone, sets, true); err != nil {
		t.Fatal(err)
	}
	var address string
	if err = db.QueryRow("SELECT content FROM records WHERE type='A'").Scan(&address); err != nil || address != "192.0.2.2" {
		t.Fatal("record update", address, err)
	}
	foreign := zone
	foreign.TenantID = "tenant_foreign"
	foreign.Generation++
	if _, err = authority.ImportRecordSets(ctx, "records_foreign", foreign, nil, true); err == nil {
		t.Fatal("cross-tenant replacement accepted")
	}
	zone.Generation++
	request := PowerDNSBrokerRequest{Version: 1, RequestID: "records_request_20260922_fixture", Operation: PowerDNSBrokerImportRecordSets, Deadline: time.Now().Add(time.Minute), EffectID: "records_clear", Zone: &zone, Replace: true}
	if err = request.Validate(time.Now()); err != nil {
		t.Fatal("empty replacement broker admission", err)
	}
	request.Replace = false
	if err = request.Validate(time.Now()); err == nil {
		t.Fatal("empty merge broker admission")
	}
	if _, err = authority.ImportRecordSets(ctx, "records_clear", zone, nil, true); err != nil {
		t.Fatal("final record deletion", err)
	}
	var soa, editable int
	if err = db.QueryRow("SELECT COUNT(*) FROM records WHERE type='SOA'").Scan(&soa); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM records WHERE type<>'SOA'").Scan(&editable); err != nil {
		t.Fatal(err)
	}
	if soa != 1 || editable != 0 {
		t.Fatalf("SOA=%d editable=%d", soa, editable)
	}
	stored, err := authority.Zone(ctx, zone.TenantID, zone.ID)
	if err != nil || stored.Generation != zone.Generation {
		t.Fatal("ownership/generation lost", err)
	}
	if _, err = authority.ImportRecordSets(ctx, "records_stale", zone, nil, true); err == nil {
		t.Fatal("stale generation accepted")
	}
	if _, err = authority.DeleteZone(ctx, "records_delete", zone); err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Zone(ctx, zone.TenantID, zone.ID); err == nil {
		t.Fatal("deleted zone still readable")
	}
}
