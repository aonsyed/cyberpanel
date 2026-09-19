package database

import (
	"encoding/json"
	"testing"
)

func TestResourceIDJSONOptionalAndRequiredBoundaries(t *testing.T) {
	for _, value := range []string{"", "database-1"} {
		var original ResourceID
		if value != "" {
			original, _ = NewResourceID(value)
		}
		encoded, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		decoded, _ := NewResourceID("previous-value")
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded != original {
			t.Fatalf("round-trip %q produced %q", value, decoded.String())
		}
	}
	for _, raw := range []string{`"unsafe/id"`, `" spaced "`, `42`, `{}`} {
		var id ResourceID
		if err := json.Unmarshal([]byte(raw), &id); err == nil {
			t.Fatalf("accepted invalid ID: %s", raw)
		}
	}
	if _, err := NewResourceID(""); err == nil {
		t.Fatal("constructor accepted required empty ID")
	}
	validID, _ := NewResourceID("resource-1")
	metadata := Metadata{ID: validID, Generation: 1, Status: ResourceStatus{Lifecycle: LifecycleReady, Health: HealthHealthy, Reconciliation: ReconciliationInSync}}
	if err := validateMetadata(metadata, false); err != nil {
		t.Fatal(err)
	}
	metadata.ID = ResourceID{}
	if err := validateMetadata(metadata, false); err == nil {
		t.Fatal("required metadata ID accepted empty value")
	}
}

func TestDatabaseWideGrantJSONRoundTrip(t *testing.T) {
	original := Grant{Scope: GrantScopeDatabase, Privileges: []Privilege{PrivilegeSelect}}
	if err := validateGrant(original); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Grant
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validateGrant(decoded); err != nil {
		t.Fatal(err)
	}
	decoded.Scope = GrantScopeTable
	if err := validateGrant(decoded); err == nil {
		t.Fatal("table grant accepted missing object name")
	}
	if _, err := ParseSQLIdentifier(""); err == nil {
		t.Fatal("required identifier accepted empty value")
	}
	for _, raw := range []string{`"unsafe.name"`, `"a;DROP"`, `42`, `{}`} {
		var value SQLIdentifier
		if err := json.Unmarshal([]byte(raw), &value); err == nil {
			t.Fatalf("accepted unsafe identifier %s", raw)
		}
	}
}
