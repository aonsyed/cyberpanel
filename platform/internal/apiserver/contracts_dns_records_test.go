package apiserver

import "testing"

func TestDNSRecordReplacementAllowsDeletingFinalRecord(t *testing.T) {
	if err := validateDNSZoneImport(&DNSZoneImportPayload{Replace: true}); err != nil {
		t.Fatalf("explicit empty replacement must delete the final editable record: %v", err)
	}
	if err := validateDNSZoneImport(&DNSZoneImportPayload{}); err == nil {
		t.Fatal("empty merge must remain invalid")
	}
}
