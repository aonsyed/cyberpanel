package apiserver

import (
	"encoding/json"
	"testing"
)

func TestDNSRecordReplacementAllowsDeletingFinalRecord(t *testing.T) {
	if err := validateDNSZoneImport(&DNSZoneImportPayload{Replace: true}); err != nil {
		t.Fatalf("explicit empty replacement must delete the final editable record: %v", err)
	}
	if err := validateDNSZoneImport(&DNSZoneImportPayload{}); err == nil {
		t.Fatal("empty merge must remain invalid")
	}
}

func TestDNSOptionalZonePayloadCanonicalization(t *testing.T) {
	for _, test := range []struct {
		name     string
		raw      json.RawMessage
		newValue func() any
		validate func(any) error
	}{
		{"records", json.RawMessage(`{"limit":1000}`), func() any { return &DNSRecordSetPagePayload{} }, validateDNSRecordSetPage},
		{"delete", json.RawMessage(`{}`), func() any { return &DNSZoneDeletePayload{} }, validateDNSZoneDelete},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := canonicalPayload(test.raw, test.newValue, test.validate); err != nil {
				t.Fatal("resource-scoped request without redundant zone", err)
			}
			if _, _, err := canonicalPayload(json.RawMessage(`{"zone":{"id":"incomplete"}}`), test.newValue, test.validate); err == nil {
				t.Fatal("incomplete explicit zone accepted")
			}
		})
	}
}
