package apiserver

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarketingCanonicalPayloadSurvivesGatewayCoreBoundary(t *testing.T) {
	registry := NewRegistry()
	if err := registerMarketingContracts(registry); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ operation, payload string }{
		{"marketing.template.create", `{"name":"Local template","text":"Exact content"}`},
		{"marketing.template.update", `{"name":"Local template","text":"Exact content"}`},
		{"marketing.campaign.create", `{"list_id":"list_qa","subject":"Local campaign","template_ref":"template_qa.1","from_mailbox":"mailbox_qa"}`},
		{"marketing.campaign.update", `{"list_id":"list_qa","subject":"Local campaign","template_ref":"template_qa.1","from_mailbox":"mailbox_qa"}`},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			request := RequestEnvelope{APIVersion: APIVersion, RequestID: "req_marketing_normalization", Operation: tc.operation, TenantID: "tenant_qa", Payload: json.RawMessage(tc.payload)}
			if tc.operation == "marketing.template.update" || tc.operation == "marketing.campaign.update" {
				request.ResourceID = "resource_qa"
				request.ExpectedGeneration = 1
			}
			_, _, gateway, err := registry.Canonicalize(request)
			if err != nil {
				t.Fatal("gateway:", err)
			}
			_, _, core, err := registry.Canonicalize(gateway)
			if err != nil {
				t.Fatal("core rejected normalized gateway payload:", err)
			}
			if !bytes.Equal(gateway.Payload, core.Payload) {
				t.Fatal("normalization is not idempotent")
			}
		})
	}
}

func TestMarketingRejectsOriginalMixedPayload(t *testing.T) {
	registry := NewRegistry()
	if err := registerMarketingContracts(registry); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ operation, payload string }{
		{"marketing.template.create", `{"name":"Flat","text":"content","template":{"name":"Nested","text":"content"}}`},
		{"marketing.campaign.create", `{"list_id":"list_qa","subject":"Flat","template_ref":"template_qa.1","from_mailbox":"mailbox_qa","campaign":{"subject":"Nested"}}`},
	} {
		request := RequestEnvelope{APIVersion: APIVersion, RequestID: "req_marketing_mixed", Operation: tc.operation, TenantID: "tenant_qa", Payload: json.RawMessage(tc.payload)}
		if _, _, _, err := registry.Canonicalize(request); err == nil {
			t.Fatalf("accepted mixed %s", tc.operation)
		}
	}
}
