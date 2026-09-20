package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

// HTTP routing/canonicalization/auth policy and server-derived call projection
// are real. Identity/signature checks and domain execution are explicit fixtures;
// native coordinator/broker/MariaDB behavior is covered by the QEMU live test.
type exportHTTPAuth struct {
	actor  Actor
	denied bool
}

func (auth *exportHTTPAuth) Authenticate(context.Context, AuthMaterial, RequestMeta) (Actor, error) {
	return auth.actor, nil
}
func (auth *exportHTTPAuth) Authorize(_ context.Context, _ Actor, permission identity.Permission, _ identity.Scope, assurance identity.AssuranceLevel) error {
	if auth.denied || permission != identity.MustPermission("database:console") || assurance != identity.AssuranceMFA {
		return ErrForbidden
	}
	return nil
}

type exportHTTPVerifier struct{}

func (exportHTTPVerifier) Verify(CoreRequest) error { return nil }

type exportHTTPDomain struct {
	DatabaseCommandService
	calls   int
	call    database.WorkspaceCall
	actor   string
	options database.WorkspaceExportOptions
}

func (domain *exportHTTPDomain) PrepareWorkspaceExport(_ context.Context, call database.WorkspaceCall, actor, command string, options database.WorkspaceExportOptions) (database.TransferJob, error) {
	domain.calls++
	domain.call = call
	domain.actor = actor
	domain.options = options
	return database.TransferJob{CreatedBy: actor}, nil
}
func (*exportHTTPDomain) RunWorkspaceExport(context.Context, database.WorkspaceCall, string, database.TransferJob) (database.TransferProcessReceipt, error) {
	return database.TransferProcessReceipt{}, database.ErrUnavailable
}
func (*exportHTTPDomain) DownloadWorkspaceExport(context.Context, database.WorkspaceCall, string, database.TransferJob, database.TransferArtifactDescriptor, uint64, uint32) (database.WorkspaceExportChunk, error) {
	return database.WorkspaceExportChunk{}, database.ErrUnavailable
}

func TestDatabaseExportHTTPPrepareScopeAndPolicy(t *testing.T) {
	registry, err := NewDomainRegistry()
	if err != nil {
		t.Fatal(err)
	}
	domain := &exportHTTPDomain{}
	if err = bindDatabaseExportContracts(registry, DomainServices{Database: domain}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"database.workspace.export_prepare", "database.workspace.export", "database.workspace.export_download"} {
		op, exists := registry.Lookup(name)
		if !exists || op.Handler == nil || op.Auth != AuthRequired || op.Assurance != identity.AssuranceMFA || op.Mutating != (name == "database.workspace.export") {
			t.Fatal("unsafe export contract", name)
		}
	}
	principal, _ := identity.NewID("http-export-actor")
	auth := &exportHTTPAuth{actor: Actor{PrincipalID: principal, Assurance: identity.AssuranceMFA, CredentialKind: CredentialAPIKey}}
	nonces, err := NewDirectoryNonceStore(filepath.Join(t.TempDir(), "nonces"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := NewDirectoryIdempotencyLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	core, err := NewCore(registry, auth, exportHTTPVerifier{}, nonces, ledger)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(core.Handler())
	defer server.Close()
	sequence := 0
	invoke := func(payload string, tenant, resource string, generation uint64, authenticated bool) CoreResponse {
		t.Helper()
		sequence++
		request := CoreRequest{ProtocolVersion: InternalProtocolVersion, KeyID: "qemu-fixture", Nonce: fmt.Sprintf("qemu-export-nonce-%08d", sequence), SentAt: time.Now().UTC(), Meta: RequestMeta{ClientIP: netip.MustParseAddr("127.0.0.1"), Host: "localhost", TLS: true, UserAgentDigest: strings.Repeat("a", 64)}, Request: RequestEnvelope{APIVersion: APIVersion, RequestID: fmt.Sprintf("export-http-%08d", sequence), Operation: "database.workspace.export_prepare", TenantID: tenant, ResourceID: resource, ExpectedGeneration: generation, Payload: json.RawMessage(payload)}}
		if authenticated {
			request.Auth = &AuthMaterial{Kind: CredentialAPIKey, APIKey: "qemu-fixture-not-a-real-key"}
		}
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.Post(server.URL+"/internal/v1/invoke", ContentTypeJSON, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result CoreResponse
		if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	payload := `{"session_id":"export-session","options":{"compression":"gzip","selection":{"schema":true,"data":true}}}`
	if response := invoke(payload, "export-tenant", "export-site", 3, true); response.Status != http.StatusOK || response.Problem != nil {
		t.Fatal("prepare HTTP failed", response.Status, response.Problem)
	}
	if domain.calls != 1 || domain.call.TenantID.String() != "export-tenant" || domain.call.SiteID.String() != "export-site" || domain.call.SessionID.String() != "export-session" || domain.call.SessionGeneration != 3 || domain.actor != principal.String() {
		t.Fatal("scope or actor not server-derived")
	}
	for _, invalid := range []string{strings.Replace(payload, `"gzip"`, `"zip"`, 1), strings.Replace(payload, `"session_id"`, `"access"`, 1), strings.Replace(payload, `"options":`, `"tenant_id":"attacker","options":`, 1)} {
		if result := invoke(invalid, "export-tenant", "export-site", 3, true); result.Status != http.StatusBadRequest {
			t.Fatal("invalid payload accepted", result.Status)
		}
	}
	if result := invoke(payload, "export-tenant", "export-site", 0, true); result.Status != http.StatusBadRequest {
		t.Fatal("missing generation accepted", result.Status)
	}
	if result := invoke(payload, "export-tenant", "export-site", 3, false); result.Status != http.StatusUnauthorized {
		t.Fatal("anonymous export accepted", result.Status)
	}
	auth.denied = true
	if result := invoke(payload, "export-tenant", "export-site", 3, true); result.Status != http.StatusForbidden {
		t.Fatal("authorization denial ignored", result.Status)
	}
	if domain.calls != 1 {
		t.Fatal("rejected request reached domain")
	}
}
