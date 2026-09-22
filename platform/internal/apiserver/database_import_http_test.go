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

type importHTTPAuth struct{ exportHTTPAuth }

func TestReplacementPreparationKeepsUploadPathDisabled(t *testing.T) {
	var operations *DatabaseTransferOperations
	_, err := operations.PrepareDatabaseImport(context.Background(), Invocation{}, DatabaseImportPreparePayload{Replacement: true, UploadSource: &database.TransferUploadIntent{}})
	if err != database.ErrUnavailable {
		t.Fatal("upload replacement reached execution", err)
	}
}

func TestImportPreparationIdentityDoesNotUseEmptyReadIdempotencyKey(t *testing.T) {
	actor, _ := identity.NewID("import-owner")
	inv := Invocation{Actor: Actor{PrincipalID: actor}, Request: RequestEnvelope{Operation: "database.import.prepare", TenantID: "import-tenant", ResourceID: "import-site", RequestID: "prepare-request-one"}}
	first, key := databaseImportIdentity(inv)
	if same, sameKey := databaseImportIdentity(inv); same != first || sameKey != key {
		t.Fatal("same preparation identity changed")
	}
	for _, change := range []func(*Invocation){
		func(v *Invocation) { v.Request.RequestID = "prepare-request-two" },
		func(v *Invocation) { v.Request.TenantID = "other-tenant" },
		func(v *Invocation) { v.Actor.PrincipalID, _ = identity.NewID("another-import-owner") },
	} {
		next := inv
		change(&next)
		id, nextKey := databaseImportIdentity(next)
		if id == first || nextKey == key {
			t.Fatal("distinct read-only preparations share a durable job identity")
		}
	}
}

func (auth *importHTTPAuth) Authorize(_ context.Context, actor Actor, permission identity.Permission, scope identity.Scope, assurance identity.AssuranceLevel) error {
	if auth.denied || permission != identity.MustPermission("database:manage") || scope.Kind != identity.ScopeSite || assurance != identity.AssuranceMFA || actor.Assurance < assurance {
		return ErrForbidden
	}
	return nil
}

type importHTTPDomain struct {
	calls      int
	invocation Invocation
	id         database.ResourceID
}

func (*importHTTPDomain) PrepareDatabaseImport(context.Context, Invocation, DatabaseImportPreparePayload) (database.TransferJob, error) {
	return database.TransferJob{}, database.ErrUnavailable
}
func (*importHTTPDomain) RunDatabaseImport(context.Context, Invocation, database.TransferJob) (database.TransferReceipt, error) {
	return database.TransferReceipt{}, database.ErrUnavailable
}
func (domain *importHTTPDomain) InspectDatabaseImport(_ context.Context, inv Invocation, id database.ResourceID) (database.TransferJobState, error) {
	domain.calls++
	domain.invocation = inv
	domain.id = id
	return database.TransferJobState{Generation: 3, Status: database.TransferCompleted}, nil
}

func (domain *importHTTPDomain) CancelDatabaseImport(ctx context.Context, inv Invocation, id database.ResourceID) (database.TransferJobState, error) {
	state, err := domain.InspectDatabaseImport(ctx, inv, id)
	state.Status = database.TransferCancelled
	state.CancellationRequested = true
	return state, err
}

func (domain *importHTTPDomain) RecoverDatabaseImport(ctx context.Context, inv Invocation, id database.ResourceID) (database.TransferReceipt, error) {
	_, err := domain.InspectDatabaseImport(ctx, inv, id)
	return database.TransferReceipt{JobID: id, Status: database.TransferCompleted, Generation: 3}, err
}

// Drives a real HTTP core. Peer signatures, authentication and domain execution
// are fixtures here, not installed end-to-end import authorization evidence.
func TestDatabaseImportHTTPPolicyAndScope(t *testing.T) {
	for _, operation := range []string{"database.import.inspect", "database.import.cancel", "database.import.recover"} {
		t.Run(operation, func(t *testing.T) { testDatabaseImportHTTPPolicyAndScope(t, operation) })
	}
}

func testDatabaseImportHTTPPolicyAndScope(t *testing.T, operation string) {
	registry, err := NewDomainRegistry()
	if err != nil {
		t.Fatal(err)
	}
	domain := &importHTTPDomain{}
	if err = bindDatabaseImportContracts(registry, DomainServices{DatabaseTransfers: domain}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"database.import.prepare", "database.import.run", "database.import.inspect", "database.import.cancel", "database.import.recover"} {
		op, ok := registry.Lookup(name)
		if !ok || op.Handler == nil || op.Permission != identity.MustPermission("database:manage") || op.Auth != AuthRequired || op.Assurance != identity.AssuranceMFA || op.Mutating != (name != "database.import.prepare" && name != "database.import.inspect") {
			t.Fatal("unsafe import contract", name)
		}
	}
	principal, _ := identity.NewID("http-import-actor")
	auth := &importHTTPAuth{exportHTTPAuth: exportHTTPAuth{actor: Actor{PrincipalID: principal, Assurance: identity.AssuranceMFA, CredentialKind: CredentialAPIKey}}}
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
	invoke := func(payload, tenant, resource string, authenticated bool) CoreResponse {
		t.Helper()
		sequence++
		request := CoreRequest{ProtocolVersion: InternalProtocolVersion, KeyID: "qemu-fixture", Nonce: fmt.Sprintf("qemu-import-nonce-%08d", sequence), SentAt: time.Now().UTC(), Meta: RequestMeta{ClientIP: netip.MustParseAddr("127.0.0.1"), Host: "localhost", TLS: true, UserAgentDigest: strings.Repeat("a", 64)}, Request: RequestEnvelope{APIVersion: APIVersion, RequestID: fmt.Sprintf("import-http-%08d", sequence), Operation: "database.import.inspect", TenantID: tenant, ResourceID: resource, Payload: json.RawMessage(payload)}}
		request.Request.Operation = operation
		if operation != "database.import.inspect" {
			request.Request.ExpectedGeneration = 3
			request.IdempotencyKey = fmt.Sprintf("cancel-http-%08d", sequence)
		}
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
	payload := `{"job_id":"import-job"}`
	if response := invoke(payload, "import-tenant", "import-site", true); response.Status != http.StatusOK {
		t.Fatal("import inspection HTTP", response.Status, response.Problem)
	}
	if domain.calls != 1 || domain.id.String() != "import-job" || domain.invocation.Actor.PrincipalID != principal || domain.invocation.Request.TenantID != "import-tenant" || domain.invocation.Request.ResourceID != "import-site" {
		t.Fatal("import scope not server-derived")
	}
	for _, invalid := range []string{`{"job_id":""}`, `{"job_id":"import-job","actor":"intruder"}`, `{"job_id":"import-job","tenant_id":"intruder"}`} {
		if response := invoke(invalid, "import-tenant", "import-site", true); response.Status != http.StatusBadRequest {
			t.Fatal("invalid import payload accepted", response.Status)
		}
	}
	if response := invoke(payload, "import-tenant", "", true); response.Status != http.StatusBadRequest {
		t.Fatal("missing site accepted", response.Status)
	}
	if response := invoke(payload, "import-tenant", "import-site", false); response.Status != http.StatusUnauthorized {
		t.Fatal("anonymous import inspection accepted", response.Status)
	}
	auth.denied = true
	if response := invoke(payload, "import-tenant", "import-site", true); response.Status != http.StatusForbidden {
		t.Fatal("denied import inspection accepted", response.Status)
	}
	auth.denied = false
	auth.actor.Assurance = identity.AssurancePassword
	if response := invoke(payload, "import-tenant", "import-site", true); response.Status != http.StatusForbidden {
		t.Fatal("low assurance accepted", response.Status)
	}
	if domain.calls != 1 {
		t.Fatal("rejected invocation reached import domain")
	}
}
