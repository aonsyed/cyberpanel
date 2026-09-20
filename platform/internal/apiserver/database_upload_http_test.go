package apiserver

import (
	"bytes"
	"context"
	"database/sql"
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
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

func uploadHTTPIntent(t *testing.T) database.TransferUploadIntent {
	t.Helper()
	now := time.Now().UTC()
	id, _ := database.NewResourceID("http-upload")
	db, _ := database.NewResourceID("http-upload-db")
	tenant, _ := site.NewTenantID("upload-tenant")
	siteID, _ := site.NewSiteID("upload-site")
	intent, err := database.SealTransferUploadIntent(database.TransferUploadIntent{ID: id, TenantID: tenant, SiteID: siteID, DatabaseID: db, DatabaseGeneration: 1, CreatedBy: "http-upload-actor", Compression: database.TransferCompressionNone, Bytes: 5, PayloadDigest: strings.Repeat("a", 64), CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

type uploadHTTPDomain struct {
	importHTTPDomain
	intent      database.TransferUploadIntent
	uploadCalls int
	lastAction  string
}

func (d *uploadHTTPDomain) BeginDatabaseUpload(_ context.Context, inv Invocation, _ DatabaseUploadBeginPayload) (DatabaseUploadBeginResult, error) {
	d.uploadCalls++
	d.invocation = inv
	d.lastAction = "begin"
	return DatabaseUploadBeginResult{Intent: d.intent, State: database.TransferUploadResult{Action: "begin", IntentDigest: d.intent.Digest}}, nil
}
func (d *uploadHTTPDomain) ExecuteDatabaseUpload(_ context.Context, inv Invocation, r database.TransferUploadRequest) (database.TransferUploadResult, error) {
	d.uploadCalls++
	d.invocation = inv
	d.lastAction = r.Action
	return database.TransferUploadResult{Action: r.Action, IntentDigest: r.Intent.Digest, NextOffset: r.Offset + uint64(len(r.Data))}, nil
}

// HTTP/signature/auth peers and upload domain are fixtures. Socket/native upload
// behavior is independently exercised by the QEMU database broker suite.
func TestDatabaseUploadHTTPContractsAndPolicy(t *testing.T) {
	registry, err := NewDomainRegistry()
	if err != nil {
		t.Fatal(err)
	}
	domain := &uploadHTTPDomain{intent: uploadHTTPIntent(t)}
	if err = bindDatabaseImportContracts(registry, DomainServices{DatabaseTransfers: domain}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"begin", "chunk", "status", "finish", "discard"} {
		op, ok := registry.Lookup("database.upload." + action)
		if !ok || op.Handler == nil || op.Auth != AuthRequired || op.Permission != identity.MustPermission("database:manage") || op.Assurance != identity.AssuranceMFA || op.Mutating != (action != "status") || op.MaximumBodyBytes > 1<<20 {
			t.Fatal("unsafe upload contract", action)
		}
	}
	principal, _ := identity.NewID(domain.intent.CreatedBy)
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
	invoke := func(action string, payload any, authenticated bool, resource string) CoreResponse {
		t.Helper()
		sequence++
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		request := CoreRequest{ProtocolVersion: InternalProtocolVersion, KeyID: "qemu-fixture", Nonce: fmt.Sprintf("qemu-upload-nonce-%08d", sequence), SentAt: time.Now().UTC(), Meta: RequestMeta{ClientIP: netip.MustParseAddr("127.0.0.1"), Host: "localhost", TLS: true, UserAgentDigest: strings.Repeat("a", 64)}, Request: RequestEnvelope{APIVersion: APIVersion, RequestID: fmt.Sprintf("upload-http-%08d", sequence), Operation: "database.upload." + action, TenantID: "upload-tenant", ResourceID: resource, ExpectedGeneration: 1, Payload: raw}}
		if action != "status" {
			request.IdempotencyKey = fmt.Sprintf("upload-key-%08d", sequence)
		}
		if authenticated {
			request.Auth = &AuthMaterial{Kind: CredentialAPIKey, APIKey: "qemu-fixture-not-real"}
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
	begin := DatabaseUploadBeginPayload{DatabaseID: domain.intent.DatabaseID, Bytes: 5, Digest: domain.intent.PayloadDigest, Compression: domain.intent.Compression}
	if r := invoke("begin", begin, true, "upload-site"); r.Status != 201 {
		t.Fatal("begin HTTP", r.Status, r.Problem)
	}
	for _, action := range []string{"chunk", "status", "finish", "discard"} {
		p := DatabaseUploadPayload{Intent: domain.intent}
		if action == "chunk" {
			p.Data = []byte("hello")
		}
		if r := invoke(action, p, true, "upload-site"); r.Status != 200 {
			t.Fatal(action, r.Status, r.Problem)
		}
		if domain.lastAction != action {
			t.Fatal("action bound to wrong closure")
		}
	}
	if domain.invocation.Actor.PrincipalID != principal || domain.invocation.Request.TenantID != "upload-tenant" || domain.invocation.Request.ResourceID != "upload-site" {
		t.Fatal("scope not derived from authenticated envelope")
	}
	calls := domain.uploadCalls
	for _, p := range []any{map[string]any{"intent": domain.intent, "data": []byte("hello"), "actor": "intruder"}, DatabaseUploadPayload{Intent: domain.intent, Data: make([]byte, database.MaximumTransferUploadChunk+1)}, DatabaseUploadPayload{Intent: domain.intent, Offset: 5, Data: []byte("x")}} {
		if r := invoke("chunk", p, true, "upload-site"); r.Status != 400 {
			t.Fatal("invalid upload admitted", r.Status)
		}
	}
	if r := invoke("begin", begin, false, "upload-site"); r.Status != 401 {
		t.Fatal("anonymous upload admitted", r.Status)
	}
	if r := invoke("begin", begin, true, ""); r.Status != 400 {
		t.Fatal("missing scope admitted", r.Status)
	}
	auth.denied = true
	if r := invoke("begin", begin, true, "upload-site"); r.Status != 403 {
		t.Fatal("denied upload admitted", r.Status)
	}
	auth.denied = false
	auth.actor.Assurance = identity.AssurancePassword
	if r := invoke("begin", begin, true, "upload-site"); r.Status != 403 {
		t.Fatal("password-only upload admitted", r.Status)
	}
	if domain.uploadCalls != calls {
		t.Fatal("rejected request reached upload domain")
	}
}

func TestDatabaseUploadIntentPersistenceAndScope(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "upload.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err = bootstrapDatabaseUploadIntents(ctx, db); err != nil {
		t.Fatal(err)
	}
	operations := &DatabaseTransferOperations{control: db}
	intent := uploadHTTPIntent(t)
	first, err := operations.persistUploadIntent(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	retry := intent
	retry.CreatedAt = retry.CreatedAt.Add(time.Minute)
	retry.ExpiresAt = retry.ExpiresAt.Add(time.Minute)
	retry, _ = database.SealTransferUploadIntent(retry)
	resumed, err := operations.persistUploadIntent(ctx, retry)
	if err != nil || resumed.Digest != first.Digest {
		t.Fatal("retry allocated new upload identity", err)
	}
	changed := retry
	changed.Bytes++
	changed, _ = database.SealTransferUploadIntent(changed)
	if _, err = operations.persistUploadIntent(ctx, changed); err == nil {
		t.Fatal("idempotency key changed upload size")
	}
	actor, _ := identity.NewID(intent.CreatedBy)
	inv := Invocation{Actor: Actor{PrincipalID: actor}, Request: RequestEnvelope{TenantID: intent.TenantID.String(), ResourceID: intent.SiteID.String(), ExpectedGeneration: intent.DatabaseGeneration}}
	for _, change := range []func(*Invocation){func(i *Invocation) { i.Actor.PrincipalID, _ = identity.NewID("foreign-owner") }, func(i *Invocation) { i.Request.TenantID = "foreign-tenant" }, func(i *Invocation) { i.Request.ResourceID = "foreign-site" }, func(i *Invocation) { i.Request.ExpectedGeneration++ }} {
		wrong := inv
		change(&wrong)
		if err = operations.authorizeUpload(ctx, wrong, intent); err == nil {
			t.Fatal("foreign upload scope accepted")
		}
	}
}
