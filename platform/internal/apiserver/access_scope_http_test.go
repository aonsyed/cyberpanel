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

	"github.com/aonsyed/cyberpanel/platform/internal/access"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/service"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/sqlrepo"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	_ "modernc.org/sqlite"
)

// Credential verification is a boundary fixture; Core authorization dispatch,
// real file handlers and the production SQLite hosting authority are exercised.
type fileScopeAuth struct{}

func (fileScopeAuth) Authenticate(_ context.Context, material AuthMaterial, _ RequestMeta) (Actor, error) {
	principal := identity.ID("tenant-reader")
	if material.APIKey == "owner-proof-key-not-production" {
		principal = "installation-owner"
	}
	return Actor{PrincipalID: principal, Assurance: identity.AssurancePassword, CredentialKind: CredentialAPIKey}, nil
}
func (fileScopeAuth) Authorize(_ context.Context, actor Actor, permission identity.Permission, scope identity.Scope, _ identity.AssuranceLevel) error {
	if permission != identity.MustPermission("file:read") {
		return ErrForbidden
	}
	if actor.PrincipalID != "installation-owner" && scope.TenantID != "tenant-aaa" {
		return ErrForbidden
	}
	return nil
}

type scopeFileExecutor struct {
	access.FileExecutor
	calls int
}

func (executor *scopeFileExecutor) List(_ context.Context, root access.SiteRoot, _ access.RelativePath, _ access.PageRequest) (access.FilePage, error) {
	executor.calls++
	path, _ := access.ParseRelativePath("protected-content.txt")
	return access.FilePage{Entries: []access.FileEntry{{Path: path, Kind: access.EntryRegular}}}, nil
}

func TestFileHTTPChecksTrustedSiteTenantBeforeExecutor(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sites.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository, err := sqlrepo.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = repository.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	for index, owner := range []string{"tenant-aaa", "tenant-bbb"} {
		tenant, _ := site.NewTenantID(owner)
		id, _ := site.NewSiteID(fmt.Sprintf("site-%d", index))
		project, _ := site.NewProjectID("project-proof")
		hostname, _ := site.ParseHostname(fmt.Sprintf("scope-%d.example.invalid", index))
		aggregate, createErr := site.Create(site.CreateInput{ID: id, TenantID: tenant, ProjectID: project, PrimaryHostname: hostname, PHPProfile: site.PHPProfile83})
		if createErr != nil {
			t.Fatal(createErr)
		}
		scope := service.CommandScope{TenantID: tenant, SiteID: id}
		request := service.SiteEffectRequest{EffectID: fmt.Sprintf("effect-%d", index)}
		command := fmt.Sprintf("create-%d", index)
		if _, err = repository.Admit(ctx, service.Admission{CommandID: command, Digest: "proof", Scope: scope, Proposal: aggregate, AcceptedAt: time.Now(), Request: request}); err != nil {
			t.Fatal(err)
		}
		if _, err = repository.Complete(ctx, service.Completion{CommandID: command, Digest: "proof", Scope: scope, Request: request, Status: service.OperationApplied}); err != nil {
			t.Fatal(err)
		}
	}
	registry, err := NewDomainRegistry()
	if err != nil {
		t.Fatal(err)
	}
	executor := &scopeFileExecutor{}
	files := &access.FileService{Executor: executor, Store: access.SQLStore{DB: db}}
	services := DomainServices{Files: files, HostingQuery: repository}
	if err = services.Bind(registry); err != nil {
		t.Fatal(err)
	}
	nonces, _ := NewDirectoryNonceStore(filepath.Join(t.TempDir(), "nonces"))
	ledger, _ := NewDirectoryIdempotencyLedger(filepath.Join(t.TempDir(), "ledger"))
	core, err := NewCore(registry, fileScopeAuth{}, exportHTTPVerifier{}, nonces, ledger)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(core.Handler())
	defer server.Close()
	sequence := 0
	invoke := func(tenant, resource, key string) CoreResponse {
		t.Helper()
		sequence++
		payload, _ := json.Marshal(FileListPayload{Root: access.SiteRoot{SiteID: access.SiteID(resource), Kind: access.RootPublic}, Page: access.PageRequest{Limit: 10}})
		request := CoreRequest{ProtocolVersion: InternalProtocolVersion, KeyID: "scope-proof", Nonce: fmt.Sprintf("scope-proof-nonce-%08d", sequence), SentAt: time.Now().UTC(), Meta: RequestMeta{ClientIP: netip.MustParseAddr("127.0.0.1"), Host: "localhost", TLS: true, UserAgentDigest: strings.Repeat("a", 64)}, Auth: &AuthMaterial{Kind: CredentialAPIKey, APIKey: key}, Request: RequestEnvelope{APIVersion: APIVersion, RequestID: fmt.Sprintf("scope-request-%08d", sequence), Operation: "access.files.list", TenantID: tenant, ResourceID: resource, Payload: payload}}
		encoded, _ := json.Marshal(request)
		response, e := http.Post(server.URL+"/internal/v1/invoke", ContentTypeJSON, bytes.NewReader(encoded))
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		var result CoreResponse
		if e = json.NewDecoder(response.Body).Decode(&result); e != nil {
			t.Fatal(e)
		}
		return result
	}
	tenantKey := "tenant-proof-key-not-production"
	ownerKey := "owner-proof-key-not-production"
	if result := invoke("tenant-aaa", "site-0", tenantKey); result.Status != 200 {
		t.Fatalf("own site denied: %+v", result.Problem)
	}
	before := executor.calls
	if result := invoke("tenant-aaa", "site-1", tenantKey); result.Status != 404 {
		t.Fatalf("tenant actor could select foreign site under own tenant: HTTP%d", result.Status)
	}
	if executor.calls != before {
		t.Fatal("mismatched tenant reached executor")
	}
	if result := invoke("tenant-bbb", "site-1", tenantKey); result.Status != 403 {
		t.Fatalf("tenant actor could claim other tenant: HTTP%d", result.Status)
	}
	if result := invoke("tenant-bbb", "site-1", ownerKey); result.Status != 200 {
		t.Fatalf("installation owner correct binding denied: HTTP%d", result.Status)
	}
	if result := invoke("tenant-aaa", "site-1", ownerKey); result.Status != 404 {
		t.Fatalf("global owner bypassed actual ownership binding: HTTP%d", result.Status)
	}
	if result := invoke("tenant-aaa", "missing-site", ownerKey); result.Status != 404 {
		t.Fatalf("unknown site did not fail closed: HTTP%d", result.Status)
	}
	// Every file-manager transfer/mutation entry point must reject the binding
	// before even loading its upload/download/trash token or invoking a broker.
	names := []string{"access.files.list", "access.files.read_editor", "access.files.mutate", "access.upload.begin", "access.upload.chunk", "access.upload.commit", "access.upload.abort", "access.download.issue", "access.files.download.issue", "access.download.get", "access.download.read", "access.download.close", "access.trash.create", "access.trash.move", "access.file.trash", "access.trash.restore", "access.trash.purge", "access.archive.create", "access.archive.extract"}
	for _, name := range names {
		operation, _ := registry.Lookup(name)
		if operation.Handler == nil {
			t.Fatalf("missing handler %s", name)
		}
		_, err = operation.Handler(ctx, Invocation{Request: RequestEnvelope{TenantID: "tenant-aaa", ResourceID: "site-1"}}, operation.NewPayload())
		if err != ErrNotFound {
			t.Fatalf("%s failed binding guard: %v", name, err)
		}
	}
	noAuthority, _ := NewDomainRegistry()
	if err = (DomainServices{Files: files}).Bind(noAuthority); err != nil {
		t.Fatal(err)
	}
	operation, _ := noAuthority.Lookup("access.files.list")
	if _, err = operation.Handler(ctx, Invocation{Request: RequestEnvelope{TenantID: "tenant-aaa", ResourceID: "site-0"}}, operation.NewPayload()); err != ErrUnavailable {
		t.Fatalf("missing authority did not fail closed: %v", err)
	}
}
