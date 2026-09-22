//go:build linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/audit"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
)

type replacementNativeSecrets struct {
	database.LinuxMariaDBSecretSource
}
type replacementIdentityVerifier struct{ identity.AuthVerifier }

func (replacementIdentityVerifier) EnrollPassword(context.Context, identity.ID, []byte) (identity.ID, error) {
	return identity.ID("replacement-fixture-verifier"), nil
}

type replacementIdentityAudit struct{}

func (replacementIdentityAudit) Record(context.Context, identity.AuditEvent) error { return nil }

type replacementSites struct{ aggregate site.Site }

func (s replacementSites) Load(_ context.Context, tenant site.TenantID, id site.SiteID) (site.Site, error) {
	if s.aggregate.TenantID() != tenant || s.aggregate.ID() != id {
		return site.Site{}, database.ErrUnauthorized
	}
	return s.aggregate, nil
}

// The HTTP router, production operations, identity authorization, SQLite jobs,
// coordinator and native MariaDB executor are real. Only transport signature
// verification/authentication use a fixture credential; no installed service is
// restarted and every native database/principal is uniquely disposable.
func TestQEMUDatabaseReplacementHTTPNative(t *testing.T) {
	if os.Getenv("CYBERPANEL_QEMU_LIVE_TRANSFER") != "1" {
		t.Skip("requires root QEMU native fixture lease")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	random := make([]byte, 8)
	_, err := rand.Read(random)
	check(err)
	name := "qa" + hex.EncodeToString(random)
	id := func(s string) database.ResourceID { v, e := database.NewResourceID(s); check(e); return v }
	sqlid := func(s string) database.SQLIdentifier { v, e := database.ParseSQLIdentifier(s); check(e); return v }
	tenant, _ := site.NewTenantID(name)
	siteID, _ := site.NewSiteID(name + "-site")
	live := database.Database{Metadata: database.Metadata{ID: id(name), TenantID: tenant, SiteID: siteID, Generation: 1, Status: database.ResourceStatus{Lifecycle: database.LifecycleReady, Health: database.HealthHealthy, Reconciliation: database.ReconciliationInSync, ObservedGeneration: 1}}, InstanceID: id("mariadb-local"), Name: sqlid(name), Charset: sqlid("utf8mb4"), Collation: sqlid("utf8mb4_unicode_ci"), QuotaBytes: 1 << 20}
	principal := database.DatabasePrincipal{Metadata: live.Metadata, InstanceID: live.InstanceID, Name: live.Name, HostScope: database.HostScopeLoopback}
	principal.ID = id(name + "-principal")
	principal.CredentialSecretRef, _ = database.NewSecretRef(name + "-secret")
	grants := database.GrantSet{Metadata: live.Metadata, InstanceID: live.InstanceID, DatabaseID: live.ID, PrincipalID: principal.ID, Grants: []database.Grant{{Scope: database.GrantScopeDatabase, Privileges: []database.Privilege{database.PrivilegeSelect, database.PrivilegeInsert}}}}
	grants.ID = id(name + "-grants")
	query := func(statement string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/usr/bin/mariadb", "--no-defaults", "--protocol=socket", "--socket=/run/mysqld/mysqld.sock", "--user=root", "--batch", "--skip-column-names")
		cmd.Stdin = strings.NewReader(statement)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("native fixture: %v %s", e, out)
		}
		return strings.TrimSpace(string(out))
	}
	query("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE TABLE `" + name + "`.sample(id INT PRIMARY KEY,body TEXT,raw_bytes BLOB) ENGINE=InnoDB; INSERT INTO `" + name + "`.sample VALUES(77,'original',X'00FF'); CREATE USER '" + name + "'@'localhost' IDENTIFIED BY 'fixture-password'; GRANT SELECT,INSERT ON `" + name + "`.* TO '" + name + "'@'localhost';")
	const root = "/var/lib/cyberpanel/database"
	for kind, r := range map[string]database.Resource{"databases": live, "principals": principal, "grants": grants} {
		raw, e := json.Marshal(r)
		check(e)
		check(os.WriteFile(filepath.Join(root, kind, r.Meta().ID.String()+".json"), raw, 0600))
	}
	var baseJob database.TransferJob
	var extraSchemas []string
	t.Cleanup(func() {
		var f struct {
			Restore *struct {
				Database database.Database
				ImportID database.ResourceID `json:"import_id"`
			}
		}
		raw, _ := os.ReadFile(filepath.Join(root, "transfer-fences", live.ID.String()+".json"))
		_ = json.Unmarshal(raw, &f)
		script := "DROP USER IF EXISTS '" + name + "'@'localhost'; DROP DATABASE IF EXISTS `" + name + "`;"
		for _, schema := range extraSchemas {
			script += "DROP DATABASE IF EXISTS `" + schema + "`;"
		}
		if f.Restore != nil {
			script += "DROP DATABASE IF EXISTS `" + f.Restore.Database.Name.String() + "`;"
			if !f.Restore.ImportID.IsZero() {
				var imp struct{ Target database.Database }
				raw, _ := os.ReadFile(filepath.Join(root, "transfer-imports", f.Restore.ImportID.String()+".json"))
				_ = json.Unmarshal(raw, &imp)
				if !imp.Target.Name.IsZero() {
					script += "DROP DATABASE IF EXISTS `" + imp.Target.Name.String() + "`;"
				}
				_ = os.Remove(filepath.Join(root, "transfer-imports", f.Restore.ImportID.String()+".json"))
			}
		}
		cmd := exec.Command("/usr/bin/mariadb", "--no-defaults", "--protocol=socket", "--socket=/run/mysqld/mysqld.sock", "--user=root")
		cmd.Stdin = strings.NewReader(script)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Errorf("cleanup: %v %s", e, out)
		}
		for kind, key := range map[string]database.ResourceID{"databases": live.ID, "principals": principal.ID, "grants": grants.ID, "transfer-fences": live.ID} {
			if e := os.Remove(filepath.Join(root, kind, key.String()+".json")); e != nil && !os.IsNotExist(e) {
				t.Error(e)
			}
		}
		_ = os.Remove(filepath.Join(root, "transfer-fences", live.ID.String()+".lock"))
	})
	control, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "control.db"))
	check(err)
	defer control.Close()
	control.SetMaxOpenConns(1)
	repository, err := database.NewSQLRepository(control)
	check(err)
	check(repository.Bootstrap(ctx))
	check(repository.EnsureBootstrapResources(ctx, live))
	store, err := identity.NewStore(control)
	check(err)
	check(store.Bootstrap(ctx))
	ident, err := identity.NewService(store, replacementIdentityVerifier{}, replacementIdentityAudit{})
	check(err)
	owner := identity.ID(name + "-owner")
	credentialID := identity.ID(name + "-key")
	_, err = ident.ClaimInstallation(ctx, identity.InstallationClaim{PrincipalID: owner, TenantID: identity.ID(name), MembershipID: identity.ID(name + "-member"), RoleID: identity.ID(name + "-role"), BindingID: identity.ID(name + "-binding"), PlanID: identity.ID(name + "-plan"), Username: name, Email: name + "@example.invalid", DisplayName: "Native replacement fixture", Password: []byte("native-fixture-password"), Quota: identity.ResourceQuota{Sites: 2, Domains: 2, DiskBytes: 1 << 30, Inodes: 1000, MemoryBytes: 1 << 28, PIDs: 32, PHPConcurrency: 2}})
	check(err)
	credential := identity.Credential{ID: credentialID, PrincipalID: owner, Kind: identity.CredentialAPIKey, State: identity.CredentialActive, Label: "Fixture", VerifierRef: identity.ID(name + "-verifier"), Scopes: []identity.Permission{identity.MustPermission("database:manage")}, AuthzEpoch: 1, CreatedAt: time.Now().UTC()}
	check(store.Apply(ctx, identity.Mutation{Credential: &credential}))
	project, _ := site.NewProjectID(name + "-project")
	hostname, _ := site.ParseHostname(name + ".example.invalid")
	aggregate, err := site.Create(site.CreateInput{ID: siteID, TenantID: tenant, ProjectID: project, PrimaryHostname: hostname, PHPProfile: site.PHPProfile83})
	check(err)
	aggregate, err = aggregate.Transition(1, site.LifecycleActive)
	check(err)
	index, err := audit.NewSQLIndex(control)
	check(err)
	check(index.Bootstrap(ctx))
	auditRoot := t.TempDir()
	check(os.Chmod(auditRoot, 0700))
	public, private, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	signer, err := audit.NewEd25519Signer("fixture", private, map[string]ed25519.PublicKey{"fixture": public})
	check(err)
	writer, err := audit.NewWriter(auditRoot, index, signer)
	check(err)
	executor, err := database.NewLinuxMariaDBExecutor(replacementNativeSecrets{}, database.LinuxMariaDBUbuntu, nil)
	check(err)
	coordinator := database.NewCoordinator(repository, executor, database.SystemClock{})
	operations, err := NewDatabaseTransferOperations(ctx, control, repository, coordinator, replacementSites{aggregate}, ident, writer)
	check(err)
	registry, err := NewDomainRegistry()
	check(err)
	check(bindDatabaseImportContracts(registry, DomainServices{DatabaseTransfers: operations}))
	auth := &importHTTPAuth{exportHTTPAuth: exportHTTPAuth{actor: Actor{PrincipalID: owner, CredentialID: credentialID, AuthzEpoch: 1, Assurance: identity.AssuranceMFA, CredentialKind: CredentialAPIKey}}}
	nonces, err := NewDirectoryNonceStore(filepath.Join(t.TempDir(), "nonces"))
	check(err)
	ledger, err := NewDirectoryIdempotencyLedger(filepath.Join(t.TempDir(), "ledger"))
	check(err)
	core, err := NewCore(registry, auth, exportHTTPVerifier{}, nonces, ledger)
	check(err)
	server := httptest.NewServer(core.Handler())
	defer server.Close()
	seq := 0
	invoke := func(operation string, payload any, generation uint64) CoreResponse {
		t.Helper()
		seq++
		raw, e := json.Marshal(payload)
		check(e)
		req := CoreRequest{ProtocolVersion: InternalProtocolVersion, KeyID: "fixture", Nonce: fmt.Sprintf("replacement-nonce-%08d", seq), SentAt: time.Now().UTC(), Meta: RequestMeta{ClientIP: netip.MustParseAddr("127.0.0.1"), Host: "localhost", TLS: true, UserAgentDigest: strings.Repeat("a", 64)}, Auth: &AuthMaterial{Kind: CredentialAPIKey, APIKey: "fixture"}, Request: RequestEnvelope{APIVersion: APIVersion, RequestID: fmt.Sprintf("replacement-request-%08d", seq), Operation: operation, TenantID: name, ResourceID: siteID.String(), ExpectedGeneration: generation, Payload: raw}}
		if operation != "database.import.prepare" && operation != "database.import.inspect" {
			req.IdempotencyKey = fmt.Sprintf("replacement-command-%08d", seq)
		}
		body, e := json.Marshal(req)
		check(e)
		response, e := http.Post(server.URL+"/internal/v1/invoke", ContentTypeJSON, bytes.NewReader(body))
		check(e)
		defer response.Body.Close()
		var result CoreResponse
		check(json.NewDecoder(response.Body).Decode(&result))
		return result
	}
	decode := func(r CoreResponse, v any) {
		t.Helper()
		if r.Status != http.StatusOK {
			t.Fatalf("HTTP %d: %+v", r.Status, r.Problem)
		}
		raw, e := json.Marshal(r.Envelope.Result)
		check(e)
		check(json.Unmarshal(raw, v))
	}
	now := time.Now().UTC()
	export := database.TransferJob{ID: id(name + "-export"), IdempotencyKey: name + "-export", TenantID: tenant, SiteID: siteID, DatabaseID: live.ID, DatabaseGeneration: 1, InstanceID: live.InstanceID, Direction: database.TransferExport, Format: database.TransferFormatSQL, Compression: database.TransferCompressionNone, Selection: database.TransferSelection{Schema: true, Data: true}, Limits: database.TransferLimits{MaximumBytes: 1 << 20, MaximumRows: 100, MaximumDuration: time.Minute}, ConflictPolicy: database.TransferConflictFail, Retention: database.TransferRetention{RetainUntil: now.Add(time.Hour)}, CreatedBy: owner.String(), CreatedAt: now, Impact: database.SealTransferImpactPreview(database.TransferImpactPreview{DatabaseID: live.ID, DatabaseGeneration: 1, Rows: 1, Bytes: 512, SchemaObjects: 1, CapturedAt: now})}
	artifact := database.WorkspaceExportArtifact(export)
	export.Destination = &artifact
	export, err = database.SealTransferJob(export)
	check(err)
	artifacts, err := database.NewLinuxTransferArtifactStore(root+"/transfers", 1<<20, time.Now)
	check(err)
	output, err := artifacts.BeginTransferArtifact(ctx, artifact, export.Format, export.Compression, export.Retention)
	check(err)
	dump := []byte("-- cyberpanel-mariadb-transfer-v1\nCREATE TABLE sample(id INT PRIMARY KEY,body TEXT,raw_bytes BLOB) ENGINE=InnoDB; INSERT INTO sample VALUES(88,'replacement',X'112200'),(99,NULL,NULL);\n")
	_, err = output.Write(dump)
	check(err)
	sum := sha256.Sum256(dump)
	descriptor, err := output.Commit(ctx, hex.EncodeToString(sum[:]), uint64(len(dump)), 2)
	check(err)
	raw, err := json.Marshal(artifact)
	check(err)
	sum = sha256.Sum256(raw)
	artifactPath := filepath.Join(root, "transfers", hex.EncodeToString(sum[:]))
	t.Cleanup(func() { check(os.RemoveAll(artifactPath)) })
	prepare := DatabaseImportPreparePayload{DatabaseID: live.ID, SourceExport: &export, Artifact: descriptor, Replacement: true}
	decode(invoke("database.import.prepare", prepare, 1), &baseJob)
	if query("SELECT COUNT(*) FROM `"+name+"`.sample;") != "1" {
		t.Fatal("preview changed original")
	}
	if query("SELECT IF(JSON_VALUE(Priv,'$.account_locked')=true,1,0) FROM mysql.global_priv WHERE User='"+name+"' AND Host='localhost';") != "0" {
		t.Fatal("preview fenced application writers")
	}
	approval := DatabaseReplacementApproval{DatabaseID: live.ID, DatabaseName: name, Generation: 1, JobDigest: baseJob.Digest, RestorePointRef: baseJob.ID, Action: "replace"}
	payload := DatabaseReplacementPayload{Job: baseJob, Approval: approval}
	for _, change := range []func(*DatabaseReplacementPayload){func(p *DatabaseReplacementPayload) { p.Approval = DatabaseReplacementApproval{} }, func(p *DatabaseReplacementPayload) { p.Approval.DatabaseName = "wrong" }, func(p *DatabaseReplacementPayload) { p.Approval.Generation = 2 }, func(p *DatabaseReplacementPayload) { p.Approval.RestorePointRef = id("wrong-point") }} {
		bad := payload
		change(&bad)
		if r := invoke("database.import.replace.run", bad, 1); r.Status < 400 {
			t.Fatal("bad approval accepted", r.Status)
		}
	}
	auth.denied = true
	if r := invoke("database.import.replace.run", payload, 1); r.Status < 400 {
		t.Fatal("unauthorized replace accepted")
	}
	auth.denied = false
	// A real failure AFTER account lock must remain explicitly reconcilable.
	pointSum := sha256.Sum256([]byte(baseJob.ID.String()))
	collision := "cprst" + hex.EncodeToString(pointSum[:])[:24]
	extraSchemas = append(extraSchemas, collision)
	query("CREATE DATABASE `" + collision + "`;")
	if r := invoke("database.import.replace.run", payload, 1); r.Status < 400 {
		t.Fatal("preexisting point accepted")
	}
	if query("SELECT IF(JSON_VALUE(Priv,'$.account_locked')=true,1,0) FROM mysql.global_priv WHERE User='"+name+"' AND Host='localhost';") != "1" {
		t.Fatal("fixture did not reach acquired fence")
	}
	abort := payload
	abort.Approval.Action = "abort"
	var released map[string]bool
	decode(invoke("database.import.replace.abort", abort, 1), &released)
	if !released["released"] || query("SELECT IF(JSON_VALUE(Priv,'$.account_locked')=true,1,0) FROM mysql.global_priv WHERE User='"+name+"' AND Host='localhost';") != "0" {
		t.Fatal("abort did not restore original access")
	}
	if query("SELECT COUNT(*) FROM `"+name+"`.sample;") != "1" || query("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+collision+"';") != "1" {
		t.Fatal("failed preparation/abort destroyed original or unowned schema")
	}
	query("DROP DATABASE `" + collision + "`;")
	decode(invoke("database.import.prepare", prepare, 1), &baseJob)
	// Reconstruct an interruption after journaling creation intent but before
	// CREATE DATABASE. Abort must release access even though no schema exists.
	_, err = coordinator.ReplacementPoint(ctx, baseJob, "replacement-prepare")
	check(err)
	fencePath := filepath.Join(root, "transfer-fences", live.ID.String()+".json")
	raw, err = os.ReadFile(fencePath)
	check(err)
	var interrupted map[string]json.RawMessage
	check(json.Unmarshal(raw, &interrupted))
	var pointRecord map[string]json.RawMessage
	check(json.Unmarshal(interrupted["restore"], &pointRecord))
	var emptyRestore database.Database
	check(json.Unmarshal(pointRecord["database"], &emptyRestore))
	query("DROP DATABASE `" + emptyRestore.Name.String() + "`;")
	pointRecord["state"] = json.RawMessage(`"creating"`)
	interrupted["restore"], err = json.Marshal(pointRecord)
	check(err)
	raw, err = json.Marshal(interrupted)
	check(err)
	check(os.WriteFile(fencePath, raw, 0600))
	abort = DatabaseReplacementPayload{Job: baseJob, Approval: DatabaseReplacementApproval{DatabaseID: live.ID, DatabaseName: name, Generation: 1, JobDigest: baseJob.Digest, RestorePointRef: baseJob.ID, Action: "abort"}}
	decode(invoke("database.import.replace.abort", abort, 1), &released)
	decode(invoke("database.import.prepare", prepare, 1), &baseJob)
	approval.JobDigest = baseJob.Digest
	approval.RestorePointRef = baseJob.ID
	payload = DatabaseReplacementPayload{Job: baseJob, Approval: approval}
	var receipt database.TransferReceipt
	decode(invoke("database.import.replace.run", payload, 1), &receipt)
	if receipt.Status != database.TransferCompleted {
		t.Fatal("replacement failed", receipt.Status)
	}
	if query("SELECT CONCAT(id,':',COALESCE(body,'NULL'),':',COALESCE(HEX(raw_bytes),'NULL')) FROM `"+name+"`.sample ORDER BY id;") != "88:replacement:112200\n99:NULL:NULL" {
		t.Fatal("new rows differ")
	}
	var journal struct {
		Restore struct{ Database database.Database }
		State   string
	}
	raw, err = os.ReadFile(filepath.Join(root, "transfer-fences", live.ID.String()+".json"))
	check(err)
	check(json.Unmarshal(raw, &journal))
	restoreName := journal.Restore.Database.Name.String()
	if journal.State != "released" || query("SELECT CONCAT(id,':',body,':',HEX(raw_bytes)) FROM `"+restoreName+"`.sample;") != "77:original:00FF" {
		t.Fatal("original not retained or fence held")
	}
	// Reconstruct API/coordinator using durable SQLite and executor journals.
	executor, err = database.NewLinuxMariaDBExecutor(replacementNativeSecrets{}, database.LinuxMariaDBUbuntu, nil)
	check(err)
	operations.coordinator = database.NewCoordinator(repository, executor, database.SystemClock{})
	decode(invoke("database.import.replace.run", payload, 1), &receipt)
	var state database.TransferJobState
	decode(invoke("database.import.inspect", DatabaseImportInspectPayload{JobID: baseJob.ID}, 0), &state)
	retire := DatabaseReplacementPayload{Job: state.Job, Approval: DatabaseReplacementApproval{DatabaseID: live.ID, DatabaseName: name, Generation: 1, JobDigest: state.Job.Digest, RestorePointRef: state.Job.RestorePointRef, Action: "retire"}}
	if r := invoke("database.import.restore_point.retire", retire, 1); r.Status < 400 {
		t.Fatal("stale retirement accepted")
	}
	var retired database.TransferRestorePoint
	decode(invoke("database.import.restore_point.retire", retire, 2), &retired)
	decode(invoke("database.import.restore_point.retire", retire, 2), &retired)
	if query("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+restoreName+"';") != "0" {
		t.Fatal("approved retained point not retired")
	}
	if query("SELECT COUNT(*) FROM `"+name+"`.sample;") != "2" {
		t.Fatal("retirement changed current database")
	}
}
