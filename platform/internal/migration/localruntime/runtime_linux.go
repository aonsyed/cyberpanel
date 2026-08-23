//go:build linux

package localruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/migration"
	cyberpanelextractor "github.com/aonsyed/cyberpanel/platform/internal/migration/cyberpanel"
)

const (
	DefaultTrustPath             = "/etc/cyberpanel/migration/trust.json"
	defaultClientCertificatePath = "/run/credentials/panel-core.service/migration-client.crt"
	defaultClientKeyPath         = "/run/credentials/panel-core.service/migration-client.key"
	defaultCertificateAuthority  = "/run/credentials/panel-core.service/migration-ca.pem"
)

// Runtime is the local panel-core migration authority. It provides signed
// remote inventory and collision-safe dry runs. Target mutation remains
// closed until every canonical resource handler, probe, activation controller,
// and secret gateway is registered.
type Runtime struct {
	Repository   *migration.SQLRepository
	Scopes       *migration.RuntimeScopeStore
	Orchestrator *migration.Orchestrator
}

func New(ctx context.Context, db *sql.DB, repository *migration.SQLRepository) (*Runtime, error) {
	if ctx == nil || db == nil || repository == nil {
		return nil, migration.ErrInvalid
	}
	scopes, err := migration.NewRuntimeScopeStore(db)
	if err != nil {
		return nil, err
	}
	if err = scopes.Bootstrap(ctx); err != nil {
		return nil, err
	}
	source := &scopedExtractorSource{scopes:scopes, clients:map[migration.ID]scopedClient{}, chunks:map[string][]migration.ID{}}
	orchestrator, err := migration.NewOrchestrator(repository, configuredManifestVerifier{path: DefaultTrustPath}, source, source, blockedTarget{})
	if err != nil {
		return nil, err
	}
	return &Runtime{Repository: repository, Scopes: scopes, Orchestrator: orchestrator}, nil
}

type trustDocument struct {
	TargetInstallationID string            `json:"target_installation_id"`
	SchemaHashes         []string          `json:"schema_hashes"`
	ManifestKeys         map[string]string `json:"manifest_keys"`
}

type configuredManifestVerifier struct{ path string }

func (verifier configuredManifestVerifier) Verify(ctx context.Context, manifest migration.Manifest) error {
	policy, err := loadTrustPolicy(verifier.path)
	if err != nil {
		return errors.Join(migration.ErrBlocked, err)
	}
	signed, err := migration.NewSignedManifestVerifier(policy)
	if err != nil {
		return err
	}
	return signed.Verify(ctx, manifest)
}

func loadTrustPolicy(path string) (migration.ManifestTrustPolicy, error) {
	if path != DefaultTrustPath {
		return migration.ManifestTrustPolicy{}, migration.ErrInvalid
	}
	raw, err := readStableFile(path, 1<<20, false)
	if err != nil {
		return migration.ManifestTrustPolicy{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var document trustDocument
	if err = decoder.Decode(&document); err != nil {
		return migration.ManifestTrustPolicy{}, migration.ErrInvalid
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return migration.ManifestTrustPolicy{}, migration.ErrInvalid
	}
	policy := migration.ManifestTrustPolicy{TargetInstallationID: strings.TrimSpace(document.TargetInstallationID), SchemaHashes: map[string]struct{}{}, Keys: map[string]ed25519.PublicKey{}}
	for _, digest := range document.SchemaHashes {
		digest = strings.ToLower(strings.TrimSpace(digest))
		if len(digest) != sha256.Size*2 {
			return migration.ManifestTrustPolicy{}, migration.ErrInvalid
		}
		if _, err = hex.DecodeString(digest); err != nil {
			return migration.ManifestTrustPolicy{}, migration.ErrInvalid
		}
		policy.SchemaHashes[digest] = struct{}{}
	}
	for keyID, encoded := range document.ManifestKeys {
		rawKey, decodeErr := hex.DecodeString(strings.TrimSpace(encoded))
		if decodeErr != nil || len(rawKey) != ed25519.PublicKeySize || strings.TrimSpace(keyID) != keyID {
			return migration.ManifestTrustPolicy{}, migration.ErrInvalid
		}
		policy.Keys[keyID] = ed25519.PublicKey(rawKey)
	}
	return policy, nil
}

type scopedClient struct{ endpoint string; client *cyberpanelextractor.Client }
type scopedExtractorSource struct{ scopes *migration.RuntimeScopeStore; mu sync.RWMutex; clients map[migration.ID]scopedClient; chunks map[string][]migration.ID }

func (source *scopedExtractorSource) Discover(ctx context.Context, id migration.ID) (migration.Manifest, error) {
	client, err := source.client(ctx, id)
	if err != nil {
		return migration.Manifest{}, err
	}
	manifest, err := client.Discover(ctx, id)
	if err != nil {
		return migration.Manifest{}, err
	}
	source.mu.Lock()
	for _, chunk := range manifest.Chunks {
		values := source.chunks[chunk.Digest]
		found := false
		for _, existing := range values { if existing == id { found = true; break } }
		if !found { values = append(values, id) }
		if len(values) > 64 { values = values[len(values)-64:] }
		source.chunks[chunk.Digest] = values
	}
	source.mu.Unlock()
	return manifest, nil
}

func (source *scopedExtractorSource) OpenChunk(ctx context.Context, digest string, offset, length uint64) ([]byte, error) {
	if source == nil || source.scopes == nil || ctx == nil || len(digest) != sha256.Size*2 || length == 0 || length > 16<<20 {
		return nil, migration.ErrInvalid
	}
	source.mu.RLock()
	ids := append([]migration.ID(nil), source.chunks[digest]...)
	source.mu.RUnlock()
	if len(ids) == 0 {
		return nil, migration.ErrNotFound
	}
	var result error
	for _, id := range ids {
		client, err := source.client(ctx, id)
		if err == nil {
			var value []byte
			value, err = client.OpenChunk(ctx, digest, offset, length)
			if err == nil { return value, nil }
		}
		result = errors.Join(result, err)
	}
	return nil, result
}

func (source *scopedExtractorSource) Generation(ctx context.Context, id migration.ID) (uint64, error) {
	client, err := source.client(ctx, id)
	if err != nil {
		return 0, err
	}
	return client.Generation(ctx, id)
}

func (source *scopedExtractorSource) Quiesce(ctx context.Context, id migration.ID, plan migration.Plan, expectedFence uint64) (migration.SourceFence, error) {
	client, err := source.client(ctx, id)
	if err != nil {
		return migration.SourceFence{}, err
	}
	return client.Quiesce(ctx, id, plan, expectedFence)
}

func (source *scopedExtractorSource) Unquiesce(ctx context.Context, fence migration.SourceFence) error {
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	return client.Unquiesce(ctx, fence)
}

func (source *scopedExtractorSource) FinalDelta(ctx context.Context, fence migration.SourceFence, base migration.Manifest) (migration.Manifest, error) {
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return migration.Manifest{}, err
	}
	return client.FinalDelta(ctx, fence, base)
}

func (source *scopedExtractorSource) CommitSource(ctx context.Context, fence migration.SourceFence) error {
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	return client.CommitSource(ctx, fence)
}

func (source *scopedExtractorSource) RollbackSource(ctx context.Context, fence migration.SourceFence) error {
	client, err := source.client(ctx, fence.MigrationID)
	if err != nil {
		return err
	}
	return client.RollbackSource(ctx, fence)
}

func (source *scopedExtractorSource) client(ctx context.Context, id migration.ID) (*cyberpanelextractor.Client, error) {
	if source == nil || source.scopes == nil || ctx == nil || !id.Valid() {
		return nil, migration.ErrInvalid
	}
	scope, err := source.scopes.LoadByMigration(ctx, id)
	if err != nil {
		return nil, err
	}
	source.mu.RLock()
	cached, found := source.clients[id]
	source.mu.RUnlock()
	if found {
		if cached.endpoint != scope.SourceEndpoint || cached.client == nil { return nil, migration.ErrConflict }
		return cached.client, nil
	}
	dial, err := extractorDialer(scope.SourceEndpoint)
	if err != nil {
		return nil, err
	}
	client, err := cyberpanelextractor.NewClient(dial, 48<<20, 2*time.Minute)
	if err != nil { return nil, err }
	source.mu.Lock()
	if existing, present := source.clients[id]; present {
		source.mu.Unlock()
		if existing.endpoint != scope.SourceEndpoint || existing.client == nil { return nil, migration.ErrConflict }
		return existing.client, nil
	}
	source.clients[id] = scopedClient{endpoint:scope.SourceEndpoint, client:client}
	source.mu.Unlock()
	return client, nil
}

func extractorDialer(endpoint string) (cyberpanelextractor.DialContext, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, migration.ErrInvalid
	}
	address := parsed.Host
	if parsed.Port() == "" {
		address = net.JoinHostPort(parsed.Hostname(), "443")
	}
	certificatePEM, err := readStableFile(defaultClientCertificatePath, 1<<20, false)
	if err != nil {
		return nil, errors.Join(migration.ErrBlocked, err)
	}
	keyPEM, err := readStableFile(defaultClientKeyPath, 1<<20, true)
	if err != nil {
		return nil, errors.Join(migration.ErrBlocked, err)
	}
	certificateAuthority, err := readStableFile(defaultCertificateAuthority, 1<<20, false)
	if err != nil {
		return nil, errors.Join(migration.ErrBlocked, err)
	}
	identity, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, migration.ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificateAuthority) {
		return nil, migration.ErrInvalid
	}
	configuration := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: parsed.Hostname(), RootCAs: roots, Certificates: []tls.Certificate{identity}}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}, Config: configuration}
	return func(ctx context.Context) (net.Conn, error) { return dialer.DialContext(ctx, "tcp", address) }, nil
}

// blockedTarget provides exact dry-run mappings and capacity observations but
// rejects every write. It is intentionally replaced only by a fully populated
// CanonicalTargetImporter; partial handler registration is not accepted.
type blockedTarget struct{}

func (blockedTarget) Capacity(ctx context.Context) (map[string]uint64, error) {
	if ctx == nil {
		return nil, migration.ErrInvalid
	}
	var statistics syscall.Statfs_t
	if err := syscall.Statfs("/", &statistics); err != nil {
		return nil, err
	}
	free := uint64(statistics.Bavail)
	block := uint64(statistics.Bsize)
	if block != 0 && free > ^uint64(0)/block {
		free = ^uint64(0)
	} else {
		free *= block
	}
	return map[string]uint64{"disk_bytes": free, "database_bytes": free, "mail_bytes": free, "certificate_bytes": free, "container_bytes": free, "dns_recordsets": ^uint64(0), "mailboxes": ^uint64(0)}, nil
}

func (blockedTarget) Plan(ctx context.Context, manifest migration.Manifest) ([]migration.Mapping, error) {
	if ctx == nil || manifest.Validate() != nil {
		return nil, migration.ErrInvalid
	}
	values := make([]migration.Mapping, 0, len(manifest.Sites)+len(manifest.Databases)+len(manifest.DNSZones)+len(manifest.MailDomains)+len(manifest.Certificates)+len(manifest.Credentials)+len(manifest.Schedules)+len(manifest.Repositories)+len(manifest.Containers)+len(manifest.BackupPolicies))
	appendMapping := func(kind string, source migration.ID, capacity map[string]uint64) {
		sum := sha256.Sum256([]byte("cyberpanel-migration-target-v1\x00" + kind + "\x00" + manifest.TargetInstallationID + "\x00" + source.String()))
		target, _ := migration.NewID("target_" + hex.EncodeToString(sum[:24]))
		values = append(values, migration.Mapping{SourceKind: kind, SourceID: source, TargetID: target, Disposition: migration.DispositionBlock, Reason: "canonical target mutation authority is not registered", Capacity: capacity})
	}
	for _, value := range manifest.Sites { appendMapping("site", value.SourceID, map[string]uint64{"disk_bytes": chunkBytes(value.Content)}) }
	for _, value := range manifest.Databases { appendMapping("database", value.SourceID, map[string]uint64{"database_bytes": chunkBytes(value.Dump)}) }
	for _, value := range manifest.DNSZones { appendMapping("dns_zone", value.SourceID, map[string]uint64{"dns_recordsets": uint64(len(value.RecordSets))}) }
	for _, value := range manifest.MailDomains { chunks := append([]migration.Chunk(nil), value.MailData...); for _, mailbox := range value.Mailboxes { chunks=append(chunks,mailbox.Data...) }; appendMapping("mail_domain", value.SourceID, map[string]uint64{"mail_bytes": chunkBytes(chunks), "mailboxes": uint64(len(value.Mailboxes))}) }
	for _, value := range manifest.Certificates { appendMapping("certificate", value.SourceID, map[string]uint64{"certificate_bytes": chunkBytes(append(append([]migration.Chunk(nil),value.Certificate...),value.Chain...))}) }
	for _, value := range manifest.Credentials { appendMapping("credential", value.SourceID, nil) }
	for _, value := range manifest.Schedules { appendMapping("schedule", value.SourceID, nil) }
	for _, value := range manifest.Repositories { appendMapping("repository", value.SourceID, nil) }
	for _, value := range manifest.Containers { appendMapping("container_application", value.SourceID, map[string]uint64{"container_bytes": chunkBytes(append(append([]migration.Chunk(nil),value.Descriptor...),value.VolumeData...))}) }
	for _, value := range manifest.BackupPolicies { appendMapping("backup_policy", value.SourceID, nil) }
	return values, nil
}

func (blockedTarget) Prepare(context.Context, migration.Migration, migration.Plan) error { return migration.ErrBlocked }
func (blockedTarget) ImportResource(context.Context, migration.Migration, migration.Mapping, migration.Manifest) (migration.ResourceProgress, error) { return migration.ResourceProgress{}, migration.ErrBlocked }
func (blockedTarget) ApplyDelta(context.Context, migration.Migration, migration.Manifest) ([]migration.ResourceProgress, error) { return nil, migration.ErrBlocked }
func (blockedTarget) VerifyDark(context.Context, migration.Migration, migration.Plan) (migration.Verification, error) { return migration.Verification{}, migration.ErrBlocked }
func (blockedTarget) Activate(context.Context, migration.Migration, migration.Plan) (migration.ActivationReceipt, error) { return migration.ActivationReceipt{}, migration.ErrBlocked }
func (blockedTarget) VerifyActive(context.Context, migration.Migration, migration.Plan, migration.ActivationReceipt) (migration.Verification, error) { return migration.Verification{}, migration.ErrBlocked }
func (blockedTarget) Deactivate(context.Context, migration.ActivationReceipt) error { return migration.ErrBlocked }
func (blockedTarget) Finalize(context.Context, migration.Migration) error { return migration.ErrBlocked }

func chunkBytes(values []migration.Chunk) uint64 {
	var total uint64
	for _, value := range values {
		if total > ^uint64(0)-value.Size {
			return ^uint64(0)
		}
		total += value.Size
	}
	return total
}

func readStableFile(path string, maximum int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum || info.Mode().Perm()&0o022 != 0 || private && info.Mode().Perm()&0o077 != 0 {
		return nil, migration.ErrBlocked
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(info, after) || int64(len(raw)) != info.Size() {
		return nil, fmt.Errorf("migration authority changed while reading")
	}
	return raw, nil
}

var _ migration.SourceReader = (*scopedExtractorSource)(nil)
var _ migration.CutoverSource = (*scopedExtractorSource)(nil)
var _ migration.TargetImporter = blockedTarget{}
